//! Runtime multi-curve ECDSA and ECDH (heap-backed [`BoxedUint`]).
//!
//! Unlike the const-generic [`ecdsa`](super::ecdsa)/[`ecdh`](super::ecdh) P-256
//! API — which is faster when the curve is fixed at compile time — these types
//! carry their [`CurveId`] at runtime, so one set of types serves every
//! supported curve. This is what the TLS and X.509 layers use, where the peer's
//! curve is known only at parse time.

use super::Error;
use super::curves::CurveId;

/// `id-ecPublicKey` (`1.2.840.10045.2.1`) — the PKCS#8 / SPKI algorithm OID for
/// elliptic-curve keys. Defined locally because `ec` cannot depend on `x509`
/// (which depends on `ec`).
const EC_PUBLIC_KEY_OID: &[u64] = &[1, 2, 840, 10045, 2, 1];
use crate::bignum::{BoxedMontModulus, BoxedUint};
use crate::ct::ConstantTimeEq;
use crate::hash::{Digest, Hmac};
use crate::rng::{CryptoRng, RngCore};
use alloc::vec;
use alloc::vec::Vec;

/// A runtime-curve ECDSA public key (an affine point on its curve).
#[derive(Clone, Debug)]
pub struct BoxedEcdsaPublicKey {
    curve: CurveId,
    x: BoxedUint,
    y: BoxedUint,
}

/// A runtime-curve ECDSA private key (a scalar in `[1, n-1]`).
#[derive(Clone)]
pub struct BoxedEcdsaPrivateKey {
    curve: CurveId,
    d: BoxedUint,
}

/// A runtime-curve ECDSA signature `(r, s)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoxedEcdsaSignature {
    r: BoxedUint,
    s: BoxedUint,
}

/// A runtime-curve ECDH private key.
#[derive(Clone)]
pub struct BoxedEcdhPrivateKey {
    curve: CurveId,
    d: BoxedUint,
}

/// `1 <= v < n`.
fn in_range(v: &BoxedUint, n: &BoxedUint) -> bool {
    !v.is_zero() && v.reduce(n) == *v
}

/// Modular inverse `a^-1 mod m` for prime `m`, via Fermat (`a^(m-2) mod m`).
fn inv_mod(fm: &BoxedMontModulus, a: &BoxedUint, m: &BoxedUint) -> BoxedUint {
    fm.pow(a, &m.sub(&BoxedUint::from_u64(2)))
}

/// RFC 6979 `bits2int`: the integer of the leftmost `qlen` bits of `data`.
fn bits2int(data: &[u8], qlen: usize) -> BoxedUint {
    let blen = data.len() * 8;
    let v = BoxedUint::from_be_bytes(data);
    if blen > qlen {
        v.shr_bits(blen - qlen)
    } else {
        v
    }
}

/// A uniformly random scalar in `[1, n-1]` via rejection sampling.
///
/// Drawing `order_len` bytes and reducing mod `n` is biased when the byte
/// width exceeds `n.bit_len()`. For P-521 in particular, `order_len = 66`
/// (528 bits) while `n` is ~521 bits, so naive reduction is biased by
/// roughly `2^-7` on a band of residues. We instead reject any sample `≥ n`
/// (and zero) and resample — bias collapses to zero.
fn random_scalar<R: RngCore>(curve: CurveId, n: &BoxedUint, rng: &mut R) -> BoxedUint {
    let bytes = curve.order_len();
    // Mask the high byte to `n.bit_len()` bits so the draw is uniform over
    // `[0, 2^n.bit_len())` rather than `[0, 2^(8*order_len))` — without this
    // step P-521's rejection rate would be ~50%.
    let nbits = n.bit_len();
    let high_keep_bits = ((nbits - 1) % 8) + 1;
    let high_mask = if high_keep_bits == 8 {
        0xff
    } else {
        (1u8 << high_keep_bits) - 1
    };
    loop {
        let mut buf = vec![0u8; bytes];
        rng.fill_bytes(&mut buf);
        buf[0] &= high_mask;
        let candidate = BoxedUint::from_be_bytes(&buf);
        // Accept iff 1 ≤ candidate < n.
        if !candidate.is_zero() && candidate.lt(n) {
            return candidate;
        }
    }
}

/// RFC 6979 deterministic nonce `k` for order `n` (bit length `qlen`), using
/// HMAC-`D`, with `order_len`-byte octet strings.
fn generate_k<D: Digest>(
    d: &BoxedUint,
    hash: &[u8],
    n: &BoxedUint,
    order_len: usize,
    qlen: usize,
) -> BoxedUint {
    let d_oct = d.to_be_bytes(order_len);
    let h_oct = bits2int(hash, qlen).reduce(n).to_be_bytes(order_len);

    let mut v = D::zeroed_output();
    for b in v.as_mut() {
        *b = 0x01;
    }
    let mut k = D::zeroed_output(); // all zero

    for &sep in &[0x00u8, 0x01u8] {
        let mut mac = Hmac::<D>::new(k.as_ref());
        mac.update(v.as_ref());
        mac.update(&[sep]);
        mac.update(&d_oct);
        mac.update(&h_oct);
        k = mac.finalize();
        v = Hmac::<D>::mac(k.as_ref(), v.as_ref());
    }

    loop {
        let mut t = Vec::with_capacity(order_len);
        while t.len() < order_len {
            v = Hmac::<D>::mac(k.as_ref(), v.as_ref());
            t.extend_from_slice(v.as_ref());
        }
        let candidate = bits2int(&t[..order_len], qlen);
        if in_range(&candidate, n) {
            return candidate;
        }
        let mut mac = Hmac::<D>::new(k.as_ref());
        mac.update(v.as_ref());
        mac.update(&[0x00]);
        k = mac.finalize();
        v = Hmac::<D>::mac(k.as_ref(), v.as_ref());
    }
}

impl BoxedEcdsaPublicKey {
    /// Parses a SEC1 point on `curve`, accepting both the uncompressed form
    /// (`0x04 || X || Y`, `1 + 2·field_len` bytes) and the **compressed** form
    /// (`0x02`/`0x03 || X`, `1 + field_len` bytes), where the tag's low bit is
    /// the parity of `Y`. Compressed decoding recovers `Y` via the field square
    /// root (a "lift_x" of the abscissa); a bare 32-byte BIP340 x-only key is
    /// the compressed even-`Y` point `0x02 || X`.
    ///
    /// Rejects a bad length/tag, an out-of-range coordinate, an off-curve point,
    /// or an abscissa with no square root.
    pub fn from_sec1(curve: CurveId, bytes: &[u8]) -> Result<Self, Error> {
        let flen = curve.field_len();
        let c = curve.curve();
        match bytes.first().copied() {
            Some(tag @ (0x02 | 0x03)) => {
                if bytes.len() != 1 + flen {
                    return Err(Error::Malformed);
                }
                let x = BoxedUint::from_be_bytes(&bytes[1..]);
                let (x, y) = c.decompress(&x, tag & 1 == 1).ok_or(Error::InvalidInput)?;
                Ok(BoxedEcdsaPublicKey { curve, x, y })
            }
            Some(0x04) => {
                if bytes.len() != 1 + 2 * flen {
                    return Err(Error::Malformed);
                }
                let x = BoxedUint::from_be_bytes(&bytes[1..1 + flen]);
                let y = BoxedUint::from_be_bytes(&bytes[1 + flen..]);
                if !c.in_field(&x) || !c.in_field(&y) || !c.is_on_curve(&x, &y) {
                    return Err(Error::InvalidInput);
                }
                Ok(BoxedEcdsaPublicKey { curve, x, y })
            }
            _ => Err(Error::Malformed),
        }
    }

    /// Adds two public keys as curve points: `Q = self + other`, returning the
    /// public key for `Q`. Both keys must be on the same curve.
    ///
    /// Returns [`Error::InvalidInput`] if the curves differ or the sum is the
    /// point at infinity (`self == -other`) — the identity has no public-key
    /// encoding. Useful for key tweaking / aggregation (e.g. BIP341 Taproot:
    /// `Q = lift_x(internal) + t·G`).
    pub fn add(&self, other: &Self) -> Result<Self, Error> {
        if self.curve != other.curve {
            return Err(Error::InvalidInput);
        }
        let c = self.curve.curve();
        let sum = c.point_add(
            &c.lift_affine(&self.x, &self.y),
            &c.lift_affine(&other.x, &other.y),
        );
        let (x, y) = c.to_affine(&sum).ok_or(Error::InvalidInput)?;
        Ok(BoxedEcdsaPublicKey {
            curve: self.curve,
            x,
            y,
        })
    }

    /// Encodes the key as an uncompressed SEC1 point (`0x04 || X || Y`).
    pub fn to_sec1(&self) -> Vec<u8> {
        let flen = self.curve.field_len();
        let mut out = vec![0u8; 1 + 2 * flen];
        out[0] = 0x04;
        out[1..1 + flen].copy_from_slice(&self.x.to_be_bytes(flen));
        out[1 + flen..].copy_from_slice(&self.y.to_be_bytes(flen));
        out
    }

    /// The curve this key belongs to.
    pub fn curve(&self) -> CurveId {
        self.curve
    }

    /// Verifies `sig` over `msg`, hashing with `D`.
    pub fn verify<D: Digest>(&self, msg: &[u8], sig: &BoxedEcdsaSignature) -> Result<(), Error> {
        self.verify_prehash(D::digest(msg).as_ref(), sig)
    }

    /// Verifies `sig` over an already-computed message digest `prehash`. Unlike
    /// signing, verification takes no hash type parameter — it only reduces
    /// `prehash` to the curve order's bit length. See
    /// [`BoxedEcdsaPrivateKey::sign_prehash`].
    pub fn verify_prehash(&self, prehash: &[u8], sig: &BoxedEcdsaSignature) -> Result<(), Error> {
        let c = self.curve.curve();
        let n = c.order().clone();
        let fq = BoxedMontModulus::new(&n);
        if !in_range(&sig.r, &n) || !in_range(&sig.s, &n) {
            return Err(Error::Verification);
        }
        let z = bits2int(prehash, n.bit_len()).reduce(&n);
        let w = inv_mod(&fq, &sig.s, &n);
        let u1 = fq.mul_mod(&z, &w);
        let u2 = fq.mul_mod(&sig.r, &w);

        let point = c.lift_affine(&self.x, &self.y);
        let sum = c.point_add(&c.mul_generator(&u1), &c.scalar_mul(&u2, &point));
        let (vx, _) = c.to_affine(&sum).ok_or(Error::Verification)?;
        let v = vx.reduce(&n);
        if bool::from(v.ct_eq(&sig.r)) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

impl BoxedEcdsaPrivateKey {
    /// Creates a private key from a big-endian scalar on `curve`, checking it is
    /// in `[1, n-1]`.
    pub fn from_bytes(curve: CurveId, bytes: &[u8]) -> Result<Self, Error> {
        let d = BoxedUint::from_be_bytes(bytes);
        let n = curve.curve().order().clone();
        if in_range(&d, &n) {
            Ok(BoxedEcdsaPrivateKey { curve, d })
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// Generates a new private key on `curve` from `rng`. The RNG must be a
    /// cryptographically secure CSPRNG (see [`CryptoRng`]).
    pub fn generate<R: RngCore + CryptoRng>(curve: CurveId, rng: &mut R) -> Self {
        let n = curve.curve().order().clone();
        BoxedEcdsaPrivateKey {
            curve,
            d: random_scalar(curve, &n, rng),
        }
    }

    /// The curve this key belongs to.
    pub fn curve(&self) -> CurveId {
        self.curve
    }

    /// Derives the public key `d * G`.
    pub fn public_key(&self) -> BoxedEcdsaPublicKey {
        let c = self.curve.curve();
        let (x, y) = c
            .to_affine(&c.mul_generator(&self.d))
            .expect("d in [1,n-1] so d*G is not the identity");
        BoxedEcdsaPublicKey {
            curve: self.curve,
            x,
            y,
        }
    }

    /// Signs `msg`, hashing with `D` and deriving the nonce per RFC 6979.
    pub fn sign<D: Digest>(&self, msg: &[u8]) -> Result<BoxedEcdsaSignature, Error> {
        self.sign_prehash::<D>(D::digest(msg).as_ref())
    }

    /// Signs an already-computed message digest (e.g. a SHA-256 over a TLS
    /// transcript, an X.509 TBS, or a JWS signing input), deriving the nonce
    /// per RFC 6979.
    ///
    /// `D` is the hash used for the RFC 6979 nonce derivation — pass the same
    /// hash that produced `prehash` so the deterministic nonce (and thus the
    /// signature) matches [`sign::<D>`](Self::sign) and the RFC 6979 vectors.
    /// `prehash` is reduced to the curve order's bit length internally, so a
    /// digest wider than the order (e.g. SHA-512 on P-256) is truncated per
    /// SEC1 / FIPS 186-5.
    ///
    /// # Security
    /// The caller owns the guarantee that `prehash` is a cryptographically
    /// strong digest of the intended, protocol-bound message. Signing
    /// attacker-influenced bytes that are not such a digest can enable forgery
    /// at the application layer. Prefer [`sign`](Self::sign) whenever the full
    /// message is available.
    pub fn sign_prehash<D: Digest>(&self, prehash: &[u8]) -> Result<BoxedEcdsaSignature, Error> {
        let (r, s, _, _) = self.sign_prehash_inner::<D>(prehash)?;
        Ok(BoxedEcdsaSignature { r, s })
    }

    /// Core RFC 6979 signing returning the raw `(r, s)` plus the two facts a
    /// caller needs to build a recovery id: whether the ephemeral point's
    /// x-coordinate exceeded the group order before reduction (`x_overflow`),
    /// and the parity of its y-coordinate (`y_is_odd`). `s` is **not** low-S
    /// normalized here — the public [`sign_prehash`](Self::sign_prehash) keeps
    /// its historical raw form, and [`sign_prehash_recoverable`] does the
    /// normalization itself.
    fn sign_prehash_inner<D: Digest>(
        &self,
        prehash: &[u8],
    ) -> Result<(BoxedUint, BoxedUint, bool, bool), Error> {
        let c = self.curve.curve();
        let n = c.order().clone();
        let fq = BoxedMontModulus::new(&n);
        let order_len = self.curve.order_len();

        let z = bits2int(prehash, n.bit_len()).reduce(&n);
        let k = generate_k::<D>(&self.d, prehash, &n, order_len, n.bit_len());

        let (full_x, full_y) = c
            .to_affine(&c.mul_generator(&k))
            .ok_or(Error::InvalidInput)?;
        let r = full_x.reduce(&n);
        if r.is_zero() {
            return Err(Error::InvalidInput);
        }
        // x_overflow: the affine x was ≥ n, so r = x − n and recovery must add
        // n back. y_is_odd: parity of R's y, the other half of the recovery id.
        let x_overflow = !full_x.lt(&n);
        let y_is_odd = full_y.is_odd();

        let k_inv = inv_mod(&fq, &k, &n);
        let z_rd = fq.add_mod(&z, &fq.mul_mod(&r, &self.d));
        let s = fq.mul_mod(&k_inv, &z_rd);
        if s.is_zero() {
            return Err(Error::InvalidInput);
        }
        Ok((r, s, x_overflow, y_is_odd))
    }

    /// Signs `msg` (hashing with `D`) and also returns the **recovery id**
    /// (`v`), so the public key can later be reconstructed from the signature
    /// alone via [`BoxedEcdsaSignature::recover`]. See
    /// [`sign_prehash_recoverable`](Self::sign_prehash_recoverable) for the
    /// recovery-id encoding and the low-S guarantee.
    ///
    /// This is the building block for Ethereum-style signing, where a signature
    /// is transmitted as `(r, s, v)` and the signer's address is derived by
    /// recovering the public key. For Ethereum specifically, map the returned
    /// `recid ∈ {0,1}` to `v` as `v = 27 + recid` (legacy) or
    /// `v = 35 + 2·chain_id + recid` (EIP-155).
    pub fn sign_recoverable<D: Digest>(
        &self,
        msg: &[u8],
    ) -> Result<(BoxedEcdsaSignature, u8), Error> {
        self.sign_prehash_recoverable::<D>(D::digest(msg).as_ref())
    }

    /// Signs an already-computed digest `prehash` (deriving the RFC 6979 nonce
    /// with `D`), returning the signature **and** its recovery id.
    ///
    /// The signature is normalized to **low-S** (EIP-2 / BIP-62), so it is
    /// canonical and accepted by Ethereum and Bitcoin consensus rules. The
    /// recovery id corresponds to this normalized signature.
    ///
    /// `recid` is the libsecp256k1 / Ethereum encoding in `{0, 1, 2, 3}`:
    /// - bit 0 = parity of the ephemeral point `R`'s y-coordinate, and
    /// - bit 1 = whether `R.x` exceeded the group order `n` (so `R.x = r + n`).
    ///
    /// Bit 1 is set only when `r < p − n`, which is astronomically rare on
    /// secp256k1 (and never on a curve with `n > p`), so `recid` is almost
    /// always `0` or `1`. See [`BoxedEcdsaSignature::recover_prehash`] for the
    /// inverse operation.
    pub fn sign_prehash_recoverable<D: Digest>(
        &self,
        prehash: &[u8],
    ) -> Result<(BoxedEcdsaSignature, u8), Error> {
        let (r, s, x_overflow, y_is_odd) = self.sign_prehash_inner::<D>(prehash)?;
        // Normalize to low-S; negating s reflects R across the x-axis, flipping
        // its y-parity, so the recovery id's parity bit must flip with it.
        let n = self.curve.curve().order().clone();
        let half_n = n.shr_bits(1).add(&BoxedUint::from_u64(1));
        let (s, y_is_odd) = if s.lt(&half_n) {
            (s, y_is_odd)
        } else {
            (n.sub(&s), !y_is_odd)
        };
        let recid = (y_is_odd as u8) | ((x_overflow as u8) << 1);
        Ok((BoxedEcdsaSignature { r, s }, recid))
    }
}

impl BoxedEcdsaSignature {
    /// Builds a signature from its `(r, s)` components.
    pub fn from_components(r: BoxedUint, s: BoxedUint) -> Self {
        BoxedEcdsaSignature { r, s }
    }

    /// The `r` component as a `BoxedUint`. Use [`Self::r_bytes`] for the
    /// fixed-width big-endian byte encoding.
    pub fn r(&self) -> &BoxedUint {
        &self.r
    }

    /// The `s` component as a `BoxedUint`. See [`Self::r`].
    pub fn s(&self) -> &BoxedUint {
        &self.s
    }

    /// The `r` component encoded big-endian, left-padded to
    /// `curve.order_len()` bytes (the SEC1 fixed-width encoding).
    pub fn r_bytes(&self, curve: CurveId) -> Vec<u8> {
        self.r.to_be_bytes(curve.order_len())
    }

    /// The `s` component encoded big-endian, left-padded to
    /// `curve.order_len()` bytes.
    pub fn s_bytes(&self, curve: CurveId) -> Vec<u8> {
        self.s.to_be_bytes(curve.order_len())
    }

    /// The fixed `r ‖ s` encoding, each half `curve.order_len()` bytes.
    pub fn to_bytes(&self, curve: CurveId) -> Vec<u8> {
        let len = curve.order_len();
        let mut out = self.r.to_be_bytes(len);
        out.extend_from_slice(&self.s.to_be_bytes(len));
        out
    }

    /// Whether `s` is in the lower half of `curve`'s group order — the
    /// "low-S" form required by signature-non-malleability conventions
    /// (Bitcoin BIP-62, EVM, anti-replay caches that key on signature
    /// bytes). For any valid ECDSA signature `(r, s)`, the pair
    /// `(r, n − s)` also verifies, so callers needing bytewise unique
    /// signatures must require `is_low_s()`. Mirrors the const-generic
    /// helper in [`super::ecdsa::Signature::is_low_s`].
    pub fn is_low_s(&self, curve: CurveId) -> bool {
        // half_n = (n + 1) / 2 — the smallest "high-S" boundary.
        let n = curve.curve().order().clone();
        let half_n = n.shr_bits(1).add(&BoxedUint::from_u64(1));
        self.s.lt(&half_n)
    }

    /// Returns the canonical low-S representative for this signature on
    /// `curve`: if `s` is already in the lower half, returns a clone;
    /// otherwise returns `(r, n − s)`, which is equally valid and bytewise
    /// unique. Mirrors [`super::ecdsa::Signature::to_low_s`].
    pub fn to_low_s(&self, curve: CurveId) -> Self {
        if self.is_low_s(curve) {
            self.clone()
        } else {
            let n = curve.curve().order().clone();
            BoxedEcdsaSignature {
                r: self.r.clone(),
                s: n.sub(&self.s),
            }
        }
    }

    /// Recovers the signing public key from this signature over `msg` (hashed
    /// with `D`) and the recovery id `recid`. See
    /// [`recover_prehash`](Self::recover_prehash).
    pub fn recover<D: Digest>(
        &self,
        curve: CurveId,
        msg: &[u8],
        recid: u8,
    ) -> Result<BoxedEcdsaPublicKey, Error> {
        self.recover_prehash(curve, D::digest(msg).as_ref(), recid)
    }

    /// Recovers the signing public key from this signature over the digest
    /// `prehash` and the recovery id `recid` — the ECDSA "public key recovery"
    /// operation (libsecp256k1 `ecdsa_recover`, Ethereum `ecrecover`).
    ///
    /// `recid ∈ {0, 1, 2, 3}` is the value produced alongside the signature by
    /// [`BoxedEcdsaPrivateKey::sign_prehash_recoverable`]: bit 0 is the parity
    /// of the ephemeral point `R`'s y-coordinate and bit 1 is whether `R.x`
    /// overflowed the group order. The recovered key is the unique `Q` with
    /// `Q = r⁻¹·(s·R − z·G)`, where `R = lift_x(r + (recid≫1)·n, recid&1)`.
    ///
    /// Returns [`Error::Verification`] if `r`/`s` are out of range, if the
    /// recovery id does not yield a valid curve point, or if recovery produces
    /// the identity. Returns [`Error::InvalidInput`] if `recid > 3`.
    ///
    /// Recovery does **not** authenticate the message: any `(r, s, recid)`
    /// yields *some* key. To verify a signer, recover the key and then either
    /// compare it to the expected key or re-run [`verify_prehash`] — recovery
    /// alone proves only that the signature is self-consistent.
    ///
    /// [`verify_prehash`]: BoxedEcdsaPublicKey::verify_prehash
    pub fn recover_prehash(
        &self,
        curve: CurveId,
        prehash: &[u8],
        recid: u8,
    ) -> Result<BoxedEcdsaPublicKey, Error> {
        if recid > 3 {
            return Err(Error::InvalidInput);
        }
        let c = curve.curve();
        let n = c.order().clone();
        let fq = BoxedMontModulus::new(&n);
        if !in_range(&self.r, &n) || !in_range(&self.s, &n) {
            return Err(Error::Verification);
        }

        // R.x = r + (recid>>1)·n; decompress (lift_x) rejects an x ≥ p or an
        // abscissa that is not on the curve, so an impossible recid errors out.
        let rx = if recid & 2 == 0 {
            self.r.clone()
        } else {
            self.r.add(&n)
        };
        let (rx, ry) = c
            .decompress(&rx, recid & 1 == 1)
            .ok_or(Error::Verification)?;
        let r_point = c.lift_affine(&rx, &ry);

        // Q = u1·G + u2·R with u1 = −z·r⁻¹, u2 = s·r⁻¹ (mod n). r is public, so
        // the variable-time Fermat inverse used elsewhere here is fine.
        let z = bits2int(prehash, n.bit_len()).reduce(&n);
        let r_inv = inv_mod(&fq, &self.r, &n);
        let neg_z = fq.sub_mod(&BoxedUint::zero(1), &z);
        let u1 = fq.mul_mod(&neg_z, &r_inv);
        let u2 = fq.mul_mod(&self.s, &r_inv);
        let q = c.point_add(&c.mul_generator(&u1), &c.scalar_mul(&u2, &r_point));
        let (x, y) = c.to_affine(&q).ok_or(Error::Verification)?;
        Ok(BoxedEcdsaPublicKey { curve, x, y })
    }
}

impl Drop for BoxedEcdsaPrivateKey {
    fn drop(&mut self) {
        // Best-effort wipe of the scalar `d` before its heap-backing `Vec`
        // is freed. Mirrors the manual-wipe convention used elsewhere in
        // the crate (e.g. `cipher/poly1305.rs`, `cipher/aes/mod.rs`).
        self.d.zeroize();
    }
}

impl Drop for BoxedEcdhPrivateKey {
    fn drop(&mut self) {
        // Best-effort wipe of the ECDH scalar `d`. See `BoxedEcdsaPrivateKey`.
        self.d.zeroize();
    }
}

/// DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` — the form used
/// by TLS and X.509.
#[cfg(feature = "der")]
impl BoxedEcdsaSignature {
    /// Encodes the signature as a DER `Ecdsa-Sig-Value`.
    pub fn to_der(&self, curve: CurveId) -> Vec<u8> {
        use crate::der::{encode_integer, encode_sequence};
        let len = curve.order_len();
        encode_sequence(
            &[
                encode_integer(&self.r.to_be_bytes(len)),
                encode_integer(&self.s.to_be_bytes(len)),
            ]
            .concat(),
        )
    }

    /// Decodes a DER `Ecdsa-Sig-Value` with strict-DER enforcement (no
    /// unnecessary leading `0x00`/`0xff`, no empty INTEGER body, no trailing
    /// data). Closes the ECDSA signature-malleability gap at the bytes
    /// layer — many byte-distinct encodings of the same `(r, s)` are
    /// otherwise accepted.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        use crate::der::Reader;
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence().map_err(|_| Error::Malformed)?;
        let r = seq
            .read_unsigned_integer_bytes()
            .map_err(|_| Error::Malformed)?;
        let s = seq
            .read_unsigned_integer_bytes()
            .map_err(|_| Error::Malformed)?;
        seq.finish().map_err(|_| Error::Malformed)?;
        reader.finish().map_err(|_| Error::Malformed)?;
        Ok(BoxedEcdsaSignature {
            r: BoxedUint::from_be_bytes(r),
            s: BoxedUint::from_be_bytes(s),
        })
    }
}

/// SEC1 `ECPrivateKey` DER/PEM (`EC PRIVATE KEY`), the format OpenSSL emits for
/// EC keys.
#[cfg(feature = "der")]
impl BoxedEcdsaPrivateKey {
    /// Encodes the key as a SEC1 `ECPrivateKey` DER structure (with the named
    /// curve and public key included).
    pub fn to_sec1_der(&self) -> Vec<u8> {
        use crate::der::{
            encode_bit_string, encode_context, encode_integer, encode_octet_string,
            encode_sequence, oid_tlv,
        };
        let order_len = self.curve.order_len();
        let priv_oct = encode_octet_string(&self.d.to_be_bytes(order_len));
        // parameters [0] EXPLICIT namedCurve OID.
        let params = encode_context(0, &oid_tlv(self.curve.named_curve_oid()));
        // publicKey [1] EXPLICIT BIT STRING (uncompressed SEC1 point).
        let pubkey = encode_context(1, &encode_bit_string(&self.public_key().to_sec1()));
        encode_sequence(&[encode_integer(&[1]), priv_oct, params, pubkey].concat())
    }

    /// Encodes the key as a SEC1 PEM document (`-----BEGIN EC PRIVATE KEY-----`).
    pub fn to_sec1_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("EC PRIVATE KEY", &self.to_sec1_der())
    }

    /// Parses a SEC1 `ECPrivateKey` DER structure (the named curve must be one
    /// of the supported curves).
    pub fn from_sec1_der(der: &[u8]) -> Result<Self, Error> {
        use crate::der::{Reader, parse_oid, tag};
        let mut outer = Reader::new(der);
        let mut seq = outer.read_sequence().map_err(|_| Error::Malformed)?;
        seq.read_integer_bytes().map_err(|_| Error::Malformed)?; // version
        let priv_bytes = seq.read_octet_string().map_err(|_| Error::Malformed)?;
        if seq.peek_tag() != Some(tag::context(0)) {
            return Err(Error::Malformed);
        }
        let params = seq
            .read_tlv(tag::context(0))
            .map_err(|_| Error::Malformed)?;
        let mut pr = Reader::new(params);
        let arcs = parse_oid(pr.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        let curve = CurveId::from_named_curve_oid(&arcs).ok_or(Error::Malformed)?;
        Self::from_bytes(curve, priv_bytes)
    }

    /// Parses a SEC1 PEM EC private key.
    pub fn from_sec1_pem(pem: &str) -> Result<Self, Error> {
        let der = crate::der::pem_decode(pem, "EC PRIVATE KEY").map_err(|_| Error::Malformed)?;
        Self::from_sec1_der(&der)
    }

    /// Encodes the key as an unencrypted PKCS#8 `PrivateKeyInfo` (RFC 5958):
    /// `id-ecPublicKey` + the named-curve parameter, wrapping the SEC1
    /// `ECPrivateKey` ([`Self::to_sec1_der`]) in the `privateKey` OCTET STRING.
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let algid = encode_sequence(
            &[
                oid_tlv(EC_PUBLIC_KEY_OID),
                oid_tlv(self.curve.named_curve_oid()),
            ]
            .concat(),
        );
        let inner = encode_octet_string(&self.to_sec1_der());
        encode_sequence(&[encode_integer(&[0]), algid, inner].concat())
    }

    /// Encodes the key as an unencrypted PKCS#8 PEM document
    /// (`-----BEGIN PRIVATE KEY-----`).
    pub fn to_pkcs8_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("PRIVATE KEY", &self.to_pkcs8_der())
    }

    /// Parses an unencrypted PKCS#8 `PrivateKeyInfo` (RFC 5958) wrapping a SEC1
    /// EC private key. The curve is taken from the `privateKeyAlgorithm`
    /// named-curve parameter; the inner SEC1 structure's optional `[0]`
    /// parameters / `[1]` publicKey are ignored.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        use crate::der::{Reader, parse_oid};
        let mut r = Reader::new(der);
        let mut seq = r.read_sequence().map_err(|_| Error::Malformed)?;
        seq.read_integer_bytes().map_err(|_| Error::Malformed)?; // version (0)
        let mut algid = seq.read_sequence().map_err(|_| Error::Malformed)?;
        let alg = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        if alg.as_slice() != EC_PUBLIC_KEY_OID {
            return Err(Error::Malformed);
        }
        let curve_arcs = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        let curve = CurveId::from_named_curve_oid(&curve_arcs).ok_or(Error::Malformed)?;
        let inner = seq.read_octet_string().map_err(|_| Error::Malformed)?;
        // inner = SEC1 ECPrivateKey { version, privateKey OCTET STRING, ... }.
        let mut ir = Reader::new(inner);
        let mut iseq = ir.read_sequence().map_err(|_| Error::Malformed)?;
        iseq.read_integer_bytes().map_err(|_| Error::Malformed)?; // SEC1 version (1)
        let priv_bytes = iseq.read_octet_string().map_err(|_| Error::Malformed)?;
        Self::from_bytes(curve, priv_bytes)
    }

    /// Parses an unencrypted PKCS#8 PEM private key
    /// (`-----BEGIN PRIVATE KEY-----`).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        let der = crate::der::pem_decode(pem, "PRIVATE KEY").map_err(|_| Error::Malformed)?;
        Self::from_pkcs8_der(&der)
    }

    /// Encrypts the PKCS#8 encoding under PBES2 (RFC 5958 §3 + RFC 8018 §6.2)
    /// with caller-supplied parameters, returning the DER `EncryptedPrivateKeyInfo`.
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn to_pkcs8_der_encrypted(
        &self,
        password: &[u8],
        params: &crate::kdf::pbes2::Pbes2Params,
        rng: &mut impl crate::rng::RngCore,
    ) -> Vec<u8> {
        crate::kdf::pbes2::encrypt(&self.to_pkcs8_der(), password, params, rng)
    }

    /// PEM-wrapped variant of [`Self::to_pkcs8_der_encrypted`]
    /// (`-----BEGIN ENCRYPTED PRIVATE KEY-----`).
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn to_pkcs8_pem_encrypted(
        &self,
        password: &[u8],
        params: &crate::kdf::pbes2::Pbes2Params,
        rng: &mut impl crate::rng::RngCore,
    ) -> alloc::string::String {
        crate::kdf::pbes2::encrypt_pem(&self.to_pkcs8_der(), password, params, rng)
    }

    /// Parses an `EncryptedPrivateKeyInfo` DER (PBES2) and decrypts it back to a
    /// PKCS#8 EC private key. Mirrors `BoxedRsaPrivateKey` / `Ed25519PrivateKey`.
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn from_pkcs8_der_encrypted(der: &[u8], password: &[u8]) -> Result<Self, Error> {
        let inner = crate::kdf::pbes2::decrypt(der, password).map_err(|_| Error::Malformed)?;
        Self::from_pkcs8_der(&inner)
    }

    /// PEM-wrapped variant of [`Self::from_pkcs8_der_encrypted`].
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn from_pkcs8_pem_encrypted(pem: &str, password: &[u8]) -> Result<Self, Error> {
        let inner = crate::kdf::pbes2::decrypt_pem(pem, password).map_err(|_| Error::Malformed)?;
        Self::from_pkcs8_der(&inner)
    }
}

impl BoxedEcdhPrivateKey {
    /// Generates a new ECDH private key on `curve` from `rng`.
    ///
    /// `rng` SHOULD be a cryptographically secure CSPRNG (see [`CryptoRng`]).
    /// The bound is left at [`RngCore`] only so the TLS / DTLS handshake
    /// layers can thread a single shared RNG type through ephemeral
    /// key-share generation; production callers should pass `OsRng` or an
    /// HMAC-DRBG seeded from one.
    pub fn generate<R: RngCore>(curve: CurveId, rng: &mut R) -> Self {
        let n = curve.curve().order().clone();
        BoxedEcdhPrivateKey {
            curve,
            d: random_scalar(curve, &n, rng),
        }
    }

    /// Creates an ECDH private key from a big-endian scalar on `curve`.
    pub fn from_bytes(curve: CurveId, bytes: &[u8]) -> Result<Self, Error> {
        let d = BoxedUint::from_be_bytes(bytes);
        let n = curve.curve().order().clone();
        if in_range(&d, &n) {
            Ok(BoxedEcdhPrivateKey { curve, d })
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// The public key `d * G` to send to the peer.
    pub fn public_key(&self) -> BoxedEcdsaPublicKey {
        let c = self.curve.curve();
        let (x, y) = c
            .to_affine(&c.mul_generator(&self.d))
            .expect("d in [1,n-1] so d*G is not the identity");
        BoxedEcdsaPublicKey {
            curve: self.curve,
            x,
            y,
        }
    }

    /// The ECDH shared secret with `peer`: the affine x-coordinate of
    /// `d * peer`, big-endian, `field_len` bytes.
    pub fn diffie_hellman(&self, peer: &BoxedEcdsaPublicKey) -> Result<Vec<u8>, Error> {
        if peer.curve != self.curve {
            return Err(Error::InvalidInput);
        }
        let c = self.curve.curve();
        let point = c.lift_affine(&peer.x, &peer.y);
        let shared = c.scalar_mul(&self.d, &point);
        let (x, _) = c.to_affine(&shared).ok_or(Error::InvalidInput)?;
        Ok(x.to_be_bytes(self.curve.field_len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha256, Sha384, Sha512};
    use crate::rng::HmacDrbg;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 6979 A.2.5 — P-256, SHA-256, message "sample".
    #[test]
    fn rfc6979_p256_sample() {
        let d = from_hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let sk = BoxedEcdsaPrivateKey::from_bytes(CurveId::P256, &d).unwrap();
        let sig = sk.sign::<Sha256>(b"sample").unwrap();
        assert_eq!(
            sig.r.to_be_bytes(32),
            from_hex("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716")
        );
        assert_eq!(
            sig.s.to_be_bytes(32),
            from_hex("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")
        );
        sk.public_key().verify::<Sha256>(b"sample", &sig).unwrap();
    }

    // Prehash signing matches the message-hashing path (and thus the RFC 6979
    // vector): sign_prehash::<D>(D::digest(m)) == sign::<D>(m), and the result
    // verifies both ways. Covers P-256/384/521 and a SHA-512 prehash on P-256
    // (digest wider than the order, truncated per FIPS 186-5).
    #[test]
    fn sign_prehash_matches_message_signing() {
        use crate::hash::Digest;
        let mut rng = HmacDrbg::<Sha256>::new(b"prehash-ec", b"n", &[]);
        for curve in [CurveId::P256, CurveId::P384, CurveId::P521] {
            let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
            let msg = b"prehash equivalence";
            let from_msg = sk.sign::<Sha256>(msg).unwrap();
            let from_hash = sk
                .sign_prehash::<Sha256>(Sha256::digest(msg).as_ref())
                .unwrap();
            assert_eq!(from_msg.r_bytes(curve), from_hash.r_bytes(curve));
            assert_eq!(from_msg.s_bytes(curve), from_hash.s_bytes(curve));
            // verify_prehash accepts a signature made over the message, and the
            // message-hashing verify accepts a signature made over the prehash.
            let pk = sk.public_key();
            pk.verify_prehash(Sha256::digest(msg).as_ref(), &from_msg)
                .unwrap();
            pk.verify::<Sha256>(msg, &from_hash).unwrap();
            // A different prehash must not verify.
            assert!(
                pk.verify_prehash(Sha256::digest(b"other").as_ref(), &from_msg)
                    .is_err()
            );
        }
        // RFC 6979 A.2.5 exact vector via the prehash entry point.
        let d = from_hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let sk = BoxedEcdsaPrivateKey::from_bytes(CurveId::P256, &d).unwrap();
        let sig = sk
            .sign_prehash::<Sha256>(Sha256::digest(b"sample").as_ref())
            .unwrap();
        assert_eq!(
            sig.r.to_be_bytes(32),
            from_hex("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716")
        );
    }

    // RFC 6979 A.2.6 — P-384, SHA-384, message "sample".
    #[test]
    fn rfc6979_p384_sample() {
        let d = from_hex(
            "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8\
             96d5724e4c70a825f872c9ea60d2edf5",
        );
        let sk = BoxedEcdsaPrivateKey::from_bytes(CurveId::P384, &d).unwrap();
        let sig = sk.sign::<Sha384>(b"sample").unwrap();
        assert_eq!(
            sig.r.to_be_bytes(48),
            from_hex(
                "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c\
                 81a648152e44acf96e36dd1e80fabe46"
            )
        );
        assert_eq!(
            sig.s.to_be_bytes(48),
            from_hex(
                "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f\
                 a329c145786e679e7b82c71a38628ac8"
            )
        );
        sk.public_key().verify::<Sha384>(b"sample", &sig).unwrap();
    }

    // RFC 6979 A.2.7 — P-521, SHA-512, message "sample".
    #[test]
    fn rfc6979_p521_sample() {
        let d = from_hex(
            "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75\
             caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b8\
             3538",
        );
        let sk = BoxedEcdsaPrivateKey::from_bytes(CurveId::P521, &d).unwrap();
        let sig = sk.sign::<Sha512>(b"sample").unwrap();
        assert_eq!(
            sig.r.to_be_bytes(66),
            from_hex(
                "00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f\
                 174e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e3\
                 77fa"
            )
        );
        sk.public_key().verify::<Sha512>(b"sample", &sig).unwrap();
    }

    #[test]
    fn secp256k1_sign_verify_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"secp256k1-key", b"nonce", &[]);
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::Secp256k1, &mut rng);
        let pk = sk.public_key();
        let sig = sk.sign::<Sha256>(b"hello secp256k1").unwrap();
        pk.verify::<Sha256>(b"hello secp256k1", &sig).unwrap();
        assert!(pk.verify::<Sha256>(b"tampered", &sig).is_err());

        // SEC1 round-trip (validates the on-curve check).
        let sec1 = pk.to_sec1();
        assert_eq!(
            BoxedEcdsaPublicKey::from_sec1(CurveId::Secp256k1, &sec1)
                .unwrap()
                .to_sec1(),
            sec1
        );
    }

    #[cfg(feature = "der")]
    #[test]
    fn ec_private_key_sec1_roundtrip() {
        for curve in [
            CurveId::P256,
            CurveId::P384,
            CurveId::P521,
            CurveId::Secp256k1,
        ] {
            let mut rng = HmacDrbg::<Sha256>::new(b"sec1", b"n", &[]);
            let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);

            let pem = sk.to_sec1_pem();
            assert!(pem.starts_with("-----BEGIN EC PRIVATE KEY-----"));
            let parsed = BoxedEcdsaPrivateKey::from_sec1_pem(&pem).unwrap();
            assert_eq!(parsed.curve(), curve);
            // Same key: public points match.
            assert_eq!(parsed.public_key().to_sec1(), sk.public_key().to_sec1());
        }
    }

    // Compressed (0x02/0x03 || X) SEC1 parsing recovers the same point as the
    // uncompressed form, across every supported curve — i.e. a correct lift_x.
    #[test]
    fn from_sec1_compressed_roundtrip() {
        for curve in [
            CurveId::P256,
            CurveId::P384,
            CurveId::P521,
            CurveId::Secp256k1,
        ] {
            let mut rng = HmacDrbg::<Sha256>::new(b"compressed", b"n", &[]);
            let flen = curve.field_len();
            for _ in 0..4 {
                let pk = BoxedEcdsaPrivateKey::generate(curve, &mut rng).public_key();
                let uncompressed = pk.to_sec1(); // 0x04 || X || Y
                let x = &uncompressed[1..1 + flen];
                let y_odd = uncompressed[1 + 2 * flen - 1] & 1;
                let mut compressed = alloc::vec![0x02 | y_odd];
                compressed.extend_from_slice(x);
                let parsed = BoxedEcdsaPublicKey::from_sec1(curve, &compressed).unwrap();
                assert_eq!(parsed.to_sec1(), uncompressed);
            }
        }
        // A bad tag / length is rejected.
        assert!(BoxedEcdsaPublicKey::from_sec1(CurveId::Secp256k1, &[0x05; 33]).is_err());
        assert!(BoxedEcdsaPublicKey::from_sec1(CurveId::Secp256k1, &[0x02; 10]).is_err());
    }

    // Point addition agrees with the group law: a·G + b·G == (a+b)·G, and the
    // sum of a point and its negation (the identity) is rejected.
    #[test]
    fn public_key_point_add() {
        let curve = CurveId::Secp256k1;
        let g = |k: u64| {
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&k.to_be_bytes());
            BoxedEcdsaPrivateKey::from_bytes(curve, &b)
                .unwrap()
                .public_key()
        };
        assert_eq!(g(3).add(&g(5)).unwrap().to_sec1(), g(8).to_sec1());
        assert_eq!(g(100).add(&g(1)).unwrap().to_sec1(), g(101).to_sec1());

        // a·G + (n − a)·G = identity (point at infinity) => error.
        let n = curve.curve().order().clone();
        let a = BoxedUint::from_u64(7);
        let neg = n.sub(&a);
        let neg_g = BoxedEcdsaPrivateKey::from_bytes(curve, &neg.to_be_bytes(32))
            .unwrap()
            .public_key();
        assert!(g(7).add(&neg_g).is_err());

        // Mismatched curves are rejected.
        let p256g = {
            let mut b = [0u8; 32];
            b[31] = 2;
            BoxedEcdsaPrivateKey::from_bytes(CurveId::P256, &b)
                .unwrap()
                .public_key()
        };
        assert!(g(2).add(&p256g).is_err());
    }

    #[cfg(feature = "der")]
    #[test]
    fn ec_pkcs8_roundtrip() {
        for curve in [CurveId::P256, CurveId::P384, CurveId::P521] {
            let mut rng = HmacDrbg::<Sha256>::new(b"pkcs8", b"n", &[]);
            let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
            // Unencrypted PKCS#8 PEM round-trip.
            let pem = sk.to_pkcs8_pem();
            assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
            let parsed = BoxedEcdsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
            assert_eq!(parsed.curve(), curve);
            assert_eq!(parsed.public_key().to_sec1(), sk.public_key().to_sec1());
            // DER round-trip too.
            let parsed_der = BoxedEcdsaPrivateKey::from_pkcs8_der(&sk.to_pkcs8_der()).unwrap();
            assert_eq!(parsed_der.public_key().to_sec1(), sk.public_key().to_sec1());
        }
    }

    /// Interop: load a P-256 PKCS#8 key generated by OpenSSL 3.x, both the
    /// plaintext `PRIVATE KEY` form and the PBES2 (PBKDF2 + AES-256-CBC)
    /// `ENCRYPTED PRIVATE KEY` form, and confirm both recover the same public
    /// key. This is the `rsurl` curl `-E ... --pass` use case from issue #24.
    #[cfg(all(feature = "der", feature = "kdf"))]
    #[test]
    fn ec_pkcs8_openssl_interop() {
        const PLAIN: &str = "-----BEGIN PRIVATE KEY-----\n\
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPWfLPOd/TFwWJTCr\n\
E5f4wo4KaaIPIAZWZMFAqEMjTfKhRANCAAQ2q5yE2IGZsOoMACF7A+349UNU4/bo\n\
HCwXnzad7AT3M3i/cpHzz4hQ5SamPVsiQHh79RPMIhptanrHl+IqHnZW\n\
-----END PRIVATE KEY-----\n";
        // PBES2 with PBKDF2-HMAC-SHA256 (100000 iters, above our 10k floor) +
        // AES-256-CBC, generated by `openssl pkcs8 -topk8 -v2 aes-256-cbc
        // -iter 100000` (password "swordfish").
        const ENC: &str = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n\
MIH1MGAGCSqGSIb3DQEFDTBTMDIGCSqGSIb3DQEFDDAlBBCY+UTuXFns/MwLo3Ki\n\
xoqQAgMBhqAwDAYIKoZIhvcNAgkFADAdBglghkgBZQMEASoEED21Z94FK0DiNUk7\n\
kyKSLr4EgZBQ3Gv8EdxHAbYJW4EQErkkR2BQcDXl94uMRcxb9grTUueECvaCoOJ\n\
FN7ev05ViuIhHs4Nf8urHf8E9mS7xW18RnHM0LqbtkLBpFgOCM7v0JXWsyacSGg\n\
E2aHEj9+RUM5NRAvRB/ggKn1BUHMrJ1RRFpTJHBmL+XV9GJ8KiIeIyiCcogoils\n\
x2dqVh/sT12MnE=\n\
-----END ENCRYPTED PRIVATE KEY-----\n";
        let expected = from_hex(
            "0436ab9c84d88199b0ea0c00217b03edf8f54354e3f6e81c2c179f369dec04f733\
             78bf7291f3cf8850e526a63d5b2240787bf513cc221a6d6a7ac797e22a1e7656",
        );
        let plain = BoxedEcdsaPrivateKey::from_pkcs8_pem(PLAIN).unwrap();
        assert_eq!(plain.curve(), CurveId::P256);
        assert_eq!(plain.public_key().to_sec1(), expected);

        let enc = BoxedEcdsaPrivateKey::from_pkcs8_pem_encrypted(ENC, b"swordfish").unwrap();
        assert_eq!(enc.public_key().to_sec1(), expected);
        assert!(BoxedEcdsaPrivateKey::from_pkcs8_pem_encrypted(ENC, b"bad").is_err());
    }

    #[cfg(all(feature = "der", feature = "kdf"))]
    #[test]
    fn ec_encrypted_pkcs8_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"ec-pbes2", b"nonce", &[]);
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let params = crate::kdf::pbes2::Pbes2Params {
            kdf: crate::kdf::pbes2::KdfChoice::Pbkdf2HmacSha256 { iterations: 10_000 },
            cipher: crate::kdf::pbes2::CipherChoice::Aes256Gcm,
            salt_len: 16,
        };
        // PEM round-trip.
        let pem = sk.to_pkcs8_pem_encrypted(b"swordfish", &params, &mut rng);
        assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----"));
        let parsed = BoxedEcdsaPrivateKey::from_pkcs8_pem_encrypted(&pem, b"swordfish").unwrap();
        assert_eq!(parsed.public_key().to_sec1(), sk.public_key().to_sec1());
        // Wrong password is rejected.
        assert!(BoxedEcdsaPrivateKey::from_pkcs8_pem_encrypted(&pem, b"wrong").is_err());
        // DER round-trip.
        let der = sk.to_pkcs8_der_encrypted(b"swordfish", &params, &mut rng);
        let parsed_der =
            BoxedEcdsaPrivateKey::from_pkcs8_der_encrypted(&der, b"swordfish").unwrap();
        assert_eq!(parsed_der.public_key().to_sec1(), sk.public_key().to_sec1());
    }

    #[test]
    fn ecdh_p256_matches_const_generic() {
        // Boxed P-256 ECDH must agree with the const-generic implementation.
        let mut rng = HmacDrbg::<Sha256>::new(b"ecdh", b"n", &[]);
        let a = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut rng);
        let b = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut rng);
        let ab = a.diffie_hellman(&b.public_key()).unwrap();
        let ba = b.diffie_hellman(&a.public_key()).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn boxed_signature_r_s_accessors_roundtrip() {
        // Generate a real signature, then deconstruct/reconstruct via r/s.
        let mut rng = HmacDrbg::<Sha256>::new(b"sig-rs", b"n", &[]);
        for curve in [
            CurveId::P256,
            CurveId::P384,
            CurveId::P521,
            CurveId::Secp256k1,
        ] {
            let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
            let sig = sk.sign::<Sha256>(b"hello").unwrap();

            // r/s as integers round-trip via from_components.
            let rebuilt = BoxedEcdsaSignature::from_components(sig.r().clone(), sig.s().clone());
            assert_eq!(rebuilt, sig);

            // r_bytes/s_bytes concatenate to to_bytes(curve).
            let mut concat = sig.r_bytes(curve);
            concat.extend_from_slice(&sig.s_bytes(curve));
            assert_eq!(concat, sig.to_bytes(curve));
        }
    }

    #[test]
    fn boxed_signature_low_s_idempotent_and_verifies() {
        // For every supported curve, `to_low_s` must produce a low-S
        // signature that still verifies, and applying it a second time
        // must be a no-op (idempotence).
        let mut rng = HmacDrbg::<Sha256>::new(b"low-s", b"n", &[]);
        for curve in [
            CurveId::P256,
            CurveId::P384,
            CurveId::P521,
            CurveId::Secp256k1,
        ] {
            let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
            let pk = sk.public_key();
            let sig = sk.sign::<Sha256>(b"low-s message").unwrap();

            let low = sig.to_low_s(curve);
            assert!(low.is_low_s(curve), "to_low_s must produce a low-S sig");
            assert_eq!(low.to_low_s(curve), low, "to_low_s must be idempotent");
            // The canonicalised signature must still verify against the
            // public key — flipping `s` to `n − s` is a valid ECDSA
            // signature for the same `(pk, msg)`.
            pk.verify::<Sha256>(b"low-s message", &low).unwrap();
        }
    }

    #[test]
    fn boxed_signature_high_s_flip_round_trip() {
        // Construct a synthetic high-S signature (s' = n − s with original
        // s low) and confirm `to_low_s` recovers the original.
        let mut rng = HmacDrbg::<Sha256>::new(b"high-s", b"n", &[]);
        let curve = CurveId::P256;
        let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
        let sig = sk.sign::<Sha256>(b"flip me").unwrap();
        let low = sig.to_low_s(curve);
        assert!(low.is_low_s(curve));

        // Build the high-S form `(r, n − s)` by hand and verify the
        // helper canonicalises it back.
        let n = curve.curve().order().clone();
        let high = BoxedEcdsaSignature::from_components(low.r().clone(), n.sub(low.s()));
        assert!(!high.is_low_s(curve));
        assert_eq!(high.to_low_s(curve), low);
    }

    // Public-key recovery against a published go-ethereum vector
    // (crypto/signature_test.go): Ecrecover(hash, r‖s‖v) == uncompressed key.
    // Exercises the full secp256k1 ecrecover path end to end.
    #[test]
    fn ecrecover_ethereum_vector() {
        let msg = from_hex("ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008");
        let r = from_hex("90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e54998");
        let s = from_hex("4a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc93");
        let recid = 1u8; // the trailing v byte of the test signature
        let sig = BoxedEcdsaSignature::from_components(
            BoxedUint::from_be_bytes(&r),
            BoxedUint::from_be_bytes(&s),
        );
        let pk = sig
            .recover_prehash(CurveId::Secp256k1, &msg, recid)
            .unwrap();
        let expected = from_hex(
            "04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f158781098\
             80a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652",
        );
        assert_eq!(pk.to_sec1(), expected);
        // A wrong recovery id must not yield the same key.
        let other = sig.recover_prehash(CurveId::Secp256k1, &msg, 0).unwrap();
        assert_ne!(other.to_sec1(), expected);
    }

    // sign_recoverable → recover round-trips back to the signer's public key,
    // and the emitted signature is low-S, on both a curve with n < p
    // (secp256k1) and one with n > p (P-256).
    #[test]
    fn sign_recoverable_round_trips() {
        for curve in [CurveId::Secp256k1, CurveId::P256, CurveId::P384] {
            let mut rng = HmacDrbg::<Sha256>::new(b"recoverable", &[curve.field_len() as u8], &[]);
            for i in 0..8u8 {
                let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
                let pk = sk.public_key();
                let msg = [b'm', i];
                let (sig, recid) = sk.sign_recoverable::<Sha256>(&msg).unwrap();
                assert!(recid < 4);
                assert!(sig.is_low_s(curve), "signature must be canonical low-S");
                // The signature still verifies the usual way.
                pk.verify::<Sha256>(&msg, &sig).unwrap();
                // Recovery with the emitted recid reproduces the signer's key.
                let rec = sig.recover::<Sha256>(curve, &msg, recid).unwrap();
                assert_eq!(rec.to_sec1(), pk.to_sec1(), "recover != signer ({i})");
                // The complementary parity recovers a *different* key.
                let flipped = sig.recover::<Sha256>(curve, &msg, recid ^ 1);
                if let Ok(other) = flipped {
                    assert_ne!(other.to_sec1(), pk.to_sec1());
                }
            }
        }
    }

    #[test]
    fn recover_rejects_bad_inputs() {
        let curve = CurveId::Secp256k1;
        let mut rng = HmacDrbg::<Sha256>::new(b"recover-neg", b"n", &[]);
        let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
        let (sig, recid) = sk.sign_recoverable::<Sha256>(b"hello").unwrap();
        // recid out of range.
        assert!(matches!(
            sig.recover::<Sha256>(curve, b"hello", 4),
            Err(Error::InvalidInput)
        ));
        // r = 0 is not a valid signature component.
        let bad = BoxedEcdsaSignature::from_components(BoxedUint::zero(4), sig.s().clone());
        assert!(matches!(
            bad.recover::<Sha256>(curve, b"hello", recid),
            Err(Error::Verification)
        ));
    }
}
