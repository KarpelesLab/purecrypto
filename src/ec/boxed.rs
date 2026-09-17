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
#[cfg(feature = "der")]
const EC_PUBLIC_KEY_OID: &[u64] = &[1, 2, 840, 10045, 2, 1];
use crate::bignum::{BoxedMontModulus, BoxedUint};
use crate::ct::ConstantTimeEq;
use crate::hash::{Digest, Hmac};
use crate::rng::{CryptoRng, RngCore};
use crate::zeroize::Zeroize;
use alloc::vec;
use alloc::vec::Vec;

/// Width to encode `v` at when the caller asked for `len` bytes: `len`, unless
/// `v` genuinely needs more. `BoxedUint::to_be_bytes` panics rather than
/// truncating, and a signature component can be wider than the curve's order
/// when the two were never paired (a signature parsed for one curve and
/// re-encoded for a narrower one). Widening keeps those re-encoders total; the
/// verifier's range check is what rejects the value.
pub(crate) fn enc_len(v: &BoxedUint, len: usize) -> usize {
    len.max(v.bit_len().div_ceil(8))
}

/// Magnitude width of a strict-DER unsigned INTEGER body: the body minus the
/// optional `0x00` sign octet (`[0x00]`, the canonical zero, has width 0).
#[cfg(feature = "der")]
pub(super) fn der_magnitude_len(body: &[u8]) -> usize {
    match body {
        [0x00, rest @ ..] => rest.len(),
        _ => body.len(),
    }
}

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

/// `1 <= v < n`, evaluated without short-circuiting (`v` may be a secret
/// scalar — private-key import, nonce rejection sampling — so the zero test
/// and the comparison must not leak which limb first differed).
fn in_range(v: &BoxedUint, n: &BoxedUint) -> bool {
    (!v.ct_is_zero() & v.reduce(n).ct_eq(v)).into()
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
        // The raw bytes are the secret scalar; don't leave them on the heap.
        buf.zeroize();
        // Accept iff 1 ≤ candidate < n; non-short-circuiting `&` so the
        // candidate's low limbs don't shape the timing of a rejection.
        if bool::from(!candidate.ct_is_zero()) & candidate.lt(n) {
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
    let mut d_oct = d.to_be_bytes(order_len);
    let mut h_oct = bits2int(hash, qlen).reduce(n).to_be_bytes(order_len);

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

    let candidate = loop {
        let mut t = Vec::with_capacity(order_len);
        while t.len() < order_len {
            v = Hmac::<D>::mac(k.as_ref(), v.as_ref());
            t.extend_from_slice(v.as_ref());
        }
        let candidate = bits2int(&t[..order_len], qlen);
        t.zeroize();
        if in_range(&candidate, n) {
            break candidate;
        }
        let mut mac = Hmac::<D>::new(k.as_ref());
        mac.update(v.as_ref());
        mac.update(&[0x00]);
        k = mac.finalize();
        v = Hmac::<D>::mac(k.as_ref(), v.as_ref());
    };

    // `d_oct` is a verbatim copy of the long-term private scalar, and the
    // HMAC-DRBG state (`k`, `v`) reproduces the nonce. Wipe all of it before
    // the buffers are returned to the allocator.
    d_oct.zeroize();
    h_oct.zeroize();
    k.as_mut().zeroize();
    v.as_mut().zeroize();
    candidate
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
        // Both operands are validated public keys, so their affine coordinates
        // are guaranteed on-curve (enforced at construction in `from_sec1`). A
        // debug-only check documents that invariant before lifting; release
        // behavior is unchanged.
        debug_assert!(
            c.is_on_curve(&self.x, &self.y),
            "self is not on the curve before point lift"
        );
        debug_assert!(
            c.is_on_curve(&other.x, &other.y),
            "other is not on the curve before point lift"
        );
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
        let mut k = generate_k::<D>(&self.d, prehash, &n, order_len, n.bit_len());

        let affine = c.to_affine(&c.mul_generator(&k));
        let Some((full_x, full_y)) = affine else {
            k.zeroize();
            return Err(Error::InvalidInput);
        };
        let r = full_x.reduce(&n);
        if r.is_zero() {
            k.zeroize();
            return Err(Error::InvalidInput);
        }
        // x_overflow: the affine x was ≥ n, so r = x − n and recovery must add
        // n back. y_is_odd: parity of R's y, the other half of the recovery id.
        let x_overflow = !full_x.lt(&n);
        let y_is_odd = full_y.is_odd();

        let mut k_inv = inv_mod(&fq, &k, &n);
        let mut z_rd = fq.add_mod(&z, &fq.mul_mod(&r, &self.d));
        let s = fq.mul_mod(&k_inv, &z_rd);
        // Wipe the per-signature secrets: `k` alone recovers the long-term
        // key as `d = (s·k − z)·r⁻¹ mod n`. `BoxedUint::zeroize` uses the
        // crate's volatile stores.
        k.zeroize();
        k_inv.zeroize();
        z_rd.zeroize();
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

    /// The widest group order this crate supports, in bytes (P-521, 521 bits
    /// → 66 bytes). Signature components parsed by
    /// [`from_der`][Self::from_der] are bounded by this.
    #[cfg_attr(not(feature = "der"), doc = "", doc = "[Self::from_der]: crate")]
    pub const MAX_ORDER_LEN: usize = 66;

    /// The `r` component encoded big-endian, left-padded to
    /// `curve.order_len()` bytes (the SEC1 fixed-width encoding).
    ///
    /// A component too wide for `curve` (only reachable by pairing a
    /// signature with a curve other than the one it was parsed/created for)
    /// widens the output rather than panicking.
    pub fn r_bytes(&self, curve: CurveId) -> Vec<u8> {
        self.r.to_be_bytes(enc_len(&self.r, curve.order_len()))
    }

    /// The `s` component encoded big-endian, left-padded to
    /// `curve.order_len()` bytes. See [`Self::r_bytes`].
    pub fn s_bytes(&self, curve: CurveId) -> Vec<u8> {
        self.s.to_be_bytes(enc_len(&self.s, curve.order_len()))
    }

    /// The fixed `r ‖ s` encoding, each half `curve.order_len()` bytes.
    /// See [`Self::r_bytes`] for the over-wide-component behaviour.
    pub fn to_bytes(&self, curve: CurveId) -> Vec<u8> {
        let len = curve.order_len();
        let mut out = self.r.to_be_bytes(enc_len(&self.r, len));
        out.extend_from_slice(&self.s.to_be_bytes(enc_len(&self.s, len)));
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
                encode_integer(&self.r.to_be_bytes(enc_len(&self.r, len))),
                encode_integer(&self.s.to_be_bytes(enc_len(&self.s, len))),
            ]
            .concat(),
        )
    }

    /// Decodes a DER `Ecdsa-Sig-Value` with strict-DER enforcement (no
    /// unnecessary leading `0x00`/`0xff`, no empty INTEGER body, no trailing
    /// data). Closes the ECDSA signature-malleability gap at the bytes
    /// layer — many byte-distinct encodings of the same `(r, s)` are
    /// otherwise accepted.
    ///
    /// `r` and `s` are additionally bounded to
    /// [`MAX_ORDER_LEN`](Self::MAX_ORDER_LEN) bytes of magnitude — the widest
    /// group order this crate supports (P-521). The curve is not known at this
    /// point, so the final range check is the verifier's `in_range`; the width
    /// bound is what keeps a hostile signature from reaching the fixed-width
    /// re-encoders. See [`Self::from_der_for_curve`] for the exact check.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        Self::from_der_bounded(der, Self::MAX_ORDER_LEN)
    }

    /// Like [`from_der`](Self::from_der), but bounds the magnitude of `r` and
    /// `s` by `curve`'s group-order width, so every fixed-width re-encoding
    /// (`r_bytes`, `s_bytes`, `to_bytes`, `to_der`) for that curve is exact.
    /// Prefer this when the curve is known at parse time.
    pub fn from_der_for_curve(der: &[u8], curve: CurveId) -> Result<Self, Error> {
        Self::from_der_bounded(der, curve.order_len())
    }

    fn from_der_bounded(der: &[u8], max_len: usize) -> Result<Self, Error> {
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
        // Reject components wider than the target order. Without this,
        // `to_bytes`/`to_der`/`r_bytes` would panic in
        // `BoxedUint::to_be_bytes` on an attacker-supplied
        // `SEQUENCE { INTEGER(40 random bytes), INTEGER(1) }`.
        if der_magnitude_len(r) > max_len || der_magnitude_len(s) > max_len {
            return Err(Error::Malformed);
        }
        Ok(BoxedEcdsaSignature {
            r: BoxedUint::from_be_bytes(r),
            s: BoxedUint::from_be_bytes(s),
        })
    }
}

/// Checks the OPTIONAL `[1] EXPLICIT BIT STRING` publicKey of a SEC1
/// `ECPrivateKey` against the scalar that was just parsed, consuming it when
/// present.
///
/// A private key whose embedded public key belongs to a *different* scalar is
/// not a key at all: whichever half the application reads, the other half is
/// wrong, and a signature made with `d` would be checked against a public key
/// nobody holds. Reject it at parse time instead of letting the mismatch
/// surface as an unverifiable signature later.
#[cfg(feature = "der")]
fn check_embedded_public_key(
    seq: &mut crate::der::Reader<'_>,
    key: &BoxedEcdsaPrivateKey,
) -> Result<(), Error> {
    use crate::der::{Reader, tag};
    if seq.peek_tag() != Some(tag::context(1)) {
        // Absent: the field is OPTIONAL, so this is a perfectly good key.
        return Ok(());
    }
    let field = seq
        .read_tlv(tag::context(1))
        .map_err(|_| Error::Malformed)?;
    let mut pr = Reader::new(field);
    let bits = pr.read_bit_string().map_err(|_| Error::Malformed)?;
    pr.finish().map_err(|_| Error::Malformed)?;
    let embedded = BoxedEcdsaPublicKey::from_sec1(key.curve, bits)?;
    // Compare the canonical uncompressed encodings, so a compressed embedded
    // key matches the derived one.
    if embedded.to_sec1() != key.public_key().to_sec1() {
        return Err(Error::InvalidInput);
    }
    Ok(())
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
    ///
    /// The OPTIONAL `[1]` publicKey is checked against the private scalar when
    /// present (a key that disagrees with itself is rejected), and trailing
    /// data after the structure is rejected.
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
        pr.finish().map_err(|_| Error::Malformed)?;
        let curve = CurveId::from_named_curve_oid(&arcs).ok_or(Error::Malformed)?;
        let key = Self::from_bytes(curve, priv_bytes)?;
        check_embedded_public_key(&mut seq, &key)?;
        seq.finish().map_err(|_| Error::Malformed)?;
        outer.finish().map_err(|_| Error::Malformed)?;
        Ok(key)
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
    /// named-curve parameter.
    ///
    /// The inner SEC1 structure's OPTIONAL fields are no longer skipped
    /// blindly: a `[0]` namedCurve must name the same curve as the PKCS#8
    /// algorithm parameter, and a `[1]` publicKey must be the public key of
    /// the private scalar. Trailing data after either structure is rejected;
    /// the RFC 5958 `[0]` attributes / `[1]` publicKey of the *outer*
    /// `OneAsymmetricKey` are still accepted and skipped.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        use crate::der::{Reader, parse_oid, tag};
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
        algid.finish().map_err(|_| Error::Malformed)?;
        let inner = seq.read_octet_string().map_err(|_| Error::Malformed)?;
        // inner = SEC1 ECPrivateKey { version, privateKey OCTET STRING,
        //                             [0] parameters OPTIONAL,
        //                             [1] publicKey OPTIONAL }.
        let mut ir = Reader::new(inner);
        let mut iseq = ir.read_sequence().map_err(|_| Error::Malformed)?;
        iseq.read_integer_bytes().map_err(|_| Error::Malformed)?; // SEC1 version (1)
        let priv_bytes = iseq.read_octet_string().map_err(|_| Error::Malformed)?;
        if iseq.peek_tag() == Some(tag::context(0)) {
            // RFC 5915 §3 requires this to be omitted inside PKCS#8; if it is
            // there anyway it must agree with the outer parameter, otherwise
            // the two halves of the file describe different curves.
            let params = iseq
                .read_tlv(tag::context(0))
                .map_err(|_| Error::Malformed)?;
            let mut pr = Reader::new(params);
            let arcs = parse_oid(pr.read_oid().map_err(|_| Error::Malformed)?)
                .map_err(|_| Error::Malformed)?;
            pr.finish().map_err(|_| Error::Malformed)?;
            if CurveId::from_named_curve_oid(&arcs) != Some(curve) {
                return Err(Error::Malformed);
            }
        }
        let key = Self::from_bytes(curve, priv_bytes)?;
        check_embedded_public_key(&mut iseq, &key)?;
        iseq.finish().map_err(|_| Error::Malformed)?;
        ir.finish().map_err(|_| Error::Malformed)?;
        // RFC 5958: OPTIONAL `[0]` attributes (IMPLICIT SET) and `[1]`
        // publicKey (IMPLICIT BIT STRING, so the primitive tag `0x81`; accept
        // the constructed spelling too) may follow, as in `Ed25519PrivateKey`.
        if seq.peek_tag() == Some(tag::context(0)) {
            seq.read_any().map_err(|_| Error::Malformed)?;
        }
        if matches!(seq.peek_tag(), Some(t) if t == tag::context(1) || t == (0x80 | 1)) {
            seq.read_any().map_err(|_| Error::Malformed)?;
        }
        seq.finish().map_err(|_| Error::Malformed)?;
        r.finish().map_err(|_| Error::Malformed)?;
        Ok(key)
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

/// The same scalar on the same curve, for key agreement. The ECDSA key is
/// dropped (and wiped) after its scalar is copied.
impl From<BoxedEcdsaPrivateKey> for BoxedEcdhPrivateKey {
    fn from(key: BoxedEcdsaPrivateKey) -> Self {
        BoxedEcdhPrivateKey {
            curve: key.curve,
            d: key.d.clone(),
        }
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

    /// Parses an unencrypted PKCS#8 `PrivateKeyInfo` carrying an
    /// `id-ecPublicKey` key — the same document
    /// [`BoxedEcdsaPrivateKey::from_pkcs8_der`] reads. An EC private key is
    /// a scalar on a named curve, usable for ECDH as much as for ECDSA; this
    /// is how a PKCS#8 / PEM key is loaded for key agreement.
    #[cfg(feature = "der")]
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        BoxedEcdsaPrivateKey::from_pkcs8_der(der).map(Self::from)
    }

    /// Parses an unencrypted PKCS#8 PEM private key
    /// (`-----BEGIN PRIVATE KEY-----`) for ECDH. See
    /// [`from_pkcs8_der`](Self::from_pkcs8_der).
    #[cfg(feature = "der")]
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        BoxedEcdsaPrivateKey::from_pkcs8_pem(pem).map(Self::from)
    }

    /// The curve this key lives on.
    pub fn curve(&self) -> CurveId {
        self.curve
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

    // Brainpool (RFC 5639) sign+verify round-trip on each curve, using the
    // curve's matched hash (P256r1/SHA-256, P384r1/SHA-384, P512r1/SHA-512).
    #[test]
    fn brainpool_sign_verify_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"brainpool-rt", b"nonce", &[]);

        // P256r1 / SHA-256.
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::BrainpoolP256r1, &mut rng);
        let pk = sk.public_key();
        let sig = sk.sign::<Sha256>(b"hello brainpool p256").unwrap();
        pk.verify::<Sha256>(b"hello brainpool p256", &sig).unwrap();
        assert!(pk.verify::<Sha256>(b"tampered", &sig).is_err());
        let sec1 = pk.to_sec1();
        assert_eq!(
            BoxedEcdsaPublicKey::from_sec1(CurveId::BrainpoolP256r1, &sec1)
                .unwrap()
                .to_sec1(),
            sec1
        );

        // P384r1 / SHA-384.
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::BrainpoolP384r1, &mut rng);
        let pk = sk.public_key();
        let sig = sk.sign::<Sha384>(b"hello brainpool p384").unwrap();
        pk.verify::<Sha384>(b"hello brainpool p384", &sig).unwrap();
        assert!(pk.verify::<Sha384>(b"tampered", &sig).is_err());

        // P512r1 / SHA-512.
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::BrainpoolP512r1, &mut rng);
        let pk = sk.public_key();
        let sig = sk.sign::<Sha512>(b"hello brainpool p512").unwrap();
        pk.verify::<Sha512>(b"hello brainpool p512", &sig).unwrap();
        assert!(pk.verify::<Sha512>(b"tampered", &sig).is_err());
    }

    // Authoritative known-answer vectors from Google/C2SP Wycheproof
    // (`ecdsa_brainpool{P256,P384,P512}r1_sha{256,384,512}_test.json`,
    // testvectors_v1). Each pins a published (public key, message, DER
    // signature) triple that MUST verify, anchoring the Brainpool curve
    // arithmetic and ECDSA verify path against an independent reference. RFC
    // 6979 itself carries no Brainpool deterministic vectors, so a verify-only
    // KAT against an external suite is the strongest pin available.
    // The fixtures are DER-encoded signatures, so the case needs the codec.
    #[cfg(feature = "der")]
    #[test]
    fn brainpool_wycheproof_kat() {
        // All three groups use tcId 2: msg = "Msg" (0x4d7367), result "valid".
        let msg = from_hex("4d7367");

        // brainpoolP256r1 / SHA-256.
        let pk = BoxedEcdsaPublicKey::from_sec1(
            CurveId::BrainpoolP256r1,
            &from_hex(
                "042676bd1e3fd83f3328d1af941442c036760f09587729419053083eb61d1ed2\
                 2c2cf769688a5ffd67da1899d243e66bcabe21f9e78335263bf5308b8e41a71b39",
            ),
        )
        .unwrap();
        let sig = BoxedEcdsaSignature::from_der(&from_hex(
            "304502200ff9279a0775740b7db8bec07f9a0401b7903886cb198c1b18c46de067\
             3b31c30221008b3c8686bd1a1508b5b785e762fece8c6cf19b6156983e5c36b2bbe724d6c23e",
        ))
        .unwrap();
        pk.verify::<Sha256>(&msg, &sig).unwrap();
        // A one-byte tweak to the message must fail.
        assert!(pk.verify::<Sha256>(b"msg", &sig).is_err());

        // brainpoolP384r1 / SHA-384.
        let pk = BoxedEcdsaPublicKey::from_sec1(
            CurveId::BrainpoolP384r1,
            &from_hex(
                "046c9aaba343cb2faf098319cc4d15ea218786f55c8cf0a8b668091170a6422f\
                 6c2498945a8164a4b6f27cdd11e800da501be961b37b09804610ce0df40dd8236\
                 c75a12d0c8014b163464a4aeba7cb18d20d3222083ec4a941852f24aa3d5d84e3",
            ),
        )
        .unwrap();
        let sig = BoxedEcdsaSignature::from_der(&from_hex(
            "3064023001057e36ad00f79e7c1cfcf4dea301e4e2350644d5eff4d4c7f23cdd2f4f\
             236093ff27e33eb44fd804b2f0daf5c327a402302a9b2b910dd23b994cac12f32282\
             8461094c8790481b392569c6674ac2eca74dd74957d94456548546b65bd50558f4a6",
        ))
        .unwrap();
        pk.verify::<Sha384>(&msg, &sig).unwrap();

        // brainpoolP512r1 / SHA-512.
        let pk = BoxedEcdsaPublicKey::from_sec1(
            CurveId::BrainpoolP512r1,
            &from_hex(
                "041ec7fe2275860c3bc0e4e6e459af7e16985d37adba7351ac357a7c397e0752\
                 2ea41bcca8e89777fe05b8f0d9dc8c614004fcaf30a97001a5011a159f46fcd54\
                 43cbc1ddfc7ac89a1a2f8eef77bf9bba8ade73da2100cb6a371546b495fb5ea88\
                 5eb631645e79591db659c49266d263d5cbd3403081cb407536efe9a5bec69955",
            ),
        )
        .unwrap();
        let sig = BoxedEcdsaSignature::from_der(&from_hex(
            "3081840240225dc2310177ce6267efde9937eff898fb0bad12b0dbeb4fa9c6be6e2\
             0f88563e6d2991d47a648b0ba5a7039842dbf883bbd735df793cce0d136023fbfc9b\
             e95024000d59783d8bd050cf728b3506c16ee4a78ac26c12fd33dadb6ee8146372e4\
             fb2a880ef77eb20ac90f3a4275c1718a033a7c0b2df538eb35827330154191153cb",
        ))
        .unwrap();
        pk.verify::<Sha512>(&msg, &sig).unwrap();
    }

    /// The SEC 2 / FIPS 186-4 / RFC 5639 small curves: every curve signs and
    /// verifies with each of SHA-224/256/384/512 (digests both narrower and
    /// wider than the order), a tampered message fails, the raw `r ‖ s`
    /// encoding is `2·order_len` bytes (one byte per half more than the
    /// coordinates on the 161/225-bit-order curves), and the DER form
    /// round-trips through the curve-bounded parser. Compressed SEC1 keys
    /// decode to the same point — this is what exercises Tonelli–Shanks on
    /// P-224 (`p ≡ 1 mod 4`) and secp224k1 (`p ≡ 5 mod 8`).
    #[test]
    fn small_curves_sign_verify_roundtrip() {
        use crate::hash::Sha224;
        let mut rng = HmacDrbg::<Sha256>::new(b"small-curves", b"nonce", &[]);
        for curve in [
            CurveId::Secp160k1,
            CurveId::Secp160r1,
            CurveId::Secp160r2,
            CurveId::Secp192k1,
            CurveId::P192,
            CurveId::Secp224k1,
            CurveId::P224,
            CurveId::BrainpoolP224r1,
            CurveId::BrainpoolP320r1,
        ] {
            let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
            let pk = sk.public_key();
            let msg = b"hello small curve";
            let sigs = [
                sk.sign::<Sha224>(msg).unwrap(),
                sk.sign::<Sha256>(msg).unwrap(),
                sk.sign::<Sha384>(msg).unwrap(),
                sk.sign::<Sha512>(msg).unwrap(),
            ];
            pk.verify::<Sha224>(msg, &sigs[0]).unwrap();
            pk.verify::<Sha256>(msg, &sigs[1]).unwrap();
            pk.verify::<Sha384>(msg, &sigs[2]).unwrap();
            pk.verify::<Sha512>(msg, &sigs[3]).unwrap();
            assert!(
                pk.verify::<Sha256>(b"tampered", &sigs[1]).is_err(),
                "{curve:?}"
            );
            assert!(
                pk.verify::<Sha384>(msg, &sigs[1]).is_err(),
                "{curve:?} hash"
            );
            for sig in &sigs {
                assert_eq!(
                    sig.to_bytes(curve).len(),
                    2 * curve.order_len(),
                    "{curve:?}"
                );
                #[cfg(feature = "der")]
                {
                    let der = sig.to_der(curve);
                    let back = BoxedEcdsaSignature::from_der_for_curve(&der, curve).unwrap();
                    assert_eq!(&back, sig, "{curve:?} DER round-trip");
                }
            }

            // Uncompressed and compressed SEC1 round-trips.
            let sec1 = pk.to_sec1();
            assert_eq!(sec1.len(), 1 + 2 * curve.field_len());
            assert_eq!(
                BoxedEcdsaPublicKey::from_sec1(curve, &sec1)
                    .unwrap()
                    .to_sec1(),
                sec1
            );
            let flen = curve.field_len();
            let mut compressed = alloc::vec![0x02 | (sec1[2 * flen] & 1)];
            compressed.extend_from_slice(&sec1[1..1 + flen]);
            assert_eq!(
                BoxedEcdsaPublicKey::from_sec1(curve, &compressed)
                    .unwrap()
                    .to_sec1(),
                sec1,
                "{curve:?} compressed"
            );
            // The other parity is the negated point (x, p − y).
            compressed[0] ^= 1;
            let other = BoxedEcdsaPublicKey::from_sec1(curve, &compressed).unwrap();
            assert_ne!(other.to_sec1(), sec1);
            assert_eq!(other.add(&pk).map(|_| ()), Err(Error::InvalidInput));

            // ECDH agrees both ways and is field-width.
            let a = BoxedEcdhPrivateKey::generate(curve, &mut rng);
            let b = BoxedEcdhPrivateKey::generate(curve, &mut rng);
            let ab = a.diffie_hellman(&b.public_key()).unwrap();
            assert_eq!(ab, b.diffie_hellman(&a.public_key()).unwrap());
            assert_eq!(ab.len(), curve.field_len());
        }
    }

    /// On the curves whose order is a bit wider than the field, a private
    /// scalar with the 161st / 225th bit set is in range and signs, while
    /// `n` itself and `0` are refused; the SEC1 private-key encoding is
    /// `order_len` bytes.
    #[test]
    fn order_wider_than_field_private_key_range() {
        for curve in [
            CurveId::Secp160k1,
            CurveId::Secp160r1,
            CurveId::Secp160r2,
            CurveId::Secp224k1,
        ] {
            let n = curve.curve().order().clone();
            let olen = curve.order_len();
            assert_eq!(n.bit_len(), 8 * curve.field_len() + 1);
            // 2^(8·field_len): one more than any field element fits.
            let mut big = vec![0u8; olen];
            big[0] = 0x01;
            let sk = BoxedEcdsaPrivateKey::from_bytes(curve, &big).unwrap();
            let sig = sk.sign::<Sha256>(b"wide scalar").unwrap();
            sk.public_key()
                .verify::<Sha256>(b"wide scalar", &sig)
                .unwrap();
            // n − 1 is the largest valid scalar; n and 0 are not.
            let n_minus_1 = n.sub(&BoxedUint::from_u64(1)).to_be_bytes(olen);
            BoxedEcdsaPrivateKey::from_bytes(curve, &n_minus_1).unwrap();
            assert!(BoxedEcdsaPrivateKey::from_bytes(curve, &n.to_be_bytes(olen)).is_err());
            assert!(BoxedEcdhPrivateKey::from_bytes(curve, &[0u8; 21]).is_err());
            #[cfg(feature = "der")]
            {
                let parsed = BoxedEcdsaPrivateKey::from_sec1_der(&sk.to_sec1_der()).unwrap();
                assert_eq!(parsed.public_key().to_sec1(), sk.public_key().to_sec1());
                let parsed = BoxedEcdsaPrivateKey::from_pkcs8_der(&sk.to_pkcs8_der()).unwrap();
                assert_eq!(parsed.curve(), curve);
            }
        }
    }

    /// RFC 6979 A.2.3 (P-192) and A.2.4 (P-224): deterministic signatures
    /// over "sample" with SHA-1/224/256/384/512, plus the P-192 "test"
    /// vector with SHA-256. These pin the nonce derivation with an
    /// `order_len`-byte octet string and the truncation of a digest wider
    /// than the order (SHA-384/512 on a 192/224-bit `n`).
    #[test]
    fn rfc6979_p192_p224_vectors() {
        use crate::hash::{Sha1, Sha224};
        let p192 = BoxedEcdsaPrivateKey::from_bytes(
            CurveId::P192,
            &from_hex("6fab034934e4c0fc9ae67f5b5659a9d7d1fefd187ee09fd4"),
        )
        .unwrap();
        assert_eq!(
            p192.public_key().to_sec1(),
            from_hex(
                "04ac2c77f529f91689fea0ea5efec7f210d8eea0b9e047ed56\
                 3bc723e57670bd4887ebc732c523063d0a7c957bc97c1c43"
            )
        );
        let p224 = BoxedEcdsaPrivateKey::from_bytes(
            CurveId::P224,
            &from_hex("f220266e1105bfe3083e03ec7a3a654651f45e37167e88600bf257c1"),
        )
        .unwrap();
        assert_eq!(
            p224.public_key().to_sec1(),
            from_hex(
                "0400cf08da5ad719e42707fa431292dea11244d64fc51610d94b130d6c\
                 eeab6f3debe455e3dbf85416f7030cbd94f34f2d6f232c69f3c1385a"
            )
        );
        // (curve key, message, r ‖ s, hash tag)
        let check = |sk: &BoxedEcdsaPrivateKey, sig: BoxedEcdsaSignature, rs: &str| {
            let curve = sk.curve();
            assert_eq!(sig.to_bytes(curve), from_hex(rs), "{curve:?} {rs}");
        };
        // P-192, "sample".
        check(
            &p192,
            p192.sign::<Sha1>(b"sample").unwrap(),
            "98c6bd12b23eaf5e2a2045132086be3eb8ebd62abf6698ff\
             57a22b07dea9530f8de9471b1dc6624472e8e2844bc25b64",
        );
        check(
            &p192,
            p192.sign::<Sha224>(b"sample").unwrap(),
            "a1f00dad97aeec91c95585f36200c65f3c01812aa60378f5\
             e07ec1304c7c6c9debbe980b9692668f81d4de7922a0f97a",
        );
        check(
            &p192,
            p192.sign::<Sha256>(b"sample").unwrap(),
            "4b0b8ce98a92866a2820e20aa6b75b56382e0f9bfd5ecb55\
             ccdb006926ea9565cbadc840829d8c384e06de1f1e381b85",
        );
        check(
            &p192,
            p192.sign::<Sha384>(b"sample").unwrap(),
            "da63bf0b9abcf948fbb1e9167f136145f7a20426dcc287d5\
             c3aa2c960972bd7a2003a57e1c4c77f0578f8ae95e31ec5e",
        );
        check(
            &p192,
            p192.sign::<Sha512>(b"sample").unwrap(),
            "4d60c5ab1996bd848343b31c00850205e2ea6922dac2e4b8\
             3f6e837448f027a1bf4b34e796e32a811cbb4050908d8f67",
        );
        // P-192, "test".
        check(
            &p192,
            p192.sign::<Sha256>(b"test").unwrap(),
            "3a718bd8b4926c3b52ee6bbe67ef79b18cb6eb62b1ad97ae\
             5662e6848a4a19b1f1ae2f72acd4b8bbe50f1eac65d9124f",
        );
        // P-224, "sample".
        check(
            &p224,
            p224.sign::<Sha1>(b"sample").unwrap(),
            "22226f9d40a96e19c4a301ce5b74b115303c0f3a4fd30fc257fb57ac\
             66d1cdd83e3af75605dd6e2feff196d30aa7ed7a2edf7af475403d69",
        );
        check(
            &p224,
            p224.sign::<Sha224>(b"sample").unwrap(),
            "1cdfe6662dde1e4a1ec4cdedf6a1f5a2fb7fbd9145c12113e6abfd3e\
             a6694fd7718a21053f225d3f46197ca699d45006c06f871808f43ebc",
        );
        check(
            &p224,
            p224.sign::<Sha256>(b"sample").unwrap(),
            "61aa3da010e8e8406c656bc477a7a7189895e7e840cdfe8ff42307ba\
             bc814050dab5d23770879494f9e0a680dc1af7161991bde692b10101",
        );
        check(
            &p224,
            p224.sign::<Sha384>(b"sample").unwrap(),
            "0b115e5e36f0f9ec81f1325a5952878d745e19d7bb3eabfaba77e953\
             830f34ccdfe826ccfdc81eb4129772e20e122348a2bbd889a1b1af1d",
        );
        check(
            &p224,
            p224.sign::<Sha512>(b"sample").unwrap(),
            "074bd1d979d5f32bf958ddc61e4fb4872adcafeb2256497cdac30397\
             a4ceca196c3d5a1ff31027b33185dc8ee43f288b21ab342e5d8eb084",
        );
        // And they verify.
        let sig = p224.sign::<Sha256>(b"sample").unwrap();
        p224.public_key().verify::<Sha256>(b"sample", &sig).unwrap();
        let sig = p192.sign::<Sha512>(b"sample").unwrap();
        p192.public_key().verify::<Sha512>(b"sample", &sig).unwrap();
    }

    /// One published verify KAT per new curve, from Wycheproof
    /// (`ecdsa_<curve>_<sha>_test.json`, testvectors_v1, tcId 2: msg "Msg",
    /// result valid). RFC 6979 has no vectors for the secp160/192k1/224k1
    /// or the 224/320-bit Brainpool curves, so an external verify pin is
    /// the strongest available; on the 161/225-bit-order curves it also
    /// pins the 21/29-byte DER INTEGER widths.
    #[cfg(feature = "der")]
    #[test]
    fn small_curves_wycheproof_kat() {
        use crate::hash::Sha224;
        type Verify = fn(&BoxedEcdsaPublicKey, &[u8], &BoxedEcdsaSignature) -> Result<(), Error>;
        let msg = from_hex("4d7367");
        let cases: [(CurveId, &str, &str, Verify); 9] = [
            (
                CurveId::Secp160k1,
                "048c8b7f800bc9c5588b4970e7559eca926fa38e7b6c5d8223426e1cf8d2a2791ab710a14305048ad3",
                "302d021469b9f46ded69a35ac00a053ef9dbb47d073d6729021500d059cb77081101578272ca48bf5980c5019febd5",
                |pk, m, s| pk.verify::<Sha256>(m, s),
            ),
            (
                CurveId::Secp160r1,
                "04b0046a56f874d30ea2ba7ac1a935fd9d754ee6417b9a54d275806819ec30b15618f5625115241f46",
                "302d02140f5720c6bd95624b603b2be5a75e487b34268d5f021500bfd6d370b516687113b12a4fc95eebb874a646fa",
                |pk, m, s| pk.verify::<Sha256>(m, s),
            ),
            (
                CurveId::Secp160r2,
                "0446f1a7493b131f3c6032e9612b8e1bd3d1a3104ce3cef3c8020c277ba45bc93a9a364f07eba8302c",
                "302c02146d8624bff7719b53dab811bdc0e434a5e9f02e8d02140b50e6dce0f5c1a757290eed8df0aa8092b2ff90",
                |pk, m, s| pk.verify::<Sha256>(m, s),
            ),
            (
                CurveId::Secp192k1,
                "0404a4e7bedc7d8137aade86c1a4d223ad704e63dad4717c493efc196def1cad9823c91f6b8be2611164b93cca4bb2c559",
                "30350218546e7cfe5f660f10a02cefdcb4bb4e0cc7a9fd43cc9e443f02190086d3a935dd62d5db7101e128f3f6048c490072a49a5ef047",
                |pk, m, s| pk.verify::<Sha256>(m, s),
            ),
            (
                CurveId::P192,
                "042a551b5a39771e436de636d6259ba6afb1afa5d4d897ccf8bca9a6ea5d92d656c4ba4f2dd85c9d86d0e2445fd5db8692",
                "303402181c5298437de413483c777e1133e62d5b81848747b89480bb021803b56152e323216bd9d9e403c8cd229a68014f6e2b69015d",
                |pk, m, s| pk.verify::<Sha256>(m, s),
            ),
            (
                CurveId::Secp224k1,
                "042ef983fa542b64472e2bc405d9eedd861acc9a7f814fad8275ce6b9a3459ba4ab52164883bd29eb6ac7e6d22ac7d302c053dc39684928ef9",
                "303e021d009868b57ff5572fd854ce7eb8b8513a1c54501e8fef97540291059a55021d008ece23bafe5a9456b59d1a17a03da1dbf825cbab651ec7d143d9b70c",
                |pk, m, s| pk.verify::<Sha256>(m, s),
            ),
            (
                CurveId::P224,
                "044c246670658a1d41f5d77bce246cbe386ac22848e269b9d4cd67c466ddd947153d39b2d42533a460def26880408caf2dd3dd48fe888cd176",
                "303d021d00f4b68df62b9238363ccc1bbee00deb3fb2693f7894178e14eeac596a021c7f51c9451adacd2bcbc721f7df0643d7cd18a6b52064b507e1912f23",
                |pk, m, s| pk.verify::<Sha256>(m, s),
            ),
            (
                CurveId::BrainpoolP224r1,
                "04b554fc25e9f098eaf1466c35328c97305d0d4aa0e4462e8baf7a8e7ed08fc40eb01dc855577baea9e3070770616f57b17ea9854cad93881a",
                "303c021c4dabc5fe962b5f8a6681e94a2165d9b6be1940f20e27ceb73fc4ea7d021c746e9bba7efb90fcecc263c229a16d809d3547c28a26cd71a52abdc5",
                |pk, m, s| pk.verify::<Sha224>(m, s),
            ),
            (
                CurveId::BrainpoolP320r1,
                "0444ab2320c2297b66114428df33fe641956f82033893398af3b49b0023179201c27d26dd65121c06e0c59524c938f19daffc2a9a4679dba7cf1991ced4700592bb75e98cf77dbf6c584c2f72735152921",
                "3055022826fd695ee1cc50c2661c2434f8699577af181304bceb7690c538b03463df24334395e791f6750ff6022900b322618cd50c6a7cffcb419ec05b67ec6a117088c78d57cecdd224902d391892ca03e4bc1bd0467b",
                |pk, m, s| pk.verify::<Sha384>(m, s),
            ),
        ];
        for (curve, key, sig, verify) in cases {
            let pk = BoxedEcdsaPublicKey::from_sec1(curve, &from_hex(key)).unwrap();
            let sig = BoxedEcdsaSignature::from_der_for_curve(&from_hex(sig), curve).unwrap();
            verify(&pk, &msg, &sig).unwrap_or_else(|e| panic!("{curve:?}: {e:?}"));
            assert!(
                verify(&pk, b"msg", &sig).is_err(),
                "{curve:?} tweaked message"
            );
        }
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

    /// A SEC1 / PKCS#8 EC key must agree with itself: an embedded `[1]`
    /// publicKey belonging to a different scalar, an inner `[0]` naming a
    /// different curve, and trailing data are all rejected — while keys
    /// without the optional fields still load.
    #[cfg(feature = "der")]
    #[test]
    fn ec_private_key_optional_fields_are_validated() {
        use crate::der::{
            encode_bit_string, encode_context, encode_integer, encode_octet_string,
            encode_sequence, oid_tlv,
        };
        let mut rng = HmacDrbg::<Sha256>::new(b"pkcs8-strict", b"n", &[]);
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let other = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);

        // Builds a SEC1 ECPrivateKey with the given optional fields.
        let sec1 = |params: Option<CurveId>, pubkey: Option<&BoxedEcdsaPrivateKey>| {
            let mut body = encode_integer(&[1]);
            body.extend_from_slice(&encode_octet_string(
                &sk.d.to_be_bytes(CurveId::P256.order_len()),
            ));
            if let Some(c) = params {
                body.extend_from_slice(&encode_context(0, &oid_tlv(c.named_curve_oid())));
            }
            if let Some(k) = pubkey {
                body.extend_from_slice(&encode_context(
                    1,
                    &encode_bit_string(&k.public_key().to_sec1()),
                ));
            }
            encode_sequence(&body)
        };
        let pkcs8 = |inner: Vec<u8>| {
            let algid = encode_sequence(
                &[
                    oid_tlv(EC_PUBLIC_KEY_OID),
                    oid_tlv(CurveId::P256.named_curve_oid()),
                ]
                .concat(),
            );
            encode_sequence(&[encode_integer(&[0]), algid, encode_octet_string(&inner)].concat())
        };

        // Baseline: with and without the optional public key.
        for der in [
            sec1(Some(CurveId::P256), Some(&sk)),
            sec1(Some(CurveId::P256), None),
        ] {
            let k = BoxedEcdsaPrivateKey::from_sec1_der(&der).unwrap();
            assert_eq!(k.public_key().to_sec1(), sk.public_key().to_sec1());
        }
        for inner in [
            sec1(None, None),
            sec1(None, Some(&sk)),
            sec1(Some(CurveId::P256), Some(&sk)),
        ] {
            let k = BoxedEcdsaPrivateKey::from_pkcs8_der(&pkcs8(inner)).unwrap();
            assert_eq!(k.public_key().to_sec1(), sk.public_key().to_sec1());
        }

        // A public key belonging to a different scalar: rejected either way.
        let mismatched = sec1(Some(CurveId::P256), Some(&other));
        assert!(BoxedEcdsaPrivateKey::from_sec1_der(&mismatched).is_err());
        assert!(BoxedEcdsaPrivateKey::from_pkcs8_der(&pkcs8(mismatched.clone())).is_err());

        // An inner [0] naming a different curve than the PKCS#8 parameter.
        let wrong_curve = sec1(Some(CurveId::P384), Some(&sk));
        assert!(BoxedEcdsaPrivateKey::from_pkcs8_der(&pkcs8(wrong_curve)).is_err());

        // Trailing data after either structure.
        let mut trailing = sec1(Some(CurveId::P256), Some(&sk));
        trailing.push(0x00);
        assert!(BoxedEcdsaPrivateKey::from_sec1_der(&trailing).is_err());
        let mut trailing8 = pkcs8(sec1(None, None));
        trailing8.extend_from_slice(&[0x00, 0x00]);
        assert!(BoxedEcdsaPrivateKey::from_pkcs8_der(&trailing8).is_err());
        // ... and inside the SEC1 structure wrapped by PKCS#8.
        let mut inner_trailing = sec1(None, None);
        inner_trailing.push(0x05);
        assert!(BoxedEcdsaPrivateKey::from_pkcs8_der(&pkcs8(inner_trailing)).is_err());

        // The keys this crate emits still load.
        BoxedEcdsaPrivateKey::from_sec1_der(&sk.to_sec1_der()).unwrap();
        BoxedEcdsaPrivateKey::from_pkcs8_der(&sk.to_pkcs8_der()).unwrap();
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

    /// A DER signature whose INTEGERs are wider than any supported group order
    /// must be rejected at parse time, not panic later in
    /// `BoxedUint::to_be_bytes` when the application re-encodes it (logging,
    /// canonicalisation, DER↔raw conversion) before verifying.
    #[cfg(feature = "der")]
    #[test]
    fn oversize_der_signature_rejected_at_parse() {
        use crate::der::{encode_integer, encode_sequence};

        // SEQUENCE { INTEGER(67 bytes), INTEGER(1) } — one byte wider than
        // P-521's order.
        let wide = [0x7fu8; 67];
        let der = encode_sequence(&[encode_integer(&wide), encode_integer(&[1])].concat());
        assert!(matches!(
            BoxedEcdsaSignature::from_der(&der),
            Err(Error::Malformed)
        ));

        // A 40-byte component is inside the generic bound but outside P-256's
        // 32-byte order: `from_der_for_curve` rejects it, and the generic
        // parse must still survive re-encoding without panicking.
        let wide40 = [0x7fu8; 40];
        let der40 = encode_sequence(&[encode_integer(&wide40), encode_integer(&[1])].concat());
        assert!(matches!(
            BoxedEcdsaSignature::from_der_for_curve(&der40, CurveId::P256),
            Err(Error::Malformed)
        ));
        let sig = BoxedEcdsaSignature::from_der(&der40).expect("within the generic bound");
        // These used to panic ("value does not fit in 32 bytes").
        assert_eq!(sig.r_bytes(CurveId::P256).len(), 40);
        assert_eq!(sig.s_bytes(CurveId::P256).len(), 32);
        assert_eq!(sig.to_bytes(CurveId::P256).len(), 72);
        let _ = sig.to_der(CurveId::P256);

        // …and it must not verify against any key on that curve.
        let mut rng = crate::rng::HmacDrbg::<Sha256>::new(b"boxed-oversize", b"n", &[]);
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        assert!(sk.public_key().verify::<Sha256>(b"hello", &sig).is_err());

        // A well-formed signature still round-trips through both parsers.
        let good = sk.sign::<Sha256>(b"hello").unwrap();
        let good_der = good.to_der(CurveId::P256);
        assert_eq!(
            BoxedEcdsaSignature::from_der_for_curve(&good_der, CurveId::P256)
                .unwrap()
                .to_bytes(CurveId::P256),
            good.to_bytes(CurveId::P256)
        );
    }
}
