//! ECDSA over secp256k1 with RFC 6979 deterministic nonces — allocation-free.
//!
//! The fixed-curve counterpart of the P-256 [`ecdsa`](crate::ec::ecdsa)
//! module for the Bitcoin / Ethereum curve. It is built on the stack-only
//! native secp256k1 arithmetic (a pseudo-Mersenne base field and the
//! Renes–Costello–Batina complete formulas), so — unlike the runtime
//! multi-curve [`boxed`](crate::ec::boxed) path, which reaches secp256k1 over
//! heap-backed bignums — it needs **no allocator**: every type here is a
//! fixed-size value and the module builds with `--no-default-features
//! --features ec` on bare-metal targets.
//!
//! The API mirrors the P-256 module one-to-one: [`Secp256k1EcdsaPrivateKey`]
//! (`generate` / `from_bytes` / `sign` / `sign_prehash`),
//! [`Secp256k1EcdsaPublicKey`] (`from_sec1` / `verify` / `verify_prehash`) and
//! the 64-byte fixed-encoding [`Secp256k1EcdsaSignature`], plus the
//! **public-key recovery** operations Bitcoin and Ethereum rely on
//! ([`sign_prehash_recoverable`](Secp256k1EcdsaPrivateKey::sign_prehash_recoverable)
//! / [`recover_prehash`](Secp256k1EcdsaSignature::recover_prehash)). Signing
//! is deterministic (RFC 6979 with HMAC-`D`), so for the same key and message
//! it produces byte-identical signatures to the boxed path.
//!
//! # Constant-time discipline
//!
//! Signing and public-key derivation use the constant-time fixed-window
//! ladder, the constant-time Fermat inverse for `k⁻¹`, and non-short-circuit
//! range checks; the nonce, its inverse, the HMAC-DRBG state and the copy of
//! the private scalar are wiped before each call returns. Verification and
//! recovery operate on public data only and reuse the same constant-time
//! routines (there is no variable-time double-scalar multiplication on this
//! curve yet, so they are simply slower than they could be, not less safe).
//!
//! # Malleability
//!
//! ECDSA signatures are inherently malleable: `(r, n − s)` verifies whenever
//! `(r, s)` does. [`sign`](Secp256k1EcdsaPrivateKey::sign) returns the raw
//! RFC 6979 output; consumers that require canonical (low-S, BIP-62 /
//! EIP-2) signatures should call
//! [`to_low_s`](Secp256k1EcdsaSignature::to_low_s) or use the recoverable
//! signing entry points, which normalise to low-S themselves.
//!
//! ```
//! use purecrypto::ec::secp256k1_ecdsa::{Secp256k1EcdsaPrivateKey, Secp256k1EcdsaPublicKey};
//! use purecrypto::hash::Sha256;
//! use purecrypto::rng::OsRng;
//!
//! let sk = Secp256k1EcdsaPrivateKey::generate(&mut OsRng);
//! let pk = sk.public_key();
//! let sig = sk.sign::<Sha256>(b"hello").unwrap();
//! pk.verify::<Sha256>(b"hello", &sig).unwrap();
//!
//! // Compressed SEC1 round-trip (33 bytes, as Bitcoin serialises keys).
//! let pk2 = Secp256k1EcdsaPublicKey::from_sec1(&pk.to_sec1_compressed()).unwrap();
//! assert_eq!(pk2, pk);
//!
//! // Recoverable signing: the public key comes back from (r, s, recid).
//! let (sig, recid) = sk.sign_recoverable::<Sha256>(b"hello").unwrap();
//! assert!(sig.is_low_s());
//! assert_eq!(sig.recover::<Sha256>(b"hello", recid).unwrap(), pk);
//! ```

use super::field_backend::{Fe, p};
use super::{AffinePoint, ProjectivePoint, Scalar};
use crate::ct::{ConstantTimeEq, ConstantTimeLess};
use crate::ec::Error;
use crate::ec::ecdsa::{bits2int, generate_k, in_range};
use crate::hash::Digest;
use crate::rng::{CryptoRng, RngCore};

/// A secp256k1 ECDSA private key (a scalar in `[1, n-1]`).
///
/// Wiped on drop (the inner `Scalar` zeroises its limbs behind a `black_box`
/// barrier).
#[derive(Clone)]
pub struct Secp256k1EcdsaPrivateKey {
    d: Scalar,
}

/// A secp256k1 ECDSA public key (an affine curve point).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secp256k1EcdsaPublicKey {
    x: Fe,
    y: Fe,
}

/// A secp256k1 ECDSA signature `(r, s)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Secp256k1EcdsaSignature {
    r: Fe,
    s: Fe,
}

/// Generates a uniformly random scalar in `[1, n-1]` by rejection sampling
/// (the same discipline as the P-256 and boxed paths: no modulo bias). `n` is
/// within `2^-128` of `2^256`, so a draw is accepted with probability
/// effectively 1.
fn random_scalar<R: RngCore>(rng: &mut R) -> Scalar {
    let n = Scalar::order();
    loop {
        let mut limbs = [0u64; 4];
        for limb in &mut limbs {
            *limb = rng.next_u64();
        }
        let d = Fe::from_limbs(limbs);
        limbs.fill(0);
        let _ = core::hint::black_box(&limbs);
        if in_range(&d, &n) {
            return Scalar(d);
        }
    }
}

impl Secp256k1EcdsaPrivateKey {
    /// Creates a private key from a 32-byte big-endian scalar, checking it is
    /// in `[1, n-1]`.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let d = Fe::from_be_bytes(bytes);
        if in_range(&d, &Scalar::order()) {
            Ok(Secp256k1EcdsaPrivateKey { d: Scalar(d) })
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// The 32-byte big-endian scalar.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.d.to_bytes_be()
    }

    /// Generates a new private key from `rng`. The RNG must be a
    /// cryptographically secure CSPRNG (see [`CryptoRng`]).
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Secp256k1EcdsaPrivateKey {
            d: random_scalar(rng),
        }
    }

    /// Derives the public key `d * G`.
    pub fn public_key(&self) -> Secp256k1EcdsaPublicKey {
        let q = ProjectivePoint::mul_generator(&self.d)
            .to_affine()
            .expect("d in [1,n-1] so d*G is not the identity");
        Secp256k1EcdsaPublicKey { x: q.x, y: q.y }
    }

    /// Signs `msg`, hashing with `D` (SHA-256 for the Bitcoin / Ethereum
    /// profile). The nonce is derived deterministically per RFC 6979, so the
    /// same key and message always yield the same signature.
    pub fn sign<D: Digest>(&self, msg: &[u8]) -> Result<Secp256k1EcdsaSignature, Error> {
        self.sign_prehash::<D>(D::digest(msg).as_ref())
    }

    /// Signs an already-computed message digest `prehash`, deriving the nonce
    /// per RFC 6979. `D` is the hash used for the nonce derivation — pass the
    /// same hash that produced `prehash` so the result matches
    /// [`sign::<D>`](Self::sign) and the RFC 6979 vectors. `prehash` is
    /// truncated to the curve order's bit length (FIPS 186-5).
    ///
    /// The signature is returned in raw RFC 6979 form (not low-S normalised);
    /// see [`Secp256k1EcdsaSignature::to_low_s`].
    ///
    /// # Security
    /// The caller must ensure `prehash` is a strong, protocol-bound digest;
    /// prefer [`sign`](Self::sign) when the message is available.
    pub fn sign_prehash<D: Digest>(
        &self,
        prehash: &[u8],
    ) -> Result<Secp256k1EcdsaSignature, Error> {
        let (r, s, _, _) = self.sign_prehash_inner::<D>(prehash)?;
        Ok(Secp256k1EcdsaSignature { r, s })
    }

    /// Core RFC 6979 signing, returning the raw `(r, s)` plus the two facts a
    /// recovery id is built from: whether the ephemeral point's x-coordinate
    /// exceeded the group order before reduction (`x_overflow`) and the parity
    /// of its y-coordinate (`y_is_odd`).
    fn sign_prehash_inner<D: Digest>(&self, prehash: &[u8]) -> Result<(Fe, Fe, bool, bool), Error> {
        let n = Scalar::order();
        let z = Scalar(bits2int(prehash).reduce(&n));

        // The nonce and every value derived from it are held in `Scalar`s,
        // whose `Drop` wipes the limbs behind a `black_box` barrier — so they
        // are zeroised on every exit path, including the `r == 0` / `s == 0`
        // rejections. `generate_k` wipes its own HMAC-DRBG state and the
        // octet copy of `d` before returning.
        let k = Scalar(generate_k::<D>(&self.d.0, prehash, &n));

        let r_point = ProjectivePoint::mul_generator(&k)
            .to_affine()
            .ok_or(Error::InvalidInput)?;
        // r = R.x mod n. R.x is a base-field residue (< p); reducing mod n
        // only ever subtracts n once, since p < 2n.
        let full_x = r_point.x;
        let r = full_x.reduce(&n);
        if bool::from(r.is_zero()) {
            return Err(Error::InvalidInput);
        }
        let x_overflow = !bool::from(full_x.ct_lt(&n));
        let y_is_odd = bool::from(r_point.y.is_odd());

        // s = k⁻¹ (z + r·d) mod n. `k` is secret, so the inversion is the
        // constant-time Fermat exponentiation (`Scalar::invert`), never a
        // variable-time Euclid: a timing leak on `k` gives away
        // `d = (s·k − z)·r⁻¹ mod n`.
        let k_inv = k.invert();
        let z_rd = z.add(&Scalar(r).mul(&self.d));
        let s = k_inv.mul(&z_rd);
        if bool::from(s.is_zero()) {
            return Err(Error::InvalidInput);
        }
        Ok((r, s.0, x_overflow, y_is_odd))
    }

    /// Signs `msg` (hashing with `D`) and also returns the **recovery id**
    /// (`v`), so the public key can later be reconstructed from the signature
    /// alone via [`Secp256k1EcdsaSignature::recover`]. See
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
    ) -> Result<(Secp256k1EcdsaSignature, u8), Error> {
        self.sign_prehash_recoverable::<D>(D::digest(msg).as_ref())
    }

    /// Signs an already-computed digest `prehash` (deriving the RFC 6979 nonce
    /// with `D`), returning the signature **and** its recovery id.
    ///
    /// The signature is normalised to **low-S** (EIP-2 / BIP-62), so it is
    /// canonical and accepted by Ethereum and Bitcoin consensus rules. The
    /// recovery id corresponds to this normalised signature.
    ///
    /// `recid` is the libsecp256k1 / Ethereum encoding in `{0, 1, 2, 3}`:
    /// - bit 0 = parity of the ephemeral point `R`'s y-coordinate, and
    /// - bit 1 = whether `R.x` exceeded the group order `n` (so `R.x = r + n`).
    ///
    /// Bit 1 is set only when `r < p − n ≈ 2^128`, which is astronomically
    /// rare, so `recid` is almost always `0` or `1`. See
    /// [`Secp256k1EcdsaSignature::recover_prehash`] for the inverse operation.
    pub fn sign_prehash_recoverable<D: Digest>(
        &self,
        prehash: &[u8],
    ) -> Result<(Secp256k1EcdsaSignature, u8), Error> {
        let (r, s, x_overflow, y_is_odd) = self.sign_prehash_inner::<D>(prehash)?;
        // Normalise to low-S; negating s reflects R across the x-axis, flipping
        // its y-parity, so the recovery id's parity bit must flip with it.
        let n = Scalar::order();
        let (s, y_is_odd) = if is_low_s(&s, &n) {
            (s, y_is_odd)
        } else {
            (n.wrapping_sub(&s), !y_is_odd)
        };
        let recid = (y_is_odd as u8) | ((x_overflow as u8) << 1);
        Ok((Secp256k1EcdsaSignature { r, s }, recid))
    }
}

/// Whether `s < (n + 1) / 2`, the low-S half of the group order.
fn is_low_s(s: &Fe, n: &Fe) -> bool {
    let half_n = n.shr1().wrapping_add(&Fe::ONE);
    bool::from(s.ct_lt(&half_n))
}

impl Secp256k1EcdsaPublicKey {
    /// Parses a SEC1 point, accepting both the 33-byte compressed form
    /// (`0x02`/`0x03 || X`, the Bitcoin serialisation) and the 65-byte
    /// uncompressed form (`0x04 || X || Y`). Rejects out-of-range coordinates,
    /// points not on the curve, and the identity.
    ///
    /// # Errors
    /// [`Error::Malformed`] for a bad length or tag; [`Error::InvalidInput`]
    /// for a coordinate `≥ p`, an off-curve point, or a compressed `X` with
    /// no square root.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, Error> {
        let pt = AffinePoint::from_sec1(bytes)?;
        Ok(Secp256k1EcdsaPublicKey { x: pt.x, y: pt.y })
    }

    /// The affine point this key is.
    fn point(&self) -> AffinePoint {
        AffinePoint {
            x: self.x,
            y: self.y,
        }
    }

    /// Encodes the key as an uncompressed SEC1 point (`0x04 || X || Y`).
    pub fn to_sec1(&self) -> [u8; 65] {
        self.point().to_sec1_uncompressed()
    }

    /// Encodes the key as a compressed SEC1 point (`0x02`/`0x03 || X`, the
    /// tag's low bit being the parity of `Y`).
    pub fn to_sec1_compressed(&self) -> [u8; 33] {
        self.point().to_sec1_compressed()
    }

    /// Verifies `sig` over `msg`, hashing with `D`.
    pub fn verify<D: Digest>(
        &self,
        msg: &[u8],
        sig: &Secp256k1EcdsaSignature,
    ) -> Result<(), Error> {
        self.verify_prehash(D::digest(msg).as_ref(), sig)
    }

    /// Verifies `sig` over an already-computed message digest `prehash` (no
    /// hash type parameter — verification only truncates `prehash`). See
    /// [`Secp256k1EcdsaPrivateKey::sign_prehash`].
    ///
    /// Accepts both `(r, s)` and its malleable twin `(r, n − s)`, as ECDSA
    /// defines; enforce [`is_low_s`](Secp256k1EcdsaSignature::is_low_s)
    /// separately where canonical signatures are required.
    pub fn verify_prehash(
        &self,
        prehash: &[u8],
        sig: &Secp256k1EcdsaSignature,
    ) -> Result<(), Error> {
        let n = Scalar::order();
        if !in_range(&sig.r, &n) || !in_range(&sig.s, &n) {
            return Err(Error::Verification);
        }
        let z = Scalar(bits2int(prehash).reduce(&n));
        let r = Scalar(sig.r);
        // `sig.s` is in [1, n-1] (checked above), so the Fermat inverse is
        // exact. Everything here is public, so constant time is not needed
        // but costs nothing in correctness.
        let w = Scalar(sig.s).invert();
        let u1 = z.mul(&w);
        let u2 = r.mul(&w);

        let sum = ProjectivePoint::mul_generator(&u1).add(&self.point().to_projective().mul(&u2));
        let v = sum.to_affine().ok_or(Error::Verification)?;
        let vx = v.x.reduce(&n);
        if bool::from(vx.ct_eq(&sig.r)) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

impl Secp256k1EcdsaSignature {
    /// Builds a signature from raw `(r, s)` 32-byte big-endian halves.
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Secp256k1EcdsaSignature {
            r: Fe::from_be_bytes(&bytes[..32]),
            s: Fe::from_be_bytes(&bytes[32..]),
        }
    }

    /// Builds a signature from explicit `(r, s)` 32-byte big-endian
    /// components. The byte order matches the SEC1 fixed encoding.
    pub fn from_components(r: &[u8; 32], s: &[u8; 32]) -> Self {
        Secp256k1EcdsaSignature {
            r: Fe::from_be_bytes(r),
            s: Fe::from_be_bytes(s),
        }
    }

    /// The 32-byte big-endian encoding of the `r` component.
    pub fn r_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.r.write_be_bytes(&mut out);
        out
    }

    /// The 32-byte big-endian encoding of the `s` component.
    pub fn s_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.s.write_be_bytes(&mut out);
        out
    }

    /// Returns the fixed 64-byte `r || s` encoding (the Bitcoin "compact" /
    /// Ethereum `r ‖ s` layout, without the recovery byte).
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.r.write_be_bytes(&mut out[..32]);
        self.s.write_be_bytes(&mut out[32..]);
        out
    }

    /// Whether `s` is in the lower half of the group order — the "low-S" form
    /// required by signature-non-malleability conventions (Bitcoin BIP-62,
    /// Ethereum EIP-2, anti-replay caches keyed on signature bytes). For any
    /// valid ECDSA signature `(r, s)`, the pair `(r, n − s)` also verifies, so
    /// callers needing unique signature bytes must require `is_low_s()`.
    pub fn is_low_s(&self) -> bool {
        is_low_s(&self.s, &Scalar::order())
    }

    /// Returns the canonical low-S representative for this signature: if
    /// `s` is already in the lower half, returns `self`; otherwise returns
    /// `(r, n − s)`, which is equally valid and bytewise unique.
    pub fn to_low_s(&self) -> Self {
        if self.is_low_s() {
            self.clone()
        } else {
            Secp256k1EcdsaSignature {
                r: self.r,
                s: Scalar::order().wrapping_sub(&self.s),
            }
        }
    }

    /// Recovers the signing public key from this signature over `msg` (hashed
    /// with `D`) and the recovery id `recid`. See
    /// [`recover_prehash`](Self::recover_prehash).
    pub fn recover<D: Digest>(
        &self,
        msg: &[u8],
        recid: u8,
    ) -> Result<Secp256k1EcdsaPublicKey, Error> {
        self.recover_prehash(D::digest(msg).as_ref(), recid)
    }

    /// Recovers the signing public key from this signature over the digest
    /// `prehash` and the recovery id `recid` — the ECDSA "public key recovery"
    /// operation (libsecp256k1 `ecdsa_recover`, Ethereum `ecrecover`).
    ///
    /// `recid ∈ {0, 1, 2, 3}` is the value produced alongside the signature by
    /// [`Secp256k1EcdsaPrivateKey::sign_prehash_recoverable`]: bit 0 is the
    /// parity of the ephemeral point `R`'s y-coordinate and bit 1 is whether
    /// `R.x` overflowed the group order. The recovered key is the unique `Q`
    /// with `Q = r⁻¹·(s·R − z·G)`, where `R = lift_x(r + (recid≫1)·n, recid&1)`.
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
    /// [`verify_prehash`]: Secp256k1EcdsaPublicKey::verify_prehash
    pub fn recover_prehash(
        &self,
        prehash: &[u8],
        recid: u8,
    ) -> Result<Secp256k1EcdsaPublicKey, Error> {
        if recid > 3 {
            return Err(Error::InvalidInput);
        }
        let n = Scalar::order();
        if !in_range(&self.r, &n) || !in_range(&self.s, &n) {
            return Err(Error::Verification);
        }

        // R.x = r + (recid>>1)·n. The overflow form is only meaningful when
        // r + n is still a field element, i.e. r < p − n (≈ 2^128); checking
        // that first keeps the 256-bit addition from wrapping into a bogus
        // small abscissa.
        let rx = if recid & 2 == 0 {
            self.r
        } else {
            let p_minus_n = p().wrapping_sub(&n);
            if !bool::from(self.r.ct_lt(&p_minus_n)) {
                return Err(Error::Verification);
            }
            self.r.wrapping_add(&n)
        };
        // lift_x with the requested parity: the SEC1 compressed decoder
        // rejects an abscissa that is off the curve.
        let mut enc = [0u8; 33];
        enc[0] = 0x02 | (recid & 1);
        rx.write_be_bytes(&mut enc[1..]);
        let r_point = AffinePoint::from_sec1(&enc).map_err(|_| Error::Verification)?;

        // Q = u1·G + u2·R with u1 = −z·r⁻¹, u2 = s·r⁻¹ (mod n).
        let z = Scalar(bits2int(prehash).reduce(&n));
        let r_inv = Scalar(self.r).invert();
        let u1 = z.negate().mul(&r_inv);
        let u2 = Scalar(self.s).mul(&r_inv);
        let q = ProjectivePoint::mul_generator(&u1)
            .add(&r_point.to_projective().mul(&u2))
            .to_affine()
            .ok_or(Error::Verification)?;
        Ok(Secp256k1EcdsaPublicKey { x: q.x, y: q.y })
    }
}

/// DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` codec — the
/// form Bitcoin scripts and X.509 carry (the fixed `r‖s` form is what
/// Ethereum and JOSE use).
#[cfg(all(feature = "der", feature = "alloc"))]
impl Secp256k1EcdsaSignature {
    /// Encodes the signature as a DER `Ecdsa-Sig-Value`.
    pub fn to_der(&self) -> alloc::vec::Vec<u8> {
        use crate::der::{encode_integer, encode_sequence};
        let raw = self.to_bytes();
        encode_sequence(&[encode_integer(&raw[..32]), encode_integer(&raw[32..])].concat())
    }

    /// Decodes a DER `Ecdsa-Sig-Value` into a signature, with strict-DER
    /// enforcement on the inner `r` / `s` INTEGERs (no unnecessary leading
    /// `0x00`, no leading-`0xff`, no empty body, no trailing bytes inside
    /// the SEQUENCE or after it) and a 32-byte magnitude bound on each. Strict
    /// DER is what closes the ECDSA signature-malleability gap at the bytes
    /// level (BIP-66) — many distinct encodings of the same `(r, s)` are
    /// otherwise accepted.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        use crate::der::Reader;
        use crate::ec::ecdsa::left_pad_32;
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

        let mut raw = [0u8; 64];
        left_pad_32(r, &mut raw[..32])?;
        left_pad_32(s, &mut raw[32..])?;
        Ok(Self::from_bytes(&raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha256, Sha512};
    use crate::rng::HmacDrbg;

    /// Decodes exactly `N` bytes of hex (no `alloc`).
    fn from_hex<const N: usize>(hex: &str) -> [u8; N] {
        assert_eq!(hex.len(), 2 * N);
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    fn hex32(hex: &str) -> [u8; 32] {
        from_hex::<32>(hex)
    }

    /// The 32-byte big-endian encoding of a 4-limb value.
    fn be32(v: &Fe) -> [u8; 32] {
        let mut out = [0u8; 32];
        v.write_be_bytes(&mut out);
        out
    }

    fn key_one() -> Secp256k1EcdsaPrivateKey {
        let mut d = [0u8; 32];
        d[31] = 1;
        Secp256k1EcdsaPrivateKey::from_bytes(&d).unwrap()
    }

    // --- RFC 6979 known answers (secp256k1, SHA-256) -------------------------
    //
    // The widely reproduced python-ecdsa / bitcoin vectors for private key 1.
    // Both the new fixed-curve path and the boxed runtime path (interop-
    // validated against OpenSSL) are checked against the literals, so a bad
    // constant would fail on the boxed side too.

    const SATOSHI_MSG: &[u8] = b"Satoshi Nakamoto";
    const SATOSHI_R: &str = "934b1ea10a4b3c1757e2b0c017d0b6143ce3c9a7e6a4a49860d7a6ab210ee3d8";
    const SATOSHI_S: &str = "2442ce9d2b916064108014783e923ec36b49743e2ffa1c4496f01a512aafd9e5";

    const RAIN_MSG: &[u8] =
        b"All those moments will be lost in time, like tears in rain. Time to die...";
    const RAIN_R: &str = "8600dbd41e348fe5c9465ab92d23e3db8b98b873beecd930736488696438cb6b";
    const RAIN_S: &str = "547fe64427496db33bf66019dacbf0039c04199abb0122918601db38a72cfc21";

    #[test]
    fn rfc6979_key_one_public_key_is_generator() {
        let pk = key_one().public_key();
        assert_eq!(
            pk.to_sec1_compressed(),
            AffinePoint::generator().to_sec1_compressed()
        );
    }

    #[test]
    fn rfc6979_published_vectors() {
        let sk = key_one();
        let pk = sk.public_key();
        for (msg, r, s) in [
            (SATOSHI_MSG, SATOSHI_R, SATOSHI_S),
            (RAIN_MSG, RAIN_R, RAIN_S),
        ] {
            let sig = sk.sign::<Sha256>(msg).unwrap();
            // The published vectors are the low-S form.
            let sig = sig.to_low_s();
            assert_eq!(sig.r_bytes(), hex32(r), "r mismatch for {msg:?}");
            assert_eq!(sig.s_bytes(), hex32(s), "s mismatch for {msg:?}");
            pk.verify::<Sha256>(msg, &sig).unwrap();

            // Cross-check the same literals against the boxed implementation.
            #[cfg(feature = "alloc")]
            {
                use crate::ec::boxed::BoxedEcdsaPrivateKey;
                use crate::ec::curves::CurveId;
                let boxed =
                    BoxedEcdsaPrivateKey::from_bytes(CurveId::Secp256k1, &sk.to_bytes()).unwrap();
                let bsig = boxed
                    .sign::<Sha256>(msg)
                    .unwrap()
                    .to_low_s(CurveId::Secp256k1);
                assert_eq!(bsig.to_bytes(CurveId::Secp256k1), sig.to_bytes());
            }
        }
    }

    // --- Determinism cross-check against the boxed runtime path --------------

    #[test]
    #[cfg(feature = "alloc")]
    fn matches_boxed_implementation() {
        use crate::bignum::BoxedUint;
        use crate::ec::boxed::{BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, BoxedEcdsaSignature};
        use crate::ec::curves::CurveId;
        let curve = CurveId::Secp256k1;
        let mut rng = HmacDrbg::<Sha256>::new(b"secp256k1-ecdsa-vs-boxed", b"nonce", &[]);
        for i in 0..24u32 {
            let sk = Secp256k1EcdsaPrivateKey::generate(&mut rng);
            let boxed = BoxedEcdsaPrivateKey::from_bytes(curve, &sk.to_bytes()).unwrap();
            let pk = sk.public_key();
            let bpk = boxed.public_key();
            assert_eq!(bpk.to_sec1(), pk.to_sec1().to_vec());
            assert_eq!(
                BoxedEcdsaPublicKey::from_sec1(curve, &pk.to_sec1_compressed())
                    .unwrap()
                    .to_sec1(),
                pk.to_sec1().to_vec()
            );

            let msg = [i as u8, (i >> 8) as u8, 0xC0, 0xDE];
            // Deterministic: byte-identical (raw, non-normalised) signatures
            // under both SHA-256 and a wider digest (truncation path).
            let sig = sk.sign::<Sha256>(&msg).unwrap();
            let bsig = boxed.sign::<Sha256>(&msg).unwrap();
            assert_eq!(
                sig.to_bytes().to_vec(),
                bsig.to_bytes(curve),
                "sha256 ({i})"
            );
            let sig512 = sk.sign::<Sha512>(&msg).unwrap();
            let bsig512 = boxed.sign::<Sha512>(&msg).unwrap();
            assert_eq!(
                sig512.to_bytes().to_vec(),
                bsig512.to_bytes(curve),
                "sha512 ({i})"
            );

            // Each verifies the other's signatures.
            bpk.verify::<Sha256>(
                &msg,
                &BoxedEcdsaSignature::from_components(
                    BoxedUint::from_be_bytes(&sig.r_bytes()),
                    BoxedUint::from_be_bytes(&sig.s_bytes()),
                ),
            )
            .unwrap();
            let raw: [u8; 64] = bsig.to_bytes(curve).try_into().unwrap();
            pk.verify::<Sha256>(&msg, &Secp256k1EcdsaSignature::from_bytes(&raw))
                .unwrap();

            // Recoverable signing agrees too (signature and recid).
            let (rsig, recid) = sk.sign_recoverable::<Sha256>(&msg).unwrap();
            let (brsig, brecid) = boxed.sign_recoverable::<Sha256>(&msg).unwrap();
            assert_eq!(rsig.to_bytes().to_vec(), brsig.to_bytes(curve));
            assert_eq!(recid, brecid);
            assert_eq!(rsig.recover::<Sha256>(&msg, recid).unwrap(), pk);
            assert_eq!(
                brsig
                    .recover::<Sha256>(curve, &msg, recid)
                    .unwrap()
                    .to_sec1(),
                pk.to_sec1().to_vec()
            );
        }
    }

    // --- Round trips ---------------------------------------------------------

    #[test]
    fn sign_verify_round_trips() {
        let mut rng = HmacDrbg::<Sha256>::new(b"secp256k1-ecdsa-roundtrip", b"nonce", &[]);
        for i in 0..32u32 {
            let sk = Secp256k1EcdsaPrivateKey::generate(&mut rng);
            let pk = sk.public_key();
            let msg = [i as u8, (i >> 8) as u8, 0xA5, 0x5A];

            let sig = sk.sign::<Sha256>(&msg).unwrap();
            pk.verify::<Sha256>(&msg, &sig).unwrap();
            // sign_prehash / verify_prehash agree with the message forms.
            let digest = Sha256::digest(&msg);
            let by_hash = sk.sign_prehash::<Sha256>(digest.as_ref()).unwrap();
            assert_eq!(by_hash, sig);
            pk.verify_prehash(digest.as_ref(), &sig).unwrap();
            // The malleable twin verifies; the low-S form is unique.
            let twin = Secp256k1EcdsaSignature {
                r: sig.r,
                s: Scalar::order().wrapping_sub(&sig.s),
            };
            pk.verify::<Sha256>(&msg, &twin).unwrap();
            assert_ne!(sig.is_low_s(), twin.is_low_s());
            assert_eq!(sig.to_low_s(), twin.to_low_s());
            assert!(sig.to_low_s().is_low_s());

            // Key and signature byte encodings round-trip.
            assert_eq!(
                Secp256k1EcdsaPrivateKey::from_bytes(&sk.to_bytes())
                    .unwrap()
                    .public_key(),
                pk
            );
            assert_eq!(
                Secp256k1EcdsaPublicKey::from_sec1(&pk.to_sec1()).unwrap(),
                pk
            );
            assert_eq!(
                Secp256k1EcdsaPublicKey::from_sec1(&pk.to_sec1_compressed()).unwrap(),
                pk
            );
            assert_eq!(Secp256k1EcdsaSignature::from_bytes(&sig.to_bytes()), sig);
            assert_eq!(
                Secp256k1EcdsaSignature::from_components(&sig.r_bytes(), &sig.s_bytes()),
                sig
            );
            let mut concat = [0u8; 64];
            concat[..32].copy_from_slice(&sig.r_bytes());
            concat[32..].copy_from_slice(&sig.s_bytes());
            assert_eq!(concat, sig.to_bytes());
        }
    }

    #[test]
    fn recoverable_round_trips_and_rejects_wrong_recid() {
        let mut rng = HmacDrbg::<Sha256>::new(b"secp256k1-ecdsa-recover", b"nonce", &[]);
        for i in 0..16u32 {
            let sk = Secp256k1EcdsaPrivateKey::generate(&mut rng);
            let pk = sk.public_key();
            let msg = [i as u8, 0x42];
            let (sig, recid) = sk.sign_recoverable::<Sha256>(&msg).unwrap();
            assert!(sig.is_low_s());
            assert!(recid <= 1, "recid 2/3 is astronomically unlikely");
            pk.verify::<Sha256>(&msg, &sig).unwrap();
            assert_eq!(sig.recover::<Sha256>(&msg, recid).unwrap(), pk);
            // The complementary parity recovers a *different* key.
            let flipped = sig.recover::<Sha256>(&msg, recid ^ 1);
            assert!(flipped.is_err() || flipped.unwrap() != pk);
            // The overflow ids cannot apply to this r (r ≥ p − n).
            assert_eq!(
                sig.recover::<Sha256>(&msg, recid | 2),
                Err(Error::Verification)
            );
            assert_eq!(sig.recover::<Sha256>(&msg, 4), Err(Error::InvalidInput));
        }
    }

    // Public-key recovery against a published go-ethereum vector
    // (crypto/signature_test.go): Ecrecover(hash, r‖s‖v) == uncompressed key.
    #[test]
    fn ecrecover_ethereum_vector() {
        let msg = hex32("ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008");
        let r = hex32("90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e54998");
        let s = hex32("4a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc93");
        let sig = Secp256k1EcdsaSignature::from_components(&r, &s);
        let pk = sig.recover_prehash(&msg, 1).unwrap();
        let expected = from_hex::<65>(
            "04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f158781098\
             80a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652",
        );
        assert_eq!(pk.to_sec1(), expected);
        pk.verify_prehash(&msg, &sig).unwrap();
        let other = sig.recover_prehash(&msg, 0).unwrap();
        assert_ne!(other, pk);
    }

    // --- Negatives -----------------------------------------------------------

    #[test]
    fn verify_rejects_bad_inputs() {
        let sk = key_one();
        let pk = sk.public_key();
        let sig = sk.sign::<Sha256>(SATOSHI_MSG).unwrap();
        let n = be32(&Scalar::order());

        // Wrong message, wrong key, tampered r / s, swapped halves.
        assert_eq!(
            pk.verify::<Sha256>(b"satoshi nakamoto", &sig),
            Err(Error::Verification)
        );
        let mut rng = HmacDrbg::<Sha256>::new(b"secp256k1-ecdsa-neg", b"nonce", &[]);
        let other = Secp256k1EcdsaPrivateKey::generate(&mut rng).public_key();
        assert_eq!(
            other.verify::<Sha256>(SATOSHI_MSG, &sig),
            Err(Error::Verification)
        );
        let mut raw = sig.to_bytes();
        raw[0] ^= 1;
        assert!(
            pk.verify::<Sha256>(SATOSHI_MSG, &Secp256k1EcdsaSignature::from_bytes(&raw))
                .is_err()
        );
        let mut raw = sig.to_bytes();
        raw[63] ^= 1;
        assert!(
            pk.verify::<Sha256>(SATOSHI_MSG, &Secp256k1EcdsaSignature::from_bytes(&raw))
                .is_err()
        );
        let swapped = Secp256k1EcdsaSignature::from_components(&sig.s_bytes(), &sig.r_bytes());
        assert!(pk.verify::<Sha256>(SATOSHI_MSG, &swapped).is_err());

        // r = 0, s = 0, r = n, s = n, s = n + 1 (all outside [1, n-1]).
        let zero = [0u8; 32];
        let mut n_plus_1 = n;
        n_plus_1[31] += 1;
        for (r, s) in [
            (zero, sig.s_bytes()),
            (sig.r_bytes(), zero),
            (n, sig.s_bytes()),
            (sig.r_bytes(), n),
            (sig.r_bytes(), n_plus_1),
            ([0xff; 32], sig.s_bytes()),
        ] {
            let bad = Secp256k1EcdsaSignature::from_components(&r, &s);
            assert_eq!(
                pk.verify::<Sha256>(SATOSHI_MSG, &bad),
                Err(Error::Verification)
            );
            assert_eq!(
                bad.recover::<Sha256>(SATOSHI_MSG, 0),
                Err(Error::Verification)
            );
        }
    }

    #[test]
    fn from_bytes_range_checks() {
        let n = be32(&Scalar::order());
        assert_eq!(
            Secp256k1EcdsaPrivateKey::from_bytes(&[0u8; 32]).err(),
            Some(Error::InvalidInput)
        );
        assert_eq!(
            Secp256k1EcdsaPrivateKey::from_bytes(&n).err(),
            Some(Error::InvalidInput)
        );
        assert_eq!(
            Secp256k1EcdsaPrivateKey::from_bytes(&[0xff; 32]).err(),
            Some(Error::InvalidInput)
        );
        // n − 1 is the largest valid scalar.
        let mut n_minus_1 = n;
        n_minus_1[31] -= 1;
        let sk = Secp256k1EcdsaPrivateKey::from_bytes(&n_minus_1).unwrap();
        assert_eq!(sk.to_bytes(), n_minus_1);
        // (n − 1)·G = −G.
        let pk = sk.public_key();
        assert_eq!(pk.to_sec1()[1..33], AffinePoint::generator().x_bytes());
        assert_ne!(pk.to_sec1()[33..], AffinePoint::generator().y_bytes());
    }

    #[test]
    fn from_sec1_rejects_invalid_points() {
        let pk = key_one().public_key();
        // Off-curve (perturbed Y), bad tag, bad lengths, X ≥ p.
        let mut sec1 = pk.to_sec1();
        sec1[64] ^= 1;
        assert_eq!(
            Secp256k1EcdsaPublicKey::from_sec1(&sec1),
            Err(Error::InvalidInput)
        );
        let mut sec1 = pk.to_sec1();
        sec1[0] = 0x05;
        assert_eq!(
            Secp256k1EcdsaPublicKey::from_sec1(&sec1),
            Err(Error::Malformed)
        );
        assert_eq!(
            Secp256k1EcdsaPublicKey::from_sec1(&pk.to_sec1()[..64]),
            Err(Error::Malformed)
        );
        assert_eq!(
            Secp256k1EcdsaPublicKey::from_sec1(&pk.to_sec1_compressed()[..32]),
            Err(Error::Malformed)
        );
        assert_eq!(
            Secp256k1EcdsaPublicKey::from_sec1(&[]),
            Err(Error::Malformed)
        );
        let mut big = [0xffu8; 33];
        big[0] = 0x02;
        assert_eq!(
            Secp256k1EcdsaPublicKey::from_sec1(&big),
            Err(Error::InvalidInput)
        );
        // x = 5 has no square root on secp256k1 (a non-residue abscissa).
        let mut nores = [0u8; 33];
        nores[0] = 0x02;
        nores[32] = 5;
        assert_eq!(
            Secp256k1EcdsaPublicKey::from_sec1(&nores),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    #[cfg(all(feature = "der", feature = "alloc"))]
    fn der_signature_roundtrip_and_strictness() {
        let sk = key_one();
        let pk = sk.public_key();
        let sig = sk.sign::<Sha256>(SATOSHI_MSG).unwrap();
        let der = sig.to_der();
        assert_eq!(der[0], 0x30);
        assert_eq!(Secp256k1EcdsaSignature::from_der(&der).unwrap(), sig);
        pk.verify::<Sha256>(
            SATOSHI_MSG,
            &Secp256k1EcdsaSignature::from_der(&der).unwrap(),
        )
        .unwrap();
        // Agrees with the boxed encoder byte-for-byte.
        {
            use crate::ec::boxed::BoxedEcdsaPrivateKey;
            use crate::ec::curves::CurveId;
            let boxed =
                BoxedEcdsaPrivateKey::from_bytes(CurveId::Secp256k1, &sk.to_bytes()).unwrap();
            assert_eq!(
                boxed
                    .sign::<Sha256>(SATOSHI_MSG)
                    .unwrap()
                    .to_der(CurveId::Secp256k1),
                der
            );
        }
        // Garbage, trailing bytes, a non-minimal INTEGER, and an over-wide
        // component are all rejected.
        assert!(Secp256k1EcdsaSignature::from_der(&[0x30, 0x00]).is_err());
        let mut trailing = der.clone();
        trailing.push(0x00);
        assert!(Secp256k1EcdsaSignature::from_der(&trailing).is_err());
        let padded = crate::der::encode_sequence(
            &[
                alloc::vec![0x02, 0x02, 0x00, 0x01],
                crate::der::encode_integer(&sig.s_bytes()),
            ]
            .concat(),
        );
        assert_eq!(
            Secp256k1EcdsaSignature::from_der(&padded),
            Err(Error::Malformed)
        );
        let wide = crate::der::encode_sequence(
            &[
                crate::der::encode_integer(&[0x7f; 40]),
                crate::der::encode_integer(&sig.s_bytes()),
            ]
            .concat(),
        );
        assert_eq!(
            Secp256k1EcdsaSignature::from_der(&wide),
            Err(Error::Malformed)
        );
    }
}
