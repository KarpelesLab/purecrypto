//! ECDSA (SEC 1 §4.1, ANSI X9.62) on the binary curves.
//!
//! Signing derives the nonce per RFC 6979 (with `qlen = bit_len(n)`), as the
//! prime-field [`boxed`](crate::ec::boxed) ECDSA does, computes `k·G` on the
//! constant-time ladder and does the arithmetic modulo `n` with the crate's
//! constant-time Montgomery multiplication and binary-GCD inversion. The
//! x-coordinate of `k·G` is a field element, i.e. a bit string, taken as an
//! integer (SEC 1 §2.3.9) and reduced modulo `n` — a full reduction, since
//! `x < 2^m` can exceed `n` by the cofactor's factor.
//!
//! Verification is variable time: `u₁·G + u₂·Q` from two ladders and one
//! affine addition.

use super::curve::{Curve, Point, limbs_is_zero, limbs_lt};
use super::field::{Fe, Limbs, MAX_LIMBS};
use super::{BinaryCurveId, BinaryPrivateKey, BinaryPublicKey, Error, limbs_from_be, limbs_to_be};
use crate::bignum::{BoxedMontModulus, BoxedUint, inv_mod_odd_ct_boxed};
use crate::ec::boxed::{bits2int, generate_k};
use crate::hash::Digest;
use crate::zeroize::Zeroize;
use alloc::vec::Vec;

/// An ECDSA signature `(r, s)` on a binary curve. Both halves are known to
/// fit the curve's scalar width ([`BinaryCurveId::scalar_len`]); the range
/// `[1, n − 1]` is the verifier's check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BinarySignature {
    curve: BinaryCurveId,
    r: Limbs,
    s: Limbs,
}

/// `bytes` as limbs when its magnitude fits `curve`'s scalar width.
fn component(curve: BinaryCurveId, bytes: &[u8]) -> Result<Limbs, Error> {
    let len = curve.scalar_len();
    let lead = bytes.iter().take_while(|&&b| b == 0).count();
    if bytes.len() - lead > len {
        return Err(Error::Malformed);
    }
    limbs_from_be(bytes).ok_or(Error::Malformed)
}

impl BinarySignature {
    /// Builds a signature from big-endian `r` and `s` (leading zeros
    /// allowed). Fails when either is wider than the curve's scalar.
    pub fn from_components(curve: BinaryCurveId, r: &[u8], s: &[u8]) -> Result<Self, Error> {
        Ok(BinarySignature {
            curve,
            r: component(curve, r)?,
            s: component(curve, s)?,
        })
    }

    /// Parses the fixed-width `r || s` form (`2 · scalar_len` bytes).
    pub fn from_bytes(curve: BinaryCurveId, bytes: &[u8]) -> Result<Self, Error> {
        let len = curve.scalar_len();
        if bytes.len() != 2 * len {
            return Err(Error::Malformed);
        }
        Self::from_components(curve, &bytes[..len], &bytes[len..])
    }

    /// Parses a strict-DER `Ecdsa-Sig-Value` (`SEQUENCE { r INTEGER, s
    /// INTEGER }`) for `curve`: non-minimal or negative integers, trailing
    /// data, and components wider than the curve's scalar are rejected.
    pub fn from_der(curve: BinaryCurveId, der: &[u8]) -> Result<Self, Error> {
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
        Self::from_components(curve, r, s)
    }

    /// The curve the signature was made on (or parsed for).
    pub fn curve(&self) -> BinaryCurveId {
        self.curve
    }

    /// `r`, big-endian, [`BinaryCurveId::scalar_len`] bytes.
    pub fn r_bytes(&self) -> Vec<u8> {
        limbs_to_be(&self.r, self.curve.scalar_len())
    }

    /// `s`, big-endian, [`BinaryCurveId::scalar_len`] bytes.
    pub fn s_bytes(&self) -> Vec<u8> {
        limbs_to_be(&self.s, self.curve.scalar_len())
    }

    /// The fixed-width `r || s` form.
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.r_bytes(), self.s_bytes()].concat()
    }

    /// The DER `Ecdsa-Sig-Value`.
    pub fn to_der(&self) -> Vec<u8> {
        use crate::der::{encode_integer, encode_sequence};
        encode_sequence(
            &[
                encode_integer(&self.r_bytes()),
                encode_integer(&self.s_bytes()),
            ]
            .concat(),
        )
    }
}

/// The limbs of `n`'s width, as a [`BoxedUint`] (a copy; `v` may be secret).
fn to_boxed(c: &Curve, v: &Limbs) -> BoxedUint {
    BoxedUint::from_limbs(v[..c.n_bits.div_ceil(64)].to_vec())
}

/// A [`BoxedUint`] below `n` back to limbs (a straight copy).
fn to_limbs(v: &BoxedUint) -> Limbs {
    let mut out = [0u64; MAX_LIMBS];
    for (dst, src) in out.iter_mut().zip(v.as_limbs()) {
        *dst = *src;
    }
    out
}

/// A field element as the integer of its bit string (SEC 1 §2.3.9).
fn fe_to_boxed(x: &Fe) -> BoxedUint {
    BoxedUint::from_limbs(x.0.to_vec())
}

impl BinaryPrivateKey {
    /// Signs `msg`, hashing with `D` and deriving the nonce per RFC 6979.
    pub fn sign<D: Digest>(&self, msg: &[u8]) -> Result<BinarySignature, Error> {
        self.sign_prehash::<D>(D::digest(msg).as_ref())
    }

    /// Signs an already-computed digest `prehash`, which is truncated to
    /// the bit length of `n` (SEC 1 §4.1.3 step 5). `D` is the HMAC hash of
    /// the RFC 6979 nonce derivation — pass the hash that produced
    /// `prehash`, so the signature matches [`sign::<D>`](Self::sign).
    ///
    /// Fails (with [`Error::InvalidInput`]) only in the negligible case
    /// `r = 0` or `s = 0`.
    pub fn sign_prehash<D: Digest>(&self, prehash: &[u8]) -> Result<BinarySignature, Error> {
        let c = self.curve.curve();
        let n = to_boxed(c, &c.n);
        let modn = BoxedMontModulus::new(&n);
        let qlen = c.n_bits;
        let mut d = to_boxed(c, &self.d);
        let z = modn.reduce(&bits2int(prehash, qlen));
        let mut k = generate_k::<D>(&d, prehash, &n, c.scalar_len(), qlen);

        let mut kl = to_limbs(&k);
        let mut big_r: Point = c.mul(&kl, &c.generator());
        kl.zeroize();
        // `k ∈ [1, n − 1]`, so `k·G` is finite; `r` is published.
        let mut x = fe_to_boxed(&big_r.x);
        big_r.zeroize();
        let r = modn.reduce(&x);
        x.zeroize();
        let r_zero = r.ct_is_zero().declassify();

        // The presence flag is public (and always set: `n` is prime).
        let mut k_inv = inv_mod_odd_ct_boxed(&k, &n)
            .into_public_option()
            .expect("n is prime and k ∈ [1, n − 1]");
        let mut rd = modn.mul_mod(&r, &d);
        let mut z_rd = modn.add_mod(&z, &rd);
        let s = modn.mul_mod(&k_inv, &z_rd);
        // `k` alone recovers `d = (s·k − z)·r⁻¹`: wipe every intermediate.
        k.zeroize();
        k_inv.zeroize();
        rd.zeroize();
        z_rd.zeroize();
        d.zeroize();
        if r_zero || s.ct_is_zero().declassify() {
            return Err(Error::InvalidInput);
        }
        // The signature is public from here.
        crate::ct::declassify_val(r.as_limbs());
        crate::ct::declassify_val(s.as_limbs());
        Ok(BinarySignature {
            curve: self.curve,
            r: to_limbs(&r),
            s: to_limbs(&s),
        })
    }
}

impl BinaryPublicKey {
    /// Verifies `sig` over `msg`, hashing with `D`.
    pub fn verify<D: Digest>(&self, msg: &[u8], sig: &BinarySignature) -> Result<(), Error> {
        self.verify_prehash(D::digest(msg).as_ref(), sig)
    }

    /// Verifies `sig` over the digest `prehash` (truncated to the bit
    /// length of `n`). A signature parsed for another curve, or with `r` or
    /// `s` outside `[1, n − 1]`, fails with [`Error::Verification`].
    pub fn verify_prehash(&self, prehash: &[u8], sig: &BinarySignature) -> Result<(), Error> {
        let c = self.curve.curve();
        let in_range = |v: &Limbs| !bool::from(limbs_is_zero(v)) && bool::from(limbs_lt(v, &c.n));
        if sig.curve != self.curve || !in_range(&sig.r) || !in_range(&sig.s) {
            return Err(Error::Verification);
        }
        let n = to_boxed(c, &c.n);
        let modn = BoxedMontModulus::new(&n);
        let r = to_boxed(c, &sig.r);
        let z = modn.reduce(&bits2int(prehash, c.n_bits));
        // `n` is prime and `s ∈ [1, n − 1]`, so the inverse exists.
        let w = inv_mod_odd_ct_boxed(&to_boxed(c, &sig.s), &n)
            .into_option()
            .ok_or(Error::Verification)?;
        let u1 = to_limbs(&modn.mul_mod(&z, &w));
        let u2 = to_limbs(&modn.mul_mod(&r, &w));
        let sum = c.add_vartime(&c.mul(&u1, &c.generator()), &c.mul(&u2, &self.point));
        if bool::from(sum.inf) {
            return Err(Error::Verification);
        }
        if modn.reduce(&fe_to_boxed(&sum.x)) == r {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha1, Sha256, Sha512};
    use crate::rng::HmacDrbg;

    #[test]
    fn sign_verify_round_trip_on_every_curve() {
        let mut rng = HmacDrbg::<Sha256>::new(b"binary-ecdsa", b"n", &[]);
        for curve in BinaryCurveId::ALL {
            let sk = BinaryPrivateKey::generate(curve, &mut rng);
            let pk = sk.public_key();
            let sig = sk.sign::<Sha256>(b"hello").unwrap();
            assert_eq!(sig.curve(), curve);
            pk.verify::<Sha256>(b"hello", &sig).unwrap();
            // Deterministic.
            assert_eq!(sk.sign::<Sha256>(b"hello").unwrap(), sig);
            assert!(pk.verify::<Sha256>(b"hellp", &sig).is_err(), "{curve}");
            // Encodings round-trip.
            let raw = sig.to_bytes();
            assert_eq!(raw.len(), 2 * curve.scalar_len());
            assert_eq!(BinarySignature::from_bytes(curve, &raw).unwrap(), sig);
            assert_eq!(
                BinarySignature::from_der(curve, &sig.to_der()).unwrap(),
                sig
            );
            // A flipped s, s = 0 and s = n all fail.
            let mut bad = raw.clone();
            *bad.last_mut().unwrap() ^= 1;
            let bad = BinarySignature::from_bytes(curve, &bad).unwrap();
            assert!(pk.verify::<Sha256>(b"hello", &bad).is_err());
            let n = curve.order();
            let zero = alloc::vec![0u8; curve.scalar_len()];
            for s in [&zero, &n] {
                let bad = BinarySignature::from_components(curve, &sig.r_bytes(), s).unwrap();
                assert_eq!(
                    pk.verify::<Sha256>(b"hello", &bad),
                    Err(Error::Verification)
                );
            }
            // Another key does not verify.
            let other = BinaryPrivateKey::generate(curve, &mut rng).public_key();
            assert!(other.verify::<Sha256>(b"hello", &sig).is_err());
        }
    }

    #[test]
    fn wide_digests_are_truncated_and_short_ones_accepted() {
        let mut rng = HmacDrbg::<Sha256>::new(b"binary-ecdsa-trunc", b"n", &[]);
        for curve in [BinaryCurveId::Sect113r1, BinaryCurveId::Sect571r1] {
            let sk = BinaryPrivateKey::generate(curve, &mut rng);
            let pk = sk.public_key();
            let s512 = sk.sign::<Sha512>(b"m").unwrap();
            pk.verify::<Sha512>(b"m", &s512).unwrap();
            let s1 = sk.sign::<Sha1>(b"m").unwrap();
            pk.verify::<Sha1>(b"m", &s1).unwrap();
        }
    }

    #[test]
    fn signature_codecs_reject_bad_input() {
        let curve = BinaryCurveId::Sect163k1;
        let len = curve.scalar_len();
        assert!(BinarySignature::from_bytes(curve, &alloc::vec![1u8; 2 * len - 1]).is_err());
        // A component one byte wider than the scalar.
        let mut wide = alloc::vec![0u8; len + 1];
        wide[0] = 1;
        assert!(BinarySignature::from_components(curve, &wide, &[1]).is_err());
        // Leading zeros are fine.
        assert!(BinarySignature::from_components(curve, &[0, 0, 1], &[1]).is_ok());
        // Trailing data after the DER.
        let sig = BinarySignature::from_components(curve, &[1], &[2]).unwrap();
        let mut der = sig.to_der();
        assert_eq!(der, [0x30, 6, 2, 1, 1, 2, 1, 2]);
        der.push(0);
        assert!(BinarySignature::from_der(curve, &der).is_err());
    }
}
