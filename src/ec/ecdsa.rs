//! ECDSA over NIST P-256, with RFC 6979 deterministic nonces.

use super::Error;
use super::p256::{Fe, P256, random_scalar};
use crate::bignum::MontModulus;
use crate::ct::{ConstantTimeEq, ConstantTimeLess};
use crate::hash::{Digest, Hmac};
use crate::rng::RngCore;

/// A P-256 ECDSA private key (a scalar in `[1, n-1]`).
#[derive(Clone)]
pub struct EcdsaPrivateKey {
    d: Fe,
}

/// A P-256 ECDSA public key (an affine curve point).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EcdsaPublicKey {
    x: Fe,
    y: Fe,
}

/// A P-256 ECDSA signature `(r, s)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    r: Fe,
    s: Fe,
}

/// Interprets the leftmost 256 bits of `hash` as an integer (RFC 6979
/// `bits2int` for a 256-bit group).
fn bits2int(hash: &[u8]) -> Fe {
    if hash.len() >= 32 {
        Fe::from_be_bytes(&hash[..32])
    } else {
        Fe::from_be_bytes(hash)
    }
}

/// Returns true iff `1 <= v < n`.
fn in_range(v: &Fe, n: &Fe) -> bool {
    !bool::from(v.is_zero()) && bool::from(v.ct_lt(n))
}

impl EcdsaPrivateKey {
    /// Creates a private key from a 32-byte big-endian scalar, checking it is
    /// in `[1, n-1]`.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, Error> {
        let d = Fe::from_be_bytes(bytes);
        if in_range(&d, &P256::order()) {
            Ok(EcdsaPrivateKey { d })
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// The 32-byte big-endian scalar.
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.d.write_be_bytes(&mut out);
        out
    }

    /// Generates a new private key from `rng`.
    pub fn generate<R: RngCore>(rng: &mut R) -> EcdsaPrivateKey {
        EcdsaPrivateKey {
            d: random_scalar(rng),
        }
    }

    /// Derives the public key `d * G`.
    pub fn public_key(&self) -> EcdsaPublicKey {
        let curve = P256::new();
        let (x, y) = curve
            .to_affine(&curve.mul_generator(&self.d))
            .expect("d in [1,n-1] so d*G is not the identity");
        EcdsaPublicKey { x, y }
    }

    /// Signs `msg`, hashing with `D` (use SHA-256 for the standard P-256
    /// profile). The nonce is derived deterministically per RFC 6979.
    pub fn sign<D: Digest>(&self, msg: &[u8]) -> Result<Signature, Error> {
        let curve = P256::new();
        let n = P256::order();
        let fq = MontModulus::new(n);

        let hash = D::digest(msg);
        let z = bits2int(hash.as_ref()).reduce(&n);
        let k = generate_k::<D>(&self.d, hash.as_ref(), &n);

        // r = (k*G).x mod n
        let r = curve
            .to_affine(&curve.mul_generator(&k))
            .ok_or(Error::InvalidInput)?
            .0
            .reduce(&n);
        if bool::from(r.is_zero()) {
            return Err(Error::InvalidInput);
        }

        // s = k^-1 (z + r*d) mod n.
        //
        // The nonce `k` is secret, so the inversion MUST be constant time. We
        // use Fermat's little theorem (`k^{n-2} mod n`, where `n` is the prime
        // order of the base point) via the constant-time Montgomery ladder,
        // NOT the variable-time extended-Euclidean `inv_mod` — leaking `k`
        // through timing would let an attacker recover the long-term key
        // `d = (s·k − z)·r^{-1} mod n` (Brumley–Tuveri, "Remote Timing Attacks
        // Are Still Practical").
        let k_inv = fq.inv_prime(&k);
        let z_rd = fq.add_mod(&z, &fq.mul_mod(&r, &self.d));
        let s = fq.mul_mod(&k_inv, &z_rd);
        if bool::from(s.is_zero()) {
            return Err(Error::InvalidInput);
        }
        Ok(Signature { r, s })
    }
}

impl EcdsaPublicKey {
    /// Parses an uncompressed SEC1 point (`0x04 || X || Y`, 65 bytes),
    /// rejecting points not on the curve.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 65 || bytes[0] != 0x04 {
            return Err(Error::Malformed);
        }
        let x = Fe::from_be_bytes(&bytes[1..33]);
        let y = Fe::from_be_bytes(&bytes[33..65]);
        // Coordinates MUST be reduced — Montgomery multiplication's invariant
        // requires `< p` operands, and the curve-membership check downstream
        // relies on it. Without this guard, an attacker can submit `x` or `y`
        // in the [p, 2^256) range and bypass on-curve checks.
        let p = P256::field_modulus();
        if !bool::from(x.ct_lt(&p)) || !bool::from(y.ct_lt(&p)) {
            return Err(Error::InvalidInput);
        }
        let curve = P256::new();
        if !curve.is_on_curve(&x, &y) {
            return Err(Error::InvalidInput);
        }
        Ok(EcdsaPublicKey { x, y })
    }

    /// The affine coordinates `(x, y)`.
    pub(crate) fn coordinates(&self) -> (Fe, Fe) {
        (self.x, self.y)
    }

    /// Builds a public key directly from affine coordinates (used internally
    /// after a scalar multiplication that is known to be on-curve).
    pub(crate) fn from_coordinates(x: Fe, y: Fe) -> Self {
        EcdsaPublicKey { x, y }
    }

    /// Encodes the key as an uncompressed SEC1 point (`0x04 || X || Y`).
    pub fn to_sec1(&self) -> [u8; 65] {
        let mut out = [0u8; 65];
        out[0] = 0x04;
        self.x.write_be_bytes(&mut out[1..33]);
        self.y.write_be_bytes(&mut out[33..65]);
        out
    }

    /// Verifies `sig` over `msg`, hashing with `D`.
    pub fn verify<D: Digest>(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        let curve = P256::new();
        let n = P256::order();
        let fq = MontModulus::new(n);

        if !in_range(&sig.r, &n) || !in_range(&sig.s, &n) {
            return Err(Error::Verification);
        }

        let hash = D::digest(msg);
        let z = bits2int(hash.as_ref()).reduce(&n);
        // Public-side inversion: `sig.s` is in [1, n-1] (checked above), so
        // Fermat works and is consistent with the constant-time discipline
        // used elsewhere (no leakage matters here, since `sig.s` is public).
        let w = fq.inv_prime(&sig.s);
        let u1 = fq.mul_mod(&z, &w);
        let u2 = fq.mul_mod(&sig.r, &w);

        let point = curve.lift_affine(&self.x, &self.y);
        let sum = curve.point_add(&curve.mul_generator(&u1), &curve.scalar_mul(&u2, &point));
        let (vx, _) = curve.to_affine(&sum).ok_or(Error::Verification)?;
        let v = vx.reduce(&n);

        if bool::from(v.ct_eq(&sig.r)) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

impl Signature {
    /// Builds a signature from raw `(r, s)` 32-byte big-endian halves.
    pub fn from_bytes(bytes: &[u8; 64]) -> Signature {
        Signature {
            r: Fe::from_be_bytes(&bytes[..32]),
            s: Fe::from_be_bytes(&bytes[32..]),
        }
    }

    /// Returns the fixed 64-byte `r || s` encoding.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        self.r.write_be_bytes(&mut out[..32]);
        self.s.write_be_bytes(&mut out[32..]);
        out
    }
}

/// DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` codec — the
/// on-the-wire form used by TLS and X.509 (the fixed `r‖s` form is used by
/// JOSE/raw APIs).
#[cfg(all(feature = "der", feature = "alloc"))]
impl Signature {
    /// Encodes the signature as a DER `Ecdsa-Sig-Value`.
    pub fn to_der(&self) -> alloc::vec::Vec<u8> {
        use crate::der::{encode_integer, encode_sequence};
        let raw = self.to_bytes();
        encode_sequence(&[encode_integer(&raw[..32]), encode_integer(&raw[32..])].concat())
    }

    /// Decodes a DER `Ecdsa-Sig-Value` into a signature, left-padding `r`/`s`
    /// to 32 bytes.
    pub fn from_der(der: &[u8]) -> Result<Signature, Error> {
        use crate::der::Reader;
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence().map_err(|_| Error::Malformed)?;
        let r = seq.read_integer_bytes().map_err(|_| Error::Malformed)?;
        let s = seq.read_integer_bytes().map_err(|_| Error::Malformed)?;
        seq.finish().map_err(|_| Error::Malformed)?;
        reader.finish().map_err(|_| Error::Malformed)?;

        let mut raw = [0u8; 64];
        left_pad_32(r, &mut raw[..32])?;
        left_pad_32(s, &mut raw[32..])?;
        Ok(Signature::from_bytes(&raw))
    }
}

/// Right-aligns a DER `INTEGER`'s magnitude (stripping a leading sign byte)
/// into a 32-byte slot.
#[cfg(all(feature = "der", feature = "alloc"))]
fn left_pad_32(int: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let start = int.iter().position(|&b| b != 0).unwrap_or(int.len());
    let mag = &int[start..];
    if mag.len() > 32 {
        return Err(Error::Malformed);
    }
    out[32 - mag.len()..].copy_from_slice(mag);
    Ok(())
}

/// RFC 6979 deterministic nonce generation for a 256-bit group, using HMAC-`D`.
fn generate_k<D: Digest>(d: &Fe, hash: &[u8], n: &Fe) -> Fe {
    let mut d_oct = [0u8; 32];
    d.write_be_bytes(&mut d_oct);
    // bits2octets(hash) = (bits2int(hash) mod n), 32 bytes.
    let mut h_oct = [0u8; 32];
    bits2int(hash).reduce(n).write_be_bytes(&mut h_oct);

    let mut v = D::zeroed_output();
    for b in v.as_mut() {
        *b = 0x01;
    }
    let mut k = D::zeroed_output(); // all zero

    // K = HMAC_K(V || 0x00 || int2octets(d) || bits2octets(h)); V = HMAC_K(V)
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
        // T = leftmost 256 bits of successive HMAC blocks.
        let mut t = [0u8; 32];
        let mut filled = 0;
        while filled < 32 {
            v = Hmac::<D>::mac(k.as_ref(), v.as_ref());
            let block = v.as_ref();
            let take = (32 - filled).min(block.len());
            t[filled..filled + take].copy_from_slice(&block[..take]);
            filled += take;
        }
        let candidate = bits2int(&t);
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

#[cfg(test)]
mod tests {
    use super::super::p256::fe_from_hex;
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    // RFC 6979 Appendix A.2.5 — P-256, SHA-256.
    const RFC6979_X: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
    const RFC6979_UX: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
    const RFC6979_UY: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

    fn priv_key() -> EcdsaPrivateKey {
        let mut b = [0u8; 32];
        fe_from_hex(RFC6979_X).write_be_bytes(&mut b);
        EcdsaPrivateKey::from_bytes(&b).unwrap()
    }

    #[test]
    fn rfc6979_public_key() {
        let pk = priv_key().public_key();
        assert_eq!(pk.x, fe_from_hex(RFC6979_UX));
        assert_eq!(pk.y, fe_from_hex(RFC6979_UY));
    }

    #[test]
    fn rfc6979_sample_signature() {
        // "sample" / SHA-256 known answer.
        let sig = priv_key().sign::<Sha256>(b"sample").unwrap();
        assert_eq!(
            sig.r,
            fe_from_hex("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716")
        );
        assert_eq!(
            sig.s,
            fe_from_hex("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")
        );
    }

    #[test]
    fn rfc6979_test_signature() {
        // "test" / SHA-256 known answer.
        let sig = priv_key().sign::<Sha256>(b"test").unwrap();
        assert_eq!(
            sig.r,
            fe_from_hex("f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367")
        );
        assert_eq!(
            sig.s,
            fe_from_hex("019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083")
        );
    }

    #[test]
    fn verify_known_signature_and_negatives() {
        let pk = priv_key().public_key();
        let sig = priv_key().sign::<Sha256>(b"sample").unwrap();
        pk.verify::<Sha256>(b"sample", &sig).unwrap();
        // Wrong message.
        assert!(pk.verify::<Sha256>(b"Sample", &sig).is_err());
        // Tampered signature.
        let mut raw = sig.to_bytes();
        raw[0] ^= 1;
        assert!(
            pk.verify::<Sha256>(b"sample", &Signature::from_bytes(&raw))
                .is_err()
        );
    }

    #[test]
    fn der_signature_roundtrip() {
        let sig = priv_key().sign::<Sha256>(b"sample").unwrap();
        let der = sig.to_der();
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert_eq!(Signature::from_der(&der).unwrap(), sig);
        // A DER-decoded signature still verifies.
        let pk = priv_key().public_key();
        pk.verify::<Sha256>(b"sample", &Signature::from_der(&der).unwrap())
            .unwrap();
        // Garbage DER is rejected.
        assert!(Signature::from_der(&[0x30, 0x00]).is_err());
    }

    #[test]
    fn generated_key_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"ecdsa-keygen", b"nonce", &[]);
        let sk = EcdsaPrivateKey::generate(&mut rng);
        let pk = sk.public_key();

        // SEC1 public-key round-trip (validates on-curve check too).
        let sec1 = pk.to_sec1();
        assert_eq!(EcdsaPublicKey::from_sec1(&sec1).unwrap(), pk);

        let sig = sk.sign::<Sha256>(b"hello ecdsa").unwrap();
        pk.verify::<Sha256>(b"hello ecdsa", &sig).unwrap();
    }

    #[test]
    fn rejects_off_curve_point() {
        let mut sec1 = priv_key().public_key().to_sec1();
        sec1[64] ^= 1; // perturb Y
        assert_eq!(EcdsaPublicKey::from_sec1(&sec1), Err(Error::InvalidInput));
    }
}
