//! PKCS#1 (RFC 8017), SPKI (RFC 5280 §4.1.2.7), and PKCS#8 (RFC 5958 §2)
//! DER/PEM serialization for the const-generic RSA keys.

use alloc::string::String;
use alloc::vec::Vec;

use super::{RsaPrivateKey, RsaPublicKey};
use crate::bignum::{Uint, inv_mod};
use crate::ct::{ConstantTimeEq, ConstantTimeLess};
use crate::der::{
    Error, Reader, encode_bit_string, encode_integer, encode_null, encode_octet_string,
    encode_sequence, oid_tlv, parse_oid, pem_decode, pem_encode,
};

const PUBLIC_LABEL: &str = "RSA PUBLIC KEY";
const PRIVATE_LABEL: &str = "RSA PRIVATE KEY";
const SPKI_LABEL: &str = "PUBLIC KEY";
const PKCS8_LABEL: &str = "PRIVATE KEY";

/// DER OID arcs for `rsaEncryption` (RFC 3279 §2.3.1).
const RSA_ENCRYPTION_OID: [u64; 7] = [1, 2, 840, 113549, 1, 1, 1];

/// Encodes the `AlgorithmIdentifier` for rsaEncryption with explicit NULL
/// parameters (the form mandated by RFC 3279 §2.3.1 / enforced on import by
/// fix H-7).
fn rsa_encryption_algid() -> Vec<u8> {
    encode_sequence(&[oid_tlv(&RSA_ENCRYPTION_OID), encode_null()].concat())
}

/// Big-endian bytes of a `Uint` (with leading zeros, which `encode_integer`
/// trims).
fn uint_be<const LIMBS: usize>(u: &Uint<LIMBS>) -> Vec<u8> {
    let mut buf = alloc::vec![0u8; LIMBS * 8];
    u.write_be_bytes(&mut buf);
    buf
}

/// Parses a DER `INTEGER`'s content bytes into a `Uint`, rejecting values that
/// don't fit.
fn int_to_uint<const LIMBS: usize>(content: &[u8]) -> Result<Uint<LIMBS>, Error> {
    let start = content
        .iter()
        .position(|&b| b != 0)
        .unwrap_or(content.len());
    let trimmed = &content[start..];
    if trimmed.len() > LIMBS * 8 {
        return Err(Error::Malformed);
    }
    Ok(Uint::from_be_bytes(trimmed))
}

/// Validates that `(n, e)` form a well-formed RSA public exponent. RFC 8017
/// §3.1 requires `e` coprime to `λ(n)`; without the prime factors we can only
/// enforce the structural shape: `e ≥ 3`, `e` odd, and `e < n`. These three
/// together rule out the degenerate values (`0`, `1`, even, oversized) that a
/// malicious PKCS#1 / SPKI / certificate could otherwise smuggle through and
/// break downstream sign / verify / encrypt math. Mirrors the boxed-key
/// validator in [`super::boxed`].
fn validate_public_exponent<const LIMBS: usize>(
    n: &Uint<LIMBS>,
    e: &Uint<LIMBS>,
) -> Result<(), Error> {
    let three = Uint::<LIMBS>::from_u64(3);
    let e_ge_3 = !bool::from(e.ct_lt(&three));
    let e_odd = bool::from(e.is_odd());
    let e_lt_n = bool::from(e.ct_lt(n));
    if !(e_ge_3 && e_odd && e_lt_n) {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Validates that the parsed PKCS#1 / PKCS#8 private-key components are
/// internally consistent: each prime is `> 1`, `p ≠ q`, and `p · q = n`
/// (RFC 8017 §3.2). Without this check a corrupted (or maliciously crafted)
/// key file with mismatched primes silently slips through and produces wrong
/// signatures, leaks information through the CRT recombination path, and
/// in the worst case enables a Bleichenbacher-style fault on the secret
/// exponent. We reject before the key is constructed. Mirrors the boxed-key
/// validator in [`super::boxed`].
fn validate_private_components<const LIMBS: usize>(
    n: &Uint<LIMBS>,
    p: &Uint<LIMBS>,
    q: &Uint<LIMBS>,
) -> Result<(), Error> {
    let one = Uint::<LIMBS>::ONE;
    let p_gt_1 = !bool::from(p.ct_lt(&one)) && !bool::from(p.ct_eq(&one));
    let q_gt_1 = !bool::from(q.ct_lt(&one)) && !bool::from(q.ct_eq(&one));
    if !(p_gt_1 && q_gt_1) {
        return Err(Error::Malformed);
    }
    if bool::from(p.ct_eq(q)) {
        return Err(Error::Malformed);
    }
    // `p · q == n` requires the full 2·LIMBS-wide product: the low half must
    // equal `n` and the high half must be zero. Using `mul_wide` keeps the
    // check sound even when `p`/`q` straddle the `LIMBS` boundary, which
    // would otherwise silently wrap.
    let (lo, hi) = p.mul_wide(q);
    if !bool::from(hi.ct_eq(&Uint::<LIMBS>::ZERO)) || !bool::from(lo.ct_eq(n)) {
        return Err(Error::Malformed);
    }
    Ok(())
}

impl<const LIMBS: usize> RsaPublicKey<LIMBS> {
    /// Encodes the key as a PKCS#1 `RSAPublicKey` DER structure.
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        let body = [
            encode_integer(&uint_be(self.modulus())),
            encode_integer(&uint_be(self.exponent())),
        ]
        .concat();
        encode_sequence(&body)
    }

    /// Decodes a PKCS#1 `RSAPublicKey` DER structure. Rejects degenerate
    /// public exponents (`e < 3`, `e` even, `e ≥ n`) per the structural
    /// shape check derived from RFC 8017 §3.1.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let n = int_to_uint(seq.read_integer_bytes()?)?;
        let e = int_to_uint(seq.read_integer_bytes()?)?;
        seq.finish()?;
        reader.finish()?;
        validate_public_exponent(&n, &e)?;
        Ok(RsaPublicKey::new(n, e))
    }

    /// Encodes the key as a PKCS#1 PEM document (`-----BEGIN RSA PUBLIC KEY-----`).
    pub fn to_pkcs1_pem(&self) -> String {
        pem_encode(PUBLIC_LABEL, &self.to_pkcs1_der())
    }

    /// Decodes a PKCS#1 PEM public key.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, Error> {
        Self::from_pkcs1_der(&pem_decode(pem, PUBLIC_LABEL)?)
    }

    /// Encodes the key as an X.509 `SubjectPublicKeyInfo` (SPKI) DER
    /// structure (RFC 5280 §4.1.2.7). The AlgorithmIdentifier is
    /// `rsaEncryption` (OID `1.2.840.113549.1.1.1`) with explicit `NULL`
    /// parameters (RFC 3279 §2.3.1); the BIT STRING body is the PKCS#1
    /// `RSAPublicKey` DER produced by [`to_pkcs1_der`](Self::to_pkcs1_der).
    pub fn to_spki_der(&self) -> Vec<u8> {
        encode_sequence(
            &[
                rsa_encryption_algid(),
                encode_bit_string(&self.to_pkcs1_der()),
            ]
            .concat(),
        )
    }

    /// Encodes the key as a PEM `-----BEGIN PUBLIC KEY-----` document
    /// (RFC 7468). Distinct from the legacy `RSA PUBLIC KEY` label which
    /// carries a bare PKCS#1 body.
    pub fn to_spki_pem(&self) -> String {
        pem_encode(SPKI_LABEL, &self.to_spki_der())
    }

    /// Parses an X.509 `SubjectPublicKeyInfo` (SPKI) DER structure for an
    /// RSA public key. Validates that the algorithm OID is `rsaEncryption`,
    /// the parameters field is an explicit `NULL` (strict per RFC 3279
    /// §2.3.1 / fix H-7), and the inner BIT STRING decodes as a valid
    /// PKCS#1 `RSAPublicKey`.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(der);
        let mut outer = reader.read_sequence()?;
        let mut algid = outer.read_sequence()?;
        let alg = parse_oid(algid.read_oid()?)?;
        if alg.as_slice() != RSA_ENCRYPTION_OID {
            return Err(Error::Malformed);
        }
        algid.read_null()?;
        algid.finish()?;
        let key_bits = outer.read_bit_string()?;
        outer.finish()?;
        reader.finish()?;
        Self::from_pkcs1_der(key_bits)
    }

    /// Parses an SPKI PEM document (`-----BEGIN PUBLIC KEY-----`, RFC 7468).
    /// The legacy `RSA PUBLIC KEY` PKCS#1 label is **not** accepted here —
    /// use [`from_pkcs1_pem`](Self::from_pkcs1_pem) for that form.
    pub fn from_spki_pem(pem: &str) -> Result<Self, Error> {
        Self::from_spki_der(&pem_decode(pem, SPKI_LABEL)?)
    }
}

impl<const LIMBS: usize> RsaPrivateKey<LIMBS> {
    /// Encodes the key as a PKCS#1 `RSAPrivateKey` DER structure, including the
    /// CRT parameters (`dP`, `dQ`, `qInv`). Requires a key that carries its
    /// prime factors (i.e. from [`generate`](RsaPrivateKey::generate)).
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        let (p, q) = self.primes();
        let d = self.private_exponent();
        let one = Uint::ONE;
        let dp = d.reduce(&p.wrapping_sub(&one));
        let dq = d.reduce(&q.wrapping_sub(&one));
        let qinv = inv_mod(q, p).unwrap_or(Uint::ZERO);

        let body = [
            encode_integer(&[0]), // version = 0 (two-prime)
            encode_integer(&uint_be(self.modulus())),
            encode_integer(&uint_be(self.exponent())),
            encode_integer(&uint_be(d)),
            encode_integer(&uint_be(p)),
            encode_integer(&uint_be(q)),
            encode_integer(&uint_be(&dp)),
            encode_integer(&uint_be(&dq)),
            encode_integer(&uint_be(&qinv)),
        ]
        .concat();
        encode_sequence(&body)
    }

    /// Decodes a PKCS#1 `RSAPrivateKey` DER structure. The CRT parameters are
    /// read but not retained. Rejects:
    /// - degenerate public exponents (`e < 3`, `e` even, `e ≥ n`),
    /// - primes `≤ 1`,
    /// - `p = q` (resulting in a non-coprime `qInv`),
    /// - `p · q ≠ n` (corruption / fault injection — without this check, the
    ///   CRT recombination path silently produces wrong signatures and can
    ///   leak `d` mod one factor).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let _version = seq.read_integer_bytes()?;
        let n = int_to_uint(seq.read_integer_bytes()?)?;
        let e = int_to_uint(seq.read_integer_bytes()?)?;
        let d = int_to_uint(seq.read_integer_bytes()?)?;
        let p = int_to_uint(seq.read_integer_bytes()?)?;
        let q = int_to_uint(seq.read_integer_bytes()?)?;
        let _dp = seq.read_integer_bytes()?;
        let _dq = seq.read_integer_bytes()?;
        let _qinv = seq.read_integer_bytes()?;
        seq.finish()?;
        reader.finish()?;
        validate_public_exponent(&n, &e)?;
        validate_private_components(&n, &p, &q)?;
        Ok(RsaPrivateKey::from_raw_parts(n, e, d, p, q))
    }

    /// Encodes the key as a PKCS#1 PEM document (`-----BEGIN RSA PRIVATE KEY-----`).
    pub fn to_pkcs1_pem(&self) -> String {
        pem_encode(PRIVATE_LABEL, &self.to_pkcs1_der())
    }

    /// Decodes a PKCS#1 PEM private key.
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, Error> {
        Self::from_pkcs1_der(&pem_decode(pem, PRIVATE_LABEL)?)
    }

    /// Encodes the key as an unencrypted PKCS#8 `PrivateKeyInfo` DER
    /// structure (RFC 5958 §2):
    ///
    /// ```text
    /// PrivateKeyInfo ::= SEQUENCE {
    ///     version INTEGER (0),
    ///     privateKeyAlgorithm AlgorithmIdentifier,  -- rsaEncryption + NULL
    ///     privateKey OCTET STRING                   -- the PKCS#1 DER
    /// }
    /// ```
    ///
    /// Encrypted PKCS#8 (`EncryptedPrivateKeyInfo`, RFC 5958 §3 / PBES2 /
    /// PBKDF2) is intentionally not implemented — wrap with a stream-cipher
    /// AEAD of your own choosing instead.
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        encode_sequence(
            &[
                encode_integer(&[0]),
                rsa_encryption_algid(),
                encode_octet_string(&self.to_pkcs1_der()),
            ]
            .concat(),
        )
    }

    /// Encodes the key as a PKCS#8 PEM document
    /// (`-----BEGIN PRIVATE KEY-----`, RFC 7468). Distinct from the legacy
    /// `RSA PRIVATE KEY` PKCS#1 label.
    pub fn to_pkcs8_pem(&self) -> String {
        pem_encode(PKCS8_LABEL, &self.to_pkcs8_der())
    }

    /// Parses an unencrypted PKCS#8 `PrivateKeyInfo` DER structure for an
    /// RSA private key. Validates `version = 0` (RFC 5958 §2 — the v2
    /// `version = 1` form is rejected), the algorithm OID is `rsaEncryption`
    /// with explicit `NULL` parameters, and the inner OCTET STRING decodes
    /// as a valid PKCS#1 `RSAPrivateKey`.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(der);
        let mut outer = reader.read_sequence()?;
        let version = outer.read_integer_bytes()?;
        if version != [0] {
            return Err(Error::Malformed);
        }
        let mut algid = outer.read_sequence()?;
        let alg = parse_oid(algid.read_oid()?)?;
        if alg.as_slice() != RSA_ENCRYPTION_OID {
            return Err(Error::Malformed);
        }
        algid.read_null()?;
        algid.finish()?;
        let inner = outer.read_octet_string()?;
        outer.finish()?;
        reader.finish()?;
        Self::from_pkcs1_der(inner)
    }

    /// Parses a PKCS#8 PEM document (`-----BEGIN PRIVATE KEY-----`,
    /// RFC 7468).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        Self::from_pkcs8_der(&pem_decode(pem, PKCS8_LABEL)?)
    }

    /// Encrypts the PKCS#8 encoding under PBES2 (RFC 5958 §3 + RFC 8018
    /// §6.2) with caller-supplied parameters, returning the DER-encoded
    /// `EncryptedPrivateKeyInfo`.
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
    /// (`-----BEGIN ENCRYPTED PRIVATE KEY-----`, RFC 7468 §11).
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn to_pkcs8_pem_encrypted(
        &self,
        password: &[u8],
        params: &crate::kdf::pbes2::Pbes2Params,
        rng: &mut impl crate::rng::RngCore,
    ) -> String {
        crate::kdf::pbes2::encrypt_pem(&self.to_pkcs8_der(), password, params, rng)
    }

    /// Parses an `EncryptedPrivateKeyInfo` DER and decrypts it back to a
    /// PKCS#8 RSA private key.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::test_util::rsa_test_key_a;

    #[test]
    fn public_key_der_pem_roundtrip() {
        let pk = rsa_test_key_a().public_key();

        let der = pk.to_pkcs1_der();
        assert_eq!(der[0], 0x30); // SEQUENCE
        assert_eq!(RsaPublicKey::<32>::from_pkcs1_der(&der).unwrap(), pk);

        let pem = pk.to_pkcs1_pem();
        assert_eq!(RsaPublicKey::<32>::from_pkcs1_pem(&pem).unwrap(), pk);
    }

    #[test]
    fn private_key_der_pem_roundtrip() {
        let key = rsa_test_key_a();

        let der = key.to_pkcs1_der();
        let decoded = RsaPrivateKey::<32>::from_pkcs1_der(&der).unwrap();
        assert_eq!(decoded.modulus(), key.modulus());
        assert_eq!(decoded.private_exponent(), key.private_exponent());
        assert_eq!(decoded.primes(), key.primes());

        let pem = key.to_pkcs1_pem();
        let decoded = RsaPrivateKey::<32>::from_pkcs1_pem(&pem).unwrap();
        assert_eq!(decoded.modulus(), key.modulus());
    }

    #[test]
    fn serialized_keys_still_work() {
        // Sign with a key round-tripped through PEM; verify with the public key
        // round-tripped through DER.
        let key = rsa_test_key_a();
        let priv_pem = key.to_pkcs1_pem();
        let pub_der = key.public_key().to_pkcs1_der();
        let priv2 = RsaPrivateKey::<32>::from_pkcs1_pem(&priv_pem).unwrap();
        let pub2 = RsaPublicKey::<32>::from_pkcs1_der(&pub_der).unwrap();

        let sig = priv2.sign_pkcs1v15::<Sha256>(b"serialized").unwrap();
        assert!(pub2.verify_pkcs1v15::<Sha256>(b"serialized", &sig).is_ok());
    }

    // ---- SPKI / PKCS#8 round-trip and reject tests ----

    #[test]
    fn const_generic_spki_der_roundtrip() {
        let pk = rsa_test_key_a().public_key();
        let der = pk.to_spki_der();
        assert_eq!(der[0], 0x30);
        assert_eq!(RsaPublicKey::<32>::from_spki_der(&der).unwrap(), pk);
    }

    #[test]
    fn const_generic_spki_pem_roundtrip() {
        let pk = rsa_test_key_a().public_key();
        let pem = pk.to_spki_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert_eq!(RsaPublicKey::<32>::from_spki_pem(&pem).unwrap(), pk);
    }

    #[test]
    fn const_generic_pkcs8_der_roundtrip() {
        let key = rsa_test_key_a();
        let der = key.to_pkcs8_der();
        assert_eq!(der[0], 0x30);
        let parsed = RsaPrivateKey::<32>::from_pkcs8_der(&der).unwrap();
        assert_eq!(parsed.modulus(), key.modulus());
        assert_eq!(parsed.private_exponent(), key.private_exponent());
        assert_eq!(parsed.primes(), key.primes());
    }

    #[test]
    fn const_generic_pkcs8_pem_roundtrip() {
        let key = rsa_test_key_a();
        let pem = key.to_pkcs8_pem();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        let parsed = RsaPrivateKey::<32>::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(parsed.modulus(), key.modulus());
    }

    /// Cross-implementation interop: the const-generic SPKI must be
    /// byte-equal to the boxed-key SPKI for the same underlying RSA
    /// modulus/exponent pair (and parseable by either parser).
    #[test]
    fn const_generic_spki_matches_boxed() {
        use crate::bignum::BoxedUint;
        use crate::rsa::BoxedRsaPublicKey;
        let pk = rsa_test_key_a().public_key();
        let cg_spki = pk.to_spki_der();
        let mut nb = [0u8; 256];
        pk.modulus().write_be_bytes(&mut nb);
        let mut eb = [0u8; 256];
        pk.exponent().write_be_bytes(&mut eb);
        let boxed =
            BoxedRsaPublicKey::new(BoxedUint::from_be_bytes(&nb), BoxedUint::from_be_bytes(&eb));
        assert_eq!(cg_spki, boxed.to_spki_der());
        // And the boxed parser eats the const-generic output.
        BoxedRsaPublicKey::from_spki_der(&cg_spki).unwrap();
    }

    #[test]
    fn const_generic_spki_rejects_non_rsa_oid() {
        // Ed25519 OID, bare AlgorithmIdentifier.
        let algid = encode_sequence(&oid_tlv(&[1, 3, 101, 112]));
        let spki = encode_sequence(&[algid, encode_bit_string(&[0u8; 32])].concat());
        assert!(RsaPublicKey::<32>::from_spki_der(&spki).is_err());
    }

    #[test]
    fn const_generic_spki_rejects_missing_null_params() {
        let algid = encode_sequence(&oid_tlv(&RSA_ENCRYPTION_OID));
        let spki = encode_sequence(&[algid, encode_bit_string(&[0u8; 16])].concat());
        assert!(RsaPublicKey::<32>::from_spki_der(&spki).is_err());
    }

    #[test]
    fn const_generic_pkcs8_rejects_nonzero_version() {
        let key = rsa_test_key_a();
        let der = encode_sequence(
            &[
                encode_integer(&[1]),
                rsa_encryption_algid(),
                encode_octet_string(&key.to_pkcs1_der()),
            ]
            .concat(),
        );
        assert!(RsaPrivateKey::<32>::from_pkcs8_der(&der).is_err());
    }

    #[test]
    fn const_generic_spki_pem_rejects_pkcs1_label() {
        let pk = rsa_test_key_a().public_key();
        let pkcs1_pem = pem_encode(PUBLIC_LABEL, &pk.to_pkcs1_der());
        assert!(RsaPublicKey::<32>::from_spki_pem(&pkcs1_pem).is_err());
    }

    // ---- RSA-1: component-level validation on const-generic parse paths ----

    /// PKCS#1 public-key DER carrying an even public exponent must be
    /// rejected (the `is_odd` gate of `validate_public_exponent`).
    #[test]
    fn const_generic_from_pkcs1_der_rejects_even_exponent() {
        let pk = rsa_test_key_a().public_key();
        let n_bytes = uint_be(pk.modulus());
        let der = encode_sequence(&[encode_integer(&n_bytes), encode_integer(&[4])].concat());
        assert!(RsaPublicKey::<32>::from_pkcs1_der(&der).is_err());
    }

    /// `e = 1` is the canonical degenerate exponent (encryption is the
    /// identity); rejected at parse time.
    #[test]
    fn const_generic_from_pkcs1_der_rejects_unit_exponent() {
        let pk = rsa_test_key_a().public_key();
        let n_bytes = uint_be(pk.modulus());
        let der = encode_sequence(&[encode_integer(&n_bytes), encode_integer(&[1])].concat());
        assert!(RsaPublicKey::<32>::from_pkcs1_der(&der).is_err());
    }

    /// PKCS#1 private-key DER whose modulus does not equal `p · q` must be
    /// rejected. Construct a key by taking a real key A and grafting key B's
    /// modulus over A's primes — the `p · q == n` check then fires.
    #[test]
    fn const_generic_from_pkcs1_der_rejects_mismatched_modulus() {
        let key_a = rsa_test_key_a();
        let (p, q) = key_a.primes();
        // Modulus from key A's public key, then perturb the low byte to
        // ensure `p · q != n` while keeping the length identical.
        let mut n_bytes = uint_be(key_a.modulus());
        // Flip the low byte; if it's already an odd value, this still moves
        // n outside `p·q`.
        let last = n_bytes.len() - 1;
        n_bytes[last] ^= 0xff;
        let der = encode_sequence(
            &[
                encode_integer(&[0]),
                encode_integer(&n_bytes),
                encode_integer(&uint_be(key_a.exponent())),
                encode_integer(&uint_be(key_a.private_exponent())),
                encode_integer(&uint_be(p)),
                encode_integer(&uint_be(q)),
                encode_integer(&[1]),
                encode_integer(&[1]),
                encode_integer(&[1]),
            ]
            .concat(),
        );
        assert!(matches!(
            RsaPrivateKey::<32>::from_pkcs1_der(&der),
            Err(Error::Malformed)
        ));
    }

    /// `p = q` is rejected: the resulting `n = p²` has only one prime
    /// factor, `qInv = q⁻¹ mod p` is undefined (gcd is `p`, not `1`), and
    /// every CRT-using path silently produces wrong output.
    #[test]
    fn const_generic_from_pkcs1_der_rejects_equal_primes() {
        let key = rsa_test_key_a();
        let (p, _q) = key.primes();
        // `n = p · p` lives in `Uint<32>` because `p` is ~1024 bits, so the
        // squared product is ~2048 bits and fits.
        let (n_sq_lo, _hi) = p.mul_wide(p);
        let der = encode_sequence(
            &[
                encode_integer(&[0]),
                encode_integer(&uint_be(&n_sq_lo)),
                encode_integer(&uint_be(key.exponent())),
                encode_integer(&uint_be(key.private_exponent())),
                encode_integer(&uint_be(p)),
                encode_integer(&uint_be(p)), // q := p
                encode_integer(&[1]),
                encode_integer(&[1]),
                encode_integer(&[1]),
            ]
            .concat(),
        );
        assert!(matches!(
            RsaPrivateKey::<32>::from_pkcs1_der(&der),
            Err(Error::Malformed)
        ));
    }

    /// `p ≤ 1` (here `p = 1`) is rejected — the boundary value that would
    /// otherwise compute `qInv = 0` silently.
    #[test]
    fn const_generic_from_pkcs1_der_rejects_unit_prime() {
        let key = rsa_test_key_a();
        let (_p, q) = key.primes();
        let der = encode_sequence(
            &[
                encode_integer(&[0]),
                encode_integer(&uint_be(key.modulus())),
                encode_integer(&uint_be(key.exponent())),
                encode_integer(&uint_be(key.private_exponent())),
                encode_integer(&[1]), // p = 1
                encode_integer(&uint_be(q)),
                encode_integer(&[1]),
                encode_integer(&[1]),
                encode_integer(&[1]),
            ]
            .concat(),
        );
        assert!(matches!(
            RsaPrivateKey::<32>::from_pkcs1_der(&der),
            Err(Error::Malformed)
        ));
    }

    /// PKCS#8 wraps PKCS#1 — degenerate components must be rejected after
    /// the outer envelope unwraps cleanly.
    #[test]
    fn const_generic_from_pkcs8_der_rejects_mismatched_modulus() {
        let key_a = rsa_test_key_a();
        let (p, q) = key_a.primes();
        let mut n_bytes = uint_be(key_a.modulus());
        let last = n_bytes.len() - 1;
        n_bytes[last] ^= 0xff;
        let pkcs1 = encode_sequence(
            &[
                encode_integer(&[0]),
                encode_integer(&n_bytes),
                encode_integer(&uint_be(key_a.exponent())),
                encode_integer(&uint_be(key_a.private_exponent())),
                encode_integer(&uint_be(p)),
                encode_integer(&uint_be(q)),
                encode_integer(&[1]),
                encode_integer(&[1]),
                encode_integer(&[1]),
            ]
            .concat(),
        );
        let der = encode_sequence(
            &[
                encode_integer(&[0]),
                rsa_encryption_algid(),
                encode_octet_string(&pkcs1),
            ]
            .concat(),
        );
        assert!(matches!(
            RsaPrivateKey::<32>::from_pkcs8_der(&der),
            Err(Error::Malformed)
        ));
    }
}
