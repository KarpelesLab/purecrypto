//! PKCS#1 (RFC 8017) DER and PEM serialization for RSA keys.

use alloc::string::String;
use alloc::vec::Vec;

use super::{RsaPrivateKey, RsaPublicKey};
use crate::bignum::{Uint, inv_mod};
use crate::der::{Error, Reader, encode_integer, encode_sequence, pem_decode, pem_encode};

const PUBLIC_LABEL: &str = "RSA PUBLIC KEY";
const PRIVATE_LABEL: &str = "RSA PRIVATE KEY";

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

    /// Decodes a PKCS#1 `RSAPublicKey` DER structure.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let n = int_to_uint(seq.read_integer_bytes()?)?;
        let e = int_to_uint(seq.read_integer_bytes()?)?;
        seq.finish()?;
        reader.finish()?;
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
    /// read but not retained.
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
}
