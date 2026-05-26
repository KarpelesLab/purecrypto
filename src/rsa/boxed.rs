//! Runtime-sized RSA keys.
//!
//! [`BoxedRsaPublicKey`]/[`BoxedRsaPrivateKey`] hold their modulus as a
//! [`BoxedUint`], so they accept keys of a size only known at runtime (e.g.
//! parsed from a certificate). They share the EMSA padding code in
//! [`super::emsa`] with the const-generic keys, so PKCS#1 v1.5 and PSS behave
//! identically.

use alloc::vec::Vec;

use super::emsa::{self, RawPrivate, RawPublic};
use super::{Error, Pkcs1Digest};
use crate::bignum::{BoxedMontModulus, BoxedUint};
use crate::hash::Digest;
use crate::rng::RngCore;

/// A runtime-sized RSA public key.
#[derive(Clone, Debug)]
pub struct BoxedRsaPublicKey {
    n: BoxedUint,
    e: BoxedUint,
    mont: BoxedMontModulus,
    /// Modulus length in octets.
    k: usize,
}

/// A runtime-sized RSA private key (signing uses `c^d mod n`; the prime factors
/// `p`, `q` are kept when the key was generated here, enabling PKCS#1 export
/// with CRT parameters, and are zero for keys imported without them).
#[derive(Clone, Debug)]
pub struct BoxedRsaPrivateKey {
    n: BoxedUint,
    e: BoxedUint,
    d: BoxedUint,
    p: BoxedUint,
    q: BoxedUint,
    mont: BoxedMontModulus,
    k: usize,
}

impl BoxedRsaPublicKey {
    /// Builds a public key from modulus `n` and exponent `e`.
    pub fn new(n: BoxedUint, e: BoxedUint) -> Self {
        let k = n.bit_len().div_ceil(8);
        let mont = BoxedMontModulus::new(&n);
        BoxedRsaPublicKey { n, e, mont, k }
    }

    /// The modulus.
    pub fn modulus(&self) -> &BoxedUint {
        &self.n
    }

    /// Verifies a PKCS#1 v1.5 signature over `msg`, hashing with `D`.
    pub fn verify_pkcs1v15<D: Pkcs1Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        emsa::verify_pkcs1v15::<D, _>(self, msg, sig)
    }

    /// Verifies an RSA-PSS signature over `msg`, hashing with `D`.
    pub fn verify_pss<D: Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        emsa::verify_pss::<D, _>(self, msg, sig)
    }

    /// Encrypts `msg` with PKCS#1 v1.5.
    pub fn encrypt_pkcs1v15<R: RngCore>(&self, msg: &[u8], rng: &mut R) -> Result<Vec<u8>, Error> {
        emsa::encrypt_pkcs1v15(self, msg, rng)
    }

    /// Encrypts `msg` with RSAES-OAEP (RFC 8017 §7.1.1), hashing with `D` and
    /// binding the optional `label`.
    pub fn encrypt_oaep<D: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        label: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        emsa::encrypt_oaep::<D, _, _>(self, msg, label, rng)
    }
}

impl BoxedRsaPrivateKey {
    /// Builds a private key from `n`, `e`, and the private exponent `d` (without
    /// the prime factors, so CRT-based PKCS#1 export is unavailable).
    pub fn from_components(n: BoxedUint, e: BoxedUint, d: BoxedUint) -> Self {
        let k = n.bit_len().div_ceil(8);
        let mont = BoxedMontModulus::new(&n);
        BoxedRsaPrivateKey {
            n,
            e,
            d,
            p: BoxedUint::zero(1),
            q: BoxedUint::zero(1),
            mont,
            k,
        }
    }

    /// Generates a runtime-sized RSA key pair with a `bits`-bit modulus and
    /// public exponent `e` (commonly 65537). `bits` must be even; each prime is
    /// `bits/2` bits. `rounds` is the Miller-Rabin count per candidate.
    ///
    /// Key generation uses non-constant-time modular inverse and primality
    /// testing (see [`inv_mod_boxed`](crate::bignum::inv_mod_boxed)); this is a
    /// one-time operation, not a per-message secret path.
    pub fn generate<R: RngCore>(bits: usize, e: BoxedUint, rng: &mut R, rounds: usize) -> Self {
        use crate::bignum::inv_mod_boxed;
        let one = BoxedUint::from_u64(1);
        let half = bits / 2;
        loop {
            let p = super::prime::random_prime_boxed(rng, half, rounds);
            let q = super::prime::random_prime_boxed(rng, half, rounds);
            if p == q {
                continue;
            }
            let n = p.mul(&q);
            let phi = p.sub(&one).mul(&q.sub(&one));
            // d = e^-1 mod φ(n); retry if e is not coprime to φ.
            if let Some(d) = inv_mod_boxed(&e, &phi) {
                let k = n.bit_len().div_ceil(8);
                let mont = BoxedMontModulus::new(&n);
                return BoxedRsaPrivateKey { n, e, d, p, q, mont, k };
            }
        }
    }

    /// The corresponding public key.
    pub fn public_key(&self) -> BoxedRsaPublicKey {
        BoxedRsaPublicKey::new(self.n.clone(), self.e.clone())
    }

    /// The modulus.
    pub fn modulus(&self) -> &BoxedUint {
        &self.n
    }

    /// Signs `msg` with PKCS#1 v1.5, hashing with `D`.
    pub fn sign_pkcs1v15<D: Pkcs1Digest>(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        emsa::sign_pkcs1v15::<D, _>(self, msg)
    }

    /// Signs `msg` with RSA-PSS, hashing with `D`.
    pub fn sign_pss<D: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        emsa::sign_pss::<D, _, R>(self, msg, rng)
    }

    /// Decrypts a PKCS#1 v1.5 ciphertext.
    pub fn decrypt_pkcs1v15(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
        emsa::decrypt_pkcs1v15(self, ct)
    }

    /// Decrypts an RSAES-OAEP ciphertext (RFC 8017 §7.1.2). Hash `D` and
    /// `label` must match those used at encryption.
    pub fn decrypt_oaep<D: Digest>(&self, ct: &[u8], label: &[u8]) -> Result<Vec<u8>, Error> {
        emsa::decrypt_oaep::<D, _>(self, ct, label)
    }
}

impl RawPublic for BoxedRsaPublicKey {
    fn key_size(&self) -> usize {
        self.k
    }
    fn modulus_bits(&self) -> usize {
        self.n.bit_len()
    }
    fn raw_public(&self, m: &[u8]) -> Vec<u8> {
        self.mont
            .pow(&BoxedUint::from_be_bytes(m), &self.e)
            .to_be_bytes(self.k)
    }
}

impl RawPrivate for BoxedRsaPrivateKey {
    fn key_size(&self) -> usize {
        self.k
    }
    fn modulus_bits(&self) -> usize {
        self.n.bit_len()
    }
    fn raw_private(&self, c: &[u8]) -> Vec<u8> {
        self.mont
            .pow(&BoxedUint::from_be_bytes(c), &self.d)
            .to_be_bytes(self.k)
    }
}

/// PKCS#1 DER for runtime-sized keys.
#[cfg(feature = "der")]
impl BoxedRsaPublicKey {
    /// Parses a PKCS#1 `RSAPublicKey` DER structure (`SEQUENCE { n, e }`).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, crate::der::Error> {
        let mut reader = crate::der::Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let n = BoxedUint::from_be_bytes(seq.read_integer_bytes()?);
        let e = BoxedUint::from_be_bytes(seq.read_integer_bytes()?);
        seq.finish()?;
        reader.finish()?;
        Ok(BoxedRsaPublicKey::new(n, e))
    }

    /// Encodes the key as a PKCS#1 `RSAPublicKey` DER structure.
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        use crate::der::{encode_integer, encode_sequence};
        let n = self.n.to_be_bytes(self.k);
        let e = self.e.to_be_bytes(self.e.bit_len().div_ceil(8).max(1));
        encode_sequence(&[encode_integer(&n), encode_integer(&e)].concat())
    }
}

/// PKCS#1 DER/PEM for runtime-sized private keys.
#[cfg(feature = "der")]
impl BoxedRsaPrivateKey {
    /// Parses a PKCS#1 `RSAPrivateKey` DER structure, retaining the modulus,
    /// public exponent, and private exponent (the CRT parameters are read and
    /// discarded — the boxed key uses plain modular exponentiation).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, crate::der::Error> {
        let mut reader = crate::der::Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let _version = seq.read_integer_bytes()?;
        let n = BoxedUint::from_be_bytes(seq.read_integer_bytes()?);
        let e = BoxedUint::from_be_bytes(seq.read_integer_bytes()?);
        let d = BoxedUint::from_be_bytes(seq.read_integer_bytes()?);
        let _p = seq.read_integer_bytes()?;
        let _q = seq.read_integer_bytes()?;
        let _dp = seq.read_integer_bytes()?;
        let _dq = seq.read_integer_bytes()?;
        let _qinv = seq.read_integer_bytes()?;
        seq.finish()?;
        reader.finish()?;
        Ok(BoxedRsaPrivateKey::from_components(n, e, d))
    }

    /// Decodes a PKCS#1 PEM private key (`-----BEGIN RSA PRIVATE KEY-----`).
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_pkcs1_der(&crate::der::pem_decode(pem, "RSA PRIVATE KEY")?)
    }

    /// Encodes the key as a PKCS#1 `RSAPrivateKey` DER structure (two-prime,
    /// with the CRT parameters `dP`, `dQ`, `qInv`).
    ///
    /// # Panics
    /// Panics if the prime factors are not retained (i.e. the key was built via
    /// [`from_components`](Self::from_components) or imported, not generated).
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        use crate::bignum::inv_mod_boxed;
        use crate::der::{encode_integer, encode_sequence};
        assert!(
            !self.p.is_zero() && !self.q.is_zero(),
            "to_pkcs1_der requires the prime factors (generated keys only)"
        );
        let one = BoxedUint::from_u64(1);
        let dp = self.d.reduce(&self.p.sub(&one));
        let dq = self.d.reduce(&self.q.sub(&one));
        let qinv = inv_mod_boxed(&self.q, &self.p).unwrap_or_else(|| BoxedUint::zero(1));
        let be = |v: &BoxedUint| v.to_be_bytes(v.bit_len().div_ceil(8).max(1));
        encode_sequence(
            &[
                encode_integer(&[0]),
                encode_integer(&be(&self.n)),
                encode_integer(&be(&self.e)),
                encode_integer(&be(&self.d)),
                encode_integer(&be(&self.p)),
                encode_integer(&be(&self.q)),
                encode_integer(&be(&dp)),
                encode_integer(&be(&dq)),
                encode_integer(&be(&qinv)),
            ]
            .concat(),
        )
    }

    /// Encodes the key as a PKCS#1 PEM document.
    pub fn to_pkcs1_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("RSA PRIVATE KEY", &self.to_pkcs1_der())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::test_util::rsa_test_key_a;

    /// Builds a boxed public key from the const-generic test key.
    fn boxed_pub() -> (crate::rsa::RsaPrivateKey<32>, BoxedRsaPublicKey) {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut n = [0u8; 256];
        pk.modulus().write_be_bytes(&mut n);
        let mut e = [0u8; 256];
        pk.exponent().write_be_bytes(&mut e);
        let boxed =
            BoxedRsaPublicKey::new(BoxedUint::from_be_bytes(&n), BoxedUint::from_be_bytes(&e));
        (key, boxed)
    }

    #[test]
    fn boxed_oaep_encrypts_const_generic_decrypts() {
        let (key, boxed) = boxed_pub();
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-oaep", b"nonce", &[]);
        let msg = b"OAEP from a runtime-sized public key";
        let ct = boxed
            .encrypt_oaep::<Sha256, _>(msg, b"label", &mut r)
            .unwrap();
        // The const-generic private key decrypts.
        assert_eq!(&key.decrypt_oaep::<Sha256>(&ct, b"label").unwrap()[..], msg);
    }

    #[test]
    fn boxed_verifies_const_generic_signatures() {
        let (key, boxed) = boxed_pub();
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-rsa", b"nonce", &[]);

        let s1 = key.sign_pkcs1v15::<Sha256>(b"hello").unwrap();
        boxed.verify_pkcs1v15::<Sha256>(b"hello", &s1).unwrap();
        assert!(boxed.verify_pkcs1v15::<Sha256>(b"other", &s1).is_err());

        let s2 = key.sign_pss::<Sha256, _>(b"hello", &mut r).unwrap();
        boxed.verify_pss::<Sha256>(b"hello", &s2).unwrap();
    }

    #[test]
    fn boxed_from_pkcs1_der() {
        let key = rsa_test_key_a();
        let der = key.public_key().to_pkcs1_der();
        let boxed = BoxedRsaPublicKey::from_pkcs1_der(&der).unwrap();
        assert_eq!(boxed.modulus().bit_len(), 2048);

        let sig = key.sign_pkcs1v15::<Sha256>(b"via der").unwrap();
        boxed.verify_pkcs1v15::<Sha256>(b"via der", &sig).unwrap();
    }

    #[test]
    fn generate_runtime_key_signs_and_exports() {
        // A small modulus keeps the test fast; the path is identical for larger
        // sizes (the CLI uses this for any non-standard size up to 65536).
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-keygen", b"nonce", &[]);
        let key = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut r, 12);
        assert_eq!(key.modulus().bit_len(), 1024);

        let sig = key.sign_pkcs1v15::<Sha256>(b"runtime keygen").unwrap();
        let pk = key.public_key();
        pk.verify_pkcs1v15::<Sha256>(b"runtime keygen", &sig).unwrap();
        assert!(pk.verify_pkcs1v15::<Sha256>(b"other", &sig).is_err());

        // PKCS#1 export (with CRT params) round-trips through the parser.
        let parsed = BoxedRsaPrivateKey::from_pkcs1_der(&key.to_pkcs1_der()).unwrap();
        let sig2 = parsed.sign_pkcs1v15::<Sha256>(b"via der").unwrap();
        pk.verify_pkcs1v15::<Sha256>(b"via der", &sig2).unwrap();
    }

    #[test]
    fn boxed_private_key_signs() {
        // Reconstruct a boxed private key from the const-generic key's parts.
        let key = rsa_test_key_a();
        let mut nb = [0u8; 256];
        key.modulus().write_be_bytes(&mut nb);
        let mut eb = [0u8; 256];
        key.exponent().write_be_bytes(&mut eb);
        let mut db = [0u8; 256];
        key.private_exponent().write_be_bytes(&mut db);
        let boxed = BoxedRsaPrivateKey::from_components(
            BoxedUint::from_be_bytes(&nb),
            BoxedUint::from_be_bytes(&eb),
            BoxedUint::from_be_bytes(&db),
        );

        let sig = boxed.sign_pkcs1v15::<Sha256>(b"sign me").unwrap();
        // Verify with the const-generic public key.
        key.public_key()
            .verify_pkcs1v15::<Sha256>(b"sign me", &sig)
            .unwrap();
    }
}
