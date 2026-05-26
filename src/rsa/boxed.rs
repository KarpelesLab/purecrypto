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
use crate::hash::{Digest, HmacSha256, Sha256};
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
///
/// # Side-channel protection
///
/// When the prime factors are known the raw private operation runs Coron's
/// base blinding (see [`RsaPrivateKey`](super::RsaPrivateKey) for the full
/// recipe). The blinder is derived deterministically from a key-bound
/// HMAC keyed by a digest of `d`, so two callers asking about the same
/// ciphertext see the same blinder but an attacker who does not know `d`
/// cannot predict it — defeating Bleichenbacher / Manger / cache-timing
/// attacks on the secret exponentiation.
///
/// Keys imported with [`from_components`](Self::from_components) (no primes)
/// fall back to plain `c^d mod n`; the constant-time Montgomery ladder still
/// applies, but base-blinding cannot.
#[derive(Clone, Debug)]
pub struct BoxedRsaPrivateKey {
    n: BoxedUint,
    e: BoxedUint,
    d: BoxedUint,
    p: BoxedUint,
    q: BoxedUint,
    mont: BoxedMontModulus,
    k: usize,
    /// `(p−1)·(q−1) − 1` when both primes are known; `None` when the key was
    /// imported without them (then blinding is disabled).
    phi_n_minus_1: Option<BoxedUint>,
    /// HMAC-SHA256 key (derived from `d`) for per-call blinding values.
    blinding_seed: [u8; 32],
}

/// Computes `phi(n) − 1` from the primes (if both are nonzero) and the
/// blinding HMAC key (always).
fn derive_blinding_boxed(
    p: &BoxedUint,
    q: &BoxedUint,
    d: &BoxedUint,
) -> (Option<BoxedUint>, [u8; 32]) {
    let phi_n_minus_1 = if p.is_zero() || q.is_zero() {
        None
    } else {
        let one = BoxedUint::from_u64(1);
        let pm1 = p.sub(&one);
        let qm1 = q.sub(&one);
        Some(pm1.mul(&qm1).sub(&one))
    };

    let mut h = Sha256::new();
    h.update(b"purecrypto-rsa-blinding-seed-v1");
    // `d` is variable-width; serialize big-endian byte-for-byte.
    let d_bytes = d.to_be_bytes(d.bit_len().div_ceil(8).max(1));
    h.update(&d_bytes);
    let digest = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(digest.as_ref());
    (phi_n_minus_1, seed)
}

/// Base-blinded raw RSA private op for the runtime-sized key.
fn raw_private_blinded_boxed(
    mont: &BoxedMontModulus,
    e: &BoxedUint,
    d: &BoxedUint,
    phi_n_minus_1: Option<&BoxedUint>,
    blinding_seed: &[u8; 32],
    k_bytes: usize,
    c: &BoxedUint,
) -> BoxedUint {
    let phi_n_minus_1 = match phi_n_minus_1 {
        Some(v) => v,
        None => return mont.pow(c, d), // imported key without primes
    };

    // Derive blinder bytes of width `k_bytes` from HMAC-SHA256.
    let c_bytes = c.to_be_bytes(k_bytes);
    let mut blinder_bytes = Vec::with_capacity(k_bytes);
    let mut counter: u32 = 0;
    while blinder_bytes.len() < k_bytes {
        let mut m = HmacSha256::new(blinding_seed);
        m.update(b"r");
        m.update(&counter.to_be_bytes());
        m.update(&c_bytes);
        let tag = m.finalize();
        blinder_bytes.extend_from_slice(tag.as_ref());
        counter += 1;
    }
    blinder_bytes.truncate(k_bytes);
    let r_raw = BoxedUint::from_be_bytes(&blinder_bytes);
    let r = r_raw.reduce(&mont.modulus());
    let r = if r.is_zero() || r == BoxedUint::from_u64(1) {
        BoxedUint::from_u64(2)
    } else {
        r
    };

    let r_e = mont.pow(&r, e);
    let r_inv = mont.pow(&r, phi_n_minus_1);
    let c_blind = mont.mul_mod(c, &r_e);
    let m_blind = mont.pow(&c_blind, d);
    mont.mul_mod(&m_blind, &r_inv)
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
    /// the prime factors, so CRT-based PKCS#1 export and base-blinding are
    /// unavailable; see the struct docs).
    pub fn from_components(n: BoxedUint, e: BoxedUint, d: BoxedUint) -> Self {
        let k = n.bit_len().div_ceil(8);
        let mont = BoxedMontModulus::new(&n);
        let p = BoxedUint::zero(1);
        let q = BoxedUint::zero(1);
        let (phi_n_minus_1, blinding_seed) = derive_blinding_boxed(&p, &q, &d);
        BoxedRsaPrivateKey {
            n,
            e,
            d,
            p,
            q,
            mont,
            k,
            phi_n_minus_1,
            blinding_seed,
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
                let (phi_n_minus_1, blinding_seed) = derive_blinding_boxed(&p, &q, &d);
                return BoxedRsaPrivateKey {
                    n,
                    e,
                    d,
                    p,
                    q,
                    mont,
                    k,
                    phi_n_minus_1,
                    blinding_seed,
                };
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
        let c_uint = BoxedUint::from_be_bytes(c);
        raw_private_blinded_boxed(
            &self.mont,
            &self.e,
            &self.d,
            self.phi_n_minus_1.as_ref(),
            &self.blinding_seed,
            self.k,
            &c_uint,
        )
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
    /// public exponent, private exponent, and the prime factors (the CRT
    /// parameters `dP`/`dQ`/`qInv` are recomputed on export, so they need not
    /// round-trip). The primes enable base-blinding on the secret-side path.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, crate::der::Error> {
        let mut reader = crate::der::Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let _version = seq.read_integer_bytes()?;
        let n = BoxedUint::from_be_bytes(seq.read_integer_bytes()?);
        let e = BoxedUint::from_be_bytes(seq.read_integer_bytes()?);
        let d = BoxedUint::from_be_bytes(seq.read_integer_bytes()?);
        let p = BoxedUint::from_be_bytes(seq.read_integer_bytes()?);
        let q = BoxedUint::from_be_bytes(seq.read_integer_bytes()?);
        let _dp = seq.read_integer_bytes()?;
        let _dq = seq.read_integer_bytes()?;
        let _qinv = seq.read_integer_bytes()?;
        seq.finish()?;
        reader.finish()?;
        let k = n.bit_len().div_ceil(8);
        let mont = BoxedMontModulus::new(&n);
        let (phi_n_minus_1, blinding_seed) = derive_blinding_boxed(&p, &q, &d);
        Ok(BoxedRsaPrivateKey {
            n,
            e,
            d,
            p,
            q,
            mont,
            k,
            phi_n_minus_1,
            blinding_seed,
        })
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
        pk.verify_pkcs1v15::<Sha256>(b"runtime keygen", &sig)
            .unwrap();
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
