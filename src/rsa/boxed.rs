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

/// Lower bound for `BoxedRsaPublicKey` parsing entry points. Anything smaller
/// is rejected as an unsigned-floor sanity check; per-protocol policy (e.g.
/// 2048-bit minimum for TLS signatures) is enforced separately by callers.
/// Set to 1024 to (a) keep `decrypt_pkcs1v15` safe from the
/// `k < 11` indexing-panic class, and (b) refuse the obviously-broken
/// modulus sizes an attacker might inject via a malicious SPKI.
pub(crate) const MIN_RSA_BITS: usize = 1024;

/// Upper bound to prevent CPU-exhaustion on parsing huge SPKI moduli.
/// `BoxedMontModulus::new` runs `2 * 64 * limbs` `add_mod` iterations for the
/// R² precomp, and every subsequent `mont_mul` is O(limbs²). 16384 bits is
/// well above any legitimate use.
pub(crate) const MAX_RSA_BITS: usize = 16384;

impl BoxedRsaPublicKey {
    /// Builds a public key from modulus `n` and exponent `e`.
    pub fn new(n: BoxedUint, e: BoxedUint) -> Self {
        let k = n.bit_len().div_ceil(8);
        let mont = BoxedMontModulus::new(&n);
        BoxedRsaPublicKey { n, e, mont, k }
    }

    /// Builds a public key from modulus `n` and exponent `e`, rejecting
    /// modulus sizes outside `[MIN_RSA_BITS, MAX_RSA_BITS]`. Used by the
    /// attacker-controlled parse paths (SPKI / certificates).
    pub fn try_new(n: BoxedUint, e: BoxedUint) -> Result<Self, Error> {
        let bits = n.bit_len();
        if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
            return Err(Error::InvalidLength);
        }
        Ok(Self::new(n, e))
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
        let bits = n.bit_len();
        if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
            return Err(crate::der::Error::Malformed);
        }
        Ok(BoxedRsaPublicKey::new(n, e))
    }

    /// Encodes the key as a PKCS#1 `RSAPublicKey` DER structure.
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        use crate::der::{encode_integer, encode_sequence};
        let n = self.n.to_be_bytes(self.k);
        let e = self.e.to_be_bytes(self.e.bit_len().div_ceil(8).max(1));
        encode_sequence(&[encode_integer(&n), encode_integer(&e)].concat())
    }

    /// Encodes the key as an X.509 `SubjectPublicKeyInfo` (SPKI) DER structure
    /// (RFC 5280 §4.1.2.7). The envelope is
    /// `SEQUENCE { AlgorithmIdentifier, BIT STRING }` where the
    /// AlgorithmIdentifier is `rsaEncryption` (OID `1.2.840.113549.1.1.1`)
    /// with an explicit `NULL` parameter (RFC 3279 §2.3.1), and the
    /// BIT STRING wraps the PKCS#1 `RSAPublicKey` DER produced by
    /// [`to_pkcs1_der`](Self::to_pkcs1_der).
    ///
    /// SPKI is the form X.509 certificates, JWKs, and most modern key-
    /// management tooling expect; the PKCS#1 form is only used by legacy
    /// OpenSSL-style PEM files.
    pub fn to_spki_der(&self) -> Vec<u8> {
        use crate::der::{encode_bit_string, encode_null, encode_sequence, oid_tlv};
        let algid = encode_sequence(&[oid_tlv(&RSA_ENCRYPTION_OID), encode_null()].concat());
        encode_sequence(&[algid, encode_bit_string(&self.to_pkcs1_der())].concat())
    }

    /// Encodes the key as a PEM `-----BEGIN PUBLIC KEY-----` document
    /// (RFC 7468). The body is [`to_spki_der`](Self::to_spki_der). Note the
    /// label has no `RSA ` prefix — the OID inside the SPKI disambiguates
    /// the algorithm.
    pub fn to_spki_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("PUBLIC KEY", &self.to_spki_der())
    }

    /// Parses an X.509 `SubjectPublicKeyInfo` (SPKI) DER structure for an RSA
    /// public key. Validates that the algorithm OID is `rsaEncryption`, the
    /// parameters field is an explicit `NULL` (per RFC 3279 §2.3.1 strict —
    /// absent or non-NULL is rejected, mirroring the hardening from fix H-7
    /// applied to the X.509 SPKI parser), and the inner BIT STRING decodes
    /// as a valid PKCS#1 `RSAPublicKey`.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, crate::der::Error> {
        let mut reader = crate::der::Reader::new(der);
        let mut outer = reader.read_sequence()?;
        let mut algid = outer.read_sequence()?;
        let alg = crate::der::parse_oid(algid.read_oid()?)?;
        if alg.as_slice() != RSA_ENCRYPTION_OID {
            return Err(crate::der::Error::Malformed);
        }
        algid.read_null()?;
        algid.finish()?;
        let key_bits = outer.read_bit_string()?;
        outer.finish()?;
        reader.finish()?;
        Self::from_pkcs1_der(key_bits)
    }

    /// Parses an SPKI PEM document (`-----BEGIN PUBLIC KEY-----`, RFC 7468).
    /// The legacy `RSA PUBLIC KEY` label (PKCS#1) is **not** accepted here —
    /// use [`from_pkcs1_der`](Self::from_pkcs1_der) after a PEM strip for
    /// that form.
    pub fn from_spki_pem(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_spki_der(&crate::der::pem_decode(pem, "PUBLIC KEY")?)
    }
}

/// DER OID arcs for `rsaEncryption` (RFC 3279 §2.3.1).
#[cfg(feature = "der")]
const RSA_ENCRYPTION_OID: [u64; 7] = [1, 2, 840, 113549, 1, 1, 1];

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
        let bits = n.bit_len();
        if !(MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bits) {
            return Err(crate::der::Error::Malformed);
        }
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
    /// Encrypted PKCS#8 (`EncryptedPrivateKeyInfo`, RFC 5958 §3, PBES2 /
    /// PBKDF2) is intentionally not implemented — pick a stream-cipher AEAD
    /// envelope of your own choosing instead.
    ///
    /// # Panics
    /// Panics if the prime factors are not retained (i.e. the key was built
    /// via [`from_components`](Self::from_components) or imported, not
    /// generated). Matches [`to_pkcs1_der`](Self::to_pkcs1_der).
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        use crate::der::{
            encode_integer, encode_null, encode_octet_string, encode_sequence, oid_tlv,
        };
        let algid = encode_sequence(&[oid_tlv(&RSA_ENCRYPTION_OID), encode_null()].concat());
        encode_sequence(
            &[
                encode_integer(&[0]),
                algid,
                encode_octet_string(&self.to_pkcs1_der()),
            ]
            .concat(),
        )
    }

    /// Encodes the key as a PKCS#8 PEM document
    /// (`-----BEGIN PRIVATE KEY-----`, RFC 7468). Distinct from the legacy
    /// `RSA PRIVATE KEY` label which carries a bare PKCS#1 body.
    pub fn to_pkcs8_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("PRIVATE KEY", &self.to_pkcs8_der())
    }

    /// Parses an unencrypted PKCS#8 `PrivateKeyInfo` DER structure for an
    /// RSA private key. Validates `version = 0`, `privateKeyAlgorithm` is
    /// `rsaEncryption` with explicit `NULL` parameters, and the inner OCTET
    /// STRING decodes as a valid PKCS#1 `RSAPrivateKey`.
    ///
    /// Encrypted PKCS#8 (`EncryptedPrivateKeyInfo`, RFC 5958 §3) is rejected
    /// at the outer SEQUENCE — its first field is an `AlgorithmIdentifier`,
    /// not the version INTEGER.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, crate::der::Error> {
        let mut reader = crate::der::Reader::new(der);
        let mut outer = reader.read_sequence()?;
        let version = outer.read_integer_bytes()?;
        // RFC 5958 §2: version MUST be 0 for the v1 (unencrypted) form.
        // The v2 form (which permits an attribute set) uses version = 1.
        if version != [0] {
            return Err(crate::der::Error::Malformed);
        }
        let mut algid = outer.read_sequence()?;
        let alg = crate::der::parse_oid(algid.read_oid()?)?;
        if alg.as_slice() != RSA_ENCRYPTION_OID {
            return Err(crate::der::Error::Malformed);
        }
        algid.read_null()?;
        algid.finish()?;
        let inner = outer.read_octet_string()?;
        // PKCS#8 v1 has no further fields after the privateKey OCTET STRING
        // for our purposes (the optional `attributes [0]` set isn't carried
        // by anything mainstream for RSA). Reject trailing junk strictly.
        outer.finish()?;
        reader.finish()?;
        Self::from_pkcs1_der(inner)
    }

    /// Parses a PKCS#8 PEM document (`-----BEGIN PRIVATE KEY-----`,
    /// RFC 7468). The legacy `RSA PRIVATE KEY` PKCS#1 label is **not**
    /// accepted here — use [`from_pkcs1_pem`](Self::from_pkcs1_pem) for
    /// that form.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_pkcs8_der(&crate::der::pem_decode(pem, "PRIVATE KEY")?)
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

    /// PEM-wrapped variant of [`to_pkcs8_der_encrypted`]
    /// (`-----BEGIN ENCRYPTED PRIVATE KEY-----`, RFC 7468 §11).
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn to_pkcs8_pem_encrypted(
        &self,
        password: &[u8],
        params: &crate::kdf::pbes2::Pbes2Params,
        rng: &mut impl crate::rng::RngCore,
    ) -> alloc::string::String {
        crate::kdf::pbes2::encrypt_pem(&self.to_pkcs8_der(), password, params, rng)
    }

    /// Parses an `EncryptedPrivateKeyInfo` DER and decrypts it back to a
    /// PKCS#8 RSA private key.
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn from_pkcs8_der_encrypted(
        der: &[u8],
        password: &[u8],
    ) -> Result<Self, crate::der::Error> {
        let inner =
            crate::kdf::pbes2::decrypt(der, password).map_err(|_| crate::der::Error::Malformed)?;
        Self::from_pkcs8_der(&inner)
    }

    /// PEM-wrapped variant of [`from_pkcs8_der_encrypted`].
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn from_pkcs8_pem_encrypted(pem: &str, password: &[u8]) -> Result<Self, crate::der::Error> {
        let inner = crate::kdf::pbes2::decrypt_pem(pem, password)
            .map_err(|_| crate::der::Error::Malformed)?;
        Self::from_pkcs8_der(&inner)
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

    /// I-1: a tiny SPKI/PKCS#1 modulus must be rejected at parse time so the
    /// downstream `decrypt_pkcs1v15` indexing path (which assumes `k >= 11`)
    /// is never reached on attacker input.
    #[test]
    fn rsa_decrypt_pkcs1v15_rejects_tiny_modulus() {
        use crate::der::{encode_integer, encode_sequence};
        // Synthesize a PKCS#1 RSAPublicKey with an 8-bit modulus (n=255, e=3).
        let n = [0xff];
        let e = [0x03];
        let der = encode_sequence(&[encode_integer(&n), encode_integer(&e)].concat());
        assert!(BoxedRsaPublicKey::from_pkcs1_der(&der).is_err());
    }

    /// I-2: a 32768-bit SPKI/PKCS#1 modulus must be rejected at parse time so
    /// `BoxedMontModulus::new` doesn't run a quadratic R² precomputation on
    /// attacker-supplied huge keys.
    #[test]
    fn rsa_rejects_modulus_above_16384_bits() {
        use crate::der::{encode_integer, encode_sequence};
        // 32768-bit modulus = 4096 bytes. The leading byte must be < 0x80 so
        // the DER INTEGER is unambiguously positive without a leading zero.
        let mut n = alloc::vec![0xffu8; 4096];
        n[0] = 0x7f;
        let e = [0x01, 0x00, 0x01];
        let der = encode_sequence(&[encode_integer(&n), encode_integer(&e)].concat());
        assert!(BoxedRsaPublicKey::from_pkcs1_der(&der).is_err());
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

    // ---- SPKI / PKCS#8 round-trip and reject tests ----

    /// Helper: generates a small (1024-bit) RSA key. Faster than 2048 in
    /// debug and exercises the same encoding path.
    fn gen_small_key(seed: &[u8]) -> BoxedRsaPrivateKey {
        let mut rng = HmacDrbg::<Sha256>::new(seed, b"n", &[]);
        BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut rng, 12)
    }

    #[test]
    fn rsa_public_key_spki_der_roundtrip() {
        let sk = gen_small_key(b"rsa-spki-der");
        let pk = sk.public_key();
        let der = pk.to_spki_der();
        // Sanity: outer SEQUENCE.
        assert_eq!(der[0], 0x30);
        let parsed = BoxedRsaPublicKey::from_spki_der(&der).unwrap();
        assert_eq!(parsed.to_pkcs1_der(), pk.to_pkcs1_der());

        // Cross-check against the X.509 layer: an SPKI built by AnyPublicKey
        // for the same key bytes must be byte-identical, so SPKI bytes
        // produced by either route are interchangeable.
        let any_spki =
            crate::x509::AnyPublicKey::Rsa(BoxedRsaPublicKey::new(pk.n.clone(), pk.e.clone()))
                .to_spki_der();
        assert_eq!(der, any_spki);
    }

    #[test]
    fn rsa_public_key_spki_pem_roundtrip() {
        let sk = gen_small_key(b"rsa-spki-pem");
        let pk = sk.public_key();
        let pem = pk.to_spki_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
        let parsed = BoxedRsaPublicKey::from_spki_pem(&pem).unwrap();
        assert_eq!(parsed.to_pkcs1_der(), pk.to_pkcs1_der());
    }

    #[test]
    fn rsa_private_key_pkcs8_der_roundtrip() {
        let sk = gen_small_key(b"rsa-pkcs8-der");
        let der = sk.to_pkcs8_der();
        assert_eq!(der[0], 0x30);
        let parsed = BoxedRsaPrivateKey::from_pkcs8_der(&der).unwrap();
        // PKCS#1 export is byte-deterministic for a given key, so the
        // round-tripped key re-serializes to the same PKCS#1 bytes.
        assert_eq!(parsed.to_pkcs1_der(), sk.to_pkcs1_der());

        // Functional: the round-tripped key still signs.
        let sig = parsed.sign_pkcs1v15::<Sha256>(b"via pkcs8").unwrap();
        sk.public_key()
            .verify_pkcs1v15::<Sha256>(b"via pkcs8", &sig)
            .unwrap();
    }

    #[test]
    fn rsa_private_key_pkcs8_pem_roundtrip() {
        let sk = gen_small_key(b"rsa-pkcs8-pem");
        let pem = sk.to_pkcs8_pem();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
        let parsed = BoxedRsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(parsed.to_pkcs1_der(), sk.to_pkcs1_der());
    }

    /// Full encrypted-PKCS#8 round trip on a real RSA key: encrypt to PEM
    /// with PBES2 (AES-256-GCM + PBKDF2-HMAC-SHA256), parse back, and
    /// verify the recovered key signs identically.
    #[test]
    fn rsa_encrypted_pkcs8_pem_roundtrip() {
        let sk = gen_small_key(b"rsa-pkcs8-pem-enc");
        let mut rng = HmacDrbg::<Sha256>::new(b"pbes2-enc", b"nonce", &[]);
        let params = crate::kdf::pbes2::Pbes2Params {
            // Tests run with a tiny iteration count for speed.
            kdf: crate::kdf::pbes2::KdfChoice::Pbkdf2HmacSha256 { iterations: 10_000 },
            cipher: crate::kdf::pbes2::CipherChoice::Aes256Gcm,
            salt_len: 16,
        };
        let pem = sk.to_pkcs8_pem_encrypted(b"swordfish", &params, &mut rng);
        assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"));
        assert!(
            pem.trim_end()
                .ends_with("-----END ENCRYPTED PRIVATE KEY-----")
        );

        let parsed = BoxedRsaPrivateKey::from_pkcs8_pem_encrypted(&pem, b"swordfish").unwrap();
        // PKCS#1 export is byte-deterministic, so the re-serialized keys
        // must match exactly.
        assert_eq!(parsed.to_pkcs1_der(), sk.to_pkcs1_der());

        // Wrong password is rejected.
        assert!(BoxedRsaPrivateKey::from_pkcs8_pem_encrypted(&pem, b"wrong").is_err());

        // Functional: the round-tripped key still signs and verifies.
        let sig = parsed
            .sign_pkcs1v15::<Sha256>(b"via encrypted pkcs8")
            .unwrap();
        sk.public_key()
            .verify_pkcs1v15::<Sha256>(b"via encrypted pkcs8", &sig)
            .unwrap();
    }

    /// Same round trip via AES-256-CBC (PKCS#7 padded), the other PBES2
    /// cipher we support.
    #[test]
    fn rsa_encrypted_pkcs8_der_roundtrip_cbc() {
        let sk = gen_small_key(b"rsa-pkcs8-der-cbc");
        let mut rng = HmacDrbg::<Sha256>::new(b"pbes2-cbc", b"nonce", &[]);
        let params = crate::kdf::pbes2::Pbes2Params {
            kdf: crate::kdf::pbes2::KdfChoice::Pbkdf2HmacSha512 { iterations: 10_000 },
            cipher: crate::kdf::pbes2::CipherChoice::Aes256Cbc,
            salt_len: 16,
        };
        let der = sk.to_pkcs8_der_encrypted(b"pass", &params, &mut rng);
        let parsed = BoxedRsaPrivateKey::from_pkcs8_der_encrypted(&der, b"pass").unwrap();
        assert_eq!(parsed.to_pkcs1_der(), sk.to_pkcs1_der());
    }

    /// SPKI carrying a non-RSA algorithm OID (here: id-Ed25519) must be
    /// rejected, not silently treated as RSA.
    #[test]
    fn rsa_public_key_from_spki_rejects_non_rsa_oid() {
        use crate::der::{encode_bit_string, encode_sequence, oid_tlv};
        // Ed25519 OID `1.3.101.112`, no parameters; key body is irrelevant
        // because we should reject before reaching it.
        let algid = encode_sequence(&oid_tlv(&[1, 3, 101, 112]));
        let dummy_key = [0u8; 32];
        let spki = encode_sequence(&[algid, encode_bit_string(&dummy_key)].concat());
        assert!(BoxedRsaPublicKey::from_spki_der(&spki).is_err());
    }

    /// SPKI for `rsaEncryption` with the parameters field absent must be
    /// rejected (RFC 3279 §2.3.1; matches the strict-NULL fix H-7 applied
    /// to the X.509 SPKI parser).
    #[test]
    fn rsa_public_key_from_spki_rejects_missing_null_params() {
        use crate::der::{encode_bit_string, encode_sequence, oid_tlv};
        // AlgorithmIdentifier with the OID but no NULL after it.
        let algid = encode_sequence(&oid_tlv(&RSA_ENCRYPTION_OID));
        // The BIT STRING content must still be valid PKCS#1 to ensure we're
        // failing on the algid check, not on a later parse step — but the
        // algid check happens first, so even garbage here is fine.
        let dummy = [0u8; 16];
        let spki = encode_sequence(&[algid, encode_bit_string(&dummy)].concat());
        assert!(BoxedRsaPublicKey::from_spki_der(&spki).is_err());
    }

    /// A PEM with the legacy PKCS#1 label (`RSA PUBLIC KEY`) must not be
    /// accepted by the SPKI PEM importer — the label disambiguates the
    /// inner format.
    #[test]
    fn rsa_public_key_from_spki_pem_rejects_pkcs1_label() {
        let sk = gen_small_key(b"rsa-spki-wrong-label");
        // The boxed public key only owns to_pkcs1_der, no to_pkcs1_pem on
        // the public type — wrap manually with the legacy label.
        let pkcs1_pem = crate::der::pem_encode("RSA PUBLIC KEY", &sk.public_key().to_pkcs1_der());
        assert!(BoxedRsaPublicKey::from_spki_pem(&pkcs1_pem).is_err());
    }

    /// PKCS#8 with `version = 1` (v2 of the format, RFC 5958 §2) is not
    /// supported here — the v1 form is what every OpenSSL-style tool emits
    /// for unencrypted RSA.
    #[test]
    fn rsa_private_key_from_pkcs8_rejects_nonzero_version() {
        use crate::der::{
            encode_integer, encode_null, encode_octet_string, encode_sequence, oid_tlv,
        };
        let sk = gen_small_key(b"rsa-pkcs8-v1");
        let algid = encode_sequence(&[oid_tlv(&RSA_ENCRYPTION_OID), encode_null()].concat());
        let der = encode_sequence(
            &[
                encode_integer(&[1]), // version = 1, not 0
                algid,
                encode_octet_string(&sk.to_pkcs1_der()),
            ]
            .concat(),
        );
        assert!(BoxedRsaPrivateKey::from_pkcs8_der(&der).is_err());
    }

    /// PKCS#8 carrying a non-RSA private-key algorithm OID is rejected.
    #[test]
    fn rsa_private_key_from_pkcs8_rejects_non_rsa_oid() {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        // Ed25519 PrivateKey OID `1.3.101.112`, no NULL (RFC 8410).
        let algid = encode_sequence(&oid_tlv(&[1, 3, 101, 112]));
        let dummy = [0u8; 34];
        let der =
            encode_sequence(&[encode_integer(&[0]), algid, encode_octet_string(&dummy)].concat());
        assert!(BoxedRsaPrivateKey::from_pkcs8_der(&der).is_err());
    }

    /// PKCS#8 SPKI with absent NULL parameters is rejected (strict-NULL
    /// policy, fix H-7).
    #[test]
    fn rsa_private_key_from_pkcs8_rejects_missing_null_params() {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let sk = gen_small_key(b"rsa-pkcs8-no-null");
        // AlgorithmIdentifier with no parameters at all.
        let algid = encode_sequence(&oid_tlv(&RSA_ENCRYPTION_OID));
        let der = encode_sequence(
            &[
                encode_integer(&[0]),
                algid,
                encode_octet_string(&sk.to_pkcs1_der()),
            ]
            .concat(),
        );
        assert!(BoxedRsaPrivateKey::from_pkcs8_der(&der).is_err());
    }
}
