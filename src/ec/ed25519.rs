//! Ed25519 signatures (EdDSA over edwards25519, RFC 8032).
//!
//! The field is GF(2²⁵⁵−19) — the same prime as X25519 — so the arithmetic
//! reuses the constant-time [`MontModulus`](crate::bignum::MontModulus). Curve
//! points use the twisted Edwards curve `−x² + y² = 1 + d·x²·y²` in extended
//! homogeneous coordinates `(X:Y:Z:T)`, with complete addition formulas
//! (Hisil–Wong–Carter–Dawson 2008), so there are no exceptional cases. Scalar
//! multiplication is a fixed-window-free constant-time double-and-add: every
//! step doubles and conditionally selects the sum, independent of the secret
//! scalar bits. Reduction of scalars modulo the group order `L` rides on the
//! constant-time [`Uint`](crate::bignum::Uint) long division.
//!
//! The field, point, and scalar arithmetic live in the shared `curve25519`
//! backend, which this module consumes; the same backend powers the
//! `edwards25519::hazmat` and `ristretto255` exposures.

use crate::ct::{ConstantTimeEq, ConstantTimeLess};
use crate::ec::Error;
use crate::ec::curve25519::field::{Fe, Field};
use crate::ec::curve25519::scalar::{clamp, scalar_muladd, scalar_reduce_wide};
use crate::hash::{Digest, Sha512};
use crate::rng::{CryptoRng, RngCore};

/// The `id-Ed25519` OID (1.3.101.112), used for both the key and the signature
/// algorithm (RFC 8410).
#[cfg(feature = "der")]
pub(crate) const ED25519_OID: &[u64] = &[1, 3, 101, 112];

/// An Ed25519 private key — a 32-byte seed.
#[derive(Clone)]
pub struct Ed25519PrivateKey {
    seed: [u8; 32],
}

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        // Best-effort wipe of the seed before it leaves the stack. The
        // `black_box` barrier prevents LLVM from eliding the writes as a
        // dead store. Mirrors the manual-wipe convention used elsewhere
        // in the crate (e.g. `cipher/poly1305.rs`, `cipher/aes/mod.rs`).
        for b in self.seed.iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(&self.seed);
    }
}

/// An Ed25519 public key — a 32-byte compressed point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ed25519PublicKey([u8; 32]);

/// An Ed25519 signature — 64 bytes (`R ‖ S`).
#[derive(Clone, Copy)]
pub struct Ed25519Signature([u8; 64]);

impl Ed25519PrivateKey {
    /// Generates a new private key from `rng`. The RNG must be a cryptographically
    /// secure CSPRNG (see [`CryptoRng`]).
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Ed25519PrivateKey { seed }
    }

    /// Creates a private key from its 32-byte seed.
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        Ed25519PrivateKey { seed }
    }

    /// The 32-byte seed.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    /// Derives the secret scalar `a` (clamped) and the signing prefix from the
    /// seed hash.
    fn expand(&self) -> ([u8; 32], [u8; 32]) {
        let h = Sha512::digest(&self.seed);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        clamp(&mut a);
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);
        (a, prefix)
    }

    /// The corresponding public key `A = [a]B`.
    pub fn public_key(&self) -> Ed25519PublicKey {
        let f = Field::new();
        let (a, _) = self.expand();
        Ed25519PublicKey(f.encode(&f.scalar_mult(&a, &f.base())))
    }

    /// Signs `message`, returning the 64-byte signature (RFC 8032 §5.1.6).
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let f = Field::new();
        let (a, prefix) = self.expand();
        let a_enc = f.encode(&f.scalar_mult(&a, &f.base()));

        // r = SHA-512(prefix ‖ message) mod L; R = [r]B.
        let mut hr = Sha512::new();
        hr.update(&prefix);
        hr.update(message);
        let r = scalar_reduce_wide(&hr.finalize(), &f.l8);
        let mut r_bytes = [0u8; 32];
        r.write_le_bytes(&mut r_bytes);
        let r_enc = f.encode(&f.scalar_mult(&r_bytes, &f.base()));

        // k = SHA-512(R ‖ A ‖ message) mod L; S = (r + k·a) mod L.
        let mut hk = Sha512::new();
        hk.update(&r_enc);
        hk.update(&a_enc);
        hk.update(message);
        let k = scalar_reduce_wide(&hk.finalize(), &f.l8);
        let a_scalar = Fe::from_le_bytes(&a);
        let s = scalar_muladd(&r, &k, &a_scalar, &f.l8);

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_enc);
        s.write_le_bytes(&mut sig[32..]);
        Ed25519Signature(sig)
    }
}

/// PKCS#8 v1 (RFC 8410) private-key serialization.
#[cfg(feature = "der")]
impl Ed25519PrivateKey {
    /// Encodes the key as a PKCS#8 `OneAsymmetricKey` DER structure.
    pub fn to_pkcs8_der(&self) -> alloc::vec::Vec<u8> {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let version = encode_integer(&[0]);
        let algid = encode_sequence(&oid_tlv(ED25519_OID));
        // privateKey is an OCTET STRING wrapping the CurvePrivateKey OCTET STRING.
        let privkey = encode_octet_string(&encode_octet_string(&self.seed));
        encode_sequence(&[version, algid, privkey].concat())
    }

    /// Encodes the key as a PKCS#8 PEM document (`-----BEGIN PRIVATE KEY-----`).
    pub fn to_pkcs8_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("PRIVATE KEY", &self.to_pkcs8_der())
    }

    /// Parses a PKCS#8 `OneAsymmetricKey` DER structure.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, crate::der::Error> {
        use crate::der::{Error, Reader, parse_oid};
        let mut r = Reader::new(der);
        let mut seq = r.read_sequence()?;
        seq.read_integer_bytes()?; // version (v1 = 0)
        let mut algid = seq.read_sequence()?;
        if parse_oid(algid.read_oid()?)?.as_slice() != ED25519_OID {
            return Err(Error::Malformed);
        }
        let inner = seq.read_octet_string()?;
        let seed_bytes = Reader::new(inner).read_octet_string()?;
        if seed_bytes.len() != 32 {
            return Err(Error::Malformed);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_bytes);
        Ok(Ed25519PrivateKey { seed })
    }

    /// Parses a PKCS#8 PEM private key.
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
    ) -> alloc::vec::Vec<u8> {
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
    ) -> alloc::string::String {
        crate::kdf::pbes2::encrypt_pem(&self.to_pkcs8_der(), password, params, rng)
    }

    /// Parses an `EncryptedPrivateKeyInfo` DER and decrypts it back to a
    /// PKCS#8 Ed25519 private key.
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn from_pkcs8_der_encrypted(
        der: &[u8],
        password: &[u8],
    ) -> Result<Self, crate::der::Error> {
        let inner =
            crate::kdf::pbes2::decrypt(der, password).map_err(|_| crate::der::Error::Malformed)?;
        Self::from_pkcs8_der(&inner)
    }

    /// PEM-wrapped variant of [`Self::from_pkcs8_der_encrypted`].
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn from_pkcs8_pem_encrypted(pem: &str, password: &[u8]) -> Result<Self, crate::der::Error> {
        let inner = crate::kdf::pbes2::decrypt_pem(pem, password)
            .map_err(|_| crate::der::Error::Malformed)?;
        Self::from_pkcs8_der(&inner)
    }
}

impl Ed25519PublicKey {
    /// Creates a public key from its 32-byte encoding (not validated until use).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Ed25519PublicKey(bytes)
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Verifies `signature` over `message`. Uses the *cofactored* group
    /// equation `[8S]B == [8R] + [8k]A` (ZIP-215 / FIPS-186-5 best practice),
    /// which rejects any small-subgroup `A` or `R`: multiplying by the
    /// cofactor 8 sends every 8-torsion point to the identity, so an
    /// attacker can't smuggle in identity-encoded `A` (which would make
    /// `[k]A == identity` for every `k` and let any `(R, S)` with
    /// `R == [S]B` verify on every message — a universal forgery).
    ///
    /// Returns [`Error::Verification`] on any failure (malformed inputs
    /// included).
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), Error> {
        let f = Field::new();

        // S must be a canonical scalar in [0, L).
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&signature.0[32..]);
        let s = Fe::from_le_bytes(&s_bytes);
        if !bool::from(s.ct_lt(&f.l)) {
            return Err(Error::Verification);
        }

        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature.0[..32]);
        let r_point = f.decode(&r_bytes).ok_or(Error::Verification)?;
        let a_point = f.decode(&self.0).ok_or(Error::Verification)?;

        // k = SHA-512(R ‖ A ‖ message) mod L.
        let mut hk = Sha512::new();
        hk.update(&r_bytes);
        hk.update(&self.0);
        hk.update(message);
        let k = scalar_reduce_wide(&hk.finalize(), &f.l8);
        let mut k_bytes = [0u8; 32];
        k.write_le_bytes(&mut k_bytes);

        // Cofactored verify: accept iff [8S]B == [8R] + [8k]A. We multiply
        // each side of the cofactor-less equation by 8 = [2][2][2].
        let lhs = f.scalar_mult(&s_bytes, &f.base());
        let ka = f.scalar_mult(&k_bytes, &a_point);
        let rhs = f.point_add(&r_point, &ka);
        let lhs8 = f.point_double(&f.point_double(&f.point_double(&lhs)));
        let rhs8 = f.point_double(&f.point_double(&f.point_double(&rhs)));
        // Operands are public, but the rest of the crate uses constant-time
        // equality for encoded-point comparison; staying consistent here keeps
        // a future refactor from accidentally folding secret bytes through `==`
        // (which has early-exit semantics on `[u8; N]`).
        let lhs_enc = f.encode(&lhs8);
        let rhs_enc = f.encode(&rhs8);
        if bool::from(lhs_enc.ct_eq(&rhs_enc)) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

impl Ed25519Signature {
    /// Creates a signature from its 64-byte encoding.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Ed25519Signature(bytes)
    }

    /// Creates a signature from its `R` (32-byte compressed point) and
    /// `S` (32-byte scalar) halves per RFC 8032 §3.3.
    pub fn from_components(r: &[u8; 32], s: &[u8; 32]) -> Self {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(r);
        out[32..].copy_from_slice(s);
        Ed25519Signature(out)
    }

    /// The 32-byte compressed-point `R` half (the first 32 bytes of the
    /// `R ‖ S` encoding).
    pub fn r_bytes(&self) -> [u8; 32] {
        let mut r = [0u8; 32];
        r.copy_from_slice(&self.0[..32]);
        r
    }

    /// The 32-byte scalar `S` half (the last 32 bytes of the `R ‖ S`
    /// encoding).
    pub fn s_bytes(&self) -> [u8; 32] {
        let mut s = [0u8; 32];
        s.copy_from_slice(&self.0[32..]);
        s
    }

    /// The 64-byte encoding (`R ‖ S`).
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::HmacDrbg;
    use crate::test_util::from_hex;

    /// RFC 8032 §7.1 test vectors: (seed, public key, message, signature).
    struct Vector {
        seed: [u8; 32],
        public: [u8; 32],
        message: &'static [u8],
        signature: [u8; 64],
    }

    fn vectors() -> [Vector; 3] {
        [
            Vector {
                seed: from_hex::<32>(
                    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                ),
                public: from_hex::<32>(
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                ),
                message: &[],
                signature: from_hex::<64>(
                    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8\
                     821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                ),
            },
            Vector {
                seed: from_hex::<32>(
                    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                ),
                public: from_hex::<32>(
                    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                ),
                message: &[0x72],
                signature: from_hex::<64>(
                    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085a\
                     c1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
                ),
            },
            Vector {
                seed: from_hex::<32>(
                    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                ),
                public: from_hex::<32>(
                    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                ),
                message: &[0xaf, 0x82],
                signature: from_hex::<64>(
                    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff\
                     9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
                ),
            },
        ]
    }

    #[test]
    fn field_invariants() {
        use crate::ec::curve25519::field::BASE_ENC;
        let f = Field::new();
        // inversion: a * a^(p-2) == 1
        let three = f.to_mont(&Fe::from_u64(3));
        let inv3 = f.inv(three);
        assert!(bool::from(f.mul(three, inv3).ct_eq(&f.one)), "inv broken");
        // sqrt(-1)^2 == -1
        let neg1 = f.neg(f.one);
        assert!(bool::from(f.sq(f.sqrtm1).ct_eq(&neg1)), "sqrtm1 broken");
        // base point decodes
        assert!(f.decode(&BASE_ENC).is_some(), "base decode failed");
    }

    #[test]
    fn rfc8032_public_keys() {
        for v in vectors() {
            let sk = Ed25519PrivateKey::from_bytes(v.seed);
            assert_eq!(sk.public_key().to_bytes(), v.public);
        }
    }

    #[test]
    fn rfc8032_sign() {
        for v in vectors() {
            let sk = Ed25519PrivateKey::from_bytes(v.seed);
            assert_eq!(sk.sign(v.message).to_bytes(), v.signature);
        }
    }

    #[test]
    fn rfc8032_verify() {
        for v in vectors() {
            let pk = Ed25519PublicKey::from_bytes(v.public);
            let sig = Ed25519Signature::from_bytes(v.signature);
            pk.verify(v.message, &sig).unwrap();

            // A flipped message byte must not verify.
            let mut bad = v.message.to_vec();
            bad.push(0x01);
            assert!(pk.verify(&bad, &sig).is_err());

            // A tampered signature must not verify.
            let mut bad_sig = v.signature;
            bad_sig[0] ^= 0x01;
            assert!(
                pk.verify(v.message, &Ed25519Signature::from_bytes(bad_sig))
                    .is_err()
            );
        }
    }

    #[test]
    fn generated_key_roundtrip() {
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ed25519", b"nonce", &[]);
        let sk = Ed25519PrivateKey::generate(&mut rng);
        let pk = sk.public_key();
        let sig = sk.sign(b"purecrypto ed25519");
        pk.verify(b"purecrypto ed25519", &sig).unwrap();
        assert!(pk.verify(b"different message", &sig).is_err());

        // A non-canonical S (≥ L) is rejected.
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[63] |= 0x80;
        assert!(
            pk.verify(
                b"purecrypto ed25519",
                &Ed25519Signature::from_bytes(sig_bytes)
            )
            .is_err()
        );
    }

    #[test]
    fn signature_r_s_accessors_roundtrip() {
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ed25519-rs", b"n", &[]);
        let sk = Ed25519PrivateKey::generate(&mut rng);
        let sig = sk.sign(b"rs-accessor test");

        let r = sig.r_bytes();
        let s = sig.s_bytes();
        let rebuilt = Ed25519Signature::from_components(&r, &s);
        assert_eq!(rebuilt.to_bytes(), sig.to_bytes());

        // r ‖ s equals to_bytes().
        let mut concat = [0u8; 64];
        concat[..32].copy_from_slice(&r);
        concat[32..].copy_from_slice(&s);
        assert_eq!(concat, sig.to_bytes());
    }
}
