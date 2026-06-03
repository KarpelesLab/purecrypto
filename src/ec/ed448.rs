//! Ed448 signatures (EdDSA over edwards448, RFC 8032).
//!
//! The field is GF(2⁴⁴⁸−2²²⁴−1); the arithmetic reuses the constant-time
//! [`MontModulus`](crate::bignum::MontModulus) over seven 64-bit limbs. Curve
//! points use the untwisted Edwards curve `x² + y² = 1 + d·x²·y²` (`a = +1`,
//! `d = −39081`) in extended homogeneous coordinates `(X:Y:Z:T)`, with complete
//! addition formulas (Hisil–Wong–Carter–Dawson 2008 for `a = +1`), so there are
//! no exceptional cases. Scalar multiplication is a constant-time
//! double-and-add. Reduction of scalars modulo the group order `L` rides on the
//! constant-time [`Uint`](crate::bignum::Uint) long division.
//!
//! Hashing is SHAKE256 (FIPS 202): the seed expansion, the nonce `r`, and the
//! challenge `k` are all 114-byte SHAKE256 outputs, prefixed by the `dom4`
//! domain string per RFC 8032 §5.2.
//!
//! Only "pure" Ed448 (`Ed448`, phflag = 0) is implemented; the prehashed
//! `Ed448ph` variant is out of scope. A context string (≤ 255 bytes) may be
//! supplied via [`Ed448PrivateKey::sign_ctx`] / [`Ed448PublicKey::verify_ctx`];
//! the no-context [`sign`](Ed448PrivateKey::sign) /
//! [`verify`](Ed448PublicKey::verify) entry points use the empty context.

use crate::ct::ConstantTimeLess;
use crate::ec::Error;
use crate::ec::curve448::field::{Fe, Field};
use crate::ec::curve448::scalar::{prune, scalar_muladd, scalar_reduce_wide};
use crate::hash::{ExtendableOutput, Shake256, XofReader};
use crate::rng::{CryptoRng, RngCore};

/// The `id-Ed448` OID (1.3.101.113), used for both the key and the signature
/// algorithm (RFC 8410).
#[cfg(feature = "der")]
pub(crate) const ED448_OID: &[u64] = &[1, 3, 101, 113];

/// SHAKE256 output length for every Ed448 hash (RFC 8032 §5.2): 114 bytes.
const HASH_LEN: usize = 114;

/// Computes the 114-byte SHAKE256 digest of the concatenated `parts`, prefixed
/// by the `dom4(phflag=0, ctx)` domain string `"SigEd448" ‖ 0x00 ‖ len(ctx) ‖
/// ctx`. Returns the raw 114-byte buffer.
fn shake_dom4(ctx: &[u8], parts: &[&[u8]]) -> [u8; HASH_LEN] {
    let mut h = Shake256::new();
    h.update(b"SigEd448");
    h.update(&[0u8]); // phflag = 0 (pure Ed448)
    h.update(&[ctx.len() as u8]);
    h.update(ctx);
    for p in parts {
        h.update(p);
    }
    let mut reader = h.finalize_xof();
    let mut out = [0u8; HASH_LEN];
    reader.read(&mut out);
    out
}

/// An Ed448 private key — a 57-byte seed.
#[derive(Clone)]
pub struct Ed448PrivateKey {
    seed: [u8; 57],
}

impl Drop for Ed448PrivateKey {
    fn drop(&mut self) {
        // Best-effort wipe of the seed before it leaves the stack; the
        // `black_box` barrier prevents LLVM from eliding the writes as a dead
        // store (mirrors the Ed25519 convention).
        for b in self.seed.iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(&self.seed);
    }
}

/// An Ed448 public key — a 57-byte compressed point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ed448PublicKey([u8; 57]);

/// An Ed448 signature — 114 bytes (`R ‖ S`).
#[derive(Clone, Copy)]
pub struct Ed448Signature([u8; 114]);

impl Ed448PrivateKey {
    /// Generates a new private key from `rng`. The RNG must be a
    /// cryptographically secure CSPRNG (see [`CryptoRng`]).
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 57];
        rng.fill_bytes(&mut seed);
        Ed448PrivateKey { seed }
    }

    /// Creates a private key from its 57-byte seed.
    pub fn from_bytes(seed: [u8; 57]) -> Self {
        Ed448PrivateKey { seed }
    }

    /// The 57-byte seed.
    pub fn to_bytes(&self) -> [u8; 57] {
        self.seed
    }

    /// Derives the secret scalar `s` (pruned, 57 bytes little-endian) and the
    /// 57-byte signing prefix from the seed hash (RFC 8032 §5.2.5).
    fn expand(&self) -> ([u8; 57], [u8; 57]) {
        // h = SHAKE256(seed, 114). No dom4 prefix on the key-expansion hash.
        let mut h = Shake256::new();
        h.update(&self.seed);
        let mut reader = h.finalize_xof();
        let mut hbuf = [0u8; HASH_LEN];
        reader.read(&mut hbuf);

        let mut s = [0u8; 57];
        s.copy_from_slice(&hbuf[..57]);
        prune(&mut s);
        let mut prefix = [0u8; 57];
        prefix.copy_from_slice(&hbuf[57..]);
        (s, prefix)
    }

    /// The corresponding public key `A = [s]B`.
    pub fn public_key(&self) -> Ed448PublicKey {
        let f = Field::new();
        let (s, _) = self.expand();
        Ed448PublicKey(f.encode(&f.scalar_mult(&s, &f.base())))
    }

    /// Signs `message` with the empty context, returning the 114-byte signature
    /// (RFC 8032 §5.2.6, pure Ed448).
    pub fn sign(&self, message: &[u8]) -> Ed448Signature {
        self.sign_ctx(message, &[])
    }

    /// Signs `message` with the given `context` string (≤ 255 bytes).
    ///
    /// # Panics
    /// Panics if `context` is longer than 255 bytes (the `dom4` length field is
    /// a single octet).
    pub fn sign_ctx(&self, message: &[u8], context: &[u8]) -> Ed448Signature {
        assert!(context.len() <= 255, "Ed448 context must be ≤ 255 bytes");
        let f = Field::new();
        let (s, prefix) = self.expand();
        let a_enc = f.encode(&f.scalar_mult(&s, &f.base()));

        // r = SHAKE256(dom4(0,ctx) ‖ prefix ‖ M, 114) mod L; R = [r]B.
        let r_hash = shake_dom4(context, &[&prefix, message]);
        let r = scalar_reduce_wide(&r_hash, &f.l15);
        let r_scalar = fe_to_scalar_bytes(&r);
        let r_enc = f.encode(&f.scalar_mult(&r_scalar, &f.base()));

        // k = SHAKE256(dom4(0,ctx) ‖ R ‖ A ‖ M, 114) mod L; S = (r + k·s) mod L.
        let k_hash = shake_dom4(context, &[&r_enc, &a_enc, message]);
        let k = scalar_reduce_wide(&k_hash, &f.l15);
        let s_scalar = Fe::from_le_bytes(&s[..56]); // s[56] == 0 after pruning
        let sig_s = scalar_muladd(&r, &k, &s_scalar, &f.l15);

        let mut sig = [0u8; 114];
        sig[..57].copy_from_slice(&r_enc);
        // S is < L < 2⁴⁴⁶, so it fits in 56 bytes; byte 56 (the 57th) is 0.
        let mut sb = [0u8; 56];
        sig_s.write_le_bytes(&mut sb);
        sig[57..113].copy_from_slice(&sb);
        Ed448Signature(sig)
    }
}

/// Renders a scalar `< L` as the 57-byte little-endian buffer the point
/// `scalar_mult` consumes (the top byte is always 0 since `L < 2⁴⁴⁶`).
fn fe_to_scalar_bytes(x: &Fe) -> [u8; 57] {
    let mut out = [0u8; 57];
    let mut b = [0u8; 56];
    x.write_le_bytes(&mut b);
    out[..56].copy_from_slice(&b);
    out
}

/// PKCS#8 v1 (RFC 8410) private-key serialization.
#[cfg(feature = "der")]
impl Ed448PrivateKey {
    /// Encodes the key as a PKCS#8 `OneAsymmetricKey` DER structure.
    pub fn to_pkcs8_der(&self) -> alloc::vec::Vec<u8> {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let version = encode_integer(&[0]);
        let algid = encode_sequence(&oid_tlv(ED448_OID));
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
        if parse_oid(algid.read_oid()?)?.as_slice() != ED448_OID {
            return Err(Error::Malformed);
        }
        let inner = seq.read_octet_string()?;
        let seed_bytes = Reader::new(inner).read_octet_string()?;
        if seed_bytes.len() != 57 {
            return Err(Error::Malformed);
        }
        let mut seed = [0u8; 57];
        seed.copy_from_slice(seed_bytes);
        Ok(Ed448PrivateKey { seed })
    }

    /// Parses a PKCS#8 PEM private key.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_pkcs8_der(&crate::der::pem_decode(pem, "PRIVATE KEY")?)
    }

    /// Encrypts the PKCS#8 encoding under PBES2 (RFC 5958 §3 + RFC 8018 §6.2)
    /// with caller-supplied parameters, returning the DER-encoded
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

    /// Parses an `EncryptedPrivateKeyInfo` DER and decrypts it back to a PKCS#8
    /// Ed448 private key.
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

impl Ed448PublicKey {
    /// Creates a public key from its 57-byte encoding (not validated until use).
    pub fn from_bytes(bytes: [u8; 57]) -> Self {
        Ed448PublicKey(bytes)
    }

    /// The 57-byte encoding.
    pub fn to_bytes(&self) -> [u8; 57] {
        self.0
    }

    /// Verifies `signature` over `message` with the empty context.
    pub fn verify(&self, message: &[u8], signature: &Ed448Signature) -> Result<(), Error> {
        self.verify_ctx(message, signature, &[])
    }

    /// Verifies `signature` over `message` with the given `context` string.
    ///
    /// Uses the *cofactored* group equation `[4S]B == [4R] + [4k]A`
    /// (RFC 8032 §5.2.7 permits the cofactored check; it additionally rejects
    /// any small-subgroup `A` or `R`). Returns [`Error::Verification`] on any
    /// failure (malformed inputs included).
    ///
    /// # Panics
    /// Panics if `context` is longer than 255 bytes.
    pub fn verify_ctx(
        &self,
        message: &[u8],
        signature: &Ed448Signature,
        context: &[u8],
    ) -> Result<(), Error> {
        assert!(context.len() <= 255, "Ed448 context must be ≤ 255 bytes");
        let f = Field::new();

        // Split R ‖ S. The 57th byte of S (signature byte 113) must be 0, and S
        // must be a canonical scalar in [0, L).
        let mut r_bytes = [0u8; 57];
        r_bytes.copy_from_slice(&signature.0[..57]);
        if signature.0[113] != 0 {
            return Err(Error::Verification);
        }
        let mut s_bytes = [0u8; 56];
        s_bytes.copy_from_slice(&signature.0[57..113]);
        let s = Fe::from_le_bytes(&s_bytes);
        if !bool::from(s.ct_lt(&f.l)) {
            return Err(Error::Verification);
        }

        let r_point = f.decode(&r_bytes).ok_or(Error::Verification)?;
        let a_point = f.decode(&self.0).ok_or(Error::Verification)?;

        // k = SHAKE256(dom4(0,ctx) ‖ R ‖ A ‖ M, 114) mod L.
        let k_hash = shake_dom4(context, &[&r_bytes, &self.0, message]);
        let k = scalar_reduce_wide(&k_hash, &f.l15);
        let k_scalar = fe_to_scalar_bytes(&k);
        let s_scalar = fe_to_scalar_bytes(&s);

        // Cofactored verify: accept iff [4S]B == [4R] + [4k]A. Multiply each
        // side of the cofactor-less equation by 4 = [2][2].
        let lhs = f.scalar_mult(&s_scalar, &f.base());
        let ka = f.scalar_mult(&k_scalar, &a_point);
        let rhs = f.point_add(&r_point, &ka);
        let lhs4 = f.point_double(&f.point_double(&lhs));
        let rhs4 = f.point_double(&f.point_double(&rhs));
        if bool::from(f.point_ct_eq(&lhs4, &rhs4)) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

impl Ed448Signature {
    /// Creates a signature from its 114-byte encoding.
    pub fn from_bytes(bytes: [u8; 114]) -> Self {
        Ed448Signature(bytes)
    }

    /// Creates a signature from its `R` (57-byte compressed point) and `S`
    /// (57-byte scalar) halves.
    pub fn from_components(r: &[u8; 57], s: &[u8; 57]) -> Self {
        let mut out = [0u8; 114];
        out[..57].copy_from_slice(r);
        out[57..].copy_from_slice(s);
        Ed448Signature(out)
    }

    /// The 57-byte compressed-point `R` half.
    pub fn r_bytes(&self) -> [u8; 57] {
        let mut r = [0u8; 57];
        r.copy_from_slice(&self.0[..57]);
        r
    }

    /// The 57-byte scalar `S` half.
    pub fn s_bytes(&self) -> [u8; 57] {
        let mut s = [0u8; 57];
        s.copy_from_slice(&self.0[57..]);
        s
    }

    /// The 114-byte encoding (`R ‖ S`).
    pub fn to_bytes(&self) -> [u8; 114] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct::ConstantTimeEq;
    use crate::rng::HmacDrbg;
    use crate::test_util::from_hex;

    /// RFC 8032 §7.4 test vectors: (seed, public key, context, message,
    /// signature). All use the empty context unless noted.
    struct Vector {
        seed: [u8; 57],
        public: [u8; 57],
        context: &'static [u8],
        message: alloc::vec::Vec<u8>,
        signature: [u8; 114],
    }

    fn vectors() -> alloc::vec::Vec<Vector> {
        alloc::vec![
            // "Blank" — empty message, empty context.
            Vector {
                seed: from_hex::<57>(
                    "6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b"
                ),
                public: from_hex::<57>(
                    "5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180"
                ),
                context: &[],
                message: alloc::vec![],
                signature: from_hex::<114>(
                    "533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600"
                ),
            },
            // "1 octet" — message 0x03, empty context.
            Vector {
                seed: from_hex::<57>(
                    "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
                ),
                public: from_hex::<57>(
                    "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
                ),
                context: &[],
                message: alloc::vec![0x03],
                signature: from_hex::<114>(
                    "26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00"
                ),
            },
            // "1 octet (with context)" — message 0x03, context "foo".
            Vector {
                seed: from_hex::<57>(
                    "c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e"
                ),
                public: from_hex::<57>(
                    "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480"
                ),
                context: b"foo",
                message: alloc::vec![0x03],
                signature: from_hex::<114>(
                    "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00"
                ),
            },
        ]
    }

    #[test]
    fn field_invariants() {
        use crate::ec::curve448::field::BASE_ENC;
        let f = Field::new();
        // inversion: a * a^(p-2) == 1
        let three = f.to_mont(&Fe::from_u64(3));
        let inv3 = f.inv(three);
        assert!(bool::from(f.mul(three, inv3).ct_eq(&f.one)), "inv broken");
        // base point decodes
        assert!(f.decode(&BASE_ENC).is_some(), "base decode failed");
        // doubling agrees with self-addition
        let b = f.base();
        let d1 = f.point_double(&b);
        let d2 = f.point_add(&b, &b);
        assert!(bool::from(f.point_ct_eq(&d1, &d2)), "double != add(P,P)");
    }

    #[test]
    fn rfc8032_public_keys() {
        for v in vectors() {
            let sk = Ed448PrivateKey::from_bytes(v.seed);
            assert_eq!(sk.public_key().to_bytes(), v.public);
        }
    }

    #[test]
    fn rfc8032_sign() {
        for v in vectors() {
            let sk = Ed448PrivateKey::from_bytes(v.seed);
            assert_eq!(
                sk.sign_ctx(&v.message, v.context).to_bytes(),
                v.signature,
                "signature mismatch"
            );
        }
    }

    #[test]
    fn rfc8032_verify() {
        for v in vectors() {
            let pk = Ed448PublicKey::from_bytes(v.public);
            let sig = Ed448Signature::from_bytes(v.signature);
            pk.verify_ctx(&v.message, &sig, v.context).unwrap();

            // A flipped message byte must not verify.
            let mut bad = v.message.clone();
            bad.push(0x01);
            assert!(pk.verify_ctx(&bad, &sig, v.context).is_err());

            // A tampered signature must not verify.
            let mut bad_sig = v.signature;
            bad_sig[0] ^= 0x01;
            assert!(
                pk.verify_ctx(&v.message, &Ed448Signature::from_bytes(bad_sig), v.context)
                    .is_err()
            );
        }
    }

    #[test]
    fn generated_key_roundtrip() {
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ed448", b"nonce", &[]);
        let sk = Ed448PrivateKey::generate(&mut rng);
        let pk = sk.public_key();
        let sig = sk.sign(b"purecrypto ed448");
        pk.verify(b"purecrypto ed448", &sig).unwrap();
        assert!(pk.verify(b"different message", &sig).is_err());

        // A non-canonical S (≥ L) is rejected: set the top of the 56-byte S.
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[112] = 0xff;
        assert!(
            pk.verify(b"purecrypto ed448", &Ed448Signature::from_bytes(sig_bytes))
                .is_err()
        );
    }

    #[test]
    fn context_binds_signature() {
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ed448-ctx", b"n", &[]);
        let sk = Ed448PrivateKey::generate(&mut rng);
        let pk = sk.public_key();
        let sig = sk.sign_ctx(b"msg", b"ctx-a");
        pk.verify_ctx(b"msg", &sig, b"ctx-a").unwrap();
        // A different context must not verify.
        assert!(pk.verify_ctx(b"msg", &sig, b"ctx-b").is_err());
    }

    #[test]
    fn signature_r_s_accessors_roundtrip() {
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ed448-rs", b"n", &[]);
        let sk = Ed448PrivateKey::generate(&mut rng);
        let sig = sk.sign(b"rs-accessor test");
        let r = sig.r_bytes();
        let s = sig.s_bytes();
        let rebuilt = Ed448Signature::from_components(&r, &s);
        assert_eq!(rebuilt.to_bytes(), sig.to_bytes());
    }

    #[cfg(feature = "der")]
    #[test]
    fn pkcs8_der_pem_roundtrip() {
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ed448-pkcs8", b"n", &[]);
        let sk = Ed448PrivateKey::generate(&mut rng);

        // DER roundtrip preserves the seed (and hence the public key).
        let der = sk.to_pkcs8_der();
        let sk2 = Ed448PrivateKey::from_pkcs8_der(&der).unwrap();
        assert_eq!(sk2.to_bytes(), sk.to_bytes());
        assert_eq!(sk2.public_key().to_bytes(), sk.public_key().to_bytes());

        // PEM roundtrip likewise.
        let pem = sk.to_pkcs8_pem();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        let sk3 = Ed448PrivateKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(sk3.to_bytes(), sk.to_bytes());

        // The DER must carry the id-Ed448 OID (1.3.101.113) — the encoded
        // OID body is 2b6571 (40·1+3 = 0x2b, 101 = 0x65, 113 = 0x71).
        assert!(
            der.windows(3).any(|w| w == [0x2b, 0x65, 0x71]),
            "id-Ed448 OID not present in DER"
        );
    }

    #[cfg(all(feature = "der", feature = "kdf"))]
    #[test]
    fn pkcs8_encrypted_roundtrip() {
        use crate::kdf::pbes2::Pbes2Params;
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ed448-enc", b"n", &[]);
        let sk = Ed448PrivateKey::generate(&mut rng);
        let params = Pbes2Params::default();
        let der = sk.to_pkcs8_der_encrypted(b"hunter2", &params, &mut rng);
        let sk2 = Ed448PrivateKey::from_pkcs8_der_encrypted(&der, b"hunter2").unwrap();
        assert_eq!(sk2.to_bytes(), sk.to_bytes());
        // A wrong password must fail.
        assert!(Ed448PrivateKey::from_pkcs8_der_encrypted(&der, b"wrong").is_err());
    }
}
