//! Ed25519 signatures (EdDSA over edwards25519, RFC 8032).
//!
//! The field is GF(2²⁵⁵−19) — the same prime as X25519 — implemented in the
//! constant-time unsaturated 5×51-bit limb representation
//! (`ec::curve25519::field`). Curve
//! points use the twisted Edwards curve `−x² + y² = 1 + d·x²·y²` in extended
//! homogeneous coordinates `(X:Y:Z:T)`, with complete addition formulas
//! (Hisil–Wong–Carter–Dawson 2008), so there are no exceptional cases. Secret
//! scalar multiplications are constant-time fixed-window ladders; signature
//! *verification* — whose inputs are all public — uses clearly-marked
//! variable-time double-base multiplication for speed. Reduction of scalars
//! modulo the group order `L` rides on the constant-time
//! [`Uint`](crate::bignum::Uint) long division.
//!
//! The field, point, and scalar arithmetic live in the shared `curve25519`
//! backend, which this module consumes; the same backend powers the
//! `edwards25519::hazmat` and `ristretto255` exposures.
//!
//! **Verification is cofactored** (`[8S]B == [8R] + [8k]A`): it may accept
//! some torsion-tainted signatures that a cofactorless verifier rejects (never
//! the reverse for canonical inputs), so implementations disagree on those
//! edge cases — do not use this for consensus-critical validation.
//! [`Ed25519PublicKey::verify_libsodium`] instead reproduces libsodium's
//! `crypto_sign_verify_detached` accept/reject decisions bit for bit
//! (cofactorless, small-order `R` and `A` rejected).
//!
//! # libsodium interoperability
//!
//! - libsodium's 64-byte secret key (`seed ‖ pk`) maps to
//!   [`Ed25519PrivateKey::from_keypair_bytes`] (checked) /
//!   [`Ed25519PrivateKey::from_keypair_bytes_unchecked`] (trusts the stored
//!   public key, as libsodium does) and
//!   [`Ed25519PrivateKey::to_keypair_bytes`].
//! - `crypto_sign_verify_detached` maps to
//!   [`Ed25519PublicKey::verify_libsodium`].
//! - `crypto_sign_ed25519_pk_to_curve25519` /
//!   `crypto_sign_ed25519_sk_to_curve25519` map to
//!   [`Ed25519PublicKey::to_x25519`] / [`Ed25519PrivateKey::to_x25519`].

use crate::ct::ConstantTimeLess;
use crate::ec::Error;
use crate::ec::curve25519::field::{Field, ScalarInt};
use crate::ec::curve25519::scalar::{clamp, scalar_muladd, scalar_reduce_wide};
use crate::ec::x25519::{X25519PrivateKey, X25519PublicKey};
use crate::hash::{Digest, Sha512};
use crate::rng::{CryptoRng, RngCore};

/// The `id-Ed25519` OID (1.3.101.112), used for both the key and the signature
/// algorithm (RFC 8410).
#[cfg(all(feature = "der", feature = "alloc"))]
pub(crate) const ED25519_OID: &[u64] = &[1, 3, 101, 112];

/// An Ed25519 private key — a 32-byte seed.
#[derive(Clone)]
pub struct Ed25519PrivateKey {
    seed: [u8; 32],
    /// The encoded public key `A`, derived once at construction: signing
    /// hashes it into every challenge, and recomputing it was a full
    /// fixed-base scalar multiplication per signature. Public, so it is not
    /// wiped on drop.
    public: [u8; 32],
}

impl Drop for Ed25519PrivateKey {
    fn drop(&mut self) {
        // Best-effort wipe of the seed before it leaves the stack, through
        // `Zeroize` (volatile stores plus a compiler fence, so LLVM cannot
        // elide the writes as a dead store).
        wipe(&mut self.seed);
    }
}

impl crate::zeroize::ZeroizeOnDrop for Ed25519PrivateKey {}

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
        Self::from_seed(seed)
    }

    /// Creates a private key from its 32-byte seed.
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        Self::from_seed(seed)
    }

    /// The 32-byte seed.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    /// Creates a private key from libsodium's 64-byte secret-key format
    /// `seed ‖ public_key` (`crypto_sign_SECRETKEYBYTES`), **checking** that
    /// the stored public key is the one the seed derives.
    ///
    /// This costs one fixed-base scalar multiplication (the same as
    /// [`from_bytes`](Self::from_bytes)). Returns [`Error::InvalidInput`] if
    /// the stored half does not match; prefer this over
    /// [`from_keypair_bytes_unchecked`](Self::from_keypair_bytes_unchecked)
    /// whenever the 64 bytes come from anywhere you do not fully control.
    pub fn from_keypair_bytes(bytes: &[u8; 64]) -> Result<Self, Error> {
        use crate::ct::ConstantTimeEq;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes[..32]);
        let key = Self::from_seed(seed);
        wipe(&mut seed);
        if bool::from(key.public[..].ct_eq(&bytes[32..])) {
            Ok(key)
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// Creates a private key from libsodium's 64-byte secret-key format
    /// `seed ‖ public_key`, **trusting** the stored public key without
    /// recomputing it — exactly what libsodium's `crypto_sign_detached` does
    /// with its `sk` argument. No scalar multiplication is performed.
    ///
    /// # Caveat: a mismatched public key leaks the private key
    ///
    /// The public key is hashed into every signature's challenge
    /// `k = SHA-512(R ‖ A ‖ M)`, while the nonce `r = SHA-512(prefix ‖ M)`
    /// depends only on the seed and message. If the stored `A` is not the
    /// seed's real public key:
    ///
    /// - every signature produced is invalid under the real key (and under
    ///   the stored one);
    /// - worse, anyone who obtains signatures over the **same message** under
    ///   two different stored public keys gets `S₁ = r + k₁·a` and
    ///   `S₂ = r + k₂·a` with the same `r`, and solves for the secret scalar
    ///   `a = (S₁ − S₂)/(k₁ − k₂)`. This is the well-known libsodium
    ///   "wrong public key" signing-oracle misuse.
    ///
    /// Use this only for key material you produced yourself (or verified
    /// once with [`from_keypair_bytes`](Self::from_keypair_bytes)) and stored
    /// with integrity protection; it exists to avoid the per-load scalar
    /// multiplication when interoperating with libsodium's key format.
    /// [`from_bytes`](Self::from_bytes) (seed only) always recomputes the
    /// public key and is unaffected.
    pub fn from_keypair_bytes_unchecked(bytes: &[u8; 64]) -> Self {
        let mut key = Ed25519PrivateKey {
            seed: [0u8; 32],
            public: [0u8; 32],
        };
        key.seed.copy_from_slice(&bytes[..32]);
        key.public.copy_from_slice(&bytes[32..]);
        key
    }

    /// The 64-byte libsodium secret-key encoding `seed ‖ public_key`. The
    /// first half is secret key material; the caller owns the returned array
    /// and is responsible for wiping it.
    pub fn to_keypair_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.seed);
        out[32..].copy_from_slice(&self.public);
        out
    }

    /// Converts this signing key to the X25519 private key of the
    /// birationally equivalent Montgomery curve, as libsodium's
    /// `crypto_sign_ed25519_sk_to_curve25519`: the first 32 bytes of
    /// `SHA-512(seed)`, clamped (RFC 7748 §5 / RFC 8032 §5.1.5). The result's
    /// [`to_bytes`](X25519PrivateKey::to_bytes) is byte-identical to
    /// libsodium's output, and its public key equals
    /// `self.public_key().to_x25519()` for a key whose public half is genuine.
    ///
    /// Reusing one key pair for both signatures and key agreement is a
    /// cross-protocol design decision the caller owns; prefer independent keys
    /// where you can. Constant-time; the intermediate hash is wiped.
    pub fn to_x25519(&self) -> X25519PrivateKey {
        let (mut a, mut prefix) = self.expand();
        wipe(&mut prefix);
        let key = X25519PrivateKey::from_bytes(a);
        wipe(&mut a);
        key
    }

    /// Derives the secret scalar `a` (clamped) and the signing prefix from the
    /// seed hash.
    ///
    /// Both halves are secret; the caller wipes them ([`wipe`]) once done.
    /// The 64-byte seed hash they are cut from is wiped here.
    fn expand(&self) -> ([u8; 32], [u8; 32]) {
        let mut h = Sha512::digest(&self.seed);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        clamp(&mut a);
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);
        wipe(&mut h);
        (a, prefix)
    }

    /// Builds the key from its seed, deriving the public key `A = [a]B` once.
    fn from_seed(seed: [u8; 32]) -> Self {
        let mut key = Ed25519PrivateKey {
            seed,
            public: [0u8; 32],
        };
        let f = Field::new();
        let (mut a, mut prefix) = key.expand();
        key.public = f.encode(&f.mul_base(&a));
        wipe(&mut a);
        wipe(&mut prefix);
        key
    }

    /// The corresponding public key `A = [a]B` (computed at construction).
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.public)
    }

    /// Signs `message`, returning the 64-byte signature (RFC 8032 §5.1.6).
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let f = Field::new();
        let (mut a, mut prefix) = self.expand();
        let a_enc = self.public;

        // r = SHA-512(prefix ‖ message) mod L; R = [r]B.
        let mut hr = Sha512::new();
        hr.update(&prefix);
        hr.update(message);
        let mut r_hash = hr.finalize();
        let mut r = scalar_reduce_wide(&r_hash);
        let mut r_bytes = [0u8; 32];
        r.write_le_bytes(&mut r_bytes);
        let r_enc = f.encode(&f.mul_base(&r_bytes));

        // k = SHA-512(R ‖ A ‖ message) mod L; S = (r + k·a) mod L.
        let mut hk = Sha512::new();
        hk.update(&r_enc);
        hk.update(&a_enc);
        hk.update(message);
        let k = scalar_reduce_wide(&hk.finalize());
        let mut a_scalar = ScalarInt::from_le_bytes(&a);
        let s = scalar_muladd(&r, &k, &a_scalar);

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_enc);
        s.write_le_bytes(&mut sig[32..]);

        // Wipe every transient secret: the clamped scalar `a` (in both its
        // byte and limb forms), the signing prefix, and the nonce `r` (hash,
        // limbs, bytes). Leaking `r` alone recovers `a` from `S = r + k·a`.
        // `k` and `s` are public.
        wipe(&mut a);
        wipe(&mut prefix);
        wipe(&mut r_hash);
        wipe(&mut r_bytes);
        crate::zeroize::Zeroize::zeroize(&mut r);
        crate::zeroize::Zeroize::zeroize(&mut a_scalar);
        Ed25519Signature(sig)
    }
}

/// Best-effort wipe of a transient secret buffer via
/// [`crate::zeroize::Zeroize`]: volatile stores plus a compiler fence, so
/// LLVM cannot elide them as dead stores.
#[inline]
fn wipe(buf: &mut [u8]) {
    crate::zeroize::Zeroize::zeroize(buf);
}

/// Checks the OPTIONAL `[1] publicKey` of a PKCS#8 v2 `OneAsymmetricKey`
/// (RFC 5958 §2) against `expected`, the public key derived from the private
/// half just read, consuming the field when present.
///
/// The field is an IMPLICIT BIT STRING, so OpenSSL emits the primitive tag
/// `0x81` with the usual unused-bits prefix; the constructed `[1]` spelling
/// (an EXPLICIT BIT STRING inside) is accepted too. A key whose embedded
/// public half belongs to a different private key is not a key at all —
/// whichever half an application reads, the other is wrong — so a mismatch
/// is rejected at parse time rather than surfacing as unverifiable
/// signatures or a failed key agreement later. Shared by the Ed448, X25519
/// and X448 parsers.
#[cfg(all(feature = "der", feature = "alloc"))]
pub(crate) fn check_pkcs8_public_key(
    seq: &mut crate::der::Reader<'_>,
    expected: &[u8],
) -> Result<(), crate::der::Error> {
    use crate::der::{Error, Reader, tag};
    let bits = match seq.peek_tag() {
        Some(0x81) => {
            let content = seq.read_tlv(0x81)?;
            match content.split_first() {
                Some((0, rest)) => rest,
                _ => return Err(Error::Malformed),
            }
        }
        Some(t) if t == tag::context(1) => {
            let mut inner = Reader::new(seq.read_tlv(t)?);
            let bits = inner.read_bit_string()?;
            inner.finish()?;
            bits
        }
        _ => return Ok(()),
    };
    if bits != expected {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// PKCS#8 v1 (RFC 8410) private-key serialization.
#[cfg(all(feature = "der", feature = "alloc"))]
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
        use crate::der::{Error, Reader, parse_oid, tag};
        let mut r = Reader::new(der);
        let mut seq = r.read_sequence()?;
        seq.read_integer_bytes()?; // version (v1 = 0, v2 = 1)
        let mut algid = seq.read_sequence()?;
        if parse_oid(algid.read_oid()?)?.as_slice() != ED25519_OID {
            return Err(Error::Malformed);
        }
        // privateKey OCTET STRING wraps `CurvePrivateKey ::= OCTET STRING`
        // (RFC 8410 §7) and nothing else.
        let inner = seq.read_octet_string()?;
        let mut ir = Reader::new(inner);
        let seed_bytes = ir.read_octet_string()?;
        ir.finish()?;
        if seed_bytes.len() != 32 {
            return Err(Error::Malformed);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_bytes);
        let key = Self::from_seed(seed);
        // RFC 5958 (PKCS#8 v2 / OneAsymmetricKey): an OPTIONAL `[0]` attributes
        // (IMPLICIT SET, constructed) and an OPTIONAL `[1]` publicKey may
        // follow the privateKey OCTET STRING. Attributes are skipped; the
        // publicKey must match the one the seed derives.
        if seq.peek_tag() == Some(tag::context(0)) {
            seq.read_any()?;
        }
        check_pkcs8_public_key(&mut seq, &key.public_key().to_bytes())?;
        seq.finish()?;
        r.finish()?;
        Ok(key)
    }

    /// Parses a PKCS#8 PEM private key.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_pkcs8_der(&crate::der::pem_decode(pem, "PRIVATE KEY")?)
    }

    /// Encrypts the PKCS#8 encoding under PBES2 (RFC 5958 §3 + RFC 8018
    /// §6.2) with caller-supplied parameters, returning the DER-encoded
    /// `EncryptedPrivateKeyInfo`.
    #[cfg(all(feature = "kdf", feature = "der", feature = "alloc"))]
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
    #[cfg(all(feature = "kdf", feature = "der", feature = "alloc"))]
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
    #[cfg(all(feature = "kdf", feature = "der", feature = "alloc"))]
    pub fn from_pkcs8_der_encrypted(
        der: &[u8],
        password: &[u8],
    ) -> Result<Self, crate::der::Error> {
        let inner =
            crate::kdf::pbes2::decrypt(der, password).map_err(|_| crate::der::Error::Malformed)?;
        Self::from_pkcs8_der(&inner)
    }

    /// PEM-wrapped variant of [`Self::from_pkcs8_der_encrypted`].
    #[cfg(all(feature = "kdf", feature = "der", feature = "alloc"))]
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

    /// Verifies `signature` over `message`.
    ///
    /// This is **not** ZIP-215. The rule set actually implemented is:
    ///
    /// * the *cofactored* group equation `[8S]B == [8R] + [8k]A`;
    /// * `S` must be canonical — reduced, `S < L`;
    /// * `R` and `A` must be *canonically* encoded — `y < p`, and the sign
    ///   bit must not select the non-existent negative zero. (ZIP-215
    ///   deliberately *accepts* non-canonical `y ∈ [p, 2²⁵⁵)`; this
    ///   implementation rejects them, which is the stricter behaviour. A
    ///   ZIP-215 verifier and this one therefore disagree on that set of
    ///   signatures — do not rely on this code for ZIP-215 consensus.)
    /// * `A` must **not** be of small order; in particular the identity
    ///   encoding is rejected.
    ///
    /// The explicit small-order check on `A` is what prevents the
    /// identity-key universal forgery. Multiplying by the cofactor does *not*
    /// reject small-subgroup keys — on the contrary, it makes `[8k]A` vanish
    /// for every 8-torsion `A`, so without the check any `(R, S)` satisfying
    /// `[8S]B == [8R]` (e.g. `R = enc(B)`, `S = 1`) would verify under
    /// `A = identity` for *every* message. The check below is the one that
    /// rules that out, matching libsodium's behaviour. `R` needs no such
    /// check: it is not a claimed key, and forging with a small-order `R`
    /// still requires solving for `S`.
    ///
    /// Returns [`Error::Verification`] on any failure (malformed inputs
    /// included).
    ///
    /// All verification inputs — signature, message, and public key — are
    /// public, so this path deliberately uses the **variable-time**
    /// interleaved double-scalar multiplication
    /// (`double_scalar_mult_base_vartime`); nothing secret flows through it. Signing and key generation stay on the
    /// constant-time ladders.
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), Error> {
        let f = Field::new();

        // S must be a canonical scalar in [0, L).
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&signature.0[32..]);
        let s = ScalarInt::from_le_bytes(&s_bytes);
        if !bool::from(s.ct_lt(&f.l)) {
            return Err(Error::Verification);
        }

        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature.0[..32]);
        let r_point = f.decode(&r_bytes).ok_or(Error::Verification)?;
        let a_point = f.decode(&self.0).ok_or(Error::Verification)?;

        // Reject small-order `A` (`[8]A == identity`), the identity encoding
        // included: the cofactored equation below would otherwise annihilate
        // `[8k]A` and turn any `(R, S)` with `[8S]B == [8R]` into a valid
        // signature over every message under such a key.
        let a8 = f.point_double(&f.point_double(&f.point_double(&a_point)));
        if bool::from(f.point_ct_eq(&a8, &f.identity())) {
            return Err(Error::Verification);
        }

        // k = SHA-512(R ‖ A ‖ message) mod L.
        let mut hk = Sha512::new();
        hk.update(&r_bytes);
        hk.update(&self.0);
        hk.update(message);
        let k = scalar_reduce_wide(&hk.finalize());
        let mut k_bytes = [0u8; 32];
        k.write_le_bytes(&mut k_bytes);

        // Cofactored verify: accept iff [8S]B == [8R] + [8k]A. We multiply
        // each side of the cofactor-less equation by 8 = [2][2][2].
        // Every operand here is public (S, k, R, A), so the variable-time
        // multiplications are safe — and much faster than the constant-time
        // gathers. They are differentially tested against the constant-time
        // paths in `curve25519::point`.
        // Rearranged as [8]([S]B + [k](−A)) == [8]R so both multiplications
        // fold into one double-scalar call.
        let lhs = f.double_scalar_mult_base_vartime(&k_bytes, &f.point_negate(&a_point), &s_bytes);
        let lhs8 = f.point_double(&f.point_double(&f.point_double(&lhs)));
        let rhs8 = f.point_double(&f.point_double(&f.point_double(&r_point)));
        // Projective cross-multiply comparison (X₁Z₂ == X₂Z₁, Y₁Z₂ == Y₂Z₁):
        // no field inversions, unlike encoding both sides.
        if bool::from(f.point_ct_eq(&lhs8, &rhs8)) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }

    /// Verifies `signature` over `message` with exactly libsodium's
    /// (≥ 1.0.16, default build) `crypto_sign_verify_detached` rules, for
    /// callers that must agree with libsodium on every edge case:
    ///
    /// * `S` must be canonical (`S < L`);
    /// * `R` must not be a small-order encoding, and `A` must be neither a
    ///   small-order encoding nor non-canonical (`y ≥ p`). The small-order
    ///   test is libsodium's byte blacklist, which ignores the sign bit and
    ///   also lists the non-canonical spellings `y = p` and `y = p + 1`;
    /// * the *cofactorless* equation `R == [S]B − [k]A`, checked by comparing
    ///   the canonical encoding of the right-hand side with the 32 `R` bytes
    ///   of the signature (so any non-canonical `R` encoding is rejected, and
    ///   `R` itself is never decompressed).
    ///
    /// Compared with [`verify`](Self::verify) this additionally rejects
    /// small-order `R`, and rejects signatures that only satisfy the
    /// cofactored equation (mixed-order `A` or `R`). On the 12 edge-case
    /// vectors of Chalkias et al., *Taming the many EdDSAs* (SSR 2020), it
    /// accepts only case 3, matching the published libsodium column.
    ///
    /// Returns [`Error::Verification`] on any failure. Like
    /// [`verify`](Self::verify), every input is public and the group
    /// arithmetic is **variable-time**.
    pub fn verify_libsodium(
        &self,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), Error> {
        let f = Field::new();
        let r_bytes = signature.r_bytes();
        let s_bytes = signature.s_bytes();

        // sc25519_is_canonical(S) and ge25519_has_small_order(R).
        if !bool::from(ScalarInt::from_le_bytes(&s_bytes).ct_lt(&f.l))
            || libsodium_has_small_order(&r_bytes)
        {
            return Err(Error::Verification);
        }
        // ge25519_is_canonical(A) and ge25519_has_small_order(A).
        if !libsodium_is_canonical(&self.0) || libsodium_has_small_order(&self.0) {
            return Err(Error::Verification);
        }
        // `A` is canonical here, and the only negative-zero encodings
        // (x = 0, sign bit set: y = ±1) are blacklisted above, so the strict
        // decoder accepts exactly what libsodium's
        // `ge25519_frombytes_negate_vartime` accepts.
        let a_point = f.decode(&self.0).ok_or(Error::Verification)?;

        // k = SHA-512(R ‖ A ‖ message) mod L.
        let mut hk = Sha512::new();
        hk.update(&r_bytes);
        hk.update(&self.0);
        hk.update(message);
        let k = scalar_reduce_wide(&hk.finalize());
        let mut k_bytes = [0u8; 32];
        k.write_le_bytes(&mut k_bytes);

        // Cofactorless: encode([S]B + [k](−A)) must equal the R bytes.
        // Public inputs only, so the vartime ladder is fine.
        let check =
            f.double_scalar_mult_base_vartime(&k_bytes, &f.point_negate(&a_point), &s_bytes);
        if f.encode(&check) == r_bytes {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }

    /// Converts this Ed25519 public key to the X25519 public key (Montgomery
    /// `u = (1 + y)/(1 − y)`) of the birationally equivalent curve25519 point,
    /// as libsodium's `crypto_sign_ed25519_pk_to_curve25519`, with the same
    /// rejections: [`Error::InvalidInput`] if the encoding is on libsodium's
    /// small-order blacklist, does not decode to a curve point, or the point
    /// is not in the prime-order subgroup (`[L]A ≠ identity`).
    ///
    /// Like libsodium, a non-canonical `y` encoding (`y ∈ [p, 2²⁵⁵)`) is
    /// reduced modulo `p` rather than rejected, so the accepted set matches
    /// libsodium's exactly. Inputs are public; the subgroup check is
    /// variable-time.
    pub fn to_x25519(&self) -> Result<X25519PublicKey, Error> {
        let f = Field::new();
        if libsodium_has_small_order(&self.0) {
            return Err(Error::InvalidInput);
        }
        // libsodium's `fe25519_frombytes` reduces y mod p; canonicalize it so
        // the strict decoder sees the same value. The only negative-zero
        // encodings (y = ±1) were blacklisted above.
        let mut y = self.0;
        y[31] &= 0x7f;
        let mut enc = crate::ec::curve25519::field::Fe::from_bytes(&y).to_bytes();
        enc[31] |= self.0[31] & 0x80;
        let a = f.decode(&enc).ok_or(Error::InvalidInput)?;
        // ge25519_is_on_main_subgroup: [L]A == identity (public input).
        let mut l_bytes = [0u8; 32];
        f.l.write_le_bytes(&mut l_bytes);
        let la = f.double_scalar_mult_base_vartime(&l_bytes, &a, &[0u8; 32]);
        if !bool::from(f.point_ct_eq(&la, &f.identity())) {
            return Err(Error::InvalidInput);
        }
        Ok(X25519PublicKey::from_bytes(f.to_montgomery_u(&a)))
    }
}

/// libsodium's `ge25519_has_small_order` (≥ 1.0.16): whether the 32-byte
/// encoding `s`, **ignoring its sign bit**, is one of the seven `y` values of
/// the 8-torsion points — `0`, `1`, the two order-8 `y`s, `p − 1` — or the
/// non-canonical spellings `p` (≡ 0) and `p + 1` (≡ 1). Byte comparison on a
/// public encoding; transcribed table, checked against the torsion subgroup
/// by `libsodium_blacklist_is_the_torsion_subgroup`.
fn libsodium_has_small_order(s: &[u8; 32]) -> bool {
    const P_MINUS_1: [u8; 32] = p_plus(0xec);
    const P: [u8; 32] = p_plus(0xed);
    const P_PLUS_1: [u8; 32] = p_plus(0xee);
    const fn p_plus(low: u8) -> [u8; 32] {
        let mut b = [0xffu8; 32];
        b[0] = low;
        b[31] = 0x7f;
        b
    }
    const BLACKLIST: [[u8; 32]; 7] = [
        // 0 (order 4)
        [0u8; 32],
        // 1 (order 1)
        {
            let mut b = [0u8; 32];
            b[0] = 1;
            b
        },
        // order 8
        [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ],
        // order 8
        [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ],
        // p − 1 (order 2)
        P_MINUS_1,
        // p (≡ 0, order 4)
        P,
        // p + 1 (≡ 1, order 1)
        P_PLUS_1,
    ];
    let mut y = *s;
    y[31] &= 0x7f;
    BLACKLIST.contains(&y)
}

/// libsodium's `ge25519_is_canonical`: the `y` field of the encoding (sign
/// bit ignored) is `< p`. Public input.
fn libsodium_is_canonical(s: &[u8; 32]) -> bool {
    let mut y = *s;
    y[31] &= 0x7f;
    bool::from(ScalarInt::from_le_bytes(&y).ct_lt(&Field::new().p))
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

    fn vectors() -> [Vector; 4] {
        [
            // "TEST SHA(abc)": the 64-byte message is SHA-512("abc").
            Vector {
                seed: from_hex::<32>(
                    "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
                ),
                public: from_hex::<32>(
                    "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
                ),
                message: &[
                    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae,
                    0x20, 0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e,
                    0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1,
                    0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23,
                    0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
                ],
                signature: from_hex::<64>(
                    "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351f\
                     c9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
                ),
            },
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
        use crate::ec::curve25519::field::{BASE_ENC, Fe};
        let f = Field::new();
        // inversion: a * a^(p-2) == 1
        let three = Fe::from_u64(3);
        let inv3 = f.inv(three);
        assert!(bool::from(f.ct_eq(f.mul(three, inv3), f.one)), "inv broken");
        // sqrt(-1)^2 == -1
        let neg1 = f.neg(f.one);
        assert!(bool::from(f.ct_eq(f.sq(f.sqrtm1), neg1)), "sqrtm1 broken");
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

    #[cfg(all(feature = "der", feature = "alloc"))]
    #[test]
    fn pkcs8_v1_round_trip() {
        let seed =
            from_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let sk = Ed25519PrivateKey::from_bytes(seed);
        let der = sk.to_pkcs8_der();
        let sk2 = Ed25519PrivateKey::from_pkcs8_der(&der).expect("v1 parse");
        assert_eq!(sk2.to_bytes(), seed);
    }

    #[cfg(all(feature = "der", feature = "alloc"))]
    #[test]
    fn pkcs8_rejects_trailing_garbage() {
        let seed =
            from_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let mut der = Ed25519PrivateKey::from_bytes(seed).to_pkcs8_der();
        // Appending junk after the well-formed SEQUENCE must now be rejected
        // (the outer reader is no longer left unverified).
        der.push(0xff);
        der.push(0x00);
        assert!(Ed25519PrivateKey::from_pkcs8_der(&der).is_err());
    }

    #[cfg(all(feature = "der", feature = "alloc"))]
    #[test]
    fn pkcs8_v2_with_public_key_parses() {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let seed =
            from_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let sk = Ed25519PrivateKey::from_bytes(seed);
        let pub_enc = sk.public_key().to_bytes();

        // Hand-build a PKCS#8 v2 (RFC 5958) key with the OPTIONAL `[1]`
        // publicKey present, encoded as a primitive IMPLICIT BIT STRING
        // (tag 0x81) the way OpenSSL emits it: 0x00 unused-bits prefix
        // followed by the 32-byte public key.
        let version = encode_integer(&[1]);
        let algid = encode_sequence(&oid_tlv(ED25519_OID));
        let privkey = encode_octet_string(&encode_octet_string(&seed));
        let mut pub_bitstring = alloc::vec![0u8]; // 0 unused bits
        pub_bitstring.extend_from_slice(&pub_enc);
        let mut pubkey_field = alloc::vec![0x81u8];
        // length is 33 (< 0x80), short form.
        pubkey_field.push(pub_bitstring.len() as u8);
        pubkey_field.extend_from_slice(&pub_bitstring);
        let der = encode_sequence(&[version, algid, privkey, pubkey_field].concat());

        let parsed = Ed25519PrivateKey::from_pkcs8_der(&der).expect("v2 parse");
        assert_eq!(parsed.to_bytes(), seed);
        assert_eq!(parsed.public_key().to_bytes(), pub_enc);

        // F7: the embedded public key must be the seed's. A different one
        // (one byte flipped) is rejected, as is a wrong length.
        let mut wrong = der.clone();
        let last = wrong.len() - 1;
        wrong[last] ^= 0x01;
        assert!(Ed25519PrivateKey::from_pkcs8_der(&wrong).is_err());
        let mut short_field = alloc::vec![0x81u8, 32, 0];
        short_field.extend_from_slice(&pub_enc[..31]);
        let short = encode_sequence(
            &[
                encode_integer(&[1]),
                encode_sequence(&oid_tlv(ED25519_OID)),
                encode_octet_string(&encode_octet_string(&seed)),
                short_field,
            ]
            .concat(),
        );
        assert!(Ed25519PrivateKey::from_pkcs8_der(&short).is_err());
        // The constructed `[1]` spelling (an EXPLICIT BIT STRING) is still
        // read, and checked the same way.
        let explicit = |pk: &[u8]| {
            let bits = crate::der::encode_bit_string(pk);
            encode_sequence(
                &[
                    encode_integer(&[1]),
                    encode_sequence(&oid_tlv(ED25519_OID)),
                    encode_octet_string(&encode_octet_string(&seed)),
                    crate::der::encode_context(1, &bits),
                ]
                .concat(),
            )
        };
        assert!(Ed25519PrivateKey::from_pkcs8_der(&explicit(&pub_enc)).is_ok());
        let mut other = pub_enc;
        other[0] ^= 0x01;
        assert!(Ed25519PrivateKey::from_pkcs8_der(&explicit(&other)).is_err());
    }

    /// F7: the privateKey OCTET STRING holds exactly the CurvePrivateKey
    /// OCTET STRING; bytes after it inside the wrapper are rejected.
    #[cfg(all(feature = "der", feature = "alloc"))]
    #[test]
    fn pkcs8_rejects_junk_inside_private_key_wrapper() {
        use crate::der::{
            encode_integer, encode_null, encode_octet_string, encode_sequence, oid_tlv,
        };
        let seed =
            from_hex::<32>("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let version = encode_integer(&[0]);
        let algid = encode_sequence(&oid_tlv(ED25519_OID));
        let privkey = encode_octet_string(&[encode_octet_string(&seed), encode_null()].concat());
        let der = encode_sequence(&[version, algid, privkey].concat());
        assert!(Ed25519PrivateKey::from_pkcs8_der(&der).is_err());
    }

    /// The old fully constant-time verification path (constant-time comb +
    /// windowed ladder + encoded comparison), kept as the differential oracle
    /// for the vartime path now used by `verify`.
    fn verify_ct_reference(
        pk: &Ed25519PublicKey,
        message: &[u8],
        signature: &Ed25519Signature,
    ) -> bool {
        use crate::ct::ConstantTimeEq;
        let f = Field::new();
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&signature.0[32..]);
        let s = ScalarInt::from_le_bytes(&s_bytes);
        if !bool::from(s.ct_lt(&f.l)) {
            return false;
        }
        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature.0[..32]);
        let (Some(r_point), Some(a_point)) = (f.decode(&r_bytes), f.decode(&pk.0)) else {
            return false;
        };
        // Same small-order rejection as `verify`, so the two paths implement
        // the same rule set.
        let a8 = f.point_double(&f.point_double(&f.point_double(&a_point)));
        if bool::from(f.point_ct_eq(&a8, &f.identity())) {
            return false;
        }
        let mut hk = Sha512::new();
        hk.update(&r_bytes);
        hk.update(&pk.0);
        hk.update(message);
        let k = scalar_reduce_wide(&hk.finalize());
        let mut k_bytes = [0u8; 32];
        k.write_le_bytes(&mut k_bytes);
        let lhs = f.mul_base(&s_bytes);
        let ka = f.scalar_mult(&k_bytes, &a_point);
        let rhs = f.point_add(&r_point, &ka);
        let lhs8 = f.point_double(&f.point_double(&f.point_double(&lhs)));
        let rhs8 = f.point_double(&f.point_double(&f.point_double(&rhs)));
        bool::from(f.encode(&lhs8).ct_eq(&f.encode(&rhs8)))
    }

    /// The vartime verify must accept/reject exactly like the constant-time
    /// reference over many random signatures, corrupted signatures (every
    /// byte position of R and S), wrong keys, and wrong messages.
    #[test]
    fn vartime_verify_matches_constant_time_reference() {
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ed25519-vartime-diff", b"n", &[]);
        for i in 0..8u8 {
            let sk = Ed25519PrivateKey::generate(&mut rng);
            let pk = sk.public_key();
            let msg = [i; 24];
            let sig = sk.sign(&msg);

            // Valid signature: both accept.
            assert!(verify_ct_reference(&pk, &msg, &sig));
            assert!(pk.verify(&msg, &sig).is_ok());

            // Corrupt each byte of the signature in turn: both paths must
            // agree bit-for-bit on accept/reject (some corruptions of R may
            // still decode; the equation then fails in both).
            for pos in 0..64 {
                let mut bad = sig.to_bytes();
                bad[pos] ^= 0x40;
                let bad_sig = Ed25519Signature::from_bytes(bad);
                assert_eq!(
                    pk.verify(&msg, &bad_sig).is_ok(),
                    verify_ct_reference(&pk, &msg, &bad_sig),
                    "vartime/CT divergence at corrupted byte {pos}"
                );
            }

            // Wrong message and wrong key: both reject.
            assert_eq!(
                pk.verify(b"other message", &sig).is_ok(),
                verify_ct_reference(&pk, b"other message", &sig)
            );
            assert!(pk.verify(b"other message", &sig).is_err());
            let pk2 = Ed25519PrivateKey::generate(&mut rng).public_key();
            assert_eq!(
                pk2.verify(&msg, &sig).is_ok(),
                verify_ct_reference(&pk2, &msg, &sig)
            );
            assert!(pk2.verify(&msg, &sig).is_err());
        }
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

    /// Regression test: an identity-encoded public key must not verify.
    ///
    /// With `A = enc(identity)` (`y = 1`, sign 0), `R = enc(B)` and `S = 1`,
    /// the cofactored equation degenerates to `[8]B == [8]B + [8k]·O`, which
    /// holds for *every* message — a universal forgery under a key nobody
    /// owns. The small-order check on `A` in `verify` is what rules it out.
    #[test]
    fn identity_public_key_universal_forgery_rejected() {
        let f = Field::new();
        let r_enc = f.encode(&f.base());

        let mut a = [0u8; 32];
        a[0] = 1; // y = 1, sign bit 0 — the identity point.
        let pk = Ed25519PublicKey::from_bytes(a);

        let mut s_bytes = [0u8; 32];
        s_bytes[0] = 1; // S = 1
        let sig = Ed25519Signature::from_components(&r_enc, &s_bytes);

        for msg in [
            &b""[..],
            b"hello world",
            b"attacker-chosen message",
            b"\x00\x01\x02\x03",
        ] {
            assert!(
                pk.verify(msg, &sig).is_err(),
                "identity public key forged a signature over {msg:?}"
            );
        }
    }

    /// Every point of small order (the full 8-torsion subgroup) must be
    /// rejected as a public key, whatever the signature.
    #[test]
    fn small_order_public_keys_rejected() {
        // The eight canonical encodings of the 8-torsion subgroup of
        // edwards25519 (identity, the order-2 point, two order-4 and four
        // order-8 points).
        let small_order = [
            "0100000000000000000000000000000000000000000000000000000000000000",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000000000000000000000000000000000000080",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
            "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        ];

        let f = Field::new();
        let r_enc = f.encode(&f.base());
        let mut s_bytes = [0u8; 32];
        s_bytes[0] = 1;
        let sig = Ed25519Signature::from_components(&r_enc, &s_bytes);

        for enc in small_order {
            let a = from_hex::<32>(enc);
            // Skip encodings this decoder rejects outright (non-canonical or
            // off-curve); the point of the test is that none of them verify.
            let pk = Ed25519PublicKey::from_bytes(a);
            assert!(
                pk.verify(b"small order", &sig).is_err(),
                "small-order key {enc} accepted"
            );
            assert!(
                pk.verify(b"", &sig).is_err(),
                "small-order key {enc} accepted"
            );
        }
    }

    /// Non-canonical encodings of `R` and `A` must be rejected by the
    /// decoder, and hence by `verify`: `y ≥ p` (`y = p`, `y = 2²⁵⁵ − 1`) and
    /// the "negative zero" encodings (`x = 0`, i.e. `y = ±1`, with the sign
    /// bit set). ZIP-215 accepts the `y ≥ p` set; this verifier is stricter.
    #[test]
    fn non_canonical_r_and_a_encodings_rejected() {
        let f = Field::new();
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ed25519-noncanon", b"n", &[]);
        let sk = Ed25519PrivateKey::generate(&mut rng);
        let pk = sk.public_key();
        let msg = b"non-canonical encodings";
        let sig = sk.sign(msg);
        pk.verify(msg, &sig).unwrap();

        let bad_encodings = [
            // y = p, sign 0.
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            // y = 2^255 − 1, sign 0 — the largest non-canonical residue.
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            // y = p, sign 1.
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            // y = 1 (x = 0) with the sign bit set: "negative zero".
            "0100000000000000000000000000000000000000000000000000000000000080",
            // y = p − 1 (x = 0) with the sign bit set.
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ];

        for enc in bad_encodings {
            let bad = from_hex::<32>(enc);
            assert!(f.decode(&bad).is_none(), "decoder accepted {enc}");

            // As R.
            let bad_r = Ed25519Signature::from_components(&bad, &sig.s_bytes());
            assert!(pk.verify(msg, &bad_r).is_err(), "R = {enc} accepted");

            // As A.
            let bad_pk = Ed25519PublicKey::from_bytes(bad);
            assert!(bad_pk.verify(msg, &sig).is_err(), "A = {enc} accepted");
        }
    }

    /// The 12 edge-case vectors of Chalkias, Garillot, Nikolaenko,
    /// *Taming the many EdDSAs* (SSR 2020, <https://eprint.iacr.org/2020/1244>),
    /// transcribed from `cases.json` of
    /// <https://github.com/novifinancial/ed25519-speccheck> (Apache-2.0):
    /// (message, public key, signature).
    const SPECCHECK: [(&str, &str, &str); 12] = [
        (
            "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a\
             0000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43\
             a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        ),
        (
            "aebf3f2601a0c8c5d39cc7d8911642f740b78168218da8471772b35f9d35b9ab",
            "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa\
             8c4bd45aecaca5b24fb97bc10ac27ac8751a7dfe1baff8b953ec9f5833ca260e",
        ),
        (
            "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
            "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f\
             87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
        ),
        (
            "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
            "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed512\
             5ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
        ),
        (
            "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
            "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7\
             e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
        ),
        (
            "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
            "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
            "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e\
             547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
        ),
        (
            "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
            "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
            "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa1942\
             7e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
        ),
        (
            "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
            "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
        ),
        (
            "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
            "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
             ca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
        ),
        (
            "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc\
             a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        ),
        (
            "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dc\
             a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
        ),
    ];

    fn speccheck_case(i: usize) -> ([u8; 32], Ed25519PublicKey, Ed25519Signature) {
        let (m, a, sig) = SPECCHECK[i];
        (
            from_hex::<32>(m),
            Ed25519PublicKey::from_bytes(from_hex::<32>(a)),
            Ed25519Signature::from_bytes(from_hex::<64>(sig)),
        )
    }

    /// `verify_libsodium` reproduces the "LibSodium" row of the speccheck
    /// results table (README of ed25519-speccheck): only case 3 verifies.
    #[test]
    fn speccheck_libsodium_column() {
        const LIBSODIUM: [bool; 12] = [
            false, false, false, true, false, false, false, false, false, false, false, false,
        ];
        for (i, &want) in LIBSODIUM.iter().enumerate() {
            let (m, pk, sig) = speccheck_case(i);
            assert_eq!(
                pk.verify_libsodium(&m, &sig).is_ok(),
                want,
                "speccheck case {i}"
            );
        }
    }

    /// Pins the default (cofactored, strict-encoding, small-order-A-rejecting)
    /// `verify` on the same vectors, so the libsodium mode demonstrably did
    /// not change it.
    #[test]
    fn speccheck_default_verify_column() {
        const DEFAULT: [bool; 12] = [
            false, false, true, true, true, true, false, false, false, false, false, false,
        ];
        for (i, &want) in DEFAULT.iter().enumerate() {
            let (m, pk, sig) = speccheck_case(i);
            assert_eq!(pk.verify(&m, &sig).is_ok(), want, "speccheck case {i}");
        }
    }

    #[test]
    fn verify_libsodium_accepts_rfc8032() {
        let f = Field::new();
        for v in vectors() {
            let pk = Ed25519PublicKey::from_bytes(v.public);
            let sig = Ed25519Signature::from_bytes(v.signature);
            pk.verify_libsodium(v.message, &sig).unwrap();
            let mut bad = v.signature;
            bad[0] ^= 1;
            assert!(
                pk.verify_libsodium(v.message, &Ed25519Signature::from_bytes(bad))
                    .is_err()
            );
            // S + L (non-canonical, same residue) is rejected.
            let s = ScalarInt::from_le_bytes(&sig.s_bytes());
            let mut s_bytes = [0u8; 32];
            s.wrapping_add(&f.l).write_le_bytes(&mut s_bytes);
            let sig2 = Ed25519Signature::from_components(&sig.r_bytes(), &s_bytes);
            assert!(pk.verify_libsodium(v.message, &sig2).is_err());
        }
    }

    /// The transcribed blacklist is exactly the `y`s of the 8-torsion
    /// subgroup (plus the non-canonical `p`, `p + 1`): every torsion point's
    /// encoding hits it with either sign bit.
    #[test]
    fn libsodium_blacklist_is_the_torsion_subgroup() {
        let f = Field::new();
        // An order-8 point (a blacklist entry with the sign bit clear).
        let t8 = f
            .decode(&from_hex::<32>(
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            ))
            .unwrap();
        let mut p = f.identity();
        for i in 0..8 {
            let enc = f.encode(&p);
            assert!(libsodium_has_small_order(&enc), "[{i}]T8");
            let mut flipped = enc;
            flipped[31] ^= 0x80;
            assert!(libsodium_has_small_order(&flipped), "[{i}]T8 sign-flipped");
            p = f.point_add(&p, &t8);
        }
        assert!(bool::from(f.point_ct_eq(&p, &f.identity())));
        assert!(!libsodium_has_small_order(&f.encode(&f.base())));
        // The non-canonical aliases of 0 and 1.
        let mut pp = [0xffu8; 32];
        pp[31] = 0x7f;
        pp[0] = 0xed;
        assert!(libsodium_has_small_order(&pp));
        assert!(!libsodium_is_canonical(&pp));
        pp[0] = 0xee;
        assert!(libsodium_has_small_order(&pp));
        pp[0] = 0xec;
        assert!(libsodium_is_canonical(&pp));
    }

    /// libsodium's 64-byte `seed ‖ pk` secret key: checked and unchecked
    /// constructors round-trip and sign the RFC 8032 vectors.
    #[test]
    fn keypair_bytes_roundtrip() {
        for v in vectors() {
            let mut kp = [0u8; 64];
            kp[..32].copy_from_slice(&v.seed);
            kp[32..].copy_from_slice(&v.public);
            let checked = Ed25519PrivateKey::from_keypair_bytes(&kp).unwrap();
            let unchecked = Ed25519PrivateKey::from_keypair_bytes_unchecked(&kp);
            assert_eq!(checked.to_keypair_bytes(), kp);
            assert_eq!(unchecked.to_keypair_bytes(), kp);
            assert_eq!(unchecked.public_key().to_bytes(), v.public);
            assert_eq!(checked.sign(v.message).to_bytes(), v.signature);
            assert_eq!(unchecked.sign(v.message).to_bytes(), v.signature);
            assert_eq!(Ed25519PrivateKey::from_bytes(v.seed).to_keypair_bytes(), kp);
        }
    }

    /// A mismatched stored public key: the checked constructor refuses it;
    /// the unchecked one keeps it verbatim (no recomputation), and its
    /// signatures verify under neither key.
    #[test]
    fn keypair_bytes_mismatched_public_key() {
        let v = &vectors()[1];
        let other = vectors()[2].public;
        let mut kp = [0u8; 64];
        kp[..32].copy_from_slice(&v.seed);
        kp[32..].copy_from_slice(&other);
        assert_eq!(
            Ed25519PrivateKey::from_keypair_bytes(&kp).err(),
            Some(Error::InvalidInput)
        );
        let sk = Ed25519PrivateKey::from_keypair_bytes_unchecked(&kp);
        assert_eq!(sk.public_key().to_bytes(), other);
        let sig = sk.sign(b"msg");
        assert!(sk.public_key().verify(b"msg", &sig).is_err());
        assert!(
            Ed25519PublicKey::from_bytes(v.public)
                .verify(b"msg", &sig)
                .is_err()
        );
    }

    /// libsodium `test/default/ed25519_convert.c` / `.exp` (1.0.18).
    #[test]
    fn libsodium_ed25519_convert_vector() {
        let seed =
            from_hex::<32>("421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee");
        let sk = Ed25519PrivateKey::from_bytes(seed);
        assert_eq!(
            sk.public_key().to_x25519().unwrap().to_bytes(),
            from_hex::<32>("f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50")
        );
        assert_eq!(
            sk.to_x25519().to_bytes(),
            from_hex::<32>("8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166")
        );
        // The same file's rejections: y = 0 (small order), y = 2 and y = 5.
        for first in [0u8, 2, 5] {
            let mut pk = [0u8; 32];
            pk[0] = first;
            assert_eq!(
                Ed25519PublicKey::from_bytes(pk).to_x25519(),
                Err(Error::InvalidInput),
                "y = {first}"
            );
        }
    }

    /// The `ed25519_convert.c` loop: for random keys, X25519 of the converted
    /// secret equals the converted public key.
    #[test]
    fn x25519_conversion_commutes() {
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ed25519-convert", b"n", &[]);
        for _ in 0..32 {
            let sk = Ed25519PrivateKey::generate(&mut rng);
            let xpk = sk.public_key().to_x25519().unwrap();
            assert_eq!(sk.to_x25519().public_key(), xpk.to_bytes());
        }
    }

    /// Conversion rejects every small-order and torsion-tainted key, and
    /// treats non-canonical `y` spellings exactly like their reduced form.
    #[test]
    fn x25519_conversion_rejections() {
        let f = Field::new();
        let t8 = f
            .decode(&from_hex::<32>(
                "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
            ))
            .unwrap();
        let a = f.decode(&vectors()[1].public).unwrap();
        let mut t = f.identity();
        for i in 0..8 {
            let pk = Ed25519PublicKey::from_bytes(f.encode(&t));
            assert!(pk.to_x25519().is_err(), "[{i}]T8");
            // Mixed-order A + [i]T8 (i > 0) fails the subgroup check.
            let mixed = Ed25519PublicKey::from_bytes(f.encode(&f.point_add(&a, &t)));
            assert_eq!(mixed.to_x25519().is_ok(), i == 0, "A + [{i}]T8");
            t = f.point_add(&t, &t8);
        }
        // y ∈ [p, 2²⁵⁵) aliases y − p ∈ [0, 19): same outcome as the
        // canonical spelling, for both sign bits.
        for low in 0u8..19 {
            for sign in [0u8, 0x80] {
                let mut canon = [0u8; 32];
                canon[0] = low;
                canon[31] = sign;
                let mut alias = [0xffu8; 32];
                alias[0] = 0xed + low;
                alias[31] = 0x7f | sign;
                assert_eq!(
                    Ed25519PublicKey::from_bytes(canon).to_x25519(),
                    Ed25519PublicKey::from_bytes(alias).to_x25519(),
                    "y = {low}, sign {sign:#x}"
                );
            }
        }
    }
}
