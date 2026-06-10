//! ML-KEM — the FIPS 203 module-lattice key-encapsulation mechanism (the
//! standardized form of Kyber), in all three parameter sets:
//!
//!  - [`MlKem512`]  / [`MlKem512DecapsKey`]  / [`MlKem512EncapsKey`]  / [`MlKem512Ciphertext`]
//!  - [`MlKem768`]  / [`MlKem768DecapsKey`]  / [`MlKem768EncapsKey`]  / [`MlKem768Ciphertext`]
//!  - [`MlKem1024`] / [`MlKem1024DecapsKey`] / [`MlKem1024EncapsKey`] / [`MlKem1024Ciphertext`]
//!
//! This is a `no_std`, allocation-free implementation: keys, ciphertexts and
//! all intermediate state live on the stack as fixed-size arrays.
//! Randomness is supplied through the [`RngCore`] trait;
//! deterministic constructors (`from_seeds`, `encapsulate_deterministic`)
//! expose the FIPS 203 internal functions for known-answer testing.
//!
//! Decapsulation never branches on secret data: the Fujisaki–Okamoto
//! re-encryption check and the implicit-rejection fallback both run in
//! constant time (see the `kem` submodule).
//!
//! # Test-vector coverage — known gap
//!
//! Unit tests cover the FIPS 203 reference flow at all three parameter
//! sets, but the crate does **not** ship the full NIST ACVP test set for
//! ML-KEM (`testdata/` carries ACVP for ML-DSA and SLH-DSA, but not yet
//! for ML-KEM). The ACVP corpus is multi-megabyte and out of scope for
//! the audit hardening batch; landing it is tracked as future work.
//! In the meantime the existing per-set fixed vectors plus deterministic
//! constructors (`from_seeds`, `encapsulate_deterministic`) make the
//! algorithm fully testable against external implementations.

pub(crate) mod indcpa;
pub(crate) mod kem;
pub(crate) mod poly;

/// Returned by the per-variant `EncapsKey::from_bytes_validated` constructor
/// when the supplied encapsulation-key bytes contain off-modulus coefficients
/// (FIPS 203 §7.2 "Encapsulation key check" failure).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncapsKeyCheckError;

impl core::fmt::Display for EncapsKeyCheckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ML-KEM encapsulation key has off-modulus coefficients (FIPS 203 §7.2)")
    }
}

impl core::error::Error for EncapsKeyCheckError {}

use crate::rng::RngCore;

/// Marker for one ML-KEM parameter set; carries no data, only used to choose
/// among the typed APIs by name.
pub struct MlKem512;
/// Marker for ML-KEM-768 (the default and most widely deployed set).
pub struct MlKem768;
/// Marker for ML-KEM-1024 (highest security level).
pub struct MlKem1024;

/// Size in bytes of an ML-KEM-768 encapsulation key (kept for back-compat).
pub const ENCAPS_KEY_BYTES: usize = kem::ek_bytes(3);
/// Size in bytes of an ML-KEM-768 decapsulation key (kept for back-compat).
pub const DECAPS_KEY_BYTES: usize = kem::dk_bytes(3);
/// Size in bytes of an ML-KEM-768 ciphertext (kept for back-compat).
pub const CIPHERTEXT_BYTES: usize = kem::ct_bytes(3, 10, 4);
/// Size in bytes of a shared secret (same across all ML-KEM sets).
pub const SHARED_SECRET_BYTES: usize = 32;

#[cfg(feature = "der")]
mod oids {
    /// `id-alg-ml-kem-512`  — 2.16.840.1.101.3.4.4.1.
    pub(crate) const ML_KEM_512: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 4, 1];
    /// `id-alg-ml-kem-768`  — 2.16.840.1.101.3.4.4.2.
    pub(crate) const ML_KEM_768: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 4, 2];
    /// `id-alg-ml-kem-1024` — 2.16.840.1.101.3.4.4.3.
    pub(crate) const ML_KEM_1024: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 4, 3];
}

/// Emits the per-set newtype wrappers and impls for one ML-KEM parameter set.
///
/// `$ek_size`, `$dk_size`, `$ct_size` are passed alongside the FIPS 203
/// (K, η₁, η₂, dᵤ, dᵥ) tuple — Rust const generics can't (yet, stably) compute
/// array sizes from other const params, so we name them at the macro call site.
macro_rules! ml_kem_set {
    (
        $set_doc:literal,
        $dk_name:ident, $ek_name:ident, $ct_name:ident,
        $k:expr, $eta1:expr, $eta2:expr, $du:expr, $dv:expr,
        $ek_size:expr, $dk_size:expr, $ct_size:expr,
        $oid:ident
    ) => {
        #[doc = concat!("An ", $set_doc, " encapsulation (public) key.")]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub struct $ek_name([u8; $ek_size]);

        #[doc = concat!("An ", $set_doc, " decapsulation (secret) key.")]
        #[derive(Clone)]
        pub struct $dk_name([u8; $dk_size]);

        #[doc = concat!("An ", $set_doc, " ciphertext.")]
        #[derive(Clone, Copy, PartialEq, Eq, Debug)]
        pub struct $ct_name([u8; $ct_size]);

        impl $dk_name {
            /// Encapsulation-key size in bytes.
            pub const ENCAPS_KEY_BYTES: usize = $ek_size;
            /// Decapsulation-key size in bytes.
            pub const DECAPS_KEY_BYTES: usize = $dk_size;
            /// Ciphertext size in bytes.
            pub const CIPHERTEXT_BYTES: usize = $ct_size;

            /// Generates a fresh key pair from `rng` (32 bytes each of `d` and `z`).
            ///
            /// `rng` SHOULD be a cryptographically secure CSPRNG (see
            /// [`CryptoRng`](crate::rng::CryptoRng)). The bound is left at
            /// [`RngCore`] only so the TLS / DTLS handshake layers can
            /// thread a single shared RNG type through hybrid key-share
            /// generation; production callers should pass `OsRng` or an
            /// HMAC-DRBG seeded from one.
            pub fn generate<R: RngCore>(rng: &mut R) -> ($dk_name, $ek_name) {
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];
                rng.fill_bytes(&mut d);
                rng.fill_bytes(&mut z);
                Self::from_seeds(&d, &z)
            }

            /// Deterministically derives a key pair from `(d, z)`
            /// (ML-KEM.KeyGen_internal). Intended for testing.
            pub fn from_seeds(d: &[u8; 32], z: &[u8; 32]) -> ($dk_name, $ek_name) {
                let mut ek = [0u8; $ek_size];
                let mut dk = [0u8; $dk_size];
                kem::keygen::<$k, $eta1>(d, z, &mut ek, &mut dk);
                ($dk_name(dk), $ek_name(ek))
            }

            /// The matching encapsulation key.
            pub fn encapsulation_key(&self) -> $ek_name {
                let pke_dk = 384 * $k;
                let mut ek = [0u8; $ek_size];
                ek.copy_from_slice(&self.0[pke_dk..pke_dk + $ek_size]);
                $ek_name(ek)
            }

            /// Decapsulates `ct`, returning the 32-byte shared secret. On an
            /// invalid ciphertext this returns a pseudo-random value (implicit
            /// rejection), not an error — the difference is unobservable to
            /// the sender.
            pub fn decapsulate(&self, ct: &$ct_name) -> [u8; SHARED_SECRET_BYTES] {
                kem::decaps::<$k, $eta1, $eta2, $du, $dv>(&self.0, &ct.0)
            }

            /// Restores a decapsulation key from its byte encoding.
            /// **No validation.** Use
            /// [`from_bytes_validated`](Self::from_bytes_validated) when
            /// the bytes come from an untrusted source.
            pub fn from_bytes(bytes: [u8; $dk_size]) -> Self {
                $dk_name(bytes)
            }

            /// FIPS 203 §7.3 "Decapsulation key check": confirms that the
            /// SHA3-256 hash of the embedded encapsulation key matches
            /// the H(ek) field stored at offset `pke_dk + ek_size` of the
            /// decapsulation key. This guards against a corrupted /
            /// adversarially-modified key file that would otherwise
            /// produce wrong shared secrets at decapsulation time.
            pub fn from_bytes_validated(
                bytes: [u8; $dk_size],
            ) -> Result<Self, crate::mlkem::EncapsKeyCheckError> {
                use crate::hash::Digest;
                let pke_dk = 384 * $k;
                let ek_start = pke_dk;
                let ek_end = ek_start + $ek_size;
                // H(ek) is the 32-byte SHA3-256 hash placed right after
                // the embedded encapsulation key, per FIPS 203 §7.3.
                let h_start = ek_end;
                let h_end = h_start + 32;
                // Defensive: a malformed bytes slice short of these
                // bounds is structurally impossible (the array length is
                // fixed at $dk_size), but assert anyway so a future
                // size mistake fails loudly rather than silently passing.
                assert!(h_end <= $dk_size);
                let mut hasher = crate::hash::Sha3_256::new();
                hasher.update(&bytes[ek_start..ek_end]);
                let h = hasher.finalize();
                if h.as_ref() != &bytes[h_start..h_end] {
                    return Err(crate::mlkem::EncapsKeyCheckError);
                }
                Ok($dk_name(bytes))
            }

            /// The byte encoding.
            pub fn to_bytes(&self) -> [u8; $dk_size] {
                self.0
            }
        }

        // FIPS 203 §3.3 mandates that decapsulation-key material be
        // zeroed before deallocation. We avoid pulling in the `zeroize`
        // crate by overwriting the bytes and routing them through
        // `core::hint::black_box`, which prevents LLVM from eliminating
        // the writes as dead stores.
        impl Drop for $dk_name {
            fn drop(&mut self) {
                for b in self.0.iter_mut() {
                    *b = 0;
                }
                let _ = core::hint::black_box(&self.0);
            }
        }

        impl $ek_name {
            /// Encapsulation-key size in bytes.
            pub const BYTES: usize = $ek_size;

            /// Encapsulates to a fresh shared secret, returning `(ciphertext, secret)`.
            ///
            /// `rng` SHOULD be a cryptographically secure CSPRNG (see
            /// [`CryptoRng`](crate::rng::CryptoRng)) — the shared secret
            /// derives from `m`, so a predictable `rng` directly compromises
            /// the secret. The bound is left at [`RngCore`] only so the TLS
            /// / DTLS handshake layers can thread a single shared RNG type;
            /// production callers should pass `OsRng` or an HMAC-DRBG seeded
            /// from one.
            pub fn encapsulate<R: RngCore>(
                &self,
                rng: &mut R,
            ) -> ($ct_name, [u8; SHARED_SECRET_BYTES]) {
                let mut m = [0u8; 32];
                rng.fill_bytes(&mut m);
                self.encapsulate_deterministic(&m)
            }

            /// Encapsulates with an explicit message `m` (ML-KEM.Encaps_internal).
            /// Intended for testing.
            pub fn encapsulate_deterministic(
                &self,
                m: &[u8; 32],
            ) -> ($ct_name, [u8; SHARED_SECRET_BYTES]) {
                let mut ct = [0u8; $ct_size];
                let ss = kem::encaps::<$k, $eta1, $eta2, $du, $dv>(&self.0, m, &mut ct);
                ($ct_name(ct), ss)
            }

            /// Restores an encapsulation key from its byte encoding.
            ///
            /// **No validation.** Use [`from_bytes_validated`](Self::from_bytes_validated)
            /// when the bytes come from an untrusted source — FIPS 203 §7.2
            /// requires verifying that every 12-bit coefficient is in `[0, q)`
            /// (re-encoding round-trip), otherwise an attacker can supply
            /// off-modulus EKs as an oracle into the encapsulator's noise.
            pub fn from_bytes(bytes: [u8; $ek_size]) -> Self {
                $ek_name(bytes)
            }

            /// FIPS 203 §7.2 "Encapsulation key check": confirms
            /// `ByteEncode₁₂(ByteDecode₁₂(t)) == t` — i.e. every 12-bit
            /// coefficient of the polynomial-vector portion of the EK is in
            /// `[0, q)` (the trailing 32-byte `rho` is opaque and not
            /// checked). Returns the validated key on success.
            pub fn from_bytes_validated(
                bytes: [u8; $ek_size],
            ) -> Result<Self, crate::mlkem::EncapsKeyCheckError> {
                const POLYBYTES_LOCAL: usize = 384;
                let polyvec = &bytes[..POLYBYTES_LOCAL * $k];
                for i in 0..$k {
                    let chunk = &polyvec[i * POLYBYTES_LOCAL..(i + 1) * POLYBYTES_LOCAL];
                    if !crate::mlkem::poly::is_canonical(chunk) {
                        return Err(crate::mlkem::EncapsKeyCheckError);
                    }
                }
                Ok($ek_name(bytes))
            }

            /// The byte encoding.
            pub fn to_bytes(&self) -> [u8; $ek_size] {
                self.0
            }
        }

        impl $ct_name {
            /// Ciphertext size in bytes.
            pub const BYTES: usize = $ct_size;

            /// Restores a ciphertext from its byte encoding.
            pub fn from_bytes(bytes: [u8; $ct_size]) -> Self {
                $ct_name(bytes)
            }

            /// The byte encoding.
            pub fn to_bytes(&self) -> [u8; $ct_size] {
                self.0
            }
        }

        /// PKCS#8 (raw expanded dk) for the decapsulation key.
        #[cfg(feature = "der")]
        impl $dk_name {
            /// Encodes the key as a PKCS#8 `PrivateKeyInfo` DER.
            pub fn to_pkcs8_der(&self) -> alloc::vec::Vec<u8> {
                use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
                let algid = encode_sequence(&oid_tlv(oids::$oid));
                encode_sequence(
                    &[encode_integer(&[0]), algid, encode_octet_string(&self.0)].concat(),
                )
            }

            /// Encodes the key as a PKCS#8 PEM document.
            pub fn to_pkcs8_pem(&self) -> alloc::string::String {
                crate::der::pem_encode("PRIVATE KEY", &self.to_pkcs8_der())
            }

            /// Parses a PKCS#8 `PrivateKeyInfo` DER (raw `dk` form).
            pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, crate::der::Error> {
                use crate::der::{Error, Reader, parse_oid};
                let mut r = Reader::new(der);
                let mut seq = r.read_sequence()?;
                seq.read_integer_bytes()?;
                let mut algid = seq.read_sequence()?;
                if parse_oid(algid.read_oid()?)?.as_slice() != oids::$oid {
                    return Err(Error::Malformed);
                }
                let inner = seq.read_octet_string()?;
                let bytes: [u8; $dk_size] = inner.try_into().map_err(|_| Error::Malformed)?;
                // PKCS#8 input is untrusted: run the FIPS 203 §7.3 hash
                // check rather than constructing the key unvalidated.
                Self::from_bytes_validated(bytes).map_err(|_| Error::Malformed)
            }

            /// Parses a PKCS#8 PEM private key.
            pub fn from_pkcs8_pem(pem: &str) -> Result<Self, crate::der::Error> {
                Self::from_pkcs8_der(&crate::der::pem_decode(pem, "PRIVATE KEY")?)
            }

            /// Encrypts the PKCS#8 encoding under PBES2 (RFC 5958 §3 +
            /// RFC 8018 §6.2), returning the DER-encoded
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

            /// PEM-wrapped variant of [`Self::to_pkcs8_der_encrypted`].
            #[cfg(all(feature = "kdf", feature = "der"))]
            pub fn to_pkcs8_pem_encrypted(
                &self,
                password: &[u8],
                params: &crate::kdf::pbes2::Pbes2Params,
                rng: &mut impl crate::rng::RngCore,
            ) -> alloc::string::String {
                crate::kdf::pbes2::encrypt_pem(&self.to_pkcs8_der(), password, params, rng)
            }

            /// Parses an `EncryptedPrivateKeyInfo` DER and decrypts it
            /// back to a PKCS#8 ML-KEM decapsulation key.
            #[cfg(all(feature = "kdf", feature = "der"))]
            pub fn from_pkcs8_der_encrypted(
                der: &[u8],
                password: &[u8],
            ) -> Result<Self, crate::der::Error> {
                let inner = crate::kdf::pbes2::decrypt(der, password)
                    .map_err(|_| crate::der::Error::Malformed)?;
                Self::from_pkcs8_der(&inner)
            }

            /// PEM-wrapped variant of [`Self::from_pkcs8_der_encrypted`].
            #[cfg(all(feature = "kdf", feature = "der"))]
            pub fn from_pkcs8_pem_encrypted(
                pem: &str,
                password: &[u8],
            ) -> Result<Self, crate::der::Error> {
                let inner = crate::kdf::pbes2::decrypt_pem(pem, password)
                    .map_err(|_| crate::der::Error::Malformed)?;
                Self::from_pkcs8_der(&inner)
            }
        }

        /// PKIX `SubjectPublicKeyInfo` for the encapsulation key.
        #[cfg(feature = "der")]
        impl $ek_name {
            /// Encodes the key as a PKIX `SubjectPublicKeyInfo` DER structure.
            pub fn to_spki_der(&self) -> alloc::vec::Vec<u8> {
                use crate::der::{encode_bit_string, encode_sequence, oid_tlv};
                let algid = encode_sequence(&oid_tlv(oids::$oid));
                encode_sequence(&[algid, encode_bit_string(&self.0)].concat())
            }

            /// Encodes the key as a PKIX PEM document (`-----BEGIN PUBLIC KEY-----`).
            pub fn to_spki_pem(&self) -> alloc::string::String {
                crate::der::pem_encode("PUBLIC KEY", &self.to_spki_der())
            }

            /// Parses a PKIX `SubjectPublicKeyInfo` DER structure.
            pub fn from_spki_der(der: &[u8]) -> Result<Self, crate::der::Error> {
                use crate::der::{Error, Reader, parse_oid};
                let mut reader = Reader::new(der);
                let mut spki = reader.read_sequence()?;
                let mut algid = spki.read_sequence()?;
                if parse_oid(algid.read_oid()?)?.as_slice() != oids::$oid {
                    return Err(Error::Malformed);
                }
                let key_bits = spki.read_bit_string()?;
                let bytes: [u8; $ek_size] = key_bits.try_into().map_err(|_| Error::Malformed)?;
                // SPKI input is untrusted: run the FIPS 203 §7.2 modulus
                // check rather than constructing the key unvalidated.
                Self::from_bytes_validated(bytes).map_err(|_| Error::Malformed)
            }

            /// Parses a PKIX PEM public key.
            pub fn from_spki_pem(pem: &str) -> Result<Self, crate::der::Error> {
                Self::from_spki_der(&crate::der::pem_decode(pem, "PUBLIC KEY")?)
            }
        }
    };
}

ml_kem_set!(
    "ML-KEM-512 (FIPS 203, security level 1)",
    MlKem512DecapsKey,
    MlKem512EncapsKey,
    MlKem512Ciphertext,
    2,
    3,
    2,
    10,
    4,
    /* ek */ 800,
    /* dk */ 1632,
    /* ct */ 768,
    ML_KEM_512
);

ml_kem_set!(
    "ML-KEM-768 (FIPS 203, security level 3)",
    MlKem768DecapsKey,
    MlKem768EncapsKey,
    MlKem768Ciphertext,
    3,
    2,
    2,
    10,
    4,
    /* ek */ 1184,
    /* dk */ 2400,
    /* ct */ 1088,
    ML_KEM_768
);

ml_kem_set!(
    "ML-KEM-1024 (FIPS 203, security level 5)",
    MlKem1024DecapsKey,
    MlKem1024EncapsKey,
    MlKem1024Ciphertext,
    4,
    2,
    2,
    11,
    5,
    /* ek */ 1568,
    /* dk */ 3168,
    /* ct */ 1568,
    ML_KEM_1024
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    #[test]
    fn fips203_sizes() {
        // FIPS 203 §8.
        assert_eq!(
            (
                MlKem512DecapsKey::ENCAPS_KEY_BYTES,
                MlKem512DecapsKey::DECAPS_KEY_BYTES,
                MlKem512DecapsKey::CIPHERTEXT_BYTES,
            ),
            (800, 1632, 768)
        );
        assert_eq!(
            (
                MlKem768DecapsKey::ENCAPS_KEY_BYTES,
                MlKem768DecapsKey::DECAPS_KEY_BYTES,
                MlKem768DecapsKey::CIPHERTEXT_BYTES,
            ),
            (1184, 2400, 1088)
        );
        assert_eq!(
            (
                MlKem1024DecapsKey::ENCAPS_KEY_BYTES,
                MlKem1024DecapsKey::DECAPS_KEY_BYTES,
                MlKem1024DecapsKey::CIPHERTEXT_BYTES,
            ),
            (1568, 3168, 1568)
        );
    }

    #[test]
    fn roundtrip_768() {
        let mut rng = HmacDrbg::<Sha256>::new(b"mlkem-768", b"nonce", &[]);
        let (dk, ek) = MlKem768DecapsKey::generate(&mut rng);
        let (ct, ss_a) = ek.encapsulate(&mut rng);
        let ss_b = dk.decapsulate(&ct);
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn roundtrip_512() {
        let mut rng = HmacDrbg::<Sha256>::new(b"mlkem-512", b"nonce", &[]);
        let (dk, ek) = MlKem512DecapsKey::generate(&mut rng);
        let (ct, ss_a) = ek.encapsulate(&mut rng);
        let ss_b = dk.decapsulate(&ct);
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn roundtrip_1024() {
        let mut rng = HmacDrbg::<Sha256>::new(b"mlkem-1024", b"nonce", &[]);
        let (dk, ek) = MlKem1024DecapsKey::generate(&mut rng);
        let (ct, ss_a) = ek.encapsulate(&mut rng);
        let ss_b = dk.decapsulate(&ct);
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn implicit_rejection_512() {
        let mut rng = HmacDrbg::<Sha256>::new(b"reject-512", b"nonce", &[]);
        let (dk, ek) = MlKem512DecapsKey::generate(&mut rng);
        let (ct, ss) = ek.encapsulate(&mut rng);
        let mut bad = ct.to_bytes();
        bad[0] ^= 1;
        let rejected = dk.decapsulate(&MlKem512Ciphertext::from_bytes(bad));
        assert_ne!(rejected, ss);
        // Deterministic: same bad ciphertext maps to the same rejection secret.
        assert_eq!(
            rejected,
            dk.decapsulate(&MlKem512Ciphertext::from_bytes(bad))
        );
    }

    #[test]
    fn implicit_rejection_1024() {
        let mut rng = HmacDrbg::<Sha256>::new(b"reject-1024", b"nonce", &[]);
        let (dk, ek) = MlKem1024DecapsKey::generate(&mut rng);
        let (ct, ss) = ek.encapsulate(&mut rng);
        let mut bad = ct.to_bytes();
        bad[0] ^= 1;
        let rejected = dk.decapsulate(&MlKem1024Ciphertext::from_bytes(bad));
        assert_ne!(rejected, ss);
        assert_eq!(
            rejected,
            dk.decapsulate(&MlKem1024Ciphertext::from_bytes(bad))
        );
    }

    /// ML-KEM-768 byte-compat with OpenSSL 3.5 (deterministic keygen with
    /// `d = z = 0³²`). The refactor must produce identical bytes.
    #[test]
    fn openssl_interop_768_unchanged_after_refactor() {
        use crate::test_util::{from_hex, from_hex_vec};
        let (dk, ek) = MlKem768DecapsKey::from_seeds(&[0u8; 32], &[0u8; 32]);

        let e = ek.to_bytes();
        assert_eq!(e[..16], from_hex::<16>("254a797885c63b1440aa389c65340ef3"));
        assert_eq!(
            e[e.len() - 32..],
            from_hex::<32>("6d3ae406763c50457d1481402aafc7e23f43f9d1d7c0af7060ac1daa9ecb0e67")
        );

        let ct_bytes = from_hex_vec(include_str!("../../testdata/mlkem768_openssl_ct.hex"));
        let mut ct = [0u8; MlKem768DecapsKey::CIPHERTEXT_BYTES];
        ct.copy_from_slice(&ct_bytes);
        let ss = dk.decapsulate(&MlKem768Ciphertext::from_bytes(ct));
        assert_eq!(
            ss,
            from_hex::<32>("2b59302b878ffc5eae9e4f5d4ddc8a73cea97ef10af90d7945b331d288683066")
        );
    }

    #[cfg(feature = "der")]
    #[test]
    fn spki_768_matches_openssl_and_roundtrips() {
        use crate::test_util::from_hex_vec;
        let (_dk, ek) = MlKem768DecapsKey::from_seeds(&[0u8; 32], &[0u8; 32]);
        let expected = from_hex_vec(include_str!("../../testdata/mlkem768_openssl_spki.hex"));
        assert_eq!(ek.to_spki_der(), expected);

        let pem = ek.to_spki_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let parsed = MlKem768EncapsKey::from_spki_pem(&pem).unwrap();
        assert_eq!(parsed, ek);
    }

    #[cfg(feature = "der")]
    #[test]
    fn pkcs8_roundtrip_each_set() {
        let mut rng = HmacDrbg::<Sha256>::new(b"pkcs8", b"nonce", &[]);
        // 512
        let (dk, _) = MlKem512DecapsKey::generate(&mut rng);
        let pem = dk.to_pkcs8_pem();
        let parsed = MlKem512DecapsKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(parsed.to_bytes(), dk.to_bytes());
        // 768
        let (dk, _) = MlKem768DecapsKey::generate(&mut rng);
        let pem = dk.to_pkcs8_pem();
        let parsed = MlKem768DecapsKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(parsed.to_bytes(), dk.to_bytes());
        // 1024
        let (dk, _) = MlKem1024DecapsKey::generate(&mut rng);
        let pem = dk.to_pkcs8_pem();
        let parsed = MlKem1024DecapsKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(parsed.to_bytes(), dk.to_bytes());
    }

    /// FIPS 203 §7.3 — the decapsulation key embeds `H(ek)` so a future
    /// decap can short-circuit a key that's been corrupted on disk. The
    /// trusted-input fast path `from_bytes` accepts anything; the strict
    /// path `from_bytes_validated` rejects a byte-flipped key.
    #[test]
    fn decaps_key_from_bytes_validated_catches_corruption() {
        let mut rng = HmacDrbg::<Sha256>::new(b"validated", b"nonce", &[]);
        // ML-KEM-512.
        let (dk, _) = MlKem512DecapsKey::generate(&mut rng);
        let good = dk.to_bytes();
        assert!(MlKem512DecapsKey::from_bytes_validated(good).is_ok());
        let mut bad = good;
        // Flip a byte inside the H(ek) digest field. Offset:
        // pke_dk = 384 * k = 768; ek_size = 800 → H starts at 1568,
        // 32 bytes long.
        bad[1570] ^= 1;
        // Trusted-input fast path: no check.
        let _trusted = MlKem512DecapsKey::from_bytes(bad);
        // Strict path: must reject.
        assert!(MlKem512DecapsKey::from_bytes_validated(bad).is_err());

        // ML-KEM-1024.
        let (dk, _) = MlKem1024DecapsKey::generate(&mut rng);
        let good = dk.to_bytes();
        assert!(MlKem1024DecapsKey::from_bytes_validated(good).is_ok());
        let mut bad = good;
        // pke_dk = 384 * 4 = 1536; ek_size = 1568 → H starts at 3104.
        bad[3105] ^= 1;
        assert!(MlKem1024DecapsKey::from_bytes_validated(bad).is_err());
    }

    /// FIPS 203 §7.2 — `from_spki_der` must reject an encapsulation key
    /// whose t̂ encoding carries an off-modulus 12-bit coefficient, not
    /// hand back an unvalidated key.
    #[cfg(feature = "der")]
    #[test]
    fn spki_rejects_off_modulus_coefficient() {
        let mut rng = HmacDrbg::<Sha256>::new(b"spki-check", b"nonce", &[]);
        let (_dk, ek) = MlKem768DecapsKey::generate(&mut rng);
        let mut bad = ek.to_bytes();
        // Force the first 12-bit coefficient to 0xFFF = 4095 ≥ q = 3329.
        bad[0] = 0xff;
        bad[1] = 0xff;
        // The strict raw-bytes path must reject it (this also exercises the
        // [q, 4096) range the old round-trip check let through unreduced).
        assert!(MlKem768EncapsKey::from_bytes_validated(bad).is_err());
        let spki = MlKem768EncapsKey::from_bytes(bad).to_spki_der();
        assert_eq!(
            MlKem768EncapsKey::from_spki_der(&spki),
            Err(crate::der::Error::Malformed)
        );
        // Sanity: the unmodified key still parses.
        assert!(MlKem768EncapsKey::from_spki_der(&ek.to_spki_der()).is_ok());
    }

    /// FIPS 203 §7.3 — `from_pkcs8_der` must reject a decapsulation key
    /// whose embedded H(ek) field has been corrupted.
    #[cfg(feature = "der")]
    #[test]
    fn pkcs8_rejects_corrupted_hash_field() {
        let mut rng = HmacDrbg::<Sha256>::new(b"pkcs8-check", b"nonce", &[]);
        let (dk, _ek) = MlKem768DecapsKey::generate(&mut rng);
        let mut bad = dk.to_bytes();
        // pke_dk = 384 * 3 = 1152; ek_size = 1184 → H(ek) starts at 2336.
        bad[2337] ^= 1;
        let der = MlKem768DecapsKey::from_bytes(bad).to_pkcs8_der();
        assert!(MlKem768DecapsKey::from_pkcs8_der(&der).is_err());
        // Sanity: the unmodified key still parses.
        assert!(MlKem768DecapsKey::from_pkcs8_der(&dk.to_pkcs8_der()).is_ok());
    }
}
