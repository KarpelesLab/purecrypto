//! PKCS#1 v1.5 encryption and signatures (RFC 8017).
//!
//! # Security note
//!
//! PKCS#1 v1.5 **encryption** padding is susceptible to Bleichenbacher-style
//! padding-oracle attacks; the decryption here removes padding in a
//! best-effort manner but the scheme is fundamentally fragile. Prefer OAEP for
//! new protocols. PKCS#1 v1.5 **signatures** remain in wide use and are
//! provided for interoperability.

use alloc::vec;
use alloc::vec::Vec;

use super::digest_info::Pkcs1Digest;
use super::emsa;
use super::{Error, RsaPrivateKey, RsaPublicKey};
use crate::hash::Digest;
use crate::rng::{CryptoRng, RngCore};

impl<const LIMBS: usize> RsaPublicKey<LIMBS> {
    /// Encrypts `msg` with PKCS#1 v1.5 (RFC 8017 §7.2.1). Returns the
    /// `LIMBS*8`-byte ciphertext.
    ///
    /// # Errors
    /// [`Error::MessageTooLong`] if `msg.len() > k - 11`, where `k = LIMBS*8`.
    pub fn encrypt_pkcs1v15<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; LIMBS * 8];
        emsa::encrypt_pkcs1v15(self, msg, rng, &mut out)?;
        Ok(out)
    }

    /// Encrypts `msg` with RSAES-OAEP (RFC 8017 §7.1.1), using hash `D` for both
    /// the label hash and MGF1, and the empty label by default — pass `label`
    /// to bind context. Returns the `LIMBS*8`-byte ciphertext.
    ///
    /// `rng` must be a cryptographically secure CSPRNG (see [`CryptoRng`]) —
    /// OAEP's security reduction depends on the seed being unpredictable.
    ///
    /// # Errors
    /// [`Error::MessageTooLong`] if `msg.len() > k - 2·hLen - 2`.
    pub fn encrypt_oaep<D: Digest, R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        label: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; LIMBS * 8];
        emsa::encrypt_oaep::<D, _, _>(self, msg, label, rng, &mut out)?;
        Ok(out)
    }

    /// Verifies a PKCS#1 v1.5 signature over `msg`, hashing with `D`.
    ///
    /// # Errors
    /// [`Error::Verification`] if the signature is invalid;
    /// [`Error::InvalidLength`] if `sig` is not `LIMBS*8` bytes.
    pub fn verify_pkcs1v15<D: Pkcs1Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let (mut em, mut expected) = (vec![0u8; LIMBS * 8], vec![0u8; LIMBS * 8]);
        emsa::verify_pkcs1v15::<D, _>(self, msg, sig, &mut em, &mut expected)
    }
}

impl<const LIMBS: usize> RsaPrivateKey<LIMBS> {
    /// Decrypts a PKCS#1 v1.5 ciphertext (RFC 8017 §7.2.2) and returns the
    /// recovered message bytes.
    ///
    /// # Errors
    /// [`Error::InvalidLength`] if `ct` is not `LIMBS*8` bytes;
    /// [`Error::Decryption`] if the recovered padding is malformed.
    ///
    /// # Security
    ///
    /// The padding check itself is constant-time, but the returned `Vec`'s
    /// **length** (and the success / [`Error::Decryption`] distinction)
    /// reveals the position of the PKCS#1 v1.5 separator byte. An adaptive
    /// chosen-ciphertext attacker who observes the protocol response can
    /// mount a Bleichenbacher / Marvin / ROBOT-class oracle.
    ///
    /// For TLS 1.0–1.2 RSA key transport, CMS / PKCS#7, JOSE RSA1_5, and
    /// other contexts where the plaintext length is known at the protocol
    /// layer, use [`decrypt_pkcs1v15_session`](Self::decrypt_pkcs1v15_session)
    /// instead. It returns a fixed-width, key-bound synthetic plaintext on
    /// padding failure so the failure mode is indistinguishable from
    /// success.
    ///
    /// For new code, prefer OAEP via [`decrypt_oaep`](Self::decrypt_oaep).
    pub fn decrypt_pkcs1v15(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
        let mut scratch = vec![0u8; LIMBS * 8];
        let mut out = vec![0u8; LIMBS * 8];
        // `scratch` holds the decrypted EM (padding + plaintext); wipe it on
        // every exit path before the Vec is freed.
        let res = emsa::decrypt_pkcs1v15(self, ct, &mut scratch, &mut out);
        super::wipe(&mut scratch);
        let n = res?;
        out.truncate(n);
        Ok(out)
    }

    /// Decrypts a PKCS#1 v1.5 ciphertext with implicit rejection (RFC 8017
    /// §7.2.2 Note, the "Marvin" / TLS 1.2-style mitigation against
    /// Bleichenbacher's attack).
    ///
    /// On padding failure, returns a deterministic pseudorandom buffer of
    /// length `expected_len` derived from the ciphertext bytes and a
    /// per-key secret. The caller (and any external observer) cannot
    /// distinguish a real decryption from a synthetic one in timing, error
    /// path, or output length — the only way to defeat a Bleichenbacher
    /// oracle when the caller's downstream behavior would otherwise leak
    /// the padding outcome.
    ///
    /// The returned `Vec` is always exactly `expected_len` bytes: PKCS#1
    /// v1.5 padding alone cannot recover the intended plaintext length, so
    /// the protocol must agree on it (e.g. TLS RSA key transport:
    /// `expected_len = 48` for the 48-byte pre-master secret). A ciphertext
    /// that decrypts to valid padding but a plaintext of a *different*
    /// length is treated exactly like malformed padding and yields the
    /// synthetic output (RFC 5246 §7.4.7.1).
    ///
    /// # Errors
    /// Only [`Error::InvalidLength`] when `ct.len() != LIMBS*8`. All other
    /// failure modes are folded into the synthetic plaintext.
    pub fn decrypt_pkcs1v15_session(
        &self,
        ct: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let mut scratch = vec![0u8; LIMBS * 8];
        let mut out = vec![0u8; expected_len];
        let res = emsa::decrypt_pkcs1v15_session(self, ct, &mut scratch, &mut out);
        super::wipe(&mut scratch);
        res?;
        Ok(out)
    }

    /// Decrypts a PKCS#1 v1.5 ciphertext with **implicit rejection** and a
    /// pseudo-random output length — the mitigation for callers that cannot
    /// pin an expected plaintext length the way
    /// [`decrypt_pkcs1v15_session`](Self::decrypt_pkcs1v15_session) requires.
    ///
    /// On malformed padding (or an out-of-range ciphertext) this returns a
    /// pseudo-random message of pseudo-random length, both derived from the
    /// ciphertext and a secret bound to this key, instead of an error. An
    /// adaptive chosen-ciphertext attacker therefore learns nothing from the
    /// success/failure distinction *or* from the returned length, closing the
    /// Bleichenbacher / Marvin / ROBOT oracle that
    /// [`decrypt_pkcs1v15`](Self::decrypt_pkcs1v15) leaves open. The
    /// application must authenticate the recovered plaintext by other means
    /// (as every sound PKCS#1 v1.5 protocol already does).
    ///
    /// # Errors
    /// Only [`Error::InvalidLength`] when `ct.len() != LIMBS*8`.
    pub fn decrypt_pkcs1v15_implicit(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
        let mut scratch = vec![0u8; LIMBS * 8];
        let mut out = vec![0u8; LIMBS * 8];
        let res = emsa::decrypt_pkcs1v15_implicit(self, ct, &mut scratch, &mut out);
        super::wipe(&mut scratch);
        let n = match res {
            Ok(n) => n,
            Err(e) => {
                super::wipe(&mut out);
                return Err(e);
            }
        };
        out.truncate(n);
        Ok(out)
    }

    /// Decrypts an RSAES-OAEP ciphertext (RFC 8017 §7.1.2). Hash `D` must match
    /// the one used at encryption; `label` must match the encryptor's label
    /// (empty by default). The padding-check path is constant-time over the
    /// decrypted EM so that a bad ciphertext is not distinguishable in timing
    /// from a bad label.
    pub fn decrypt_oaep<D: Digest>(&self, ct: &[u8], label: &[u8]) -> Result<Vec<u8>, Error> {
        let mut scratch = vec![0u8; LIMBS * 8];
        let mut out = vec![0u8; LIMBS * 8];
        let res = emsa::decrypt_oaep::<D, _>(self, ct, label, &mut scratch, &mut out);
        super::wipe(&mut scratch);
        let n = res?;
        out.truncate(n);
        Ok(out)
    }

    /// Produces a PKCS#1 v1.5 signature over `msg`, hashing with `D`
    /// (RFC 8017 §8.2.1).
    ///
    /// # Errors
    /// [`Error::MessageTooLong`] if the modulus is too small for the digest.
    pub fn sign_pkcs1v15<D: Pkcs1Digest>(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; LIMBS * 8];
        emsa::sign_pkcs1v15::<D, _>(self, msg, &mut out)?;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha224, Sha256};
    use crate::rng::HmacDrbg;
    use crate::test_util::rsa_test_key_a;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        // RSA-2048: k = 256, so up to 245 message bytes.
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-enc", b"nonce", &[]);

        let msg = b"hello rsa";
        let ct = pk.encrypt_pkcs1v15(msg, &mut r).unwrap();
        assert_eq!(ct.len(), 256);
        assert_ne!(&ct[..], msg);
        assert_eq!(key.decrypt_pkcs1v15(&ct).unwrap(), msg);
    }

    #[test]
    fn encrypt_rejects_overlong() {
        let pk = rsa_test_key_a().public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-enc2", b"nonce", &[]);
        // k - 11 = 245; 246 bytes must be rejected.
        assert_eq!(
            pk.encrypt_pkcs1v15(&[0u8; 246], &mut r),
            Err(Error::MessageTooLong)
        );
    }

    #[test]
    fn oaep_roundtrip_sha256() {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-oaep", b"nonce", &[]);

        // RSA-2048 + SHA-256: k - 2*hLen - 2 = 256 - 64 - 2 = 190 max message bytes.
        let msg = b"OAEP round-trip with the default empty label";
        let ct = pk.encrypt_oaep::<Sha256, _>(msg, b"", &mut r).unwrap();
        assert_eq!(ct.len(), 256);
        assert_ne!(&ct[..msg.len()], msg);
        let pt = key.decrypt_oaep::<Sha256>(&ct, b"").unwrap();
        assert_eq!(&pt[..], msg);
    }

    #[test]
    fn oaep_distinct_ciphertexts() {
        // OAEP draws a fresh random seed per encryption, so two encryptions of
        // the same message produce distinct ciphertexts.
        let pk = rsa_test_key_a().public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-oaep-rand", b"nonce", &[]);
        let msg = b"x";
        let c1 = pk.encrypt_oaep::<Sha256, _>(msg, b"", &mut r).unwrap();
        let c2 = pk.encrypt_oaep::<Sha256, _>(msg, b"", &mut r).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn oaep_label_binds() {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-oaep-label", b"nonce", &[]);
        let msg = b"context-bound";
        let ct = pk
            .encrypt_oaep::<Sha256, _>(msg, b"label-A", &mut r)
            .unwrap();
        // Same ciphertext, different label => decryption rejects.
        assert_eq!(
            key.decrypt_oaep::<Sha256>(&ct, b"label-B"),
            Err(Error::Decryption)
        );
        // Matching label succeeds.
        assert_eq!(
            &key.decrypt_oaep::<Sha256>(&ct, b"label-A").unwrap()[..],
            msg
        );
    }

    #[test]
    fn oaep_rejects_overlong() {
        let pk = rsa_test_key_a().public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-oaep-long", b"nonce", &[]);
        // RSA-2048 + SHA-256: max message = 190 bytes; 191 must be rejected.
        assert_eq!(
            pk.encrypt_oaep::<Sha256, _>(&[0u8; 191], b"", &mut r),
            Err(Error::MessageTooLong)
        );
    }

    #[test]
    fn oaep_rejects_tampered() {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-oaep-tamper", b"nonce", &[]);
        let mut ct = pk
            .encrypt_oaep::<Sha256, _>(b"to be tampered", b"", &mut r)
            .unwrap();
        ct[42] ^= 1;
        assert_eq!(key.decrypt_oaep::<Sha256>(&ct, b""), Err(Error::Decryption));
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = rsa_test_key_a();
        let pk = key.public_key();

        let msg = b"sign me";
        let sig = key.sign_pkcs1v15::<Sha256>(msg).unwrap();
        assert_eq!(sig.len(), 256);
        assert!(pk.verify_pkcs1v15::<Sha256>(msg, &sig).is_ok());

        // Wrong message fails.
        assert_eq!(
            pk.verify_pkcs1v15::<Sha256>(b"other", &sig),
            Err(Error::Verification)
        );
        // Tampered signature fails.
        let mut bad = sig.clone();
        bad[40] ^= 1;
        assert_eq!(
            pk.verify_pkcs1v15::<Sha256>(msg, &bad),
            Err(Error::Verification)
        );
        // Wrong hash algorithm fails (different DigestInfo).
        assert_eq!(
            pk.verify_pkcs1v15::<Sha224>(msg, &sig),
            Err(Error::Verification)
        );
    }

    /// RFC 8017 §8.2.2 step 4 requires comparing the *whole* encoded message
    /// `EM' = 0x00 ‖ 0x01 ‖ PS ‖ 0x00 ‖ T` against the recovered one. A
    /// verifier that instead parses `EM` — skips the `0xFF` run, finds the
    /// `0x00`, then only checks that `T` follows — accepts encodings with a
    /// short `PS` and trailing garbage after `T`, which is exactly what makes
    /// the Bleichenbacher `e = 3` cube-root forgery (2006) and its `DigestInfo`
    /// parameter variants (CVE-2006-4339 and successors) work. This pins the
    /// strict behaviour: every malformed `EM` below is signed with the real
    /// private key (so the signature is a perfectly valid RSA representative
    /// of that `EM`) and must still be refused, while a canonical `EM`
    /// assembled the same way is accepted.
    #[test]
    fn pkcs1v15_verify_rejects_malformed_encodings() {
        use crate::bignum::Uint;
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let msg = b"strict EMSA-PKCS1-v1_5 comparison";
        let k = 256usize;
        let t: Vec<u8> = [
            <Sha256 as Pkcs1Digest>::DIGEST_INFO_PREFIX,
            Sha256::digest(msg).as_ref(),
        ]
        .concat();
        let ps_len = k - t.len() - 3;

        // Signs an arbitrary `k`-octet encoded message with the private key.
        let sign_em = |em: &[u8]| -> Vec<u8> {
            assert_eq!(em.len(), k);
            assert_eq!(em[0], 0x00, "EM must be < n");
            let mut out = alloc::vec![0u8; k];
            key.raw(&Uint::<32>::from_be_bytes(em))
                .write_be_bytes(&mut out);
            out
        };

        // Canonical: 00 01 FF…FF 00 T — must verify (proves the harness).
        let canonical = [&[0x00, 0x01][..], &alloc::vec![0xffu8; ps_len], &[0x00], &t].concat();
        pk.verify_pkcs1v15::<Sha256>(msg, &sign_em(&canonical))
            .unwrap();

        let garbage = alloc::vec![0x42u8; ps_len - 8];
        let malformed: [(&str, Vec<u8>); 5] = [
            (
                "short PS + trailing garbage after T (Bleichenbacher '06 shape)",
                [&[0x00, 0x01][..], &[0xff; 8], &[0x00], &t, &garbage].concat(),
            ),
            (
                "T followed by a single trailing octet",
                [
                    &[0x00, 0x01][..],
                    &alloc::vec![0xffu8; ps_len - 1],
                    &[0x00],
                    &t,
                    &[0x00],
                ]
                .concat(),
            ),
            ("non-0xFF octet inside PS", {
                let mut em = canonical.clone();
                em[2 + ps_len / 2] = 0xfe;
                em
            }),
            ("block type 0x02 instead of 0x01", {
                let mut em = canonical.clone();
                em[1] = 0x02;
                em
            }),
            (
                "PS shorter than 8 octets padded with zeros before T",
                [
                    &[0x00, 0x01][..],
                    &[0xff; 7],
                    &[0x00],
                    &alloc::vec![0u8; ps_len - 7],
                    &t,
                ]
                .concat(),
            ),
        ];
        for (what, em) in &malformed {
            assert_eq!(em.len(), k, "{what}");
            assert_eq!(
                pk.verify_pkcs1v15::<Sha256>(msg, &sign_em(em)),
                Err(Error::Verification),
                "{what} must be rejected"
            );
        }
    }

    // ---- RSA-2: implicit-rejection (decrypt_pkcs1v15_session) ----

    /// Round-trip: a real PKCS#1 v1.5 ciphertext decrypts to its original
    /// plaintext when `expected_len` matches.
    #[test]
    fn session_decrypt_recovers_message_on_valid_ct() {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-session-ok", b"nonce", &[]);
        let msg = [0xa5u8; 48]; // 48-byte premaster-secret-shaped message.
        let ct = pk.encrypt_pkcs1v15(&msg, &mut r).unwrap();
        let out = key.decrypt_pkcs1v15_session(&ct, msg.len()).unwrap();
        assert_eq!(out, msg);
    }

    /// A ciphertext whose decryption yields malformed padding must not
    /// surface an error: the session API returns an `expected_len`-byte
    /// pseudorandom plaintext instead, indistinguishable in shape from
    /// success. This is the core anti-Bleichenbacher property.
    #[test]
    fn session_decrypt_returns_synthetic_on_bad_padding() {
        let key = rsa_test_key_a();
        // Any 256-byte buffer that decrypts under `key` to something
        // not starting with 0x00 0x02. The all-ones ciphertext below
        // overwhelmingly fits.
        let bogus_ct = [0x7eu8; 256];
        let out = key.decrypt_pkcs1v15_session(&bogus_ct, 48).unwrap();
        assert_eq!(out.len(), 48);
    }

    /// The synthetic plaintext is deterministic for a given (key, ct,
    /// expected_len) triple, so repeated calls under the same long-term
    /// secret produce identical output. This is what lets a protocol layer
    /// treat the failure path as "as if decryption succeeded".
    #[test]
    fn session_decrypt_is_deterministic_under_same_key() {
        let key = rsa_test_key_a();
        let bogus_ct = [0x3cu8; 256];
        let a = key.decrypt_pkcs1v15_session(&bogus_ct, 48).unwrap();
        let b = key.decrypt_pkcs1v15_session(&bogus_ct, 48).unwrap();
        assert_eq!(a, b);
    }

    /// A ciphertext with **valid** padding but a plaintext of the wrong
    /// length must be rejected exactly like bad padding: RFC 5246 §7.4.7.1
    /// requires a random premaster whenever the recovered length is not 48.
    /// Before the length check was folded into the constant-time `bad`
    /// mask, a 47-byte message came back as `msg ‖ 00`, which is both a
    /// padding oracle and a protocol bug.
    #[test]
    fn session_decrypt_rejects_valid_padding_with_wrong_length() {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-session-len", b"nonce", &[]);
        let msg = [0x5au8; 47]; // one byte short of a premaster secret
        let ct = pk.encrypt_pkcs1v15(&msg, &mut r).unwrap();
        let out = key.decrypt_pkcs1v15_session(&ct, 48).unwrap();
        assert_eq!(out.len(), 48);
        assert_ne!(&out[..47], &msg[..], "must not leak the short plaintext");
        assert_ne!(out[47], 0, "must not be the zero-padded real plaintext");
        // Deterministic, like every other implicit-rejection outcome.
        let again = key.decrypt_pkcs1v15_session(&ct, 48).unwrap();
        assert_eq!(out, again);
        // And the correctly-sized message still round-trips.
        let msg48 = [0x5au8; 48];
        let ct48 = pk.encrypt_pkcs1v15(&msg48, &mut r).unwrap();
        assert_eq!(key.decrypt_pkcs1v15_session(&ct48, 48).unwrap(), msg48);
    }

    // ---- implicit rejection with pseudo-random length ----

    /// Every plaintext length round-trips exactly through the
    /// implicit-rejection decrypt.
    #[test]
    fn implicit_decrypt_roundtrips_every_length() {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"rsa-implicit-rt", b"nonce", &[]);
        for len in [0usize, 1, 16, 48, 200, 245] {
            let msg = vec![0x2bu8; len];
            let ct = pk.encrypt_pkcs1v15(&msg, &mut r).unwrap();
            assert_eq!(
                key.decrypt_pkcs1v15_implicit(&ct).unwrap(),
                msg,
                "len {len}"
            );
            // The allocation-free variant agrees.
            let mut out = [0u8; 256];
            let n = key.decrypt_pkcs1v15_implicit_into(&ct, &mut out).unwrap();
            assert_eq!(&out[..n], &msg[..]);
        }
    }

    /// Bad padding never surfaces an error, and the synthetic plaintext's
    /// length varies with the ciphertext — the property the plain
    /// `decrypt_pkcs1v15` lacks (its length reveals the separator position).
    #[test]
    fn implicit_decrypt_hides_padding_failures() {
        let key = rsa_test_key_a();
        let mut lens = Vec::new();
        for i in 0..16u8 {
            let bogus = [0x11u8 ^ i; 256];
            let out = key.decrypt_pkcs1v15_implicit(&bogus).unwrap();
            assert!(out.len() <= 245);
            // Deterministic per ciphertext.
            assert_eq!(out, key.decrypt_pkcs1v15_implicit(&bogus).unwrap());
            lens.push(out.len());
        }
        assert!(
            lens.iter().any(|l| *l != lens[0]),
            "synthetic lengths must not be constant: {lens:?}"
        );
        // Out-of-range (c >= n) is absorbed the same way.
        assert!(key.decrypt_pkcs1v15_implicit(&[0xffu8; 256]).is_ok());
        // A wrong-size ciphertext is public information and still errors.
        assert_eq!(
            key.decrypt_pkcs1v15_implicit(&[0u8; 255]),
            Err(Error::InvalidLength)
        );
    }

    /// `Error::InvalidLength` is the only failure surfaced (ciphertext
    /// length mismatch is public, not a padding-dependent secret).
    #[test]
    fn session_decrypt_rejects_wrong_length_ct() {
        let key = rsa_test_key_a();
        let short = [0u8; 255];
        assert_eq!(
            key.decrypt_pkcs1v15_session(&short, 48),
            Err(Error::InvalidLength)
        );
    }
}
