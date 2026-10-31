//! The BLS signature scheme of `draft-irtf-cfrg-bls-signature-05`, written
//! once over the group and pairing interface the `bn254` and `bls12_377`
//! modules share, and instantiated per curve and variant by
//! [`bls_signature!`].
//!
//! The instantiating module must have in scope (as `super::…`): `Fr`,
//! `G1`, `G2`, `Error` (with the signature variants), the pairing module's
//! crate-internal `PairingAccumulator`, and `hash_to_curve`'s multi-part
//! `hash_to_g1_parts` / `hash_to_g2_parts`.
//!
//! Everything the macro emits is allocator-free: Message Augmentation
//! streams `PK || msg` into `expand_message_xmd` as two parts, and
//! aggregate verification pushes each `(key, H(msg))` pair into a
//! stack-chunked shared Miller loop with one final exponentiation.

/// Emits a complete BLS signature API (types, ciphersuite IDs, aggregate
/// verification) for one curve and one variant.
///
/// * `variant: min_pk` — public keys in `G1`, signatures in `G2`;
///   `min_sig` — public keys in `G2`, signatures in `G1`.
/// * `suite` — the hash-to-curve suite ID of the signature group, from
///   which the draft's ciphersuite IDs are formed.
macro_rules! bls_signature {
    (
        curve: $curve:literal,
        variant: min_pk,
        suite: $suite:literal,
        pk_len: $pk_len:literal,
        pk_ulen: $pk_ulen:literal,
        sig_len: $sig_len:literal,
        sig_ulen: $sig_ulen:literal $(,)?
    ) => {
        $crate::pairing_common::bls_sig::bls_signature!(@emit
            curve: $curve,
            variant_name: "minimal-pubkey-size",
            suite: $suite,
            pk: G1, pk_g: "G1", sig: G2, sig_g: "G2",
            hash: hash_to_g2_parts,
            pk_len: $pk_len, pk_ulen: $pk_ulen,
            sig_len: $sig_len, sig_ulen: $sig_ulen,
        );

        /// Adds `e(pk, h)` to a pairing product.
        #[inline]
        fn push_key(acc: &mut super::pairing::PairingAccumulator, pk: &G1, h: &G2) {
            acc.push(pk, h);
        }

        /// Adds `e(-G1, sig)` to a pairing product.
        #[inline]
        fn push_sig(acc: &mut super::pairing::PairingAccumulator, sig: &G2) {
            acc.push(&-G1::generator(), sig);
        }

        /// The generator of the public-key group.
        #[inline]
        fn pk_generator() -> G1 {
            G1::generator()
        }
    };
    (
        curve: $curve:literal,
        variant: min_sig,
        suite: $suite:literal,
        pk_len: $pk_len:literal,
        pk_ulen: $pk_ulen:literal,
        sig_len: $sig_len:literal,
        sig_ulen: $sig_ulen:literal $(,)?
    ) => {
        $crate::pairing_common::bls_sig::bls_signature!(@emit
            curve: $curve,
            variant_name: "minimal-signature-size",
            suite: $suite,
            pk: G2, pk_g: "G2", sig: G1, sig_g: "G1",
            hash: hash_to_g1_parts,
            pk_len: $pk_len, pk_ulen: $pk_ulen,
            sig_len: $sig_len, sig_ulen: $sig_ulen,
        );

        /// Adds `e(h, pk)` to a pairing product.
        #[inline]
        fn push_key(acc: &mut super::pairing::PairingAccumulator, pk: &G2, h: &G1) {
            acc.push(h, pk);
        }

        /// Adds `e(sig, -G2)` to a pairing product.
        #[inline]
        fn push_sig(acc: &mut super::pairing::PairingAccumulator, sig: &G1) {
            acc.push(sig, &-G2::generator());
        }

        /// The generator of the public-key group.
        #[inline]
        fn pk_generator() -> G2 {
            G2::generator()
        }
    };
    (@emit
        curve: $curve:literal,
        variant_name: $vname:literal,
        suite: $suite:literal,
        pk: $Pk:ident, pk_g: $pk_g:literal, sig: $Sig:ident, sig_g: $sig_g:literal,
        hash: $hash:ident,
        pk_len: $pk_len:literal, pk_ulen: $pk_ulen:literal,
        sig_len: $sig_len:literal, sig_ulen: $sig_ulen:literal $(,)?
    ) => {
        use super::Error;
        use super::fr::Fr;
        use super::g1::G1;
        use super::g2::G2;
        use super::hash_to_curve::$hash as hash_parts;
        use super::pairing::PairingAccumulator;
        use $crate::hash::{Digest, Hmac, Sha256};
        use $crate::zeroize::Zeroize;

        #[doc = concat!("Ciphersuite ID of the Basic scheme: `BLS_SIG_", $suite, "NUL_`.")]
        pub const DST_BASIC: &[u8] = concat!("BLS_SIG_", $suite, "NUL_").as_bytes();
        #[doc = concat!("Ciphersuite ID of the Message Augmentation scheme: `BLS_SIG_", $suite, "AUG_`.")]
        pub const DST_AUG: &[u8] = concat!("BLS_SIG_", $suite, "AUG_").as_bytes();
        #[doc = concat!("Ciphersuite ID of the Proof of Possession scheme (signatures): `BLS_SIG_", $suite, "POP_`.")]
        pub const DST_POP: &[u8] = concat!("BLS_SIG_", $suite, "POP_").as_bytes();
        #[doc = concat!("Domain separation tag of the proofs of possession themselves: `BLS_POP_", $suite, "POP_`.")]
        pub const DST_POP_PROOF: &[u8] = concat!("BLS_POP_", $suite, "POP_").as_bytes();

        /// The three BLS schemes of the draft (§3).
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum Scheme {
            /// §3.1: plain signatures; aggregates need distinct messages.
            Basic,
            /// §3.2: the public key is prepended to the message before hashing.
            MessageAugmentation,
            /// §3.3: rogue-key attacks are prevented by proofs of possession.
            ProofOfPossession,
        }

        impl Scheme {
            /// The ciphersuite's domain separation tag.
            pub fn dst(self) -> &'static [u8] {
                match self {
                    Scheme::Basic => DST_BASIC,
                    Scheme::MessageAugmentation => DST_AUG,
                    Scheme::ProofOfPossession => DST_POP,
                }
            }
        }

        /// A BLS secret key: a nonzero scalar in `Fr`. Wiped on drop; its
        /// `Debug` output never shows the scalar.
        pub struct SecretKey(Fr);

        #[doc = concat!("A BLS public key: a non-identity point of `", $pk_g, "` (", $vname, " variant).")]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct PublicKey($Pk);

        #[doc = concat!("A BLS signature: a point of `", $sig_g, "`.")]
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct Signature($Sig);

        /// A proof of possession for the Proof of Possession scheme (§3.3):
        /// a signature over the public key itself under [`DST_POP_PROOF`].
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct ProofOfPossession($Sig);

        /// `KeyGen` output length `L = ceil(3·ceil(log2 r) / 16) = 48` (for
        /// both the 253- and 254-bit group orders).
        const KEYGEN_L: usize = 48;

        impl SecretKey {
            /// `KeyGen(IKM, key_info)` (§2.3): derives a key from at least 32
            /// bytes of input keying material with the HKDF loop of the
            /// draft (`salt = H(salt)`, `PRK = HKDF-Extract(salt, IKM ||
            /// 0x00)`, `OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)`,
            /// `SK = OS2IP(OKM) mod r`, repeated while `SK = 0`).
            ///
            /// Constant time in `IKM`: the reduction is a fixed wide
            /// reduction, and the only branch is the retry on `SK = 0`,
            /// which happens with probability about `2^-253` (and reveals
            /// nothing about the key finally returned).
            pub fn generate(ikm: &[u8], key_info: &[u8]) -> Result<SecretKey, Error> {
                if ikm.len() < 32 {
                    return Err(Error::InsufficientKeyMaterial);
                }
                let mut salt: [u8; 32] = Sha256::digest(b"BLS-SIG-KEYGEN-SALT-");
                loop {
                    // HKDF-Extract(salt, IKM || I2OSP(0, 1))
                    let mut h = Hmac::<Sha256>::new(&salt);
                    h.update(ikm);
                    h.update(&[0u8]);
                    let mut prk = h.finalize();
                    // HKDF-Expand(PRK, key_info || I2OSP(L, 2), L): two
                    // blocks. Every intermediate determines the key, so each
                    // is wiped once copied into place.
                    let mut t1 = Hmac::<Sha256>::new(&prk);
                    t1.update(key_info);
                    t1.update(&[0u8, KEYGEN_L as u8]);
                    t1.update(&[1u8]);
                    let mut t1 = t1.finalize();
                    let mut t2 = Hmac::<Sha256>::new(&prk);
                    prk.zeroize();
                    t2.update(&t1);
                    t2.update(key_info);
                    t2.update(&[0u8, KEYGEN_L as u8]);
                    t2.update(&[2u8]);
                    let mut t2 = t2.finalize();
                    // OS2IP of the 48-byte OKM, left-padded to the 64 bytes
                    // of the wide reduction.
                    let mut wide = [0u8; 64];
                    wide[16..48].copy_from_slice(&t1);
                    wide[48..].copy_from_slice(&t2[..16]);
                    t1.zeroize();
                    t2.zeroize();
                    let sk = Fr::from_bytes_wide(&wide);
                    wide.zeroize();
                    // Public by specification (a retry decision): `SK = 0`
                    // happens with probability ≈ 2^-253 and only the retry
                    // count is observable, never the key that is returned.
                    if !sk.is_zero().declassify() {
                        return Ok(SecretKey(sk));
                    }
                    // Negligible: only when OKM ≡ 0 (mod r). Re-salt, retry.
                    salt = Sha256::digest(&salt);
                }
            }

            /// Generates a key from 32 bytes of randomness drawn from `rng`.
            #[cfg(feature = "rng")]
            pub fn random<R: $crate::rng::RngCore + $crate::rng::CryptoRng>(
                rng: &mut R,
            ) -> SecretKey {
                let mut ikm = [0u8; 32];
                rng.fill_bytes(&mut ikm);
                let sk = SecretKey::generate(&ikm, b"");
                ikm.zeroize();
                // 32 bytes of IKM never trip the length check.
                match sk {
                    Ok(sk) => sk,
                    Err(_) => unreachable!("32-byte IKM"),
                }
            }

            /// Loads a key from its 32-byte big-endian encoding; the scalar
            /// must be canonical (`< r`) and nonzero.
            pub fn from_bytes(bytes: &[u8; 32]) -> Result<SecretKey, Error> {
                let sk = Fr::from_bytes(bytes).ok_or(Error::InvalidScalar)?;
                // Public: the caller sees the verdict as `Err`.
                if sk.is_zero().declassify() {
                    return Err(Error::InvalidScalar);
                }
                Ok(SecretKey(sk))
            }

            /// Wraps a nonzero scalar.
            pub fn from_scalar(sk: Fr) -> Result<SecretKey, Error> {
                // Public: the caller sees the verdict as `Err`.
                if sk.is_zero().declassify() {
                    return Err(Error::InvalidScalar);
                }
                Ok(SecretKey(sk))
            }

            /// The 32-byte big-endian encoding.
            pub fn to_bytes(&self) -> [u8; 32] {
                self.0.to_bytes()
            }

            /// The scalar itself.
            pub fn scalar(&self) -> &Fr {
                &self.0
            }

            #[doc = concat!("`SkToPk`: the public key `sk·", $pk_g, "` (constant time).")]
            pub fn public_key(&self) -> PublicKey {
                PublicKey(pk_generator().mul(&self.0))
            }

            /// `CoreSign` with the scheme's DST (and, for Message
            /// Augmentation, the public key prepended to the message):
            /// `sk·H(msg)`, a constant-time scalar multiplication.
            pub fn sign(&self, scheme: Scheme, msg: &[u8]) -> Signature {
                let h = match scheme {
                    Scheme::MessageAugmentation => {
                        let pk = self.public_key().to_bytes();
                        hash_parts(&[&pk, msg], DST_AUG)
                    }
                    _ => hash_parts(&[msg], scheme.dst()),
                };
                Signature(h.mul(&self.0))
            }

            /// `PopProve` (§3.3.2): a signature over the public key under
            /// [`DST_POP_PROOF`].
            pub fn pop_prove(&self) -> ProofOfPossession {
                let pk = self.public_key().to_bytes();
                ProofOfPossession(hash_parts(&[&pk], DST_POP_PROOF).mul(&self.0))
            }
        }

        impl Drop for SecretKey {
            fn drop(&mut self) {
                self.0.zeroize();
            }
        }

        impl $crate::zeroize::ZeroizeOnDrop for SecretKey {}

        impl core::fmt::Debug for SecretKey {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str("SecretKey(..)")
            }
        }

        /// The hashed message point of `scheme` for signer `pk`.
        fn hash_message(scheme: Scheme, pk: &PublicKey, msg: &[u8]) -> $Sig {
            match scheme {
                Scheme::MessageAugmentation => hash_parts(&[&pk.to_bytes(), msg], DST_AUG),
                _ => hash_parts(&[msg], scheme.dst()),
            }
        }

        /// `CoreVerify` given the already-hashed message point: the
        /// pairing equation of `pk`, `h` and `sig` with one final
        /// exponentiation.
        fn core_verify(pk: &$Pk, h: &$Sig, sig: &$Sig) -> Result<(), Error> {
            let mut acc = PairingAccumulator::new();
            push_key(&mut acc, pk, h);
            push_sig(&mut acc, sig);
            if bool::from(acc.finish().is_identity()) {
                Ok(())
            } else {
                Err(Error::InvalidSignature)
            }
        }

        impl PublicKey {
            #[doc = concat!("`KeyValidate` on a ", stringify!($pk_len), "-byte compressed `", $pk_g, "` encoding: decodes with the full curve and subgroup checks and rejects the identity.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
                Self::from_point($Pk::from_compressed(bytes)?)
            }

            #[doc = concat!("`KeyValidate` on a ", stringify!($pk_ulen), "-byte uncompressed `", $pk_g, "` encoding.")]
            pub fn from_uncompressed(bytes: &[u8]) -> Result<PublicKey, Error> {
                Self::from_point($Pk::from_uncompressed(bytes)?)
            }

            #[doc = concat!("Wraps a `", $pk_g, "` point, rejecting the identity.")]
            pub fn from_point(p: $Pk) -> Result<PublicKey, Error> {
                if bool::from(p.is_identity()) {
                    return Err(Error::IdentityPoint);
                }
                Ok(PublicKey(p))
            }

            #[doc = concat!("The ", stringify!($pk_len), "-byte compressed encoding (the octets hashed by Message Augmentation and proofs of possession).")]
            pub fn to_bytes(&self) -> [u8; $pk_len] {
                self.0.to_compressed()
            }

            #[doc = concat!("The ", stringify!($pk_ulen), "-byte uncompressed encoding.")]
            pub fn to_uncompressed(&self) -> [u8; $pk_ulen] {
                self.0.to_uncompressed()
            }

            /// The underlying point.
            pub fn point(&self) -> &$Pk {
                &self.0
            }

            /// `Verify(PK, message, signature)` for the given scheme.
            pub fn verify(&self, scheme: Scheme, msg: &[u8], sig: &Signature) -> Result<(), Error> {
                core_verify(&self.0, &hash_message(scheme, self, msg), &sig.0)
            }

            /// `PopVerify` (§3.3.3).
            pub fn pop_verify(&self, proof: &ProofOfPossession) -> Result<(), Error> {
                let h = hash_parts(&[&self.to_bytes()], DST_POP_PROOF);
                core_verify(&self.0, &h, &proof.0)
            }
        }

        impl Signature {
            #[doc = concat!("Decodes a ", stringify!($sig_len), "-byte compressed `", $sig_g, "` encoding with the curve and subgroup checks (`signature_subgroup_check`).")]
            pub fn from_bytes(bytes: &[u8]) -> Result<Signature, Error> {
                Ok(Signature($Sig::from_compressed(bytes)?))
            }

            #[doc = concat!("Decodes a ", stringify!($sig_ulen), "-byte uncompressed `", $sig_g, "` encoding with full validation.")]
            pub fn from_uncompressed(bytes: &[u8]) -> Result<Signature, Error> {
                Ok(Signature($Sig::from_uncompressed(bytes)?))
            }

            #[doc = concat!("Wraps a `", $sig_g, "` point.")]
            pub fn from_point(p: $Sig) -> Signature {
                Signature(p)
            }

            #[doc = concat!("The ", stringify!($sig_len), "-byte compressed encoding.")]
            pub fn to_bytes(&self) -> [u8; $sig_len] {
                self.0.to_compressed()
            }

            #[doc = concat!("The ", stringify!($sig_ulen), "-byte uncompressed encoding.")]
            pub fn to_uncompressed(&self) -> [u8; $sig_ulen] {
                self.0.to_uncompressed()
            }

            /// The underlying point.
            pub fn point(&self) -> &$Sig {
                &self.0
            }

            /// `Aggregate` (§2.8): the sum of the signatures; fails on an
            /// empty input.
            pub fn aggregate(sigs: &[Signature]) -> Result<Signature, Error> {
                let mut acc = sigs.first().ok_or(Error::EmptyAggregate)?.0;
                for s in &sigs[1..] {
                    acc = acc.add(&s.0);
                }
                Ok(Signature(acc))
            }
        }

        impl ProofOfPossession {
            #[doc = concat!("Decodes a ", stringify!($sig_len), "-byte compressed `", $sig_g, "` encoding with full validation.")]
            pub fn from_bytes(bytes: &[u8]) -> Result<ProofOfPossession, Error> {
                Ok(ProofOfPossession($Sig::from_compressed(bytes)?))
            }

            #[doc = concat!("The ", stringify!($sig_len), "-byte compressed encoding.")]
            pub fn to_bytes(&self) -> [u8; $sig_len] {
                self.0.to_compressed()
            }

            /// The underlying point.
            pub fn point(&self) -> &$Sig {
                &self.0
            }
        }

        /// `AggregateVerify` (§3.1.1 / §3.2.1 / §3.3.1): checks an aggregate
        /// signature over `(pks[i], msgs[i])` pairs.
        ///
        /// Fails on zero signers, on mismatched slice lengths, and — for
        /// [`Scheme::Basic`] — on repeated messages (checked by pairwise
        /// comparison, `O(n²)` on public data, so no allocator is needed).
        /// The public keys were validated when they were built. Each message
        /// is hashed and fed to a streaming pairing product as it comes, so
        /// any number of signers verifies in fixed stack space with one
        /// final exponentiation.
        ///
        /// With [`Scheme::ProofOfPossession`] this is only sound when each
        /// public key's proof of possession has been checked with
        /// [`PublicKey::pop_verify`]: that scheme neither requires distinct
        /// messages nor binds the key into the hashed message, so an
        /// unchecked rogue key (`pk' = x·g − pk_victim`) lets an attacker
        /// forge an aggregate that appears to include the victim's
        /// signature.
        pub fn aggregate_verify(
            scheme: Scheme,
            pks: &[PublicKey],
            msgs: &[&[u8]],
            sig: &Signature,
        ) -> Result<(), Error> {
            if pks.is_empty() {
                return Err(Error::EmptyAggregate);
            }
            if pks.len() != msgs.len() {
                return Err(Error::LengthMismatch);
            }
            if scheme == Scheme::Basic {
                for (i, a) in msgs.iter().enumerate() {
                    if msgs[..i].iter().any(|b| b == a) {
                        return Err(Error::DuplicateMessage);
                    }
                }
            }
            let mut acc = PairingAccumulator::new();
            for (pk, msg) in pks.iter().zip(msgs) {
                push_key(&mut acc, &pk.0, &hash_message(scheme, pk, msg));
            }
            push_sig(&mut acc, &sig.0);
            if bool::from(acc.finish().is_identity()) {
                Ok(())
            } else {
                Err(Error::InvalidSignature)
            }
        }

        /// `FastAggregateVerify` (§3.3.4) of the Proof of Possession scheme:
        /// one message signed by every key in `pks`. Only sound when each
        /// public key's proof of possession has been checked with
        /// [`PublicKey::pop_verify`].
        pub fn fast_aggregate_verify(
            pks: &[PublicKey],
            msg: &[u8],
            sig: &Signature,
        ) -> Result<(), Error> {
            let mut agg = pks.first().ok_or(Error::EmptyAggregate)?.0;
            for pk in &pks[1..] {
                agg = agg.add(&pk.0);
            }
            // CoreVerify's KeyValidate on the aggregate key.
            if bool::from(agg.is_identity()) {
                return Err(Error::IdentityPoint);
            }
            core_verify(&agg, &hash_parts(&[msg], DST_POP), &sig.0)
        }
    };
}
pub(crate) use bls_signature;

/// The shared test suite of one [`bls_signature!`] instantiation: KATs
/// from `tools/pairing-interop/bls-sig/` (KeyGen from a stdlib Python
/// implementation of the draft, keys and signatures from gnark-crypto's
/// scalar multiplication and hash-to-curve) plus the scheme's properties.
/// Allocator-free, so it runs in the leanest feature set.
#[cfg(test)]
macro_rules! bls_signature_tests {
    (curve: $curve:literal, variant: $variant:literal, pk_len: $pk_len:literal, sig_len: $sig_len:literal $(,)?) => {
        #[cfg(test)]
        mod tests {
            use super::*;

            const VECTORS: &str =
                include_str!("../../tools/pairing-interop/bls-sig/vectors/gnark.jsonl");

            /// The string value of `"key":"…"` in a one-line flat JSON object.
            fn field<'a>(line: &'a str, key: &str) -> &'a str {
                let mut it = line.split('"');
                while let Some(tok) = it.next() {
                    if tok == key {
                        // Skip the `:` separator, then take the value.
                        let _ = it.next();
                        return it.next().unwrap_or("");
                    }
                }
                panic!("no {key} in {line}")
            }

            fn hex_into<'b>(s: &str, buf: &'b mut [u8]) -> &'b [u8] {
                let b = s.as_bytes();
                assert_eq!(b.len() % 2, 0);
                for (i, pair) in b.chunks_exact(2).enumerate() {
                    let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
                    let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
                    buf[i] = (hi << 4) | lo;
                }
                &buf[..b.len() / 2]
            }

            fn records() -> impl Iterator<Item = &'static str> {
                VECTORS
                    .lines()
                    .filter(|l| field(l, "curve") == $curve && field(l, "variant") == $variant)
            }

            fn sk(i: u8) -> SecretKey {
                SecretKey::generate(&[i; 32], b"test").unwrap()
            }

            const ALL: [Scheme; 3] = [
                Scheme::Basic,
                Scheme::MessageAugmentation,
                Scheme::ProofOfPossession,
            ];

            #[test]
            fn interop_vectors() {
                let mut n = 0;
                for l in records() {
                    let (mut b1, mut b2, mut b3) = ([0u8; 512], [0u8; 64], [0u8; 512]);
                    let ikm = hex_into(field(l, "ikm"), &mut b1);
                    let info = hex_into(field(l, "key_info"), &mut b2);
                    let key = SecretKey::generate(ikm, info).unwrap();
                    assert_eq!(hex_into(field(l, "sk"), &mut b3), key.to_bytes(), "KeyGen");
                    let pk = key.public_key();
                    assert_eq!(hex_into(field(l, "pk"), &mut b3), pk.to_bytes(), "SkToPk");
                    assert_eq!(PublicKey::from_bytes(&pk.to_bytes()).unwrap(), pk);
                    let pop = key.pop_prove();
                    assert_eq!(
                        hex_into(field(l, "pop"), &mut b3),
                        pop.to_bytes(),
                        "PopProve"
                    );
                    pk.pop_verify(&pop).unwrap();
                    let msg = hex_into(field(l, "msg"), &mut b1);
                    for (scheme, k) in ALL.into_iter().zip(["basic", "aug", "pop_sig"]) {
                        let sig = key.sign(scheme, msg);
                        let want = hex_into(field(l, k), &mut b3);
                        assert_eq!(want, sig.to_bytes(), "{k}");
                        let parsed = Signature::from_bytes(want).unwrap();
                        pk.verify(scheme, msg, &parsed).unwrap();
                    }
                    n += 1;
                }
                // 6 keys × 5 messages per curve and variant.
                assert_eq!(n, 30);
            }

            #[test]
            fn ciphersuite_ids() {
                for d in [DST_BASIC, DST_AUG, DST_POP, DST_POP_PROOF] {
                    assert!(d.starts_with(b"BLS_") && d.ends_with(b"_"));
                }
                assert!(DST_BASIC.ends_with(b"_RO_NUL_") && DST_POP_PROOF.starts_with(b"BLS_POP_"));
                assert_ne!(DST_POP, DST_POP_PROOF);
            }

            #[test]
            fn sign_verify_all_schemes() {
                let (a, b) = (sk(1), sk(2));
                for scheme in ALL {
                    let sig = a.sign(scheme, b"message");
                    a.public_key().verify(scheme, b"message", &sig).unwrap();
                    assert_eq!(
                        a.public_key().verify(scheme, b"messagf", &sig),
                        Err(Error::InvalidSignature)
                    );
                    assert_eq!(
                        b.public_key().verify(scheme, b"message", &sig),
                        Err(Error::InvalidSignature)
                    );
                    // Ciphersuites are separated: a signature under one scheme
                    // never verifies under another.
                    for other in ALL {
                        if other != scheme {
                            assert!(a.public_key().verify(other, b"message", &sig).is_err());
                        }
                    }
                    let u = Signature::from_uncompressed(&sig.to_uncompressed()).unwrap();
                    assert_eq!(u, sig);
                }
                let pk = a.public_key();
                assert_eq!(
                    PublicKey::from_uncompressed(&pk.to_uncompressed()).unwrap(),
                    pk
                );
            }

            #[test]
            fn aggregation() {
                // Ten signers: more than one stack chunk of the pairing product.
                let keys: [SecretKey; 10] = core::array::from_fn(|i| sk(10 + i as u8));
                let pks: [PublicKey; 10] = core::array::from_fn(|i| keys[i].public_key());
                let bufs: [[u8; 5]; 10] =
                    core::array::from_fn(|i| [b'm', b's', b'g', b'-', b'0' + i as u8]);
                let msgs: [&[u8]; 10] = core::array::from_fn(|i| &bufs[i][..]);
                for scheme in ALL {
                    let sigs: [Signature; 10] =
                        core::array::from_fn(|i| keys[i].sign(scheme, msgs[i]));
                    let agg = Signature::aggregate(&sigs).unwrap();
                    aggregate_verify(scheme, &pks, &msgs, &agg).unwrap();
                    // A swapped message, a missing signer, mismatched lengths.
                    let mut swapped = msgs;
                    swapped.swap(0, 1);
                    assert_eq!(
                        aggregate_verify(scheme, &pks, &swapped, &agg),
                        Err(Error::InvalidSignature)
                    );
                    let partial = Signature::aggregate(&sigs[1..]).unwrap();
                    assert_eq!(
                        aggregate_verify(scheme, &pks, &msgs, &partial),
                        Err(Error::InvalidSignature)
                    );
                    assert_eq!(
                        aggregate_verify(scheme, &pks[..9], &msgs, &agg),
                        Err(Error::LengthMismatch)
                    );
                    assert_eq!(
                        aggregate_verify(scheme, &[], &[], &agg),
                        Err(Error::EmptyAggregate)
                    );
                }
                assert!(matches!(
                    Signature::aggregate(&[]),
                    Err(Error::EmptyAggregate)
                ));

                // Repeated messages: Basic refuses them, Augmentation allows them.
                let same: [&[u8]; 3] = [b"same", b"same", b"same"];
                let basic: [Signature; 3] =
                    core::array::from_fn(|i| keys[i].sign(Scheme::Basic, same[i]));
                let agg = Signature::aggregate(&basic).unwrap();
                assert_eq!(
                    aggregate_verify(Scheme::Basic, &pks[..3], &same, &agg),
                    Err(Error::DuplicateMessage)
                );
                let aug: [Signature; 3] =
                    core::array::from_fn(|i| keys[i].sign(Scheme::MessageAugmentation, same[i]));
                let agg = Signature::aggregate(&aug).unwrap();
                aggregate_verify(Scheme::MessageAugmentation, &pks[..3], &same, &agg).unwrap();
            }

            #[test]
            fn proof_of_possession_and_rogue_keys() {
                let keys: [SecretKey; 4] = core::array::from_fn(|i| sk(40 + i as u8));
                let pks: [PublicKey; 4] = core::array::from_fn(|i| keys[i].public_key());
                for (k, pk) in keys.iter().zip(&pks) {
                    pk.pop_verify(&k.pop_prove()).unwrap();
                }
                // A proof does not transfer to another key.
                assert_eq!(
                    pks[1].pop_verify(&keys[0].pop_prove()),
                    Err(Error::InvalidSignature)
                );
                let sigs: [Signature; 4] = core::array::from_fn(|i| {
                    keys[i].sign(Scheme::ProofOfPossession, b"one message")
                });
                let agg = Signature::aggregate(&sigs).unwrap();
                fast_aggregate_verify(&pks, b"one message", &agg).unwrap();
                assert_eq!(
                    fast_aggregate_verify(&pks, b"another message", &agg),
                    Err(Error::InvalidSignature)
                );
                assert_eq!(
                    fast_aggregate_verify(&pks[..3], b"one message", &agg),
                    Err(Error::InvalidSignature)
                );
                assert_eq!(
                    fast_aggregate_verify(&[], b"one message", &agg),
                    Err(Error::EmptyAggregate)
                );

                // The rogue-key attack proofs of possession exist to stop: the
                // attacker publishes pk_r = a·G − pk_victim, so the aggregate
                // key is a·G and the forgery a·H(m) passes
                // FastAggregateVerify — but pk_r has no valid proof.
                let attacker = sk(99);
                let rogue = PublicKey::from_point(*attacker.public_key().point() - *pks[0].point())
                    .unwrap();
                let forged = attacker.sign(Scheme::ProofOfPossession, b"forged");
                fast_aggregate_verify(&[pks[0], rogue], b"forged", &forged).unwrap();
                assert_eq!(
                    rogue.pop_verify(&attacker.pop_prove()),
                    Err(Error::InvalidSignature)
                );
                // Keys summing to the identity are rejected outright.
                let neg = PublicKey::from_point(-*pks[0].point()).unwrap();
                assert_eq!(
                    fast_aggregate_verify(&[pks[0], neg], b"x", &agg),
                    Err(Error::IdentityPoint)
                );
            }

            #[test]
            fn key_and_encoding_validation() {
                assert!(matches!(
                    SecretKey::generate(&[0u8; 31], b""),
                    Err(Error::InsufficientKeyMaterial)
                ));
                assert!(matches!(
                    SecretKey::from_bytes(&[0u8; 32]),
                    Err(Error::InvalidScalar)
                ));
                assert!(matches!(
                    SecretKey::from_bytes(&[0xffu8; 32]),
                    Err(Error::InvalidScalar)
                ));
                assert!(matches!(
                    SecretKey::from_scalar(Fr::ZERO),
                    Err(Error::InvalidScalar)
                ));
                let k = sk(7);
                let k2 = SecretKey::from_bytes(&k.to_bytes()).unwrap();
                assert_eq!(k2.public_key(), k.public_key());
                assert_eq!(
                    SecretKey::from_scalar(*k.scalar()).unwrap().to_bytes(),
                    k.to_bytes()
                );
                // Debug never prints the scalar.
                let mut buf = [0u8; 64];
                let mut w = $crate::pairing_common::bls_sig::tests_support::Buf::new(&mut buf);
                core::fmt::Write::write_fmt(&mut w, format_args!("{:?}", k)).unwrap();
                assert_eq!(w.as_str(), "SecretKey(..)");

                // The identity is never a public key.
                let ident = *k.public_key().point() - *k.public_key().point();
                assert_eq!(PublicKey::from_point(ident), Err(Error::IdentityPoint));
                assert_eq!(
                    PublicKey::from_bytes(&ident.to_compressed()),
                    Err(Error::IdentityPoint)
                );

                // Malformed encodings.
                let pk = k.public_key().to_bytes();
                assert_eq!(
                    PublicKey::from_bytes(&pk[..$pk_len - 1]),
                    Err(Error::InvalidLength)
                );
                let sig = k.sign(Scheme::Basic, b"m").to_bytes();
                assert_eq!(
                    Signature::from_bytes(&sig[..$sig_len - 1]),
                    Err(Error::InvalidLength)
                );
                assert!(ProofOfPossession::from_bytes(&sig[1..]).is_err());
                // A corrupted byte either fails to decode or no longer verifies.
                let mut bad = sig;
                bad[$sig_len - 1] ^= 1;
                if let Ok(s) = Signature::from_bytes(&bad) {
                    assert!(k.public_key().verify(Scheme::Basic, b"m", &s).is_err());
                }
                let mut badpk = pk;
                badpk[$pk_len - 1] ^= 1;
                if let Ok(p) = PublicKey::from_bytes(&badpk) {
                    assert!(
                        p.verify(Scheme::Basic, b"m", &Signature::from_bytes(&sig).unwrap())
                            .is_err()
                    );
                }
                // A non-canonical x coordinate (all ones under the flag bits,
                // `>= p` on both curves) is rejected.
                let mut big = [0xffu8; $sig_len];
                big[0] = 0xbf;
                assert!(Signature::from_bytes(&big).is_err());
            }
        }
    };
}
#[cfg(test)]
pub(crate) use bls_signature_tests;

/// Allocator-free helpers for the generated tests.
#[cfg(test)]
pub(crate) mod tests_support {
    /// A `core::fmt::Write` sink over a fixed buffer.
    pub(crate) struct Buf<'a> {
        buf: &'a mut [u8],
        len: usize,
    }

    impl<'a> Buf<'a> {
        pub(crate) fn new(buf: &'a mut [u8]) -> Self {
            Buf { buf, len: 0 }
        }

        pub(crate) fn as_str(&self) -> &str {
            core::str::from_utf8(&self.buf[..self.len]).unwrap()
        }
    }

    impl core::fmt::Write for Buf<'_> {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let end = self.len + s.len();
            if end > self.buf.len() {
                return Err(core::fmt::Error);
            }
            self.buf[self.len..end].copy_from_slice(s.as_bytes());
            self.len = end;
            Ok(())
        }
    }
}
