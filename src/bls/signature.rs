//! The BLS signature scheme (`draft-irtf-cfrg-bls-signature-05`),
//! minimal-pubkey-size variant: public keys in `G1` (48 bytes), signatures
//! in `G2` (96 bytes), hashing to `G2` with
//! `BLS12381G2_XMD:SHA-256_SSWU_RO_`.
//!
//! The three schemes of the draft share `KeyGen`, `SkToPk`, `CoreSign`,
//! `CoreVerify` and `Aggregate`, and differ in the domain separation tag
//! and in how aggregates are checked:
//!
//! * [`Scheme::Basic`] — `AggregateVerify` requires distinct messages.
//! * [`Scheme::MessageAugmentation`] — every message is prefixed with the
//!   signer's public key before hashing.
//! * [`Scheme::ProofOfPossession`] — signers publish a proof of possession
//!   ([`SecretKey::pop_prove`] / [`PublicKey::pop_verify`]), which makes
//!   [`fast_aggregate_verify`] (one message, many signers) safe.
//!
//! `KeyValidate` (subgroup membership and non-identity) is applied by
//! [`PublicKey::from_bytes`], so every `PublicKey` value is valid.
//! Signatures are subgroup-checked on decoding, as `CoreVerify` requires.

use super::Error;
use super::fr::Fr;
use super::g1::G1;
use super::g2::G2;
use super::hash_to_curve::hash_to_g2;
use super::pairing::multi_pairing;
use crate::hash::{Digest, Hmac, Sha256};
use crate::rng::{CryptoRng, RngCore};
use crate::zeroize::Zeroize;
use alloc::vec::Vec;

/// Ciphersuite ID of the Basic scheme.
pub const DST_BASIC: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
/// Ciphersuite ID of the Message Augmentation scheme.
pub const DST_AUG: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_";
/// Ciphersuite ID of the Proof of Possession scheme (signatures).
pub const DST_POP: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
/// Domain separation tag of the proofs of possession themselves.
pub const DST_POP_PROOF: &[u8] = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

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

/// A BLS secret key: a nonzero scalar in `Fr`. Wiped on drop.
pub struct SecretKey(Fr);

/// A BLS public key: a non-identity point of `G1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey(G1);

/// A BLS signature: a point of `G2`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature(G2);

/// A proof of possession for the Proof of Possession scheme (§3.3): a
/// signature over the public key itself under [`DST_POP_PROOF`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofOfPossession(G2);

/// `KeyGen` output length `L = ceil((3·ceil(log2(r)))/16) = 48`.
const KEYGEN_L: usize = 48;

impl SecretKey {
    /// `KeyGen(IKM, key_info)` (§2.3): derives a key from at least 32 bytes
    /// of input keying material with the HKDF-based loop of the draft
    /// (`salt = H(salt)`, `PRK = HKDF-Extract(salt, IKM || 0x00)`,
    /// `OKM = HKDF-Expand(PRK, key_info || I2OSP(L, 2), L)`,
    /// `SK = OS2IP(OKM) mod r`, repeated while `SK = 0`).
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
            let prk = h.finalize();
            // HKDF-Expand(PRK, key_info || I2OSP(L, 2), L): two blocks.
            let mut okm = [0u8; KEYGEN_L];
            let mut t1 = Hmac::<Sha256>::new(&prk);
            t1.update(key_info);
            t1.update(&[0u8, KEYGEN_L as u8]);
            t1.update(&[1u8]);
            let t1 = t1.finalize();
            let mut t2 = Hmac::<Sha256>::new(&prk);
            t2.update(&t1);
            t2.update(key_info);
            t2.update(&[0u8, KEYGEN_L as u8]);
            t2.update(&[2u8]);
            let t2 = t2.finalize();
            okm[..32].copy_from_slice(&t1);
            okm[32..].copy_from_slice(&t2[..16]);
            let sk = Fr::from_bytes_wide(&okm);
            okm.zeroize();
            if !bool::from(sk.is_zero()) {
                return Ok(SecretKey(sk));
            }
            // Negligible: only when OKM ≡ 0 (mod r). Re-salt and retry.
            salt = Sha256::digest(&salt);
        }
    }

    /// Generates a key from 32 bytes of randomness drawn from `rng`.
    pub fn random<R: RngCore + CryptoRng>(rng: &mut R) -> SecretKey {
        let mut ikm = [0u8; 32];
        rng.fill_bytes(&mut ikm);
        // 32 bytes of IKM never trips the length check.
        let sk = SecretKey::generate(&ikm, b"").expect("32-byte IKM");
        ikm.zeroize();
        sk
    }

    /// Loads a key from its 32-byte big-endian encoding; the scalar must be
    /// canonical (`< r`) and nonzero.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<SecretKey, Error> {
        let sk = Fr::from_bytes(bytes).ok_or(Error::InvalidScalar)?;
        if bool::from(sk.is_zero()) {
            return Err(Error::InvalidScalar);
        }
        Ok(SecretKey(sk))
    }

    /// Wraps a nonzero scalar.
    pub fn from_scalar(sk: Fr) -> Result<SecretKey, Error> {
        if bool::from(sk.is_zero()) {
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

    /// `SkToPk`: the public key `sk·G1`.
    pub fn public_key(&self) -> PublicKey {
        PublicKey(G1::generator().mul(&self.0))
    }

    /// `CoreSign` with the scheme's DST (and, for Message Augmentation, the
    /// public key prepended to the message): `sk·H(msg)`.
    pub fn sign(&self, scheme: Scheme, msg: &[u8]) -> Signature {
        let h = match scheme {
            Scheme::MessageAugmentation => {
                let augmented = augment(&self.public_key(), msg);
                hash_to_g2(&augmented, DST_AUG)
            }
            _ => hash_to_g2(msg, scheme.dst()),
        };
        Signature(h.mul(&self.0))
    }

    /// `PopProve` (§3.3.2): a signature over the public key under
    /// [`DST_POP_PROOF`].
    pub fn pop_prove(&self) -> ProofOfPossession {
        let pk = self.public_key().to_bytes();
        ProofOfPossession(hash_to_g2(&pk, DST_POP_PROOF).mul(&self.0))
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl crate::zeroize::ZeroizeOnDrop for SecretKey {}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// `pk || msg` for the Message Augmentation scheme.
fn augment(pk: &PublicKey, msg: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(48 + msg.len());
    v.extend_from_slice(&pk.to_bytes());
    v.extend_from_slice(msg);
    v
}

/// `CoreVerify` given the already-hashed message point:
/// `e(pk, H) = e(G1, sig)`, evaluated as `e(pk, H)·e(-G1, sig) = 1`.
fn core_verify(pk: &G1, h: &G2, sig: &G2) -> Result<(), Error> {
    let neg_g = -G1::generator();
    if bool::from(multi_pairing(&[(pk, h), (&neg_g, sig)]).is_identity()) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

impl PublicKey {
    /// `KeyValidate` on a 48-byte compressed `G1` encoding: decodes with
    /// the full curve and subgroup checks and rejects the identity.
    pub fn from_bytes(bytes: &[u8]) -> Result<PublicKey, Error> {
        Self::from_point(G1::from_compressed(bytes)?)
    }

    /// Wraps a `G1` point, rejecting the identity.
    pub fn from_point(p: G1) -> Result<PublicKey, Error> {
        if bool::from(p.is_identity()) {
            return Err(Error::IdentityPoint);
        }
        Ok(PublicKey(p))
    }

    /// The 48-byte compressed encoding.
    pub fn to_bytes(&self) -> [u8; 48] {
        self.0.to_compressed()
    }

    /// The underlying point.
    pub fn point(&self) -> &G1 {
        &self.0
    }

    /// `Verify(PK, message, signature)` for the given scheme.
    pub fn verify(&self, scheme: Scheme, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        let h = match scheme {
            Scheme::MessageAugmentation => hash_to_g2(&augment(self, msg), DST_AUG),
            _ => hash_to_g2(msg, scheme.dst()),
        };
        core_verify(&self.0, &h, &sig.0)
    }

    /// `PopVerify` (§3.3.3).
    pub fn pop_verify(&self, proof: &ProofOfPossession) -> Result<(), Error> {
        let h = hash_to_g2(&self.to_bytes(), DST_POP_PROOF);
        core_verify(&self.0, &h, &proof.0)
    }
}

impl Signature {
    /// Decodes a 96-byte compressed `G2` encoding with the curve and
    /// subgroup checks (`signature_subgroup_check`).
    pub fn from_bytes(bytes: &[u8]) -> Result<Signature, Error> {
        Ok(Signature(G2::from_compressed(bytes)?))
    }

    /// Wraps a `G2` point.
    pub fn from_point(p: G2) -> Signature {
        Signature(p)
    }

    /// The 96-byte compressed encoding.
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_compressed()
    }

    /// The underlying point.
    pub fn point(&self) -> &G2 {
        &self.0
    }

    /// `Aggregate` (§2.8): the sum of the signatures; fails on an empty
    /// input.
    pub fn aggregate(sigs: &[Signature]) -> Result<Signature, Error> {
        let mut acc = *sigs.first().ok_or(Error::EmptyAggregate)?;
        for s in &sigs[1..] {
            acc.0 += s.0;
        }
        Ok(acc)
    }
}

impl ProofOfPossession {
    /// Decodes a 96-byte compressed `G2` encoding with full validation.
    pub fn from_bytes(bytes: &[u8]) -> Result<ProofOfPossession, Error> {
        Ok(ProofOfPossession(G2::from_compressed(bytes)?))
    }

    /// The 96-byte compressed encoding.
    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_compressed()
    }

    /// The underlying point.
    pub fn point(&self) -> &G2 {
        &self.0
    }
}

/// `AggregateVerify` (§3.1.1 / §3.2.1 / §3.3.1): checks an aggregate
/// signature over `(pks[i], msgs[i])` pairs.
///
/// Fails on zero signers, on mismatched slice lengths, and — for
/// [`Scheme::Basic`] — on repeated messages. The public keys were validated
/// when they were built; the check is
/// `∏ e(pk_i, H(msg_i)) · e(-G1, sig) = 1` with one final exponentiation.
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
    let hashes: Vec<G2> = pks
        .iter()
        .zip(msgs)
        .map(|(pk, msg)| match scheme {
            Scheme::MessageAugmentation => hash_to_g2(&augment(pk, msg), DST_AUG),
            _ => hash_to_g2(msg, scheme.dst()),
        })
        .collect();
    let neg_g = -G1::generator();
    let mut pairs: Vec<(&G1, &G2)> = pks.iter().map(|pk| &pk.0).zip(hashes.iter()).collect();
    pairs.push((&neg_g, &sig.0));
    if bool::from(multi_pairing(&pairs).is_identity()) {
        Ok(())
    } else {
        Err(Error::InvalidSignature)
    }
}

/// `FastAggregateVerify` (§3.3.4) of the Proof of Possession scheme: one
/// message signed by every key in `pks`. Only sound when each public key's
/// proof of possession has been checked with [`PublicKey::pop_verify`].
pub fn fast_aggregate_verify(pks: &[PublicKey], msg: &[u8], sig: &Signature) -> Result<(), Error> {
    let mut agg = pks.first().ok_or(Error::EmptyAggregate)?.0;
    for pk in &pks[1..] {
        agg += pk.0;
    }
    // CoreVerify's KeyValidate on the aggregate key.
    if bool::from(agg.is_identity()) {
        return Err(Error::IdentityPoint);
    }
    core_verify(&agg, &hash_to_g2(msg, DST_POP), &sig.0)
}

#[cfg(test)]
mod tests {
    use super::super::eth_vectors as eth;
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn keygen_sign_verify_all_schemes() {
        let sk = SecretKey::generate(b"0123456789abcdef0123456789abcdef", b"info").unwrap();
        assert_eq!(
            SecretKey::generate(b"too short", b"").err(),
            Some(Error::InsufficientKeyMaterial)
        );
        let sk2 = SecretKey::from_bytes(&sk.to_bytes()).unwrap();
        assert_eq!(sk.to_bytes(), sk2.to_bytes());
        assert_eq!(
            SecretKey::from_bytes(&[0u8; 32]).err(),
            Some(Error::InvalidScalar)
        );
        assert_eq!(
            SecretKey::from_bytes(&[0xffu8; 32]).err(),
            Some(Error::InvalidScalar)
        );
        let pk = sk.public_key();
        assert_eq!(PublicKey::from_bytes(&pk.to_bytes()).unwrap(), pk);
        for scheme in [
            Scheme::Basic,
            Scheme::MessageAugmentation,
            Scheme::ProofOfPossession,
        ] {
            let sig = sk.sign(scheme, b"hello");
            assert_eq!(Signature::from_bytes(&sig.to_bytes()).unwrap(), sig);
            pk.verify(scheme, b"hello", &sig).unwrap();
            assert_eq!(
                pk.verify(scheme, b"hellp", &sig),
                Err(Error::InvalidSignature)
            );
            assert_eq!(sk2.public_key().verify(scheme, b"hello", &sig), Ok(()));
            let other = SecretKey::generate(b"fedcba9876543210fedcba9876543210", b"").unwrap();
            assert_eq!(
                other.public_key().verify(scheme, b"hello", &sig),
                Err(Error::InvalidSignature)
            );
            // Cross-scheme signatures do not verify.
            for other_scheme in [
                Scheme::Basic,
                Scheme::MessageAugmentation,
                Scheme::ProofOfPossession,
            ] {
                if other_scheme != scheme {
                    assert!(pk.verify(other_scheme, b"hello", &sig).is_err());
                }
            }
        }
        // Proof of possession.
        let pop = sk.pop_prove();
        pk.pop_verify(&pop).unwrap();
        assert_eq!(ProofOfPossession::from_bytes(&pop.to_bytes()).unwrap(), pop);
        let sk3 = SecretKey::generate(b"another thirty-two byte ikm value!", b"").unwrap();
        assert!(sk3.public_key().pop_verify(&pop).is_err());
        // Identity public key is rejected.
        let mut inf = [0u8; 48];
        inf[0] = 0xc0;
        assert_eq!(PublicKey::from_bytes(&inf), Err(Error::IdentityPoint));
        assert_eq!(
            PublicKey::from_point(G1::IDENTITY),
            Err(Error::IdentityPoint)
        );
    }

    #[test]
    fn aggregation() {
        let sks: Vec<SecretKey> = (0u8..3)
            .map(|i| SecretKey::generate(&[i; 32], b"").unwrap())
            .collect();
        let pks: Vec<PublicKey> = sks.iter().map(|s| s.public_key()).collect();
        let msgs: [&[u8]; 3] = [b"m0", b"m1", b"m2"];
        for scheme in [
            Scheme::Basic,
            Scheme::MessageAugmentation,
            Scheme::ProofOfPossession,
        ] {
            let sigs: Vec<Signature> = sks
                .iter()
                .zip(msgs)
                .map(|(s, m)| s.sign(scheme, m))
                .collect();
            let agg = Signature::aggregate(&sigs).unwrap();
            aggregate_verify(scheme, &pks, &msgs, &agg).unwrap();
            assert_eq!(
                aggregate_verify(scheme, &pks, &[b"m0", b"m1", b"mX"], &agg),
                Err(Error::InvalidSignature)
            );
            assert_eq!(
                aggregate_verify(scheme, &pks, &msgs[..2], &agg),
                Err(Error::LengthMismatch)
            );
            assert_eq!(
                aggregate_verify(scheme, &[], &[], &agg),
                Err(Error::EmptyAggregate)
            );
            // Same message from every signer.
            let same: Vec<Signature> = sks.iter().map(|s| s.sign(scheme, b"same")).collect();
            let agg_same = Signature::aggregate(&same).unwrap();
            let r = aggregate_verify(scheme, &pks, &[b"same", b"same", b"same"], &agg_same);
            if scheme == Scheme::Basic {
                assert_eq!(r, Err(Error::DuplicateMessage));
            } else {
                r.unwrap();
            }
            if scheme == Scheme::ProofOfPossession {
                fast_aggregate_verify(&pks, b"same", &agg_same).unwrap();
                assert_eq!(
                    fast_aggregate_verify(&pks, b"other", &agg_same),
                    Err(Error::InvalidSignature)
                );
                assert_eq!(
                    fast_aggregate_verify(&pks[..2], b"same", &agg_same),
                    Err(Error::InvalidSignature)
                );
                assert_eq!(
                    fast_aggregate_verify(&[], b"same", &agg_same),
                    Err(Error::EmptyAggregate)
                );
            }
        }
        assert_eq!(Signature::aggregate(&[]), Err(Error::EmptyAggregate));
    }

    #[test]
    fn random_keys_differ() {
        let mut rng = crate::rng::HmacDrbg::<Sha256>::new(b"seed for the bls test", b"", b"");
        let a = SecretKey::random(&mut rng);
        let b = SecretKey::random(&mut rng);
        assert_ne!(a.to_bytes(), b.to_bytes());
        let sig = a.sign(Scheme::Basic, b"x");
        a.public_key().verify(Scheme::Basic, b"x", &sig).unwrap();
    }

    // ---- Ethereum 2.0 BLS test vectors (github.com/ethereum/bls12-381-tests v0.1.2),
    // which use the Proof of Possession ciphersuite DST.

    #[test]
    fn eth_sign() {
        for c in eth::SIGN {
            let sk = unhex(c.privkey);
            let sk: [u8; 32] = sk.try_into().unwrap();
            let msg = unhex(c.message);
            match (SecretKey::from_bytes(&sk), c.output) {
                (Ok(sk), Some(expected)) => {
                    let sig = sk.sign(Scheme::ProofOfPossession, &msg);
                    assert_eq!(sig.to_bytes().to_vec(), unhex(expected), "{}", c.name);
                }
                (Err(_), None) => {}
                (r, e) => panic!("{}: got {:?}, expected {:?}", c.name, r.map(|_| ()), e),
            }
        }
    }

    #[test]
    fn eth_verify() {
        for c in eth::VERIFY {
            let ok = (|| {
                let pk = PublicKey::from_bytes(&unhex(c.pubkey))?;
                let sig = Signature::from_bytes(&unhex(c.signature))?;
                pk.verify(Scheme::ProofOfPossession, &unhex(c.message), &sig)
            })()
            .is_ok();
            assert_eq!(ok, c.output, "{}", c.name);
        }
    }

    #[test]
    fn eth_aggregate() {
        for c in eth::AGGREGATE {
            let sigs: Result<Vec<Signature>, Error> = c
                .input
                .iter()
                .map(|s| Signature::from_bytes(&unhex(s)))
                .collect();
            let got = sigs.and_then(|s| Signature::aggregate(&s));
            match (got, c.output) {
                (Ok(agg), Some(expected)) => {
                    assert_eq!(agg.to_bytes().to_vec(), unhex(expected), "{}", c.name)
                }
                (Err(_), None) => {}
                (r, e) => panic!("{}: got {:?}, expected {:?}", c.name, r.map(|_| ()), e),
            }
        }
    }

    #[test]
    fn eth_aggregate_verify() {
        for c in eth::AGGREGATE_VERIFY {
            let ok = (|| {
                let pks: Result<Vec<PublicKey>, Error> = c
                    .pubkeys
                    .iter()
                    .map(|s| PublicKey::from_bytes(&unhex(s)))
                    .collect();
                let msgs: Vec<Vec<u8>> = c.messages.iter().map(|m| unhex(m)).collect();
                let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
                let sig = Signature::from_bytes(&unhex(c.signature))?;
                aggregate_verify(Scheme::ProofOfPossession, &pks?, &msg_refs, &sig)
            })()
            .is_ok();
            assert_eq!(ok, c.output, "{}", c.name);
        }
    }

    #[test]
    fn eth_fast_aggregate_verify() {
        for c in eth::FAST_AGGREGATE_VERIFY {
            let ok = (|| {
                let pks: Result<Vec<PublicKey>, Error> = c
                    .pubkeys
                    .iter()
                    .map(|s| PublicKey::from_bytes(&unhex(s)))
                    .collect();
                let sig = Signature::from_bytes(&unhex(c.signature))?;
                fast_aggregate_verify(&pks?, &unhex(c.message), &sig)
            })()
            .is_ok();
            assert_eq!(ok, c.output, "{}", c.name);
        }
    }

    #[test]
    fn eth_deserialization() {
        for c in eth::DESERIALIZATION_G1 {
            // The suite's notion of a valid public key: decodes, in the
            // subgroup; the identity is allowed here (KeyValidate is separate).
            let ok = G1::from_compressed(&unhex(c.input)).is_ok();
            assert_eq!(ok, c.output, "G1 {}", c.name);
        }
        for c in eth::DESERIALIZATION_G2 {
            let ok = G2::from_compressed(&unhex(c.input)).is_ok();
            assert_eq!(ok, c.output, "G2 {}", c.name);
        }
    }

    #[test]
    fn eth_hash_to_g2() {
        use super::super::fp::Fp;
        use super::super::fp2::Fp2;
        let fp = |s: &str| {
            let mut b = [0u8; 48];
            b.copy_from_slice(&unhex(s));
            Fp::from_bytes(&b).unwrap()
        };
        // These are the RFC 9380 J.10.1 vectors, so they use the RFC's DST.
        let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
        for c in eth::HASH_TO_G2 {
            let p = hash_to_g2(c.msg.as_bytes(), dst);
            let (x, y) = p.to_affine().unwrap();
            assert_eq!(x, Fp2::new(fp(c.x.0), fp(c.x.1)), "{}", c.name);
            assert_eq!(y, Fp2::new(fp(c.y.0), fp(c.y.1)), "{}", c.name);
        }
    }
}
