//! Ring-signature address whitelisting (Elements/Liquid).
//!
//! **EXPERIMENTAL** — no semver-stability guarantee. See the [module-level
//! documentation](super) for the clean-room policy and interop caveats.
//!
//! # What it proves
//!
//! An Elements-style *whitelist* is a list of `n` key pairs
//! `(P_i, Q_i)` — an **online** key `P_i` and an **offline** key `Q_i` — that a
//! federation has approved. A user who wants to whitelist a fresh destination
//! key `W` proves, in zero knowledge with respect to the index `i`, that `W`
//! was derived from one of those approved pairs: the proof convinces a verifier
//! that the prover knows the discrete logarithm of
//!
//! ```text
//! K_i = P_i + H(Q_i + W) · (Q_i + W)
//! ```
//!
//! for *some* `i`, where `H` is SHA-256 of the compressed SEC1 serialization of
//! the point, interpreted as a scalar. The prover holds `p_i` (the online
//! secret) and `t_i = dlog(Q_i + W)` (the "summed" secret, i.e. the secret of
//! the whitelisted key added to the secret of the signer's offline key), so it
//! knows `k_i = p_i + H(Q_i + W)·t_i`. Since only the holder of `q_i` can
//! produce `t_i` for a `W` it controls, a valid proof means the destination is
//! controlled by the same party as one of the whitelisted offline keys — while
//! the ring signature hides *which* one.
//!
//! The witness is a one-of-many (AOS / Borromean-style) ring signature over the
//! `n` derived keys `K_i`, with a single ring.
//!
//! # Degenerate destination `W = -Q_i`
//!
//! If the destination is the negation of a whitelisted offline key, the summand
//! `Q_i + W` is the point at infinity, the tweak drops out and the ring key
//! collapses to `K_i = P_i`: the online key alone then produces a valid proof.
//! This is accepted deliberately (upstream does the same). The resulting output
//! is spendable only by the holder of `q_i` — the offline half of the very same
//! whitelist entry — so no funds can be diverted by it.
//!
//! # Construction
//!
//! Let `W` be the destination, `(P_i, Q_i)` the whitelist, and
//!
//! ```text
//! m    = SHA256( W ‖ Q_1 ‖ P_1 ‖ Q_2 ‖ P_2 ‖ … ‖ Q_n ‖ P_n )   (33-byte compressed keys)
//! K_i  = P_i + H(Q_i + W)·(Q_i + W)
//! e_0  = SHA256( e0 ‖ m ‖ BE32(0) ‖ BE32(0) )
//! R_i+1 = s_i·G + e_i·K_i
//! e_i+1 = SHA256( R_i+1 ‖ m ‖ BE32(0) ‖ BE32(i+1) )            (i+1 < n)
//! ```
//!
//! and the proof is `(e0, s_0 … s_n-1)`, accepted iff
//! `e0 == SHA256(R_n ‖ m)`. `BE32(0)` is the ring index (there is exactly one
//! ring). Signing picks a nonce `k`, sets `R_index+1 = k·G`, chooses the other
//! `s_i` at random, walks the ring forward from `index + 1`, closes it through
//! `e0`, walks on to `index`, and finally solves `s_index = k − e_index·k_i`.
//!
//! # Encoding
//!
//! [`Whitelist::to_bytes`] emits `1 + 32 + 32·n` bytes: a one-byte `n_keys`,
//! a 32-byte big-endian `e0`, then `n` 32-byte big-endian `s` values. This is
//! the encoding documented in the upstream `secp256k1_whitelist.h`, and
//! [`MAX_KEYS`] (255) is the ring-size ceiling it implies.
//! [`Whitelist::from_bytes`] rejects a length that is not exactly
//! `33 + 32·n_keys`, a zero ring, and any scalar that is zero or `>= n` (the
//! group order) — upstream guarantees such a signature fails verification, so
//! rejecting it up front is equivalent and keeps the parsed type canonical.
//!
//! # Interop
//!
//! **Byte-exact interoperability with Elements/Liquid has been established** for
//! this module, and is regression-tested against committed vectors in
//! `tools/zkp-interop/vectors/whitelist.json`.
//!
//! There is no normative specification for this construction; the format above
//! was derived from the public header `include/secp256k1_whitelist.h` (the
//! interface contract: the API shape, the ring-key relation, the tweak hash and
//! the serialized layout) plus black-box probing of a built `secp256k1-zkp`
//! through its public C API. No implementation source was read. Two facts are
//! *not* determinable from the header and were pinned by oracle probing:
//!
//! * the challenge hash structure (`SHA256(prev ‖ m ‖ BE32(ring) ‖ BE32(idx))`,
//!   the ring-closing hash `SHA256(R_n ‖ m)`, and the `R = s·G + e·K` sign
//!   convention);
//! * the byte order inside the message hash. The header's prose says the keys
//!   are committed in the order `(whitelist, online_1, offline_1, …)`, but the
//!   oracle in fact commits `(whitelist, offline_1, online_1, …)` — offline
//!   first within each pair. Rings of size ≥ 2 distinguish the two, and only
//!   the latter reproduces the oracle's signatures.
//!
//! Both directions were checked against the oracle over rings of size 1, 2, 3,
//! 5, 7 and 16, with the signer at the first, a middle and the last position:
//! every proof produced by `secp256k1_whitelist_sign` is accepted by [`verify`]
//! here, and every proof produced by [`sign`] here is accepted by
//! `secp256k1_whitelist_signature_parse` + `secp256k1_whitelist_verify`. Both
//! sets are committed as vectors (`source: "oracle"` and
//! `source: "purecrypto"`). Signatures are randomized, so the two sides do not
//! produce identical bytes for the same statement; what is byte-exact is the
//! encoding and the transcript, which is what cross-verification establishes. Two behaviours are *inferred*
//! rather than observed, because they occur with probability about `2^-128`
//! and cannot be triggered: how upstream treats a challenge hash `e` that is
//! `>= n` (we reduce it modulo `n`) and an `R` that is the point at infinity
//! (we serialize 33 zero bytes, which makes verification fail).

use alloc::vec::Vec;

use crate::ct::{ConditionallySelectable, ConstantTimeEq};
use crate::ec::Error;
use crate::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use crate::hash::{Digest, Sha256};
use crate::rng::{CryptoRng, RngCore};

/// Largest ring (number of whitelist entries) the encoding can express.
///
/// The serialized `n_keys` field is a single byte, so a proof can cover at most
/// 255 key pairs. This matches upstream's `SECP256K1_WHITELIST_MAX_N_KEYS`.
pub const MAX_KEYS: usize = 255;

/// A compressed SEC1 public key: `0x02`/`0x03` followed by the 32-byte
/// x-coordinate.
pub type CompressedPoint = [u8; 33];

/// A whitelist ring signature: the challenge seed `e0` and one `s` scalar per
/// ring member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Whitelist {
    e0: [u8; 32],
    s: Vec<[u8; 32]>,
}

impl Whitelist {
    /// The ring size this proof was made for.
    ///
    /// This is a property of the proof alone; it may disagree with the number
    /// of keys the verifier holds, in which case [`verify`] fails.
    pub fn n_keys(&self) -> usize {
        self.s.len()
    }

    /// Serialized length of a proof over `n_keys` ring members
    /// (`33 + 32·n_keys`).
    pub const fn serialized_len(n_keys: usize) -> usize {
        33 + 32 * n_keys
    }

    /// Encodes the proof as `n_keys ‖ e0 ‖ s_0 ‖ … ‖ s_n-1`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::serialized_len(self.s.len()));
        // `s.len() <= MAX_KEYS` is an invariant of every constructor.
        out.push(self.s.len() as u8);
        out.extend_from_slice(&self.e0);
        for s in &self.s {
            out.extend_from_slice(s);
        }
        out
    }

    /// Decodes a proof.
    ///
    /// # Errors
    /// [`Error::Malformed`] if the buffer is empty, if its length is not
    /// exactly `33 + 32·n_keys` for the leading `n_keys` byte, if `n_keys` is
    /// zero, or if `e0` or any `s` value is zero or not less than the group
    /// order.
    pub fn from_bytes(bytes: &[u8]) -> Result<Whitelist, Error> {
        let n = match bytes.first() {
            Some(&n) => n as usize,
            None => return Err(Error::Malformed),
        };
        // A zero-key ring can never verify (there is nothing to prove), and a
        // one-byte `n_keys` caps `n` at MAX_KEYS, so the capacity below is
        // bounded before anything is allocated.
        if n == 0 || n > MAX_KEYS || bytes.len() != Self::serialized_len(n) {
            return Err(Error::Malformed);
        }
        let mut e0 = [0u8; 32];
        e0.copy_from_slice(&bytes[1..33]);
        check_scalar(&e0)?;
        let mut s = Vec::with_capacity(n);
        for i in 0..n {
            let mut si = [0u8; 32];
            si.copy_from_slice(&bytes[33 + 32 * i..65 + 32 * i]);
            check_scalar(&si)?;
            s.push(si);
        }
        Ok(Whitelist { e0, s })
    }
}

/// Rejects a 32-byte value that is not a canonical nonzero scalar.
fn check_scalar(b: &[u8; 32]) -> Result<(), Error> {
    let s = Scalar::from_bytes_be(b).map_err(|_| Error::Malformed)?;
    if bool::from(s.is_zero()) {
        return Err(Error::Malformed);
    }
    Ok(())
}

/// Compressed serialization of a point, or 33 zero bytes for the identity.
///
/// The identity has no SEC1 encoding. It only arises here with negligible
/// probability (an `R` value that lands on infinity), and the substitute keeps
/// the transcript well defined instead of panicking; such a proof then fails
/// verification.
fn ser_point(p: &ProjectivePoint) -> CompressedPoint {
    match p.to_affine() {
        Some(a) => a.to_sec1_compressed(),
        None => [0u8; 33],
    }
}

/// `SHA256(prev ‖ m ‖ BE32(ring) ‖ BE32(idx))` — the ring challenge hash.
fn challenge(prev: &[u8], m: &[u8; 32], ring: u32, idx: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(prev);
    h.update(m);
    h.update(&ring.to_be_bytes());
    h.update(&idx.to_be_bytes());
    h.finalize()
}

/// `SHA256(R ‖ m)` — the hash that closes the ring.
fn close(r: &CompressedPoint, m: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(r);
    h.update(m);
    h.finalize()
}

/// Parses the key lists and derives the ring keys `K_i` and the message hash.
fn ring_keys(
    online_pubkeys: &[CompressedPoint],
    offline_pubkeys: &[CompressedPoint],
    sub_pubkey: &CompressedPoint,
) -> Result<(Vec<ProjectivePoint>, [u8; 32]), Error> {
    let n = online_pubkeys.len();
    if n == 0 || n > MAX_KEYS || offline_pubkeys.len() != n {
        return Err(Error::InvalidInput);
    }
    let w = AffinePoint::from_sec1(sub_pubkey)?.to_projective();
    let w_ser = ser_point(&w);

    let mut hasher = Sha256::new();
    hasher.update(&w_ser);
    let mut keys = Vec::with_capacity(n);
    for (on, off) in online_pubkeys.iter().zip(offline_pubkeys.iter()) {
        let p = AffinePoint::from_sec1(on)?.to_projective();
        let q = AffinePoint::from_sec1(off)?.to_projective();
        // Re-serialize rather than hashing the caller's bytes: `from_sec1`
        // accepts only canonical encodings, so this is the same string, but it
        // keeps the commitment tied to the parsed points.
        hasher.update(&ser_point(&q));
        hasher.update(&ser_point(&p));

        let t = q.add(&w);
        let tweak = Scalar::from_bytes_be_reduce(&Sha256::digest(&ser_point(&t)));
        // If `t` is the identity (W = -Q_i) this is `K_i = P_i`, the
        // deliberately accepted degenerate case.
        keys.push(p.add(&t.mul(&tweak)));
    }
    Ok((keys, hasher.finalize()))
}

/// Draws a uniform nonzero scalar by rejection sampling.
fn random_scalar<R: RngCore + CryptoRng>(rng: &mut R) -> Result<Scalar, Error> {
    // The rejection probability is about 2^-128 per draw; the bound only exists
    // so a broken RNG cannot spin forever.
    for _ in 0..64 {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        let candidate = Scalar::from_bytes_be(&b);
        b = [0u8; 32];
        let _ = core::hint::black_box(&b);
        if let Ok(s) = candidate
            && !bool::from(s.is_zero())
        {
            return Ok(s);
        }
    }
    Err(Error::InvalidInput)
}

/// Produces a whitelist proof for ring position `index`.
///
/// `online_seckey` is the secret of `online_pubkeys[index]`; `summed_seckey` is
/// the secret of `offline_pubkeys[index] + sub_pubkey`, i.e. the sum of the
/// signer's offline secret and the secret of the key being whitelisted. All
/// public keys are 33-byte compressed SEC1 encodings.
///
/// # Constant time
///
/// The running time and memory-access pattern are independent of `index` and of
/// both secret keys: the whole ring is walked in a fixed order and every
/// index-dependent choice is a constant-time select. The only exceptions are
/// the up-front argument checks, which fail closed and reveal nothing beyond
/// "these arguments were invalid": that `index` is in range, that the secret
/// keys are canonical and nonzero, and that they actually match the ring entry
/// at `index`.
///
/// # Errors
/// [`Error::InvalidInput`] if the key lists have different lengths, are empty
/// or longer than [`MAX_KEYS`], if a public key is not a valid curve point, if
/// `index` is out of range, if either secret key is not a canonical
/// nonzero scalar, if the secret keys do not correspond to ring position
/// `index`, or if `rng` fails to produce a usable scalar;
/// [`Error::Malformed`] if a public key has a bad length or SEC1 tag.
pub fn sign<R: RngCore + CryptoRng>(
    online_seckey: &[u8; 32],
    summed_seckey: &[u8; 32],
    online_pubkeys: &[CompressedPoint],
    offline_pubkeys: &[CompressedPoint],
    sub_pubkey: &CompressedPoint,
    index: usize,
    rng: &mut R,
) -> Result<Whitelist, Error> {
    let (keys, m) = ring_keys(online_pubkeys, offline_pubkeys, sub_pubkey)?;
    let n = keys.len();
    if index >= n {
        return Err(Error::InvalidInput);
    }

    let online = Scalar::from_bytes_be(online_seckey)?;
    let summed = Scalar::from_bytes_be(summed_seckey)?;
    if bool::from(online.is_zero()) || bool::from(summed.is_zero()) {
        return Err(Error::InvalidInput);
    }

    // The signer's ring secret: k_index = online + H(Q_index + W)·summed.
    // `Q_index + W = summed·G` is public, so recomputing it from `summed`
    // avoids a secret-indexed lookup into `offline_pubkeys`.
    let tweak = Scalar::from_bytes_be_reduce(&Sha256::digest(&ser_point(
        &ProjectivePoint::mul_generator(&summed),
    )));
    let secret = online.add(&tweak.mul(&summed));

    // Fail closed if the caller's secrets do not open the ring entry at
    // `index`; the ring key is selected without branching on `index`.
    let mut selected = ProjectivePoint::identity();
    for (i, k) in keys.iter().enumerate() {
        selected = ProjectivePoint::conditional_select(k, &selected, i.ct_eq(&index));
    }
    if !bool::from(ProjectivePoint::mul_generator(&secret).ct_eq(&selected)) {
        return Err(Error::InvalidInput);
    }

    // Random `s` for every position (the signer's own is overwritten last) and
    // the nonce `k`, whose commitment closes the ring.
    let mut s: Vec<Scalar> = Vec::with_capacity(n);
    for _ in 0..n {
        s.push(random_scalar(rng)?);
    }
    let nonce = random_scalar(rng)?;
    let nonce_commit = ser_point(&ProjectivePoint::mul_generator(&nonce));

    // Forward walk. Positions at or before `index` compute garbage that is
    // discarded when the chain is re-seeded with `nonce_commit` at
    // `index + 1`; the work is done anyway so the pattern does not depend on
    // `index`.
    let mut prev = [0u8; 33];
    for (i, (si, ki)) in s.iter().zip(keys.iter()).enumerate() {
        let seed = i.ct_eq(&index.wrapping_add(1));
        let input = <[u8; 33]>::conditional_select(&nonce_commit, &prev, seed);
        let e = Scalar::from_bytes_be_reduce(&challenge(&input, &m, 0, i as u32));
        prev = ser_point(&ProjectivePoint::mul_generator(si).add(&ki.mul(&e)));
    }
    // When the signer sits last, the chain above never got re-seeded and the
    // ring closes on the nonce commitment directly.
    let last = <[u8; 33]>::conditional_select(&nonce_commit, &prev, index.ct_eq(&(n - 1)));
    let e0 = close(&last, &m);

    // Second walk, from the top of the ring, to recover the signer's challenge.
    let mut e = challenge(&e0, &m, 0, 0);
    let mut e_signer = [0u8; 32];
    for (i, (si, ki)) in s.iter().zip(keys.iter()).enumerate() {
        e_signer = <[u8; 32]>::conditional_select(&e, &e_signer, i.ct_eq(&index));
        let es = Scalar::from_bytes_be_reduce(&e);
        let r = ser_point(&ProjectivePoint::mul_generator(si).add(&ki.mul(&es)));
        e = challenge(&r, &m, 0, (i + 1) as u32);
    }

    // s_index = nonce - e_index * secret.
    let signer_s = nonce.sub(&Scalar::from_bytes_be_reduce(&e_signer).mul(&secret));
    let mut signer_bytes = signer_s.to_bytes_be();
    let mut out = Vec::with_capacity(n);
    for (i, si) in s.iter().enumerate() {
        out.push(<[u8; 32]>::conditional_select(
            &signer_bytes,
            &si.to_bytes_be(),
            i.ct_eq(&index),
        ));
    }
    signer_bytes = [0u8; 32];
    let _ = core::hint::black_box(&signer_bytes);

    Ok(Whitelist { e0, s: out })
}

/// Verifies a whitelist proof against the ring and the destination key.
///
/// # Errors
/// [`Error::InvalidInput`] if the key lists have different lengths, are empty
/// or longer than [`MAX_KEYS`], or if a public key is not a valid curve point;
/// [`Error::Malformed`] if a public key has a bad length or SEC1 tag;
/// [`Error::Verification`] if the proof's ring size does not match the key
/// lists or the ring does not close.
pub fn verify(
    proof: &Whitelist,
    online_pubkeys: &[CompressedPoint],
    offline_pubkeys: &[CompressedPoint],
    sub_pubkey: &CompressedPoint,
) -> Result<(), Error> {
    let (keys, m) = ring_keys(online_pubkeys, offline_pubkeys, sub_pubkey)?;
    let n = keys.len();
    if proof.s.len() != n {
        return Err(Error::Verification);
    }

    let mut e = challenge(&proof.e0, &m, 0, 0);
    let mut r = [0u8; 33];
    for (i, (si, ki)) in proof.s.iter().zip(keys.iter()).enumerate() {
        // `from_bytes_be` cannot fail: `Whitelist` only ever holds canonical
        // scalars, but fail closed rather than unwrap.
        let s = Scalar::from_bytes_be(si).map_err(|_| Error::Verification)?;
        let es = Scalar::from_bytes_be_reduce(&e);
        r = ser_point(&ProjectivePoint::mul_generator(&s).add(&ki.mul(&es)));
        if i + 1 < n {
            e = challenge(&r, &m, 0, (i + 1) as u32);
        }
    }
    if bool::from(close(&r, &m).ct_eq(&proof.e0)) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// Deterministic test RNG (a 64-bit LCG); tests must be reproducible.
    struct DetRng(u64);
    impl RngCore for DetRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(0x5851_F42D_4C95_7F2D)
                    .wrapping_add(0x1405_7B7E_F767_814F);
                *b = (self.0 >> 56) as u8;
            }
        }
    }
    impl CryptoRng for DetRng {}

    fn sk(i: u64) -> Scalar {
        let mut b = [0u8; 32];
        b[24..].copy_from_slice(&(i + 1).to_be_bytes());
        Scalar::from_bytes_be(&b).unwrap()
    }

    fn pk(s: &Scalar) -> CompressedPoint {
        ser_point(&ProjectivePoint::mul_generator(s))
    }

    /// Builds a ring of `n` pairs plus a destination key derived from the pair
    /// at `index`, and returns everything `sign` needs.
    #[allow(clippy::type_complexity)]
    fn ring(
        n: usize,
        index: usize,
    ) -> (
        Vec<CompressedPoint>,
        Vec<CompressedPoint>,
        CompressedPoint,
        [u8; 32],
        [u8; 32],
    ) {
        let online: Vec<Scalar> = (0..n).map(|i| sk(i as u64)).collect();
        let offline: Vec<Scalar> = (0..n).map(|i| sk(1000 + i as u64)).collect();
        let sub = sk(90_000);
        let online_pk: Vec<CompressedPoint> = online.iter().map(pk).collect();
        let offline_pk: Vec<CompressedPoint> = offline.iter().map(pk).collect();
        let summed = sub.add(&offline[index]);
        (
            online_pk,
            offline_pk,
            pk(&sub),
            online[index].to_bytes_be(),
            summed.to_bytes_be(),
        )
    }

    #[test]
    fn sign_verify_round_trip() {
        for n in [1usize, 2, 3, 8] {
            for index in [0, n / 2, n - 1] {
                let (on, off, sub, osk, ssk) = ring(n, index);
                let mut rng = DetRng(0xA11CE ^ (n as u64) << 8 ^ index as u64);
                let proof = sign(&osk, &ssk, &on, &off, &sub, index, &mut rng).unwrap();
                assert_eq!(proof.n_keys(), n);
                verify(&proof, &on, &off, &sub).unwrap();

                let bytes = proof.to_bytes();
                assert_eq!(bytes.len(), Whitelist::serialized_len(n));
                assert_eq!(bytes[0] as usize, n);
                let parsed = Whitelist::from_bytes(&bytes).unwrap();
                assert_eq!(parsed, proof);
                verify(&parsed, &on, &off, &sub).unwrap();
            }
        }
    }

    #[test]
    fn rejects_wrong_sub_key() {
        let (on, off, sub, osk, ssk) = ring(4, 2);
        let mut rng = DetRng(7);
        let proof = sign(&osk, &ssk, &on, &off, &sub, 2, &mut rng).unwrap();
        let other = pk(&sk(90_001));
        assert_eq!(verify(&proof, &on, &off, &other), Err(Error::Verification));
        // The destination is committed, so even a whitelist key is rejected.
        assert_eq!(verify(&proof, &on, &off, &off[2]), Err(Error::Verification));
    }

    #[test]
    fn rejects_tampered_proof() {
        let (on, off, sub, osk, ssk) = ring(3, 1);
        let mut rng = DetRng(11);
        let proof = sign(&osk, &ssk, &on, &off, &sub, 1, &mut rng).unwrap();
        for flip in [1usize, 33, 40, 96] {
            let mut bytes = proof.to_bytes();
            bytes[flip] ^= 0x01;
            match Whitelist::from_bytes(&bytes) {
                Ok(p) => assert_eq!(verify(&p, &on, &off, &sub), Err(Error::Verification)),
                Err(e) => assert_eq!(e, Error::Malformed),
            }
        }
    }

    #[test]
    fn rejects_reordered_ring() {
        let (on, off, sub, osk, ssk) = ring(3, 0);
        let mut rng = DetRng(13);
        let proof = sign(&osk, &ssk, &on, &off, &sub, 0, &mut rng).unwrap();
        let mut on2 = on.clone();
        on2.swap(0, 2);
        let mut off2 = off.clone();
        off2.swap(0, 2);
        assert_eq!(verify(&proof, &on2, &off2, &sub), Err(Error::Verification));
        // Swapping only one list also breaks it.
        assert_eq!(verify(&proof, &on2, &off, &sub), Err(Error::Verification));
        // Online and offline lists are not interchangeable.
        assert_eq!(verify(&proof, &off, &on, &sub), Err(Error::Verification));
    }

    #[test]
    fn rejects_proof_from_a_different_ring() {
        let (on, off, sub, osk, ssk) = ring(3, 1);
        let mut rng = DetRng(17);
        let proof = sign(&osk, &ssk, &on, &off, &sub, 1, &mut rng).unwrap();

        // Same size, different keys.
        let mut on2 = on.clone();
        on2[0] = pk(&sk(555));
        assert_eq!(verify(&proof, &on2, &off, &sub), Err(Error::Verification));

        // Different size: the proof's ring size no longer matches.
        let (on3, off3, sub3, _, _) = ring(4, 1);
        assert_eq!(verify(&proof, &on3, &off3, &sub3), Err(Error::Verification));
    }

    #[test]
    fn sign_rejects_bad_arguments() {
        let (on, off, sub, osk, ssk) = ring(3, 1);
        let mut rng = DetRng(19);
        // Index out of range.
        assert_eq!(
            sign(&osk, &ssk, &on, &off, &sub, 3, &mut rng),
            Err(Error::InvalidInput)
        );
        // Secrets that do not open the entry at `index`.
        assert_eq!(
            sign(&osk, &ssk, &on, &off, &sub, 0, &mut rng),
            Err(Error::InvalidInput)
        );
        // Zero secret key.
        assert_eq!(
            sign(&[0u8; 32], &ssk, &on, &off, &sub, 1, &mut rng),
            Err(Error::InvalidInput)
        );
        // Mismatched list lengths.
        assert_eq!(
            sign(&osk, &ssk, &on[..2], &off, &sub, 1, &mut rng),
            Err(Error::InvalidInput)
        );
        // Empty ring.
        assert_eq!(
            sign(&osk, &ssk, &[], &[], &sub, 0, &mut rng),
            Err(Error::InvalidInput)
        );
        // Not a point: a bad tag is `Malformed`, a valid tag over an
        // x-coordinate with no square root is `InvalidInput`.
        let bad_tag = [0xffu8; 33];
        assert_eq!(
            sign(&osk, &ssk, &[bad_tag; 3], &off, &sub, 1, &mut rng),
            Err(Error::Malformed)
        );
        let mut off_curve = [0u8; 33];
        off_curve[0] = 0x02;
        off_curve[32] = 1;
        assert_eq!(
            sign(&osk, &ssk, &[off_curve; 3], &off, &sub, 1, &mut rng),
            Err(Error::InvalidInput)
        );
    }

    #[test]
    fn verify_rejects_bad_keys_without_panicking() {
        let (on, off, sub, osk, ssk) = ring(2, 0);
        let mut rng = DetRng(23);
        let proof = sign(&osk, &ssk, &on, &off, &sub, 0, &mut rng).unwrap();
        let bad = [0u8; 33];
        assert!(verify(&proof, &[bad, bad], &off, &sub).is_err());
        assert!(verify(&proof, &on, &[bad, bad], &sub).is_err());
        assert!(verify(&proof, &on, &off, &bad).is_err());
        assert!(verify(&proof, &on, &off[..1], &sub).is_err());
        assert!(verify(&proof, &[], &[], &sub).is_err());
    }

    #[test]
    fn parse_rejects_malformed() {
        // Empty, truncated, over-long, zero ring.
        assert_eq!(Whitelist::from_bytes(&[]), Err(Error::Malformed));
        assert_eq!(Whitelist::from_bytes(&[0u8; 33]), Err(Error::Malformed));
        assert_eq!(Whitelist::from_bytes(&[1u8; 32]), Err(Error::Malformed));
        assert_eq!(Whitelist::from_bytes(&[1u8; 64]), Err(Error::Malformed));
        assert_eq!(Whitelist::from_bytes(&[1u8; 66]), Err(Error::Malformed));

        // Absurd ring size with a short buffer: must not allocate or panic.
        let mut absurd = vec![0u8; 40];
        absurd[0] = 255;
        assert_eq!(Whitelist::from_bytes(&absurd), Err(Error::Malformed));

        // A 255-key claim with the right length parses (given valid scalars).
        let mut big = vec![1u8; Whitelist::serialized_len(255)];
        big[0] = 255;
        assert_eq!(Whitelist::from_bytes(&big).unwrap().n_keys(), 255);

        // Zero scalars are rejected.
        let mut zero_e0 = vec![0u8; Whitelist::serialized_len(1)];
        zero_e0[0] = 1;
        zero_e0[64] = 1;
        assert_eq!(Whitelist::from_bytes(&zero_e0), Err(Error::Malformed));
        let mut zero_s = vec![0u8; Whitelist::serialized_len(1)];
        zero_s[0] = 1;
        zero_s[32] = 1;
        assert_eq!(Whitelist::from_bytes(&zero_s), Err(Error::Malformed));

        // Overflowing scalars (>= n) are rejected.
        let mut overflow = vec![0xffu8; Whitelist::serialized_len(1)];
        overflow[0] = 1;
        assert_eq!(Whitelist::from_bytes(&overflow), Err(Error::Malformed));

        // Every truncation of a valid proof is rejected.
        let (on, off, sub, osk, ssk) = ring(2, 1);
        let mut rng = DetRng(29);
        let bytes = sign(&osk, &ssk, &on, &off, &sub, 1, &mut rng)
            .unwrap()
            .to_bytes();
        for cut in 0..bytes.len() {
            assert!(Whitelist::from_bytes(&bytes[..cut]).is_err());
        }
    }

    #[test]
    fn degenerate_destination_is_accepted() {
        // W = -Q_index makes the tweak drop out: the ring key collapses to the
        // online key, and the online secret alone signs. Upstream documents
        // this and accepts it deliberately.
        let n = 3;
        let index = 1;
        let online: Vec<Scalar> = (0..n).map(|i| sk(i as u64)).collect();
        let offline: Vec<Scalar> = (0..n).map(|i| sk(1000 + i as u64)).collect();
        let online_pk: Vec<CompressedPoint> = online.iter().map(pk).collect();
        let offline_pk: Vec<CompressedPoint> = offline.iter().map(pk).collect();
        let sub = ser_point(&ProjectivePoint::mul_generator(&offline[index]).negate());

        // `summed` would be zero here, so `sign` refuses; the proof is built by
        // hand from the same equations to exercise `verify`'s degenerate path.
        let (keys, m) = ring_keys(&online_pk, &offline_pk, &sub).unwrap();
        assert!(bool::from(
            keys[index].ct_eq(&ProjectivePoint::mul_generator(&online[index]))
        ));

        let mut rng = DetRng(31);
        let mut s: Vec<Scalar> = (0..n).map(|_| random_scalar(&mut rng).unwrap()).collect();
        let nonce = random_scalar(&mut rng).unwrap();
        let mut prev = ser_point(&ProjectivePoint::mul_generator(&nonce));
        for i in index + 1..n {
            let e = Scalar::from_bytes_be_reduce(&challenge(&prev, &m, 0, i as u32));
            prev = ser_point(&ProjectivePoint::mul_generator(&s[i]).add(&keys[i].mul(&e)));
        }
        let e0 = close(&prev, &m);
        let mut e = challenge(&e0, &m, 0, 0);
        for i in 0..index {
            let es = Scalar::from_bytes_be_reduce(&e);
            let r = ser_point(&ProjectivePoint::mul_generator(&s[i]).add(&keys[i].mul(&es)));
            e = challenge(&r, &m, 0, (i + 1) as u32);
        }
        s[index] = nonce.sub(&Scalar::from_bytes_be_reduce(&e).mul(&online[index]));
        let proof = Whitelist {
            e0,
            s: s.iter().map(|x| x.to_bytes_be()).collect(),
        };
        verify(&proof, &online_pk, &offline_pk, &sub).unwrap();
    }

    // ---- interop vectors -------------------------------------------------
    //
    // `whitelist.json` is generated outside the crate by the black-box harness
    // in `tools/zkp-interop/` (see its README). This test reads the committed
    // JSON only; it never links against the oracle.

    /// The committed interop vectors.
    const VECTORS: &str = include_str!("../../tools/zkp-interop/vectors/whitelist.json");

    /// Splits the `vectors` array into its objects. The file has no nested
    /// objects and no braces inside strings, so brace scanning is enough.
    fn objects(list: &str) -> Vec<&str> {
        let mut out = Vec::new();
        let mut rest = list;
        while let Some(a) = rest.find('{') {
            let after = &rest[a + 1..];
            let end = match after.find('}') {
                Some(e) => e,
                None => break,
            };
            out.push(&after[..end]);
            rest = &after[end + 1..];
        }
        out
    }

    /// The raw text following `"key":` in `obj`.
    fn field<'a>(obj: &'a str, key: &str) -> &'a str {
        let mut pat = alloc::string::String::from("\"");
        pat.push_str(key);
        pat.push('"');
        let after = obj.split(pat.as_str()).nth(1).expect("field present");
        after
            .trim_start()
            .strip_prefix(':')
            .expect("colon")
            .trim_start()
    }

    fn num_field(obj: &str, key: &str) -> usize {
        field(obj, key)
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<alloc::string::String>()
            .parse()
            .expect("number")
    }

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex");
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    fn hex_field(obj: &str, key: &str) -> Vec<u8> {
        let v = field(obj, key).strip_prefix('"').expect("string");
        unhex(&v[..v.find('"').expect("close quote")])
    }

    fn key_field(obj: &str, key: &str) -> CompressedPoint {
        let mut out = [0u8; 33];
        out.copy_from_slice(&hex_field(obj, key));
        out
    }

    fn key_list(obj: &str, key: &str) -> Vec<CompressedPoint> {
        let v = field(obj, key).strip_prefix('[').expect("array");
        v[..v.find(']').expect("close bracket")]
            .split(',')
            .map(|e| {
                let e = e.trim().trim_matches('"');
                let mut out = [0u8; 33];
                out.copy_from_slice(&unhex(e));
                out
            })
            .collect()
    }

    #[test]
    fn interop_vectors() {
        let list = VECTORS.split("\"vectors\"").nth(1).expect("vectors array");
        let objs = objects(list);
        assert!(objs.len() >= 11, "expected the committed vector set");
        let mut oracle = 0;
        let mut ours = 0;
        for obj in objs {
            let n = num_field(obj, "n_keys");
            let index = num_field(obj, "index");
            let online = key_list(obj, "online");
            let offline = key_list(obj, "offline");
            let sub = key_field(obj, "sub");
            let bytes = hex_field(obj, "proof");
            assert_eq!(online.len(), n);
            assert_eq!(offline.len(), n);
            match field(obj, "source").split('"').nth(1).expect("source") {
                "oracle" => oracle += 1,
                "purecrypto" => ours += 1,
                other => panic!("unknown vector source {other}"),
            }

            let proof = Whitelist::from_bytes(&bytes).expect("parses");
            assert_eq!(proof.n_keys(), n);
            assert_eq!(proof.to_bytes(), bytes, "serialization round trip");
            verify(&proof, &online, &offline, &sub).expect("vector verifies");

            // Same ring, wrong destination: must fail.
            let mut other_sub = sub;
            other_sub[32] ^= 1;
            assert!(verify(&proof, &online, &offline, &other_sub).is_err());

            // Re-sign the same statement with our own signer and check it
            // verifies (the secrets in the vectors are the signer's).
            let mut osk = [0u8; 32];
            osk.copy_from_slice(&hex_field(obj, "online_seckey"));
            let mut ssk = [0u8; 32];
            ssk.copy_from_slice(&hex_field(obj, "summed_seckey"));
            let mut rng = DetRng(0x5EED ^ (n as u64) << 16 ^ index as u64);
            let mine = sign(&osk, &ssk, &online, &offline, &sub, index, &mut rng).expect("signs");
            verify(&mine, &online, &offline, &sub).expect("our proof verifies");
            assert_eq!(mine.to_bytes().len(), bytes.len());
        }
        assert!(oracle > 0 && ours > 0, "both interop directions covered");
    }
}
