//! Asset surjection proofs for Confidential Assets.
//!
//! **EXPERIMENTAL** — no semver-stability guarantee. See the [module-level
//! documentation](super) for the clean-room policy and interop caveats.
//!
//! # Source of truth
//!
//! *Confidential Assets* (Poelstra, Back, Friedenbach, Maxwell, Wuille,
//! FC 2017), section on asset surjection, and Maxwell–Poelstra, *Borromean
//! Ring Signatures* (2015) for the ring construction. NOTE: the wire format
//! has no normative specification; see [Interop](#interop) below for exactly
//! what was established against the reference and what was not.
//!
//! # What it proves
//!
//! Confidential Assets hides the asset of an output behind a blinded generator
//! `H' = H_a + r·G`, where `H_a` is the per-asset generator of
//! [`Generator::from_asset_tag`] and `r` is a secret blinding factor. A
//! *surjection proof* convinces a verifier that the asset behind an output's
//! generator is one of the assets behind the transaction's *input* generators
//! — that the map from inputs to that output is surjective onto the output's
//! asset — without revealing which input it came from.
//!
//! The observation that makes this cheap: if input `i` and the output carry the
//! same asset tag, then
//!
//! ```text
//! H'_out − H'_in_i = (H_a + r_out·G) − (H_a + r_in·G) = (r_out − r_in)·G
//! ```
//!
//! so the *difference* of the two published generators is a plain public key
//! whose secret key the prover knows. If the assets differ, the difference
//! contains `H_a − H_b`, whose discrete logarithm with respect to `G` nobody
//! knows. A one-of-many ring signature over the differences
//! `{H'_out − H'_in_i}` therefore proves exactly the surjection claim, and
//! hides the index.
//!
//! # Construction
//!
//! Let `A_0 … A_n-1` be the input generators, `A_out` the output generator, and
//! `u_0 < u_1 < … < u_m-1` the selected subset of input indices (the anonymity
//! set, recorded in the proof's bitmap). With `SEC1(P)` the 33-byte compressed
//! encoding of a curve point:
//!
//! ```text
//! m32   = SHA256( SEC1(A_0) ‖ SEC1(A_1) ‖ … ‖ SEC1(A_n-1) ‖ SEC1(A_out) )
//! K_j   = A_out − A_u_j                                          (ring keys)
//! e_0   = SHA256( e0 ‖ m32 ‖ BE32(0) ‖ BE32(0) )
//! R_j   = s_j·G + e_j·K_j
//! e_j+1 = SHA256( R_j ‖ m32 ‖ BE32(0) ‖ BE32(j+1) )              (j+1 < m)
//! ```
//!
//! and the proof `(e0, s_0 … s_m-1)` is accepted iff
//! `e0 == SHA256( R_m-1 ‖ m32 )`. Every hash output is read as a big-endian
//! integer and reduced modulo the group order before use as a scalar. `BE32(0)`
//! is the Borromean ring index: a surjection proof has exactly one ring, so it
//! is always zero. Note that `m32` commits to **all** input generators, not
//! only the selected ones — the bitmap is what selects the ring, and it is
//! itself covered because the verifier reconstructs the ring from it.
//!
//! Signing is the usual Borromean walk: pick a nonce `k`, set `R_index = k·G`,
//! choose the other `s_j` at random, walk the ring forward from `index + 1`,
//! close it through `e0`, walk on to `index`, and solve
//! `s_index = k − e_index·(r_out − r_in)`.
//!
//! # Encoding
//!
//! [`SurjectionProof::serialize`] emits, exactly as the reference's
//! `secp256k1_surjectionproof_parse` documents:
//!
//! ```text
//! n_inputs   2 bytes, little endian, 0 ..= 256
//! bitmap     ceil(n_inputs / 8) bytes, bit i of byte i/8 (LSB first)
//! e0         32 bytes, big endian
//! s_j        32 bytes each, big endian, one per set bit, in increasing index order
//! ```
//!
//! so a proof is `2 + ceil(n/8) + 32·(1 + m)` bytes, at most 8258 for the
//! maximum 256 inputs all used.
//!
//! # Constant time
//!
//! [`SurjectionProof::generate`] is constant time in the blinding factors and
//! in the input index: the whole ring is walked in a fixed order and every
//! index-dependent choice is a constant-time select, never a branch or a
//! secret-indexed load. The up-front argument checks fail closed and reveal
//! only that the arguments were invalid — that the index is in range, that it
//! is in the proof's anonymity set (which is public, being part of the proof),
//! and that the two blinding factors really open that ring position.
//! Blinding factors and ring secrets held in local buffers are wiped with a
//! [`core::hint::black_box`] barrier.
//!
//! [`SurjectionProof::initialize`] is **not** constant time, and cannot be: it
//! draws candidate anonymity sets until one covers an input whose asset tag
//! matches the output's, so its running time depends on when that happens. The
//! reference has the same property. Tag comparisons themselves are
//! constant-time, and the set it settles on is published in the proof.
//!
//! [`SurjectionProof::verify`] and [`SurjectionProof::parse`] operate purely on
//! public data and are variable time.
//!
//! # Interop
//!
//! **Byte-exact interoperability with Elements/Liquid has been established for
//! the wire format, the input selection and the verification transcript, but
//! *not* for the bytes a fresh [`generate`](SurjectionProof::generate)
//! produces.** Vectors are committed at
//! `tools/zkp-interop/vectors/surjection.json`; the crate's tests read that
//! JSON and never link the oracle.
//!
//! Established against the `secp256k1-zkp` black-box oracle (driven only
//! through `include/secp256k1_surjectionproof.h`, see
//! `tools/zkp-interop/README.md`):
//!
//! * **Serialization and parsing.** The layout above round-trips through
//!   `secp256k1_surjectionproof_parse`/`_serialize`, including the acceptance
//!   rules: bits set beyond `n_inputs` are rejected, a length that is not
//!   exactly `2 + ceil(n/8) + 32·(1 + popcount)` is rejected, `n_inputs > 256`
//!   is rejected, and `n_inputs == 0` or an all-zero bitmap *parse* (and then
//!   never verify).
//! * **Input selection.** [`initialize`](SurjectionProof::initialize)
//!   reproduces the reference's anonymity-set bitmap and `input_index`
//!   exactly, over 25 committed vectors spanning 1 … 256 inputs, input counts
//!   that are and are not powers of two, duplicate asset tags, exhausted
//!   iteration budgets and `max_iterations = 0`. (The development harness also
//!   matched the reference's iteration *count* over 120 randomized
//!   configurations; that count is internal, so this API does not expose it.)
//!   See that function for the exact algorithm, which was recovered by probing
//!   and is documented nowhere else.
//! * **Verification.** Proofs produced by `secp256k1_surjectionproof_generate`
//!   are accepted by [`verify`](SurjectionProof::verify), and proofs produced
//!   here are accepted by `secp256k1_surjectionproof_verify`, over input sets
//!   of 1, 2, 3, 8, 16 and 256 inputs with the true input first, in the middle
//!   and last — 12 vectors in each direction. That pins the message hash, the
//!   ring-key relation, the challenge chaining and the `R = s·G + e·K` sign
//!   convention.
//!
//! **Not established: the nonce derivation.** The reference's `generate` takes
//! no randomness and is deterministic, so its `(e0, s)` values are a fixed
//! function of its inputs; that function could not be recovered by black-box
//! probing (a wide search over plausible SHA-256/HMAC-DRBG/ChaCha20 seedings of
//! the message, blinding factors, ring keys and bitmap found nothing). This
//! module therefore uses **its own** derivation — a SHA-256 chain over a
//! domain-separated seed, documented on
//! [`generate`](SurjectionProof::generate) — so for the same inputs our proof
//! bytes differ from the reference's. Both verify under either implementation,
//! which is what interoperability requires; only bit-identical *reproduction*
//! of a reference proof is unavailable. Do not rely on this module to
//! regenerate a byte-identical copy of a proof made by Elements/Liquid.

use alloc::vec::Vec;

use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::ec::Error;
use crate::ec::secp256k1::{ProjectivePoint, Scalar};
use crate::hash::{Digest, Sha256};
use crate::rng::{CryptoRng, RngCore};
use crate::zkp::pedersen::Generator;

/// Largest number of input assets a proof can be over.
///
/// The serialized input count is two little-endian bytes, but the reference
/// caps it here (`SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS`) and rejects anything
/// larger at parse time, so this module does too.
pub const MAX_N_INPUTS: usize = 256;

/// Largest anonymity set (number of ring members) a proof can use.
///
/// Matches `SECP256K1_SURJECTIONPROOF_MAX_USED_INPUTS`. A proof cannot use more
/// inputs than it has, so the effective bound is
/// `min(MAX_USED_INPUTS, n_inputs)`.
pub const MAX_USED_INPUTS: usize = 256;

/// Domain separator for this module's deterministic nonce derivation.
const NONCE_TAG: &[u8] = b"purecrypto/zkp-surjection/nonce";

/// A compressed SEC1 point, or 33 zero bytes for the identity.
type CompressedPoint = [u8; 33];

// =====================================================================
// Helpers
// =====================================================================

/// Compressed serialization of a point, or 33 zero bytes for the identity.
///
/// The identity has no SEC1 encoding. Only the prover uses this substitute,
/// and only on values it discards (the chain positions before the signer's)
/// or on a nonce commitment that is the identity with negligible probability;
/// it keeps the constant-time walk well defined instead of panicking.
/// [`SurjectionProof::verify`] never substitutes: an `R` on infinity is
/// rejected outright, as the reference does.
fn ser_point(p: &ProjectivePoint) -> CompressedPoint {
    match p.to_affine() {
        Some(a) => a.to_sec1_compressed(),
        None => [0u8; 33],
    }
}

/// `SHA256(prev ‖ m ‖ BE32(ring) ‖ BE32(idx))` — the Borromean challenge hash.
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

/// The message the ring signs: every input generator, then the output
/// generator, each as a 33-byte compressed SEC1 point.
fn message(input_generators: &[Generator], output_generator: &Generator) -> [u8; 32] {
    let mut h = Sha256::new();
    for g in input_generators {
        h.update(&ser_point(&g.as_point()));
    }
    h.update(&ser_point(&output_generator.as_point()));
    h.finalize()
}

/// Number of bitmap bytes for `n_inputs` inputs.
const fn bitmap_len(n_inputs: usize) -> usize {
    n_inputs.div_ceil(8)
}

/// Returns whether bit `i` of `bitmap` is set. `i` must be in range.
fn bit(bitmap: &[u8], i: usize) -> bool {
    bitmap[i / 8] >> (i % 8) & 1 == 1
}

/// Sets bit `i` of `bitmap`. `i` must be in range.
fn set_bit(bitmap: &mut [u8], i: usize) {
    bitmap[i / 8] |= 1 << (i % 8);
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

// =====================================================================
// Input selection
// =====================================================================

/// The reference's anonymity-set selection byte stream.
///
/// A 32-byte buffer starts out holding the seed. Bytes 0…30 are handed out one
/// at a time; the 32nd byte is never used, because on exhaustion the buffer is
/// replaced by its own SHA-256 digest and the count restarts. The stream is
/// therefore
///
/// ```text
/// seed[0..31] ‖ SHA256(seed)[0..31] ‖ SHA256²(seed)[0..31] ‖ …
/// ```
///
/// This 31-of-32 quirk is not documented anywhere; it was recovered by probing
/// the oracle (see the module's Interop section) and is reproduced exactly so
/// that a given seed selects the same anonymity set here as in Elements.
struct SelectRng {
    buf: [u8; 32],
    pos: usize,
}

impl SelectRng {
    fn new(seed: &[u8; 32]) -> SelectRng {
        SelectRng { buf: *seed, pos: 0 }
    }

    fn next_byte(&mut self) -> u8 {
        let b = self.buf[self.pos];
        self.pos += 1;
        if self.pos == 31 {
            self.buf = Sha256::digest(&self.buf);
            self.pos = 0;
        }
        b
    }
}

// =====================================================================
// The proof
// =====================================================================

/// An asset surjection proof: the anonymity-set bitmap plus a one-ring
/// Borromean signature over the generator differences.
///
/// Build one with [`SurjectionProof::initialize`] (which picks the anonymity
/// set and finds the input that matches) followed by
/// [`SurjectionProof::generate`] (which signs), or decode one with
/// [`SurjectionProof::parse`].
///
/// A parsed proof is *well formed* — its bitmap fits its input count and its
/// scalar count matches its bitmap — but says nothing about validity; only
/// [`SurjectionProof::verify`] does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SurjectionProof {
    /// Total number of input assets, `0 ..= MAX_N_INPUTS`.
    n_inputs: usize,
    /// Anonymity-set bitmap, `ceil(n_inputs / 8)` bytes, LSB first.
    used: Vec<u8>,
    /// The Borromean seed challenge.
    e0: [u8; 32],
    /// One scalar per set bit, in increasing input-index order.
    s: Vec<[u8; 32]>,
}

impl SurjectionProof {
    /// The total number of input assets this proof is over.
    pub fn n_inputs(&self) -> usize {
        self.n_inputs
    }

    /// The number of inputs in the anonymity set — the ring size.
    pub fn n_used(&self) -> usize {
        self.s.len()
    }

    /// The input indices in the anonymity set, in increasing order.
    pub fn used_inputs(&self) -> Vec<usize> {
        (0..self.n_inputs).filter(|&i| bit(&self.used, i)).collect()
    }

    /// Serialized length of a proof over `n_inputs` inputs with `n_used` of
    /// them in the anonymity set: `2 + ceil(n_inputs/8) + 32·(1 + n_used)`.
    pub const fn serialized_len(n_inputs: usize, n_used: usize) -> usize {
        2 + bitmap_len(n_inputs) + 32 * (1 + n_used)
    }

    /// This proof's serialized length.
    pub fn serialized_size(&self) -> usize {
        Self::serialized_len(self.n_inputs, self.n_used())
    }

    /// Chooses the anonymity set and locates the input that matches the output.
    ///
    /// Returns the initialized (but unsigned) proof and the index of the input
    /// whose asset tag equals `output_tag`; pass both to
    /// [`generate`](SurjectionProof::generate).
    ///
    /// # The algorithm
    ///
    /// This reproduces the reference's `secp256k1_surjectionproof_initialize`
    /// exactly, so a given `seed` yields the same anonymity set as Elements
    /// does. Bytes come from the stream described on `SelectRng`. Each attempt
    /// draws `n_used` *distinct* indices:
    ///
    /// ```text
    /// limit = (256 / n_inputs) * n_inputs          (integer division)
    /// repeat:
    ///     draw a byte b; if b >= limit, draw again  (unbiased rejection)
    ///     i = b % n_inputs; if i is already in the set, draw again
    /// ```
    ///
    /// and then keeps the set if any drawn index carries `output_tag`,
    /// otherwise starts a fresh attempt — continuing the same byte stream — up
    /// to `max_iterations` times. When several drawn inputs carry the tag, the
    /// **last one drawn** is returned, which is what the reference does.
    ///
    /// `max_iterations` is an upper bound on the attempts, but one attempt is
    /// always made: `0` and `1` behave identically, again matching the
    /// reference.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if `input_tags` is empty or longer than
    /// [`MAX_N_INPUTS`], if `n_used` is zero, greater than
    /// [`MAX_USED_INPUTS`], or greater than the number of inputs, if no input
    /// carries `output_tag` at all (detected up front, without drawing), or if
    /// no attempt covered an input carrying it — probability roughly
    /// `(1 − n_used/n_inputs)^max_iterations`.
    pub fn initialize(
        input_tags: &[[u8; 32]],
        n_used: usize,
        output_tag: &[u8; 32],
        max_iterations: usize,
        seed: &[u8; 32],
    ) -> Result<(SurjectionProof, usize), Error> {
        let n = input_tags.len();
        if n == 0 || n > MAX_N_INPUTS || n_used == 0 || n_used > MAX_USED_INPUTS || n_used > n {
            return Err(Error::InvalidInput);
        }

        // Which tags match, computed once and in constant time. The result is
        // public: the caller already knows its own tags.
        let matches: Vec<Choice> = input_tags.iter().map(|t| t.ct_eq(output_tag)).collect();
        // With no matching input no draw can ever succeed; fail now rather
        // than after `max_iterations` fruitless attempts.
        let any = matches.iter().fold(Choice::from(0), |acc, &hit| acc | hit);
        if !bool::from(any) {
            return Err(Error::InvalidInput);
        }

        let mut rng = SelectRng::new(seed);
        // `limit` discards the tail of the byte range that would bias `% n`.
        let limit = (256 / n) * n;
        let mut drawn: Vec<usize> = Vec::with_capacity(n_used);

        for _ in 0..max_iterations.max(1) {
            let mut used = alloc::vec![0u8; bitmap_len(n)];
            drawn.clear();
            for _ in 0..n_used {
                // Terminates: at most `n_used <= n` indices are taken, so a
                // free one always remains, and each draw is accepted with
                // probability at least (limit/256)·(1/n) > 0.
                loop {
                    let b = rng.next_byte() as usize;
                    if b >= limit {
                        continue;
                    }
                    let i = b % n;
                    if !bit(&used, i) {
                        set_bit(&mut used, i);
                        drawn.push(i);
                        break;
                    }
                }
            }
            // Last match drawn wins, as upstream. Scanned without branching on
            // the comparison result.
            let mut index = 0usize;
            let mut found = Choice::from(0);
            for &i in &drawn {
                let hit = matches[i];
                index = usize::conditional_select(&i, &index, hit);
                found |= hit;
            }
            if bool::from(found) {
                return Ok((
                    SurjectionProof {
                        n_inputs: n,
                        used,
                        e0: [0u8; 32],
                        s: alloc::vec![[0u8; 32]; n_used],
                    },
                    index,
                ));
            }
        }
        Err(Error::InvalidInput)
    }

    /// Signs the ring, filling in `e0` and the `s` scalars.
    ///
    /// `input_generators` must be the ephemeral (blinded) generator of **every**
    /// input, in the order the bitmap indexes; `output_generator` the output's.
    /// `input_index` is the index [`initialize`](SurjectionProof::initialize)
    /// returned, `input_blind` the blinding factor of
    /// `input_generators[input_index]` and `output_blind` that of
    /// `output_generator` — the two must differ by the ring secret, i.e. the
    /// two generators must hide the same asset tag.
    ///
    /// # Nonces
    ///
    /// The nonce and the decoy `s` values are derived deterministically, from a
    /// seed that commits to the ring secret and the whole transcript:
    ///
    /// ```text
    /// seed  = SHA256( "purecrypto/zkp-surjection/nonce" ‖ (r_out − r_in)
    ///                 ‖ m32 ‖ LE16(n_inputs) ‖ bitmap ‖ BE32(ring position) )
    /// s_j   = SHA256( seed ‖ BE32(j) )                      j = 0 … m−1
    /// k     = SHA256( seed ‖ BE32(0xffffffff) )
    /// ```
    ///
    /// each read big-endian and reduced modulo the group order. Because the
    /// seed covers both the secret and the message, two different statements
    /// never share a nonce, which is the condition a ring signature needs; and
    /// because it needs no entropy source, a proof is reproducible. This is
    /// **not** the reference's derivation (see the module's Interop section) —
    /// use [`generate_with_rng`](SurjectionProof::generate_with_rng) if you
    /// would rather randomize.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if the number of generators does not match
    /// [`n_inputs`](SurjectionProof::n_inputs), if the anonymity set is empty,
    /// if `input_index` is out of range or not in the anonymity set, if either
    /// blinding factor is not a canonical scalar (`>= n`), or if the two
    /// blinding factors do not open the ring at `input_index` — which is the
    /// case exactly when the two generators hide different asset tags.
    pub fn generate(
        &mut self,
        input_generators: &[Generator],
        output_generator: &Generator,
        input_index: usize,
        input_blind: &[u8; 32],
        output_blind: &[u8; 32],
    ) -> Result<(), Error> {
        self.generate_inner(
            input_generators,
            output_generator,
            input_index,
            input_blind,
            output_blind,
            None::<&mut DummyRng>,
        )
    }

    /// [`generate`](SurjectionProof::generate) with the nonce and the decoy `s`
    /// values drawn from `rng` instead of derived.
    ///
    /// The resulting proof is equally valid; it just is not reproducible. `rng`
    /// must be a cryptographically secure generator: predictable decoys break
    /// the anonymity the proof exists to provide, and a repeated nonce across
    /// two different statements leaks the blinding-factor difference.
    ///
    /// # Errors
    /// As [`generate`](SurjectionProof::generate), plus [`Error::InvalidInput`]
    /// if `rng` cannot produce a usable scalar.
    pub fn generate_with_rng<R: RngCore + CryptoRng>(
        &mut self,
        input_generators: &[Generator],
        output_generator: &Generator,
        input_index: usize,
        input_blind: &[u8; 32],
        output_blind: &[u8; 32],
        rng: &mut R,
    ) -> Result<(), Error> {
        self.generate_inner(
            input_generators,
            output_generator,
            input_index,
            input_blind,
            output_blind,
            Some(rng),
        )
    }

    fn generate_inner<R: RngCore + CryptoRng>(
        &mut self,
        input_generators: &[Generator],
        output_generator: &Generator,
        input_index: usize,
        input_blind: &[u8; 32],
        output_blind: &[u8; 32],
        rng: Option<&mut R>,
    ) -> Result<(), Error> {
        let used = self.used_inputs();
        let ring = used.len();
        if input_generators.len() != self.n_inputs || ring == 0 || input_index >= self.n_inputs {
            return Err(Error::InvalidInput);
        }

        let m = message(input_generators, output_generator);
        let out_point = output_generator.as_point();
        let keys: Vec<ProjectivePoint> = used
            .iter()
            .map(|&i| out_point.add(&input_generators[i].as_point().negate()))
            .collect();

        // The ring secret: r_out − r_in, the discrete logarithm of
        // `A_out − A_in_index` with respect to G.
        let secret = Scalar::from_bytes_be(output_blind)?.sub(&Scalar::from_bytes_be(input_blind)?);

        // Ring position of `input_index`, without branching on it.
        let mut pos = 0usize;
        let mut found = Choice::from(0);
        for (j, &u) in used.iter().enumerate() {
            let hit = u.ct_eq(&input_index);
            pos = usize::conditional_select(&j, &pos, hit);
            found |= hit;
        }
        if !bool::from(found) {
            return Err(Error::InvalidInput);
        }

        // Fail closed if the blinding factors do not open the ring entry at
        // `pos`; the key is selected without a secret-indexed load.
        let mut selected = ProjectivePoint::identity();
        for (j, k) in keys.iter().enumerate() {
            selected = ProjectivePoint::conditional_select(k, &selected, j.ct_eq(&pos));
        }
        if !bool::from(ProjectivePoint::mul_generator(&secret).ct_eq(&selected)) {
            return Err(Error::InvalidInput);
        }

        // Nonce and decoys.
        let (nonce, s) = match rng {
            Some(rng) => {
                let mut s = Vec::with_capacity(ring);
                for _ in 0..ring {
                    s.push(random_scalar(rng)?);
                }
                (random_scalar(rng)?, s)
            }
            None => self.derive_nonces(&secret, &m, pos, ring),
        };

        let nonce_commit = ser_point(&ProjectivePoint::mul_generator(&nonce));

        // Forward walk. Positions at or before `pos` compute values that are
        // discarded when the chain is re-seeded with `nonce_commit` at
        // `pos + 1`; the work is done anyway so the pattern does not depend on
        // `pos`.
        let mut prev = [0u8; 33];
        for (j, (sj, kj)) in s.iter().zip(keys.iter()).enumerate() {
            let reseed = j.ct_eq(&pos.wrapping_add(1));
            let input = <[u8; 33]>::conditional_select(&nonce_commit, &prev, reseed);
            let e = Scalar::from_bytes_be_reduce(&challenge(&input, &m, 0, j as u32));
            prev = ser_point(&ProjectivePoint::mul_generator(sj).add(&kj.mul(&e)));
        }
        // When the signer sits last, the chain above never got re-seeded and
        // the ring closes on the nonce commitment directly.
        let last = <[u8; 33]>::conditional_select(&nonce_commit, &prev, pos.ct_eq(&(ring - 1)));
        let e0 = close(&last, &m);

        // Second walk, from the top of the ring, to recover the signer's
        // challenge.
        let mut e = challenge(&e0, &m, 0, 0);
        let mut e_signer = [0u8; 32];
        for (j, (sj, kj)) in s.iter().zip(keys.iter()).enumerate() {
            e_signer = <[u8; 32]>::conditional_select(&e, &e_signer, j.ct_eq(&pos));
            let es = Scalar::from_bytes_be_reduce(&e);
            let r = ser_point(&ProjectivePoint::mul_generator(sj).add(&kj.mul(&es)));
            e = challenge(&r, &m, 0, (j + 1) as u32);
        }

        // s_pos = nonce − e_pos·secret, written without revealing `pos`.
        let signer = nonce.sub(&Scalar::from_bytes_be_reduce(&e_signer).mul(&secret));
        // The signer's challenge identifies `pos`.
        e_signer = [0u8; 32];
        let _ = core::hint::black_box(&e_signer);
        let mut signer_bytes = signer.to_bytes_be();
        let mut out = Vec::with_capacity(ring);
        for (j, sj) in s.iter().enumerate() {
            out.push(<[u8; 32]>::conditional_select(
                &signer_bytes,
                &sj.to_bytes_be(),
                j.ct_eq(&pos),
            ));
        }
        signer_bytes = [0u8; 32];
        let _ = core::hint::black_box(&signer_bytes);

        self.e0 = e0;
        self.s = out;
        Ok(())
    }

    /// Derives the nonce and the decoy `s` values; see
    /// [`generate`](SurjectionProof::generate) for the construction.
    fn derive_nonces(
        &self,
        secret: &Scalar,
        m: &[u8; 32],
        pos: usize,
        ring: usize,
    ) -> (Scalar, Vec<Scalar>) {
        let mut secret_bytes = secret.to_bytes_be();
        let mut h = Sha256::new();
        h.update(NONCE_TAG);
        h.update(&secret_bytes);
        h.update(m);
        h.update(&(self.n_inputs as u16).to_le_bytes());
        h.update(&self.used);
        h.update(&(pos as u32).to_be_bytes());
        let mut seed = h.finalize();
        secret_bytes = [0u8; 32];
        let _ = core::hint::black_box(&secret_bytes);

        let derive = |counter: u32| {
            let mut h = Sha256::new();
            h.update(&seed);
            h.update(&counter.to_be_bytes());
            Scalar::from_bytes_be_reduce(&h.finalize())
        };
        let s: Vec<Scalar> = (0..ring).map(|j| derive(j as u32)).collect();
        let nonce = derive(u32::MAX);

        seed = [0u8; 32];
        let _ = core::hint::black_box(&seed);
        (nonce, s)
    }

    /// Verifies the proof against the input and output generators.
    ///
    /// Succeeds only if the ring closes, which means the asset behind
    /// `output_generator` is the asset behind one of the inputs the proof's
    /// bitmap selects. It says nothing about the inputs the bitmap leaves out:
    /// a caller who cares that the anonymity set is large enough must check
    /// [`n_used`](SurjectionProof::n_used) itself.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if the number of generators does not match
    /// [`n_inputs`](SurjectionProof::n_inputs);
    /// [`Error::Verification`] if the anonymity set is empty, if a scalar in
    /// the proof is not canonical (`>= n`), if an `R` value is the point at
    /// infinity, or if the ring does not close. Never panics, whatever the
    /// proof contains.
    pub fn verify(
        &self,
        input_generators: &[Generator],
        output_generator: &Generator,
    ) -> Result<(), Error> {
        if input_generators.len() != self.n_inputs {
            return Err(Error::InvalidInput);
        }
        let used = self.used_inputs();
        let ring = used.len();
        // `s.len() == popcount(bitmap)` is an invariant of every constructor.
        if ring == 0 || ring != self.s.len() {
            return Err(Error::Verification);
        }

        let m = message(input_generators, output_generator);
        let out_point = output_generator.as_point();

        let mut e = challenge(&self.e0, &m, 0, 0);
        let mut r = [0u8; 33];
        for (j, &u) in used.iter().enumerate() {
            let s = Scalar::from_bytes_be(&self.s[j]).map_err(|_| Error::Verification)?;
            let key = out_point.add(&input_generators[u].as_point().negate());
            let es = Scalar::from_bytes_be_reduce(&e);
            // An `R` on infinity has no encoding to hash; a prover reaches it
            // only with a zero nonce, and the reference rejects such a proof.
            r = ProjectivePoint::mul_generator(&s)
                .add(&key.mul(&es))
                .to_affine()
                .ok_or(Error::Verification)?
                .to_sec1_compressed();
            if j + 1 < ring {
                e = challenge(&r, &m, 0, (j + 1) as u32);
            }
        }
        if bool::from(close(&r, &m).ct_eq(&self.e0)) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }

    /// Encodes the proof; see the module's [Encoding](self#encoding) section.
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.serialized_size());
        // `n_inputs <= MAX_N_INPUTS` is an invariant of every constructor.
        out.extend_from_slice(&(self.n_inputs as u16).to_le_bytes());
        out.extend_from_slice(&self.used);
        out.extend_from_slice(&self.e0);
        for s in &self.s {
            out.extend_from_slice(s);
        }
        out
    }

    /// Decodes a proof.
    ///
    /// Every length is bounded before anything is allocated, so a hostile
    /// buffer cannot make this allocate more than the 8258 bytes a maximal
    /// proof needs.
    ///
    /// Like the reference, this accepts a proof whose input count or bitmap is
    /// empty; such a proof is well formed but can never verify.
    ///
    /// # Errors
    /// [`Error::Malformed`] if the buffer is shorter than two bytes, if the
    /// input count exceeds [`MAX_N_INPUTS`], if the bitmap has a bit set at or
    /// beyond the input count, or if the length is not exactly
    /// [`serialized_len`](SurjectionProof::serialized_len) for the input count
    /// and the bitmap's population. Never panics, for any input.
    pub fn parse(bytes: &[u8]) -> Result<SurjectionProof, Error> {
        if bytes.len() < 2 {
            return Err(Error::Malformed);
        }
        let n_inputs = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
        if n_inputs > MAX_N_INPUTS {
            return Err(Error::Malformed);
        }
        let bm = bitmap_len(n_inputs);
        // 2 + bitmap + e0 is the smallest a proof over `n_inputs` can be.
        if bytes.len() < 2 + bm + 32 {
            return Err(Error::Malformed);
        }
        let bitmap = &bytes[2..2 + bm];
        // Bits at or beyond `n_inputs` would index a generator that does not
        // exist; the reference rejects them and so do we.
        if !n_inputs.is_multiple_of(8) && bitmap[bm - 1] >> (n_inputs % 8) != 0 {
            return Err(Error::Malformed);
        }
        let n_used = bitmap
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum::<usize>();
        if bytes.len() != Self::serialized_len(n_inputs, n_used) {
            return Err(Error::Malformed);
        }

        let mut e0 = [0u8; 32];
        e0.copy_from_slice(&bytes[2 + bm..34 + bm]);
        let mut s = Vec::with_capacity(n_used);
        for j in 0..n_used {
            let mut sj = [0u8; 32];
            sj.copy_from_slice(&bytes[34 + bm + 32 * j..66 + bm + 32 * j]);
            s.push(sj);
        }
        Ok(SurjectionProof {
            n_inputs,
            used: bitmap.to_vec(),
            e0,
            s,
        })
    }
}

/// Stand-in generator for the deterministic path, which never draws from it.
///
/// [`generate`](SurjectionProof::generate) and
/// [`generate_with_rng`](SurjectionProof::generate_with_rng) share one
/// implementation whose randomness is an `Option<&mut R>`; the deterministic
/// caller passes `None`, and Rust still needs a concrete `R` to instantiate.
struct DummyRng;

impl RngCore for DummyRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Unreachable: `generate` passes `None`. Filling with zeros keeps this
        // panic-free even if that ever changed.
        dest.fill(0);
    }
}

impl CryptoRng for DummyRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;
    use alloc::vec;

    /// The oracle-generated interop corpus. See `tools/zkp-interop/README.md`.
    const VECTORS: &str = include_str!("../../tools/zkp-interop/vectors/surjection.json");

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

    // --- fixtures ---

    fn tag(i: usize) -> [u8; 32] {
        let mut t = [0u8; 32];
        t[0] = i as u8;
        t[1] = (i >> 8) as u8;
        t[2] = 0x5a;
        t
    }

    fn blind(i: usize) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[31] = (i + 1) as u8;
        b[0] = (i + 3) as u8;
        b
    }

    /// Builds `n` input generators over distinct assets plus an output
    /// generator carrying the asset of input `index`.
    fn setup(n: usize, index: usize) -> (Vec<[u8; 32]>, Vec<Generator>, Generator, [u8; 32]) {
        let tags: Vec<[u8; 32]> = (0..n).map(tag).collect();
        let gens: Vec<Generator> = (0..n)
            .map(|i| Generator::from_asset_tag_blinded(&tags[i], &blind(i)).unwrap())
            .collect();
        let ob = blind(1000);
        let out = Generator::from_asset_tag_blinded(&tags[index], &ob).unwrap();
        (tags, gens, out, ob)
    }

    fn prove(
        n: usize,
        n_used: usize,
        index: usize,
        seed: u8,
    ) -> (SurjectionProof, Vec<Generator>, Generator) {
        let (tags, gens, out, ob) = setup(n, index);
        let mut s = [0u8; 32];
        s[31] = seed;
        let (mut proof, idx) =
            SurjectionProof::initialize(&tags, n_used, &tags[index], 100_000, &s).unwrap();
        assert_eq!(idx, index);
        proof
            .generate(&gens, &out, idx, &blind(index), &ob)
            .unwrap();
        (proof, gens, out)
    }

    // --- round trips ---

    #[test]
    fn round_trip_across_sizes_and_positions() {
        for n in [1usize, 2, 3, 16, 255, 256] {
            for index in [0, n / 2, n - 1] {
                let n_used = core::cmp::min(3, n);
                let (proof, gens, out) = prove(n, n_used, index, 7);
                assert_eq!(proof.n_inputs(), n);
                assert_eq!(proof.n_used(), n_used);
                assert!(proof.used_inputs().contains(&index));
                proof.verify(&gens, &out).unwrap();

                let bytes = proof.serialize();
                assert_eq!(bytes.len(), SurjectionProof::serialized_len(n, n_used));
                assert_eq!(bytes.len(), proof.serialized_size());
                let parsed = SurjectionProof::parse(&bytes).unwrap();
                assert_eq!(parsed, proof);
                parsed.verify(&gens, &out).unwrap();
            }
        }
    }

    #[test]
    fn maximal_anonymity_set() {
        // 16 inputs, all 16 used: the largest ring the fixture builds quickly.
        let (proof, gens, out) = prove(16, 16, 9, 3);
        assert_eq!(proof.n_used(), 16);
        assert_eq!(proof.used_inputs(), (0..16).collect::<Vec<_>>());
        proof.verify(&gens, &out).unwrap();
        assert_eq!(
            proof.serialize().len(),
            SurjectionProof::serialized_len(16, 16)
        );
    }

    #[test]
    fn generation_is_deterministic_and_rng_variant_verifies() {
        let (tags, gens, out, ob) = setup(8, 5);
        let seed = [9u8; 32];
        let (mut a, idx) = SurjectionProof::initialize(&tags, 3, &tags[5], 10_000, &seed).unwrap();
        let mut b = a.clone();
        a.generate(&gens, &out, idx, &blind(5), &ob).unwrap();
        b.generate(&gens, &out, idx, &blind(5), &ob).unwrap();
        assert_eq!(a, b, "deterministic generation must be reproducible");

        let mut c = b.clone();
        let mut rng = DetRng(0xC0FFEE);
        c.generate_with_rng(&gens, &out, idx, &blind(5), &ob, &mut rng)
            .unwrap();
        assert_ne!(
            c, a,
            "the randomized variant must not match the derived one"
        );
        c.verify(&gens, &out).unwrap();
    }

    #[test]
    fn blinded_generators_of_the_same_asset_are_interchangeable() {
        // Two inputs of the *same* asset with different generator blinds: the
        // proof must work from either of them.
        let t = tag(42);
        let gens = vec![
            Generator::from_asset_tag_blinded(&t, &blind(1)).unwrap(),
            Generator::from_asset_tag_blinded(&t, &blind(2)).unwrap(),
        ];
        let tags = vec![t, t];
        let ob = blind(9);
        let out = Generator::from_asset_tag_blinded(&t, &ob).unwrap();
        for index in [0usize, 1] {
            let (mut proof, _) =
                SurjectionProof::initialize(&tags, 2, &t, 1000, &[1u8; 32]).unwrap();
            proof
                .generate(&gens, &out, index, &blind(index + 1), &ob)
                .unwrap();
            proof.verify(&gens, &out).unwrap();
        }
    }

    // --- soundness ---

    #[test]
    fn rejects_wrong_output_generator() {
        let (proof, gens, _out) = prove(4, 2, 1, 1);
        let other = Generator::from_asset_tag_blinded(&tag(1), &blind(77)).unwrap();
        assert_eq!(
            proof.verify(&gens, &other).unwrap_err(),
            Error::Verification
        );
        // ... and a generator for a different asset entirely
        let other_asset = Generator::from_asset_tag_blinded(&tag(99), &blind(1000)).unwrap();
        assert_eq!(
            proof.verify(&gens, &other_asset).unwrap_err(),
            Error::Verification
        );
    }

    #[test]
    fn rejects_tampered_proof() {
        let (proof, gens, out) = prove(4, 3, 2, 5);
        let bytes = proof.serialize();
        for pos in [3usize, 20, 40, 70, 100] {
            let mut bad = bytes.clone();
            bad[pos] ^= 1;
            if let Ok(p) = SurjectionProof::parse(&bad) {
                assert!(p.verify(&gens, &out).is_err(), "flip at {pos} accepted");
            }
        }
    }

    #[test]
    fn rejects_reordered_and_truncated_input_sets() {
        let (proof, gens, out) = prove(4, 2, 1, 2);
        let mut swapped = gens.clone();
        swapped.swap(0, 1);
        assert!(proof.verify(&swapped, &out).is_err());
        // dropping an input changes the count, not just the message
        assert_eq!(
            proof.verify(&gens[..3], &out).unwrap_err(),
            Error::InvalidInput
        );
    }

    #[test]
    fn rejects_input_set_without_the_true_input() {
        // Replace the true input's generator with one for another asset: the
        // ring key it opened is gone.
        let (proof, gens, out) = prove(4, 2, 1, 4);
        let mut broken = gens.clone();
        broken[1] = Generator::from_asset_tag_blinded(&tag(200), &blind(1)).unwrap();
        assert_eq!(
            proof.verify(&broken, &out).unwrap_err(),
            Error::Verification
        );
    }

    #[test]
    fn rejects_proof_made_for_another_output() {
        let (tags, gens, _out, _ob) = setup(4, 1);
        let ob2 = blind(555);
        let out2 = Generator::from_asset_tag_blinded(&tags[1], &ob2).unwrap();
        let (mut proof, idx) =
            SurjectionProof::initialize(&tags, 2, &tags[1], 10_000, &[3u8; 32]).unwrap();
        proof.generate(&gens, &out2, idx, &blind(1), &ob2).unwrap();
        proof.verify(&gens, &out2).unwrap();
        // the same proof against a third output generator
        let ob3 = blind(556);
        let out3 = Generator::from_asset_tag_blinded(&tags[1], &ob3).unwrap();
        assert_eq!(proof.verify(&gens, &out3).unwrap_err(), Error::Verification);
    }

    #[test]
    fn generate_rejects_mismatched_secrets() {
        let (tags, gens, out, ob) = setup(4, 2);
        let (mut proof, idx) =
            SurjectionProof::initialize(&tags, 3, &tags[2], 10_000, &[1u8; 32]).unwrap();
        // wrong input blind
        assert!(proof.generate(&gens, &out, idx, &blind(0), &ob).is_err());
        // wrong output blind
        assert!(
            proof
                .generate(&gens, &out, idx, &blind(2), &blind(4))
                .is_err()
        );
        // index outside the anonymity set or out of range
        let outside = (0..4).find(|i| !proof.used_inputs().contains(i));
        if let Some(i) = outside {
            assert!(proof.generate(&gens, &out, i, &blind(i), &ob).is_err());
        }
        assert!(proof.generate(&gens, &out, 9, &blind(2), &ob).is_err());
        // wrong generator count
        assert!(
            proof
                .generate(&gens[..3], &out, idx, &blind(2), &ob)
                .is_err()
        );
        // non-canonical blinding factor
        assert!(proof.generate(&gens, &out, idx, &[0xff; 32], &ob).is_err());
    }

    #[test]
    fn initialize_rejects_bad_shapes() {
        let tags: Vec<[u8; 32]> = (0..4).map(tag).collect();
        let seed = [0u8; 32];
        assert!(SurjectionProof::initialize(&[], 1, &tags[0], 100, &seed).is_err());
        assert!(SurjectionProof::initialize(&tags, 0, &tags[0], 100, &seed).is_err());
        assert!(SurjectionProof::initialize(&tags, 5, &tags[0], 100, &seed).is_err());
        let big: Vec<[u8; 32]> = (0..257).map(tag).collect();
        assert!(SurjectionProof::initialize(&big, 3, &tags[0], 100, &seed).is_err());
        // no input carries the output tag
        assert!(SurjectionProof::initialize(&tags, 2, &tag(9), 100, &seed).is_err());
    }

    #[test]
    fn rejects_an_r_on_infinity() {
        // A prover with nonce k = 0 in a one-member ring: R = k·G is the
        // identity, and s = 0 − e·secret makes the verifier's
        // R = s·G + e·K land on infinity too. Serializing that as 33 zero
        // bytes would close the ring; the reference cannot encode it and
        // rejects, so must we.
        let (_tags, gens, out, ob) = setup(1, 0);
        let m = message(&gens, &out);
        let secret = Scalar::from_bytes_be(&ob)
            .unwrap()
            .sub(&Scalar::from_bytes_be(&blind(0)).unwrap());
        let key = out.as_point().add(&gens[0].as_point().negate());
        assert!(bool::from(
            ProjectivePoint::mul_generator(&secret).ct_eq(&key)
        ));

        let e0 = close(&[0u8; 33], &m);
        let e = Scalar::from_bytes_be_reduce(&challenge(&e0, &m, 0, 0));
        let s0 = Scalar::ZERO.sub(&e.mul(&secret));
        let r = ProjectivePoint::mul_generator(&s0).add(&key.mul(&e));
        assert!(
            r.to_affine().is_none(),
            "the construction must hit infinity"
        );

        let proof = SurjectionProof {
            n_inputs: 1,
            used: vec![0x01],
            e0,
            s: vec![s0.to_bytes_be()],
        };
        assert_eq!(proof.verify(&gens, &out), Err(Error::Verification));
        // The same bytes through the parser.
        let parsed = SurjectionProof::parse(&proof.serialize()).unwrap();
        assert_eq!(parsed.verify(&gens, &out), Err(Error::Verification));
    }

    #[test]
    fn initialize_fails_fast_when_no_input_matches() {
        // Without the up-front check this would loop `usize::MAX` times.
        let tags: Vec<[u8; 32]> = (0..4).map(tag).collect();
        assert_eq!(
            SurjectionProof::initialize(&tags, 2, &tag(9), usize::MAX, &[0u8; 32]).unwrap_err(),
            Error::InvalidInput
        );
        // A matching input still goes through the normal selection.
        let (proof, idx) =
            SurjectionProof::initialize(&tags, 2, &tags[1], 1_000, &[0u8; 32]).unwrap();
        assert_eq!(idx, 1);
        assert!(proof.used_inputs().contains(&1));
    }

    #[test]
    fn initialize_finds_the_last_drawn_match() {
        // All tags equal: every draw matches, and the index returned must be
        // one of the selected ones.
        let tags = vec![[7u8; 32]; 8];
        let (proof, idx) =
            SurjectionProof::initialize(&tags, 3, &[7u8; 32], 10, &[0u8; 32]).unwrap();
        assert!(proof.used_inputs().contains(&idx));
        assert_eq!(proof.n_used(), 3);
    }

    // --- parsing ---

    #[test]
    fn parse_rejects_malformed() {
        let (proof, _, _) = prove(4, 2, 1, 1);
        let bytes = proof.serialize();
        // truncations
        for cut in 0..bytes.len() {
            assert!(
                SurjectionProof::parse(&bytes[..cut]).is_err(),
                "truncation to {cut} accepted"
            );
        }
        // extra byte
        let mut long = bytes.clone();
        long.push(0);
        assert!(SurjectionProof::parse(&long).is_err());
        // absurd input count
        let mut huge = bytes.clone();
        huge[0] = 0xff;
        huge[1] = 0xff;
        assert!(SurjectionProof::parse(&huge).is_err());
        huge[0] = 1;
        huge[1] = 1; // 257
        assert!(SurjectionProof::parse(&huge).is_err());
        // bitmap bit at or beyond n_inputs
        let mut pad = bytes.clone();
        pad[2] |= 0x80;
        assert!(SurjectionProof::parse(&pad).is_err());
    }

    #[test]
    fn parse_accepts_the_degenerate_shapes_upstream_accepts() {
        // n_inputs = 0: two bytes plus e0.
        let mut buf = vec![0u8; 34];
        buf[33] = 1;
        let p = SurjectionProof::parse(&buf).unwrap();
        assert_eq!(p.n_inputs(), 0);
        assert_eq!(p.n_used(), 0);
        assert_eq!(p.serialize(), buf);
        // empty bitmap over 8 inputs.
        let mut buf = vec![0u8; 35];
        buf[0] = 8;
        let p = SurjectionProof::parse(&buf).unwrap();
        assert_eq!(p.n_used(), 0);
        assert_eq!(p.serialize(), buf);
        // ... and neither can verify.
        let (_, gens, out, _) = setup(8, 0);
        assert_eq!(p.verify(&gens, &out).unwrap_err(), Error::Verification);
    }

    #[test]
    fn parsing_never_panics() {
        // Deterministically walk a wide slice of the input space.
        let mut state = 0x1234_5678_9abc_def0u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut buf = vec![0u8; 600];
        for _ in 0..3000 {
            for b in buf.iter_mut() {
                *b = (next() >> 24) as u8;
            }
            let len = (next() as usize) % buf.len();
            let _ = SurjectionProof::parse(&buf[..len]);
            // and with a plausible header, which reaches deeper into the parser
            buf[0] = (next() % 300) as u8;
            buf[1] = 0;
            let _ = SurjectionProof::parse(&buf[..len]);
        }
        // every truncation of a valid proof
        let (proof, gens, out) = prove(16, 3, 8, 1);
        let bytes = proof.serialize();
        for cut in 0..=bytes.len() {
            if let Ok(p) = SurjectionProof::parse(&bytes[..cut]) {
                let _ = p.verify(&gens, &out);
            }
        }
    }

    #[test]
    fn verify_never_panics_on_hostile_proofs() {
        let (_, gens, out, _) = setup(4, 0);
        // scalars that are zero, the group order, and all-ones
        for fill in [0x00u8, 0xff] {
            let mut buf = vec![fill; SurjectionProof::serialized_len(4, 2)];
            buf[0] = 4;
            buf[1] = 0;
            buf[2] = 0x03;
            let p = SurjectionProof::parse(&buf).unwrap();
            assert!(p.verify(&gens, &out).is_err());
        }
        let n = from_hex::<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        let mut buf = Vec::new();
        buf.extend_from_slice(&[4, 0, 0x03]);
        buf.extend_from_slice(&n);
        buf.extend_from_slice(&n);
        buf.extend_from_slice(&n);
        let p = SurjectionProof::parse(&buf).unwrap();
        assert_eq!(p.verify(&gens, &out).unwrap_err(), Error::Verification);
    }

    // --- interop vectors ---

    /// Returns the body of the top-level array `"<name>": [ ... ]`.
    fn section<'a>(src: &'a str, name: &str) -> &'a str {
        let mut key = alloc::string::String::from("\"");
        key.push_str(name);
        key.push_str("\": [");
        let start = src.find(&key).expect("section") + key.len();
        let rest = &src[start..];
        let end = rest.find("\n  ]").expect("section end");
        &rest[..end]
    }

    /// Splits a section body into its `{ ... }` objects.
    fn objects(section: &str) -> impl Iterator<Item = &str> {
        section
            .split('{')
            .skip(1)
            .map(|o| o.split('}').next().unwrap())
    }

    /// Returns the raw token following `"key":` in `obj`.
    fn raw<'a>(obj: &'a str, key: &str) -> &'a str {
        let mut needle = alloc::string::String::from("\"");
        needle.push_str(key);
        needle.push_str("\":");
        let i = obj.find(&needle).expect("key") + needle.len();
        obj[i..].trim_start()
    }

    /// Returns the string value of `"key": "..."`.
    fn text<'a>(obj: &'a str, key: &str) -> &'a str {
        let v = raw(obj, key).strip_prefix('"').expect("string value");
        &v[..v.find('"').expect("string end")]
    }

    /// Returns the integer value of `"key": 123`.
    fn number(obj: &str, key: &str) -> usize {
        let v = raw(obj, key);
        let end = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
        v[..end].parse().expect("number")
    }

    /// Iterates the quoted strings of `"key": ["..", ".."]`.
    fn text_list<'a>(obj: &'a str, key: &str) -> impl Iterator<Item = &'a str> {
        let v = raw(obj, key).strip_prefix('[').expect("array value");
        let body = &v[..v.find(']').expect("array end")];
        body.split('"').skip(1).step_by(2)
    }

    /// Iterates the integers of `"key": [1, 2]`.
    fn number_list<'a>(obj: &'a str, key: &str) -> impl Iterator<Item = usize> + 'a {
        let v = raw(obj, key).strip_prefix('[').expect("array value");
        let body = &v[..v.find(']').expect("array end")];
        body.split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().parse().expect("number"))
    }

    fn hex_vec(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn interop_initialize() {
        // Each vector fixes a seed, an input tag set and an output tag; the
        // oracle's bitmap, input index and iteration count must match ours.
        let mut count = 0;
        for obj in objects(section(VECTORS, "initialize")) {
            let seed = from_hex::<32>(text(obj, "seed"));
            let tags: Vec<[u8; 32]> = text_list(obj, "input_tags").map(from_hex::<32>).collect();
            let out = from_hex::<32>(text(obj, "output_tag"));
            let n_used = number(obj, "n_used");
            let max_iterations = number(obj, "max_iterations");
            let expect_used: Vec<usize> = number_list(obj, "used").collect();
            let ok = number(obj, "ok") == 1;
            match SurjectionProof::initialize(&tags, n_used, &out, max_iterations, &seed) {
                Ok((proof, idx)) => {
                    assert!(ok, "we selected where the oracle failed");
                    assert_eq!(proof.used_inputs(), expect_used);
                    assert_eq!(idx, number(obj, "input_index"));
                    assert_eq!(proof.n_inputs(), tags.len());
                }
                Err(_) => assert!(!ok, "we failed where the oracle selected"),
            }
            count += 1;
        }
        assert!(
            count >= 20,
            "expected a broad initialize corpus, got {count}"
        );
    }

    #[test]
    fn interop_verify_oracle_proofs() {
        // Proofs produced by `secp256k1_surjectionproof_generate`.
        let mut count = 0;
        for obj in objects(section(VECTORS, "proofs")) {
            let gens: Vec<Generator> = text_list(obj, "input_generators")
                .map(|s| Generator::parse(&from_hex::<33>(s)).expect("generator"))
                .collect();
            let out = Generator::parse(&from_hex::<33>(text(obj, "output_generator"))).unwrap();
            let bytes = hex_vec(text(obj, "proof"));
            let proof = SurjectionProof::parse(&bytes).expect("oracle proof must parse");
            assert_eq!(proof.serialize(), bytes, "re-serialization must be exact");
            assert_eq!(proof.n_inputs(), gens.len());
            assert_eq!(proof.n_used(), number(obj, "n_used"));
            proof.verify(&gens, &out).expect("oracle proof must verify");

            // and a proof of ours over the same statement verifies too
            let index = number(obj, "input_index");
            let mut ours = proof.clone();
            let ib = from_hex::<32>(text(obj, "input_blind"));
            let ob = from_hex::<32>(text(obj, "output_blind"));
            ours.generate(&gens, &out, index, &ib, &ob).unwrap();
            ours.verify(&gens, &out).unwrap();
            count += 1;
        }
        assert!(count >= 8, "expected a broad proof corpus, got {count}");
    }

    #[test]
    fn interop_our_proofs_the_oracle_accepted() {
        // Proofs this crate produced, recorded after
        // `secp256k1_surjectionproof_verify` accepted them.
        let mut count = 0;
        for obj in objects(section(VECTORS, "purecrypto_proofs")) {
            let gens: Vec<Generator> = text_list(obj, "input_generators")
                .map(|s| Generator::parse(&from_hex::<33>(s)).expect("generator"))
                .collect();
            let out = Generator::parse(&from_hex::<33>(text(obj, "output_generator"))).unwrap();
            let bytes = hex_vec(text(obj, "proof"));
            let proof = SurjectionProof::parse(&bytes).expect("must parse");
            proof.verify(&gens, &out).expect("must verify");
            // regenerating from the recorded secrets reproduces it byte for byte
            let mut again = proof.clone();
            again
                .generate(
                    &gens,
                    &out,
                    number(obj, "input_index"),
                    &from_hex::<32>(text(obj, "input_blind")),
                    &from_hex::<32>(text(obj, "output_blind")),
                )
                .unwrap();
            assert_eq!(again.serialize(), bytes, "generation drifted");
            count += 1;
        }
        assert!(count >= 8, "expected a broad proof corpus, got {count}");
    }

    #[test]
    fn interop_rejections() {
        let mut count = 0;
        for obj in objects(section(VECTORS, "invalid_proofs")) {
            let bytes = hex_vec(text(obj, "proof"));
            assert!(
                SurjectionProof::parse(&bytes).is_err(),
                "accepted {}, which the oracle rejects",
                text(obj, "proof")
            );
            count += 1;
        }
        assert!(count >= 8, "expected a broad rejection corpus, got {count}");
    }

    #[test]
    fn interop_accepted_encodings() {
        // Encodings the oracle's parser accepts; ours must too, byte-exactly.
        let mut count = 0;
        for obj in objects(section(VECTORS, "valid_encodings")) {
            let bytes = hex_vec(text(obj, "proof"));
            let p = SurjectionProof::parse(&bytes).expect("oracle accepts this");
            assert_eq!(p.n_inputs(), number(obj, "n_inputs"));
            assert_eq!(p.n_used(), number(obj, "n_used"));
            assert_eq!(p.serialize(), bytes);
            count += 1;
        }
        assert!(count >= 4);
    }
}
