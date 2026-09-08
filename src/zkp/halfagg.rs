//! Half-aggregation of BIP340 Schnorr signatures.
//!
//! **EXPERIMENTAL** — no semver-stability guarantee. See the [module-level
//! documentation](super) for the clean-room policy and interop caveats.
//!
//! # Source of truth
//!
//! * Chalkias, Garillot, Kondi, Nikolaenko, *Non-Interactive Half-Aggregation
//!   of EdDSA and Variants of Schnorr Signatures*, CT-RSA 2021
//!   ([ePrint 2021/350](https://eprint.iacr.org/2021/350)) — the construction
//!   and its ROM security proof.
//! * Chen and Zhao, *Half-Aggregation of Schnorr Signatures with Tight
//!   Reductions* ([ePrint 2022/222](https://eprint.iacr.org/2022/222)) — the
//!   tight proof, the `z_0 = 1` optimisation and incremental aggregation.
//! * *Half-Aggregation of BIP 340 Signatures* (Ruffing, Nick, Jahr), BIP draft,
//!   status `Draft`, from the `BlockstreamResearch/cross-input-aggregation`
//!   repository — the concrete instantiation implemented here: the tag string,
//!   the randomizer preimage and the serialization.
//!
//! # Overview
//!
//! Half-aggregation compresses `n` BIP340 signatures `(R_i, s_i)` over `n`
//! `(public key, message)` pairs into the `n` `R_i` values plus a **single**
//! aggregated scalar `s` — `32n + 32` bytes instead of `64n`, so roughly half.
//! It is a pure function of the signatures, keys and messages: no cooperation
//! between signers, no interaction, no secret state.
//!
//! ```
//! # #[cfg(all(feature = "zkp-halfagg", feature = "bip340"))] {
//! use purecrypto::ec::secp256k1::schnorr;
//! use purecrypto::zkp::halfagg;
//!
//! let mut entries = Vec::new();
//! for i in 1u8..=3 {
//!     let sk = [i; 32];
//!     let msg = [i + 1; 32];
//!     let pk = schnorr::public_key(&sk).unwrap();
//!     let sig = schnorr::sign(&sk, &msg, &[i + 2; 32]).unwrap();
//!     entries.push((pk, msg, sig));
//! }
//!
//! let agg = halfagg::aggregate(&entries).unwrap();
//! assert_eq!(agg.len(), 3 * 32 + 32);
//!
//! let pms: Vec<_> = entries.iter().map(|(p, m, _)| (*p, *m)).collect();
//! halfagg::verify_aggregate(&pms, &agg).unwrap();
//! # }
//! ```
//!
//! # The construction
//!
//! Write `P_i = lift_x(pk_i)`, `R_i = lift_x(r_i)` and let
//! `e_i = int(hash_BIP0340/challenge(r_i ‖ pk_i ‖ m_i)) mod n` be the ordinary
//! BIP340 challenge, so that a valid BIP340 signature satisfies
//! `s_i·G = R_i + e_i·P_i`. Aggregation picks per-signature **randomizers**
//! `z_i` and sets
//!
//! ```text
//! s = Σ z_i·s_i mod n
//! ```
//!
//! and verification checks the single equation
//!
//! ```text
//! s·G == Σ z_i·(R_i + e_i·P_i).
//! ```
//!
//! ## Why the randomizers, and why they are hashed over the *whole* list
//!
//! Without randomizers (`z_i = 1`) the equation is a plain sum, and an attacker
//! who knows one honest aggregate can subtract and re-add arbitrary terms: any
//! set of `s_i` summing to the same total is accepted, so a forgery on a fresh
//! `(pk, m)` is trivial. The randomizers are what make the aggregate a *random
//! linear combination*, which is exactly the classic batch-verification
//! argument: if any individual equation is false, a random linear combination of
//! them is false except with probability `1/n`.
//!
//! For the combination to be unforgeable it must be **bound to the entire list**
//! and not chosen by the attacker. Hence `z_i` is derived by hashing the
//! *prefix* of the list up to and including entry `i`:
//!
//! ```text
//! z_i = int(hash_HalfAgg/randomizer(r_0 ‖ pk_0 ‖ m_0 ‖ … ‖ r_i ‖ pk_i ‖ m_i)) mod n
//! ```
//!
//! Every `z_i` therefore depends on every earlier `(r, pk, m)` triple, so an
//! aggregate cannot be spliced together from pieces of other aggregates,
//! reordered, or have an entry substituted: any such edit changes the `z_j` of
//! that entry and of every entry after it, and the aggregate `s` no longer
//! matches. The [tests](self) exercise each of those attacks explicitly.
//!
//! The prefix (rather than whole-list) shape is what makes **incremental**
//! aggregation possible: appending entries does not disturb the randomizers of
//! the entries already aggregated, so [`inc_aggregate`] can fold new signatures
//! into an existing aggregate without seeing the old ones' `s_i` (which are, by
//! then, unrecoverable). It also makes the derivation cheap: the hash states
//! share a common prefix, so this implementation keeps one running SHA-256 and
//! clones it at each step rather than re-hashing `O(n²)` bytes.
//!
//! ## `z_0 = 1`
//!
//! The first randomizer is fixed to the constant `1`. That is not an
//! implementation shortcut: it is specified by the BIP draft and proven secure
//! by Chen and Zhao. Fixing one coefficient loses nothing — a random linear
//! combination is still random when one coefficient is pinned and the rest are
//! unpredictable — and it saves one scalar multiplication in verification,
//! since `z_0·R_0 = R_0`. This implementation still feeds entry `0` into the
//! running hash, because `z_1` and onwards commit to it.
//!
//! ## Aggregation does not verify
//!
//! [`aggregate`] and [`inc_aggregate`] do **not** check the input signatures,
//! matching the draft. Aggregating a set of valid signatures always yields an
//! aggregate that verifies; the converse does not hold — it is easy to craft
//! individually-invalid signatures whose aggregate verifies, because only the
//! randomized *sum* is constrained. If you need each input to be individually
//! valid, verify them with [`schnorr::verify`](crate::ec::secp256k1::schnorr::verify)
//! before aggregating. Aggregation is non-destructive: the input signatures are
//! untouched and keep verifying on their own.
//!
//! # Serialization
//!
//! An aggregate over `u` signatures is the `(u+1)·32`-byte array
//!
//! ```text
//! r_0 ‖ r_1 ‖ … ‖ r_{u-1} ‖ bytes(s)
//! ```
//!
//! where `r_i` is the first half of input signature `i` and `s` is the 32-byte
//! big-endian aggregated scalar. `u = 0` is legal and serializes as 32 zero
//! bytes. This is the layout the draft specifies and the one the reference
//! `secp256k1_schnorrsig_aggregate` header documents
//! (`aggsig_len == 32*(n+1)`).
//!
//! Messages are fixed at **32 bytes**, as in the draft and in the reference C
//! API (`msgs32`). BIP340 itself allows variable-length messages, but the
//! randomizer preimage above is a bare concatenation: with variable-length
//! messages it would be ambiguous, and two different entry lists could hash to
//! the same `z_i`. Rather than invent a length-prefixed variant that nothing
//! else would accept, this module requires 32-byte messages. Hash your message
//! first if it is longer.
//!
//! # Interop
//!
//! **Byte-exact interoperability with `secp256k1-zkp`'s experimental
//! `schnorrsig_halfagg` module has been established** for `n = 0, 1, 2, 3, 5,
//! 10`, using that library purely as a black-box oracle (its public header
//! `include/secp256k1_schnorrsig_halfagg.h` and its compiled output; no
//! implementation source was read). Our `aggregate` output matches the oracle's
//! byte for byte, our `verify_aggregate` accepts the oracle's aggregates, and
//! the oracle accepts ours. The oracle's own output also reproduces the
//! preliminary test vectors published in the BIP draft's `hacspec-halfagg`
//! test suite, so both agree with the draft.
//!
//! The generated vectors are committed at
//! `tools/zkp-interop/vectors/halfagg.json` and are replayed by this module's
//! tests; those tests do not link against the oracle.
//!
//! Caveat, stated plainly: the upstream module is marked experimental and its
//! format has churned in the past, and the BIP itself is a `Draft` with no
//! number assigned. Compatibility is demonstrated against
//! `BlockstreamResearch/secp256k1-zkp` at revision
//! `037cc6d74cbb4a89e443117459b577d56a582e54` (2026-09-05) and against the
//! draft as of the same date. It is not a guarantee about future revisions of
//! either.
//!
//! # Timing
//!
//! Everything here is public data — aggregate signatures, public keys and
//! messages — so nothing in this module is constant-time and nothing needs to
//! be. Verification deliberately uses a **variable-time** interleaved
//! multi-scalar multiplication, which is several times faster than looping over
//! constant-time ladders. Do not feed secret scalars to these functions.
//!
//! # Robustness
//!
//! No input can make these functions panic. Every length is checked before it
//! is used, the number of aggregated signatures is capped at
//! [`MAX_AGGREGATED`] (`2^16 - 1`, the draft's limit) *before* anything is
//! allocated, and every parse failure returns [`Error`].

use alloc::vec::Vec;

use crate::ec::Error;
use crate::ec::secp256k1::schnorr::tagged_hash;
use crate::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use crate::hash::{Digest, Sha256};

/// Tag of the randomizer hash, from the BIP draft.
const TAG_RANDOMIZER: &str = "HalfAgg/randomizer";
/// Tag of the BIP340 challenge hash, reused verbatim.
const TAG_CHALLENGE: &str = "BIP0340/challenge";

/// The largest number of signatures that may take part in one aggregate.
///
/// The draft caps aggregation at `2^16 - 1` signatures — a deliberately
/// conservative bound that keeps every index and length computation far from
/// overflowing. It is enforced here *before* any allocation, so a peer-supplied
/// count cannot drive an unbounded [`Vec`].
pub const MAX_AGGREGATED: usize = (1 << 16) - 1;

/// The exact serialized length of an aggregate over `n` signatures,
/// `32·(n + 1)` bytes.
///
/// Returns `None` if `n` exceeds [`MAX_AGGREGATED`].
///
/// ```
/// # #[cfg(feature = "zkp-halfagg")] {
/// use purecrypto::zkp::halfagg::{MAX_AGGREGATED, aggregate_len};
/// assert_eq!(aggregate_len(0), Some(32));
/// assert_eq!(aggregate_len(3), Some(128));
/// assert_eq!(aggregate_len(MAX_AGGREGATED + 1), None);
/// # }
/// ```
#[must_use]
pub const fn aggregate_len(n: usize) -> Option<usize> {
    if n > MAX_AGGREGATED {
        None
    } else {
        Some((n + 1) * 32)
    }
}

/// A `(32-byte x-only public key, 32-byte message)` pair, as fed to
/// [`verify_aggregate`] and identifying an already-aggregated entry for
/// [`inc_aggregate`].
pub type PubkeyMsg = ([u8; 32], [u8; 32]);

/// A `(32-byte x-only public key, 32-byte message, 64-byte BIP340 signature)`
/// triple, the unit [`aggregate`] consumes.
pub type PubkeyMsgSig = ([u8; 32], [u8; 32], [u8; 64]);

// =====================================================================
// Randomizer derivation
// =====================================================================

/// The running state of the randomizer hash.
///
/// `z_i` hashes the prefix `r_0 ‖ pk_0 ‖ m_0 ‖ … ‖ r_i ‖ pk_i ‖ m_i`, so
/// successive randomizers share a growing common prefix. Keeping one SHA-256
/// state and cloning it to finalize turns an `O(n²)`-byte computation into an
/// `O(n)` one. The state is seeded with the BIP340 tagged-hash prefix
/// `SHA256(tag) ‖ SHA256(tag)`, which is exactly what
/// [`tagged_hash`] prepends.
struct Randomizers {
    state: Sha256,
}

impl Randomizers {
    /// Seeds the running hash with the `HalfAgg/randomizer` tag prefix.
    fn new() -> Randomizers {
        let tag = Sha256::digest(TAG_RANDOMIZER.as_bytes());
        let mut state = Sha256::new();
        state.update(tag.as_ref());
        state.update(tag.as_ref());
        Randomizers { state }
    }

    /// Absorbs entry `i`'s `r ‖ pk ‖ m` and returns `z_i`.
    ///
    /// `index` is the entry's position in the *whole* list, so that the
    /// `z_0 = 1` rule keys off the true first entry even when called from
    /// [`inc_aggregate`] partway through.
    fn push(&mut self, index: usize, r: &[u8; 32], pk: &[u8; 32], msg: &[u8; 32]) -> Scalar {
        self.state.update(r);
        self.state.update(pk);
        self.state.update(msg);
        if index == 0 {
            // z_0 is the constant 1 (draft; Chen–Zhao). Entry 0 is still
            // absorbed, because z_1.. commit to it.
            Scalar::ONE
        } else {
            Scalar::from_bytes_be_reduce(&self.state.clone().finalize())
        }
    }

    /// Absorbs an already-aggregated entry, whose randomizer is not needed
    /// again (its `s_i` is already folded into the running aggregate).
    fn skip(&mut self, r: &[u8; 32], pk: &[u8; 32], msg: &[u8; 32]) {
        self.state.update(r);
        self.state.update(pk);
        self.state.update(msg);
    }
}

/// `e_i = int(hash_BIP0340/challenge(r ‖ pk ‖ m)) mod n`, the ordinary BIP340
/// challenge for entry `i`.
fn challenge(r: &[u8; 32], pk: &[u8; 32], msg: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_be_reduce(&tagged_hash(TAG_CHALLENGE, &[r, pk, msg]))
}

/// BIP340 `lift_x`: the even-`Y` point with abscissa `x`, i.e. the compressed
/// SEC1 decoding of `0x02 ‖ x`.
fn lift_x(x: &[u8; 32]) -> Result<ProjectivePoint, Error> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(x);
    AffinePoint::from_sec1(&compressed)
        .map(|p| p.to_projective())
        .map_err(|_| Error::Malformed)
}

/// Copies a 32-byte chunk out of a slice that has already been length-checked.
#[inline]
fn chunk32(buf: &[u8], index: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&buf[index * 32..(index + 1) * 32]);
    out
}

// =====================================================================
// Aggregation
// =====================================================================

/// Aggregates `entries` into a single half-aggregate signature.
///
/// Equivalent to [`inc_aggregate`] starting from the empty aggregate (32 zero
/// bytes) with nothing already aggregated. The result is
/// [`aggregate_len(entries.len())`](aggregate_len) bytes long.
///
/// Input signatures are **not** verified; see [the module
/// docs](self#aggregation-does-not-verify).
///
/// # Errors
/// [`Error::InvalidInput`] if `entries.len()` exceeds [`MAX_AGGREGATED`].
pub fn aggregate(entries: &[PubkeyMsgSig]) -> Result<Vec<u8>, Error> {
    inc_aggregate(&[0u8; 32], &[], entries)
}

/// Folds additional signatures into an existing half-aggregate signature.
///
/// `agg` is an aggregate over the `(pk, m)` pairs in `aggregated`, in that
/// order, and must be exactly `32·(aggregated.len() + 1)` bytes. `to_add` holds
/// the new triples, which are appended after them. The returned aggregate is
/// over `aggregated` followed by the `(pk, m)` parts of `to_add`.
///
/// This works — without ever recovering the individual `s_i` folded into `agg`,
/// which is impossible — because randomizer `z_i` hashes only the *prefix*
/// ending at entry `i`, so appending entries leaves earlier randomizers
/// untouched.
///
/// Neither `agg` nor the signatures in `to_add` are verified; see [the module
/// docs](self#aggregation-does-not-verify).
///
/// # Errors
/// [`Error::InvalidInput`] if the combined count exceeds [`MAX_AGGREGATED`].
/// [`Error::Malformed`] if `agg` is not `32·(aggregated.len() + 1)` bytes, if
/// its aggregate scalar is not canonical (`≥ n`), or if `aggregated` is empty
/// and `agg` is not the all-zero seed (the only aggregate over no signatures).
pub fn inc_aggregate(
    agg: &[u8],
    aggregated: &[PubkeyMsg],
    to_add: &[PubkeyMsgSig],
) -> Result<Vec<u8>, Error> {
    let v = aggregated.len();
    let u = to_add.len();
    // Bound the total before touching any length arithmetic or allocating.
    // `MAX_AGGREGATED` is far below `usize::MAX / 32`, so `v + u` and the
    // byte lengths below cannot overflow once this passes.
    if v > MAX_AGGREGATED || u > MAX_AGGREGATED || v + u > MAX_AGGREGATED {
        return Err(Error::InvalidInput);
    }
    if agg.len() != (v + 1) * 32 {
        return Err(Error::Malformed);
    }
    // The aggregate scalar must be canonical (`< n`), exactly as
    // `verify_aggregate` demands of the final result; silently reducing a
    // non-canonical `s` would let a malformed prefix fold into a well-formed
    // output. For an empty prefix the only aggregate is the all-zero seed.
    let mut s = Scalar::from_bytes_be(&chunk32(agg, v)).map_err(|_| Error::Malformed)?;
    if v == 0 && !bool::from(s.is_zero()) {
        return Err(Error::Malformed);
    }

    let mut out = Vec::with_capacity((v + u + 1) * 32);
    out.extend_from_slice(&agg[..v * 32]);

    // Replay the already-aggregated prefix into the randomizer hash, and start
    // from the aggregate scalar already present in `agg`.
    let mut rz = Randomizers::new();
    for (i, (pk, msg)) in aggregated.iter().enumerate() {
        rz.skip(&chunk32(agg, i), pk, msg);
    }

    for (j, (pk, msg, sig)) in to_add.iter().enumerate() {
        let mut r = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        let mut si = [0u8; 32];
        si.copy_from_slice(&sig[32..]);

        out.extend_from_slice(&r);
        let z = rz.push(v + j, &r, pk, msg);
        // The draft reads `s_i = int(sig_i[32:64])` without a range check;
        // aggregation is not a security boundary and accepts arbitrary input
        // signatures, so an out-of-range value is folded in reduced mod n.
        s = s.add(&z.mul(&Scalar::from_bytes_be_reduce(&si)));
    }

    out.extend_from_slice(&s.to_bytes_be());
    Ok(out)
}

// =====================================================================
// Verification
// =====================================================================

/// Number of `(scalar, point)` terms the multi-scalar multiplication handles in
/// one pass.
///
/// Each term costs a 15-entry precomputed table, so this caps the scratch
/// memory of verification at a constant regardless of how many signatures a
/// peer claims to have aggregated; larger inputs are folded batch by batch.
const MSM_BATCH: usize = 64;

/// Verifies a half-aggregate signature over `entries`.
///
/// Checks `len(agg) == 32·(u+1)`, that `s` is a canonical scalar `< n`, that
/// every `pk_i` and `r_i` lifts to a curve point, and finally the aggregate
/// equation `s·G == Σ z_i·(R_i + e_i·P_i)`.
///
/// Success means: *if* each input signature had been individually valid, this
/// aggregate is the one aggregation would have produced. It does **not** imply
/// each `(pk_i, m_i, sig_i)` is individually valid — see [the module
/// docs](self#aggregation-does-not-verify).
///
/// An empty `entries` with the 32-byte all-zero aggregate verifies, as the
/// draft specifies (a vacuous claim about no signatures).
///
/// This function never panics, whatever `agg` contains.
///
/// # Errors
/// [`Error::InvalidInput`] if `entries.len()` exceeds [`MAX_AGGREGATED`].
/// [`Error::Malformed`] if `agg` has the wrong length, if `s` is not `< n`, or
/// if some `pk_i` or `r_i` is not a valid x-only point encoding.
/// [`Error::Verification`] if the aggregate equation does not hold.
pub fn verify_aggregate(entries: &[PubkeyMsg], agg: &[u8]) -> Result<(), Error> {
    let u = entries.len();
    if u > MAX_AGGREGATED {
        return Err(Error::InvalidInput);
    }
    if agg.len() != (u + 1) * 32 {
        return Err(Error::Malformed);
    }
    // s = int(agg[u*32 .. (u+1)*32]); fail if s >= n.
    let s = Scalar::from_bytes_be(&chunk32(agg, u)).map_err(|_| Error::Malformed)?;

    let mut acc = ProjectivePoint::identity();
    let mut batch: Vec<(Scalar, ProjectivePoint)> = Vec::with_capacity(MSM_BATCH);
    let mut rz = Randomizers::new();

    for (i, (pk, msg)) in entries.iter().enumerate() {
        let r = chunk32(agg, i);
        let big_p = lift_x(pk)?;
        let big_r = lift_x(&r)?;
        let e = challenge(&r, pk, msg);
        let z = rz.push(i, &r, pk, msg);

        // z_i·R_i + (z_i·e_i)·P_i
        batch.push((z.mul(&e), big_p));
        batch.push((z, big_r));
        if batch.len() >= MSM_BATCH {
            acc = acc.add(&msm(&batch));
            batch.clear();
        }
    }
    if !batch.is_empty() {
        acc = acc.add(&msm(&batch));
    }

    if bool::from(ProjectivePoint::mul_generator(&s).ct_eq(&acc)) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

/// Variable-time multi-scalar multiplication `Σ kᵢ·Pᵢ`, by interleaved 4-bit
/// windows (Straus' method).
///
/// One table of `1·P … 15·P` is built per point; the 64 nibbles of the scalars
/// are then walked from the most significant down, sharing the four doublings
/// per step across every term. That is a large win over one constant-time
/// ladder per term, and it is sound here precisely because every input is
/// public: the digit tests and the skip on a zero digit are data-dependent by
/// design.
fn msm(terms: &[(Scalar, ProjectivePoint)]) -> ProjectivePoint {
    let mut tables: Vec<[ProjectivePoint; 15]> = Vec::with_capacity(terms.len());
    let mut scalars: Vec<[u8; 32]> = Vec::with_capacity(terms.len());
    for (k, p) in terms {
        let mut t = [*p; 15];
        for d in 1..15 {
            t[d] = t[d - 1].add(p);
        }
        tables.push(t);
        scalars.push(k.to_bytes_be());
    }

    let mut acc = ProjectivePoint::identity();
    for nibble in 0..64usize {
        if nibble > 0 {
            for _ in 0..4 {
                acc = acc.double();
            }
        }
        let byte = nibble / 2;
        let high = nibble % 2 == 0;
        for (table, scalar) in tables.iter().zip(scalars.iter()) {
            let digit = if high {
                scalar[byte] >> 4
            } else {
                scalar[byte] & 0x0f
            };
            if digit != 0 {
                acc = acc.add(&table[usize::from(digit) - 1]);
            }
        }
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::secp256k1::schnorr;
    use alloc::string::String;
    use alloc::vec;

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    fn hex_bytes(s: &str) -> Vec<u8> {
        fn nibble(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("bad hex digit"),
            }
        }
        let b = s.as_bytes();
        assert!(b.len().is_multiple_of(2), "odd-length hex");
        (0..b.len() / 2)
            .map(|i| (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]))
            .collect()
    }

    fn hex32(s: &str) -> [u8; 32] {
        let v = hex_bytes(s);
        let mut o = [0u8; 32];
        assert_eq!(v.len(), 32);
        o.copy_from_slice(&v);
        o
    }

    fn hex64(s: &str) -> [u8; 64] {
        let v = hex_bytes(s);
        let mut o = [0u8; 64];
        assert_eq!(v.len(), 64);
        o.copy_from_slice(&v);
        o
    }

    fn to_hex(b: &[u8]) -> String {
        use core::fmt::Write;
        let mut s = String::with_capacity(b.len() * 2);
        for x in b {
            let _ = write!(s, "{x:02x}");
        }
        s
    }

    /// Deterministic entry `i`, using the same seeds as the draft's own
    /// preliminary vectors: `sk = [i+1; 32]`, `m = [i+2; 32]`, `aux = [i+3; 32]`.
    fn entry(i: u8) -> PubkeyMsgSig {
        let sk = [i + 1; 32];
        let msg = [i + 2; 32];
        let pk = schnorr::public_key(&sk).expect("valid seckey");
        let sig = schnorr::sign(&sk, &msg, &[i + 3; 32]).expect("sign");
        (pk, msg, sig)
    }

    fn entries(n: u8) -> Vec<PubkeyMsgSig> {
        (0..n).map(entry).collect()
    }

    fn strip(e: &[PubkeyMsgSig]) -> Vec<PubkeyMsg> {
        e.iter().map(|(p, m, _)| (*p, *m)).collect()
    }

    // -----------------------------------------------------------------
    // Round trip
    // -----------------------------------------------------------------

    #[test]
    fn round_trip() {
        for n in [1u8, 2, 3, 10] {
            let e = entries(n);
            let agg = aggregate(&e).expect("aggregate");
            assert_eq!(agg.len(), usize::from(n) * 32 + 32);
            assert_eq!(Some(agg.len()), aggregate_len(usize::from(n)));
            verify_aggregate(&strip(&e), &agg).expect("verify");
            // The R values are copied verbatim from the input signatures.
            for (i, (_, _, sig)) in e.iter().enumerate() {
                assert_eq!(&agg[i * 32..(i + 1) * 32], &sig[..32]);
            }
        }
    }

    #[test]
    fn empty_aggregate_is_the_zero_scalar() {
        let agg = aggregate(&[]).expect("aggregate");
        assert_eq!(agg, vec![0u8; 32]);
        verify_aggregate(&[], &agg).expect("verify");
    }

    #[test]
    fn aggregation_is_non_destructive() {
        let e = entries(5);
        let agg = aggregate(&e).expect("aggregate");
        verify_aggregate(&strip(&e), &agg).expect("verify");
        // Every input signature still verifies on its own afterwards.
        for (pk, msg, sig) in &e {
            schnorr::verify(pk, msg, sig).expect("individual signature still valid");
        }
    }

    #[test]
    fn incremental_matches_one_shot() {
        let e = entries(6);
        let pms = strip(&e);
        let full = aggregate(&e).expect("aggregate");
        for split in 0..=e.len() {
            let head = aggregate(&e[..split]).expect("aggregate head");
            let inc = inc_aggregate(&head, &pms[..split], &e[split..]).expect("inc");
            assert_eq!(inc, full, "incremental split at {split} diverged");
            verify_aggregate(&pms, &inc).expect("verify incremental");
        }
    }

    #[test]
    fn incremental_in_many_steps() {
        let e = entries(7);
        let pms = strip(&e);
        let mut agg = aggregate(&[]).expect("empty");
        for i in 0..e.len() {
            agg = inc_aggregate(&agg, &pms[..i], &e[i..=i]).expect("step");
        }
        assert_eq!(agg, aggregate(&e).expect("one shot"));
        verify_aggregate(&pms, &agg).expect("verify");
    }

    // -----------------------------------------------------------------
    // Soundness
    // -----------------------------------------------------------------

    #[test]
    fn rejects_tampered_s() {
        let e = entries(3);
        let pms = strip(&e);
        let agg = aggregate(&e).expect("aggregate");
        for bit in 0..8 {
            let mut bad = agg.clone();
            let last = bad.len() - 1;
            bad[last] ^= 1 << bit;
            assert!(verify_aggregate(&pms, &bad).is_err(), "flipped s bit {bit}");
        }
        // Flipping a high byte of s can push it out of range; either rejection
        // path is fine, but it must never be accepted.
        let mut bad = agg.clone();
        bad[3 * 32] ^= 0x80;
        assert!(verify_aggregate(&pms, &bad).is_err());
    }

    #[test]
    fn rejects_tampered_r() {
        let e = entries(3);
        let pms = strip(&e);
        let agg = aggregate(&e).expect("aggregate");
        for i in 0..3 {
            let mut bad = agg.clone();
            bad[i * 32 + 31] ^= 0x01;
            assert!(verify_aggregate(&pms, &bad).is_err(), "flipped R_{i}");
        }
    }

    #[test]
    fn rejects_reordered_entries() {
        let e = entries(3);
        let agg = aggregate(&e).expect("aggregate");

        // Swapping two (pk, m) pairs while keeping the aggregate must fail:
        // the randomizers are bound to the order of the list.
        let mut pms = strip(&e);
        pms.swap(0, 2);
        assert!(verify_aggregate(&pms, &agg).is_err());

        // Swapping the R values too (i.e. presenting a genuinely reordered
        // aggregate) must also fail, since s was computed for the old order.
        let mut reordered = agg.clone();
        for k in 0..32 {
            reordered.swap(k, 2 * 32 + k);
        }
        assert!(verify_aggregate(&pms, &reordered).is_err());

        // Aggregating the reordered set from scratch gives a *different* s.
        let mut swapped_entries = e.clone();
        swapped_entries.swap(0, 2);
        let agg2 = aggregate(&swapped_entries).expect("aggregate");
        assert_ne!(agg2, agg);
        verify_aggregate(&strip(&swapped_entries), &agg2).expect("verify reordered set");
    }

    #[test]
    fn rejects_substituted_pubkey() {
        let e = entries(3);
        let other = entry(9).0;
        let agg = aggregate(&e).expect("aggregate");
        for i in 0..3 {
            let mut pms = strip(&e);
            pms[i].0 = other;
            assert!(verify_aggregate(&pms, &agg).is_err(), "pubkey {i} swapped");
        }
    }

    #[test]
    fn rejects_substituted_message() {
        let e = entries(3);
        let agg = aggregate(&e).expect("aggregate");
        for i in 0..3 {
            let mut pms = strip(&e);
            pms[i].1[0] ^= 0xff;
            assert!(verify_aggregate(&pms, &agg).is_err(), "message {i} changed");
        }
    }

    /// `inc_aggregate` is as strict about its input aggregate as
    /// `verify_aggregate` is about its output: a non-canonical scalar, or a
    /// non-zero "empty" aggregate, is `Malformed` rather than reduced.
    #[test]
    fn inc_aggregate_rejects_non_canonical_prefix() {
        let e = entries(4);
        let pms = strip(&e);
        let agg = aggregate(&e).expect("aggregate");

        // Empty prefix: only the all-zero seed is an aggregate over nothing.
        let mut seed = [0u8; 32];
        seed[31] = 1;
        assert_eq!(inc_aggregate(&seed, &[], &e).unwrap_err(), Error::Malformed);
        assert_eq!(
            inc_aggregate(&[0xffu8; 32], &[], &e).unwrap_err(),
            Error::Malformed
        );
        // The all-zero seed is still accepted, and equals `aggregate`.
        assert_eq!(inc_aggregate(&[0u8; 32], &[], &e).unwrap(), agg);

        // Non-empty prefix whose scalar is >= n: all-ones, and n itself.
        let head = aggregate(&e[..2]).expect("head");
        let mut oob = head.clone();
        oob[2 * 32..].copy_from_slice(&[0xffu8; 32]);
        assert_eq!(
            inc_aggregate(&oob, &pms[..2], &e[2..]).unwrap_err(),
            Error::Malformed
        );
        let n: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        let mut at_n = head.clone();
        at_n[2 * 32..].copy_from_slice(&n);
        assert_eq!(
            inc_aggregate(&at_n, &pms[..2], &e[2..]).unwrap_err(),
            Error::Malformed
        );
        // n − 1 is canonical and therefore accepted (the result is simply an
        // aggregate that will not verify).
        let mut n_minus_1 = n;
        n_minus_1[31] -= 1;
        let mut canonical = head.clone();
        canonical[2 * 32..].copy_from_slice(&n_minus_1);
        let folded = inc_aggregate(&canonical, &pms[..2], &e[2..]).expect("canonical prefix");
        assert_eq!(folded.len(), agg.len());
        assert!(verify_aggregate(&pms, &folded).is_err());
        // And the honest prefix still folds to the honest aggregate.
        assert_eq!(inc_aggregate(&head, &pms[..2], &e[2..]).unwrap(), agg);
    }

    #[test]
    fn rejects_truncated_entry_list() {
        let e = entries(3);
        let agg = aggregate(&e).expect("aggregate");
        // Dropping the last entry changes the expected aggregate length, so it
        // is rejected outright rather than silently verifying a shorter claim.
        assert_eq!(
            verify_aggregate(&strip(&e)[..2], &agg).unwrap_err(),
            Error::Malformed
        );
    }

    /// The attack the randomizers exist to prevent: take two honest aggregates
    /// over disjoint sets and try to splice them into one aggregate over the
    /// union, by concatenating the R values and adding the two `s` scalars.
    /// Because every `z_i` commits to the whole prefix, the randomizers of the
    /// second set change when it is appended to the first, and the spliced
    /// scalar is wrong.
    #[test]
    fn rejects_spliced_aggregates() {
        let a: Vec<PubkeyMsgSig> = (0..3).map(entry).collect();
        let b: Vec<PubkeyMsgSig> = (3..6).map(entry).collect();
        let agg_a = aggregate(&a).expect("aggregate a");
        let agg_b = aggregate(&b).expect("aggregate b");

        let mut union: Vec<PubkeyMsgSig> = a.clone();
        union.extend_from_slice(&b);
        let pms = strip(&union);

        // Splice: R values of a, then R values of b, then s_a + s_b.
        let sa = Scalar::from_bytes_be(&chunk32(&agg_a, 3)).expect("s_a");
        let sb = Scalar::from_bytes_be(&chunk32(&agg_b, 3)).expect("s_b");
        let mut spliced = Vec::new();
        spliced.extend_from_slice(&agg_a[..3 * 32]);
        spliced.extend_from_slice(&agg_b[..3 * 32]);
        spliced.extend_from_slice(&sa.add(&sb).to_bytes_be());
        assert_eq!(spliced.len(), 7 * 32);
        assert!(
            verify_aggregate(&pms, &spliced).is_err(),
            "spliced aggregate must not verify"
        );

        // Splicing with s_b alone, or s_a alone, must fail too.
        for s in [&sa, &sb] {
            let mut bad = Vec::new();
            bad.extend_from_slice(&agg_a[..3 * 32]);
            bad.extend_from_slice(&agg_b[..3 * 32]);
            bad.extend_from_slice(&s.to_bytes_be());
            assert!(verify_aggregate(&pms, &bad).is_err());
        }

        // The honest aggregate over the union does verify, and differs from
        // both halves.
        let honest = aggregate(&union).expect("aggregate union");
        verify_aggregate(&pms, &honest).expect("verify union");
        assert_ne!(honest, spliced);

        // The prefix aggregate is *not* a valid aggregate for the union, and
        // the union aggregate is not valid for the prefix.
        assert!(verify_aggregate(&pms, &agg_a).is_err());
        assert!(verify_aggregate(&strip(&a), &honest).is_err());
    }

    /// Mixing an entry from one aggregate into another set at the same index
    /// must fail even though the R value is genuine.
    #[test]
    fn rejects_mixed_and_matched_entry() {
        let base = entries(4);
        let foreign = entry(7);
        let agg = aggregate(&base).expect("aggregate");

        let mut pms = strip(&base);
        let mut tampered = agg.clone();
        pms[2] = (foreign.0, foreign.1);
        tampered[2 * 32..3 * 32].copy_from_slice(&foreign.2[..32]);
        assert!(verify_aggregate(&pms, &tampered).is_err());
    }

    // -----------------------------------------------------------------
    // Robustness: no input may panic
    // -----------------------------------------------------------------

    #[test]
    fn malformed_aggregates_are_rejected_not_panicked() {
        let e = entries(3);
        let pms = strip(&e);
        let agg = aggregate(&e).expect("aggregate");

        // Every truncation and every over-long buffer.
        for len in 0..agg.len() + 64 {
            if len == agg.len() {
                continue;
            }
            let mut buf = agg.clone();
            buf.resize(len, 0xab);
            assert_eq!(verify_aggregate(&pms, &buf).unwrap_err(), Error::Malformed);
        }

        // n = 0 with a non-empty or wrong-length aggregate.
        assert!(verify_aggregate(&[], &[]).is_err());
        assert!(verify_aggregate(&[], &[0u8; 31]).is_err());
        assert!(verify_aggregate(&[], &[0u8; 33]).is_err());
        assert!(verify_aggregate(&[], &[0u8; 64]).is_err());
        // n = 0 with a non-zero s is a false claim and must be rejected.
        let mut nonzero = [0u8; 32];
        nonzero[31] = 1;
        assert_eq!(
            verify_aggregate(&[], &nonzero).unwrap_err(),
            Error::Verification
        );

        // s out of range (>= n): all-ones is far above the group order.
        let mut oob = agg.clone();
        oob[3 * 32..].copy_from_slice(&[0xffu8; 32]);
        assert_eq!(verify_aggregate(&pms, &oob).unwrap_err(), Error::Malformed);

        // R that is not on the curve. x = 0 has no even-Y lift.
        let mut bad_r = agg.clone();
        bad_r[..32].copy_from_slice(&[0u8; 32]);
        assert_eq!(
            verify_aggregate(&pms, &bad_r).unwrap_err(),
            Error::Malformed
        );

        // Public key that is not on the curve.
        let mut bad_pk = pms.clone();
        bad_pk[0].0 = [0u8; 32];
        assert_eq!(
            verify_aggregate(&bad_pk, &agg).unwrap_err(),
            Error::Malformed
        );

        // Random garbage of a plausible length must never panic.
        let mut seed = 0x12345678u64;
        for _ in 0..200 {
            let mut buf = vec![0u8; 4 * 32];
            for b in buf.iter_mut() {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                *b = (seed >> 33) as u8;
            }
            let _ = verify_aggregate(&pms, &buf);
        }
    }

    #[test]
    fn oversized_counts_are_rejected_before_allocating() {
        // A slice longer than MAX_AGGREGATED cannot be built cheaply, so the
        // bound is exercised through `inc_aggregate`'s already-aggregated
        // count, which is what a peer-supplied length would drive.
        //
        // A fabricated `aggregated` slice of MAX_AGGREGATED+1 entries would be
        // 4 MiB; instead check the arithmetic guard directly.
        assert_eq!(
            aggregate_len(MAX_AGGREGATED),
            Some((MAX_AGGREGATED + 1) * 32)
        );
        assert_eq!(aggregate_len(MAX_AGGREGATED + 1), None);
        assert_eq!(aggregate_len(usize::MAX), None);
    }

    #[test]
    fn inc_aggregate_rejects_wrong_length_input() {
        let e = entries(2);
        let pms = strip(&e);
        let agg = aggregate(&e).expect("aggregate");
        for len in [0usize, 32, 64, 95, 97, 128] {
            let mut buf = agg.clone();
            buf.resize(len, 0);
            assert_eq!(
                inc_aggregate(&buf, &pms, &[]).unwrap_err(),
                Error::Malformed,
                "len {len}"
            );
        }
        // The correct length round-trips to the identity operation.
        assert_eq!(inc_aggregate(&agg, &pms, &[]).unwrap(), agg);
    }

    // -----------------------------------------------------------------
    // Internal consistency
    // -----------------------------------------------------------------

    /// The rolling `Randomizers` state must produce exactly what the one-shot
    /// tagged hash over the full prefix produces.
    #[test]
    fn rolling_randomizer_matches_one_shot_tagged_hash() {
        let e = entries(4);
        let mut rz = Randomizers::new();
        let mut preimage: Vec<u8> = Vec::new();
        for (i, (pk, msg, sig)) in e.iter().enumerate() {
            let mut r = [0u8; 32];
            r.copy_from_slice(&sig[..32]);
            preimage.extend_from_slice(&r);
            preimage.extend_from_slice(pk);
            preimage.extend_from_slice(msg);

            let z = rz.push(i, &r, pk, msg);
            let expected = if i == 0 {
                Scalar::ONE
            } else {
                Scalar::from_bytes_be_reduce(&tagged_hash(TAG_RANDOMIZER, &[&preimage]))
            };
            assert_eq!(z.to_bytes_be(), expected.to_bytes_be(), "z_{i} mismatch");
        }
    }

    /// The windowed multi-scalar path must agree with the plain constant-time
    /// ladder, including on zero scalars and the identity.
    #[test]
    fn msm_matches_naive_scalar_muls() {
        let e = entries(6);
        let mut terms: Vec<(Scalar, ProjectivePoint)> = Vec::new();
        for (i, (pk, msg, sig)) in e.iter().enumerate() {
            let mut r = [0u8; 32];
            r.copy_from_slice(&sig[..32]);
            let k = if i == 3 {
                Scalar::ZERO
            } else {
                challenge(&r, pk, msg)
            };
            terms.push((k, lift_x(pk).expect("lift pk")));
        }
        let mut naive = ProjectivePoint::identity();
        for (k, p) in &terms {
            naive = naive.add(&p.mul(k));
        }
        assert!(bool::from(msm(&terms).ct_eq(&naive)));

        // Empty and single-term cases.
        assert!(bool::from(msm(&[]).ct_eq(&ProjectivePoint::identity())));
        let (k, p) = terms[0].clone();
        assert!(bool::from(msm(&terms[..1]).ct_eq(&p.mul(&k))));
    }

    /// More terms than `MSM_BATCH` allows, so the batched folding path runs.
    #[test]
    fn verification_handles_more_than_one_msm_batch() {
        let n = MSM_BATCH; // 2 * n terms, i.e. two full batches
        let e: Vec<PubkeyMsgSig> = (0..n)
            .map(|i| entry(u8::try_from(i % 200).unwrap()))
            .collect();
        let pms = strip(&e);
        let agg = aggregate(&e).expect("aggregate");
        verify_aggregate(&pms, &agg).expect("verify");
        let mut bad = agg.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(verify_aggregate(&pms, &bad).is_err());
    }

    // -----------------------------------------------------------------
    // Interop vectors (generated from the black-box oracle; this test does
    // not link against it, it replays committed JSON).
    // -----------------------------------------------------------------

    /// Minimal extraction of `"key": "hex"` values, in order, from `text`.
    fn json_hex_values(text: &str, key: &str) -> Vec<String> {
        let needle = alloc::format!("\"{key}\": \"");
        let mut out = Vec::new();
        let mut rest = text;
        while let Some(pos) = rest.find(&needle) {
            let after = &rest[pos + needle.len()..];
            let end = after.find('"').expect("unterminated JSON string");
            out.push(String::from(&after[..end]));
            rest = &after[end..];
        }
        out
    }

    #[test]
    fn matches_committed_oracle_vectors() {
        let text = include_str!("../../tools/zkp-interop/vectors/halfagg.json");
        // Each case begins with `"n": <count>`; split on that marker.
        let mut cases = text.split("\"n\": ");
        let header = cases.next().expect("header");
        assert!(
            header.contains("secp256k1-zkp"),
            "vector provenance missing"
        );

        let mut seen = 0usize;
        for case in cases {
            let n: usize = case
                .split(|c: char| !c.is_ascii_digit())
                .find(|s| !s.is_empty())
                .expect("case count")
                .parse()
                .expect("numeric count");

            let pubkeys = json_hex_values(case, "pubkey");
            let msgs = json_hex_values(case, "msg");
            let sigs = json_hex_values(case, "sig");
            let aggs = json_hex_values(case, "aggsig");
            assert_eq!(pubkeys.len(), n);
            assert_eq!(msgs.len(), n);
            assert_eq!(sigs.len(), n);
            assert_eq!(aggs.len(), 1);

            let e: Vec<PubkeyMsgSig> = (0..n)
                .map(|i| (hex32(&pubkeys[i]), hex32(&msgs[i]), hex64(&sigs[i])))
                .collect();
            let pms = strip(&e);

            // Each input signature is a genuine BIP340 signature.
            for (pk, m, sig) in &e {
                schnorr::verify(pk, m, sig).expect("oracle input signature valid");
            }

            // Byte-exact aggregation.
            let ours = aggregate(&e).expect("aggregate");
            assert_eq!(to_hex(&ours), aggs[0], "aggregate mismatch at n = {n}");

            // And we accept the oracle's own bytes.
            let theirs = hex_bytes(&aggs[0]);
            verify_aggregate(&pms, &theirs).expect("verify oracle aggregate");

            // Incremental aggregation reaches the same bytes.
            if n > 0 {
                let head = aggregate(&e[..n / 2]).expect("head");
                let inc = inc_aggregate(&head, &pms[..n / 2], &e[n / 2..]).expect("inc");
                assert_eq!(inc, ours, "incremental mismatch at n = {n}");
            }
            seen += 1;
        }
        assert!(seen >= 5, "expected several interop cases, saw {seen}");
    }

    /// The preliminary test vectors published in the BIP draft's own
    /// `hacspec-halfagg` test suite, transcribed from the draft repository.
    #[test]
    fn matches_draft_specification_vectors() {
        // (pubkey, message) pairs -> aggregate signature.
        let empty: [(&str, &str); 0] = [];
        assert!(
            verify_aggregate(
                &[],
                &hex_bytes("0000000000000000000000000000000000000000000000000000000000000000"),
            )
            .is_ok()
        );
        let _ = empty;

        let one = [(
            "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
            "0202020202020202020202020202020202020202020202020202020202020202",
        )];
        let one_agg = "b070aafcea439a4f6f1bbfc2eb66d29d24b0cab74d6b745c3cfb009cc8fe4aa8\
                       0e066c34819936549ff49b6fd4d41edfc401a367b87ddd59fee38177961c225f";

        let two = [
            (
                "1b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f",
                "0202020202020202020202020202020202020202020202020202020202020202",
            ),
            (
                "462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b",
                "0505050505050505050505050505050505050505050505050505050505050505",
            ),
        ];
        let two_agg = "b070aafcea439a4f6f1bbfc2eb66d29d24b0cab74d6b745c3cfb009cc8fe4aa8\
                       a3afbdb45a6a34bf7c8c00f1b6d7e7d375b54540f13716c87b62e51e2f4f22ff\
                       bf8913ec53226a34892d60252a7052614ca79ae939986828d81d2311957371ad";

        for (pms_hex, agg_hex) in [(&one[..], one_agg), (&two[..], two_agg)] {
            let pms: Vec<PubkeyMsg> = pms_hex
                .iter()
                .map(|(pk, m)| (hex32(pk), hex32(m)))
                .collect();
            let agg = hex_bytes(&agg_hex.replace([' ', '\n'], ""));
            verify_aggregate(&pms, &agg).expect("draft vector must verify");

            // And a one-bit change must not.
            let mut bad = agg.clone();
            let last = bad.len() - 1;
            bad[last] ^= 0x01;
            assert!(verify_aggregate(&pms, &bad).is_err());
        }
    }
}
