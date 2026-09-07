//! Borromean-ring range proofs over Pedersen commitments.
//!
//! **EXPERIMENTAL** — no semver-stability guarantee. See the [module-level
//! documentation](super) for the clean-room policy and interop caveats.
//!
//! # Source of truth
//!
//! *Confidential Assets* (Poelstra, Back, Friedenbach, Maxwell, Wuille,
//! FC 2017) and Maxwell–Poelstra, *Borromean Ring Signatures* (2015), plus the
//! interface contract in the public header `include/secp256k1_rangeproof.h`.
//! **The wire format has no normative specification**; it is defined by the
//! reference implementation and was recovered here by black-box probing (see
//! [Interop](#interop) below).
//!
//! # What a range proof proves
//!
//! A Pedersen [`Commitment`] `C = v·H + r·G` hides `v` perfectly, and the
//! commitment algebra is only sound if every `v` is known to be *small*: values
//! live in `Z/nZ`, so an "output" of `n − 1` behaves like `−1` and a
//! transaction that balances on paper can mint coins. A range proof closes
//! that hole. [`verify`] returns a public interval `[min, max] ⊆ [0, 2⁶⁴)` and
//! guarantees the committed value lies inside it, while revealing nothing else.
//!
//! The proven interval is
//!
//! ```text
//! [ min_value , min_value + (2^mantissa − 1)·10^exp ]
//! ```
//!
//! so the value is written as `min_value + m·10^exp` with `m` an
//! `mantissa`-bit integer. The exponent is what makes the proof compact:
//! proof size grows with `mantissa`, so an amount known to be a round number
//! of, say, thousands can publish that fact and pay only for the digits that
//! actually vary. `exp = -1` is the degenerate case that publishes the value
//! outright, proving only that `C` opens to that exact amount.
//!
//! # Construction
//!
//! The `mantissa` bits are cut into base-4 digits, one **ring** per digit
//! (`ceil(mantissa/2)` rings; the top ring has two members when `mantissa` is
//! odd). The prover splits the blinding factor `r = Σ rᵢ` and publishes a
//! digit commitment
//!
//! ```text
//! Cᵢ = dᵢ·4ⁱ·10^exp·H + rᵢ·G
//! ```
//!
//! per ring. Ring `i` has one public key per candidate digit,
//! `P_{i,j} = Cᵢ − j·4ⁱ·10^exp·H`, and the prover knows `log_G P_{i,dᵢ} = rᵢ`
//! for exactly one `j`. A **Borromean ring signature** over all the rings at
//! once proves "one member of every ring is known" with a single shared
//! challenge `e₀` plus one scalar per member.
//!
//! Two size optimisations from the reference are reproduced here:
//!
//! * the **last** ring's commitment is not transmitted — the verifier recovers
//!   it as `C − min_value·H − Σ_{i<n−1} Cᵢ`;
//! * digit commitments are stored as a 32-byte x-coordinate plus one packed
//!   bit, rather than 33 bytes each.
//!
//! Every hash is bound to
//! `m = SHA-256(C ‖ H ‖ header ‖ C₀ ‖ … ‖ C_{n−2} ‖ extra_commit)`, which
//! stops an attacker moving `y·G` from one digit commitment to another and
//! obtaining a second valid proof for the same commitment.
//!
//! # Rewinding
//!
//! All of the prover's randomness comes from an HMAC-SHA256 (RFC 6979) DRBG
//! seeded with a 32-byte `nonce` together with the commitment, the generator
//! and the proof header. Anyone holding that nonce — in Confidential Assets it
//! is an ECDH shared secret — can replay the stream and [`rewind`] the proof
//! back to the exact `value`, the blinding factor `r`, and an arbitrary
//! **embedded message** the prover XOR-folded into the ring signature's forged
//! scalars. That is how a Confidential Transactions receiver learns what it
//! was paid without a side channel.
//!
//! The nonce is therefore as sensitive as the value: **never reuse it**, and
//! never publish it to anyone who should not learn the amount.
//!
//! # Serialization
//!
//! ```text
//! byte 0      flags | exp
//!             bit 6 (0x40): a mantissa/exponent byte follows (exp >= 0)
//!             bit 5 (0x20): an 8-byte big-endian min_value follows
//!             bits 4..0   : exp, 0..=18   (absent => exp = -1)
//! byte 1      mantissa - 1, 0..=63              (only when bit 6 is set)
//! [8 bytes]   min_value, big-endian             (only when bit 5 is set)
//! ceil((n-1)/8) bytes  one bit per transmitted digit commitment, LSB-first:
//!                      set iff that commitment's y is a quadratic non-residue
//! 32·(n-1)    the x-coordinates of C₀ … C_{n−2}
//! 32          e₀, the Borromean ring signature's shared challenge
//! 32·N        the ring scalars, ring-major
//! ```
//!
//! with `n` rings and `N = Σ rsizes` members. The quadratic-residue convention
//! for the packed bits is [`pedersen`](super::pedersen)'s, not SEC1 parity.
//! The reserved bits (`0x80` of byte 0, `0xc0` of byte 1) must be clear and
//! trailing bytes are refused, so every proof has exactly one encoding. The
//! largest shape the layout admits is [`MAX_PROOF_LEN`]; the largest a prover
//! can actually reach is 5126 bytes (`mantissa = 64`, `min_value = 0`).
//!
//! # Constant time
//!
//! The value, the blinding factor and the nonce are secret. The base-4 digits
//! are extracted with public shifts of a secret word; every per-ring "which
//! member do I know" decision is a constant-time select over all members, so
//! the sequence of curve operations, hashes and memory writes in [`sign`] is
//! the same for every value. The DRBG state, the per-ring secrets, the derived
//! nonces and the scratch buffers are wiped with a [`core::hint::black_box`]
//! barrier. [`rewind`] is likewise branch-free in the recovered digits.
//!
//! [`verify`] and [`info`] see only public data and are deliberately
//! variable-time. They never panic: every byte string either parses or returns
//! an error, and every peer-driven length is bounded before anything is
//! allocated.
//!
//! # Interop
//!
//! **Verified byte-for-byte** against the `secp256k1-zkp` black-box oracle
//! (driven through `include/secp256k1_rangeproof.h`, `secp256k1_generator.h`
//! and `secp256k1.h` only — see `tools/zkp-interop/README.md`), from the
//! vectors committed at `tools/zkp-interop/vectors/rangeproof.json`:
//!
//! * 58 proofs are reproduced **byte-identically** by [`sign`] from the same
//!   `(commitment, blind, nonce, value, min_value, exp, min_bits, message,
//!   extra_commit, generator)`. They span `value = 0`, `value = 2⁶⁴−1`,
//!   `min_value = value`, single-bit proofs, `exp` from `-1` to `6`,
//!   `min_bits` from 0 to 64, embedded messages up to the 3968-byte maximum,
//!   `extra_commit` blobs, per-asset generators, and the all-zero blinding
//!   factor the reference permits at `min_bits >= 3`.
//! * [`verify`] accepts all 58 and returns the oracle's `(min, max)`.
//! * [`info`] returns the oracle's `(exp, mantissa, min, max)` for all 58.
//! * [`rewind`] recovers the oracle's `value`, blinding factor and message
//!   buffer (including its `outlen`) for all 58.
//! * 20 proofs the oracle rejects — truncations, single-byte mutations and a
//!   proof checked against the wrong commitment — are rejected here too.
//! * The oracle's strictness was probed directly and is matched: it refuses a
//!   proof with trailing bytes, an `exp` field above 18, and either header
//!   byte's reserved bits set.
//!
//! The crate's tests read that JSON; they never link against the oracle.
//!
//! **Not verified.** The reference retries when a DRBG output is zero or `≥ n`
//! (probability ≈ 2⁻¹²⁷ per draw); this module reduces such a draw modulo `n`
//! instead, so the two would diverge on an input no one will ever find. The
//! exponent/mantissa/`min_value` selection was cross-checked against the
//! oracle over 7040 parameter combinations, including every rejection.

use alloc::vec;
use alloc::vec::Vec;

use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::ec::Error;
use crate::ec::secp256k1::{ProjectivePoint, Scalar};
use crate::hash::{Digest, HmacSha256, Sha256};

use super::pedersen::{Commitment, Generator, value_scalar};

// =====================================================================
// Limits
// =====================================================================

/// The largest message [`sign`] can embed, over every proof shape.
///
/// A given proof usually holds less; [`message_capacity`] gives the exact
/// capacity for one set of parameters. This is the value the reference
/// exposes as `SECP256K1_RANGEPROOF_MAX_MESSAGE_LEN`, for buffer sizing.
pub const MAX_MESSAGE_LEN: usize = 3968;

/// An upper bound on the size of a proof, matching the reference's documented
/// maximum. The largest proof [`sign`] actually produces is 5126 bytes.
pub const MAX_PROOF_LEN: usize = 5134;

/// The largest `exp` [`sign`] accepts (`-1` is the smallest).
const MAX_EXP: i32 = 18;

/// `ceil(64 / 2)`, the most rings a proof can have.
const MAX_RINGS: usize = 32;

// =====================================================================
// RFC 6979 HMAC-SHA256 DRBG
// =====================================================================

/// The deterministic bit generator the prover's randomness comes from.
///
/// This is RFC 6979 §3.2's `K`/`V` construction used as a stream: `generate`
/// performs the standard "retry" update (`K = HMAC_K(V ‖ 0x00)`, `V =
/// HMAC_K(V)`) on every call after the first, so successive 32-byte draws are
/// exactly the reference's successive `generate(..., 32)` calls.
struct Drbg {
    k: [u8; 32],
    v: [u8; 32],
    started: bool,
}

impl Drbg {
    /// Seeds the generator. `seed` plays the role of RFC 6979's
    /// `int2octets(x) ‖ bits2octets(h1)`.
    fn new(seed: &[u8]) -> Drbg {
        let mut k = [0u8; 32];
        let mut v = [1u8; 32];
        k = HmacSha256::new(&k)
            .chain(&v)
            .chain(&[0x00])
            .chain(seed)
            .finalize();
        v = HmacSha256::new(&k).chain(&v).finalize();
        k = HmacSha256::new(&k)
            .chain(&v)
            .chain(&[0x01])
            .chain(seed)
            .finalize();
        v = HmacSha256::new(&k).chain(&v).finalize();
        Drbg {
            k,
            v,
            started: false,
        }
    }

    /// Draws the next 32 bytes.
    fn generate(&mut self, out: &mut [u8; 32]) {
        if self.started {
            self.k = HmacSha256::new(&self.k)
                .chain(&self.v)
                .chain(&[0x00])
                .finalize();
            self.v = HmacSha256::new(&self.k).chain(&self.v).finalize();
        }
        self.v = HmacSha256::new(&self.k).chain(&self.v).finalize();
        *out = self.v;
        self.started = true;
    }
}

impl Drop for Drbg {
    fn drop(&mut self) {
        self.k = [0u8; 32];
        self.v = [0u8; 32];
        let _ = core::hint::black_box((&self.k, &self.v));
    }
}

// =====================================================================
// Proof shape
// =====================================================================

/// The parameters a proof header encodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Params {
    /// Base-10 exponent, `-1..=18`. `-1` publishes the value.
    exp: i32,
    /// Number of private bits, `0` when `exp == -1`, else `1..=64`.
    mantissa: u32,
    /// The lower end of the proven interval.
    min_value: u64,
    /// `10^exp`, or `1` when `exp == -1`.
    scale: u64,
    /// `min_value + (2^mantissa − 1)·scale`, the upper end.
    max_value: u64,
}

/// The ring structure of a proof with `mantissa` private bits.
#[derive(Clone, Copy)]
struct Layout {
    /// Members per ring.
    rsizes: [usize; MAX_RINGS],
    /// Index of ring `i`'s first member in the flat scalar array.
    starts: [usize; MAX_RINGS],
    /// Number of rings.
    rings: usize,
    /// Total number of ring members.
    npub: usize,
}

impl Layout {
    /// Derives the ring structure. `mantissa == 0` is the `exp == -1` shape:
    /// a single one-member ring, i.e. a plain Schnorr proof of knowledge of
    /// `log_G (C − value·H)`.
    fn new(mantissa: u32) -> Layout {
        let mut rsizes = [0usize; MAX_RINGS];
        let mut starts = [0usize; MAX_RINGS];
        let rings = if mantissa == 0 {
            rsizes[0] = 1;
            1
        } else {
            let rings = (mantissa as usize).div_ceil(2);
            for size in rsizes.iter_mut().take(rings) {
                *size = 4;
            }
            if mantissa % 2 == 1 {
                rsizes[rings - 1] = 2;
            }
            rings
        };
        let mut npub = 0;
        for i in 0..rings {
            starts[i] = npub;
            npub += rsizes[i];
        }
        Layout {
            rsizes,
            starts,
            rings,
            npub,
        }
    }

    /// Number of digit commitments carried in the proof (the last ring's is
    /// recovered by the verifier), and the number of bytes their packed sign
    /// bits occupy.
    fn commitments(&self) -> (usize, usize) {
        let n = if self.rsizes[0] == 1 {
            0
        } else {
            self.rings - 1
        };
        (n, n.div_ceil(8))
    }
}

/// The exact number of message bytes a proof of this shape can embed.
///
/// The embedding uses the ring signature's forged scalars, and the last ring's
/// scalars are reserved for the value marker and the blinding-factor recovery,
/// so the capacity is `32 · (members − last ring's members)`.
fn max_message_len(layout: &Layout) -> usize {
    32 * (layout.npub - layout.rsizes[layout.rings - 1])
}

/// Bit length of `x` (`0` for zero).
fn bit_len(x: u64) -> u32 {
    64 - x.leading_zeros()
}

/// `10^exp`, saturating (never reached: `exp <= 18`).
fn pow10(exp: i32) -> u64 {
    let mut scale = 1u64;
    for _ in 0..exp.max(0) {
        scale = scale.saturating_mul(10);
    }
    scale
}

/// Computes `min_value + (2^mantissa − 1)·scale`, or `None` on overflow.
fn span(min_value: u64, mantissa: u32, scale: u64) -> Option<u64> {
    let width = if mantissa >= 64 {
        u64::MAX
    } else {
        (1u64 << mantissa) - 1
    };
    width.checked_mul(scale)?.checked_add(min_value)
}

/// Picks the exponent, mantissa width and effective `min_value` for a proof,
/// mirroring the reference's choice exactly.
///
/// `exp` and `min_bits` are requests, not commands: the exponent shrinks until
/// the proven interval fits in a `u64`, the mantissa is capped so that
/// `min_value` and the interval width do not collide in 64 bits, and any part
/// of `value − min_value` below `10^exp` is folded into `min_value`.
///
/// Returns the parameters and the mantissa value `m` with
/// `value = min_value + m·10^exp`.
fn choose_params(
    value: u64,
    min_value: u64,
    exp: i32,
    min_bits: u32,
) -> Result<(Params, u64), Error> {
    if !(-1..=MAX_EXP).contains(&exp) || min_bits > 64 || min_value > value {
        return Err(Error::InvalidInput);
    }
    if exp == -1 {
        return Ok((
            Params {
                exp: -1,
                mantissa: 0,
                min_value: value,
                scale: 1,
                max_value: value,
            },
            0,
        ));
    }
    // The reference restricts a shifted or offset proof to [0, 2^63) so the
    // proven interval cannot run past 2^64; with min_value == 0 it silently
    // falls back to exp = 0 rather than failing.
    let mut exp = exp;
    if value > i64::MAX as u64 {
        if min_value != 0 {
            return Err(Error::InvalidInput);
        }
        exp = 0;
    }
    // The mantissa may not overlap min_value's high bits.
    let max_bits = 64 - bit_len(min_value);
    let min_bits = min_bits.min(max_bits);
    let delta = value - min_value;
    loop {
        let scale = pow10(exp);
        let mantissa_value = delta / scale;
        let effective_min = min_value + (delta - mantissa_value * scale);
        let mantissa = bit_len(mantissa_value).max(min_bits).max(1);
        if let Some(max_value) = span(effective_min, mantissa, scale) {
            return Ok((
                Params {
                    exp,
                    mantissa,
                    min_value: effective_min,
                    scale,
                    max_value,
                },
                mantissa_value,
            ));
        }
        if exp == 0 {
            return Err(Error::InvalidInput);
        }
        exp -= 1;
    }
}

/// Serializes the header bytes of a proof.
fn write_header(out: &mut Vec<u8>, params: &Params) {
    let mut flags = 0u8;
    if params.exp >= 0 {
        flags |= 0x40 | (params.exp as u8);
    }
    if params.min_value != 0 {
        flags |= 0x20;
    }
    out.push(flags);
    if params.exp >= 0 {
        out.push((params.mantissa - 1) as u8);
    }
    if params.min_value != 0 {
        out.extend_from_slice(&params.min_value.to_be_bytes());
    }
}

/// Reads a proof header. Returns the parameters and the header length.
fn read_header(proof: &[u8]) -> Result<(Params, usize), Error> {
    let flags = *proof.first().ok_or(Error::Malformed)?;
    if flags & 0x80 != 0 {
        return Err(Error::Malformed);
    }
    let mut off = 1;
    let (exp, mantissa) = if flags & 0x40 != 0 {
        let byte = *proof.get(1).ok_or(Error::Malformed)?;
        off = 2;
        let exp = i32::from(flags & 0x1f);
        // The unused bits of both header bytes must be clear, so a proof has
        // exactly one encoding.
        if exp > MAX_EXP || byte & 0xc0 != 0 {
            return Err(Error::Malformed);
        }
        (exp, u32::from(byte) + 1)
    } else {
        (-1, 0)
    };
    let min_value = if flags & 0x20 != 0 {
        let bytes: [u8; 8] = proof
            .get(off..off + 8)
            .ok_or(Error::Malformed)?
            .try_into()
            .map_err(|_| Error::Malformed)?;
        off += 8;
        u64::from_be_bytes(bytes)
    } else {
        0
    };
    let scale = pow10(exp);
    let max_value = span(min_value, mantissa, scale).ok_or(Error::Malformed)?;
    Ok((
        Params {
            exp,
            mantissa,
            min_value,
            scale,
            max_value,
        },
        off,
    ))
}

// =====================================================================
// Hashing
// =====================================================================

/// The 33-byte "sign bit ‖ x" encoding the proof's hashes use for points:
/// byte 0 is 1 iff `y` is a quadratic non-residue, which is the low bit of the
/// [`pedersen`](super::pedersen) tagged prefix.
fn point_enc(tagged: &[u8; 33]) -> [u8; 33] {
    let mut out = *tagged;
    out[0] = tagged[0] & 1;
    out
}

/// The message every hash in the proof is bound to:
/// `SHA-256(C ‖ H ‖ header ‖ C₀ ‖ … ‖ C_{n−2} ‖ extra_commit)`.
fn proof_message(
    commit: &[u8; 33],
    generator: &[u8; 33],
    header: &[u8],
    digits: &[[u8; 33]],
    extra_commit: &[u8],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(commit);
    h.update(generator);
    h.update(header);
    for digit in digits {
        h.update(digit);
    }
    h.update(extra_commit);
    h.finalize()
}

/// The Borromean ring signature's per-step challenge hash,
/// `SHA-256(e ‖ m ‖ ring ‖ pos)` with the indices big-endian 32-bit.
fn borromean_hash(m: &[u8; 32], e: &[u8], ring: u32, pos: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(e);
    h.update(m);
    h.update(&ring.to_be_bytes());
    h.update(&pos.to_be_bytes());
    h.finalize()
}

/// A fixed stand-in used when a scratch point lands on the identity, which has
/// no compressed encoding. Only reachable on discarded intermediates.
const DUMMY_POINT: [u8; 33] = [
    0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b,
    0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17,
    0x98,
];

/// Compressed SEC1 encoding, falling back to [`DUMMY_POINT`] for the identity.
fn sec1(point: &ProjectivePoint) -> [u8; 33] {
    match point.to_affine() {
        Some(affine) => affine.to_sec1_compressed(),
        None => DUMMY_POINT,
    }
}

// =====================================================================
// Shared plumbing
// =====================================================================

/// `commit`, `generator` and the header, laid out as the DRBG seed
/// `nonce ‖ enc(C) ‖ enc(H) ‖ header`.
fn drbg_seed(
    nonce: &[u8; 32],
    commit_enc: &[u8; 33],
    generator_enc: &[u8; 33],
    header: &[u8],
) -> ([u8; 32 + 33 + 33 + 10], usize) {
    let mut seed = [0u8; 32 + 33 + 33 + 10];
    seed[..32].copy_from_slice(nonce);
    seed[32..65].copy_from_slice(commit_enc);
    seed[65..98].copy_from_slice(generator_enc);
    seed[98..98 + header.len()].copy_from_slice(header);
    (seed, 98 + header.len())
}

/// `j · 4^ring · scale`, the value ring member `j` stands for.
///
/// Bounded by `(2^mantissa − 1)·scale`, which [`choose_params`] and
/// [`read_header`] both keep inside a `u64`.
fn member_offset(j: u64, ring: usize, scale: u64) -> u64 {
    j.wrapping_mul(1u64.wrapping_shl(2 * ring as u32))
        .wrapping_mul(scale)
}

/// Builds ring member `j`'s public key `Cᵢ − j·4ⁱ·scale·H`.
fn member_pubkey(
    digit_commit: &ProjectivePoint,
    j: u64,
    ring: usize,
    scale: u64,
    generator: &ProjectivePoint,
) -> ProjectivePoint {
    let offset = member_offset(j, ring, scale);
    if offset == 0 {
        *digit_commit
    } else {
        digit_commit.add(&generator.mul(&value_scalar(offset)).negate())
    }
}

/// Recovers the digit commitments from a proof body and returns them together
/// with their 33-byte hash encodings.
///
/// `body` is the proof from the end of the header to the start of `e₀`.
fn parse_digit_commitments(
    body: &[u8],
    count: usize,
    sign_bytes: usize,
) -> Result<(Vec<ProjectivePoint>, Vec<[u8; 33]>), Error> {
    let mut points = Vec::with_capacity(count);
    let mut encs = Vec::with_capacity(count);
    for i in 0..count {
        let bit = (body[i / 8] >> (i % 8)) & 1;
        let mut tagged = [0u8; 33];
        tagged[0] = 0x08 | bit;
        tagged[1..].copy_from_slice(&body[sign_bytes + 32 * i..sign_bytes + 32 * (i + 1)]);
        points.push(Commitment::parse(&tagged)?.as_point());
        encs.push(point_enc(&tagged));
    }
    Ok((points, encs))
}

/// The pieces of a parsed proof that both [`verify`] and [`rewind`] need.
struct Parsed {
    params: Params,
    layout: Layout,
    /// Ring member public keys, flat and ring-major.
    pubs: Vec<ProjectivePoint>,
    /// The bound message every hash covers.
    message: [u8; 32],
    /// The shared Borromean challenge.
    e0: [u8; 32],
    /// The ring scalars, flat and ring-major.
    s: Vec<[u8; 32]>,
    /// The header bytes, for reseeding the DRBG on a rewind.
    header_len: usize,
}

/// Parses and structurally validates a proof, without checking the signature.
fn parse(
    commit: &Commitment,
    proof: &[u8],
    extra_commit: &[u8],
    generator: &Generator,
) -> Result<Parsed, Error> {
    let (params, header_len) = read_header(proof)?;
    let layout = Layout::new(params.mantissa);
    let (ncommit, sign_bytes) = layout.commitments();

    // Every peer-driven length is bounded here, before anything is allocated:
    // `mantissa <= 64` caps `ncommit` at 31 and `npub` at 128.
    let body_len = sign_bytes + 32 * ncommit;
    let total = header_len
        .checked_add(body_len)
        .and_then(|n| n.checked_add(32))
        .and_then(|n| n.checked_add(32 * layout.npub))
        .ok_or(Error::Malformed)?;
    if proof.len() != total {
        return Err(Error::Malformed);
    }

    let body = &proof[header_len..header_len + body_len];
    let (points, encs) = parse_digit_commitments(body, ncommit, sign_bytes)?;

    let message = proof_message(
        &point_enc(&commit.serialize()),
        &point_enc(&generator.serialize()),
        &proof[..header_len],
        &encs,
        extra_commit,
    );

    // The last ring's commitment is C − min_value·H − Σ Cᵢ.
    let gen_point = generator.as_point();
    let mut last = commit.as_point();
    if params.min_value != 0 {
        last = last.add(&gen_point.mul(&value_scalar(params.min_value)).negate());
    }
    for point in &points {
        last = last.add(&point.negate());
    }

    let mut digit_commits = points;
    digit_commits.push(last);
    if digit_commits.len() != layout.rings {
        return Err(Error::Malformed);
    }

    let mut pubs = Vec::with_capacity(layout.npub);
    for (i, digit_commit) in digit_commits.iter().enumerate() {
        for j in 0..layout.rsizes[i] {
            pubs.push(member_pubkey(
                digit_commit,
                j as u64,
                i,
                params.scale,
                &gen_point,
            ));
        }
    }

    let sig = &proof[header_len + body_len..];
    let e0: [u8; 32] = sig[..32].try_into().map_err(|_| Error::Malformed)?;
    let mut s = Vec::with_capacity(layout.npub);
    for i in 0..layout.npub {
        let chunk: [u8; 32] = sig[32 + 32 * i..32 + 32 * (i + 1)]
            .try_into()
            .map_err(|_| Error::Malformed)?;
        // Reject over-large scalars rather than reducing them, so a proof has
        // exactly one encoding.
        Scalar::from_bytes_be(&chunk).map_err(|_| Error::Malformed)?;
        s.push(chunk);
    }

    Ok(Parsed {
        params,
        layout,
        pubs,
        message,
        e0,
        s,
        header_len,
    })
}

/// Replays the Borromean ring signature.
///
/// Returns the per-member challenges `e_{i,j}` on success — [`rewind`] needs
/// them to solve for the last ring's blinding share. Public data only, so this
/// is variable time.
fn borromean_verify(parsed: &Parsed) -> Result<Vec<[u8; 32]>, Error> {
    let layout = &parsed.layout;
    let mut challenges = vec![[0u8; 32]; layout.npub];
    let mut e0h = Sha256::new();
    for i in 0..layout.rings {
        let start = layout.starts[i];
        let mut e = borromean_hash(&parsed.message, &parsed.e0, i as u32, 0);
        for j in 0..layout.rsizes[i] {
            challenges[start + j] = e;
            let s = Scalar::from_bytes_be(&parsed.s[start + j]).map_err(|_| Error::Malformed)?;
            let scalar = Scalar::from_bytes_be_reduce(&e);
            let r = ProjectivePoint::mul_generator(&s).add(&parsed.pubs[start + j].mul(&scalar));
            let affine = r.to_affine().ok_or(Error::Verification)?;
            let ser = affine.to_sec1_compressed();
            if j + 1 < layout.rsizes[i] {
                e = borromean_hash(&parsed.message, &ser, i as u32, (j + 1) as u32);
            } else {
                e0h.update(&ser);
            }
        }
    }
    e0h.update(&parsed.message);
    let recomputed = e0h.finalize();
    if !bool::from(recomputed.ct_eq(&parsed.e0)) {
        return Err(Error::Verification);
    }
    Ok(challenges)
}

// =====================================================================
// Public API
// =====================================================================

/// Reads a proof's header without verifying it.
///
/// Returns `(exp, mantissa, min_value, max_value)`: the base-10 exponent
/// (`-1` when the value is public), the number of private mantissa bits (`0`
/// when the value is public), and the interval the proof *claims*. Nothing
/// here is authenticated — a header is just bytes until [`verify`] accepts the
/// proof. Never panics.
pub fn info(proof: &[u8]) -> Result<(i32, u32, u64, u64), Error> {
    let (params, _) = read_header(proof)?;
    Ok((
        params.exp,
        params.mantissa,
        params.min_value,
        params.max_value,
    ))
}

/// The number of message bytes [`sign`] can embed in a proof of the shape the
/// given parameters produce.
///
/// Returns an error for parameters [`sign`] itself would reject.
pub fn message_capacity(
    value: u64,
    min_value: u64,
    exp: i32,
    min_bits: u32,
) -> Result<usize, Error> {
    let (params, _) = choose_params(value, min_value, exp, min_bits)?;
    Ok(max_message_len(&Layout::new(params.mantissa)))
}

/// Verifies a range proof and returns the interval it proves.
///
/// On success the committed value is guaranteed to lie in `[min, max]`.
/// `extra_commit` and `generator` must be exactly what the prover used.
///
/// This runs on public data and is deliberately variable time. It never
/// panics: any byte string, truncated or adversarial, returns an error.
pub fn verify(
    commit: &Commitment,
    proof: &[u8],
    extra_commit: &[u8],
    generator: &Generator,
) -> Result<(u64, u64), Error> {
    let parsed = parse(commit, proof, extra_commit, generator)?;
    borromean_verify(&parsed)?;
    Ok((parsed.params.min_value, parsed.params.max_value))
}

/// Creates a range proof for `commit = value·generator + blind·G`.
///
/// * `nonce` seeds every random choice in the proof. It **must be unique per
///   proof** and secret from anyone who should not learn the value: whoever
///   holds it can [`rewind`] the proof. Reusing it across proofs can leak
///   `blind`.
/// * `exp` is the base-10 exponent, `-1..=18`. `-1` publishes the value; `0`
///   is the most private. Larger exponents shrink the proof by making the
///   low decimal digits public.
/// * `min_bits` is the minimum number of private mantissa bits, `0..=64`,
///   with `0` meaning "just enough for this value". A larger value hides how
///   big the amount is at the cost of size.
/// * `message` is embedded in the proof and recovered by [`rewind`]. See
///   [`message_capacity`] for how much fits; [`MAX_MESSAGE_LEN`] bounds every
///   shape.
/// * `extra_commit` is bound into the proof but not carried by it; the
///   verifier must supply the same bytes.
///
/// `exp` and `min_bits` are requests: both are reduced as needed so the proven
/// interval fits in a `u64`. Use [`info`] on the result to see what was
/// actually proven.
///
/// Runs in time independent of `value`, `blind` and `nonce`.
// The argument list mirrors `secp256k1_rangeproof_sign`; keeping the same
// shape is what makes the interop corpus a line-for-line translation.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    commit: &Commitment,
    blind: &[u8; 32],
    nonce: &[u8; 32],
    value: u64,
    min_value: u64,
    exp: i32,
    min_bits: u32,
    message: &[u8],
    extra_commit: &[u8],
    generator: &Generator,
) -> Result<Vec<u8>, Error> {
    let (params, mantissa_value) = choose_params(value, min_value, exp, min_bits)?;
    let layout = Layout::new(params.mantissa);
    let (ncommit, sign_bytes) = layout.commitments();
    if message.len() > max_message_len(&layout) {
        return Err(Error::InvalidInput);
    }
    let blind_scalar = Scalar::from_bytes_be(blind)?;

    let mut proof = Vec::with_capacity(MAX_PROOF_LEN);
    write_header(&mut proof, &params);

    let commit_enc = point_enc(&commit.serialize());
    let generator_enc = point_enc(&generator.serialize());
    let (seed, seed_len) = drbg_seed(nonce, &commit_enc, &generator_enc, &proof);
    let mut rng = Drbg::new(&seed[..seed_len]);

    // --- the prover's randomness -------------------------------------
    //
    // Per ring, in order: two draws whose second is the ring's blinding share
    // (the last ring's share is whatever balances the total), then one draw
    // per ring member. The draw at the member the prover knows becomes that
    // ring's Borromean nonce k; the rest are the forged scalars.
    let mut sec = vec![[0u8; 32]; layout.rings];
    let mut raw = vec![[0u8; 32]; layout.npub];
    let mut acc = Scalar::ZERO;
    let mut slot = 0;
    for (i, share) in sec.iter_mut().enumerate() {
        if i + 1 < layout.rings {
            let mut tmp = [0u8; 32];
            rng.generate(&mut tmp);
            rng.generate(&mut tmp);
            *share = tmp;
            acc = acc.add(&Scalar::from_bytes_be_reduce(&tmp));
            tmp = [0u8; 32];
            let _ = core::hint::black_box(&tmp);
        }
        for _ in 0..layout.rsizes[i] {
            rng.generate(&mut raw[slot]);
            slot += 1;
        }
    }
    sec[layout.rings - 1] = blind_scalar.sub(&acc).to_bytes_be();

    // --- the embedded data -------------------------------------------
    //
    // `prep` is XORed into the DRBG stream slot by slot. The caller's message
    // occupies the leading slots; the last slot that is not the final ring's
    // known member carries the mantissa value, which is how `rewind` learns
    // the top digit it cannot derive from the digit commitments.
    let mut prep = vec![0u8; 32 * layout.npub];
    prep[..message.len()].copy_from_slice(message);
    let last_ring = layout.rings - 1;
    let mut digits = [0u64; MAX_RINGS];
    for (i, digit) in digits.iter_mut().enumerate().take(layout.rings) {
        *digit = (mantissa_value >> (2 * i)) & 3;
    }
    if layout.npub >= 2 {
        let mut marker = [0u8; 32];
        marker[0] = 0x80;
        for chunk in 1..4 {
            marker[8 * chunk..8 * (chunk + 1)].copy_from_slice(&mantissa_value.to_be_bytes());
        }
        let known = (layout.starts[last_ring] as u64) + digits[last_ring];
        let at_end = known.ct_eq(&((layout.npub - 1) as u64));
        let tail: [u8; 32] = prep[32 * (layout.npub - 1)..].try_into().unwrap();
        let prev: [u8; 32] = prep[32 * (layout.npub - 2)..32 * (layout.npub - 1)]
            .try_into()
            .unwrap();
        // When the final ring's known member is the very last slot, the marker
        // moves one slot earlier; both writes always happen.
        let new_tail = <[u8; 32]>::conditional_select(&tail, &marker, at_end);
        let new_prev = <[u8; 32]>::conditional_select(&marker, &prev, at_end);
        prep[32 * (layout.npub - 1)..].copy_from_slice(&new_tail);
        prep[32 * (layout.npub - 2)..32 * (layout.npub - 1)].copy_from_slice(&new_prev);
    }

    let mut s = vec![[0u8; 32]; layout.npub];
    for i in 0..layout.npub {
        for b in 0..32 {
            s[i][b] = raw[i][b] ^ prep[32 * i + b];
        }
    }
    // k_i is the draw at the member the prover knows, chosen without a
    // secret-dependent index.
    let mut nonces = vec![[0u8; 32]; layout.rings];
    for i in 0..layout.rings {
        let mut k = [0u8; 32];
        for j in 0..layout.rsizes[i] {
            let is_known = (j as u64).ct_eq(&digits[i]);
            k = <[u8; 32]>::conditional_select(&s[layout.starts[i] + j], &k, is_known);
        }
        nonces[i] = k;
    }

    // --- digit commitments and ring public keys ----------------------
    let gen_point = generator.as_point();
    let mut digit_commits = Vec::with_capacity(layout.rings);
    for i in 0..layout.rings {
        let offset = value_scalar(member_offset(digits[i], i, params.scale));
        let share = Scalar::from_bytes_be_reduce(&sec[i]);
        digit_commits.push(
            gen_point
                .mul(&offset)
                .add(&ProjectivePoint::mul_generator(&share)),
        );
    }
    let mut encs = Vec::with_capacity(ncommit);
    let mut body = vec![0u8; sign_bytes + 32 * ncommit];
    for (i, digit_commit) in digit_commits.iter().enumerate().take(ncommit) {
        let tagged = Commitment::from_point(digit_commit)?.serialize();
        body[i / 8] |= (tagged[0] & 1) << (i % 8);
        body[sign_bytes + 32 * i..sign_bytes + 32 * (i + 1)].copy_from_slice(&tagged[1..]);
        encs.push(point_enc(&tagged));
    }

    let mut pubs = Vec::with_capacity(layout.npub);
    for (i, digit_commit) in digit_commits.iter().enumerate() {
        for j in 0..layout.rsizes[i] {
            pubs.push(member_pubkey(
                digit_commit,
                j as u64,
                i,
                params.scale,
                &gen_point,
            ));
        }
    }

    let m = proof_message(&commit_enc, &generator_enc, &proof, &encs, extra_commit);

    // --- Borromean signature, forward pass ---------------------------
    //
    // Each ring is walked from member 0 to the end. Before the known member
    // the running point is a fixed dummy whose chain is discarded; at the
    // known member it is replaced by k·G with a constant-time select; after it
    // the real chain runs. The work is identical whatever the digit is.
    let mut e0h = Sha256::new();
    for i in 0..layout.rings {
        let start = layout.starts[i];
        let k = Scalar::from_bytes_be_reduce(&nonces[i]);
        let kg = ProjectivePoint::mul_generator(&k);
        let mut r = ProjectivePoint::generator();
        for j in 0..layout.rsizes[i] {
            let is_known = (j as u64).ct_eq(&digits[i]);
            r = ProjectivePoint::conditional_select(&kg, &r, is_known);
            if j + 1 < layout.rsizes[i] {
                let e = borromean_hash(&m, &sec1(&r), i as u32, (j + 1) as u32);
                let e = Scalar::from_bytes_be_reduce(&e);
                let sj = Scalar::from_bytes_be_reduce(&s[start + j + 1]);
                r = ProjectivePoint::mul_generator(&sj).add(&pubs[start + j + 1].mul(&e));
            }
        }
        let affine = r.to_affine().ok_or(Error::InvalidInput)?;
        e0h.update(&affine.to_sec1_compressed());
    }
    e0h.update(&m);
    let e0 = e0h.finalize();

    // --- Borromean signature, closing pass ---------------------------
    for i in 0..layout.rings {
        let start = layout.starts[i];
        let mut e = borromean_hash(&m, &e0, i as u32, 0);
        let mut e_known = [0u8; 32];
        for j in 0..layout.rsizes[i] {
            let is_known = (j as u64).ct_eq(&digits[i]);
            e_known = <[u8; 32]>::conditional_select(&e, &e_known, is_known);
            if j + 1 < layout.rsizes[i] {
                let scalar = Scalar::from_bytes_be_reduce(&e);
                let sj = Scalar::from_bytes_be_reduce(&s[start + j]);
                let r = ProjectivePoint::mul_generator(&sj).add(&pubs[start + j].mul(&scalar));
                e = borromean_hash(&m, &sec1(&r), i as u32, (j + 1) as u32);
            }
        }
        // s = k − e·rᵢ at the known member.
        let k = Scalar::from_bytes_be_reduce(&nonces[i]);
        let share = Scalar::from_bytes_be_reduce(&sec[i]);
        let closing = k
            .sub(&Scalar::from_bytes_be_reduce(&e_known).mul(&share))
            .to_bytes_be();
        for j in 0..layout.rsizes[i] {
            let is_known = (j as u64).ct_eq(&digits[i]);
            s[start + j] = <[u8; 32]>::conditional_select(&closing, &s[start + j], is_known);
        }
    }

    proof.extend_from_slice(&body);
    proof.extend_from_slice(&e0);
    for chunk in &s {
        proof.extend_from_slice(chunk);
    }

    // Wipe everything that would reveal the value or the blinding factor.
    for buf in sec
        .iter_mut()
        .chain(raw.iter_mut())
        .chain(nonces.iter_mut())
    {
        *buf = [0u8; 32];
    }
    prep.iter_mut().for_each(|b| *b = 0);
    digits = [0u64; MAX_RINGS];
    let _ = core::hint::black_box((&sec, &raw, &nonces, &prep, &digits));

    Ok(proof)
}

/// What [`rewind`] recovers from a proof.
#[derive(Clone, Debug)]
pub struct Rewound {
    /// The exact committed value.
    pub value: u64,
    /// The blinding factor `r` with `commit = value·generator + r·G`.
    pub blind: [u8; 32],
    /// The embedded message, zero-padded to the proof's recoverable capacity.
    ///
    /// This is the reference's `message_out[..outlen]`: bytes past the message
    /// the prover supplied are zero, so a caller that knows its own framing can
    /// trim it.
    pub message: Vec<u8>,
    /// The lower end of the proven interval, as [`verify`] reports it.
    pub min_value: u64,
    /// The upper end of the proven interval, as [`verify`] reports it.
    pub max_value: u64,
}

/// Verifies a proof and, using the prover's `nonce`, recovers the value, the
/// blinding factor and the embedded message.
///
/// The proof is fully verified first, so a `Ok` result is also a successful
/// [`verify`]. Fails if the proof is invalid, if the nonce is wrong, or if the
/// recovered opening does not match `commit` — so a caller can trust the
/// returned `value`/`blind` pair without re-deriving the commitment.
///
/// Runs in time independent of the recovered value and blinding factor.
pub fn rewind(
    commit: &Commitment,
    proof: &[u8],
    nonce: &[u8; 32],
    extra_commit: &[u8],
    generator: &Generator,
) -> Result<Rewound, Error> {
    let parsed = parse(commit, proof, extra_commit, generator)?;
    let challenges = borromean_verify(&parsed)?;
    let layout = &parsed.layout;
    let params = &parsed.params;

    let commit_enc = point_enc(&commit.serialize());
    let generator_enc = point_enc(&generator.serialize());
    let (seed, seed_len) = drbg_seed(
        nonce,
        &commit_enc,
        &generator_enc,
        &proof[..parsed.header_len],
    );
    let mut rng = Drbg::new(&seed[..seed_len]);

    let mut sec = vec![[0u8; 32]; layout.rings];
    let mut raw = vec![[0u8; 32]; layout.npub];
    let mut acc = Scalar::ZERO;
    let mut slot = 0;
    for (i, share) in sec.iter_mut().enumerate() {
        if i + 1 < layout.rings {
            let mut tmp = [0u8; 32];
            rng.generate(&mut tmp);
            rng.generate(&mut tmp);
            *share = tmp;
            acc = acc.add(&Scalar::from_bytes_be_reduce(&tmp));
            tmp = [0u8; 32];
            let _ = core::hint::black_box(&tmp);
        }
        for _ in 0..layout.rsizes[i] {
            rng.generate(&mut raw[slot]);
            slot += 1;
        }
    }

    // The digits of every ring but the last follow from its blinding share:
    // Cᵢ − rᵢ·G must be dᵢ·4ⁱ·scale·H.
    let gen_point = generator.as_point();
    let mut digits = [0u64; MAX_RINGS];
    for i in 0..layout.rings - 1 {
        let share = Scalar::from_bytes_be_reduce(&sec[i]);
        let target =
            parsed.pubs[layout.starts[i]].add(&ProjectivePoint::mul_generator(&share).negate());
        let mut found = Choice::from(0u8);
        for j in 0..layout.rsizes[i] {
            let offset = member_offset(j as u64, i, params.scale);
            let candidate = if offset == 0 {
                ProjectivePoint::identity()
            } else {
                gen_point.mul(&value_scalar(offset))
            };
            let hit = target.ct_eq(&candidate);
            digits[i] = u64::conditional_select(&(j as u64), &digits[i], hit);
            found |= hit;
        }
        if !bool::from(found) {
            return Err(Error::Verification);
        }
    }

    // The last ring's digit comes from the marker slot: the mantissa value the
    // prover folded into the stream. It sits in the final slot unless that is
    // the ring's known member, in which case it sits one slot earlier. Both
    // candidates are examined, so which one carried it stays secret.
    let last_ring = layout.rings - 1;
    let mut mantissa_value = 0u64;
    let mut have_marker = Choice::from(0u8);
    if layout.npub >= 2 {
        for slot in [layout.npub - 1, layout.npub - 2] {
            let mut folded = [0u8; 32];
            for b in 0..32 {
                folded[b] = parsed.s[slot][b] ^ raw[slot][b];
            }
            let first = u64::from_be_bytes(folded[8..16].try_into().unwrap());
            let second = u64::from_be_bytes(folded[16..24].try_into().unwrap());
            let third = u64::from_be_bytes(folded[24..32].try_into().unwrap());
            let shaped = folded[0].ct_eq(&0x80)
                & folded[1..8].ct_eq(&[0u8; 7][..])
                & first.ct_eq(&second)
                & second.ct_eq(&third);
            let take = shaped & !have_marker;
            mantissa_value = u64::conditional_select(&first, &mantissa_value, take);
            have_marker |= shaped;
        }
    }
    if params.mantissa != 0 && !bool::from(have_marker) {
        return Err(Error::Verification);
    }
    digits[last_ring] = (mantissa_value >> (2 * last_ring)) & 3;
    let value = params
        .min_value
        .checked_add(
            mantissa_value
                .checked_mul(params.scale)
                .ok_or(Error::Verification)?,
        )
        .ok_or(Error::Verification)?;

    // The last ring's blinding share falls out of its closing scalar,
    // `s = k − e·r`, with `k` the raw draw at the known member. That member is
    // read by scanning the ring rather than indexing it.
    let last_start = layout.starts[last_ring];
    let last_size = layout.rsizes[last_ring];
    let known = (last_start as u64) + digits[last_ring];
    let mut k_bytes = [0u8; 32];
    let mut s_bytes = [0u8; 32];
    let mut e_bytes = [0u8; 32];
    for j in 0..last_size {
        let slot = last_start + j;
        let hit = (j as u64).ct_eq(&digits[last_ring]);
        k_bytes = <[u8; 32]>::conditional_select(&raw[slot], &k_bytes, hit);
        s_bytes = <[u8; 32]>::conditional_select(&parsed.s[slot], &s_bytes, hit);
        e_bytes = <[u8; 32]>::conditional_select(&challenges[slot], &e_bytes, hit);
    }
    let e = Scalar::from_bytes_be_reduce(&e_bytes);
    if bool::from(e.is_zero()) {
        return Err(Error::Verification);
    }
    let last_share = Scalar::from_bytes_be_reduce(&k_bytes)
        .sub(&Scalar::from_bytes_be_reduce(&s_bytes))
        .mul(&e.invert());
    let mut blind_scalar = Scalar::from_bytes_be_reduce(&last_share.to_bytes_be());
    for share in sec.iter().take(last_ring) {
        blind_scalar = blind_scalar.add(&Scalar::from_bytes_be_reduce(share));
    }
    let blind = blind_scalar.to_bytes_be();
    sec[last_ring] = last_share.to_bytes_be();

    // Undo the stream fold on every slot. A forged scalar carries its embedded
    // bytes directly; the known member of a ring carries them inside its
    // closing equation. Both forms are computed and one is selected.
    let mut folded = vec![[0u8; 32]; layout.npub];
    for i in 0..layout.rings {
        let share = Scalar::from_bytes_be_reduce(&sec[i]);
        for j in 0..layout.rsizes[i] {
            let slot = layout.starts[i] + j;
            let s = Scalar::from_bytes_be_reduce(&parsed.s[slot]);
            let e = Scalar::from_bytes_be_reduce(&challenges[slot]);
            let closing = s.add(&e.mul(&share)).to_bytes_be();
            let is_known = (j as u64).ct_eq(&digits[i]);
            let chosen = <[u8; 32]>::conditional_select(&closing, &parsed.s[slot], is_known);
            for b in 0..32 {
                folded[slot][b] = chosen[b] ^ raw[slot][b];
            }
        }
    }

    // Every slot but the last ring's known member and the marker is
    // recoverable. Which two those are is secret, so the last ring's chunks
    // are emitted by a constant-time scan rather than an indexed skip.
    let marker_slot = u64::conditional_select(
        &(layout.npub.saturating_sub(2) as u64),
        &(layout.npub.saturating_sub(1) as u64),
        known.ct_eq(&(layout.npub.saturating_sub(1) as u64)),
    );
    let mut message = Vec::with_capacity(32 * layout.npub.saturating_sub(2));
    for chunk in folded.iter().take(last_start) {
        message.extend_from_slice(chunk);
    }
    for p in 0..last_size.saturating_sub(2) {
        let mut out = [0u8; 32];
        let mut rank = 0u64;
        for j in 0..last_size {
            let slot = (last_start + j) as u64;
            let excluded = slot.ct_eq(&known) | slot.ct_eq(&marker_slot);
            let hit = !excluded & rank.ct_eq(&(p as u64));
            out = <[u8; 32]>::conditional_select(&folded[last_start + j], &out, hit);
            rank = u64::conditional_select(&(rank + 1), &rank, !excluded);
        }
        message.extend_from_slice(&out);
    }

    // The recovered opening must actually open the commitment.
    let reopened = Commitment::with_generator(value, &blind, generator)?;
    if !bool::from(reopened.ct_eq(commit)) {
        return Err(Error::Verification);
    }

    for buf in sec.iter_mut().chain(raw.iter_mut()) {
        *buf = [0u8; 32];
    }
    digits = [0u64; MAX_RINGS];
    let _ = core::hint::black_box((&sec, &raw, &digits));

    Ok(Rewound {
        value,
        blind,
        message,
        min_value: params.min_value,
        max_value: params.max_value,
    })
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{from_hex, from_hex_vec};

    /// The oracle-generated interop corpus. See `tools/zkp-interop/README.md`.
    const VECTORS: &str = include_str!("../../tools/zkp-interop/vectors/rangeproof.json");

    // --- minimal JSON reading ---

    fn section<'a>(src: &'a str, name: &str) -> &'a str {
        let key = alloc::format!("\"{name}\": [");
        let start = src.find(&key).expect("section") + key.len();
        let rest = &src[start..];
        let end = rest.find("\n  ]").expect("section end");
        &rest[..end]
    }

    fn objects(section: &str) -> impl Iterator<Item = &str> {
        section
            .split('{')
            .skip(1)
            .map(|o| o.split('}').next().unwrap())
    }

    fn raw<'a>(obj: &'a str, key: &str) -> &'a str {
        let needle = alloc::format!("\"{key}\":");
        let i = obj.find(&needle).expect("key") + needle.len();
        obj[i..].trim_start()
    }

    fn text<'a>(obj: &'a str, key: &str) -> &'a str {
        let v = raw(obj, key);
        let v = v.strip_prefix('"').expect("string value");
        &v[..v.find('"').expect("string end")]
    }

    fn number(obj: &str, key: &str) -> i64 {
        let v = raw(obj, key);
        let end = v
            .find(|c: char| !c.is_ascii_digit() && c != '-')
            .unwrap_or(v.len());
        v[..end].parse().expect("number")
    }

    fn unsigned(obj: &str, key: &str) -> u64 {
        let v = raw(obj, key);
        let end = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
        v[..end].parse().expect("number")
    }

    fn h() -> Generator {
        Generator::h()
    }

    fn blind_of(seed: u8) -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = 0x11;
        b[31] = seed;
        b
    }

    fn nonce_of(seed: u8) -> [u8; 32] {
        let mut n = [0xABu8; 32];
        n[0] = seed;
        n
    }

    // --- round trips ---

    #[test]
    fn round_trip_over_a_range_of_parameters() {
        let cases: &[(u64, u64, i32, u32)] = &[
            (0, 0, 0, 0),
            (1, 0, 0, 0),
            (0, 0, 0, 1),
            (1, 0, 0, 1),
            (5, 0, 0, 0),
            (255, 0, 0, 0),
            (256, 0, 0, 0),
            (3, 0, 0, 5),
            (42, 0, 0, 32),
            (42, 0, 0, 64),
            (u64::MAX, 0, 0, 0),
            (i64::MAX as u64, 0, 0, 0),
            (1000, 0, 1, 0),
            (1000, 0, 2, 0),
            (1234, 0, 2, 0),
            (1000000000, 0, 6, 0),
            (1000, 0, -1, 0),
            (0, 0, -1, 0),
            (u64::MAX, 0, -1, 0),
            (1000, 500, 0, 0),
            (1000, 1000, 0, 0),
            (7, 7, 0, 0),
            (1000, 500, 1, 0),
            (4294967295, 1, 0, 0),
        ];
        for (idx, &(value, min_value, exp, min_bits)) in cases.iter().enumerate() {
            let blind = blind_of(idx as u8 + 1);
            let nonce = nonce_of(idx as u8 + 1);
            let commit = Commitment::new(value, &blind).unwrap();
            let proof = sign(
                &commit,
                &blind,
                &nonce,
                value,
                min_value,
                exp,
                min_bits,
                &[],
                &[],
                &h(),
            )
            .unwrap_or_else(|e| panic!("sign {idx}: {e}"));
            let (min, max) =
                verify(&commit, &proof, &[], &h()).unwrap_or_else(|e| panic!("verify {idx}: {e}"));
            assert!(min <= value && value <= max, "case {idx}: {min}..{max}");
            let (iexp, imant, imin, imax) = info(&proof).unwrap();
            assert_eq!((imin, imax), (min, max));
            if exp == -1 {
                assert_eq!((iexp, imant), (-1, 0));
                assert_eq!((min, max), (value, value));
            }
        }
    }

    #[test]
    fn single_bit_proof_is_tight() {
        let blind = blind_of(9);
        let nonce = nonce_of(9);
        for value in [0u64, 1] {
            let commit = Commitment::new(value, &blind).unwrap();
            let proof = sign(&commit, &blind, &nonce, value, 0, 0, 1, &[], &[], &h()).unwrap();
            assert_eq!(verify(&commit, &proof, &[], &h()).unwrap(), (0, 1));
            assert_eq!(proof.len(), 98);
        }
    }

    #[test]
    fn exact_value_proof_reveals_the_value() {
        let blind = blind_of(11);
        let nonce = nonce_of(11);
        let commit = Commitment::new(12345, &blind).unwrap();
        let proof = sign(&commit, &blind, &nonce, 12345, 12345, 0, 0, &[], &[], &h()).unwrap();
        let (min, max) = verify(&commit, &proof, &[], &h()).unwrap();
        assert_eq!(min, 12345);
        assert!(max >= 12345);
    }

    #[test]
    fn rewind_recovers_value_blind_and_message() {
        let blind = blind_of(21);
        let nonce = nonce_of(21);
        let value = 4242u64;
        let commit = Commitment::new(value, &blind).unwrap();
        let msg = b"the quick brown fox jumps over the lazy dog";
        let proof = sign(&commit, &blind, &nonce, value, 0, 0, 32, msg, b"aad", &h()).unwrap();
        let out = rewind(&commit, &proof, &nonce, b"aad", &h()).unwrap();
        assert_eq!(out.value, value);
        assert_eq!(out.blind, blind);
        assert_eq!(&out.message[..msg.len()], msg);
        assert!(out.message[msg.len()..].iter().all(|&b| b == 0));
        assert!(out.min_value <= value && value <= out.max_value);
    }

    #[test]
    fn rewind_with_the_wrong_nonce_fails() {
        let blind = blind_of(22);
        let nonce = nonce_of(22);
        let commit = Commitment::new(7, &blind).unwrap();
        let proof = sign(&commit, &blind, &nonce, 7, 0, 0, 16, &[], &[], &h()).unwrap();
        assert!(rewind(&commit, &proof, &nonce_of(23), &[], &h()).is_err());
    }

    #[test]
    fn rewind_covers_every_proof_shape() {
        let cases: &[(u64, u64, i32, u32)] = &[
            (0, 0, 0, 0),
            (1, 0, 0, 1),
            (u64::MAX, 0, 0, 0),
            (1000, 0, 2, 0),
            (1000, 500, 1, 0),
            (1000, 0, -1, 0),
            (0, 0, -1, 0),
            (12345, 0, 0, 64),
        ];
        for (idx, &(value, min_value, exp, min_bits)) in cases.iter().enumerate() {
            let blind = blind_of(idx as u8 + 40);
            let nonce = nonce_of(idx as u8 + 40);
            let commit = Commitment::new(value, &blind).unwrap();
            let proof = sign(
                &commit,
                &blind,
                &nonce,
                value,
                min_value,
                exp,
                min_bits,
                &[],
                &[],
                &h(),
            )
            .unwrap();
            let out = rewind(&commit, &proof, &nonce, &[], &h())
                .unwrap_or_else(|e| panic!("rewind {idx}: {e}"));
            assert_eq!(out.value, value, "case {idx}");
            assert_eq!(out.blind, blind, "case {idx}");
        }
    }

    #[test]
    fn messages_fill_the_declared_capacity() {
        let blind = blind_of(31);
        let nonce = nonce_of(31);
        let commit = Commitment::new(9, &blind).unwrap();
        let cap = message_capacity(9, 0, 0, 32).unwrap();
        let msg: Vec<u8> = (0..cap).map(|i| (i % 251) as u8).collect();
        let proof = sign(&commit, &blind, &nonce, 9, 0, 0, 32, &msg, &[], &h()).unwrap();
        let out = rewind(&commit, &proof, &nonce, &[], &h()).unwrap();
        assert_eq!(&out.message[..cap], &msg[..]);
        // One byte more must be refused rather than silently truncated.
        let mut over = msg.clone();
        over.push(0);
        assert!(sign(&commit, &blind, &nonce, 9, 0, 0, 32, &over, &[], &h()).is_err());
    }

    #[test]
    fn message_capacity_matches_the_documented_maximum() {
        assert_eq!(message_capacity(0, 0, 0, 64).unwrap(), MAX_MESSAGE_LEN);
        assert_eq!(message_capacity(0, 0, 0, 1).unwrap(), 0);
    }

    // --- soundness ---

    #[test]
    fn a_proof_does_not_verify_against_another_commitment() {
        let blind = blind_of(51);
        let nonce = nonce_of(51);
        let commit = Commitment::new(100, &blind).unwrap();
        let proof = sign(&commit, &blind, &nonce, 100, 0, 0, 16, &[], &[], &h()).unwrap();
        let other = Commitment::new(100, &blind_of(52)).unwrap();
        assert!(verify(&other, &proof, &[], &h()).is_err());
        let same_blind_other_value = Commitment::new(101, &blind).unwrap();
        assert!(verify(&same_blind_other_value, &proof, &[], &h()).is_err());
    }

    #[test]
    fn a_tampered_proof_fails() {
        let blind = blind_of(53);
        let nonce = nonce_of(53);
        let commit = Commitment::new(77, &blind).unwrap();
        let proof = sign(&commit, &blind, &nonce, 77, 0, 0, 8, &[], &[], &h()).unwrap();
        assert!(verify(&commit, &proof, &[], &h()).is_ok());
        for i in 0..proof.len() {
            let mut bad = proof.clone();
            bad[i] ^= 0x01;
            assert!(
                verify(&commit, &bad, &[], &h()).is_err(),
                "byte {i} flip verified"
            );
        }
    }

    #[test]
    fn extra_commit_and_generator_are_bound() {
        let blind = blind_of(54);
        let nonce = nonce_of(54);
        let commit = Commitment::new(5, &blind).unwrap();
        let proof = sign(&commit, &blind, &nonce, 5, 0, 0, 8, &[], b"context", &h()).unwrap();
        assert!(verify(&commit, &proof, b"context", &h()).is_ok());
        assert!(verify(&commit, &proof, b"contexT", &h()).is_err());
        assert!(verify(&commit, &proof, &[], &h()).is_err());

        let asset = Generator::from_asset_tag(&[7u8; 32]).unwrap();
        let acommit = Commitment::with_generator(5, &blind, &asset).unwrap();
        let aproof = sign(&acommit, &blind, &nonce, 5, 0, 0, 8, &[], &[], &asset).unwrap();
        assert!(verify(&acommit, &aproof, &[], &asset).is_ok());
        assert!(verify(&acommit, &aproof, &[], &h()).is_err());
        let out = rewind(&acommit, &aproof, &nonce, &[], &asset).unwrap();
        assert_eq!(out.value, 5);
        assert_eq!(out.blind, blind);
    }

    #[test]
    fn the_claimed_interval_bounds_the_value() {
        let blind = blind_of(55);
        let nonce = nonce_of(55);
        for &(value, min_value, exp, min_bits) in &[
            (0u64, 0u64, 0i32, 0u32),
            (1, 0, 0, 0),
            (999, 0, 1, 0),
            (999, 0, 2, 0),
            (123456789, 0, 4, 0),
            (500, 500, 0, 0),
            (1024, 512, 0, 0),
            (u64::MAX, 0, 0, 0),
        ] {
            let commit = Commitment::new(value, &blind).unwrap();
            let proof = sign(
                &commit,
                &blind,
                &nonce,
                value,
                min_value,
                exp,
                min_bits,
                &[],
                &[],
                &h(),
            )
            .unwrap();
            let (min, max) = verify(&commit, &proof, &[], &h()).unwrap();
            assert!(min <= value, "{value} < min {min}");
            assert!(value <= max, "{value} > max {max}");
            assert!(min >= min_value);
        }
    }

    #[test]
    fn sign_rejects_impossible_parameters() {
        let blind = blind_of(56);
        let nonce = nonce_of(56);
        let commit = Commitment::new(10, &blind).unwrap();
        // min_value above the value.
        assert!(sign(&commit, &blind, &nonce, 10, 11, 0, 0, &[], &[], &h()).is_err());
        // Out-of-range exponent and min_bits.
        assert!(sign(&commit, &blind, &nonce, 10, 0, 19, 0, &[], &[], &h()).is_err());
        assert!(sign(&commit, &blind, &nonce, 10, 0, -2, 0, &[], &[], &h()).is_err());
        assert!(sign(&commit, &blind, &nonce, 10, 0, 0, 65, &[], &[], &h()).is_err());
        // A shifted proof of a value at or above 2^63 with a nonzero minimum.
        let big = Commitment::new(u64::MAX, &blind).unwrap();
        assert!(sign(&big, &blind, &nonce, u64::MAX, 1, 0, 0, &[], &[], &h()).is_err());
    }

    // --- no panics on hostile input ---

    #[test]
    fn truncations_never_panic() {
        let blind = blind_of(61);
        let nonce = nonce_of(61);
        let commit = Commitment::new(4242, &blind).unwrap();
        let proof = sign(&commit, &blind, &nonce, 4242, 7, 1, 16, b"hi", b"x", &h()).unwrap();
        for cut in 0..proof.len() {
            assert!(verify(&commit, &proof[..cut], b"x", &h()).is_err());
            assert!(rewind(&commit, &proof[..cut], &nonce, b"x", &h()).is_err());
            let _ = info(&proof[..cut]);
        }
        // Trailing bytes are refused too.
        let mut longer = proof.clone();
        longer.push(0);
        assert!(verify(&commit, &longer, b"x", &h()).is_err());
    }

    #[test]
    fn adversarial_byte_strings_never_panic() {
        let blind = blind_of(62);
        let commit = Commitment::new(1, &blind).unwrap();
        // Headers claiming absurd shapes, plus a deterministic pseudo-random
        // sweep. Nothing may panic; everything must return an error.
        let mut state = 0x9E3779B97F4A7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for len in [0usize, 1, 2, 3, 9, 10, 33, 65, 97, 98, 200, 1000, 5200] {
            for _ in 0..24 {
                let mut buf = vec![0u8; len];
                for chunk in buf.chunks_mut(8) {
                    let word = next().to_le_bytes();
                    chunk.copy_from_slice(&word[..chunk.len()]);
                }
                let _ = info(&buf);
                let _ = verify(&commit, &buf, &[], &h());
                let _ = rewind(&commit, &buf, &nonce_of(1), &[], &h());
            }
        }
        for flags in 0u16..256 {
            for second in [0u8, 0x3f, 0xff] {
                let mut buf = vec![flags as u8, second];
                buf.extend_from_slice(&[0xffu8; 16]);
                let _ = info(&buf);
                let _ = verify(&commit, &buf, &[], &h());
                let mut big = vec![flags as u8, second];
                big.resize(5200, 0xAA);
                let _ = info(&big);
                let _ = verify(&commit, &big, &[], &h());
                let _ = rewind(&commit, &big, &nonce_of(2), &[], &h());
            }
        }
    }

    #[test]
    fn reserved_header_bits_are_rejected() {
        let blind = blind_of(63);
        let nonce = nonce_of(63);
        let commit = Commitment::new(42, &blind).unwrap();
        let proof = sign(&commit, &blind, &nonce, 42, 0, 0, 8, &[], &[], &h()).unwrap();
        assert!(verify(&commit, &proof, &[], &h()).is_ok());
        for (index, mask) in [(0usize, 0x80u8), (1, 0x40), (1, 0x80)] {
            let mut bad = proof.clone();
            bad[index] |= mask;
            assert!(info(&bad).is_err(), "byte {index} | {mask:#x} parsed");
            assert!(verify(&commit, &bad, &[], &h()).is_err());
        }
        // The exponent field only runs to 18.
        for exp in 19u8..32 {
            let mut bad = proof.clone();
            bad[0] = (bad[0] & 0xe0) | exp;
            assert!(info(&bad).is_err(), "exp {exp} parsed");
            assert!(verify(&commit, &bad, &[], &h()).is_err());
        }
    }

    #[test]
    fn info_never_accepts_an_overflowing_header() {
        // exp = 18, mantissa = 64, min_value = 2^64-1: the claimed interval
        // cannot be represented, so the header is malformed.
        let mut proof = vec![0x40 | 0x20 | 18, 63];
        proof.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(info(&proof).is_err());
    }

    // --- interop against the oracle corpus ---

    #[test]
    fn interop_sign_reproduces_the_oracle_byte_for_byte() {
        let mut count = 0;
        for obj in objects(section(VECTORS, "proofs")) {
            let value = unsigned(obj, "value");
            let min_value = unsigned(obj, "min_value");
            let exp = number(obj, "exp") as i32;
            let min_bits = unsigned(obj, "min_bits") as u32;
            let blind = from_hex::<32>(text(obj, "blind"));
            let nonce = from_hex::<32>(text(obj, "nonce"));
            let generator = Generator::parse(&from_hex::<33>(text(obj, "generator"))).unwrap();
            let commit = Commitment::parse(&from_hex::<33>(text(obj, "commitment"))).unwrap();
            let message = from_hex_vec(text(obj, "message"));
            let extra = from_hex_vec(text(obj, "extra_commit"));
            let expected = from_hex_vec(text(obj, "proof"));

            let proof = sign(
                &commit, &blind, &nonce, value, min_value, exp, min_bits, &message, &extra,
                &generator,
            )
            .unwrap_or_else(|e| panic!("sign v={value} min={min_value} exp={exp}: {e}"));
            assert_eq!(
                proof, expected,
                "proof mismatch for value={value} min={min_value} exp={exp} min_bits={min_bits}"
            );
            count += 1;
        }
        assert!(count >= 55, "expected the full corpus, got {count}");
    }

    #[test]
    fn interop_verify_and_info_match_the_oracle() {
        for obj in objects(section(VECTORS, "proofs")) {
            let generator = Generator::parse(&from_hex::<33>(text(obj, "generator"))).unwrap();
            let commit = Commitment::parse(&from_hex::<33>(text(obj, "commitment"))).unwrap();
            let extra = from_hex_vec(text(obj, "extra_commit"));
            let proof = from_hex_vec(text(obj, "proof"));
            let min = unsigned(obj, "min");
            let max = unsigned(obj, "max");
            assert_eq!(
                verify(&commit, &proof, &extra, &generator).unwrap(),
                (min, max)
            );
            let (exp, mantissa, imin, imax) = info(&proof).unwrap();
            assert_eq!(exp, number(obj, "info_exp") as i32);
            assert_eq!(mantissa, unsigned(obj, "info_mantissa") as u32);
            assert_eq!((imin, imax), (min, max));
        }
    }

    #[test]
    fn interop_rewind_matches_the_oracle() {
        for obj in objects(section(VECTORS, "proofs")) {
            let generator = Generator::parse(&from_hex::<33>(text(obj, "generator"))).unwrap();
            let commit = Commitment::parse(&from_hex::<33>(text(obj, "commitment"))).unwrap();
            let nonce = from_hex::<32>(text(obj, "nonce"));
            let extra = from_hex_vec(text(obj, "extra_commit"));
            let proof = from_hex_vec(text(obj, "proof"));
            let out = rewind(&commit, &proof, &nonce, &extra, &generator).unwrap();
            assert_eq!(out.value, unsigned(obj, "rewind_value"));
            assert_eq!(out.blind, from_hex::<32>(text(obj, "rewind_blind")));
            assert_eq!(out.message.len(), unsigned(obj, "rewind_outlen") as usize);
            assert_eq!(out.message, from_hex_vec(text(obj, "rewind_message")));
        }
    }

    #[test]
    fn interop_rejections_match_the_oracle() {
        let mut count = 0;
        for obj in objects(section(VECTORS, "rejects")) {
            let generator = Generator::parse(&from_hex::<33>(text(obj, "generator"))).unwrap();
            let commit = Commitment::parse(&from_hex::<33>(text(obj, "commitment"))).unwrap();
            let proof = from_hex_vec(text(obj, "proof"));
            assert!(
                verify(&commit, &proof, &[], &generator).is_err(),
                "accepted a proof the oracle rejects ({})",
                text(obj, "why")
            );
            count += 1;
        }
        assert!(count > 10, "expected the reject corpus, got {count}");
    }
}
