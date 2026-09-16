//! Falcon (FN-DSA) signatures — Falcon-512 and Falcon-1024: key generation,
//! signing, and verification.
//!
//! Falcon is the NTRU-lattice hash-and-sign signature scheme selected by NIST
//! for standardization as FN-DSA (FIPS 206, draft). This module implements the
//! full scheme: [`FalconPrivateKey::generate`] / [`FalconPrivateKey::sign`] and
//! the [`verify`] / [`FalconPublicKey`] verification path.
//!
//! The verification half needs no allocator; `FalconPrivateKey` (key generation
//! and signing) is behind the `alloc` feature. See "Memory" below for the
//! measurements behind that split.
//!
//! **Floating point.** Signing needs an FFT, an LDL tree, and a discrete
//! Gaussian sampler — all floating-point — but the crate is `no_std` with no
//! `libm`, and the signing path is secret-dependent. So all FP runs in a
//! software-emulated IEEE-754 double (`fpr`, the approach Falcon's reference
//! calls FPEMU): pure integer ops, no FPU required, identical on every target,
//! and bit-reproducible. The emulation is **branch-free by construction**:
//! every operation is straight-line mask arithmetic with fixed-trip loops (see
//! the "Constant-time contract" in `fpr`), so no operand value ever selects a
//! branch, a memory address, or a shift count.
//!
//! **Constant-time scope.** The **per-signature path is constant-time** at the
//! source level: the FPEMU beneath the sampler and the FFT/tree arithmetic has
//! no value-dependent branches, and the sampler and `ff_sampling` are
//! data-oblivious apart from what the Falcon design itself leaks (the number
//! of rejection-sampling rounds and `ber_exp` byte comparisons, which depend on
//! fresh randomness — the same trade-off the reference implementation makes).
//! **Key generation is best-effort** — NTRUSolve's big-integer arithmetic and
//! the Gaussian-rejection retries are variable-time (as in the reference);
//! keygen is one-time, on fresh entropy.
//! **Verification** takes only public inputs, never panics on malformed input
//! (every access is bounds-checked), and returns `false`/`Err` instead.
//!
//! **Signature format.** Falcon standardizes two encodings of the same
//! signature — padded (fixed length) and compressed/unpadded (variable length,
//! what the NIST KAT vectors carry). Accepting both at once would make
//! signatures malleable, so every verification entry point pins exactly one:
//! [`verify`] and [`FalconPublicKey::verify`] require the [`Format::Padded`]
//! form that [`FalconPrivateKey::sign`] emits, and
//! [`verify_with_format`] / [`FalconPublicKey::verify_with_format`] let a caller
//! ask for the compressed form instead.
//!
//! Verification needs only SHAKE-256 (for `HashToPoint`) and integer arithmetic
//! modulo `q = 12289`.
//!
//! # Memory
//!
//! **Verification is allocator-free** — [`verify`], [`verify_with_format`],
//! [`FalconPublicKey`] and its methods need no `alloc` feature and perform zero
//! heap allocations (measured: 0 bytes, 0 calls, at both degrees). The whole
//! working set is one `[i16; 1024]` for the decompressed `s₂`: the hashed point
//! `c` is squeezed off SHAKE-256 one coefficient at a time, and the negacyclic
//! product `s₂·h` is computed one output coefficient at a time, so neither
//! needs a buffer. Measured `thumbv7em-none-eabi` release frames:
//! [`FalconPublicKey::verify_with_format`] 2 584 B, and 4 160 B more for the
//! free [`verify`], which parses the 2 056-byte key into its own frame — so an
//! embedded caller that parses once and keeps the [`FalconPublicKey`] pays
//! ~2.6 KiB per call rather than ~6.8 KiB.
//!
//! **Signing and key generation require `alloc`**, and deliberately keep it.
//! The numbers, measured with a counting global allocator:
//!
//! | | Falcon-512 | Falcon-1024 |
//! |---|---|---|
//! | expanded key, resident for the key's lifetime | 170 KiB | 354 KiB |
//! | transient, per signature | 141 KiB | 282 KiB |
//! | transient, `generate` | 881 KiB | 3 265 KiB |
//! | transient, `FalconPrivateKey::from_bytes` | 393 KiB | 802 KiB |
//!
//! A caller-supplied scratch buffer in the style of the reference
//! implementation's `falcon_sign_dyn(tmp, tmp_len)` would therefore have to be
//! ~311 KiB (Falcon-512) or ~636 KiB (Falcon-1024) to sign, which is more RAM
//! than the Cortex-M class of part this directive is for has in total; the
//! expanded basis and LDL tree alone exceed it. `generate` is worse still and
//! not even fixed-size: NTRUSolve's tower-of-rings recursion drives
//! variable-width big integers (~8 kbit at n = 512, ~16 kbit at n = 1024) and
//! 21.6 M / 122 M individual allocations, whose sizes depend on the sampled
//! polynomials. So the split is verify-only, as in `xmss`, rather than an
//! `_into` + scratch API that could not be used in practice.
//!
//! Implemented against the Falcon specification v1.2 (2020-10-01), the document
//! underlying the NIST round-3 submission and the FN-DSA draft:
//!
//! * `HashToPoint` — spec §3.7, Algorithm 3.
//! * `Verify` — spec §3.10, Algorithm 16.
//! * `Decompress` (signature `s`) — spec §3.11.2, Algorithm 18, including the
//!   three canonicality checks (fixed bit length, no `100000001` encoding of
//!   zero, trailing bits must be zero).
//! * Public-key / signature encoding — spec §3.11.3–3.11.4.
//! * Parameters (`q`, `⌊β²⌋`, byte lengths) — spec §3.13, Table 3.3.
//!
//! # Example
//!
//! ```ignore
//! use purecrypto::falcon::verify;
//! let ok = verify(public_key, message, signature);
//! ```
#![cfg_attr(
    not(feature = "alloc"),
    doc = "",
    doc = "[`FalconPrivateKey::generate`]: crate::falcon#memory",
    doc = "[`FalconPrivateKey::sign`]: crate::falcon#memory"
)]
#![allow(clippy::needless_range_loop)]

// Everything below the verification path needs a heap: see the "Memory" section
// in the module docs for the measured numbers behind that split.
#[cfg(feature = "alloc")]
mod encode;
#[cfg(feature = "alloc")]
mod fft;
#[cfg(feature = "alloc")]
mod fpr;
#[cfg(feature = "key")]
mod key_impl;
#[cfg(feature = "alloc")]
mod keygen;
#[cfg(feature = "alloc")]
mod sampler;
#[cfg(feature = "alloc")]
mod sign;
#[cfg(feature = "alloc")]
mod tree;
#[cfg(feature = "alloc")]
mod zint;

use crate::hash::{ExtendableOutput, Shake256, XofReader};

/// Falcon modulus `q`.
const Q: u32 = 12289;

/// `k = ⌊2¹⁶ / q⌋`; the `HashToPoint` rejection threshold is `k·q`
/// (spec §3.7, Algorithm 3, line 1).
const HASH_REJECT: u32 = 5 * Q; // 61445

/// Errors returned by Falcon parsing/verification helpers.
///
/// The top-level [`verify`] function maps every failure to `false`; the typed
/// API ([`FalconPublicKey::verify`]) surfaces these so callers can distinguish
/// a malformed key from a signature that simply did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A public key, signature, or one of their fields had the wrong length.
    InvalidLength,
    /// A header byte, packing, or encoding was structurally invalid.
    Malformed,
    /// Signing exhausted its rejection-sampling retry budget. Unreachable for a
    /// key that [`FalconPrivateKey::generate`] produced or
    /// [`FalconPrivateKey::from_bytes`] accepted; the budget exists so that a
    /// degenerate basis fails instead of looping forever. See
    /// [`FalconPrivateKey::try_sign`].
    #[cfg_attr(
        not(feature = "alloc"),
        doc = "",
        doc = "[`FalconPrivateKey::generate`]: crate::falcon#memory",
        doc = "[`FalconPrivateKey::from_bytes`]: crate::falcon#memory",
        doc = "[`FalconPrivateKey::try_sign`]: crate::falcon#memory"
    )]
    SamplingFailed,
}

/// A Falcon parameter set (degree).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Degree {
    /// Falcon-512 (`n = 512`, NIST level I).
    Falcon512,
    /// Falcon-1024 (`n = 1024`, NIST level V).
    Falcon1024,
}

impl Degree {
    /// Ring degree `n`.
    const fn n(self) -> usize {
        match self {
            Degree::Falcon512 => 512,
            Degree::Falcon1024 => 1024,
        }
    }

    /// Encoded public-key length, in bytes (spec §3.13).
    ///
    /// `1` header byte `+ ⌈14·n / 8⌉` for the 14-bit-packed `h`.
    const fn pubkey_len(self) -> usize {
        match self {
            Degree::Falcon512 => 897,
            Degree::Falcon1024 => 1793,
        }
    }

    /// Full padded signature length `sbytelen`, in bytes (spec §3.13).
    const fn sig_len(self) -> usize {
        match self {
            Degree::Falcon512 => 666,
            Degree::Falcon1024 => 1280,
        }
    }

    /// Largest [`Format::Compressed`] signature accepted, in bytes: header,
    /// nonce, and up to `⌈11n/8⌉` bytes of compressed `s` — the reference
    /// implementation's `FALCON_SIG_COMPRESSED_MAXSIZE(logn)`, which is also
    /// what its signer bounds an unpadded signature by before retrying.
    ///
    /// The compressed form is variable-length and, unlike the padded one, is
    /// *not* capped at [`sig_len`](Self::sig_len): the NIST KAT signer
    /// (`nist.c`, `CRYPTO_BYTES`) and `falcon_sign_dyn` both emit `s`
    /// encodings longer than `sig_len − 41` whenever the sampled vector needs
    /// them (about 6·10⁻⁴ of Falcon-1024 signatures), and the reference
    /// verifier accepts any length that decodes exactly.
    const fn compressed_max_len(self) -> usize {
        1 + NONCE_LEN + (11 * self.n()).div_ceil(8)
    }

    /// Acceptance bound `⌊β²⌋` (spec §3.13, Table 3.3).
    const fn sig_bound(self) -> u64 {
        match self {
            Degree::Falcon512 => 34_034_726,
            Degree::Falcon1024 => 70_265_242,
        }
    }

    /// The `logn` nibble used in encoding headers (`log₂ n`).
    #[cfg(feature = "alloc")]
    const fn logn(self) -> u8 {
        match self {
            Degree::Falcon512 => 9,
            Degree::Falcon1024 => 10,
        }
    }

    /// Recover the parameter set from a header `logn` nibble.
    const fn from_logn(logn: u8) -> Option<Degree> {
        match logn {
            9 => Some(Degree::Falcon512),
            10 => Some(Degree::Falcon1024),
            _ => None,
        }
    }
}

/// Length of the salt/nonce `r` prepended to the message before hashing.
const NONCE_LEN: usize = 40;

/// The largest ring degree any parameter set uses (Falcon-1024).
///
/// Every fixed-size buffer on the verification path is cut to this, so one
/// concrete type covers both parameter sets; a Falcon-512 key leaves the upper
/// half unused. That costs 1 KiB per key versus a per-degree type, which is the
/// price of keeping [`FalconPublicKey`] a single type — [`verify`] discovers the
/// degree from the encoded header at run time, so the size is not known at the
/// API boundary the way `mlkem`'s is.
const MAX_N: usize = 1024;

/// A parsed Falcon public key: the polynomial `h` with `n` coefficients in
/// `[0, q)`, plus its degree.
///
/// Holds `h` inline (`2·MAX_N` bytes), so parsing and verifying a signature
/// needs no allocator.
pub struct FalconPublicKey {
    degree: Degree,
    /// `h`, `n` coefficients, each already reduced into `[0, q)`; entries past
    /// `degree.n()` are zero and never read.
    h: [u16; MAX_N],
}

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

impl FalconPublicKey {
    /// Parse an encoded Falcon public key (spec §3.11.4).
    ///
    /// The first byte is a header `0000nnnn`; the four high bits must be zero
    /// and `nnnn` selects the degree. The remaining `⌈14n/8⌉` bytes pack the
    /// `n` coefficients of `h` at 14 bits each, big-endian within the bit
    /// stream. Every coefficient must lie in `[0, q)`.
    pub fn from_bytes(pk: &[u8]) -> Result<FalconPublicKey, Error> {
        let header = *pk.first().ok_or(Error::InvalidLength)?;
        // Header must be exactly 0000nnnn (top nibble zero).
        if header & 0xF0 != 0x00 {
            return Err(Error::Malformed);
        }
        let degree = Degree::from_logn(header & 0x0F).ok_or(Error::Malformed)?;
        let n = degree.n();

        if pk.len() != degree.pubkey_len() {
            return Err(Error::InvalidLength);
        }

        let body = &pk[1..];
        // Unpack n 14-bit big-endian values from `body`.
        let mut h = [0u16; MAX_N];
        let mut acc: u32 = 0;
        let mut acc_bits: u32 = 0;
        let mut idx = 0usize;
        for slot in h[..n].iter_mut() {
            // Refill the accumulator until at least 14 bits are buffered.
            while acc_bits < 14 {
                let byte = *body.get(idx).ok_or(Error::InvalidLength)?;
                idx += 1;
                acc = (acc << 8) | byte as u32;
                acc_bits += 8;
            }
            acc_bits -= 14;
            let coeff = (acc >> acc_bits) & 0x3FFF;
            if coeff >= Q {
                return Err(Error::Malformed);
            }
            *slot = coeff as u16;
        }

        // Any leftover bits (the padding tail of the final byte) must be zero,
        // and there must be no trailing bytes — both already implied by the
        // exact-length check plus consuming `idx` up to the end. Enforce the
        // padding-bits-zero rule for canonicality.
        let leftover_mask = if acc_bits == 0 {
            0
        } else {
            (1u32 << acc_bits) - 1
        };
        if acc & leftover_mask != 0 {
            return Err(Error::Malformed);
        }
        // All input bytes must have been consumed.
        if idx != body.len() {
            return Err(Error::Malformed);
        }

        Ok(FalconPublicKey { degree, h })
    }

    /// The parameter set (degree) of this key.
    pub fn degree(&self) -> Degree {
        self.degree
    }

    /// Verify `sig` over `msg` under this public key, requiring the
    /// [`Format::Padded`] encoding that [`FalconPrivateKey::sign`] emits.
    ///
    /// Returns `Ok(true)` for a valid signature, `Ok(false)` for a
    /// well-formed-but-invalid one, and `Err` if the signature is structurally
    /// malformed (wrong length, bad header, non-canonical compression). Never
    /// panics.
    ///
    /// Falcon defines two encodings of the same signature, and accepting both
    /// makes signatures malleable: an attacker can rewrite a valid compressed
    /// signature into the padded form (or the reverse) and obtain a second,
    /// distinct byte string that verifies for the same `(msg, pk)`. Anything
    /// keyed on `H(signature)` — dedup caches, transaction ids, replay tables —
    /// then sees one authenticated payload under two identities. So this
    /// entry point pins one format. Use [`verify_with_format`] to verify
    /// signatures produced elsewhere in the compressed encoding (the NIST KAT
    /// vectors, for instance, carry that form).
    ///
    /// [`verify_with_format`]: FalconPublicKey::verify_with_format
    #[cfg_attr(
        not(feature = "alloc"),
        doc = "",
        doc = "[`FalconPrivateKey::sign`]: crate::falcon#memory"
    )]
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, Error> {
        self.verify_with_format(msg, sig, Format::Padded)
    }

    /// Verify `sig` over `msg` under this public key, requiring exactly the
    /// given signature [`Format`].
    ///
    /// A signature in the other encoding is rejected with `Err`, even if it
    /// would otherwise be valid — that is the point: see [`Self::verify`].
    pub fn verify_with_format(
        &self,
        msg: &[u8],
        sig: &[u8],
        format: Format,
    ) -> Result<bool, Error> {
        let n = self.degree.n();

        // --- Parse signature header. ---
        //
        // Falcon defines two on-the-wire encodings of the compressed signature
        // (spec §3.11.3 / §3.11.6):
        //
        //   * **Padded**: header byte `0011nnnn` (`0x30 + logn`); the whole
        //     signature is a fixed `sbytelen` bytes, the compressed `s` being
        //     zero-padded up to that length (`Degree::sig_len`).
        //   * **Compressed / unpadded**: header byte `0010nnnn`
        //     (`0x20 + logn`); the signature is variable length, exactly
        //     `1 + 40 + |compressed-s|` bytes — this is what the NIST KAT
        //     vectors carry.
        //
        // Both wrap `header || nonce(40) || compressed-s`, and the *same*
        // signature can be written either way — so accepting both at once would
        // make signatures malleable. The caller pins one, and a header for the
        // other format is rejected outright.
        let header = *sig.first().ok_or(Error::InvalidLength)?;
        if Degree::from_logn(header & 0x0F) != Some(self.degree) {
            return Err(Error::Malformed);
        }
        if header & 0xF0 != format.header_nibble() {
            return Err(Error::Malformed);
        }
        let is_padded = format == Format::Padded;
        if is_padded {
            // Padded: must be exactly sbytelen, with zero-byte tail (the
            // trailing-bit-zero check in `decompress` enforces canonicality
            // of that padding).
            if sig.len() != self.degree.sig_len() {
                return Err(Error::InvalidLength);
            }
        } else {
            // Unpadded: just needs room for the header + nonce, and must
            // not exceed the reference's compressed-size bound (see
            // `Degree::compressed_max_len` for why that is *not* `sig_len`).
            if sig.len() <= 1 + NONCE_LEN || sig.len() > self.degree.compressed_max_len() {
                return Err(Error::InvalidLength);
            }
        }

        let nonce = &sig[1..1 + NONCE_LEN];
        let s_bytes = &sig[1 + NONCE_LEN..];

        // --- Decompress s -> s2 (n signed coefficients), canonical. ---
        //
        // `s2` is the only polynomial buffer verification needs: `c` is consumed
        // one coefficient at a time straight off the SHAKE-256 stream, and the
        // convolution below is transposed so it needs no accumulator array. The
        // frame is therefore `2·MAX_N` bytes regardless of degree.
        let mut s2 = [0i16; MAX_N];
        let consumed_bits = match decompress(s_bytes, &mut s2[..n]) {
            Some(v) => v,
            None => return Ok(false),
        };

        // Canonical encoding (unpadded only): the padded format legitimately
        // zero-pads `s` up to a fixed length, but the unpadded format is
        // variable-length, so a whole unused trailing byte means the signature
        // carries surplus bytes. Appending `0x00` bytes leaves the residual-bit
        // check (in `decompress`) satisfied yet changes the encoding, giving one
        // (message, key) pair multiple valid byte-encodings (malleability).
        // Reject when a full unused trailing byte remains.
        if !is_padded && s_bytes.len() * 8 - consumed_bits >= 8 {
            return Ok(false);
        }

        // --- s1 = c - s2*h mod q, centered; accumulate ||(s1, s2)||^2. ---
        //
        // `c = HashToPoint(nonce ‖ msg)` is squeezed lazily: coefficient `k` is
        // drawn exactly when it is needed, so the whole polynomial never has to
        // be materialized. The negacyclic product `s2·h mod (xⁿ+1)` is likewise
        // computed one output coefficient at a time — `(s2·h)_k` gathers
        // `s2_i·h_{k-i}` for `i ≤ k` and `−s2_i·h_{k+n-i}` for `i > k`
        // (`xⁿ = −1`) — which is the same `O(n²)` schoolbook work as
        // accumulating into a `[i64; n]` product array, minus the array.
        let mut point = hash_to_point_reader(nonce, msg);

        let bound = self.degree.sig_bound();
        let mut norm: u64 = 0;
        for k in 0..n {
            let c_k = next_point_coeff(&mut point);

            // |s2_i| ≤ 2047 (`decompress` caps the unary run) and h_j < q, so
            // each term is below 2²⁵ and n ≤ 1024 of them stay far inside i64.
            let mut prod: i64 = 0;
            for i in 0..=k {
                prod += s2[i] as i64 * self.h[k - i] as i64;
            }
            for i in k + 1..n {
                prod -= s2[i] as i64 * self.h[k + n - i] as i64;
            }

            // s1_k = c_k - (s2·h)_k (mod q), then centered to (-q/2, q/2].
            let v = (c_k as i64 - prod).rem_euclid(Q as i64); // in [0, q)
            let centered = center(v as u32);
            norm += (centered as i64 * centered as i64) as u64;

            // s2 is already a centered signed value.
            let s2v = s2[k] as i64;
            norm += (s2v * s2v) as u64;

            if norm > bound {
                return Ok(false);
            }
        }

        Ok(norm <= bound)
    }
}

/// Center a value `v ∈ [0, q)` into the symmetric range `(-q/2, q/2]`.
#[inline]
fn center(v: u32) -> i32 {
    let v = v as i32;
    if v > (Q as i32) / 2 { v - Q as i32 } else { v }
}

/// Start `HashToPoint(r ‖ msg, q, n)` — spec §3.7, Algorithm 3.
///
/// Absorbs `nonce ‖ msg` into SHAKE-256 and hands back the squeezing reader;
/// [`next_point_coeff`] draws the coefficients one at a time. Splitting it this
/// way lets verification consume `c` as a stream (no polynomial buffer) while
/// signing, which needs `c` twice, still materializes it.
fn hash_to_point_reader(nonce: &[u8], msg: &[u8]) -> impl XofReader {
    let mut xof = Shake256::new();
    xof.update(nonce);
    xof.update(msg);
    xof.finalize_xof()
}

/// Draw the next `HashToPoint` coefficient: squeeze 16 bits at a time
/// (big-endian), reject any draw `≥ 5q`, and reduce the rest mod `q`.
#[inline]
fn next_point_coeff<R: XofReader>(reader: &mut R) -> u16 {
    let mut buf = [0u8; 2];
    loop {
        reader.read(&mut buf);
        let t = ((buf[0] as u32) << 8) | buf[1] as u32;
        if t < HASH_REJECT {
            return (t % Q) as u16;
        }
    }
}

/// Fill `out` with `out.len()` `HashToPoint` coefficients.
#[cfg(feature = "alloc")]
fn hash_to_point_into(nonce: &[u8], msg: &[u8], out: &mut [u16]) {
    let mut reader = hash_to_point_reader(nonce, msg);
    for slot in out.iter_mut() {
        *slot = next_point_coeff(&mut reader);
    }
}

/// `Decompress(str, slen)` for the signature polynomial `s` — spec §3.11.2,
/// Algorithm 18, with all three canonicality checks.
///
/// `s_bytes` is the byte region following the nonce in the signature; the bit
/// length `slen = 8·sbytelen − 328` is therefore `8 · s_bytes.len()`. The `n`
/// coefficients are written into `out` (whose length *is* `n`). Returns `None`
/// (the spec's `⊥`) on any malformed / non-canonical input, otherwise the number
/// of bits consumed by the coefficient encoding (i.e. excluding the trailing
/// zero-padding bits the caller may further gate).
fn decompress(s_bytes: &[u8], out: &mut [i16]) -> Option<usize> {
    // A bit cursor over `s_bytes`, MSB-first within each byte.
    let total_bits = s_bytes.len() * 8;
    let mut pos = 0usize;

    // Read one bit at the cursor, advancing it. Returns None past the end.
    let get_bit = |s: &[u8], p: &mut usize| -> Option<u32> {
        if *p >= total_bits {
            return None;
        }
        let byte = s[*p >> 3];
        let bit = (byte >> (7 - (*p & 7))) & 1;
        *p += 1;
        Some(bit as u32)
    };

    for slot in out.iter_mut() {
        // Sign bit.
        let sign = get_bit(s_bytes, &mut pos)?;
        // 7 low bits, most-significant first.
        let mut low: u32 = 0;
        for _ in 0..7 {
            low = (low << 1) | get_bit(s_bytes, &mut pos)?;
        }
        // Unary high bits: count zeros until a terminating 1.
        let mut high: u32 = 0;
        loop {
            let b = get_bit(s_bytes, &mut pos)?;
            if b == 1 {
                break;
            }
            high += 1;
            // Spec §3.11.2 / reference `comp_decode`: the unary part may not
            // exceed 15, i.e. every coefficient magnitude is below 2¹¹ = 2048.
            // Rejecting on the 16th zero matches the reference decoder exactly.
            if high > 15 {
                return None;
            }
        }

        // `high ≤ 15`, `low < 128`: the magnitude is at most 2047.
        let magnitude = (high << 7) | low;
        // Canonical: reject the encoding "1 0000000 1" of zero (sign=1, mag=0),
        // i.e. a negative zero. (Spec §3.11.2 check 2 / Alg 18 lines 9-10.)
        if magnitude == 0 && sign == 1 {
            return None;
        }
        *slot = if sign == 1 {
            -(magnitude as i16)
        } else {
            magnitude as i16
        };
    }

    // Bits consumed by the coefficient encoding proper, before the trailing
    // zero-padding the caller may additionally constrain.
    let consumed_bits = pos;

    // Canonical: every remaining bit must be zero (Alg 18 lines 12-13).
    while pos < total_bits {
        if get_bit(s_bytes, &mut pos)? != 0 {
            return None;
        }
    }

    Some(consumed_bits)
}

/// The on-the-wire encoding of a Falcon signature (spec §3.11.3 / §3.11.6).
///
/// Falcon standardizes two encodings of the *same* signature, and a valid one
/// can be rewritten from either into the other. A verifier that accepts both at
/// once therefore accepts two distinct byte strings for one `(msg, pk)` pair —
/// signature malleability. Every verification entry point here pins exactly one
/// format; [`FalconPrivateKey::sign`] emits [`Format::Padded`], which is what
/// the default [`verify`] requires.
#[cfg_attr(
    not(feature = "alloc"),
    doc = "",
    doc = "[`FalconPrivateKey::sign`]: crate::falcon#memory"
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Format {
    /// Fixed length. Header byte `0011nnnn` (`0x30 | logn`); the whole
    /// signature is exactly `Degree::sig_len()` bytes, with the compressed `s`
    /// zero-padded up to that length. This is what
    /// [`FalconPrivateKey::sign`] produces.
    #[cfg_attr(
        not(feature = "alloc"),
        doc = "",
        doc = "[`FalconPrivateKey::sign`]: crate::falcon#memory"
    )]
    Padded,
    /// Variable length ("compressed", or "unpadded"). Header byte `0010nnnn`
    /// (`0x20 | logn`); the signature is exactly `1 + 40 + |compressed-s|`
    /// bytes. The NIST KAT vectors use this form.
    Compressed,
}

impl Format {
    /// The high nibble of the header byte for this format.
    const fn header_nibble(self) -> u8 {
        match self {
            Format::Padded => 0x30,
            Format::Compressed => 0x20,
        }
    }
}

/// A Falcon secret key: the NTRU polynomials `(f, g, F, G)`, the public key
/// `h`, and a cached expanded form (FFT basis + LDL tree) for fast signing.
///
/// Generation and signing require a CSPRNG. The secret polynomials — including
/// the expanded FFT basis and LDL tree, which are lossless representations of
/// `(f, g, F, G)` — are wiped on drop.
///
/// Signing is constant-time at the source level: the emulated `fpr` double
/// under the sampler and the FFT/LDL arithmetic is branch-free by construction
/// (see the "Constant-time contract" in `fpr`), so the secret-derived operands
/// on the signing path never select a branch, a memory address or a shift
/// count. Key generation is best-effort (it samples and solves the NTRU
/// equation with variable-time big-integer arithmetic), but is one-time and
/// runs on fresh entropy.
///
/// # Memory
///
/// Requires the `alloc` feature. Signing keeps the expanded basis and LDL tree
/// resident — measured at 170 KiB (Falcon-512) / 354 KiB (Falcon-1024) — and
/// each signature needs a further 141 KiB / 282 KiB of transient buffers, so
/// there is no stack- or scratch-buffer form of this type that would be usable
/// on the targets the allocator-free verification path is for. See the "Memory"
/// section in the module docs.
#[cfg(feature = "alloc")]
pub struct FalconPrivateKey {
    degree: Degree,
    f: Vec<i64>,
    g: Vec<i64>,
    cap_f: Vec<i64>,
    cap_g: Vec<i64>,
    h: Vec<u16>,
    expanded: sign::ExpandedKey,
}

/// Adapts a [`crate::rng::RngCore`] CSPRNG to the sampler's byte-source trait.
#[cfg(feature = "alloc")]
struct RngBytes<'a, R>(&'a mut R);

#[cfg(feature = "alloc")]
impl<R: crate::rng::RngCore> sampler::SamplerRng for RngBytes<'_, R> {
    fn next_bytes(&mut self, buf: &mut [u8]) {
        self.0.fill_bytes(buf);
    }
}

#[cfg(feature = "alloc")]
impl FalconPrivateKey {
    /// Generate a fresh Falcon key of the given degree from a CSPRNG.
    pub fn generate<R: crate::rng::RngCore + crate::rng::CryptoRng>(
        degree: Degree,
        rng: &mut R,
    ) -> FalconPrivateKey {
        let n = degree.n();
        let (f, g, cap_f, cap_g, h) = {
            let mut src = RngBytes(rng);
            keygen::ntru_gen(n, &mut src)
        };
        let expanded = sign::expand_key(&f, &g, &cap_f, &cap_g, degree);
        FalconPrivateKey {
            degree,
            f,
            g,
            cap_f,
            cap_g,
            h,
            expanded,
        }
    }

    /// The parameter set of this key.
    pub fn degree(&self) -> Degree {
        self.degree
    }

    /// Sign `msg`, returning an encoded Falcon signature (padded format,
    /// `header || salt || compressed-s`). Draws a fresh salt and sampler
    /// randomness from `rng`.
    ///
    /// The per-signature path is constant-time at the source level: the
    /// emulated `fpr` arithmetic beneath `sampler_z` and `ff_sampling` is
    /// branch-free by construction (see the type-level note on
    /// [`FalconPrivateKey`] and the "Constant-time contract" in `fpr`). What
    /// remains observable is what Falcon's design itself exposes — the number
    /// of rejection-sampling rounds, driven by fresh randomness, as in the
    /// reference implementation.
    /// # Panics
    ///
    /// Only if the rejection sampler fails a million consecutive rounds, which
    /// a key that passed [`generate`](Self::generate) or
    /// [`from_bytes`](Self::from_bytes) cannot do — both enforce the
    /// Gram-Schmidt norm bound that makes the acceptance probability per round
    /// better than one half. Use [`try_sign`](Self::try_sign) to get an error
    /// instead of a panic.
    pub fn sign<R: crate::rng::RngCore + crate::rng::CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Vec<u8> {
        self.try_sign(msg, rng)
            .expect("a key that passed the Gram-Schmidt bound cannot exhaust the resampling cap")
    }

    /// As [`sign`](Self::sign), but returns [`Error::SamplingFailed`] instead of
    /// panicking if the rejection sampler exhausts its retry budget.
    ///
    /// That budget exists so a degenerate secret basis cannot turn signing into
    /// an unbounded loop. Keys produced by [`generate`](Self::generate) or
    /// accepted by [`from_bytes`](Self::from_bytes) never reach it.
    pub fn try_sign<R: crate::rng::RngCore + crate::rng::CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut salt = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut salt);
        let mut src = RngBytes(rng);
        sign::sign_internal(&self.expanded, msg, &salt, &mut src).ok_or(Error::SamplingFailed)
    }

    /// The matching public key.
    pub fn public_key(&self) -> FalconPublicKey {
        let mut h = [0u16; MAX_N];
        h[..self.h.len()].copy_from_slice(&self.h);
        FalconPublicKey {
            degree: self.degree,
            h,
        }
    }

    /// The encoded public key bytes (header + 14-bit-packed `h`).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        encode::encode_pubkey(&self.h, self.degree.logn())
    }

    /// Serialize to the compact secret-key encoding (`0101nnnn` header, then
    /// `f`, `g`, `F`; `G` is recomputed on import).
    ///
    /// Always succeeds: both constructors guarantee the coefficients fit their
    /// packed field widths — [`generate`](Self::generate) retries key
    /// generation until they do (the reference implementation's mandatory
    /// range condition), and [`from_bytes`](Self::from_bytes) can only produce
    /// values the decoder itself read out of those same fields.
    pub fn to_bytes(&self) -> Vec<u8> {
        encode::encode_privkey(&self.f, &self.g, &self.cap_f, self.degree.logn())
            .expect("keygen and from_bytes both bound the coefficients to their field widths")
    }

    /// Parse a compact secret-key encoding, recomputing `G` and `h` and
    /// rebuilding the expanded form. Returns `Err` if the key is malformed or
    /// `f` is not invertible mod `q`.
    ///
    /// Every check key generation applies is re-applied here, because a secret
    /// key is attacker-supplied input in some deployments: the coefficient
    /// ranges (`decode_privkey` rejects the most-negative value of each field,
    /// exactly as the reference `trim_i8_decode` does), the Gram-Schmidt norm
    /// bound, invertibility of `f`, and the NTRU equation itself. Skipping the
    /// norm bound would admit degenerate bases — `f = 1, g = 0, F = 0, G = q`
    /// passes the NTRU equation — for which the sampler can never reach the
    /// signature norm bound, so signing would loop indefinitely.
    pub fn from_bytes(sk: &[u8]) -> Result<FalconPrivateKey, Error> {
        let header = *sk.first().ok_or(Error::InvalidLength)?;
        if header & 0xF0 != 0x50 {
            return Err(Error::Malformed);
        }
        let degree = Degree::from_logn(header & 0x0F).ok_or(Error::Malformed)?;
        let n = degree.n();
        let (f, g, cap_f) = encode::decode_privkey(sk, n).ok_or(Error::InvalidLength)?;
        // Cheapest structural check first (O(n log n)), before the O(n²) `h`.
        if !keygen::gs_norm_ok(&f, &g, n) {
            return Err(Error::Malformed);
        }
        let h = keygen::compute_h(&f, &g, n).ok_or(Error::Malformed)?;
        let cap_g = keygen::recompute_g(&f, &g, &cap_f, n);
        // Validate the NTRU equation `f·G − g·F ≡ q (mod xⁿ+1)`: a corrupted but
        // still-invertible `f` produces a structurally valid key whose signatures
        // would silently fail to verify. Reject it here instead.
        if !keygen::check_ntru(&f, &g, &cap_f, &cap_g) {
            return Err(Error::Malformed);
        }
        let expanded = sign::expand_key(&f, &g, &cap_f, &cap_g, degree);
        Ok(FalconPrivateKey {
            degree,
            f,
            g,
            cap_f,
            cap_g,
            h,
            expanded,
        })
    }
}

#[cfg(feature = "alloc")]
impl Drop for FalconPrivateKey {
    fn drop(&mut self) {
        // Wipe the secret polynomials with the crate's volatile `zeroize`
        // stores, which are not elided (same pattern as the RSA/ML-DSA
        // private keys).
        for v in [&mut self.f, &mut self.g, &mut self.cap_f, &mut self.cap_g] {
            crate::zeroize::Zeroize::zeroize(v.as_mut_slice());
        }
    }
}

/// Verify a Falcon signature.
///
/// `pk` is an encoded Falcon public key (header + packed `h`), `msg` the signed
/// message, and `sig` an encoded compressed Falcon signature (header + 40-byte
/// nonce + compressed `s`). The parameter set (Falcon-512 vs Falcon-1024) is
/// detected from the public-key header and cross-checked against the signature
/// header.
///
/// Returns `true` iff the signature is valid. Any malformed input, length
/// mismatch, non-canonical encoding, or failed bound check yields `false`.
/// Never panics.
///
/// Only the [`Format::Padded`] encoding that [`FalconPrivateKey::sign`] emits
/// is accepted, so one `(msg, pk)` pair has exactly one valid byte string; see
/// [`FalconPublicKey::verify`] for why. To verify a signature produced
/// elsewhere in the compressed encoding, use [`verify_with_format`].
#[cfg_attr(
    not(feature = "alloc"),
    doc = "",
    doc = "[`FalconPrivateKey::sign`]: crate::falcon#memory"
)]
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    verify_with_format(pk, msg, sig, Format::Padded)
}

/// Verify a Falcon signature in exactly the given [`Format`].
///
/// As [`verify`], but pins the signature encoding explicitly: a signature in
/// the other format yields `false` even if it would otherwise be valid.
pub fn verify_with_format(pk: &[u8], msg: &[u8], sig: &[u8], format: Format) -> bool {
    match FalconPublicKey::from_bytes(pk) {
        Ok(key) => key.verify_with_format(msg, sig, format).unwrap_or(false),
        Err(_) => false,
    }
}

// The KAT vectors and round-trip tests are written against the allocating
// entry points (and the sign/keygen ones exist only there). The no-alloc build's
// verification path is exercised by a host-side `no_std` runner instead; see the
// commit that made this module allocator-free.
#[cfg(all(test, feature = "alloc"))]
mod tests;
