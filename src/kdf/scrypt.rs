//! scrypt — memory-hard password-based key-derivation function (RFC 7914).
//!
//! scrypt's cost parameters (`N = 2^log_n`, `r`, `p`) tune CPU and memory
//! usage. The function allocates `128 · r · N` bytes once for ROMix; at the
//! commonly-recommended `(log_n=14, r=8, p=1)` that is ~16 MiB. This makes
//! scrypt only available with the `alloc` feature.
//!
//! Parameter errors return [`Error::InvalidParam`] rather than panicking,
//! because the parameters are usually runtime-supplied (parsed from PHC
//! strings, config, etc.). For the same reason the working memory is
//! allocated fallibly: valid parameters can still ask for up to ~128 GiB, and
//! if that cannot be had the call returns [`Error::OutOfMemory`] instead of
//! aborting the process.
//!
//! Internally: outer `PBKDF2-HMAC-SHA256` envelope, inner [`crate::cipher`]
//! Salsa20/8 BlockMix on `128·r`-byte sub-blocks.
//!
//! _Not constant time in the password._ scrypt's design fundamentally
//! depends on its memory access pattern (controlled by the password via
//! the data-dependent `j` indexing in ROMix's second loop), so scrypt's
//! side-channel posture is the same as the reference implementation.

extern crate alloc;
use alloc::vec::Vec;

use crate::cipher::salsa20::salsa20_8_words;
use crate::hash::Sha256;
use crate::kdf::pbkdf2;
use crate::zeroize::zero_bulk;

/// scrypt errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// One of `log_n`, `r`, `p`, or `dkLen` is outside the enforced range:
    /// `log_n` must be in `1..64`, `r ≥ 1`, `p ≥ 1`, `r·N < 2³⁰`,
    /// `N < 2^(16·r)` (RFC 7914 §1), `p ≤ ((2³² − 1)·32)/(128·r)` (RFC 7914
    /// §2), and `p · ⌈dkLen/32⌉ ≤ (2³² − 1)`. Beyond those, total work still
    /// scales with `p`, so untrusted parameters need a caller-side clamp (see
    /// [`scrypt`]).
    InvalidParam,
    /// The parameters are valid but their working memory (about
    /// `128·r·(N + p + 2)` bytes) could not be allocated. Nothing was
    /// computed.
    OutOfMemory,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidParam => f.write_str("scrypt: invalid parameter"),
            Error::OutOfMemory => f.write_str("scrypt: cannot allocate the working memory"),
        }
    }
}

/// Reserves exactly `len` bytes of capacity without aborting on failure; the
/// returned vector is empty. In unit tests a per-thread ceiling can make the
/// reservation fail deterministically (see `tests::fail_allocs_above`).
fn try_buffer(len: usize) -> Result<Vec<u8>, Error> {
    #[cfg(all(test, feature = "std"))]
    if len > tests::ALLOC_CEILING.with(|c| c.get()) {
        return Err(Error::OutOfMemory);
    }
    let mut v = Vec::new();
    v.try_reserve_exact(len).map_err(|_| Error::OutOfMemory)?;
    Ok(v)
}

/// [`try_buffer`], zero-filled to `len`.
fn try_zeroed(len: usize) -> Result<Vec<u8>, Error> {
    let mut v = try_buffer(len)?;
    v.resize(len, 0);
    Ok(v)
}

impl core::error::Error for Error {}

/// Derives `out.len()` key bytes from `(password, salt)` using scrypt with
/// parameters `(log_n, r, p)` (so `N = 2^log_n`).
///
/// # Enforced bounds
///
/// - `r·N < 2³⁰` (with `N = 2^log_n`), which caps the `128·r·N`-byte ROMix
///   allocation;
/// - `N < 2^(16·r)`, the RFC 7914 §1 relation (`N < 2^(128·r/8)`) — for
///   `r = 1` it limits `N` to `2^15`;
/// - `p ≤ ((2³² − 1)·32)/(128·r)` and `p · ⌈dkLen/32⌉ ≤ 2³² − 1`, the RFC 7914
///   §2 constraints that keep both PBKDF2 expansions inside their 32-bit block
///   counters.
///
/// # Untrusted parameters
///
/// Those are *structural* bounds, not a work cap: total work still scales with
/// `p` (and with `r·N`), so a large `p` that satisfies them all is still a
/// CPU-exhaustion DoS vector. Callers that derive `(log_n, r, p)` from
/// untrusted input (e.g. a parsed PHC `$scrypt$` string) MUST clamp them to
/// sane maxima themselves before calling.
///
/// # Errors
///
/// [`Error::InvalidParam`] for parameters outside the bounds above (or
/// whose buffer sizes overflow `usize`), [`Error::OutOfMemory`] if the
/// `128·r·(N + p + 2)` bytes of working memory cannot be allocated. Either
/// way `out` is left untouched. (On systems that overcommit memory an
/// allocation can succeed and the process still be killed later when the
/// pages are touched; that is outside what a library can detect, so bound
/// `r·N` for untrusted input.)
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
    out: &mut [u8],
) -> Result<(), Error> {
    // --- Parameter validation (RFC 7914 §1) ---
    if log_n == 0 || log_n >= 64 || r == 0 || p == 0 {
        return Err(Error::InvalidParam);
    }
    let n: u64 = 1u64 << log_n;
    // RFC 7914 §1: N < 2^(128·r/8) = 2^(16·r). Only binding for r = 1 (N <
    // 2^15) and r = 2 (N < 2^32); for r ≥ 4 the r·N bound below is stricter.
    // Enforced so a caller cannot ask for a parameter set the specification
    // does not define.
    if 16u64.saturating_mul(r as u64) <= log_n as u64 {
        return Err(Error::InvalidParam);
    }
    // r · N < 2³⁰
    let rn = (r as u64).checked_mul(n).ok_or(Error::InvalidParam)?;
    if rn >= (1u64 << 30) {
        return Err(Error::InvalidParam);
    }
    // p · (128 · r) must fit in usize for the buffer.
    let block_size = 128usize
        .checked_mul(r as usize)
        .ok_or(Error::InvalidParam)?;
    let b_len = block_size
        .checked_mul(p as usize)
        .ok_or(Error::InvalidParam)?;
    if out.is_empty() {
        return Err(Error::InvalidParam);
    }
    // p · ⌈dkLen/32⌉ ≤ 2³² − 1 (documented above; RFC 7914 §2's dkLen / p
    // constraints with hLen = 32): keeps the final PBKDF2 expansion within
    // its 32-bit block counter instead of panicking there.
    let dk_blocks = (out.len() as u64).div_ceil(32);
    if (p as u64)
        .checked_mul(dk_blocks)
        .is_none_or(|v| v > u32::MAX as u64)
    {
        return Err(Error::InvalidParam);
    }
    // The first expansion derives p·128·r bytes = 4·r·p blocks, which must
    // also fit the 32-bit block counter: this is exactly RFC 7914 §2's
    // p ≤ ((2³² − 1) · hLen) / MFLen = ((2³² − 1)·32) / (128·r). Checked here,
    // before the b/v allocations, so violating params return InvalidParam
    // rather than aborting on a huge allocation or panicking inside pbkdf2.
    if 4u64 * (r as u64) * (p as u64) > u32::MAX as u64 {
        return Err(Error::InvalidParam);
    }

    let n_us = usize::try_from(n).map_err(|_| Error::InvalidParam)?;
    // Guard the V-buffer size: on 32-bit targets n_us · block_size can wrap
    // usize for attacker-influenced (but per-RFC "valid") params, which would
    // under-allocate and lead to an OOB write panic. Match the checked_mul
    // discipline of the sibling allocations above.
    let v_len = n_us.checked_mul(block_size).ok_or(Error::InvalidParam)?;

    // --- Allocate everything up front, fallibly ---
    // The bounds above still admit ~128 GiB for V alone, so an allocation
    // failure is an ordinary, caller-reachable outcome: report it rather than
    // abort the process (which `vec![0; n]` does). All four buffers are
    // reserved before any password-derived byte is written, so the error path
    // has nothing to wipe. V, the largest, goes first and is not pre-zeroed:
    // ROMix's first loop fills it block by block within the reserved capacity.
    let mut v = try_buffer(v_len)?;
    let mut b = try_zeroed(b_len)?;
    let mut x = try_zeroed(block_size)?;
    // One BlockMix scratch buffer, reused across all 2·N·p calls instead of
    // allocating a fresh `128·r`-byte Vec inside every BlockMix.
    let mut y = try_zeroed(block_size)?;

    // --- First PBKDF2 expansion: B = PBKDF2-HMAC-SHA256(P, S, 1, p·128·r) ---
    pbkdf2::<Sha256>(password, salt, 1, &mut b);

    // --- ROMix on each p block in turn, reusing one V scratch ---
    for i in 0..p as usize {
        let off = i * block_size;
        x.copy_from_slice(&b[off..off + block_size]);
        romix(&mut x, n_us, r as usize, &mut v, &mut y);
        b[off..off + block_size].copy_from_slice(&x);
    }

    // --- Second PBKDF2 expansion: DK = PBKDF2-HMAC-SHA256(P, B, 1, dkLen) ---
    pbkdf2::<Sha256>(password, &b, 1, out);

    // Wipe the password-derived ROMix scratch before it drops. No early returns
    // follow the allocations above, so this single pass covers every non-panic
    // exit. (`zero_bulk` rather than `crate::zeroize::Zeroize`: `v` alone is
    // `N·128·r` bytes — up to hundreds of megabytes — and volatile per-word
    // stores would not vectorize; see its docs for how the plain stores are
    // kept from being elided.)
    zero_bulk(&mut b);
    zero_bulk(&mut v);
    zero_bulk(&mut x);
    zero_bulk(&mut y);
    Ok(())
}

/// ROMix(X, N, r) — the memory-hard core (RFC 7914 §4). `y` is a caller-owned
/// `128·r`-byte BlockMix scratch buffer. BlockMix writes its output into the
/// other buffer, and the two swap roles after every call (ping-pong) instead
/// of copying the result back. There are `2N` calls, an even number, so the
/// result ends up back in `x`.
///
/// `v` has capacity for `N·128·r` bytes; its first loop refills it from
/// empty (so it is never zero-filled first), leaving it full afterwards.
fn romix(x: &mut [u8], n: usize, r: usize, v: &mut Vec<u8>, y: &mut [u8]) {
    let block_size = 128 * r;
    let (mut cur, mut next) = (x, y);

    // V_i = X^{(i)} for i = 0..N. Within the reserved capacity, so these
    // appends never reallocate (which would leave a stale copy behind).
    v.clear();
    debug_assert!(v.capacity() >= n * block_size);
    for _ in 0..n {
        v.extend_from_slice(cur);
        block_mix(cur, r, next);
        core::mem::swap(&mut cur, &mut next);
    }

    // Second loop: data-dependent indexing.
    for _ in 0..n {
        let j = integerify(cur, r) % n as u64;
        let j_off = j as usize * block_size;
        for (c, vj) in cur.iter_mut().zip(&v[j_off..j_off + block_size]) {
            *c ^= *vj;
        }
        block_mix(cur, r, next);
        core::mem::swap(&mut cur, &mut next);
    }
}

/// Loads one 64-byte sub-block as words (the byte order is little-endian;
/// on such targets this is sixteen plain loads).
#[inline(always)]
fn load_sub(b: &[u8]) -> [u32; 16] {
    core::array::from_fn(|i| u32::from_le_bytes(b[4 * i..4 * i + 4].try_into().expect("4 bytes")))
}

/// BlockMix(B, r) — applies Salsa20/8 sequentially over `2r` 64-byte sub-blocks
/// of `b` and writes them, reordered, into `out` (RFC 7914 §3): `Y_i` lands at
/// position `i/2` for even `i` and `r + i/2` for odd `i`. `out` is fully
/// overwritten. The chaining value `X` stays in words throughout.
fn block_mix(b: &[u8], r: usize, out: &mut [u8]) {
    let two_r = 2 * r;
    // X = B_{2r-1}.
    let mut x = load_sub(&b[(two_r - 1) * 64..two_r * 64]);

    // Y_i = Salsa20/8(X ⊕ B_i); X' = Y_i for the next iteration.
    for i in 0..two_r {
        let bi = load_sub(&b[i * 64..(i + 1) * 64]);
        for (w, v) in x.iter_mut().zip(bi.iter()) {
            *w ^= *v;
        }
        salsa20_8_words(&mut x);
        let pos = i / 2 + (i % 2) * r;
        let dst = &mut out[pos * 64..(pos + 1) * 64];
        for (chunk, w) in dst.chunks_exact_mut(4).zip(x.iter()) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
    }
}

/// Integerify(B) — read the first 8 bytes of the last 64-byte sub-block as a
/// little-endian u64.
fn integerify(b: &[u8], r: usize) -> u64 {
    let off = (2 * r - 1) * 64;
    u64::from_le_bytes(b[off..off + 8].try_into().expect("8 bytes"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    #[cfg(feature = "std")]
    std::thread_local! {
        /// Per-thread allocation ceiling consulted by `try_buffer`, so a test
        /// can make an allocation fail without the machine actually running
        /// out of memory (on a large host with overcommit, a 128 GiB
        /// reservation genuinely succeeds).
        pub(super) static ALLOC_CEILING: core::cell::Cell<usize> =
            const { core::cell::Cell::new(usize::MAX) };
    }

    /// Runs `f` with every `try_buffer` reservation above `limit` bytes
    /// failing as the allocator would.
    #[cfg(feature = "std")]
    fn fail_allocs_above<T>(limit: usize, f: impl FnOnce() -> T) -> T {
        ALLOC_CEILING.with(|c| c.set(limit));
        let out = f();
        ALLOC_CEILING.with(|c| c.set(usize::MAX));
        out
    }

    /// Valid but absurd parameters — `N = 2`, `r = 2²⁹ − 1`, about 128 GiB for
    /// V plus three 64 GiB buffers (on 64-bit targets) — must come back as `OutOfMemory`, not
    /// abort the process, and leave `out` alone.
    #[cfg(feature = "std")]
    #[test]
    fn impossible_memory_returns_error() {
        let mut out = [0xaau8; 32];
        // On 32-bit targets those sizes overflow `usize` (InvalidParam), so
        // use r = 2²³ there: a 2 GiB V, still above the ceiling.
        #[cfg(target_pointer_width = "64")]
        let r = (1u32 << 29) - 1;
        #[cfg(not(target_pointer_width = "64"))]
        let r = 1u32 << 23;
        assert_eq!(
            fail_allocs_above(1 << 30, || scrypt(b"p", b"s", 1, r, 1, &mut out)),
            Err(Error::OutOfMemory)
        );
        assert_eq!(out, [0xaau8; 32]);
        // A failure on any one of the buffers is reported the same way: with
        // N = 16, r = 1, p = 1, V is 2 KiB and the rest are 128 bytes.
        for limit in [0, 127, 2047] {
            assert_eq!(
                fail_allocs_above(limit, || scrypt(b"p", b"s", 4, 1, 1, &mut out)),
                Err(Error::OutOfMemory),
                "limit={limit}"
            );
        }
        assert_eq!(out, [0xaau8; 32]);
        // Exactly enough is enough.
        assert!(fail_allocs_above(2048, || scrypt(b"p", b"s", 4, 1, 1, &mut out)).is_ok());
    }

    /// On 32-bit targets the real allocator refuses a V larger than
    /// `isize::MAX` — no ceiling needed.
    #[cfg(target_pointer_width = "32")]
    #[test]
    fn oversized_v_is_out_of_memory_on_32_bit() {
        let mut out = [0u8; 32];
        assert_eq!(
            scrypt(b"p", b"s", 1, 1 << 23, 1, &mut out),
            Err(Error::OutOfMemory)
        );
    }

    /// RFC 7914 §11 Test Vector 1: `scrypt("", "", N=16, r=1, p=1, dkLen=64)`.
    #[test]
    fn rfc7914_vector_1() {
        let expected = from_hex::<64>(
            "77d6576238657b203b19ca42c18a0497\
             f16b4844e3074ae8dfdffa3fede21442\
             fcd0069ded0948f8326a753a0fc81f17\
             e8d3e0fb2e0d3628cf35e20c38d18906",
        );
        let mut out = [0u8; 64];
        scrypt(b"", b"", 4, 1, 1, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    /// RFC 7914 §11 Test Vector 2: `scrypt("password", "NaCl", N=1024, r=8, p=16, 64)`.
    #[test]
    fn rfc7914_vector_2() {
        let expected = from_hex::<64>(
            "fdbabe1c9d3472007856e7190d01e9fe\
             7c6ad7cbc8237830e77376634b373162\
             2eaf30d92e22a3886ff109279d9830da\
             c727afb94a83ee6d8360cbdfa2cc0640",
        );
        let mut out = [0u8; 64];
        scrypt(b"password", b"NaCl", 10, 8, 16, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    /// RFC 7914 §11 Test Vector 3: `scrypt("pleaseletmein", "SodiumChloride", N=16384, r=8, p=1, 64)`.
    #[test]
    #[ignore = "16-MiB allocation; slow in debug — `cargo test --release -- --ignored`"]
    fn rfc7914_vector_3() {
        let expected = from_hex::<64>(
            "7023bdcb3afd7348461c06cd81fd38eb\
             fda8fbba904f8e3ea9b543f6545da1f2\
             d5432955613f0fcf62d49705242a9af9\
             e61e85dc0d651e40dfcf017b45575887",
        );
        let mut out = [0u8; 64];
        scrypt(b"pleaseletmein", b"SodiumChloride", 14, 8, 1, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn rejects_invalid_parameters() {
        let mut out = [0u8; 32];
        assert_eq!(
            scrypt(b"p", b"s", 0, 1, 1, &mut out),
            Err(Error::InvalidParam)
        );
        assert_eq!(
            scrypt(b"p", b"s", 4, 0, 1, &mut out),
            Err(Error::InvalidParam)
        );
        assert_eq!(
            scrypt(b"p", b"s", 4, 1, 0, &mut out),
            Err(Error::InvalidParam)
        );
        assert_eq!(
            scrypt(b"p", b"s", 4, 1, 1, &mut []),
            Err(Error::InvalidParam)
        );
        // r·N ≥ 2³⁰ → reject.
        assert_eq!(
            scrypt(b"p", b"s", 30, 1, 1, &mut out),
            Err(Error::InvalidParam)
        );
        // RFC 7914 §1: N < 2^(16·r). With r = 1 that caps N at 2^15, so
        // log_n = 16 is out of range even though r·N is well under 2³⁰ …
        assert_eq!(
            scrypt(b"p", b"s", 16, 1, 1, &mut out),
            Err(Error::InvalidParam)
        );
        // … while the largest in-range N for r = 1 still works, and r = 2
        // lifts the ceiling (N = 2^16 is then fine).
        assert!(scrypt(b"p", b"s", 15, 1, 1, &mut out).is_ok());
        assert!(scrypt(b"p", b"s", 16, 2, 1, &mut out).is_ok());
        // p · ⌈dkLen/32⌉ > 2³² − 1 → reject (documented bound) — must
        // return InvalidParam before any allocation / PBKDF2 panic.
        let mut out64 = [0u8; 64];
        assert_eq!(
            scrypt(b"p", b"s", 4, 1, u32::MAX, &mut out64),
            Err(Error::InvalidParam)
        );
        // 4·r·p > 2³² − 1 (first-expansion block counter) → reject.
        assert_eq!(
            scrypt(b"p", b"s", 1, 1 << 20, 1 << 11, &mut out),
            Err(Error::InvalidParam)
        );
    }

    #[test]
    fn large_params_reject_without_panic() {
        // Regression for the V-buffer size guard: large-but-"shaped" params
        // that on a 32-bit target could wrap `n_us * block_size` must return
        // InvalidParam (caught by the r·N bound), never panic via an
        // under-allocated buffer. log_n=31, r=64 gives r·N = 64·2^31 ≥ 2^30.
        let mut out = [0u8; 32];
        assert_eq!(
            scrypt(b"p", b"s", 31, 64, 1, &mut out),
            Err(Error::InvalidParam)
        );
    }
}
