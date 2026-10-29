//! Argon2 v1.3 — memory-hard password-hashing function (RFC 9106), all three
//! variants:
//!
//!  - [`Argon2Type::Argon2d`]  — data-dependent indexing; fastest on a GPU
//!    adversary but offers no resistance to side-channel attacks. Suitable
//!    for back-end uses where the attacker has no concurrent observation.
//!  - [`Argon2Type::Argon2i`]  — data-independent indexing; constant-time
//!    memory access pattern, resistant to side channels at the cost of
//!    some TMTO weakness for low memory.
//!  - [`Argon2Type::Argon2id`] — the recommended hybrid: Argon2i for the
//!    first half of the first pass (where the side-channel risk is highest),
//!    Argon2d for the remainder.
//!
//! All variants share the same memory matrix layout `B[i][j]` and compression
//! function `G`; they differ only in how each block's reference index is
//! chosen.
//!
//! [`argon2`] fills the lanes one after another on the calling thread. With
//! `std`, [`argon2_threaded`] fills the `parallelism` lanes of each slice on
//! up to that many scoped threads instead. Both produce the same output: the
//! slice structure already makes the lanes of a slice independent of one
//! another.
//!
//! # Performance notes
//!
//! - On x86_64 the compression function `G` runs on AVX-512 (F + BW) or AVX2
//!   when the CPU has them (detected at run time), otherwise on the portable
//!   scalar code; all three are byte-identical. Each step is fused: the
//!   previous block stays in a scratch buffer, and the `X ⊕ Y` input and the
//!   v1.3 XOR into the old block are done during G's loads and stores.
//! - The fill is memory-latency bound, so the reference block is
//!   prefetched: `PREFETCH_AHEAD` blocks ahead in data-independent segments
//!   (those addresses are public, so the access pattern stays independent
//!   of the password), and in data-dependent ones as soon as the next index
//!   is known, from word 0 of the block being computed.
//! - On Linux (x86_64, aarch64) the matrix is advised for transparent huge
//!   pages (one raw `madvise` syscall; see `hugepages`), which removes most
//!   TLB misses of the scattered reference reads.
//!
//! Behind `feature = "alloc"`: Argon2 allocates `m_cost_kib · 1024` bytes
//! (plus one cache line, for alignment) for the memory matrix.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::hash::Blake2bMac;
use crate::zeroize::{Zeroize, zero_bulk};

/// Bytes per memory block.
const BLOCK: usize = 1024;

/// Argon2 variant: which addressing scheme to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Type {
    /// Data-dependent indexing (fastest but side-channel-exposed).
    Argon2d,
    /// Data-independent indexing (constant-time memory access).
    Argon2i,
    /// Hybrid (recommended default).
    Argon2id,
}

impl Argon2Type {
    fn ty_byte(self) -> u32 {
        match self {
            Argon2Type::Argon2d => 0,
            Argon2Type::Argon2i => 1,
            Argon2Type::Argon2id => 2,
        }
    }
}

/// Argon2 cost parameters.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    /// Number of iterations (`t`).
    pub t_cost: u32,
    /// Memory cost in KiB (`m`).
    pub m_cost_kib: u32,
    /// Lane count / parallelism (`p`). [`argon2`] computes the lanes
    /// sequentially; [`argon2_threaded`] can run them on separate threads.
    pub parallelism: u32,
    /// Variant.
    pub variant: Argon2Type,
    /// Version (Argon2 v1.3 = `0x13`).
    pub version: u32,
}

impl Argon2Params {
    /// RFC 9106 §4 high-memory recommendation, with `t_cost = 1`.
    pub fn recommended() -> Self {
        Argon2Params {
            t_cost: 1,
            m_cost_kib: 2 * 1024 * 1024, // 2 GiB
            parallelism: 4,
            variant: Argon2Type::Argon2id,
            version: 0x13,
        }
    }
}

/// Argon2 parameter-validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// One of the cost parameters is outside RFC 9106's permitted range, or
    /// the output buffer is too small / large.
    InvalidParam,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("argon2: invalid parameter")
    }
}

impl core::error::Error for Error {}

/// Computes Argon2 over `(password, salt, secret, ad)` with the chosen
/// parameters, writing `out.len()` bytes into `out`. `out.len()` must be
/// in `4..=2^32 − 1` and `salt.len()` in `8..=2^32 − 1` (RFC 9106 §3.1:
/// the reference implementation's 8-byte minimum; 16 bytes is
/// recommended).
///
/// Runs entirely on the calling thread, whatever `parallelism` is; see
/// [`argon2_threaded`] for a multi-threaded fill.
///
/// # Untrusted parameters
///
/// `m_cost_kib` and `t_cost` have **no upper bound** here: Argon2 allocates
/// `m_cost_kib · 1024` bytes and runs `t_cost` passes over them, so a
/// hostile `(m, t)` pair is an OOM/CPU-exhaustion DoS vector. Callers that
/// derive these costs from untrusted input — e.g. the `m=`/`t=` fields of a
/// parsed PHC `$argon2...$` string — MUST clamp them to sane maxima before
/// calling. (Compare PBES2, which caps the attacker-controlled PBKDF2
/// iteration count it accepts from a key file.)
pub fn argon2(
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    argon2_impl(
        params,
        password,
        salt,
        secret,
        ad,
        out,
        Backend::detect(),
        1,
    )
}

/// [`argon2`] with the lanes of each slice filled on up to `max_threads`
/// threads (at most `parallelism` are used; `0` and `1` mean the calling
/// thread only). The output is identical to [`argon2`]'s.
///
/// Threads are spawned with [`std::thread::scope`] once per slice — four
/// times per pass, like the reference implementation — so this only pays
/// off when each segment is large (a few MiB per lane or more). If the OS
/// refuses a thread, its lanes are filled on the calling thread instead.
///
/// The same caveat about untrusted `(m, t)` costs as for [`argon2`] applies,
/// and a hostile `parallelism` can additionally ask for many threads: clamp
/// `max_threads` to what the caller is willing to spend.
#[cfg(feature = "std")]
pub fn argon2_threaded(
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    out: &mut [u8],
    max_threads: usize,
) -> Result<(), Error> {
    argon2_impl(
        params,
        password,
        salt,
        secret,
        ad,
        out,
        Backend::detect(),
        max_threads,
    )
}

#[allow(clippy::too_many_arguments)]
fn argon2_impl(
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    out: &mut [u8],
    backend: Backend,
    max_threads: usize,
) -> Result<(), Error> {
    // --- Parameter bounds (RFC 9106 §3.1) ---
    if params.parallelism == 0 || params.parallelism > (1u32 << 24) - 1 {
        return Err(Error::InvalidParam);
    }
    if params.t_cost == 0 {
        return Err(Error::InvalidParam);
    }
    if params.m_cost_kib < 8 * params.parallelism {
        return Err(Error::InvalidParam);
    }
    if !matches!(params.version, 0x10 | 0x13) {
        return Err(Error::InvalidParam);
    }
    if !(4..=(u32::MAX as usize)).contains(&out.len()) {
        return Err(Error::InvalidParam);
    }
    if password.len() > u32::MAX as usize
        || salt.len() > u32::MAX as usize
        || secret.len() > u32::MAX as usize
        || ad.len() > u32::MAX as usize
    {
        return Err(Error::InvalidParam);
    }
    // RFC 9106 §3.1 / reference implementation: at least 8 bytes of salt.
    // Shorter (or empty) salts gut Argon2's defense against precomputation.
    if salt.len() < 8 {
        return Err(Error::InvalidParam);
    }

    let p = params.parallelism as usize;
    let m_prime = 4 * p * (params.m_cost_kib as usize / (4 * p)); // floor to multiple of 4p
    if m_prime < 8 * p {
        return Err(Error::InvalidParam);
    }
    let q = m_prime / p;
    let seg_len = q / 4;
    let seg_bytes = seg_len * BLOCK;

    // --- H0 = BLAKE2b(p ‖ T ‖ m ‖ t ‖ v ‖ y ‖ |P| ‖ P ‖ |S| ‖ S ‖ |K| ‖ K ‖ |X| ‖ X) ---
    let mut h0 = [0u8; 64];
    {
        let mut mac = Blake2bMac::new_unkeyed(64);
        let outlen = out.len() as u32;
        mac.update(&params.parallelism.to_le_bytes());
        mac.update(&outlen.to_le_bytes());
        mac.update(&params.m_cost_kib.to_le_bytes());
        mac.update(&params.t_cost.to_le_bytes());
        mac.update(&params.version.to_le_bytes());
        mac.update(&params.variant.ty_byte().to_le_bytes());
        mac.update(&(password.len() as u32).to_le_bytes());
        mac.update(password);
        mac.update(&(salt.len() as u32).to_le_bytes());
        mac.update(salt);
        mac.update(&(secret.len() as u32).to_le_bytes());
        mac.update(secret);
        mac.update(&(ad.len() as u32).to_le_bytes());
        mac.update(ad);
        mac.finalize_into(&mut h0);
    }

    // --- Allocate the memory matrix: m' 1024-byte blocks ---
    // Guard the matrix size: on 32-bit targets m' · 1024 can wrap usize for
    // per-RFC "valid" params, which would under-allocate and lead to OOB
    // panics. Match the checked_mul discipline of the sibling scrypt code.
    //
    // One spare cache line lets the matrix start 64-byte aligned (a large
    // allocation typically comes back 16 bytes past a page boundary, which
    // would split every other 32-byte SIMD access across two cache lines).
    let mem_len = m_prime.checked_mul(BLOCK).ok_or(Error::InvalidParam)?;
    let mut mem: Vec<u8> = vec![0u8; mem_len.checked_add(64).ok_or(Error::InvalidParam)?];
    let align = match mem.as_ptr().align_offset(64) {
        a if a < 64 => a,
        _ => 0,
    };
    let blocks = &mut mem[align..align + mem_len];
    // Before anything touches the matrix (the zeroed allocation is still
    // untouched, demand-zero pages), ask for transparent huge pages: the
    // reference-block reads are scattered over the whole matrix, and with
    // 4 KiB pages nearly every one of them also misses the TLB.
    hugepages::advise(blocks);

    // The matrix is stored slice-major — all lanes' segments of slice 0, then
    // of slice 1, … — rather than lane-major: B[i][j] lives at
    // `block_index(i, j)`. That puts the segments being filled concurrently
    // in one contiguous region, so a slice splits safely into one `&mut`
    // segment per lane plus shared views of the other slices.
    let block_index = |lane: usize, col: usize| -> usize {
        ((col / seg_len) * p + lane) * seg_len + col % seg_len
    };

    // --- Initialize B[i][0] and B[i][1] for each lane i ---
    // `input` embeds H0, so it is as password-derived as H0 itself; it is
    // hoisted out of the loop and wiped alongside it below.
    let mut input = [0u8; 64 + 8];
    for i in 0..p {
        // B[i][0] = H'(H0 ‖ LE32(0) ‖ LE32(i), 1024)
        input[..64].copy_from_slice(&h0);
        input[64..68].copy_from_slice(&0u32.to_le_bytes());
        input[68..72].copy_from_slice(&(i as u32).to_le_bytes());
        let off = block_index(i, 0) * BLOCK;
        h_prime(&input, &mut blocks[off..off + BLOCK]);

        // B[i][1] = H'(H0 ‖ LE32(1) ‖ LE32(i), 1024)
        input[64..68].copy_from_slice(&1u32.to_le_bytes());
        let off = block_index(i, 1) * BLOCK;
        h_prime(&input, &mut blocks[off..off + BLOCK]);
    }

    // H0 (and the `H0 ‖ …` block fed to H′) is password-derived and only
    // needed for lane initialization; wipe both before the long main loop runs.
    super::wipe(&mut h0);
    super::wipe(&mut input);

    // --- Main loop: t passes × 4 slices × p lanes × seg_len blocks ---
    // Without `std` there are no threads; `argon2_threaded` does not exist
    // there and `argon2` always asks for one.
    let threads = if cfg!(feature = "std") {
        max_threads.clamp(1, p)
    } else {
        1
    };
    for pass in 0..params.t_cost as usize {
        for slice in 0..4 {
            let (before, rest) = blocks.split_at_mut(slice * p * seg_bytes);
            let (cur, after) = rest.split_at_mut(p * seg_bytes);
            let ctx = SegCtx {
                before,
                after,
                pass,
                slice,
                p,
                q,
                seg_len,
                params,
                backend,
            };
            if threads == 1 {
                for (lane, own) in cur.chunks_exact_mut(seg_bytes).enumerate() {
                    fill_segment(&ctx, lane, own);
                }
            } else {
                #[cfg(feature = "std")]
                fill_slice_threaded(&ctx, cur, threads);
            }
        }
    }

    // --- Final block C = ⨁ B[i][q-1] ---
    let mut c = [0u8; BLOCK];
    for i in 0..p {
        let off = block_index(i, q - 1) * BLOCK;
        for (ck, mk) in c.iter_mut().zip(&blocks[off..off + BLOCK]) {
            *ck ^= mk;
        }
    }

    // --- Output = H'(C, T) ---
    h_prime(&c, out);

    // Wipe the password-derived working buffers before they drop. There are no
    // early returns past the `mem` allocation above, so this single pass covers
    // every non-panic exit. (`zero_bulk` rather than `wipe`/`Zeroize`: the
    // matrix is up to gigabytes and volatile per-word stores would not
    // vectorize; see its docs for how the plain stores are kept from being
    // elided.)
    zero_bulk(&mut c);
    zero_bulk(&mut mem);
    Ok(())
}

/// Fills the `p` segments of one slice (`cur`, `p · seg_len` blocks) on
/// `threads` scoped threads, `⌈p / threads⌉` consecutive lanes each. The
/// calling thread takes the first group; a group whose thread cannot be
/// spawned is filled by the calling thread afterwards.
#[cfg(feature = "std")]
fn fill_slice_threaded(ctx: &SegCtx<'_>, cur: &mut [u8], threads: usize) {
    use std::sync::Mutex;

    let seg_bytes = ctx.seg_len * BLOCK;
    let per = ctx.p.div_ceil(threads);
    let fill_group = |g: usize, group: &mut [u8]| {
        for (k, own) in group.chunks_exact_mut(seg_bytes).enumerate() {
            fill_segment(ctx, g * per + k, own);
        }
    };
    // Each group sits behind a `Mutex<Option<…>>` so that whoever runs it —
    // its own thread, or the caller if that thread failed to spawn — takes
    // the `&mut` out exactly once.
    let groups: Vec<Mutex<Option<&mut [u8]>>> = cur
        .chunks_mut(per * seg_bytes)
        .map(|g| Mutex::new(Some(g)))
        .collect();
    let run = |g: usize| {
        let taken = groups[g].lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(group) = taken {
            fill_group(g, group);
        }
    };
    std::thread::scope(|s| {
        let mut failed = Vec::new();
        for g in 1..groups.len() {
            let run = &run;
            if std::thread::Builder::new()
                .spawn_scoped(s, move || run(g))
                .is_err()
            {
                failed.push(g);
            }
        }
        run(0);
        for g in failed {
            run(g);
        }
    });
}

/// The parts of the matrix and the parameters that every segment of one
/// slice shares: the slices before and after the current one (read-only;
/// the current slice's segments are handed out separately as `&mut`).
struct SegCtx<'a> {
    before: &'a [u8],
    after: &'a [u8],
    pass: usize,
    slice: usize,
    p: usize,
    q: usize,
    seg_len: usize,
    params: &'a Argon2Params,
    backend: Backend,
}

impl SegCtx<'_> {
    /// B[lane][col] for a column outside the current slice.
    fn block(&self, lane: usize, col: usize) -> &[u8; BLOCK] {
        let s = col / self.seg_len;
        let (area, s_rel) = if s < self.slice {
            (self.before, s)
        } else {
            assert!(s > self.slice, "argon2: reference into the current slice");
            (self.after, s - self.slice - 1)
        };
        let off = ((s_rel * self.p + lane) * self.seg_len + col % self.seg_len) * BLOCK;
        area[off..off + BLOCK].try_into().unwrap()
    }
}

/// How many blocks ahead a data-independent segment prefetches reference
/// blocks (measured on Zen 5: 1 → 4 cut a 64 MiB Argon2i by a third; more
/// gained nothing).
const PREFETCH_AHEAD: usize = 4;

/// Processes one (pass, slice, lane) segment: `seg_len` blocks in lane `lane`,
/// columns `slice·seg_len .. (slice+1)·seg_len`, written into `own`. Reads
/// B[i][j-1] and a reference block determined per the variant's indexing
/// rules.
fn fill_segment(ctx: &SegCtx<'_>, lane: usize, own: &mut [u8]) {
    let SegCtx {
        pass,
        slice,
        p,
        q,
        seg_len,
        params,
        backend,
        ..
    } = *ctx;

    // Decide whether THIS segment uses data-independent (Argon2i-style) addressing.
    let data_independent = match params.variant {
        Argon2Type::Argon2i => true,
        Argon2Type::Argon2d => false,
        Argon2Type::Argon2id => pass == 0 && slice < 2,
    };

    let start_idx = if pass == 0 && slice == 0 { 2 } else { 0 };
    let xor_into = pass > 0 && params.version == 0x13;

    // G's working blocks live here rather than in the compression function's
    // own frame, so that they can be wiped once per segment instead of on
    // every one of the millions of block compressions (a per-call volatile
    // wipe of 2 KiB would cost more than the compression itself).
    // `scratch.state` carries B[lane][j-1] from one block to the next, so the
    // previous block is read from memory only once per segment.
    let mut scratch = GScratch::new();
    let first = slice * seg_len + start_idx;
    let prev_col = if first == 0 { q - 1 } else { first - 1 };
    let prev = if prev_col / seg_len == slice {
        let off = (prev_col % seg_len) * BLOCK;
        <&[u8; BLOCK]>::try_from(&own[off..off + BLOCK]).unwrap()
    } else {
        ctx.block(lane, prev_col)
    };
    scratch.set_state(prev);

    // The Argon2i / Argon2id-first-half (J1, J2) stream: address block `k`
    // (counter `k + 1`) holds the pairs for blocks `128k .. 128k + 128` of
    // the segment. The current block and the next are kept, so that the
    // prefetch below can look `PREFETCH_AHEAD` blocks ahead across a 128-block
    // boundary; each is generated when that look-ahead first reaches it.
    // Built only from public segment parameters, so neither they nor their
    // scratch need a wipe.
    let mut addr = [[0u8; BLOCK]; 2];
    let mut addr_scratch = GScratch::new();
    let mut gen_addr = |k: usize, addr: &mut [[u8; BLOCK]; 2]| {
        address_block(
            pass,
            lane,
            slice,
            p * q,
            params,
            k as u64 + 1,
            backend,
            &mut addr_scratch,
            &mut addr[k & 1],
        );
    };
    let pair = |addr: &[[u8; BLOCK]; 2], i: usize| -> (u32, u32) {
        let a = &addr[(i / 128) & 1];
        let off = (i % 128) * 8;
        (
            u32::from_le_bytes(a[off..off + 4].try_into().unwrap()),
            u32::from_le_bytes(a[off + 4..off + 8].try_into().unwrap()),
        )
    };
    if data_independent {
        gen_addr(0, &mut addr);
    }
    // Only ever used as a prefetch address, never dereferenced.
    let own_base = own.as_ptr();

    for i_seg in start_idx..seg_len {
        // Get J1, J2 — either from the previous block (Argon2d) or the
        // pseudo-random address stream (Argon2i / first-half Argon2id).
        let (j1, j2) = if data_independent {
            pair(&addr, i_seg)
        } else {
            let w0 = scratch.state[0];
            (w0 as u32, (w0 >> 32) as u32)
        };

        // Reference block index.
        let (ref_lane, ref_col) =
            compute_ref_index(pass, lane, slice, i_seg, p, q, seg_len, j1, j2);

        // B[lane][j] = G(B[lane][j-1], B[ref_lane][ref_col]) (XORed into
        // the current B[lane][j] on pass > 0, per v1.3). The reference area
        // never includes the block being written, and inside the current
        // slice only this lane's already-computed blocks.
        let (done, rest) = own.split_at_mut(i_seg * BLOCK);
        let next: &mut [u8; BLOCK] = (&mut rest[..BLOCK]).try_into().unwrap();
        let refb: &[u8; BLOCK] = if ref_col / seg_len == slice {
            assert_eq!(ref_lane, lane, "argon2: cross-lane reference in slice");
            let off = (ref_col % seg_len) * BLOCK;
            done[off..off + BLOCK].try_into().unwrap()
        } else {
            ctx.block(ref_lane, ref_col)
        };

        // What to prefetch while this block is computed (see
        // `Backend::compress`): in data-independent segments the reference
        // block `PREFETCH_AHEAD` steps ahead, read off the address stream;
        // otherwise the next step's, from the new block's word 0 exactly as
        // the next iteration will derive it — which only exists near the end
        // of this step, so that prefetch has less time to land.
        let ahead = i_seg + PREFETCH_AHEAD;
        if data_independent && ahead < seg_len && ahead.is_multiple_of(128) {
            gen_addr(ahead / 128, &mut addr);
        }
        let addr = &addr;
        let hint = |w0: u64| -> *const u8 {
            let (n, (j1, j2)) = if data_independent {
                (
                    ahead,
                    if ahead < seg_len {
                        pair(addr, ahead)
                    } else {
                        (0, 0)
                    },
                )
            } else {
                (i_seg + 1, (w0 as u32, (w0 >> 32) as u32))
            };
            if n >= seg_len {
                return core::ptr::null();
            }
            let (rl, rc) = compute_ref_index(pass, lane, slice, n, p, q, seg_len, j1, j2);
            if rc / seg_len == slice {
                own_base.wrapping_add((rc % seg_len) * BLOCK)
            } else {
                ctx.block(rl, rc).as_ptr()
            }
        };
        backend.compress(&mut scratch, refb, next, xor_into, hint);
    }

    scratch.wipe();
}

/// Argon2i / Argon2id (first-half) pseudo-random address generation: fills
/// `addr_block` with address block number `counter` of the segment, 128
/// (J1, J2) pairs as consecutive little-endian `u32`s.
#[allow(clippy::too_many_arguments)]
fn address_block(
    pass: usize,
    lane: usize,
    slice: usize,
    total_blocks: usize,
    params: &Argon2Params,
    counter: u64,
    backend: Backend,
    scratch: &mut GScratch,
    addr_block: &mut [u8; BLOCK],
) {
    let mut input = [0u8; BLOCK];
    input[0..8].copy_from_slice(&(pass as u64).to_le_bytes());
    input[8..16].copy_from_slice(&(lane as u64).to_le_bytes());
    input[16..24].copy_from_slice(&(slice as u64).to_le_bytes());
    input[24..32].copy_from_slice(&(total_blocks as u64).to_le_bytes()); // m'
    input[32..40].copy_from_slice(&(params.t_cost as u64).to_le_bytes());
    input[40..48].copy_from_slice(&(params.variant.ty_byte() as u64).to_le_bytes());
    input[48..56].copy_from_slice(&counter.to_le_bytes());

    // ADDR_BLOCK = G(zero, G(zero, INPUT_BLOCK))
    // Nothing here is password-derived (the inputs are the public segment
    // parameters), so this scratch needs no wipe.
    let mut tmp = [0u8; BLOCK];
    scratch.state = [0u64; 128];
    let none = |_| core::ptr::null();
    backend.compress(scratch, &input, &mut tmp, false, none);
    scratch.state = [0u64; 128];
    backend.compress(scratch, &tmp, addr_block, false, none);
}

/// Maps (J1, J2) to a `(ref_lane, ref_col)` using RFC 9106 §3.4's mapping.
#[allow(clippy::too_many_arguments)]
fn compute_ref_index(
    pass: usize,
    lane: usize,
    slice: usize,
    j_within_seg: usize,
    p: usize,
    q: usize,
    seg_len: usize,
    j1: u32,
    j2: u32,
) -> (usize, usize) {
    // Reference lane.
    let ref_lane = if pass == 0 && slice == 0 {
        lane
    } else {
        (j2 as usize) % p
    };

    let same_lane = ref_lane == lane;

    // Size of the reference area W.
    let w: usize = if pass == 0 {
        if slice == 0 {
            // Only this segment is candidate (this block depends on prev only).
            j_within_seg - 1
        } else if same_lane {
            slice * seg_len + j_within_seg - 1
        } else if j_within_seg == 0 {
            slice * seg_len - 1
        } else {
            slice * seg_len
        }
    } else if same_lane {
        q - seg_len + j_within_seg - 1
    } else if j_within_seg == 0 {
        q - seg_len - 1
    } else {
        q - seg_len
    };

    // Map J1 into [0, W-1].
    let x = ((j1 as u64).wrapping_mul(j1 as u64)) >> 32;
    let y = ((w as u64).wrapping_mul(x)) >> 32;
    let z = w - 1 - (y as usize);

    let start: usize = if pass == 0 {
        0
    } else {
        ((slice + 1) * seg_len) % q
    };

    let ref_col = (start + z) % q;
    (ref_lane, ref_col)
}

// --------------------------------------------------------------------------
// H' — Argon2's variable-output BLAKE2b wrapper (RFC 9106 §3.3).
// --------------------------------------------------------------------------
fn h_prime(input: &[u8], out: &mut [u8]) {
    let outlen = out.len() as u32;
    let outlen_bytes = outlen.to_le_bytes();
    if out.len() <= 64 {
        let mut mac = Blake2bMac::new_unkeyed(out.len());
        mac.update(&outlen_bytes);
        mac.update(input);
        mac.finalize_into(out);
        return;
    }

    // V_1 = BLAKE2b_64(LE32(T) ‖ input).
    let mut v = [0u8; 64];
    {
        let mut mac = Blake2bMac::new_unkeyed(64);
        mac.update(&outlen_bytes);
        mac.update(input);
        mac.finalize_into(&mut v);
    }
    out[..32].copy_from_slice(&v[..32]);

    let r = out.len().div_ceil(32) - 2;
    let mut written = 32;
    let mut next = [0u8; 64];
    for _ in 1..r {
        let mut mac = Blake2bMac::new_unkeyed(64);
        mac.update(&v);
        mac.finalize_into(&mut next);
        out[written..written + 32].copy_from_slice(&next[..32]);
        written += 32;
        v = next;
    }
    // V_{r+1} = BLAKE2b(V_r, T - 32·r).
    let final_len = out.len() - 32 * r;
    let mut mac = Blake2bMac::new_unkeyed(final_len);
    mac.update(&v);
    mac.finalize_into(&mut out[written..]);

    // `v`/`next` hold whole V_i blocks, of which only the leading 32 bytes
    // reach `out`; the rest is unpublished keying material. Wipe both — H′ runs
    // once per lane plus once at the end, not per memory block, so this is off
    // the hot path.
    super::wipe(&mut v);
    super::wipe(&mut next);
}

// --------------------------------------------------------------------------
// G compression function (RFC 9106 §3.6).
// --------------------------------------------------------------------------

/// Which implementation of `G` to run. Chosen once per [`argon2`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Backend {
    /// Scalar `u64` code, any target.
    Portable,
    /// 256-bit lanes: one BLAKE2b row (16 words) in four `ymm`.
    #[cfg(target_arch = "x86_64")]
    Avx2,
    /// 512-bit lanes, with `vprorq` rotations.
    #[cfg(target_arch = "x86_64")]
    Avx512,
}

impl Backend {
    fn detect() -> Self {
        #[cfg(target_arch = "x86_64")]
        if !crate::ct::force_portable() {
            if simd::avx512_supported() {
                return Backend::Avx512;
            }
            if simd::avx2_supported() {
                return Backend::Avx2;
            }
        }
        Backend::Portable
    }

    /// The fused per-block step on `s.state` = B[lane][j-1]:
    /// `next ← G(state, refb)` (or `next ← next ⊕ G(state, refb)` when
    /// `xor_into`), and `state ← next`.
    ///
    /// `hint` is called once, with word 0 of the new block, as soon as that
    /// word is known (before the rest of the block is): it returns the
    /// address of the block the *next* step will reference, or null, and the
    /// SIMD backends prefetch it while they finish this block.
    #[inline]
    fn compress<F: FnOnce(u64) -> *const u8>(
        self,
        s: &mut GScratch,
        refb: &[u8; BLOCK],
        next: &mut [u8; BLOCK],
        xor_into: bool,
        hint: F,
    ) {
        match self {
            // Nothing to overlap a prefetch with in the scalar code.
            Backend::Portable => {
                drop(hint);
                compress_portable(s, refb, next, xor_into)
            }
            #[cfg(target_arch = "x86_64")]
            Backend::Avx2 => {
                simd::compress_avx2(&mut s.state, &mut s.xy, refb, next, xor_into, hint)
            }
            #[cfg(target_arch = "x86_64")]
            Backend::Avx512 => {
                simd::compress_avx512(&mut s.state, &mut s.xy, refb, next, xor_into, hint)
            }
        }
    }
}

/// BLAKE2b-style mixing function `GB` used by Argon2.
#[inline]
fn gb(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    let f = |x: u64, y: u64| 2u64.wrapping_mul((x & 0xffff_ffff).wrapping_mul(y & 0xffff_ffff));
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(f(v[a], v[b]));
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]).wrapping_add(f(v[c], v[d]));
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(f(v[a], v[b]));
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]).wrapping_add(f(v[c], v[d]));
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// One BLAKE2b round: column-then-diagonal GB sequence on a `[u64; 16]`.
fn p_round(v: &mut [u64; 16]) {
    gb(v, 0, 4, 8, 12);
    gb(v, 1, 5, 9, 13);
    gb(v, 2, 6, 10, 14);
    gb(v, 3, 7, 11, 15);
    gb(v, 0, 5, 10, 15);
    gb(v, 1, 6, 11, 12);
    gb(v, 2, 7, 8, 13);
    gb(v, 3, 4, 9, 14);
}

/// `G`'s working blocks, owned by the caller: `state`, the previous block
/// B[lane][j-1] (which becomes the new block after each step), and `xy`,
/// the `R ⊕ B[lane][j]` term of the final XOR.
///
/// They hold password-derived data on the main fill path, so they must be
/// wiped — but `G` runs once per 1 KiB memory block (millions of times for
/// realistic parameters), and a volatile wipe of 2 KiB per call would dominate
/// the compression itself. Keeping them in the caller's frame lets the whole
/// segment share one buffer that is wiped once, in [`fill_segment`].
/// 64-byte aligned for the SIMD backends' aligned loads and stores.
#[repr(C, align(64))]
struct GScratch {
    state: [u64; 128],
    xy: [u64; 128],
}

impl GScratch {
    fn new() -> Self {
        GScratch {
            state: [0u64; 128],
            xy: [0u64; 128],
        }
    }

    fn wipe(&mut self) {
        self.state.zeroize();
        self.xy.zeroize();
    }

    /// Loads a block (little-endian words) into `state`.
    fn set_state(&mut self, block: &[u8; BLOCK]) {
        for (w, c) in self.state.iter_mut().zip(block.chunks_exact(8)) {
            *w = u64::from_le_bytes(c.try_into().unwrap());
        }
    }
}

/// Portable [`Backend::compress`].
fn compress_portable(s: &mut GScratch, refb: &[u8; BLOCK], next: &mut [u8; BLOCK], xor_into: bool) {
    let GScratch { state: z, xy } = s;

    // R = X ⊕ Y into `z`; `xy` = R (⊕ the old B[lane][j] for v1.3 pass > 0).
    for (i, rc) in refb.chunks_exact(8).enumerate() {
        z[i] ^= u64::from_le_bytes(rc.try_into().unwrap());
    }
    if xor_into {
        for (i, nc) in next.chunks_exact(8).enumerate() {
            xy[i] = z[i] ^ u64::from_le_bytes(nc.try_into().unwrap());
        }
    } else {
        xy.copy_from_slice(z);
    }

    // One P-round working row, wiped at the end: it holds password-derived
    // state and would otherwise drop in the clear on the stack (every use
    // below overwrites all 16 words first).
    let mut tmp = [0u64; 16];

    // Apply P to each row (16 consecutive u64s).
    for row in 0..8 {
        tmp.copy_from_slice(&z[row * 16..row * 16 + 16]);
        p_round(&mut tmp);
        z[row * 16..row * 16 + 16].copy_from_slice(&tmp);
    }

    // Apply P to each "column" (2 consecutive u64s per row, 8 rows → 16
    // u64s).
    for col in 0..8 {
        for i in 0..8 {
            tmp[2 * i] = z[16 * i + 2 * col];
            tmp[2 * i + 1] = z[16 * i + 2 * col + 1];
        }
        p_round(&mut tmp);
        for i in 0..8 {
            z[16 * i + 2 * col] = tmp[2 * i];
            z[16 * i + 2 * col + 1] = tmp[2 * i + 1];
        }
    }
    tmp.zeroize();

    // B[lane][j] = P(R) ⊕ xy, which is also the next step's previous block.
    for (i, o) in next.chunks_exact_mut(8).enumerate() {
        z[i] ^= xy[i];
        o.copy_from_slice(&z[i].to_le_bytes());
    }
}

/// Transparent-huge-page advice for the memory matrix.
///
/// On Linux (x86_64, aarch64) this is one raw `madvise(MADV_HUGEPAGE)`
/// syscall — the crate has no `libc` dependency; compare
/// `rng::linux_getrandom` — over the 2 MiB-aligned interior of the matrix.
/// It only marks the range as eligible for huge pages (contents, protection
/// and the allocator's ownership are unchanged), so it is sound on memory the
/// global allocator handed out, and its result is ignored: with THP disabled
/// (`/sys/kernel/mm/transparent_hugepage/enabled = never`) or unsupported it
/// fails harmlessly, with THP set to `always` it is redundant. With the
/// common `madvise` setting it is what turns huge pages on, which measured
/// ~20% faster for a 64 MiB Argon2id. Elsewhere it does nothing.
mod hugepages {
    /// Huge-page size the advice is aligned to (x86_64 and 4 KiB-granule
    /// aarch64 PMD size).
    const HUGE: usize = 2 << 20;

    pub(super) fn advise(buf: &mut [u8]) {
        let start = buf.as_ptr() as usize;
        let lo = start.next_multiple_of(HUGE);
        let hi = (start + buf.len()) & !(HUGE - 1);
        if hi > lo {
            imp::madvise_hugepage(buf[lo - start..hi - start].as_mut_ptr(), hi - lo);
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    ))]
    #[allow(unsafe_code)] // the raw syscall
    mod imp {
        /// `MADV_HUGEPAGE` (`include/uapi/asm-generic/mman-common.h`).
        const MADV_HUGEPAGE: usize = 14;

        /// `madvise(addr, len, MADV_HUGEPAGE)`; `addr` is 2 MiB-aligned and
        /// `[addr, addr + len)` lies inside one live allocation.
        pub(super) fn madvise_hugepage(addr: *mut u8, len: usize) {
            // SAFETY: `MADV_HUGEPAGE` does not change the contents, mapping
            // or protection of the range — it only sets the VMA's THP
            // eligibility — so no Rust-visible memory is affected whatever
            // the outcome; the error return is deliberately ignored.
            let _ = unsafe { syscall3(addr, len, MADV_HUGEPAGE) };
        }

        /// x86_64: `madvise` is syscall 28; args in rdi/rsi/rdx, return in
        /// rax; `syscall` clobbers rcx and r11.
        #[cfg(target_arch = "x86_64")]
        unsafe fn syscall3(addr: *mut u8, len: usize, advice: usize) -> isize {
            let ret: isize;
            unsafe {
                core::arch::asm!(
                    "syscall",
                    inlateout("rax") 28isize => ret,
                    in("rdi") addr,
                    in("rsi") len,
                    in("rdx") advice,
                    lateout("rcx") _,
                    lateout("r11") _,
                    options(nostack, preserves_flags),
                );
            }
            ret
        }

        /// aarch64: `madvise` is syscall 233 (asm-generic); number in x8,
        /// args in x0/x1/x2, return in x0.
        #[cfg(target_arch = "aarch64")]
        unsafe fn syscall3(addr: *mut u8, len: usize, advice: usize) -> isize {
            let ret: isize;
            unsafe {
                core::arch::asm!(
                    "svc #0",
                    in("x8") 233isize,
                    inlateout("x0") addr as isize => ret,
                    in("x1") len,
                    in("x2") advice,
                    options(nostack, preserves_flags),
                );
            }
            ret
        }
    }

    #[cfg(not(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        not(miri)
    )))]
    mod imp {
        pub(super) fn madvise_hugepage(_addr: *mut u8, _len: usize) {}
    }
}

/// x86_64 AVX2 / AVX-512 `G`, after the reference implementation's
/// `blamka-round-opt.h`: the fBlaMka product `2·lo(a)·lo(b)` is one
/// `vpmuludq`, and the rotations are byte shuffles (AVX2) or `vprorq`
/// (AVX-512). The block is 128 words `v[0..128]`, eight 16-word rows.
///
/// - Row rounds hold row `r` as four 4-word vectors `a b c d` (one BLAKE2b
///   state) and diagonalize with cross-lane `vpermq`. The AVX-512 kernel puts
///   two rows side by side, one per 256-bit half.
/// - Column rounds keep the natural memory layout: the 32-byte chunk `j` of
///   row `i` holds the two words that columns `2j` and `2j+1` take from that
///   row, one column per 128-bit lane. Lining the eight rows' chunk `j` up as
///   `Y0..Y7`, the column step is lanewise on `(Y0,Y2,Y4,Y6)` and
///   `(Y1,Y3,Y5,Y7)`, and the diagonal step only needs in-lane `vpalignr`
///   (and a swap of `Y4`/`Y5`). The AVX-512 kernel does chunks `2k` and
///   `2k+1` together, which is exactly one 64-byte load per row.
#[cfg(target_arch = "x86_64")]
#[allow(unsafe_code)]
mod simd {
    use super::BLOCK;
    use core::arch::x86_64::*;

    pub(super) fn avx2_supported() -> bool {
        crate::cpu::avx2()
    }

    pub(super) fn avx512_supported() -> bool {
        crate::cpu::avx512bw()
    }

    /// Expands `$body` once per listed index, with `$k` bound to that
    /// literal: a guaranteed full unroll, so every vector index is a constant
    /// and the whole block stays in registers.
    macro_rules! unroll {
        ([$($i:literal)*], |$k:ident| $body:block) => {
            $( { let $k: usize = $i; $body } )*
        };
    }

    /// Prefetches the 1 KiB block at `p` (no-op for null). A prefetch never
    /// faults, whatever the address.
    #[inline(always)]
    unsafe fn prefetch_block(p: *const u8) {
        if !p.is_null() {
            unsafe {
                unroll!([0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15], |i| {
                    _mm_prefetch::<_MM_HINT_T0>(p.wrapping_add(64 * i).cast::<i8>());
                });
            }
        }
    }

    // ---------------------------------------------------------------- AVX2

    #[inline(always)]
    unsafe fn fblamka2(x: __m256i, y: __m256i) -> __m256i {
        unsafe {
            let z = _mm256_mul_epu32(x, y);
            _mm256_add_epi64(_mm256_add_epi64(x, y), _mm256_add_epi64(z, z))
        }
    }

    /// `GB` lanewise on four vectors; `r24` / `r16` are the byte-shuffle
    /// masks for the 24- and 16-bit rotations.
    #[inline(always)]
    unsafe fn g2(
        a: &mut __m256i,
        b: &mut __m256i,
        c: &mut __m256i,
        d: &mut __m256i,
        r24: __m256i,
        r16: __m256i,
    ) {
        unsafe {
            *a = fblamka2(*a, *b);
            *d = _mm256_shuffle_epi32::<0b10_11_00_01>(_mm256_xor_si256(*d, *a));
            *c = fblamka2(*c, *d);
            *b = _mm256_shuffle_epi8(_mm256_xor_si256(*b, *c), r24);
            *a = fblamka2(*a, *b);
            *d = _mm256_shuffle_epi8(_mm256_xor_si256(*d, *a), r16);
            *c = fblamka2(*c, *d);
            let t = _mm256_xor_si256(*b, *c);
            *b = _mm256_xor_si256(_mm256_srli_epi64::<63>(t), _mm256_add_epi64(t, t));
        }
    }

    /// Row round on row `r`: `v[4r..4r+4]` = `a b c d`.
    #[inline(always)]
    unsafe fn row2(v: &mut [__m256i; 32], r: usize, r24: __m256i, r16: __m256i) {
        unsafe {
            let (mut a, mut b, mut c, mut d) = (v[4 * r], v[4 * r + 1], v[4 * r + 2], v[4 * r + 3]);
            g2(&mut a, &mut b, &mut c, &mut d, r24, r16);
            b = _mm256_permute4x64_epi64::<0x39>(b);
            c = _mm256_permute4x64_epi64::<0x4e>(c);
            d = _mm256_permute4x64_epi64::<0x93>(d);
            g2(&mut a, &mut b, &mut c, &mut d, r24, r16);
            v[4 * r] = a;
            v[4 * r + 1] = _mm256_permute4x64_epi64::<0x93>(b);
            v[4 * r + 2] = _mm256_permute4x64_epi64::<0x4e>(c);
            v[4 * r + 3] = _mm256_permute4x64_epi64::<0x39>(d);
        }
    }

    /// Column round on columns `2j`, `2j+1`: `Yi = v[4i + j]`.
    #[inline(always)]
    unsafe fn col2(v: &mut [__m256i; 32], j: usize, r24: __m256i, r16: __m256i) {
        unsafe {
            let (mut y0, mut y1, mut y2, mut y3) = (v[j], v[4 + j], v[8 + j], v[12 + j]);
            let (mut y4, mut y5, mut y6, mut y7) = (v[16 + j], v[20 + j], v[24 + j], v[28 + j]);
            g2(&mut y0, &mut y2, &mut y4, &mut y6, r24, r16);
            g2(&mut y1, &mut y3, &mut y5, &mut y7, r24, r16);
            // Diagonalize: (Y0, [b1 b2], Y5, [d3 d0]) and
            // (Y1, [b3 b0], Y4, [d1 d2]), per 128-bit lane.
            let mut b0 = _mm256_alignr_epi8::<8>(y3, y2);
            let mut b1 = _mm256_alignr_epi8::<8>(y2, y3);
            let mut d0 = _mm256_alignr_epi8::<8>(y6, y7);
            let mut d1 = _mm256_alignr_epi8::<8>(y7, y6);
            g2(&mut y0, &mut b0, &mut y5, &mut d0, r24, r16);
            g2(&mut y1, &mut b1, &mut y4, &mut d1, r24, r16);
            v[j] = y0;
            v[4 + j] = y1;
            v[8 + j] = _mm256_alignr_epi8::<8>(b0, b1);
            v[12 + j] = _mm256_alignr_epi8::<8>(b1, b0);
            v[16 + j] = y4;
            v[20 + j] = y5;
            v[24 + j] = _mm256_alignr_epi8::<8>(d1, d0);
            v[28 + j] = _mm256_alignr_epi8::<8>(d0, d1);
        }
    }

    /// Safe entry: [`super::Backend::compress`] for AVX2.
    pub(super) fn compress_avx2<F: FnOnce(u64) -> *const u8>(
        state: &mut [u64; 128],
        xy: &mut [u64; 128],
        refb: &[u8; BLOCK],
        next: &mut [u8; BLOCK],
        xor_into: bool,
        hint: F,
    ) {
        assert!(avx2_supported());
        // SAFETY: AVX2 was just confirmed; all pointers come from references
        // to 1024-byte buffers, and `state`/`xy` are 64-byte aligned
        // (`GScratch` is `align(64)` with `state` at offset 0, `xy` at 1024).
        unsafe { compress_avx2_impl(state, xy, refb, next, xor_into, hint) }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn compress_avx2_impl<F: FnOnce(u64) -> *const u8>(
        state: &mut [u64; 128],
        xy: &mut [u64; 128],
        refb: &[u8; BLOCK],
        next: &mut [u8; BLOCK],
        xor_into: bool,
        hint: F,
    ) {
        unsafe {
            let sp = state.as_mut_ptr().cast::<__m256i>();
            let xp = xy.as_mut_ptr().cast::<__m256i>();
            let rp = refb.as_ptr().cast::<__m256i>();
            let np = next.as_mut_ptr().cast::<__m256i>();

            let mut v = [_mm256_setzero_si256(); 32];
            unroll!([0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31], |k| {
                let t = _mm256_xor_si256(_mm256_load_si256(sp.add(k)), _mm256_loadu_si256(rp.add(k)));
                v[k] = t;
                let w = if xor_into { _mm256_xor_si256(t, _mm256_loadu_si256(np.add(k))) } else { t };
                _mm256_store_si256(xp.add(k), w);
            });

            #[rustfmt::skip]
            let r24 = _mm256_setr_epi8(
                3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10,
                3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10,
            );
            #[rustfmt::skip]
            let r16 = _mm256_setr_epi8(
                2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9,
                2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9,
            );

            unroll!([0 1 2 3 4 5 6 7], |r| {
                row2(&mut v, r, r24, r16);
            });
            // Columns 0 and 1 hold word 0 of the result, which is all the
            // caller needs to locate the next reference block: hand it over
            // now, so that block's prefetch overlaps the other columns.
            col2(&mut v, 0, r24, r16);
            let w0 = _mm256_xor_si256(v[0], _mm256_load_si256(xp));
            prefetch_block(hint(_mm_cvtsi128_si64(_mm256_castsi256_si128(w0)) as u64));
            unroll!([1 2 3], |j| {
                col2(&mut v, j, r24, r16);
            });

            unroll!([0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31], |k| {
                let t = _mm256_xor_si256(v[k], _mm256_load_si256(xp.add(k)));
                _mm256_storeu_si256(np.add(k), t);
                _mm256_store_si256(sp.add(k), t);
            });
        }
    }

    // ------------------------------------------------------------- AVX-512

    #[inline(always)]
    unsafe fn fblamka5(x: __m512i, y: __m512i) -> __m512i {
        unsafe {
            let z = _mm512_mul_epu32(x, y);
            _mm512_add_epi64(_mm512_add_epi64(x, y), _mm512_add_epi64(z, z))
        }
    }

    #[inline(always)]
    unsafe fn g5(a: &mut __m512i, b: &mut __m512i, c: &mut __m512i, d: &mut __m512i) {
        unsafe {
            *a = fblamka5(*a, *b);
            *d = _mm512_ror_epi64::<32>(_mm512_xor_si512(*d, *a));
            *c = fblamka5(*c, *d);
            *b = _mm512_ror_epi64::<24>(_mm512_xor_si512(*b, *c));
            *a = fblamka5(*a, *b);
            *d = _mm512_ror_epi64::<16>(_mm512_xor_si512(*d, *a));
            *c = fblamka5(*c, *d);
            *b = _mm512_ror_epi64::<63>(_mm512_xor_si512(*b, *c));
        }
    }

    /// Row round on rows `r` and `r+1` side by side (`r` even): with
    /// `v[2r] = [a|b]`, `v[2r+1] = [c|d]` of row `r`, regroup into
    /// `a = [a_r | a_{r+1}]` etc.
    #[inline(always)]
    unsafe fn row5(v: &mut [__m512i; 16], r: usize) {
        unsafe {
            let mut a = _mm512_shuffle_i64x2::<0x44>(v[2 * r], v[2 * r + 2]);
            let mut b = _mm512_shuffle_i64x2::<0xee>(v[2 * r], v[2 * r + 2]);
            let mut c = _mm512_shuffle_i64x2::<0x44>(v[2 * r + 1], v[2 * r + 3]);
            let mut d = _mm512_shuffle_i64x2::<0xee>(v[2 * r + 1], v[2 * r + 3]);
            g5(&mut a, &mut b, &mut c, &mut d);
            b = _mm512_permutex_epi64::<0x39>(b);
            c = _mm512_permutex_epi64::<0x4e>(c);
            d = _mm512_permutex_epi64::<0x93>(d);
            g5(&mut a, &mut b, &mut c, &mut d);
            b = _mm512_permutex_epi64::<0x93>(b);
            c = _mm512_permutex_epi64::<0x4e>(c);
            d = _mm512_permutex_epi64::<0x39>(d);
            v[2 * r] = _mm512_shuffle_i64x2::<0x44>(a, b);
            v[2 * r + 2] = _mm512_shuffle_i64x2::<0xee>(a, b);
            v[2 * r + 1] = _mm512_shuffle_i64x2::<0x44>(c, d);
            v[2 * r + 3] = _mm512_shuffle_i64x2::<0xee>(c, d);
        }
    }

    /// Column round on columns `4k..4k+4`: `Yi = v[2i + k]` (see the module
    /// docs; the 128-bit lanes are independent, as in [`col2`]).
    #[inline(always)]
    unsafe fn col5(v: &mut [__m512i; 16], k: usize) {
        unsafe {
            let (mut y0, mut y1, mut y2, mut y3) = (v[k], v[2 + k], v[4 + k], v[6 + k]);
            let (mut y4, mut y5, mut y6, mut y7) = (v[8 + k], v[10 + k], v[12 + k], v[14 + k]);
            g5(&mut y0, &mut y2, &mut y4, &mut y6);
            g5(&mut y1, &mut y3, &mut y5, &mut y7);
            let mut b0 = _mm512_alignr_epi8::<8>(y3, y2);
            let mut b1 = _mm512_alignr_epi8::<8>(y2, y3);
            let mut d0 = _mm512_alignr_epi8::<8>(y6, y7);
            let mut d1 = _mm512_alignr_epi8::<8>(y7, y6);
            g5(&mut y0, &mut b0, &mut y5, &mut d0);
            g5(&mut y1, &mut b1, &mut y4, &mut d1);
            v[k] = y0;
            v[2 + k] = y1;
            v[4 + k] = _mm512_alignr_epi8::<8>(b0, b1);
            v[6 + k] = _mm512_alignr_epi8::<8>(b1, b0);
            v[8 + k] = y4;
            v[10 + k] = y5;
            v[12 + k] = _mm512_alignr_epi8::<8>(d1, d0);
            v[14 + k] = _mm512_alignr_epi8::<8>(d0, d1);
        }
    }

    /// Safe entry: [`super::Backend::compress`] for AVX-512 (F + BW).
    pub(super) fn compress_avx512<F: FnOnce(u64) -> *const u8>(
        state: &mut [u64; 128],
        xy: &mut [u64; 128],
        refb: &[u8; BLOCK],
        next: &mut [u8; BLOCK],
        xor_into: bool,
        hint: F,
    ) {
        assert!(avx512_supported());
        // SAFETY: AVX-512F/BW were just confirmed; pointers and alignment as
        // in `compress_avx2`.
        unsafe { compress_avx512_impl(state, xy, refb, next, xor_into, hint) }
    }

    #[target_feature(enable = "avx512f,avx512bw")]
    unsafe fn compress_avx512_impl<F: FnOnce(u64) -> *const u8>(
        state: &mut [u64; 128],
        xy: &mut [u64; 128],
        refb: &[u8; BLOCK],
        next: &mut [u8; BLOCK],
        xor_into: bool,
        hint: F,
    ) {
        unsafe {
            let sp = state.as_mut_ptr().cast::<__m512i>();
            let xp = xy.as_mut_ptr().cast::<__m512i>();
            let rp = refb.as_ptr().cast::<__m512i>();
            let np = next.as_mut_ptr().cast::<__m512i>();

            // v[2r] = [a|b] and v[2r+1] = [c|d] of row r.
            let mut v = [_mm512_setzero_si512(); 16];
            unroll!([0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15], |k| {
                let t = _mm512_xor_si512(_mm512_load_si512(sp.add(k)), _mm512_loadu_si512(rp.add(k)));
                v[k] = t;
                let w = if xor_into { _mm512_xor_si512(t, _mm512_loadu_si512(np.add(k))) } else { t };
                _mm512_store_si512(xp.add(k), w);
            });

            unroll!([0 2 4 6], |r| {
                row5(&mut v, r);
            });
            // See `compress_avx2_impl`: word 0 is final after columns 0..4.
            col5(&mut v, 0);
            let w0 = _mm512_xor_si512(v[0], _mm512_load_si512(xp));
            prefetch_block(hint(_mm_cvtsi128_si64(_mm512_castsi512_si128(w0)) as u64));
            col5(&mut v, 1);

            unroll!([0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15], |k| {
                let t = _mm512_xor_si512(v[k], _mm512_load_si512(xp.add(k)));
                _mm512_storeu_si512(np.add(k), t);
                _mm512_store_si512(sp.add(k), t);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// Common RFC 9106 §5 test-vector parameters.
    fn rfc_inputs() -> (Argon2Params, [u8; 32], [u8; 16], [u8; 8], [u8; 12]) {
        let mut p = [0u8; 32];
        for b in p.iter_mut() {
            *b = 1;
        }
        let mut s = [0u8; 16];
        for b in s.iter_mut() {
            *b = 2;
        }
        let mut k = [0u8; 8];
        for b in k.iter_mut() {
            *b = 3;
        }
        let mut x = [0u8; 12];
        for b in x.iter_mut() {
            *b = 4;
        }
        let params = Argon2Params {
            t_cost: 3,
            m_cost_kib: 32,
            parallelism: 4,
            variant: Argon2Type::Argon2d,
            version: 0x13,
        };
        (params, p, s, k, x)
    }

    /// RFC 9106 §5.1: Argon2d test vector.
    #[test]
    fn rfc9106_argon2d() {
        let (mut params, p, s, k, x) = rfc_inputs();
        params.variant = Argon2Type::Argon2d;
        let expected = from_hex::<32>(
            "512b391b6f1162975371d3091973429\
             4f868e3be3984f3c1a13a4db9fabe4acb",
        );
        let mut out = [0u8; 32];
        argon2(&params, &p, &s, &k, &x, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    /// RFC 9106 §5.2: Argon2i test vector.
    #[test]
    fn rfc9106_argon2i() {
        let (mut params, p, s, k, x) = rfc_inputs();
        params.variant = Argon2Type::Argon2i;
        let expected = from_hex::<32>(
            "c814d9d1dc7f37aa13f0d77f2494bd\
             a1c8de6b016dd388d29952a4c4672b6ce8",
        );
        let mut out = [0u8; 32];
        argon2(&params, &p, &s, &k, &x, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    /// RFC 9106 §5.3: Argon2id test vector.
    #[test]
    fn multi_address_block_segments() {
        // Segments longer than one 128-pair address block (m = 2048 KiB,
        // p = 1: 512 blocks per segment), so the data-independent path walks
        // several address blocks generated on demand. Pinned to the output of
        // the previous implementation (which precomputed every pair of the
        // segment up front); the RFC 9106 vectors only have 2-block segments.
        for (variant, hex) in [
            (
                Argon2Type::Argon2i,
                "bd34fcc2a9ed6be231f431864134d250fee5c104b03abc4a0fcd14add0bb327f",
            ),
            (
                Argon2Type::Argon2id,
                "9bc1d339eedaa42961447df64465675eb061d5797b7b63f47af520832daf971f",
            ),
            (
                Argon2Type::Argon2d,
                "b643ff91180a11ddbf6bd6dd6601166d165e01007892cbc20e2d6d99e45b5b78",
            ),
        ] {
            let params = Argon2Params {
                t_cost: 2,
                m_cost_kib: 2048,
                parallelism: 1,
                variant,
                version: 0x13,
            };
            let mut out = [0u8; 32];
            argon2(&params, b"password", b"somesalt", &[], &[], &mut out).unwrap();
            assert_eq!(out, from_hex::<32>(hex), "{variant:?}");
        }
    }

    /// The phc-winner-argon2 reference test vector (`test.c`, Argon2i v1.3,
    /// t = 2, m = 2^16 KiB, p = 1).
    #[test]
    #[cfg_attr(debug_assertions, ignore = "64 MiB fill; run with --release")]
    fn reference_argon2i_m65536() {
        let params = Argon2Params {
            t_cost: 2,
            m_cost_kib: 1 << 16,
            parallelism: 1,
            variant: Argon2Type::Argon2i,
            version: 0x13,
        };
        let mut out = [0u8; 32];
        argon2(&params, b"password", b"somesalt", &[], &[], &mut out).unwrap();
        assert_eq!(
            out,
            from_hex::<32>("c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0")
        );
    }

    #[test]
    fn rfc9106_argon2id() {
        let (mut params, p, s, k, x) = rfc_inputs();
        params.variant = Argon2Type::Argon2id;
        let expected = from_hex::<32>(
            "0d640df58d78766c08c037a34a8b\
             53c9d01ef0452d75b65eb52520e96b01e659",
        );
        let mut out = [0u8; 32];
        argon2(&params, &p, &s, &k, &x, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn rejects_invalid_params() {
        let mut out = [0u8; 32];
        let bad_t = Argon2Params {
            t_cost: 0,
            m_cost_kib: 32,
            parallelism: 4,
            variant: Argon2Type::Argon2id,
            version: 0x13,
        };
        assert_eq!(
            argon2(&bad_t, b"p", b"saltsalt", b"", b"", &mut out),
            Err(Error::InvalidParam)
        );
        let bad_p = Argon2Params {
            t_cost: 1,
            m_cost_kib: 32,
            parallelism: 0,
            variant: Argon2Type::Argon2id,
            version: 0x13,
        };
        assert_eq!(
            argon2(&bad_p, b"p", b"saltsalt", b"", b"", &mut out),
            Err(Error::InvalidParam)
        );
        let bad_m = Argon2Params {
            t_cost: 1,
            m_cost_kib: 16, // < 8·p = 32
            parallelism: 4,
            variant: Argon2Type::Argon2id,
            version: 0x13,
        };
        assert_eq!(
            argon2(&bad_m, b"p", b"saltsalt", b"", b"", &mut out),
            Err(Error::InvalidParam)
        );
        let bad_v = Argon2Params {
            t_cost: 1,
            m_cost_kib: 32,
            parallelism: 4,
            variant: Argon2Type::Argon2id,
            version: 0x42,
        };
        assert_eq!(
            argon2(&bad_v, b"p", b"saltsalt", b"", b"", &mut out),
            Err(Error::InvalidParam)
        );
        // Salt below the RFC 9106 8-byte minimum (incl. empty) is rejected.
        let ok = Argon2Params {
            t_cost: 1,
            m_cost_kib: 32,
            parallelism: 4,
            variant: Argon2Type::Argon2id,
            version: 0x13,
        };
        assert_eq!(
            argon2(&ok, b"p", b"7bytes!", b"", b"", &mut out),
            Err(Error::InvalidParam)
        );
        assert_eq!(
            argon2(&ok, b"p", b"", b"", b"", &mut out),
            Err(Error::InvalidParam)
        );
        // The 8-byte boundary itself is accepted.
        assert!(argon2(&ok, b"p", b"saltsalt", b"", b"", &mut out).is_ok());
    }

    /// Every backend this CPU can run, the portable one first.
    fn backends() -> Vec<Backend> {
        #[allow(unused_mut)]
        let mut v = vec![Backend::Portable];
        #[cfg(target_arch = "x86_64")]
        {
            if simd::avx2_supported() {
                v.push(Backend::Avx2);
            }
            if simd::avx512_supported() {
                v.push(Backend::Avx512);
            }
        }
        v
    }

    /// SplitMix64, for reproducible random test blocks.
    fn fill_random(seed: &mut u64, buf: &mut [u8]) {
        for c in buf.chunks_mut(8) {
            *seed = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = *seed;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^= z >> 31;
            c.copy_from_slice(&z.to_le_bytes()[..c.len()]);
        }
    }

    /// Each SIMD `G` matches the portable one on random blocks, with and
    /// without the v1.3 XOR into the destination, including the carried
    /// state and the word-0 value handed to the prefetch hint.
    #[test]
    fn simd_compress_matches_portable() {
        let backends = backends();
        let mut seed = 1u64;
        for _ in 0..64 {
            let mut prev = [0u8; BLOCK];
            let mut refb = [0u8; BLOCK];
            let mut dst = [0u8; BLOCK];
            fill_random(&mut seed, &mut prev);
            fill_random(&mut seed, &mut refb);
            fill_random(&mut seed, &mut dst);
            for xor_into in [false, true] {
                let run = |b: Backend| {
                    let mut s = GScratch::new();
                    s.set_state(&prev);
                    let mut out = dst;
                    let mut hinted = None;
                    b.compress(&mut s, &refb, &mut out, xor_into, |w0| {
                        hinted = Some(w0);
                        core::ptr::null()
                    });
                    (out, s.state, hinted)
                };
                let (want, want_state, _) = run(Backend::Portable);
                let mut want_words = [0u64; 128];
                for (w, c) in want_words.iter_mut().zip(want.chunks_exact(8)) {
                    *w = u64::from_le_bytes(c.try_into().unwrap());
                }
                assert_eq!(want_state, want_words, "state carries the new block");
                for &b in &backends[1..] {
                    let (got, state, hinted) = run(b);
                    assert_eq!(got, want, "{b:?} xor_into={xor_into}");
                    assert_eq!(state, want_state, "{b:?} state");
                    assert_eq!(hinted, Some(want_words[0]), "{b:?} hint word");
                }
            }
        }
    }

    /// RFC 9106 vectors on every backend, the portable one included (the
    /// `#[test]`s above use whichever one the CPU selects).
    #[test]
    fn rfc9106_all_backends() {
        let (mut params, p, s, k, x) = rfc_inputs();
        for (variant, hex) in [
            (
                Argon2Type::Argon2d,
                "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
            ),
            (
                Argon2Type::Argon2i,
                "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
            ),
            (
                Argon2Type::Argon2id,
                "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
            ),
        ] {
            params.variant = variant;
            for b in backends() {
                for threads in [1, 4] {
                    let mut out = [0u8; 32];
                    argon2_impl(&params, &p, &s, &k, &x, &mut out, b, threads).unwrap();
                    assert_eq!(
                        out,
                        from_hex::<32>(hex),
                        "{variant:?} {b:?} threads={threads}"
                    );
                }
            }
        }
    }

    /// Whole hashes agree across backends and thread counts for assorted
    /// shapes: several lanes, segments longer than one address block (so
    /// the address look-ahead crosses 128-block boundaries), segment lengths
    /// that are not a multiple of 128, v1.0, and outputs longer than 64
    /// bytes.
    #[test]
    fn backends_and_threads_agree() {
        let shapes: &[(u32, u32, u32, u32, usize)] = &[
            // (m_kib, t, p, version, out_len)
            (8, 1, 1, 0x13, 32),
            (64, 3, 2, 0x13, 32),
            (100, 2, 3, 0x13, 80),
            (1024, 2, 1, 0x13, 32),
            (1032, 1, 2, 0x10, 16),
            (2052, 3, 4, 0x13, 64),
            (600, 2, 5, 0x13, 128),
        ];
        let mut seed = 7u64;
        for &(m, t, p, version, out_len) in shapes {
            for variant in [
                Argon2Type::Argon2d,
                Argon2Type::Argon2i,
                Argon2Type::Argon2id,
            ] {
                let params = Argon2Params {
                    t_cost: t,
                    m_cost_kib: m,
                    parallelism: p,
                    variant,
                    version,
                };
                let mut pw = [0u8; 13];
                fill_random(&mut seed, &mut pw);
                let mut want = vec![0u8; out_len];
                argon2_impl(
                    &params,
                    &pw,
                    b"somesalt",
                    b"key",
                    b"ad",
                    &mut want,
                    Backend::Portable,
                    1,
                )
                .unwrap();
                for b in backends() {
                    for threads in [1, 2, p as usize, 64] {
                        let mut got = vec![0u8; out_len];
                        argon2_impl(
                            &params,
                            &pw,
                            b"somesalt",
                            b"key",
                            b"ad",
                            &mut got,
                            b,
                            threads,
                        )
                        .unwrap();
                        assert_eq!(
                            got, want,
                            "m={m} t={t} p={p} v={version:#x} {variant:?} {b:?} threads={threads}"
                        );
                    }
                }
            }
        }
    }

    /// The public threaded entry point matches the sequential one.
    #[cfg(feature = "std")]
    #[test]
    fn threaded_matches_sequential() {
        let params = Argon2Params {
            t_cost: 2,
            m_cost_kib: 4096,
            parallelism: 4,
            variant: Argon2Type::Argon2id,
            version: 0x13,
        };
        let mut want = [0u8; 32];
        argon2(&params, b"password", b"somesalt", &[], &[], &mut want).unwrap();
        for threads in [0, 1, 3, 4, 100] {
            let mut got = [0u8; 32];
            argon2_threaded(
                &params,
                b"password",
                b"somesalt",
                &[],
                &[],
                &mut got,
                threads,
            )
            .unwrap();
            assert_eq!(got, want, "threads={threads}");
        }
    }

    /// The huge-page advice copes with buffers that do not span an aligned
    /// 2 MiB page and with ones that do (it must leave the contents alone).
    #[test]
    fn hugepage_advice_is_harmless() {
        for len in [0usize, 1024, 3 << 20, 9 << 20] {
            let mut v = vec![0xa5u8; len];
            hugepages::advise(&mut v);
            assert!(v.iter().all(|&b| b == 0xa5));
        }
    }
}
