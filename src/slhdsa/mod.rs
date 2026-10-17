//! SLH-DSA — the Stateless Hash-Based Digital Signature Algorithm (FIPS 205),
//! the standardized form of SPHINCS+.
//!
//! All twelve parameter sets are supported (SHA-2 / SHAKE × 128/192/256 × s/f)
//! through a runtime [`ParamSet`]. The scheme is built purely from the hash
//! primitives this crate already provides; it needs `alloc` for the large
//! signatures (up to ~50 KB) but no other foreign code.
//!
//! Signing is hedged by default and has a deterministic variant; both are
//! validated against the FIPS 205 ACVP vectors.

// The tree algorithms are faithful ports that thread the params, seeds, address,
// and several buffers explicitly.
#![allow(clippy::too_many_arguments)]

mod adrs;
mod hash;
#[cfg(feature = "key")]
mod key_impl;
mod params;
#[cfg(feature = "x509")]
pub(crate) mod registry;

use adrs::{Adrs, AdrsType};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use hash::Seed;
use params::{MAX_CONTEXT, MAX_K, MAX_M, MAX_N, MAX_WOTS_LEN, Params, SETS};

use crate::ct::ConstantTimeEq;
use crate::rng::{CryptoRng, RngCore};

/// Zeroizes `v` before it drops, via [`crate::zeroize::Zeroize`]: volatile
/// stores plus a compiler fence, so the writes cannot be eliminated as dead
/// stores (the wipe idiom used by the key epilogues below).
#[inline]
fn wipe(v: &mut [u8]) {
    crate::zeroize::Zeroize::zeroize(v);
}

/// Errors from SLH-DSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A key had the wrong length or its root did not check out.
    InvalidKey,
    /// The context string exceeded 255 bytes.
    ContextTooLong,
    /// Retained for API compatibility: empty messages are accepted (FIPS 205
    /// places no lower bound on `M`), so this variant is no longer returned.
    EmptyMessage,
    /// A DER/PEM structure was malformed.
    Malformed,
    /// A caller-supplied output buffer had the wrong length.
    InvalidLength,
}

/// An SLH-DSA parameter set (FIPS 205). Variant names mirror the standard set
/// names (e.g. `SLH-DSA-SHA2-128s`).
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum ParamSet {
    /// SLH-DSA-SHA2-128s.
    Sha2_128s = 0,
    /// SLH-DSA-SHA2-128f.
    Sha2_128f = 1,
    /// SLH-DSA-SHA2-192s.
    Sha2_192s = 2,
    /// SLH-DSA-SHA2-192f.
    Sha2_192f = 3,
    /// SLH-DSA-SHA2-256s.
    Sha2_256s = 4,
    /// SLH-DSA-SHA2-256f.
    Sha2_256f = 5,
    /// SLH-DSA-SHAKE-128s.
    Shake_128s = 6,
    /// SLH-DSA-SHAKE-128f.
    Shake_128f = 7,
    /// SLH-DSA-SHAKE-192s.
    Shake_192s = 8,
    /// SLH-DSA-SHAKE-192f.
    Shake_192f = 9,
    /// SLH-DSA-SHAKE-256s.
    Shake_256s = 10,
    /// SLH-DSA-SHAKE-256f.
    Shake_256f = 11,
}

impl ParamSet {
    fn params(self) -> &'static Params {
        &SETS[self as usize]
    }

    /// The signature size for this set, in bytes.
    pub fn signature_size(self) -> usize {
        self.params().sig_size
    }

    /// The PKIX algorithm OID arcs for this parameter set (FIPS 205 / NIST).
    /// Used for both SPKI and the X.509 certificate signatureAlgorithm.
    pub fn oid(self) -> &'static [u64] {
        self.params().oid
    }
}

// --- internal helpers operating on raw seeds (all slices are n-byte views) ---

/// Big-endian bytes → integer.
fn to_int(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |acc, &v| (acc << 8) | v as u64)
}

/// FIPS 205 Algorithm 4: base-2^b decomposition.
fn base_2b(input: &[u8], b: u32, out: &mut [u32]) {
    let mask = (1u32 << b) - 1;
    let mut bits = 0u32;
    let mut total = 0u32;
    let mut idx = 0;
    for o in out.iter_mut() {
        while bits < b {
            total = (total << 8) | input[idx] as u32;
            idx += 1;
            bits += 8;
        }
        bits -= b;
        *o = (total >> bits) & mask;
    }
}

/// Bytes → base-16 nibbles.
fn bytes_to_nibbles(input: &[u8], out: &mut [u8]) {
    for (i, &x) in input.iter().enumerate() {
        out[2 * i] = x >> 4;
        out[2 * i + 1] = x & 0x0f;
    }
}

/// WOTS+ chaining (Algorithm 5): apply `F` `steps` times from `start`.
fn wots_chain(p: &Params, pk_seed: &Seed, inout: &mut [u8], start: u8, steps: u8, addr: &mut Adrs) {
    let n = p.n as usize;
    for i in start..start + steps {
        addr.set_hash(i as u32);
        let mut tmp = [0u8; MAX_N];
        hash::f(p, pk_seed, addr.bytes(), &inout[..n], &mut tmp);
        inout[..n].copy_from_slice(&tmp[..n]);
    }
}

/// Multi-buffer hashing for the WOTS+ chains and FORS subtrees: `L`
/// independent single-block hashes evaluated per kernel call.
///
/// On x86_64 with AVX2 / AVX-512 the kernels are the SIMD multi-buffer
/// SHA-256 / SHA-512 / Keccak implementations in `crate::hash`. Everywhere
/// else (aarch64 in particular) a kernel issues [`LOCKSTEP`](mb::LOCKSTEP)
/// single-stream compressions back-to-back: the compressions are mutually
/// independent, so the out-of-order core overlaps the hardware SHA
/// instruction chains (measured on Apple M-series: SHA-256 51.6 → 22.9 ns per
/// compression, SHA-512 83 → 61 ns). Keccak gains nothing from the overlap
/// (the scalar permutation is throughput-bound), but the lane loop is still a
/// single-permutation path without the sponge bookkeeping.
///
/// Every batcher is byte-identical to the scalar loop it replaces (pinned by
/// differential tests) and keeps the scalar path as its reference.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod mb {
    /// Lanes of the lockstep (non-SIMD) kernels. Two lanes already reach the
    /// SHA-256 throughput plateau; four leave headroom for the SHA-512 unit's
    /// longer latency at a stack cost of a few hundred bytes.
    pub(super) const LOCKSTEP: usize = 4;

    /// An `L`-lane SHA-256 kernel: compresses `blocks[l]` into `states[l]` for
    /// every `l < lanes`. The SIMD kernels process all `L` lanes regardless
    /// (the idle lanes' results are simply never read).
    pub(super) type Sha256Kernel<const L: usize> = fn(&mut [[u32; 8]; L], &[[u8; 64]; L], usize);
    /// The SHA-512 counterpart of [`Sha256Kernel`].
    pub(super) type Sha512Kernel<const L: usize> = fn(&mut [[u64; 8]; L], &[[u8; 128]; L], usize);

    pub(super) fn lockstep256<const L: usize>(
        states: &mut [[u32; 8]; L],
        blocks: &[[u8; 64]; L],
        lanes: usize,
    ) {
        for (s, b) in states.iter_mut().zip(blocks).take(lanes) {
            crate::hash::sha256::compress256(s, b);
        }
    }

    pub(super) fn lockstep512<const L: usize>(
        states: &mut [[u64; 8]; L],
        blocks: &[[u8; 128]; L],
        lanes: usize,
    ) {
        for (s, b) in states.iter_mut().zip(blocks).take(lanes) {
            crate::hash::sha512::compress512(s, b);
        }
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    pub(super) fn sha256_x8(
        states: &mut [[u32; 8]; crate::hash::sha256_mb::LANES],
        blocks: &[[u8; 64]; crate::hash::sha256_mb::LANES],
        _lanes: usize,
    ) {
        crate::hash::sha256_mb::compress8(states, blocks);
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    pub(super) fn sha256_x16(
        states: &mut [[u32; 8]; crate::hash::sha256_mb::LANES16],
        blocks: &[[u8; 64]; crate::hash::sha256_mb::LANES16],
        _lanes: usize,
    ) {
        crate::hash::sha256_mb::compress16(states, blocks);
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    pub(super) fn sha512_x4(
        states: &mut [[u64; 8]; crate::hash::sha512_mb::LANES],
        blocks: &[[u8; 128]; crate::hash::sha512_mb::LANES],
        _lanes: usize,
    ) {
        crate::hash::sha512_mb::compress4(states, blocks);
    }

    /// Lane scheduler for WOTS+ chains of unequal length. Chain `c` (the
    /// `N`-byte value at `tmp[c·N..]`, `c < len`) is advanced from position
    /// `pos[c]` to `end[c]` through `step`, which applies one `F` to every
    /// active lane: `step(inout, chain, at, lanes)` must replace `inout[l]`
    /// by `F(…, chain[l], at[l], inout[l])` for every `l < lanes`.
    ///
    /// Lanes are refilled as chains finish, so the kernel runs with every
    /// lane active until the last `L − 1` chains drain — the total work is
    /// `⌈Σ steps / L⌉` kernel calls rather than `Σ max-of-group`. Chain
    /// positions are public (they are the signature's WOTS+ digits), so the
    /// scheduling may depend on them.
    pub(super) fn run_chains<const N: usize, const L: usize>(
        tmp: &mut [u8],
        pos: &[u8],
        end: &[u8],
        len: usize,
        mut step: impl FnMut(&mut [[u8; N]; L], &[u32; L], &[u8; L], usize),
    ) {
        let mut chain = [0u32; L];
        let mut at = [0u8; L];
        let mut stop = [0u8; L];
        let mut inout = [[0u8; N]; L];
        let mut active = 0usize;
        let mut next = 0usize;
        loop {
            // Fill idle lanes with the next chains that have steps left.
            while active < L && next < len {
                let c = next;
                next += 1;
                if pos[c] >= end[c] {
                    continue;
                }
                chain[active] = c as u32;
                at[active] = pos[c];
                stop[active] = end[c];
                inout[active].copy_from_slice(&tmp[c * N..c * N + N]);
                active += 1;
            }
            if active == 0 {
                break;
            }
            step(&mut inout, &chain, &at, active);
            for a in at.iter_mut().take(active) {
                *a += 1;
            }
            // Retire finished lanes, moving the last active lane into the gap
            // so the active lanes stay a prefix.
            let mut l = 0;
            while l < active {
                if at[l] == stop[l] {
                    let c = chain[l] as usize;
                    tmp[c * N..c * N + N].copy_from_slice(&inout[l]);
                    active -= 1;
                    chain[l] = chain[active];
                    at[l] = at[active];
                    stop[l] = stop[active];
                    inout[l] = inout[active];
                } else {
                    l += 1;
                }
            }
        }
        // The lanes carried secret chain starts and every intermediate value.
        super::wipe(inout.as_flattened_mut());
    }
}

/// Expands to `$f::<$n, L>($args…, kernel)` with the widest available
/// SHA-256 kernel: 16 lanes on AVX-512, 8 on AVX2, else the lockstep kernel.
/// Must be the tail expression of a function returning what `$f` returns.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! sha256_dispatch {
    ($f:ident::<$n:literal>($($a:expr),* $(,)?)) => {{
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        {
            if crate::hash::sha256_mb::supported16() {
                return $f::<$n, { crate::hash::sha256_mb::LANES16 }>($($a,)* super::mb::sha256_x16);
            }
            if crate::hash::sha256_mb::supported() {
                return $f::<$n, { crate::hash::sha256_mb::LANES }>($($a,)* super::mb::sha256_x8);
            }
        }
        $f::<$n, { super::mb::LOCKSTEP }>($($a,)* super::mb::lockstep256::<{ super::mb::LOCKSTEP }>)
    }};
}

/// Expands to `$f::<$n, L256, L512>($args…, k256, k512)` with the AVX2
/// SHA-256 (8-lane) and SHA-512 (4-lane) kernels where available, else the
/// lockstep kernels. Must be the tail expression of a function returning what
/// `$f` returns.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! sha2_pair_dispatch {
    ($f:ident::<$n:literal>($($a:expr),* $(,)?)) => {{
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        {
            if crate::hash::sha256_mb::supported() && crate::hash::sha512_mb::supported() {
                return $f::<
                    $n,
                    { crate::hash::sha256_mb::LANES },
                    { crate::hash::sha512_mb::LANES },
                >($($a,)* super::mb::sha256_x8, super::mb::sha512_x4);
            }
        }
        $f::<$n, { super::mb::LOCKSTEP }, { super::mb::LOCKSTEP }>(
            $($a,)*
            super::mb::lockstep256::<{ super::mb::LOCKSTEP }>,
            super::mb::lockstep512::<{ super::mb::LOCKSTEP }>,
        )
    }};
}

/// Expands to `$f::<$n, L>($args…)` with the Keccak lane count: 8 on AVX-512,
/// else 4 (the AVX2 kernel or the lockstep loop, chosen inside
/// [`wots_shake_mb::shake_n`]). Must be the tail expression of a function
/// returning what `$f` returns.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
macro_rules! shake_dispatch {
    ($f:ident::<$n:literal>($($a:expr),* $(,)?)) => {{
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        {
            if crate::hash::keccak_x4::supported8() {
                return $f::<$n, { crate::hash::keccak_x4::LANES8 }>($($a),*);
            }
        }
        $f::<$n, { super::mb::LOCKSTEP }>($($a),*)
    }};
}

/// Fills `out` with the `len` per-chain secret start values `PRF(pk_seed,
/// sk_seed, sk_addr{chain = i})`. `sk_addr` is WotsPrf-typed with the
/// layer/tree/key-pair fields set; the chain field is set per value.
fn wots_prf_fill(p: &Params, pk_seed: &Seed, sk_seed: &[u8], sk_addr: &mut Adrs, out: &mut [u8]) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        if wots_mb::eligible(p) {
            wots_mb::prf_fill(p, pk_seed, sk_seed, sk_addr, out);
            return;
        }
        if p.is_shake {
            wots_shake_mb::prf_fill(p, pk_seed, sk_seed, sk_addr, out);
            return;
        }
    }
    let n = p.n as usize;
    for i in 0..p.len {
        sk_addr.set_chain(i);
        hash::prf(
            p,
            pk_seed,
            sk_seed,
            sk_addr.bytes(),
            &mut out[i as usize * n..],
        );
    }
}

/// Advances every WOTS+ chain `i` of `tmp` (`len` values of `n` bytes, in
/// place) from position `pos[i]` to `end[i]` (`end[i] <= 15`; chains with
/// `pos >= end` are left untouched). `addr` is WotsHash-typed with the
/// layer/tree/key-pair fields set; chain and hash are set per step. Chain
/// positions are public (the WOTS+ digits of the published signature).
///
/// The chains are mutually independent, so where a multi-buffer kernel exists
/// they run in lockstep through it — this dominates WOTS+ keygen, signing,
/// verification and hypertree building. Byte-identical to the scalar
/// [`wots_chain`] loop (pinned by differential tests).
fn wots_chains(
    p: &Params,
    pk_seed: &Seed,
    addr: &mut Adrs,
    tmp: &mut [u8],
    pos: &[u8],
    end: &[u8],
) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        if wots_mb::eligible(p) {
            wots_mb::chains(p, pk_seed, addr, tmp, pos, end);
            return;
        }
        if p.is_shake {
            wots_shake_mb::chains(p, pk_seed, addr, tmp, pos, end);
            return;
        }
    }
    let n = p.n as usize;
    for i in 0..p.len as usize {
        addr.set_chain(i as u32);
        wots_chain(
            p,
            pk_seed,
            &mut tmp[i * n..i * n + n],
            pos[i],
            end[i].saturating_sub(pos[i]),
            addr,
        );
    }
}

/// Chain positions `0` for every chain (full-chain start).
const CHAIN_START: [u8; MAX_WOTS_LEN] = [0; MAX_WOTS_LEN];
/// Chain position `15` (`w − 1`) for every chain (full-chain end).
const CHAIN_END: [u8; MAX_WOTS_LEN] = [15; MAX_WOTS_LEN];

/// WOTS+ public-key generation (Algorithm 6).
fn wots_pk_gen(
    p: &Params,
    pk_seed: &Seed,
    sk_seed: &[u8],
    out: &mut [u8],
    tmp: &mut [u8],
    addr: &mut Adrs,
) {
    let n = p.n as usize;
    let len = p.len as usize;
    let mut sk_addr = *addr;
    sk_addr.set_type_and_clear(AdrsType::WotsPrf);
    sk_addr.copy_key_pair(addr);
    wots_prf_fill(p, pk_seed, sk_seed, &mut sk_addr, tmp);
    wots_chains(
        p,
        pk_seed,
        addr,
        tmp,
        &CHAIN_START[..len],
        &CHAIN_END[..len],
    );
    let mut pk_addr = *addr;
    pk_addr.set_type_and_clear(AdrsType::WotsPk);
    pk_addr.copy_key_pair(addr);
    hash::t(p, pk_seed, pk_addr.bytes(), &tmp[..len * n], out);
}

/// Multi-buffer WOTS+ evaluation for SLH-DSA's SHA-2 sets: independent `F`
/// / `PRF` calls hashed in lockstep through a SHA-256 kernel. In the SHA-2
/// instantiation `F(pk_seed, addr, m1)` is `SHA256(pk_seed[..n] ‖ 0^(64−n) ‖
/// addr(22) ‖ m1[..n])` for **every** n (16/24/32 — FIPS 205 §11.2; only
/// `H`/`T` switch to SHA-512 at n ≥ 24) — a two-block message whose first
/// block (`pk_seed ‖ 0^(64−n)`) is constant, so its midstate is precomputed
/// once and reused for every lane and step. `PRF(pk_seed, sk_seed, addr)` has
/// the same shape with `sk_seed` in place of `m1`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod wots_mb {
    use super::adrs::Adrs;
    use super::mb::{self, Sha256Kernel};
    use super::params::{MAX_N, Params};
    use crate::hash::sha256::{H256, compress256_soft};

    /// The batcher handles every SHA-2 (`!is_shake`) set: `F` is SHA-256 for
    /// all of them, and for n ≤ 32 the variable tail (`addr(22) ‖ m1(n) ‖
    /// 0x80-padding ‖ 8-byte length`) fits a single second block.
    pub(super) fn eligible(p: &Params) -> bool {
        !p.is_shake && matches!(p.n, 16 | 24 | 32)
    }

    /// Second block of the `(86 + N)`-byte `F` message: `addr(22) ‖ m1(N) ‖
    /// 0x80 ‖ 0…0 ‖ len`, with `len = (64 + 22 + N) · 8` bits. `addr` is the
    /// 22-byte compressed ADRS; `m1` is the N-byte chain value. Const-generic
    /// over N so the copies compile to fixed-size moves in the hot loop.
    #[inline]
    pub(super) fn block1_f<const N: usize>(addr: &[u8], m1: &[u8; N]) -> [u8; 64] {
        const { assert!(N <= MAX_N) };
        debug_assert_eq!(addr.len(), 22);
        let mut b = [0u8; 64];
        b[..22].copy_from_slice(addr);
        b[22..22 + N].copy_from_slice(m1);
        b[22 + N] = 0x80;
        let bits = ((64 + 22 + N) * 8) as u64;
        b[56..64].copy_from_slice(&bits.to_be_bytes());
        b
    }

    /// Big-endian serialization of a SHA-256 state, truncated to N bytes
    /// (always a multiple of 4 for the standardized sets).
    #[inline]
    pub(super) fn state_be<const N: usize>(s: &[u32; 8], out: &mut [u8; N]) {
        const { assert!(N.is_multiple_of(4) && N <= 32) };
        for i in 0..N / 4 {
            out[i * 4..i * 4 + 4].copy_from_slice(&s[i].to_be_bytes());
        }
    }

    /// SHA-256 midstate after the constant first block `pk_seed[..n] ‖
    /// 0^(64−n)` — shared by every `F`/`PRF` evaluation of the key.
    #[inline]
    pub(super) fn midstate256(pk_seed: &[u8], n: usize) -> [u32; 8] {
        let mut b0 = [0u8; 64];
        b0[..n].copy_from_slice(&pk_seed[..n]);
        let mut mid = H256;
        compress256_soft(&mut mid, &b0);
        mid
    }

    /// [`super::wots_prf_fill`] through the SHA-256 kernel.
    pub(super) fn prf_fill(
        p: &Params,
        pk_seed: &[u8],
        sk_seed: &[u8],
        base: &Adrs,
        out: &mut [u8],
    ) {
        match p.n {
            16 => sha256_dispatch!(prf_fill_n::<16>(p, pk_seed, sk_seed, base, out)),
            24 => sha256_dispatch!(prf_fill_n::<24>(p, pk_seed, sk_seed, base, out)),
            _ => sha256_dispatch!(prf_fill_n::<32>(p, pk_seed, sk_seed, base, out)),
        }
    }

    fn prf_fill_n<const N: usize, const L: usize>(
        p: &Params,
        pk_seed: &[u8],
        sk_seed: &[u8],
        base: &Adrs,
        out: &mut [u8],
        kernel: Sha256Kernel<L>,
    ) {
        let mid = midstate256(pk_seed, N);
        let sk: &[u8; N] = (&sk_seed[..N]).try_into().unwrap();
        let len = p.len as usize;
        let mut blocks = [[0u8; 64]; L];
        let mut st = [mid; L];
        let mut c0 = 0usize;
        while c0 < len {
            let lanes = (len - c0).min(L);
            for (l, b) in blocks.iter_mut().enumerate().take(lanes) {
                let mut a = *base;
                a.set_chain((c0 + l) as u32);
                *b = block1_f(a.bytes(), sk);
            }
            st = [mid; L];
            kernel(&mut st, &blocks, lanes);
            for (l, s) in st.iter().enumerate().take(lanes) {
                let o: &mut [u8; N] = (&mut out[(c0 + l) * N..(c0 + l) * N + N])
                    .try_into()
                    .unwrap();
                state_be(s, o);
            }
            c0 += lanes;
        }
        // The blocks embed SK.seed and the states are the secret chain starts
        // (the caller owns the copies in `out`).
        super::wipe(blocks.as_flattened_mut());
        crate::zeroize::Zeroize::zeroize(st.as_flattened_mut());
    }

    /// [`super::wots_chains`] through the SHA-256 kernel.
    pub(super) fn chains(
        p: &Params,
        pk_seed: &[u8],
        base: &Adrs,
        tmp: &mut [u8],
        pos: &[u8],
        end: &[u8],
    ) {
        match p.n {
            16 => sha256_dispatch!(chains_n::<16>(p, pk_seed, base, tmp, pos, end)),
            24 => sha256_dispatch!(chains_n::<24>(p, pk_seed, base, tmp, pos, end)),
            _ => sha256_dispatch!(chains_n::<32>(p, pk_seed, base, tmp, pos, end)),
        }
    }

    pub(super) fn chains_n<const N: usize, const L: usize>(
        p: &Params,
        pk_seed: &[u8],
        base: &Adrs,
        tmp: &mut [u8],
        pos: &[u8],
        end: &[u8],
        kernel: Sha256Kernel<L>,
    ) {
        let mid = midstate256(pk_seed, N);
        let mut blocks = [[0u8; 64]; L];
        let mut st = [mid; L];
        mb::run_chains::<N, L>(tmp, pos, end, p.len as usize, |inout, chain, at, lanes| {
            for l in 0..lanes {
                let mut a = *base;
                a.set_chain(chain[l]);
                a.set_hash(at[l] as u32);
                blocks[l] = block1_f(a.bytes(), &inout[l]);
            }
            st = [mid; L];
            kernel(&mut st, &blocks, lanes);
            for (l, s) in st.iter().enumerate().take(lanes) {
                state_be(s, &mut inout[l]);
            }
        });
        // The blocks carried every intermediate chain value.
        super::wipe(blocks.as_flattened_mut());
        crate::zeroize::Zeroize::zeroize(st.as_flattened_mut());
    }
}

/// Multi-buffer WOTS+ evaluation for SLH-DSA's SHAKE sets. In the SHAKE
/// instantiation `F(pk_seed, addr, m1)` is `SHAKE256(pk_seed[..n] ‖ ADRS(32)
/// ‖ m1[..n], 8n)` (FIPS 205 §11.1) — a `2n + 32 ≤ 96`-byte message, so every
/// evaluation is a single 136-byte rate block absorbed and a single block
/// squeezed: one permutation per call, through the AVX2 / AVX-512 Keccak
/// kernel where present (one `L`-way permutation per `L` calls), else a
/// scalar permutation per lane with no sponge bookkeeping.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod wots_shake_mb {
    use super::adrs::Adrs;
    use super::mb;
    use super::params::{MAX_N, Params};

    /// SHAKE256's rate in bytes. Every tweakable-hash preimage of the
    /// standardized SHAKE sets fits one block (`F`/`PRF`: 2n + 32 ≤ 96 bytes;
    /// `H`: 3n + 32 ≤ 128), as does the n-byte output.
    pub(super) const RATE: usize = 136;

    /// Fills the single-block preimage `pk_seed[..N] ‖ ADRS(32) ‖ tail…` into
    /// `m`, returning the message length.
    #[inline]
    pub(super) fn fill_msg<const N: usize>(
        m: &mut [u8; RATE],
        pk_seed: &[u8],
        adrs: &[u8],
        tails: &[&[u8]],
    ) -> usize {
        const { assert!(N <= MAX_N) };
        debug_assert_eq!(adrs.len(), 32);
        m[..N].copy_from_slice(&pk_seed[..N]);
        m[N..N + 32].copy_from_slice(adrs);
        let mut off = N + 32;
        for t in tails {
            m[off..off + t.len()].copy_from_slice(t);
            off += t.len();
        }
        off
    }

    /// `lanes` one-shot SHAKE256 streams over `msgs[l][..msg_len]`, N output
    /// bytes each. Lanes `>= lanes` are left zero.
    pub(super) fn shake_n<const N: usize, const L: usize>(
        msgs: &[[u8; RATE]; L],
        msg_len: usize,
        lanes: usize,
    ) -> [[u8; N]; L] {
        const { assert!(N.is_multiple_of(8) && N <= MAX_N) };
        debug_assert!(msg_len < RATE);
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        {
            use crate::hash::keccak_x4::{
                KeccakXn, LANES, LANES8, MAX_RATE, supported, supported8,
            };
            if (L == LANES && supported()) || (L == LANES8 && supported8()) {
                let refs: [&[u8]; L] = core::array::from_fn(|l| &msgs[l][..msg_len]);
                let mut x = KeccakXn::<L>::new(RATE, refs, 0x1F);
                let mut blocks = [[0u8; MAX_RATE]; L];
                x.squeeze_blocks(&mut blocks);
                let out: [[u8; N]; L] =
                    core::array::from_fn(|l| blocks[l][..N].try_into().unwrap());
                // The absorbed messages carry SK.seed (PRF) or a secret chain
                // value (F), so the sponge state and the squeezed rate blocks
                // are secret too — the caller only ever keeps the first N
                // bytes. `KeccakXn` wipes its own state in `Drop`; the
                // squeezed blocks are wiped here.
                super::wipe(blocks.as_flattened_mut());
                return out;
            }
        }
        // One permutation per lane: pad the block, load it as the fresh
        // state, permute, read N bytes.
        let mut out = [[0u8; N]; L];
        let mut block = [0u8; RATE];
        let mut st = [0u64; 25];
        for (m, o) in msgs.iter().zip(out.iter_mut()).take(lanes) {
            block.fill(0);
            block[..msg_len].copy_from_slice(&m[..msg_len]);
            block[msg_len] = 0x1F;
            block[RATE - 1] |= 0x80;
            st.fill(0);
            for (lane, chunk) in st.iter_mut().zip(block.chunks_exact(8)) {
                *lane = u64::from_le_bytes(chunk.try_into().unwrap());
            }
            crate::hash::keccak::keccak_p(&mut st, 24);
            for (chunk, lane) in o.chunks_exact_mut(8).zip(st.iter()) {
                chunk.copy_from_slice(&lane.to_le_bytes());
            }
        }
        super::wipe(&mut block);
        crate::zeroize::Zeroize::zeroize(&mut st);
        out
    }

    /// [`super::wots_prf_fill`] through the Keccak kernel.
    pub(super) fn prf_fill(
        p: &Params,
        pk_seed: &[u8],
        sk_seed: &[u8],
        base: &Adrs,
        out: &mut [u8],
    ) {
        match p.n {
            16 => shake_dispatch!(prf_fill_n::<16>(p, pk_seed, sk_seed, base, out)),
            24 => shake_dispatch!(prf_fill_n::<24>(p, pk_seed, sk_seed, base, out)),
            _ => shake_dispatch!(prf_fill_n::<32>(p, pk_seed, sk_seed, base, out)),
        }
    }

    fn prf_fill_n<const N: usize, const L: usize>(
        p: &Params,
        pk_seed: &[u8],
        sk_seed: &[u8],
        base: &Adrs,
        out: &mut [u8],
    ) {
        let len = p.len as usize;
        let mut msgs = [[0u8; RATE]; L];
        let mut c0 = 0usize;
        while c0 < len {
            let lanes = (len - c0).min(L);
            let mut msg_len = 0;
            for (l, m) in msgs.iter_mut().enumerate().take(lanes) {
                let mut a = *base;
                a.set_chain((c0 + l) as u32);
                msg_len = fill_msg::<N>(m, pk_seed, a.bytes(), &[&sk_seed[..N]]);
            }
            let mut outs = shake_n::<N, L>(&msgs, msg_len, lanes);
            for (l, o) in outs.iter().enumerate().take(lanes) {
                out[(c0 + l) * N..(c0 + l) * N + N].copy_from_slice(o);
            }
            // The outputs are the secret chain starts (the caller owns the
            // copies in `out`).
            super::wipe(outs.as_flattened_mut());
            c0 += lanes;
        }
        // The lane messages embed SK.seed.
        super::wipe(msgs.as_flattened_mut());
    }

    /// [`super::wots_chains`] through the Keccak kernel.
    pub(super) fn chains(
        p: &Params,
        pk_seed: &[u8],
        base: &Adrs,
        tmp: &mut [u8],
        pos: &[u8],
        end: &[u8],
    ) {
        match p.n {
            16 => shake_dispatch!(chains_n::<16>(p, pk_seed, base, tmp, pos, end)),
            24 => shake_dispatch!(chains_n::<24>(p, pk_seed, base, tmp, pos, end)),
            _ => shake_dispatch!(chains_n::<32>(p, pk_seed, base, tmp, pos, end)),
        }
    }

    fn chains_n<const N: usize, const L: usize>(
        p: &Params,
        pk_seed: &[u8],
        base: &Adrs,
        tmp: &mut [u8],
        pos: &[u8],
        end: &[u8],
    ) {
        let mut msgs = [[0u8; RATE]; L];
        mb::run_chains::<N, L>(tmp, pos, end, p.len as usize, |inout, chain, at, lanes| {
            let mut msg_len = 0;
            for l in 0..lanes {
                let mut a = *base;
                a.set_chain(chain[l]);
                a.set_hash(at[l] as u32);
                msg_len = fill_msg::<N>(&mut msgs[l], pk_seed, a.bytes(), &[&inout[l]]);
            }
            let outs = shake_n::<N, L>(&msgs, msg_len, lanes);
            inout[..lanes].copy_from_slice(&outs[..lanes]);
        });
        // The lane messages carried every intermediate chain value.
        super::wipe(msgs.as_flattened_mut());
    }
}

/// Differential tests: every batched WOTS+ path must equal the scalar loops
/// over the same inputs, for every set width (n = 16/24/32) of both hash
/// families, for full chains and for random partial chains. On x86_64 the
/// dispatcher picks the SIMD kernel when the CPU has it; the lockstep kernels
/// are exercised explicitly as well so both are pinned everywhere.
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod wots_mb_tests {
    use super::*;

    /// Deterministic chain positions: `(pos, end)` per chain, with a mix of
    /// empty, partial and full chains.
    fn positions(len: usize, salt: usize) -> ([u8; MAX_WOTS_LEN], [u8; MAX_WOTS_LEN]) {
        let mut pos = [0u8; MAX_WOTS_LEN];
        let mut end = [0u8; MAX_WOTS_LEN];
        for i in 0..len {
            let a = ((i * 7 + salt * 3) % 16) as u8;
            let b = ((i * 11 + salt * 5 + 1) % 16) as u8;
            pos[i] = a.min(b);
            end[i] = a.max(b);
        }
        (pos, end)
    }

    fn check_set(set: ParamSet) {
        let p = set.params();
        let n = p.n as usize;
        let len = p.len as usize;
        let total = len * n;
        let mut starts = alloc::vec![0u8; total];
        for (i, b) in starts.iter_mut().enumerate() {
            *b = (i.wrapping_mul(13).wrapping_add(3)) as u8;
        }
        let pk_seed_bytes: Vec<u8> = (0..n).map(|i| (i * 5 + 7) as u8).collect();
        let pk_seed = Seed::new(p, &pk_seed_bytes);
        let sk_seed: Vec<u8> = (0..n).map(|i| (i * 9 + 4) as u8).collect();

        let mut base = Adrs::new(p.is_shake);
        base.set_type_and_clear(AdrsType::WotsHash);
        base.set_layer(1);
        base.set_tree(0x0807_0605_0403_0201);
        base.set_key_pair(17);

        for salt in 0..3 {
            let (pos, end) = if salt == 0 {
                (CHAIN_START, CHAIN_END)
            } else {
                positions(len, salt)
            };
            // Scalar reference.
            let mut want = starts.clone();
            for i in 0..len {
                let mut a = base;
                a.set_chain(i as u32);
                wots_chain(
                    p,
                    &pk_seed,
                    &mut want[i * n..i * n + n],
                    pos[i],
                    end[i] - pos[i],
                    &mut a,
                );
            }
            // Dispatched (SIMD where the CPU has it).
            let mut got = starts.clone();
            let mut a = base;
            wots_chains(p, &pk_seed, &mut a, &mut got, &pos[..len], &end[..len]);
            assert_eq!(want, got, "set {set:?} salt {salt} (dispatch)");
            // The SHA-256 lockstep kernel explicitly (the Keccak lockstep
            // path is selected inside `shake_n` wherever the SIMD kernel is
            // absent, so the dispatch above already covers it there).
            if !p.is_shake {
                let mut got = starts.clone();
                match n {
                    16 => wots_mb::chains_n::<16, 4>(
                        p,
                        &pk_seed,
                        &base,
                        &mut got,
                        &pos[..len],
                        &end[..len],
                        mb::lockstep256::<4>,
                    ),
                    24 => wots_mb::chains_n::<24, 4>(
                        p,
                        &pk_seed,
                        &base,
                        &mut got,
                        &pos[..len],
                        &end[..len],
                        mb::lockstep256::<4>,
                    ),
                    _ => wots_mb::chains_n::<32, 4>(
                        p,
                        &pk_seed,
                        &base,
                        &mut got,
                        &pos[..len],
                        &end[..len],
                        mb::lockstep256::<4>,
                    ),
                }
                assert_eq!(want, got, "set {set:?} salt {salt} (lockstep)");
            }
        }

        // PRF fill.
        let mut sk_addr = base;
        sk_addr.set_type_and_clear(AdrsType::WotsPrf);
        sk_addr.copy_key_pair(&base);
        let mut want = alloc::vec![0u8; total];
        for i in 0..len {
            let mut a = sk_addr;
            a.set_chain(i as u32);
            hash::prf(p, &pk_seed, &sk_seed, a.bytes(), &mut want[i * n..]);
        }
        let mut got = alloc::vec![0u8; total];
        let mut a = sk_addr;
        wots_prf_fill(p, &pk_seed, &sk_seed, &mut a, &mut got);
        assert_eq!(want, got, "set {set:?} prf");
    }

    #[test]
    fn sha2_batched_matches_scalar() {
        for set in [
            ParamSet::Sha2_128s,
            ParamSet::Sha2_192s,
            ParamSet::Sha2_256s,
        ] {
            check_set(set);
        }
    }

    #[test]
    fn shake_batched_matches_scalar() {
        for set in [
            ParamSet::Shake_128s,
            ParamSet::Shake_192s,
            ParamSet::Shake_256s,
        ] {
            check_set(set);
        }
    }
}

/// Computes the WOTS+ message-and-checksum nibbles for an n-byte message.
fn wots_msg_csum(p: &Params, msg: &[u8]) -> [u8; MAX_WOTS_LEN] {
    let mut mc = [0u8; MAX_WOTS_LEN];
    bytes_to_nibbles(&msg[..p.n as usize], &mut mc);
    let len1 = (p.n * 2) as usize;
    // The checksum `15 * len1 - sum(nibbles)` accumulates into a u16; its
    // maximum value is `15 * len1` (when every nibble is zero). For all 12
    // standardized SLH-DSA parameter sets `len1 <= 64` (n <= 32), so this is at
    // most 960 and cannot overflow. Assert the invariant so a future,
    // non-standard parameter set cannot silently wrap.
    debug_assert!(15 * len1 as u32 <= u16::MAX as u32);
    let mut csum: u16 = 0;
    for &x in &mc[..len1] {
        csum += x as u16;
    }
    csum = 15 * len1 as u16 - csum;
    mc[len1] = (csum >> 8) as u8 & 0x0f;
    mc[len1 + 1] = (csum >> 4) as u8 & 0x0f;
    mc[len1 + 2] = csum as u8 & 0x0f;
    mc
}

/// WOTS+ sign (Algorithm 7): writes `len·n` bytes into `sig`.
fn wots_sign(
    p: &Params,
    pk_seed: &Seed,
    sk_seed: &[u8],
    msg: &[u8],
    addr: &mut Adrs,
    sig: &mut [u8],
) {
    let len = p.len as usize;
    let mc = wots_msg_csum(p, msg);
    let mut sk_addr = *addr;
    sk_addr.set_type_and_clear(AdrsType::WotsPrf);
    sk_addr.copy_key_pair(addr);
    wots_prf_fill(p, pk_seed, sk_seed, &mut sk_addr, sig);
    wots_chains(p, pk_seed, addr, sig, &CHAIN_START[..len], &mc[..len]);
}

/// WOTS+ public key from a signature (Algorithm 8).
fn wots_pk_from_sig(
    p: &Params,
    pk_seed: &Seed,
    sig: &[u8],
    msg: &[u8],
    tmp: &mut [u8],
    addr: &mut Adrs,
    out: &mut [u8],
) {
    let n = p.n as usize;
    let len = p.len as usize;
    let mc = wots_msg_csum(p, msg);
    let total = len * n;
    tmp[..total].copy_from_slice(&sig[..total]);
    wots_chains(p, pk_seed, addr, tmp, &mc[..len], &CHAIN_END[..len]);
    let mut pk_addr = *addr;
    pk_addr.set_type_and_clear(AdrsType::WotsPk);
    pk_addr.copy_key_pair(addr);
    hash::t(p, pk_seed, pk_addr.bytes(), &tmp[..total], out);
}

/// XMSS node computation (Algorithm 9).
fn xmss_node(
    p: &Params,
    pk_seed: &Seed,
    sk_seed: &[u8],
    out: &mut [u8],
    tmp: &mut [u8],
    i: u32,
    z: u32,
    addr: &mut Adrs,
) {
    let n = p.n as usize;
    if z == 0 {
        addr.set_type_and_clear(AdrsType::WotsHash);
        addr.set_key_pair(i);
        wots_pk_gen(p, pk_seed, sk_seed, out, tmp, addr);
    } else {
        let mut lnode = [0u8; MAX_N];
        let mut rnode = [0u8; MAX_N];
        xmss_node(p, pk_seed, sk_seed, &mut lnode, tmp, 2 * i, z - 1, addr);
        xmss_node(p, pk_seed, sk_seed, &mut rnode, tmp, 2 * i + 1, z - 1, addr);
        addr.set_type_and_clear(AdrsType::Tree);
        addr.set_tree_height(z);
        addr.set_tree_index(i);
        hash::h(p, pk_seed, addr.bytes(), &lnode[..n], &rnode[..n], out);
    }
}

/// XMSS sign (Algorithm 10): WOTS+ signature followed by the authentication path.
fn xmss_sign(
    p: &Params,
    pk_seed: &Seed,
    sk_seed: &[u8],
    msg: &[u8],
    tmp: &mut [u8],
    leaf_idx: u32,
    addr: &mut Adrs,
    sig: &mut [u8],
) {
    let n = p.n as usize;
    let auth_start = n * p.len as usize;
    let mut idx = leaf_idx;
    for j in 0..p.h_prime {
        let off = auth_start + j as usize * n;
        xmss_node(
            p,
            pk_seed,
            sk_seed,
            &mut sig[off..off + n],
            tmp,
            idx ^ 1,
            j,
            addr,
        );
        idx >>= 1;
    }
    addr.set_type_and_clear(AdrsType::WotsHash);
    addr.set_key_pair(leaf_idx);
    wots_sign(p, pk_seed, sk_seed, msg, addr, sig);
}

/// XMSS public key from a signature (Algorithm 11).
fn xmss_pk_from_sig(
    p: &Params,
    pk_seed: &Seed,
    mut leaf_idx: u32,
    sig: &[u8],
    msg: &[u8],
    tmp: &mut [u8],
    addr: &mut Adrs,
    out: &mut [u8],
) {
    let n = p.n as usize;
    addr.set_type_and_clear(AdrsType::WotsHash);
    addr.set_key_pair(leaf_idx);
    wots_pk_from_sig(p, pk_seed, sig, msg, tmp, addr, out);

    addr.set_type_and_clear(AdrsType::Tree);
    let mut ap = &sig[p.len as usize * n..]; // authentication path
    for k in 0..p.h_prime {
        addr.set_tree_height(k + 1);
        let node = &ap[..n];
        if leaf_idx & 1 == 0 {
            leaf_idx >>= 1;
            addr.set_tree_index(leaf_idx);
            let mut tmp_out = [0u8; MAX_N];
            hash::h(p, pk_seed, addr.bytes(), &out[..n], node, &mut tmp_out);
            out[..n].copy_from_slice(&tmp_out[..n]);
        } else {
            leaf_idx = (leaf_idx - 1) >> 1;
            addr.set_tree_index(leaf_idx);
            let mut tmp_out = [0u8; MAX_N];
            hash::h(p, pk_seed, addr.bytes(), node, &out[..n], &mut tmp_out);
            out[..n].copy_from_slice(&tmp_out[..n]);
        }
        ap = &ap[n..];
    }
}

/// Hypertree sign (Algorithm 12).
fn ht_sign(
    p: &Params,
    pk_seed: &Seed,
    sk_seed: &[u8],
    pk_fors: &[u8],
    mut tree_idx: u64,
    mut leaf_idx: u32,
    sig: &mut [u8],
) {
    let n = p.n as usize;
    let per_layer = (p.h_prime + p.len) as usize * n;
    let mask = p.leaf_idx_mask();
    let mut root = [0u8; MAX_N];
    root[..n].copy_from_slice(&pk_fors[..n]);
    // `p.len <= MAX_WOTS_LEN` and `n <= MAX_N`, so this WOTS scratch is bounded
    // and lives on the stack.
    let mut tmp = [0u8; MAX_WOTS_LEN * MAX_N];
    let tmp = &mut tmp[..n * p.len as usize];
    let mut off = 0;

    let mut addr = Adrs::new(p.is_shake);
    for j in 0..p.d {
        addr.set_layer(j);
        addr.set_tree(tree_idx);
        xmss_sign(
            p,
            pk_seed,
            sk_seed,
            &root[..n],
            tmp,
            leaf_idx,
            &mut addr,
            &mut sig[off..],
        );
        // This layer's XMSS signature is published; the root recomputed from
        // it (the next layer's WOTS+ message) is public.
        crate::ct::declassify(&sig[off..off + per_layer]);
        if j < p.d - 1 {
            let mut new_root = [0u8; MAX_N];
            xmss_pk_from_sig(
                p,
                pk_seed,
                leaf_idx,
                &sig[off..],
                &root[..n],
                tmp,
                &mut addr,
                &mut new_root,
            );
            root[..n].copy_from_slice(&new_root[..n]);
            leaf_idx = (tree_idx & mask) as u32;
            tree_idx >>= p.h_prime;
            off += per_layer;
        }
    }
}

/// Hypertree verify (Algorithm 13).
fn ht_verify(
    p: &Params,
    pk_seed: &Seed,
    pk_root: &[u8],
    pk_fors: &[u8],
    sig: &[u8],
    mut tree_idx: u64,
    mut leaf_idx: u32,
) -> bool {
    let n = p.n as usize;
    let per_layer = (p.h_prime + p.len) as usize * n;
    let mask = p.leaf_idx_mask();
    let mut root = [0u8; MAX_N];
    root[..n].copy_from_slice(&pk_fors[..n]);
    // `p.len <= MAX_WOTS_LEN` and `n <= MAX_N`, so this WOTS scratch is bounded
    // and lives on the stack.
    let mut tmp = [0u8; MAX_WOTS_LEN * MAX_N];
    let tmp = &mut tmp[..n * p.len as usize];

    let mut addr = Adrs::new(p.is_shake);
    let mut off = 0;
    for j in 0..p.d {
        addr.set_layer(j);
        addr.set_tree(tree_idx);
        let mut new_root = [0u8; MAX_N];
        xmss_pk_from_sig(
            p,
            pk_seed,
            leaf_idx,
            &sig[off..],
            &root[..n],
            tmp,
            &mut addr,
            &mut new_root,
        );
        root[..n].copy_from_slice(&new_root[..n]);
        leaf_idx = (tree_idx & mask) as u32;
        tree_idx >>= p.h_prime;
        off += per_layer;
    }
    bool::from(root[..n].ct_eq(&pk_root[..n]))
}

/// FORS private value (Algorithm 14).
fn fors_gen_sk(p: &Params, pk_seed: &Seed, sk_seed: &[u8], idx: u32, addr: &Adrs, out: &mut [u8]) {
    let mut sk_addr = *addr;
    sk_addr.set_type_and_clear(AdrsType::ForsPrf);
    sk_addr.copy_key_pair(addr);
    sk_addr.set_tree_index(idx);
    hash::prf(p, pk_seed, sk_seed, sk_addr.bytes(), out);
}

/// FORS node (Algorithm 15).
fn fors_node(
    p: &Params,
    pk_seed: &Seed,
    sk_seed: &[u8],
    node_id: u32,
    layer: u32,
    addr: &mut Adrs,
    out: &mut [u8],
) {
    // Where a multi-buffer kernel exists, height-3 subtrees are computed
    // batched. SHA-2 sets: the eight leaves' PRF+F through the SHA-256 kernel
    // and the sibling `H` merges through the SHA-512 kernel (n ≥ 24) or the
    // SHA-256 kernel (n = 16). SHAKE sets: PRF, F, and `H` all through the
    // Keccak kernel. Deeper recursions land here for each height-3 subtree.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if layer == 3 {
        if fors_mb::eligible(p) {
            fors_mb::subtree8(p, pk_seed, sk_seed, node_id, addr, out);
            return;
        }
        if p.is_shake {
            fors_shake_mb::subtree8(p, pk_seed, sk_seed, node_id, addr, out);
            return;
        }
    }
    fors_node_scalar(p, pk_seed, sk_seed, node_id, layer, addr, out);
}

/// Scalar recursion for [`fors_node`]. Children re-enter `fors_node`, so trees
/// higher than 3 still batch their height-3 subtrees.
fn fors_node_scalar(
    p: &Params,
    pk_seed: &Seed,
    sk_seed: &[u8],
    node_id: u32,
    layer: u32,
    addr: &mut Adrs,
    out: &mut [u8],
) {
    let n = p.n as usize;
    if layer == 0 {
        let mut sk = [0u8; MAX_N];
        fors_gen_sk(p, pk_seed, sk_seed, node_id, addr, &mut sk);
        addr.set_tree_height(0);
        addr.set_tree_index(node_id);
        hash::f(p, pk_seed, addr.bytes(), &sk[..n], out);
        // The FORS secret value is revealed only for the signed leaf; wipe it.
        wipe(&mut sk);
    } else {
        let mut lnode = [0u8; MAX_N];
        let mut rnode = [0u8; MAX_N];
        fors_node(
            p,
            pk_seed,
            sk_seed,
            node_id * 2,
            layer - 1,
            addr,
            &mut lnode,
        );
        fors_node(
            p,
            pk_seed,
            sk_seed,
            node_id * 2 + 1,
            layer - 1,
            addr,
            &mut rnode,
        );
        addr.set_tree_height(layer);
        addr.set_tree_index(node_id);
        hash::h(p, pk_seed, addr.bytes(), &lnode[..n], &rnode[..n], out);
    }
}

/// Multi-buffer FORS subtree evaluation for the SHA-2 sets: a height-3
/// subtree is eight leaves (PRF + F, both SHA-256 for every n — batched
/// through the SHA-256 kernel) merged by seven `H` calls (SHA-512 for n ≥ 24,
/// batched through the SHA-512 kernel; SHA-256 for n = 16). Produces
/// byte-identical output to the scalar [`fors_node_scalar`] recursion (pinned
/// by a differential test). Like `F`, `H`'s first block (`pk_seed ‖
/// 0^(blk−n)`) is constant, so its midstate is computed once per subtree.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod fors_mb {
    use super::Seed;
    use super::adrs::{Adrs, AdrsType};
    use super::mb::{Sha256Kernel, Sha512Kernel};
    use super::params::Params;
    use super::wots_mb::{block1_f, midstate256, state_be};
    use crate::hash::sha512::{H512, compress512_soft};

    /// Same coverage as the WOTS batcher: every SHA-2 (`!is_shake`) set.
    pub(super) fn eligible(p: &Params) -> bool {
        super::wots_mb::eligible(p)
    }

    /// Second block of the SHA-512 `H` message: `addr(22) ‖ l(N) ‖ r(N) ‖ 0x80
    /// ‖ 0…0 ‖ len`, with `len = (128 + 22 + 2N) · 8` bits (the n ≥ 24 sets).
    #[inline]
    fn block1_h512<const N: usize>(addr: &[u8], l: &[u8; N], r: &[u8; N]) -> [u8; 128] {
        debug_assert!(N == 24 || N == 32);
        debug_assert_eq!(addr.len(), 22);
        let mut b = [0u8; 128];
        b[..22].copy_from_slice(addr);
        b[22..22 + N].copy_from_slice(l);
        b[22 + N..22 + 2 * N].copy_from_slice(r);
        b[22 + 2 * N] = 0x80;
        let bits = ((128 + 22 + 2 * N) * 8) as u64;
        b[120..128].copy_from_slice(&bits.to_be_bytes());
        b
    }

    /// Second block of the SHA-256 `H` message (the n = 16 sets): `addr(22) ‖
    /// l(16) ‖ r(16) ‖ 0x80 ‖ 0…0 ‖ len`, with `len = 944` bits (`118 · 8`).
    #[inline]
    fn block1_h256<const N: usize>(addr: &[u8], l: &[u8; N], r: &[u8; N]) -> [u8; 64] {
        debug_assert!(N == 16);
        debug_assert_eq!(addr.len(), 22);
        let mut b = [0u8; 64];
        b[..22].copy_from_slice(addr);
        b[22..22 + N].copy_from_slice(l);
        b[22 + N..22 + 2 * N].copy_from_slice(r);
        b[22 + 2 * N] = 0x80;
        let bits = ((64 + 22 + 2 * N) * 8) as u64;
        b[56..64].copy_from_slice(&bits.to_be_bytes());
        b
    }

    /// Big-endian serialization of a SHA-512 state, truncated to N bytes
    /// (N = 24/32; both multiples of 8).
    #[inline]
    fn state_be64<const N: usize>(s: &[u64; 8], out: &mut [u8; N]) {
        const { assert!(N.is_multiple_of(8) && N <= 64) };
        for i in 0..N / 8 {
            out[i * 8..i * 8 + 8].copy_from_slice(&s[i].to_be_bytes());
        }
    }

    /// Computes the eight leaves of a height-3 subtree — the PRF secret
    /// values, then F over each — through the SHA-256 kernel, `L` leaves per
    /// call.
    fn leaves8<const N: usize, const L: usize>(
        sk_seed: &[u8],
        mid256: &[u32; 8],
        leaf0: u32,
        addr: &mut Adrs,
        kernel: Sha256Kernel<L>,
    ) -> [[u8; N]; 8] {
        let sk: &[u8; N] = (&sk_seed[..N]).try_into().unwrap();
        let mut sk_addr = *addr;
        sk_addr.set_type_and_clear(AdrsType::ForsPrf);
        sk_addr.copy_key_pair(addr);
        let mut blocks = [[0u8; 64]; L];
        let mut st = [*mid256; L];
        let mut nodes = [[0u8; N]; 8];
        for first in (0..8).step_by(L) {
            let lanes = (8 - first).min(L);
            for (l, b) in blocks.iter_mut().enumerate().take(lanes) {
                sk_addr.set_tree_index(leaf0 + (first + l) as u32);
                *b = block1_f(sk_addr.bytes(), sk);
            }
            st = [*mid256; L];
            kernel(&mut st, &blocks, lanes);
            for (l, s) in st.iter().enumerate().take(lanes) {
                state_be(s, &mut nodes[first + l]);
            }
        }

        addr.set_tree_height(0);
        for first in (0..8).step_by(L) {
            let lanes = (8 - first).min(L);
            for (l, b) in blocks.iter_mut().enumerate().take(lanes) {
                addr.set_tree_index(leaf0 + (first + l) as u32);
                *b = block1_f(addr.bytes(), &nodes[first + l]);
            }
            st = [*mid256; L];
            kernel(&mut st, &blocks, lanes);
            for (l, s) in st.iter().enumerate().take(lanes) {
                state_be(s, &mut nodes[first + l]);
            }
        }
        // `blocks` embedded SK.seed (first pass) and the secret FORS values
        // (second pass); `nodes` was overwritten in place with the public
        // leaves. Wipe the blocks and the compression states.
        super::wipe(blocks.as_flattened_mut());
        crate::zeroize::Zeroize::zeroize(st.as_flattened_mut());
        nodes
    }

    /// One merge level for the n = 16 sets (`H` is SHA-256): hashes `pairs`
    /// (≤ 4 ≤ L) sibling pairs `(nodes[2j], nodes[2j+1])` into `nodes[j]`
    /// with tree index `idx0 + j` at `height`.
    fn merge_level256<const N: usize, const L: usize>(
        mid256: &[u32; 8],
        addr: &mut Adrs,
        idx0: u32,
        height: u32,
        nodes: &mut [[u8; N]; 8],
        pairs: usize,
        kernel: Sha256Kernel<L>,
    ) {
        debug_assert!(pairs <= L);
        addr.set_tree_height(height);
        let mut blocks = [[0u8; 64]; L];
        for (j, b) in blocks.iter_mut().enumerate().take(pairs) {
            addr.set_tree_index(idx0 + j as u32);
            *b = block1_h256(addr.bytes(), &nodes[2 * j], &nodes[2 * j + 1]);
        }
        let mut st = [*mid256; L];
        kernel(&mut st, &blocks, pairs);
        for (j, s) in st.iter().enumerate().take(pairs) {
            state_be(s, &mut nodes[j]);
        }
    }

    /// One merge level for the n = 24/32 sets (`H` is SHA-512), through the
    /// SHA-512 kernel. Same contract as [`merge_level256`].
    fn merge_level512<const N: usize, const L: usize>(
        mid512: &[u64; 8],
        addr: &mut Adrs,
        idx0: u32,
        height: u32,
        nodes: &mut [[u8; N]; 8],
        pairs: usize,
        kernel: Sha512Kernel<L>,
    ) {
        debug_assert!(pairs <= L);
        addr.set_tree_height(height);
        let mut blocks = [[0u8; 128]; L];
        for (j, b) in blocks.iter_mut().enumerate().take(pairs) {
            addr.set_tree_index(idx0 + j as u32);
            *b = block1_h512(addr.bytes(), &nodes[2 * j], &nodes[2 * j + 1]);
        }
        let mut st = [*mid512; L];
        kernel(&mut st, &blocks, pairs);
        for (j, s) in st.iter().enumerate().take(pairs) {
            state_be64(s, &mut nodes[j]);
        }
    }

    /// Computes FORS node `node_id` at layer 3 — a height-3 subtree over
    /// leaves `8·node_id .. 8·node_id + 8` — writing the n-byte root to `out`.
    /// Hash-for-hash identical to the scalar recursion (same ADRS values).
    pub(super) fn subtree8(
        p: &Params,
        pk_seed: &Seed,
        sk_seed: &[u8],
        node_id: u32,
        addr: &mut Adrs,
        out: &mut [u8],
    ) {
        // Monomorphize on n (`eligible` admits only the SHA-2 sets).
        match p.n {
            16 => sha2_pair_dispatch!(subtree_n::<16>(p, pk_seed, sk_seed, node_id, addr, out)),
            24 => sha2_pair_dispatch!(subtree_n::<24>(p, pk_seed, sk_seed, node_id, addr, out)),
            _ => sha2_pair_dispatch!(subtree_n::<32>(p, pk_seed, sk_seed, node_id, addr, out)),
        }
    }

    pub(super) fn subtree_n<const N: usize, const L256: usize, const L512: usize>(
        p: &Params,
        pk_seed: &Seed,
        sk_seed: &[u8],
        node_id: u32,
        addr: &mut Adrs,
        out: &mut [u8],
        k256: Sha256Kernel<L256>,
        k512: Sha512Kernel<L512>,
    ) {
        let mid256 = midstate256(pk_seed, N);
        let mut nodes = leaves8::<N, L256>(sk_seed, &mid256, node_id * 8, addr, k256);
        // Merge levels 1 and 2 batched; the top level is a single pair, so it
        // goes through the scalar `H` (which also restores the ADRS state the
        // scalar recursion leaves behind).
        if N == 16 {
            merge_level256::<N, L256>(&mid256, addr, node_id * 4, 1, &mut nodes, 4, k256);
            merge_level256::<N, L256>(&mid256, addr, node_id * 2, 2, &mut nodes, 2, k256);
        } else {
            // SHA-512 midstate over the constant block `pk_seed ‖ 0^(128−N)`.
            let mid512 = {
                let mut b0 = [0u8; 128];
                b0[..N].copy_from_slice(&pk_seed[..N]);
                let mut m = H512;
                compress512_soft(&mut m, &b0);
                m
            };
            merge_level512::<N, L512>(&mid512, addr, node_id * 4, 1, &mut nodes, 4, k512);
            merge_level512::<N, L512>(&mid512, addr, node_id * 2, 2, &mut nodes, 2, k512);
        }
        addr.set_tree_height(3);
        addr.set_tree_index(node_id);
        super::hash::h(p, pk_seed, addr.bytes(), &nodes[0], &nodes[1], out);
    }
}

/// Multi-buffer FORS subtree evaluation for the SHAKE sets: a height-3
/// subtree is eight leaves (PRF + F, each a single-block SHAKE256 call) merged
/// by seven `H` calls (also single-block SHAKE256), all through the Keccak
/// kernel. Produces byte-identical output to the scalar [`fors_node_scalar`]
/// recursion (pinned by a differential test).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod fors_shake_mb {
    use super::Seed;
    use super::adrs::{Adrs, AdrsType};
    use super::params::Params;
    use super::wots_shake_mb::{RATE, fill_msg, shake_n};

    /// Computes the eight leaves of a height-3 subtree — the PRF secret
    /// values, then F over each — through the Keccak kernel, `L` leaves per
    /// call.
    fn leaves8<const N: usize, const L: usize>(
        pk_seed: &Seed,
        sk_seed: &[u8],
        leaf0: u32,
        addr: &mut Adrs,
    ) -> [[u8; N]; 8] {
        let mut sk_addr = *addr;
        sk_addr.set_type_and_clear(AdrsType::ForsPrf);
        sk_addr.copy_key_pair(addr);
        // Every lane message below embeds a secret (SK.seed, then the FORS
        // secret values); the buffer is wiped once the leaves are public.
        let mut msgs = [[0u8; RATE]; L];
        let mut sk_nodes = [[0u8; N]; 8];
        for first in (0..8).step_by(L) {
            let lanes = (8 - first).min(L);
            let mut msg_len = 0;
            for (l, m) in msgs.iter_mut().enumerate().take(lanes) {
                sk_addr.set_tree_index(leaf0 + (first + l) as u32);
                msg_len = fill_msg::<N>(m, pk_seed, sk_addr.bytes(), &[&sk_seed[..N]]);
            }
            let outs = shake_n::<N, L>(&msgs, msg_len, lanes);
            sk_nodes[first..first + lanes].copy_from_slice(&outs[..lanes]);
        }

        addr.set_tree_height(0);
        let mut nodes = [[0u8; N]; 8];
        for first in (0..8).step_by(L) {
            let lanes = (8 - first).min(L);
            let mut msg_len = 0;
            for (l, m) in msgs.iter_mut().enumerate().take(lanes) {
                addr.set_tree_index(leaf0 + (first + l) as u32);
                msg_len = fill_msg::<N>(m, pk_seed, addr.bytes(), &[&sk_nodes[first + l]]);
            }
            let outs = shake_n::<N, L>(&msgs, msg_len, lanes);
            nodes[first..first + lanes].copy_from_slice(&outs[..lanes]);
        }
        super::wipe(msgs.as_flattened_mut());
        super::wipe(sk_nodes.as_flattened_mut());
        nodes
    }

    /// One merge level: hashes `pairs` (≤ 4 ≤ L) sibling pairs `(nodes[2j],
    /// nodes[2j+1])` into `nodes[j]` with tree index `idx0 + j` at `height`.
    fn merge_level<const N: usize, const L: usize>(
        pk_seed: &Seed,
        addr: &mut Adrs,
        idx0: u32,
        height: u32,
        nodes: &mut [[u8; N]; 8],
        pairs: usize,
    ) {
        debug_assert!(pairs <= L);
        addr.set_tree_height(height);
        let mut msgs = [[0u8; RATE]; L];
        let mut msg_len = 0;
        for (j, m) in msgs.iter_mut().enumerate().take(pairs) {
            addr.set_tree_index(idx0 + j as u32);
            msg_len = fill_msg::<N>(
                m,
                pk_seed,
                addr.bytes(),
                &[&nodes[2 * j], &nodes[2 * j + 1]],
            );
        }
        let merged = shake_n::<N, L>(&msgs, msg_len, pairs);
        nodes[..pairs].copy_from_slice(&merged[..pairs]);
    }

    /// Computes FORS node `node_id` at layer 3 — a height-3 subtree over
    /// leaves `8·node_id .. 8·node_id + 8` — writing the n-byte root to `out`.
    /// Hash-for-hash identical to the scalar recursion (same ADRS values).
    pub(super) fn subtree8(
        p: &Params,
        pk_seed: &Seed,
        sk_seed: &[u8],
        node_id: u32,
        addr: &mut Adrs,
        out: &mut [u8],
    ) {
        match p.n {
            16 => shake_dispatch!(subtree8_n::<16>(p, pk_seed, sk_seed, node_id, addr, out)),
            24 => shake_dispatch!(subtree8_n::<24>(p, pk_seed, sk_seed, node_id, addr, out)),
            _ => shake_dispatch!(subtree8_n::<32>(p, pk_seed, sk_seed, node_id, addr, out)),
        }
    }

    fn subtree8_n<const N: usize, const L: usize>(
        p: &Params,
        pk_seed: &Seed,
        sk_seed: &[u8],
        node_id: u32,
        addr: &mut Adrs,
        out: &mut [u8],
    ) {
        let mut nodes = leaves8::<N, L>(pk_seed, sk_seed, node_id * 8, addr);
        // Merge levels 1 and 2 batched; the top level is a single pair, so it
        // goes through the scalar `H` (which also restores the ADRS state the
        // scalar recursion leaves behind).
        merge_level::<N, L>(pk_seed, addr, node_id * 4, 1, &mut nodes, 4);
        merge_level::<N, L>(pk_seed, addr, node_id * 2, 2, &mut nodes, 2);
        addr.set_tree_height(3);
        addr.set_tree_index(node_id);
        super::hash::h(p, pk_seed, addr.bytes(), &nodes[0], &nodes[1], out);
    }
}

/// Differential tests: the batched height-3 FORS subtree must equal the pure
/// scalar recursion (children of `fors_node_scalar` at layer ≤ 2 never
/// re-batch), for every set (n = 16/24/32) of both hash families, through the
/// dispatched kernel and (SHA-2) the lockstep kernels explicitly.
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod fors_mb_tests {
    use super::*;

    fn check_set(set: ParamSet) {
        let p = set.params();
        let n = p.n as usize;
        let pk_seed_bytes: Vec<u8> = (0..n).map(|i| (i * 3 + 5) as u8).collect();
        let pk_seed = Seed::new(p, &pk_seed_bytes);
        let sk_seed: Vec<u8> = (0..n).map(|i| (i * 11 + 1) as u8).collect();

        let mut base = Adrs::new(p.is_shake);
        base.set_type_and_clear(AdrsType::ForsTree);
        base.set_layer(0);
        base.set_tree(0x1122_3344_5566_7788);
        base.set_key_pair(3);

        for node_id in [0u32, 5] {
            let mut want = [0u8; MAX_N];
            let mut a = base;
            fors_node_scalar(p, &pk_seed, &sk_seed, node_id, 3, &mut a, &mut want);
            let mut got = [0u8; MAX_N];
            let mut b = base;
            fors_node(p, &pk_seed, &sk_seed, node_id, 3, &mut b, &mut got);
            assert_eq!(want[..n], got[..n], "set {set:?} node {node_id}");
            assert_eq!(a.bytes(), b.bytes(), "set {set:?} node {node_id} addr");
            if !p.is_shake {
                let mut got = [0u8; MAX_N];
                let mut b = base;
                match n {
                    16 => fors_mb::subtree_n::<16, 4, 4>(
                        p,
                        &pk_seed,
                        &sk_seed,
                        node_id,
                        &mut b,
                        &mut got,
                        mb::lockstep256::<4>,
                        mb::lockstep512::<4>,
                    ),
                    24 => fors_mb::subtree_n::<24, 4, 4>(
                        p,
                        &pk_seed,
                        &sk_seed,
                        node_id,
                        &mut b,
                        &mut got,
                        mb::lockstep256::<4>,
                        mb::lockstep512::<4>,
                    ),
                    _ => fors_mb::subtree_n::<32, 4, 4>(
                        p,
                        &pk_seed,
                        &sk_seed,
                        node_id,
                        &mut b,
                        &mut got,
                        mb::lockstep256::<4>,
                        mb::lockstep512::<4>,
                    ),
                }
                assert_eq!(want[..n], got[..n], "set {set:?} node {node_id} lockstep");
            }
        }
    }

    #[test]
    fn sha2_subtree_matches_scalar() {
        use ParamSet::*;
        for set in [
            Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f,
        ] {
            check_set(set);
        }
    }

    #[test]
    fn shake_subtree_matches_scalar() {
        use ParamSet::*;
        for set in [
            Shake_128s, Shake_128f, Shake_192s, Shake_192f, Shake_256s, Shake_256f,
        ] {
            check_set(set);
        }
    }
}

/// FORS sign (Algorithm 16).
fn fors_sign(
    p: &Params,
    pk_seed: &Seed,
    sk_seed: &[u8],
    md: &[u8],
    addr: &mut Adrs,
    sig: &mut [u8],
) {
    let n = p.n as usize;
    let mut indices = [0u32; MAX_K];
    base_2b(md, p.a, &mut indices[..p.k as usize]);
    let two_a = 1u32 << p.a;
    let mut tree_base = 0u32;
    let mut off = 0;
    for tree_id in 0..p.k {
        let mut node_id = indices[tree_id as usize];
        fors_gen_sk(
            p,
            pk_seed,
            sk_seed,
            node_id + tree_base,
            addr,
            &mut sig[off..],
        );
        off += n;
        let mut tree_off = tree_base;
        for j in 0..p.a {
            fors_node(
                p,
                pk_seed,
                sk_seed,
                (node_id ^ 1) + tree_off,
                j,
                addr,
                &mut sig[off..],
            );
            node_id >>= 1;
            tree_off >>= 1;
            off += n;
        }
        tree_base += two_a;
    }
}

/// FORS public key from a signature (Algorithm 17). Returns the bytes consumed.
fn fors_pk_from_sig(
    p: &Params,
    pk_seed: &Seed,
    md: &[u8],
    sig: &[u8],
    addr: &mut Adrs,
    out: &mut [u8],
) -> usize {
    let n = p.n as usize;
    let mut indices = [0u32; MAX_K];
    base_2b(md, p.a, &mut indices[..p.k as usize]);
    let two_a = 1u32 << p.a;
    let mut tree_base = 0u32;
    // `p.k <= MAX_K` FORS trees of `n` octets each.
    let mut roots = [0u8; MAX_K * MAX_N];
    let roots = &mut roots[..n * p.k as usize];
    let mut off = 0;
    for tree_id in 0..p.k {
        let rp = tree_id as usize * n;
        let mut node_id = indices[tree_id as usize];
        let mut tree_idx = node_id + tree_base;
        addr.set_tree_height(0);
        addr.set_tree_index(tree_idx);
        hash::f(
            p,
            pk_seed,
            addr.bytes(),
            &sig[off..off + n],
            &mut roots[rp..],
        );
        off += n;
        for layer in 0..p.a {
            addr.set_tree_height(layer + 1);
            let node = &sig[off..off + n];
            let mut tmp_out = [0u8; MAX_N];
            if node_id & 1 == 0 {
                tree_idx >>= 1;
                addr.set_tree_index(tree_idx);
                hash::h(
                    p,
                    pk_seed,
                    addr.bytes(),
                    &roots[rp..rp + n],
                    node,
                    &mut tmp_out,
                );
            } else {
                tree_idx = (tree_idx - 1) >> 1;
                addr.set_tree_index(tree_idx);
                hash::h(
                    p,
                    pk_seed,
                    addr.bytes(),
                    node,
                    &roots[rp..rp + n],
                    &mut tmp_out,
                );
            }
            roots[rp..rp + n].copy_from_slice(&tmp_out[..n]);
            off += n;
            node_id >>= 1;
        }
        tree_base += two_a;
    }
    let mut pk_addr = *addr;
    pk_addr.set_type_and_clear(AdrsType::ForsRoots);
    pk_addr.copy_key_pair(addr);
    hash::t(p, pk_seed, pk_addr.bytes(), roots, out);
    off
}

/// Computes the top-tree root (FIPS 205 Algorithm 18, slh_keygen step).
fn compute_root(p: &Params, pk_seed: &[u8], sk_seed: &[u8], out: &mut [u8]) {
    let pk_seed = &Seed::new(p, pk_seed);
    let mut addr = Adrs::new(p.is_shake);
    addr.set_layer(p.d - 1);
    let mut tmp = [0u8; MAX_WOTS_LEN * MAX_N];
    let tmp = &mut tmp[..p.n as usize * p.len as usize];
    xmss_node(p, pk_seed, sk_seed, out, tmp, 0, p.h_prime, &mut addr);
}

/// Splits the message digest into FORS message, tree index, and leaf index.
fn split_digest(p: &Params, digest: &[u8]) -> (usize, u64, u32) {
    let md_len = p.md_len();
    let rest = &digest[md_len..];
    let til = p.tree_idx_len();
    let lil = p.leaf_idx_len();
    // `to_int` folds into a `u64`; all twelve standardized parameter sets have
    // tree/leaf index lengths <= 8, so this never truncates. Assert it so a
    // future parameter set that violated the invariant fails loudly in debug
    // rather than silently dropping high index bytes.
    debug_assert!(til <= 8 && lil <= 8, "SLH-DSA index length exceeds u64");
    let tree_idx = to_int(&rest[..til]) & p.tree_idx_mask();
    let leaf_idx = (to_int(&rest[til..til + lil]) & p.leaf_idx_mask()) as u32;
    (md_len, tree_idx, leaf_idx)
}

/// slh_sign_internal (FIPS 205 Algorithm 19). `m_prefix` is `0x00 ‖ |ctx| ‖ ctx`.
fn sign_internal(
    p: &Params,
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    m_prefix: &[u8],
    msg: &[u8],
    opt_rand: &[u8],
    sig: &mut [u8],
) {
    let n = p.n as usize;
    let pk_seed = &Seed::new(p, pk_seed);
    debug_assert_eq!(sig.len(), p.sig_size);
    sig.fill(0);

    // Randomizer R = PRF_msg(opt_rand, m_prefix, msg) into sig[..n].
    hash::prf_msg(p, sk_prf, opt_rand, m_prefix, msg, sig);
    // Every signature component is declassified as it is written: it is
    // published, and SLH-DSA's control flow and memory indices (tree and
    // leaf index, FORS indices, WOTS+ chain lengths) are functions of the
    // signature and the public key alone (FIPS 205 Algorithms 19-20). R is
    // the first; H_msg(R, PK.seed, PK.root, M) is then public.
    crate::ct::declassify(&sig[..n]);
    let mut r = [0u8; MAX_N];
    r[..n].copy_from_slice(&sig[..n]);

    // Message digest.
    let mut digest = [0u8; MAX_M];
    hash::h_msg(p, pk_seed, pk_root, &r[..n], m_prefix, msg, &mut digest);
    let (md_len, tree_idx, leaf_idx) = split_digest(p, &digest);
    let md = &digest[..md_len];

    // FORS signature over the digest.
    let mut addr = Adrs::new(p.is_shake);
    addr.set_tree(tree_idx);
    addr.set_type_and_clear(AdrsType::ForsTree);
    addr.set_key_pair(leaf_idx);
    fors_sign(p, pk_seed, sk_seed, md, &mut addr, &mut sig[n..]);
    // The FORS signature (the rest of `sig` is still zero): published, so
    // the FORS public key recomputed from it — the message the hypertree
    // signs — is public too.
    crate::ct::declassify(&sig[n..]);

    // FORS public key, then hypertree signature over it.
    let mut pk_fors = [0u8; MAX_N];
    let consumed = fors_pk_from_sig(p, pk_seed, md, &sig[n..], &mut addr, &mut pk_fors);
    let ht_off = n + consumed;
    ht_sign(
        p,
        pk_seed,
        sk_seed,
        &pk_fors[..n],
        tree_idx,
        leaf_idx,
        &mut sig[ht_off..],
    );
}

/// slh_verify_internal (FIPS 205 Algorithm 20).
fn verify_internal(
    p: &Params,
    pk_seed: &[u8],
    pk_root: &[u8],
    sig: &[u8],
    m_prefix: &[u8],
    msg: &[u8],
) -> bool {
    let n = p.n as usize;
    let pk_seed = &Seed::new(p, pk_seed);
    let r = &sig[..n];

    let mut digest = [0u8; MAX_M];
    hash::h_msg(p, pk_seed, pk_root, r, m_prefix, msg, &mut digest);
    let (md_len, tree_idx, leaf_idx) = split_digest(p, &digest);
    let md = &digest[..md_len];

    let mut addr = Adrs::new(p.is_shake);
    addr.set_tree(tree_idx);
    addr.set_type_and_clear(AdrsType::ForsTree);
    addr.set_key_pair(leaf_idx);

    let mut pk_fors = [0u8; MAX_N];
    let consumed = fors_pk_from_sig(p, pk_seed, md, &sig[n..], &mut addr, &mut pk_fors);
    let ht_sig = &sig[n + consumed..];
    ht_verify(
        p,
        pk_seed,
        pk_root,
        &pk_fors[..n],
        ht_sig,
        tree_idx,
        leaf_idx,
    )
}

/// Builds `0x00 ‖ |ctx| ‖ ctx` into `buf`, returning the filled prefix.
///
/// `ctx` is capped at [`MAX_CONTEXT`] (255) by every caller, so the buffer is a
/// fixed 257 octets and this needs no heap.
fn m_prefix<'a>(ctx: &[u8], buf: &'a mut [u8; 2 + MAX_CONTEXT]) -> &'a [u8] {
    buf[0] = 0;
    buf[1] = ctx.len() as u8;
    buf[2..2 + ctx.len()].copy_from_slice(ctx);
    &buf[..2 + ctx.len()]
}

/// An SLH-DSA private (signing) key.
#[derive(Clone)]
pub struct PrivateKey {
    set: ParamSet,
    /// `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` — `4n <= 4 * MAX_N` octets, so a
    /// fixed array; the parameter set fixes the used prefix.
    bytes: [u8; 4 * MAX_N],
}

/// An SLH-DSA public (verification) key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
    set: ParamSet,
    /// `PK.seed ‖ PK.root` — `2n <= 2 * MAX_N` octets.
    bytes: [u8; 2 * MAX_N],
}

impl PrivateKey {
    /// The parameter set this key was generated for.
    pub fn parameter_set(&self) -> ParamSet {
        self.set
    }

    /// Deterministically derives a key pair from the three n-byte seeds.
    ///
    /// # Panics
    ///
    /// Each of `sk_seed`, `sk_prf`, and `pk_seed` must be at least
    /// `set.params().n` bytes long (16, 24, or 32 depending on the parameter
    /// set); this panics otherwise. The seeds are caller-supplied local key
    /// material, never attacker-controlled wire data.
    pub fn from_seeds(
        set: ParamSet,
        sk_seed: &[u8],
        sk_prf: &[u8],
        pk_seed: &[u8],
    ) -> (PrivateKey, PublicKey) {
        let p = set.params();
        let n = p.n as usize;
        assert!(
            sk_seed.len() >= n && sk_prf.len() >= n && pk_seed.len() >= n,
            "SLH-DSA from_seeds: each seed must be at least n bytes"
        );
        let mut root = [0u8; MAX_N];
        compute_root(p, &pk_seed[..n], &sk_seed[..n], &mut root);

        let mut bytes = [0u8; 4 * MAX_N];
        bytes[..n].copy_from_slice(&sk_seed[..n]);
        bytes[n..2 * n].copy_from_slice(&sk_prf[..n]);
        bytes[2 * n..3 * n].copy_from_slice(&pk_seed[..n]);
        bytes[3 * n..4 * n].copy_from_slice(&root[..n]);

        let mut pk = [0u8; 2 * MAX_N];
        pk[..n].copy_from_slice(&pk_seed[..n]);
        pk[n..2 * n].copy_from_slice(&root[..n]);
        (PrivateKey { set, bytes }, PublicKey { set, bytes: pk })
    }

    /// Generates a fresh key pair from `rng`. The RNG must be a cryptographically
    /// secure CSPRNG (see [`CryptoRng`]).
    pub fn generate<R: RngCore + CryptoRng>(set: ParamSet, rng: &mut R) -> (PrivateKey, PublicKey) {
        let n = set.params().n as usize;
        let mut seeds = [0u8; 3 * MAX_N];
        rng.fill_bytes(&mut seeds[..3 * n]);
        let keys = Self::from_seeds(set, &seeds[..n], &seeds[n..2 * n], &seeds[2 * n..3 * n]);
        // Wipe the stack copy of SK.seed / SK.prf / PK.seed before
        // returning.
        wipe(&mut seeds);
        keys
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        let n = self.set.params().n as usize;
        let mut pk = [0u8; 2 * MAX_N];
        pk[..n].copy_from_slice(&self.bytes[2 * n..3 * n]); // PK.seed
        pk[n..2 * n].copy_from_slice(&self.bytes[3 * n..4 * n]); // PK.root
        PublicKey {
            set: self.set,
            bytes: pk,
        }
    }

    /// Signs `msg` with optional `ctx` (≤ 255 bytes), hedged with `rng`.
    ///
    /// `rng` SHOULD be a cryptographically secure CSPRNG (see [`CryptoRng`])
    /// — a predictable nonce degrades SLH-DSA's hedged mode to deterministic-
    /// equivalent signing (still safe per FIPS 205, but loses hedging). The
    /// bound is left at [`RngCore`] only so the X.509 / TLS dispatch layers
    /// can thread a single shared RNG type.
    #[cfg(feature = "alloc")]
    pub fn sign<R: RngCore>(&self, rng: &mut R, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; self.signature_len()];
        self.sign_into(rng, msg, ctx, &mut out)?;
        Ok(out)
    }

    /// Byte length of the signatures this key produces — the exact size the
    /// `out` buffer of [`sign_into`](Self::sign_into) must have.
    pub fn signature_len(&self) -> usize {
        self.set.signature_size()
    }

    /// Signs `msg` into `out` (exactly [`signature_len`](Self::signature_len)
    /// octets), returning the number written. Allocation-free counterpart of
    /// [`sign`][Self::sign].
    ///
    /// SLH-DSA signatures are large — from ~7.8 KiB to ~49 KiB depending on the
    /// parameter set — so the buffer is the caller's to place.
    #[cfg_attr(not(feature = "alloc"), doc = "", doc = "[Self::sign]: crate#no_std")]
    pub fn sign_into<R: RngCore>(
        &self,
        rng: &mut R,
        msg: &[u8],
        ctx: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if ctx.len() > MAX_CONTEXT {
            return Err(Error::ContextTooLong);
        }
        if out.len() != self.signature_len() {
            return Err(Error::InvalidLength);
        }
        let n = self.set.params().n as usize;
        let mut rnd = [0u8; MAX_N];
        rng.fill_bytes(&mut rnd[..n]);
        self.do_sign(msg, ctx, &rnd[..n], out);
        Ok(out.len())
    }

    /// Signs `msg` deterministically (the public seed is the randomizer).
    #[cfg(feature = "alloc")]
    pub fn sign_deterministic(&self, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; self.signature_len()];
        self.sign_deterministic_into(msg, ctx, &mut out)?;
        Ok(out)
    }

    /// Signs `msg` deterministically into `out`. Allocation-free counterpart of
    /// [`sign_deterministic`][Self::sign_deterministic].
    #[cfg_attr(
        not(feature = "alloc"),
        doc = "",
        doc = "[Self::sign_deterministic]: crate#no_std"
    )]
    pub fn sign_deterministic_into(
        &self,
        msg: &[u8],
        ctx: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if ctx.len() > MAX_CONTEXT {
            return Err(Error::ContextTooLong);
        }
        if out.len() != self.signature_len() {
            return Err(Error::InvalidLength);
        }
        let n = self.set.params().n as usize;
        let mut pk_seed = [0u8; MAX_N];
        pk_seed[..n].copy_from_slice(&self.bytes[2 * n..3 * n]);
        self.do_sign(msg, ctx, &pk_seed[..n], out);
        Ok(out.len())
    }

    fn do_sign(&self, msg: &[u8], ctx: &[u8], opt_rand: &[u8], out: &mut [u8]) {
        let p = self.set.params();
        let n = p.n as usize;
        let mut pfx = [0u8; 2 + MAX_CONTEXT];
        let pfx = m_prefix(ctx, &mut pfx);
        sign_internal(
            p,
            &self.bytes[..n],
            &self.bytes[n..2 * n],
            &self.bytes[2 * n..3 * n],
            &self.bytes[3 * n..4 * n],
            pfx,
            msg,
            opt_rand,
            out,
        )
    }

    /// The encoded private key (`SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`).
    ///
    /// The backing array is sized for the widest parameter set, so this slices
    /// to the `4n` actually in use — returning the whole array would append
    /// trailing zeros for every set with `n < MAX_N`.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes[..4 * self.set.params().n as usize]
    }

    /// Parses a private key, recomputing and checking the embedded root.
    pub fn from_bytes(set: ParamSet, bytes: &[u8]) -> Result<Self, Error> {
        let p = set.params();
        let n = p.n as usize;
        if bytes.len() != p.sk_size {
            return Err(Error::InvalidKey);
        }
        let mut root = [0u8; MAX_N];
        compute_root(p, &bytes[2 * n..3 * n], &bytes[..n], &mut root);
        if !bool::from(root[..n].ct_eq(&bytes[3 * n..4 * n])) {
            return Err(Error::InvalidKey);
        }
        let mut b = [0u8; 4 * MAX_N];
        b[..bytes.len()].copy_from_slice(bytes);
        Ok(PrivateKey { set, bytes: b })
    }

    /// Encodes the private key as a PKCS#8 `PrivateKeyInfo` DER (matches the
    /// OpenSSL 3.5 SLH-DSA layout: `privateKey` OCTET STRING holds the raw
    /// `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` bytes).
    #[cfg(feature = "der")]
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let algid = encode_sequence(&oid_tlv(self.set.params().oid));
        encode_sequence(
            &[
                encode_integer(&[0]),
                algid,
                encode_octet_string(self.to_bytes()),
            ]
            .concat(),
        )
    }

    /// Encodes the private key as a PKCS#8 PEM document.
    #[cfg(feature = "der")]
    pub fn to_pkcs8_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("PRIVATE KEY", &self.to_pkcs8_der())
    }

    /// Parses a PKCS#8 `PrivateKeyInfo` DER, returning `(set, key)`. The set is
    /// inferred from the embedded OID. Validates the key's root against the
    /// encoded `PK.root`.
    #[cfg(feature = "der")]
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        use crate::der::{Reader, parse_oid};
        let mut r = Reader::new(der);
        let mut seq = r.read_sequence().map_err(|_| Error::Malformed)?;
        seq.read_integer_bytes().map_err(|_| Error::Malformed)?;
        let mut algid = seq.read_sequence().map_err(|_| Error::Malformed)?;
        let oid = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        let set = ParamSet::from_oid(oid.as_slice()).ok_or(Error::Malformed)?;
        let inner = seq.read_octet_string().map_err(|_| Error::Malformed)?;
        Self::from_bytes(set, inner)
    }

    /// Parses a PKCS#8 PEM private key.
    #[cfg(feature = "der")]
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        let der = crate::der::pem_decode(pem, "PRIVATE KEY").map_err(|_| Error::Malformed)?;
        Self::from_pkcs8_der(&der)
    }

    /// Encrypts the PKCS#8 encoding under PBES2 (RFC 5958 §3 + RFC 8018
    /// §6.2), returning the DER-encoded `EncryptedPrivateKeyInfo`.
    #[cfg(all(feature = "der", feature = "kdf"))]
    pub fn to_pkcs8_der_encrypted(
        &self,
        password: &[u8],
        params: &crate::kdf::pbes2::Pbes2Params,
        rng: &mut impl crate::rng::RngCore,
    ) -> Vec<u8> {
        crate::kdf::pbes2::encrypt(&self.to_pkcs8_der(), password, params, rng)
    }

    /// PEM-wrapped variant of [`Self::to_pkcs8_der_encrypted`].
    #[cfg(all(feature = "der", feature = "kdf"))]
    pub fn to_pkcs8_pem_encrypted(
        &self,
        password: &[u8],
        params: &crate::kdf::pbes2::Pbes2Params,
        rng: &mut impl crate::rng::RngCore,
    ) -> alloc::string::String {
        crate::kdf::pbes2::encrypt_pem(&self.to_pkcs8_der(), password, params, rng)
    }

    /// Parses an `EncryptedPrivateKeyInfo` DER and decrypts it back to a
    /// PKCS#8 SLH-DSA private key.
    #[cfg(all(feature = "der", feature = "kdf"))]
    pub fn from_pkcs8_der_encrypted(der: &[u8], password: &[u8]) -> Result<Self, Error> {
        let inner = crate::kdf::pbes2::decrypt(der, password).map_err(|_| Error::Malformed)?;
        Self::from_pkcs8_der(&inner)
    }

    /// PEM-wrapped variant of [`Self::from_pkcs8_der_encrypted`].
    #[cfg(all(feature = "der", feature = "kdf"))]
    pub fn from_pkcs8_pem_encrypted(pem: &str, password: &[u8]) -> Result<Self, Error> {
        let inner = crate::kdf::pbes2::decrypt_pem(pem, password).map_err(|_| Error::Malformed)?;
        Self::from_pkcs8_der(&inner)
    }
}

// FIPS 205 expects the SLH-DSA private key (`SK.seed ‖ SK.prf ‖
// PK.seed ‖ PK.root`) to be wiped before deallocation. `wipe` uses the
// crate's volatile [`zeroize`](crate::zeroize) stores, which LLVM cannot
// eliminate as dead stores.
impl Drop for PrivateKey {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl crate::zeroize::ZeroizeOnDrop for PrivateKey {}

impl ParamSet {
    /// Finds the parameter set matching an algorithm OID, if any.
    pub fn from_oid(oid: &[u64]) -> Option<Self> {
        use ParamSet::*;
        const SETS: &[ParamSet] = &[
            Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f, Shake_128s,
            Shake_128f, Shake_192s, Shake_192f, Shake_256s, Shake_256f,
        ];
        SETS.iter().copied().find(|s| s.params().oid == oid)
    }
}

impl PublicKey {
    /// The parameter set this key was generated for.
    pub fn parameter_set(&self) -> ParamSet {
        self.set
    }

    /// Verifies `sig` over `msg` with optional `ctx`.
    pub fn verify(&self, sig: &[u8], msg: &[u8], ctx: &[u8]) -> bool {
        let p = self.set.params();
        if ctx.len() > MAX_CONTEXT || sig.len() != p.sig_size {
            return false;
        }
        let n = p.n as usize;
        let mut pfx = [0u8; 2 + MAX_CONTEXT];
        let pfx = m_prefix(ctx, &mut pfx);
        verify_internal(p, &self.bytes[..n], &self.bytes[n..2 * n], sig, pfx, msg)
    }

    /// The encoded public key (`PK.seed ‖ PK.root`).
    ///
    /// Sliced to the `2n` in use — see [`PrivateKey::to_bytes`].
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes[..2 * self.set.params().n as usize]
    }

    /// Parses a raw public key.
    pub fn from_bytes(set: ParamSet, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != set.params().pk_size {
            return Err(Error::InvalidKey);
        }
        let mut b = [0u8; 2 * MAX_N];
        b[..bytes.len()].copy_from_slice(bytes);
        Ok(PublicKey { set, bytes: b })
    }

    /// Encodes the key as a PKIX `SubjectPublicKeyInfo` DER structure
    /// (draft-ietf-lamps-x509-slhdsa).
    #[cfg(feature = "der")]
    pub fn to_spki_der(&self) -> Vec<u8> {
        use crate::der::{encode_bit_string, encode_sequence, oid_tlv};
        let algid = encode_sequence(&oid_tlv(self.set.params().oid));
        encode_sequence(&[algid, encode_bit_string(self.to_bytes())].concat())
    }

    /// Encodes the key as a PKIX PEM document.
    #[cfg(feature = "der")]
    pub fn to_spki_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("PUBLIC KEY", &self.to_spki_der())
    }

    /// Parses a PKIX `SubjectPublicKeyInfo` DER structure for parameter `set`.
    #[cfg(feature = "der")]
    pub fn from_spki_der(set: ParamSet, der: &[u8]) -> Result<Self, Error> {
        use crate::der::{Reader, parse_oid};
        let mut reader = Reader::new(der);
        let mut spki = reader.read_sequence().map_err(|_| Error::Malformed)?;
        let mut algid = spki.read_sequence().map_err(|_| Error::Malformed)?;
        let oid = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        if oid.as_slice() != set.params().oid {
            return Err(Error::Malformed);
        }
        let bits = spki.read_bit_string().map_err(|_| Error::Malformed)?;
        Self::from_bytes(set, bits).map_err(|_| Error::Malformed)
    }

    /// Parses a PKIX PEM public key for parameter `set`.
    #[cfg(feature = "der")]
    pub fn from_spki_pem(set: ParamSet, pem: &str) -> Result<Self, Error> {
        let der = crate::der::pem_decode(pem, "PUBLIC KEY").map_err(|_| Error::Malformed)?;
        Self::from_spki_der(set, &der)
    }
}

// The ACVP vector suite decodes hex into `Vec`s and drives the `Vec`-returning
// API; `nobuf_tests` covers the allocator-free path.
#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn unhex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut v = Vec::with_capacity(b.len() / 2);
        let mut i = 0;
        while i < b.len() {
            let hi = (b[i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
            v.push((hi << 4) | lo);
            i += 2;
        }
        v
    }

    fn pset(i: usize) -> ParamSet {
        use ParamSet::*;
        [
            Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f, Shake_128s,
            Shake_128f, Shake_192s, Shake_192f, Shake_256s, Shake_256f,
        ][i]
    }

    /// Empty context is encoded as "-".
    fn ctx(tok: &str) -> Vec<u8> {
        if tok == "-" { Vec::new() } else { unhex(tok) }
    }

    fn check_keygen(only_fast: bool) {
        for line in include_str!("../../testdata/slhdsa_keygen.kat").lines() {
            let mut it = line.split_whitespace();
            let idx: usize = it.next().unwrap().parse().unwrap();
            if only_fast && idx.is_multiple_of(2) {
                continue; // skip the slow 's' sets
            }
            let set = pset(idx);
            let sk_seed = unhex(it.next().unwrap());
            let sk_prf = unhex(it.next().unwrap());
            let pk_seed = unhex(it.next().unwrap());
            let sk_exp = unhex(it.next().unwrap());
            let pk_exp = unhex(it.next().unwrap());
            let (sk, pk) = PrivateKey::from_seeds(set, &sk_seed, &sk_prf, &pk_seed);
            assert_eq!(sk.to_bytes(), sk_exp, "sk set {idx}");
            assert_eq!(pk.to_bytes(), pk_exp, "pk set {idx}");
        }
    }

    fn check_siggen(only_fast: bool) {
        for line in include_str!("../../testdata/slhdsa_siggen.kat").lines() {
            let mut it = line.split_whitespace();
            let idx: usize = it.next().unwrap().parse().unwrap();
            if only_fast && idx.is_multiple_of(2) {
                continue;
            }
            let set = pset(idx);
            let sk = unhex(it.next().unwrap());
            let context = ctx(it.next().unwrap());
            let msg = unhex(it.next().unwrap());
            let sig_exp = unhex(it.next().unwrap());
            let key = PrivateKey::from_bytes(set, &sk).unwrap();
            let sig = key.sign_deterministic(&msg, &context).unwrap();
            assert_eq!(sig, sig_exp, "signature set {idx}");
        }
    }

    #[test]
    fn acvp_keygen_fast() {
        check_keygen(true);
    }

    #[test]
    fn acvp_siggen_fast() {
        check_siggen(true);
    }

    /// Hedged signing against the ACVP `additionalRandomness` vectors: the
    /// `n` bytes the RNG hands `sign_into` are `opt_rand` verbatim, so a
    /// fixed-output RNG reproduces the published signature. Covers the path
    /// `sign_deterministic` never takes (`opt_rand != PK.seed`).
    #[test]
    fn acvp_siggen_hedged() {
        /// Serves exactly the vector's entropy, once.
        struct FixedRng(Vec<u8>);
        impl RngCore for FixedRng {
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                assert_eq!(dest.len(), self.0.len(), "opt_rand must be n bytes");
                dest.copy_from_slice(&self.0);
                self.0.clear();
            }
        }

        let mut count = 0;
        for line in include_str!("../../testdata/slhdsa_siggen_hedged.kat").lines() {
            let mut it = line.split_whitespace();
            let idx: usize = it.next().unwrap().parse().unwrap();
            let set = pset(idx);
            let sk = unhex(it.next().unwrap());
            let context = ctx(it.next().unwrap());
            let entropy = unhex(it.next().unwrap());
            let msg = unhex(it.next().unwrap());
            let sig_exp = unhex(it.next().unwrap());
            let key = PrivateKey::from_bytes(set, &sk).unwrap();
            let mut rng = FixedRng(entropy);
            let sig = key.sign(&mut rng, &msg, &context).unwrap();
            assert!(rng.0.is_empty(), "sign must draw the randomizer");
            assert_eq!(sig, sig_exp, "hedged signature set {idx}");
            assert!(key.public_key().verify(&sig, &msg, &context));
            count += 1;
        }
        assert!(count >= 2, "expected hedged KAT lines, got {count}");
    }

    #[test]
    fn acvp_sigver() {
        for line in include_str!("../../testdata/slhdsa_sigver.kat").lines() {
            let mut it = line.split_whitespace();
            let idx: usize = it.next().unwrap().parse().unwrap();
            let set = pset(idx);
            let pk = unhex(it.next().unwrap());
            let context = ctx(it.next().unwrap());
            let msg = unhex(it.next().unwrap());
            let sig = unhex(it.next().unwrap());
            let want = it.next().unwrap() == "1";
            let key = PublicKey::from_bytes(set, &pk).unwrap();
            assert_eq!(key.verify(&sig, &msg, &context), want, "verify set {idx}");
        }
    }

    #[cfg(feature = "der")]
    #[test]
    fn spki_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa-spki", b"n", &[]);
        let (_sk, pk) = PrivateKey::generate(ParamSet::Sha2_128f, &mut rng);
        let pem = pk.to_spki_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let parsed = PublicKey::from_spki_pem(ParamSet::Sha2_128f, &pem).unwrap();
        assert_eq!(parsed, pk);
    }

    #[test]
    fn roundtrip_and_reject() {
        let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa", b"nonce", &[]);
        let (sk, pk) = PrivateKey::generate(ParamSet::Sha2_128f, &mut rng);
        let sig = sk.sign(&mut rng, b"hello purecrypto", b"ctx").unwrap();
        assert!(pk.verify(&sig, b"hello purecrypto", b"ctx"));
        assert!(!pk.verify(&sig, b"other", b"ctx"));
        assert!(!pk.verify(&sig, b"hello purecrypto", b"x"));
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(!pk.verify(&bad, b"hello purecrypto", b"ctx"));

        // Deterministic signing is reproducible.
        let d1 = sk.sign_deterministic(b"abc", b"").unwrap();
        let d2 = sk.sign_deterministic(b"abc", b"").unwrap();
        assert_eq!(d1, d2);
        assert!(pk.verify(&d1, b"abc", b""));
    }

    // Slow paths (the 's' parameter sets and their signing): run with
    // `cargo test --release -- --ignored`.
    #[test]
    #[ignore = "slow in debug; run with --release --ignored"]
    fn acvp_keygen_all() {
        check_keygen(false);
    }

    #[test]
    #[ignore = "slow in debug; run with --release --ignored"]
    fn acvp_siggen_all() {
        check_siggen(false);
    }

    /// Deterministic keygen + sign + verify roundtrip on every fast
    /// (`f`-flavored) parameter set. Regression guard for the
    /// `tree_idx_mask` shift overflow (audit C-1): `Sha2_256f` and
    /// `Shake_256f` panic in a debug build before the fix because
    /// `h - h_prime = 64`.
    #[test]
    fn roundtrip_all_fast_param_sets() {
        use ParamSet::*;
        let fast = [
            Sha2_128f, Sha2_192f, Sha2_256f, Shake_128f, Shake_192f, Shake_256f,
        ];
        for set in fast {
            let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa-roundtrip", set.oid_label(), &[]);
            let (sk, pk) = PrivateKey::generate(set, &mut rng);

            // Hedged sign + verify.
            let sig = sk.sign(&mut rng, b"purecrypto-kat", b"ctx").unwrap();
            assert!(pk.verify(&sig, b"purecrypto-kat", b"ctx"), "verify {set:?}");
            assert!(
                !pk.verify(&sig, b"other-msg", b"ctx"),
                "wrong msg verifies {set:?}"
            );
            assert!(
                !pk.verify(&sig, b"purecrypto-kat", b"x"),
                "wrong ctx verifies {set:?}"
            );
            let mut tampered = sig.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(
                !pk.verify(&tampered, b"purecrypto-kat", b"ctx"),
                "tampered sig verifies {set:?}"
            );

            // Deterministic sign is reproducible and self-consistent.
            let d1 = sk.sign_deterministic(b"abc", b"").unwrap();
            let d2 = sk.sign_deterministic(b"abc", b"").unwrap();
            assert_eq!(d1, d2, "deterministic mismatch {set:?}");
            assert!(pk.verify(&d1, b"abc", b""), "det verify {set:?}");

            // Signature length matches the spec.
            assert_eq!(sig.len(), set.signature_size(), "sig size {set:?}");
        }
    }

    /// Roundtrip across every parameter set including the slow `s`-flavored
    /// ones. Ignored by default because signing for the `s` sets takes
    /// minutes in debug builds.
    #[test]
    #[ignore = "slow in debug; run with --release --ignored"]
    fn roundtrip_all_param_sets() {
        use ParamSet::*;
        let all = [
            Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f, Shake_128s,
            Shake_128f, Shake_192s, Shake_192f, Shake_256s, Shake_256f,
        ];
        for set in all {
            let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa-roundtrip-all", set.oid_label(), &[]);
            let (sk, pk) = PrivateKey::generate(set, &mut rng);
            let sig = sk.sign_deterministic(b"purecrypto-kat", b"ctx").unwrap();
            assert!(pk.verify(&sig, b"purecrypto-kat", b"ctx"), "verify {set:?}");
            assert_eq!(sig.len(), set.signature_size(), "sig size {set:?}");
        }
    }

    impl ParamSet {
        /// Stable byte label used to personalize the test DRBG per set.
        fn oid_label(self) -> &'static [u8] {
            match self {
                ParamSet::Sha2_128s => b"sha2-128s",
                ParamSet::Sha2_128f => b"sha2-128f",
                ParamSet::Sha2_192s => b"sha2-192s",
                ParamSet::Sha2_192f => b"sha2-192f",
                ParamSet::Sha2_256s => b"sha2-256s",
                ParamSet::Sha2_256f => b"sha2-256f",
                ParamSet::Shake_128s => b"shake-128s",
                ParamSet::Shake_128f => b"shake-128f",
                ParamSet::Shake_192s => b"shake-192s",
                ParamSet::Shake_192f => b"shake-192f",
                ParamSet::Shake_256s => b"shake-256s",
                ParamSet::Shake_256f => b"shake-256f",
            }
        }
    }
}

#[cfg(test)]
mod nobuf_tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    /// Sign into a caller buffer and verify, with no allocator. Uses a `f`
    /// (fast) set so the test stays quick; the `s` sets differ only in
    /// parameters, not in the buffer plumbing.
    #[test]
    fn sign_into_verify_roundtrip_no_alloc() {
        let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa-nobuf", b"nonce", &[]);
        let (sk, pk) = PrivateKey::generate(ParamSet::Sha2_128f, &mut rng);

        let n = sk.signature_len();
        assert_eq!(n, ParamSet::Sha2_128f.signature_size());
        let mut sig = [0u8; 17088]; // SLH-DSA-SHA2-128f signature size
        let written = sk
            .sign_into(&mut rng, b"firmware", b"", &mut sig[..n])
            .expect("sign");
        assert_eq!(written, n);

        assert!(pk.verify(&sig[..n], b"firmware", b""));
        assert!(!pk.verify(&sig[..n], b"other", b""));
    }

    /// FIPS 205 places no lower bound on the message length: the empty
    /// message signs and verifies like any other, in both signing modes, and
    /// is not confused with a one-byte message or a different context.
    #[test]
    fn empty_message_signs_and_verifies() {
        let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa-empty", b"nonce", &[]);
        let (sk, pk) = PrivateKey::generate(ParamSet::Sha2_128f, &mut rng);
        let n = sk.signature_len();

        let mut sig = [0u8; 17088];
        let written = sk
            .sign_into(&mut rng, b"", b"", &mut sig[..n])
            .expect("empty message must sign");
        assert_eq!(written, n);
        assert!(pk.verify(&sig[..n], b"", b""));
        assert!(!pk.verify(&sig[..n], b"\0", b""));
        assert!(!pk.verify(&sig[..n], b"", b"ctx"));

        let mut det = [0u8; 17088];
        sk.sign_deterministic_into(b"", b"ctx", &mut det[..n])
            .expect("empty message must sign deterministically");
        assert!(pk.verify(&det[..n], b"", b"ctx"));
        assert!(!pk.verify(&det[..n], b"", b""));
    }

    /// Deterministic signing is reproducible and binds the context.
    #[test]
    fn deterministic_sign_is_stable_no_alloc() {
        let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa-det", b"nonce", &[]);
        let (sk, pk) = PrivateKey::generate(ParamSet::Sha2_128f, &mut rng);
        let n = sk.signature_len();
        let mut a = [0u8; 17088];
        let mut b = [0u8; 17088];
        sk.sign_deterministic_into(b"msg", b"ctx", &mut a[..n])
            .unwrap();
        sk.sign_deterministic_into(b"msg", b"ctx", &mut b[..n])
            .unwrap();
        assert_eq!(a[..n], b[..n]);
        assert!(pk.verify(&a[..n], b"msg", b"ctx"));
        assert!(!pk.verify(&a[..n], b"msg", b"other"));
    }

    /// Keys round-trip through their raw encodings, which must carry the used
    /// prefix rather than the max-sized backing array.
    #[test]
    fn key_encoding_roundtrip_no_alloc() {
        let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa-enc", b"nonce", &[]);
        let (sk, pk) = PrivateKey::generate(ParamSet::Sha2_128f, &mut rng);
        let p = ParamSet::Sha2_128f.params();
        assert_eq!(sk.to_bytes().len(), 4 * p.n as usize);
        assert_eq!(pk.to_bytes().len(), 2 * p.n as usize);
        let pk2 = PublicKey::from_bytes(ParamSet::Sha2_128f, pk.to_bytes()).expect("pk");
        assert_eq!(pk2.to_bytes(), pk.to_bytes());
        assert!(PublicKey::from_bytes(ParamSet::Sha2_128f, &pk.to_bytes()[..3]).is_err());
    }

    /// A wrong-size output buffer is rejected rather than silently truncating.
    #[test]
    fn sign_into_rejects_wrong_buffer_len() {
        let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa-len", b"nonce", &[]);
        let (sk, _pk) = PrivateKey::generate(ParamSet::Sha2_128f, &mut rng);
        let mut short = [0u8; 64];
        assert!(sk.sign_into(&mut rng, b"m", b"", &mut short).is_err());
    }
}
