//! AVX-512 IFMA backend for the runtime-width Montgomery exponentiations.
//!
//! The portable [`BoxedMontModulus`](super::BoxedMontModulus) kernels run
//! 64-bit limbs through `u64 × u64 → u128` scalar multiplies. CPUs with
//! AVX-512 IFMA (`vpmadd52luq` / `vpmadd52huq`: eight 52 × 52-bit multiplies
//! per instruction, accumulated into 64-bit lanes) can instead hold an
//! operand as `d` 52-bit digits spread over `V = ⌈d/8⌉` ZMM registers and
//! process a whole Montgomery row per pair of instructions. This is the
//! technique OpenSSL's `rsaz-*-avx512` code uses for RSA.
//!
//! # Arithmetic
//!
//! Values are in radix `2^52` with `R = 2^(52·d)`, where `d` is the smallest
//! digit count with `R ≥ 4n`. The multiplication is *almost* Montgomery
//! (Walter's no-final-subtraction form): for inputs `a, b < 2n` the result
//! `(a·b + m·n)/R` is below `4n²/R + n ≤ 2n`, so the bound is closed under
//! multiplication and the exponentiation ladders never need a conditional
//! subtraction; one masked subtraction at the very end brings the result
//! into `[0, n)`. Each row adds the low halves of `a·bᵢ` and `m·n` into an
//! accumulator, shifts the accumulator down one digit (the low digit is zero
//! by the choice of `m`), and adds the high halves; the lanes hold up to 64
//! bits, so carries are left in place until a single normalisation per
//! multiplication.
//!
//! Two independent problems can share one call (`K = 2`): the RSA CRT
//! exponentiations mod `p` and mod `q` run in lock step, so the latency of
//! one row's reduction step (extract the low digit, multiply by `n'`,
//! broadcast) overlaps the other's multiplies.
//!
//! # Constant time
//!
//! The digit count, the row count and every loop bound are functions of the
//! modulus width only. IFMA, the shifts, blends and mask moves have
//! data-independent timing; carry normalisation resolves the
//! carry-propagation chain with a scalar add over lane masks rather than a
//! loop; table lookups scan every entry with a masked move whose mask comes
//! from a comparison against an opaque (`black_box`ed) index vector, so the
//! compiler cannot turn the scan into an indexed load or a branch.
//!
//! The backend is used only when the CPU reports AVX-512F + AVX-512 IFMA (and
//! the OS saves ZMM state) and [`crate::ct::force_portable`] is off, so the
//! Valgrind constant-time harness keeps exercising the portable kernels.
#![allow(unsafe_code)]
// The kernels index parallel register arrays (`a[v]`, `n[v]`, `l[v]`) by
// the same register number; iterator chains would obscure that.
#![allow(clippy::needless_range_loop)]

use super::montgomery::{inv_mod_2_64, mont_final_sub};
use super::uint::Limb;
use alloc::vec;
use alloc::vec::Vec;
use core::arch::x86_64::*;

/// Digit mask: 52 bits.
const M52: u64 = (1 << 52) - 1;

/// Largest supported operand size: sixteen ZMM registers (`d ≤ 128`, the
/// per-lane carry masks fit one `u128`), i.e. moduli up to 6654 bits —
/// every RSA modulus through RSA-6144 for the public operations.
const MAX_V: usize = 16;

/// Largest operand size for a two-way call: the CRT halves of RSA-6144 and
/// below. Two problems of more than eight registers each would not fit the
/// register file anyway.
const MAX_PAIR_V: usize = 8;

/// Whether the CPU (and OS) support the IFMA kernels. Cached after the first
/// query; racing first calls run the idempotent detection and store the same
/// value.
fn cpu_has_ifma() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    // 0 = unknown, 1 = absent, 2 = present.
    static STATE: AtomicU8 = AtomicU8::new(0);
    match STATE.load(Ordering::Relaxed) {
        1 => false,
        2 => true,
        _ => {
            // `avx512f()` has already checked CPUID leaf 7 exists and that the
            // OS saves the opmask / ZMM state; IFMA is leaf 7, EBX bit 21.
            let on = crate::cpu::avx512f() && {
                // SAFETY: `CPUID` exists on every x86_64 CPU and leaf 7 is in
                // range (checked by `avx512f`). Newer toolchains make the
                // intrinsic safe, hence `unused_unsafe`.
                #[allow(unused_unsafe)]
                let l7 = unsafe { __cpuid_count(7, 0) };
                l7.ebx & (1 << 21) != 0
            };
            STATE.store(if on { 2 } else { 1 }, Ordering::Relaxed);
            on
        }
    }
}

/// Whether the IFMA kernels may run now: hardware support, and the
/// portable-dispatch override (used by the constant-time harness) is off.
#[inline]
pub(crate) fn enabled() -> bool {
    !crate::ct::force_portable() && cpu_has_ifma()
}

/// Whether to build the IFMA parameters at all (hardware support only; the
/// override is consulted at each call, see [`enabled`]).
#[inline]
pub(crate) fn supported() -> bool {
    cpu_has_ifma()
}

/// One operand: `V` ZMM registers' worth of 52-bit digits, little-endian,
/// 64-byte aligned so the loads are full-line.
#[derive(Clone, Copy)]
#[repr(C, align(64))]
struct Zv<const V: usize>([[u64; 8]; V]);

impl<const V: usize> Zv<V> {
    const ZERO: Self = Zv([[0; 8]; V]);

    #[inline(always)]
    fn digits(&self) -> &[u64] {
        self.0.as_flattened()
    }

    #[inline(always)]
    fn digits_mut(&mut self) -> &mut [u64] {
        self.0.as_flattened_mut()
    }

    fn wipe(&mut self) {
        crate::zeroize::Zeroize::zeroize(self.digits_mut());
    }
}

fn wipe_all<const V: usize>(v: &mut [Zv<V>]) {
    for z in v {
        z.wipe();
    }
}

/// `x` (64-bit limbs) as `out.len()` 52-bit digits. Positions past `x` read
/// as zero; the shifts and limb indices are public.
fn to_digits(x: &[Limb], out: &mut [u64]) {
    for (j, o) in out.iter_mut().enumerate() {
        let bit = 52 * j;
        let (li, sh) = (bit / 64, bit % 64);
        let lo = x.get(li).copied().unwrap_or(0) >> sh;
        let hi = if sh > 12 {
            x.get(li + 1).copied().unwrap_or(0) << (64 - sh)
        } else {
            0
        };
        *o = (lo | hi) & M52;
    }
}

/// Canonical 52-bit digits back to 64-bit limbs; bits past `out` are
/// dropped (callers only convert values that fit).
fn from_digits(dg: &[u64], out: &mut [Limb]) {
    out.fill(0);
    for (j, &v) in dg.iter().enumerate() {
        let bit = 52 * j;
        let (li, sh) = (bit / 64, bit % 64);
        if li < out.len() {
            out[li] |= v << sh;
        }
        if sh > 12 && li + 1 < out.len() {
            out[li + 1] |= v >> (64 - sh);
        }
    }
}

/// The IFMA form of one odd modulus: its digits, `n' = −n⁻¹ mod 2^52`, and
/// `R² mod n` for its `R = 2^(52·d)`. As secret as the modulus (an RSA
/// prime), so wiped on drop.
#[derive(Clone)]
pub(crate) struct IfmaModulus {
    /// Digit count `d` (`R = 2^(52·d)`).
    d: usize,
    /// ZMM registers per operand, `⌈d/8⌉`.
    v: usize,
    /// `n` as `8·v` digits.
    n: Vec<u64>,
    /// `n` as 64-bit limbs (the final subtraction).
    n_limbs: Vec<Limb>,
    /// `−n⁻¹ mod 2^52`.
    k0: u64,
    /// `R² mod n` as `8·v` digits.
    rr: Vec<u64>,
}

impl Drop for IfmaModulus {
    fn drop(&mut self) {
        crate::zeroize::Zeroize::zeroize(&mut self.n);
        crate::zeroize::Zeroize::zeroize(&mut self.n_limbs);
        crate::zeroize::Zeroize::zeroize(&mut self.rr);
        crate::zeroize::Zeroize::zeroize(&mut self.k0);
    }
}

impl IfmaModulus {
    /// IFMA parameters for the odd modulus `n` (64-bit limbs, top limb
    /// nonzero) of public bit length `bits`, or `None` when it is too wide
    /// for the kernels. `pow2_mod_n(e)` must return `2^e mod n` as limbs —
    /// the caller's portable reduction supplies `R² mod n`.
    pub(crate) fn new(
        n: &[Limb],
        bits: usize,
        pow2_mod_n: impl FnOnce(usize) -> Vec<Limb>,
    ) -> Option<Self> {
        // R = 2^(52·d) ≥ 4n: d·52 ≥ bits + 2. Also at least the limb
        // storage width, so any `l`-limb base converts without truncation
        // (a base below R is all the first conversion `base·R²·R⁻¹` needs
        // to land below 2n).
        let d = (bits + 2).div_ceil(52).max((64 * n.len()).div_ceil(52));
        let v = d.div_ceil(8);
        if v > MAX_V || v == 0 {
            return None;
        }
        let mut nd = vec![0u64; 8 * v];
        to_digits(n, &mut nd[..d]);
        let k0 = inv_mod_2_64(n[0]).wrapping_neg() & M52;
        let mut rr_limbs = pow2_mod_n(2 * 52 * d);
        let mut rr = vec![0u64; 8 * v];
        to_digits(&rr_limbs, &mut rr[..d]);
        crate::zeroize::Zeroize::zeroize(&mut rr_limbs);
        Some(IfmaModulus {
            d,
            v,
            n: nd,
            n_limbs: n.to_vec(),
            k0,
            rr,
        })
    }

    /// Whether two moduli can share a two-way call (same digit count, small
    /// enough for the paired kernels).
    #[cfg_attr(not(feature = "rsa"), allow(dead_code))]
    pub(crate) fn pairs_with(&self, other: &IfmaModulus) -> bool {
        self.d == other.d && self.v <= MAX_PAIR_V
    }
}

/// What a ladder exponentiates.
#[derive(Clone, Copy)]
pub(crate) enum Job<'a> {
    /// `base^exp` with 5-bit fixed windows over `bits` exponent bits.
    Pow {
        base: &'a [Limb],
        exp: &'a [Limb],
        bits: usize,
    },
    /// `a^x · b^y` with a 2-bit joint (Straus) window over `bits` bits.
    Pow2 {
        a: &'a [Limb],
        x: &'a [Limb],
        b: &'a [Limb],
        y: &'a [Limb],
        bits: usize,
    },
}

/// `width` bits of `e` from bit `pos`, with bits at or above `bound` read
/// as zero. Every index and shift is a public position.
#[inline(always)]
fn window(e: &[Limb], pos: usize, width: usize, bound: usize) -> usize {
    if pos >= bound {
        return 0;
    }
    let w = width.min(bound - pos);
    let (li, sh) = (pos / 64, pos % 64);
    let lo = e.get(li).copied().unwrap_or(0) >> sh;
    let hi = if sh + w > 64 {
        e.get(li + 1).copied().unwrap_or(0) << (64 - sh)
    } else {
        0
    };
    ((lo | hi) & ((1u64 << w) - 1)) as usize
}

/// Runs `K` independent exponentiations (`K = 1` or `2`, all moduli of the
/// same digit count) and writes each fully reduced result to `outs[k]`
/// (`n_limbs.len()` limbs). Every base must be below its modulus; all jobs
/// must be of the same kind and the same `bits`.
///
/// # Panics
/// Panics if [`enabled`] is false — callers check it first.
pub(crate) fn run<const K: usize>(
    ms: [&IfmaModulus; K],
    jobs: [Job<'_>; K],
    outs: [&mut [Limb]; K],
) {
    assert!(enabled(), "ifma::run without IFMA support");
    let v = ms[0].v;
    debug_assert!(ms.iter().all(|m| m.d == ms[0].d));
    // SAFETY: `enabled()` confirmed AVX-512F and AVX-512 IFMA (with OS ZMM
    // state) at run time, which is every target feature the kernels use.
    unsafe {
        if K == 1 {
            dispatch!(v, ladder, K, (ms, jobs, outs), 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
        } else {
            assert!(v <= MAX_PAIR_V, "ifma::run: pair too wide");
            dispatch!(v, ladder, K, (ms, jobs, outs), 1 2 3 4 5 6 7 8)
        }
    }
}

/// Calls `$f::<V[, K]>` for the runtime register count `$v`, over the listed
/// instantiations.
macro_rules! dispatch {
    ($v:expr, $f:ident, $k:ident, $args:tt, $($n:literal)+) => {
        match $v {
            $($n => dispatch!(@call $f, $n, $k, $args),)+
            _ => unreachable!("IfmaModulus::new caps v at MAX_V"),
        }
    };
    ($v:expr, $f:ident, $args:tt, $($n:literal)+) => {
        match $v {
            $($n => dispatch!(@call1 $f, $n, $args),)+
            _ => unreachable!("IfmaModulus::new caps v at MAX_V"),
        }
    };
    (@call $f:ident, $n:literal, $k:ident, ($($a:expr),*)) => { $f::<$n, $k>($($a),*) };
    (@call1 $f:ident, $n:literal, ($($a:expr),*)) => { $f::<$n>($($a),*) };
}
use dispatch;

/// `base^exp mod n` for a **public** exponent of at most 64 bits
/// (left-to-right binary, branching on the exponent's bits only); `base`
/// stays protected. Result fully reduced into `out`.
///
/// # Panics
/// Panics if [`enabled`] is false.
pub(crate) fn pow_public_u64(m: &IfmaModulus, base: &[Limb], exp: u64, out: &mut [Limb]) {
    assert!(enabled(), "ifma::pow_public_u64 without IFMA support");
    // SAFETY: as in `run`.
    unsafe {
        dispatch!(m.v, pow_public_impl, (m, base, exp, out), 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16)
    }
}

/// Loads one ZMM register's digits.
#[target_feature(enable = "avx512f")]
#[inline]
fn load(x: &[u64; 8]) -> __m512i {
    // SAFETY: `x` is eight readable `u64`s; the unaligned load has no
    // alignment requirement.
    unsafe { _mm512_loadu_epi64(x.as_ptr().cast()) }
}

/// Stores one ZMM register's digits.
#[target_feature(enable = "avx512f")]
#[inline]
fn store(x: &mut [u64; 8], v: __m512i) {
    // SAFETY: `x` is eight writable `u64`s.
    unsafe { _mm512_storeu_epi64(x.as_mut_ptr().cast(), v) }
}

/// Resolves the per-lane carries of an accumulator whose lanes hold up to
/// 64 bits into canonical 52-bit digits. The value must fit in `8·V`
/// digits (true for every result `< 2n < R`).
///
/// One vector pass moves each lane's bits above 52 into the next lane,
/// leaving lanes of at most `2^52 + 2^12`, i.e. a carry of at most one;
/// that remaining ripple is solved with the carry-lookahead identity
/// `carry_in = ((G << 1) + P) ⊕ P` over the lane masks (`G`: lane exceeds
/// `2^52 − 1`, generating a carry; `P`: lane equals it, propagating one) —
/// a scalar add, so the ripple costs no data-dependent loop.
#[target_feature(enable = "avx512f")]
#[inline]
fn normalize<const V: usize>(l: &mut [__m512i; V]) {
    let m52 = _mm512_set1_epi64(M52 as i64);
    let zero = _mm512_setzero_si512();
    let one = _mm512_set1_epi64(1);
    let mut c = [zero; V];
    for v in 0..V {
        c[v] = _mm512_srli_epi64::<52>(l[v]);
        l[v] = _mm512_and_si512(l[v], m52);
    }
    for v in 0..V {
        // Lane j receives lane j − 1's carry (lane 0 of vector v receives
        // lane 7 of vector v − 1).
        let prev = if v == 0 { zero } else { c[v - 1] };
        l[v] = _mm512_add_epi64(l[v], _mm512_alignr_epi64::<7>(c[v], prev));
    }
    let mut g: u128 = 0;
    let mut p: u128 = 0;
    for v in 0..V {
        g |= (_mm512_cmpgt_epu64_mask(l[v], m52) as u128) << (8 * v);
        p |= (_mm512_cmpeq_epu64_mask(l[v], m52) as u128) << (8 * v);
    }
    // Up to eight registers the masks fit a `u64` (a compile-time choice).
    let cin = if V <= 8 {
        let (g, p) = (g as u64, p as u64);
        ((g << 1).wrapping_add(p) ^ p) as u128
    } else {
        (g << 1).wrapping_add(p) ^ p
    };
    for v in 0..V {
        let k = (cin >> (8 * v)) as u8;
        l[v] = _mm512_and_si512(_mm512_mask_add_epi64(l[v], k, l[v], one), m52);
    }
}

/// `K` independent almost-Montgomery multiplications `a·b·R⁻¹` (see the
/// module docs), over `d` rows. Inputs are canonical digits below `2n`;
/// the outputs are canonical and below `2n`.
#[target_feature(enable = "avx512f,avx512ifma")]
#[inline]
fn amm<const V: usize, const K: usize>(
    a: [&Zv<V>; K],
    b: [&Zv<V>; K],
    n: &[Zv<V>; K],
    k0: [u64; K],
    d: usize,
) -> [Zv<V>; K] {
    let zero = _mm512_setzero_si512();
    let mut av = [[zero; V]; K];
    let mut nv = [[zero; V]; K];
    let mut a0 = [0u64; K];
    for k in 0..K {
        for v in 0..V {
            av[k][v] = load(&a[k].0[v]);
            nv[k][v] = load(&n[k].0[v]);
        }
        a0[k] = a[k].0[0][0];
    }
    let a0v: [__m512i; K] = core::array::from_fn(|k| _mm512_set1_epi64(a0[k] as i64));
    let k0v: [__m512i; K] = core::array::from_fn(|k| _mm512_set1_epi64(k0[k] as i64));
    let mut l = [[zero; V]; K];
    for i in 0..d {
        for k in 0..K {
            let bv = _mm512_set1_epi64(b[k].0[i / 8][i % 8] as i64);
            // m = (l₀ + a₀·bᵢ)·n' mod 2^52, in every lane. The part from
            // a₀·bᵢ does not depend on the accumulator, so only one IFMA
            // (l₀·n', accumulated onto it) sits on the row-to-row critical
            // path after the broadcast of l₀. IFMA reads just the low 52 bits
            // of each multiplicand, which is exactly the reduction mod 2^52
            // that m needs, so no masking is required anywhere.
            let p = _mm512_madd52lo_epu64(zero, a0v[k], bv);
            let q = _mm512_madd52lo_epu64(zero, p, k0v[k]);
            let l0 = _mm512_broadcastq_epi64(_mm512_castsi512_si128(l[k][0]));
            let mv = _mm512_madd52lo_epu64(q, l0, k0v[k]);
            let mut x = l[k];
            let mut h = [zero; V];
            for v in 0..V {
                x[v] = _mm512_madd52lo_epu64(x[v], av[k][v], bv);
                h[v] = _mm512_madd52hi_epu64(zero, av[k][v], bv);
            }
            for v in 0..V {
                x[v] = _mm512_madd52lo_epu64(x[v], nv[k][v], mv);
                h[v] = _mm512_madd52hi_epu64(h[v], nv[k][v], mv);
            }
            // The low digit is now 0 mod 2^52: its top bits carry into
            // digit 1 (folded into the high halves, which sit one digit up),
            // and every lane shifts down one.
            h[0] = _mm512_add_epi64(h[0], _mm512_maskz_srli_epi64::<52>(1, x[0]));
            for v in 0..V - 1 {
                l[k][v] = _mm512_add_epi64(_mm512_alignr_epi64::<1>(x[v + 1], x[v]), h[v]);
            }
            l[k][V - 1] = _mm512_add_epi64(_mm512_alignr_epi64::<1>(zero, x[V - 1]), h[V - 1]);
        }
    }
    let mut out = [Zv::<V>::ZERO; K];
    for k in 0..K {
        normalize(&mut l[k]);
        for v in 0..V {
            store(&mut out[k].0[v], l[k][v]);
        }
    }
    out
}

/// Constant-time table lookup: every entry is read, the one at `idx` kept
/// by a masked move.
#[target_feature(enable = "avx512f")]
#[inline]
fn gather<const V: usize>(table: &[Zv<V>], idx: usize) -> Zv<V> {
    let zero = _mm512_setzero_si512();
    // Opaque to the optimiser: it cannot see that every lane holds the same
    // value, so the per-entry compare stays a per-lane vector mask instead
    // of collapsing into a scalar `idx == e` branch.
    let iv = core::hint::black_box(_mm512_set1_epi64(idx as i64));
    let mut acc = [zero; V];
    for (e, ent) in table.iter().enumerate() {
        let mask = _mm512_cmpeq_epi64_mask(_mm512_set1_epi64(e as i64), iv);
        for v in 0..V {
            acc[v] = _mm512_mask_mov_epi64(acc[v], mask, load(&ent.0[v]));
        }
    }
    let mut out = Zv::<V>::ZERO;
    for v in 0..V {
        store(&mut out.0[v], acc[v]);
    }
    out
}

/// Loads a modulus' digits into a `Zv`.
fn zv_from<const V: usize>(digits: &[u64]) -> Zv<V> {
    let mut z = Zv::<V>::ZERO;
    z.digits_mut().copy_from_slice(&digits[..8 * V]);
    z
}

/// Converts a canonical almost-reduced (`≤ n`) digit vector to limbs and
/// subtracts `n` once if needed.
fn finish<const V: usize>(m: &IfmaModulus, acc: &Zv<V>, out: &mut [Limb]) {
    let l = m.n_limbs.len();
    let mut t = vec![0 as Limb; l];
    from_digits(&acc.digits()[..m.d], &mut t);
    mont_final_sub(&m.n_limbs, &t, 0, &mut out[..l]);
    crate::zeroize::Zeroize::zeroize(&mut t);
}

/// The shared fixed-window ladder (see [`run`]).
#[target_feature(enable = "avx512f,avx512ifma")]
fn ladder<const V: usize, const K: usize>(
    ms: [&IfmaModulus; K],
    jobs: [Job<'_>; K],
    outs: [&mut [Limb]; K],
) {
    let d = ms[0].d;
    let n: [Zv<V>; K] = core::array::from_fn(|k| zv_from(&ms[k].n));
    let rr: [Zv<V>; K] = core::array::from_fn(|k| zv_from(&ms[k].rr));
    let k0: [u64; K] = core::array::from_fn(|k| ms[k].k0);
    let mut one = Zv::<V>::ZERO;
    one.0[0][0] = 1;
    let ones = [&one; K];
    let digits_of = |x: &[Limb]| {
        let mut z = Zv::<V>::ZERO;
        to_digits(x, &mut z.digits_mut()[..d]);
        z
    };
    let mul = |a: [&Zv<V>; K], b: [&Zv<V>; K]| amm::<V, K>(a, b, &n, k0, d);

    // The Montgomery one, R mod n (below 2n).
    let one_m = mul(core::array::from_fn(|k| &rr[k]), ones);
    let (joint, size, width, bits) = match jobs[0] {
        Job::Pow { bits, .. } => (false, 32usize, 5usize, bits),
        Job::Pow2 { bits, .. } => (true, 16, 2, bits),
    };
    let mut tables: [Vec<Zv<V>>; K] = core::array::from_fn(|_| vec![Zv::<V>::ZERO; size]);
    for k in 0..K {
        tables[k][0] = one_m[k];
    }
    // Plain bases → Montgomery form (`base · R² · R⁻¹`).
    let mut plain: [[Zv<V>; 2]; K] = core::array::from_fn(|k| match jobs[k] {
        Job::Pow { base, .. } => [digits_of(base), Zv::ZERO],
        Job::Pow2 { a, b, .. } => [digits_of(a), digits_of(b)],
    });
    let base_m = mul(
        core::array::from_fn(|k| &plain[k][0]),
        core::array::from_fn(|k| &rr[k]),
    );
    for k in 0..K {
        tables[k][1] = base_m[k];
    }
    if !joint {
        // table[i] = base^i.
        for i in 2..size {
            let r = mul(
                core::array::from_fn(|k| &tables[k][i - 1]),
                core::array::from_fn(|k| &tables[k][1]),
            );
            for k in 0..K {
                tables[k][i] = r[k];
            }
        }
    } else {
        // table[i + 4j] = a^i · b^j.
        let b_m = mul(
            core::array::from_fn(|k| &plain[k][1]),
            core::array::from_fn(|k| &rr[k]),
        );
        for k in 0..K {
            tables[k][4] = b_m[k];
        }
        for (dst, src) in [(8usize, 4usize), (12, 8)] {
            let r = mul(
                core::array::from_fn(|k| &tables[k][src]),
                core::array::from_fn(|k| &tables[k][4]),
            );
            for k in 0..K {
                tables[k][dst] = r[k];
            }
        }
        for j in 0..4 {
            for i in 1..4 {
                if j == 0 && i == 1 {
                    continue;
                }
                let e = 4 * j + i;
                let r = mul(
                    core::array::from_fn(|k| &tables[k][e - 1]),
                    core::array::from_fn(|k| &tables[k][1]),
                );
                for k in 0..K {
                    tables[k][e] = r[k];
                }
            }
        }
    }
    for p in plain.iter_mut() {
        wipe_all(p);
    }

    let digit = |k: usize, w: usize| -> usize {
        match jobs[k] {
            Job::Pow { exp, bits, .. } => window(exp, 5 * w, 5, bits),
            Job::Pow2 { x, y, bits, .. } => {
                window(x, 2 * w, 2, bits) | (window(y, 2 * w, 2, bits) << 2)
            }
        }
    };
    let windows = bits.div_ceil(width).max(1);
    let mut w = windows - 1;
    let mut acc: [Zv<V>; K] = core::array::from_fn(|k| gather(&tables[k], digit(k, w)));
    while w > 0 {
        w -= 1;
        for _ in 0..width {
            acc = mul(
                core::array::from_fn(|k| &acc[k]),
                core::array::from_fn(|k| &acc[k]),
            );
        }
        let mut sel: [Zv<V>; K] = core::array::from_fn(|k| gather(&tables[k], digit(k, w)));
        acc = mul(
            core::array::from_fn(|k| &acc[k]),
            core::array::from_fn(|k| &sel[k]),
        );
        wipe_all(&mut sel);
    }
    // Out of the Montgomery domain: a·1·R⁻¹ ≤ n.
    let mut res = mul(core::array::from_fn(|k| &acc[k]), ones);
    for (k, out) in outs.into_iter().enumerate() {
        finish(ms[k], &res[k], out);
    }
    wipe_all(&mut res);
    wipe_all(&mut acc);
    for t in tables.iter_mut() {
        wipe_all(t);
    }
}

#[target_feature(enable = "avx512f,avx512ifma")]
fn pow_public_impl<const V: usize>(m: &IfmaModulus, base: &[Limb], exp: u64, out: &mut [Limb]) {
    let d = m.d;
    let n = [zv_from::<V>(&m.n)];
    let rr = zv_from::<V>(&m.rr);
    let mut one = Zv::<V>::ZERO;
    one.0[0][0] = 1;
    let mul = |a: &Zv<V>, b: &Zv<V>| amm::<V, 1>([a], [b], &n, [m.k0], d)[0];
    let mut acc;
    if exp == 0 {
        acc = mul(&rr, &one);
    } else {
        let mut b = Zv::<V>::ZERO;
        to_digits(base, &mut b.digits_mut()[..d]);
        let mut base_m = mul(&b, &rr);
        b.wipe();
        acc = base_m;
        let bits = 64 - exp.leading_zeros() as usize;
        for i in (0..bits - 1).rev() {
            acc = mul(&acc, &acc);
            if (exp >> i) & 1 == 1 {
                acc = mul(&acc, &base_m);
            }
        }
        base_m.wipe();
    }
    let mut res = mul(&acc, &one);
    finish(m, &res, out);
    res.wipe();
    acc.wipe();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    #[test]
    fn digit_round_trip() {
        let mut s = 7u64;
        for l in [1usize, 2, 7, 16, 17, 32, 51] {
            let x: Vec<Limb> = (0..l).map(|_| splitmix64(&mut s)).collect();
            let d = (64 * l).div_ceil(52);
            let mut dg = vec![0u64; d];
            to_digits(&x, &mut dg);
            assert!(dg.iter().all(|&v| v <= M52));
            let mut back = vec![0 as Limb; l];
            from_digits(&dg, &mut back);
            assert_eq!(back, x);
        }
    }

    /// The carry-lookahead normalisation against a scalar ripple, on lane
    /// patterns built to chain long propagate runs.
    #[test]
    fn normalize_matches_ripple() {
        if !enabled() {
            return;
        }
        #[target_feature(enable = "avx512f")]
        fn run3(lanes: &[u64; 24]) -> [u64; 24] {
            let mut l = [_mm512_setzero_si512(); 3];
            for v in 0..3 {
                l[v] = load(lanes[8 * v..8 * v + 8].try_into().unwrap());
            }
            normalize(&mut l);
            let mut out = [0u64; 24];
            for v in 0..3 {
                store((&mut out[8 * v..8 * v + 8]).try_into().unwrap(), l[v]);
            }
            out
        }
        let mut s = 99u64;
        for round in 0..2000 {
            let mut lanes = [0u64; 24];
            for (j, x) in lanes.iter_mut().enumerate().take(23) {
                let r = splitmix64(&mut s);
                *x = match (round + j) % 4 {
                    0 => M52,
                    1 => r >> 6,
                    2 => M52 - (r & 1),
                    _ => r & M52,
                };
            }
            // Scalar reference: ripple the carries.
            let mut want = [0u64; 24];
            let mut carry: u128 = 0;
            for j in 0..24 {
                let t = lanes[j] as u128 + carry;
                want[j] = (t as u64) & M52;
                carry = t >> 52;
            }
            // SAFETY: `enabled()` checked AVX-512F above.
            let got = unsafe { run3(&lanes) };
            assert_eq!(got, want, "round {round}");
        }
    }
}
