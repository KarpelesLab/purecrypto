//! Constant-time Montgomery modular arithmetic for [`BoxedUint`].
//!
//! A runtime-width port of [`MontModulus`](super::MontModulus): same CIOS
//! multiplication and square-and-multiply-always exponentiation, over
//! `Vec<Limb>` scratch so the modulus width is chosen at runtime.

use super::boxed::{BoxedUint, adc_limbs, sbb_limbs, select_limbs};
use super::montgomery::{inv_mod_2_64, mont_mul_kernel, mont_sqr_kernel};
use super::uint::{Limb, adc, sbb};
use crate::ct::{Choice, ConstantTimeEq};
use alloc::vec;
use alloc::vec::Vec;

#[cfg(target_arch = "x86_64")]
use super::ifma::{self, IfmaModulus, Job};

/// Best-effort wipe of a secret-dependent `Vec<Limb>` scratch buffer.
///
/// Mirrors [`BoxedUint::zeroize`](super::boxed::BoxedUint): the writes are
/// unconditional (no data-dependent branch, so the constant-time property is
/// preserved) and [`crate::zeroize::Zeroize`]'s volatile stores plus compiler
/// fence keep LLVM from eliding them as dead stores.
#[inline]
fn zeroize_limbs(v: &mut [Limb]) {
    crate::zeroize::Zeroize::zeroize(v);
}

/// `(a + b) mod n` for equal-length `a, b < n`.
fn add_mod_limbs(n: &[Limb], a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let (sum, carry) = adc_limbs(a, b, 0);
    let (diff, borrow) = sbb_limbs(&sum, n, 0);
    let subtract = carry | (borrow ^ 1);
    select_limbs(&diff, &sum, Choice::from(subtract as u8))
}

/// `out ← (a + b) mod n` for equal-length `a, b < n`, where `a` is consumed as
/// the sum buffer — the allocation-free form of [`add_mod_limbs`].
fn add_mod_in_place(n: &[Limb], a: &mut [Limb], b: &[Limb], out: &mut [Limb]) {
    let mut c: Limb = 0;
    for (x, &y) in a.iter_mut().zip(b) {
        let (s, co) = adc(*x, y, c);
        *x = s;
        c = co;
    }
    let mut bo: Limb = 0;
    for j in 0..n.len() {
        let (d, b) = sbb(a[j], n[j], bo);
        out[j] = d;
        bo = b;
    }
    // Keep the difference when the add carried or the sum is >= n; else
    // take the sum back. One opaque mask for the whole select.
    let subtract = Choice::from((c | (bo ^ 1)) as u8);
    crate::ct::assign_limbs(&mut out[..n.len()], &a[..n.len()], !subtract);
}

/// `(a - b) mod n` for equal-length `a, b < n`.
fn sub_mod_limbs(n: &[Limb], a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let (diff, borrow) = sbb_limbs(a, b, 0);
    let (wrapped, _) = adc_limbs(&diff, n, 0);
    select_limbs(&wrapped, &diff, Choice::from(borrow as u8))
}

/// Runtime-width Montgomery parameters for an odd modulus.
///
/// The modulus is frequently a *secret*: the RSA CRT path builds one context
/// per prime factor, so `n` here is `p` or `q`. Consequently this type wipes
/// its buffers on drop and its `Debug` never prints them.
#[derive(Clone)]
pub struct BoxedMontModulus {
    n: Vec<Limb>,
    n_prime: Limb,
    r2: Vec<Limb>,
    limbs: usize,
    /// The AVX-512 IFMA form of the modulus, built when the CPU has IFMA
    /// (see [`super::ifma`]); the exponentiations use it whenever the
    /// portable-dispatch override is off.
    #[cfg(target_arch = "x86_64")]
    ifma: Option<IfmaModulus>,
}

// The modulus may be a secret prime (RSA CRT), so never format the limbs:
// the derived `Debug` printed `n` (= p or q) and `r2` into any log line that
// formatted a key-bearing struct. The impl is kept — dropping the trait would
// be a breaking change for downstream code that derives `Debug` on a type
// holding one.
impl core::fmt::Debug for BoxedMontModulus {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BoxedMontModulus")
            .field("limbs", &self.limbs)
            .finish_non_exhaustive()
    }
}

// Best-effort wipe: `n` and `r2` are secret whenever the modulus is (the RSA
// CRT contexts hold `p` and `q`), and `Vec<Limb>` returns its buffer to the
// allocator with the limbs intact otherwise.
impl Drop for BoxedMontModulus {
    fn drop(&mut self) {
        zeroize_limbs(&mut self.n);
        zeroize_limbs(&mut self.r2);
        crate::zeroize::Zeroize::zeroize(&mut self.n_prime);
    }
}

impl crate::zeroize::ZeroizeOnDrop for BoxedMontModulus {}

impl BoxedMontModulus {
    /// Builds parameters for an odd `modulus`.
    ///
    /// # Panics
    /// Panics if `modulus` is even or zero.
    pub fn new(modulus: &BoxedUint) -> Self {
        // Zero is even, so the odd-modulus assertion below also catches it;
        // we check explicitly first to give a precise diagnostic and to
        // document that a zero modulus is rejected rather than silently
        // producing a meaningless parameter set.
        //
        // The modulus may be secret (an RSA prime, a Miller-Rabin
        // candidate): both checks are branch-free until their verdict, which
        // is public — it is a panic.
        assert!(
            !modulus.ct_is_zero().declassify(),
            "BoxedMontModulus::new: modulus must be nonzero"
        );
        let limbs = modulus.significant_limbs();
        let n = modulus.limbs_resized(limbs);
        assert!(
            crate::ct::declassify_value(n[0] & 1 == 1),
            "Montgomery modulus must be odd"
        );
        let n_prime = inv_mod_2_64(n[0]).wrapping_neg();

        let mut m = BoxedMontModulus {
            n,
            n_prime,
            r2: vec![0 as Limb; limbs],
            limbs,
            #[cfg(target_arch = "x86_64")]
            ifma: None,
        };
        m.r2 = m.compute_r2();
        #[cfg(target_arch = "x86_64")]
        if ifma::supported() {
            // The bit length is public (see `compute_r2`).
            let top = crate::ct::declassify_value(m.n[limbs - 1].leading_zeros()) as usize;
            let bits = 64 * limbs - top;
            m.ifma = IfmaModulus::new(&m.n, bits, |e| {
                // 2^e mod n through the portable Horner reduction.
                let mut x = vec![0 as Limb; e / 64 + 1];
                x[e / 64] = 1 << (e % 64);
                let r = m.reduce(&BoxedUint::from_limbs(x));
                r.as_limbs().to_vec()
            });
        }
        m
    }

    /// The IFMA parameters, when present and the kernels may run now.
    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn ifma(&self) -> Option<&IfmaModulus> {
        self.ifma.as_ref().filter(|_| ifma::enabled())
    }

    /// Runs one exponentiation job on the IFMA backend, if available.
    #[cfg(target_arch = "x86_64")]
    fn ifma_job(&self, job: Job<'_>) -> Option<BoxedUint> {
        let im = self.ifma()?;
        let mut out = vec![0 as Limb; self.limbs];
        ifma::run([im], [job], [&mut out]);
        Some(BoxedUint::from_limbs(out))
    }

    /// `R² mod n` for `R = 2^(64·l)`, `l = limbs`, without the `2·64·l`
    /// modular doublings of the textbook loop (and without an allocation
    /// per step).
    ///
    /// Writing `M(x) = x·R mod n` for the Montgomery form, a modular doubling
    /// maps `M(2^e)` to `M(2^(e+1))` and a Montgomery squaring maps it to
    /// `M(2^(2e))`; the target `R² = M(2^(64·l))`. Starting from
    /// `2^(bits−1)` — below `n`, which has that bit set — `64·l − bits + 1 + l`
    /// doublings reach `M(2^l)`, and six squarings (`64 = 2^6`) reach
    /// `M(2^(64·l))`. Six is about where another squaring stops paying for
    /// the doublings it replaces (a doubling is ~3 limb operations, a
    /// squaring ~l² multiplies): `l + 1` doublings for a full-width modulus
    /// is a fraction of one squaring, against the 65 doublings and
    /// `log₂(64·l)` (11 at 2048 bits) squarings of the previous chain.
    ///
    /// Constant time in `n`: the only branches are on `limbs` and on the
    /// bit length of `n`, both public by the width convention documented at
    /// [`BoxedUint::significant_limbs`] (the bit length is declassified for
    /// the taint harness below); every doubling and squaring is the
    /// masked-select arithmetic used everywhere else.
    fn compute_r2(&self) -> Vec<Limb> {
        let l = self.limbs;
        // The bit length of a modulus is public (an RSA prime's is fixed by
        // the key size, a group prime's by the group); declassified, like
        // the limb count, so the doubling count may depend on it.
        let top = crate::ct::declassify_value(self.n[l - 1].leading_zeros()) as usize;
        let bits = 64 * l - top;
        let mut x = vec![0 as Limb; l];
        x[(bits - 1) / 64] = 1 << ((bits - 1) % 64);
        let mut tmp = vec![0 as Limb; 2 * l];
        for _ in 0..(64 * l - bits + 1 + l) {
            self.double_in_place(&mut x, &mut tmp);
        }
        let mut out = vec![0 as Limb; l];
        for _ in 0..6 {
            self.mont_sqr_to(&x, &mut tmp, &mut out);
            core::mem::swap(&mut x, &mut out);
        }
        // The intermediates are powers of two mod `n` — functions of the
        // (possibly secret) modulus — so scrub them like the CIOS scratch.
        zeroize_limbs(&mut tmp);
        zeroize_limbs(&mut out);
        x
    }

    /// `x ← 2x mod n` for `x < n`, using `tmp` (at least `limbs` long) as the
    /// trial-subtraction buffer. Same masked conditional subtraction as
    /// [`add_mod_limbs`], minus its three allocations.
    fn double_in_place(&self, x: &mut [Limb], tmp: &mut [Limb]) {
        let mut carry: Limb = 0;
        for w in x.iter_mut() {
            let next = *w >> 63;
            *w = (*w << 1) | carry;
            carry = next;
        }
        let mut bo: Limb = 0;
        for j in 0..self.limbs {
            let (d, b) = sbb(x[j], self.n[j], bo);
            tmp[j] = d;
            bo = b;
        }
        // Subtract when the shift overflowed or the shifted value is >= n.
        let ge = Choice::from((carry | (bo ^ 1)) as u8);
        crate::ct::assign_limbs(&mut x[..self.limbs], &tmp[..self.limbs], ge);
    }

    /// The modulus width in limbs.
    #[inline]
    pub fn limbs(&self) -> usize {
        self.limbs
    }

    /// CIOS Montgomery multiplication of two `limbs`-wide values into `out`,
    /// with caller-provided scratch `t` (at least `limbs` limbs) — no
    /// allocation, so the exponentiation ladders can reuse two buffers
    /// across their thousands of multiplies instead of hitting the allocator
    /// on each one. The arithmetic is the shared
    /// [`mont_mul_kernel`](super::montgomery::mont_mul_kernel) (merged CIOS
    /// rows, two per pass).
    ///
    /// `out` may alias `a` and/or `b`: the accumulation only reads them, and
    /// `out` is written exclusively in the final-subtraction step, after the
    /// last read. (Rust's borrow rules forbid literal aliasing anyway;
    /// callers ping-pong two buffers and `mem::swap`.) `t` must not alias
    /// anything.
    #[inline]
    fn mont_mul_to(&self, a: &[Limb], b: &[Limb], t: &mut [Limb], out: &mut [Limb]) {
        mont_mul_kernel(&self.n, self.n_prime, a, b, t, out);
    }

    /// Montgomery squaring of a `limbs`-wide value into `out`, with
    /// caller-provided scratch `t` of at least `2 * limbs` limbs: the shared
    /// [`mont_sqr_kernel`](super::montgomery::mont_sqr_kernel), bit-identical
    /// to `mont_mul_to(a, a, ..)` at roughly half the multiplies.
    ///
    /// `out` may alias `a`: `a` is only read while the square is accumulated
    /// into `t`, and `out` is written exclusively in the final-subtraction
    /// step. `t` must not alias anything.
    #[inline]
    fn mont_sqr_to(&self, a: &[Limb], t: &mut [Limb], out: &mut [Limb]) {
        mont_sqr_kernel(&self.n, self.n_prime, a, t, out);
    }

    /// CIOS Montgomery multiplication of two `limbs`-wide values.
    fn mont_mul_limbs(&self, a: &[Limb], b: &[Limb]) -> Vec<Limb> {
        let mut t = vec![0 as Limb; self.limbs];
        let mut out = vec![0 as Limb; self.limbs];
        self.mont_mul_to(a, b, &mut t, &mut out);
        // Scrub the secret-dependent CIOS scratch before it drops.
        zeroize_limbs(&mut t);
        out
    }

    fn to_mont_limbs(&self, x: &[Limb]) -> Vec<Limb> {
        self.mont_mul_limbs(x, &self.r2)
    }

    fn demont_limbs(&self, x: &[Limb]) -> Vec<Limb> {
        let mut one = vec![0 as Limb; self.limbs];
        one[0] = 1;
        self.mont_mul_limbs(x, &one)
    }

    /// The modulus as a [`BoxedUint`].
    pub fn modulus(&self) -> BoxedUint {
        BoxedUint::from_limbs(self.n.clone())
    }

    /// Converts a plain value `< n` into the Montgomery domain.
    pub fn to_mont(&self, x: &BoxedUint) -> BoxedUint {
        BoxedUint::from_limbs(self.to_mont_limbs(&x.limbs_resized(self.limbs)))
    }

    /// Converts a Montgomery-domain value back to a plain value.
    pub fn from_mont(&self, x: &BoxedUint) -> BoxedUint {
        BoxedUint::from_limbs(self.demont_limbs(&x.limbs_resized(self.limbs)))
    }

    /// Montgomery-domain multiply: given `a, b` in Montgomery form, returns
    /// `a·b` in Montgomery form (a single CIOS reduction).
    pub fn mont_mul(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        BoxedUint::from_limbs(
            self.mont_mul_limbs(&a.limbs_resized(self.limbs), &b.limbs_resized(self.limbs)),
        )
    }

    /// Reduces `x` (of any width) modulo `n` — the result is `limbs` wide.
    ///
    /// Horner over `limbs`-sized chunks `c_i` of `x = Σ c_i·R^i` in the
    /// Montgomery domain: `M(c) = mont_mul(c, R²)` holds for *any* `c < R`
    /// (CIOS only needs one operand below `n` for its `< 2n` output bound),
    /// and `M(acc·R) = mont_mul(M(acc), R²)`, so each chunk costs two
    /// Montgomery multiplications plus a modular addition, and one final
    /// `from_mont` undoes the domain. For the RSA CRT split (a 2048-bit value
    /// mod a 1024-bit prime) that is five half-width multiplies instead of
    /// the 2048 trial subtractions of [`BoxedUint::reduce`].
    ///
    /// Constant time: the chunk count and every loop bound are functions of
    /// the (public) widths of `x` and `n`; the arithmetic is the masked CIOS
    /// and add/select code, so neither the value of `x` nor of a secret `n`
    /// steers anything.
    pub fn reduce(&self, x: &BoxedUint) -> BoxedUint {
        let l = self.limbs;
        let xl = x.as_limbs();
        let chunks = xl.len().div_ceil(l);
        let mut t = vec![0 as Limb; l];
        let mut acc = vec![0 as Limb; l];
        let mut c = vec![0 as Limb; l];
        let mut cm = vec![0 as Limb; l];
        for i in (0..chunks).rev() {
            for (j, cj) in c.iter_mut().enumerate() {
                *cj = xl.get(i * l + j).copied().unwrap_or(0);
            }
            self.mont_mul_to(&c, &self.r2, &mut t, &mut cm);
            if i + 1 == chunks {
                core::mem::swap(&mut acc, &mut cm);
            } else {
                // acc ← M(prefix·R), then add M(c_i).
                self.mont_mul_to(&acc, &self.r2, &mut t, &mut c);
                add_mod_in_place(&self.n, &mut c, &cm, &mut acc);
            }
        }
        // from_mont: multiply by plain 1 (`cm` reused as the constant).
        cm.fill(0);
        cm[0] = 1;
        self.mont_mul_to(&acc, &cm, &mut t, &mut c);
        zeroize_limbs(&mut t);
        zeroize_limbs(&mut acc);
        zeroize_limbs(&mut cm);
        BoxedUint::from_limbs(c)
    }

    /// Montgomery-domain squaring: given `a` in Montgomery form, returns `a²`
    /// in Montgomery form — [`mont_mul`](Self::mont_mul)`(a, a)` with the
    /// dedicated squaring's roughly halved multiply count.
    pub fn mont_sqr(&self, a: &BoxedUint) -> BoxedUint {
        let mut t = vec![0 as Limb; 2 * self.limbs];
        let mut out = vec![0 as Limb; self.limbs];
        self.mont_sqr_to(&a.limbs_resized(self.limbs), &mut t, &mut out);
        zeroize_limbs(&mut t);
        BoxedUint::from_limbs(out)
    }

    /// Returns `(a * b) mod n` for `a, b < n`.
    pub fn mul_mod(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        let a = a.limbs_resized(self.limbs);
        let b = b.limbs_resized(self.limbs);
        let t = self.mont_mul_limbs(&a, &b);
        BoxedUint::from_limbs(self.mont_mul_limbs(&t, &self.r2))
    }

    /// Computes `base^exp mod n` in constant time (fixed-window
    /// square-and-multiply-always over every bit of `exp`'s storage).
    ///
    /// The exponent is zero-padded to at least `self.limbs` 64-bit limbs, so
    /// the loop runs over `max(self.limbs, exp.limbs())` limbs: the storage
    /// width, which is public, never the position of the exponent's top set
    /// bit. The RSA case (`d < n`) is exactly `self.limbs`; a wider exponent
    /// keeps every bit rather than being silently truncated to
    /// `exp mod 2^(64·self.limbs)`. A caller whose secret exponent has a
    /// smaller public bound (a DH exponent of `priv_bits`, a DSA nonce below
    /// `q`) should use [`pow_bits`](Self::pow_bits) instead of paying for the
    /// padding.
    pub fn pow(&self, base: &BoxedUint, exp: &BoxedUint) -> BoxedUint {
        // `exp.limbs()` (the storage width) is public; `significant_limbs()`
        // would scan the secret exponent's leading zero limbs.
        let exp_width = exp.limbs().max(self.limbs);
        self.pow_bits(base, exp, 64 * exp_width)
    }

    /// Computes `base^exp mod n` in constant time for a secret `exp` known to
    /// be below `2^bits`, where `bits` is a **public** bound (the width of the
    /// group order, a configured exponent size): the ladder runs
    /// `⌈bits/4⌉` windows, independent of the exponent's value. Bits of `exp`
    /// at or above `bits` are ignored, so the bound must hold — `exp < 2^bits`
    /// is the caller's precondition.
    ///
    /// Fixed 4-bit window: precompute `base^0 … base^15` (Montgomery form)
    /// once, then consume the exponent four bits at a time — four squarings
    /// and one multiply by the window's value per nibble. The table value is
    /// chosen by scanning all 16 entries with a constant-time select (no
    /// secret-indexed memory access) and the per-nibble multiply is
    /// unconditional, so the operation sequence is a function of `bits`
    /// only, leaking nothing about `base` or the exponent's bits.
    ///
    /// On x86_64 CPUs with AVX-512 IFMA the same ladder runs on the 52-bit
    /// radix kernels of [`super::ifma`] (5-bit windows, 32-entry table), with
    /// the identical constant-time structure.
    pub fn pow_bits(&self, base: &BoxedUint, exp: &BoxedUint, bits: usize) -> BoxedUint {
        #[cfg(target_arch = "x86_64")]
        {
            let l = self.limbs;
            let mut b = base.limbs_resized(l);
            let r = self.ifma_job(Job::Pow {
                base: &b,
                exp: exp.as_limbs(),
                bits,
            });
            zeroize_limbs(&mut b);
            if let Some(r) = r {
                return r;
            }
        }
        self.pow_bits_portable(base, exp, bits)
    }

    /// The portable (64-bit-limb CIOS) body of [`pow_bits`](Self::pow_bits).
    fn pow_bits_portable(&self, base: &BoxedUint, exp: &BoxedUint, bits: usize) -> BoxedUint {
        let l = self.limbs;
        // Flat 16-entry table, entry i at `table[i*l..(i+1)*l]`: base^i in
        // Montgomery form (entry 0 is R mod n, the Montgomery 1).
        let mut table = vec![0 as Limb; 16 * l];
        let mut t = vec![0 as Limb; l];
        let mut one = vec![0 as Limb; l];
        one[0] = 1;
        self.mont_mul_to(&one, &self.r2, &mut t, &mut table[..l]);
        self.mont_mul_to(
            &base.limbs_resized(l),
            &self.r2,
            &mut t,
            &mut table[l..2 * l],
        );
        for i in 2..16 {
            let (done, rest) = table.split_at_mut(i * l);
            self.mont_mul_to(
                &done[(i - 1) * l..],
                &done[l..2 * l],
                &mut t,
                &mut rest[..l],
            );
        }
        let exp = exp.as_limbs();
        let windows = bits.div_ceil(4).max(1);
        // Nibble `w` of the exponent; positions past its storage read as 0.
        // The limb index and shift are public loop quantities.
        let digit = |w: usize| (exp.get(w / 16).copied().unwrap_or(0) >> (4 * (w % 16))) & 0xf;
        let result = self.window_ladder(&table, windows, 4, |w| digit(w) as usize);
        zeroize_limbs(&mut table);
        zeroize_limbs(&mut t);
        result
    }

    /// Computes `a^x · b^y mod n` in constant time, for secret `x, y` below
    /// `2^bits` (`bits` public, as in [`pow_bits`](Self::pow_bits)), with one
    /// shared chain of squarings (Straus/Shamir): a 2-bit joint window over
    /// the table `a^i·b^j`, `i, j ∈ 0..4`, so `bits` squarings plus `bits/2`
    /// multiplies instead of the `2·bits` squarings two separate ladders
    /// would spend.
    ///
    /// The RSA CRT half uses it to fold the Fermat inverse of the blinder
    /// (`r^(p−2)`) into the exponentiation it unblinds. Same constant-time
    /// discipline as `pow_bits`: the 16-entry table is gathered by a full
    /// masked scan and every window multiplies unconditionally.
    pub fn pow2_bits(
        &self,
        a: &BoxedUint,
        x: &BoxedUint,
        b: &BoxedUint,
        y: &BoxedUint,
        bits: usize,
    ) -> BoxedUint {
        #[cfg(target_arch = "x86_64")]
        {
            let l = self.limbs;
            let (mut al, mut bl) = (a.limbs_resized(l), b.limbs_resized(l));
            let r = self.ifma_job(Job::Pow2 {
                a: &al,
                x: x.as_limbs(),
                b: &bl,
                y: y.as_limbs(),
                bits,
            });
            zeroize_limbs(&mut al);
            zeroize_limbs(&mut bl);
            if let Some(r) = r {
                return r;
            }
        }
        self.pow2_bits_portable(a, x, b, y, bits)
    }

    /// The portable body of [`pow2_bits`](Self::pow2_bits).
    fn pow2_bits_portable(
        &self,
        a: &BoxedUint,
        x: &BoxedUint,
        b: &BoxedUint,
        y: &BoxedUint,
        bits: usize,
    ) -> BoxedUint {
        let l = self.limbs;
        // Flat table, entry i + 4j = a^i · b^j (Montgomery form) at
        // `table[(i + 4j)*l..]`.
        let mut table = vec![0 as Limb; 16 * l];
        let mut t = vec![0 as Limb; l];
        let mut one = vec![0 as Limb; l];
        one[0] = 1;
        self.mont_mul_to(&one, &self.r2, &mut t, &mut table[..l]);
        self.mont_mul_to(&a.limbs_resized(l), &self.r2, &mut t, &mut table[l..2 * l]);
        self.mont_mul_to(
            &b.limbs_resized(l),
            &self.r2,
            &mut t,
            &mut table[4 * l..5 * l],
        );
        // Entry 8 = b², entry 12 = b³.
        for (dst, src) in [(8usize, 4usize), (12, 8)] {
            let (done, rest) = table.split_at_mut(dst * l);
            self.mont_mul_to(
                &done[src * l..(src + 1) * l],
                &done[4 * l..5 * l],
                &mut t,
                &mut rest[..l],
            );
        }
        // Within each row j: entry 4j+i = entry 4j+i−1 · a.
        for j in 0..4 {
            for i in 1..4 {
                if j == 0 && i == 1 {
                    continue;
                }
                let k = 4 * j + i;
                let (done, rest) = table.split_at_mut(k * l);
                self.mont_mul_to(
                    &done[(k - 1) * l..],
                    &done[l..2 * l],
                    &mut t,
                    &mut rest[..l],
                );
            }
        }
        let (x, y) = (x.as_limbs(), y.as_limbs());
        let windows = bits.div_ceil(2).max(1);
        let two_bits =
            |e: &[Limb], w: usize| (e.get(w / 32).copied().unwrap_or(0) >> (2 * (w % 32))) & 3;
        let result = self.window_ladder(&table, windows, 2, |w| {
            (two_bits(x, w) | (two_bits(y, w) << 2)) as usize
        });
        zeroize_limbs(&mut table);
        zeroize_limbs(&mut t);
        result
    }

    /// The shared fixed-window ladder: `windows` windows of `width` bits,
    /// most significant first, where `digit(w)` is the (secret) table index
    /// of window `w`. `table` is flat, `limbs` limbs per entry. The
    /// accumulator starts at the top window's entry (saving the squarings
    /// of 1); each later window squares `width` times and multiplies by its
    /// entry. Entries are gathered by a full masked scan of `table` — the
    /// index comparison goes through `ct_eq` (branch-free by construction)
    /// rather than a `==` the compiler may lower to a branch on the secret,
    /// one opaque mask per entry OR-accumulated across its limbs — and
    /// every multiply is unconditional, so the operation sequence depends
    /// only on `windows` and `width`.
    fn window_ladder(
        &self,
        table: &[Limb],
        windows: usize,
        width: usize,
        digit: impl Fn(usize) -> usize,
    ) -> BoxedUint {
        let l = self.limbs;
        // Reused scratch: accumulator `t` (sized 2·limbs for the squaring's
        // full product; `mont_mul_to` uses its low half), ping-pong output
        // `nxt`, and the gather buffer `sel`. All hold base-derived secrets
        // during the loop and are scrubbed at the end.
        let mut t = vec![0 as Limb; 2 * l];
        let mut nxt = vec![0 as Limb; l];
        let mut sel = vec![0 as Limb; l];
        let gather = |sel: &mut [Limb], idx: usize| {
            sel.fill(0);
            for (j, entry) in table.chunks_exact(l).enumerate() {
                let mask = crate::ct::limb_mask(j.ct_eq(&idx));
                for (s, e) in sel.iter_mut().zip(entry) {
                    *s |= e & mask;
                }
            }
        };
        let mut w = windows - 1;
        let mut acc = vec![0 as Limb; l];
        gather(&mut acc, digit(w));
        while w > 0 {
            w -= 1;
            for _ in 0..width {
                self.mont_sqr_to(&acc, &mut t, &mut nxt);
                core::mem::swap(&mut acc, &mut nxt);
            }
            gather(&mut sel, digit(w));
            self.mont_mul_to(&acc, &sel, &mut t, &mut nxt);
            core::mem::swap(&mut acc, &mut nxt);
        }
        // Construct the result first (a fresh Vec from `demont_limbs`), then
        // scrub the accumulator and scratch.
        let result = BoxedUint::from_limbs(self.demont_limbs(&acc));
        zeroize_limbs(&mut acc);
        zeroize_limbs(&mut t);
        zeroize_limbs(&mut nxt);
        zeroize_limbs(&mut sel);
        result
    }

    /// Computes `base^exp mod n` for a **public** exponent, sized to the
    /// exponent's actual bit length rather than the modulus width.
    ///
    /// Variable time in `exp` only — **`exp` must be public** (an RSA public
    /// exponent, a DSA verification scalar, a group order); never call it
    /// with a secret exponent, use [`pow`](Self::pow) /
    /// [`pow_bits`](Self::pow_bits) for those. The sequence of squarings and
    /// multiplications, and the table entry each multiply reads, are
    /// functions of `exp` alone, so a secret `base` is still protected:
    /// nothing branches on or is indexed by a base-derived value.
    ///
    /// Exponents up to 64 bits (RSA `e = 65537`: 16 squarings and one
    /// multiply) run left-to-right binary, multiplying only on set bits;
    /// wider ones a fixed 4-bit window that skips zero windows.
    pub fn pow_public(&self, base: &BoxedUint, exp: &BoxedUint) -> BoxedUint {
        #[cfg(target_arch = "x86_64")]
        if exp.bit_len() <= 64
            && let Some(im) = self.ifma()
        {
            let l = self.limbs;
            let mut b = base.limbs_resized(l);
            let mut out = vec![0 as Limb; l];
            let e = exp.as_limbs().first().copied().unwrap_or(0);
            ifma::pow_public_u64(im, &b, e, &mut out);
            zeroize_limbs(&mut b);
            return BoxedUint::from_limbs(out);
        }
        self.pow_public_portable(base, exp)
    }

    /// The portable body of [`pow_public`](Self::pow_public).
    fn pow_public_portable(&self, base: &BoxedUint, exp: &BoxedUint) -> BoxedUint {
        let l = self.limbs;
        let bits = exp.bit_len();
        if bits == 0 {
            // base^0 = 1.
            let mut one = vec![0 as Limb; l];
            one[0] = 1;
            return BoxedUint::from_limbs(self.demont_limbs(&self.to_mont_limbs(&one)));
        }
        let exp = exp.as_limbs();
        let bit = |i: usize| (exp[i / 64] >> (i % 64)) & 1 == 1;
        let mut base_m = self.to_mont_limbs(&base.limbs_resized(l));
        let mut t = vec![0 as Limb; 2 * l];
        let mut nxt = vec![0 as Limb; l];
        let mut table: Vec<Vec<Limb>> = Vec::new();
        let mut acc;
        if bits <= 64 {
            acc = base_m.clone();
            for i in (0..bits - 1).rev() {
                self.mont_sqr_to(&acc, &mut t, &mut nxt);
                core::mem::swap(&mut acc, &mut nxt);
                if bit(i) {
                    self.mont_mul_to(&acc, &base_m, &mut t, &mut nxt);
                    core::mem::swap(&mut acc, &mut nxt);
                }
            }
        } else {
            // table[i] = base^i for i in 1..16 (index 0 is never read).
            table.push(Vec::new());
            table.push(base_m.clone());
            for i in 2..16 {
                table.push(self.mont_mul_limbs(&table[i - 1], &table[1]));
            }
            let digit = |w: usize| ((exp[w / 16] >> (4 * (w % 16))) & 0xf) as usize;
            let mut w = (bits - 1) / 4;
            acc = table[digit(w)].clone(); // the top window is nonzero
            while w > 0 {
                w -= 1;
                for _ in 0..4 {
                    self.mont_sqr_to(&acc, &mut t, &mut nxt);
                    core::mem::swap(&mut acc, &mut nxt);
                }
                let d = digit(w);
                if d != 0 {
                    self.mont_mul_to(&acc, &table[d], &mut t, &mut nxt);
                    core::mem::swap(&mut acc, &mut nxt);
                }
            }
        }
        // `acc` and the table still hold base-derived values even though the
        // exponent is public.
        let result = BoxedUint::from_limbs(self.demont_limbs(&acc));
        zeroize_limbs(&mut base_m);
        zeroize_limbs(&mut acc);
        zeroize_limbs(&mut t);
        zeroize_limbs(&mut nxt);
        for entry in table.iter_mut() {
            zeroize_limbs(entry);
        }
        result
    }

    /// Two independent constant-time exponentiations, `base_a^exp_a mod a`
    /// and `base_b^exp_b mod b`, each as [`pow_bits`](Self::pow_bits) with
    /// the same public bound `bits`. On the IFMA backend, two moduli of the
    /// same width run in lock step (the RSA CRT halves); otherwise this is
    /// two `pow_bits` calls.
    #[cfg_attr(not(feature = "rsa"), allow(dead_code))]
    pub(crate) fn pow_bits_pair(
        ma: &Self,
        base_a: &BoxedUint,
        exp_a: &BoxedUint,
        mb: &Self,
        base_b: &BoxedUint,
        exp_b: &BoxedUint,
        bits: usize,
    ) -> (BoxedUint, BoxedUint) {
        #[cfg(target_arch = "x86_64")]
        if let (Some(ia), Some(ib)) = (ma.ifma(), mb.ifma())
            && ia.pairs_with(ib)
        {
            let (mut ba, mut bb) = (
                base_a.limbs_resized(ma.limbs),
                base_b.limbs_resized(mb.limbs),
            );
            let mut oa = vec![0 as Limb; ma.limbs];
            let mut ob = vec![0 as Limb; mb.limbs];
            ifma::run(
                [ia, ib],
                [
                    Job::Pow {
                        base: &ba,
                        exp: exp_a.as_limbs(),
                        bits,
                    },
                    Job::Pow {
                        base: &bb,
                        exp: exp_b.as_limbs(),
                        bits,
                    },
                ],
                [&mut oa, &mut ob],
            );
            zeroize_limbs(&mut ba);
            zeroize_limbs(&mut bb);
            return (BoxedUint::from_limbs(oa), BoxedUint::from_limbs(ob));
        }
        (
            ma.pow_bits(base_a, exp_a, bits),
            mb.pow_bits(base_b, exp_b, bits),
        )
    }

    /// Two independent [`pow2_bits`](Self::pow2_bits), run in lock step on
    /// the IFMA backend when the moduli have the same width.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(not(feature = "rsa"), allow(dead_code))]
    pub(crate) fn pow2_bits_pair(
        ma: &Self,
        (a1, x1, b1, y1): (&BoxedUint, &BoxedUint, &BoxedUint, &BoxedUint),
        mb: &Self,
        (a2, x2, b2, y2): (&BoxedUint, &BoxedUint, &BoxedUint, &BoxedUint),
        bits: usize,
    ) -> (BoxedUint, BoxedUint) {
        #[cfg(target_arch = "x86_64")]
        if let (Some(ia), Some(ib)) = (ma.ifma(), mb.ifma())
            && ia.pairs_with(ib)
        {
            let mut ins = [
                a1.limbs_resized(ma.limbs),
                b1.limbs_resized(ma.limbs),
                a2.limbs_resized(mb.limbs),
                b2.limbs_resized(mb.limbs),
            ];
            let mut oa = vec![0 as Limb; ma.limbs];
            let mut ob = vec![0 as Limb; mb.limbs];
            ifma::run(
                [ia, ib],
                [
                    Job::Pow2 {
                        a: &ins[0],
                        x: x1.as_limbs(),
                        b: &ins[1],
                        y: y1.as_limbs(),
                        bits,
                    },
                    Job::Pow2 {
                        a: &ins[2],
                        x: x2.as_limbs(),
                        b: &ins[3],
                        y: y2.as_limbs(),
                        bits,
                    },
                ],
                [&mut oa, &mut ob],
            );
            for v in ins.iter_mut() {
                zeroize_limbs(v);
            }
            return (BoxedUint::from_limbs(oa), BoxedUint::from_limbs(ob));
        }
        (
            ma.pow2_bits(a1, x1, b1, y1, bits),
            mb.pow2_bits(a2, x2, b2, y2, bits),
        )
    }

    /// Returns `(a + b) mod n`.
    pub fn add_mod(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        BoxedUint::from_limbs(add_mod_limbs(
            &self.n,
            &a.limbs_resized(self.limbs),
            &b.limbs_resized(self.limbs),
        ))
    }

    /// Returns `(a - b) mod n`.
    pub fn sub_mod(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        BoxedUint::from_limbs(sub_mod_limbs(
            &self.n,
            &a.limbs_resized(self.limbs),
            &b.limbs_resized(self.limbs),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::{MontModulus, Uint};

    /// The modulus is a secret whenever it is an RSA prime factor (the CRT
    /// path builds one context per prime), so `Debug` must not print the
    /// limbs — the derived impl used to dump `n` and `r2`.
    #[test]
    fn debug_does_not_print_the_modulus() {
        let modulus = BoxedUint::from_be_bytes(&[0xC0, 0x05, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89]);
        let m = BoxedMontModulus::new(&modulus);
        let s = alloc::format!("{m:?}");
        assert!(!s.contains("13836218847371372169"), "leaked n: {s}");
        for limb in m.n.iter().chain(m.r2.iter()) {
            assert!(
                !s.contains(&alloc::format!("{limb}")),
                "Debug leaked a limb: {s}"
            );
        }
    }

    #[test]
    fn pow_public_matches_pow() {
        // The public-exponent modexp must return exactly the same value as the
        // constant-time `pow` for every (base, exp); it only changes timing.
        let modulus = BoxedUint::from_be_bytes(&[
            0xC0, 0x05, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x00, 0x11, 0x22,
            0x33, 0x45,
        ]); // odd 128-bit
        let m = BoxedMontModulus::new(&modulus);
        let exps: [u64; 7] = [0, 1, 2, 3, 65537, 0x1_0001, u32::MAX as u64];
        for be in 1u64..=9 {
            let base = BoxedUint::from_u64(be.wrapping_mul(0x9E37_79B9));
            for &e in &exps {
                let exp = BoxedUint::from_u64(e);
                assert_eq!(
                    m.pow(&base, &exp),
                    m.pow_public(&base, &exp),
                    "base={be} e={e}"
                );
            }
        }
    }

    #[test]
    fn modexp_matches_u128() {
        // Cross-check against the const-generic path for 64-bit moduli.
        let moduli: [u64; 3] = [0xFFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0001, 1_000_003];
        let bases: [u64; 3] = [2, 3, 0x1234_5678_9abc_def1];
        let exps: [u64; 3] = [1, 17, 0xdead_beef];
        for &nv in &moduli {
            let m = BoxedMontModulus::new(&BoxedUint::from_u64(nv));
            for &b in &bases {
                for &e in &exps {
                    let got = m
                        .pow(&BoxedUint::from_u64(b % nv), &BoxedUint::from_u64(e))
                        .to_be_bytes(8);
                    let nn = nv as u128;
                    let mut r: u128 = 1 % nn;
                    let mut base = (b % nv) as u128 % nn;
                    let mut exp = e;
                    while exp > 0 {
                        if exp & 1 == 1 {
                            r = r * base % nn;
                        }
                        base = base * base % nn;
                        exp >>= 1;
                    }
                    let mut expected = [0u8; 8];
                    expected.copy_from_slice(&(r as u64).to_be_bytes());
                    assert_eq!(got, expected, "n={nv} b={b} e={e}");
                }
            }
        }
    }

    #[test]
    fn textbook_rsa() {
        // n=3233, e=17, d=2753; encrypt/decrypt 65.
        let m = BoxedMontModulus::new(&BoxedUint::from_u64(3233));
        let msg = BoxedUint::from_u64(65);
        let ct = m.pow(&msg, &BoxedUint::from_u64(17));
        assert_eq!(ct, BoxedUint::from_u64(2790));
        assert_eq!(m.pow(&ct, &BoxedUint::from_u64(2753)), msg);
    }

    /// `add_mod` / `sub_mod` against `u128` arithmetic on a 64-bit modulus,
    /// including the wrap-around cases (sum >= n, a < b) and operands padded
    /// with leading zero limbs.
    #[test]
    fn add_sub_mod_match_u128() {
        let n: u64 = 0xFFFF_FFFF_FFFF_FFC5;
        let m = BoxedMontModulus::new(&BoxedUint::from_u64(n));
        let vals: [u64; 5] = [0, 1, n - 1, n / 2, 0x0123_4567_89ab_cdef];
        for &a in &vals {
            for &b in &vals {
                let (ba, bb) = (BoxedUint::from_u64(a), BoxedUint::from_u64(b));
                let sum = ((a as u128 + b as u128) % n as u128) as u64;
                let diff = ((a as u128 + n as u128 - b as u128) % n as u128) as u64;
                assert_eq!(m.add_mod(&ba, &bb), BoxedUint::from_u64(sum), "{a}+{b}");
                assert_eq!(m.sub_mod(&ba, &bb), BoxedUint::from_u64(diff), "{a}-{b}");
                // Wider-than-modulus (zero-padded) operands are resized.
                let wide = BoxedUint::from_limbs(vec![a, 0, 0]);
                assert_eq!(m.sub_mod(&wide, &bb), BoxedUint::from_u64(diff));
            }
        }
    }

    #[test]
    #[should_panic(expected = "modulus must be nonzero")]
    fn new_zero_modulus_panics() {
        // Zero is also even, but the explicit nonzero check fires first
        // and gives the diagnostic that matches the documented contract.
        let _ = BoxedMontModulus::new(&BoxedUint::zero(2));
    }

    #[test]
    fn pow_does_not_truncate_overwide_exponent() {
        // Modulus is a single 64-bit limb but the exponent spans two limbs:
        // the silent-truncation bug would reduce `exp mod 2^64`, dropping
        // the bottom 64 bits to zero and computing `base^0 = 1`. With the
        // fix the full exponent is honoured.
        let n: u64 = 0xFFFF_FFFF_FFFF_FFC5; // small odd prime-like
        let m = BoxedMontModulus::new(&BoxedUint::from_u64(n));
        // exp = 2^64 (only the high limb is set). `base^(2^64) mod n` for
        // base=3 must equal the iterated 64-square of 3 mod n.
        let exp = BoxedUint::from_limbs(vec![0, 1]);
        let got = m.pow(&BoxedUint::from_u64(3), &exp).to_be_bytes(8);

        // Reference: square 3 sixty-four times mod n via u128.
        let mut r: u128 = 3;
        for _ in 0..64 {
            r = (r * r) % n as u128;
        }
        let expected = (r as u64).to_be_bytes();
        assert_eq!(got, expected);

        // Sanity: the truncation bug would have produced 1.
        assert_ne!(got, [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    /// SplitMix64 — deterministic test-only RNG.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    #[test]
    fn mont_sqr_matches_mont_mul() {
        // Differential: the dedicated squaring must produce bit-identical
        // output to the general multiply with both operands equal, across
        // every limb width the RSA/DH paths use, random odd moduli, random
        // residues, and the edge values 0, 1, n-1, and all-limbs-set
        // (reduced). Both routines require inputs < n.
        let mut rng: u64 = 0x5EED_CAFE_F00D_D00D;
        for limbs in 1..=64usize {
            // More modulus/value samples at the small widths where edge
            // cases concentrate; keep the total runtime sane at width 64.
            let moduli_per_width = if limbs <= 8 { 4 } else { 2 };
            for _ in 0..moduli_per_width {
                let mut n_limbs: Vec<Limb> = (0..limbs).map(|_| splitmix64(&mut rng)).collect();
                n_limbs[0] |= 1; // odd
                n_limbs[limbs - 1] |= 1 << 63; // full width
                let n = BoxedUint::from_limbs(n_limbs);
                let m = BoxedMontModulus::new(&n);
                assert_eq!(m.limbs(), limbs);

                let mut values: Vec<BoxedUint> = Vec::new();
                // Edge values: 0, 1, n-1, all-ones (reduced mod n).
                values.push(BoxedUint::zero(limbs));
                values.push(BoxedUint::from_u64(1));
                values.push(n.sub(&BoxedUint::from_u64(1)));
                let ones = BoxedUint::from_limbs(vec![Limb::MAX; limbs]);
                values.push(ones.reduce(&n));
                // Random residues, including some with only high limbs set.
                for k in 0..6 {
                    let v: Vec<Limb> = (0..limbs)
                        .map(|j| {
                            if k >= 4 && j < limbs / 2 {
                                0 // top-heavy value
                            } else {
                                splitmix64(&mut rng)
                            }
                        })
                        .collect();
                    values.push(BoxedUint::from_limbs(v).reduce(&n));
                }

                let mut t_mul = vec![0 as Limb; limbs];
                let mut t_sqr = vec![0 as Limb; 2 * limbs];
                let mut out_mul = vec![0 as Limb; limbs];
                let mut out_sqr = vec![0 as Limb; limbs];
                for v in &values {
                    let a = v.limbs_resized(limbs);
                    m.mont_mul_to(&a, &a, &mut t_mul, &mut out_mul);
                    m.mont_sqr_to(&a, &mut t_sqr, &mut out_sqr);
                    assert_eq!(out_sqr, out_mul, "limbs={limbs} a={a:x?}");
                }
            }
        }
    }

    /// The textbook `R²` computation `compute_r2` replaced: `2·64·limbs`
    /// modular doublings of 1.
    fn r2_by_doubling(n: &[Limb]) -> Vec<Limb> {
        let mut r2 = vec![0 as Limb; n.len()];
        r2[0] = 1;
        for _ in 0..2 * 64 * n.len() {
            r2 = add_mod_limbs(n, &r2, &r2);
        }
        r2
    }

    #[test]
    fn r2_matches_doubling_oracle() {
        let mut rng: u64 = 0x0123_4567_89AB_CDEF;
        let check = |n: BoxedUint| {
            let m = BoxedMontModulus::new(&n);
            let expected = r2_by_doubling(&n.limbs_resized(m.limbs()));
            assert_eq!(m.r2, expected, "n={:x?}", n.as_limbs());
        };
        // Small and boundary moduli, including padded storage (the context
        // strips leading zero limbs).
        for v in [3u64, 5, 7, 0xFFFF_FFFF_FFFF_FFC5, 1 << 63 | 1, u64::MAX] {
            check(BoxedUint::from_u64(v));
            check(BoxedUint::from_limbs(vec![v, 0, 0]));
        }
        check(BoxedUint::from_limbs(vec![1, 1]));
        check(BoxedUint::from_limbs(vec![u64::MAX; 5]));
        for limbs in 1..=40usize {
            for k in 0..3 {
                let mut v: Vec<Limb> = (0..limbs).map(|_| splitmix64(&mut rng)).collect();
                // Full-width, small top limb, and top limb = 1.
                match k {
                    0 => v[limbs - 1] |= 1 << 63,
                    1 => v[limbs - 1] = (v[limbs - 1] >> 40).max(1),
                    _ => v[limbs - 1] = 1,
                }
                v[0] |= 1;
                if v == [1] {
                    v[0] = 3;
                }
                check(BoxedUint::from_limbs(v));
            }
        }
    }

    #[test]
    fn mont_reduce_matches_long_division() {
        let mut rng: u64 = 0xA076_1D64_78BD_642F;
        for nl in 1..=20usize {
            for k in 0..2 {
                let mut v: Vec<Limb> = (0..nl).map(|_| splitmix64(&mut rng)).collect();
                if k == 0 {
                    v[nl - 1] |= 1 << 63;
                } else {
                    v[nl - 1] = (v[nl - 1] >> 33).max(1);
                }
                v[0] |= 1;
                if v == [1] {
                    v[0] = 3;
                }
                let n = BoxedUint::from_limbs(v);
                let m = BoxedMontModulus::new(&n);
                // Inputs narrower, equal and up to 3x wider than n, plus the
                // edge values 0, n - 1, n, all-ones.
                let mut xs = vec![
                    BoxedUint::zero(1),
                    n.sub(&BoxedUint::from_u64(1)),
                    n.clone(),
                    BoxedUint::from_limbs(vec![Limb::MAX; 3 * nl]),
                ];
                for xl in [
                    1,
                    nl.saturating_sub(1).max(1),
                    nl,
                    nl + 1,
                    2 * nl,
                    3 * nl + 1,
                ] {
                    xs.push(BoxedUint::from_limbs(
                        (0..xl).map(|_| splitmix64(&mut rng)).collect(),
                    ));
                }
                for x in &xs {
                    let got = m.reduce(x);
                    assert_eq!(got.limbs(), m.limbs());
                    assert_eq!(got, x.reduce(&n), "n={n:?} x={x:?}");
                }
            }
        }
    }

    /// Reference modexp: right-to-left binary over `mul_mod`, one bit at a
    /// time with ordinary branches (test-only, nothing secret).
    fn pow_reference(m: &BoxedMontModulus, base: &BoxedUint, exp: &BoxedUint) -> BoxedUint {
        let mut acc = m.reduce(&BoxedUint::from_u64(1));
        let mut b = m.reduce(base);
        for i in 0..exp.limbs() * 64 {
            if (exp.as_limbs()[i / 64] >> (i % 64)) & 1 == 1 {
                acc = m.mul_mod(&acc, &b);
            }
            b = m.mul_mod(&b, &b);
        }
        acc
    }

    #[test]
    fn pow_variants_match_reference() {
        let mut rng: u64 = 0x7A3C_91E5_0B2D_F468;
        for nl in [1usize, 2, 3, 5, 8, 16] {
            let mut v: Vec<Limb> = (0..nl).map(|_| splitmix64(&mut rng)).collect();
            v[0] |= 1;
            v[nl - 1] |= 1 << 63;
            let n = BoxedUint::from_limbs(v);
            let m = BoxedMontModulus::new(&n);
            let rand = |rng: &mut u64, limbs: usize| {
                BoxedUint::from_limbs((0..limbs).map(|_| splitmix64(rng)).collect())
            };
            let mut exps = vec![
                BoxedUint::zero(1),
                BoxedUint::from_u64(1),
                BoxedUint::from_u64(2),
                BoxedUint::from_u64(65537),
                BoxedUint::from_u64(u64::MAX),
                BoxedUint::from_limbs(vec![0, 1]),
                BoxedUint::from_limbs(vec![u64::MAX; nl + 1]),
            ];
            for el in [1, nl, nl + 2] {
                exps.push(rand(&mut rng, el));
            }
            // Exponents with a sparse top: bit lengths 65..=68 exercise the
            // public window's partial top nibble.
            for top in 0..4u32 {
                exps.push(BoxedUint::from_limbs(vec![splitmix64(&mut rng), 1 << top]));
            }
            let bases = [
                BoxedUint::zero(1),
                BoxedUint::from_u64(1),
                n.sub(&BoxedUint::from_u64(1)),
                m.reduce(&rand(&mut rng, nl)),
            ];
            for base in &bases {
                for e in &exps {
                    let want = pow_reference(&m, base, e);
                    assert_eq!(m.pow(base, e), want, "pow nl={nl} e={e:?}");
                    assert_eq!(m.pow_public(base, e), want, "pow_public nl={nl} e={e:?}");
                    // Tightest public bound and a looser, odd one.
                    let bits = e.bit_len();
                    assert_eq!(m.pow_bits(base, e, bits), want, "pow_bits nl={nl}");
                    assert_eq!(m.pow_bits(base, e, bits + 7), want, "pow_bits nl={nl}");
                }
            }
            for i in 0..exps.len() {
                let j = (i * 5 + 3) % exps.len();
                let (x, y) = (&exps[i], &exps[j]);
                let (a, b) = (&bases[i % 4], &bases[3 - j % 4]);
                let want = m.mul_mod(&pow_reference(&m, a, x), &pow_reference(&m, b, y));
                let bits = x.bit_len().max(y.bit_len());
                assert_eq!(m.pow2_bits(a, x, b, y, bits), want, "pow2 nl={nl}");
                assert_eq!(m.pow2_bits(a, x, b, y, bits + 3), want, "pow2 nl={nl}");
            }
        }
    }

    #[test]
    fn matches_const_generic_256bit() {
        // Boxed modexp must equal the fixed-width path on a 256-bit modulus.
        let n4 = Uint::<4>::from_limbs([
            0x1234_5678_9abc_def1,
            0xfedc_ba98_7654_3211,
            0x0f0f_0f0f_0f0f_0f0f,
            0x8000_0000_0000_0001,
        ]);
        let mut n_bytes = [0u8; 32];
        n4.write_be_bytes(&mut n_bytes);

        let base4 = Uint::<4>::from_u64(0xdead_beef);
        let exp4 = Uint::<4>::from_u64(65537);
        let fixed = MontModulus::new(n4).pow(&base4, &exp4);
        let mut fixed_bytes = [0u8; 32];
        fixed.write_be_bytes(&mut fixed_bytes);

        let boxed = BoxedMontModulus::new(&BoxedUint::from_be_bytes(&n_bytes)).pow(
            &BoxedUint::from_u64(0xdead_beef),
            &BoxedUint::from_u64(65537),
        );
        assert_eq!(boxed.to_be_bytes(32), fixed_bytes);
    }

    /// A random `bits`-bit odd modulus; `shape` picks the top limbs: random,
    /// all ones (stresses the `< 2n` bound of the almost-Montgomery
    /// kernels), or `2^(bits−1) + small` (the smallest modulus of the width).
    fn random_modulus(rng: &mut u64, bits: usize, shape: usize) -> BoxedUint {
        let l = bits.div_ceil(64);
        let mut n: Vec<Limb> = (0..l).map(|_| splitmix64(rng)).collect();
        match shape {
            1 => n.iter_mut().for_each(|w| *w = u64::MAX),
            2 => {
                n.iter_mut().for_each(|w| *w = 0);
                n[0] = splitmix64(rng) & 0xffff;
            }
            _ => {}
        }
        let top = bits - 64 * (l - 1);
        if top < 64 {
            n[l - 1] &= (1u64 << top) - 1;
        }
        n[l - 1] |= 1u64 << (top - 1);
        n[0] |= 1;
        BoxedUint::from_limbs(n)
    }

    /// A random value below `n` (same limb width).
    fn random_below(rng: &mut u64, n: &BoxedUint) -> BoxedUint {
        let x: Vec<Limb> = (0..n.limbs()).map(|_| splitmix64(rng)).collect();
        BoxedUint::from_limbs(x).reduce(n)
    }

    /// The dispatched exponentiations (the AVX-512 IFMA kernels on a CPU
    /// that has them) against the portable CIOS bodies, across widths that
    /// hit every digit/register boundary of the IFMA layout: RSA prime and
    /// modulus sizes, odd sizes one bit past a limb or digit boundary, the
    /// largest width the IFMA backend takes (6654 bits) and one past it.
    #[test]
    fn dispatched_pow_matches_portable() {
        let mut rng = 0x1f3a_9b2c_77d1_0e45u64;
        let sizes = [
            62usize, 64, 65, 127, 256, 414, 415, 512, 1022, 1023, 1024, 1025, 1038, 1039, 1536,
            2047, 2048, 2049, 3072, 3326, 3327, 4096, 4097, 6654, 6655,
        ];
        for (si, &bits) in sizes.iter().enumerate() {
            let shape = si % 3;
            let n = random_modulus(&mut rng, bits, shape);
            let m = BoxedMontModulus::new(&n);
            let big = bits > 3000;
            let trials = if big { 1 } else { 3 };
            for t in 0..trials {
                let base = match t {
                    0 => random_below(&mut rng, &n),
                    1 => n.sub(&BoxedUint::from_u64(1)),
                    _ => BoxedUint::from_u64(t as u64 - 2),
                };
                let base2 = random_below(&mut rng, &n);
                let exp = random_below(&mut rng, &n);
                let exp2 = random_below(&mut rng, &n);
                // Bounds that are and are not multiples of the window
                // widths, and one that cuts the exponent short (bits above
                // the bound must be ignored identically).
                let ebits = [64 * n.limbs(), bits, bits.saturating_sub(3).max(1), 1];
                for &eb in &ebits[..if big { 1 } else { 4 }] {
                    // The bound is a precondition (`exp < 2^eb`).
                    let cut = |e: &BoxedUint| {
                        let mut l = e.as_limbs().to_vec();
                        for (i, w) in l.iter_mut().enumerate() {
                            let lo = 64 * i;
                            if lo >= eb {
                                *w = 0;
                            } else if eb - lo < 64 {
                                *w &= (1u64 << (eb - lo)) - 1;
                            }
                        }
                        BoxedUint::from_limbs(l)
                    };
                    let (exp, exp2) = (cut(&exp), cut(&exp2));
                    assert_eq!(
                        m.pow_bits(&base, &exp, eb),
                        m.pow_bits_portable(&base, &exp, eb),
                        "pow_bits bits={bits} eb={eb} t={t}"
                    );
                    if !big {
                        assert_eq!(
                            m.pow2_bits(&base, &exp, &base2, &exp2, eb),
                            m.pow2_bits_portable(&base, &exp, &base2, &exp2, eb),
                            "pow2_bits bits={bits} eb={eb} t={t}"
                        );
                    }
                }
                for e in [0u64, 1, 2, 3, 65537, splitmix64(&mut rng), u64::MAX] {
                    let e = BoxedUint::from_u64(e);
                    assert_eq!(
                        m.pow_public(&base, &e),
                        m.pow_public_portable(&base, &e),
                        "pow_public bits={bits} t={t}"
                    );
                }
            }
        }
    }

    /// The paired exponentiations (lock-step on the IFMA backend) against
    /// two portable runs, for equal-width moduli (paired) and unequal ones
    /// (sequential fallback).
    #[test]
    fn pow_pairs_match_portable() {
        let mut rng = 0x5eed_0fba_1100_u64;
        for &(ba, bb) in &[
            (256usize, 256usize),
            (512, 512),
            (1024, 1024),
            (1025, 1025),
            (1536, 1536),
            (2048, 2048),
            (1024, 1023),
            (1024, 1100),
            (4096, 4096),
            (4200, 4200),
        ] {
            let (na, nb) = (
                random_modulus(&mut rng, ba, 0),
                random_modulus(&mut rng, bb, 1),
            );
            let (ma, mb) = (BoxedMontModulus::new(&na), BoxedMontModulus::new(&nb));
            let bits = 64 * na.limbs().max(nb.limbs());
            let (xa, ea, ya, fa) = (
                random_below(&mut rng, &na),
                random_below(&mut rng, &na),
                random_below(&mut rng, &na),
                random_below(&mut rng, &na),
            );
            let (xb, eb, yb, fb) = (
                random_below(&mut rng, &nb),
                random_below(&mut rng, &nb),
                random_below(&mut rng, &nb),
                random_below(&mut rng, &nb),
            );
            let (ra, rb) = BoxedMontModulus::pow_bits_pair(&ma, &xa, &ea, &mb, &xb, &eb, bits);
            assert_eq!(ra, ma.pow_bits_portable(&xa, &ea, bits), "{ba}/{bb}");
            assert_eq!(rb, mb.pow_bits_portable(&xb, &eb, bits), "{ba}/{bb}");
            let (ra, rb) = BoxedMontModulus::pow2_bits_pair(
                &ma,
                (&xa, &ea, &ya, &fa),
                &mb,
                (&xb, &eb, &yb, &fb),
                bits,
            );
            assert_eq!(ra, ma.pow2_bits_portable(&xa, &ea, &ya, &fa, bits));
            assert_eq!(rb, mb.pow2_bits_portable(&xb, &eb, &yb, &fb, bits));
        }
    }
}
