//! Constant-time Montgomery modular arithmetic for [`BoxedUint`].
//!
//! A runtime-width port of [`MontModulus`](super::MontModulus): same CIOS
//! multiplication and square-and-multiply-always exponentiation, over
//! `Vec<Limb>` scratch so the modulus width is chosen at runtime.

use super::boxed::{BoxedUint, adc_limbs, sbb_limbs, select_limbs};
use super::montgomery::inv_mod_2_64;
use super::mul::mac;
use super::uint::{Limb, adc, sbb};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use alloc::vec;
use alloc::vec::Vec;

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
    let subtract = Choice::from((c | (bo ^ 1)) as u8);
    for j in 0..n.len() {
        out[j] = Limb::conditional_select(&out[j], &a[j], subtract);
    }
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
        };
        m.r2 = m.compute_r2();
        m
    }

    /// `R² mod n` for `R = 2^k`, `k = 64·limbs`, without the `2k` modular
    /// doublings of the textbook loop (and without an allocation per step).
    ///
    /// Writing `M(x) = x·R mod n` for the Montgomery form, a modular doubling
    /// maps `M(2^e)` to `M(2^(e+1))` and a Montgomery squaring maps it to
    /// `M(2^(2e))`; the target `R² = M(2^k)`. So: reach `M(2) = 2R mod n` by
    /// doublings, then walk the bits of `k` below its leading one — square,
    /// and double where the bit is set — which takes `e` from 1 to `k` in
    /// `⌊log₂ k⌋` squarings (11 at 2048 bits) plus `popcount(k) − 1`
    /// doublings.
    ///
    /// The doublings start at `2^(64·(limbs−1))`, which is already below `n`:
    /// the top limb of `n` is nonzero, and `n` is odd so it cannot equal that
    /// power for `limbs > 1` (for `limbs = 1` the start is `1 < n`). That
    /// leaves `64 + 1` doublings to `M(2)` instead of `64·limbs + 1`.
    ///
    /// Constant time in `n`: the only branches are on `limbs` and the bits of
    /// `k`, both functions of the (public) modulus width; every doubling and
    /// squaring is the masked-select arithmetic used everywhere else.
    fn compute_r2(&self) -> Vec<Limb> {
        let l = self.limbs;
        let mut x = vec![0 as Limb; l];
        x[l - 1] = 1;
        let mut tmp = vec![0 as Limb; 2 * l];
        for _ in 0..65 {
            self.double_in_place(&mut x, &mut tmp);
        }
        let k = 64 * l;
        let mut out = vec![0 as Limb; l];
        let mut i = usize::BITS - 1 - k.leading_zeros();
        while i > 0 {
            i -= 1;
            self.mont_sqr_to(&x, &mut tmp, &mut out);
            core::mem::swap(&mut x, &mut out);
            if (k >> i) & 1 == 1 {
                self.double_in_place(&mut x, &mut tmp);
            }
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
        for j in 0..self.limbs {
            x[j] = Limb::conditional_select(&tmp[j], &x[j], ge);
        }
    }

    /// The modulus width in limbs.
    #[inline]
    pub fn limbs(&self) -> usize {
        self.limbs
    }

    /// CIOS Montgomery multiplication of two `limbs`-wide values into `out`,
    /// with caller-provided scratch `t` — no allocation, so the
    /// exponentiation ladders can reuse two buffers across their thousands
    /// of multiplies instead of hitting the allocator on each one.
    ///
    /// `out` may alias `a` and/or `b`: the accumulation only reads them, and
    /// `out` is written exclusively in the final-subtraction step, after the
    /// last read. (Rust's borrow rules forbid literal aliasing anyway;
    /// callers ping-pong two buffers and `mem::swap`.) `t` must not alias
    /// anything. The operation sequence is identical to the previous
    /// allocating version — same mask-based conditional subtraction, no new
    /// branches — so the constant-time property is unchanged.
    fn mont_mul_to(&self, a: &[Limb], b: &[Limb], t: &mut [Limb], out: &mut [Limb]) {
        let l = self.limbs;
        let n = &self.n;
        // Only the low `l` limbs of `t` are used; the exponentiation ladders
        // hand in the wider squaring scratch and share it with `mont_sqr_to`.
        t[..l].fill(0);
        let mut ts: Limb = 0;

        for &bi in b.iter().take(l) {
            let mut carry = 0;
            for j in 0..l {
                let (s, c) = mac(t[j], a[j], bi, carry);
                t[j] = s;
                carry = c;
            }
            let (s, c) = adc(ts, carry, 0);
            ts = s;
            let ts1 = c;

            let m = t[0].wrapping_mul(self.n_prime);
            let (_, mut carry) = mac(t[0], m, n[0], 0);
            for j in 1..l {
                let (s, c) = mac(t[j], m, n[j], carry);
                t[j - 1] = s;
                carry = c;
            }
            let (s, c) = adc(ts, carry, 0);
            t[l - 1] = s;
            ts = ts1 + c;
        }

        // Conditional final subtraction (result < 2N): out = t - n, kept only
        // when the subtraction doesn't underflow the (l+1)-limb value.
        let mut bo: Limb = 0;
        for j in 0..l {
            let (d, b) = sbb(t[j], n[j], bo);
            out[j] = d;
            bo = b;
        }
        let (_, borrow) = sbb(ts, 0, bo);
        let ge = Choice::from((borrow ^ 1) as u8);
        for j in 0..l {
            out[j] = Limb::conditional_select(&out[j], &t[j], ge);
        }
    }

    /// Montgomery squaring of a `limbs`-wide value into `out`, with
    /// caller-provided scratch `t` of at least `2 * limbs` limbs.
    ///
    /// Produces exactly the same value as `mont_mul_to(a, a, ..)` but uses the
    /// standard squaring optimization: each off-diagonal partial product
    /// `a[i]·a[j]` (`i < j`) is computed once and doubled, then the diagonal
    /// `a[i]²` terms are added — roughly halving the `mac` count of the
    /// schoolbook phase. The Montgomery reduction is then done as a separate
    /// SOS pass over the full `2·limbs`-limb square (CIOS interleaving is not
    /// possible once the product is formed up front).
    ///
    /// Constant time: every loop bound is a function of `self.limbs` only (a
    /// public quantity), the doubling is an unconditional shift across the
    /// whole product, and the final subtraction uses the same mask-based
    /// select as `mont_mul_to` — no data-dependent branch anywhere.
    ///
    /// `out` may alias `a`: `a` is only read while the square is accumulated
    /// into `t`, and `out` is written exclusively in the final-subtraction
    /// step. `t` must not alias anything.
    fn mont_sqr_to(&self, a: &[Limb], t: &mut [Limb], out: &mut [Limb]) {
        let l = self.limbs;
        let n = &self.n;
        let p = &mut t[..2 * l];
        p.fill(0);

        // Off-diagonal partial products a[i]·a[j] for i < j, each computed
        // once. Iteration i writes p[2i+1 ..= i+l-1] and drops its carry into
        // p[i+l], which iteration i+1 then accumulates into — the ordinary
        // schoolbook triangle.
        for i in 0..l {
            let mut carry = 0;
            for j in (i + 1)..l {
                let (s, c) = mac(p[i + j], a[i], a[j], carry);
                p[i + j] = s;
                carry = c;
            }
            p[i + l] = carry;
        }

        // Double the off-diagonal sum S. 2S <= a² < 2^(128·l), so the shift
        // cannot carry out of the 2l-limb product.
        let mut carry: Limb = 0;
        for w in p.iter_mut() {
            let next = *w >> 63;
            *w = (*w << 1) | carry;
            carry = next;
        }

        // Add the diagonal a[i]² terms at positions (2i, 2i+1). The high half
        // of each square lands on an odd position whose add can carry into the
        // next even position, which is exactly where the next mac's carry-in
        // goes. The total is a², which fits in 2l limbs, so the last carry
        // out is zero.
        let mut carry: Limb = 0;
        for i in 0..l {
            let (s, c) = mac(p[2 * i], a[i], a[i], carry);
            p[2 * i] = s;
            let (s, c2) = adc(p[2 * i + 1], c, 0);
            p[2 * i + 1] = s;
            carry = c2;
        }

        // Montgomery reduction, SOS style: for each of the l low limbs, add
        // m·N so the limb cancels, then shift the window up one limb (done
        // implicitly by indexing from i). `hi` carries the overflow of
        // iteration i's top-limb add into position i+l+1, which is where
        // iteration i+1 adds its own top carry — so a single riding limb
        // suffices and the loop shape stays independent of the data.
        let mut hi: Limb = 0;
        for i in 0..l {
            let m = p[i].wrapping_mul(self.n_prime);
            let mut carry = 0;
            for j in 0..l {
                let (s, c) = mac(p[i + j], m, n[j], carry);
                p[i + j] = s;
                carry = c;
            }
            let (s, c) = adc(p[i + l], carry, hi);
            p[i + l] = s;
            hi = c;
        }

        // Result is the (l+1)-limb value (p[l..2l], hi) and is < 2N; same
        // mask-based conditional final subtraction as `mont_mul_to`.
        let mut bo: Limb = 0;
        for j in 0..l {
            let (d, b) = sbb(p[l + j], n[j], bo);
            out[j] = d;
            bo = b;
        }
        let (_, borrow) = sbb(hi, 0, bo);
        let ge = Choice::from((borrow ^ 1) as u8);
        for j in 0..l {
            out[j] = Limb::conditional_select(&out[j], &p[l + j], ge);
        }
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
    pub fn pow_bits(&self, base: &BoxedUint, exp: &BoxedUint, bits: usize) -> BoxedUint {
        let l = self.limbs;
        let base_m = self.to_mont_limbs(&base.limbs_resized(l));
        let mut one = vec![0 as Limb; l];
        one[0] = 1;
        let r_mod_n = self.to_mont_limbs(&one); // R mod N (= 1 in Montgomery form)
        let mut table: Vec<Vec<Limb>> = Vec::with_capacity(16);
        table.push(r_mod_n);
        table.push(base_m);
        for i in 2..16 {
            table.push(self.mont_mul_limbs(&table[i - 1], &table[1]));
        }
        let exp = exp.as_limbs();
        let windows = bits.div_ceil(4).max(1);
        // Nibble `w` of the exponent; positions past its storage read as 0.
        // The limb index and shift are public loop quantities.
        let digit = |w: usize| (exp.get(w / 16).copied().unwrap_or(0) >> (4 * (w % 16))) & 0xf;
        let result = self.window_ladder(&table, windows, 4, |w| digit(w) as usize);
        for entry in table.iter_mut() {
            zeroize_limbs(entry);
        }
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
        let l = self.limbs;
        let mut one = vec![0 as Limb; l];
        one[0] = 1;
        // table[i + 4j] = a^i · b^j (Montgomery form).
        let mut table: Vec<Vec<Limb>> = vec![Vec::new(); 16];
        table[0] = self.to_mont_limbs(&one);
        table[1] = self.to_mont_limbs(&a.limbs_resized(l));
        table[4] = self.to_mont_limbs(&b.limbs_resized(l));
        table[8] = self.mont_mul_limbs(&table[4], &table[4]);
        table[12] = self.mont_mul_limbs(&table[8], &table[4]);
        for j in 0..4 {
            for i in 1..4 {
                if j == 0 && i == 1 {
                    continue;
                }
                table[4 * j + i] = self.mont_mul_limbs(&table[4 * j + i - 1], &table[1]);
            }
        }
        let (x, y) = (x.as_limbs(), y.as_limbs());
        let windows = bits.div_ceil(2).max(1);
        let two_bits =
            |e: &[Limb], w: usize| (e.get(w / 32).copied().unwrap_or(0) >> (2 * (w % 32))) & 3;
        let result = self.window_ladder(&table, windows, 2, |w| {
            (two_bits(x, w) | (two_bits(y, w) << 2)) as usize
        });
        for entry in table.iter_mut() {
            zeroize_limbs(entry);
        }
        result
    }

    /// The shared fixed-window ladder: `windows` windows of `width` bits,
    /// most significant first, where `digit(w)` is the (secret) table index
    /// of window `w`. The accumulator starts at the top window's entry
    /// (saving the squarings of 1); each later window squares `width` times
    /// and multiplies by its entry. Entries are gathered by a full masked
    /// scan of `table` — the index comparison goes through `ct_eq`
    /// (branch-free by construction) rather than a `==` the compiler may
    /// lower to a branch on the secret — and every multiply is
    /// unconditional, so the operation sequence depends only on `windows`
    /// and `width`.
    fn window_ladder(
        &self,
        table: &[Vec<Limb>],
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
            sel.copy_from_slice(&table[0]);
            for (j, entry) in table.iter().enumerate() {
                let hit = j.ct_eq(&idx);
                for (s, e) in sel.iter_mut().zip(entry.iter()) {
                    *s = Limb::conditional_select(e, s, hit);
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
}
