//! Constant-time modular arithmetic in Montgomery form.
//!
//! For an odd modulus `N` of `LIMBS` limbs and `R = 2^(64*LIMBS)`, a value `x`
//! is represented in *Montgomery form* as `xR mod N`. The product of two
//! Montgomery-form values is computed with [`MontModulus::mont_mul`], which
//! yields `abR^-1 mod N` — i.e. the Montgomery form of `ab mod N` — using the
//! CIOS algorithm with no data-dependent branches.

use super::Uint;
use super::mul::mac;
use super::uint::{Limb, adc, sbb};
use crate::ct::{Choice, ConditionallySelectable};

/// Computes `n^-1 mod 2^64` for odd `n` via Newton's iteration (each step
/// doubles the number of correct low bits; six steps cover 64 bits). Shared
/// with [`super::boxed_montgomery`].
pub(crate) const fn inv_mod_2_64(n: u64) -> u64 {
    let mut x = 1u64; // correct mod 2 (n is odd)
    let mut i = 0;
    while i < 6 {
        x = x.wrapping_mul(2u64.wrapping_sub(n.wrapping_mul(x)));
        i += 1;
    }
    x
}

/// Returns `(a + b) mod n`, assuming `a, b < n`.
fn add_mod<const LIMBS: usize>(n: &Uint<LIMBS>, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
    let (sum, carry) = a.adc(b, 0);
    let (diff, borrow) = sum.sbb(n, 0);
    // Subtract n when the sum overflowed (carry) or sum >= n (no borrow).
    let subtract = carry | (borrow ^ 1);
    Uint::conditional_select(&diff, &sum, Choice::from(subtract as u8))
}

/// Returns `(a - b) mod n`, assuming `a, b < n`.
fn sub_mod<const LIMBS: usize>(n: &Uint<LIMBS>, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
    let (diff, borrow) = a.sbb(b, 0);
    let (wrapped, _) = diff.adc(n, 0);
    // If a < b (borrow), the true result wrapped negative; add n back.
    Uint::conditional_select(&wrapped, &diff, Choice::from(borrow as u8))
}

/// Parameters for modular arithmetic with a fixed odd modulus.
#[derive(Clone, Debug)]
pub struct MontModulus<const LIMBS: usize> {
    modulus: Uint<LIMBS>,
    /// `-N^-1 mod 2^64`.
    n_prime: Limb,
    /// `R^2 mod N`, used to convert into Montgomery form.
    r2: Uint<LIMBS>,
}

impl<const LIMBS: usize> MontModulus<LIMBS> {
    /// Builds modular parameters for an odd `modulus`.
    ///
    /// # Panics
    /// Panics if `modulus` is even (Montgomery reduction requires an odd
    /// modulus).
    pub fn new(modulus: Uint<LIMBS>) -> Self {
        assert!(
            modulus.as_limbs()[0] & 1 == 1,
            "Montgomery modulus must be odd"
        );
        let n_prime = inv_mod_2_64(modulus.as_limbs()[0]).wrapping_neg();

        // R^2 mod N = 2^(2*64*LIMBS) mod N, by doubling 1 that many times.
        let mut r2 = Uint::ONE;
        let mut i = 0;
        let bits = 2 * 64 * LIMBS;
        while i < bits {
            r2 = add_mod(&modulus, &r2, &r2);
            i += 1;
        }

        MontModulus {
            modulus,
            n_prime,
            r2,
        }
    }

    /// The modulus `N`.
    #[inline]
    pub fn modulus(&self) -> &Uint<LIMBS> {
        &self.modulus
    }

    /// Montgomery multiplication: given `a, b` in Montgomery form, returns
    /// `a*b*R^-1 mod N` (the Montgomery form of the product). CIOS, constant
    /// time.
    pub fn mont_mul(&self, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
        let a = a.as_limbs();
        let b = b.as_limbs();
        let n = self.modulus.as_limbs();

        // t spans LIMBS+2 words: the array holds t[0..LIMBS-1]; ts = t[LIMBS],
        // ts1 = t[LIMBS+1].
        let mut t = [0 as Limb; LIMBS];
        let mut ts: Limb = 0;

        let mut i = 0;
        while i < LIMBS {
            // t += a * b[i]
            let mut carry = 0;
            let mut j = 0;
            while j < LIMBS {
                let (s, c) = mac(t[j], a[j], b[i], carry);
                t[j] = s;
                carry = c;
                j += 1;
            }
            let (s, c) = adc(ts, carry, 0);
            ts = s;
            let ts1 = c; // t[LIMBS + 1]; only lives within this iteration

            // m = t[0] * n' mod 2^64; t = (t + m*N) / 2^64
            let m = t[0].wrapping_mul(self.n_prime);
            let (_, mut carry) = mac(t[0], m, n[0], 0); // low word becomes 0
            let mut j = 1;
            while j < LIMBS {
                let (s, c) = mac(t[j], m, n[j], carry);
                t[j - 1] = s;
                carry = c;
                j += 1;
            }
            let (s, c) = adc(ts, carry, 0);
            t[LIMBS - 1] = s;
            ts = ts1 + c;

            i += 1;
        }

        // Result is (t, ts) across LIMBS+1 words and is < 2N; subtract N once
        // if it is >= N.
        let result = Uint::from_limbs(t);
        let (diff, borrow_low) = result.sbb(&self.modulus, 0);
        let (_, borrow) = sbb(ts, 0, borrow_low);
        // borrow == 0 means the (LIMBS+1)-word value was >= N: take the
        // subtracted result; otherwise keep the original.
        let ge = Choice::from((borrow ^ 1) as u8);
        Uint::conditional_select(&diff, &result, ge)
    }

    /// Montgomery squaring: given `a` in Montgomery form, returns
    /// `a²·R^-1 mod N` — exactly [`mont_mul`](Self::mont_mul)`(a, a)`, but
    /// with the standard squaring optimization: each off-diagonal partial
    /// product `a[i]·a[j]` (`i < j`) is computed once and doubled, then the
    /// diagonal `a[i]²` terms are added, roughly halving the `mac` count of
    /// the schoolbook phase. The Montgomery reduction is a separate SOS pass
    /// over the full `2·LIMBS`-limb square held in `(lo, hi)` halves.
    ///
    /// Constant time: all loop bounds and the `lo`/`hi` split are functions
    /// of the public `LIMBS` and loop indices only (the same public-index
    /// branch pattern as [`Uint::mul_wide`]); the final subtraction uses the
    /// same mask-based select as `mont_mul`.
    pub fn mont_sqr(&self, a: &Uint<LIMBS>) -> Uint<LIMBS> {
        let a = a.as_limbs();
        let n = self.modulus.as_limbs();

        // The 2·LIMBS-limb square lives in (lo, hi); positions >= LIMBS map
        // into hi. The index is always a public loop expression.
        let mut lo = [0 as Limb; LIMBS];
        let mut hi = [0 as Limb; LIMBS];

        // Off-diagonal partial products a[i]·a[j] for i < j, each once.
        // Iteration i drops its carry into position i+LIMBS (hi[i]), which
        // the next iteration's top mac then accumulates into.
        let mut i = 0;
        while i < LIMBS {
            let mut carry = 0;
            let mut j = i + 1;
            while j < LIMBS {
                let p = i + j;
                if p < LIMBS {
                    let (v, c) = mac(lo[p], a[i], a[j], carry);
                    lo[p] = v;
                    carry = c;
                } else {
                    let (v, c) = mac(hi[p - LIMBS], a[i], a[j], carry);
                    hi[p - LIMBS] = v;
                    carry = c;
                }
                j += 1;
            }
            hi[i] = carry; // position i + LIMBS, untouched so far
            i += 1;
        }

        // Double the off-diagonal sum S: 2S <= a² < 2^(128·LIMBS), so the
        // shift cannot carry out of the top limb.
        let mut carry: Limb = 0;
        let mut k = 0;
        while k < LIMBS {
            let next = lo[k] >> 63;
            lo[k] = (lo[k] << 1) | carry;
            carry = next;
            k += 1;
        }
        let mut k = 0;
        while k < LIMBS {
            let next = hi[k] >> 63;
            hi[k] = (hi[k] << 1) | carry;
            carry = next;
            k += 1;
        }

        // Add the diagonal a[i]² terms at positions (2i, 2i+1); the high
        // half's carry-out feeds the next even position's mac carry-in. The
        // total is a², which fits in 2·LIMBS limbs, so the last carry is 0.
        let mut carry: Limb = 0;
        let mut i = 0;
        while i < LIMBS {
            let (p0, p1) = (2 * i, 2 * i + 1);
            let w0 = if p0 < LIMBS { lo[p0] } else { hi[p0 - LIMBS] };
            let (v, c) = mac(w0, a[i], a[i], carry);
            if p0 < LIMBS {
                lo[p0] = v;
            } else {
                hi[p0 - LIMBS] = v;
            }
            let w1 = if p1 < LIMBS { lo[p1] } else { hi[p1 - LIMBS] };
            let (v, c2) = adc(w1, c, 0);
            if p1 < LIMBS {
                lo[p1] = v;
            } else {
                hi[p1 - LIMBS] = v;
            }
            carry = c2;
            i += 1;
        }

        // Montgomery reduction, SOS style: cancel the LIMBS low limbs one at
        // a time. `hic` carries iteration i's top-limb overflow into position
        // i+LIMBS+1, exactly where iteration i+1 adds its own top carry, so a
        // single riding limb suffices.
        let mut hic: Limb = 0;
        let mut i = 0;
        while i < LIMBS {
            let m = lo[i].wrapping_mul(self.n_prime);
            let mut carry = 0;
            let mut j = 0;
            while j < LIMBS {
                let p = i + j;
                if p < LIMBS {
                    let (v, c) = mac(lo[p], m, n[j], carry);
                    lo[p] = v;
                    carry = c;
                } else {
                    let (v, c) = mac(hi[p - LIMBS], m, n[j], carry);
                    hi[p - LIMBS] = v;
                    carry = c;
                }
                j += 1;
            }
            let (v, c) = adc(hi[i], carry, hic);
            hi[i] = v;
            hic = c;
            i += 1;
        }

        // Result is the (LIMBS+1)-limb value (hi, hic) and is < 2N; same
        // mask-based conditional final subtraction as `mont_mul`.
        let result = Uint::from_limbs(hi);
        let (diff, borrow_low) = result.sbb(&self.modulus, 0);
        let (_, borrow) = sbb(hic, 0, borrow_low);
        let ge = Choice::from((borrow ^ 1) as u8);
        Uint::conditional_select(&diff, &result, ge)
    }

    /// Converts `x` (a plain residue `< N`) into Montgomery form `xR mod N`.
    ///
    /// `x` is required to be a plain residue strictly below the modulus; a
    /// debug-only assertion documents and checks that precondition (it also
    /// guards [`pow`](Self::pow), which routes its `base` through here).
    /// Release behavior is unchanged.
    #[inline]
    pub fn to_mont(&self, x: &Uint<LIMBS>) -> Uint<LIMBS> {
        debug_assert!(
            bool::from(crate::ct::ConstantTimeLess::ct_lt(x, &self.modulus)),
            "to_mont precondition violated: base must be < N"
        );
        self.mont_mul(x, &self.r2)
    }

    /// Converts `x` out of Montgomery form, returning the plain residue.
    #[inline]
    pub fn from_mont(&self, x: &Uint<LIMBS>) -> Uint<LIMBS> {
        self.mont_mul(x, &Uint::ONE)
    }

    /// Returns `(a + b) mod N` for plain residues `a, b < N`.
    #[inline]
    pub fn add_mod(&self, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
        add_mod(&self.modulus, a, b)
    }

    /// Returns `(a - b) mod N` for plain residues `a, b < N`.
    #[inline]
    pub fn sub_mod(&self, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
        sub_mod(&self.modulus, a, b)
    }

    /// Returns `(a * b) mod N` for plain residues `a, b < N`.
    pub fn mul_mod(&self, a: &Uint<LIMBS>, b: &Uint<LIMBS>) -> Uint<LIMBS> {
        // mont_mul(a, b) = ab·R^-1; multiplying by R^2 (·R^-1) restores ab.
        let t = self.mont_mul(a, b);
        self.mont_mul(&t, &self.r2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct::{ConstantTimeEq, ConstantTimeGreater};

    // --- independent reference modular arithmetic (comparison-based) ---

    fn ge<const L: usize>(a: &Uint<L>, n: &Uint<L>) -> bool {
        bool::from(a.ct_gt(n)) || bool::from(a.ct_eq(n))
    }

    fn addmod_ref<const L: usize>(a: &Uint<L>, b: &Uint<L>, n: &Uint<L>) -> Uint<L> {
        let (s, carry) = a.adc(b, 0);
        if carry == 1 || ge(&s, n) {
            s.wrapping_sub(n)
        } else {
            s
        }
    }

    fn mulmod_ref<const L: usize>(a: &Uint<L>, b: &Uint<L>, n: &Uint<L>) -> Uint<L> {
        // Double-and-add; assumes a, b < n.
        let mut res = Uint::ZERO;
        for li in (0..L).rev() {
            let limb = b.as_limbs()[li];
            for bit in (0..64).rev() {
                res = addmod_ref(&res, &res, n);
                if (limb >> bit) & 1 == 1 {
                    res = addmod_ref(&res, a, n);
                }
            }
        }
        res
    }

    #[test]
    fn mulmod_matches_u128_for_64bit() {
        let n_vals: [u64; 3] = [0xFFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0001, 97];
        let vals: [u64; 5] = [0, 1, 2, 0x1234_5678_9abc_def1, 0xfedc_ba98_7654_3211];
        for &nv in &n_vals {
            let m = MontModulus::new(Uint::<1>::from_u64(nv));
            for &av in &vals {
                for &bv in &vals {
                    let a = Uint::<1>::from_u64(av % nv);
                    let b = Uint::<1>::from_u64(bv % nv);
                    let got = m.mul_mod(&a, &b).as_limbs()[0];
                    let expected = ((av % nv) as u128 * (bv % nv) as u128 % nv as u128) as u64;
                    assert_eq!(got, expected, "n={nv} a={av} b={bv}");
                }
            }
        }
    }

    #[test]
    fn mulmod_matches_reference_128bit() {
        // Odd 128-bit moduli with values spanning both limbs.
        let moduli = [
            Uint::<2>::from_limbs([0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF]),
            Uint::<2>::from_limbs([0x1234_5678_9abc_def1, 0x0fed_cba9_8765_4321]),
            Uint::<2>::from_limbs([3, 0]),
        ];
        let vals = [
            Uint::<2>::from_limbs([0xdead_beef_cafe_babe, 0x0123_4567_89ab_cdef]),
            Uint::<2>::from_limbs([0, 1]),
            Uint::<2>::from_limbs([1, 0]),
            Uint::<2>::from_limbs([0xFFFF_FFFF_FFFF_FFFE, 0x7FFF_FFFF_FFFF_FFFE]),
        ];
        for n in &moduli {
            let m = MontModulus::new(*n);
            for a0 in &vals {
                // reduce a, b below n
                let a = reduce(a0, n);
                for b0 in &vals {
                    let b = reduce(b0, n);
                    assert_eq!(m.mul_mod(&a, &b), mulmod_ref(&a, &b, n));
                    assert_eq!(m.add_mod(&a, &b), addmod_ref(&a, &b, n));
                    // Montgomery roundtrip.
                    assert_eq!(m.from_mont(&m.to_mont(&a)), a);
                }
            }
        }
    }

    /// Reduces `x mod n` via binary long division (test moduli have their top
    /// bit clear, so `r * 2` never overflows the width).
    fn reduce<const L: usize>(x: &Uint<L>, n: &Uint<L>) -> Uint<L> {
        let mut r = Uint::ZERO;
        for li in (0..L).rev() {
            let limb = x.as_limbs()[li];
            for bit in (0..64).rev() {
                let b = (limb >> bit) & 1;
                r = r.wrapping_add(&r).wrapping_add(&Uint::from_u64(b)); // (r << 1) | b
                if ge(&r, n) {
                    r = r.wrapping_sub(n);
                }
            }
        }
        r
    }

    /// SplitMix64 — deterministic test-only RNG.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Differential: `mont_sqr(a)` must be bit-identical to `mont_mul(a, a)`
    /// for random odd moduli and residues, plus the edge values 0, 1, n-1,
    /// and all-limbs-set (reduced).
    fn sqr_matches_mul_width<const L: usize>(rng: &mut u64) {
        for _ in 0..4 {
            let mut n_limbs = [0 as Limb; L];
            for l in n_limbs.iter_mut() {
                *l = splitmix64(rng);
            }
            n_limbs[0] |= 1; // odd
            n_limbs[L - 1] &= !(1 << 63); // top bit clear so `reduce` works
            n_limbs[L - 1] |= 1 << 62; // ...but still (64L-1)-bit wide
            let n = Uint::<L>::from_limbs(n_limbs);
            let m = MontModulus::new(n);

            let mut values = [Uint::<L>::ZERO; 10];
            values[1] = Uint::ONE;
            values[2] = n.wrapping_sub(&Uint::ONE);
            values[3] = reduce(&Uint::from_limbs([Limb::MAX; L]), &n);
            for k in 0..6 {
                let mut v = [0 as Limb; L];
                for (j, l) in v.iter_mut().enumerate() {
                    // Include top-heavy values (low limbs zero).
                    *l = if k >= 4 && j < L / 2 {
                        0
                    } else {
                        splitmix64(rng)
                    };
                }
                values[4 + k] = reduce(&Uint::from_limbs(v), &n);
            }
            for a in &values {
                assert_eq!(m.mont_sqr(a), m.mont_mul(a, a), "L={L} a={a:?}");
            }
        }
    }

    #[test]
    fn mont_sqr_matches_mont_mul() {
        let mut rng: u64 = 0xD1F5_ACE5_0FBE_EF01;
        sqr_matches_mul_width::<1>(&mut rng);
        sqr_matches_mul_width::<2>(&mut rng);
        sqr_matches_mul_width::<3>(&mut rng);
        sqr_matches_mul_width::<4>(&mut rng);
        sqr_matches_mul_width::<7>(&mut rng);
        sqr_matches_mul_width::<8>(&mut rng);
        sqr_matches_mul_width::<16>(&mut rng);
    }

    #[test]
    fn sub_mod_wraps() {
        let n = Uint::<2>::from_limbs([101, 0]);
        let m = MontModulus::new(n);
        let a = Uint::<2>::from_u64(3);
        let b = Uint::<2>::from_u64(10);
        // 3 - 10 mod 101 = 94
        assert_eq!(m.sub_mod(&a, &b), Uint::<2>::from_u64(94));
    }
}
