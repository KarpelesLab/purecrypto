//! Constant-time modular inversion.
//!
//! Two building blocks, each with a fixed-size ([`Uint`]) and a runtime-sized
//! ([`BoxedUint`]) form:
//!
//! - [`inv_mod_odd_ct`]: `a⁻¹ mod m` for a **public odd** modulus `m` and a
//!   secret `a`, by a binary extended GCD that runs a fixed `2·bits(m)`
//!   iterations and selects among the four possible steps with masks. Every
//!   iteration does the same work; nothing is indexed or branched on `a`.
//! - [`inv_mod_ct`]: `e⁻¹ mod φ` for a **public odd** `e` and a secret `φ` of
//!   either parity (RSA key generation: `d = e⁻¹ mod φ(n)`). The direct
//!   extended Euclid on `φ` has a data-dependent trip count, so instead:
//!   `t = φ mod e` (constant-time long division), `y = (−t)⁻¹ mod e` via
//!   [`inv_mod_odd_ct`], and `d = (1 + φ·y) / e`. That division is exact, so
//!   it is done as a multiplication by `e⁻¹ mod 2^W` (Newton iteration on the
//!   public `e`) — no secret-dependent division anywhere.
//!
//! Both return "no inverse" (`gcd ≠ 1`) as a [`CtOption`]; whether the caller
//! turns that into a branch is its own decision (RSA key generation does,
//! since the retry is public by nature).

use super::{LIMB_BITS, Uint};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess, CtOption};

#[cfg(feature = "alloc")]
use super::BoxedUint;
#[cfg(feature = "alloc")]
use super::boxed::{adc_limbs, sbb_limbs, select_limbs};
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// `x / 2 mod m` for `x < m`, `m` odd: `x >> 1` when `x` is even, else
/// `(x + m) >> 1` (with the carry out of the addition shifted back in).
fn half_mod<const LIMBS: usize>(x: &Uint<LIMBS>, m: &Uint<LIMBS>) -> Uint<LIMBS> {
    let (sum, carry) = x.adc(m, 0);
    let mut sum_half = *sum.shr1().as_limbs();
    sum_half[LIMBS - 1] |= carry << (LIMB_BITS - 1);
    Uint::conditional_select(&Uint::from_limbs(sum_half), &x.shr1(), x.is_odd())
}

/// `(a − b) mod m` for `a, b < m`.
fn sub_mod<const LIMBS: usize>(a: &Uint<LIMBS>, b: &Uint<LIMBS>, m: &Uint<LIMBS>) -> Uint<LIMBS> {
    let (diff, borrow) = a.sbb(b, 0);
    let fixed = diff.wrapping_add(m);
    Uint::conditional_select(&fixed, &diff, Choice::from(borrow as u8))
}

/// Constant-time `a⁻¹ mod m` for an odd, public `m` (`m ≥ 3`) and a secret
/// `a` (reduced mod `m` first). Runs exactly `2·bits(m)` identical iterations
/// of the binary extended GCD; `is_none` when `gcd(a, m) ≠ 1` (including
/// `a ≡ 0`).
///
/// Invariant: `A·a ≡ u` and `C·a ≡ v (mod m)`, with `u`/`v` shrinking by at
/// least one bit per iteration until `u = 0`, at which point `v = gcd(a, m)`
/// and `C` is the inverse when that gcd is 1.
pub fn inv_mod_odd_ct<const LIMBS: usize>(
    a: &Uint<LIMBS>,
    m: &Uint<LIMBS>,
) -> CtOption<Uint<LIMBS>> {
    assert!(
        bool::from(m.is_odd()),
        "inv_mod_odd_ct: modulus must be odd"
    );
    let one = Uint::ONE;
    let mut u = a.reduce(m);
    let mut v = *m;
    let mut big_a = one;
    let mut big_c = Uint::ZERO;
    // `bits(m)` is public (the modulus is), so the trip count leaks nothing.
    for _ in 0..2 * m.bit_len() {
        let u_odd = u.is_odd();
        let v_odd = v.is_odd();
        let u_ge_v = !u.ct_lt(&v);
        let c1 = !u_odd; // u even: halve u
        let c2 = u_odd & !v_odd; // v even: halve v
        let c3 = u_odd & v_odd & u_ge_v; // both odd, u ≥ v: u = (u − v)/2
        let c4 = u_odd & v_odd & !u_ge_v; // both odd, u < v: v = (v − u)/2

        let u_half = u.shr1();
        let v_half = v.shr1();
        let umv_half = u.wrapping_sub(&v).shr1();
        let vmu_half = v.wrapping_sub(&u).shr1();
        let a_half = half_mod(&big_a, m);
        let c_half = half_mod(&big_c, m);
        let amc_half = half_mod(&sub_mod(&big_a, &big_c, m), m);
        let cma_half = half_mod(&sub_mod(&big_c, &big_a, m), m);

        u = Uint::conditional_select(&u_half, &Uint::conditional_select(&umv_half, &u, c3), c1);
        v = Uint::conditional_select(&v_half, &Uint::conditional_select(&vmu_half, &v, c4), c2);
        big_a = Uint::conditional_select(
            &a_half,
            &Uint::conditional_select(&amc_half, &big_a, c3),
            c1,
        );
        big_c = Uint::conditional_select(
            &c_half,
            &Uint::conditional_select(&cma_half, &big_c, c4),
            c2,
        );
    }
    CtOption::new(big_c, v.ct_eq(&one))
}

/// `e⁻¹ mod 2^(64·LIMBS)` for odd `e`, by Newton iteration (`e` is public;
/// the iteration count depends only on the width).
fn inv_mod_pow2<const LIMBS: usize>(e: &Uint<LIMBS>) -> Uint<LIMBS> {
    let two = Uint::from_u64(2);
    // `e·e ≡ 1 (mod 8)` for odd `e`: three correct bits to start, doubling
    // every step.
    let mut inv = *e;
    let mut correct_bits = 3;
    while correct_bits < LIMBS * LIMB_BITS {
        let e_inv = e.mul_wide(&inv).0;
        inv = inv.mul_wide(&two.wrapping_sub(&e_inv)).0;
        correct_bits *= 2;
    }
    inv
}

/// Constant-time `e⁻¹ mod phi` for a public odd `e ≥ 3` and a secret `phi`
/// (`phi > e`, either parity). `is_none` when `gcd(e, phi) ≠ 1`.
///
/// With `t = phi mod e` and `y = (−t)⁻¹ mod e`, `1 + phi·y` is an exact
/// multiple of `e`, and the quotient `d = (1 + phi·y)/e` satisfies
/// `e·d ≡ 1 (mod phi)` with `d < phi`. The exact division is a
/// multiplication by `e⁻¹ mod 2^W`, so the whole computation is
/// multiplications, one constant-time reduction and one
/// [`inv_mod_odd_ct`].
pub fn inv_mod_ct<const LIMBS: usize>(e: &Uint<LIMBS>, phi: &Uint<LIMBS>) -> CtOption<Uint<LIMBS>> {
    assert!(bool::from(e.is_odd()), "inv_mod_ct: e must be odd");
    let t = phi.reduce(e);
    let neg_t = sub_mod(&Uint::ZERO, &t, e);
    let y = inv_mod_odd_ct(&neg_t, e);
    let e_inv = inv_mod_pow2(e);
    let num = phi
        .mul_wide(&y.unwrap_or(Uint::ZERO))
        .0
        .wrapping_add(&Uint::ONE);
    let d = num.mul_wide(&e_inv).0;
    CtOption::new(d, y.is_some())
}

// ---- runtime-sized ---------------------------------------------------------

/// Low bit of a limb vector as a [`Choice`].
#[cfg(feature = "alloc")]
fn odd_limbs(x: &[u64]) -> Choice {
    Choice::from((x[0] & 1) as u8)
}

/// `x / 2 mod m` on limb slices of equal length, `x < m`, `m` odd.
#[cfg(feature = "alloc")]
fn half_mod_limbs(x: &[u64], m: &[u64]) -> Vec<u64> {
    let n = x.len();
    let (sum, carry) = adc_limbs(x, m, 0);
    let mut sum_half = shr1_limbs(&sum);
    sum_half[n - 1] |= carry << (LIMB_BITS - 1);
    select_limbs(&sum_half, &shr1_limbs(x), odd_limbs(x))
}

/// `(a − b) mod m` on limb slices of equal length, `a, b < m`.
#[cfg(feature = "alloc")]
fn sub_mod_limbs(a: &[u64], b: &[u64], m: &[u64]) -> Vec<u64> {
    let (diff, borrow) = sbb_limbs(a, b, 0);
    let (fixed, _) = adc_limbs(&diff, m, 0);
    select_limbs(&fixed, &diff, Choice::from(borrow as u8))
}

/// `x >> 1` on a limb slice.
#[cfg(feature = "alloc")]
fn shr1_limbs(x: &[u64]) -> Vec<u64> {
    let mut out = x.to_vec();
    let mut carry = 0u64;
    for limb in out.iter_mut().rev() {
        let next = *limb & 1;
        *limb = (*limb >> 1) | (carry << (LIMB_BITS - 1));
        carry = next;
    }
    out
}

/// `a < b` on limb slices of equal length, as a [`Choice`].
#[cfg(feature = "alloc")]
fn lt_limbs(a: &[u64], b: &[u64]) -> Choice {
    let (_, borrow) = sbb_limbs(a, b, 0);
    Choice::from(borrow as u8)
}

/// Runtime-sized [`inv_mod_odd_ct`]. The result has `m`'s limb count.
#[cfg(feature = "alloc")]
pub fn inv_mod_odd_ct_boxed(a: &BoxedUint, m: &BoxedUint) -> CtOption<BoxedUint> {
    let (inv, ok) = xgcd_boxed(a, m);
    CtOption::new(inv, ok)
}

/// The binary extended GCD behind [`inv_mod_odd_ct_boxed`]: returns the
/// candidate inverse and whether `gcd(a, m) = 1`.
#[cfg(feature = "alloc")]
fn xgcd_boxed(a: &BoxedUint, m: &BoxedUint) -> (BoxedUint, Choice) {
    assert!(m.is_odd(), "inv_mod_odd_ct_boxed: modulus must be odd");
    let n = m.limbs();
    let m_limbs = m.as_limbs();
    let mut u = a.reduce(m).limbs_resized(n);
    let mut v = m_limbs.to_vec();
    let mut big_a = BoxedUint::from_u64(1).limbs_resized(n);
    let mut big_c = alloc::vec![0u64; n];
    for _ in 0..2 * m.bit_len() {
        let u_odd = odd_limbs(&u);
        let v_odd = odd_limbs(&v);
        let u_ge_v = !lt_limbs(&u, &v);
        let c1 = !u_odd;
        let c2 = u_odd & !v_odd;
        let c3 = u_odd & v_odd & u_ge_v;
        let c4 = u_odd & v_odd & !u_ge_v;

        let u_half = shr1_limbs(&u);
        let v_half = shr1_limbs(&v);
        let umv_half = shr1_limbs(&sbb_limbs(&u, &v, 0).0);
        let vmu_half = shr1_limbs(&sbb_limbs(&v, &u, 0).0);
        let a_half = half_mod_limbs(&big_a, m_limbs);
        let c_half = half_mod_limbs(&big_c, m_limbs);
        let amc_half = half_mod_limbs(&sub_mod_limbs(&big_a, &big_c, m_limbs), m_limbs);
        let cma_half = half_mod_limbs(&sub_mod_limbs(&big_c, &big_a, m_limbs), m_limbs);

        u = select_limbs(&u_half, &select_limbs(&umv_half, &u, c3), c1);
        v = select_limbs(&v_half, &select_limbs(&vmu_half, &v, c4), c2);
        big_a = select_limbs(&a_half, &select_limbs(&amc_half, &big_a, c3), c1);
        big_c = select_limbs(&c_half, &select_limbs(&cma_half, &big_c, c4), c2);
    }
    let is_one = BoxedUint::from_limbs(v).ct_eq(&BoxedUint::from_u64(1));
    (BoxedUint::from_limbs(big_c), is_one)
}

/// Runtime-sized [`inv_mod_ct`]. The result has `phi`'s limb count.
#[cfg(feature = "alloc")]
pub fn inv_mod_ct_boxed(e: &BoxedUint, phi: &BoxedUint) -> CtOption<BoxedUint> {
    assert!(e.is_odd(), "inv_mod_ct_boxed: e must be odd");
    let w = phi.limbs();
    let t = phi.reduce(e);
    let e_w = e.limbs_resized(e.limbs());
    let zero = alloc::vec![0u64; e.limbs()];
    let neg_t = sub_mod_limbs(&zero, &t.limbs_resized(e.limbs()), &e_w);
    // When there is no inverse `y` is garbage, but the result is flagged
    // `none` and the arithmetic below runs on it regardless (same work).
    let (y, ok) = xgcd_boxed(&BoxedUint::from_limbs(neg_t), e);
    // e⁻¹ mod 2^(64·w) by Newton iteration on the public `e`.
    let e_low = e.limbs_resized(w);
    let mut inv = e_low.clone();
    let mut correct_bits = 3;
    while correct_bits < w * LIMB_BITS {
        let e_inv = BoxedUint::from_limbs(e_low.clone())
            .mul(&BoxedUint::from_limbs(inv.clone()))
            .limbs_resized(w);
        let two_minus = BoxedUint::from_u64(2).limbs_resized(w);
        let (two_minus, _) = sbb_limbs(&two_minus, &e_inv, 0);
        inv = BoxedUint::from_limbs(inv)
            .mul(&BoxedUint::from_limbs(two_minus))
            .limbs_resized(w);
        correct_bits *= 2;
    }
    let num = phi.mul(&y).limbs_resized(w);
    let (num, _) = adc_limbs(&num, &BoxedUint::from_u64(1).limbs_resized(w), 0);
    let d = BoxedUint::from_limbs(num)
        .mul(&BoxedUint::from_limbs(inv))
        .limbs_resized(w);
    CtOption::new(BoxedUint::from_limbs(d), ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::inv_mod;

    fn lcg(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        *state ^ (*state >> 29)
    }

    fn random_uint<const LIMBS: usize>(state: &mut u64) -> Uint<LIMBS> {
        let mut limbs = [0u64; LIMBS];
        for l in &mut limbs {
            *l = lcg(state);
        }
        Uint::from_limbs(limbs)
    }

    #[test]
    fn odd_modulus_inverse_matches_euclid() {
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..200 {
            let m = random_uint::<4>(&mut state);
            let m = Uint::from_limbs({
                let mut l = *m.as_limbs();
                l[0] |= 1;
                l
            });
            let a = random_uint::<4>(&mut state);
            let expect = inv_mod(&a, &m);
            let got = inv_mod_odd_ct(&a, &m).into_option();
            assert_eq!(got, expect);
        }
        // Small hand cases.
        let m = Uint::<1>::from_u64(65537);
        assert_eq!(
            inv_mod_odd_ct(&Uint::from_u64(3), &m).into_option(),
            inv_mod(&Uint::from_u64(3), &m)
        );
        assert!(
            inv_mod_odd_ct(&Uint::from_u64(0), &m)
                .into_option()
                .is_none()
        );
        let m = Uint::<1>::from_u64(15);
        assert!(
            inv_mod_odd_ct(&Uint::from_u64(5), &m)
                .into_option()
                .is_none()
        );
        assert_eq!(
            inv_mod_odd_ct(&Uint::from_u64(7), &m).into_option(),
            Some(Uint::from_u64(13))
        );
    }

    #[test]
    fn public_e_inverse_matches_euclid() {
        let mut state = 0xdead_beef_0bad_f00du64;
        for &e in &[3u64, 5, 17, 257, 65537, 0x1_0000_0001, (1u64 << 63) | 12345] {
            let e = Uint::<8>::from_u64(e);
            for _ in 0..40 {
                // Even and odd φ alike.
                let phi = random_uint::<8>(&mut state);
                let expect = inv_mod(&e, &phi);
                let got = inv_mod_ct(&e, &phi).into_option();
                assert_eq!(got, expect, "e={e:?}");
                if let Some(d) = got {
                    // e·d ≡ 1 (mod φ)
                    let (lo, hi) = e.mul_wide(&d);
                    let prod = Uint::<16>::from_limbs({
                        let mut l = [0u64; 16];
                        l[..8].copy_from_slice(lo.as_limbs());
                        l[8..].copy_from_slice(hi.as_limbs());
                        l
                    });
                    let phi16 = Uint::<16>::from_limbs({
                        let mut l = [0u64; 16];
                        l[..8].copy_from_slice(phi.as_limbs());
                        l
                    });
                    assert_eq!(prod.reduce(&phi16), Uint::<16>::ONE);
                    assert!(bool::from(d.ct_lt(&phi)));
                }
            }
        }
        // A 256-bit e (the RSA cap).
        let e = Uint::<8>::from_limbs([0x1234_5679, 0xabcd, 0, 0x8000_0000_0000_0001, 0, 0, 0, 0]);
        let phi = Uint::<8>::from_limbs([0xfffe, 0, 0, 0, 0, 0x77, 0, 0x1234]);
        assert_eq!(inv_mod_ct(&e, &phi).into_option(), inv_mod(&e, &phi));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn boxed_forms_match_fixed() {
        use crate::bignum::inv_mod_boxed;
        let mut state = 0x0f0f_1e1e_2d2d_3c3cu64;
        for _ in 0..100 {
            let m = random_uint::<4>(&mut state);
            let mut ml = *m.as_limbs();
            ml[0] |= 1;
            let m = BoxedUint::from_limbs(ml.to_vec());
            let a = BoxedUint::from_limbs(random_uint::<4>(&mut state).as_limbs().to_vec());
            assert_eq!(
                inv_mod_odd_ct_boxed(&a, &m).into_option(),
                inv_mod_boxed(&a, &m)
            );
        }
        for &e in &[3u64, 65537, 0x1_0000_0001] {
            let e = BoxedUint::from_u64(e);
            for _ in 0..40 {
                let phi = BoxedUint::from_limbs(random_uint::<6>(&mut state).as_limbs().to_vec());
                let expect = inv_mod_boxed(&e, &phi);
                let got = inv_mod_ct_boxed(&e, &phi).into_option();
                assert_eq!(
                    got.as_ref().map(|d| d.to_be_bytes(48)),
                    expect.as_ref().map(|d| d.to_be_bytes(48))
                );
            }
        }
    }
}
