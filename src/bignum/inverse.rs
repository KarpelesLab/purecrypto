//! Modular inverse via the binary extended GCD.

use super::Uint;
use super::uint::LIMB_BITS;
use crate::ct::ConstantTimeLess;

/// Computes `a^-1 mod m` for an **odd** modulus `m`, returning `None` when no
/// inverse exists (`gcd(a, m) != 1`, or `a == 0`).
///
/// Uses the binary extended GCD. **This routine is not constant time** — its
/// control flow and iteration count depend on the operand values. It is meant
/// for key generation (computing `d = e^-1 mod λ(n)`, a one-time step), not for
/// repeated operations on attacker-influenced secrets. A constant-time
/// replacement (e.g. safegcd) can be dropped in later.
///
/// `a` is expected to be reduced (`a < m`).
pub fn inv_mod<const LIMBS: usize>(a: &Uint<LIMBS>, m: &Uint<LIMBS>) -> Option<Uint<LIMBS>> {
    debug_assert!(bool::from(m.is_odd()), "modulus must be odd");
    if bool::from(a.is_zero()) {
        return None;
    }

    // Invariant: a * x1 ≡ u  and  a * x2 ≡ v  (mod m).
    let mut u = *a;
    let mut v = *m;
    let mut x1 = Uint::ONE;
    let mut x2 = Uint::ZERO;

    let one = Uint::ONE;
    // Each main-loop turn strictly reduces u + v's size; this bound is generous
    // and guarantees termination (returning None) for non-coprime inputs.
    let max_iters = 8 * LIMBS * LIMB_BITS;
    let mut iters = 0;

    while u != one && v != one {
        iters += 1;
        if iters > max_iters {
            return None;
        }

        while !bool::from(u.is_odd()) && !bool::from(u.is_zero()) {
            u = u.shr1();
            x1 = half_mod(&x1, m);
        }
        while !bool::from(v.is_odd()) && !bool::from(v.is_zero()) {
            v = v.shr1();
            x2 = half_mod(&x2, m);
        }

        // u >= v  ⇔  not (u < v)
        if !bool::from(u.ct_lt(&v)) {
            u = u.wrapping_sub(&v);
            x1 = sub_mod(&x1, &x2, m);
        } else {
            v = v.wrapping_sub(&u);
            x2 = sub_mod(&x2, &x1, m);
        }
    }

    if u == one { Some(x1) } else { Some(x2) }
}

/// `(a - b) mod m`, for `a, b < m`.
fn sub_mod<const LIMBS: usize>(a: &Uint<LIMBS>, b: &Uint<LIMBS>, m: &Uint<LIMBS>) -> Uint<LIMBS> {
    let (diff, borrow) = a.sbb(b, 0);
    let (wrapped, _) = diff.adc(m, 0);
    if borrow == 1 { wrapped } else { diff }
}

/// `x / 2 mod m` (i.e. `x * 2^-1 mod m`) for odd `m` and `x < m`.
fn half_mod<const LIMBS: usize>(x: &Uint<LIMBS>, m: &Uint<LIMBS>) -> Uint<LIMBS> {
    if bool::from(x.is_odd()) {
        // x odd, m odd => x + m even; halve the (LIMBS+1)-bit sum.
        let (sum, carry) = x.adc(m, 0);
        let mut limbs = *sum.shr1().as_limbs();
        if carry == 1 {
            limbs[LIMBS - 1] |= 1 << (LIMB_BITS - 1);
        }
        Uint::from_limbs(limbs)
    } else {
        x.shr1()
    }
}

#[cfg(test)]
mod tests {
    use super::super::MontModulus;
    use super::*;
    use crate::ct::ConstantTimeEq;

    #[test]
    fn small_inverses() {
        // 3^-1 mod 11 = 4
        assert_eq!(
            inv_mod(&Uint::<1>::from_u64(3), &Uint::<1>::from_u64(11)),
            Some(Uint::<1>::from_u64(4))
        );
        // 7^-1 mod 15 = 13 (15 is composite but coprime to 7)
        assert_eq!(
            inv_mod(&Uint::<1>::from_u64(7), &Uint::<1>::from_u64(15)),
            Some(Uint::<1>::from_u64(13))
        );
    }

    #[test]
    fn non_invertible_returns_none() {
        // gcd(3, 15) = 3
        assert_eq!(
            inv_mod(&Uint::<1>::from_u64(3), &Uint::<1>::from_u64(15)),
            None
        );
        // gcd(0, m) — zero has no inverse
        assert_eq!(inv_mod(&Uint::<1>::ZERO, &Uint::<1>::from_u64(7)), None);
    }

    #[test]
    fn inverse_property_u64() {
        let moduli: [u64; 3] = [97, 0xFFFF_FFFF_FFFF_FFFF, 1_000_003];
        let vals: [u64; 4] = [2, 3, 0x1234_5678, 0xfedc_ba98_7654_3211];
        for &m in &moduli {
            for &a in &vals {
                let a = a % m;
                if a == 0 {
                    continue;
                }
                if let Some(inv) = inv_mod(&Uint::<1>::from_u64(a), &Uint::<1>::from_u64(m)) {
                    let prod = (a as u128 * inv.as_limbs()[0] as u128 % m as u128) as u64;
                    assert_eq!(prod, 1, "a={a} m={m}");
                }
            }
        }
    }

    #[test]
    fn inverse_property_128bit() {
        // Verify a * a^-1 ≡ 1 (mod m) using Montgomery mul, for an odd composite m.
        let m = Uint::<2>::from_limbs([0x1234_5678_9abc_def1, 0x0fed_cba9_8765_4321]);
        let modulus = MontModulus::new(m);
        let a = Uint::<2>::from_u64(0x9e3779b97f4a7c15);
        let inv = inv_mod(&a, &m).expect("a coprime to m");
        assert!(bool::from(modulus.mul_mod(&a, &inv).ct_eq(&Uint::ONE)));
    }

    #[test]
    fn rsa_style_exponent() {
        // d = e^-1 mod λ, with e = 65537 and a composite λ; check e*d ≡ 1.
        let lambda = Uint::<2>::from_u64(0x0003_a8f2_1c4b_d7e9); // arbitrary odd value
        let e = Uint::<2>::from_u64(65537);
        let d = inv_mod(&e, &lambda).expect("65537 coprime to lambda");
        let modulus = MontModulus::new(lambda);
        assert!(bool::from(modulus.mul_mod(&e, &d).ct_eq(&Uint::ONE)));
    }
}
