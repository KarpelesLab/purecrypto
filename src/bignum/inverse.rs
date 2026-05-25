//! Modular inverse via the extended Euclidean algorithm.

use super::Uint;
use crate::ct::ConstantTimeLess;

/// Computes `a^-1 mod m`, returning `None` when no inverse exists
/// (`gcd(a, m) != 1`, or `a`/`m` is zero). Works for any modulus, even or odd.
///
/// Uses the iterative extended Euclidean algorithm, tracking the Bézout
/// coefficient for `a` as a sign-magnitude value (its magnitude stays below
/// `m`). **This routine is not constant time** — its control flow and
/// iteration count depend on the operands. It is intended for key generation
/// (computing `d = e^-1 mod φ(n)`, a one-time step), not for repeated use on
/// attacker-influenced secrets; a constant-time replacement (safegcd) can be
/// dropped in later.
pub fn inv_mod<const LIMBS: usize>(a: &Uint<LIMBS>, m: &Uint<LIMBS>) -> Option<Uint<LIMBS>> {
    if bool::from(a.is_zero()) || bool::from(m.is_zero()) {
        return None;
    }

    let one = Uint::ONE;
    let (mut old_r, mut r) = (a.reduce(m), *m);
    // Bézout coefficient for `a`, as (magnitude, is_negative).
    let (mut old_s, mut old_neg) = (one, false);
    let (mut s, mut s_neg) = (Uint::ZERO, false);

    while !bool::from(r.is_zero()) {
        let (q, rem) = old_r.divrem(&r);
        old_r = r;
        r = rem;

        // new_s = old_s - q * s. The product q*|s| stays below m, so the low
        // half of the widening multiply is exact.
        let qs = q.mul_wide(&s).0;
        let (new_s, new_neg) = signed_sub(&old_s, old_neg, &qs, s_neg);
        old_s = s;
        old_neg = s_neg;
        s = new_s;
        s_neg = new_neg;
    }

    if old_r != one {
        return None; // gcd(a, m) != 1
    }
    // Reduce the (possibly negative) coefficient into [0, m).
    if old_neg {
        Some(m.wrapping_sub(&old_s))
    } else {
        Some(old_s)
    }
}

/// Computes `(±a) - (±b)` in sign-magnitude, where the inputs and result all
/// have magnitude `< m` (so the additions/subtractions don't overflow).
fn signed_sub<const LIMBS: usize>(
    a: &Uint<LIMBS>,
    a_neg: bool,
    b: &Uint<LIMBS>,
    b_neg: bool,
) -> (Uint<LIMBS>, bool) {
    if a_neg == b_neg {
        // Same sign: result = sign * (a - b).
        if !bool::from(a.ct_lt(b)) {
            (a.wrapping_sub(b), a_neg) // a >= b
        } else {
            (b.wrapping_sub(a), !a_neg)
        }
    } else {
        // Opposite signs: result = sign(a) * (a + b).
        (a.wrapping_add(b), a_neg)
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
        // 7^-1 mod 15 = 13
        assert_eq!(
            inv_mod(&Uint::<1>::from_u64(7), &Uint::<1>::from_u64(15)),
            Some(Uint::<1>::from_u64(13))
        );
        // Even modulus: 3^-1 mod 10 = 7
        assert_eq!(
            inv_mod(&Uint::<1>::from_u64(3), &Uint::<1>::from_u64(10)),
            Some(Uint::<1>::from_u64(7))
        );
        // 1^-1 mod m = 1
        assert_eq!(
            inv_mod(&Uint::<1>::ONE, &Uint::<1>::from_u64(97)),
            Some(Uint::<1>::ONE)
        );
    }

    #[test]
    fn non_invertible_returns_none() {
        assert_eq!(
            inv_mod(&Uint::<1>::from_u64(3), &Uint::<1>::from_u64(15)),
            None // gcd = 3
        );
        assert_eq!(
            inv_mod(&Uint::<1>::from_u64(4), &Uint::<1>::from_u64(10)),
            None // gcd = 2
        );
        assert_eq!(inv_mod(&Uint::<1>::ZERO, &Uint::<1>::from_u64(7)), None);
    }

    #[test]
    fn inverse_property_u64() {
        let moduli: [u64; 4] = [97, 0xFFFF_FFFF_FFFF_FFFF, 1_000_003, 0x1_0000_0000];
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
    fn inverse_property_128bit_odd() {
        let m = Uint::<2>::from_limbs([0x1234_5678_9abc_def1, 0x0fed_cba9_8765_4321]);
        let modulus = MontModulus::new(m);
        let a = Uint::<2>::from_u64(0x9e3779b97f4a7c15);
        let inv = inv_mod(&a, &m).expect("a coprime to m");
        assert!(bool::from(modulus.mul_mod(&a, &inv).ct_eq(&Uint::ONE)));
    }

    #[test]
    fn rsa_style_even_modulus() {
        // φ(n) is even; check e * (e^-1 mod φ) ≡ 1 (mod φ) via long division.
        let phi = Uint::<2>::from_u64(0x0003_a8f2_1c4b_d7e8); // even
        let e = Uint::<2>::from_u64(65537);
        let d = inv_mod(&e, &phi).expect("65537 coprime to phi");
        let prod = e.mul_wide(&d).0; // e*d fits in 2 limbs here
        assert_eq!(prod.divrem(&phi).1, Uint::ONE);
    }
}
