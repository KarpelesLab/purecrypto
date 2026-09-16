//! Modular inverse via the extended Euclidean algorithm.

use super::Uint;
use crate::ct::ConstantTimeLess;

#[cfg(feature = "alloc")]
use super::BoxedUint;

/// Runtime-sized counterpart of [`inv_mod`] for [`BoxedUint`]. Same iterative
/// extended-Euclid algorithm and non-constant-time caveat; used by runtime RSA
/// key generation.
#[cfg(feature = "alloc")]
pub fn inv_mod_boxed(a: &BoxedUint, m: &BoxedUint) -> Option<BoxedUint> {
    if a.is_zero() || m.is_zero() {
        return None;
    }
    let one = BoxedUint::from_u64(1);
    let (mut old_r, mut r) = (a.reduce(m), m.clone());
    let (mut old_s, mut old_neg) = (one.clone(), false);
    let (mut s, mut s_neg) = (BoxedUint::zero(m.limbs()), false);

    while !r.is_zero() {
        let (q, rem) = old_r.divrem(&r);
        old_r = r;
        r = rem;
        // new_s = old_s - q*s, in sign-magnitude (the magnitude stays below m).
        let qs = q.mul(&s);
        let (new_s, new_neg) = signed_sub_boxed(&old_s, old_neg, &qs, s_neg);
        old_s = s;
        old_neg = s_neg;
        // `|new_s| <= m` (Bézout), so trimming to `m`'s width drops only zero
        // limbs. Without this, `mul` widens by `m.limbs()` and `add` by one
        // limb on every step, so `s` grows linearly with the iteration count
        // and the whole loop goes quadratic: ~35 ms for a 1024-bit inverse.
        s = BoxedUint::from_limbs(new_s.limbs_resized(m.limbs()));
        s_neg = new_neg;
    }

    if old_r != one {
        return None; // gcd(a, m) != 1
    }
    if old_neg {
        Some(m.sub(&old_s).reduce(m))
    } else {
        Some(old_s.reduce(m))
    }
}

/// `(±a) − (±b)` in sign-magnitude for [`BoxedUint`].
#[cfg(feature = "alloc")]
fn signed_sub_boxed(a: &BoxedUint, a_neg: bool, b: &BoxedUint, b_neg: bool) -> (BoxedUint, bool) {
    if a_neg == b_neg {
        if !a.lt(b) {
            (a.sub(b), a_neg)
        } else {
            (b.sub(a), !a_neg)
        }
    } else {
        (a.add(b), a_neg)
    }
}

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

    /// `inv_mod_boxed` on RSA-prime-sized operands: the inverse must satisfy
    /// `a · a⁻¹ ≡ 1 (mod m)` for odd and even multi-limb moduli, agree with
    /// the fixed-width `inv_mod`, and report `None` when `gcd(a, m) != 1`.
    #[cfg(feature = "alloc")]
    #[test]
    fn boxed_inverse_multi_limb() {
        use super::super::BoxedMontModulus;
        use alloc::vec::Vec;

        let mut s = 0x5EED_1234_ABCD_EF01u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };

        // 1024-bit odd modulus, random residue: Montgomery check.
        for _ in 0..3 {
            let mut m_limbs: Vec<u64> = (0..16).map(|_| next()).collect();
            m_limbs[0] |= 1;
            let m = BoxedUint::from_limbs(m_limbs);
            let a_limbs: Vec<u64> = (0..16).map(|_| next()).collect();
            let a = BoxedUint::from_limbs(a_limbs).reduce(&m);
            if let Some(inv) = inv_mod_boxed(&a, &m) {
                assert!(inv.lt(&m), "inverse must be reduced");
                let mont = BoxedMontModulus::new(&m);
                assert_eq!(mont.mul_mod(&a, &inv), BoxedUint::from_u64(1));
            }
        }

        // Even modulus (an RSA φ(n)-like value) with e = 65537: check via
        // widening multiply and long division.
        let mut phi_limbs: Vec<u64> = (0..16).map(|_| next()).collect();
        phi_limbs[0] &= !1;
        let phi = BoxedUint::from_limbs(phi_limbs);
        let e = BoxedUint::from_u64(65537);
        if let Some(d) = inv_mod_boxed(&e, &phi) {
            assert!(d.lt(&phi));
            assert_eq!(e.mul(&d).reduce(&phi), BoxedUint::from_u64(1));
        }

        // Agrees with the fixed-width routine on a 128-bit odd modulus.
        let m2 = Uint::<2>::from_limbs([0x1234_5678_9abc_def1, 0x0fed_cba9_8765_4321]);
        let a2 = Uint::<2>::from_u64(0x9e37_79b9_7f4a_7c15);
        let want = inv_mod(&a2, &m2).expect("coprime");
        let got = inv_mod_boxed(
            &BoxedUint::from_limbs(a2.as_limbs().to_vec()),
            &BoxedUint::from_limbs(m2.as_limbs().to_vec()),
        )
        .expect("coprime");
        assert_eq!(got.as_limbs()[..2], want.as_limbs()[..]);

        // Not invertible: shared factor 3.
        let m3 = BoxedUint::from_u64(3).mul(&BoxedUint::from_limbs(alloc::vec![u64::MAX, 7]));
        let a3 = BoxedUint::from_u64(3).mul(&BoxedUint::from_limbs(alloc::vec![5, 1]));
        assert!(inv_mod_boxed(&a3, &m3).is_none());
        assert!(inv_mod_boxed(&BoxedUint::zero(2), &m3).is_none());
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
