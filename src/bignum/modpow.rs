//! Constant-time modular exponentiation and inversion.

use super::MontModulus;
use super::Uint;
use crate::ct::{Choice, ConditionallySelectable};

impl<const LIMBS: usize> MontModulus<LIMBS> {
    /// Computes `base^exp mod N` in constant time, for `base < N`.
    ///
    /// Uses the square-and-multiply-always ladder over Montgomery
    /// multiplication: every exponent bit performs one squaring and one
    /// multiplication, and selects the result with a constant-time
    /// [`ConditionallySelectable`], so the running time is independent of the
    /// exponent's value (suitable for secret exponents).
    pub fn pow(&self, base: &Uint<LIMBS>, exp: &Uint<LIMBS>) -> Uint<LIMBS> {
        let base_m = self.to_mont(base);
        // Montgomery form of 1 is R mod N.
        let mut acc = self.to_mont(&Uint::ONE);

        let exp = exp.as_limbs();
        let mut limb_idx = LIMBS;
        while limb_idx > 0 {
            limb_idx -= 1;
            let limb = exp[limb_idx];
            let mut bit = 64;
            while bit > 0 {
                bit -= 1;
                acc = self.mont_mul(&acc, &acc);
                let multiplied = self.mont_mul(&acc, &base_m);
                let set = Choice::from(((limb >> bit) & 1) as u8);
                // Take the multiplied value when the exponent bit is set.
                acc = Uint::conditional_select(&multiplied, &acc, set);
            }
        }

        self.from_mont(&acc)
    }

    /// Computes the modular inverse `a^-1 mod N` **assuming `N` is prime**, via
    /// Fermat's little theorem (`a^(N-2) mod N`). Constant time.
    ///
    /// For a non-prime modulus this does not produce an inverse; a general
    /// constant-time inversion (binary GCD) is a separate routine.
    pub fn inv_prime(&self, a: &Uint<LIMBS>) -> Uint<LIMBS> {
        let exp = self.modulus().wrapping_sub(&Uint::from_u64(2));
        self.pow(a, &exp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ct::ConstantTimeEq;

    fn modexp_u64(base: u64, mut exp: u64, n: u64) -> u64 {
        let nn = n as u128;
        let mut r: u128 = 1 % nn;
        let mut b = base as u128 % nn;
        while exp > 0 {
            if exp & 1 == 1 {
                r = r * b % nn;
            }
            b = b * b % nn;
            exp >>= 1;
        }
        r as u64
    }

    #[test]
    fn pow_matches_u128() {
        let moduli: [u64; 3] = [0xFFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0001, 1_000_003];
        let bases: [u64; 4] = [0, 2, 3, 0x1234_5678_9abc_def1];
        let exps: [u64; 4] = [0, 1, 17, 0xdead_beef];
        for &n in &moduli {
            let m = MontModulus::new(Uint::<2>::from_u64(n));
            for &base in &bases {
                for &e in &exps {
                    let got = m
                        .pow(&Uint::<2>::from_u64(base % n), &Uint::<2>::from_u64(e))
                        .as_limbs()[0];
                    assert_eq!(got, modexp_u64(base % n, e, n), "{base}^{e} mod {n}");
                }
            }
        }
    }

    #[test]
    fn textbook_rsa() {
        // p=61, q=53, n=3233, e=17, d=2753; encrypt/decrypt m=65.
        let m = MontModulus::new(Uint::<1>::from_u64(3233));
        let msg = Uint::<1>::from_u64(65);
        let ct = m.pow(&msg, &Uint::from_u64(17));
        assert_eq!(ct, Uint::<1>::from_u64(2790));
        let back = m.pow(&ct, &Uint::from_u64(2753));
        assert_eq!(back, msg);
    }

    #[test]
    fn fermat_inverse_mod_mersenne_prime() {
        // 2^127 - 1 is a (prime) Mersenne prime.
        let p = Uint::<2>::from_limbs([u64::MAX, 0x7FFF_FFFF_FFFF_FFFF]);
        let m = MontModulus::new(p);
        let p_minus_1 = p.wrapping_sub(&Uint::ONE);

        let values = [
            Uint::<2>::from_u64(2),
            Uint::<2>::from_u64(3),
            Uint::<2>::from_limbs([0x0123_4567_89ab_cdef, 0x1111_2222_3333_4444]),
        ];
        for a in &values {
            // a^(p-1) == 1 (mod p) for a != 0.
            assert!(bool::from(m.pow(a, &p_minus_1).ct_eq(&Uint::ONE)));
            // a * a^-1 == 1 (mod p).
            let inv = m.inv_prime(a);
            assert!(bool::from(m.mul_mod(a, &inv).ct_eq(&Uint::ONE)));
        }
    }
}
