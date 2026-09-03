//! Constant-time modular exponentiation and inversion.

use super::MontModulus;
use super::Uint;
use crate::ct::{Choice, ConditionallySelectable};

impl<const LIMBS: usize> MontModulus<LIMBS> {
    /// Computes `base^exp mod N` in constant time, for `base < N`.
    ///
    /// Fixed-window (`W = 4`) square-and-multiply over Montgomery
    /// multiplication. Every window performs `W` squarings and exactly one
    /// multiplication by a table entry chosen with a constant-time scan over
    /// all `2^W` entries, so both the operation sequence and the memory access
    /// pattern are independent of the exponent — suitable for secret exponents.
    ///
    /// The window replaces the older multiply-always ladder, which spent two
    /// Montgomery multiplies per exponent *bit*. At `W = 4` a `b`-bit exponent
    /// costs `b` squarings plus `b/4` multiplies instead of `b` plus `b`, i.e.
    /// about 1.6x fewer multiplies, which is the dominant cost in RSA and DH.
    ///
    /// The table is `2^W` values of `Uint<LIMBS>` on the stack —
    /// `16 * LIMBS * 8` bytes, so 4 KiB for a 2048-bit modulus and 16 KiB for
    /// an 8192-bit one. That matters on small no-`alloc` targets; the window is
    /// a compile-time constant here so it can be lowered if it ever needs to be.
    pub fn pow(&self, base: &Uint<LIMBS>, exp: &Uint<LIMBS>) -> Uint<LIMBS> {
        /// Window width in bits. Must divide 64 so windows never straddle limbs.
        const W: usize = 4;
        const TABLE: usize = 1 << W;

        let base_m = self.to_mont(base);
        let one_m = self.to_mont(&Uint::ONE);

        // table[i] = base^i in Montgomery form.
        let mut table = [one_m; TABLE];
        table[1] = base_m;
        let mut i = 2;
        while i < TABLE {
            table[i] = self.mont_mul(&table[i - 1], &base_m);
            i += 1;
        }

        let exp = exp.as_limbs();
        let mut acc = one_m;
        // Most-significant window first. `LIMBS * 64` is a multiple of W, so
        // every window lies inside one limb.
        let mut bit = LIMBS * 64;
        while bit >= W {
            bit -= W;
            // acc = acc^(2^W)
            let mut k = 0;
            while k < W {
                acc = self.mont_sqr(&acc);
                k += 1;
            }
            let idx = ((exp[bit / 64] >> (bit % 64)) & ((1 << W) - 1)) as usize;
            // Constant-time gather: touch every table entry in a fixed order
            // and keep the one whose index matches. A direct `table[idx]` would
            // make the load address depend on the secret exponent.
            // Note the argument order: this crate's `conditional_select(a, b, c)`
            // returns `a` when `c` is true (inverted from the `subtle` crate),
            // so the matching entry goes first.
            let mut sel = table[0];
            for (j, t) in table.iter().enumerate() {
                sel = Uint::conditional_select(t, &sel, Choice::from((j == idx) as u8));
            }
            // Unconditional: a zero window multiplies by the Montgomery 1.
            acc = self.mont_mul(&acc, &sel);
        }

        self.from_mont(&acc)
    }

    /// Computes `base^exp mod N` for a **public** exponent.
    ///
    /// Square-and-multiply-*always* exactly like [`pow`](Self::pow) — branchless
    /// and leaking nothing about `base` — but it iterates `exp.bit_len()` times
    /// instead of padding to the full modulus width, so its running time depends
    /// on `exp`. **`exp` must be public** (e.g. an RSA public exponent in
    /// verify/encrypt, where both `exp` and `base` are public); never call it
    /// with a secret exponent — use [`pow`](Self::pow) for those. For the common
    /// RSA `e = 65537` this replaces ~2048 squarings with ~17.
    pub fn pow_public(&self, base: &Uint<LIMBS>, exp: &Uint<LIMBS>) -> Uint<LIMBS> {
        let base_m = self.to_mont(base);
        // Montgomery form of 1 is R mod N.
        let mut acc = self.to_mont(&Uint::ONE);

        let bits = exp.bit_len();
        // base^0 = 1.
        if bits == 0 {
            return self.from_mont(&acc);
        }
        let exp = exp.as_limbs();
        let mut i = bits;
        while i > 0 {
            i -= 1;
            acc = self.mont_sqr(&acc);
            let multiplied = self.mont_mul(&acc, &base_m);
            let set = Choice::from(((exp[i / 64] >> (i % 64)) & 1) as u8);
            // Take the multiplied value when the exponent bit is set.
            acc = Uint::conditional_select(&multiplied, &acc, set);
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
    fn pow_public_matches_pow() {
        // The public-exponent ladder must return exactly the same value as the
        // constant-time `pow` for every (base, exp); it only changes timing.
        let moduli: [u64; 3] = [0xFFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0001, 1_000_003];
        let bases: [u64; 4] = [0, 2, 3, 0x1234_5678_9abc_def1];
        let exps: [u64; 5] = [0, 1, 17, 65537, 0xdead_beef];
        for &n in &moduli {
            let m = MontModulus::new(Uint::<2>::from_u64(n));
            for &base in &bases {
                let b = Uint::<2>::from_u64(base % n);
                for &e in &exps {
                    let e = Uint::<2>::from_u64(e);
                    assert_eq!(m.pow_public(&b, &e), m.pow(&b, &e), "{base}^{e:?} mod {n}");
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
