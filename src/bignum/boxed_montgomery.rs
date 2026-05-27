//! Constant-time Montgomery modular arithmetic for [`BoxedUint`].
//!
//! A runtime-width port of [`MontModulus`](super::MontModulus): same CIOS
//! multiplication and square-and-multiply-always exponentiation, over
//! `Vec<Limb>` scratch so the modulus width is chosen at runtime.

use super::boxed::BoxedUint;
use super::mul::mac;
use super::uint::{Limb, adc, sbb};
use crate::ct::{Choice, ConditionallySelectable};
use alloc::vec;
use alloc::vec::Vec;

/// `n^-1 mod 2^64` for odd `n` (Newton's iteration).
fn inv_mod_2_64(n: u64) -> u64 {
    let mut x = 1u64;
    let mut i = 0;
    while i < 6 {
        x = x.wrapping_mul(2u64.wrapping_sub(n.wrapping_mul(x)));
        i += 1;
    }
    x
}

/// `a + b + carry` over equal-length limb slices, returning `(sum, carry_out)`.
fn adc_limbs(a: &[Limb], b: &[Limb], carry_in: Limb) -> (Vec<Limb>, Limb) {
    let mut out = vec![0 as Limb; a.len()];
    let mut c = carry_in;
    for i in 0..a.len() {
        let (s, co) = adc(a[i], b[i], c);
        out[i] = s;
        c = co;
    }
    (out, c)
}

/// `a - b - borrow` over equal-length limb slices, returning `(diff, borrow_out)`.
fn sbb_limbs(a: &[Limb], b: &[Limb], borrow_in: Limb) -> (Vec<Limb>, Limb) {
    let mut out = vec![0 as Limb; a.len()];
    let mut bo = borrow_in;
    for i in 0..a.len() {
        let (d, b) = sbb(a[i], b[i], bo);
        out[i] = d;
        bo = b;
    }
    (out, bo)
}

/// Selects `a` if `choice` is true, else `b`, limb-by-limb (constant time).
fn select_limbs(a: &[Limb], b: &[Limb], choice: Choice) -> Vec<Limb> {
    (0..a.len())
        .map(|i| Limb::conditional_select(&a[i], &b[i], choice))
        .collect()
}

/// `(a + b) mod n` for equal-length `a, b < n`.
fn add_mod_limbs(n: &[Limb], a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let (sum, carry) = adc_limbs(a, b, 0);
    let (diff, borrow) = sbb_limbs(&sum, n, 0);
    let subtract = carry | (borrow ^ 1);
    select_limbs(&diff, &sum, Choice::from(subtract as u8))
}

/// `(a - b) mod n` for equal-length `a, b < n`.
fn sub_mod_limbs(n: &[Limb], a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let (diff, borrow) = sbb_limbs(a, b, 0);
    let (wrapped, _) = adc_limbs(&diff, n, 0);
    select_limbs(&wrapped, &diff, Choice::from(borrow as u8))
}

/// Runtime-width Montgomery parameters for an odd modulus.
#[derive(Clone, Debug)]
pub struct BoxedMontModulus {
    n: Vec<Limb>,
    n_prime: Limb,
    r2: Vec<Limb>,
    limbs: usize,
}

impl BoxedMontModulus {
    /// Builds parameters for an odd `modulus`.
    ///
    /// # Panics
    /// Panics if `modulus` is even or zero.
    pub fn new(modulus: &BoxedUint) -> Self {
        let limbs = modulus.significant_limbs();
        let n = modulus.limbs_resized(limbs);
        assert!(n[0] & 1 == 1, "Montgomery modulus must be odd");
        let n_prime = inv_mod_2_64(n[0]).wrapping_neg();

        // r2 = 2^(2*64*limbs) mod n, by doubling 1 that many times.
        let mut r2 = vec![0 as Limb; limbs];
        r2[0] = 1;
        let bits = 2 * 64 * limbs;
        for _ in 0..bits {
            r2 = add_mod_limbs(&n, &r2, &r2);
        }

        BoxedMontModulus {
            n,
            n_prime,
            r2,
            limbs,
        }
    }

    /// The modulus width in limbs.
    #[inline]
    pub fn limbs(&self) -> usize {
        self.limbs
    }

    /// CIOS Montgomery multiplication of two `limbs`-wide values.
    fn mont_mul_limbs(&self, a: &[Limb], b: &[Limb]) -> Vec<Limb> {
        let l = self.limbs;
        let n = &self.n;
        let mut t = vec![0 as Limb; l];
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

        // Conditional final subtraction (result < 2N).
        let (diff, borrow_low) = sbb_limbs(&t, n, 0);
        let (_, borrow) = sbb(ts, 0, borrow_low);
        let ge = Choice::from((borrow ^ 1) as u8);
        select_limbs(&diff, &t, ge)
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

    /// Returns `(a * b) mod n` for `a, b < n`.
    pub fn mul_mod(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        let a = a.limbs_resized(self.limbs);
        let b = b.limbs_resized(self.limbs);
        let t = self.mont_mul_limbs(&a, &b);
        BoxedUint::from_limbs(self.mont_mul_limbs(&t, &self.r2))
    }

    /// Computes `base^exp mod n` in constant time (square-and-multiply-always
    /// over all bits of `exp`).
    ///
    /// The exponent is zero-padded to `self.limbs` 64-bit limbs before the
    /// loop. Iteration count is therefore a function of the modulus width
    /// alone — two secret exponents of the same modulus cannot produce
    /// different running times even if one was parsed from a DER blob with
    /// the leading zero limbs of `d` stripped.
    pub fn pow(&self, base: &BoxedUint, exp: &BoxedUint) -> BoxedUint {
        let base_m = self.to_mont_limbs(&base.limbs_resized(self.limbs));
        let mut one = vec![0 as Limb; self.limbs];
        one[0] = 1;
        let mut acc = self.to_mont_limbs(&one); // R mod N

        // Pad the exponent to `self.limbs` 64-bit words. `limbs_resized`
        // zero-pads when the exponent is shorter (the common case for
        // imported `d` values whose high-zero limbs were stripped by the
        // ASN.1 unsigned-integer encoder).
        let exp_limbs = exp.limbs_resized(self.limbs);
        let mut i = exp_limbs.len();
        while i > 0 {
            i -= 1;
            let limb = exp_limbs[i];
            let mut bit = 64;
            while bit > 0 {
                bit -= 1;
                acc = self.mont_mul_limbs(&acc, &acc);
                let mult = self.mont_mul_limbs(&acc, &base_m);
                let set = Choice::from(((limb >> bit) & 1) as u8);
                acc = select_limbs(&mult, &acc, set);
            }
        }
        BoxedUint::from_limbs(self.demont_limbs(&acc))
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
