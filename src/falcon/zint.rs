//! Minimal arbitrary-precision signed integers for Falcon key generation.
//!
//! NTRUSolve's tower-of-rings recursion drives the base-case integers up to
//! several thousand bits (≈8k at n=512, ≈16k at n=1024), far beyond the crate's
//! fixed-width `Uint`. This module provides just enough: sign-magnitude integers
//! (little-endian `u32` limbs) with add/sub/mul, bit shifts, comparison, the
//! reference's byte-rounded `bitsize`, and a **binary extended GCD** (Stein) so
//! the base case needs no long division — only shifts, subtraction and
//! comparison.
//!
//! Key generation is a one-time, non-secret-dependent operation, so these
//! routines favor clarity over constant-time or peak throughput.

use alloc::vec::Vec;
use core::cmp::Ordering;

/// A sign-magnitude big integer. `mag` is little-endian base-2³², trimmed of
/// trailing zero limbs; the empty vector is zero and `neg` is then `false`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct Zint {
    neg: bool,
    mag: Vec<u32>,
}

fn trim(v: &mut Vec<u32>) {
    while v.last() == Some(&0) {
        v.pop();
    }
}

fn cmp_mag(a: &[u32], b: &[u32]) -> Ordering {
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    Ordering::Equal
}

/// `a + b` (magnitudes).
fn add_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len().max(b.len()) + 1);
    let mut carry = 0u64;
    for i in 0..a.len().max(b.len()) {
        let x = *a.get(i).unwrap_or(&0) as u64;
        let y = *b.get(i).unwrap_or(&0) as u64;
        let s = x + y + carry;
        out.push(s as u32);
        carry = s >> 32;
    }
    if carry != 0 {
        out.push(carry as u32);
    }
    trim(&mut out);
    out
}

/// `a − b` (magnitudes), requires `a ≥ b`.
fn sub_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = 0i64;
    for i in 0..a.len() {
        let x = a[i] as i64;
        let y = *b.get(i).unwrap_or(&0) as i64;
        let mut d = x - y - borrow;
        if d < 0 {
            d += 1 << 32;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out.push(d as u32);
    }
    trim(&mut out);
    out
}

/// Schoolbook magnitude multiplication.
fn mul_mag(a: &[u32], b: &[u32]) -> Vec<u32> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut out = alloc::vec![0u32; a.len() + b.len()];
    for (i, &ai) in a.iter().enumerate() {
        let mut carry = 0u64;
        let aiv = ai as u64;
        for (j, &bj) in b.iter().enumerate() {
            let cur = out[i + j] as u64 + aiv * bj as u64 + carry;
            out[i + j] = cur as u32;
            carry = cur >> 32;
        }
        out[i + b.len()] += carry as u32;
    }
    trim(&mut out);
    out
}

/// Logical left shift of a magnitude by `bits`.
fn shl_mag(a: &[u32], bits: usize) -> Vec<u32> {
    if a.is_empty() {
        return Vec::new();
    }
    let words = bits / 32;
    let rem = bits % 32;
    let mut out = alloc::vec![0u32; words];
    if rem == 0 {
        out.extend_from_slice(a);
    } else {
        let mut carry = 0u64;
        for &limb in a {
            let v = ((limb as u64) << rem) | carry;
            out.push(v as u32);
            carry = v >> 32;
        }
        if carry != 0 {
            out.push(carry as u32);
        }
    }
    trim(&mut out);
    out
}

/// Logical right shift of a magnitude by `bits` (truncating toward zero of the
/// magnitude).
fn shr_mag(a: &[u32], bits: usize) -> Vec<u32> {
    let words = bits / 32;
    let rem = bits % 32;
    if words >= a.len() {
        return Vec::new();
    }
    let mut out: Vec<u32> = a[words..].to_vec();
    if rem != 0 {
        let mut carry = 0u32;
        for i in (0..out.len()).rev() {
            let v = out[i];
            out[i] = (v >> rem) | carry;
            carry = v << (32 - rem);
        }
    }
    trim(&mut out);
    out
}

impl Zint {
    pub(crate) fn zero() -> Zint {
        Zint {
            neg: false,
            mag: Vec::new(),
        }
    }

    pub(crate) fn from_i64(v: i64) -> Zint {
        let neg = v < 0;
        let mut x = (v as i128).unsigned_abs();
        let mut mag = Vec::new();
        while x != 0 {
            mag.push((x & 0xFFFF_FFFF) as u32);
            x >>= 32;
        }
        Zint { neg, mag }
    }

    #[cfg(test)]
    pub(crate) fn from_i128(v: i128) -> Zint {
        let neg = v < 0;
        let mut x = v.unsigned_abs();
        let mut mag = Vec::new();
        while x != 0 {
            mag.push((x & 0xFFFF_FFFF) as u32);
            x >>= 32;
        }
        Zint { neg, mag }
    }

    /// Reconstruct an `i128` if the value fits in ≤4 limbs and the `i128` range.
    #[cfg(test)]
    pub(crate) fn to_i128(&self) -> Option<i128> {
        if self.mag.len() > 4 {
            return None;
        }
        let mut m: u128 = 0;
        for &limb in self.mag.iter().rev() {
            m = (m << 32) | limb as u128;
        }
        if self.neg {
            if m <= (i128::MAX as u128) + 1 {
                Some(m.wrapping_neg() as i128)
            } else {
                None
            }
        } else if m <= i128::MAX as u128 {
            Some(m as i128)
        } else {
            None
        }
    }

    fn from_parts(neg: bool, mag: Vec<u32>) -> Zint {
        if mag.is_empty() {
            Zint::zero()
        } else {
            Zint { neg, mag }
        }
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.mag.is_empty()
    }

    pub(crate) fn is_negative(&self) -> bool {
        self.neg
    }

    fn is_even(&self) -> bool {
        self.mag.first().map(|&l| l & 1 == 0).unwrap_or(true)
    }

    pub(crate) fn neg(&self) -> Zint {
        Zint::from_parts(!self.neg, self.mag.clone())
    }

    pub(crate) fn abs(&self) -> Zint {
        Zint::from_parts(false, self.mag.clone())
    }

    /// Signed comparison.
    pub(crate) fn cmp(&self, o: &Zint) -> Ordering {
        match (self.neg, o.neg) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => cmp_mag(&self.mag, &o.mag),
            (true, true) => cmp_mag(&o.mag, &self.mag),
        }
    }

    pub(crate) fn add(&self, o: &Zint) -> Zint {
        if self.neg == o.neg {
            Zint::from_parts(self.neg, add_mag(&self.mag, &o.mag))
        } else {
            match cmp_mag(&self.mag, &o.mag) {
                Ordering::Equal => Zint::zero(),
                Ordering::Greater => Zint::from_parts(self.neg, sub_mag(&self.mag, &o.mag)),
                Ordering::Less => Zint::from_parts(o.neg, sub_mag(&o.mag, &self.mag)),
            }
        }
    }

    pub(crate) fn sub(&self, o: &Zint) -> Zint {
        self.add(&o.neg())
    }

    pub(crate) fn mul(&self, o: &Zint) -> Zint {
        Zint::from_parts(self.neg != o.neg, mul_mag(&self.mag, &o.mag))
    }

    /// Left shift (multiply by 2^bits), sign preserved.
    pub(crate) fn shl(&self, bits: usize) -> Zint {
        Zint::from_parts(self.neg, shl_mag(&self.mag, bits))
    }

    /// Right shift of the magnitude by `bits` (truncating toward zero). Used by
    /// keygen only to scale magnitudes down for an FFT approximation, where a
    /// 1-ulp difference is irrelevant; sign is preserved.
    pub(crate) fn shr(&self, bits: usize) -> Zint {
        Zint::from_parts(self.neg, shr_mag(&self.mag, bits))
    }

    fn halve(&self) -> Zint {
        Zint::from_parts(self.neg, shr_mag(&self.mag, 1))
    }

    /// Bitsize as the reference computes it: rounded up to a multiple of 8,
    /// sign not counted (so `bitsize(0) = 0`).
    pub(crate) fn bitsize(&self) -> usize {
        // Number of significant bytes × 8.
        if self.mag.is_empty() {
            return 0;
        }
        let top = *self.mag.last().unwrap();
        let top_bytes = (4 - (top.leading_zeros() as usize / 8)).max(1);
        ((self.mag.len() - 1) * 4 + top_bytes) * 8
    }

    /// The low 64 bits as an `i64` if the value fits, else `None`.
    pub(crate) fn to_i64(&self) -> Option<i64> {
        if self.mag.len() > 2 {
            return None;
        }
        let lo = *self.mag.first().unwrap_or(&0) as u64;
        let hi = *self.mag.get(1).unwrap_or(&0) as u64;
        let m = lo | (hi << 32);
        if self.neg {
            if m <= (i64::MAX as u64) + 1 {
                Some((m as i128).wrapping_neg() as i64)
            } else {
                None
            }
        } else if m <= i64::MAX as u64 {
            Some(m as i64)
        } else {
            None
        }
    }
}

/// Extended binary GCD (HAC 14.61). Returns `(g, a, b)` with
/// `a·x + b·y = g = gcd(x, y)`. Requires `x, y` not both zero.
pub(crate) fn ext_gcd(x: &Zint, y: &Zint) -> (Zint, Zint, Zint) {
    // Work on magnitudes; x, y are non-negative in NTRUSolve's base case usage,
    // but handle signs by folding them into the returned coefficients.
    let xa = x.abs();
    let ya = y.abs();
    if xa.is_zero() {
        return (ya.clone(), Zint::zero(), sign_unit(y));
    }
    if ya.is_zero() {
        return (xa.clone(), sign_unit(x), Zint::zero());
    }

    // Factor out common powers of two.
    let mut shift = 0usize;
    let mut xx = xa.clone();
    let mut yy = ya.clone();
    while xx.is_even() && yy.is_even() {
        xx = xx.halve();
        yy = yy.halve();
        shift += 1;
    }

    let x0 = xx.clone();
    let y0 = yy.clone();
    let mut u = xx;
    let mut v = yy;
    let mut a = Zint::from_i64(1);
    let mut b = Zint::zero();
    let mut c = Zint::zero();
    let mut d = Zint::from_i64(1);

    loop {
        while u.is_even() {
            u = u.halve();
            if a.is_even() && b.is_even() {
                a = a.halve();
                b = b.halve();
            } else {
                a = a.add(&y0).halve();
                b = b.sub(&x0).halve();
            }
        }
        while v.is_even() {
            v = v.halve();
            if c.is_even() && d.is_even() {
                c = c.halve();
                d = d.halve();
            } else {
                c = c.add(&y0).halve();
                d = d.sub(&x0).halve();
            }
        }
        if u.cmp(&v) != Ordering::Less {
            u = u.sub(&v);
            a = a.sub(&c);
            b = b.sub(&d);
        } else {
            v = v.sub(&u);
            c = c.sub(&a);
            d = d.sub(&b);
        }
        if u.is_zero() {
            break;
        }
    }

    // gcd = v << shift; coefficients (c, d) satisfy c·|x| + d·|y| = v.
    let g = v.shl(shift);
    // Fold the original signs: c·x + d·y = g needs c → c·sign(x), d → d·sign(y).
    let ca = if x.is_negative() { c.neg() } else { c };
    let db = if y.is_negative() { d.neg() } else { d };
    (g, ca, db)
}

fn sign_unit(z: &Zint) -> Zint {
    if z.is_negative() {
        Zint::from_i64(-1)
    } else {
        Zint::from_i64(1)
    }
}

#[cfg(test)]
#[path = "zint_tests.rs"]
mod zint_tests;
