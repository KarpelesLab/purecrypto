//! Complex FFT over the emulated [`Fpr`] double, for the ring `R = ℝ[x]/(xⁿ+1)`.
//!
//! Falcon does its lattice arithmetic — the LDL tree and fast-Fourier sampling —
//! in the FFT domain. A real polynomial `f` of degree `< n` is represented by its
//! `n` complex evaluations at the roots of `xⁿ+1`; the layout, the recursive
//! `split`/`merge` structure, and the `splitfft`/`mergefft` operators follow the
//! Falcon specification (§3.4) and the `tprest/falcon.py` reference.
//!
//! The roots of unity are derived with **no trigonometry and no constant table**:
//! starting from the single root `-1` of `x+1`, each level's roots are the
//! principal complex square roots of the previous level's roots (a root `ζ` of
//! `xⁿ+1` squares to a root of `x^(n/2)+1`). This needs only `Fpr` add/sub/mul/
//! sqrt, so it is portable and constant-time like the rest of `fpr`. The roots
//! carry a few ulps of accumulated error versus an exact `cos/sin` table — more
//! than enough for correctness (validated by `FFT∘iFFT == id` and
//! `FFT-mul == schoolbook` in `fft_tests.rs`), though not bit-identical to the C
//! reference's table (so signing is validated by round-trip + the sampler KAT
//! rather than byte-exact NIST sign vectors; see the module docs).

#![allow(dead_code)] // consumed by the tree/sign phases

use super::fpr::Fpr;
use alloc::vec;
use alloc::vec::Vec;

/// A complex number with [`Fpr`] real and imaginary parts.
#[derive(Clone, Copy)]
pub(crate) struct Cplx {
    pub(crate) re: Fpr,
    pub(crate) im: Fpr,
}

impl Cplx {
    #[inline]
    pub(crate) const fn new(re: Fpr, im: Fpr) -> Cplx {
        Cplx { re, im }
    }

    #[inline]
    pub(crate) fn zero() -> Cplx {
        Cplx::new(Fpr::from_f64(0.0), Fpr::from_f64(0.0))
    }

    #[inline]
    pub(crate) fn add(self, o: Cplx) -> Cplx {
        Cplx::new(self.re.add(o.re), self.im.add(o.im))
    }

    #[inline]
    pub(crate) fn sub(self, o: Cplx) -> Cplx {
        Cplx::new(self.re.sub(o.re), self.im.sub(o.im))
    }

    /// Complex multiplication: `(a+bi)(c+di) = (ac−bd) + (ad+bc)i`.
    #[inline]
    pub(crate) fn mul(self, o: Cplx) -> Cplx {
        Cplx::new(
            self.re.mul(o.re).sub(self.im.mul(o.im)),
            self.re.mul(o.im).add(self.im.mul(o.re)),
        )
    }

    /// Complex conjugate.
    #[inline]
    pub(crate) fn conj(self) -> Cplx {
        Cplx::new(self.re, self.im.neg())
    }

    /// Multiply by a real scalar.
    #[inline]
    pub(crate) fn scale(self, s: Fpr) -> Cplx {
        Cplx::new(self.re.mul(s), self.im.mul(s))
    }

    /// `1 / self` for a nonzero complex value: `conj / |self|²`.
    #[inline]
    pub(crate) fn inv(self) -> Cplx {
        let d = self.re.mul(self.re).add(self.im.mul(self.im));
        Cplx::new(self.re.div(d), self.im.neg().div(d))
    }

    /// Complex division `self / o`.
    #[inline]
    pub(crate) fn div(self, o: Cplx) -> Cplx {
        let d = o.re.mul(o.re).add(o.im.mul(o.im));
        Cplx::new(
            self.re.mul(o.re).add(self.im.mul(o.im)).div(d),
            self.im.mul(o.re).sub(self.re.mul(o.im)).div(d),
        )
    }

    /// Principal complex square root of a value on the unit circle (`|self| = 1`,
    /// as every root of unity here is): `√(a+bi) = √((1+a)/2) + sgn(b)·√((1−a)/2)i`.
    fn unit_sqrt(self) -> Cplx {
        let one = Fpr::from_f64(1.0);
        let re = one.add(self.re).half().sqrt();
        let mut im = one.sub(self.re).half().sqrt();
        // Sign of the imaginary part follows sign of b (the original imag part).
        if self.im.lt(Fpr::from_f64(0.0)) {
            im = im.neg();
        }
        Cplx::new(re, im)
    }
}

/// Precomputed twiddle factors for an FFT over `ℝ[x]/(xⁿ+1)`.
///
/// `rho[k]` holds the `2^k / 2` roots used by the merge/split at level
/// `m = 2^k` (`k = 1..=log2 n`); `rho[k][i]` is a principal square root of the
/// level-`(m/2)` root `eta[i]`.
pub(crate) struct Fft {
    pub(crate) n: usize,
    rho: Vec<Vec<Cplx>>,
}

impl Fft {
    /// Build the twiddle tables for degree `n` (a power of two ≥ 2).
    pub(crate) fn new(n: usize) -> Fft {
        debug_assert!(n.is_power_of_two() && n >= 2);
        // eta for level 1 (roots of x+1): just {-1}.
        let mut eta: Vec<Cplx> = vec![Cplx::new(Fpr::from_f64(-1.0), Fpr::from_f64(0.0))];
        let mut rho: Vec<Vec<Cplx>> = vec![Vec::new()]; // index 0 unused
        let mut m = 2;
        while m <= n {
            let half = m / 2;
            let mut rho_m = Vec::with_capacity(half);
            let mut next_eta = vec![Cplx::zero(); m];
            for i in 0..half {
                let r = eta[i].unit_sqrt();
                rho_m.push(r);
                next_eta[2 * i] = r;
                next_eta[2 * i + 1] = r.neg_c();
            }
            rho.push(rho_m);
            eta = next_eta;
            m *= 2;
        }
        Fft { n, rho }
    }

    /// Forward FFT: real coefficients (length `n`) → complex evaluations
    /// (length `n`, with conjugate redundancy, matching the reference layout).
    pub(crate) fn fft(&self, f: &[Fpr]) -> Vec<Cplx> {
        debug_assert_eq!(f.len(), self.n);
        let cplx: Vec<Cplx> = f
            .iter()
            .map(|&c| Cplx::new(c, Fpr::from_f64(0.0)))
            .collect();
        self.fft_rec(&cplx)
    }

    fn fft_rec(&self, f: &[Cplx]) -> Vec<Cplx> {
        let m = f.len();
        if m == 2 {
            // x²+1: evaluate at ±i. f = f0 + f1·x → f(i) = f0 + i·f1.
            let f0 = f[0];
            let f1 = f[1];
            return vec![
                Cplx::new(f0.re.sub(f1.im), f0.im.add(f1.re)),
                Cplx::new(f0.re.add(f1.im), f0.im.sub(f1.re)),
            ];
        }
        // Coefficient split into even/odd halves.
        let half = m / 2;
        let mut f0 = Vec::with_capacity(half);
        let mut f1 = Vec::with_capacity(half);
        for i in 0..half {
            f0.push(f[2 * i]);
            f1.push(f[2 * i + 1]);
        }
        let f0h = self.fft_rec(&f0);
        let f1h = self.fft_rec(&f1);
        self.merge_fft(&f0h, &f1h)
    }

    /// Inverse FFT: complex evaluations (length `n`) → real coefficients.
    pub(crate) fn ifft(&self, fh: &[Cplx]) -> Vec<Fpr> {
        debug_assert_eq!(fh.len(), self.n);
        let c = self.ifft_rec(fh);
        c.iter().map(|z| z.re).collect()
    }

    fn ifft_rec(&self, fh: &[Cplx]) -> Vec<Cplx> {
        let m = fh.len();
        if m == 2 {
            // Invert the n=2 base: f0 = Re(fh[0]), f1 = Im(fh[0]).
            return vec![
                Cplx::new(fh[0].re, Fpr::from_f64(0.0)),
                Cplx::new(fh[0].im, Fpr::from_f64(0.0)),
            ];
        }
        let (f0h, f1h) = self.split_fft(fh);
        let f0 = self.ifft_rec(&f0h);
        let f1 = self.ifft_rec(&f1h);
        // Coefficient merge (interleave even/odd).
        let mut out = vec![Cplx::zero(); m];
        for i in 0..m / 2 {
            out[2 * i] = f0[i];
            out[2 * i + 1] = f1[i];
        }
        out
    }

    /// `mergefft`: combine the FFTs of the even/odd halves into the level-`m` FFT.
    /// `f_fft[2i] = f0[i] + ρ·f1[i]`, `f_fft[2i+1] = f0[i] − ρ·f1[i]`.
    fn merge_fft(&self, f0h: &[Cplx], f1h: &[Cplx]) -> Vec<Cplx> {
        let half = f0h.len();
        let m = 2 * half;
        let level = m.trailing_zeros() as usize;
        let rho = &self.rho[level];
        let mut out = vec![Cplx::zero(); m];
        for i in 0..half {
            let t = rho[i].mul(f1h[i]);
            out[2 * i] = f0h[i].add(t);
            out[2 * i + 1] = f0h[i].sub(t);
        }
        out
    }

    /// `splitfft`: inverse of `merge_fft` in the FFT domain.
    /// `f0[i] = ½(f_fft[2i] + f_fft[2i+1])`,
    /// `f1[i] = ½(f_fft[2i] − f_fft[2i+1])·conj(ρ)`.
    pub(crate) fn split_fft(&self, fh: &[Cplx]) -> (Vec<Cplx>, Vec<Cplx>) {
        let m = fh.len();
        let half = m / 2;
        let level = m.trailing_zeros() as usize;
        let rho = &self.rho[level];
        let mut f0 = Vec::with_capacity(half);
        let mut f1 = Vec::with_capacity(half);
        for i in 0..half {
            let a = fh[2 * i];
            let b = fh[2 * i + 1];
            f0.push(a.add(b).scale(Fpr::from_f64(0.5)));
            f1.push(a.sub(b).scale(Fpr::from_f64(0.5)).mul(rho[i].conj()));
        }
        (f0, f1)
    }

    /// `mergefft` exposed for the tree code (combines two half-length FFTs).
    pub(crate) fn merge_fft_pub(&self, f0h: &[Cplx], f1h: &[Cplx]) -> Vec<Cplx> {
        self.merge_fft(f0h, f1h)
    }
}

impl Cplx {
    /// Negate both components.
    #[inline]
    fn neg_c(self) -> Cplx {
        Cplx::new(self.re.neg(), self.im.neg())
    }
}

/// Elementwise complex multiply (pointwise product in the FFT domain).
pub(crate) fn mul_fft(a: &[Cplx], b: &[Cplx]) -> Vec<Cplx> {
    a.iter().zip(b).map(|(&x, &y)| x.mul(y)).collect()
}

/// Elementwise complex add.
pub(crate) fn add_fft(a: &[Cplx], b: &[Cplx]) -> Vec<Cplx> {
    a.iter().zip(b).map(|(&x, &y)| x.add(y)).collect()
}

/// Elementwise complex subtract.
pub(crate) fn sub_fft(a: &[Cplx], b: &[Cplx]) -> Vec<Cplx> {
    a.iter().zip(b).map(|(&x, &y)| x.sub(y)).collect()
}

/// Elementwise complex conjugate (the `adj` / Hermitian adjoint of a poly).
pub(crate) fn adj_fft(a: &[Cplx]) -> Vec<Cplx> {
    a.iter().map(|&x| x.conj()).collect()
}

/// Elementwise complex division (pointwise quotient in the FFT domain).
pub(crate) fn div_fft(a: &[Cplx], b: &[Cplx]) -> Vec<Cplx> {
    a.iter().zip(b).map(|(&x, &y)| x.div(y)).collect()
}

#[cfg(test)]
#[path = "fft_tests.rs"]
mod fft_tests;
