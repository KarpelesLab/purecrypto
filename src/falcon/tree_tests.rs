//! LDL-tree and ffSampling sanity checks. The LDL math is pinned exactly
//! (reconstruction `L·D·L* == G`); ffSampling is checked for integrality and
//! determinism on a synthetic basis. End-to-end statistical correctness is
//! covered by the sign round-trip in a later phase.

use super::super::fft::{Cplx, Fft, add_fft, adj_fft, div_fft, mul_fft, sub_fft};
use super::super::fpr::Fpr;
use super::super::sampler::SamplerRng;
use super::{FftTree, ff_sampling, ffldl, gram};
use alloc::vec::Vec;

struct Sm64(u64);
impl Sm64 {
    fn new(s: u64) -> Sm64 {
        Sm64(s)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn small_poly(&mut self, n: usize) -> Vec<Fpr> {
        (0..n)
            .map(|_| Fpr::of_i64((self.next() & 0x7) as i64 - 3))
            .collect()
    }
}

/// A deterministic byte source for the sampler in these tests.
struct DetRng(u64);
impl SamplerRng for DetRng {
    fn next_bytes(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(0x5851_F42D_4C95_7F2D)
                .wrapping_add(0x1405_7B7E_F767_814F);
            *b = (self.0 >> 56) as u8;
        }
    }
}

fn maxdiff(a: &[Cplx], b: &[Cplx]) -> f64 {
    let mut m = 0.0f64;
    for (x, y) in a.iter().zip(b) {
        m = m
            .max((x.re.to_f64() - y.re.to_f64()).abs())
            .max((x.im.to_f64() - y.im.to_f64()).abs());
    }
    m
}

/// Build a synthetic 2×2 basis B = [[g, −f], [G, −F]] in FFT form from random
/// small integer polynomials (no NTRU relation needed for these checks).
fn synthetic_basis(rng: &mut Sm64, fft: &Fft, n: usize) -> [[Vec<Cplx>; 2]; 2] {
    let neg = |p: &[Fpr]| p.iter().map(|x| x.neg()).collect::<Vec<_>>();
    let f = rng.small_poly(n);
    let g = rng.small_poly(n);
    let cap_f = rng.small_poly(n);
    let cap_g = rng.small_poly(n);
    [
        [fft.fft(&g), fft.fft(&neg(&f))],
        [fft.fft(&cap_g), fft.fft(&neg(&cap_f))],
    ]
}

#[test]
fn ldl_reconstructs_gram() {
    let mut rng = Sm64::new(0x1234_5678_9ABC_DEF0);
    for &n in &[2usize, 4, 8, 256, 512] {
        let fft = Fft::new(n);
        let b = synthetic_basis(&mut rng, &fft, n);
        let g = gram(&b);
        // Single LDL* step (top level), mirroring `ffldl`.
        let d00 = g[0][0].clone();
        let l10 = div_fft(&g[1][0], &g[0][0]);
        let d11 = sub_fft(&g[1][1], &mul_fft(&mul_fft(&l10, &adj_fft(&l10)), &g[0][0]));
        // Reconstruct: R00=D00, R10=L10·D00, R11=D11 + L10·adj(L10)·D00.
        let r00 = d00.clone();
        let r10 = mul_fft(&l10, &d00);
        let r11 = add_fft(&d11, &mul_fft(&mul_fft(&l10, &adj_fft(&l10)), &d00));
        assert!(maxdiff(&r00, &g[0][0]) < 1e-6, "n={n} R00");
        assert!(maxdiff(&r10, &g[1][0]) < 1e-6, "n={n} R10");
        assert!(maxdiff(&r11, &g[1][1]) < 1e-6, "n={n} R11");
    }
}

fn count_leaves(t: &FftTree) -> usize {
    match t {
        FftTree::Leaf(_) => 1,
        FftTree::Node { left, right, .. } => count_leaves(left) + count_leaves(right),
    }
}

#[test]
fn tree_has_n_leaves() {
    for &n in &[2usize, 4, 8, 16, 512, 1024] {
        let mut rng = Sm64::new(0xABCD_0000 ^ n as u64);
        let fft = Fft::new(n);
        let b = synthetic_basis(&mut rng, &fft, n);
        let g = gram(&b);
        let tree = ffldl(&fft, &g, Fpr::from_f64(165.736_617_182_977_6));
        assert_eq!(count_leaves(&tree), n, "n={n} leaf count");
    }
}

#[test]
fn ffsampling_integral_and_deterministic() {
    let sigmin = Fpr::from_f64(1.277_833_696_912_833_7);
    let sigma = Fpr::from_f64(165.736_617_182_977_6);
    for &n in &[4usize, 8, 256, 512] {
        let mut rng = Sm64::new(0x5005_0000 ^ n as u64);
        let fft = Fft::new(n);
        let b = synthetic_basis(&mut rng, &fft, n);
        let g = gram(&b);
        let tree = ffldl(&fft, &g, sigma);

        // Arbitrary target in FFT form (from a small real vector).
        let t0 = fft.fft(&rng.small_poly(n));
        let t1 = fft.fft(&rng.small_poly(n));

        let (z0a, z1a) = ff_sampling(&fft, &t0, &t1, &tree, sigmin, &mut DetRng(42));
        let (z0b, z1b) = ff_sampling(&fft, &t0, &t1, &tree, sigmin, &mut DetRng(42));
        // Determinism: identical random stream → identical output.
        assert!(
            maxdiff(&z0a, &z0b) == 0.0 && maxdiff(&z1a, &z1b) == 0.0,
            "n={n} determinism"
        );

        // The sampled vectors are FFTs of integer polynomials.
        for zf in [&z0a, &z1a] {
            for c in fft.ifft(zf) {
                let v = c.to_f64();
                assert!((v - v.round()).abs() < 1e-6, "n={n} non-integral coeff {v}");
            }
        }
    }
}
