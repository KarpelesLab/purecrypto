//! The Falcon LDL tree (`ffLDL`) and fast-Fourier sampling (`ffSampling`).
//!
//! Signing reduces a target point to a nearby lattice point using the secret
//! basis. To do that in `O(n log n)`, Falcon precomputes — once per key — the
//! LDL\* decomposition tree of the basis Gram matrix in the FFT domain, with
//! each leaf normalized to the per-leaf Gaussian standard deviation
//! `σ / √(D_ii)`. At sign time, [`ff_sampling`] walks that tree, splitting the
//! target with `splitfft`, and at the leaves draws integers with the
//! constant-time [`sampler_z`]. Structure follows the Falcon spec (§3.9,
//! Algorithms 9 & 11) and `tprest/falcon.py` (`ffldl_fft` / `normalize_tree` /
//! `ffsampling_fft`).
//!
//! Everything runs in the emulated [`Fpr`], so the sign-time path is
//! data-oblivious. The LDL math is checked by `tree_tests.rs`
//! (`L·D·L\* == G`); the full statistical behavior is exercised by the
//! sign round-trip in a later phase.

#![allow(dead_code)] // consumed by the sign phase

use super::fft::{Cplx, Fft, add_fft, adj_fft, div_fft, mul_fft, sub_fft};
use super::fpr::Fpr;
use super::sampler::{SamplerRng, sampler_z};
use alloc::boxed::Box;
use alloc::vec::Vec;

/// A 2×2 Gram matrix in FFT form: `g[i][j]` is a length-`m` FFT array.
pub(crate) type Gram = [[Vec<Cplx>; 2]; 2];

/// A node of the Falcon LDL tree.
pub(crate) enum FftTree {
    /// Bottom of the recursion: the normalized leaf standard deviation
    /// `σ / √(D[0].re)` used directly as the [`sampler_z`] sigma.
    Leaf(Fpr),
    /// Internal node: the `L₁₀` factor (length-`m` FFT array) and the two
    /// half-size subtrees from the diagonal bisection.
    Node {
        l10: Vec<Cplx>,
        left: Box<FftTree>,
        right: Box<FftTree>,
    },
}

/// Compute the Gram matrix `G = B·B*` of the 2×2 basis
/// `B = [[b00, b01], [b10, b11]]`, all given as FFT arrays of equal length.
pub(crate) fn gram(b: &[[Vec<Cplx>; 2]; 2]) -> Gram {
    let mut g: Gram = [[Vec::new(), Vec::new()], [Vec::new(), Vec::new()]];
    for (i, grow) in g.iter_mut().enumerate() {
        for (j, gij) in grow.iter_mut().enumerate() {
            // G[i][j] = Σ_k B[i][k] · adj(B[j][k]).
            let mut acc = vec_zero(b[0][0].len());
            for k in 0..2 {
                let term = mul_fft(&b[i][k], &adj_fft(&b[j][k]));
                for (a, t) in acc.iter_mut().zip(term) {
                    *a = a.add(t);
                }
            }
            *gij = acc;
        }
    }
    g
}

fn vec_zero(m: usize) -> Vec<Cplx> {
    let mut v = Vec::with_capacity(m);
    v.resize(m, Cplx::zero());
    v
}

/// Build the normalized Falcon tree from a Gram matrix `g` (length-`m` entries),
/// for signing standard deviation `sigma`. Folds the `normalize_tree` pass into
/// construction: leaves are stored as `sigma / √(D_ii[0].re)`.
pub(crate) fn ffldl(fft: &Fft, g: &Gram, sigma: Fpr) -> FftTree {
    let m = g[0][0].len();
    // LDL*: D00 = G00; L10 = G10 / G00; D11 = G11 − L10·adj(L10)·G00.
    let d00 = g[0][0].clone();
    let l10 = div_fft(&g[1][0], &g[0][0]);
    let tmp = mul_fft(&mul_fft(&l10, &adj_fft(&l10)), &g[0][0]);
    let d11 = sub_fft(&g[1][1], &tmp);

    if m > 2 {
        // Bisect each diagonal block and recurse.
        let (d00a, d00b) = fft.split_fft(&d00);
        let (d11a, d11b) = fft.split_fft(&d11);
        let g0: Gram = [[d00a.clone(), d00b.clone()], [adj_fft(&d00b), d00a]];
        let g1: Gram = [[d11a.clone(), d11b.clone()], [adj_fft(&d11b), d11a]];
        FftTree::Node {
            l10,
            left: Box::new(ffldl(fft, &g0, sigma)),
            right: Box::new(ffldl(fft, &g1, sigma)),
        }
    } else {
        // m == 2: the two diagonal entries become normalized leaves.
        let leaf0 = sigma.div(d00[0].re.sqrt());
        let leaf1 = sigma.div(d11[0].re.sqrt());
        FftTree::Node {
            l10,
            left: Box::new(FftTree::Leaf(leaf0)),
            right: Box::new(FftTree::Leaf(leaf1)),
        }
    }
}

/// Fast-Fourier sampling: given the target `(t0, t1)` (length-`m` FFT arrays)
/// and the tree, return `(z0, z1)`, the FFT of an integral lattice vector close
/// to the target. Draws leaf integers with [`sampler_z`] (consuming `rng`).
pub(crate) fn ff_sampling<R: SamplerRng>(
    fft: &Fft,
    t0: &[Cplx],
    t1: &[Cplx],
    tree: &FftTree,
    sigmin: Fpr,
    rng: &mut R,
) -> (Vec<Cplx>, Vec<Cplx>) {
    match tree {
        FftTree::Leaf(sigma) => {
            // Length-1 arrays: sample both coordinates with the leaf sigma.
            let z0 = sampler_z(t0[0].re, *sigma, sigmin, rng);
            let z1 = sampler_z(t1[0].re, *sigma, sigmin, rng);
            (
                alloc::vec![Cplx::new(Fpr::of_i64(z0), Fpr::from_f64(0.0))],
                alloc::vec![Cplx::new(Fpr::of_i64(z1), Fpr::from_f64(0.0))],
            )
        }
        FftTree::Node { l10, left, right } => {
            // Sample the second coordinate first (split → recurse → merge).
            let (t1a, t1b) = fft.split_fft(t1);
            let (z1a, z1b) = ff_sampling(fft, &t1a, &t1b, right, sigmin, rng);
            let z1 = fft.merge_fft_pub(&z1a, &z1b);
            // t0' = t0 + (t1 − z1)·L10.
            let diff = sub_fft(t1, &z1);
            let t0b = add_fft(t0, &mul_fft(&diff, l10));
            let (t0a, t0bb) = fft.split_fft(&t0b);
            let (z0a, z0b) = ff_sampling(fft, &t0a, &t0bb, left, sigmin, rng);
            let z0 = fft.merge_fft_pub(&z0a, &z0b);
            (z0, z1)
        }
    }
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tree_tests;
