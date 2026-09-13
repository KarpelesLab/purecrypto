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
//! Everything runs in the emulated [`Fpr`], which is branch-free by
//! construction (see the "Constant-time contract" in `fpr`), so the
//! secret-derived tree walk here selects no branch, address or shift count from
//! its operands. The LDL math is checked by `tree_tests.rs` (`L·D·L\* == G`);
//! the statistical behavior is exercised by the sign round-trip tests.

use super::fft::{Cplx, Fft, add_fft, adj_fft, div_fft, mul_fft, sub_fft, wipe_cplx};
use super::fpr::{FPR_ZERO, Fpr};
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

impl FftTree {
    /// Overwrite the whole tree with zeros.
    ///
    /// Every node is a function of the secret basis `(f, g, F, G)` — the `L₁₀`
    /// factors and the normalized leaf deviations both leak it — so the tree is
    /// key-equivalent material and is scrubbed when the expanded key is
    /// dropped. Recursion depth is `log₂ n` (≤ 10).
    pub(crate) fn wipe(&mut self) {
        match self {
            FftTree::Leaf(sigma) => {
                *sigma = FPR_ZERO;
                let _ = core::hint::black_box(&*sigma);
            }
            FftTree::Node { l10, left, right } => {
                wipe_cplx(l10);
                left.wipe();
                right.wipe();
            }
        }
    }
}

/// Overwrite a 2×2 Gram / basis matrix of FFT arrays with zeros.
pub(crate) fn wipe_gram(g: &mut Gram) {
    for row in g.iter_mut() {
        for cell in row.iter_mut() {
            wipe_cplx(cell);
        }
    }
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
                let mut adj = adj_fft(&b[j][k]);
                let mut term = mul_fft(&b[i][k], &adj);
                for (a, t) in acc.iter_mut().zip(term.iter()) {
                    *a = a.add(*t);
                }
                // Both are products of secret basis polynomials.
                wipe_cplx(&mut term);
                wipe_cplx(&mut adj);
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
    let mut d00 = g[0][0].clone();
    let l10 = div_fft(&g[1][0], &g[0][0]);
    let mut adj_l10 = adj_fft(&l10);
    let mut tmp = mul_fft(&mul_fft(&l10, &adj_l10), &g[0][0]);
    let mut d11 = sub_fft(&g[1][1], &tmp);

    let node = if m > 2 {
        // Bisect each diagonal block and recurse.
        let (d00a, d00b) = fft.split_fft(&d00);
        let (d11a, d11b) = fft.split_fft(&d11);
        let mut g0: Gram = [[d00a.clone(), d00b.clone()], [adj_fft(&d00b), d00a]];
        let mut g1: Gram = [[d11a.clone(), d11b.clone()], [adj_fft(&d11b), d11a]];
        let left = Box::new(ffldl(fft, &g0, sigma));
        let right = Box::new(ffldl(fft, &g1, sigma));
        // The bisected diagonal blocks are as key-equivalent as the tree they
        // build; only the tree itself (wiped by `FftTree::wipe`) may survive.
        wipe_gram(&mut g0);
        wipe_gram(&mut g1);
        FftTree::Node { l10, left, right }
    } else {
        // m == 2: the two diagonal entries become normalized leaves.
        let leaf0 = sigma.div(d00[0].re.sqrt());
        let leaf1 = sigma.div(d11[0].re.sqrt());
        FftTree::Node {
            l10,
            left: Box::new(FftTree::Leaf(leaf0)),
            right: Box::new(FftTree::Leaf(leaf1)),
        }
    };
    for v in [&mut d00, &mut d11, &mut tmp, &mut adj_l10] {
        wipe_cplx(v);
    }
    node
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
            let (mut t1a, mut t1b) = fft.split_fft(t1);
            let (mut z1a, mut z1b) = ff_sampling(fft, &t1a, &t1b, right, sigmin, rng);
            let z1 = fft.merge_fft(&z1a, &z1b);
            // t0' = t0 + (t1 − z1)·L10.
            let mut diff = sub_fft(t1, &z1);
            let mut t0b = add_fft(t0, &mul_fft(&diff, l10));
            let (mut t0a, mut t0bb) = fft.split_fft(&t0b);
            let (mut z0a, mut z0b) = ff_sampling(fft, &t0a, &t0bb, left, sigmin, rng);
            let z0 = fft.merge_fft(&z0a, &z0b);
            // Every split half, sub-result and the L10-corrected target are
            // functions of the secret basis and of the sampled lattice point;
            // only the merged `(z0, z1)` leave this frame, so the rest is wiped
            // rather than freed in the clear.
            for v in [
                &mut t1a, &mut t1b, &mut z1a, &mut z1b, &mut diff, &mut t0b, &mut t0a, &mut t0bb,
                &mut z0a, &mut z0b,
            ] {
                wipe_cplx(v);
            }
            (z0, z1)
        }
    }
}

#[cfg(test)]
#[path = "tree_tests.rs"]
mod tree_tests;
