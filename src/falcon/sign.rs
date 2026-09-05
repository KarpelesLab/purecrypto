//! Falcon signing (spec §3.9, Algorithm 10) and the expanded secret key.
//!
//! From the NTRU polynomials `(f, g, F, G)` we form the basis
//! `B = [[g, −f], [G, −F]]` in the FFT domain and its normalized LDL tree (the
//! one-time "key expansion"). To sign, we hash the salted message to a point
//! `c`, build the target `t = (c, 0)·B⁻¹` in the FFT domain, draw a nearby
//! lattice point with the constant-time fast-Fourier sampler, form the short
//! vector `s = (c, 0) − z·B`, and compress `s₁`, retrying until the squared
//! norm and the compressed length are within bounds. Mirrors
//! `tprest/falcon.py` (`__sample_preimage__` / `sign`).
//!
//! The expansion and the per-signature sampling run entirely in the emulated
//! [`Fpr`], which removes the subnormal-timing and FMA-contraction leaks of a
//! hardware `f64`. That is **not** the same as being data-oblivious: `Fpr` is
//! best-effort constant time, not branch-free (see its "Constant-time caveat"),
//! and this is the secret-dependent path, so a residual floating-point timing
//! side channel remains. A fully branchless FPEMU is the fix and is future
//! work; until then, treat Falcon signing as not strictly constant time.

use super::Degree;
use super::encode::compress;
use super::fft::{Cplx, Fft, add_fft, mul_fft, wipe_cplx};
use super::fpr::{FPR_ZERO, Fpr, wipe_fpr};
use super::sampler::SamplerRng;
use super::tree::{FftTree, ff_sampling, ffldl, gram, wipe_gram};
use alloc::vec::Vec;

/// Length of the salt prepended to the message before hashing.
const SALT_LEN: usize = 40;

/// An expanded Falcon secret key: the basis in FFT form plus the sampling tree.
pub(crate) struct ExpandedKey {
    degree: Degree,
    fft: Fft,
    /// `B = [[a, b], [c, d]] = [[fft(g), fft(−f)], [fft(G), fft(−F)]]`.
    a: Vec<Cplx>,
    b: Vec<Cplx>,
    c: Vec<Cplx>,
    d: Vec<Cplx>,
    tree: FftTree,
    sigmin: Fpr,
}

impl Drop for ExpandedKey {
    fn drop(&mut self) {
        // `b = FFT(−f)` (and `d = FFT(−F)`) is a *lossless* representation of
        // the secret polynomial: one `ifft` plus `rint` recovers `f` exactly.
        // The LDL tree is likewise a function of the whole secret basis. That
        // is ~128 KB of key-equivalent material at n = 1024, and
        // `FalconPrivateKey`'s own `Drop` never reached any of it.
        for v in [&mut self.a, &mut self.b, &mut self.c, &mut self.d] {
            wipe_cplx(v);
        }
        self.tree.wipe();
        self.sigmin = FPR_ZERO;
        let _ = core::hint::black_box(&self.sigmin);
        // `fft` holds only the public roots of unity, and `degree` is public.
    }
}

fn to_fpr(p: &[i64]) -> Vec<Fpr> {
    p.iter().map(|&c| Fpr::of_i64(c)).collect()
}

fn neg_fpr(p: &[i64]) -> Vec<Fpr> {
    p.iter().map(|&c| Fpr::of_i64(-c)).collect()
}

/// Signing standard deviation σ for a parameter set (spec Table 3.3).
fn sigma_of(d: Degree) -> Fpr {
    match d {
        Degree::Falcon512 => Fpr::from_f64(165.736_617_182_977_6),
        Degree::Falcon1024 => Fpr::from_f64(168.388_571_446_543_95),
    }
}

/// Lower bound σ_min on the per-leaf deviation (spec Table 3.3).
fn sigmin_of(d: Degree) -> Fpr {
    match d {
        Degree::Falcon512 => Fpr::from_f64(1.277_833_696_912_833_7),
        Degree::Falcon1024 => Fpr::from_f64(1.298_280_334_344_292),
    }
}

/// Expand `(f, g, F, G)` into the FFT basis and the normalized LDL tree.
pub(crate) fn expand_key(
    f: &[i64],
    g: &[i64],
    cap_f: &[i64],
    cap_g: &[i64],
    degree: Degree,
) -> ExpandedKey {
    let n = degree.n();
    let fft = Fft::new(n);
    // Bind the coefficient buffers so they can be wiped: each is a plain copy
    // of a secret polynomial, and as temporaries they would otherwise be freed
    // in the clear.
    let (mut gc, mut fc, mut cgc, mut cfc) = (to_fpr(g), neg_fpr(f), to_fpr(cap_g), neg_fpr(cap_f));
    let a = fft.fft(&gc);
    let b = fft.fft(&fc);
    let c = fft.fft(&cgc);
    let d = fft.fft(&cfc);
    for v in [&mut gc, &mut fc, &mut cgc, &mut cfc] {
        wipe_fpr(v);
    }
    let mut basis = [[a.clone(), b.clone()], [c.clone(), d.clone()]];
    let mut g_gram = gram(&basis);
    let tree = ffldl(&fft, &g_gram, sigma_of(degree));
    // The basis copy and the Gram matrix are both secret-derived.
    wipe_gram(&mut basis);
    wipe_gram(&mut g_gram);
    ExpandedKey {
        degree,
        fft,
        a,
        b,
        c,
        d,
        tree,
        sigmin: sigmin_of(degree),
    }
}

/// Produce a Falcon signature `header || salt || compress(s₁)` over `msg`,
/// using the given 40-byte `salt` and a sampler randomness source `rng`.
/// Loops (resampling) until the norm bound and compression both succeed.
pub(crate) fn sign_internal<R: SamplerRng>(
    key: &ExpandedKey,
    msg: &[u8],
    salt: &[u8; SALT_LEN],
    rng: &mut R,
) -> Vec<u8> {
    let n = key.degree.n();
    let logn = n.trailing_zeros() as u8;
    let sig_bound = key.degree.sig_bound();
    let slen = key.degree.sig_len() - 1 - SALT_LEN;

    // c = HashToPoint(salt || msg); fft(c).
    let c = super::hash_to_point(salt, msg, n);
    let c_fpr: Vec<Fpr> = c.iter().map(|&x| Fpr::of_i64(x as i64)).collect();
    let point_fft = key.fft.fft(&c_fpr);

    let inv_q = Fpr::from_f64(1.0).div(Fpr::of_i64(super::Q as i64));
    let neg_inv_q = inv_q.neg();

    loop {
        // Target: t0 = c·d/q, t1 = −c·b/q (FFT domain).
        let pd = mul_fft(&point_fft, &key.d);
        let t0: Vec<Cplx> = pd.iter().map(|z| z.scale(inv_q)).collect();
        let pb = mul_fft(&point_fft, &key.b);
        let t1: Vec<Cplx> = pb.iter().map(|z| z.scale(neg_inv_q)).collect();

        let (z0, z1) = ff_sampling(&key.fft, &t0, &t1, &key.tree, key.sigmin, rng);

        // v = z·B; s = (c, 0) − v.
        let v0 = key
            .fft
            .ifft(&add_fft(&mul_fft(&z0, &key.a), &mul_fft(&z1, &key.c)));
        let v1 = key
            .fft
            .ifft(&add_fft(&mul_fft(&z0, &key.b), &mul_fft(&z1, &key.d)));
        let s0: Vec<i64> = (0..n).map(|i| c[i] as i64 - v0[i].rint()).collect();
        let s1: Vec<i64> = (0..n).map(|i| -v1[i].rint()).collect();

        let norm: u64 = s0.iter().chain(s1.iter()).map(|&x| (x * x) as u64).sum();
        if norm > sig_bound {
            continue;
        }
        let s1_i16: Vec<i16> = s1.iter().map(|&x| x as i16).collect();
        if let Some(enc) = compress(&s1_i16, slen) {
            let mut out = Vec::with_capacity(key.degree.sig_len());
            out.push(0x30 | logn); // padded format header
            out.extend_from_slice(salt);
            out.extend_from_slice(&enc);
            return out;
        }
    }
}

#[cfg(test)]
#[path = "sign_tests.rs"]
mod sign_tests;
