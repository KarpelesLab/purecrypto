//! Falcon key generation: `NTRUGen` / `NTRUSolve` / `Reduce` (spec §3.8.2).
//!
//! Samples the secret NTRU polynomials `f, g` from a discrete Gaussian, then
//! solves the NTRU equation `f·G − g·F = q (mod xⁿ+1)` via the tower-of-rings
//! recursion, and derives the public key `h = g·f⁻¹ (mod q)`. Mirrors
//! `tprest/falcon.py` (`ntrugen.py`).
//!
//! The lift + Karatsuba construction in `ntru_solve` already guarantees the NTRU
//! equation exactly (over ℤ); `reduce` (Babai, via the emulated FFT) only shrinks
//! the coefficients so the result is encodable. Big integers use [`Zint`].
//!
//! Key generation is one-time and operates on fresh, non-secret-dependent
//! entropy, so it favors clarity over constant-time.

use super::fft::{Cplx, Fft, add_fft, adj_fft, div_fft, mul_fft};
use super::fpr::Fpr;
use super::sampler::{SamplerRng, sampler_z};
use super::zint::{Zint, ext_gcd};
use alloc::vec::Vec;

/// Falcon modulus.
const Q: i64 = 12289;

/// The raw output of key generation: `(f, g, F, G, h)` — the secret NTRU
/// polynomials with `f·G − g·F = q`, and the public key `h = g·f⁻¹ mod q`.
pub(crate) type RawNtruKey = (Vec<i64>, Vec<i64>, Vec<i64>, Vec<i64>, Vec<u16>);

// ---------------------------------------------------------------------------
// Modular arithmetic and a direct negacyclic transform mod q (for the
// invertibility check and for h = g·f⁻¹). O(n²), used only at keygen time.
// ---------------------------------------------------------------------------

fn pow_mod(mut b: i64, mut e: i64, q: i64) -> i64 {
    b = b.rem_euclid(q);
    let mut r = 1i64;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % q;
        }
        b = b * b % q;
        e >>= 1;
    }
    r
}

fn inv_mod(a: i64, q: i64) -> i64 {
    pow_mod(a.rem_euclid(q), q - 2, q)
}

/// Find a primitive `2n`-th root of unity ψ mod q (ψⁿ ≡ −1).
fn find_psi(n: usize) -> i64 {
    let twon = (2 * n) as i64;
    let exp = (Q - 1) / twon;
    for base in 2..Q {
        let psi = pow_mod(base, exp, Q);
        if pow_mod(psi, n as i64, Q) == Q - 1 {
            return psi;
        }
    }
    unreachable!("q supports a 2n-th root of unity for Falcon degrees")
}

/// Negacyclic evaluation `F[i] = f(ψ^{2i+1})` via pre-scaling + a cyclic DFT.
/// Returns the `n` evaluations mod q. `coeffs` are reduced mod q first.
fn negacyclic_eval(coeffs: &[i64], psi_pows: &[i64], omega_pows: &[i64], n: usize) -> Vec<i64> {
    // b[k] = a[k]·ψ^k.
    let b: Vec<i64> = (0..n)
        .map(|k| coeffs[k].rem_euclid(Q) * psi_pows[k] % Q)
        .collect();
    // F[i] = Σ_k b[k]·ω^{ik}.
    let mut out = alloc::vec![0i64; n];
    for (i, oi) in out.iter_mut().enumerate() {
        let mut acc = 0i64;
        for k in 0..n {
            acc += b[k] * omega_pows[(i * k) % n] % Q;
            acc %= Q;
        }
        *oi = acc;
    }
    out
}

/// Inverse of [`negacyclic_eval`]: recover coefficients in `[0, q)`.
fn negacyclic_interp(
    evals: &[i64],
    psi_inv_pows: &[i64],
    omega_inv_pows: &[i64],
    n: usize,
) -> Vec<i64> {
    let ninv = inv_mod(n as i64, Q);
    let mut out = alloc::vec![0i64; n];
    for (k, ok) in out.iter_mut().enumerate() {
        // b[k] = n⁻¹·Σ_i F[i]·ω^{-ik}.
        let mut acc = 0i64;
        for (i, &fi) in evals.iter().enumerate() {
            acc += fi * omega_inv_pows[(i * k) % n] % Q;
            acc %= Q;
        }
        let bk = acc * ninv % Q;
        // a[k] = b[k]·ψ^{-k}.
        *ok = bk * psi_inv_pows[k] % Q;
    }
    out
}

/// Recompute `G` from `(f, g, F)` via `G = (q + g·F)/f`, exact in the ring (the
/// FFT division is rounded back to integers). Used when importing a compact
/// secret key that omits `G`.
pub(crate) fn recompute_g(f: &[i64], g: &[i64], cap_f: &[i64], n: usize) -> Vec<i64> {
    let fft = Fft::new(n);
    let to_fpr = |p: &[i64]| -> Vec<Fpr> { p.iter().map(|&c| Fpr::of_i64(c)).collect() };
    let f_fft = fft.fft(&to_fpr(f));
    let g_fft = fft.fft(&to_fpr(g));
    let cf_fft = fft.fft(&to_fpr(cap_f));
    let qf = Fpr::of_i64(Q);
    // num = q + g·F (the constant polynomial q has FFT equal to q everywhere).
    let num: Vec<Cplx> = (0..n)
        .map(|i| {
            let gf = g_fft[i].mul(cf_fft[i]);
            Cplx::new(gf.re.add(qf), gf.im)
        })
        .collect();
    let g_cap_fft = div_fft(&num, &f_fft);
    fft.ifft(&g_cap_fft).iter().map(|x| x.rint()).collect()
}

/// Compute `h = g·f⁻¹ mod (xⁿ+1, q)`, or `None` if `f` is not invertible.
pub(crate) fn compute_h(f: &[i64], g: &[i64], n: usize) -> Option<Vec<u16>> {
    let psi = find_psi(n);
    let omega = psi * psi % Q;
    let psi_inv = inv_mod(psi, Q);
    let omega_inv = inv_mod(omega, Q);
    let pow_table = |base: i64| -> Vec<i64> {
        let mut v = alloc::vec![1i64; n];
        for i in 1..n {
            v[i] = v[i - 1] * base % Q;
        }
        v
    };
    let psi_pows = pow_table(psi);
    let omega_pows = pow_table(omega);
    let psi_inv_pows = pow_table(psi_inv);
    let omega_inv_pows = pow_table(omega_inv);

    let fe = negacyclic_eval(f, &psi_pows, &omega_pows, n);
    if fe.contains(&0) {
        return None; // f not invertible
    }
    let ge = negacyclic_eval(g, &psi_pows, &omega_pows, n);
    let he: Vec<i64> = (0..n).map(|i| ge[i] * inv_mod(fe[i], Q) % Q).collect();
    let h = negacyclic_interp(&he, &psi_inv_pows, &omega_inv_pows, n);
    Some(h.iter().map(|&x| x.rem_euclid(Q) as u16).collect())
}

// ---------------------------------------------------------------------------
// Polynomial operations over Z (Zint coefficients).
// ---------------------------------------------------------------------------

/// Karatsuba product of two length-`n` polynomials; returns length `2n`.
fn karatsuba(a: &[Zint], b: &[Zint], n: usize) -> Vec<Zint> {
    if n == 1 {
        return alloc::vec![a[0].mul(&b[0]), Zint::zero()];
    }
    let n2 = n / 2;
    let (a0, a1) = (&a[..n2], &a[n2..]);
    let (b0, b1) = (&b[..n2], &b[n2..]);
    let ax: Vec<Zint> = (0..n2).map(|i| a0[i].add(&a1[i])).collect();
    let bx: Vec<Zint> = (0..n2).map(|i| b0[i].add(&b1[i])).collect();
    let a0b0 = karatsuba(a0, b0, n2);
    let a1b1 = karatsuba(a1, b1, n2);
    let mut axbx = karatsuba(&ax, &bx, n2);
    for i in 0..n {
        axbx[i] = axbx[i].sub(&a0b0[i].add(&a1b1[i]));
    }
    let mut ab = alloc::vec![Zint::zero(); 2 * n];
    for i in 0..n {
        ab[i] = ab[i].add(&a0b0[i]);
        ab[i + n] = ab[i + n].add(&a1b1[i]);
        ab[i + n2] = ab[i + n2].add(&axbx[i]);
    }
    ab
}

/// Karatsuba product reduced mod (xⁿ+1): `ab[i] − ab[i+n]`.
fn karamul(a: &[Zint], b: &[Zint]) -> Vec<Zint> {
    let n = a.len();
    let ab = karatsuba(a, b, n);
    (0..n).map(|i| ab[i].sub(&ab[i + n])).collect()
}

/// Galois conjugate `a(−x)`: negate odd-index coefficients.
fn galois_conjugate(a: &[Zint]) -> Vec<Zint> {
    a.iter()
        .enumerate()
        .map(|(i, c)| if i & 1 == 1 { c.neg() } else { c.clone() })
        .collect()
}

/// Field norm: project `ℤ[x]/(xⁿ+1)` onto `ℤ[x]/(x^(n/2)+1)`.
fn field_norm(a: &[Zint]) -> Vec<Zint> {
    let n2 = a.len() / 2;
    let ae: Vec<Zint> = (0..n2).map(|i| a[2 * i].clone()).collect();
    let ao: Vec<Zint> = (0..n2).map(|i| a[2 * i + 1].clone()).collect();
    let ae_sq = karamul(&ae, &ae);
    let ao_sq = karamul(&ao, &ao);
    let mut res = ae_sq;
    for i in 0..n2 - 1 {
        res[i + 1] = res[i + 1].sub(&ao_sq[i]);
    }
    res[0] = res[0].add(&ao_sq[n2 - 1]);
    res
}

/// Lift `a(x)` from `ℤ[x]/(x^(n/2)+1)` to `a(x²)` in `ℤ[x]/(xⁿ+1)`.
fn lift(a: &[Zint]) -> Vec<Zint> {
    let n = a.len();
    let mut res = alloc::vec![Zint::zero(); 2 * n];
    for i in 0..n {
        res[2 * i] = a[i].clone();
    }
    res
}

/// Max byte-rounded bitsize over the coefficients of `f` and `g`.
fn max_bitsize(f: &[Zint], g: &[Zint]) -> usize {
    let mut m = 53usize;
    for c in f.iter().chain(g.iter()) {
        m = m.max(c.bitsize());
    }
    m
}

/// Babai reduction of `(F, G)` against `(f, g)` (spec Alg. 7), via the emulated
/// FFT. Shrinks `F, G` in place; the NTRU equation is preserved.
fn reduce(f: &[Zint], g: &[Zint], cap_f: &mut [Zint], cap_g: &mut [Zint]) {
    let n = f.len();
    let fft = Fft::new(n);
    let size = max_bitsize(f, g);
    let adjust = |p: &[Zint], sz: usize| -> Vec<Fpr> {
        p.iter()
            .map(|c| Fpr::of_i64(c.shr(sz - 53).to_i64().unwrap_or(0)))
            .collect()
    };
    let fa = fft.fft(&adjust(f, size));
    let ga = fft.fft(&adjust(g, size));
    let adj_fa = adj_fft(&fa);
    let adj_ga = adj_fft(&ga);
    let den = add_fft(&mul_fft(&fa, &adj_fa), &mul_fft(&ga, &adj_ga));

    loop {
        let big = max_bitsize(cap_f, cap_g);
        if big < size {
            break;
        }
        let cap_fa = fft.fft(&adjust(cap_f, big));
        let cap_ga = fft.fft(&adjust(cap_g, big));
        let num = add_fft(&mul_fft(&cap_fa, &adj_fa), &mul_fft(&cap_ga, &adj_ga));
        let k_real = fft.ifft(&div_fft(&num, &den));
        let k: Vec<Zint> = k_real.iter().map(|x| Zint::from_i64(x.rint())).collect();
        if k.iter().all(|z| z.is_zero()) {
            break;
        }
        let fk = karamul(f, &k);
        let gk = karamul(g, &k);
        let sh = big - size;
        for i in 0..n {
            cap_f[i] = cap_f[i].sub(&fk[i].shl(sh));
            cap_g[i] = cap_g[i].sub(&gk[i].shl(sh));
        }
    }
}

/// Solve the NTRU equation for `f, g`. Returns `(F, G)` with
/// `f·G − g·F = q`, or `None` if unsolvable (caller retries keygen).
fn ntru_solve(f: &[Zint], g: &[Zint]) -> Option<(Vec<Zint>, Vec<Zint>)> {
    let n = f.len();
    if n == 1 {
        let (d, u, v) = ext_gcd(&f[0], &g[0]);
        if d != Zint::from_i64(1) {
            return None;
        }
        let q = Zint::from_i64(Q);
        // F = -q·v, G = q·u.
        return Some((alloc::vec![q.mul(&v).neg()], alloc::vec![q.mul(&u)]));
    }
    let fp = field_norm(f);
    let gp = field_norm(g);
    let (cap_fp, cap_gp) = ntru_solve(&fp, &gp)?;
    let mut cap_f = karamul(&lift(&cap_fp), &galois_conjugate(g));
    let mut cap_g = karamul(&lift(&cap_gp), &galois_conjugate(f));
    reduce(f, g, &mut cap_f, &mut cap_g);
    Some((cap_f, cap_g))
}

// ---------------------------------------------------------------------------
// Gaussian sampling of f, g and the Gram-Schmidt rejection bound.
// ---------------------------------------------------------------------------

/// `σ_fg = 1.17·√(q/2n)` (constant per the reference; here as the literal it
/// rounds to: `1.17·√(12289/8192)`).
const SIGMA_FG: Fpr = Fpr::from_f64(1.43300980528773);

/// Generate a polynomial of degree `< n` with discrete-Gaussian coefficients,
/// by summing `4096/n` base samples per coefficient (so the per-coefficient
/// deviation is `σ_fg`). Mirrors `gen_poly`.
fn gen_poly<R: SamplerRng>(n: usize, rng: &mut R) -> Vec<i64> {
    let sigmin = Fpr::from_f64(1.43300980528773 - 0.001);
    let zero = Fpr::from_f64(0.0);
    let total = 4096;
    let samples: Vec<i64> = (0..total)
        .map(|_| sampler_z(zero, SIGMA_FG, sigmin, rng))
        .collect();
    let k = total / n;
    (0..n)
        .map(|i| (0..k).map(|j| samples[i * k + j]).sum())
        .collect()
}

/// Squared Gram-Schmidt norm of the NTRU basis `[[g, −f], [G, −F]]`
/// (spec Alg. 5 line 9), in the emulated FFT.
fn gs_norm(f: &[i64], g: &[i64], n: usize) -> Fpr {
    let fft = Fft::new(n);
    let ff: Vec<Fpr> = f.iter().map(|&c| Fpr::of_i64(c)).collect();
    let gf: Vec<Fpr> = g.iter().map(|&c| Fpr::of_i64(c)).collect();

    let sqnorm_fg = {
        let mut s = Fpr::from_f64(0.0);
        for &c in f.iter().chain(g.iter()) {
            let cf = Fpr::of_i64(c);
            s = s.add(cf.mul(cf));
        }
        s
    };

    let f_fft = fft.fft(&ff);
    let g_fft = fft.fft(&gf);
    // ffgg = f·adj(f) + g·adj(g).
    let ffgg = add_fft(
        &mul_fft(&f_fft, &adj_fft(&f_fft)),
        &mul_fft(&g_fft, &adj_fft(&g_fft)),
    );
    // Ft = adj(g)/ffgg, Gt = adj(f)/ffgg, then back to coefficients.
    let ft = fft.ifft(&div_fft(&adj_fft(&g_fft), &ffgg));
    let gt = fft.ifft(&div_fft(&adj_fft(&f_fft), &ffgg));
    let mut s_ftgt = Fpr::from_f64(0.0);
    for c in ft.iter().chain(gt.iter()) {
        s_ftgt = s_ftgt.add(c.mul(*c));
    }
    let qsq = Fpr::of_i64(Q * Q);
    let sqnorm_cap = qsq.mul(s_ftgt);

    if sqnorm_fg.lt(sqnorm_cap) {
        sqnorm_cap
    } else {
        sqnorm_fg
    }
}

/// Generate Falcon NTRU polynomials `(f, g, F, G)` with `f·G − g·F = q`, plus
/// the public key `h = g·f⁻¹ mod q`. Loops until the rejection conditions pass
/// and the NTRU equation is solvable.
pub(crate) fn ntru_gen<R: SamplerRng>(n: usize, rng: &mut R) -> RawNtruKey {
    // Rejection bound (1.17²·q).
    let bound = Fpr::of_i64(Q).mul(Fpr::from_f64(1.17 * 1.17));
    loop {
        let f = gen_poly(n, rng);
        let g = gen_poly(n, rng);
        if bound.lt(gs_norm(&f, &g, n)) {
            continue;
        }
        let h = match compute_h(&f, &g, n) {
            Some(h) => h,
            None => continue, // f not invertible mod q
        };
        let fz: Vec<Zint> = f.iter().map(|&c| Zint::from_i64(c)).collect();
        let gz: Vec<Zint> = g.iter().map(|&c| Zint::from_i64(c)).collect();
        let (cap_f, cap_g) = match ntru_solve(&fz, &gz) {
            Some(fg) => fg,
            None => continue,
        };
        // F, G must fit i64 to be a usable key; otherwise retry.
        let cap_f_i: Option<Vec<i64>> = cap_f.iter().map(|z| z.to_i64()).collect();
        let cap_g_i: Option<Vec<i64>> = cap_g.iter().map(|z| z.to_i64()).collect();
        match (cap_f_i, cap_g_i) {
            (Some(cf), Some(cg)) => return (f, g, cf, cg, h),
            _ => continue,
        }
    }
}

#[cfg(test)]
#[path = "keygen_tests.rs"]
mod keygen_tests;
