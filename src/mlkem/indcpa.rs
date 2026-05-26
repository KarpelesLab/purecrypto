//! K-PKE — the IND-CPA public-key scheme underlying ML-KEM (FIPS 203 §5).
//!
//! All key, ciphertext and intermediate buffers are fixed-size, so this layer
//! is `no_std` and allocation-free. Operations are constant time in the secret
//! key and message; the only data-dependent branching is the rejection sampling
//! of the public matrix `Â`, which depends solely on the public seed `ρ`.

use super::poly::{self, N, Poly};
use crate::hash::{ExtendableOutput, Shake128, XofReader, shake256};

/// Module rank.
pub(crate) const K: usize = 3;
/// CBD parameter (η₁ = η₂ = 2 for ML-KEM-768).
const ETA: usize = 2;
/// Bytes per `ByteEncode₁₂` polynomial.
const POLYBYTES: usize = 384;
/// `d_u` compressed polynomial size (320 = 256·10/8).
const DU_BYTES: usize = 320;
/// `d_v` compressed polynomial size (128 = 256·4/8).
const DV_BYTES: usize = 128;
/// SHAKE128 rate, the matrix-XOF squeeze block (divisible by 3).
const XOF_BLOCK: usize = 168;

/// K-PKE encryption-key bytes (`t̂ ‖ ρ`).
pub(crate) const PKE_EK_BYTES: usize = POLYBYTES * K + 32;
/// K-PKE decryption-key bytes (`ŝ`).
pub(crate) const PKE_DK_BYTES: usize = POLYBYTES * K;
/// K-PKE ciphertext bytes (`c₁ ‖ c₂`).
pub(crate) const CT_BYTES: usize = DU_BYTES * K + DV_BYTES;

/// Generates the public matrix `Â` (or its transpose) by rejection sampling a
/// SHAKE128 stream per entry. `Â[i][j]` absorbs `ρ ‖ j ‖ i` (or `ρ ‖ i ‖ j`
/// when transposed), matching the FIPS 203 / pq-crystals ordering.
fn gen_matrix(seed: &[u8; 32], transposed: bool) -> [[Poly; K]; K] {
    let mut a = [[Poly::zero(); K]; K];
    // i and j are both the matrix indices and the XOF domain-separation bytes.
    #[allow(clippy::needless_range_loop)]
    for i in 0..K {
        for j in 0..K {
            let (x, y) = if transposed {
                (i as u8, j as u8)
            } else {
                (j as u8, i as u8)
            };
            let mut xof = Shake128::new();
            xof.update(seed);
            xof.update(&[x, y]);
            let mut reader = xof.finalize_xof();
            let mut ctr = 0;
            let mut block = [0u8; XOF_BLOCK];
            while ctr < N {
                reader.read(&mut block);
                ctr += poly::rej_uniform(&mut a[i][j].c[ctr..], &block);
            }
        }
    }
    a
}

/// Samples a CBD noise polynomial: `PRF_η(seed, nonce)` then `SamplePolyCBD_η`.
fn getnoise(seed: &[u8; 32], nonce: u8) -> Poly {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(seed);
    input[32] = nonce;
    let mut buf = [0u8; 64 * ETA];
    shake256(&input, &mut buf);
    poly::cbd2(&buf)
}

/// Forward NTT on every component of a module vector.
fn vec_ntt(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.ntt();
    }
}

/// Inverse NTT on every component of a module vector.
fn vec_inv_ntt(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.inv_ntt();
    }
}

/// Accumulated pointwise product `Σ a[i] ∘ b[i]`, Barrett-reduced.
fn basemul_acc(a: &[Poly; K], b: &[Poly; K]) -> Poly {
    let mut r = poly::poly_basemul(&a[0], &b[0]);
    for i in 1..K {
        let t = poly::poly_basemul(&a[i], &b[i]);
        r.add(&t);
    }
    r.reduce();
    r
}

/// K-PKE.KeyGen (FIPS 203 Algorithm 13). Returns `(ek_PKE, dk_PKE)`.
pub(crate) fn keygen(d: &[u8; 32]) -> ([u8; PKE_EK_BYTES], [u8; PKE_DK_BYTES]) {
    // (ρ, σ) ← G(d ‖ k).
    let mut g_in = [0u8; 33];
    g_in[..32].copy_from_slice(d);
    g_in[32] = K as u8;
    let g = crate::hash::sha3_512(&g_in);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    let sigma = &g[32..];
    let mut sigma32 = [0u8; 32];
    sigma32.copy_from_slice(sigma);

    let a = gen_matrix(&rho, false);

    let mut nonce = 0u8;
    let mut s = [Poly::zero(); K];
    for p in s.iter_mut() {
        *p = getnoise(&sigma32, nonce);
        nonce += 1;
    }
    let mut e = [Poly::zero(); K];
    for p in e.iter_mut() {
        *p = getnoise(&sigma32, nonce);
        nonce += 1;
    }
    vec_ntt(&mut s);
    vec_ntt(&mut e);

    // t̂ = Â ∘ ŝ + ê.
    let mut t = [Poly::zero(); K];
    for i in 0..K {
        t[i] = basemul_acc(&a[i], &s);
        t[i].to_mont();
        t[i].add(&e[i]);
        t[i].reduce();
    }

    let mut ek = [0u8; PKE_EK_BYTES];
    for i in 0..K {
        ek[i * POLYBYTES..(i + 1) * POLYBYTES].copy_from_slice(&poly::to_bytes(&t[i]));
    }
    ek[POLYBYTES * K..].copy_from_slice(&rho);

    let mut dk = [0u8; PKE_DK_BYTES];
    for i in 0..K {
        dk[i * POLYBYTES..(i + 1) * POLYBYTES].copy_from_slice(&poly::to_bytes(&s[i]));
    }
    (ek, dk)
}

/// K-PKE.Encrypt (FIPS 203 Algorithm 14). `coins` is the encryption randomness.
pub(crate) fn encrypt(ek: &[u8; PKE_EK_BYTES], m: &[u8; 32], coins: &[u8; 32]) -> [u8; CT_BYTES] {
    let mut t = [Poly::zero(); K];
    for i in 0..K {
        t[i] = poly::from_bytes(&ek[i * POLYBYTES..(i + 1) * POLYBYTES]);
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[POLYBYTES * K..]);

    let mu = poly::from_msg(m);
    let at = gen_matrix(&rho, true);

    let mut nonce = 0u8;
    let mut sp = [Poly::zero(); K];
    for p in sp.iter_mut() {
        *p = getnoise(coins, nonce);
        nonce += 1;
    }
    let mut ep = [Poly::zero(); K];
    for p in ep.iter_mut() {
        *p = getnoise(coins, nonce);
        nonce += 1;
    }
    let epp = getnoise(coins, nonce);

    vec_ntt(&mut sp);

    // u = NTT⁻¹(Âᵀ ∘ r̂) + e₁.
    let mut u = [Poly::zero(); K];
    for i in 0..K {
        u[i] = basemul_acc(&at[i], &sp);
    }
    vec_inv_ntt(&mut u);
    for i in 0..K {
        u[i].add(&ep[i]);
        u[i].reduce();
    }

    // v = NTT⁻¹(t̂ᵀ ∘ r̂) + e₂ + μ.
    let mut v = basemul_acc(&t, &sp);
    v.inv_ntt();
    v.add(&epp);
    v.add(&mu);
    v.reduce();

    let mut ct = [0u8; CT_BYTES];
    for i in 0..K {
        ct[i * DU_BYTES..(i + 1) * DU_BYTES].copy_from_slice(&poly::compress10(&u[i]));
    }
    ct[DU_BYTES * K..].copy_from_slice(&poly::compress4(&v));
    ct
}

/// K-PKE.Decrypt (FIPS 203 Algorithm 15). Returns the recovered message.
pub(crate) fn decrypt(dk: &[u8; PKE_DK_BYTES], ct: &[u8; CT_BYTES]) -> [u8; 32] {
    let mut u = [Poly::zero(); K];
    for i in 0..K {
        u[i] = poly::decompress10(&ct[i * DU_BYTES..(i + 1) * DU_BYTES]);
    }
    let v = poly::decompress4(&ct[DU_BYTES * K..]);

    let mut s = [Poly::zero(); K];
    for i in 0..K {
        s[i] = poly::from_bytes(&dk[i * POLYBYTES..(i + 1) * POLYBYTES]);
    }

    vec_ntt(&mut u);
    let mut w = basemul_acc(&s, &u);
    w.inv_ntt();

    let mut m_poly = Poly::zero();
    m_poly.sub(&v, &w);
    m_poly.reduce();
    poly::to_msg(&m_poly)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_cancellation() {
        // 1×1 "matrix": t = A·s, b = A·sp. Then t·sp − s·b = 0 exactly.
        let mut a = Poly::zero();
        let mut s = Poly::zero();
        let mut sp = Poly::zero();
        for k in 0..N {
            a.c[k] = ((k * 3 + 1) % poly::Q as usize) as i16;
            s.c[k] = ((k % 5) as i16) - 2;
            sp.c[k] = (((k + 2) % 5) as i16) - 2;
        }
        let (mut na, mut ns, mut nsp) = (a, s, sp);
        na.ntt();
        ns.ntt();
        nsp.ntt();

        // t̂ = to_mont(Â ∘ ŝ)
        let mut t = poly::poly_basemul(&na, &ns);
        t.reduce();
        t.to_mont();
        // b̂ = Â ∘ ŝp (then to normal, then re-ntt to mimic decrypt)
        let mut b = poly::poly_basemul(&na, &nsp);
        b.inv_ntt();
        b.reduce();
        b.ntt();

        let mut v = poly::poly_basemul(&t, &nsp);
        v.inv_ntt();
        let mut w = poly::poly_basemul(&ns, &b);
        w.inv_ntt();
        let mut diff = Poly::zero();
        diff.sub(&v, &w);
        diff.reduce();
        let maxabs = diff.c.iter().map(|&c| c.unsigned_abs()).max().unwrap();
        assert!(maxabs <= 1, "1x1 cancellation failed: {maxabs}");
    }

    #[test]
    fn cancellation_leaves_only_small_noise() {
        // Noise-free: t = A∘ŝ, b = Aᵀ∘ŝp ⇒ t·sp − s·b = 0 exactly.
        let rho = [5u8; 32];
        let a = gen_matrix(&rho, false);
        let at = gen_matrix(&rho, true);

        let mut s = [Poly::zero(); K];
        let mut sp = [Poly::zero(); K];
        for i in 0..K {
            for k in 0..N {
                s[i].c[k] = (((i + k) % 5) as i16) - 2;
                sp[i].c[k] = (((i + k + 2) % 5) as i16) - 2;
            }
            s[i].ntt();
            sp[i].ntt();
        }

        let mut t = [Poly::zero(); K];
        for i in 0..K {
            t[i] = basemul_acc(&a[i], &s);
            t[i].to_mont();
        }
        let mut v = basemul_acc(&t, &sp);
        v.inv_ntt();

        let mut b = [Poly::zero(); K];
        for i in 0..K {
            b[i] = basemul_acc(&at[i], &sp);
            b[i].inv_ntt();
            b[i].reduce();
            b[i].ntt();
        }
        let mut w = basemul_acc(&s, &b);
        w.inv_ntt();

        let mut diff = Poly::zero();
        diff.sub(&v, &w);
        diff.reduce();
        let maxabs = diff.c.iter().map(|&c| c.unsigned_abs()).max().unwrap();
        assert!(maxabs <= 1, "cancellation residual too large: {maxabs}");
    }

    #[test]
    fn matrix_transpose_consistency() {
        let seed = [3u8; 32];
        let a = gen_matrix(&seed, false);
        let at = gen_matrix(&seed, true);
        for i in 0..K {
            for j in 0..K {
                assert_eq!(a[i][j].c, at[j][i].c, "a[{i}][{j}] != at[{j}][{i}]");
            }
        }
    }

    #[test]
    fn kpke_roundtrip() {
        let d = [7u8; 32];
        let m = [0x42u8; 32];
        let coins = [0x11u8; 32];
        let (ek, dk) = keygen(&d);
        let ct = encrypt(&ek, &m, &coins);
        assert_eq!(decrypt(&dk, &ct), m);
    }
}
