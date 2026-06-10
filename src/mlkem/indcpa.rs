//! K-PKE — the IND-CPA public-key scheme underlying ML-KEM (FIPS 203 §5).
//!
//! This layer is parameterized over the FIPS 203 set constants
//! (`K`, `ETA1`, `ETA2`, `DU`, `DV`) as const generics; the macro in
//! [`super`] instantiates one monomorphization per ML-KEM set. All keys,
//! ciphertexts and intermediate buffers are passed as slices sized at
//! the call site by the per-set wrapper — `no_std`, allocation-free.
//!
//! Operations are constant time in the secret key and message; the only
//! data-dependent branching is the rejection sampling of the public matrix
//! `Â`, which depends solely on the public seed `ρ`.

use super::poly::{self, N, Poly};
use crate::hash::{ExtendableOutput, Shake128, XofReader, shake256};

/// Bytes per `ByteEncode₁₂` polynomial.
pub(crate) const POLYBYTES: usize = 384;
/// SHAKE128 rate, the matrix-XOF squeeze block (divisible by 3).
const XOF_BLOCK: usize = 168;

/// Bytes per compressed `u` polynomial: `32·DU`.
pub(crate) const fn du_bytes(du: usize) -> usize {
    32 * du
}
/// Bytes per compressed `v` polynomial: `32·DV`.
pub(crate) const fn dv_bytes(dv: usize) -> usize {
    32 * dv
}

/// Generates the public matrix `Â` (or its transpose) by rejection sampling a
/// SHAKE128 stream per entry. `Â[i][j]` absorbs `ρ ‖ j ‖ i` (or `ρ ‖ i ‖ j`
/// when transposed), matching the FIPS 203 / pq-crystals ordering.
fn gen_matrix<const K: usize>(seed: &[u8; 32], transposed: bool) -> [[Poly; K]; K] {
    let mut a = [[Poly::zero(); K]; K];
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
/// The PRF output buffer is sized to `64·ETA` bytes; we use a worst-case
/// `[u8; 192]` stack buffer (η ≤ 3) and slice it down.
fn getnoise<const ETA: usize>(seed: &[u8; 32], nonce: u8) -> Poly {
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(seed);
    input[32] = nonce;
    let mut buf = [0u8; 192];
    let need = 64 * ETA;
    shake256(&input, &mut buf[..need]);
    let out = poly::cbd::<ETA>(&buf[..need]);
    // Wipe the PRF input (a copy of the secret noise seed) and output (the
    // raw bits the secret noise polynomial is read from) before they drop.
    for b in input.iter_mut().chain(buf.iter_mut()) {
        *b = 0;
    }
    let _ = core::hint::black_box((&input, &buf));
    out
}

/// Forward NTT on every component of a module vector.
fn vec_ntt<const K: usize>(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.ntt();
    }
}

/// Inverse NTT on every component of a module vector.
fn vec_inv_ntt<const K: usize>(v: &mut [Poly; K]) {
    for p in v.iter_mut() {
        p.inv_ntt();
    }
}

/// Accumulated pointwise product `Σ a[i] ∘ b[i]`, Barrett-reduced.
fn basemul_acc<const K: usize>(a: &[Poly; K], b: &[Poly; K]) -> Poly {
    let mut r = poly::poly_basemul(&a[0], &b[0]);
    for i in 1..K {
        let t = poly::poly_basemul(&a[i], &b[i]);
        r.add(&t);
    }
    r.reduce();
    r
}

/// K-PKE.KeyGen (FIPS 203 Algorithm 13). Writes `ek_PKE` to `ek` and
/// `dk_PKE` to `dk`; sizes must be `POLYBYTES·K + 32` and `POLYBYTES·K`.
pub(crate) fn keygen<const K: usize, const ETA1: usize>(
    d: &[u8; 32],
    ek: &mut [u8],
    dk: &mut [u8],
) {
    debug_assert_eq!(ek.len(), POLYBYTES * K + 32);
    debug_assert_eq!(dk.len(), POLYBYTES * K);

    // (ρ, σ) ← G(d ‖ k).
    let mut g_in = [0u8; 33];
    g_in[..32].copy_from_slice(d);
    g_in[32] = K as u8;
    let mut g = crate::hash::sha3_512(&g_in);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    let mut sigma32 = [0u8; 32];
    sigma32.copy_from_slice(&g[32..]);

    let a = gen_matrix::<K>(&rho, false);

    let mut nonce = 0u8;
    let mut s: [Poly; K] = [Poly::zero(); K];
    for p in s.iter_mut() {
        *p = getnoise::<ETA1>(&sigma32, nonce);
        nonce += 1;
    }
    let mut e: [Poly; K] = [Poly::zero(); K];
    for p in e.iter_mut() {
        *p = getnoise::<ETA1>(&sigma32, nonce);
        nonce += 1;
    }
    vec_ntt::<K>(&mut s);
    vec_ntt::<K>(&mut e);

    // t̂ = Â ∘ ŝ + ê.
    let mut t: [Poly; K] = [Poly::zero(); K];
    for i in 0..K {
        t[i] = basemul_acc::<K>(&a[i], &s);
        t[i].to_mont();
        t[i].add(&e[i]);
        t[i].reduce();
    }

    for i in 0..K {
        ek[i * POLYBYTES..(i + 1) * POLYBYTES].copy_from_slice(&poly::to_bytes(&t[i]));
    }
    ek[POLYBYTES * K..].copy_from_slice(&rho);

    for i in 0..K {
        dk[i * POLYBYTES..(i + 1) * POLYBYTES].copy_from_slice(&poly::to_bytes(&s[i]));
    }

    // Wipe the transient secrets: the G input (a copy of the seed `d`, which
    // alone reconstructs the whole key), the G output, and the noise seed σ.
    // ρ is public (it is serialized into `ek`).
    for b in g_in
        .iter_mut()
        .chain(g.iter_mut())
        .chain(sigma32.iter_mut())
    {
        *b = 0;
    }
    let _ = core::hint::black_box((&g_in, &g, &sigma32));
}

/// K-PKE.Encrypt (FIPS 203 Algorithm 14). Writes the ciphertext into `ct`.
/// Sizes: `ek.len() = POLYBYTES·K + 32`; `ct.len() = du_bytes(DU)·K + dv_bytes(DV)`.
pub(crate) fn encrypt<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    ek: &[u8],
    m: &[u8; 32],
    coins: &[u8; 32],
    ct: &mut [u8],
) {
    debug_assert_eq!(ek.len(), POLYBYTES * K + 32);
    debug_assert_eq!(ct.len(), du_bytes(DU) * K + dv_bytes(DV));

    let mut t: [Poly; K] = [Poly::zero(); K];
    for i in 0..K {
        t[i] = poly::from_bytes(&ek[i * POLYBYTES..(i + 1) * POLYBYTES]);
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[POLYBYTES * K..]);

    let mu = poly::from_msg(m);
    let at = gen_matrix::<K>(&rho, true);

    let mut nonce = 0u8;
    let mut sp: [Poly; K] = [Poly::zero(); K];
    for p in sp.iter_mut() {
        *p = getnoise::<ETA1>(coins, nonce);
        nonce += 1;
    }
    let mut ep: [Poly; K] = [Poly::zero(); K];
    for p in ep.iter_mut() {
        *p = getnoise::<ETA2>(coins, nonce);
        nonce += 1;
    }
    let epp = getnoise::<ETA2>(coins, nonce);

    vec_ntt::<K>(&mut sp);

    // u = NTT⁻¹(Âᵀ ∘ r̂) + e₁.
    let mut u: [Poly; K] = [Poly::zero(); K];
    for i in 0..K {
        u[i] = basemul_acc::<K>(&at[i], &sp);
    }
    vec_inv_ntt::<K>(&mut u);
    for i in 0..K {
        u[i].add(&ep[i]);
        u[i].reduce();
    }

    // v = NTT⁻¹(t̂ᵀ ∘ r̂) + e₂ + μ.
    let mut v = basemul_acc::<K>(&t, &sp);
    v.inv_ntt();
    v.add(&epp);
    v.add(&mu);
    v.reduce();

    let du_b = du_bytes(DU);
    let dv_b = dv_bytes(DV);
    for i in 0..K {
        poly::compress::<DU>(&u[i], &mut ct[i * du_b..(i + 1) * du_b]);
    }
    poly::compress::<DV>(&v, &mut ct[du_b * K..du_b * K + dv_b]);
}

/// K-PKE.Decrypt (FIPS 203 Algorithm 15). Returns the recovered message.
/// Sizes: `dk.len() = POLYBYTES·K`; `ct.len() = du_bytes(DU)·K + dv_bytes(DV)`.
pub(crate) fn decrypt<const K: usize, const DU: usize, const DV: usize>(
    dk: &[u8],
    ct: &[u8],
) -> [u8; 32] {
    debug_assert_eq!(dk.len(), POLYBYTES * K);
    debug_assert_eq!(ct.len(), du_bytes(DU) * K + dv_bytes(DV));

    let du_b = du_bytes(DU);
    let dv_b = dv_bytes(DV);

    let mut u: [Poly; K] = [Poly::zero(); K];
    for i in 0..K {
        poly::decompress::<DU>(&ct[i * du_b..(i + 1) * du_b], &mut u[i]);
    }
    let mut v = Poly::zero();
    poly::decompress::<DV>(&ct[du_b * K..du_b * K + dv_b], &mut v);

    let mut s: [Poly; K] = [Poly::zero(); K];
    for i in 0..K {
        s[i] = poly::from_bytes(&dk[i * POLYBYTES..(i + 1) * POLYBYTES]);
    }

    vec_ntt::<K>(&mut u);
    let mut w = basemul_acc::<K>(&s, &u);
    w.inv_ntt();

    let mut m_poly = Poly::zero();
    m_poly.sub(&v, &w);
    m_poly.reduce();
    poly::to_msg(&m_poly)
}

#[cfg(test)]
mod tests {
    use super::*;

    const K_TEST: usize = 3;
    const ETA1_TEST: usize = 2;
    const ETA2_TEST: usize = 2;
    const DU_TEST: usize = 10;
    const DV_TEST: usize = 4;
    const POLY: usize = POLYBYTES; // alias

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

        let mut t = poly::poly_basemul(&na, &ns);
        t.reduce();
        t.to_mont();
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
        // ML-KEM-768 K = 3.
        let rho = [5u8; 32];
        let a = gen_matrix::<K_TEST>(&rho, false);
        let at = gen_matrix::<K_TEST>(&rho, true);

        let mut s = [Poly::zero(); K_TEST];
        let mut sp = [Poly::zero(); K_TEST];
        for i in 0..K_TEST {
            for k in 0..N {
                s[i].c[k] = (((i + k) % 5) as i16) - 2;
                sp[i].c[k] = (((i + k + 2) % 5) as i16) - 2;
            }
            s[i].ntt();
            sp[i].ntt();
        }

        let mut t = [Poly::zero(); K_TEST];
        for i in 0..K_TEST {
            t[i] = basemul_acc::<K_TEST>(&a[i], &s);
            t[i].to_mont();
        }
        let mut v = basemul_acc::<K_TEST>(&t, &sp);
        v.inv_ntt();

        let mut b = [Poly::zero(); K_TEST];
        for i in 0..K_TEST {
            b[i] = basemul_acc::<K_TEST>(&at[i], &sp);
            b[i].inv_ntt();
            b[i].reduce();
            b[i].ntt();
        }
        let mut w = basemul_acc::<K_TEST>(&s, &b);
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
        let a = gen_matrix::<K_TEST>(&seed, false);
        let at = gen_matrix::<K_TEST>(&seed, true);
        for i in 0..K_TEST {
            for j in 0..K_TEST {
                assert_eq!(a[i][j].c, at[j][i].c, "a[{i}][{j}] != at[{j}][{i}]");
            }
        }
    }

    #[test]
    fn kpke_roundtrip() {
        let d = [7u8; 32];
        let m = [0x42u8; 32];
        let coins = [0x11u8; 32];
        let mut ek = [0u8; POLY * K_TEST + 32];
        let mut dk = [0u8; POLY * K_TEST];
        keygen::<K_TEST, ETA1_TEST>(&d, &mut ek, &mut dk);
        let mut ct = [0u8; du_bytes(DU_TEST) * K_TEST + dv_bytes(DV_TEST)];
        encrypt::<K_TEST, ETA1_TEST, ETA2_TEST, DU_TEST, DV_TEST>(&ek, &m, &coins, &mut ct);
        assert_eq!(decrypt::<K_TEST, DU_TEST, DV_TEST>(&dk, &ct), m);
    }
}
