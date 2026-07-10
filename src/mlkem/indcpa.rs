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

/// Rejection-samples one matrix entry from `SHAKE128(seed ‖ x ‖ y)`.
fn gen_matrix_entry(seed: &[u8; 32], x: u8, y: u8, out: &mut Poly) {
    let mut xof = Shake128::new();
    xof.update(seed);
    xof.update(&[x, y]);
    let mut reader = xof.finalize_xof();
    let mut ctr = 0;
    let mut block = [0u8; XOF_BLOCK];
    while ctr < N {
        reader.read(&mut block);
        ctr += poly::rej_uniform(&mut out.c[ctr..], &block);
    }
}

/// Generates the public matrix `Â` (or its transpose) by rejection sampling a
/// SHAKE128 stream per entry. `Â[i][j]` absorbs `ρ ‖ j ‖ i` (or `ρ ‖ i ‖ j`
/// when transposed), matching the FIPS 203 / pq-crystals ordering.
///
/// On x86_64 with AVX2 the K² independent streams are squeezed four at a
/// time by the 4-way Keccak kernel (byte-identical output); the seed and the
/// rejection-sampling control flow are public (`ρ` is serialized into `ek`).
fn gen_matrix<const K: usize>(seed: &[u8; 32], transposed: bool) -> [[Poly; K]; K] {
    let mut a = [[Poly::zero(); K]; K];
    let mut done = 0;

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    if crate::hash::keccak_x4::supported() {
        use crate::hash::keccak_x4::{KeccakX4, LANES, MAX_RATE};
        while done + LANES <= K * K {
            let mut msgs = [[0u8; 34]; LANES];
            for (l, msg) in msgs.iter_mut().enumerate() {
                let (i, j) = ((done + l) / K, (done + l) % K);
                msg[..32].copy_from_slice(seed);
                let (x, y) = if transposed {
                    (i as u8, j as u8)
                } else {
                    (j as u8, i as u8)
                };
                msg[32] = x;
                msg[33] = y;
            }
            let msgs_ref: [&[u8]; LANES] = core::array::from_fn(|l| &msgs[l][..]);
            let mut x4 = KeccakX4::new(XOF_BLOCK, msgs_ref, 0x1F);
            let mut blocks = [[0u8; MAX_RATE]; LANES];
            let mut ctrs = [0usize; LANES];
            while ctrs.iter().any(|&c| c < N) {
                x4.squeeze_blocks(&mut blocks);
                for (l, ctr) in ctrs.iter_mut().enumerate() {
                    if *ctr < N {
                        let (i, j) = ((done + l) / K, (done + l) % K);
                        *ctr += poly::rej_uniform(&mut a[i][j].c[*ctr..], &blocks[l][..XOF_BLOCK]);
                    }
                }
            }
            done += LANES;
        }
    }

    // Scalar path: all entries when the 4-way kernel is unavailable, or the
    // `K² mod 4` remainder after the batched groups.
    while done < K * K {
        let (i, j) = (done / K, done % K);
        let (x, y) = if transposed {
            (i as u8, j as u8)
        } else {
            (j as u8, i as u8)
        };
        gen_matrix_entry(seed, x, y, &mut a[i][j]);
        done += 1;
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

/// Four [`getnoise`] PRF streams squeezed in parallel by the 4-way AVX2
/// Keccak kernel: `PRF_η(seed, nonces[l])` then `SamplePolyCBD_η` per lane.
/// Byte-identical to four scalar calls. The kernel is branch-free in the
/// state, so the secret seed sees the same bitwise-only pipeline as the
/// scalar sponge; all buffers holding key-derived bytes are wiped.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn getnoise_x4<const ETA: usize>(seed: &[u8; 32], nonces: [u8; 4]) -> [Poly; 4] {
    use crate::hash::keccak_x4::{KeccakX4, LANES, MAX_RATE};
    /// The SHAKE256 rate.
    const RATE: usize = 136;
    let need = 64 * ETA;
    debug_assert!(need <= 2 * RATE);

    let mut msgs = [[0u8; 33]; LANES];
    for (l, msg) in msgs.iter_mut().enumerate() {
        msg[..32].copy_from_slice(seed);
        msg[32] = nonces[l];
    }
    let msgs_ref: [&[u8]; LANES] = core::array::from_fn(|l| &msgs[l][..]);
    let mut x4 = KeccakX4::new(RATE, msgs_ref, 0x1F);

    let mut bufs = [[0u8; 2 * RATE]; LANES];
    let mut blocks = [[0u8; MAX_RATE]; LANES];
    let mut off = 0;
    while off < need {
        x4.squeeze_blocks(&mut blocks);
        let take = RATE.min(need - off);
        for (buf, block) in bufs.iter_mut().zip(blocks.iter()) {
            buf[off..off + take].copy_from_slice(&block[..take]);
        }
        off += RATE;
    }
    let out = core::array::from_fn(|l| poly::cbd::<ETA>(&bufs[l][..need]));

    // Wipe everything derived from the secret noise seed: the PRF inputs,
    // the sponge states, and the raw CBD bit buffers.
    x4.zeroize();
    for b in msgs
        .iter_mut()
        .flatten()
        .chain(bufs.iter_mut().flatten())
        .chain(blocks.iter_mut().flatten())
    {
        *b = 0;
    }
    let _ = core::hint::black_box((&msgs, &bufs, &blocks));
    out
}

/// Fills `out[i]` with the CBD noise polynomial `PRF_η(seed, base + i)`,
/// batching four PRF streams at a time through the 4-way Keccak kernel when
/// available (scalar remainder). Byte-identical to per-index [`getnoise`].
fn fill_noise<const ETA: usize>(seed: &[u8; 32], base: u8, out: &mut [Poly]) {
    let mut idx = 0;

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    if crate::hash::keccak_x4::supported() {
        while idx + 4 <= out.len() {
            let nonces = core::array::from_fn(|l| base + (idx + l) as u8);
            let polys = getnoise_x4::<ETA>(seed, nonces);
            out[idx..idx + 4].copy_from_slice(&polys);
            idx += 4;
        }
    }

    while idx < out.len() {
        out[idx] = getnoise::<ETA>(seed, base + idx as u8);
        idx += 1;
    }
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

    // s ‖ e is one run of 2K nonce-indexed PRF_η₁ streams; sampling them
    // through a single flat slice lets `fill_noise` batch across the s/e
    // boundary (e.g. one 4-way group for K = 2, one plus two scalar for K = 3).
    let mut se = [[Poly::zero(); K]; 2];
    fill_noise::<ETA1>(&sigma32, 0, se.as_flattened_mut());
    let [mut s, mut e] = se;
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

    // r̂ uses PRF_η₁ (nonces 0..K); e₁ ‖ e₂ is one run of K+1 PRF_η₂ streams
    // (nonces K..2K+1), sampled through a flat slice so `fill_noise` can
    // batch across the e₁/e₂ boundary (a full 4-way group for K = 3).
    let mut sp: [Poly; K] = [Poly::zero(); K];
    fill_noise::<ETA1>(coins, 0, &mut sp);
    let mut ep_epp = [[Poly::zero(); K]; 2];
    fill_noise::<ETA2>(coins, K as u8, &mut ep_epp.as_flattened_mut()[..K + 1]);
    let ep = ep_epp[0];
    let epp = ep_epp[1][0];

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

    /// The (possibly 4-way-batched) `gen_matrix` must be byte-identical to
    /// the per-entry scalar oracle.
    #[test]
    #[allow(clippy::needless_range_loop)]
    fn gen_matrix_matches_scalar_oracle() {
        let seed = [0xa7u8; 32];
        for transposed in [false, true] {
            let a = gen_matrix::<K_TEST>(&seed, transposed);
            for i in 0..K_TEST {
                for j in 0..K_TEST {
                    let (x, y) = if transposed {
                        (i as u8, j as u8)
                    } else {
                        (j as u8, i as u8)
                    };
                    let mut expect = Poly::zero();
                    gen_matrix_entry(&seed, x, y, &mut expect);
                    assert_eq!(a[i][j].c, expect.c, "entry ({i},{j}) t={transposed}");
                }
            }
        }
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
