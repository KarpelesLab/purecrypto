//! Rejection / expansion sampling from SHAKE (FIPS 204 §7.1, §7.3).
//!
//! SHAKE is a byte stream, so reading it in fixed chunks (as the reference does)
//! is equivalent to reading exactly the bytes consumed; the matrix XOF rate of
//! 168 is a multiple of 3, so no triple straddles a block.

use super::encode::{unpack_z17, unpack_z19};
use super::field::{N, Poly, Q, sub};
use crate::hash::{ExtendableOutput, Shake128, Shake256, XofReader};

/// The SHAKE128 rate — the matrix-XOF squeeze block (a multiple of 3).
const NTT_XOF_BLOCK: usize = 168;

/// Consumes the 3-byte groups of one XOF `block`, rejection-filling `a.c[j..]`
/// with coefficients `< Q`; returns the updated fill count.
fn rej_ntt_block(a: &mut Poly, mut j: usize, block: &[u8]) -> usize {
    for chunk in block.chunks_exact(3) {
        if j == N {
            break;
        }
        let d = chunk[0] as u32 | (chunk[1] as u32) << 8 | ((chunk[2] as u32 & 0x7f) << 16);
        if d < Q {
            a.c[j] = d;
            j += 1;
        }
    }
    j
}

/// RejNTTPoly (Algorithm 30): a uniform NTT-domain polynomial from
/// `SHAKE128(rho ‖ s ‖ r)`, squeezed a full rate block at a time.
pub(crate) fn sample_ntt_poly(rho: &[u8], s: u8, r: u8) -> Poly {
    let mut xof = Shake128::new();
    xof.update(rho);
    xof.update(&[s, r]);
    let mut reader = xof.finalize_xof();

    let mut a = Poly::zero();
    let mut j = 0;
    let mut block = [0u8; NTT_XOF_BLOCK];
    while j < N {
        reader.read(&mut block);
        j = rej_ntt_block(&mut a, j, &block);
    }
    a
}

/// Four [`sample_ntt_poly`] streams squeezed in parallel by the 4-way AVX2
/// Keccak kernel. `rho` must be the 32-byte public seed; `sr[l]` is the
/// `(s, r)` index pair of stream `l`. Byte-identical to the scalar sampler
/// (pinned by a differential test); all inputs and the rejection control
/// flow are public.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
pub(crate) fn sample_ntt_x4(rho: &[u8], sr: [(u8, u8); 4]) -> [Poly; 4] {
    use crate::hash::keccak_x4::{KeccakX4, LANES, MAX_RATE};
    debug_assert_eq!(rho.len(), 32);
    let mut msgs = [[0u8; 34]; LANES];
    for (l, msg) in msgs.iter_mut().enumerate() {
        msg[..32].copy_from_slice(rho);
        msg[32] = sr[l].0;
        msg[33] = sr[l].1;
    }
    let msgs_ref: [&[u8]; LANES] = core::array::from_fn(|l| &msgs[l][..]);
    let mut x4 = KeccakX4::new(NTT_XOF_BLOCK, msgs_ref, 0x1F);
    let mut blocks = [[0u8; MAX_RATE]; LANES];
    let mut a = [Poly::zero(); LANES];
    let mut fill = [0usize; LANES];
    while fill.iter().any(|&j| j < N) {
        x4.squeeze_blocks(&mut blocks);
        for (l, j) in fill.iter_mut().enumerate() {
            if *j < N {
                *j = rej_ntt_block(&mut a[l], *j, &blocks[l][..NTT_XOF_BLOCK]);
            }
        }
    }
    a
}

/// RejBoundedPoly (Algorithm 31): coefficients in `[−η, η]` from
/// `SHAKE256(seed ‖ nonce)`.
pub(crate) fn sample_bounded_poly(seed: &[u8], eta: u32, nonce: u16) -> Poly {
    let mut xof = Shake256::new();
    xof.update(seed);
    xof.update(&[nonce as u8, (nonce >> 8) as u8]);
    let mut reader = xof.finalize_xof();

    let mut a = Poly::zero();
    let mut j = 0;
    // Squeeze full SHAKE256 rate blocks (136 bytes) rather than a byte at a
    // time; the byte stream (and thus the sampled polynomial) is unchanged,
    // any unused tail of the final block is simply discarded.
    let mut block = [0u8; 136];
    'outer: while j < N {
        reader.read(&mut block);
        for &byte in block.iter() {
            let z0 = byte & 0x0f;
            let z1 = byte >> 4;
            if eta == 2 {
                if z0 < 15 {
                    a.c[j] = sub(2, (z0 % 5) as u32);
                    j += 1;
                }
                if j < N && z1 < 15 {
                    a.c[j] = sub(2, (z1 % 5) as u32);
                    j += 1;
                }
            } else {
                if z0 <= 8 {
                    a.c[j] = sub(4, z0 as u32);
                    j += 1;
                }
                if j < N && z1 <= 8 {
                    a.c[j] = sub(4, z1 as u32);
                    j += 1;
                }
            }
            if j == N {
                break 'outer;
            }
        }
    }
    a
}

/// SampleInBall (Algorithm 29): a challenge with `tau` coefficients in `{−1, 1}`.
pub(crate) fn sample_challenge(seed: &[u8], tau: usize) -> Poly {
    let mut xof = Shake256::new();
    xof.update(seed);
    let mut reader = xof.finalize_xof();

    let mut head = [0u8; 8];
    reader.read(&mut head);
    let mut signs = u64::from_le_bytes(head);

    let mut c = Poly::zero();
    let mut byte = [0u8; 1];
    for i in (N - tau)..N {
        // Sample j uniformly in [0, i] by rejection.
        let jpos = loop {
            reader.read(&mut byte);
            if byte[0] as usize <= i {
                break byte[0] as usize;
            }
        };
        c.c[i] = c.c[jpos];
        c.c[jpos] = if signs & 1 == 0 { 1 } else { Q - 1 };
        signs >>= 1;
    }
    c
}

/// ExpandMask (Algorithm 34): the masking vector polynomial from
/// `SHAKE256(seed)`, with `gamma1_bits` of 17 or 19.
pub(crate) fn expand_mask(seed: &[u8], gamma1_bits: u32) -> Poly {
    let mut xof = Shake256::new();
    xof.update(seed);
    let mut reader = xof.finalize_xof();
    if gamma1_bits == 17 {
        let mut buf = [0u8; N * 18 / 8];
        reader.read(&mut buf);
        unpack_z17(&buf)
    } else {
        let mut buf = [0u8; N * 20 / 8];
        reader.read(&mut buf);
        unpack_z19(&buf)
    }
}

/// ExpandMask for a whole masking vector: `y[i] = ExpandMask(seed_buf[..64] ‖
/// LE16(kappa + i))`, batching full groups of four SHAKE256 streams through
/// the 4-way Keccak kernel when available (scalar remainder, as in the ML-KEM
/// noise sampler). Byte-identical to the scalar per-index
/// [`expand_mask`] loop. `seed_buf` holds `rho''` in its first 64 bytes; its
/// two nonce bytes are scratch (the scalar fallback writes them).
pub(crate) fn expand_mask_vec(
    y: &mut [Poly],
    seed_buf: &mut [u8; 66],
    kappa: u16,
    gamma1_bits: u32,
) {
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    let done = if crate::hash::keccak_x4::supported() {
        let mut i = 0;
        while y.len() - i >= 4 {
            let nonces: [u16; 4] = core::array::from_fn(|l| kappa.wrapping_add((i + l) as u16));
            let mut polys = expand_mask_x4(&seed_buf[..64], nonces, gamma1_bits);
            y[i..i + 4].copy_from_slice(&polys);
            // The mask vector is secret; the local candidate array must not
            // linger on the stack.
            super::wipe_polys(&mut polys);
            i += 4;
        }
        i
    } else {
        0
    };
    #[cfg(not(all(feature = "std", target_arch = "x86_64")))]
    let done = 0;
    for (j, yi) in y.iter_mut().enumerate().skip(done) {
        let nu = kappa.wrapping_add(j as u16);
        seed_buf[64] = nu as u8;
        seed_buf[65] = (nu >> 8) as u8;
        *yi = expand_mask(seed_buf, gamma1_bits);
    }
}

/// Four [`expand_mask`] streams squeezed in parallel by the 4-way AVX2 Keccak
/// kernel: single-block absorb of `rho''(64) ‖ LE16(nonce)`, then 5 rate
/// blocks squeezed per stream. The output is the SECRET mask vector y — the
/// kernel is branch-free in the state, and every intermediate buffer holding
/// seed or squeezed bytes is wiped before returning (the [`super`] caller
/// wipes the returned polynomials).
#[cfg(all(feature = "std", target_arch = "x86_64"))]
fn expand_mask_x4(rho_prime: &[u8], nonces: [u16; 4], gamma1_bits: u32) -> [Poly; 4] {
    use crate::hash::keccak_x4::{KeccakX4, LANES, MAX_RATE};
    /// The SHAKE256 rate.
    const RATE: usize = 136;
    debug_assert_eq!(rho_prime.len(), 64);
    let need = if gamma1_bits == 17 {
        N * 18 / 8
    } else {
        N * 20 / 8
    };
    debug_assert!(need <= 5 * RATE);

    let mut msgs = [[0u8; 66]; LANES];
    for (l, msg) in msgs.iter_mut().enumerate() {
        msg[..64].copy_from_slice(rho_prime);
        msg[64] = nonces[l] as u8;
        msg[65] = (nonces[l] >> 8) as u8;
    }
    let msgs_ref: [&[u8]; LANES] = core::array::from_fn(|l| &msgs[l][..]);
    let mut x4 = KeccakX4::new(RATE, msgs_ref, 0x1F);

    let mut bufs = [[0u8; 5 * RATE]; LANES];
    let mut blocks = [[0u8; MAX_RATE]; LANES];
    let mut off = 0;
    while off < need {
        x4.squeeze_blocks(&mut blocks);
        let take = RATE.min(need - off);
        for (buf, block) in bufs.iter_mut().zip(blocks.iter()) {
            buf[off..off + take].copy_from_slice(&block[..take]);
        }
        off += take;
    }
    let out = core::array::from_fn(|l| {
        if gamma1_bits == 17 {
            unpack_z17(&bufs[l][..need])
        } else {
            unpack_z19(&bufs[l][..need])
        }
    });

    // Wipe everything derived from the secret rho'': the XOF inputs, the
    // sponge states, and the raw packed-mask buffers.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The 4-way batched NTT sampler must be byte-identical to the scalar
    /// one for every stream.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn sample_ntt_x4_matches_scalar() {
        if !crate::hash::keccak_x4::supported() {
            return;
        }
        let rho: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(0x33));
        let sr = [(0u8, 0u8), (4, 1), (2, 7), (255, 3)];
        let batched = sample_ntt_x4(&rho, sr);
        for (l, &(s, r)) in sr.iter().enumerate() {
            let expect = sample_ntt_poly(&rho, s, r);
            assert_eq!(batched[l].c, expect.c, "stream {l} (s={s}, r={r})");
        }
    }

    /// The batched mask expansion must be byte-identical to the scalar
    /// per-index sampler, for every vector length L and both gamma1 widths
    /// (including the duplicated remainder lanes for L = 5 and 7).
    #[test]
    fn expand_mask_vec_matches_scalar() {
        let mut seed_buf = [0u8; 66];
        for (i, b) in seed_buf[..64].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(0x5b).wrapping_add(3);
        }
        for gamma1_bits in [17u32, 19] {
            for len in [4usize, 5, 7] {
                let kappa = 0xfffd; // exercises the wrapping nonce
                let mut y = alloc::vec![Poly::zero(); len];
                let mut sb = seed_buf;
                expand_mask_vec(&mut y, &mut sb, kappa, gamma1_bits);
                for (i, yi) in y.iter().enumerate() {
                    let nu = kappa.wrapping_add(i as u16);
                    let mut sb2 = seed_buf;
                    sb2[64] = nu as u8;
                    sb2[65] = (nu >> 8) as u8;
                    let expect = expand_mask(&sb2, gamma1_bits);
                    assert_eq!(yi.c, expect.c, "gamma1_bits {gamma1_bits} len {len} i {i}");
                }
            }
        }
    }
}
