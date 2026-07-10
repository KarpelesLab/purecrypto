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
}
