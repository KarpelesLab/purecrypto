//! Rejection / expansion sampling from SHAKE (FIPS 204 §7.1, §7.3).
//!
//! SHAKE is a byte stream, so reading it in fixed chunks (as the reference does)
//! is equivalent to reading exactly the bytes consumed; the matrix XOF rate of
//! 168 is a multiple of 3, so no triple straddles a block.

use super::encode::{unpack_z17, unpack_z19};
use super::field::{N, Poly, Q, sub};
use crate::hash::{ExtendableOutput, Shake128, Shake256, XofReader};

/// RejNTTPoly (Algorithm 30): a uniform NTT-domain polynomial from
/// `SHAKE128(rho ‖ s ‖ r)`.
pub(crate) fn sample_ntt_poly(rho: &[u8], s: u8, r: u8) -> Poly {
    let mut xof = Shake128::new();
    xof.update(rho);
    xof.update(&[s, r]);
    let mut reader = xof.finalize_xof();

    let mut a = Poly::zero();
    let mut j = 0;
    let mut buf = [0u8; 3];
    while j < N {
        reader.read(&mut buf);
        let d = buf[0] as u32 | (buf[1] as u32) << 8 | ((buf[2] as u32 & 0x7f) << 16);
        if d < Q {
            a.c[j] = d;
            j += 1;
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
    let mut byte = [0u8; 1];
    while j < N {
        reader.read(&mut byte);
        let z0 = byte[0] & 0x0f;
        let z1 = byte[0] >> 4;
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
