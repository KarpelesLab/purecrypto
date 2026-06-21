//! Signature compression and public-key packing (spec §3.11).
//!
//! [`compress`] is the exact inverse of the verifier's `decompress`
//! (`falcon/mod.rs`): per coefficient, 1 sign bit, 7 low bits (MSB first), then
//! the high bits in unary. [`encode_pubkey`] packs `h` at 14 bits/coefficient,
//! matching `FalconPublicKey::from_bytes`.

#![allow(dead_code)] // consumed by the sign / public-API phases

use alloc::vec::Vec;

/// Compress the signature polynomial `s` into exactly `slen` bytes, or `None`
/// if it does not fit (the caller resamples). Mirrors the reference `compress`.
pub(crate) fn compress(s: &[i16], slen: usize) -> Option<Vec<u8>> {
    let mut bits: Vec<u8> = Vec::with_capacity(s.len() * 9);
    for &coef in s {
        let c = coef as i32;
        bits.push((c < 0) as u8);
        let a = c.unsigned_abs();
        // 7 low bits, most-significant first.
        for k in (0..7).rev() {
            bits.push(((a >> k) & 1) as u8);
        }
        // High bits in unary: `a >> 7` zeros, then a terminating 1.
        bits.resize(bits.len() + (a >> 7) as usize, 0);
        bits.push(1);
    }
    if bits.len() > 8 * slen {
        return None; // too long
    }
    bits.resize(8 * slen, 0);
    let mut out = alloc::vec![0u8; slen];
    for (i, &b) in bits.iter().enumerate() {
        if b == 1 {
            out[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    Some(out)
}

/// Pack a public key `h` (each coefficient in `[0, q)`) into the encoded form:
/// a `0000nnnn` header byte followed by `⌈14n/8⌉` bytes of 14-bit big-endian
/// coefficients. Inverse of `FalconPublicKey::from_bytes`.
pub(crate) fn encode_pubkey(h: &[u16], logn: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + (14 * h.len()).div_ceil(8));
    out.push(logn); // top nibble zero
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;
    for &c in h {
        acc = (acc << 14) | (c as u32 & 0x3FFF);
        acc_bits += 14;
        while acc_bits >= 8 {
            acc_bits -= 8;
            out.push((acc >> acc_bits) as u8);
        }
    }
    if acc_bits > 0 {
        out.push((acc << (8 - acc_bits)) as u8);
    }
    out
}
