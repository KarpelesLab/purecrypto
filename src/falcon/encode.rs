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

/// Pack `n` signed coefficients at `w` bits each (two's complement, MSB first).
/// `n·w` is a multiple of 8 for the Falcon parameter sets, so the result is
/// byte-aligned.
fn pack_signed(coeffs: &[i64], w: u32) -> Vec<u8> {
    let mut bits: Vec<u8> = Vec::with_capacity(coeffs.len() * w as usize);
    for &c in coeffs {
        let u = c & ((1i64 << w) - 1);
        for k in (0..w).rev() {
            bits.push(((u >> k) & 1) as u8);
        }
    }
    let mut out = alloc::vec![0u8; bits.len() / 8];
    for (i, &b) in bits.iter().enumerate() {
        if b == 1 {
            out[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    out
}

/// Inverse of [`pack_signed`]: read `n` sign-extended `w`-bit coefficients.
fn unpack_signed(bytes: &[u8], n: usize, w: u32) -> Vec<i64> {
    let mut out = Vec::with_capacity(n);
    let mut pos = 0usize;
    for _ in 0..n {
        let mut v: i64 = 0;
        for _ in 0..w {
            let bit = (bytes[pos >> 3] >> (7 - (pos & 7))) & 1;
            v = (v << 1) | bit as i64;
            pos += 1;
        }
        // Sign-extend from w bits.
        if v & (1 << (w - 1)) != 0 {
            v -= 1 << w;
        }
        out.push(v);
    }
    out
}

/// Bit width for `f`/`g` coefficients in the compact secret key: 6 bits for
/// `n = 512`, 5 bits for `n = 1024` (spec §3.11.5).
pub(crate) fn fg_bits(n: usize) -> u32 {
    if n <= 512 { 6 } else { 5 }
}

/// Encode a secret key into the compact form: `0101nnnn` header, then `f` and
/// `g` at `fg_bits` each and `F` at 8 bits (`G` is recomputed on decode).
pub(crate) fn encode_privkey(f: &[i64], g: &[i64], cap_f: &[i64], logn: u8) -> Vec<u8> {
    let n = f.len();
    let w = fg_bits(n);
    let mut out = Vec::new();
    out.push(0x50 | logn);
    out.extend_from_slice(&pack_signed(f, w));
    out.extend_from_slice(&pack_signed(g, w));
    out.extend_from_slice(&pack_signed(cap_f, 8));
    out
}

/// Decode the compact secret key into `(f, g, F)`; returns `None` on a bad
/// header or length. `G` must be recomputed by the caller.
pub(crate) fn decode_privkey(bytes: &[u8], n: usize) -> Option<(Vec<i64>, Vec<i64>, Vec<i64>)> {
    let w = fg_bits(n);
    let fg_len = n * w as usize / 8;
    let f_len = 8 * n / 8; // F at 8 bits
    let expected = 1 + 2 * fg_len + f_len;
    if bytes.len() != expected {
        return None;
    }
    let body = &bytes[1..];
    let f = unpack_signed(&body[..fg_len], n, w);
    let g = unpack_signed(&body[fg_len..2 * fg_len], n, w);
    let cap_f = unpack_signed(&body[2 * fg_len..], n, 8);
    Some((f, g, cap_f))
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
