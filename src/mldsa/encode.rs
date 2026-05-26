//! Bit-packing of polynomials and the hint (FIPS 204 §7.2–§7.3).
//!
//! Mirrors the reference byte layout exactly. Packers return `Vec<u8>`;
//! unpackers read borrowed slices. The `eta` and hint unpackers validate their
//! input and return an error on malformed encodings.

use super::field::{N, Poly, sub};
use alloc::vec;
use alloc::vec::Vec;

/// Reads 8 little-endian bytes as a `u64`.
#[inline]
fn le64(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[..8]);
    u64::from_le_bytes(a)
}

/// Packs `t1` with 10 bits per coefficient (320 bytes).
pub(crate) fn pack_t1(f: &Poly) -> Vec<u8> {
    let mut b = vec![0u8; N * 10 / 8];
    for i in (0..N).step_by(4) {
        let x = f.c[i] as u64
            | (f.c[i + 1] as u64) << 10
            | (f.c[i + 2] as u64) << 20
            | (f.c[i + 3] as u64) << 30;
        let o = i / 4 * 5;
        b[o..o + 5].copy_from_slice(&x.to_le_bytes()[..5]);
    }
    b
}

/// Unpacks `t1` (10 bits per coefficient).
pub(crate) fn unpack_t1(b: &[u8]) -> Poly {
    let mut f = Poly::zero();
    for i in (0..N).step_by(4) {
        let o = i / 4 * 5;
        let x = le64(&[&b[o..o + 5], &[0, 0, 0][..]].concat());
        f.c[i] = (x & 0x3ff) as u32;
        f.c[i + 1] = ((x >> 10) & 0x3ff) as u32;
        f.c[i + 2] = ((x >> 20) & 0x3ff) as u32;
        f.c[i + 3] = ((x >> 30) & 0x3ff) as u32;
    }
    f
}

/// Packs `t0` with 13 bits per signed coefficient (416 bytes).
pub(crate) fn pack_t0(f: &Poly) -> Vec<u8> {
    const CENTER: u32 = 1 << 12;
    let mut b = vec![0u8; N * 13 / 8];
    let mut idx = 0;
    for i in (0..N).step_by(8) {
        let mut x1 = sub(CENTER, f.c[i]) as u64;
        x1 |= (sub(CENTER, f.c[i + 1]) as u64) << 13;
        x1 |= (sub(CENTER, f.c[i + 2]) as u64) << 26;
        x1 |= (sub(CENTER, f.c[i + 3]) as u64) << 39;
        let a = sub(CENTER, f.c[i + 4]) as u64;
        x1 |= a << 52;
        let mut x2 = a >> 12;
        x2 |= (sub(CENTER, f.c[i + 5]) as u64) << 1;
        x2 |= (sub(CENTER, f.c[i + 6]) as u64) << 14;
        x2 |= (sub(CENTER, f.c[i + 7]) as u64) << 27;
        b[idx..idx + 8].copy_from_slice(&x1.to_le_bytes());
        b[idx + 8..idx + 13].copy_from_slice(&x2.to_le_bytes()[..5]);
        idx += 13;
    }
    b
}

/// Unpacks `t0` (13 bits per signed coefficient).
pub(crate) fn unpack_t0(b: &[u8]) -> Poly {
    const CENTER: u32 = 1 << 12;
    const MASK: u64 = (1 << 13) - 1;
    let mut f = Poly::zero();
    let mut o = 0;
    for i in (0..N).step_by(8) {
        let x1 = le64(&b[o..o + 8]);
        let x2 = le64(&[&b[o + 8..o + 13], &[0, 0, 0][..]].concat());
        o += 13;
        f.c[i] = sub(CENTER, (x1 & MASK) as u32);
        f.c[i + 1] = sub(CENTER, ((x1 >> 13) & MASK) as u32);
        f.c[i + 2] = sub(CENTER, ((x1 >> 26) & MASK) as u32);
        f.c[i + 3] = sub(CENTER, ((x1 >> 39) & MASK) as u32);
        f.c[i + 4] = sub(CENTER, (((x1 >> 52) | (x2 << 12)) & MASK) as u32);
        f.c[i + 5] = sub(CENTER, ((x2 >> 1) & MASK) as u32);
        f.c[i + 6] = sub(CENTER, ((x2 >> 14) & MASK) as u32);
        f.c[i + 7] = sub(CENTER, ((x2 >> 27) & MASK) as u32);
    }
    f
}

/// Packs a secret coefficient vector with `η = 2` (3 bits each, 96 bytes).
pub(crate) fn pack_eta2(f: &Poly) -> Vec<u8> {
    let mut b = vec![0u8; N * 3 / 8];
    for i in (0..N).step_by(8) {
        let mut x = 0u32;
        for j in 0..8 {
            x |= sub(2, f.c[i + j]) << (3 * j);
        }
        let o = i / 8 * 3;
        b[o..o + 3].copy_from_slice(&x.to_le_bytes()[..3]);
    }
    b
}

/// Unpacks an `η = 2` vector, validating each 3-bit group is ≤ 4.
pub(crate) fn unpack_eta2(b: &[u8]) -> Result<Poly, ()> {
    let mut f = Poly::zero();
    for i in (0..N).step_by(8) {
        let o = i / 8 * 3;
        let x = b[o] as u32 | (b[o + 1] as u32) << 8 | (b[o + 2] as u32) << 16;
        let msbs = x & 0o44444444;
        if ((msbs >> 1) | (msbs >> 2)) & x != 0 {
            return Err(());
        }
        for j in 0..8 {
            f.c[i + j] = sub(2, (x >> (3 * j)) & 0x7);
        }
    }
    Ok(f)
}

/// Packs a secret coefficient vector with `η = 4` (4 bits each, 128 bytes).
pub(crate) fn pack_eta4(f: &Poly) -> Vec<u8> {
    let mut b = vec![0u8; N * 4 / 8];
    for i in (0..N).step_by(2) {
        b[i / 2] = (sub(4, f.c[i]) | (sub(4, f.c[i + 1]) << 4)) as u8;
    }
    b
}

/// Unpacks an `η = 4` vector, validating each nibble is ≤ 8.
pub(crate) fn unpack_eta4(b: &[u8]) -> Result<Poly, ()> {
    let mut f = Poly::zero();
    for i in (0..N).step_by(8) {
        let o = i / 8 * 4;
        let x = b[o] as u32
            | (b[o + 1] as u32) << 8
            | (b[o + 2] as u32) << 16
            | (b[o + 3] as u32) << 24;
        let msbs = x & 0x8888_8888;
        if ((msbs >> 1) | (msbs >> 2) | (msbs >> 3)) & x != 0 {
            return Err(());
        }
        for j in 0..8 {
            f.c[i + j] = sub(4, (x >> (4 * j)) & 0xf);
        }
    }
    Ok(f)
}

/// Packs `z` with `γ₁ = 2¹⁷` (18 bits each, 576 bytes).
pub(crate) fn pack_z17(f: &Poly) -> Vec<u8> {
    const G: u32 = 1 << 17;
    let mut b = vec![0u8; N * 18 / 8];
    let mut idx = 0;
    for i in (0..N).step_by(4) {
        let mut x1 = sub(G, f.c[i]) as u64;
        x1 |= (sub(G, f.c[i + 1]) as u64) << 18;
        x1 |= (sub(G, f.c[i + 2]) as u64) << 36;
        let mut x2 = sub(G, f.c[i + 3]) as u64;
        x1 |= x2 << 54;
        x2 >>= 10;
        b[idx..idx + 8].copy_from_slice(&x1.to_le_bytes());
        b[idx + 8] = x2 as u8;
        idx += 9;
    }
    b
}

/// Packs `z` with `γ₁ = 2¹⁹` (20 bits each, 640 bytes).
pub(crate) fn pack_z19(f: &Poly) -> Vec<u8> {
    const G: u32 = 1 << 19;
    let mut b = vec![0u8; N * 20 / 8];
    let mut idx = 0;
    for i in (0..N).step_by(4) {
        let mut x1 = sub(G, f.c[i]) as u64;
        x1 |= (sub(G, f.c[i + 1]) as u64) << 20;
        x1 |= (sub(G, f.c[i + 2]) as u64) << 40;
        let mut x2 = sub(G, f.c[i + 3]) as u64;
        x1 |= x2 << 60;
        x2 >>= 4;
        b[idx..idx + 8].copy_from_slice(&x1.to_le_bytes());
        b[idx + 8..idx + 10].copy_from_slice(&(x2 as u16).to_le_bytes());
        idx += 10;
    }
    b
}

/// Unpacks `z` with `γ₁ = 2¹⁷` (18 bits each). Used for both `ExpandMask`
/// output and signature decode.
pub(crate) fn unpack_z17(b: &[u8]) -> Poly {
    const G: u32 = 1 << 17;
    const MASK: u64 = (1 << 18) - 1;
    let mut f = Poly::zero();
    let mut o = 0;
    for i in (0..N).step_by(4) {
        let x1 = le64(&b[o..o + 8]);
        let x2 = b[o + 8] as u64;
        o += 9;
        f.c[i] = sub(G, (x1 & MASK) as u32);
        f.c[i + 1] = sub(G, ((x1 >> 18) & MASK) as u32);
        f.c[i + 2] = sub(G, ((x1 >> 36) & MASK) as u32);
        f.c[i + 3] = sub(G, (((x1 >> 54) | (x2 << 10)) & MASK) as u32);
    }
    f
}

/// Unpacks `z` with `γ₁ = 2¹⁹` (20 bits each).
pub(crate) fn unpack_z19(b: &[u8]) -> Poly {
    const G: u32 = 1 << 19;
    const MASK: u64 = (1 << 20) - 1;
    let mut f = Poly::zero();
    let mut o = 0;
    for i in (0..N).step_by(4) {
        let x1 = le64(&b[o..o + 8]);
        let x2 = b[o + 8] as u64 | (b[o + 9] as u64) << 8;
        o += 10;
        f.c[i] = sub(G, (x1 & MASK) as u32);
        f.c[i + 1] = sub(G, ((x1 >> 20) & MASK) as u32);
        f.c[i + 2] = sub(G, ((x1 >> 40) & MASK) as u32);
        f.c[i + 3] = sub(G, (((x1 >> 60) | (x2 << 4)) & MASK) as u32);
    }
    f
}

/// Packs `w1` with 4 bits per coefficient (ML-DSA-65/87, 128 bytes).
pub(crate) fn pack_w1_4(f: &Poly) -> Vec<u8> {
    let mut b = vec![0u8; N * 4 / 8];
    for i in (0..N).step_by(2) {
        b[i / 2] = (f.c[i] | (f.c[i + 1] << 4)) as u8;
    }
    b
}

/// Packs `w1` with 6 bits per coefficient (ML-DSA-44, 192 bytes).
pub(crate) fn pack_w1_6(f: &Poly) -> Vec<u8> {
    let mut b = vec![0u8; N * 6 / 8];
    for i in (0..N).step_by(4) {
        let x = f.c[i] | (f.c[i + 1] << 6) | (f.c[i + 2] << 12) | (f.c[i + 3] << 18);
        let o = i / 4 * 3;
        b[o..o + 3].copy_from_slice(&x.to_le_bytes()[..3]);
    }
    b
}

/// Packs the hint: positions of set bits per polynomial, then the running
/// counts (`omega + k` bytes).
pub(crate) fn pack_hint(hints: &[Poly], omega: usize) -> Vec<u8> {
    let k = hints.len();
    let mut b = vec![0u8; omega + k];
    let mut idx = 0;
    for (i, h) in hints.iter().enumerate() {
        for (j, &c) in h.c.iter().enumerate() {
            if c != 0 {
                b[idx] = j as u8;
                idx += 1;
            }
        }
        b[omega + i] = idx as u8;
    }
    b
}

/// Unpacks the hint into `hints`, rejecting malformed encodings (non-increasing
/// positions, out-of-range counts, or non-zero padding).
pub(crate) fn unpack_hint(b: &[u8], hints: &mut [Poly], omega: usize) -> bool {
    let k = hints.len();
    let mut idx = 0usize;
    for i in 0..k {
        let limit = b[omega + i] as usize;
        if limit < idx || limit > omega {
            return false;
        }
        let prev = idx;
        while idx < limit {
            let pos = b[idx];
            if idx > prev && b[idx - 1] >= pos {
                return false;
            }
            hints[i].c[pos as usize] = 1;
            idx += 1;
        }
    }
    for &x in &b[idx..omega] {
        if x != 0 {
            return false;
        }
    }
    true
}
