//! Degree-255 polynomials over Z_q (q = 3329) — the arithmetic core of ML-KEM.
//!
//! Coefficients are held as signed `i16` (the pq-crystals layout): reductions
//! produce centered representatives and only the (de)serialization routines
//! force the canonical `[0, q)` range. Multiplication uses the Montgomery and
//! Barrett reductions and the length-256 negacyclic NTT. All routines are
//! branch-free in their coefficient data, so secret polynomials leak nothing
//! through timing.

/// The polynomial degree (number of coefficients).
pub(crate) const N: usize = 256;
/// The modulus `q`.
pub(crate) const Q: i16 = 3329;
const Q32: i32 = Q as i32;
/// `q⁻¹ mod 2¹⁶`.
const QINV: i32 = 62209;

/// Montgomery NTT twiddle factors (`ζ^brv(i)·2¹⁶ mod q`, centered).
const ZETAS: [i16; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202, -1474, 1468,
    573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608, -1542, 411, -205, -1571,
    1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8, -320, -666, -1618, -1162, 126, 1469,
    -853, -90, -271, 830, 107, -1421, -247, -951, -398, 961, -1508, -725, 448, -1065, 677, -1275,
    -1103, 430, 555, 843, -1251, 871, 1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246,
    778, 1159, -147, -777, 1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097,
    603, 610, 1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522, 1628,
];

/// Montgomery reduction: returns `a·2⁻¹⁶ mod q` in `(-q, q)`.
#[inline]
fn montgomery_reduce(a: i32) -> i16 {
    let t = a.wrapping_mul(QINV) as i16 as i32;
    ((a - t * Q32) >> 16) as i16
}

/// Barrett reduction: returns a representative of `a mod q` in `(-q/2, q/2]`.
#[inline]
fn barrett_reduce(a: i16) -> i16 {
    const V: i32 = 20159; // ((1<<26) + q/2) / q
    let t = ((V * a as i32 + (1 << 25)) >> 26) * Q32;
    (a as i32 - t) as i16
}

/// Montgomery multiplication of two field elements.
#[inline]
fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce(a as i32 * b as i32)
}

/// A polynomial: 256 coefficients in Z_q.
#[derive(Clone, Copy)]
pub(crate) struct Poly {
    pub(crate) c: [i16; N],
}

impl Poly {
    /// The zero polynomial.
    pub(crate) fn zero() -> Self {
        Poly { c: [0; N] }
    }

    /// `self += other`.
    pub(crate) fn add(&mut self, other: &Poly) {
        for i in 0..N {
            self.c[i] += other.c[i];
        }
    }

    /// `self = a - b`.
    pub(crate) fn sub(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N {
            self.c[i] = a.c[i] - b.c[i];
        }
    }

    /// Barrett-reduces every coefficient toward the centered range.
    pub(crate) fn reduce(&mut self) {
        for i in 0..N {
            self.c[i] = barrett_reduce(self.c[i]);
        }
    }

    /// Converts each coefficient into the Montgomery domain (`·2¹⁶ mod q`),
    /// in place (mirrors pq-crystals' `poly_tomont`).
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn to_mont(&mut self) {
        const F: i16 = 1353; // 2³² mod q
        for i in 0..N {
            self.c[i] = montgomery_reduce(self.c[i] as i32 * F as i32);
        }
    }

    /// In-place forward NTT, leaving coefficients Barrett-reduced (matching
    /// pq-crystals' `poly_ntt`, so the result is safe to serialize).
    pub(crate) fn ntt(&mut self) {
        let r = &mut self.c;
        let mut k = 1;
        let mut len = 128;
        while len >= 2 {
            let mut start = 0;
            while start < 256 {
                let zeta = ZETAS[k];
                k += 1;
                let mut j = start;
                while j < start + len {
                    let t = fqmul(zeta, r[j + len]);
                    r[j + len] = r[j] - t;
                    r[j] += t;
                    j += 1;
                }
                start = j + len;
            }
            len >>= 1;
        }
        self.reduce();
    }

    /// In-place inverse NTT (output left in the Montgomery domain).
    pub(crate) fn inv_ntt(&mut self) {
        const F: i16 = 1441; // mont² / 128
        let r = &mut self.c;
        let mut k = 127;
        let mut len = 2;
        while len <= 128 {
            let mut start = 0;
            while start < 256 {
                let zeta = ZETAS[k];
                k -= 1;
                let mut j = start;
                while j < start + len {
                    let t = r[j];
                    r[j] = barrett_reduce(t + r[j + len]);
                    r[j + len] -= t;
                    r[j + len] = fqmul(zeta, r[j + len]);
                    j += 1;
                }
                start = j + len;
            }
            len <<= 1;
        }
        for x in r.iter_mut() {
            *x = fqmul(*x, F);
        }
    }
}

/// The NTT base-case multiply on a degree-1 polynomial pair modulo `X²−ζ`.
#[inline]
fn basemul(r: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    r[0] = fqmul(fqmul(a[1], b[1]), zeta) + fqmul(a[0], b[0]);
    r[1] = fqmul(a[0], b[1]) + fqmul(a[1], b[0]);
}

/// Pointwise product in the NTT domain: `r = a ∘ b`.
pub(crate) fn poly_basemul(a: &Poly, b: &Poly) -> Poly {
    let mut r = Poly::zero();
    for i in 0..N / 4 {
        let z = ZETAS[64 + i];
        basemul(&mut r.c[4 * i..], &a.c[4 * i..], &b.c[4 * i..], z);
        basemul(&mut r.c[4 * i + 2..], &a.c[4 * i + 2..], &b.c[4 * i + 2..], -z);
    }
    r
}

/// Centered binomial sampling with parameter η, consuming `64·ETA` bytes of
/// PRF output. Each coefficient is `popcount(a) − popcount(b)` over two
/// adjacent η-bit groups, so the result lies in `[-ETA, ETA]`.
///
/// Implemented branch-free in `ETA`: the loop bound and shift amounts are
/// `const`s, so monomorphization specializes the entire body per set.
/// Supported values: η ∈ {2, 3} (FIPS 203). Other ETA still works mechanically
/// up to ETA = 8 but is not exercised.
pub(crate) fn cbd<const ETA: usize>(buf: &[u8]) -> Poly {
    debug_assert_eq!(buf.len(), 64 * ETA);
    let mut p = Poly::zero();
    let mask: u32 = (1u32 << ETA) - 1;
    let group_bits = 2 * ETA;
    for k in 0..N {
        let bit_pos = k * group_bits;
        let byte_idx = bit_pos / 8;
        let bit_off = bit_pos & 7;
        // Read up to 24 bits, which is the most we ever need (η = 3 ⇒ 6
        // group bits; with an offset of 7 the span crosses two bytes; pad
        // to 3 bytes to keep the indexing uniform).
        let b0 = buf[byte_idx] as u32;
        let b1 = if byte_idx + 1 < buf.len() {
            buf[byte_idx + 1] as u32
        } else {
            0
        };
        let b2 = if byte_idx + 2 < buf.len() {
            buf[byte_idx + 2] as u32
        } else {
            0
        };
        let raw = b0 | (b1 << 8) | (b2 << 16);
        let chunk = (raw >> bit_off) & ((1u32 << group_bits) - 1);
        let a = (chunk & mask).count_ones() as i16;
        let b = ((chunk >> ETA) & mask).count_ones() as i16;
        p.c[k] = a - b;
    }
    p
}

/// Back-compat shim for the η = 2 case (kept for the existing tests; new
/// callers use `cbd::<ETA>` directly).
#[allow(dead_code)]
pub(crate) fn cbd2(buf: &[u8; 128]) -> Poly {
    cbd::<2>(buf)
}

/// Forces `x` into `[0, q)` (adds q when the sign bit is set).
#[inline]
fn freeze(x: i16) -> i16 {
    x + ((x >> 15) & Q)
}

/// `ByteEncode₁₂`: serializes a polynomial to 384 bytes (12 bits/coefficient).
pub(crate) fn to_bytes(p: &Poly) -> [u8; 384] {
    let mut r = [0u8; 384];
    for i in 0..N / 2 {
        let t0 = freeze(p.c[2 * i]) as u16;
        let t1 = freeze(p.c[2 * i + 1]) as u16;
        r[3 * i] = t0 as u8;
        r[3 * i + 1] = ((t0 >> 8) | (t1 << 4)) as u8;
        r[3 * i + 2] = (t1 >> 4) as u8;
    }
    r
}

/// `ByteDecode₁₂`: parses a 384-byte polynomial (12 bits/coefficient).
pub(crate) fn from_bytes(a: &[u8]) -> Poly {
    let mut p = Poly::zero();
    for i in 0..N / 2 {
        let b0 = a[3 * i] as u16;
        let b1 = a[3 * i + 1] as u16;
        let b2 = a[3 * i + 2] as u16;
        p.c[2 * i] = (b0 | (b1 << 8)) as i16 & 0xfff;
        p.c[2 * i + 1] = ((b1 >> 4) | (b2 << 4)) as i16 & 0xfff;
    }
    p
}

/// `Decompress₁`: expands a 32-byte message to a polynomial (0 or ⌈q/2⌋).
pub(crate) fn from_msg(msg: &[u8; 32]) -> Poly {
    let mut p = Poly::zero();
    for (i, &byte) in msg.iter().enumerate() {
        for j in 0..8 {
            let mask = 0i16.wrapping_sub(((byte >> j) & 1) as i16);
            p.c[8 * i + j] = mask & ((Q + 1) / 2);
        }
    }
    p
}

/// `Compress₁`: extracts the 32-byte message from a polynomial.
pub(crate) fn to_msg(p: &Poly) -> [u8; 32] {
    let mut msg = [0u8; 32];
    for (i, byte) in msg.iter_mut().enumerate() {
        for j in 0..8 {
            let t = freeze(p.c[8 * i + j]) as u32;
            let bit = (((t << 1) + (Q as u32 / 2)) / Q as u32) & 1;
            *byte |= (bit as u8) << j;
        }
    }
    msg
}

/// `ByteEncode_D(Compress_D(p))`: packs N coefficients into `N·D/8` bytes,
/// little-endian within the bitstream. Constant time over `p`'s coefficients.
/// Supported D: 4, 5, 10, 11 (all FIPS 203 values for `du` / `dv`).
pub(crate) fn compress<const D: usize>(p: &Poly, out: &mut [u8]) {
    debug_assert_eq!(out.len(), N * D / 8);
    for byte in out.iter_mut() {
        *byte = 0;
    }
    let mask: u32 = (1u32 << D) - 1;
    let mut bit_pos = 0usize;
    for i in 0..N {
        let x = freeze(p.c[i]) as u64;
        let v = (((x << D) + (Q as u64 / 2)) / Q as u64) as u32 & mask;
        let mut bits_left = D;
        let mut value = v;
        let mut byte_idx = bit_pos / 8;
        let mut shift = bit_pos & 7;
        while bits_left > 0 {
            let space = 8 - shift;
            let take = bits_left.min(space);
            let chunk = (value & ((1u32 << take) - 1)) as u8;
            out[byte_idx] |= chunk << shift;
            value >>= take;
            bits_left -= take;
            byte_idx += 1;
            shift = 0;
        }
        bit_pos += D;
    }
}

/// `Decompress_D(ByteDecode_D(c))`: inverse of [`compress`].
pub(crate) fn decompress<const D: usize>(input: &[u8], p: &mut Poly) {
    debug_assert_eq!(input.len(), N * D / 8);
    let mut bit_pos = 0usize;
    for i in 0..N {
        let mut value = 0u32;
        let mut bits_left = D;
        let mut byte_idx = bit_pos / 8;
        let mut shift = bit_pos & 7;
        let mut out_shift = 0;
        while bits_left > 0 {
            let space = 8 - shift;
            let take = bits_left.min(space);
            // Use u32 for the mask so `take == 8` doesn't trip a u8 shift overflow.
            let chunk = (input[byte_idx] as u32 >> shift) & ((1u32 << take) - 1);
            value |= chunk << out_shift;
            out_shift += take;
            bits_left -= take;
            byte_idx += 1;
            shift = 0;
        }
        p.c[i] = (((value as u64) * Q as u64 + (1u64 << (D - 1))) >> D) as i16;
        bit_pos += D;
    }
}

/// Rejection sampling of a polynomial in the NTT domain from XOF output
/// (`SampleNTT`). Returns the number of coefficients filled (≤ remaining).
pub(crate) fn rej_uniform(coeffs: &mut [i16], buf: &[u8]) -> usize {
    let mut ctr = 0;
    let mut pos = 0;
    while ctr < coeffs.len() && pos + 3 <= buf.len() {
        let val0 = (buf[pos] as u16 | ((buf[pos + 1] as u16) << 8)) & 0xfff;
        let val1 = ((buf[pos + 1] as u16 >> 4) | ((buf[pos + 2] as u16) << 4)) & 0xfff;
        pos += 3;
        if val0 < Q as u16 {
            coeffs[ctr] = val0 as i16;
            ctr += 1;
        }
        if ctr < coeffs.len() && val1 < Q as u16 {
            coeffs[ctr] = val1 as i16;
            ctr += 1;
        }
    }
    ctr
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Schoolbook multiply in Z_q[X]/(X²⁵⁶+1), result in [0, q).
    fn schoolbook(a: &Poly, b: &Poly) -> [i16; N] {
        let mut acc = [0i64; N];
        for i in 0..N {
            for j in 0..N {
                let prod = a.c[i] as i64 * b.c[j] as i64;
                if i + j < N {
                    acc[i + j] += prod;
                } else {
                    acc[i + j - N] -= prod; // X²⁵⁶ = −1
                }
            }
        }
        let mut r = [0i16; N];
        for k in 0..N {
            r[k] = acc[k].rem_euclid(Q as i64) as i16;
        }
        r
    }

    #[test]
    fn bytes_roundtrip() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.c[i] = (i % Q as usize) as i16;
        }
        let q = from_bytes(&to_bytes(&p));
        for i in 0..N {
            assert_eq!(freeze(p.c[i]), q.c[i], "coeff {i}");
        }
    }

    #[test]
    fn msg_roundtrip() {
        let mut msg = [0u8; 32];
        for (i, b) in msg.iter_mut().enumerate() {
            *b = (i * 9 + 1) as u8;
        }
        assert_eq!(to_msg(&from_msg(&msg)), msg);
    }

    #[test]
    fn cbd2_in_range() {
        let buf = [0xa5u8; 128];
        let p = cbd2(&buf);
        for &c in p.c.iter() {
            assert!((-2..=2).contains(&c), "cbd coeff {c} out of range");
        }
    }

    #[test]
    fn compress_roundtrip_is_close() {
        let mut p = Poly::zero();
        for i in 0..N {
            p.c[i] = (i % Q as usize) as i16;
        }
        // Validate each FIPS 203-used D against its expected error bound.
        let cases: &[(usize, i16)] = &[(4, 120), (5, 60), (10, 2), (11, 1)];
        for &(d, max_err) in cases {
            let mut buf = alloc::vec![0u8; N * d / 8];
            let mut r = Poly::zero();
            match d {
                4 => {
                    compress::<4>(&p, &mut buf);
                    decompress::<4>(&buf, &mut r);
                }
                5 => {
                    compress::<5>(&p, &mut buf);
                    decompress::<5>(&buf, &mut r);
                }
                10 => {
                    compress::<10>(&p, &mut buf);
                    decompress::<10>(&buf, &mut r);
                }
                11 => {
                    compress::<11>(&p, &mut buf);
                    decompress::<11>(&buf, &mut r);
                }
                _ => unreachable!(),
            }
            for i in 0..N {
                let diff = (r.c[i] - p.c[i]).rem_euclid(Q);
                let dist = diff.min(Q - diff);
                assert!(dist <= max_err, "D={d} coeff {i} err {dist}");
            }
        }
    }

    #[test]
    fn ntt_multiply_matches_schoolbook() {
        let mut a = Poly::zero();
        let mut b = Poly::zero();
        for i in 0..N {
            a.c[i] = ((i * 7 + 3) % Q as usize) as i16;
            b.c[i] = ((i * 5 + 1) % Q as usize) as i16;
        }
        let expected = schoolbook(&a, &b);

        let mut na = a;
        let mut nb = b;
        na.ntt();
        nb.ntt();
        let mut prod = poly_basemul(&na, &nb);
        prod.inv_ntt();

        for (k, &e) in expected.iter().enumerate() {
            assert_eq!(freeze(prod.c[k]), e, "coeff {k}");
        }
    }
}
