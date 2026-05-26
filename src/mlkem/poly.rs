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

/// Centered binomial sampling with η = 2 from a 128-byte PRF block.
pub(crate) fn cbd2(buf: &[u8; 128]) -> Poly {
    let mut p = Poly::zero();
    for i in 0..N / 8 {
        let t = u32::from_le_bytes([buf[4 * i], buf[4 * i + 1], buf[4 * i + 2], buf[4 * i + 3]]);
        let d = (t & 0x5555_5555) + ((t >> 1) & 0x5555_5555);
        for j in 0..8 {
            let a = ((d >> (4 * j)) & 0x3) as i16;
            let b = ((d >> (4 * j + 2)) & 0x3) as i16;
            p.c[8 * i + j] = a - b;
        }
    }
    p
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

/// `ByteEncode₁₀(Compress₁₀(p))`: 320 bytes per polynomial (`d_u = 10`).
pub(crate) fn compress10(p: &Poly) -> [u8; 320] {
    let mut r = [0u8; 320];
    let mut o = 0;
    for i in 0..N / 4 {
        let mut t = [0u16; 4];
        for (k, tk) in t.iter_mut().enumerate() {
            let x = freeze(p.c[4 * i + k]) as u32;
            *tk = ((((x << 10) + (Q as u32 / 2)) / Q as u32) & 0x3ff) as u16;
        }
        r[o] = t[0] as u8;
        r[o + 1] = ((t[0] >> 8) | (t[1] << 2)) as u8;
        r[o + 2] = ((t[1] >> 6) | (t[2] << 4)) as u8;
        r[o + 3] = ((t[2] >> 4) | (t[3] << 6)) as u8;
        r[o + 4] = (t[3] >> 2) as u8;
        o += 5;
    }
    r
}

/// `Decompress₁₀(ByteDecode₁₀(c))`: inverse of [`compress10`].
pub(crate) fn decompress10(a: &[u8]) -> Poly {
    let mut p = Poly::zero();
    let mut o = 0;
    for i in 0..N / 4 {
        let b: [u32; 5] = [
            a[o] as u32,
            a[o + 1] as u32,
            a[o + 2] as u32,
            a[o + 3] as u32,
            a[o + 4] as u32,
        ];
        let t = [
            (b[0] | (b[1] << 8)) & 0x3ff,
            ((b[1] >> 2) | (b[2] << 6)) & 0x3ff,
            ((b[2] >> 4) | (b[3] << 4)) & 0x3ff,
            ((b[3] >> 6) | (b[4] << 2)) & 0x3ff,
        ];
        for (k, &tk) in t.iter().enumerate() {
            p.c[4 * i + k] = ((tk * Q as u32 + 512) >> 10) as i16;
        }
        o += 5;
    }
    p
}

/// `ByteEncode₄(Compress₄(p))`: 128 bytes per polynomial (`d_v = 4`).
pub(crate) fn compress4(p: &Poly) -> [u8; 128] {
    let mut r = [0u8; 128];
    for i in 0..N / 8 {
        let mut t = [0u8; 8];
        for (k, tk) in t.iter_mut().enumerate() {
            let x = freeze(p.c[8 * i + k]) as u32;
            *tk = (((((x << 4) + (Q as u32 / 2)) / Q as u32) & 0xf) as u8) & 0xf;
        }
        for j in 0..4 {
            r[4 * i + j] = t[2 * j] | (t[2 * j + 1] << 4);
        }
    }
    r
}

/// `Decompress₄(ByteDecode₄(c))`: inverse of [`compress4`].
pub(crate) fn decompress4(a: &[u8]) -> Poly {
    let mut p = Poly::zero();
    for (i, &b) in a.iter().take(N / 2).enumerate() {
        let byte = b as u32;
        p.c[2 * i] = (((byte & 0xf) * Q as u32 + 8) >> 4) as i16;
        p.c[2 * i + 1] = (((byte >> 4) * Q as u32 + 8) >> 4) as i16;
    }
    p
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
        // d_u = 10: error must be < q/2^10 ≈ 4.
        let r10 = decompress10(&compress10(&p));
        for i in 0..N {
            let diff = (r10.c[i] - p.c[i]).rem_euclid(Q);
            let d = diff.min(Q - diff);
            assert!(d <= 2, "du coeff {i} error {d}");
        }
        // d_v = 4: error must be < q/2^4 ≈ 104.
        let r4 = decompress4(&compress4(&p));
        for i in 0..N {
            let diff = (r4.c[i] - p.c[i]).rem_euclid(Q);
            let d = diff.min(Q - diff);
            assert!(d <= 120, "dv coeff {i} error {d}");
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
