//! Constant-time GF(2⁸) arithmetic and the AES S-box.
//!
//! The AES field is GF(2⁸) with reduction polynomial
//! `x⁸ + x⁴ + x³ + x + 1` (`0x11b`). The S-box is computed as the
//! multiplicative inverse followed by an affine transform — **without any
//! lookup table** — so every operation runs in time independent of its
//! (secret) input.

/// Multiplies two field elements in constant time (branchless Russian-peasant
/// multiplication with reduction by `0x11b`).
#[inline]
pub(crate) fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0u8;
    let mut i = 0;
    while i < 8 {
        // Add `a` into the product when the low bit of `b` is set.
        let bit = 0u8.wrapping_sub(b & 1); // 0x00 or 0xff
        product ^= bit & a;
        // a = xtime(a): multiply by x, reducing mod 0x11b on carry-out.
        let carry = 0u8.wrapping_sub(a >> 7); // 0x00 or 0xff
        a = (a << 1) ^ (carry & 0x1b);
        b >>= 1;
        i += 1;
    }
    product
}

/// Multiplicative inverse in GF(2⁸), with `inverse(0) = 0` (matching the AES
/// S-box convention).
///
/// Computed as `x²⁵⁴`; since `x²⁵⁵ = 1` for every nonzero `x`, this equals
/// `x⁻¹`. The fixed addition chain runs in constant time.
#[inline]
pub(crate) fn gf_inv(x: u8) -> u8 {
    let x2 = gf_mul(x, x); // x^2
    let x4 = gf_mul(x2, x2); // x^4
    let x8 = gf_mul(x4, x4); // x^8
    let x16 = gf_mul(x8, x8); // x^16
    let x32 = gf_mul(x16, x16); // x^32
    let x64 = gf_mul(x32, x32); // x^64
    let x128 = gf_mul(x64, x64); // x^128

    // x^254 = x^2 · x^4 · x^8 · x^16 · x^32 · x^64 · x^128
    let mut r = x2;
    r = gf_mul(r, x4);
    r = gf_mul(r, x8);
    r = gf_mul(r, x16);
    r = gf_mul(r, x32);
    r = gf_mul(r, x64);
    gf_mul(r, x128)
}

/// AES S-box: multiplicative inverse, then the forward affine transform.
#[inline]
pub(crate) fn sub_byte(x: u8) -> u8 {
    let inv = gf_inv(x);
    inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63
}

/// AES inverse S-box: inverse affine transform, then the multiplicative
/// inverse.
#[inline]
pub(crate) fn inv_sub_byte(x: u8) -> u8 {
    let t = x.rotate_left(1) ^ x.rotate_left(3) ^ x.rotate_left(6) ^ 0x05;
    gf_inv(t)
}

// --- Bitsliced S-box ---------------------------------------------------------
//
// The scalar `gf_inv` above costs 13 field multiplications of 8 masked steps
// each, per byte. The AES rounds instead evaluate the S-box on a whole state
// at once: the bytes are transposed into eight bit-planes (`q[i]` holds bit
// `i` of every byte), the Boyar–Peralta 113-gate circuit runs on the planes
// with plain AND/XOR/NOT, and the planes are transposed back. Every step is a
// fixed sequence of word operations: no table, no secret-dependent branch or
// index.

/// Transposes the 8×8 bit matrix held in `x` (byte `j` bit `i` ↔ byte `i`
/// bit `j`), Hacker's Delight §7-3. An involution.
#[inline(always)]
fn transpose8(mut x: u64) -> u64 {
    let t = (x ^ (x >> 7)) & 0x00aa_00aa_00aa_00aa;
    x ^= t ^ (t << 7);
    let t = (x ^ (x >> 14)) & 0x0000_cccc_0000_cccc;
    x ^= t ^ (t << 14);
    let t = (x ^ (x >> 28)) & 0x0000_0000_f0f0_f0f0;
    x ^= t ^ (t << 28);
    x
}

/// Splits four little-endian words (32 bytes) into bit-planes: bit
/// `8w + j` of `q[i]` is bit `i` of byte `j` of word `w`.
#[inline(always)]
fn to_planes(words: &[u64; 4]) -> [u32; 8] {
    let mut q = [0u32; 8];
    for (w, &x) in words.iter().enumerate() {
        let t = transpose8(x);
        for (i, p) in q.iter_mut().enumerate() {
            *p |= ((t >> (8 * i)) as u8 as u32) << (8 * w);
        }
    }
    q
}

/// Inverse of [`to_planes`].
#[inline(always)]
fn from_planes(q: &[u32; 8], words: &mut [u64; 4]) {
    for (w, x) in words.iter_mut().enumerate() {
        let mut t = 0u64;
        for (i, &p) in q.iter().enumerate() {
            t |= ((p >> (8 * w)) as u8 as u64) << (8 * i);
        }
        *x = transpose8(t);
    }
}

/// The AES S-box on bit-planes: the Boyar–Peralta depth-16, 113-gate circuit
/// ("A depth-16 circuit for the AES S-box", 2011), in the gate order of
/// BearSSL's `aes_ct`. `x0` is the most significant bit.
#[inline(always)]
fn sbox_planes(q: &mut [u32; 8]) {
    let (x0, x1, x2, x3) = (q[7], q[6], q[5], q[4]);
    let (x4, x5, x6, x7) = (q[3], q[2], q[1], q[0]);

    // Top linear transformation.
    let y14 = x3 ^ x5;
    let y13 = x0 ^ x6;
    let y9 = x0 ^ x3;
    let y8 = x0 ^ x5;
    let t0 = x1 ^ x2;
    let y1 = t0 ^ x7;
    let y4 = y1 ^ x3;
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x0;
    let y5 = y1 ^ x6;
    let y3 = y5 ^ y8;
    let t1 = x4 ^ y12;
    let y15 = t1 ^ x5;
    let y20 = t1 ^ x1;
    let y6 = y15 ^ x7;
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x7 ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x0 ^ y16;

    // Non-linear section.
    let t2 = y12 & y15;
    let t3 = y3 & y6;
    let t4 = t3 ^ t2;
    let t5 = y4 & x7;
    let t6 = t5 ^ t2;
    let t7 = y13 & y16;
    let t8 = y5 & y1;
    let t9 = t8 ^ t7;
    let t10 = y2 & y7;
    let t11 = t10 ^ t7;
    let t12 = y9 & y11;
    let t13 = y14 & y17;
    let t14 = t13 ^ t12;
    let t15 = y8 & y10;
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y20;
    let t22 = t18 ^ y19;
    let t23 = t19 ^ y21;
    let t24 = t20 ^ y18;

    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;

    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41;
    let z0 = t44 & y15;
    let z1 = t37 & y6;
    let z2 = t33 & x7;
    let z3 = t43 & y16;
    let z4 = t40 & y1;
    let z5 = t29 & y7;
    let z6 = t42 & y11;
    let z7 = t45 & y17;
    let z8 = t41 & y10;
    let z9 = t44 & y12;
    let z10 = t37 & y3;
    let z11 = t33 & y4;
    let z12 = t43 & y13;
    let z13 = t40 & y5;
    let z14 = t29 & y2;
    let z15 = t42 & y9;
    let z16 = t45 & y14;
    let z17 = t41 & y8;

    // Bottom linear transformation.
    let t46 = z15 ^ z16;
    let t47 = z10 ^ z11;
    let t48 = z5 ^ z13;
    let t49 = z9 ^ z10;
    let t50 = z2 ^ z12;
    let t51 = z2 ^ z5;
    let t52 = z7 ^ z8;
    let t53 = z0 ^ z3;
    let t54 = z6 ^ z7;
    let t55 = z16 ^ z17;
    let t56 = z12 ^ t48;
    let t57 = t50 ^ t53;
    let t58 = z4 ^ t46;
    let t59 = z3 ^ t54;
    let t60 = t46 ^ t57;
    let t61 = z14 ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = z4 ^ t59;
    let t65 = t61 ^ t62;
    let t66 = z1 ^ t63;
    let s0 = t59 ^ t63;
    let s6 = t56 ^ !t62;
    let s7 = t48 ^ !t60;
    let t67 = t64 ^ t65;
    let s3 = t53 ^ t66;
    let s4 = t51 ^ t66;
    let s5 = t47 ^ t65;
    let s1 = t64 ^ !s3;
    let s2 = t55 ^ !t67;

    *q = [s7, s6, s5, s4, s3, s2, s1, s0];
}

/// The inverse of the S-box's output affine map, on bit-planes:
/// `A⁻¹(y) = (y <<< 1) ⊕ (y <<< 3) ⊕ (y <<< 6) ⊕ 0x05` is a plane renaming
/// plus XORs. Since `S = A ∘ inv`, `S⁻¹ = inv ∘ A⁻¹ = A⁻¹ ∘ S ∘ A⁻¹`, so the
/// one forward circuit serves both directions.
#[inline(always)]
fn inv_affine_planes(q: &mut [u32; 8]) {
    let x = *q;
    for (i, p) in q.iter_mut().enumerate() {
        *p = x[(i + 7) % 8] ^ x[(i + 5) % 8] ^ x[(i + 2) % 8];
    }
    q[0] = !q[0];
    q[2] = !q[2];
}

/// Applies the AES S-box (`inv == false`) or its inverse to every byte of
/// `words` (four little-endian words, 32 bytes). `inv` is the public
/// direction, so branching on it is fine. Deliberately one out-of-line copy:
/// it is the bulk of the software AES code, shared by every caller.
#[inline(never)]
pub(crate) fn sub_words(words: &mut [u64; 4], inv: bool) {
    let mut q = to_planes(words);
    if inv {
        inv_affine_planes(&mut q);
    }
    sbox_planes(&mut q);
    if inv {
        inv_affine_planes(&mut q);
    }
    from_planes(&q, words);
}

/// Applies the AES S-box (`INV == false`) or its inverse to all 16 bytes of
/// `state` (byte-array form, for the tests).
#[cfg(test)]
fn sub_bytes16<const INV: bool>(state: &mut [u8; 16]) {
    let (lo, hi) = state.split_at_mut(8);
    let mut w = [
        u64::from_le_bytes((&*lo).try_into().expect("8 bytes")),
        u64::from_le_bytes((&*hi).try_into().expect("8 bytes")),
        0,
        0,
    ];
    sub_words(&mut w, INV);
    lo.copy_from_slice(&w[0].to_le_bytes());
    hi.copy_from_slice(&w[1].to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_mul_known() {
        // FIPS-197 worked example: 0x57 · 0x13 = 0xfe.
        assert_eq!(gf_mul(0x57, 0x13), 0xfe);
        assert_eq!(gf_mul(0x57, 0x83), 0xc1);
        assert_eq!(gf_mul(0x00, 0xff), 0x00);
        assert_eq!(gf_mul(0x01, 0xab), 0xab); // 1 is the identity
    }

    #[test]
    fn gf_inv_is_inverse() {
        assert_eq!(gf_inv(0), 0);
        for x in 1u16..=255 {
            let x = x as u8;
            assert_eq!(gf_mul(x, gf_inv(x)), 1, "inverse failed for {x:#04x}");
        }
    }

    #[test]
    fn sbox_known_values() {
        assert_eq!(sub_byte(0x00), 0x63);
        assert_eq!(sub_byte(0x01), 0x7c);
        assert_eq!(sub_byte(0x10), 0xca);
        assert_eq!(sub_byte(0x53), 0xed);
        assert_eq!(sub_byte(0x7c), 0x10);
        assert_eq!(sub_byte(0xff), 0x16);
    }

    #[test]
    fn sbox_is_bijection_and_invertible() {
        let mut seen = [false; 256];
        for x in 0u16..=255 {
            let x = x as u8;
            let s = sub_byte(x);
            assert!(!seen[s as usize], "S-box not injective at {x:#04x}");
            seen[s as usize] = true;
            // Inverse S-box undoes the forward S-box.
            assert_eq!(inv_sub_byte(s), x, "inv S-box failed for {x:#04x}");
        }
    }

    /// The bitsliced circuit must agree with the `gf_inv`-based scalar S-box
    /// (the oracle) on all 256 inputs, in both directions, in every byte
    /// position of a 16-byte state and of a 32-byte (four-word) batch.
    #[test]
    fn bitsliced_sbox_matches_scalar() {
        for base in (0u16..256).step_by(16) {
            let mut st = [0u8; 16];
            for (j, b) in st.iter_mut().enumerate() {
                *b = base as u8 + j as u8;
            }
            for rot in 0..16 {
                let mut fwd = st;
                fwd.rotate_left(rot);
                let orig = fwd;
                let mut inv = fwd;
                sub_bytes16::<false>(&mut fwd);
                sub_bytes16::<true>(&mut inv);
                for j in 0..16 {
                    assert_eq!(fwd[j], sub_byte(orig[j]), "S({:#04x})", orig[j]);
                    assert_eq!(inv[j], inv_sub_byte(orig[j]), "S^-1({:#04x})", orig[j]);
                }
            }
        }
        for x in 0u16..256 {
            let mut bytes = [0u8; 32];
            for (j, b) in bytes.iter_mut().enumerate() {
                *b = (x as u8).wrapping_add(j as u8 * 8);
            }
            let mut words = [0u64; 4];
            for (w, c) in words.iter_mut().zip(bytes.chunks_exact(8)) {
                *w = u64::from_le_bytes(c.try_into().unwrap());
            }
            let mut inv = words;
            sub_words(&mut words, false);
            sub_words(&mut inv, true);
            for ((w, v), c) in words.iter().zip(&inv).zip(bytes.chunks_exact(8)) {
                for ((o, p), &i) in w.to_le_bytes().iter().zip(v.to_le_bytes()).zip(c) {
                    assert_eq!(*o, sub_byte(i));
                    assert_eq!(p, inv_sub_byte(i));
                }
            }
        }
    }
}
