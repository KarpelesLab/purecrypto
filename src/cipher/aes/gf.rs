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
}
