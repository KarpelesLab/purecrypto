//! Salsa20/8 core function — the 8-round variant of D. Bernstein's Salsa20
//! stream cipher. Used as scrypt's BlockMix primitive (RFC 7914 §3); not
//! exposed as a full stream cipher because the AEAD-friendly alternative
//! (ChaCha20) is preferred for that purpose.
//!
//! Operates on a single 64-byte block treated as a row-major `[u32; 16]`
//! matrix in little-endian byte order:
//! `out = block + Salsa20_doubleround⁴(block)`.
//! Pure ARX, branchless; constant time on every coefficient.

#[inline(always)]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
    x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
    x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
    x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
}

/// Salsa20/8 core: 8 rounds (4 double-rounds) on a 64-byte block, then add
/// the original block back in. Mirrors the description in RFC 7914 §3.
pub(crate) fn salsa20_8(block: &mut [u8; 64]) {
    let mut x = [0u32; 16];
    for (i, w) in x.iter_mut().enumerate() {
        *w = u32::from_le_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let original = x;

    for _ in 0..4 {
        // Column rounds.
        quarter_round(&mut x, 0, 4, 8, 12);
        quarter_round(&mut x, 5, 9, 13, 1);
        quarter_round(&mut x, 10, 14, 2, 6);
        quarter_round(&mut x, 15, 3, 7, 11);
        // Row rounds.
        quarter_round(&mut x, 0, 1, 2, 3);
        quarter_round(&mut x, 5, 6, 7, 4);
        quarter_round(&mut x, 10, 11, 8, 9);
        quarter_round(&mut x, 15, 12, 13, 14);
    }

    for (i, &w) in x.iter().enumerate() {
        let v = w.wrapping_add(original[i]);
        block[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// RFC 7914 §8: the published Salsa20/8 input/output pair (in hex).
    #[test]
    fn rfc7914_salsa20_8_block() {
        let mut block = from_hex::<64>(
            "7e879a214f3ec9867ca940e641718f26\
             baee555b8c61c1b50df846116dcd3b1d\
             ee24f319df9b3d8514121e4b5ac5aa32\
             76021d2909c74829edebc68db8b8c25e",
        );
        let expected = from_hex::<64>(
            "a41f859c6608cc993b81cacb020cef05\
             044b2181a2fd337dfd7b1c6396682f29\
             b4393168e3c9e6bcfe6bc5b7a06d96ba\
             e424cc102c91745c24ad673dc7618f81",
        );
        salsa20_8(&mut block);
        assert_eq!(block, expected);
    }
}
