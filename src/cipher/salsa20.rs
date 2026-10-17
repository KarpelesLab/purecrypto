//! Salsa20/8 core function — the 8-round variant of D. Bernstein's Salsa20
//! stream cipher. Used as scrypt's BlockMix primitive (RFC 7914 §3); not
//! exposed as a full stream cipher because the AEAD-friendly alternative
//! (ChaCha20) is preferred for that purpose.
//!
//! Operates on a single 64-byte block treated as a row-major `[u32; 16]`
//! matrix in little-endian byte order:
//! `out = block + Salsa20_doubleround⁴(block)`.
//! Pure ARX, branchless; constant time on every coefficient.
//!
//! The block is taken as words so that scrypt's BlockMix can keep its
//! chaining value in registers between calls instead of serialising it to
//! bytes and back. A 4-lane SIMD kernel in the Percival shuffled-column
//! layout was measured and rejected: on a wide out-of-order core the scalar
//! schedule runs its four column chains in parallel, whereas the vector form
//! is a single dependency chain of add / shift / insert / XOR per step and
//! came out 2.5× *slower* (scrypt 2¹⁴/8/1: 40 ms vs 16 ms on Apple M5).

#[inline(always)]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
    x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
    x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
    x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
}

/// Salsa20/8 core on a block of sixteen little-endian words: 8 rounds
/// (4 double-rounds), then add the original block back in. Mirrors the
/// description in RFC 7914 §3.
#[inline]
pub(crate) fn salsa20_8_words(x: &mut [u32; 16]) {
    let original = *x;

    for _ in 0..4 {
        // Column rounds.
        quarter_round(x, 0, 4, 8, 12);
        quarter_round(x, 5, 9, 13, 1);
        quarter_round(x, 10, 14, 2, 6);
        quarter_round(x, 15, 3, 7, 11);
        // Row rounds.
        quarter_round(x, 0, 1, 2, 3);
        quarter_round(x, 5, 6, 7, 4);
        quarter_round(x, 10, 11, 8, 9);
        quarter_round(x, 15, 12, 13, 14);
    }

    for (w, &o) in x.iter_mut().zip(original.iter()) {
        *w = w.wrapping_add(o);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// RFC 7914 §8: the published Salsa20/8 input/output pair (in hex).
    #[test]
    fn rfc7914_salsa20_8_block() {
        let block = from_hex::<64>(
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
        let mut x: [u32; 16] = core::array::from_fn(|i| {
            u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap())
        });
        salsa20_8_words(&mut x);
        let mut out = [0u8; 64];
        for (chunk, w) in out.chunks_exact_mut(4).zip(x.iter()) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        assert_eq!(out, expected);
    }
}
