//! The ChaCha20 stream cipher (RFC 8439 §2.4).
//!
//! ChaCha20 expands a 256-bit key, a 96-bit nonce and a 32-bit block counter
//! into a 64-byte keystream block by running 20 rounds (ten "double rounds") of
//! the quarter-round function over a 4×4 matrix of 32-bit words. The cipher is
//! inherently constant time: it is built from 32-bit add/xor/rotate with no
//! secret-dependent branches or memory indexing.
//!
//! A given (key, nonce) pair must **never** be reused with overlapping counter
//! ranges: as with any stream cipher, keystream reuse destroys confidentiality.

/// The ChaCha20 constants — the ASCII string `"expand 32-byte k"` as four
/// little-endian words (RFC 8439 §2.3).
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

/// The ChaCha20 quarter-round on four words of the state (RFC 8439 §2.1).
#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// A ChaCha20 cipher keyed with a 256-bit key.
#[derive(Clone)]
pub struct ChaCha20 {
    key: [u32; 8],
}

impl ChaCha20 {
    /// Creates a ChaCha20 cipher from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut k = [0u32; 8];
        for (word, chunk) in k.iter_mut().zip(key.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        ChaCha20 { key: k }
    }

    /// Builds the initial state matrix for a nonce and block counter.
    fn state(&self, nonce: &[u8; 12], counter: u32) -> [u32; 16] {
        let mut s = [0u32; 16];
        s[0..4].copy_from_slice(&CONSTANTS);
        s[4..12].copy_from_slice(&self.key);
        s[12] = counter;
        for (word, chunk) in s[13..16].iter_mut().zip(nonce.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        s
    }

    /// Generates the 64-byte keystream block for `(nonce, counter)`.
    pub fn block(&self, nonce: &[u8; 12], counter: u32) -> [u8; 64] {
        let initial = self.state(nonce, counter);
        let mut s = initial;
        // 20 rounds = 10 double-rounds (column rounds then diagonal rounds).
        for _ in 0..10 {
            quarter_round(&mut s, 0, 4, 8, 12);
            quarter_round(&mut s, 1, 5, 9, 13);
            quarter_round(&mut s, 2, 6, 10, 14);
            quarter_round(&mut s, 3, 7, 11, 15);
            quarter_round(&mut s, 0, 5, 10, 15);
            quarter_round(&mut s, 1, 6, 11, 12);
            quarter_round(&mut s, 2, 7, 8, 13);
            quarter_round(&mut s, 3, 4, 9, 14);
        }

        let mut out = [0u8; 64];
        for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
            let word = s[i].wrapping_add(initial[i]);
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out
    }

    /// XORs the keystream into `buf` in place, starting at block `counter`
    /// (RFC 8439 §2.4). The counter increments per 64-byte block.
    pub fn apply_keystream(&self, nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        let mut block_counter = counter;
        for block in buf.chunks_mut(64) {
            let ks = self.block(nonce, block_counter);
            for (b, k) in block.iter_mut().zip(ks.iter()) {
                *b ^= *k;
            }
            block_counter = block_counter.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    #[test]
    fn rfc8439_block_function() {
        // RFC 8439 §2.3.2.
        let key = from_hex::<32>(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        let nonce = from_hex::<12>("000000090000004a00000000");
        let c = ChaCha20::new(&key);
        let block = c.block(&nonce, 1);
        assert_eq!(
            block,
            from_hex::<64>(
                "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
                 d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
            )
        );
    }

    #[test]
    fn rfc8439_encryption() {
        // RFC 8439 §2.4.2: encrypt the sunscreen plaintext at initial counter 1.
        let key = from_hex::<32>(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        );
        let nonce = from_hex::<12>("000000000000004a00000000");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
        let mut buf = plaintext.to_vec();
        ChaCha20::new(&key).apply_keystream(&nonce, 1, &mut buf);
        let expected = from_hex::<114>(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );
        assert_eq!(buf, expected);

        // Keystream is its own inverse: re-applying recovers the plaintext.
        ChaCha20::new(&key).apply_keystream(&nonce, 1, &mut buf);
        assert_eq!(buf, plaintext);
    }
}
