//! MD2 (RFC 1319).
//!
//! Cryptographically broken (collisions and preimage weaknesses are known);
//! provided only for interoperability with legacy artifacts. Do not use for
//! security.
//!
//! The compression is driven by a fixed 256-byte substitution table derived from
//! the digits of π. As with the other table-based hashes here, lookups are not
//! constant-time with respect to the (public) message bytes.

use super::Digest;

/// The MD2 S-box `PI_SUBST`: a permutation of `0..256` built from π (RFC 1319).
const PI_SUBST: [u8; 256] = [
    41, 46, 67, 201, 162, 216, 124, 1, 61, 54, 84, 161, 236, 240, 6, 19, 98, 167, 5, 243, 192, 199,
    115, 140, 152, 147, 43, 217, 188, 76, 130, 202, 30, 155, 87, 60, 253, 212, 224, 22, 103, 66,
    111, 24, 138, 23, 229, 18, 190, 78, 196, 214, 218, 158, 222, 73, 160, 251, 245, 142, 187, 47,
    238, 122, 169, 104, 121, 145, 21, 178, 7, 63, 148, 194, 16, 137, 11, 34, 95, 33, 128, 127, 93,
    154, 90, 144, 50, 39, 53, 62, 204, 231, 191, 247, 151, 3, 255, 25, 48, 179, 72, 165, 181, 209,
    215, 94, 146, 42, 172, 86, 170, 198, 79, 184, 56, 210, 150, 164, 125, 182, 118, 252, 107, 226,
    156, 116, 4, 241, 69, 157, 112, 89, 100, 113, 135, 32, 134, 91, 207, 101, 230, 45, 168, 2, 27,
    96, 37, 173, 174, 176, 185, 246, 28, 70, 97, 105, 52, 64, 126, 15, 85, 71, 163, 35, 221, 81,
    175, 58, 195, 92, 249, 206, 186, 197, 234, 38, 44, 83, 13, 110, 133, 40, 132, 9, 211, 223, 205,
    244, 65, 129, 77, 82, 106, 220, 55, 200, 108, 193, 171, 250, 36, 225, 123, 8, 12, 189, 177, 74,
    120, 136, 149, 139, 227, 99, 232, 109, 233, 203, 213, 254, 59, 0, 29, 57, 242, 239, 183, 14,
    102, 88, 208, 228, 166, 119, 114, 248, 235, 117, 75, 10, 49, 68, 80, 180, 143, 237, 31, 26,
    219, 153, 141, 51, 159, 17, 131, 20,
];

/// Mixes a 16-byte `block` into the 48-byte state `x` (RFC 1319 §3.4, the inner
/// 18-pass transform). Does not touch the checksum.
fn mix(x: &mut [u8; 48], block: &[u8; 16]) {
    for j in 0..16 {
        x[16 + j] = block[j];
        x[32 + j] = x[16 + j] ^ x[j];
    }
    let mut t = 0u8;
    for r in 0..18u8 {
        for slot in x.iter_mut() {
            *slot ^= PI_SUBST[t as usize];
            t = *slot;
        }
        t = t.wrapping_add(r);
    }
}

/// Folds a 16-byte `block` into the running checksum `c` (RFC 1319 §3.2).
fn checksum_update(c: &mut [u8; 16], block: &[u8; 16]) {
    let mut l = c[15];
    for j in 0..16 {
        c[j] ^= PI_SUBST[(block[j] ^ l) as usize];
        l = c[j];
    }
}

/// The MD2 hash function (128-bit output).
#[derive(Clone)]
pub struct Md2 {
    x: [u8; 48],
    checksum: [u8; 16],
    buf: [u8; 16],
    buf_len: usize,
}

impl Md2 {
    /// Processes one full 16-byte message block: state mix plus checksum update.
    fn process(&mut self, block: &[u8; 16]) {
        mix(&mut self.x, block);
        checksum_update(&mut self.checksum, block);
    }
}

impl Digest for Md2 {
    type Output = [u8; 16];
    type Block = [u8; 16];
    const OUTPUT_LEN: usize = 16;
    const BLOCK_LEN: usize = 16;

    #[inline]
    fn new() -> Self {
        Md2 {
            x: [0u8; 48],
            checksum: [0u8; 16],
            buf: [0u8; 16],
            buf_len: 0,
        }
    }
    #[inline]
    fn zeroed_block() -> [u8; 16] {
        [0u8; 16]
    }
    #[inline]
    fn zeroed_output() -> [u8; 16] {
        [0u8; 16]
    }
    fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (16 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 16 {
                let block = self.buf;
                self.process(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 16 {
            let block: [u8; 16] = data[..16].try_into().unwrap();
            self.process(&block);
            data = &data[16..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }
    fn finalize(mut self) -> [u8; 16] {
        // Pad with `pad` bytes each equal to `pad` (always 1..=16 bytes).
        let pad = (16 - self.buf_len) as u8;
        for b in self.buf[self.buf_len..].iter_mut() {
            *b = pad;
        }
        let block = self.buf;
        self.process(&block);
        // Append the checksum as a final block, mixed into the state only.
        let cs = self.checksum;
        mix(&mut self.x, &cs);
        let mut out = [0u8; 16];
        out.copy_from_slice(&self.x[..16]);
        out
    }
    #[inline]
    fn zeroize(&mut self) {
        super::zeroize::zero_bytes(&mut self.x);
        super::zeroize::zero_bytes(&mut self.checksum);
        super::zeroize::zero_bytes(&mut self.buf);
        self.buf_len = 0;
    }
}

impl Drop for Md2 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Computes the MD2 digest of `data`.
#[inline]
pub fn md2(data: &[u8]) -> [u8; 16] {
    Md2::digest(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // RFC 1319, Appendix A.5 test suite. Cross-checked byte-for-byte against
    // PyCryptodome's `Crypto.Hash.MD2` (OpenSSL 3.x dropped MD2 entirely).
    #[test]
    fn rfc1319_vectors() {
        assert_eq!(md2(b""), from_hex::<16>("8350e5a3e24c153df2275c9f80692773"));
        assert_eq!(
            md2(b"a"),
            from_hex::<16>("32ec01ec4a6dac72c0ab96fb34c0b5d1")
        );
        assert_eq!(
            md2(b"abc"),
            from_hex::<16>("da853b0d3f88d99b30283a69e6ded6bb")
        );
        assert_eq!(
            md2(b"message digest"),
            from_hex::<16>("ab4f496bfb2a530b219ff33031fe06b0")
        );
        assert_eq!(
            md2(b"abcdefghijklmnopqrstuvwxyz"),
            from_hex::<16>("4e8ddff3650292ab5a4108c3aa47940b")
        );
        assert_eq!(
            md2(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
            from_hex::<16>("da33def2a42df13975352846c30338cd")
        );
        assert_eq!(
            md2(
                b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"
            ),
            from_hex::<16>("d5976f79d83d3a0dc9806c3c66f3efd8")
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let msg = [0x61u8; 200];
        let oneshot = md2(&msg);
        let mut h = Md2::new();
        h.update(&msg[..1]);
        h.update(&msg[1..17]);
        h.update(&msg[17..]);
        assert_eq!(h.finalize(), oneshot);
    }
}
