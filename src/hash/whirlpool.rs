//! Whirlpool (ISO/IEC 10118-3, the final 2003 revision).
//!
//! A 512-bit Merkle–Damgård hash whose compression is the Miyaguchi–Preneel
//! mode over the `W` block cipher — an AES-like SPN on an 8×8 byte state, with
//! ten rounds of `SubBytes`/`ShiftColumns`/`MixRows`/`AddRoundKey` in
//! GF(2⁸) under the reduction polynomial `x⁸ + x⁴ + x³ + x² + 1` (`0x11d`).
//!
//! Implemented in the standard table-driven form: a single 256-entry round
//! table `C0` (the S-box composed with the MDS column), with the other seven
//! tables obtained by byte rotation. The table is built at compile time from
//! the S-box, so the module stays `no_std` and allocation-free. Lookups are not
//! constant-time with respect to the (public) message bytes.

use super::Digest;

/// The Whirlpool S-box (final 2003 version).
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x18, 0x23, 0xc6, 0xe8, 0x87, 0xb8, 0x01, 0x4f, 0x36, 0xa6, 0xd2, 0xf5, 0x79, 0x6f, 0x91, 0x52,
    0x60, 0xbc, 0x9b, 0x8e, 0xa3, 0x0c, 0x7b, 0x35, 0x1d, 0xe0, 0xd7, 0xc2, 0x2e, 0x4b, 0xfe, 0x57,
    0x15, 0x77, 0x37, 0xe5, 0x9f, 0xf0, 0x4a, 0xda, 0x58, 0xc9, 0x29, 0x0a, 0xb1, 0xa0, 0x6b, 0x85,
    0xbd, 0x5d, 0x10, 0xf4, 0xcb, 0x3e, 0x05, 0x67, 0xe4, 0x27, 0x41, 0x8b, 0xa7, 0x7d, 0x95, 0xd8,
    0xfb, 0xee, 0x7c, 0x66, 0xdd, 0x17, 0x47, 0x9e, 0xca, 0x2d, 0xbf, 0x07, 0xad, 0x5a, 0x83, 0x33,
    0x63, 0x02, 0xaa, 0x71, 0xc8, 0x19, 0x49, 0xd9, 0xf2, 0xe3, 0x5b, 0x88, 0x9a, 0x26, 0x32, 0xb0,
    0xe9, 0x0f, 0xd5, 0x80, 0xbe, 0xcd, 0x34, 0x48, 0xff, 0x7a, 0x90, 0x5f, 0x20, 0x68, 0x1a, 0xae,
    0xb4, 0x54, 0x93, 0x22, 0x64, 0xf1, 0x73, 0x12, 0x40, 0x08, 0xc3, 0xec, 0xdb, 0xa1, 0x8d, 0x3d,
    0x97, 0x00, 0xcf, 0x2b, 0x76, 0x82, 0xd6, 0x1b, 0xb5, 0xaf, 0x6a, 0x50, 0x45, 0xf3, 0x30, 0xef,
    0x3f, 0x55, 0xa2, 0xea, 0x65, 0xba, 0x2f, 0xc0, 0xde, 0x1c, 0xfd, 0x4d, 0x92, 0x75, 0x06, 0x8a,
    0xb2, 0xe6, 0x0e, 0x1f, 0x62, 0xd4, 0xa8, 0x96, 0xf9, 0xc5, 0x25, 0x59, 0x84, 0x72, 0x39, 0x4c,
    0x5e, 0x78, 0x38, 0x8c, 0xd1, 0xa5, 0xe2, 0x61, 0xb3, 0x21, 0x9c, 0x1e, 0x43, 0xc7, 0xfc, 0x04,
    0x51, 0x99, 0x6d, 0x0d, 0xfa, 0xdf, 0x7e, 0x24, 0x3b, 0xab, 0xce, 0x11, 0x8f, 0x4e, 0xb7, 0xeb,
    0x3c, 0x81, 0x94, 0xf7, 0xb9, 0x13, 0x2c, 0xd3, 0xe7, 0x6e, 0xc4, 0x03, 0x56, 0x44, 0x7f, 0xa9,
    0x2a, 0xbb, 0xc1, 0x53, 0xdc, 0x0b, 0x9d, 0x6c, 0x31, 0x74, 0xf6, 0x46, 0xac, 0x89, 0x14, 0xe1,
    0x16, 0x3a, 0x69, 0x09, 0x70, 0xb6, 0xd0, 0xed, 0xcc, 0x42, 0x98, 0xa4, 0x28, 0x5c, 0xf8, 0x86,
];

/// Multiplies a byte by 2 in GF(2⁸) with reduction polynomial `0x11d`.
const fn xtime(x: u64) -> u64 {
    let r = (x << 1) & 0xff;
    if x & 0x80 != 0 { r ^ 0x1d } else { r }
}

/// Builds the primary round table `C0`: `S(x)` spread across a 64-bit lane by
/// the MDS row `[1, 1, 4, 1, 8, 5, 2, 9]`.
const fn build_c0() -> [u64; 256] {
    let mut c = [0u64; 256];
    let mut x = 0;
    while x < 256 {
        let v1 = SBOX[x] as u64;
        let v2 = xtime(v1);
        let v4 = xtime(v2);
        let v5 = v4 ^ v1;
        let v8 = xtime(v4);
        let v9 = v8 ^ v1;
        c[x] = (v1 << 56)
            | (v1 << 48)
            | (v4 << 40)
            | (v1 << 32)
            | (v8 << 24)
            | (v5 << 16)
            | (v2 << 8)
            | v9;
        x += 1;
    }
    c
}

/// The ten W-cipher round constants, derived from the diagonal of `C0`.
const fn build_rc(c0: &[u64; 256]) -> [u64; 10] {
    let mut rc = [0u64; 10];
    let mut r = 0;
    while r < 10 {
        let mut acc = 0u64;
        let mut t = 0;
        while t < 8 {
            let val = c0[8 * r + t].rotate_right(8 * t as u32);
            let mask = 0xffu64 << (56 - 8 * t);
            acc ^= val & mask;
            t += 1;
        }
        rc[r] = acc;
        r += 1;
    }
    rc
}

const C0: [u64; 256] = build_c0();
const RC: [u64; 10] = build_rc(&C0);

/// One application of the W round's linear layer (the eight table lookups), used
/// both for the key schedule and the state transformation.
#[inline]
fn w_theta(inp: &[u64; 8]) -> [u64; 8] {
    let mut out = [0u64; 8];
    let mut i = 0;
    while i < 8 {
        let mut acc = 0u64;
        let mut t = 0;
        while t < 8 {
            let word = inp[(i + 8 - t) & 7];
            let byte = ((word >> (56 - 8 * t)) & 0xff) as usize;
            acc ^= C0[byte].rotate_right(8 * t as u32);
            t += 1;
        }
        out[i] = acc;
        i += 1;
    }
    out
}

/// The Whirlpool hash function (512-bit output).
#[derive(Clone)]
pub struct Whirlpool {
    hash: [u64; 8],
    buf: [u8; 64],
    buf_len: usize,
    /// Total message length in bits (the 256-bit field never overflows for any
    /// realistic input, so a `u128` of low bits suffices).
    bit_len: u128,
}

impl Whirlpool {
    /// Miyaguchi–Preneel compression of one 64-byte block into `hash`.
    fn compress(&mut self, block: &[u8; 64]) {
        let mut m = [0u64; 8];
        for (w, chunk) in m.iter_mut().zip(block.chunks_exact(8)) {
            *w = u64::from_be_bytes(chunk.try_into().unwrap());
        }
        let mut k = self.hash;
        let mut state = [0u64; 8];
        for i in 0..8 {
            state[i] = m[i] ^ k[i];
        }
        for &rc in RC.iter() {
            // K^r = rho(K^{r-1}) with the round constant in the first lane.
            let mut kr = w_theta(&k);
            kr[0] ^= rc;
            k = kr;
            // state = rho(state) ^ K^r.
            let mut sr = w_theta(&state);
            for i in 0..8 {
                sr[i] ^= k[i];
            }
            state = sr;
        }
        for i in 0..8 {
            self.hash[i] ^= state[i] ^ m[i];
        }
    }
}

impl Digest for Whirlpool {
    type Output = [u8; 64];
    type Block = [u8; 64];
    const OUTPUT_LEN: usize = 64;
    const BLOCK_LEN: usize = 64;

    #[inline]
    fn new() -> Self {
        Whirlpool {
            hash: [0u64; 8],
            buf: [0u8; 64],
            buf_len: 0,
            bit_len: 0,
        }
    }
    #[inline]
    fn zeroed_block() -> [u8; 64] {
        [0u8; 64]
    }
    #[inline]
    fn zeroed_output() -> [u8; 64] {
        [0u8; 64]
    }
    fn update(&mut self, mut data: &[u8]) {
        self.bit_len = self.bit_len.wrapping_add((data.len() as u128) * 8);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let block: [u8; 64] = data[..64].try_into().unwrap();
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }
    fn finalize(mut self) -> [u8; 64] {
        let bits = self.bit_len;
        let mut buf = self.buf;
        let mut i = self.buf_len;
        // Append the mandatory `1` bit (0x80), then pad with zeros so the final
        // 32 bytes hold the 256-bit big-endian length.
        buf[i] = 0x80;
        i += 1;
        if i > 32 {
            for b in buf[i..64].iter_mut() {
                *b = 0;
            }
            self.compress(&buf);
            buf = [0u8; 64];
            i = 0;
        }
        for b in buf[i..32].iter_mut() {
            *b = 0;
        }
        // 256-bit length: the high 16 bytes are always zero here.
        buf[32..48].copy_from_slice(&[0u8; 16]);
        buf[48..64].copy_from_slice(&bits.to_be_bytes());
        self.compress(&buf);

        let mut out = [0u8; 64];
        for (chunk, &h) in out.chunks_exact_mut(8).zip(self.hash.iter()) {
            chunk.copy_from_slice(&h.to_be_bytes());
        }
        out
    }
    #[inline]
    fn zeroize(&mut self) {
        super::zeroize::zero_words(&mut self.hash);
        super::zeroize::zero_bytes(&mut self.buf);
        self.buf_len = 0;
        self.bit_len = 0;
    }
}

impl Drop for Whirlpool {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Computes the Whirlpool digest of `data`.
#[inline]
pub fn whirlpool(data: &[u8]) -> [u8; 64] {
    Whirlpool::digest(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // ISO/IEC 10118-3 / NESSIE reference vectors (final 2003 Whirlpool).
    // Cross-checked byte-for-byte against `openssl dgst -whirlpool` (the legacy
    // provider in OpenSSL 3.x).
    #[test]
    fn reference_vectors() {
        assert_eq!(
            whirlpool(b""),
            from_hex::<64>(
                "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7\
                 3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"
            )
        );
        assert_eq!(
            whirlpool(b"abc"),
            from_hex::<64>(
                "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c\
                 7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5"
            )
        );
        assert_eq!(
            whirlpool(b"message digest"),
            from_hex::<64>(
                "378c84a4126e2dc6e56dcc7458377aac838d00032230f53ce1f5700c0ffb4d3b\
                 8421557659ef55c106b4b52ac5a4aaa692ed920052838f3362e86dbd37a8903e"
            )
        );
        assert_eq!(
            whirlpool(b"abcdefghijklmnopqrstuvwxyz"),
            from_hex::<64>(
                "f1d754662636ffe92c82ebb9212a484a8d38631ead4238f5442ee13b8054e41b\
                 08bf2a9251c30b6a0b8aae86177ab4a6f68f673e7207865d5d9819a3dba4eb3b"
            )
        );
        assert_eq!(
            whirlpool(b"The quick brown fox jumps over the lazy dog"),
            from_hex::<64>(
                "b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725f\
                 d2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35"
            )
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        // 200 bytes spans multiple 64-byte blocks and a non-trivial final pad.
        let msg = [0x61u8; 200];
        let oneshot = whirlpool(&msg);
        let mut h = Whirlpool::new();
        h.update(&msg[..1]);
        h.update(&msg[1..65]);
        h.update(&msg[65..130]);
        h.update(&msg[130..]);
        assert_eq!(h.finalize(), oneshot);
    }

    // A message whose padded length forces an extra all-padding final block
    // (length field cannot fit after the 0x80 in the same block).
    #[test]
    fn extra_padding_block() {
        let msg = [0x55u8; 60];
        let oneshot = whirlpool(&msg);
        let mut h = Whirlpool::new();
        for c in msg.chunks(7) {
            h.update(c);
        }
        assert_eq!(h.finalize(), oneshot);
    }
}
