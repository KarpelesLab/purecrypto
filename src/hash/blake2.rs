//! BLAKE2 (RFC 7693): BLAKE2b (64-bit) and BLAKE2s (32-bit), unkeyed.
//!
//! The digest length is a parameter folded into the initial state, so the same
//! core produces BLAKE2b-256/384/512 and BLAKE2s-256. Keyed mode, salt, and
//! personalization are not exposed.

use super::Digest;

/// Message-word schedule (12 rounds). BLAKE2b uses all 12; BLAKE2s uses the
/// first 10.
#[rustfmt::skip]
const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

// ---- BLAKE2b (64-bit words, 128-byte blocks, 12 rounds) ----

const IV_B: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

fn compress_b(h: &mut [u64; 8], block: &[u8; 128], t0: u64, t1: u64, last: bool) {
    let mut m = [0u64; 16];
    for (word, chunk) in m.iter_mut().zip(block.chunks_exact(8)) {
        *word = u64::from_le_bytes(chunk.try_into().unwrap());
    }

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV_B);
    v[12] ^= t0;
    v[13] ^= t1;
    if last {
        v[14] ^= !0u64;
    }

    macro_rules! g {
        ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $y:expr) => {
            v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add($x);
            v[$d] = (v[$d] ^ v[$a]).rotate_right(32);
            v[$c] = v[$c].wrapping_add(v[$d]);
            v[$b] = (v[$b] ^ v[$c]).rotate_right(24);
            v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add($y);
            v[$d] = (v[$d] ^ v[$a]).rotate_right(16);
            v[$c] = v[$c].wrapping_add(v[$d]);
            v[$b] = (v[$b] ^ v[$c]).rotate_right(63);
        };
    }

    for s in SIGMA.iter() {
        g!(0, 4, 8, 12, m[s[0]], m[s[1]]);
        g!(1, 5, 9, 13, m[s[2]], m[s[3]]);
        g!(2, 6, 10, 14, m[s[4]], m[s[5]]);
        g!(3, 7, 11, 15, m[s[6]], m[s[7]]);
        g!(0, 5, 10, 15, m[s[8]], m[s[9]]);
        g!(1, 6, 11, 12, m[s[10]], m[s[11]]);
        g!(2, 7, 8, 13, m[s[12]], m[s[13]]);
        g!(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

#[derive(Clone)]
struct Blake2bState {
    h: [u64; 8],
    t0: u64,
    t1: u64,
    buf: [u8; 128],
    buf_len: usize,
}

impl Blake2bState {
    fn new(outlen: usize) -> Self {
        let mut h = IV_B;
        h[0] ^= 0x0101_0000 ^ outlen as u64; // unkeyed, fanout=depth=1
        Blake2bState {
            h,
            t0: 0,
            t1: 0,
            buf: [0u8; 128],
            buf_len: 0,
        }
    }

    fn inc(&mut self, n: u64) {
        let (t0, carry) = self.t0.overflowing_add(n);
        self.t0 = t0;
        if carry {
            self.t1 = self.t1.wrapping_add(1);
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        let fill = 128 - self.buf_len;
        // Only compress a full buffer when more data is known to follow, so the
        // final block is processed with the last-block flag in `finalize`.
        if data.len() > fill {
            self.buf[self.buf_len..].copy_from_slice(&data[..fill]);
            self.inc(128);
            compress_b(&mut self.h, &self.buf, self.t0, self.t1, false);
            self.buf_len = 0;
            data = &data[fill..];
            while data.len() > 128 {
                let block: &[u8; 128] = data[..128].try_into().unwrap();
                self.inc(128);
                compress_b(&mut self.h, block, self.t0, self.t1, false);
                data = &data[128..];
            }
        }
        self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
        self.buf_len += data.len();
    }

    fn finalize_into(mut self, out: &mut [u8]) {
        self.inc(self.buf_len as u64);
        for b in self.buf[self.buf_len..].iter_mut() {
            *b = 0;
        }
        compress_b(&mut self.h, &self.buf, self.t0, self.t1, true);

        let mut bytes = [0u8; 64];
        for (chunk, word) in bytes.chunks_exact_mut(8).zip(self.h.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out.copy_from_slice(&bytes[..out.len()]);
    }
}

// ---- BLAKE2s (32-bit words, 64-byte blocks, 10 rounds) ----

const IV_S: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

fn compress_s(h: &mut [u32; 8], block: &[u8; 64], t0: u32, t1: u32, last: bool) {
    let mut m = [0u32; 16];
    for (word, chunk) in m.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap());
    }

    let mut v = [0u32; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV_S);
    v[12] ^= t0;
    v[13] ^= t1;
    if last {
        v[14] ^= !0u32;
    }

    macro_rules! g {
        ($a:expr, $b:expr, $c:expr, $d:expr, $x:expr, $y:expr) => {
            v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add($x);
            v[$d] = (v[$d] ^ v[$a]).rotate_right(16);
            v[$c] = v[$c].wrapping_add(v[$d]);
            v[$b] = (v[$b] ^ v[$c]).rotate_right(12);
            v[$a] = v[$a].wrapping_add(v[$b]).wrapping_add($y);
            v[$d] = (v[$d] ^ v[$a]).rotate_right(8);
            v[$c] = v[$c].wrapping_add(v[$d]);
            v[$b] = (v[$b] ^ v[$c]).rotate_right(7);
        };
    }

    for s in SIGMA.iter().take(10) {
        g!(0, 4, 8, 12, m[s[0]], m[s[1]]);
        g!(1, 5, 9, 13, m[s[2]], m[s[3]]);
        g!(2, 6, 10, 14, m[s[4]], m[s[5]]);
        g!(3, 7, 11, 15, m[s[6]], m[s[7]]);
        g!(0, 5, 10, 15, m[s[8]], m[s[9]]);
        g!(1, 6, 11, 12, m[s[10]], m[s[11]]);
        g!(2, 7, 8, 13, m[s[12]], m[s[13]]);
        g!(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

#[derive(Clone)]
struct Blake2sState {
    h: [u32; 8],
    t0: u32,
    t1: u32,
    buf: [u8; 64],
    buf_len: usize,
}

impl Blake2sState {
    fn new(outlen: usize) -> Self {
        let mut h = IV_S;
        h[0] ^= 0x0101_0000 ^ outlen as u32;
        Blake2sState {
            h,
            t0: 0,
            t1: 0,
            buf: [0u8; 64],
            buf_len: 0,
        }
    }

    fn inc(&mut self, n: u32) {
        let (t0, carry) = self.t0.overflowing_add(n);
        self.t0 = t0;
        if carry {
            self.t1 = self.t1.wrapping_add(1);
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        let fill = 64 - self.buf_len;
        if data.len() > fill {
            self.buf[self.buf_len..].copy_from_slice(&data[..fill]);
            self.inc(64);
            compress_s(&mut self.h, &self.buf, self.t0, self.t1, false);
            self.buf_len = 0;
            data = &data[fill..];
            while data.len() > 64 {
                let block: &[u8; 64] = data[..64].try_into().unwrap();
                self.inc(64);
                compress_s(&mut self.h, block, self.t0, self.t1, false);
                data = &data[64..];
            }
        }
        self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
        self.buf_len += data.len();
    }

    fn finalize_into(mut self, out: &mut [u8]) {
        self.inc(self.buf_len as u32);
        for b in self.buf[self.buf_len..].iter_mut() {
            *b = 0;
        }
        compress_s(&mut self.h, &self.buf, self.t0, self.t1, true);

        let mut bytes = [0u8; 32];
        for (chunk, word) in bytes.chunks_exact_mut(4).zip(self.h.iter()) {
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        out.copy_from_slice(&bytes[..out.len()]);
    }
}

/// Defines a BLAKE2b variant of the given output length.
macro_rules! blake2b {
    ($name:ident, $func:ident, $out:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            state: Blake2bState,
        }
        impl Digest for $name {
            type Output = [u8; $out];
            type Block = [u8; 128];
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = 128;
            #[inline]
            fn new() -> Self {
                $name {
                    state: Blake2bState::new($out),
                }
            }
            #[inline]
            fn zeroed_block() -> [u8; 128] {
                [0u8; 128]
            }
            #[inline]
            fn zeroed_output() -> [u8; $out] {
                [0u8; $out]
            }
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.state.update(data);
            }
            #[inline]
            fn finalize(self) -> [u8; $out] {
                let mut out = [0u8; $out];
                self.state.finalize_into(&mut out);
                out
            }
        }
        #[doc = $doc]
        #[inline]
        pub fn $func(data: &[u8]) -> [u8; $out] {
            $name::digest(data)
        }
    };
}

blake2b!(Blake2b256, blake2b256, 32, "BLAKE2b with a 256-bit digest.");
blake2b!(Blake2b384, blake2b384, 48, "BLAKE2b with a 384-bit digest.");
blake2b!(Blake2b512, blake2b512, 64, "BLAKE2b with a 512-bit digest.");

/// BLAKE2s with a 256-bit digest.
#[derive(Clone)]
pub struct Blake2s256 {
    state: Blake2sState,
}
impl Digest for Blake2s256 {
    type Output = [u8; 32];
    type Block = [u8; 64];
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
    #[inline]
    fn new() -> Self {
        Blake2s256 {
            state: Blake2sState::new(32),
        }
    }
    #[inline]
    fn zeroed_block() -> [u8; 64] {
        [0u8; 64]
    }
    #[inline]
    fn zeroed_output() -> [u8; 32] {
        [0u8; 32]
    }
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }
    #[inline]
    fn finalize(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.state.finalize_into(&mut out);
        out
    }
}

/// BLAKE2s-256 of `data`.
#[inline]
pub fn blake2s256(data: &[u8]) -> [u8; 32] {
    Blake2s256::digest(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // RFC 7693 Appendix A/E reference vectors for "abc".
    #[test]
    fn rfc7693_abc() {
        assert_eq!(
            blake2b512(b"abc"),
            from_hex::<64>(
                "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
            )
        );
        assert_eq!(
            blake2s256(b"abc"),
            from_hex::<32>("508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
        );
    }

    // Vectors generated with `b2sum -l <bits>` / `openssl dgst`.
    #[test]
    fn empty_and_lengths() {
        assert_eq!(
            blake2b512(b""),
            from_hex::<64>(
                "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
            )
        );
        assert_eq!(
            blake2s256(b""),
            from_hex::<32>("69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
        );
        assert_eq!(
            blake2b256(b"abc"),
            from_hex::<32>("bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319")
        );
        assert_eq!(
            blake2b384(b"abc"),
            from_hex::<48>(
                "6f56a82c8e7ef526dfe182eb5212f7db9df1317e57815dbda46083fc30f54ee6c66ba83be64b302d7cba6ce15bb556f4"
            )
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let msg = [0xa5u8; 300];
        let oneshot = blake2b512(&msg);
        let mut h = Blake2b512::new();
        h.update(&msg[..1]);
        h.update(&msg[1..128]); // exactly fills a block at byte 129 boundary
        h.update(&msg[128..256]);
        h.update(&msg[256..]);
        assert_eq!(h.finalize(), oneshot);

        let oneshot_s = blake2s256(&msg);
        let mut hs = Blake2s256::new();
        for c in msg.chunks(7) {
            hs.update(c);
        }
        assert_eq!(hs.finalize(), oneshot_s);
    }
}
