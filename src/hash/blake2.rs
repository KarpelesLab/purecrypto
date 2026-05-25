//! BLAKE2 (RFC 7693): BLAKE2b (64-bit) and BLAKE2s (32-bit), unkeyed.
//!
//! The digest length is a parameter folded into the initial state, so the same
//! core produces BLAKE2b-256/384/512 and BLAKE2s-256. Keyed mode, salt, and
//! personalization are not exposed.

use super::{Digest, Mac};
use crate::ct::{Choice, ConstantTimeEq};

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

/// Builds a 64-byte BLAKE2b parameter block.
#[allow(clippy::too_many_arguments)]
fn param_b(
    digest_length: u8,
    key_length: u8,
    fanout: u8,
    depth: u8,
    leaf_length: u32,
    node_offset: u32,
    xof_length: u32,
    node_depth: u8,
    inner_length: u8,
) -> [u8; 64] {
    let mut p = [0u8; 64];
    p[0] = digest_length;
    p[1] = key_length;
    p[2] = fanout;
    p[3] = depth;
    p[4..8].copy_from_slice(&leaf_length.to_le_bytes());
    p[8..12].copy_from_slice(&node_offset.to_le_bytes());
    p[12..16].copy_from_slice(&xof_length.to_le_bytes());
    p[16] = node_depth;
    p[17] = inner_length;
    p
}

/// Initial state = IV XOR the parameter block, word by word.
fn iv_from_param_b(p: &[u8; 64]) -> [u64; 8] {
    let mut h = IV_B;
    for (i, hw) in h.iter_mut().enumerate() {
        *hw ^= u64::from_le_bytes(p[8 * i..8 * i + 8].try_into().unwrap());
    }
    h
}

impl Blake2bState {
    fn from_h(h: [u64; 8]) -> Self {
        Blake2bState {
            h,
            t0: 0,
            t1: 0,
            buf: [0u8; 128],
            buf_len: 0,
        }
    }

    fn new(outlen: usize) -> Self {
        Self::from_h(iv_from_param_b(&param_b(
            outlen as u8,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
        )))
    }

    /// Keyed init: the key is processed as a zero-padded first block.
    fn with_key(outlen: usize, key: &[u8]) -> Self {
        let mut s = Self::from_h(iv_from_param_b(&param_b(
            outlen as u8,
            key.len() as u8,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
        )));
        let mut block = [0u8; 128];
        block[..key.len()].copy_from_slice(key);
        s.update(&block);
        s
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

/// Builds a 32-byte BLAKE2s parameter block (`xof_length` is 16-bit here).
#[allow(clippy::too_many_arguments)]
fn param_s(
    digest_length: u8,
    key_length: u8,
    fanout: u8,
    depth: u8,
    leaf_length: u32,
    node_offset: u32,
    xof_length: u16,
    node_depth: u8,
    inner_length: u8,
) -> [u8; 32] {
    let mut p = [0u8; 32];
    p[0] = digest_length;
    p[1] = key_length;
    p[2] = fanout;
    p[3] = depth;
    p[4..8].copy_from_slice(&leaf_length.to_le_bytes());
    p[8..12].copy_from_slice(&node_offset.to_le_bytes());
    p[12..14].copy_from_slice(&xof_length.to_le_bytes());
    p[14] = node_depth;
    p[15] = inner_length;
    p
}

/// Initial state = IV XOR the parameter block, word by word.
fn iv_from_param_s(p: &[u8; 32]) -> [u32; 8] {
    let mut h = IV_S;
    for (i, hw) in h.iter_mut().enumerate() {
        *hw ^= u32::from_le_bytes(p[4 * i..4 * i + 4].try_into().unwrap());
    }
    h
}

impl Blake2sState {
    fn from_h(h: [u32; 8]) -> Self {
        Blake2sState {
            h,
            t0: 0,
            t1: 0,
            buf: [0u8; 64],
            buf_len: 0,
        }
    }

    fn new(outlen: usize) -> Self {
        Self::from_h(iv_from_param_s(&param_s(
            outlen as u8,
            0,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
        )))
    }

    /// Keyed init: the key is processed as a zero-padded first block.
    fn with_key(outlen: usize, key: &[u8]) -> Self {
        let mut s = Self::from_h(iv_from_param_s(&param_s(
            outlen as u8,
            key.len() as u8,
            1,
            1,
            0,
            0,
            0,
            0,
            0,
        )));
        let mut block = [0u8; 64];
        block[..key.len()].copy_from_slice(key);
        s.update(&block);
        s
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

// ---- Keyed BLAKE2 (MAC) ----

/// BLAKE2b in keyed mode — a MAC with a caller-chosen key and output length.
#[derive(Clone)]
pub struct Blake2bMac {
    state: Blake2bState,
    out_len: usize,
}

impl Blake2bMac {
    /// A keyed BLAKE2b producing `out_len` bytes (1..=64); `key` ≤ 64 bytes.
    pub fn new(key: &[u8], out_len: usize) -> Self {
        Blake2bMac {
            state: Blake2bState::with_key(out_len, key),
            out_len,
        }
    }
    /// Feeds message bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }
    /// Writes the `out_len`-byte tag into `out` (`out.len()` must equal the
    /// `out_len` given to [`new`](Self::new)).
    pub fn finalize_into(self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.out_len);
        self.state.finalize_into(out);
    }
    /// Consumes the MAC and checks it against `expected` in constant time.
    pub fn verify(self, expected: &[u8]) -> Choice {
        let mut buf = [0u8; 64];
        let n = self.out_len;
        self.state.finalize_into(&mut buf[..n]);
        // Fails closed if `expected.len() != out_len`.
        let eq = buf[..n].ct_eq(expected);
        super::zeroize::zero_bytes(&mut buf);
        eq
    }
}

impl Mac for Blake2bMac {
    fn update(&mut self, data: &[u8]) {
        Blake2bMac::update(self, data);
    }
    fn finalize_into(self, out: &mut [u8]) {
        Blake2bMac::finalize_into(self, out);
    }
    fn verify(self, expected: &[u8]) -> Choice {
        Blake2bMac::verify(self, expected)
    }
}

/// BLAKE2s in keyed mode — a MAC with a caller-chosen key and output length.
#[derive(Clone)]
pub struct Blake2sMac {
    state: Blake2sState,
    out_len: usize,
}

impl Blake2sMac {
    /// A keyed BLAKE2s producing `out_len` bytes (1..=32); `key` ≤ 32 bytes.
    pub fn new(key: &[u8], out_len: usize) -> Self {
        Blake2sMac {
            state: Blake2sState::with_key(out_len, key),
            out_len,
        }
    }
    /// Feeds message bytes.
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }
    /// Writes the `out_len`-byte tag into `out`.
    pub fn finalize_into(self, out: &mut [u8]) {
        debug_assert_eq!(out.len(), self.out_len);
        self.state.finalize_into(out);
    }
    /// Consumes the MAC and checks it against `expected` in constant time.
    pub fn verify(self, expected: &[u8]) -> Choice {
        let mut buf = [0u8; 32];
        let n = self.out_len;
        self.state.finalize_into(&mut buf[..n]);
        // Fails closed if `expected.len() != out_len`.
        let eq = buf[..n].ct_eq(expected);
        super::zeroize::zero_bytes(&mut buf);
        eq
    }
}

impl Mac for Blake2sMac {
    fn update(&mut self, data: &[u8]) {
        Blake2sMac::update(self, data);
    }
    fn finalize_into(self, out: &mut [u8]) {
        Blake2sMac::finalize_into(self, out);
    }
    fn verify(self, expected: &[u8]) -> Choice {
        Blake2sMac::verify(self, expected)
    }
}

// ---- BLAKE2X (extendable output) ----

/// BLAKE2Xb: an extendable-output function built on BLAKE2b. The total output
/// length is declared up front (folded into the parameter block).
#[derive(Clone)]
pub struct Blake2xb {
    state: Blake2bState,
    xof_len: u32,
}

/// Output reader for [`Blake2xb`].
#[derive(Clone)]
pub struct Blake2xbReader {
    b0: [u8; 64],
    xof_len: u32,
    pos: u32,
    node: [u8; 64],
    node_idx: u32,
    node_len: usize,
}

impl Blake2xb {
    /// A BLAKE2Xb producing `out_len` output bytes in total.
    pub fn new(out_len: usize) -> Self {
        let xof_len = out_len as u32;
        Blake2xb {
            state: Blake2bState::from_h(iv_from_param_b(&param_b(
                64, 0, 1, 1, 0, 0, xof_len, 0, 0,
            ))),
            xof_len,
        }
    }
    /// Feeds input.
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }
    /// Finalizes and returns the output reader.
    pub fn finalize_xof(self) -> Blake2xbReader {
        let mut b0 = [0u8; 64];
        self.state.finalize_into(&mut b0);
        Blake2xbReader {
            b0,
            xof_len: self.xof_len,
            pos: 0,
            node: [0u8; 64],
            node_idx: u32::MAX,
            node_len: 0,
        }
    }
    /// Finalizes and squeezes `out.len()` bytes.
    pub fn finalize_into(self, out: &mut [u8]) {
        use super::XofReader;
        self.finalize_xof().read(out);
    }
}

impl super::XofReader for Blake2xbReader {
    fn read(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            let idx = self.pos / 64;
            let within = (self.pos % 64) as usize;
            if self.node_idx != idx {
                let block_len = (self.xof_len - idx * 64).min(64) as usize;
                let h = iv_from_param_b(&param_b(
                    block_len as u8,
                    0,
                    0,
                    0,
                    64,
                    idx,
                    self.xof_len,
                    0,
                    64,
                ));
                let mut st = Blake2bState::from_h(h);
                st.update(&self.b0);
                self.node = [0u8; 64];
                st.finalize_into(&mut self.node[..block_len]);
                self.node_len = block_len;
                self.node_idx = idx;
            }
            let take = (out.len() - i).min(self.node_len - within);
            out[i..i + take].copy_from_slice(&self.node[within..within + take]);
            i += take;
            self.pos += take as u32;
        }
    }
}

/// BLAKE2Xs: an extendable-output function built on BLAKE2s.
#[derive(Clone)]
pub struct Blake2xs {
    state: Blake2sState,
    xof_len: u16,
}

/// Output reader for [`Blake2xs`].
#[derive(Clone)]
pub struct Blake2xsReader {
    b0: [u8; 32],
    xof_len: u16,
    pos: u32,
    node: [u8; 32],
    node_idx: u32,
    node_len: usize,
}

impl Blake2xs {
    /// A BLAKE2Xs producing `out_len` output bytes in total (≤ 65535).
    pub fn new(out_len: usize) -> Self {
        let xof_len = out_len as u16;
        Blake2xs {
            state: Blake2sState::from_h(iv_from_param_s(&param_s(
                32, 0, 1, 1, 0, 0, xof_len, 0, 0,
            ))),
            xof_len,
        }
    }
    /// Feeds input.
    pub fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }
    /// Finalizes and returns the output reader.
    pub fn finalize_xof(self) -> Blake2xsReader {
        let mut b0 = [0u8; 32];
        self.state.finalize_into(&mut b0);
        Blake2xsReader {
            b0,
            xof_len: self.xof_len,
            pos: 0,
            node: [0u8; 32],
            node_idx: u32::MAX,
            node_len: 0,
        }
    }
    /// Finalizes and squeezes `out.len()` bytes.
    pub fn finalize_into(self, out: &mut [u8]) {
        use super::XofReader;
        self.finalize_xof().read(out);
    }
}

impl super::XofReader for Blake2xsReader {
    fn read(&mut self, out: &mut [u8]) {
        let mut i = 0;
        while i < out.len() {
            let idx = self.pos / 32;
            let within = (self.pos % 32) as usize;
            if self.node_idx != idx {
                let block_len = (self.xof_len as u32 - idx * 32).min(32) as usize;
                let h = iv_from_param_s(&param_s(
                    block_len as u8,
                    0,
                    0,
                    0,
                    32,
                    idx,
                    self.xof_len,
                    0,
                    32,
                ));
                let mut st = Blake2sState::from_h(h);
                st.update(&self.b0);
                self.node = [0u8; 32];
                st.finalize_into(&mut self.node[..block_len]);
                self.node_len = block_len;
                self.node_idx = idx;
            }
            let take = (out.len() - i).min(self.node_len - within);
            out[i..i + take].copy_from_slice(&self.node[within..within + take]);
            i += take;
            self.pos += take as u32;
        }
    }
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

    // Official BLAKE2 keyed KAT (key = 00..3f / 00..1f, empty message).
    #[test]
    fn keyed_macs() {
        let key64: [u8; 64] = core::array::from_fn(|i| i as u8);
        let key32: [u8; 32] = core::array::from_fn(|i| i as u8);

        let mut out = [0u8; 64];
        Blake2bMac::new(&key64, 64).finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<64>(
                "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568"
            )
        );

        let mut out = [0u8; 32];
        Blake2sMac::new(&key32, 32).finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<32>("48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49")
        );
    }

    #[test]
    fn keyed_mac_verify_constant_time() {
        let key = b"a secret key";
        let msg = b"authenticate me";

        let mut tag = [0u8; 32];
        let mut m = Blake2bMac::new(key, 32);
        m.update(msg);
        m.finalize_into(&mut tag);

        let mut m = Blake2bMac::new(key, 32);
        m.update(msg);
        assert!(bool::from(m.verify(&tag)));

        let mut bad = tag;
        bad[7] ^= 0x80;
        let mut m = Blake2bMac::new(key, 32);
        m.update(msg);
        assert!(!bool::from(m.verify(&bad)));

        // Wrong length fails closed.
        let mut m = Blake2bMac::new(key, 32);
        m.update(msg);
        assert!(!bool::from(m.verify(&tag[..16])));

        // BLAKE2s MAC round-trip.
        let mut tag = [0u8; 16];
        let mut m = Blake2sMac::new(key, 16);
        m.update(msg);
        m.finalize_into(&mut tag);
        let mut m = Blake2sMac::new(key, 16);
        m.update(msg);
        assert!(bool::from(m.verify(&tag)));
    }

    // Official BLAKE2X KAT: input = 00..ff (256 bytes), 256-byte output
    // (spans several output nodes). Vectors from BLAKE2/testvectors.
    #[test]
    fn blake2x_vectors() {
        let input: [u8; 256] = core::array::from_fn(|i| i as u8);

        let mut out = [0u8; 256];
        let mut xb = Blake2xb::new(256);
        xb.update(&input);
        xb.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<256>(
                "59f8eea01a07a2670f2fe464bd755d8cde620cb4bac6006556a8663d2d9625c62fe63b6b68adba279ab287c04d3de6c4c17e6428dff30e9b2524fea1e869e42485c03a9f48af40d12d5cba0d13abac272ee36efeb8bd098ce0e1da8233ef6e6b3e96c9e05a7fedb79ae44e698640e6b8f26c43674e2c32ef17b4d7b005554ec4fd8aa1dac0f975fc888bec5bd7a06fbf29ae09f2d37c5eb7d0f67c9c77d5caf7afe681ae336fb3fccd97ecdec0348cdea4787a4e9de4df4bbfb209eeb642ce8f92730d598a71c94259e648d0a4dd89079a06c4b463ba1d175476337d553b0401d2b6f0c32639e3edcdd8c225c61e0afa5cd103b5d26a56afe3ac9462df794dc0"
            )
        );

        let mut out = [0u8; 256];
        let mut xs = Blake2xs::new(256);
        xs.update(&input);
        xs.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<256>(
                "d4a23a17b657fa3ddc2df61eefce362f048b9dd156809062997ab9d5b1fb26b8542b1a638f517fcbad72a6fb23de0754db7bb488b75c12ac826dcced9806d7873e6b31922097ef7b42506275ccc54caf86918f9d1c6cdb9bad2bacf123c0380b2e5dc3e98de83a159ee9e10a8444832c371e5b72039b31c38621261aa04d8271598b17dba0d28c20d1858d879038485ab069bdb58733b5495f934889658ae81b7536bcf601cfcc572060863c1ff2202d2ea84c800482dbe777335002204b7c1f70133e4d8a6b7516c66bb433ad31030a7a9a9a6b9ea69890aa40662d908a5acfe8328802595f0284c51a000ce274a985823de9ee74250063a879a3787fca23a6"
            )
        );
    }
}
