//! SHA-224 and SHA-256 (FIPS 180-4), built on a shared 32-bit SHA-2 core.

use super::Digest;

/// SHA-256 initial hash value.
pub(crate) const H256: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-224 initial hash value.
const H224: [u32; 8] = [
    0xc105_9ed8,
    0x367c_d507,
    0x3070_dd17,
    0xf70e_5939,
    0xffc0_0b31,
    0x6858_1511,
    0x64f9_8fa7,
    0xbefa_4fa4,
];

/// SHA-256 round constants (first 32 bits of the fractional parts of the cube
/// roots of the first 64 primes).
pub(crate) const K256: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

/// Streaming state shared by SHA-224 and SHA-256 (they differ only in the
/// initial value and the amount of output retained).
#[derive(Clone)]
struct State256 {
    h: [u32; 8],
    /// Partial input not yet compressed (`block_len` valid bytes).
    block: [u8; 64],
    block_len: usize,
    /// Total message length in bytes.
    msg_len: u64,
}

impl State256 {
    #[inline]
    fn new(iv: [u32; 8]) -> Self {
        State256 {
            h: iv,
            block: [0u8; 64],
            block_len: 0,
            msg_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.msg_len = self.msg_len.wrapping_add(data.len() as u64);

        // Top up a partially filled block first.
        if self.block_len > 0 {
            let take = (64 - self.block_len).min(data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
            if self.block_len == 64 {
                compress256(&mut self.h, &self.block);
                self.block_len = 0;
            }
        }

        // Compress all full blocks straight from the input in one call, so the
        // hardware backend keeps the state register-resident across them.
        let full = data.len() & !63;
        if full > 0 {
            compress256_blocks(&mut self.h, &data[..full]);
            data = &data[full..];
        }

        // Stash the remainder.
        if !data.is_empty() {
            self.block[..data.len()].copy_from_slice(data);
            self.block_len = data.len();
        }
    }

    /// Best-effort wipe of the state words and partial block.
    fn zeroize(&mut self) {
        super::zeroize::zero_words(&mut self.h);
        super::zeroize::zero_bytes(&mut self.block);
        self.block_len = 0;
        self.msg_len = 0;
    }

    /// Applies SHA-2 padding and returns the final state words.
    fn finalize(mut self) -> [u32; 8] {
        let bit_len = self.msg_len.wrapping_mul(8);

        let mut i = self.block_len;
        self.block[i] = 0x80;
        i += 1;

        // Need 8 trailing bytes for the length; if they don't fit, finish this
        // block and continue in a fresh zero block.
        if i > 56 {
            while i < 64 {
                self.block[i] = 0;
                i += 1;
            }
            compress256(&mut self.h, &self.block);
            i = 0;
        }
        while i < 56 {
            self.block[i] = 0;
            i += 1;
        }
        self.block[56..64].copy_from_slice(&bit_len.to_be_bytes());
        compress256(&mut self.h, &self.block);

        self.h
    }
}

/// `u32` right-rotation as an explicit shift-or rather than
/// [`u32::rotate_right`]. In debug builds `rotate_right` lowers to a real
/// (non-inlined) `core::intrinsics::rotate_right` call, and SHA-256 issues ~440
/// of them per 64-byte block — profiling showed that intrinsic alone at ~11% of
/// XMSS keygen time. The shift-or inlines in debug; release codegen is identical.
// Intentionally NOT `x.rotate_right(n)`: that lowers to a non-inlined
// `core::intrinsics::rotate_right` call in debug builds (the whole point here).
#[inline(always)]
#[allow(clippy::manual_rotate)]
const fn rotr(x: u32, n: u32) -> u32 {
    (x >> n) | (x << (32 - n))
}

/// SHA-256 compression function: folds a 64-byte block into the state.
///
/// Dispatches to the hardware SHA-256 extension (SHA-NI on x86_64, `sha2` on
/// aarch64) when the CPU supports it, falling back to the portable software path
/// otherwise. Both produce identical state and are constant-time.
#[inline]
fn compress256(h: &mut [u32; 8], block: &[u8; 64]) {
    #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
    if super::sha_hw::sha256_supported() {
        super::sha_hw::compress256(h, block);
        return;
    }
    compress256_soft(h, block);
}

/// Compresses `data` (a whole number of 64-byte blocks) into the state.
///
/// Dispatches the entire run to the hardware backend in a single call when
/// available — the backend keeps the state in registers across all blocks,
/// avoiding the per-block spill/reload of repeated [`compress256`] calls — and
/// otherwise loops the software compression.
#[inline]
fn compress256_blocks(h: &mut [u32; 8], data: &[u8]) {
    debug_assert!(data.len().is_multiple_of(64));
    #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
    if super::sha_hw::sha256_supported() {
        super::sha_hw::compress256_blocks(h, data);
        return;
    }
    for block in data.chunks_exact(64) {
        compress256_soft(h, block.try_into().unwrap());
    }
}

/// Portable software SHA-256 compression (the constant-time fallback).
#[inline]
pub(crate) fn compress256_soft(h: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (word, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes(chunk.try_into().unwrap());
    }
    for i in 16..64 {
        let s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        let s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;

    for i in 0..64 {
        let s1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K256[i])
            .wrapping_add(w[i]);
        let s0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// Serializes `n` state words as big-endian bytes into a fresh array.
#[inline]
fn words_to_bytes<const N: usize>(h: &[u32; 8]) -> [u8; N] {
    let mut out = [0u8; N];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h.iter()) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// The SHA-256 hash function.
#[derive(Clone)]
pub struct Sha256 {
    state: State256,
}

impl Digest for Sha256 {
    type Output = [u8; 32];
    type Block = [u8; 64];
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;

    #[inline]
    fn new() -> Self {
        Sha256 {
            state: State256::new(H256),
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
        words_to_bytes(&self.state.finalize())
    }
    #[inline]
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

/// The SHA-224 hash function (SHA-256 with a different IV, truncated to 224
/// bits).
#[derive(Clone)]
pub struct Sha224 {
    state: State256,
}

impl Digest for Sha224 {
    type Output = [u8; 28];
    type Block = [u8; 64];
    const OUTPUT_LEN: usize = 28;
    const BLOCK_LEN: usize = 64;

    #[inline]
    fn new() -> Self {
        Sha224 {
            state: State256::new(H224),
        }
    }

    #[inline]
    fn zeroed_block() -> [u8; 64] {
        [0u8; 64]
    }

    #[inline]
    fn zeroed_output() -> [u8; 28] {
        [0u8; 28]
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.state.update(data);
    }

    #[inline]
    fn finalize(self) -> [u8; 28] {
        // First 7 of the 8 state words.
        words_to_bytes(&self.state.finalize())
    }
    #[inline]
    fn zeroize(&mut self) {
        self.state.zeroize();
    }
}

/// Computes the SHA-256 digest of `data`.
#[inline]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data)
}

/// Computes the SHA-224 digest of `data`.
#[inline]
pub fn sha224(data: &[u8]) -> [u8; 28] {
    Sha224::digest(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// The SHA-NI compression must produce identical state to the software
    /// path for every block, across all initial-state / message combinations
    /// exercised here. Runs only where the extension exists.
    #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
    #[test]
    fn sha256_hardware_matches_software() {
        if !super::super::sha_hw::sha256_supported() {
            return;
        }
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..2000 {
            let mut h_sw = H256;
            for (j, v) in h_sw.iter_mut().enumerate() {
                if j % 3 == 0 {
                    *v = next() as u32;
                }
            }
            let h_hw = h_sw;
            let mut block = [0u8; 64];
            next(); // advance
            for b in block.iter_mut() {
                *b = (next() >> 24) as u8;
            }
            let mut a = h_sw;
            let mut b = h_hw;
            compress256_soft(&mut a, &block);
            super::super::sha_hw::compress256(&mut b, &block);
            assert_eq!(a, b, "HW/soft mismatch");
        }
        // Multi-block kernel: the register-resident `compress256_blocks` over a
        // run of N blocks must equal looping `compress256_soft` block-by-block,
        // from an arbitrary (non-IV) start state. Directly pins the cross-block
        // Davies-Meyer feed-forward in the multi-block path.
        for nblocks in [1usize, 2, 5, 16] {
            let mut start = H256;
            for v in start.iter_mut() {
                *v ^= next() as u32;
            }
            let mut blocks = alloc::vec![0u8; nblocks * 64];
            for b in blocks.iter_mut() {
                *b = (next() >> 24) as u8;
            }
            let mut h_hw = start;
            super::super::sha_hw::compress256_blocks(&mut h_hw, &blocks);
            let mut h_sw = start;
            for chunk in blocks.chunks_exact(64) {
                compress256_soft(&mut h_sw, chunk.try_into().unwrap());
            }
            assert_eq!(h_hw, h_sw, "multi-block HW/soft mismatch (n={nblocks})");
        }

        // Multi-block consistency through the public API vs a forced-software
        // recomputation: the dispatcher (HW here) must equal the soft digest.
        let data: alloc::vec::Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let hw = sha256(&data);
        // Recompute purely in software by feeding compress256_soft directly.
        let mut h = H256;
        let mut buf = data.clone();
        let bitlen = (buf.len() as u64) * 8;
        buf.push(0x80);
        while buf.len() % 64 != 56 {
            buf.push(0);
        }
        buf.extend_from_slice(&bitlen.to_be_bytes());
        for chunk in buf.chunks_exact(64) {
            compress256_soft(&mut h, chunk.try_into().unwrap());
        }
        let mut soft = [0u8; 32];
        for (o, w) in soft.chunks_exact_mut(4).zip(h.iter()) {
            o.copy_from_slice(&w.to_be_bytes());
        }
        assert_eq!(hw, soft, "dispatched digest must equal software digest");
    }

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            sha256(b""),
            from_hex::<32>("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(
            sha256(b"abc"),
            from_hex::<32>("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        // 56 bytes: forces a second padding block.
        assert_eq!(
            sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            from_hex::<32>("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
        );
    }

    #[test]
    fn sha224_vectors() {
        assert_eq!(
            sha224(b""),
            from_hex::<28>("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f")
        );
        assert_eq!(
            sha224(b"abc"),
            from_hex::<28>("23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7")
        );
        assert_eq!(
            sha224(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            from_hex::<28>("75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525")
        );
    }

    #[test]
    fn sha256_one_million_a() {
        let mut h = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            h.finalize(),
            from_hex::<32>("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let msg: &[u8] = b"The quick brown fox jumps over the lazy dog";
        let one = sha256(msg);
        // Feed one byte at a time.
        let mut h = Sha256::new();
        for &byte in msg {
            h.update(&[byte]);
        }
        assert_eq!(h.finalize(), one);

        // Feed in awkward chunk boundaries around the block size.
        let big = [0x5au8; 200];
        let oneshot = sha256(&big);
        let mut h = Sha256::new();
        h.update(&big[..1]);
        h.update(&big[1..63]);
        h.update(&big[63..130]);
        h.update(&big[130..]);
        assert_eq!(h.finalize(), oneshot);
    }
}
