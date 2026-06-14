//! BLAKE3 — a fast tree hash and XOF.
//!
//! Implements the regular hash, keyed hashing, and context key derivation, each
//! usable as a fixed 32-byte [`Digest`] or as an
//! [`ExtendableOutput`](super::ExtendableOutput) of arbitrary length. Portable
//! reference design (no SIMD), `no_std` and allocation-free.

use super::{Digest, ExtendableOutput, XofReader};

const OUT_LEN: usize = 32;
const BLOCK_LEN: usize = 64;
// `pub(super)` items are shared with the SIMD backend in `super::blake3_simd`.
pub(super) const CHUNK_LEN: usize = 1024;

pub(super) const CHUNK_START: u32 = 1 << 0;
pub(super) const CHUNK_END: u32 = 1 << 1;
const PARENT: u32 = 1 << 2;
const ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;
const DERIVE_KEY_CONTEXT: u32 = 1 << 5;
const DERIVE_KEY_MATERIAL: u32 = 1 << 6;

pub(super) const IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

pub(super) const MSG_PERMUTATION: [usize; 16] =
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

#[inline]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

#[inline]
fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    // Columns.
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    // Diagonals.
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

#[inline]
fn permute(m: &[u32; 16]) -> [u32; 16] {
    let mut out = [0u32; 16];
    for (i, &p) in MSG_PERMUTATION.iter().enumerate() {
        out[i] = m[p];
    }
    out
}

/// The BLAKE3 compression: 7 rounds over the 16-word state, returning the full
/// 16-word result (the first 8 form a chaining value; all 16 feed the XOF).
fn compress(
    cv: &[u32; 8],
    block: &[u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
) -> [u32; 16] {
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len,
        flags,
    ];
    let mut m = *block;
    for r in 0..7 {
        round(&mut state, &m);
        if r < 6 {
            m = permute(&m);
        }
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    state
}

#[inline]
fn first8(words: [u32; 16]) -> [u32; 8] {
    let mut cv = [0u32; 8];
    cv.copy_from_slice(&words[..8]);
    cv
}

#[inline]
fn words_from_block(block: &[u8; 64]) -> [u32; 16] {
    let mut m = [0u32; 16];
    for (w, chunk) in m.iter_mut().zip(block.chunks_exact(4)) {
        *w = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    m
}

#[inline]
fn words_from_key(key: &[u8; 32]) -> [u32; 8] {
    let mut k = [0u32; 8];
    for (w, chunk) in k.iter_mut().zip(key.chunks_exact(4)) {
        *w = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    k
}

/// A finalized node, expandable into the output stream.
#[derive(Clone)]
struct Output {
    input_cv: [u32; 8],
    block: [u32; 16],
    counter: u64,
    block_len: u32,
    flags: u32,
}

impl Output {
    fn chaining_value(&self) -> [u32; 8] {
        first8(compress(
            &self.input_cv,
            &self.block,
            self.counter,
            self.block_len,
            self.flags,
        ))
    }
}

/// The state for the chunk currently being absorbed.
#[derive(Clone)]
struct ChunkState {
    cv: [u32; 8],
    chunk_counter: u64,
    block: [u8; 64],
    block_len: u8,
    blocks_compressed: u8,
    flags: u32,
}

impl ChunkState {
    fn new(key: [u32; 8], chunk_counter: u64, flags: u32) -> Self {
        ChunkState {
            cv: key,
            chunk_counter,
            block: [0u8; 64],
            block_len: 0,
            blocks_compressed: 0,
            flags,
        }
    }

    fn len(&self) -> usize {
        BLOCK_LEN * self.blocks_compressed as usize + self.block_len as usize
    }

    fn start_flag(&self) -> u32 {
        if self.blocks_compressed == 0 {
            CHUNK_START
        } else {
            0
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let m = words_from_block(&self.block);
                self.cv = first8(compress(
                    &self.cv,
                    &m,
                    self.chunk_counter,
                    BLOCK_LEN as u32,
                    self.flags | self.start_flag(),
                ));
                self.blocks_compressed += 1;
                self.block = [0u8; 64];
                self.block_len = 0;
            }
            let want = BLOCK_LEN - self.block_len as usize;
            let take = want.min(input.len());
            self.block[self.block_len as usize..self.block_len as usize + take]
                .copy_from_slice(&input[..take]);
            self.block_len += take as u8;
            input = &input[take..];
        }
    }

    fn output(&self) -> Output {
        Output {
            input_cv: self.cv,
            block: words_from_block(&self.block),
            counter: self.chunk_counter,
            block_len: self.block_len as u32,
            flags: self.flags | self.start_flag() | CHUNK_END,
        }
    }

    fn zeroize(&mut self) {
        super::zeroize::zero_words(&mut self.cv);
        super::zeroize::zero_bytes(&mut self.block);
        self.block_len = 0;
        self.blocks_compressed = 0;
    }
}

fn parent_output(left: [u32; 8], right: [u32; 8], key: [u32; 8], flags: u32) -> Output {
    let mut block = [0u32; 16];
    block[..8].copy_from_slice(&left);
    block[8..].copy_from_slice(&right);
    Output {
        input_cv: key,
        block,
        counter: 0,
        block_len: BLOCK_LEN as u32,
        flags: flags | PARENT,
    }
}

fn parent_cv(left: [u32; 8], right: [u32; 8], key: [u32; 8], flags: u32) -> [u32; 8] {
    parent_output(left, right, key, flags).chaining_value()
}

/// The BLAKE3 hasher: a regular, keyed, or key-derivation hash, finalizable as
/// a fixed 32-byte digest or an arbitrary-length stream.
#[derive(Clone)]
pub struct Blake3 {
    chunk_state: ChunkState,
    key: [u32; 8],
    cv_stack: [[u32; 8]; 54],
    cv_stack_len: usize,
    flags: u32,
}

impl Blake3 {
    fn from_key_words(key: [u32; 8], flags: u32) -> Self {
        Blake3 {
            chunk_state: ChunkState::new(key, 0, flags),
            key,
            cv_stack: [[0u32; 8]; 54],
            cv_stack_len: 0,
            flags,
        }
    }

    /// A regular (unkeyed) BLAKE3 hasher.
    pub fn new() -> Self {
        Self::from_key_words(IV, 0)
    }

    /// A keyed BLAKE3 hasher (a 256-bit MAC / PRF).
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self::from_key_words(words_from_key(key), KEYED_HASH)
    }

    /// A BLAKE3 key-derivation hasher bound to `context`. The output is key
    /// material derived from the input under that context string.
    pub fn new_derive_key(context: &str) -> Self {
        let mut ctx = Self::from_key_words(IV, DERIVE_KEY_CONTEXT);
        ctx.update(context.as_bytes());
        let mut context_key = [0u8; 32];
        ctx.finalize_into_slice(&mut context_key);
        Self::from_key_words(words_from_key(&context_key), DERIVE_KEY_MATERIAL)
    }

    fn push_cv(&mut self, cv: [u32; 8]) {
        self.cv_stack[self.cv_stack_len] = cv;
        self.cv_stack_len += 1;
    }

    fn add_chunk_cv(&mut self, mut new_cv: [u32; 8], mut total_chunks: u64) {
        // Merge with the right number of subtrees: as many trailing-zero bits of
        // `total_chunks` as there are completed left subtrees to combine.
        while total_chunks & 1 == 0 {
            self.cv_stack_len -= 1;
            new_cv = parent_cv(
                self.cv_stack[self.cv_stack_len],
                new_cv,
                self.key,
                self.flags,
            );
            total_chunks >>= 1;
        }
        self.push_cv(new_cv);
    }

    /// Feeds input.
    pub fn update(&mut self, mut input: &[u8]) {
        // SIMD fast path: on a fresh chunk boundary with more than `DEGREE` full
        // chunks still ahead (the strict `>` keeps at least one byte, so none of
        // the batched chunks can be the final/root chunk), hash `DEGREE` chunks
        // at once and feed their chaining values into the tree. The scalar loop
        // below owns the last — possibly partial, possibly root — chunk.
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        {
            use super::blake3_simd::{DEGREE, hash_chunks8, supported};
            const BULK: usize = DEGREE * CHUNK_LEN;
            if supported() {
                while self.chunk_state.len() == 0 && input.len() > BULK {
                    let base = self.chunk_state.chunk_counter;
                    let cvs = hash_chunks8(&input[..BULK], &self.key, base, self.flags);
                    for (k, cv) in cvs.iter().enumerate() {
                        self.add_chunk_cv(*cv, base + k as u64 + 1);
                    }
                    // The batched chunks are absorbed directly; advance the
                    // (still-empty) chunk_state to the next chunk index.
                    self.chunk_state.chunk_counter = base + DEGREE as u64;
                    input = &input[BULK..];
                }
            }
        }

        while !input.is_empty() {
            if self.chunk_state.len() == CHUNK_LEN {
                let chunk_cv = self.chunk_state.output().chaining_value();
                let total_chunks = self.chunk_state.chunk_counter + 1;
                self.add_chunk_cv(chunk_cv, total_chunks);
                self.chunk_state = ChunkState::new(self.key, total_chunks, self.flags);
            }
            let want = CHUNK_LEN - self.chunk_state.len();
            let take = want.min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
        }
    }

    /// Builds the root output node by folding the chaining-value stack.
    fn root_output(&self) -> Output {
        let mut output = self.chunk_state.output();
        let mut remaining = self.cv_stack_len;
        while remaining > 0 {
            remaining -= 1;
            output = parent_output(
                self.cv_stack[remaining],
                output.chaining_value(),
                self.key,
                self.flags,
            );
        }
        output
    }

    fn finalize_into_slice(&self, out: &mut [u8]) {
        Blake3Reader::new(self.root_output()).read(out);
    }

    /// The standard 32-byte digest.
    pub fn finalize(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.finalize_into_slice(&mut out);
        out
    }

    /// Finalizes into an arbitrary-length output reader.
    pub fn finalize_xof(self) -> Blake3Reader {
        Blake3Reader::new(self.root_output())
    }

    /// One-shot regular hash.
    pub fn hash(data: &[u8]) -> [u8; 32] {
        let mut h = Self::new();
        h.update(data);
        h.finalize()
    }

    /// Best-effort wipe of the key and tree state.
    fn zeroize(&mut self) {
        self.chunk_state.zeroize();
        super::zeroize::zero_words(&mut self.key);
        for cv in self.cv_stack.iter_mut() {
            super::zeroize::zero_words(cv);
        }
        self.cv_stack_len = 0;
    }
}

impl Drop for Blake3 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl Default for Blake3 {
    fn default() -> Self {
        Self::new()
    }
}

/// The output stream of a finalized [`Blake3`] hasher.
#[derive(Clone)]
pub struct Blake3Reader {
    output: Output,
    block: [u8; 64],
    block_counter: u64,
    offset: usize,
}

impl Blake3Reader {
    fn new(output: Output) -> Self {
        Blake3Reader {
            output,
            block: [0u8; 64],
            block_counter: 0,
            offset: BLOCK_LEN, // force a fill on first read
        }
    }

    fn fill(&mut self) {
        let words = compress(
            &self.output.input_cv,
            &self.output.block,
            self.block_counter,
            self.output.block_len,
            self.output.flags | ROOT,
        );
        for (chunk, w) in self.block.chunks_exact_mut(4).zip(words.iter()) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        self.block_counter += 1;
        self.offset = 0;
    }
}

impl XofReader for Blake3Reader {
    fn read(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            if self.offset == BLOCK_LEN {
                self.fill();
            }
            *b = self.block[self.offset];
            self.offset += 1;
        }
    }
}

impl Digest for Blake3 {
    type Output = [u8; OUT_LEN];
    type Block = [u8; BLOCK_LEN];
    const OUTPUT_LEN: usize = OUT_LEN;
    const BLOCK_LEN: usize = BLOCK_LEN;

    fn new() -> Self {
        Blake3::from_key_words(IV, 0)
    }
    fn zeroed_block() -> [u8; BLOCK_LEN] {
        [0u8; BLOCK_LEN]
    }
    fn zeroed_output() -> [u8; OUT_LEN] {
        [0u8; OUT_LEN]
    }
    fn update(&mut self, data: &[u8]) {
        Blake3::update(self, data);
    }
    fn finalize(self) -> [u8; OUT_LEN] {
        Blake3::finalize(&self)
    }
    fn zeroize(&mut self) {
        Blake3::zeroize(self);
    }
}

impl ExtendableOutput for Blake3 {
    type Reader = Blake3Reader;
    const BLOCK_LEN: usize = BLOCK_LEN;

    fn new() -> Self {
        Blake3::from_key_words(IV, 0)
    }
    fn update(&mut self, data: &[u8]) {
        Blake3::update(self, data);
    }
    fn finalize_xof(self) -> Blake3Reader {
        Blake3::finalize_xof(self)
    }
}

/// Computes the 32-byte BLAKE3 digest of `data`.
#[inline]
pub fn blake3(data: &[u8]) -> [u8; 32] {
    Blake3::hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // Official BLAKE3 `test_vectors.json` parameters.
    const KEY: &[u8; 32] = b"whats the Elvish word for friend";
    const CONTEXT: &str = "BLAKE3 2019-12-27 16:29:52 test vectors context";

    /// Fills `buf` with the official test input pattern `input[i] = i % 251`.
    fn fill_input(buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
    }

    /// Reads a 64-byte XOF prefix in two pieces, to exercise incremental reads.
    fn read64(mut h: Blake3, input: &[u8]) -> [u8; 64] {
        h.update(input);
        let mut out = [0u8; 64];
        let mut r = h.finalize_xof();
        r.read(&mut out[..13]);
        r.read(&mut out[13..]);
        out
    }

    /// Checks the three modes against 64-byte prefixes of the reference output.
    fn check(input: &[u8], hash: &str, keyed: &str, derive: &str) {
        assert_eq!(read64(Blake3::new(), input), from_hex::<64>(hash));
        assert_eq!(read64(Blake3::new_keyed(KEY), input), from_hex::<64>(keyed));
        assert_eq!(
            read64(Blake3::new_derive_key(CONTEXT), input),
            from_hex::<64>(derive)
        );
    }

    #[test]
    fn empty_digest() {
        assert_eq!(
            blake3(b""),
            from_hex::<32>("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
        );
    }

    #[test]
    fn official_vectors() {
        let mut buf = [0u8; 2049];
        fill_input(&mut buf);

        check(
            &buf[..0],
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a",
            "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26b18171a2f22a4b94822c701f107153dba24918c4bae4d2945c20ece13387627d",
            "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d905630c8be290dfcf3e6842f13bddd573c098c3f17361f1f206b8cad9d088aa4",
        );
        check(
            &buf[..1],
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213c3a6cb8bf623e20cdb535f8d1a5ffb86342d9c0b64aca3bce1d31f60adfa137b",
            "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b6568c0490609413006fbd428eb3fd14e7756d90f73a4725fad147f7bf70fd61c",
            "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c5827b91bf889b6b97c5477f535361caefca0b5d8c4746441c576171119331589",
        );
        check(
            &buf[..1024],
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af71cf8107265ecdaf8505b95d8fcec83a98a6a96ea5109d2c179c47a387ffbb404",
            "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4a78bc838c72852d4f49c864acb7adafe2478e824afe51c8919d06168414c265f",
            "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a6896843027066c23b601d3ddfb391e90d5c8eccdef4ae2a264bce9e612ba15e2bc9d654af148",
        );
        check(
            &buf[..1025],
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bf",
            "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69362396b77fdc0d2634a552970843722066c3c15902ae5097e00ff53f1e116f1c",
            "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb5d31013a167509e9066273ab6e2123bc835b408b067d88f96addb550d96b6852",
        );
        check(
            &buf[..2049],
            "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b687952256303096de31d71d74103403822a2e0bc1eb193e7aecc9643a76b7bbc0c9f9c52e8783",
            "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5f9a88abfefdfa1e00b418971f2b39c64ca621e8eb37fceac57fd0c8fc8e117d4",
            "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf27316d8e9e79081a80b046b60f6a263616f33ca464bd78d79fa18200d06c7fc9bff",
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let mut buf = [0u8; 3000];
        fill_input(&mut buf);
        let oneshot = blake3(&buf);

        let mut h = Blake3::new();
        h.update(&buf[..1]);
        h.update(&buf[1..64]);
        h.update(&buf[64..1024]);
        h.update(&buf[1024..1025]);
        h.update(&buf[1025..]);
        assert_eq!(h.finalize(), oneshot);
    }

    /// Deterministic xorshift byte generator for the SIMD differential tests.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    fn xorshift(seed: u64) -> impl FnMut() -> u8 {
        let mut s = seed | 1;
        move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        }
    }

    /// The AVX2 8-way chunk kernel must produce, for every lane, exactly the
    /// chaining value the scalar `ChunkState` produces for that chunk — across
    /// random data, several counter bases, and every keying mode.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn simd_chunk_kernel_matches_scalar() {
        use super::super::blake3_simd::{hash_chunks8, supported};
        if !supported() {
            return;
        }
        let mut next = xorshift(0x1234_5678_9abc_def0);
        let mut key = [0u32; 8];
        for w in key.iter_mut() {
            *w = u32::from_le_bytes([next(), next(), next(), next()]);
        }

        for &(k, flags) in &[(IV, 0u32), (key, KEYED_HASH), (key, DERIVE_KEY_MATERIAL)] {
            for &base in &[0u64, 1, 7, 8, 1_000_000, (1u64 << 32) - 3] {
                let mut buf = alloc::vec![0u8; 8 * CHUNK_LEN];
                for b in buf.iter_mut() {
                    *b = next();
                }
                let simd = hash_chunks8(&buf, &k, base, flags);
                for (lane, got) in simd.iter().enumerate() {
                    let mut cs = ChunkState::new(k, base + lane as u64, flags);
                    cs.update(&buf[lane * CHUNK_LEN..(lane + 1) * CHUNK_LEN]);
                    let want = cs.output().chaining_value();
                    assert_eq!(*got, want, "lane {lane}, base {base}, flags {flags}");
                }
            }
        }
    }

    /// End-to-end: hashing a large buffer through the public API (which takes
    /// the SIMD bulk path for inputs above 8 chunks) must equal feeding the same
    /// bytes in sub-8-KiB pieces (which never triggers the bulk path), for every
    /// hasher mode. Validates the bulk-path counter / tree-merge integration on
    /// top of the kernel.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn simd_bulk_matches_scalar_end_to_end() {
        use super::super::blake3_simd::supported;
        if !supported() {
            return;
        }
        // Sizes around chunk-batch boundaries plus a large value, including a
        // partial trailing chunk.
        for &n in &[8 * CHUNK_LEN + 1, 24 * CHUNK_LEN + 5, 97 * CHUNK_LEN + 672] {
            let mut buf = alloc::vec![0u8; n];
            fill_input(&mut buf);

            #[allow(clippy::type_complexity)]
            let mk: [(fn() -> Blake3, &str); 3] = [
                (|| Blake3::new(), "hash"),
                (|| Blake3::new_keyed(KEY), "keyed"),
                (|| Blake3::new_derive_key(CONTEXT), "derive"),
            ];
            for (ctor, name) in mk {
                // Bulk path (single update of the whole buffer).
                let mut a = ctor();
                a.update(&buf);
                let simd = a.finalize();
                // Scalar reference: feed in 4000-byte pieces (< 8 KiB each, so
                // the bulk fast path never fires on a fresh chunk boundary).
                let mut b = ctor();
                for piece in buf.chunks(4000) {
                    b.update(piece);
                }
                let scalar = b.finalize();
                assert_eq!(simd, scalar, "mode {name}, n {n}");
            }
        }
    }
}
