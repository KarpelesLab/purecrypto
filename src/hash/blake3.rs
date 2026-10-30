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
pub(super) const PARENT: u32 = 1 << 2;
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

/// The message word order of each of the seven rounds: round `r` reads
/// `m[MSG_SCHEDULE[r][k]]` where the reference applies its message permutation
/// (`[2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]`, row 1 here) `r`
/// times. Indexed only by constants from the unrolled compressions, scalar
/// and SIMD alike, so it is a compile-time table: no message word moves
/// between rounds.
pub(super) const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
];

#[inline(always)]
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

/// Round `R` (0..7) over the unpermuted message words.
#[inline(always)]
fn round<const R: usize>(state: &mut [u32; 16], m: &[u32; 16]) {
    let s = &MSG_SCHEDULE[R];
    // Columns.
    g(state, 0, 4, 8, 12, m[s[0]], m[s[1]]);
    g(state, 1, 5, 9, 13, m[s[2]], m[s[3]]);
    g(state, 2, 6, 10, 14, m[s[4]], m[s[5]]);
    g(state, 3, 7, 11, 15, m[s[6]], m[s[7]]);
    // Diagonals.
    g(state, 0, 5, 10, 15, m[s[8]], m[s[9]]);
    g(state, 1, 6, 11, 12, m[s[10]], m[s[11]]);
    g(state, 2, 7, 8, 13, m[s[12]], m[s[13]]);
    g(state, 3, 4, 9, 14, m[s[14]], m[s[15]]);
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
    round::<0>(&mut state, block);
    round::<1>(&mut state, block);
    round::<2>(&mut state, block);
    round::<3>(&mut state, block);
    round::<4>(&mut state, block);
    round::<5>(&mut state, block);
    round::<6>(&mut state, block);
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

    /// Folds one full block into the chaining value.
    #[inline]
    fn compress_block(&mut self, block: &[u8; 64]) {
        let m = words_from_block(block);
        self.cv = first8(compress(
            &self.cv,
            &m,
            self.chunk_counter,
            BLOCK_LEN as u32,
            self.flags | self.start_flag(),
        ));
        self.blocks_compressed += 1;
    }

    fn update(&mut self, mut input: &[u8]) {
        // The last block of a chunk is never compressed here (its output needs
        // `CHUNK_END`), so a full buffered block is only folded once more input
        // arrives, and the direct path below stops while a block or less is
        // left. The buffer's unused tail is kept zero (`output` reads all 64
        // bytes), re-zeroed only when a fresh partial block starts.
        while !input.is_empty() {
            if self.block_len as usize == BLOCK_LEN {
                let block = self.block;
                self.compress_block(&block);
                self.block_len = 0;
            }
            if self.block_len == 0 {
                // Full blocks straight from the input slice: no copy into the
                // buffer and no re-zeroing of it per block.
                while input.len() > BLOCK_LEN {
                    let (block, rest) = input.split_at(BLOCK_LEN);
                    self.compress_block(block.try_into().expect("BLOCK_LEN bytes"));
                    input = rest;
                }
                if input.len() < BLOCK_LEN {
                    self.block[input.len()..].fill(0);
                }
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

/// The deepest the chunk tree can get: 2^54 chunks of 1 KiB is the 2^64-byte
/// input limit. The chaining-value stack holds one more entry than this, as
/// merging is lazy (see [`Blake3::push_cv`]).
const MAX_DEPTH: usize = 54;

/// Chunks hashed per pass of the bulk path in [`Blake3::update`]: a whole
/// number of the widest kernel's lanes. Larger batches mean fewer subtree
/// pushes and scalar stack merges per byte; past 128 the gain stops, while
/// the scratch on the stack (`MAX_BATCH * 48` bytes, here 6 KiB) keeps
/// growing.
#[cfg(any(
    target_arch = "x86_64",
    all(feature = "std", target_arch = "aarch64", target_endian = "little")
))]
const MAX_BATCH: usize = 128;

/// Without SIMD kernels a batch does the same compressions as chunk-by-chunk
/// hashing, so it is kept small for the small stacks of the targets
/// concerned (`no_std`, wasm).
#[cfg(not(any(
    target_arch = "x86_64",
    all(feature = "std", target_arch = "aarch64", target_endian = "little")
)))]
const MAX_BATCH: usize = 8;

/// Inputs (chunks or parents) the next kernel pass should take out of
/// `left`, or 0 to take one on the scalar path. A lone input stays scalar,
/// since a kernel pass costs the same however few of its lanes are used —
/// which is also why an AVX-512 pass beats AVX2 for anything over 8.
fn simd_lanes(left: usize) -> usize {
    if left < 2 {
        return 0;
    }
    #[cfg(target_arch = "x86_64")]
    {
        use super::blake3_simd::{DEGREE, DEGREE16, supported, supported16};
        if supported16() && (left > DEGREE || !supported()) {
            return left.min(DEGREE16);
        }
        if supported() {
            return left.min(DEGREE);
        }
    }
    #[cfg(all(feature = "std", target_arch = "aarch64", target_endian = "little"))]
    {
        use super::blake3_neon::{DEGREE, supported};
        if supported() {
            return left.min(DEGREE);
        }
    }
    0
}

/// One kernel pass over the `out.len()` chunks [`simd_lanes`] chose.
#[cfg(target_arch = "x86_64")]
fn simd_chunks(input: &[u8], key: &[u32; 8], base: u64, flags: u32, out: &mut [[u32; 8]]) {
    use super::blake3_simd::{DEGREE, hash_chunks8, hash_chunks16, supported};
    if out.len() > DEGREE || !supported() {
        hash_chunks16(input, key, base, flags, out);
    } else {
        hash_chunks8(input, key, base, flags, out);
    }
}

/// One kernel pass over the `out.len()` parents [`simd_lanes`] chose.
#[cfg(target_arch = "x86_64")]
fn simd_parents(cvs: &[[u32; 8]], key: &[u32; 8], flags: u32, out: &mut [[u32; 8]]) {
    use super::blake3_simd::{DEGREE, hash_parents8, hash_parents16, supported};
    if out.len() > DEGREE || !supported() {
        hash_parents16(cvs, key, flags, out);
    } else {
        hash_parents8(cvs, key, flags, out);
    }
}

#[cfg(all(feature = "std", target_arch = "aarch64", target_endian = "little"))]
use super::blake3_neon::{hash_chunks4 as simd_chunks, hash_parents4 as simd_parents};

// No kernels here: `simd_lanes` is always 0, so these are never reached.
#[cfg(not(any(
    target_arch = "x86_64",
    all(feature = "std", target_arch = "aarch64", target_endian = "little")
)))]
fn simd_chunks(_: &[u8], _: &[u32; 8], _: u64, _: u32, _: &mut [[u32; 8]]) {
    unreachable!("blake3: no SIMD backend on this target")
}
#[cfg(not(any(
    target_arch = "x86_64",
    all(feature = "std", target_arch = "aarch64", target_endian = "little")
)))]
fn simd_parents(_: &[[u32; 8]], _: &[u32; 8], _: u32, _: &mut [[u32; 8]]) {
    unreachable!("blake3: no SIMD backend on this target")
}

/// Chaining values of the `out.len()` consecutive full chunks in `input`,
/// chunk `k` at counter `base + k`, on the widest kernel available.
fn chunk_cvs(input: &[u8], key: &[u32; 8], base: u64, flags: u32, out: &mut [[u32; 8]]) {
    let mut done = 0;
    while done < out.len() {
        let at = base + done as u64;
        let src = &input[done * CHUNK_LEN..];
        let take = simd_lanes(out.len() - done);
        if take > 0 {
            simd_chunks(
                &src[..take * CHUNK_LEN],
                key,
                at,
                flags,
                &mut out[done..done + take],
            );
            done += take;
        } else {
            let mut cs = ChunkState::new(*key, at, flags);
            cs.update(&src[..CHUNK_LEN]);
            out[done] = cs.output().chaining_value();
            cs.zeroize();
            done += 1;
        }
    }
}

/// Parent chaining values: `out[k]` is the parent of `cvs[2k]` and
/// `cvs[2k + 1]`, on the widest kernel available.
fn parent_cvs(cvs: &[[u32; 8]], key: &[u32; 8], flags: u32, out: &mut [[u32; 8]]) {
    let mut done = 0;
    while done < out.len() {
        let src = &cvs[2 * done..];
        let take = simd_lanes(out.len() - done);
        if take > 0 {
            simd_parents(&src[..2 * take], key, flags, &mut out[done..done + take]);
            done += take;
        } else {
            out[done] = parent_cv(src[0], src[1], *key, flags);
            done += 1;
        }
    }
}

/// Collapses the chaining values of a power-of-two run of at least two chunks
/// (a complete, aligned subtree) to the two children of the subtree's root,
/// one tree level per parent pass. `cvs` is used as scratch.
fn subtree_children(cvs: &mut [[u32; 8]], key: &[u32; 8], flags: u32) -> [[u32; 8]; 2] {
    debug_assert!(cvs.len().is_power_of_two() && (2..=MAX_BATCH).contains(&cvs.len()));
    let mut len = cvs.len();
    let mut next = [[0u32; 8]; MAX_BATCH / 2];
    while len > 2 {
        let half = len / 2;
        parent_cvs(&cvs[..len], key, flags, &mut next[..half]);
        cvs[..half].copy_from_slice(&next[..half]);
        len = half;
    }
    super::zeroize::zero_words(next[..cvs.len() / 2].as_flattened_mut());
    [cvs[0], cvs[1]]
}

/// The BLAKE3 hasher: a regular, keyed, or key-derivation hash, finalizable as
/// a fixed 32-byte digest or an arbitrary-length stream.
#[derive(Clone)]
pub struct Blake3 {
    chunk_state: ChunkState,
    key: [u32; 8],
    cv_stack: [[u32; 8]; MAX_DEPTH + 1],
    cv_stack_len: usize,
    flags: u32,
}

impl Blake3 {
    fn from_key_words(key: [u32; 8], flags: u32) -> Self {
        Blake3 {
            chunk_state: ChunkState::new(key, 0, flags),
            key,
            cv_stack: [[0u32; 8]; MAX_DEPTH + 1],
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
        let hasher = Self::from_key_words(words_from_key(&context_key), DERIVE_KEY_MATERIAL);
        // The context key is key material; it now lives only in the hasher's
        // key words (wiped on drop), so clear the stack copy.
        super::zeroize::zero_bytes(&mut context_key);
        hasher
    }

    /// Pushes the chaining value of the subtree starting at chunk
    /// `chunk_counter`, first merging every completed subtree to its left.
    ///
    /// Merging is lazy: the stack keeps one entry per set bit of the chunk
    /// count *before* the new subtree, so the newest entry is never merged
    /// until more input follows it. That keeps the last two entries apart
    /// when the input ends on a subtree boundary, where their parent is the
    /// root and needs the `ROOT` flag.
    fn push_cv(&mut self, cv: [u32; 8], chunk_counter: u64) {
        self.merge_cv_stack(chunk_counter);
        self.cv_stack[self.cv_stack_len] = cv;
        self.cv_stack_len += 1;
    }

    /// Merges completed subtrees on the stack until it holds one entry per
    /// set bit of `chunk_counter`, the number of chunks before the next one.
    fn merge_cv_stack(&mut self, chunk_counter: u64) {
        let keep = chunk_counter.count_ones() as usize;
        while self.cv_stack_len > keep {
            let right = self.cv_stack[self.cv_stack_len - 1];
            let left = self.cv_stack[self.cv_stack_len - 2];
            self.cv_stack_len -= 1;
            self.cv_stack[self.cv_stack_len - 1] = parent_cv(left, right, self.key, self.flags);
        }
    }

    /// Feeds input.
    pub fn update(&mut self, mut input: &[u8]) {
        // Top up a partially filled chunk. It is pushed only once more input
        // follows it, since the last chunk may be the root.
        if self.chunk_state.len() > 0 {
            let take = (CHUNK_LEN - self.chunk_state.len()).min(input.len());
            self.chunk_state.update(&input[..take]);
            input = &input[take..];
            if input.is_empty() {
                return;
            }
            let counter = self.chunk_state.chunk_counter;
            let cv = self.chunk_state.output().chaining_value();
            self.push_cv(cv, counter);
            self.chunk_state = ChunkState::new(self.key, counter + 1, self.flags);
        }

        // Bulk path, on a chunk boundary with more than one chunk ahead: hash
        // the largest power-of-two run of whole chunks that fits, is aligned
        // to its own size and is at most `MAX_BATCH`, as one subtree. Several
        // chunks are pushed as the subtree's two children rather than its
        // root, so the run may end the input: if it does, `root_output` makes
        // their parent the root. A lone chunk always has input after it.
        while input.len() > CHUNK_LEN {
            let base = self.chunk_state.chunk_counter;
            let whole = (input.len() / CHUNK_LEN).min(MAX_BATCH);
            let mut size = 1usize << (usize::BITS - 1 - whole.leading_zeros());
            if base != 0 {
                size = size.min(1 << base.trailing_zeros().min(usize::BITS - 1));
            }
            let mut cvs = [[0u32; 8]; MAX_BATCH];
            chunk_cvs(
                &input[..size * CHUNK_LEN],
                &self.key,
                base,
                self.flags,
                &mut cvs[..size],
            );
            if size == 1 {
                self.push_cv(cvs[0], base);
            } else {
                let [left, right] = subtree_children(&mut cvs[..size], &self.key, self.flags);
                self.push_cv(left, base);
                self.push_cv(right, base + size as u64 / 2);
            }
            super::zeroize::zero_words(cvs[..size].as_flattened_mut());
            self.chunk_state.chunk_counter = base + size as u64;
            input = &input[size * CHUNK_LEN..];
        }

        // At most one chunk left: buffer it. Once it holds input, nothing on
        // the stack can be a child of the root, so finish the merges that
        // `push_cv` deferred: `root_output` folds the stack as one entry per
        // completed subtree.
        if !input.is_empty() {
            self.chunk_state.update(input);
            self.merge_cv_stack(self.chunk_state.chunk_counter);
        }
    }

    /// Builds the root output node by folding the chaining-value stack.
    fn root_output(&self) -> Output {
        // An input that ended on a subtree boundary leaves the chunk state
        // empty, and the last two stack entries are the root's children.
        let (mut output, mut remaining) = if self.chunk_state.len() > 0 || self.cv_stack_len == 0 {
            (self.chunk_state.output(), self.cv_stack_len)
        } else {
            let n = self.cv_stack_len;
            let root = parent_output(
                self.cv_stack[n - 2],
                self.cv_stack[n - 1],
                self.key,
                self.flags,
            );
            (root, n - 2)
        };
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
        // One root compression written straight out, rather than building a
        // `Blake3Reader` (its own block buffer, fill and drop-wipe) for a
        // single block's worth of output.
        let mut output = self.root_output();
        let mut words = compress(
            &output.input_cv,
            &output.block,
            0,
            output.block_len,
            output.flags | ROOT,
        );
        let mut out = [0u8; 32];
        for (chunk, w) in out.chunks_exact_mut(4).zip(words.iter()) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        // The root node is key material in the keyed modes, and the full
        // 16-word state holds the next XOF block beyond the digest.
        super::zeroize::zero_words(&mut words);
        super::zeroize::zero_words(&mut output.input_cv);
        super::zeroize::zero_words(&mut output.block);
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
        // Only the live entries ever held anything; the rest of the 54-entry
        // stack is still the zeros it was built with, and wiping all 1.7 KB
        // with volatile stores dominated the cost of hashing a short message.
        let used = self.cv_stack_len.min(self.cv_stack.len());
        super::zeroize::zero_words(self.cv_stack[..used].as_flattened_mut());
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
    fn read(&mut self, mut out: &mut [u8]) {
        while !out.is_empty() {
            if self.offset == BLOCK_LEN {
                self.fill();
            }
            let n = (BLOCK_LEN - self.offset).min(out.len());
            let (head, rest) = out.split_at_mut(n);
            head.copy_from_slice(&self.block[self.offset..self.offset + n]);
            self.offset += n;
            out = rest;
        }
    }
}

impl Drop for Blake3Reader {
    fn drop(&mut self) {
        // The squeezed-output block buffer and the root output state it is
        // derived from are key material; wipe them, matching the rest of the
        // crate's best-effort zeroization.
        super::zeroize::zero_bytes(&mut self.block);
        super::zeroize::zero_words(&mut self.output.input_cv);
        super::zeroize::zero_words(&mut self.output.block);
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

    /// The official vectors past two chunks, whole and split at chunk and
    /// subtree boundaries, pin every subtree shape of the bulk path —
    /// including inputs that end on a subtree boundary, whose root is the
    /// parent of the last two stack entries — to the reference output.
    #[test]
    fn official_vectors_multi_chunk() {
        const CASES: &[(usize, &str, &str, &str)] = &[
            (
                3072,
                "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd29a3f6b0b978d6608335c09dc94ccf682f9951cdfc501bfe47b9c9189a6fc7b40",
                "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df19177022f302d0529e4174cc507c463671217975e81dab02b8fdeb0d7ccc7568dd2257",
                "050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b3604131bbd6e3ba573b6dd682fa0a63e5b165d39fc43a625d00207607a2bfeb6",
            ),
            (
                3073,
                "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd39a27ae3b79d68d89da9bf25bc27139ae65a324918a5f9b7828181e52cf373c84",
                "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a96d6da3fe985054d3478865be9a092250839a697bbda74e279e8a9e69f0025e4",
                "72613c9ec9ff7e40f8f5c173784c532ad852e827dba2bf85b2ab4b76f7079081576288e552647a9d86481c2cae75c2dd4e7c5195fb9ada1ef50e9c5098c249d7",
            ),
            (
                4096,
                "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e9690289e9409ddb1b99768eafe1623da896faf7e1114bebeadc1be30829b6f8af70",
                "befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0bbb64a36edb564e01e4b4aaf3b060092a6b838bea44afebd2deb8298fa562b7b",
                "1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9d78038f7b198596c6cc4a9ccf93223c08722d684f240ff6569075ed81591fd93",
            ),
            (
                4097,
                "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb99505f91b0b5600a11251652eacfa9497b31cd3c409ce2e45cfe6c0a016967316c4",
                "00df940cd36bb9fa7cbbc3556744e0dbc8191401afe70520ba292ee3ca80abbc606db4976cfdd266ae0abf667d9481831ff12e0caa268e7d3e57260c0824115a",
                "aca51029626b55fda7117b42a7c211f8c6e9ba4fe5b7a8ca922f34299500ead8a897f66a400fed9198fd61dd2d58d382458e64e100128075fc54b860934e8de2",
            ),
            (
                5120,
                "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833acc61c8fdc114a2010ce8038c853e121e1544985133fccdd0a2d507e8e615e61",
                "2c493e48e9b9bf31e0553a22b23503c0a3388f035cece68eb438d22fa1943e209b4dc9209cd80ce7c1f7c9a744658e7e288465717ae6e56d5463d4f80cdb2ef5",
                "7a7acac8a02adcf3038d74cdd1d34527de8a0fcc0ee3399d1262397ce5817f6055d0cefd84d9d57fe792d65a278fd20384ac6c30fdb340092f1a74a92ace99c4",
            ),
            (
                5121,
                "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff96adaab0613a6146cdaabe498c3a94e529d3fc1da2bd08edf54ed64d40dcd677",
                "6ccf1c34753e7a044db80798ecd0782a8f76f33563accaddbfbb2e0ea4b2d0240d07e63f13667a8d1490e5e04f13eb617aea16a8c8a5aaed1ef6fbde1b0515e3",
                "b07f01e518e702f7ccb44a267e9e112d403a7b3f4883a47ffbed4b48339b3c341a0add0ac032ab5aaea1e4e5b004707ec5681ae0fcbe3796974c0b1cf31a1947",
            ),
            (
                6144,
                "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca2054d742022da6fdda444ebc384b04a54c3ac5839b49da7d39f6d8a9db03deab32a",
                "3d6b6d21281d0ade5b2b016ae4034c5dec10ca7e475f90f76eac7138e9bc8f1dc35754060091dc5caf3efabe0603c60f45e415bb3407db67e6beb3d11cf8e4f7",
                "2a95beae63ddce523762355cf4b9c1d8f131465780a391286a5d01abb5683a1597099e3c6488aab6c48f3c15dbe1942d21dbcdc12115d19a8b8465fb54e90533",
            ),
            (
                6145,
                "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f18a2cfdd73c6e39dd75ce7c1c6e3ef238fd54465f053b25d21044ccb2093beb0",
                "9ac301e9e39e45e3250a7e3b3df701aa0fb6889fbd80eeecf28dbc6300fbc539f3c184ca2f59780e27a576c1d1fb9772e99fd17881d02ac7dfd39675aca91845",
                "379bcc61d0051dd489f686c13de00d5b14c505245103dc040d9e4dd1facab8e5114493d029bdbd295aaa744a59e31f35c7f52dba9c3642f773dd0b4262a9980a",
            ),
            (
                7168,
                "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a5707c321c83361793b9af62a40f43b523df1c8633cecb4cd14d00bdc79c78fca",
                "b42835e40e9d4a7f42ad8cc04f85a963a76e18198377ed84adddeaecacc6f3fca2f01d5277d69bb681c70fa8d36094f73ec06e452c80d2ff2257ed82e7ba3484",
                "11c37a112765370c94a51415d0d651190c288566e295d505defdad895dae223730d5a5175a38841693020669c7638f40b9bc1f9f39cf98bda7a5b54ae24218a8",
            ),
            (
                7169,
                "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e781798a8b20534be1ca9eb2ae2df3fae2ea60e48c6fb0b850b1385b5de0fe460dbe9",
                "ed9b1a922c046fdb3d423ae34e143b05ca1bf28b710432857bf738bcedbfa5113c9e28d72fcbfc020814ce3f5d4fc867f01c8f5b6caf305b3ea8a8ba2da3ab69",
                "554b0a5efea9ef183f2f9b931b7497995d9eb26f5c5c6dad2b97d62fc5ac31d99b20652c016d88ba2a611bbd761668d5eda3e568e940faae24b0d9991c3bd25a",
            ),
            (
                8192,
                "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a635fe51a27db045a567c1ad51be5aa34c01c6651c4d9b5b5ac5d0fd58cf18dd61a",
                "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a4834464159dcbc12a0ba0c6d6eb41bac0ed6585cabfe0aca36a375e6c5480c22",
                "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d4c9e58958553513b67f84f8eac653aeeb02ae1d5672dcecf91cd9985a0e67f45",
            ),
            (
                8193,
                "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3bb2282aa69be089359ea1154b9a9286c4a56af4de975a9aa4a5c497654914d279",
                "954a2a75420c8d6547e3ba5b98d963e6fa6491addc8c023189cc519821b4a1f5f03228648fd983aef045c2fa8290934b0866b615f585149587dda22990399653",
                "af1e0346e389b17c23200270a64aa4e1ead98c61695d917de7d5b00491c9b0f12f20a01d6d622edf3de026a4db4e4526225debb93c1237934d71c7340bb59161",
            ),
            (
                16384,
                "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde49d764c270176e53e97bdffa58d549073f2c660be0e81293767ed4e4929f9ad34",
                "9e9fc4eb7cf081ea7c47d1807790ed211bfec56aa25bb7037784c13c4b707b0df9e601b101e4cf63a404dfe50f2e1865bb12edc8fca166579ce0c70dba5a5c0f",
                "160e18b5878cd0df1c3af85eb25a0db5344d43a6fbd7a8ef4ed98d0714c3f7e160dc0b1f09caa35f2f417b9ef309dfe5ebd67f4c9507995a531374d099cf8ae3",
            ),
            (
                31744,
                "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47860cc51f2b0c28a7b77304bd55fe73af663c02d3f52ea053ba43431ca5bab7bf",
                "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a4193a7258db2d9cd32a7a3ecfce46144114b15c2fcb68a618a976bd74515d47be08",
                "39772aef80e0ebe60596361e45b061e8f417429d529171b6764468c22928e28e9759adeb797a3fbf771b1bcea30150a020e317982bf0d6e7d14dd9f064bc1102",
            ),
            (
                102400,
                "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085e01c59dab908c04c3342b816941a26d69c2605ebee5ec5291cc55e15b76146e6",
                "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7f9dbdd3e1d81dcbca3ba241bb18760f207710b751846faaeb9dff8262710999a",
                "4652cff7a3f385a6103b5c260fc1593e13c778dbe608efb092fe7ee69df6e9c6d83a3e041bc3a48df2879f4a0a3ed40e7c961c73eff740f3117a0504c2dff478",
            ),
        ];
        let mut buf = [0u8; 102400];
        fill_input(&mut buf);
        for &(len, hash, keyed, derive) in CASES {
            let input = &buf[..len];
            check(input, hash, keyed, derive);
            let want = blake3(input);
            for split in [
                1usize, 1023, 1024, 1025, 2048, 3072, 4096, 5000, 8192, 16384,
            ] {
                if split >= len {
                    continue;
                }
                let mut h = Blake3::new();
                h.update(&input[..split]);
                h.update(&input[split..]);
                assert_eq!(h.finalize(), want, "len {len} split {split}");
            }
            // Pieces of at most one chunk never reach the bulk path.
            let mut h = Blake3::new();
            for piece in input.chunks(1000) {
                h.update(piece);
            }
            assert_eq!(h.finalize(), want, "len {len} in 1000-byte pieces");
        }
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

        // Every split of a few-block message, so the direct-from-slice block
        // path, the buffered top-up and the kept-back final block are all
        // exercised against each other (the tail of the block buffer must stay
        // zero across a partial block that is later extended).
        for len in [63usize, 64, 65, 127, 128, 129, 200, 1023, 1024, 1025, 2049] {
            let want = blake3(&buf[..len]);
            for split in [0usize, 1, 31, 63, 64, 65, 100, 128, 129] {
                if split > len {
                    continue;
                }
                let mut h = Blake3::new();
                h.update(&buf[..split]);
                h.update(&buf[split..len]);
                assert_eq!(h.finalize(), want, "len {len} split {split}");
            }
            let mut h = Blake3::new();
            for piece in buf[..len].chunks(7) {
                h.update(piece);
            }
            assert_eq!(h.finalize(), want, "len {len} in 7-byte pieces");
        }
    }

    /// Deterministic xorshift byte generator for the SIMD differential tests.
    #[cfg(all(
        feature = "std",
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    fn xorshift(seed: u64) -> impl FnMut() -> u8 {
        let mut s = seed | 1;
        move || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        }
    }

    /// Random chunks, a random key, and the scalar chunk/parent chaining values
    /// the SIMD kernels must reproduce lane for lane.
    #[cfg(all(
        feature = "std",
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    struct KernelCase {
        key: [u32; 8],
        flags: u32,
        base: u64,
        chunks: alloc::vec::Vec<u8>,
        chunk_cvs: alloc::vec::Vec<[u32; 8]>,
        parents_input: alloc::vec::Vec<[u32; 8]>,
        parents: alloc::vec::Vec<[u32; 8]>,
    }

    /// Builds `KernelCase`s with `lanes` chunks (and `lanes` parents over
    /// `2 * lanes` random chaining values) across every keying mode and
    /// several counter bases, including one whose lanes straddle a carry into
    /// the counter's high word.
    #[cfg(all(
        feature = "std",
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    fn kernel_cases(lanes: usize) -> alloc::vec::Vec<KernelCase> {
        let mut next = xorshift(0x1234_5678_9abc_def0 ^ lanes as u64);
        let mut word = || u32::from_le_bytes([next(), next(), next(), next()]);
        let mut key = [0u32; 8];
        for w in key.iter_mut() {
            *w = word();
        }
        let mut cases = alloc::vec::Vec::new();
        for &(k, flags) in &[(IV, 0u32), (key, KEYED_HASH), (key, DERIVE_KEY_MATERIAL)] {
            for &base in &[0u64, 1, 7, 8, 1_000_000, (1u64 << 32) - 3] {
                let chunks: alloc::vec::Vec<u8> =
                    (0..lanes * CHUNK_LEN).map(|_| word() as u8).collect();
                let chunk_cvs = (0..lanes)
                    .map(|lane| {
                        let mut cs = ChunkState::new(k, base + lane as u64, flags);
                        cs.update(&chunks[lane * CHUNK_LEN..(lane + 1) * CHUNK_LEN]);
                        cs.output().chaining_value()
                    })
                    .collect();
                let pairs: alloc::vec::Vec<[u32; 8]> = (0..2 * lanes)
                    .map(|_| core::array::from_fn(|_| word()))
                    .collect();
                let parents = (0..lanes)
                    .map(|i| parent_cv(pairs[2 * i], pairs[2 * i + 1], k, flags))
                    .collect();
                cases.push(KernelCase {
                    key: k,
                    flags,
                    base,
                    chunks,
                    chunk_cvs,
                    parents_input: pairs,
                    parents,
                });
            }
        }
        cases
    }

    /// Each x86 kernel, chunk and parent mode, at every lane count from one to
    /// its width, must produce exactly the scalar chaining values.
    ///
    /// The kernels are driven directly rather than through `update`, so an
    /// AVX-512 host still covers the 8-wide path (the dispatcher would rarely
    /// reach it) and vice versa.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn simd_kernels_match_scalar() {
        use super::super::blake3_simd::{
            DEGREE, DEGREE16, hash_chunks8, hash_chunks8_no_vl, hash_chunks16, hash_parents8,
            hash_parents8_no_vl, hash_parents16, supported, supported16,
        };
        std::eprintln!(
            "blake3: avx2={} avx512={}",
            if supported() { "RUNNING" } else { "SKIPPED" },
            if supported16() { "RUNNING" } else { "SKIPPED" },
        );
        type Chunks = fn(&[u8], &[u32; 8], u64, u32, &mut [[u32; 8]]);
        type Parents = fn(&[[u32; 8]], &[u32; 8], u32, &mut [[u32; 8]]);
        let kernels: [(bool, usize, Chunks, Parents, &str); 3] = [
            (
                supported(),
                DEGREE,
                hash_chunks8_no_vl,
                hash_parents8_no_vl,
                "avx2",
            ),
            (
                supported(),
                DEGREE,
                hash_chunks8,
                hash_parents8,
                "avx2 (vl if present)",
            ),
            (
                supported16(),
                DEGREE16,
                hash_chunks16,
                hash_parents16,
                "avx512",
            ),
        ];
        for (ok, width, chunks, parents, name) in kernels {
            if !ok {
                continue;
            }
            for lanes in 1..=width {
                for c in kernel_cases(lanes) {
                    let mut got = alloc::vec![[0u32; 8]; lanes];
                    chunks(&c.chunks, &c.key, c.base, c.flags, &mut got);
                    assert_eq!(
                        got, c.chunk_cvs,
                        "{name} chunks: {lanes} lanes, base {}, flags {}",
                        c.base, c.flags
                    );
                    parents(&c.parents_input, &c.key, c.flags, &mut got);
                    assert_eq!(
                        got, c.parents,
                        "{name} parents: {lanes} lanes, flags {}",
                        c.flags
                    );
                }
            }
        }
    }

    /// The NEON kernel, chunk and parent mode, at every lane count from one to
    /// four, must produce exactly the scalar chaining values.
    #[cfg(all(feature = "std", target_arch = "aarch64", target_endian = "little"))]
    #[test]
    fn neon_kernels_match_scalar() {
        use super::super::blake3_neon::{DEGREE, hash_chunks4, hash_parents4, supported};
        std::eprintln!(
            "blake3: neon={}",
            if supported() { "RUNNING" } else { "SKIPPED" }
        );
        if !supported() {
            return;
        }
        for lanes in 1..=DEGREE {
            for c in kernel_cases(lanes) {
                let mut got = alloc::vec![[0u32; 8]; lanes];
                hash_chunks4(&c.chunks, &c.key, c.base, c.flags, &mut got);
                assert_eq!(
                    got, c.chunk_cvs,
                    "neon chunks: {lanes} lanes, base {}, flags {}",
                    c.base, c.flags
                );
                hash_parents4(&c.parents_input, &c.key, c.flags, &mut got);
                assert_eq!(
                    got, c.parents,
                    "neon parents: {lanes} lanes, flags {}",
                    c.flags
                );
            }
        }
    }

    /// End-to-end: hashing a large buffer through the public API (which takes
    /// the bulk path, on SIMD kernels where the CPU has them) must equal
    /// feeding the same bytes in pieces of at most one chunk (which never
    /// reach the bulk path), for every hasher mode. Validates the bulk-path
    /// counter / subtree / lazy-merge integration on top of the kernels.
    #[cfg(feature = "std")]
    #[test]
    fn simd_bulk_matches_scalar_end_to_end() {
        // Sizes around kernel widths and subtree sizes, exact multiples
        // (ending on a subtree boundary, so the root is a pair off the
        // stack) and partial trailing chunks, up to several `MAX_BATCH`
        // passes.
        for &n in &[
            2 * CHUNK_LEN,
            3 * CHUNK_LEN,
            4 * CHUNK_LEN + 1,
            8 * CHUNK_LEN + 1,
            16 * CHUNK_LEN + 1,
            24 * CHUNK_LEN + 5,
            25 * CHUNK_LEN + 3,
            64 * CHUNK_LEN,
            97 * CHUNK_LEN + 672,
            128 * CHUNK_LEN,
            200 * CHUNK_LEN + 1,
        ] {
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
                // Scalar reference: pieces of at most one chunk never reach
                // the bulk path.
                let mut b = ctor();
                for piece in buf.chunks(1000) {
                    b.update(piece);
                }
                let scalar = b.finalize();
                assert_eq!(simd, scalar, "mode {name}, n {n}");
                // A bulk pass that starts mid-tree: three chunks and a bit
                // go in scalar first, so the subtrees after them start
                // unaligned and must shrink to stay aligned.
                let head = (3 * CHUNK_LEN + 5).min(n);
                let mut c = ctor();
                for piece in buf[..head].chunks(1000) {
                    c.update(piece);
                }
                c.update(&buf[head..]);
                assert_eq!(c.finalize(), scalar, "mode {name}, n {n}, unaligned start");
            }
        }
    }
}
