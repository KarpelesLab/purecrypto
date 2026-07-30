//! Shared 64-byte Merkle–Damgård buffering for the MD4 / MD5 / SHA-1 /
//! RIPEMD-160 family.
//!
//! These hashes share the same framing — 64-byte blocks, a `0x80` pad byte, and
//! a trailing 64-bit message-bit-length — differing only in their compression
//! function and in the endianness of the length field (big-endian for SHA-1,
//! little-endian for the MD/RIPEMD hashes). [`MdState`] captures the common
//! part; each algorithm supplies its `compress` function.

/// Multi-block compression: folds a whole number of 64-byte blocks into the `W`
/// state words in a single call (see [`MdState::new_bulk`]).
type CompressBlocks<const W: usize> = fn(&mut [u32; W], &[u8]);

/// Streaming state for a 64-byte-block Merkle–Damgård hash over `W` 32-bit
/// state words.
#[derive(Clone)]
pub(super) struct MdState<const W: usize> {
    h: [u32; W],
    block: [u8; 64],
    block_len: usize,
    msg_len: u64,
    /// Whether the trailing length field is big-endian (SHA-1) vs little-endian.
    len_be: bool,
    compress: fn(&mut [u32; W], &[u8; 64]),
    /// Optional multi-block compression for the bulk path (see [`Self::new_bulk`]).
    compress_blocks: Option<CompressBlocks<W>>,
}

impl<const W: usize> MdState<W> {
    #[inline]
    pub(super) fn new(iv: [u32; W], len_be: bool, compress: fn(&mut [u32; W], &[u8; 64])) -> Self {
        MdState {
            h: iv,
            block: [0u8; 64],
            block_len: 0,
            msg_len: 0,
            len_be,
            compress,
            compress_blocks: None,
        }
    }

    /// Like [`Self::new`], but with a multi-block compression function for the
    /// bulk path: [`Self::update`] hands every full block of the input to
    /// `compress_blocks` in one call instead of looping `compress`, so a hardware
    /// backend can keep the hash state register-resident across them (SHA-1).
    /// `compress` still handles the partial-block top-up and the padding blocks.
    #[inline]
    pub(super) fn new_bulk(
        iv: [u32; W],
        len_be: bool,
        compress: fn(&mut [u32; W], &[u8; 64]),
        compress_blocks: CompressBlocks<W>,
    ) -> Self {
        MdState {
            compress_blocks: Some(compress_blocks),
            ..Self::new(iv, len_be, compress)
        }
    }

    pub(super) fn update(&mut self, mut data: &[u8]) {
        self.msg_len = self.msg_len.wrapping_add(data.len() as u64);

        if self.block_len > 0 {
            let take = (64 - self.block_len).min(data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
            if self.block_len == 64 {
                (self.compress)(&mut self.h, &self.block);
                self.block_len = 0;
            }
        }

        // Compress all full blocks. With a bulk function they go out in a single
        // call, so a hardware backend keeps the state register-resident across
        // them; otherwise, block by block.
        let full = data.len() & !63;
        if full > 0 {
            if let Some(compress_blocks) = self.compress_blocks {
                compress_blocks(&mut self.h, &data[..full]);
            } else {
                for block in data[..full].chunks_exact(64) {
                    (self.compress)(&mut self.h, block.try_into().unwrap());
                }
            }
            data = &data[full..];
        }

        if !data.is_empty() {
            self.block[..data.len()].copy_from_slice(data);
            self.block_len = data.len();
        }
    }

    /// Best-effort wipe of the state words and partial block.
    pub(super) fn zeroize(&mut self) {
        super::zeroize::zero_words(&mut self.h);
        super::zeroize::zero_bytes(&mut self.block);
        self.block_len = 0;
        self.msg_len = 0;
    }

    /// Applies the padding and returns the final state words.
    pub(super) fn finalize(mut self) -> [u32; W] {
        let bit_len = self.msg_len.wrapping_mul(8);
        let len_bytes = if self.len_be {
            bit_len.to_be_bytes()
        } else {
            bit_len.to_le_bytes()
        };

        let mut i = self.block_len;
        self.block[i] = 0x80;
        i += 1;

        if i > 56 {
            while i < 64 {
                self.block[i] = 0;
                i += 1;
            }
            (self.compress)(&mut self.h, &self.block);
            i = 0;
        }
        while i < 56 {
            self.block[i] = 0;
            i += 1;
        }
        self.block[56..64].copy_from_slice(&len_bytes);
        (self.compress)(&mut self.h, &self.block);

        self.h
    }
}

/// Serializes `W` state words as little-endian bytes (MD4/MD5/RIPEMD-160).
#[inline]
pub(super) fn words_to_bytes_le<const W: usize, const N: usize>(h: &[u32; W]) -> [u8; N] {
    let mut out = [0u8; N];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h.iter()) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Serializes `W` state words as big-endian bytes (SHA-1).
#[inline]
pub(super) fn words_to_bytes_be<const W: usize, const N: usize>(h: &[u32; W]) -> [u8; N] {
    let mut out = [0u8; N];
    for (chunk, word) in out.chunks_exact_mut(4).zip(h.iter()) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// Loads the 16 little-endian message words of a block (MD4/MD5/RIPEMD-160).
#[inline]
pub(super) fn block_words_le(block: &[u8; 64]) -> [u32; 16] {
    let mut m = [0u32; 16];
    for (word, chunk) in m.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes(chunk.try_into().unwrap());
    }
    m
}
