//! Byte-to-block buffering shared by the `legacy-hashes` digests (Tiger,
//! Snefru, GOST R 34.11-94, HAVAL).
//!
//! Their framings differ — pad byte, length-field width and endianness, a
//! trailing checksum block — so only the streaming part is shared: collect
//! input into `B`-byte blocks, hand each full block to the compression
//! function, and count the bytes absorbed. Each algorithm pads its own
//! [`BlockBuffer::pending`] tail at finalization.

#[derive(Clone)]
pub(super) struct BlockBuffer<const B: usize> {
    buf: [u8; B],
    len: usize,
    /// Bytes absorbed so far (wrapping; the hashes encode it modulo 2^64 bits).
    total: u64,
}

impl<const B: usize> BlockBuffer<B> {
    #[inline]
    pub(super) const fn new() -> Self {
        BlockBuffer {
            buf: [0u8; B],
            len: 0,
            total: 0,
        }
    }

    /// Absorbs `data`, calling `compress` on every block that fills up.
    pub(super) fn update(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8; B])) {
        self.total = self.total.wrapping_add(data.len() as u64);

        if self.len > 0 {
            let take = (B - self.len).min(data.len());
            self.buf[self.len..self.len + take].copy_from_slice(&data[..take]);
            self.len += take;
            data = &data[take..];
            if self.len < B {
                return;
            }
            compress(&self.buf);
            self.len = 0;
        }

        let mut blocks = data.chunks_exact(B);
        for block in &mut blocks {
            compress(block.try_into().unwrap());
        }
        let rest = blocks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.len = rest.len();
    }

    /// The buffered partial block (fewer than `B` bytes).
    #[inline]
    pub(super) fn pending(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Total bits absorbed, modulo 2^64 (the length field these hashes use).
    #[inline]
    pub(super) fn total_bits(&self) -> u64 {
        self.total.wrapping_mul(8)
    }

    /// Exported-state length of the buffer part: the byte counter (`u64`),
    /// the buffered count (`u8`) and the `B`-byte buffer.
    pub(super) const STATE_LEN: usize = 8 + 1 + B;

    /// Writes the byte counter, then the buffered count and buffer (see
    /// [`ExportableState`](super::ExportableState)).
    pub(super) fn export_into(&self, w: &mut super::state::Writer<'_>) {
        w.u64(self.total);
        w.buffer(&self.buf, self.len);
    }

    /// Reads what [`Self::export_into`] wrote. Full blocks are compressed as
    /// soon as they fill, so the buffered count must be below `B` and equal
    /// to the byte counter modulo `B`.
    pub(super) fn import_from(r: &mut super::state::Reader<'_>) -> Result<Self, super::StateError> {
        let total = r.u64();
        let mut buf = [0u8; B];
        let len = r.buffer(&mut buf, B - 1)?;
        if total % B as u64 != len as u64 {
            return Err(super::StateError::Inconsistent);
        }
        Ok(BlockBuffer { buf, len, total })
    }

    /// Best-effort wipe of the buffered bytes and the counter.
    pub(super) fn zeroize(&mut self) {
        super::zeroize::zero_bytes(&mut self.buf);
        self.len = 0;
        self.total = 0;
    }
}
