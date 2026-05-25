//! The Keccak-`f`[1600] permutation and a sponge, shared by SHA-3, SHAKE,
//! Keccak-256, cSHAKE, and KMAC.
//!
//! The sponge is parameterized by its rate (bytes) and the domain-separation
//! byte applied at padding (`0x06` SHA-3, `0x1F` SHAKE, `0x01` legacy Keccak,
//! `0x04` cSHAKE), and supports incremental squeezing for XOF output.

use super::XofReader;

/// Keccak-f[1600] round constants.
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets for the combined ρ/π step.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane permutation for the combined ρ/π step.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation over a 5×5 array of 64-bit lanes.
fn keccak_f(a: &mut [u64; 25]) {
    for &rc in RC.iter() {
        // θ
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }

        // ρ and π
        let mut last = a[1];
        for i in 0..24 {
            let j = PI[i];
            let tmp = a[j];
            a[j] = last.rotate_left(RHO[i]);
            last = tmp;
        }

        // χ
        for y in 0..5 {
            let row = [
                a[5 * y],
                a[5 * y + 1],
                a[5 * y + 2],
                a[5 * y + 3],
                a[5 * y + 4],
            ];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }

        // ι
        a[0] ^= rc;
    }
}

/// The maximum supported rate (SHAKE128), bounding the absorb buffer.
const MAX_RATE: usize = 168;

/// A Keccak sponge supporting absorption then (incremental) squeezing.
#[derive(Clone)]
pub(super) struct Keccak {
    state: [u64; 25],
    buf: [u8; MAX_RATE],
    buf_len: usize,
    rate: usize,
    /// Byte offset within the current rate block during squeezing.
    squeeze_offset: usize,
}

impl Keccak {
    pub(super) fn new(rate: usize) -> Self {
        Keccak {
            state: [0u64; 25],
            buf: [0u8; MAX_RATE],
            buf_len: 0,
            rate,
            squeeze_offset: 0,
        }
    }

    /// XORs the full `rate`-byte buffer into the state and permutes.
    fn absorb_buf(&mut self) {
        for (i, chunk) in self.buf[..self.rate].chunks_exact(8).enumerate() {
            self.state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }
        keccak_f(&mut self.state);
    }

    pub(super) fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (self.rate - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == self.rate {
                self.absorb_buf();
                self.buf_len = 0;
            }
        }
        while data.len() >= self.rate {
            self.buf[..self.rate].copy_from_slice(&data[..self.rate]);
            self.absorb_buf();
            data = &data[self.rate..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Applies the `pad10*1` padding with domain byte `pad` and permutes, after
    /// which [`squeeze`](Keccak::squeeze) yields the output stream.
    pub(super) fn finalize(&mut self, pad: u8) {
        let len = self.buf_len;
        for b in self.buf[len..self.rate].iter_mut() {
            *b = 0;
        }
        self.buf[len] ^= pad;
        self.buf[self.rate - 1] ^= 0x80;
        self.absorb_buf();
        self.buf_len = 0;
        self.squeeze_offset = 0;
    }

    /// Squeezes `out.len()` bytes, continuing the stream across calls.
    pub(super) fn squeeze(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            if self.squeeze_offset == self.rate {
                keccak_f(&mut self.state);
                self.squeeze_offset = 0;
            }
            let p = self.squeeze_offset;
            *b = (self.state[p / 8] >> (8 * (p % 8))) as u8;
            self.squeeze_offset += 1;
        }
    }
}

/// A [`XofReader`] over a finalized Keccak sponge, returned by the SHAKE,
/// cSHAKE, and KMAC-XOF functions.
#[derive(Clone)]
pub struct KeccakReader {
    keccak: Keccak,
}

impl KeccakReader {
    /// Finalizes `keccak` with domain byte `pad` and returns a reader.
    pub(super) fn new(mut keccak: Keccak, pad: u8) -> Self {
        keccak.finalize(pad);
        KeccakReader { keccak }
    }
}

impl XofReader for KeccakReader {
    fn read(&mut self, out: &mut [u8]) {
        self.keccak.squeeze(out);
    }
}
