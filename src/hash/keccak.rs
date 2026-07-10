//! The Keccak-`p`[1600, n] permutation and a sponge, shared by SHA-3, SHAKE,
//! Keccak-256, cSHAKE, KMAC, and (with 12 rounds) TurboSHAKE/KangarooTwelve.
//!
//! The sponge is parameterized by its rate (bytes), its round count (24 for the
//! full Keccak-f, 12 for TurboSHAKE), and the domain-separation byte applied at
//! padding (`0x06` SHA-3, `0x1F` SHAKE, `0x01` legacy Keccak, `0x04` cSHAKE,
//! `0x07`/`0x0B`/`0x06` KangarooTwelve), and supports incremental squeezing for
//! XOF output.

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

/// Lanes stored complemented in the in-round state representation (the XKCP
/// "bebigokimisa" pattern, flat indices `x + 5y`). Complementing exactly these
/// lanes lets χ be computed with plain AND/OR for all but 8 of the 25 output
/// lanes per round (instead of a NOT in every one), and the pattern is
/// invariant across rounds so a single unrolled round body serves all rounds.
const COMPLEMENTED: [usize; 6] = [1, 2, 8, 12, 17, 20];

/// One lane-complemented Keccak-p round: θ, fused ρ/π (into fresh `b` lanes,
/// with the θ `d` values folded in), then χ+ι in the complemented
/// representation.
///
/// The straight-line body is machine-derived from the loop formulation this
/// replaces (see git history) by propagating a per-lane complement flag
/// through θ (flags XOR through the column parities) and ρ/π (flags follow
/// the lane permutation), then choosing for each χ output the single AND/OR
/// form that yields the output lane again in the [`COMPLEMENTED`] pattern.
/// It is pinned by the SHA-3/SHAKE KATs (24 rounds) and the
/// TurboSHAKE/KangarooTwelve vectors (12 rounds).
#[inline(always)]
fn round(a: &mut [u64; 25], rc: u64) {
    // θ: column parities and the per-column mixers. Complement flags cancel
    // structurally; no extra NOTs are needed here.
    let c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
    let c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
    let c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
    let c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
    let c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
    let d0 = c4 ^ c1.rotate_left(1);
    let d1 = c0 ^ c2.rotate_left(1);
    let d2 = c1 ^ c3.rotate_left(1);
    let d3 = c2 ^ c4.rotate_left(1);
    let d4 = c3 ^ c0.rotate_left(1);

    // θ (lane update) fused with ρ/π: b[π(i)] = (a[i] ^ d[i mod 5]) <<< ρ(i).
    let b0 = a[0] ^ d0;
    let b1 = (a[6] ^ d1).rotate_left(44);
    let b2 = (a[12] ^ d2).rotate_left(43);
    let b3 = (a[18] ^ d3).rotate_left(21);
    let b4 = (a[24] ^ d4).rotate_left(14);
    let b5 = (a[3] ^ d3).rotate_left(28);
    let b6 = (a[9] ^ d4).rotate_left(20);
    let b7 = (a[10] ^ d0).rotate_left(3);
    let b8 = (a[16] ^ d1).rotate_left(45);
    let b9 = (a[22] ^ d2).rotate_left(61);
    let b10 = (a[1] ^ d1).rotate_left(1);
    let b11 = (a[7] ^ d2).rotate_left(6);
    let b12 = (a[13] ^ d3).rotate_left(25);
    let b13 = (a[19] ^ d4).rotate_left(8);
    let b14 = (a[20] ^ d0).rotate_left(18);
    let b15 = (a[4] ^ d4).rotate_left(27);
    let b16 = (a[5] ^ d0).rotate_left(36);
    let b17 = (a[11] ^ d1).rotate_left(10);
    let b18 = (a[17] ^ d2).rotate_left(15);
    let b19 = (a[23] ^ d3).rotate_left(56);
    let b20 = (a[2] ^ d2).rotate_left(62);
    let b21 = (a[8] ^ d3).rotate_left(55);
    let b22 = (a[14] ^ d4).rotate_left(39);
    let b23 = (a[15] ^ d0).rotate_left(41);
    let b24 = (a[21] ^ d1).rotate_left(2);

    // χ (complemented form) and ι.
    a[0] = (b0 ^ (b1 | b2)) ^ rc;
    a[1] = b1 ^ (!b2 | b3);
    a[2] = b2 ^ (b3 & b4);
    a[3] = b3 ^ (b4 | b0);
    a[4] = b4 ^ (b0 & b1);
    a[5] = b5 ^ (b6 | b7);
    a[6] = b6 ^ (b7 & b8);
    a[7] = b7 ^ (b8 | !b9);
    a[8] = b8 ^ (b9 | b5);
    a[9] = b9 ^ (b5 & b6);
    a[10] = b10 ^ (b11 | b12);
    a[11] = b11 ^ (b12 & b13);
    a[12] = b12 ^ (!b13 & b14);
    a[13] = b13 ^ !(b14 | b10);
    a[14] = b14 ^ (b10 & b11);
    a[15] = b15 ^ (b16 & b17);
    a[16] = b16 ^ (b17 | b18);
    a[17] = b17 ^ (!b18 | b19);
    a[18] = b18 ^ !(b19 & b15);
    a[19] = b19 ^ (b15 | b16);
    a[20] = b20 ^ (!b21 & b22);
    a[21] = b21 ^ !(b22 | b23);
    a[22] = b22 ^ (b23 & b24);
    a[23] = b23 ^ (b24 | b20);
    a[24] = b24 ^ (b20 & b21);
}

/// The Keccak-p[1600, `rounds`] permutation over a 5×5 array of 64-bit lanes.
///
/// `rounds == 24` is the full Keccak-f used by SHA-3, SHAKE, and KMAC; the
/// reduced-round variant (`rounds == 12`, the last 12 round constants) is used
/// by TurboSHAKE and KangarooTwelve. Constant time: bitwise operations only.
pub(super) fn keccak_p(a: &mut [u64; 25], rounds: usize) {
    // Enter the lane-complemented representation, run the (identical) rounds,
    // and leave it again. The pattern is round-invariant, so the round count
    // (24 or 12) does not matter.
    for &i in COMPLEMENTED.iter() {
        a[i] = !a[i];
    }
    for &rc in RC[24 - rounds..].iter() {
        round(a, rc);
    }
    for &i in COMPLEMENTED.iter() {
        a[i] = !a[i];
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
    /// Permutation round count: 24 for SHA-3/SHAKE/KMAC, 12 for TurboSHAKE.
    rounds: usize,
    /// Byte offset within the current rate block during squeezing.
    squeeze_offset: usize,
}

impl Default for Keccak {
    /// A zeroed placeholder sponge. Used as the `core::mem::take` filler when
    /// finalize-style methods move the real sponge into a [`KeccakReader`];
    /// the original wrapper's `Drop` then wipes this all-zero stand-in,
    /// avoiding the "cannot move out of type that implements `Drop`" error.
    fn default() -> Self {
        Keccak {
            state: [0u64; 25],
            buf: [0u8; MAX_RATE],
            buf_len: 0,
            rate: 0,
            rounds: 0,
            squeeze_offset: 0,
        }
    }
}

impl Keccak {
    pub(super) fn new(rate: usize) -> Self {
        Self::with_rounds(rate, 24)
    }

    /// A sponge using a reduced-round Keccak-p permutation (e.g. 12 for
    /// TurboSHAKE).
    pub(super) fn with_rounds(rate: usize, rounds: usize) -> Self {
        Keccak {
            state: [0u64; 25],
            buf: [0u8; MAX_RATE],
            buf_len: 0,
            rate,
            rounds,
            squeeze_offset: 0,
        }
    }

    /// XORs the full `rate`-byte buffer into the state and permutes.
    fn absorb_buf(&mut self) {
        for (i, chunk) in self.buf[..self.rate].chunks_exact(8).enumerate() {
            self.state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }
        keccak_p(&mut self.state, self.rounds);
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

    /// Best-effort wipe of the sponge state and absorb buffer.
    pub(super) fn zeroize(&mut self) {
        super::zeroize::zero_words(&mut self.state);
        super::zeroize::zero_bytes(&mut self.buf);
        self.buf_len = 0;
        self.squeeze_offset = 0;
    }

    /// Squeezes `out.len()` bytes, continuing the stream across calls.
    pub(super) fn squeeze(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            if self.squeeze_offset == self.rate {
                keccak_p(&mut self.state, self.rounds);
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

impl Drop for KeccakReader {
    fn drop(&mut self) {
        self.keccak.zeroize();
    }
}
