//! MORUS — AND/XOR/rotate-based authenticated encryption
//! (Wu & Huang, CAESAR round-3 finalist, MORUS v2).
//!
//! Implements [`Morus640`] (128-bit key, five 128-bit state registers) and
//! [`Morus1280`] (128- or 256-bit key, five 256-bit registers). Both take a
//! 128-bit nonce and produce a 128-bit tag. The state update is five steps of
//! `XOR`, `AND`, per-word rotation and whole-register word rotation, so the
//! whole construction is inherently constant time: there are no S-boxes and
//! no data-dependent branches or memory accesses.
//!
//! The crate AEAD shape is followed: [`encrypt`](Morus640::encrypt) transforms
//! the buffer in place and returns the tag; [`decrypt`](Morus640::decrypt)
//! verifies the tag in constant time and only then releases the plaintext,
//! returning [`TagMismatch`] (and leaving the buffer untouched) on failure.
//! Like the AEGIS decryption next door, verification trial-decrypts into a
//! scratch buffer (a `Vec` with `alloc`, a 4 KiB stack array without — see
//! the [`aegis`](super::Aegis128L#decryption-without-alloc) notes).
//!
//! MORUS did not make the final CAESAR portfolio and has a published
//! linear-bias distinguisher on its keystream (Ashur et al., 2018) that,
//! while far beyond practical data volumes, makes it a poor choice for new
//! designs; this module exists for interoperability with existing MORUS
//! ciphertext. A `(key, nonce)` pair must never be reused.
//!
//! Correctness is checked against the Wycheproof `morus640` / `morus1280`
//! vector files.

use core::ops::{BitAnd, BitXor, BitXorAssign};

use super::aegis::ScratchVec;
use super::{AeadError, TagMismatch};
use crate::ct::ConstantTimeEq;
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// MORUS constant `const_0` (the Fibonacci sequence modulo 256).
const C0: [u8; 16] = [
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
];
/// MORUS constant `const_1`.
const C1: [u8; 16] = [
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
];

/// A state-register word: `u32` for MORUS-640, `u64` for MORUS-1280. A
/// register is four words; a message block is one register.
trait Word:
    Copy + Default + BitAnd<Output = Self> + BitXor<Output = Self> + BitXorAssign + Zeroize
{
    /// Width in bytes.
    const BYTES: usize;
    /// Per-step intra-word rotation amounts `b0..b4`.
    const ROT: [u32; 5];
    fn rotl(self, n: u32) -> Self;
    fn from_le(bytes: &[u8]) -> Self;
    fn to_le(self, out: &mut [u8]);
}

impl Word for u32 {
    const BYTES: usize = 4;
    const ROT: [u32; 5] = [5, 31, 7, 22, 13];
    #[inline]
    fn rotl(self, n: u32) -> u32 {
        self.rotate_left(n)
    }
    #[inline]
    fn from_le(bytes: &[u8]) -> u32 {
        u32::from_le_bytes(bytes.try_into().unwrap())
    }
    #[inline]
    fn to_le(self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_le_bytes());
    }
}

impl Word for u64 {
    const BYTES: usize = 8;
    const ROT: [u32; 5] = [13, 46, 38, 7, 4];
    #[inline]
    fn rotl(self, n: u32) -> u64 {
        self.rotate_left(n)
    }
    #[inline]
    fn from_le(bytes: &[u8]) -> u64 {
        u64::from_le_bytes(bytes.try_into().unwrap())
    }
    #[inline]
    fn to_le(self, out: &mut [u8]) {
        out.copy_from_slice(&self.to_le_bytes());
    }
}

/// Loads a register / message block from exactly `4 * W::BYTES` bytes
/// (little-endian words); shorter input is zero-padded on the right.
#[inline]
fn load<W: Word>(bytes: &[u8]) -> [W; 4] {
    let mut buf = [0u8; 32];
    buf[..bytes.len()].copy_from_slice(bytes);
    let mut r = [W::default(); 4];
    for (i, w) in r.iter_mut().enumerate() {
        *w = W::from_le(&buf[i * W::BYTES..(i + 1) * W::BYTES]);
    }
    r
}

/// Stores a register as little-endian words into `out` (`4 * W::BYTES` bytes).
#[inline]
fn store<W: Word>(r: &[W; 4], out: &mut [u8]) {
    for (i, w) in r.iter().enumerate() {
        w.to_le(&mut out[i * W::BYTES..(i + 1) * W::BYTES]);
    }
}

/// Rotates the four words of a register: `new[i] = old[(i + k) mod 4]`.
#[inline]
fn rot_words<W: Word>(r: [W; 4], k: usize) -> [W; 4] {
    [r[k % 4], r[(k + 1) % 4], r[(k + 2) % 4], r[(k + 3) % 4]]
}

/// Rotates every word of a register left by `n` bits.
#[inline]
fn rotl_each<W: Word>(r: [W; 4], n: u32) -> [W; 4] {
    [r[0].rotl(n), r[1].rotl(n), r[2].rotl(n), r[3].rotl(n)]
}

#[inline]
fn xor<W: Word>(a: [W; 4], b: [W; 4]) -> [W; 4] {
    [a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]]
}

#[inline]
fn and<W: Word>(a: [W; 4], b: [W; 4]) -> [W; 4] {
    [a[0] & b[0], a[1] & b[1], a[2] & b[2], a[3] & b[3]]
}

/// The five-register MORUS state.
struct State<W: Word> {
    s: [[W; 4]; 5],
}

impl<W: Word> State<W> {
    /// `StateUpdate(S, m)`: the five MORUS steps. Each step XORs the message
    /// block (from step 2 on), one register and the AND of two others into
    /// the target register, rotates its words, and word-rotates a further
    /// register (`w0..w4` = 1, 2, 3, 2, 1 words).
    #[inline]
    fn update(&mut self, m: [W; 4]) {
        let s = &mut self.s;
        s[0] = rotl_each(xor(xor(s[0], s[3]), and(s[1], s[2])), W::ROT[0]);
        s[3] = rot_words(s[3], 3);
        s[1] = rotl_each(xor(xor(xor(s[1], m), s[4]), and(s[2], s[3])), W::ROT[1]);
        s[4] = rot_words(s[4], 2);
        s[2] = rotl_each(xor(xor(xor(s[2], m), s[0]), and(s[3], s[4])), W::ROT[2]);
        s[0] = rot_words(s[0], 1);
        s[3] = rotl_each(xor(xor(xor(s[3], m), s[1]), and(s[4], s[0])), W::ROT[3]);
        s[1] = rot_words(s[1], 2);
        s[4] = rotl_each(xor(xor(xor(s[4], m), s[2]), and(s[0], s[1])), W::ROT[4]);
        s[2] = rot_words(s[2], 3);
    }

    /// The shared tail of `Initialization`: sixteen updates with a zero
    /// block, then the key is XORed back into `S1`.
    fn init_rounds(&mut self, key: [W; 4]) {
        for _ in 0..16 {
            self.update([W::default(); 4]);
        }
        self.s[1] = xor(self.s[1], key);
    }

    /// Keystream block `S0 ⊕ (S1 ⋘ one word) ⊕ (S2 & S3)`.
    #[inline]
    fn keystream(&self) -> [W; 4] {
        let s = &self.s;
        xor(xor(s[0], rot_words(s[1], 1)), and(s[2], s[3]))
    }

    /// Absorbs the associated data: whole blocks, then a zero-padded tail if
    /// any.
    fn absorb_ad(&mut self, ad: &[u8]) {
        let bs = 4 * W::BYTES;
        let mut chunks = ad.chunks_exact(bs);
        for c in &mut chunks {
            self.update(load(c));
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.update(load(rem));
        }
    }

    /// Encrypts `buffer` in place.
    fn encrypt(&mut self, buffer: &mut [u8]) {
        let bs = 4 * W::BYTES;
        let mut chunks = buffer.chunks_exact_mut(bs);
        for c in &mut chunks {
            let m = load(c);
            store(&xor(m, self.keystream()), c);
            self.update(m);
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let m = load(rem);
            let mut out = [0u8; 32];
            store(&xor(m, self.keystream()), &mut out[..bs]);
            rem.copy_from_slice(&out[..rem.len()]);
            self.update(m);
            out.zeroize();
        }
    }

    /// Decrypts `buffer` in place (the tag is checked by the caller). The
    /// partial tail is decrypted from a zero-padded block, then truncated
    /// before being absorbed, exactly as the reference `DecPartial`.
    fn decrypt(&mut self, buffer: &mut [u8]) {
        let bs = 4 * W::BYTES;
        let mut chunks = buffer.chunks_exact_mut(bs);
        for c in &mut chunks {
            let m = xor(load(c), self.keystream());
            store(&m, c);
            self.update(m);
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let mut out = [0u8; 32];
            store(&xor(load(rem), self.keystream()), &mut out[..bs]);
            for b in out.iter_mut().skip(rem.len()) {
                *b = 0;
            }
            rem.copy_from_slice(&out[..rem.len()]);
            self.update(load(&out[..bs]));
            out.zeroize();
        }
    }

    /// `Finalization`: absorbs the bit lengths for ten rounds and returns the
    /// 128-bit tag (the first 16 bytes of the keystream block).
    fn finalize(&mut self, ad_len: usize, msg_len: usize) -> [u8; 16] {
        let mut len = [0u8; 32];
        len[..8].copy_from_slice(&((ad_len as u64) * 8).to_le_bytes());
        len[8..16].copy_from_slice(&((msg_len as u64) * 8).to_le_bytes());
        let block = load::<W>(&len[..4 * W::BYTES]);
        self.s[4] = xor(self.s[4], self.s[0]);
        for _ in 0..10 {
            self.update(block);
        }
        let mut out = [0u8; 32];
        store(&self.keystream(), &mut out[..4 * W::BYTES]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&out[..16]);
        out.zeroize();
        tag
    }
}

impl<W: Word> Drop for State<W> {
    fn drop(&mut self) {
        for r in self.s.iter_mut() {
            r.zeroize();
        }
    }
}

/// Runs the whole AEAD encryption over an initialized state.
fn seal<W: Word>(mut st: State<W>, aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
    st.absorb_ad(aad);
    st.encrypt(buffer);
    st.finalize(aad.len(), buffer.len())
}

/// Runs the whole AEAD decryption over an initialized state, decrypting into
/// a scratch copy and committing it to `buffer` only when the tag matches.
fn open<W: Word>(
    mut st: State<W>,
    aad: &[u8],
    buffer: &mut [u8],
    tag: &[u8; 16],
) -> Result<(), TagMismatch> {
    // Without `alloc` the scratch copy is a fixed 4 KiB buffer; a longer
    // ciphertext is rejected, not a panic — the length is attacker-controlled.
    let mut scratch = ScratchVec::from_slice(buffer).ok_or(TagMismatch)?;
    st.absorb_ad(aad);
    st.decrypt(scratch.as_mut());
    let expected = st.finalize(aad.len(), buffer.len());
    if !bool::from(expected.ct_eq(tag)) {
        return Err(TagMismatch);
    }
    buffer.copy_from_slice(scratch.as_mut());
    Ok(())
}

// ===========================================================================
// MORUS-640
// ===========================================================================

/// MORUS-640: 128-bit key, 128-bit nonce, 128-bit tag, five 128-bit
/// registers.
///
/// Construct with [`Morus640::new`]; the instance stores only the key, which
/// is wiped on drop.
#[derive(Clone)]
pub struct Morus640 {
    key: [u32; 4],
}

impl Morus640 {
    /// Key size in bytes.
    pub const KEY_SIZE: usize = 16;
    /// Nonce size in bytes.
    pub const NONCE_SIZE: usize = 16;
    /// Tag size in bytes.
    pub const TAG_SIZE: usize = 16;

    /// Creates a MORUS-640 instance from a 128-bit key.
    pub fn new(key: &[u8; 16]) -> Self {
        Morus640 { key: load(key) }
    }

    /// `Initialization(K, IV)`: `S0 = IV`, `S1 = K`, `S2 = 1¹²⁸`,
    /// `S3 = const_0`, `S4 = const_1`, then the shared rounds.
    fn init(&self, nonce: &[u8; 16]) -> State<u32> {
        let mut st = State {
            s: [load(nonce), self.key, [u32::MAX; 4], load(&C0), load(&C1)],
        };
        st.init_rounds(self.key);
        st
    }

    /// Encrypts `buffer` in place, binding `aad`, and returns the 128-bit tag.
    pub fn encrypt(&self, nonce: &[u8; 16], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        seal(self.init(nonce), aad, buffer)
    }

    /// Verifies `tag` and, only if it matches, decrypts `buffer` in place. On
    /// mismatch the buffer is left as ciphertext and [`TagMismatch`] is
    /// returned. The tag check is constant time.
    ///
    /// Without the `alloc` feature a `buffer` longer than 4 KiB also returns
    /// [`TagMismatch`]; see the module docs.
    pub fn decrypt(
        &self,
        nonce: &[u8; 16],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        open(self.init(nonce), aad, buffer, tag)
    }
}

impl Drop for Morus640 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for Morus640 {}

// ===========================================================================
// MORUS-1280
// ===========================================================================

/// MORUS-1280: 128- or 256-bit key, 128-bit nonce, 128-bit tag, five 256-bit
/// registers.
///
/// A 128-bit key `K` is used as `K ‖ K` (MORUS v2 §2.3). Construct with
/// [`Morus1280::new`] / [`Morus1280::try_new`]; the instance stores only the
/// expanded key, which is wiped on drop.
#[derive(Clone)]
pub struct Morus1280 {
    key: [u64; 4],
}

impl Morus1280 {
    /// Nonce size in bytes.
    pub const NONCE_SIZE: usize = 16;
    /// Tag size in bytes.
    pub const TAG_SIZE: usize = 16;

    /// Creates a MORUS-1280 instance from a 16- or 32-byte key.
    ///
    /// # Panics
    /// Panics on any other key length; see [`try_new`](Self::try_new).
    pub fn new(key: &[u8]) -> Self {
        Self::try_new(key).unwrap_or_else(|_| panic!("MORUS-1280 key must be 16 or 32 bytes"))
    }

    /// Fallible [`new`](Self::new): returns [`AeadError::InvalidKeyLength`]
    /// for a key that is neither 16 nor 32 bytes.
    pub fn try_new(key: &[u8]) -> Result<Self, AeadError> {
        let mut k = [0u8; 32];
        match key.len() {
            16 => {
                k[..16].copy_from_slice(key);
                k[16..].copy_from_slice(key);
            }
            32 => k.copy_from_slice(key),
            _ => return Err(AeadError::InvalidKeyLength),
        }
        let words = load(&k);
        k.zeroize();
        Ok(Morus1280 { key: words })
    }

    /// `Initialization(K, IV)`: `S0 = IV ‖ 0¹²⁸`, `S1 = K`, `S2 = 1²⁵⁶`,
    /// `S3 = 0²⁵⁶`, `S4 = const_0 ‖ const_1`, then the shared rounds.
    fn init(&self, nonce: &[u8; 16]) -> State<u64> {
        let mut consts = [0u8; 32];
        consts[..16].copy_from_slice(&C0);
        consts[16..].copy_from_slice(&C1);
        let mut st = State {
            s: [
                load(nonce),
                self.key,
                [u64::MAX; 4],
                [0u64; 4],
                load(&consts),
            ],
        };
        st.init_rounds(self.key);
        st
    }

    /// Encrypts `buffer` in place, binding `aad`, and returns the 128-bit tag.
    pub fn encrypt(&self, nonce: &[u8; 16], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        seal(self.init(nonce), aad, buffer)
    }

    /// Verifies `tag` and, only if it matches, decrypts `buffer` in place. On
    /// mismatch the buffer is left as ciphertext and [`TagMismatch`] is
    /// returned. The tag check is constant time.
    ///
    /// Without the `alloc` feature a `buffer` longer than 4 KiB also returns
    /// [`TagMismatch`]; see the module docs.
    pub fn decrypt(
        &self,
        nonce: &[u8; 16],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        open(self.init(nonce), aad, buffer, tag)
    }
}

impl Drop for Morus1280 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for Morus1280 {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // Wycheproof `morus640_test.json` / `morus1280_test.json`, tcId 1 (empty
    // message and AD) — the full files run in the integration harness.
    const KEY: &str = "b67b1a6efdd40d37080fbe8f8047aeb9";
    const NONCE: &str = "fa294b129972f7fc5bbd5b96bba837c9";

    #[test]
    fn morus640_empty() {
        let aead = Morus640::new(&from_hex::<16>(KEY));
        let nonce = from_hex::<16>(NONCE);
        let tag = aead.encrypt(&nonce, &[], &mut []);
        assert_eq!(tag, from_hex::<16>("2baf614371e3e6b295279730d3dd6dec"));
        aead.decrypt(&nonce, &[], &mut [], &tag).unwrap();
    }

    #[test]
    fn morus1280_empty_128bit_key() {
        let aead = Morus1280::new(&from_hex::<16>(KEY));
        let nonce = from_hex::<16>(NONCE);
        let tag = aead.encrypt(&nonce, &[], &mut []);
        assert_eq!(tag, from_hex::<16>("fc8a5aad4371edff2a0026597b848dff"));
        aead.decrypt(&nonce, &[], &mut [], &tag).unwrap();
    }

    #[test]
    fn round_trip_and_rejection() {
        let aead = Morus1280::new(&[0x42u8; 32]);
        let nonce = [1u8; 16];
        let aad = b"header";
        let msg = b"a message spanning more than one 32-byte block, plus a tail";
        let mut buf = msg.to_vec();
        let tag = aead.encrypt(&nonce, aad, &mut buf);
        assert_ne!(&buf[..], &msg[..]);
        let ct = buf.clone();

        let mut bad = tag;
        bad[15] ^= 1;
        assert_eq!(aead.decrypt(&nonce, aad, &mut buf, &bad), Err(TagMismatch));
        assert_eq!(buf, ct, "buffer untouched on failure");
        assert_eq!(
            aead.decrypt(&nonce, b"other", &mut buf, &tag),
            Err(TagMismatch)
        );

        aead.decrypt(&nonce, aad, &mut buf, &tag).unwrap();
        assert_eq!(&buf[..], &msg[..]);
        assert!(Morus1280::try_new(&[0u8; 24]).is_err());
    }
}
