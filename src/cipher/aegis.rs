//! AEGIS — AES-round-based authenticated encryption
//! (`draft-irtf-cfrg-aegis-aead`, the CFRG AEGIS family).
//!
//! Implements [`Aegis128L`] (128-bit key and nonce, eight-block state) and
//! [`Aegis256`] (256-bit key and nonce, six-block state). Both are AEAD schemes
//! whose state transition is built entirely from the bare AES round
//! ([`aes_round`](super::aes::aes_round)), so on a constant-time AES core the
//! whole construction is constant time and table-free.
//!
//! The crate AEAD shape is followed: [`encrypt`](Aegis128L::encrypt) transforms
//! the buffer in place and returns the 128-bit tag; [`decrypt`](Aegis128L::decrypt)
//! verifies the tag in constant time and only then releases the plaintext,
//! returning [`TagMismatch`] (and leaving the buffer untouched) on failure.
//! The 256-bit tag variants ([`encrypt_tag256`](Aegis128L::encrypt_tag256) /
//! [`decrypt_tag256`](Aegis128L::decrypt_tag256)) are also provided.
//!
//! As with all nonce-based AEADs, a given (key, nonce) pair must **never** be
//! reused.

use super::TagMismatch;
use super::aes::aes_round;
use crate::ct::ConstantTimeEq;

/// AEGIS constant `C0` (`draft-irtf-cfrg-aegis-aead`, derived from the
/// Fibonacci sequence modulo 256).
const C0: [u8; 16] = [
    0x00, 0x01, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62,
];
/// AEGIS constant `C1` (`draft-irtf-cfrg-aegis-aead`, derived from the
/// golden-ratio prime).
const C1: [u8; 16] = [
    0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd,
];

/// XOR of two 128-bit blocks.
#[inline]
fn xor(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = a[i] ^ b[i];
    }
    o
}

/// Bitwise AND of two 128-bit blocks.
#[inline]
fn and(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    let mut o = [0u8; 16];
    for i in 0..16 {
        o[i] = a[i] & b[i];
    }
    o
}

/// Loads up to 16 bytes as a block, zero-padded on the right.
#[inline]
fn zero_pad16(chunk: &[u8]) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..chunk.len()].copy_from_slice(chunk);
    b
}

/// Builds the 128-bit length block `LE64(ad_bits) || LE64(msg_bits)`.
#[inline]
fn len_block(ad_len: usize, msg_len: usize) -> [u8; 16] {
    let ad_bits = (ad_len as u64) * 8;
    let msg_bits = (msg_len as u64) * 8;
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&ad_bits.to_le_bytes());
    b[8..].copy_from_slice(&msg_bits.to_le_bytes());
    b
}

// ===========================================================================
// AEGIS-128L
// ===========================================================================

/// AEGIS-128L: 128-bit key, 128-bit nonce, 1024-bit (eight-block) state.
///
/// Construct with [`Aegis128L::new`], then call one of the AEAD methods. The
/// instance only stores the key; per-message state lives on the stack and is
/// wiped between calls.
#[derive(Clone)]
pub struct Aegis128L {
    key: [u8; 16],
}

/// The mutable 1024-bit AEGIS-128L state: eight 128-bit blocks.
struct State128L {
    s: [[u8; 16]; 8],
}

impl State128L {
    /// `StateUpdate128L(M0, M1)` — the AEGIS-128L round, injecting two 128-bit
    /// message blocks at state words 0 and 4.
    #[inline]
    fn update(&mut self, m0: [u8; 16], m1: [u8; 16]) {
        let s = &self.s;
        let n0 = aes_round(s[7], xor(s[0], m0));
        let n1 = aes_round(s[0], s[1]);
        let n2 = aes_round(s[1], s[2]);
        let n3 = aes_round(s[2], s[3]);
        let n4 = aes_round(s[3], xor(s[4], m1));
        let n5 = aes_round(s[4], s[5]);
        let n6 = aes_round(s[5], s[6]);
        let n7 = aes_round(s[6], s[7]);
        self.s = [n0, n1, n2, n3, n4, n5, n6, n7];
    }

    /// `Init(key, nonce)`.
    fn init(key: [u8; 16], nonce: [u8; 16]) -> Self {
        let kn = xor(key, nonce);
        let mut st = State128L {
            s: [kn, C1, C0, C1, kn, xor(key, C0), xor(key, C1), xor(key, C0)],
        };
        for _ in 0..10 {
            st.update(nonce, key);
        }
        st
    }

    /// `Absorb(ai)` for a full 256-bit AD block.
    #[inline]
    fn absorb(&mut self, t0: [u8; 16], t1: [u8; 16]) {
        self.update(t0, t1);
    }

    /// `Enc(xi)` for a full 256-bit plaintext block, returning the ciphertext.
    #[inline]
    fn enc(&mut self, t0: [u8; 16], t1: [u8; 16]) -> ([u8; 16], [u8; 16]) {
        let s = &self.s;
        let z0 = xor(xor(s[1], s[6]), and(s[2], s[3]));
        let z1 = xor(xor(s[2], s[5]), and(s[6], s[7]));
        let c0 = xor(t0, z0);
        let c1 = xor(t1, z1);
        self.update(t0, t1);
        (c0, c1)
    }

    /// `Dec(ci)` for a full 256-bit ciphertext block, returning the plaintext.
    #[inline]
    fn dec(&mut self, c0: [u8; 16], c1: [u8; 16]) -> ([u8; 16], [u8; 16]) {
        let s = &self.s;
        let z0 = xor(xor(s[1], s[6]), and(s[2], s[3]));
        let z1 = xor(xor(s[2], s[5]), and(s[6], s[7]));
        let t0 = xor(c0, z0);
        let t1 = xor(c1, z1);
        self.update(t0, t1);
        (t0, t1)
    }

    /// `Finalize`: returns the 256-bit raw tag material `S0..S7`.
    fn finalize(&mut self, ad_len: usize, msg_len: usize) {
        let t = xor(self.s[2], len_block(ad_len, msg_len));
        for _ in 0..7 {
            self.update(t, t);
        }
    }

    /// 128-bit tag: `S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5 ^ S6`.
    fn tag128(&self) -> [u8; 16] {
        let mut t = self.s[0];
        for i in 1..7 {
            t = xor(t, self.s[i]);
        }
        t
    }

    /// 256-bit tag: `(S0^S1^S2^S3) || (S4^S5^S6^S7)`.
    fn tag256(&self) -> [u8; 32] {
        let a = xor(xor(self.s[0], self.s[1]), xor(self.s[2], self.s[3]));
        let b = xor(xor(self.s[4], self.s[5]), xor(self.s[6], self.s[7]));
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&a);
        out[16..].copy_from_slice(&b);
        out
    }
}

impl Drop for State128L {
    fn drop(&mut self) {
        self.s = [[0u8; 16]; 8];
        let _ = core::hint::black_box(&self.s);
    }
}

/// Absorbs all associated data through the state.
fn absorb_ad_128l(st: &mut State128L, ad: &[u8]) {
    let mut chunks = ad.chunks_exact(32);
    for c in &mut chunks {
        st.absorb(zero_pad16(&c[..16]), zero_pad16(&c[16..]));
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let t0 = zero_pad16(&rem[..rem.len().min(16)]);
        let t1 = if rem.len() > 16 {
            zero_pad16(&rem[16..])
        } else {
            [0u8; 16]
        };
        st.absorb(t0, t1);
    }
}

impl Aegis128L {
    /// AEGIS-128L key size in bytes.
    pub const KEY_SIZE: usize = 16;
    /// AEGIS-128L nonce size in bytes.
    pub const NONCE_SIZE: usize = 16;
    /// AEGIS-128L tag size in bytes (the default 128-bit tag).
    pub const TAG_SIZE: usize = 16;

    /// Creates an AEGIS-128L instance from a 128-bit key.
    pub fn new(key: &[u8; 16]) -> Self {
        Aegis128L { key: *key }
    }

    fn encrypt_inner(&self, nonce: &[u8; 16], aad: &[u8], buffer: &mut [u8]) -> State128L {
        let mut st = State128L::init(self.key, *nonce);
        absorb_ad_128l(&mut st, aad);
        let msg_len = buffer.len();
        let mut chunks = buffer.chunks_exact_mut(32);
        for c in &mut chunks {
            let (c0, c1) = st.enc(zero_pad16(&c[..16]), zero_pad16(&c[16..]));
            c[..16].copy_from_slice(&c0);
            c[16..].copy_from_slice(&c1);
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let t0 = zero_pad16(&rem[..rem.len().min(16)]);
            let t1 = if rem.len() > 16 {
                zero_pad16(&rem[16..])
            } else {
                [0u8; 16]
            };
            let (c0, c1) = st.enc(t0, t1);
            let mut full = [0u8; 32];
            full[..16].copy_from_slice(&c0);
            full[16..].copy_from_slice(&c1);
            rem.copy_from_slice(&full[..rem.len()]);
        }
        st.finalize(aad.len(), msg_len);
        st
    }

    /// Encrypts `buffer` in place, binding `aad`, and returns the 128-bit tag.
    pub fn encrypt(&self, nonce: &[u8; 16], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        self.encrypt_inner(nonce, aad, buffer).tag128()
    }

    /// Encrypts `buffer` in place, binding `aad`, and returns the 256-bit tag.
    pub fn encrypt_tag256(&self, nonce: &[u8; 16], aad: &[u8], buffer: &mut [u8]) -> [u8; 32] {
        self.encrypt_inner(nonce, aad, buffer).tag256()
    }

    /// Decrypts the partial tail in place, returning the updated state. `buffer`
    /// holds the ciphertext on entry; the matching plaintext on return.
    fn decrypt_inner_tag(&self, nonce: &[u8; 16], aad: &[u8], buffer: &mut [u8]) -> State128L {
        let mut st = State128L::init(self.key, *nonce);
        absorb_ad_128l(&mut st, aad);
        let msg_len = buffer.len();
        let mut chunks = buffer.chunks_exact_mut(32);
        for c in &mut chunks {
            let mut c0 = [0u8; 16];
            let mut c1 = [0u8; 16];
            c0.copy_from_slice(&c[..16]);
            c1.copy_from_slice(&c[16..]);
            let (t0, t1) = st.dec(c0, c1);
            c[..16].copy_from_slice(&t0);
            c[16..].copy_from_slice(&t1);
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            // DecPartial: keystream-XOR the zero-padded ciphertext, truncate to
            // the real length, then absorb the re-zero-padded plaintext.
            let s = &st.s;
            let z0 = xor(xor(s[1], s[6]), and(s[2], s[3]));
            let z1 = xor(xor(s[2], s[5]), and(s[6], s[7]));
            let c0 = zero_pad16(&rem[..rem.len().min(16)]);
            let c1 = if rem.len() > 16 {
                zero_pad16(&rem[16..])
            } else {
                [0u8; 16]
            };
            let out0 = xor(c0, z0);
            let out1 = xor(c1, z1);
            let mut xn = [0u8; 32];
            xn[..16].copy_from_slice(&out0);
            xn[16..].copy_from_slice(&out1);
            // Truncate (zero the padding region) before feeding back in.
            for b in xn.iter_mut().skip(rem.len()) {
                *b = 0;
            }
            let v0 = zero_pad16(&xn[..16]);
            let v1 = zero_pad16(&xn[16..]);
            st.update(v0, v1);
            rem.copy_from_slice(&xn[..rem.len()]);
        }
        st.finalize(aad.len(), msg_len);
        st
    }

    /// Verifies `tag` (128-bit) and, only if it matches, decrypts `buffer` in
    /// place. On mismatch the buffer is left as ciphertext and [`TagMismatch`]
    /// is returned. The tag check is constant time.
    pub fn decrypt(
        &self,
        nonce: &[u8; 16],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        // Decrypt into a scratch copy so a tag failure leaves `buffer` intact.
        let mut scratch = ScratchVec::from_slice(buffer);
        let st = self.decrypt_inner_tag(nonce, aad, scratch.as_mut());
        let expected = st.tag128();
        if !bool::from(expected.ct_eq(tag)) {
            return Err(TagMismatch);
        }
        buffer.copy_from_slice(scratch.as_mut());
        Ok(())
    }

    /// Verifies `tag` (256-bit) and, only if it matches, decrypts `buffer` in
    /// place. On mismatch the buffer is left as ciphertext.
    pub fn decrypt_tag256(
        &self,
        nonce: &[u8; 16],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 32],
    ) -> Result<(), TagMismatch> {
        let mut scratch = ScratchVec::from_slice(buffer);
        let st = self.decrypt_inner_tag(nonce, aad, scratch.as_mut());
        let expected = st.tag256();
        if !bool::from(expected.ct_eq(tag)) {
            return Err(TagMismatch);
        }
        buffer.copy_from_slice(scratch.as_mut());
        Ok(())
    }
}

impl Drop for Aegis128L {
    fn drop(&mut self) {
        self.key = [0u8; 16];
        let _ = core::hint::black_box(&self.key);
    }
}

// ===========================================================================
// AEGIS-256
// ===========================================================================

/// AEGIS-256: 256-bit key, 256-bit nonce, 768-bit (six-block) state.
///
/// Construct with [`Aegis256::new`], then call one of the AEAD methods.
#[derive(Clone)]
pub struct Aegis256 {
    key: [u8; 32],
}

/// The mutable 768-bit AEGIS-256 state: six 128-bit blocks.
struct State256 {
    s: [[u8; 16]; 6],
}

impl State256 {
    /// `StateUpdate256(M)` — the AEGIS-256 round, injecting one 128-bit block
    /// at state word 0.
    #[inline]
    fn update(&mut self, m: [u8; 16]) {
        let s = &self.s;
        let n0 = aes_round(s[5], xor(s[0], m));
        let n1 = aes_round(s[0], s[1]);
        let n2 = aes_round(s[1], s[2]);
        let n3 = aes_round(s[2], s[3]);
        let n4 = aes_round(s[3], s[4]);
        let n5 = aes_round(s[4], s[5]);
        self.s = [n0, n1, n2, n3, n4, n5];
    }

    /// `Init(key, nonce)`.
    fn init(key: [u8; 32], nonce: [u8; 32]) -> Self {
        let mut k0 = [0u8; 16];
        let mut k1 = [0u8; 16];
        k0.copy_from_slice(&key[..16]);
        k1.copy_from_slice(&key[16..]);
        let mut n0 = [0u8; 16];
        let mut n1 = [0u8; 16];
        n0.copy_from_slice(&nonce[..16]);
        n1.copy_from_slice(&nonce[16..]);
        let mut st = State256 {
            s: [xor(k0, n0), xor(k1, n1), C1, C0, xor(k0, C0), xor(k1, C1)],
        };
        let kn0 = xor(k0, n0);
        let kn1 = xor(k1, n1);
        for _ in 0..4 {
            st.update(k0);
            st.update(k1);
            st.update(kn0);
            st.update(kn1);
        }
        st
    }

    /// `Absorb(ai)` for a full 128-bit AD block.
    #[inline]
    fn absorb(&mut self, t: [u8; 16]) {
        self.update(t);
    }

    /// `Enc(xi)` for a full 128-bit plaintext block, returning ciphertext.
    #[inline]
    fn enc(&mut self, t: [u8; 16]) -> [u8; 16] {
        let s = &self.s;
        let z = xor(xor(xor(s[1], s[4]), s[5]), and(s[2], s[3]));
        let c = xor(t, z);
        self.update(t);
        c
    }

    /// `Dec(ci)` for a full 128-bit ciphertext block, returning plaintext.
    #[inline]
    fn dec(&mut self, c: [u8; 16]) -> [u8; 16] {
        let s = &self.s;
        let z = xor(xor(xor(s[1], s[4]), s[5]), and(s[2], s[3]));
        let t = xor(c, z);
        self.update(t);
        t
    }

    /// `Finalize`.
    fn finalize(&mut self, ad_len: usize, msg_len: usize) {
        let t = xor(self.s[3], len_block(ad_len, msg_len));
        for _ in 0..7 {
            self.update(t);
        }
    }

    /// 128-bit tag: `S0 ^ S1 ^ S2 ^ S3 ^ S4 ^ S5`.
    fn tag128(&self) -> [u8; 16] {
        let mut t = self.s[0];
        for i in 1..6 {
            t = xor(t, self.s[i]);
        }
        t
    }

    /// 256-bit tag: `(S0^S1^S2) || (S3^S4^S5)`.
    fn tag256(&self) -> [u8; 32] {
        let a = xor(xor(self.s[0], self.s[1]), self.s[2]);
        let b = xor(xor(self.s[3], self.s[4]), self.s[5]);
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&a);
        out[16..].copy_from_slice(&b);
        out
    }
}

impl Drop for State256 {
    fn drop(&mut self) {
        self.s = [[0u8; 16]; 6];
        let _ = core::hint::black_box(&self.s);
    }
}

/// Absorbs all associated data through the state.
fn absorb_ad_256(st: &mut State256, ad: &[u8]) {
    let mut chunks = ad.chunks_exact(16);
    for c in &mut chunks {
        st.absorb(zero_pad16(c));
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        st.absorb(zero_pad16(rem));
    }
}

impl Aegis256 {
    /// AEGIS-256 key size in bytes.
    pub const KEY_SIZE: usize = 32;
    /// AEGIS-256 nonce size in bytes.
    pub const NONCE_SIZE: usize = 32;
    /// AEGIS-256 tag size in bytes (the default 128-bit tag).
    pub const TAG_SIZE: usize = 16;

    /// Creates an AEGIS-256 instance from a 256-bit key.
    pub fn new(key: &[u8; 32]) -> Self {
        Aegis256 { key: *key }
    }

    fn encrypt_inner(&self, nonce: &[u8; 32], aad: &[u8], buffer: &mut [u8]) -> State256 {
        let mut st = State256::init(self.key, *nonce);
        absorb_ad_256(&mut st, aad);
        let msg_len = buffer.len();
        let mut chunks = buffer.chunks_exact_mut(16);
        for c in &mut chunks {
            let ct = st.enc(zero_pad16(c));
            c.copy_from_slice(&ct);
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let ct = st.enc(zero_pad16(rem));
            rem.copy_from_slice(&ct[..rem.len()]);
        }
        st.finalize(aad.len(), msg_len);
        st
    }

    /// Encrypts `buffer` in place, binding `aad`, and returns the 128-bit tag.
    pub fn encrypt(&self, nonce: &[u8; 32], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        self.encrypt_inner(nonce, aad, buffer).tag128()
    }

    /// Encrypts `buffer` in place, binding `aad`, and returns the 256-bit tag.
    pub fn encrypt_tag256(&self, nonce: &[u8; 32], aad: &[u8], buffer: &mut [u8]) -> [u8; 32] {
        self.encrypt_inner(nonce, aad, buffer).tag256()
    }

    fn decrypt_inner_tag(&self, nonce: &[u8; 32], aad: &[u8], buffer: &mut [u8]) -> State256 {
        let mut st = State256::init(self.key, *nonce);
        absorb_ad_256(&mut st, aad);
        let msg_len = buffer.len();
        let mut chunks = buffer.chunks_exact_mut(16);
        for c in &mut chunks {
            let mut ci = [0u8; 16];
            ci.copy_from_slice(c);
            let t = st.dec(ci);
            c.copy_from_slice(&t);
        }
        let rem = chunks.into_remainder();
        if !rem.is_empty() {
            let s = &st.s;
            let z = xor(xor(xor(s[1], s[4]), s[5]), and(s[2], s[3]));
            let out = xor(zero_pad16(rem), z);
            let mut xn = out;
            for b in xn.iter_mut().skip(rem.len()) {
                *b = 0;
            }
            st.update(xn);
            rem.copy_from_slice(&xn[..rem.len()]);
        }
        st.finalize(aad.len(), msg_len);
        st
    }

    /// Verifies `tag` (128-bit) and, only if it matches, decrypts `buffer` in
    /// place. On mismatch the buffer is left as ciphertext.
    pub fn decrypt(
        &self,
        nonce: &[u8; 32],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        let mut scratch = ScratchVec::from_slice(buffer);
        let st = self.decrypt_inner_tag(nonce, aad, scratch.as_mut());
        let expected = st.tag128();
        if !bool::from(expected.ct_eq(tag)) {
            return Err(TagMismatch);
        }
        buffer.copy_from_slice(scratch.as_mut());
        Ok(())
    }

    /// Verifies `tag` (256-bit) and, only if it matches, decrypts `buffer` in
    /// place. On mismatch the buffer is left as ciphertext.
    pub fn decrypt_tag256(
        &self,
        nonce: &[u8; 32],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 32],
    ) -> Result<(), TagMismatch> {
        let mut scratch = ScratchVec::from_slice(buffer);
        let st = self.decrypt_inner_tag(nonce, aad, scratch.as_mut());
        let expected = st.tag256();
        if !bool::from(expected.ct_eq(tag)) {
            return Err(TagMismatch);
        }
        buffer.copy_from_slice(scratch.as_mut());
        Ok(())
    }
}

impl Drop for Aegis256 {
    fn drop(&mut self) {
        self.key = [0u8; 32];
        let _ = core::hint::black_box(&self.key);
    }
}

/// A small heap-free scratch buffer for trial decryption, so a tag mismatch
/// never overwrites the caller's ciphertext. Uses `alloc` when available, and
/// a fixed-size inline buffer otherwise (decryption inputs above the inline cap
/// require `alloc`).
struct ScratchVec {
    #[cfg(feature = "alloc")]
    data: alloc::vec::Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    data: [u8; 4096],
    #[cfg(not(feature = "alloc"))]
    len: usize,
}

impl ScratchVec {
    #[cfg(feature = "alloc")]
    fn from_slice(s: &[u8]) -> Self {
        ScratchVec { data: s.to_vec() }
    }

    #[cfg(not(feature = "alloc"))]
    fn from_slice(s: &[u8]) -> Self {
        assert!(
            s.len() <= 4096,
            "AEGIS decryption of >4096 bytes requires the `alloc` feature"
        );
        let mut data = [0u8; 4096];
        data[..s.len()].copy_from_slice(s);
        ScratchVec { data, len: s.len() }
    }

    #[cfg(feature = "alloc")]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    #[cfg(not(feature = "alloc"))]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data[..self.len]
    }
}

impl Drop for ScratchVec {
    fn drop(&mut self) {
        for b in self.as_mut().iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(self.as_mut());
    }
}

// The KAT suite uses `Vec`-backed hex fixtures, so it requires `alloc`.
#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::test_util::from_hex;
    use crate::test_util::from_hex_vec;

    // --- AEGIS-128L Update intermediate (draft Appendix A.2.1) ---
    #[test]
    fn aegis128l_update_kat() {
        let mut st = State128L {
            s: [
                from_hex::<16>("9b7e60b24cc873ea894ecc07911049a3"),
                from_hex::<16>("330be08f35300faa2ebf9a7b0d274658"),
                from_hex::<16>("7bbd5bd2b049f7b9b515cf26fbe7756c"),
                from_hex::<16>("c35a00f55ea86c3886ec5e928f87db18"),
                from_hex::<16>("9ebccafce87cab446396c4334592c91f"),
                from_hex::<16>("58d83e31f256371e60fc6bb257114601"),
                from_hex::<16>("1639b56ea322c88568a176585bc915de"),
                from_hex::<16>("640818ffb57dc0fbc2e72ae93457e39a"),
            ],
        };
        st.update(
            from_hex::<16>("033e6975b94816879e42917650955aa0"),
            from_hex::<16>("fcc1968a46b7e97861bd6e89af6aa55f"),
        );
        assert_eq!(st.s[0], from_hex::<16>("596ab773e4433ca0127c73f60536769d"));
        assert_eq!(st.s[1], from_hex::<16>("790394041a3d26ab697bde865014652d"));
        assert_eq!(st.s[2], from_hex::<16>("38cf49e4b65248acd533041b64dd0611"));
        assert_eq!(st.s[3], from_hex::<16>("16d8e58748f437bfff1797f780337cee"));
        assert_eq!(st.s[4], from_hex::<16>("9689ecdf08228c74d7e3360cca53d0a5"));
        assert_eq!(st.s[5], from_hex::<16>("a21746bb193a569e331e1aa985d0d729"));
        assert_eq!(st.s[6], from_hex::<16>("09d714e6fcf9177a8ed1cde7e3d259a6"));
        assert_eq!(st.s[7], from_hex::<16>("61279ba73167f0ab76f0a11bf203bdff"));
    }

    fn check_128l(
        key: &str,
        nonce: &str,
        ad: &str,
        msg: &str,
        ct: &str,
        tag128: &str,
        tag256: &str,
    ) {
        let k = from_hex::<16>(key);
        let n = from_hex::<16>(nonce);
        let aad = from_hex_vec(ad);
        let pt = from_hex_vec(msg);
        let expect_ct = from_hex_vec(ct);
        let cipher = Aegis128L::new(&k);

        // 128-bit tag.
        let mut buf = pt.clone();
        let t = cipher.encrypt(&n, &aad, &mut buf);
        assert_eq!(buf, expect_ct, "ct mismatch ({msg})");
        assert_eq!(&t[..], &from_hex_vec(tag128)[..], "tag128 mismatch ({msg})");
        cipher.decrypt(&n, &aad, &mut buf, &t).unwrap();
        assert_eq!(buf, pt, "decrypt roundtrip ({msg})");

        // 256-bit tag.
        let mut buf = pt.clone();
        let t256_v = from_hex_vec(tag256);
        let mut t256 = [0u8; 32];
        t256.copy_from_slice(&t256_v);
        let t = cipher.encrypt_tag256(&n, &aad, &mut buf);
        assert_eq!(buf, expect_ct, "ct mismatch tag256 ({msg})");
        assert_eq!(t, t256, "tag256 mismatch ({msg})");
        cipher.decrypt_tag256(&n, &aad, &mut buf, &t).unwrap();
        assert_eq!(buf, pt, "decrypt256 roundtrip ({msg})");
    }

    #[test]
    fn aegis128l_tv1() {
        check_128l(
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "",
            "00000000000000000000000000000000",
            "c1c0e58bd913006feba00f4b3cc3594e",
            "abe0ece80c24868a226a35d16bdae37a",
            "25835bfbb21632176cf03840687cb968cace4617af1bd0f7d064c639a5c79ee4",
        );
    }

    #[test]
    fn aegis128l_tv2_empty() {
        check_128l(
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "",
            "",
            "",
            "c2b879a67def9d74e6c14f708bbcc9b4",
            "1360dc9db8ae42455f6e5b6a9d488ea4f2184c4e12120249335c4ee84bafe25d",
        );
    }

    #[test]
    fn aegis128l_tv3() {
        check_128l(
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "0001020304050607",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "79d94593d8c2119d7e8fd9b8fc77845c5c077a05b2528b6ac54b563aed8efe84",
            "cc6f3372f6aa1bb82388d695c3962d9a",
            "022cb796fe7e0ae1197525ff67e309484cfbab6528ddef89f17d74ef8ecd82b3",
        );
    }

    #[test]
    fn aegis128l_tv4_partial() {
        check_128l(
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "0001020304050607",
            "000102030405060708090a0b0c0d",
            "79d94593d8c2119d7e8fd9b8fc77",
            "5c04b3dba849b2701effbe32c7f0fab7",
            "86f1b80bfb463aba711d15405d094baf4a55a15dbfec81a76f35ed0b9c8b04ac",
        );
    }

    #[test]
    fn aegis128l_tv5_long() {
        check_128l(
            "10010000000000000000000000000000",
            "10000200000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "b31052ad1cca4e291abcf2df3502e6bdb1bfd6db36798be3607b1f94d34478aa7ede7f7a990fec10",
            "7542a745733014f9474417b337399507",
            "b91e2947a33da8bee89b6794e647baf0fc835ff574aca3fc27c33be0db2aff98",
        );
    }

    #[test]
    fn aegis128l_auth_failure() {
        // TV6: key/nonce swapped vs TV4 — must reject.
        let k = from_hex::<16>("10000200000000000000000000000000");
        let n = from_hex::<16>("10010000000000000000000000000000");
        let aad = from_hex_vec("0001020304050607");
        let cipher = Aegis128L::new(&k);
        let mut buf = from_hex_vec("79d94593d8c2119d7e8fd9b8fc77");
        let saved = buf.clone();
        let tag = from_hex::<16>("5c04b3dba849b2701effbe32c7f0fab7");
        assert_eq!(cipher.decrypt(&n, &aad, &mut buf, &tag), Err(TagMismatch));
        assert_eq!(buf, saved, "buffer must be untouched on auth failure");

        // TV7: altered last ciphertext byte.
        let k = from_hex::<16>("10010000000000000000000000000000");
        let n = from_hex::<16>("10000200000000000000000000000000");
        let cipher = Aegis128L::new(&k);
        let mut buf = from_hex_vec("79d94593d8c2119d7e8fd9b8fc78");
        let tag = from_hex::<16>("5c04b3dba849b2701effbe32c7f0fab7");
        assert_eq!(cipher.decrypt(&n, &aad, &mut buf, &tag), Err(TagMismatch));

        // TV8: altered AD.
        let aad_bad = from_hex_vec("0001020304050608");
        let mut buf = from_hex_vec("79d94593d8c2119d7e8fd9b8fc77");
        assert_eq!(
            cipher.decrypt(&n, &aad_bad, &mut buf, &tag),
            Err(TagMismatch)
        );

        // TV9: altered tag.
        let mut buf = from_hex_vec("79d94593d8c2119d7e8fd9b8fc77");
        let bad_tag = from_hex::<16>("6c04b3dba849b2701effbe32c7f0fab8");
        assert_eq!(
            cipher.decrypt(&n, &aad, &mut buf, &bad_tag),
            Err(TagMismatch)
        );
    }

    // --- AEGIS-256 Update intermediate (draft Appendix A.3.1) ---
    #[test]
    fn aegis256_update_kat() {
        let mut st = State256 {
            s: [
                from_hex::<16>("1fa1207ed76c86f2c4bb40e8b395b43e"),
                from_hex::<16>("b44c375e6c1e1978db64bcd12e9e332f"),
                from_hex::<16>("0dab84bfa9f0226432ff630f233d4e5b"),
                from_hex::<16>("d7ef65c9b93e8ee60c75161407b066e7"),
                from_hex::<16>("a760bb3da073fbd92bdc24734b1f56fb"),
                from_hex::<16>("a828a18d6a964497ac6e7e53c5f55c73"),
            ],
        };
        st.update(from_hex::<16>("b165617ed04ab738afb2612c6d18a1ec"));
        assert_eq!(st.s[0], from_hex::<16>("e6bc643bae82dfa3d991b1b323839dcd"));
        assert_eq!(st.s[1], from_hex::<16>("648578232ba0f2f0a3677f617dc052c3"));
        assert_eq!(st.s[2], from_hex::<16>("ea788e0e572044a46059212dd007a789"));
        assert_eq!(st.s[3], from_hex::<16>("2f1498ae19b80da13fba698f088a8590"));
        assert_eq!(st.s[4], from_hex::<16>("a54c2ee95e8c2a2c3dae2ec743ae6b86"));
        assert_eq!(st.s[5], from_hex::<16>("a3240fceb68e32d5d114df1b5363ab67"));
    }

    fn check_256(
        key: &str,
        nonce: &str,
        ad: &str,
        msg: &str,
        ct: &str,
        tag128: &str,
        tag256: &str,
    ) {
        let k = from_hex::<32>(key);
        let n = from_hex::<32>(nonce);
        let aad = from_hex_vec(ad);
        let pt = from_hex_vec(msg);
        let expect_ct = from_hex_vec(ct);
        let cipher = Aegis256::new(&k);

        let mut buf = pt.clone();
        let t = cipher.encrypt(&n, &aad, &mut buf);
        assert_eq!(buf, expect_ct, "ct mismatch ({msg})");
        assert_eq!(&t[..], &from_hex_vec(tag128)[..], "tag128 mismatch ({msg})");
        cipher.decrypt(&n, &aad, &mut buf, &t).unwrap();
        assert_eq!(buf, pt, "decrypt roundtrip ({msg})");

        let mut buf = pt.clone();
        let t256_v = from_hex_vec(tag256);
        let mut t256 = [0u8; 32];
        t256.copy_from_slice(&t256_v);
        let t = cipher.encrypt_tag256(&n, &aad, &mut buf);
        assert_eq!(buf, expect_ct, "ct mismatch tag256 ({msg})");
        assert_eq!(t, t256, "tag256 mismatch ({msg})");
        cipher.decrypt_tag256(&n, &aad, &mut buf, &t).unwrap();
        assert_eq!(buf, pt, "decrypt256 roundtrip ({msg})");
    }

    #[test]
    fn aegis256_tv1() {
        check_256(
            "1001000000000000000000000000000000000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "",
            "00000000000000000000000000000000",
            "754fc3d8c973246dcc6d741412a4b236",
            "3fe91994768b332ed7f570a19ec5896e",
            "1181a1d18091082bf0266f66297d167d2e68b845f61a3b0527d31fc7b7b89f13",
        );
    }

    #[test]
    fn aegis256_tv2_empty() {
        check_256(
            "1001000000000000000000000000000000000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "",
            "",
            "",
            "e3def978a0f054afd1e761d7553afba3",
            "6a348c930adbd654896e1666aad67de989ea75ebaa2b82fb588977b1ffec864a",
        );
    }

    #[test]
    fn aegis256_tv3() {
        check_256(
            "1001000000000000000000000000000000000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "f373079ed84b2709faee373584585d60accd191db310ef5d8b11833df9dec711",
            "8d86f91ee606e9ff26a01b64ccbdd91d",
            "b7d28d0c3c0ebd409fd22b44160503073a547412da0854bfb9723020dab8da1a",
        );
    }

    #[test]
    fn aegis256_tv4_partial() {
        check_256(
            "1001000000000000000000000000000000000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "0001020304050607",
            "000102030405060708090a0b0c0d",
            "f373079ed84b2709faee37358458",
            "c60b9c2d33ceb058f96e6dd03c215652",
            "8c1cc703c81281bee3f6d9966e14948b4a175b2efbdc31e61a98b4465235c2d9",
        );
    }

    #[test]
    fn aegis256_tv5_long() {
        check_256(
            "1001000000000000000000000000000000000000000000000000000000000000",
            "1000020000000000000000000000000000000000000000000000000000000000",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
            "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637",
            "57754a7d09963e7c787583a2e7b859bb24fa1e04d49fd550b2511a358e3bca252a9b1b8b30cc4a67",
            "ab8a7d53fd0e98d727accca94925e128",
            "a3aca270c006094d71c20e6910b5161c0826df233d08919a566ec2c05990f734",
        );
    }

    #[test]
    fn aegis256_auth_failure() {
        // TV6: key/nonce swapped.
        let k = from_hex::<32>("1000020000000000000000000000000000000000000000000000000000000000");
        let n = from_hex::<32>("1001000000000000000000000000000000000000000000000000000000000000");
        let aad = from_hex_vec("0001020304050607");
        let cipher = Aegis256::new(&k);
        let mut buf = from_hex_vec("f373079ed84b2709faee37358458");
        let saved = buf.clone();
        let tag = from_hex::<16>("c60b9c2d33ceb058f96e6dd03c215652");
        assert_eq!(cipher.decrypt(&n, &aad, &mut buf, &tag), Err(TagMismatch));
        assert_eq!(buf, saved, "buffer must be untouched on auth failure");

        // TV9: altered tag with correct key/nonce.
        let k = from_hex::<32>("1001000000000000000000000000000000000000000000000000000000000000");
        let n = from_hex::<32>("1000020000000000000000000000000000000000000000000000000000000000");
        let cipher = Aegis256::new(&k);
        let mut buf = from_hex_vec("f373079ed84b2709faee37358458");
        let bad_tag = from_hex::<16>("c60b9c2d33ceb058f96e6dd03c215653");
        assert_eq!(
            cipher.decrypt(&n, &aad, &mut buf, &bad_tag),
            Err(TagMismatch)
        );
    }
}
