//! The ChaCha20 stream cipher (RFC 8439 §2.4).
//!
//! ChaCha20 expands a 256-bit key, a 96-bit nonce and a 32-bit block counter
//! into a 64-byte keystream block by running 20 rounds (ten "double rounds") of
//! the quarter-round function over a 4×4 matrix of 32-bit words. The cipher is
//! inherently constant time: it is built from 32-bit add/xor/rotate with no
//! secret-dependent branches or memory indexing.
//!
//! A given (key, nonce) pair must **never** be reused with overlapping counter
//! ranges: as with any stream cipher, keystream reuse destroys confidentiality.

use super::CounterOverflow;

/// The ChaCha20 constants — the ASCII string `"expand 32-byte k"` as four
/// little-endian words (RFC 8439 §2.3).
const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// Best-effort wipe of the state matrix inside [`ChaCha20::block`].
///
/// Every ChaCha20 state matrix embeds the 256-bit key, and raw keystream is
/// key-equivalent for the bytes it covers — neither should be left behind in a
/// dead stack frame for a later caller to read.
///
/// This is deliberately **not** [`crate::zeroize::Zeroize`]: `block` runs once
/// per 64 bytes on the scalar path, and volatile stores are never merged into
/// the single vector store the plain assignment compiles to — measured at ~7%
/// of that kernel's throughput. `Zeroize`'s word-at-a-time path narrows the
/// gap but cannot close it, since this is per-block rather than per-operation.
/// Per-operation wipes elsewhere in the crate (including this cipher's own
/// one-time key and Poly1305 state) do use `Zeroize`.
#[inline]
fn wipe_words(w: &mut [u32; 16]) {
    *w = [0u32; 16];
    let _ = core::hint::black_box(w);
}

/// The ChaCha20 quarter-round on four words of the state (RFC 8439 §2.1).
#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// HChaCha20 (draft-irtf-cfrg-xchacha §2.2): a keyed hash producing a 256-bit
/// subkey from a 256-bit key and a 128-bit nonce. It runs the 20-round ChaCha20
/// permutation over `constants ‖ key ‖ nonce16` and returns the first and last
/// four state words **without** the final feed-forward addition. Used to derive
/// the per-message subkey in [`XChaCha20`] and
/// [`XChaCha20Poly1305`](super::XChaCha20Poly1305); equivalent to libsodium's
/// `crypto_core_hchacha20` with the default constant (`c = NULL`).
///
/// Constant time. The output is a full-strength key: wipe it when done.
pub fn hchacha20(key: &[u8; 32], nonce16: &[u8; 16]) -> [u8; 32] {
    let mut s = [0u32; 16];
    s[0..4].copy_from_slice(&CONSTANTS);
    for (word, chunk) in s[4..12].iter_mut().zip(key.chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for (word, chunk) in s[12..16].iter_mut().zip(nonce16.chunks_exact(4)) {
        *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    for _ in 0..10 {
        quarter_round(&mut s, 0, 4, 8, 12);
        quarter_round(&mut s, 1, 5, 9, 13);
        quarter_round(&mut s, 2, 6, 10, 14);
        quarter_round(&mut s, 3, 7, 11, 15);
        quarter_round(&mut s, 0, 5, 10, 15);
        quarter_round(&mut s, 1, 6, 11, 12);
        quarter_round(&mut s, 2, 7, 8, 13);
        quarter_round(&mut s, 3, 4, 9, 14);
    }

    let mut out = [0u8; 32];
    // Output words 0..=3 followed by 12..=15 (no final add).
    for (i, &idx) in [0usize, 1, 2, 3, 12, 13, 14, 15].iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&s[idx].to_le_bytes());
    }
    // `s[4..12]` held the input key verbatim before the permutation and the
    // rest of the matrix is the subkey; neither belongs in a dead frame.
    wipe_words(&mut s);
    out
}

/// A ChaCha20 cipher keyed with a 256-bit key.
///
/// # Variants and counter overflow
///
/// State words 12..=15 hold the block counter and the nonce; the variants
/// differ only in where the boundary between them sits:
///
/// | API | words 12..=15 | counter range | libsodium / OpenSSL |
/// | --- | --- | --- | --- |
/// | [`ChaCha20::apply_keystream`] / [`try_apply_keystream`](ChaCha20::try_apply_keystream) | `ctr32 ‖ nonce96` (RFC 8439) | `2³²` blocks (256 GiB) | `crypto_stream_chacha20_ietf_xor_ic` |
/// | [`ChaCha20::apply_keystream_djb`] / [`block_djb`](ChaCha20::block_djb) | `ctr64 ‖ nonce64` (original) | `2⁶⁴` blocks | `crypto_stream_chacha20_xor_ic` |
/// | [`ChaCha20::apply_keystream_carry`] | `ctr32 ‖ nonce96`, carry into the first nonce word | `2⁶⁴` blocks | OpenSSL `EVP_chacha20` (16-byte IV `ctr32 ‖ nonce96`) |
/// | [`XChaCha20::apply_keystream`] | HChaCha20 subkey, then `ctr64 ‖ nonce[16..24]` | `2⁶⁴` blocks | `crypto_stream_xchacha20_xor_ic` |
///
/// None of them ever wraps silently, because a wrapped counter replays
/// keystream already used for this (key, nonce):
///
/// * RFC 8439 defines no carry, so the IETF form stops at `2³²` blocks.
///   [`apply_keystream`](ChaCha20::apply_keystream) keeps its historical
///   panic there; [`try_apply_keystream`](ChaCha20::try_apply_keystream)
///   returns [`CounterOverflow`] instead (libsodium aborts the process).
/// * [`apply_keystream_carry`](ChaCha20::apply_keystream_carry) is the same
///   state layout, but when word 12 wraps it carries into word 13 — the first
///   word of the nonce — exactly as OpenSSL does. Output is identical to the
///   IETF form up to the `2³²` boundary and continues past it with what
///   OpenSSL produces. (OpenSSL lets word 13 itself wrap without further
///   carry; that is the `2⁶⁴`-block limit of this form, where it returns
///   [`CounterOverflow`].) Use it only where OpenSSL interop is the point:
///   the blocks past the boundary belong to a *different* RFC 8439 nonce.
/// * The 64-bit-counter forms carry between words 12 and 13 naturally and
///   return [`CounterOverflow`] only if the counter would pass `2⁶⁴ − 1`,
///   which needs a starting counter within a buffer's length of the top.
///
/// In every case the check happens before any byte is touched, so on error
/// the buffer is unchanged.
#[derive(Clone)]
pub struct ChaCha20 {
    key: [u32; 8],
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        // The whole state *is* the 256-bit key, so without this a retired
        // ChaCha20 traffic key (TLS 1.3 `KeyUpdate`, connection close) stays in
        // freed memory — where the AES-GCM `RecordCrypter` scrubs its round
        // keys and GHASH subkey. `Zeroize` gives volatile stores plus a
        // compiler fence, so LLVM cannot elide them as dead stores.
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for ChaCha20 {}

impl ChaCha20 {
    /// Creates a ChaCha20 cipher from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut k = [0u32; 8];
        for (word, chunk) in k.iter_mut().zip(key.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        ChaCha20 { key: k }
    }

    /// Builds the initial state matrix for a nonce and block counter.
    fn state(&self, nonce: &[u8; 12], counter: u32) -> [u32; 16] {
        let mut s = [0u32; 16];
        s[0..4].copy_from_slice(&CONSTANTS);
        s[4..12].copy_from_slice(&self.key);
        s[12] = counter;
        for (word, chunk) in s[13..16].iter_mut().zip(nonce.chunks_exact(4)) {
            *word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        s
    }

    /// Generates the 64-byte keystream block for `(nonce, counter)`.
    pub fn block(&self, nonce: &[u8; 12], counter: u32) -> [u8; 64] {
        let mut initial = self.state(nonce, counter);
        let mut s = initial;
        // 20 rounds = 10 double-rounds (column rounds then diagonal rounds).
        for _ in 0..10 {
            quarter_round(&mut s, 0, 4, 8, 12);
            quarter_round(&mut s, 1, 5, 9, 13);
            quarter_round(&mut s, 2, 6, 10, 14);
            quarter_round(&mut s, 3, 7, 11, 15);
            quarter_round(&mut s, 0, 5, 10, 15);
            quarter_round(&mut s, 1, 6, 11, 12);
            quarter_round(&mut s, 2, 7, 8, 13);
            quarter_round(&mut s, 3, 4, 9, 14);
        }

        let mut out = [0u8; 64];
        for (i, chunk) in out.chunks_exact_mut(4).enumerate() {
            let word = s[i].wrapping_add(initial[i]);
            chunk.copy_from_slice(&word.to_le_bytes());
        }
        // `initial[4..12]` is the key; `s` is the pre-feed-forward state
        // (key-equivalent for this block).
        wipe_words(&mut initial);
        wipe_words(&mut s);
        out
    }

    /// Generates the 64-byte keystream block for the original (DJB) layout:
    /// a 64-bit block `counter` in state words 12–13 and a 64-bit `nonce` in
    /// words 14–15 (libsodium `crypto_stream_chacha20`).
    pub fn block_djb(&self, nonce: &[u8; 8], counter: u64) -> [u8; 64] {
        let n12 = djb_nonce12((counter >> 32) as u32, nonce);
        self.block(&n12, counter as u32)
    }

    /// XORs the keystream into `buf` in place, starting at block `counter`
    /// (RFC 8439 §2.4). The counter increments per 64-byte block.
    ///
    /// # Panics
    /// Panics if the requested operation would wrap the 32-bit block counter.
    /// RFC 8439 §2.4 caps a single ChaCha20 invocation at `2^32` blocks
    /// (256 GiB), and the AEAD wrapper at `2^32 − 1` (because counter 0 is
    /// reserved for the Poly1305 OTK). Wrapping would reuse keystream and
    /// catastrophically break confidentiality — fail loud rather than
    /// silently produce a two-time pad. Use
    /// [`try_apply_keystream`](Self::try_apply_keystream) to get an error
    /// instead, or [`apply_keystream_carry`](Self::apply_keystream_carry) for
    /// OpenSSL's carry-into-the-nonce behaviour (see the
    /// [type-level docs](ChaCha20#variants-and-counter-overflow)).
    pub fn apply_keystream(&self, nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        assert!(
            ietf_fits(counter, buf.len()),
            "ChaCha20 counter would overflow 2^32 (buf too large for a single invocation)"
        );
        self.xor_ctr32(nonce, counter, buf);
    }

    /// Fallible [`apply_keystream`](Self::apply_keystream): XORs the RFC 8439
    /// keystream into `buf` starting at block `counter`, or returns
    /// [`CounterOverflow`] — with `buf` untouched — if that would need more
    /// than the `2³² − counter` blocks left before the 32-bit counter wraps.
    /// Matches libsodium's `crypto_stream_chacha20_ietf_xor_ic`, which aborts
    /// the process in the same case.
    pub fn try_apply_keystream(
        &self,
        nonce: &[u8; 12],
        counter: u32,
        buf: &mut [u8],
    ) -> Result<(), CounterOverflow> {
        if !ietf_fits(counter, buf.len()) {
            return Err(CounterOverflow);
        }
        self.xor_ctr32(nonce, counter, buf);
        Ok(())
    }

    /// XORs the keystream of the original (DJB) ChaCha20 into `buf` in place:
    /// 64-bit `nonce`, 64-bit block `counter` starting at the given value
    /// (libsodium `crypto_stream_chacha20_xor_ic`; `counter = 0` gives
    /// `crypto_stream_chacha20_xor`).
    ///
    /// The counter carries from its low word into its high word as the
    /// original design specifies, so for `counter < 2³²` the output also
    /// matches [`apply_keystream_carry`](Self::apply_keystream_carry) with a
    /// nonce of `[0; 4] ‖ nonce`. Returns [`CounterOverflow`], with `buf`
    /// untouched, only if the counter would pass `2⁶⁴ − 1` — where libsodium
    /// silently wraps.
    pub fn apply_keystream_djb(
        &self,
        nonce: &[u8; 8],
        counter: u64,
        buf: &mut [u8],
    ) -> Result<(), CounterOverflow> {
        self.xor_ctr64(counter, nonce, buf)
    }

    /// XORs the keystream into `buf` in place with OpenSSL's counter
    /// semantics: the state is laid out as in RFC 8439 (`counter ‖ nonce`,
    /// i.e. OpenSSL `EVP_chacha20`'s 16-byte IV is `counter` little-endian
    /// followed by `nonce`), but when the 32-bit block counter wraps it
    /// carries into the first nonce word instead of stopping.
    ///
    /// Byte-identical to [`apply_keystream`](Self::apply_keystream) whenever
    /// that does not panic. Past the `2³²`-block boundary it reproduces
    /// OpenSSL's output; note that those blocks are the keystream of a
    /// different RFC 8439 nonce (first nonce word + 1), so do not mix this
    /// with nonces chosen as consecutive integers in that word. Returns
    /// [`CounterOverflow`], with `buf` untouched, if the 64-bit combined
    /// counter would pass `2⁶⁴ − 1` (where OpenSSL silently wraps).
    pub fn apply_keystream_carry(
        &self,
        nonce: &[u8; 12],
        counter: u32,
        buf: &mut [u8],
    ) -> Result<(), CounterOverflow> {
        let hi = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
        let tail: [u8; 8] = nonce[4..].try_into().expect("8 bytes");
        self.xor_ctr64((u64::from(hi) << 32) | u64::from(counter), &tail, buf)
    }

    /// The 64-bit-counter driver shared by the DJB, carry and XChaCha20
    /// forms: words 12–13 are `counter`, words 14–15 `tail`. Splits `buf` at
    /// each point where the low counter word wraps, so the 32-bit-counter
    /// kernels below never see a wrap inside the bytes they emit.
    fn xor_ctr64(
        &self,
        counter: u64,
        tail: &[u8; 8],
        buf: &mut [u8],
    ) -> Result<(), CounterOverflow> {
        let blocks = buf.len().div_ceil(64) as u128;
        if u128::from(counter) + blocks > 1u128 << 64 {
            return Err(CounterOverflow);
        }
        let mut ctr = counter;
        let mut rest = buf;
        while !rest.is_empty() {
            let lo = ctr as u32;
            // Blocks left before the low word wraps: 1..=2^32.
            let seg_blocks = (1u64 << 32) - u64::from(lo);
            let seg_bytes = usize::try_from(seg_blocks.saturating_mul(64))
                .unwrap_or(usize::MAX)
                .min(rest.len());
            let (seg, tail_buf) = rest.split_at_mut(seg_bytes);
            self.xor_ctr32(&djb_nonce12((ctr >> 32) as u32, tail), lo, seg);
            rest = tail_buf;
            // Only reached with bytes left when the segment ran to the wrap,
            // so `ctr + seg_blocks` is the next counter and (by the check
            // above) still in range.
            if !rest.is_empty() {
                ctr += seg_blocks;
            }
        }
        Ok(())
    }

    /// The RFC 8439 keystream XOR without the range check: the caller
    /// guarantees `counter + ⌈len/64⌉ ≤ 2³²`.
    fn xor_ctr32(&self, nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        // On x86_64, generate the keystream many blocks at a time — ChaCha20
        // blocks are independent, so the wide layout needs no diagonal
        // shuffles. AVX-512 does sixteen blocks per pass, AVX2 eight; both are
        // byte-identical to the scalar path.
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        if simd512::supported() {
            simd512::apply_keystream(&self.key, nonce, counter, buf);
            return;
        }
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        if simd::supported() {
            simd::apply_keystream(&self.key, nonce, counter, buf);
            return;
        }
        // On aarch64 NEON is part of the baseline ISA, so the 2×4-way kernel
        // is the normal path with no runtime probe. It hands back a tail of
        // up to two blocks, where a 4-wide pass would mostly compute
        // discarded blocks (measured: slower than the scalar loop up to 128
        // bytes, faster from three blocks on), to the scalar loop below —
        // which also remains the whole path for buffers that short
        // (single-block callers such as the Poly1305 OTK derivation never
        // enter the kernel) and in the constant-time harness's
        // forced-portable mode.
        #[cfg(target_arch = "aarch64")]
        let (done, mut block_counter) = if buf.len() > 128 && neon::supported() {
            neon::apply_keystream(&self.key, nonce, counter, buf)
        } else {
            (0, counter)
        };
        #[cfg(not(target_arch = "aarch64"))]
        let (done, mut block_counter) = (0, counter);
        for block in buf[done..].chunks_mut(64) {
            let mut ks = self.block(nonce, block_counter);
            for (b, k) in block.iter_mut().zip(ks.iter()) {
                *b ^= *k;
            }
            // Don't leave raw keystream for this key in the stack frame — this
            // runs on every ChaCha20 / ChaCha20-Poly1305 operation. Per-block
            // inner loop, so not `Zeroize` (see `wipe_words`).
            ks = [0u8; 64];
            let _ = core::hint::black_box(&ks);
            block_counter = block_counter.wrapping_add(1);
        }
    }
}

/// Whether `len` bytes starting at block `counter` stay within RFC 8439's
/// 32-bit counter (`counter + ⌈len/64⌉ ≤ 2³²`).
#[inline]
fn ietf_fits(counter: u32, len: usize) -> bool {
    u64::from(counter) + len.div_ceil(64) as u64 <= 1u64 << 32
}

/// The RFC 8439-shaped 12-byte "nonce" (state words 13–15) for the 64-bit
/// counter layout: the counter's high word followed by the 8-byte nonce.
#[inline]
fn djb_nonce12(counter_hi: u32, nonce: &[u8; 8]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..4].copy_from_slice(&counter_hi.to_le_bytes());
    n[4..].copy_from_slice(nonce);
    n
}

/// The XChaCha20 stream cipher: ChaCha20 with a 192-bit nonce
/// (draft-irtf-cfrg-xchacha §2.3; libsodium `crypto_stream_xchacha20`).
///
/// Each call derives the subkey `HChaCha20(key, nonce[0..16])` and runs the
/// original 64-bit-counter ChaCha20 with `nonce[16..24]`. With a counter
/// below `2³²` this is the same keystream that
/// [`XChaCha20Poly1305`](super::XChaCha20Poly1305) uses (whose inner nonce is
/// `[0; 4] ‖ nonce[16..24]`). The nonce is long enough to pick at random.
#[derive(Clone)]
pub struct XChaCha20 {
    key: [u8; 32],
}

impl Drop for XChaCha20 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for XChaCha20 {}

impl XChaCha20 {
    /// Creates an XChaCha20 cipher from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        XChaCha20 { key: *key }
    }

    /// XORs the keystream for `nonce` into `buf` in place, starting at
    /// 64-byte block `counter` (libsodium `crypto_stream_xchacha20_xor_ic`;
    /// `counter = 0` gives `crypto_stream_xchacha20_xor`).
    ///
    /// Returns [`CounterOverflow`], with `buf` untouched, only if the 64-bit
    /// counter would pass `2⁶⁴ − 1`; from `counter = 0` that cannot happen.
    pub fn apply_keystream(
        &self,
        nonce: &[u8; 24],
        counter: u64,
        buf: &mut [u8],
    ) -> Result<(), CounterOverflow> {
        let n16: &[u8; 16] = nonce[..16].try_into().expect("16 bytes");
        let tail: &[u8; 8] = nonce[16..].try_into().expect("8 bytes");
        let mut subkey = hchacha20(&self.key, n16);
        let inner = ChaCha20::new(&subkey);
        subkey.zeroize();
        inner.apply_keystream_djb(tail, counter, buf)
    }
}

/// AVX-512 16-way ChaCha20 keystream (x86_64). Same shape as the AVX2 kernel
/// below, with each of the 16 state words held in a `__m512i` lane-per-block
/// across sixteen consecutive counters, so one pass emits 1 KiB of keystream.
///
/// Two AVX-512 instructions do real work here beyond the doubled width:
/// `vprold` rotates in one instruction where AVX2 needs a shift/shift/or trio,
/// which matters because ChaCha20 is four rotates per quarter-round and nothing
/// else. Pinned byte-for-byte against the scalar path by a differential test.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod simd512 {
    use super::CONSTANTS;
    use core::arch::x86_64::*;

    pub(super) fn supported() -> bool {
        !crate::ct::force_portable() && std::is_x86_feature_detected!("avx512f")
    }

    /// Rotate-left each 32-bit lane by `N` — a single `vprold`.
    #[inline(always)]
    unsafe fn rol<const N: i32>(x: __m512i) -> __m512i {
        unsafe { _mm512_rol_epi32::<N>(x) }
    }

    #[inline(always)]
    unsafe fn qr(v: &mut [__m512i; 16], a: usize, b: usize, c: usize, d: usize) {
        unsafe {
            v[a] = _mm512_add_epi32(v[a], v[b]);
            v[d] = rol::<16>(_mm512_xor_si512(v[d], v[a]));
            v[c] = _mm512_add_epi32(v[c], v[d]);
            v[b] = rol::<12>(_mm512_xor_si512(v[b], v[c]));
            v[a] = _mm512_add_epi32(v[a], v[b]);
            v[d] = rol::<8>(_mm512_xor_si512(v[d], v[a]));
            v[c] = _mm512_add_epi32(v[c], v[d]);
            v[b] = rol::<7>(_mm512_xor_si512(v[b], v[c]));
        }
    }

    pub(super) fn apply_keystream(key: &[u32; 8], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        // SAFETY: `supported()` (checked by the caller) confirmed AVX-512F.
        unsafe { apply_keystream_avx512(key, nonce, counter, buf) }
    }

    #[target_feature(enable = "avx512f")]
    unsafe fn apply_keystream_avx512(
        key: &[u32; 8],
        nonce: &[u8; 12],
        counter: u32,
        buf: &mut [u8],
    ) {
        unsafe {
            let n =
                |o: usize| u32::from_le_bytes([nonce[o], nonce[o + 1], nonce[o + 2], nonce[o + 3]]);
            let (n0, n1, n2) = (n(0), n(4), n(8));
            #[rustfmt::skip]
            let lanes = _mm512_setr_epi32(
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            );

            let mut ctr = counter;
            let mut off = 0usize;
            // Hoisted out of the loop so one wipe at the end covers them; they
            // are fully overwritten every pass.
            let mut words = [[0u32; 16]; 16];
            let mut ks = [0u8; 1024];
            while off < buf.len() {
                let mut v = [
                    _mm512_set1_epi32(CONSTANTS[0] as i32),
                    _mm512_set1_epi32(CONSTANTS[1] as i32),
                    _mm512_set1_epi32(CONSTANTS[2] as i32),
                    _mm512_set1_epi32(CONSTANTS[3] as i32),
                    _mm512_set1_epi32(key[0] as i32),
                    _mm512_set1_epi32(key[1] as i32),
                    _mm512_set1_epi32(key[2] as i32),
                    _mm512_set1_epi32(key[3] as i32),
                    _mm512_set1_epi32(key[4] as i32),
                    _mm512_set1_epi32(key[5] as i32),
                    _mm512_set1_epi32(key[6] as i32),
                    _mm512_set1_epi32(key[7] as i32),
                    _mm512_add_epi32(_mm512_set1_epi32(ctr as i32), lanes),
                    _mm512_set1_epi32(n0 as i32),
                    _mm512_set1_epi32(n1 as i32),
                    _mm512_set1_epi32(n2 as i32),
                ];
                let mut init = v;
                for _ in 0..10 {
                    qr(&mut v, 0, 4, 8, 12);
                    qr(&mut v, 1, 5, 9, 13);
                    qr(&mut v, 2, 6, 10, 14);
                    qr(&mut v, 3, 7, 11, 15);
                    qr(&mut v, 0, 5, 10, 15);
                    qr(&mut v, 1, 6, 11, 12);
                    qr(&mut v, 2, 7, 8, 13);
                    qr(&mut v, 3, 4, 9, 14);
                }
                for i in 0..16 {
                    let added = _mm512_add_epi32(v[i], init[i]);
                    _mm512_storeu_si512(words[i].as_mut_ptr() as *mut _, added);
                }
                // Emit up to sixteen 64-byte keystream blocks (lane = block) and
                // XOR the bytes still needed into `buf`.
                let avail = (buf.len() - off).min(1024);
                for (b, blk) in ks.chunks_exact_mut(64).enumerate() {
                    for (i, word) in blk.chunks_exact_mut(4).enumerate() {
                        word.copy_from_slice(&words[i][b].to_le_bytes());
                    }
                }
                for (dst, k) in buf[off..off + avail].iter_mut().zip(ks.iter()) {
                    *dst ^= *k;
                }
                // `init[4..12]` is the key broadcast across lanes and `v` the
                // pre-feed-forward state; both are loop-scoped, so scrub them
                // here rather than trusting the register allocator not to have
                // spilled them.
                for (a, b) in v.iter_mut().zip(init.iter_mut()) {
                    *a = _mm512_setzero_si512();
                    *b = _mm512_setzero_si512();
                }
                let _ = core::hint::black_box(&v);
                let _ = core::hint::black_box(&init);
                off += 1024;
                ctr = ctr.wrapping_add(16);
            }
            // Don't leave raw keystream for this key in the stack frame — this
            // runs on every ChaCha20 / ChaCha20-Poly1305 operation. `words`
            // and `ks` are the same 1 KiB of keystream in two layouts.
            //
            // Not `Zeroize`: that is ~2 KiB of per-byte volatile stores on
            // *every* call regardless of payload size (measured ~1% at 64 KiB,
            // proportionally far worse on small TLS/QUIC records), so this
            // bulk-cipher path keeps the vector store plus `black_box` barrier.
            words = [[0u32; 16]; 16];
            ks = [0u8; 1024];
            let _ = core::hint::black_box(&words);
            let _ = core::hint::black_box(&ks);
        }
    }
}

/// AVX2 8-way ChaCha20 keystream (x86_64). Each of the 16 state words is held in
/// a `__m256i` lane-per-block across eight consecutive block counters; the
/// quarter-round indices are identical to the scalar path (independent blocks =
/// no diagonalization). Pinned byte-for-byte by a differential test.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
#[allow(unsafe_code)]
mod simd {
    use super::CONSTANTS;
    use core::arch::x86_64::*;

    pub(super) fn supported() -> bool {
        !crate::ct::force_portable() && std::is_x86_feature_detected!("avx2")
    }

    /// Rotate-left each 32-bit lane by `N` (with `M = 32 - N`).
    #[inline(always)]
    unsafe fn rol<const N: i32, const M: i32>(x: __m256i) -> __m256i {
        unsafe { _mm256_or_si256(_mm256_slli_epi32::<N>(x), _mm256_srli_epi32::<M>(x)) }
    }

    #[inline(always)]
    #[allow(clippy::too_many_arguments)]
    unsafe fn qr(v: &mut [__m256i; 16], a: usize, b: usize, c: usize, d: usize) {
        unsafe {
            v[a] = _mm256_add_epi32(v[a], v[b]);
            v[d] = rol::<16, 16>(_mm256_xor_si256(v[d], v[a]));
            v[c] = _mm256_add_epi32(v[c], v[d]);
            v[b] = rol::<12, 20>(_mm256_xor_si256(v[b], v[c]));
            v[a] = _mm256_add_epi32(v[a], v[b]);
            v[d] = rol::<8, 24>(_mm256_xor_si256(v[d], v[a]));
            v[c] = _mm256_add_epi32(v[c], v[d]);
            v[b] = rol::<7, 25>(_mm256_xor_si256(v[b], v[c]));
        }
    }

    pub(super) fn apply_keystream(key: &[u32; 8], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        // SAFETY: `supported()` (checked by the caller) confirmed AVX2.
        unsafe { apply_keystream_avx2(key, nonce, counter, buf) }
    }

    #[target_feature(enable = "avx2")]
    unsafe fn apply_keystream_avx2(key: &[u32; 8], nonce: &[u8; 12], counter: u32, buf: &mut [u8]) {
        unsafe {
            let n =
                |o: usize| u32::from_le_bytes([nonce[o], nonce[o + 1], nonce[o + 2], nonce[o + 3]]);
            let (n0, n1, n2) = (n(0), n(4), n(8));
            let lanes = _mm256_setr_epi32(0, 1, 2, 3, 4, 5, 6, 7);

            let mut ctr = counter;
            let mut off = 0usize;
            // Hoisted out of the loop so one wipe at the end covers them; they
            // are fully overwritten every pass.
            let mut words = [[0u32; 8]; 16];
            let mut ks = [0u8; 512];
            while off < buf.len() {
                let mut v = [
                    _mm256_set1_epi32(CONSTANTS[0] as i32),
                    _mm256_set1_epi32(CONSTANTS[1] as i32),
                    _mm256_set1_epi32(CONSTANTS[2] as i32),
                    _mm256_set1_epi32(CONSTANTS[3] as i32),
                    _mm256_set1_epi32(key[0] as i32),
                    _mm256_set1_epi32(key[1] as i32),
                    _mm256_set1_epi32(key[2] as i32),
                    _mm256_set1_epi32(key[3] as i32),
                    _mm256_set1_epi32(key[4] as i32),
                    _mm256_set1_epi32(key[5] as i32),
                    _mm256_set1_epi32(key[6] as i32),
                    _mm256_set1_epi32(key[7] as i32),
                    _mm256_add_epi32(_mm256_set1_epi32(ctr as i32), lanes),
                    _mm256_set1_epi32(n0 as i32),
                    _mm256_set1_epi32(n1 as i32),
                    _mm256_set1_epi32(n2 as i32),
                ];
                let mut init = v;
                for _ in 0..10 {
                    qr(&mut v, 0, 4, 8, 12);
                    qr(&mut v, 1, 5, 9, 13);
                    qr(&mut v, 2, 6, 10, 14);
                    qr(&mut v, 3, 7, 11, 15);
                    qr(&mut v, 0, 5, 10, 15);
                    qr(&mut v, 1, 6, 11, 12);
                    qr(&mut v, 2, 7, 8, 13);
                    qr(&mut v, 3, 4, 9, 14);
                }
                for i in 0..16 {
                    let added = _mm256_add_epi32(v[i], init[i]);
                    _mm256_storeu_si256(words[i].as_mut_ptr() as *mut __m256i, added);
                }
                // Emit up to eight 64-byte keystream blocks (lane = block) and
                // XOR the bytes still needed into `buf`.
                let avail = (buf.len() - off).min(512);
                for (b, blk) in ks.chunks_exact_mut(64).enumerate() {
                    for (i, word) in blk.chunks_exact_mut(4).enumerate() {
                        word.copy_from_slice(&words[i][b].to_le_bytes());
                    }
                }
                for (dst, k) in buf[off..off + avail].iter_mut().zip(ks.iter()) {
                    *dst ^= *k;
                }
                // See the AVX-512 kernel: scrub the key-bearing vectors.
                for (a, b) in v.iter_mut().zip(init.iter_mut()) {
                    *a = _mm256_setzero_si256();
                    *b = _mm256_setzero_si256();
                }
                let _ = core::hint::black_box(&v);
                let _ = core::hint::black_box(&init);
                off += 512;
                ctr = ctr.wrapping_add(8);
            }
            // Don't leave raw keystream for this key in the stack frame — this
            // runs on every ChaCha20 / ChaCha20-Poly1305 operation. Not
            // `Zeroize`, for the per-call cost noted in the AVX-512 kernel.
            words = [[0u32; 8]; 16];
            ks = [0u8; 512];
            let _ = core::hint::black_box(&words);
            let _ = core::hint::black_box(&ks);
        }
    }
}

/// NEON 4-way ChaCha20 keystream (aarch64), two independent 4-block sets per
/// pass so one set's eight quarter-round dependency chains overlap with the
/// other's. Each of the 16 state words is a `uint32x4_t` holding one
/// consecutive block counter per lane, so the quarter-round indices are the
/// scalar ones and no diagonalisation is needed; the lane-to-block transpose
/// at the end is two `trn1`/`trn2` levels per 4-word group.
///
/// Rotations: `<<< 16` is a `rev32.16` (swap halves), `<<< 8` a byte shuffle
/// (`tbl`), and `<<< 12` / `<<< 7` a shift plus shift-right-insert (`sri`),
/// two instructions instead of the shift/shift/or trio. NEON is in the
/// aarch64 baseline, so there is no runtime feature probe and the module
/// builds for `no_std`. Pinned byte-for-byte to the scalar path by a
/// differential test over every length in `0..=1024` and beyond.
#[cfg(target_arch = "aarch64")]
#[allow(unsafe_code)]
mod neon {
    use super::CONSTANTS;
    use core::arch::aarch64::*;

    pub(super) fn supported() -> bool {
        !crate::ct::force_portable()
    }

    #[inline(always)]
    unsafe fn rot16(x: uint32x4_t) -> uint32x4_t {
        unsafe { vreinterpretq_u32_u16(vrev32q_u16(vreinterpretq_u16_u32(x))) }
    }

    #[inline(always)]
    unsafe fn rot12(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<20>(vshlq_n_u32::<12>(x), x) }
    }

    #[inline(always)]
    unsafe fn rot8(x: uint32x4_t, tbl: uint8x16_t) -> uint32x4_t {
        unsafe { vreinterpretq_u32_u8(vqtbl1q_u8(vreinterpretq_u8_u32(x), tbl)) }
    }

    #[inline(always)]
    unsafe fn rot7(x: uint32x4_t) -> uint32x4_t {
        unsafe { vsriq_n_u32::<25>(vshlq_n_u32::<7>(x), x) }
    }

    #[inline(always)]
    unsafe fn qr(
        v: &mut [uint32x4_t; 16],
        a: usize,
        b: usize,
        c: usize,
        d: usize,
        tbl: uint8x16_t,
    ) {
        unsafe {
            v[a] = vaddq_u32(v[a], v[b]);
            v[d] = rot16(veorq_u32(v[d], v[a]));
            v[c] = vaddq_u32(v[c], v[d]);
            v[b] = rot12(veorq_u32(v[b], v[c]));
            v[a] = vaddq_u32(v[a], v[b]);
            v[d] = rot8(veorq_u32(v[d], v[a]), tbl);
            v[c] = vaddq_u32(v[c], v[d]);
            v[b] = rot7(veorq_u32(v[b], v[c]));
        }
    }

    /// One double round (column round, then diagonal round) on a 4-block set.
    #[inline(always)]
    unsafe fn double_round(v: &mut [uint32x4_t; 16], tbl: uint8x16_t) {
        unsafe {
            qr(v, 0, 4, 8, 12, tbl);
            qr(v, 1, 5, 9, 13, tbl);
            qr(v, 2, 6, 10, 14, tbl);
            qr(v, 3, 7, 11, 15, tbl);
            qr(v, 0, 5, 10, 15, tbl);
            qr(v, 1, 6, 11, 12, tbl);
            qr(v, 2, 7, 8, 13, tbl);
            qr(v, 3, 4, 9, 14, tbl);
        }
    }

    /// The initial state for blocks `ctr .. ctr + 4`, lane = block.
    #[inline(always)]
    unsafe fn init4(key: &[u32; 8], n: &[u32; 3], ctr: u32) -> [uint32x4_t; 16] {
        unsafe {
            let lanes = vld1q_u32([0u32, 1, 2, 3].as_ptr());
            [
                vdupq_n_u32(CONSTANTS[0]),
                vdupq_n_u32(CONSTANTS[1]),
                vdupq_n_u32(CONSTANTS[2]),
                vdupq_n_u32(CONSTANTS[3]),
                vdupq_n_u32(key[0]),
                vdupq_n_u32(key[1]),
                vdupq_n_u32(key[2]),
                vdupq_n_u32(key[3]),
                vdupq_n_u32(key[4]),
                vdupq_n_u32(key[5]),
                vdupq_n_u32(key[6]),
                vdupq_n_u32(key[7]),
                vaddq_u32(vdupq_n_u32(ctr), lanes),
                vdupq_n_u32(n[0]),
                vdupq_n_u32(n[1]),
                vdupq_n_u32(n[2]),
            ]
        }
    }

    /// Feed-forward, transpose lane-major into four 64-byte blocks, and either
    /// XOR them into `p` (`XOR`) or store the raw keystream there. `p` must
    /// address 256 writable bytes.
    #[inline(always)]
    unsafe fn emit4<const XOR: bool>(v: &[uint32x4_t; 16], init: &[uint32x4_t; 16], p: *mut u8) {
        unsafe {
            for g in 0..4 {
                let w0 = vaddq_u32(v[4 * g], init[4 * g]);
                let w1 = vaddq_u32(v[4 * g + 1], init[4 * g + 1]);
                let w2 = vaddq_u32(v[4 * g + 2], init[4 * g + 2]);
                let w3 = vaddq_u32(v[4 * g + 3], init[4 * g + 3]);
                // 4×4 transpose of 32-bit lanes: row i = words 4g..4g+4 of
                // block i.
                let t0 = vreinterpretq_u64_u32(vtrn1q_u32(w0, w1));
                let t1 = vreinterpretq_u64_u32(vtrn2q_u32(w0, w1));
                let t2 = vreinterpretq_u64_u32(vtrn1q_u32(w2, w3));
                let t3 = vreinterpretq_u64_u32(vtrn2q_u32(w2, w3));
                let rows = [
                    vreinterpretq_u8_u64(vtrn1q_u64(t0, t2)),
                    vreinterpretq_u8_u64(vtrn1q_u64(t1, t3)),
                    vreinterpretq_u8_u64(vtrn2q_u64(t0, t2)),
                    vreinterpretq_u8_u64(vtrn2q_u64(t1, t3)),
                ];
                for (i, r) in rows.iter().enumerate() {
                    let q = p.add(64 * i + 16 * g);
                    if XOR {
                        vst1q_u8(q, veorq_u8(vld1q_u8(q), *r));
                    } else {
                        vst1q_u8(q, *r);
                    }
                }
            }
        }
    }

    /// Scrubs a key-bearing state set: `init[4..12]` is the key broadcast
    /// across lanes and `v` the pre-feed-forward state (key-equivalent).
    #[inline(always)]
    unsafe fn wipe(v: &mut [uint32x4_t; 16], init: &mut [uint32x4_t; 16]) {
        unsafe {
            for (a, b) in v.iter_mut().zip(init.iter_mut()) {
                *a = vdupq_n_u32(0);
                *b = vdupq_n_u32(0);
            }
            let _ = core::hint::black_box(&*v);
            let _ = core::hint::black_box(&*init);
        }
    }

    /// Applies the keystream to as much of `buf` as the wide kernels cover
    /// and returns `(bytes done, next block counter)`. The remainder is at
    /// most 128 bytes, left for the caller's scalar loop (for a tail that
    /// short, a 4-wide pass would mostly compute discarded blocks).
    pub(super) fn apply_keystream(
        key: &[u32; 8],
        nonce: &[u8; 12],
        counter: u32,
        buf: &mut [u8],
    ) -> (usize, u32) {
        // SAFETY: NEON is a baseline feature of every aarch64 target, and the
        // kernel's pointer arithmetic stays inside `buf` and its own scratch.
        unsafe { apply_keystream_neon(key, nonce, counter, buf) }
    }

    #[target_feature(enable = "neon")]
    unsafe fn apply_keystream_neon(
        key: &[u32; 8],
        nonce: &[u8; 12],
        counter: u32,
        buf: &mut [u8],
    ) -> (usize, u32) {
        unsafe {
            let n =
                |o: usize| u32::from_le_bytes([nonce[o], nonce[o + 1], nonce[o + 2], nonce[o + 3]]);
            let n = [n(0), n(4), n(8)];
            #[rustfmt::skip]
            let tbl = vld1q_u8([3u8, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14].as_ptr());

            let mut ctr = counter;
            let mut off = 0usize;
            let base = buf.as_mut_ptr();
            let len = buf.len();

            // The two state sets live outside the loops so that one wipe at
            // the end covers them; every pass fully overwrites them.
            let mut ia = [vdupq_n_u32(0); 16];
            let mut ib = [vdupq_n_u32(0); 16];
            let mut a = ia;
            let mut b = ib;

            // Eight blocks per pass: two independent 4-block sets whose round
            // computations interleave.
            while off + 512 <= len {
                ia = init4(key, &n, ctr);
                ib = init4(key, &n, ctr.wrapping_add(4));
                a = ia;
                b = ib;
                for _ in 0..10 {
                    double_round(&mut a, tbl);
                    double_round(&mut b, tbl);
                }
                emit4::<true>(&a, &ia, base.add(off));
                emit4::<true>(&b, &ib, base.add(off + 256));
                off += 512;
                ctr = ctr.wrapping_add(8);
            }
            // One more full 4-block set, if it fits.
            if off + 256 <= len {
                ia = init4(key, &n, ctr);
                a = ia;
                for _ in 0..10 {
                    double_round(&mut a, tbl);
                }
                emit4::<true>(&a, &ia, base.add(off));
                off += 256;
                ctr = ctr.wrapping_add(4);
            }
            // Tail of three or four blocks (129..256 bytes): generate a
            // 4-block set into scratch and XOR what is needed. Blocks past the
            // end of `buf` are computed and discarded, so the counter wrap
            // they could incur is harmless.
            if off + 128 < len {
                ia = init4(key, &n, ctr);
                a = ia;
                for _ in 0..10 {
                    double_round(&mut a, tbl);
                }
                let mut ks = [0u8; 256];
                emit4::<false>(&a, &ia, ks.as_mut_ptr());
                let used = len - off;
                for (dst, k) in buf[off..].iter_mut().zip(ks.iter()) {
                    *dst ^= *k;
                }
                // Raw keystream for this key: same `black_box` barrier as the
                // scalar path (per-call, so not `Zeroize` — see `wipe_words`).
                ks = [0u8; 256];
                let _ = core::hint::black_box(&ks);
                off = len;
                ctr = ctr.wrapping_add(used.div_ceil(64) as u32);
            }
            wipe(&mut a, &mut ia);
            // The second set is only written by the 8-way loop (a public
            // length condition).
            if len >= 512 {
                wipe(&mut b, &mut ib);
            }
            (off, ctr)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// The NEON 2×4-way keystream must equal the scalar block path for every
    /// length in `0..=1024` (partial blocks, partial 4- and 8-block groups)
    /// plus larger buffers, across counter values near the 32-bit boundary.
    #[cfg(all(target_arch = "aarch64", feature = "alloc"))]
    #[test]
    fn neon_matches_scalar() {
        use alloc::vec::Vec;
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(3));
        let c = ChaCha20::new(&key);
        for len in (0usize..=1024).chain([1500, 4096 + 7, 65536 + 33]) {
            for &ctr in &[0u32, 1, 100, u32::MAX - 20] {
                if (ctr as u64) + (len.div_ceil(64) as u64) > u64::from(u32::MAX) + 1 {
                    continue;
                }
                let base: Vec<u8> = (0..len).map(|i| (i * 31 + 9) as u8).collect();
                let mut scalar = base.clone();
                let mut bc = ctr;
                for block in scalar.chunks_mut(64) {
                    let ks = c.block(&nonce, bc);
                    for (b, k) in block.iter_mut().zip(ks.iter()) {
                        *b ^= *k;
                    }
                    bc = bc.wrapping_add(1);
                }
                // The kernel directly, with its scalar-finished tail: it must
                // report the right resume point and leave under 128 bytes.
                let mut w = base.clone();
                let (done, mut next) = super::neon::apply_keystream(&c.key, &nonce, ctr, &mut w);
                assert!(len - done <= 128, "neon tail len={len} done={done}");
                assert_eq!(next, ctr.wrapping_add(done.div_ceil(64) as u32));
                for block in w[done..].chunks_mut(64) {
                    let ks = c.block(&nonce, next);
                    for (b, k) in block.iter_mut().zip(ks.iter()) {
                        *b ^= *k;
                    }
                    next = next.wrapping_add(1);
                }
                assert_eq!(w, scalar, "neon len={len} ctr={ctr}");
                let mut d = base.clone();
                c.apply_keystream(&nonce, ctr, &mut d);
                assert_eq!(d, scalar, "dispatch len={len} ctr={ctr}");
            }
        }
    }

    #[test]
    fn rfc8439_block_function() {
        // RFC 8439 §2.3.2.
        let key =
            from_hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = from_hex::<12>("000000090000004a00000000");
        let c = ChaCha20::new(&key);
        let block = c.block(&nonce, 1);
        assert_eq!(
            block,
            from_hex::<64>(
                "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e\
                 d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
            )
        );
    }

    #[test]
    fn xchacha_draft_hchacha20() {
        // draft-irtf-cfrg-xchacha §2.2.1 test vector.
        let key =
            from_hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = from_hex::<16>("000000090000004a0000000031415927");
        let out = hchacha20(&key, &nonce);
        assert_eq!(
            out,
            from_hex::<32>("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
        );
    }

    #[test]
    fn rfc8439_encryption() {
        // RFC 8439 §2.4.2: encrypt the sunscreen plaintext at initial counter 1.
        let key =
            from_hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce = from_hex::<12>("000000000000004a00000000");
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
        let mut buf = plaintext.to_vec();
        ChaCha20::new(&key).apply_keystream(&nonce, 1, &mut buf);
        let expected = from_hex::<114>(
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42874d",
        );
        assert_eq!(buf, expected);

        // Keystream is its own inverse: re-applying recovers the plaintext.
        ChaCha20::new(&key).apply_keystream(&nonce, 1, &mut buf);
        assert_eq!(buf, plaintext);
    }

    /// Key `00..1f`, 24-byte nonce `40..57` (prefixes used for the shorter
    /// nonces) and the message `00 01 .. c7`: the inputs of the libsodium
    /// 1.0.20 / OpenSSL 3.5 cross-check vectors below.
    fn xcheck_inputs() -> ([u8; 32], [u8; 24], [u8; 200]) {
        (
            core::array::from_fn(|i| i as u8),
            core::array::from_fn(|i| 0x40 + i as u8),
            core::array::from_fn(|i| i as u8),
        )
    }

    /// The original ChaCha20 with an all-zero key and nonce
    /// (draft-agl-tls-chacha20poly1305-04 §7, first vector).
    #[test]
    fn djb_zero_vector() {
        let c = ChaCha20::new(&[0u8; 32]);
        let expected = from_hex::<64>(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7\
             da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
        );
        assert_eq!(c.block_djb(&[0u8; 8], 0), expected);
        let mut buf = [0u8; 64];
        c.apply_keystream_djb(&[0u8; 8], 0, &mut buf).unwrap();
        assert_eq!(buf, expected);
    }

    /// `crypto_stream_chacha20_xor_ic` from libsodium, at counter 0 and at
    /// `2³² − 2`, where the 200 bytes carry the counter into its high word
    /// (which also exercises the wrap-splitting in front of the wide
    /// kernels).
    #[test]
    fn djb_matches_libsodium() {
        let (key, nonce, msg) = xcheck_inputs();
        let n8: [u8; 8] = nonce[..8].try_into().unwrap();
        let c = ChaCha20::new(&key);
        let mut buf = msg;
        c.apply_keystream_djb(&n8, 0, &mut buf).unwrap();
        assert_eq!(
            buf,
            from_hex::<200>(
                "db6544e75e520e6f3457a0722e1d7ee83149d8bb24cec13dba33bc8fd2a2ed47\
                 dfef89dee3d446e36517df97cc4077db520c09644e2a6ae8cd3557b6f52ec349\
                 2451a7dbece1425048bbc702e9f70724a075842990f5f77338f0f55b5a568f82\
                 a744fe6770593fbdd90b8b7383d33bb6cd3ffa7371f01f2dff5ecac803617050\
                 fdb09f84aaf7a9cf68d32e5eed55dd331d58cceba210b54087e16274df4f3dfe\
                 33f44fe4d69b7b81761c9216e0086d48ba23cc8be51e9ac37f727e5c6bef3355\
                 615b8d4c06eb7187"
            )
        );
        let mut buf = msg;
        c.apply_keystream_djb(&n8, 0xffff_fffe, &mut buf).unwrap();
        let expected = from_hex::<200>(
            "3056f1c5f59d5378b7f247dddff565ff1a61ced11cf1e4f869a200fe18f8622a\
             7c5e1a0652ccd16202ceba34789c38847df0a14362566892417aaf0839d99d32\
             f1770ff01a8b4561d561db54633f9da6e1c1ff35dd1019b395307cdae03896b1\
             66f218ab92328ee936cd13c003b2e5290ef9bef166b4a82686b8b0e313a55104\
             3c2db9ca28bd75616b77789ae77d47d30d597d46de3c01c2b69f67fc0d1a827d\
             3bad835cb5bd4b5bf74d60df219dd45889729977f5f163a2c10fecf5509e5bfd\
             357ae2eb31613156",
        );
        assert_eq!(buf, expected);
        // Block by block through `block_djb` agrees.
        let mut ks = msg;
        for (i, chunk) in ks.chunks_mut(64).enumerate() {
            let b = c.block_djb(&n8, 0xffff_fffe + i as u64);
            for (x, k) in chunk.iter_mut().zip(b.iter()) {
                *x ^= *k;
            }
        }
        assert_eq!(ks, expected);
        // …as does the carry form with a zero first nonce word.
        let mut n12 = [0u8; 12];
        n12[4..].copy_from_slice(&n8);
        let mut buf = msg;
        c.apply_keystream_carry(&n12, 0xffff_fffe, &mut buf)
            .unwrap();
        assert_eq!(buf, expected);
    }

    /// The 64-bit counter may run up to and including `2⁶⁴ − 1`, never past.
    #[test]
    fn djb_counter_overflow_is_an_error() {
        let c = ChaCha20::new(&[3u8; 32]);
        let mut buf = [0x55u8; 129];
        assert_eq!(
            c.apply_keystream_djb(&[0u8; 8], u64::MAX - 1, &mut buf),
            Err(CounterOverflow)
        );
        assert_eq!(buf, [0x55u8; 129], "untouched on error");
        let mut buf = [0u8; 128];
        c.apply_keystream_djb(&[0u8; 8], u64::MAX - 1, &mut buf)
            .unwrap();
        assert_eq!(buf[64..], c.block_djb(&[0u8; 8], u64::MAX)[..]);
        // An empty buffer never overflows.
        c.apply_keystream_djb(&[0u8; 8], u64::MAX, &mut []).unwrap();
    }

    /// `crypto_stream_chacha20_ietf_xor_ic` from libsodium.
    #[test]
    fn ietf_matches_libsodium() {
        let (key, nonce, msg) = xcheck_inputs();
        let n12: [u8; 12] = nonce[..12].try_into().unwrap();
        let mut buf = msg;
        ChaCha20::new(&key)
            .try_apply_keystream(&n12, 7, &mut buf)
            .unwrap();
        assert_eq!(
            buf,
            from_hex::<200>(
                "92a0a025fa40cbf99f10c1feac62539159a1a44e2b12eb2abe953cc1a80c23fb\
                 445d85e8adc5d6297243ac0e790af863731b8d4fe146d58d3564228a40c8c214\
                 a35b056c6f2e046319d636e931f5c2f334695b990a3e66f1d432b59ecd92733d\
                 9b48b6ef40a4ec3979ecc7997398beb1cb2e1bb636d9789c9bb821c9d95c5010\
                 8def3f7d8324304ab42e80e55ce36d4b5331ee6a5cbccab86ae2cb8764692c70\
                 8946cd0b7e926a0f8527c9e0b452391d91fbeecf4023443d9ae4c522250cb23c\
                 c87d9a723f53f1d3"
            )
        );
    }

    /// The IETF form refuses (libsodium: aborts) to run past `2³²` blocks,
    /// while the carry form continues exactly as OpenSSL's `EVP_chacha20`.
    #[test]
    fn ietf_overflow_and_openssl_carry() {
        let (key, nonce, msg) = xcheck_inputs();
        let n12: [u8; 12] = nonce[..12].try_into().unwrap();
        let c = ChaCha20::new(&key);

        // The last block of the 32-bit range is fine …
        let mut buf = [0u8; 64];
        c.try_apply_keystream(&n12, u32::MAX, &mut buf).unwrap();
        assert_eq!(buf, c.block(&n12, u32::MAX));
        // … one byte more is not, and leaves the buffer alone.
        let mut buf = msg;
        assert_eq!(
            c.try_apply_keystream(&n12, 0xffff_fffe, &mut buf),
            Err(CounterOverflow)
        );
        assert_eq!(buf, msg);
        let mut short = [0u8; 65];
        assert_eq!(
            c.try_apply_keystream(&n12, u32::MAX, &mut short),
            Err(CounterOverflow)
        );

        // OpenSSL 3.5: EVP_chacha20 with IV = fe ff ff ff ‖ n12.
        let openssl = from_hex::<200>(
            "673c490d4ca6ddc5f9e0c641aa5b085f2b0069fced2c08647216f1352bf580bd\
             8d65baad3ab34dcf4049ac1c13c5f7ae600db950678165cc73bba6bff673f818\
             6ca2517ce61031e33432ed51fbbbe66afd5a51a011e70bd3e7f66194303955b7\
             b59cf2c9ec89e7fa16a1103834fc4f63c9d81205c36f990921a569d4ddc5dc98\
             f89f2ece238af4fc2c507c5746a72b602688636d1638013e97d67419bd1005d0\
             a4c929b8d423c1bfdb6f99a330774aa3554d80b4439da65c8c234b116a40c802\
             b8bee7719f21b175",
        );
        let mut buf = msg;
        c.apply_keystream_carry(&n12, 0xffff_fffe, &mut buf)
            .unwrap();
        assert_eq!(buf, openssl);
        // Up to the boundary the carry form is the IETF form.
        let mut a = [7u8; 128];
        let mut b = a;
        c.apply_keystream_carry(&n12, 0xffff_fffe, &mut a).unwrap();
        c.apply_keystream(&n12, 0xffff_fffe, &mut b);
        assert_eq!(a, b);

        // OpenSSL with IV = fe ff ‖ ff×14: its first two blocks (counter
        // words up to 2⁶⁴ − 1); OpenSSL then silently wraps to keystream it
        // already produced for counter 0, which the carry form refuses.
        let openssl_top = from_hex::<128>(
            "995808b89abacb7e9be40490c51aa3a176a02c2b7e84a3851fbfe0aecdf511c2\
             36696cf3272fee51648265d408c821d33d553cf7109daa073c60e4c7b4b807a4\
             7a352185f6ef57ad52b15b0dd0c1daf6774b1244ae29a700183aab71e888e8da\
             6e891a901f9f537280b680149904d0681af7b7636d320d2542f202dddfade699",
        );
        let ff = [0xffu8; 12];
        let mut buf: [u8; 128] = msg[..128].try_into().unwrap();
        c.apply_keystream_carry(&ff, 0xffff_fffe, &mut buf).unwrap();
        assert_eq!(buf, openssl_top);
        let mut buf = msg;
        assert_eq!(
            c.apply_keystream_carry(&ff, 0xffff_fffe, &mut buf),
            Err(CounterOverflow)
        );
        assert_eq!(buf, msg);
    }

    /// libsodium `crypto_core_hchacha20` and `crypto_stream_xchacha20_xor_ic`
    /// (counter `2³² − 2`, so the 64-bit counter carries).
    #[test]
    fn xchacha20_matches_libsodium() {
        let (key, nonce, msg) = xcheck_inputs();
        let n16: [u8; 16] = nonce[..16].try_into().unwrap();
        assert_eq!(
            hchacha20(&key, &n16),
            from_hex::<32>("001b38f1bc654a0470f0172049103eccb67d8bb16b11d2a468db66a2dd53d47d")
        );
        let x = XChaCha20::new(&key);
        let mut buf = msg;
        x.apply_keystream(&nonce, 0xffff_fffe, &mut buf).unwrap();
        assert_eq!(
            buf,
            from_hex::<200>(
                "77d5d28d9de11cde63b48477ea8de070b6d8316dc6403009c44aff78fe04b0bb\
                 14bf77d2c2f2d978c6f94d6eff0f03cc22496971543e8b3a14421c26147e8f25\
                 fb049f571cab9236d3f229723612b9ed1b6d1e30a87af433b1b2e42dbd1a3d7f\
                 62672e9f4ec76c507e78ca9522271b1f04561fe62914f9246d549eeb5f262855\
                 f988d94a8dbb5326f49670757d0048b3edf6b3925fa53ae02b2bab98ac6cad2b\
                 fc5522a9e34179dcc911bf000b69d69848917abf1167140d52c6c7fefe91f6a2\
                 cdc2a3ecc6071683"
            )
        );
        x.apply_keystream(&nonce, 0xffff_fffe, &mut buf).unwrap();
        assert_eq!(buf, msg);
    }

    /// XChaCha20 at counter 1 is the keystream XChaCha20-Poly1305 encrypts
    /// with (draft-irtf-cfrg-xchacha §A.3.1 plaintext and ciphertext).
    #[test]
    fn xchacha20_matches_aead_keystream() {
        let key =
            from_hex::<32>("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = from_hex::<24>("404142434445464748494a4b4c4d4e4f5051525354555657");
        let mut buf = *b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.";
        XChaCha20::new(&key)
            .apply_keystream(&nonce, 1, &mut buf)
            .unwrap();
        assert_eq!(
            buf,
            from_hex::<114>(
                "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
                 731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
                 2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
                 21f9664c97637da9768812f615c68b13b52e"
            )
        );
    }

    /// The AVX2 8-way keystream must equal the scalar block path for every
    /// length, including partial blocks and partial 8-block groups, and across
    /// a counter value near the 32-bit boundary.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn simd_matches_scalar() {
        use alloc::vec::Vec;
        // Exercise *each* wide kernel against the scalar path, rather than
        // whichever one `apply_keystream` happens to select: on an AVX-512 host
        // the dispatcher never reaches the AVX2 kernel, so going through it
        // would leave the 8-wide path untested there (and vice versa).
        let mut ran_any = false;
        if super::simd::supported() {
            std::eprintln!("chacha20: RUNNING avx2 8-wide kernel vs scalar");
            ran_any = true;
        } else {
            std::eprintln!("chacha20: SKIPPED avx2 (no AVX2 on this CPU)");
        }
        if super::simd512::supported() {
            std::eprintln!("chacha20: RUNNING avx512 16-wide kernel vs scalar");
            ran_any = true;
        } else {
            std::eprintln!("chacha20: SKIPPED avx512 (no AVX-512F on this CPU)");
        }
        if !ran_any {
            return;
        }
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(1));
        let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(3));
        let c = ChaCha20::new(&key);
        for &len in &[
            0usize,
            1,
            63,
            64,
            65,
            200,
            511,
            512,
            513,
            1024,
            1500,
            4096 + 7,
        ] {
            for &ctr in &[0u32, 1, 100, u32::MAX - 20] {
                // Skip combinations that would legitimately overflow the counter.
                if (ctr as u64) + (len.div_ceil(64) as u64) > u64::from(u32::MAX) + 1 {
                    continue;
                }
                let base: Vec<u8> = (0..len).map(|i| (i * 31 + 9) as u8).collect();
                // Scalar reference, block by block.
                let mut scalar = base.clone();
                let mut bc = ctr;
                for block in scalar.chunks_mut(64) {
                    let ks = c.block(&nonce, bc);
                    for (b, k) in block.iter_mut().zip(ks.iter()) {
                        *b ^= *k;
                    }
                    bc = bc.wrapping_add(1);
                }
                // Each wide kernel, called directly.
                if super::simd::supported() {
                    let mut w = base.clone();
                    super::simd::apply_keystream(&c.key, &nonce, ctr, &mut w);
                    assert_eq!(w, scalar, "avx2 len={len} ctr={ctr}");
                }
                if super::simd512::supported() {
                    let mut w = base.clone();
                    super::simd512::apply_keystream(&c.key, &nonce, ctr, &mut w);
                    assert_eq!(w, scalar, "avx512 len={len} ctr={ctr}");
                }
                // ...and the dispatcher, which must agree with both.
                let mut simd = base.clone();
                c.apply_keystream(&nonce, ctr, &mut simd);
                assert_eq!(simd, scalar, "dispatch len={len} ctr={ctr}");
            }
        }
    }
}
