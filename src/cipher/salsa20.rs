//! The Salsa20 family: D. J. Bernstein's Salsa20/20 stream cipher, the
//! HSalsa20 subkey derivation, XSalsa20 (192-bit nonce) and NaCl's
//! `secretbox` (XSalsa20-Poly1305), plus the crate-private Salsa20/8 core that
//! scrypt's BlockMix is built on (RFC 7914 §3).
//!
//! These exist for libsodium / NaCl interoperability: [`Salsa20`] is
//! `crypto_stream_salsa20` (32-byte key, 64-bit nonce, 64-bit block counter),
//! [`XSalsa20`] is `crypto_stream_xsalsa20` / `crypto_stream`, [`hsalsa20`] is
//! `crypto_core_hsalsa20`, and [`XSalsa20Poly1305`] is
//! `crypto_secretbox_xsalsa20poly1305` / `crypto_secretbox`. For new designs
//! prefer [`XChaCha20Poly1305`](super::XChaCha20Poly1305), which binds
//! associated data and has wide SIMD kernels.
//!
//! Everything here is pure 32-bit ARX with no secret-dependent branches or
//! memory indexing, so it is constant time. The stream functions are scalar,
//! one 64-byte block at a time.
//!
//! The 64-bit counter never wraps silently: a request that would run it past
//! `2⁶⁴ − 1` returns [`CounterOverflow`] with the buffer untouched (libsodium
//! wraps), which needs a starting counter within a buffer's length of the top.
//!
//! # The Salsa20/8 core and scrypt
//!
//! The scrypt core operates on a single 64-byte block treated as a row-major
//! `[u32; 16]` matrix in little-endian byte order:
//! `out = block + Salsa20_doubleround⁴(block)`.
//!
//! The block is taken as words so that scrypt's BlockMix can keep its
//! chaining value in registers between calls instead of serialising it to
//! bytes and back. A 4-lane SIMD kernel in the Percival shuffled-column
//! layout was measured and rejected: on a wide out-of-order core the scalar
//! schedule runs its four column chains in parallel, whereas the vector form
//! is a single dependency chain of add / shift / insert / XOR per step and
//! came out 2.5× *slower* (scrypt 2¹⁴/8/1: 40 ms vs 16 ms on Apple M5). The
//! 20-round functions below share the quarter-round but none of scrypt's
//! code path, which is unchanged.

use super::poly1305::Poly1305;
use super::{CounterOverflow, TagMismatch};
use crate::ct::ConstantTimeEq;
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// The Salsa20 constants for a 256-bit key — `"expand 32-byte k"` as four
/// little-endian words, placed on the matrix diagonal (words 0, 5, 10, 15).
const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline(always)]
fn quarter_round(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
    x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
    x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
    x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
}

/// One Salsa20 double round: a column round, then a row round.
#[inline(always)]
fn double_round(x: &mut [u32; 16]) {
    quarter_round(x, 0, 4, 8, 12);
    quarter_round(x, 5, 9, 13, 1);
    quarter_round(x, 10, 14, 2, 6);
    quarter_round(x, 15, 3, 7, 11);
    quarter_round(x, 0, 1, 2, 3);
    quarter_round(x, 5, 6, 7, 4);
    quarter_round(x, 10, 11, 8, 9);
    quarter_round(x, 15, 12, 13, 14);
}

/// Salsa20/8 core on a block of sixteen little-endian words: 8 rounds
/// (4 double-rounds), then add the original block back in. Mirrors the
/// description in RFC 7914 §3.
#[cfg(all(feature = "kdf", feature = "alloc"))]
#[inline]
pub(crate) fn salsa20_8_words(x: &mut [u32; 16]) {
    let original = *x;

    for _ in 0..4 {
        double_round(x);
    }

    for (w, &o) in x.iter_mut().zip(original.iter()) {
        *w = w.wrapping_add(o);
    }
}

/// Best-effort wipe of a state matrix (key-equivalent); a plain store plus a
/// barrier, as in ChaCha20's per-block path.
#[inline]
fn wipe_words(w: &mut [u32; 16]) {
    *w = [0u32; 16];
    let _ = core::hint::black_box(w);
}

#[inline]
fn le_words<const N: usize>(bytes: &[u8]) -> [u32; N] {
    core::array::from_fn(|i| {
        u32::from_le_bytes([
            bytes[4 * i],
            bytes[4 * i + 1],
            bytes[4 * i + 2],
            bytes[4 * i + 3],
        ])
    })
}

/// The Salsa20 input matrix: constants on the diagonal, the key in words
/// 1–4 and 11–14, and `mid` (nonce ‖ counter, or HSalsa20's input) in 6–9.
#[inline]
fn matrix(key: &[u32; 8], mid: &[u32; 4]) -> [u32; 16] {
    [
        SIGMA[0], key[0], key[1], key[2], key[3], SIGMA[1], mid[0], mid[1], mid[2], mid[3],
        SIGMA[2], key[4], key[5], key[6], key[7], SIGMA[3],
    ]
}

/// HSalsa20 (Bernstein, "Extending the Salsa20 nonce", 2008): derives a
/// 256-bit subkey from a 256-bit key and a 128-bit input by running the
/// 20-round Salsa20 permutation **without** the final feed-forward and
/// returning words 0, 5, 10, 15, 6, 7, 8, 9. This is libsodium's
/// `crypto_core_hsalsa20` with the default constant (`c = NULL`), the subkey
/// step of [`XSalsa20`], and (with a zero input) the step that turns a raw
/// X25519 shared secret into NaCl's `crypto_box` key.
///
/// Constant time. The output is a full-strength key: wipe it when done.
pub fn hsalsa20(key: &[u8; 32], input: &[u8; 16]) -> [u8; 32] {
    let mut k: [u32; 8] = le_words(key);
    let mut x = matrix(&k, &le_words(input));
    k.zeroize();
    for _ in 0..10 {
        double_round(&mut x);
    }
    let mut out = [0u8; 32];
    for (chunk, &idx) in out
        .chunks_exact_mut(4)
        .zip(&[0usize, 5, 10, 15, 6, 7, 8, 9])
    {
        chunk.copy_from_slice(&x[idx].to_le_bytes());
    }
    wipe_words(&mut x);
    out
}

/// The Salsa20/20 stream cipher with a 256-bit key, 64-bit nonce and 64-bit
/// block counter (libsodium `crypto_stream_salsa20`).
///
/// A (key, nonce) pair must never be used twice over overlapping counter
/// ranges. With random nonces, 64 bits are too few: use [`XSalsa20`].
#[derive(Clone)]
pub struct Salsa20 {
    key: [u32; 8],
}

impl Drop for Salsa20 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for Salsa20 {}

impl Salsa20 {
    /// Creates a Salsa20 cipher from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        Salsa20 { key: le_words(key) }
    }

    /// Generates the 64-byte keystream block for `(nonce, counter)`.
    pub fn block(&self, nonce: &[u8; 8], counter: u64) -> [u8; 64] {
        let n: [u32; 2] = le_words(nonce);
        let mut initial = matrix(
            &self.key,
            &[n[0], n[1], counter as u32, (counter >> 32) as u32],
        );
        let mut x = initial;
        for _ in 0..10 {
            double_round(&mut x);
        }
        let mut out = [0u8; 64];
        for ((chunk, w), i) in out.chunks_exact_mut(4).zip(x.iter()).zip(initial.iter()) {
            chunk.copy_from_slice(&w.wrapping_add(*i).to_le_bytes());
        }
        wipe_words(&mut initial);
        wipe_words(&mut x);
        out
    }

    /// XORs the keystream into `buf` in place, starting at 64-byte block
    /// `counter` (libsodium `crypto_stream_salsa20_xor_ic`; `counter = 0` is
    /// `crypto_stream_salsa20_xor`). Encryption and decryption are the same
    /// operation.
    ///
    /// Returns [`CounterOverflow`], with `buf` untouched, if the counter would
    /// pass `2⁶⁴ − 1`; from `counter = 0` that cannot happen.
    pub fn apply_keystream(
        &self,
        nonce: &[u8; 8],
        counter: u64,
        buf: &mut [u8],
    ) -> Result<(), CounterOverflow> {
        if u128::from(counter) + buf.len().div_ceil(64) as u128 > 1u128 << 64 {
            return Err(CounterOverflow);
        }
        self.xor_from(nonce, counter, buf);
        Ok(())
    }

    /// [`apply_keystream`](Self::apply_keystream) without the range check:
    /// the caller guarantees the counter does not pass `2⁶⁴ − 1`.
    fn xor_from(&self, nonce: &[u8; 8], mut counter: u64, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(64) {
            let mut ks = self.block(nonce, counter);
            for (b, k) in chunk.iter_mut().zip(ks.iter()) {
                *b ^= *k;
            }
            ks = [0u8; 64];
            let _ = core::hint::black_box(&ks);
            counter = counter.wrapping_add(1);
        }
    }
}

/// Derives the inner Salsa20 cipher and 8-byte nonce for a 24-byte XSalsa20
/// nonce: subkey `HSalsa20(key, nonce[0..16])`, nonce `nonce[16..24]`.
fn xsalsa20_inner(key: &[u8; 32], nonce: &[u8; 24]) -> (Salsa20, [u8; 8]) {
    let n16: &[u8; 16] = nonce[..16].try_into().expect("16 bytes");
    let mut subkey = hsalsa20(key, n16);
    let cipher = Salsa20::new(&subkey);
    subkey.zeroize();
    (cipher, nonce[16..].try_into().expect("8 bytes"))
}

/// The XSalsa20 stream cipher: Salsa20/20 with a 192-bit nonce, large enough
/// to choose at random (libsodium `crypto_stream_xsalsa20`, NaCl
/// `crypto_stream`). Each call derives `HSalsa20(key, nonce[0..16])` and runs
/// [`Salsa20`] under it with `nonce[16..24]`.
#[derive(Clone)]
pub struct XSalsa20 {
    key: [u8; 32],
}

impl Drop for XSalsa20 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for XSalsa20 {}

impl XSalsa20 {
    /// Creates an XSalsa20 cipher from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        XSalsa20 { key: *key }
    }

    /// XORs the keystream for `nonce` into `buf` in place, starting at 64-byte
    /// block `counter` (libsodium `crypto_stream_xsalsa20_xor_ic`;
    /// `counter = 0` is `crypto_stream_xsalsa20_xor`).
    ///
    /// Returns [`CounterOverflow`], with `buf` untouched, if the counter would
    /// pass `2⁶⁴ − 1`; from `counter = 0` that cannot happen.
    pub fn apply_keystream(
        &self,
        nonce: &[u8; 24],
        counter: u64,
        buf: &mut [u8],
    ) -> Result<(), CounterOverflow> {
        let (cipher, n8) = xsalsa20_inner(&self.key, nonce);
        cipher.apply_keystream(&n8, counter, buf)
    }
}

/// NaCl's `secretbox`: XSalsa20 encryption with a Poly1305 tag over the
/// ciphertext (libsodium `crypto_secretbox_xsalsa20poly1305`, the default
/// `crypto_secretbox`). 256-bit key, 192-bit nonce (random is fine), 16-byte
/// tag, no associated data.
///
/// The Poly1305 one-time key is the first 32 bytes of the XSalsa20 keystream;
/// the message is encrypted with the keystream from byte 32 on. The methods
/// here are the *detached* form (`crypto_secretbox_detached`); libsodium's
/// `crypto_secretbox_easy` output is `tag ‖ ciphertext`, and NaCl's original
/// `crypto_secretbox` output is 16 zero bytes, then `tag ‖ ciphertext`.
///
/// On a failed [`decrypt`](Self::decrypt) the buffer is left as ciphertext:
/// the tag is checked before anything is decrypted.
///
/// This exists for NaCl / libsodium interop. For new designs prefer
/// [`XChaCha20Poly1305`](super::XChaCha20Poly1305), which also binds
/// associated data and has wide SIMD kernels.
#[derive(Clone)]
pub struct XSalsa20Poly1305 {
    key: [u8; 32],
}

impl Drop for XSalsa20Poly1305 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for XSalsa20Poly1305 {}

impl XSalsa20Poly1305 {
    /// Creates a secretbox context from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        XSalsa20Poly1305 { key: *key }
    }

    /// Returns the inner cipher, its 8-byte nonce, the Poly1305 one-time key
    /// and the remaining 32 bytes of keystream block 0.
    fn setup(&self, nonce: &[u8; 24]) -> (Salsa20, [u8; 8], [u8; 32], [u8; 32]) {
        let (cipher, n8) = xsalsa20_inner(&self.key, nonce);
        let mut block0 = cipher.block(&n8, 0);
        let otk: [u8; 32] = block0[..32].try_into().expect("32 bytes");
        let rest: [u8; 32] = block0[32..].try_into().expect("32 bytes");
        block0.zeroize();
        (cipher, n8, otk, rest)
    }

    /// XORs the message keystream (XSalsa20 from byte 32) into `buffer`.
    fn crypt(cipher: &Salsa20, n8: &[u8; 8], rest: &[u8; 32], buffer: &mut [u8]) {
        let head = buffer.len().min(32);
        for (b, k) in buffer[..head].iter_mut().zip(rest.iter()) {
            *b ^= *k;
        }
        // From block 1 the counter cannot reach 2⁶⁴ for any slice length.
        cipher.xor_from(n8, 1, &mut buffer[head..]);
    }

    /// Encrypts `buffer` in place and returns the 16-byte Poly1305 tag
    /// (`crypto_secretbox_detached`).
    pub fn encrypt(&self, nonce: &[u8; 24], buffer: &mut [u8]) -> [u8; 16] {
        let (cipher, n8, mut otk, mut rest) = self.setup(nonce);
        Self::crypt(&cipher, &n8, &rest, buffer);
        rest.zeroize();
        let mut mac = Poly1305::new(&otk);
        otk.zeroize();
        mac.update(buffer);
        mac.finish()
    }

    /// Verifies `tag` over the ciphertext in `buffer` and, only if it matches,
    /// decrypts `buffer` in place (`crypto_secretbox_open_detached`). The tag
    /// comparison is constant time; on mismatch `buffer` is unchanged.
    pub fn decrypt(
        &self,
        nonce: &[u8; 24],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        let (cipher, n8, mut otk, mut rest) = self.setup(nonce);
        let mut mac = Poly1305::new(&otk);
        otk.zeroize();
        mac.update(buffer);
        let expected = mac.finish();
        // The accept/reject verdict is the public outcome of decryption.
        if !expected.ct_eq(tag).declassify() {
            rest.zeroize();
            return Err(TagMismatch);
        }
        Self::crypt(&cipher, &n8, &rest, buffer);
        rest.zeroize();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// RFC 7914 §8: the published Salsa20/8 input/output pair (in hex).
    #[cfg(all(feature = "kdf", feature = "alloc"))]
    #[test]
    fn rfc7914_salsa20_8_block() {
        let block = from_hex::<64>(
            "7e879a214f3ec9867ca940e641718f26\
             baee555b8c61c1b50df846116dcd3b1d\
             ee24f319df9b3d8514121e4b5ac5aa32\
             76021d2909c74829edebc68db8b8c25e",
        );
        let expected = from_hex::<64>(
            "a41f859c6608cc993b81cacb020cef05\
             044b2181a2fd337dfd7b1c6396682f29\
             b4393168e3c9e6bcfe6bc5b7a06d96ba\
             e424cc102c91745c24ad673dc7618f81",
        );
        let mut x: [u32; 16] = core::array::from_fn(|i| {
            u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap())
        });
        salsa20_8_words(&mut x);
        let mut out = [0u8; 64];
        for (chunk, w) in out.chunks_exact_mut(4).zip(x.iter()) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        assert_eq!(out, expected);
    }

    /// "Cryptography in NaCl" (Bernstein), §3/§6: Alice and Bob's X25519
    /// shared secret through HSalsa20 with a zero input gives `firstkey`
    /// (libsodium `test/default/core1`).
    const SHARED: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    const FIRSTKEY: &str = "1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389";
    /// The paper's 24-byte nonce.
    const NONCE: &str = "69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37";

    #[test]
    fn nacl_hsalsa20() {
        assert_eq!(
            hsalsa20(&from_hex::<32>(SHARED), &[0u8; 16]),
            from_hex::<32>(FIRSTKEY)
        );
    }

    /// "Cryptography in NaCl" §9 / libsodium `test/default/secretbox`: the
    /// 131-byte message under `firstkey` and the paper's nonce.
    #[test]
    fn nacl_secretbox() {
        let m = from_hex::<131>(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc\
             e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31\
             0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde\
             048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864\
             5e0705",
        );
        // `crypto_secretbox_easy` output: tag ‖ ciphertext.
        let easy = from_hex::<147>(
            "f3ffc7703f9400e52a7dfb4b3d3305d9\
             8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a\
             c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738\
             b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da\
             99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74\
             e355a5",
        );
        let sb = XSalsa20Poly1305::new(&from_hex::<32>(FIRSTKEY));
        let nonce = from_hex::<24>(NONCE);
        let mut buf = m;
        let tag = sb.encrypt(&nonce, &mut buf);
        assert_eq!(tag[..], easy[..16]);
        assert_eq!(buf[..], easy[16..]);

        let ct = buf;
        let mut bad = tag;
        bad[15] ^= 0x80;
        assert_eq!(sb.decrypt(&nonce, &mut buf, &bad), Err(TagMismatch));
        assert_eq!(buf, ct, "untouched on tag failure");
        let mut flipped = ct;
        flipped[100] ^= 1;
        assert_eq!(sb.decrypt(&nonce, &mut flipped, &tag), Err(TagMismatch));
        sb.decrypt(&nonce, &mut buf, &tag).unwrap();
        assert_eq!(buf, m);
    }

    /// Short messages (inside keystream block 0) and the empty message.
    #[test]
    fn secretbox_round_trips_every_short_length() {
        let sb = XSalsa20Poly1305::new(&[0x42; 32]);
        let nonce = [0x24; 24];
        let x = XSalsa20::new(&[0x42; 32]);
        for len in 0..=130 {
            let pt: [u8; 130] = core::array::from_fn(|i| (i * 7) as u8);
            let mut buf = pt;
            let tag = sb.encrypt(&nonce, &mut buf[..len]);
            // Ciphertext = XSalsa20 keystream from byte 32.
            let mut ks = [0u8; 162];
            x.apply_keystream(&nonce, 0, &mut ks).unwrap();
            for i in 0..len {
                assert_eq!(buf[i], pt[i] ^ ks[32 + i], "len={len} i={i}");
            }
            sb.decrypt(&nonce, &mut buf[..len], &tag).unwrap();
            assert_eq!(buf, pt);
        }
    }

    /// libsodium `test/default/stream`: SHA-256 of 4 MiB of XSalsa20
    /// keystream under `firstkey` and the paper's nonce; plus, as a libsodium
    /// 1.0.20 cross-check, the same for Salsa20 under the nonce's last 8 bytes.
    #[cfg(all(feature = "hash", feature = "alloc"))]
    #[test]
    fn nacl_stream_4mib() {
        use crate::hash::{Digest, Sha256};
        let key = from_hex::<32>(FIRSTKEY);
        let nonce = from_hex::<24>(NONCE);
        let mut buf = alloc::vec![0u8; 4 << 20];
        XSalsa20::new(&key)
            .apply_keystream(&nonce, 0, &mut buf)
            .unwrap();
        assert_eq!(
            Sha256::digest(&buf)[..],
            from_hex::<32>("662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2")
        );
        buf.fill(0);
        let n8: [u8; 8] = nonce[16..].try_into().unwrap();
        Salsa20::new(&key)
            .apply_keystream(&n8, 0, &mut buf)
            .unwrap();
        assert_eq!(
            Sha256::digest(&buf)[..],
            from_hex::<32>("921a4efa6244776ed8e41ab30317441681d3bbda91bd3a268d1070554ef3cebf")
        );
    }

    /// Key `00..1f`, nonce `40..57`, message `00 01 .. c7`: inputs of the
    /// libsodium 1.0.20 `*_xor_ic` cross-check vectors below.
    fn xcheck_inputs() -> ([u8; 32], [u8; 24], [u8; 200]) {
        (
            core::array::from_fn(|i| i as u8),
            core::array::from_fn(|i| 0x40 + i as u8),
            core::array::from_fn(|i| i as u8),
        )
    }

    #[test]
    fn salsa20_xor_ic_matches_libsodium() {
        let (key, nonce, msg) = xcheck_inputs();
        let n8: [u8; 8] = nonce[..8].try_into().unwrap();
        let s = Salsa20::new(&key);

        let mut buf = msg;
        s.apply_keystream(&n8, 0, &mut buf).unwrap();
        assert_eq!(
            buf,
            from_hex::<200>(
                "d2508c8ac140cdacd6b42870d3c768284a84ecc15c455d761081156b94f84545\
                 ab7039737025bb5880f4ea080ac5e21f931a42f38ac4b1a85da1436d9bee979c\
                 65be9cad387f187fce90661945f24bd1fff14248860fc560d0b0dd95f79f89b6\
                 bf296bdbba6d44a49aefa98bee597086afcdf047af589716c8e7392e09852950\
                 6e57a4e158ca7d8118b980e54f6035a7a04e3eaae9ecf76afb5dad44fdec9396\
                 2ae4bd48659bfb97d1bb177676bf19b68e9876f18d60b7ab7261e213f89b1899\
                 937cfebf446058fc"
            )
        );

        // Counter 2³² − 2: the 64-bit counter carries into its high word.
        let mut buf = msg;
        s.apply_keystream(&n8, 0xffff_fffe, &mut buf).unwrap();
        assert_eq!(
            buf,
            from_hex::<200>(
                "dd34c6a18a962c0e497b2582434db038711b3dd7d9b4c278dff407bba24a434c\
                 7ba70d5c88840b9e0ccc19fa5239f9274f2a2d9374299b49b8c64148d85fb036\
                 305bf935907060f6ccde88061b07588200443088d53e05c7c0ee22340912d999\
                 29cb71eb2517e18fd61fe487513bca8d861576db717e8f29cb4aad5ba04ebe17\
                 203c1222066838fbf7b6db5359c680ee17a5bd5693c8bbbf84b5f54fab604ae3\
                 11efc610e0724bafdad7624b8e0b47626b1d1c7cc1e8d7e0e62d6721b501b5e6\
                 8526385a8dbba320"
            )
        );

        // Counter 2⁶⁴ − 3: three blocks reach the top of the range and match
        // libsodium; a fourth would wrap (libsodium silently reuses block 0),
        // which is an error here.
        let top = from_hex::<192>(
            "dbbcdd7cd579e74d6cd608576120814f4650427be2d90d8ad9487295a329b956\
             8000633d5db19ccea0ef392135336c6a925e2c9ebc0a6cccab157cca485005ec\
             851c32d1bed021a12a5f65a766c0fec4c7f9a4ac1e15501e2b6e841573cd8573\
             3b4e210a0f8a519bd62402fe849f196c926bdda770ce499da3c6a010666ad50d\
             e2dcd9b8e5c6275e1e30e816a436c0c1aaa810276e7eebd8b794693255beba36\
             ad0db73bdbdced3359dffe142b43f8af03cad51cfc7d4b611cf35c06a582048d",
        );
        let mut buf: [u8; 192] = msg[..192].try_into().unwrap();
        s.apply_keystream(&n8, u64::MAX - 2, &mut buf).unwrap();
        assert_eq!(buf, top);
        let mut buf = msg;
        assert_eq!(
            s.apply_keystream(&n8, u64::MAX - 2, &mut buf),
            Err(CounterOverflow)
        );
        assert_eq!(buf, msg, "untouched on error");
    }

    #[test]
    fn xsalsa20_xor_ic_matches_libsodium() {
        let (key, nonce, msg) = xcheck_inputs();
        let x = XSalsa20::new(&key);
        let mut buf = msg;
        x.apply_keystream(&nonce, 5, &mut buf).unwrap();
        assert_eq!(
            buf,
            from_hex::<200>(
                "1d7c43a2928bdfcc977bf10ed260301800a1f5c63660a1b520df98e187f67b14\
                 1ca10d3163b8b89ba532ad12fa71f2a23f887e73898503e34b242ff2c989ae1a\
                 a355c5923cb14f20a4b718a42e6bcf27c5846cb2c25886f7aa9ec23062589b9b\
                 dc74b8573e5796122d69a7eed2b21f4699e788fc742a8c6c1ce8ce59eadaaad2\
                 0c71771334a2a42f3d7c4b1188c25bc2bcd60c92e38f99bb6c58956da4ba89eb\
                 d2277cc169326b2d73447cdab97cafc9e7421beaed7a2ada83786b8f88643dcb\
                 c7a1ac099398b7c5"
            )
        );
        x.apply_keystream(&nonce, 5, &mut buf).unwrap();
        assert_eq!(buf, msg);
    }
}
