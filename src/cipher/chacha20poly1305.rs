//! ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).
//!
//! Confidentiality comes from ChaCha20 and authenticity from Poly1305 over the
//! associated data and ciphertext. The one-time Poly1305 key is the first 32
//! bytes of the ChaCha20 keystream at block counter 0; the payload itself is
//! encrypted starting at block counter 1. The API mirrors [`Gcm`](super::Gcm):
//! 12-byte nonce, in-place buffer, 16-byte tag, constant-time tag check on open.
//!
//! As with any (key, nonce)-based AEAD, a nonce must never repeat under one key.

use super::TagMismatch;
use super::chacha20::ChaCha20;
use super::poly1305::Poly1305;
use crate::ct::ConstantTimeEq;

/// A ChaCha20-Poly1305 AEAD context keyed with a 256-bit key.
///
/// The 256-bit key is wiped on drop: the only key material this type holds is
/// the inner [`ChaCha20`], whose own `Drop` zeroizes it (the per-message
/// Poly1305 one-time key is derived and dropped inside each call, and
/// [`Poly1305`] wipes itself too).
#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    cipher: ChaCha20,
}

/// Feeds `len` worth of zero padding to round `mac` up to a 16-byte boundary.
fn pad16(mac: &mut Poly1305, len: usize) {
    let rem = len % 16;
    if rem != 0 {
        mac.update(&[0u8; 16][..16 - rem]);
    }
}

impl ChaCha20Poly1305 {
    /// Creates an AEAD context from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        ChaCha20Poly1305 {
            cipher: ChaCha20::new(key),
        }
    }

    /// Derives the one-time Poly1305 key from the keystream block at counter 0.
    /// The full 64-byte `block0` is zeroized after extracting the first 32
    /// bytes (RFC 8439 §2.6) so the unused half-block of secret keystream
    /// doesn't linger on the stack.
    ///
    /// Wiped through [`crate::zeroize::Zeroize`]. This runs once per AEAD
    /// record; the word-at-a-time volatile wipe makes it free (a per-byte
    /// version measured ~3% slower on a 1 KiB record, which is why this was
    /// once a plain store plus a `black_box` barrier).
    fn poly_key(&self, nonce: &[u8; 12]) -> [u8; 32] {
        let mut block0 = self.cipher.block(nonce, 0);
        let mut otk = [0u8; 32];
        otk.copy_from_slice(&block0[..32]);
        crate::zeroize::Zeroize::zeroize(&mut block0);
        otk
    }

    /// A Poly1305 state for `otk` that has absorbed the padded `aad`.
    fn mac_with_aad(otk: &[u8; 32], aad: &[u8]) -> Poly1305 {
        let mut mac = Poly1305::new(otk);
        mac.update(aad);
        pad16(&mut mac, aad.len());
        mac
    }

    /// Pads the ciphertext, absorbs the length block and returns the tag.
    fn finish_tag(mut mac: Poly1305, aad_len: usize, ct_len: usize) -> [u8; 16] {
        pad16(&mut mac, ct_len);
        let mut lens = [0u8; 16];
        lens[0..8].copy_from_slice(&(aad_len as u64).to_le_bytes());
        lens[8..16].copy_from_slice(&(ct_len as u64).to_le_bytes());
        mac.update(&lens);
        mac.finish()
    }

    /// Encrypts (`open = false`) or decrypts the longest multiple of 1 KiB
    /// at the front of `buf`, absorbing its ciphertext into `mac`, in one
    /// stitched loop where the hardware allows; returns the bytes covered
    /// (0 if it did nothing). The caller has checked the message length
    /// against the counter limit.
    #[cfg(target_arch = "x86_64")]
    fn stitched(&self, mac: &mut Poly1305, nonce: &[u8; 12], buf: &mut [u8], open: bool) -> usize {
        if buf.len() < 1024 || !mac.stitch_ready() {
            return 0;
        }
        // SAFETY: `stitch_ready` confirmed AVX-512F and AVX-512 IFMA.
        #[allow(unsafe_code)]
        unsafe {
            stitched_avx512(&self.cipher, mac, nonce, buf, open)
        }
    }

    /// RFC 8439 §2.8 caps a single ChaCha20-Poly1305 message at
    /// `(2^32 − 1) × 64` bytes (≈ 256 GiB minus 64) because counter 0 is the
    /// Poly1305 OTK and counters 1..=2^32-1 are the keystream. Above this,
    /// the counter wraps to 0 and reuses the OTK block as keystream —
    /// catastrophic.
    pub const MAX_PLAINTEXT_LEN: u64 = (u32::MAX as u64) * 64;

    /// Encrypts `buffer` in place and returns the 16-byte tag, binding `aad`.
    ///
    /// # Panics
    /// Panics if `buffer.len()` exceeds [`Self::MAX_PLAINTEXT_LEN`].
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        assert!(
            (buffer.len() as u64) <= Self::MAX_PLAINTEXT_LEN,
            "ChaCha20-Poly1305 plaintext exceeds 2^32 − 1 blocks (RFC 8439 §2.8)"
        );
        let mut otk = self.poly_key(nonce);
        let mut mac = Self::mac_with_aad(&otk, aad);
        #[cfg(target_arch = "x86_64")]
        let done = self.stitched(&mut mac, nonce, buffer, false);
        #[cfg(not(target_arch = "x86_64"))]
        let done = 0;
        // The rest (all of it without the stitched loop) in two passes.
        let rest = &mut buffer[done..];
        self.cipher
            .apply_keystream(nonce, 1 + (done / 64) as u32, rest);
        mac.update(rest);
        let tag = Self::finish_tag(mac, aad.len(), buffer.len());
        // The one-time key forges tags for this nonce; `Poly1305` wipes its
        // own copy on drop, so this frame's is the only leftover. Plain store
        // plus a barrier, for the per-record cost noted on `poly_key`.
        crate::zeroize::Zeroize::zeroize(&mut otk);
        tag
    }

    /// Verifies `tag` and, only if it matches, decrypts `buffer` in place.
    ///
    /// The tag is checked in constant time; on mismatch the buffer is left as
    /// ciphertext and [`TagMismatch`] is returned.
    ///
    /// # Panics
    /// Panics if `buffer.len()` exceeds [`Self::MAX_PLAINTEXT_LEN`].
    pub fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        assert!(
            (buffer.len() as u64) <= Self::MAX_PLAINTEXT_LEN,
            "ChaCha20-Poly1305 ciphertext exceeds 2^32 − 1 blocks (RFC 8439 §2.8)"
        );
        let mut otk = self.poly_key(nonce);
        let mut mac = Self::mac_with_aad(&otk, aad);
        // The stitched loop decrypts its prefix while authenticating it; on
        // a mismatch that prefix is re-encrypted below, so the caller still
        // only ever sees ciphertext or verified plaintext (the buffer is
        // exclusively borrowed for the whole call).
        #[cfg(target_arch = "x86_64")]
        let done = self.stitched(&mut mac, nonce, buffer, true);
        #[cfg(not(target_arch = "x86_64"))]
        let done = 0;
        mac.update(&buffer[done..]);
        let expected = Self::finish_tag(mac, aad.len(), buffer.len());
        crate::zeroize::Zeroize::zeroize(&mut otk);
        // The accept/reject verdict is the public outcome of decryption.
        if !expected.ct_eq(tag).declassify() {
            self.cipher.apply_keystream(nonce, 1, &mut buffer[..done]);
            return Err(TagMismatch);
        }
        self.cipher
            .apply_keystream(nonce, 1 + (done / 64) as u32, &mut buffer[done..]);
        Ok(())
    }
}

/// The stitched loop: each 1 KiB ChaCha20 pass runs Poly1305's IFMA steps
/// for its eight 128-byte groups before double rounds 1–8 (one each), so
/// the multiplies fill issue slots the rounds leave idle rather than running
/// as a second pass. Sealing absorbs the previous pass's ciphertext during
/// each pass (the last one after the loop); opening absorbs each pass's own
/// input, which the keystream XOR at the end of the pass then overwrites.
/// Measured on Zen 5 (cycles/byte, seal): two passes 0.684 (16 KiB) / 0.643
/// (1 MiB), stitched at rounds 0–7 0.638 / 0.587, at rounds 1–8 0.621 /
/// 0.569; ChaCha20 alone is 0.525. (Calling the plain 1 KiB kernel and the
/// IFMA steps one after the other in one loop, relying on out-of-order
/// overlap, measured slower than two passes: 0.710 / 0.660.)
///
/// Returns the bytes covered.
///
/// # Safety
/// The CPU must support AVX-512F and AVX-512 IFMA, `mac` must be
/// [`stitch_ready`](Poly1305::stitch_ready), and the 32-bit block counter
/// must not wrap over `buf`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512ifma")]
#[allow(unsafe_code)]
unsafe fn stitched_avx512(
    cipher: &ChaCha20,
    mac: &mut Poly1305,
    nonce: &[u8; 12],
    buf: &mut [u8],
    open: bool,
) -> usize {
    unsafe {
        let n = buf.len() & !1023;
        let mut s = mac.stitch();
        // All accesses go through this one pointer: chunk `i` is written
        // while chunk `i − 1` is read.
        let base = buf.as_mut_ptr();
        for i in 0..n / 1024 {
            let p = base.add(1024 * i);
            let ctr = 1 + 16 * i as u32;
            if open {
                cipher.xor_pass_avx512(nonce, ctr, p, &mut |dr| {
                    if (1..9).contains(&dr) {
                        s.absorb(p.add(128 * (dr - 1)));
                    }
                });
            } else {
                let prev = p.wrapping_sub(1024);
                cipher.xor_pass_avx512(nonce, ctr, p, &mut |dr| {
                    if i > 0 && (1..9).contains(&dr) {
                        s.absorb(prev.add(128 * (dr - 1)));
                    }
                });
            }
        }
        if !open {
            let last = base.add(n - 1024);
            for g in 0..8 {
                s.absorb(last.add(128 * g));
            }
        }
        s.finish();
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // RFC 8439 §2.8.2.
    fn vector() -> ([u8; 32], [u8; 12], [u8; 12], [u8; 114]) {
        let key =
            from_hex::<32>("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = from_hex::<12>("070000004041424344454647");
        let aad = from_hex::<12>("50515253c0c1c2c3c4c5c6c7");
        let mut plaintext = [0u8; 114];
        plaintext.copy_from_slice(
            b"Ladies and Gentlemen of the class of '99: If I could offer you \
only one tip for the future, sunscreen would be it.",
        );
        (key, nonce, aad, plaintext)
    }

    #[test]
    fn rfc8439_seal() {
        let (key, nonce, aad, plaintext) = vector();
        let mut buf = plaintext;
        let tag = ChaCha20Poly1305::new(&key).encrypt(&nonce, &aad, &mut buf);
        let expected_ct = from_hex::<114>(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6\
             3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36\
             92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc\
             3ff4def08e4b7a9de576d26586cec64b6116",
        );
        assert_eq!(buf, expected_ct);
        assert_eq!(tag, from_hex::<16>("1ae10b594f09e26a7e902ecbd0600691"));
    }

    /// The AEAD (stitched loop where available, two passes otherwise) must
    /// match an independent composition of the ChaCha20 and Poly1305
    /// primitives — keystream from counter 1, MAC over the padded AAD,
    /// ciphertext and lengths fed in small (always scalar) pieces — for
    /// every length in `0..=1100`, across the 1 KiB stitch boundary and for
    /// large buffers, with and without AAD. Opening must round-trip, and a
    /// rejected open must leave the ciphertext exactly as it was (the
    /// stitched open decrypts before it knows, then re-encrypts).
    #[cfg(feature = "alloc")]
    #[test]
    fn matches_two_pass_reference() {
        use alloc::vec::Vec;
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        if super::super::poly1305::Poly1305::new(&[0; 32]).stitch_ready() {
            std::eprintln!("chacha20poly1305: RUNNING stitched avx512-ifma loop vs reference");
        } else {
            std::eprintln!("chacha20poly1305: SKIPPED stitched loop (no AVX-512 IFMA here)");
        }
        let key: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(3));
        let nonce: [u8; 12] = core::array::from_fn(|i| (i as u8).wrapping_mul(11).wrapping_add(5));
        let aead = ChaCha20Poly1305::new(&key);
        let cipher = ChaCha20::new(&key);
        let reference = |aad: &[u8], pt: &[u8]| -> (Vec<u8>, [u8; 16]) {
            let mut ct = pt.to_vec();
            cipher.apply_keystream(&nonce, 1, &mut ct);
            let block0 = cipher.block(&nonce, 0);
            let otk: [u8; 32] = block0[..32].try_into().unwrap();
            let mut mac = Poly1305::new(&otk);
            let mut feed = |data: &[u8]| {
                for chunk in data.chunks(48) {
                    mac.update(chunk);
                }
            };
            feed(aad);
            feed(&[0u8; 16][..(16 - aad.len() % 16) % 16]);
            feed(&ct);
            feed(&[0u8; 16][..(16 - ct.len() % 16) % 16]);
            feed(&(aad.len() as u64).to_le_bytes());
            feed(&(ct.len() as u64).to_le_bytes());
            (ct, mac.finish())
        };
        for len in (0usize..=1100).chain([2047, 2048, 3072 + 1, 16384, 65536 + 5]) {
            let pt: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
            for aad in [&b""[..], &b"thirteen byte"[..]] {
                let (want_ct, want_tag) = reference(aad, &pt);
                let mut buf = pt.clone();
                let tag = aead.encrypt(&nonce, aad, &mut buf);
                assert_eq!(buf, want_ct, "ciphertext len={len} aad={}", aad.len());
                assert_eq!(tag, want_tag, "tag len={len} aad={}", aad.len());

                let mut bad = tag;
                bad[15] ^= 0x80;
                assert_eq!(aead.decrypt(&nonce, aad, &mut buf, &bad), Err(TagMismatch));
                assert_eq!(
                    buf, want_ct,
                    "rejected open must keep the ciphertext, len={len}"
                );

                aead.decrypt(&nonce, aad, &mut buf, &tag).unwrap();
                assert_eq!(buf, pt, "round trip len={len}");
            }
        }
    }

    #[test]
    fn roundtrip_and_reject() {
        let (key, nonce, aad, plaintext) = vector();
        let aead = ChaCha20Poly1305::new(&key);

        let mut buf = plaintext;
        let tag = aead.encrypt(&nonce, &aad, &mut buf);
        let ciphertext = buf;
        aead.decrypt(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plaintext);

        // Corrupted tag is rejected; buffer left as ciphertext.
        let mut buf = ciphertext;
        let mut bad = tag;
        bad[0] ^= 1;
        assert_eq!(aead.decrypt(&nonce, &aad, &mut buf, &bad), Err(TagMismatch));
        assert_eq!(buf, ciphertext);

        // Tampered AAD is rejected.
        let mut buf = ciphertext;
        let mut bad_aad = aad;
        bad_aad[0] ^= 1;
        assert_eq!(
            aead.decrypt(&nonce, &bad_aad, &mut buf, &tag),
            Err(TagMismatch)
        );
    }
}
