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
    fn poly_key(&self, nonce: &[u8; 12]) -> [u8; 32] {
        let block0 = self.cipher.block(nonce, 0);
        let mut otk = [0u8; 32];
        otk.copy_from_slice(&block0[..32]);
        otk
    }

    /// Computes the Poly1305 tag over `aad` and the ciphertext `ct`.
    fn tag(&self, otk: &[u8; 32], aad: &[u8], ct: &[u8]) -> [u8; 16] {
        let mut mac = Poly1305::new(otk);
        mac.update(aad);
        pad16(&mut mac, aad.len());
        mac.update(ct);
        pad16(&mut mac, ct.len());
        let mut lens = [0u8; 16];
        lens[0..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lens[8..16].copy_from_slice(&(ct.len() as u64).to_le_bytes());
        mac.update(&lens);
        mac.finish()
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
    /// Panics if `buffer.len()` exceeds [`MAX_PLAINTEXT_LEN`].
    pub fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        assert!(
            (buffer.len() as u64) <= Self::MAX_PLAINTEXT_LEN,
            "ChaCha20-Poly1305 plaintext exceeds 2^32 − 1 blocks (RFC 8439 §2.8)"
        );
        let otk = self.poly_key(nonce);
        self.cipher.apply_keystream(nonce, 1, buffer);
        self.tag(&otk, aad, buffer)
    }

    /// Verifies `tag` and, only if it matches, decrypts `buffer` in place.
    ///
    /// The tag is checked in constant time; on mismatch the buffer is left as
    /// ciphertext and [`TagMismatch`] is returned.
    ///
    /// # Panics
    /// Panics if `buffer.len()` exceeds [`MAX_PLAINTEXT_LEN`].
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
        let otk = self.poly_key(nonce);
        let expected = self.tag(&otk, aad, buffer);
        if !bool::from(expected.ct_eq(tag)) {
            return Err(TagMismatch);
        }
        self.cipher.apply_keystream(nonce, 1, buffer);
        Ok(())
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
