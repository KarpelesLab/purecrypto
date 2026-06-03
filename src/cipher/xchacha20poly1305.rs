//! XChaCha20-Poly1305 AEAD (draft-irtf-cfrg-xchacha-03).
//!
//! XChaCha20-Poly1305 extends [`ChaCha20Poly1305`](super::ChaCha20Poly1305) to
//! a 192-bit (24-byte) nonce, large enough to choose nonces at random without a
//! birthday-bound collision worry. The construction derives a per-message
//! subkey via HChaCha20 over the first 16 nonce bytes, then runs ordinary
//! ChaCha20-Poly1305 with that subkey and a 96-bit nonce of `0⁴² ‖ nonce[16..]`
//! (draft §2.3).

use super::TagMismatch;
use super::chacha20::hchacha20;
use super::chacha20poly1305::ChaCha20Poly1305;

/// An XChaCha20-Poly1305 AEAD context keyed with a 256-bit key.
#[derive(Clone)]
pub struct XChaCha20Poly1305 {
    key: [u8; 32],
}

impl XChaCha20Poly1305 {
    /// Creates an AEAD context from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        XChaCha20Poly1305 { key: *key }
    }

    /// Derives the inner ChaCha20-Poly1305 instance and 96-bit nonce for a
    /// 24-byte XChaCha nonce: subkey = HChaCha20(key, nonce[0..16]) and the
    /// inner nonce is `[0,0,0,0] ‖ nonce[16..24]` (draft §2.3).
    fn inner(&self, nonce: &[u8; 24]) -> (ChaCha20Poly1305, [u8; 12]) {
        let mut n16 = [0u8; 16];
        n16.copy_from_slice(&nonce[..16]);
        let subkey = hchacha20(&self.key, &n16);
        let aead = ChaCha20Poly1305::new(&subkey);
        let mut inner_nonce = [0u8; 12];
        inner_nonce[4..].copy_from_slice(&nonce[16..]);
        (aead, inner_nonce)
    }

    /// Encrypts `buffer` in place and returns the 16-byte tag, binding `aad`.
    pub fn encrypt(&self, nonce: &[u8; 24], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        let (aead, inner_nonce) = self.inner(nonce);
        aead.encrypt(&inner_nonce, aad, buffer)
    }

    /// Verifies `tag` and, only on match, decrypts `buffer` in place.
    ///
    /// The tag is checked in constant time; on mismatch the buffer is left as
    /// ciphertext and [`TagMismatch`] is returned (matching
    /// [`ChaCha20Poly1305`](super::ChaCha20Poly1305)).
    pub fn decrypt(
        &self,
        nonce: &[u8; 24],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        let (aead, inner_nonce) = self.inner(nonce);
        aead.decrypt(&inner_nonce, aad, buffer, tag)
    }
}

impl Drop for XChaCha20Poly1305 {
    fn drop(&mut self) {
        // Best-effort wipe of the key, matching the AES round-key drop.
        self.key = [0u8; 32];
        let _ = core::hint::black_box(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{from_hex, from_hex_vec};

    // draft-irtf-cfrg-xchacha §A.3 / §2.2.2: AEAD encryption test vector.
    #[test]
    fn draft_aead_vector() {
        let key =
            from_hex::<32>("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce = from_hex::<24>("404142434445464748494a4b4c4d4e4f5051525354555657");
        let aad = from_hex::<12>("50515253c0c1c2c3c4c5c6c7");
        let plaintext = from_hex_vec(
            "4c616469657320616e642047656e746c\
             656d656e206f662074686520636c6173\
             73206f66202739393a20496620492063\
             6f756c64206f6666657220796f75206f\
             6e6c79206f6e652074697020666f7220\
             746865206675747572652c2073756e73\
             637265656e20776f756c642062652069\
             742e",
        );

        let aead = XChaCha20Poly1305::new(&key);
        let mut buf = plaintext.clone();
        let tag = aead.encrypt(&nonce, &aad, &mut buf);

        let expected_ct = from_hex_vec(
            "bd6d179d3e83d43b9576579493c0e939\
             572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39\
             ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e\
             3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13\
             b52e",
        );
        assert_eq!(buf, expected_ct);
        assert_eq!(tag, from_hex::<16>("c0875924c1c7987947deafd8780acf49"));

        // Round-trip.
        aead.decrypt(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plaintext);
    }

    #[test]
    fn reject_tamper() {
        let key = [7u8; 32];
        let nonce = [9u8; 24];
        let aead = XChaCha20Poly1305::new(&key);
        let pt = *b"XChaCha20-Poly1305 tamper test..";
        let mut buf = pt;
        let tag = aead.encrypt(&nonce, b"hdr", &mut buf);
        let ciphertext = buf;

        let mut bad = tag;
        bad[0] ^= 1;
        assert_eq!(
            aead.decrypt(&nonce, b"hdr", &mut buf, &bad),
            Err(TagMismatch)
        );
        assert_eq!(buf, ciphertext, "buffer untouched on auth failure");
    }
}
