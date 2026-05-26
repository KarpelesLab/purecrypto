//! AES-GCM — Galois/Counter Mode authenticated encryption (NIST SP 800-38D).
//!
//! GCM combines CTR-mode confidentiality with a GHASH authenticator over the
//! GF(2¹²⁸) field. The field multiply here is the branchless, table-free
//! bit-by-bit algorithm, so it leaks nothing about the (secret) hash subkey
//! through cache timing.
//!
//! A given (key, nonce) pair must **never** be reused: nonce reuse in GCM is
//! catastrophic, revealing the hash subkey and breaking authenticity.

use super::{BlockCipher, TagMismatch};
use crate::ct::ConstantTimeEq;

/// GF(2¹²⁸) reduction constant `R = 11100001 ‖ 0¹²⁰` in the GCM bit ordering.
const R: u128 = 0xe1000000000000000000000000000000;

/// Multiplies two field elements in GF(2¹²⁸) using the GCM bit convention,
/// in constant time (128 fixed iterations, no branches or table lookups).
fn gf_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    let mut i = 0;
    while i < 128 {
        // GCM bit i of x is u128 bit (127 - i): process from the left.
        let xi = (x >> (127 - i)) & 1;
        z ^= 0u128.wrapping_sub(xi) & v;
        // Shift v right (toward GCM bit 127); reduce if the bit shifted out set.
        let lsb = v & 1;
        v >>= 1;
        v ^= 0u128.wrapping_sub(lsb) & R;
        i += 1;
    }
    z
}

/// Loads up to 16 bytes as a big-endian block, zero-padded on the right.
#[inline]
fn load_block(chunk: &[u8]) -> u128 {
    let mut b = [0u8; 16];
    b[..chunk.len()].copy_from_slice(chunk);
    u128::from_be_bytes(b)
}

/// Increments the rightmost 32 bits of a counter block (GCM `inc32`).
#[inline]
fn inc32(block: u128) -> u128 {
    let ctr = (block as u32).wrapping_add(1);
    (block & !0xffff_ffffu128) | ctr as u128
}

/// AES-GCM context, parameterized over the underlying block cipher.
#[derive(Clone)]
pub struct Gcm<C: BlockCipher> {
    cipher: C,
    /// Hash subkey `H = E_K(0¹²⁸)`.
    h: u128,
}

impl<C: BlockCipher> Gcm<C> {
    /// Creates a GCM context, deriving the hash subkey from `cipher`.
    pub fn new(cipher: C) -> Self {
        let mut h = [0u8; 16];
        cipher.encrypt_block(&mut h);
        Gcm {
            cipher,
            h: u128::from_be_bytes(h),
        }
    }

    /// Computes the pre-counter block `J0` for a nonce of any length.
    fn j0(&self, nonce: &[u8]) -> u128 {
        if nonce.len() == 12 {
            // Recommended case: J0 = IV ‖ 0³¹ ‖ 1.
            let mut block = [0u8; 16];
            block[..12].copy_from_slice(nonce);
            block[15] = 1;
            u128::from_be_bytes(block)
        } else {
            // J0 = GHASH_H(IV padded ‖ 0⁶⁴ ‖ [len(IV)]₆₄).
            let mut x = 0u128;
            for chunk in nonce.chunks(16) {
                x = gf_mul(x ^ load_block(chunk), self.h);
            }
            x = gf_mul(x ^ (nonce.len() as u128 * 8), self.h);
            x
        }
    }

    /// GHASH over associated data `aad` and ciphertext `ct`.
    fn ghash(&self, aad: &[u8], ct: &[u8]) -> u128 {
        let mut x = 0u128;
        for chunk in aad.chunks(16) {
            x = gf_mul(x ^ load_block(chunk), self.h);
        }
        for chunk in ct.chunks(16) {
            x = gf_mul(x ^ load_block(chunk), self.h);
        }
        // Length block: [len(aad)]₆₄ ‖ [len(ct)]₆₄, in bits.
        let len_block = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
        gf_mul(x ^ len_block, self.h)
    }

    /// XORs the GCTR keystream (counter increments only its low 32 bits) into
    /// `buf`, starting from `counter`.
    fn gctr(&self, mut counter: u128, buf: &mut [u8]) {
        let mut ks = [0u8; 16];
        let mut pos = 16;
        for byte in buf.iter_mut() {
            if pos == 16 {
                ks = counter.to_be_bytes();
                self.cipher.encrypt_block(&mut ks);
                counter = inc32(counter);
                pos = 0;
            }
            *byte ^= ks[pos];
            pos += 1;
        }
    }

    /// Computes the authentication tag `E_K(J0) ⊕ GHASH(aad, ct)`.
    fn tag(&self, j0: u128, aad: &[u8], ct: &[u8]) -> [u8; 16] {
        let s = self.ghash(aad, ct);
        let mut ej0 = j0.to_be_bytes();
        self.cipher.encrypt_block(&mut ej0);
        (u128::from_be_bytes(ej0) ^ s).to_be_bytes()
    }

    /// NIST SP 800-38D §5.2.1.1: |IV| ∈ [1, 2^64−1] bits. We surface the
    /// upper end as a byte cap; the lower end forbids zero-length nonces.
    const MAX_NONCE_LEN: usize = (1usize << 61) - 1;
    /// NIST SP 800-38D §5.2.1.1: |P| ≤ 2^39 − 256 bits, i.e. `(1<<36) − 32`
    /// bytes. Above this, the 32-bit GCTR counter wraps and reuses keystream.
    pub const MAX_PLAINTEXT_LEN: u64 = (1u64 << 36) - 32;

    fn validate(nonce: &[u8], buffer: &[u8]) {
        assert!(
            !nonce.is_empty() && nonce.len() <= Self::MAX_NONCE_LEN,
            "AES-GCM nonce must be 1..=2^61-1 bytes (NIST SP 800-38D §5.2.1.1)"
        );
        assert!(
            (buffer.len() as u64) <= Self::MAX_PLAINTEXT_LEN,
            "AES-GCM plaintext exceeds 2^39 − 256 bits (NIST SP 800-38D §5.2.1.1)"
        );
    }

    /// Encrypts `buffer` in place and returns the 16-byte authentication tag,
    /// binding the optional `aad`.
    ///
    /// # Panics
    /// Panics if `nonce.is_empty()` or `buffer.len()` exceeds the NIST
    /// SP 800-38D plaintext cap (`2^39 − 256` bits).
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        Self::validate(nonce, buffer);
        let j0 = self.j0(nonce);
        self.gctr(inc32(j0), buffer);
        self.tag(j0, aad, buffer)
    }

    /// Verifies `tag` and, only if it matches, decrypts `buffer` in place.
    ///
    /// The tag is checked in constant time. On mismatch the ciphertext is
    /// **left untouched** (no unauthenticated plaintext is produced) and
    /// [`TagMismatch`] is returned.
    ///
    /// # Panics
    /// Panics if `nonce.is_empty()` or `buffer.len()` exceeds the NIST cap.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        Self::validate(nonce, buffer);
        let j0 = self.j0(nonce);
        // GHASH is computed over the ciphertext, which is still in `buffer`.
        let expected = self.tag(j0, aad, buffer);
        if !bool::from(expected.ct_eq(tag)) {
            return Err(TagMismatch);
        }
        self.gctr(inc32(j0), buffer);
        Ok(())
    }
}

/// AES-128 in GCM mode.
pub type Aes128Gcm = Gcm<super::Aes128>;
/// AES-256 in GCM mode.
pub type Aes256Gcm = Gcm<super::Aes256>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::Aes128;
    use crate::test_util::from_hex;

    fn gcm128(key_hex: &str) -> Gcm<Aes128> {
        Gcm::new(Aes128::new(&from_hex::<16>(key_hex)))
    }

    // McGrew & Viega GCM test vectors (AES-128).

    #[test]
    fn tc1_empty() {
        let g = gcm128("00000000000000000000000000000000");
        let nonce = from_hex::<12>("000000000000000000000000");
        let mut buf: [u8; 0] = [];
        let tag = g.encrypt(&nonce, &[], &mut buf);
        assert_eq!(tag, from_hex::<16>("58e2fccefa7e3061367f1d57a4e7455a"));
    }

    #[test]
    fn tc2_one_block() {
        let g = gcm128("00000000000000000000000000000000");
        let nonce = from_hex::<12>("000000000000000000000000");
        let mut buf = from_hex::<16>("00000000000000000000000000000000");
        let tag = g.encrypt(&nonce, &[], &mut buf);
        assert_eq!(buf, from_hex::<16>("0388dace60b6a392f328c2b971b2fe78"));
        assert_eq!(tag, from_hex::<16>("ab6e47d42cec13bdf53a67b21257bddf"));
    }

    #[test]
    fn tc3_multiblock() {
        let g = gcm128("feffe9928665731c6d6a8f9467308308");
        let nonce = from_hex::<12>("cafebabefacedbaddecaf888");
        let mut buf = from_hex::<64>(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let tag = g.encrypt(&nonce, &[], &mut buf);
        assert_eq!(
            buf,
            from_hex::<64>(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
            )
        );
        assert_eq!(tag, from_hex::<16>("4d5c2af327cd64a62cf35abd2ba6fab4"));
    }

    #[test]
    fn tc4_with_aad() {
        let g = gcm128("feffe9928665731c6d6a8f9467308308");
        let nonce = from_hex::<12>("cafebabefacedbaddecaf888");
        let aad = from_hex::<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let mut buf = from_hex::<60>(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let tag = g.encrypt(&nonce, &aad, &mut buf);
        assert_eq!(
            buf,
            from_hex::<60>(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
            )
        );
        assert_eq!(tag, from_hex::<16>("5bc94fbc3221a5db94fae95ae7121a47"));
    }

    #[test]
    fn decrypt_roundtrip_and_reject() {
        let g = gcm128("feffe9928665731c6d6a8f9467308308");
        let nonce = from_hex::<12>("cafebabefacedbaddecaf888");
        let aad = from_hex::<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = from_hex::<60>(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );

        let mut buf = plaintext;
        let tag = g.encrypt(&nonce, &aad, &mut buf);
        // Correct tag decrypts back to the plaintext.
        g.decrypt(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plaintext);

        // A corrupted tag is rejected, and the buffer is left as ciphertext.
        let mut ct = plaintext;
        let tag = g.encrypt(&nonce, &aad, &mut ct);
        let ciphertext = ct;
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        assert_eq!(g.decrypt(&nonce, &aad, &mut ct, &bad_tag), Err(TagMismatch));
        assert_eq!(ct, ciphertext, "buffer must be unchanged on auth failure");

        // Tampered AAD is also rejected.
        let mut ct = ciphertext;
        let mut bad_aad = aad;
        bad_aad[0] ^= 1;
        assert_eq!(g.decrypt(&nonce, &bad_aad, &mut ct, &tag), Err(TagMismatch));
    }
}
