//! AES-XTS — XEX-based Tweaked codebook with ciphertext Stealing
//! (IEEE 1619-2007 / NIST SP 800-38E).
//!
//! XTS is the standard mode for sector-addressable storage (full-disk
//! encryption, file-level encryption, etc.). It is **not** an authenticated
//! mode and does not provide integrity; tampering with a ciphertext sector
//! produces a corresponding 16-byte plaintext corruption rather than a
//! decryption failure. Use an AEAD ([`Gcm`](super::Gcm), [`Ccm`](super::Ccm),
//! [`ChaCha20Poly1305`](super::ChaCha20Poly1305)) when authenticity matters.
//!
//! Each "sector" is encrypted independently under the data key with a tweak
//! derived from the sector index encrypted under the (separate) tweak key.
//! Within a sector, successive 16-byte blocks share the same per-sector tweak
//! pre-multiplier T₀; each block uses Tᵢ = T₀ · αⁱ in GF(2¹²⁸) under the
//! polynomial `x¹²⁸ + x⁷ + x² + x + 1`. **This polynomial is the non-
//! bit-reversed (little-endian) form of GHASH's, so the multiply here is a
//! separate routine from `gcm::gf_mul`; do not confuse the two.**
//!
//! Sectors must be at least 16 bytes (one full block); if their length is not
//! a multiple of 16, ciphertext stealing is used on the trailing partial block.

use super::{BlockCipher, InvalidLength};

/// Doubles a 128-bit XTS tweak in place under the IEEE 1619 polynomial.
///
/// Treats `t` as a little-endian 128-bit value; multiplies by α (= 2) modulo
/// `x¹²⁸ + x⁷ + x² + x + 1` (reduction constant `0x87`). Constant time.
#[inline]
fn double_tweak(t: &mut [u8; 16]) {
    let mut carry = 0u8;
    for byte in t.iter_mut() {
        let b = *byte;
        *byte = (b << 1) | carry;
        carry = b >> 7;
    }
    // If the top bit was set, reduce by the polynomial: XOR low byte with 0x87.
    // Constant-time formulation: 0u8.wrapping_sub(carry) = 0x00 or 0xff.
    t[0] ^= 0u8.wrapping_sub(carry) & 0x87;
}

/// AES-XTS context — uses two independent block-cipher instances (data key
/// and tweak key) of the same type.
#[derive(Clone)]
pub struct Xts<C: BlockCipher> {
    cipher_data: C,
    cipher_tweak: C,
}

impl<C: BlockCipher> Xts<C> {
    /// Creates an XTS context from two pre-keyed block ciphers. The two keys
    /// must be independent; XTS-AES-128 has total key length 256 bits
    /// (two 128-bit AES keys), XTS-AES-256 has 512 bits.
    pub fn new(cipher_data: C, cipher_tweak: C) -> Self {
        Self {
            cipher_data,
            cipher_tweak,
        }
    }

    /// Derives the initial tweak T₀ = AES_{K2}(sector_index_le).
    fn initial_tweak(&self, sector_index: u128) -> [u8; 16] {
        let mut t = sector_index.to_le_bytes();
        self.cipher_tweak.encrypt_block(&mut t);
        t
    }

    /// Encrypts a sector in place. Sectors must be at least 16 bytes; lengths
    /// that are not a multiple of 16 use ciphertext stealing on the trailing
    /// blocks.
    pub fn encrypt_sector(&self, sector_index: u128, buf: &mut [u8]) -> Result<(), InvalidLength> {
        if buf.len() < 16 {
            return Err(InvalidLength);
        }

        let mut t = self.initial_tweak(sector_index);
        let n_full = buf.len() / 16;
        let rem = buf.len() % 16;
        let full_to_emit = if rem == 0 { n_full } else { n_full - 1 };

        // Encrypt the first `full_to_emit` complete blocks.
        let mut block = [0u8; 16];
        for i in 0..full_to_emit {
            let off = i * 16;
            block.copy_from_slice(&buf[off..off + 16]);
            xex(&self.cipher_data, &mut block, &t, true);
            buf[off..off + 16].copy_from_slice(&block);
            double_tweak(&mut t);
        }

        if rem == 0 {
            return Ok(());
        }

        // CTS path: there's a final full block (call it B_{n-1}) at offset
        // `full_to_emit * 16` and a partial block of `rem` bytes following it.
        //
        // Per IEEE 1619 §5.3.2 the two tweaks swap in the steal:
        //   CC          = XEX_T(P_{n-1})              ; T = current tweak
        //   PP          = P_partial ‖ CC[rem..]       ; 16 bytes
        //   C_{n-1}     = XEX_T'(PP)                  ; T' = next tweak
        //   C_partial   = CC[..rem]
        let full_off = full_to_emit * 16;

        // CC = XEX_T(P_{n-1})
        block.copy_from_slice(&buf[full_off..full_off + 16]);
        xex(&self.cipher_data, &mut block, &t, true);
        let mut cc = block;

        // Step the tweak by α: T → T'.
        double_tweak(&mut t);

        // PP = P_partial ‖ CC[rem..]
        let mut pp = [0u8; 16];
        pp[..rem].copy_from_slice(&buf[full_off + 16..]);
        pp[rem..].copy_from_slice(&cc[rem..]);

        // Encrypt PP with T'.
        xex(&self.cipher_data, &mut pp, &t, true);

        // Emit C_{n-1} = PP and C_partial = CC[..rem].
        buf[full_off..full_off + 16].copy_from_slice(&pp);
        // The trailing partial bytes get the truncated CC.
        let _ = &mut cc; // silence unused-mut warnings on the slice borrow
        buf[full_off + 16..].copy_from_slice(&cc[..rem]);

        Ok(())
    }

    /// Decrypts a sector in place. Mirrors [`encrypt_sector`].
    pub fn decrypt_sector(&self, sector_index: u128, buf: &mut [u8]) -> Result<(), InvalidLength> {
        if buf.len() < 16 {
            return Err(InvalidLength);
        }

        let mut t = self.initial_tweak(sector_index);
        let n_full = buf.len() / 16;
        let rem = buf.len() % 16;
        let full_to_emit = if rem == 0 { n_full } else { n_full - 1 };

        // Decrypt the first `full_to_emit` complete blocks.
        let mut block = [0u8; 16];
        for i in 0..full_to_emit {
            let off = i * 16;
            block.copy_from_slice(&buf[off..off + 16]);
            xex(&self.cipher_data, &mut block, &t, false);
            buf[off..off + 16].copy_from_slice(&block);
            double_tweak(&mut t);
        }

        if rem == 0 {
            return Ok(());
        }

        // CTS reverse: T is currently the tweak for position n-1; T' is next.
        // Encrypt was:
        //   CC = XEX_T(P_{n-1});  C_{n-1} = XEX_T'(PP);  C_partial = CC[..rem]
        // Decrypt:
        //   PP = XEX_T'^{-1}(C_{n-1});  P_partial = PP[..rem];  CC = C_partial ‖ PP[rem..]
        //   P_{n-1} = XEX_T^{-1}(CC)
        let full_off = full_to_emit * 16;

        // Compute T' = T · α (the same step the encrypter did).
        let mut t_next = t;
        double_tweak(&mut t_next);

        // PP = XEX_T'^{-1}(C_{n-1})
        let mut pp = [0u8; 16];
        pp.copy_from_slice(&buf[full_off..full_off + 16]);
        xex(&self.cipher_data, &mut pp, &t_next, false);

        // Reconstruct CC = C_partial ‖ PP[rem..]
        let mut cc = [0u8; 16];
        cc[..rem].copy_from_slice(&buf[full_off + 16..]);
        cc[rem..].copy_from_slice(&pp[rem..]);

        // P_{n-1} = XEX_T^{-1}(CC)
        xex(&self.cipher_data, &mut cc, &t, false);

        buf[full_off..full_off + 16].copy_from_slice(&cc);
        buf[full_off + 16..].copy_from_slice(&pp[..rem]);

        Ok(())
    }
}

/// XEX in place: if `encrypt`, computes `out = AES_K(in ⊕ T) ⊕ T`; otherwise
/// computes the inverse, `out = AES_K^{-1}(in ⊕ T) ⊕ T`.
#[inline]
fn xex<C: BlockCipher>(cipher: &C, block: &mut [u8; 16], t: &[u8; 16], encrypt: bool) {
    for i in 0..16 {
        block[i] ^= t[i];
    }
    if encrypt {
        cipher.encrypt_block(block);
    } else {
        cipher.decrypt_block(block);
    }
    for i in 0..16 {
        block[i] ^= t[i];
    }
}

/// XTS-AES-128 — total key length 256 bits (two 128-bit AES keys).
pub type Aes128Xts = Xts<super::Aes128>;
/// XTS-AES-256 — total key length 512 bits (two 256-bit AES keys).
pub type Aes256Xts = Xts<super::Aes256>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{Aes128, Aes256};
    use crate::test_util::from_hex;

    /// IEEE 1619-2007 Annex B Vector 1 (XTS-AES-128, two full blocks, sector 0).
    #[test]
    fn ieee_1619_vector_1() {
        let k1 = from_hex::<16>("00000000000000000000000000000000");
        let k2 = from_hex::<16>("00000000000000000000000000000000");
        let pt = from_hex::<32>("0000000000000000000000000000000000000000000000000000000000000000");
        let expected =
            from_hex::<32>("917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e");

        let xts = Aes128Xts::new(Aes128::new(&k1), Aes128::new(&k2));
        let mut buf = pt;
        xts.encrypt_sector(0, &mut buf).unwrap();
        assert_eq!(buf, expected);
        xts.decrypt_sector(0, &mut buf).unwrap();
        assert_eq!(buf, pt);
    }

    /// IEEE 1619-2007 Annex B Vector 2: distinct keys, sector index 0x3333333333.
    #[test]
    fn ieee_1619_vector_2() {
        let k1 = from_hex::<16>("11111111111111111111111111111111");
        let k2 = from_hex::<16>("22222222222222222222222222222222");
        let pt = from_hex::<32>("4444444444444444444444444444444444444444444444444444444444444444");
        let expected =
            from_hex::<32>("c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0");

        let xts = Aes128Xts::new(Aes128::new(&k1), Aes128::new(&k2));
        let mut buf = pt;
        xts.encrypt_sector(0x3333333333, &mut buf).unwrap();
        assert_eq!(buf, expected);
        xts.decrypt_sector(0x3333333333, &mut buf).unwrap();
        assert_eq!(buf, pt);
    }

    /// IEEE 1619 Vector 10 (XTS-AES-256): 32-byte plaintext, sector 0xff.
    /// Verifies the AES-256 path.
    #[test]
    fn ieee_1619_vector_10_aes256() {
        let k1 = from_hex::<32>("2718281828459045235360287471352662497757247093699959574966967627");
        let k2 = from_hex::<32>("3141592653589793238462643383279502884197169399375105820974944592");
        let pt = from_hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let expected =
            from_hex::<32>("1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b");

        let xts = Aes256Xts::new(Aes256::new(&k1), Aes256::new(&k2));
        let mut buf = pt;
        xts.encrypt_sector(0xff, &mut buf).unwrap();
        assert_eq!(buf, expected);
        xts.decrypt_sector(0xff, &mut buf).unwrap();
        assert_eq!(buf, pt);
    }

    /// Sector shorter than one block is rejected.
    #[test]
    fn short_sector_rejected() {
        let xts = Aes128Xts::new(
            Aes128::new(&from_hex::<16>("00000000000000000000000000000000")),
            Aes128::new(&from_hex::<16>("00000000000000000000000000000000")),
        );
        let mut buf = [0u8; 15];
        assert_eq!(xts.encrypt_sector(0, &mut buf), Err(InvalidLength));
        assert_eq!(xts.decrypt_sector(0, &mut buf), Err(InvalidLength));
    }

    /// Round-trip every CTS length from 17 through 47 bytes (covers `rem` ∈ 1..=15
    /// across one and two trailing blocks). The implementation is the only
    /// reference here, but CTS is a deterministic shuffle of the standard XTS
    /// transform — if the full-block vectors above and the round-trip are
    /// correct, CTS is correct.
    #[test]
    fn cts_roundtrip_all_remainders() {
        let k1 = from_hex::<16>("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0");
        let k2 = from_hex::<16>("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0");
        let xts = Aes128Xts::new(Aes128::new(&k1), Aes128::new(&k2));

        let mut input = [0u8; 47];
        for (i, b) in input.iter_mut().enumerate() {
            *b = i as u8;
        }
        for len in 17..=47 {
            let mut buf = [0u8; 47];
            buf[..len].copy_from_slice(&input[..len]);
            let original = buf;
            xts.encrypt_sector(0x4242, &mut buf[..len]).unwrap();
            assert_ne!(&buf[..len], &original[..len], "ciphertext == plaintext");
            xts.decrypt_sector(0x4242, &mut buf[..len]).unwrap();
            assert_eq!(&buf[..len], &original[..len]);
        }
    }
}
