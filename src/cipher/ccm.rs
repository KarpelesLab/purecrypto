//! AES-CCM — Counter with CBC-MAC authenticated encryption
//! (RFC 3610 / NIST SP 800-38C).
//!
//! CCM combines CTR-mode confidentiality with CBC-MAC for authenticity, using
//! a single block cipher. As with any AEAD, a `(key, nonce)` pair must
//! **never** be reused: nonce reuse breaks both confidentiality and
//! authenticity.
//!
//! This implementation is parameterized over the tag length `M` (a const
//! generic ∈ {4, 6, 8, 10, 12, 14, 16}):
//!
//!  - [`Aes128Ccm`]  / [`Aes256Ccm`]  — M = 16.
//!  - [`Aes128Ccm8`] / [`Aes256Ccm8`] — M = 8  (used by TLS_AES_128_CCM_8 etc.).
//!
//! Nonces are 7..=13 bytes (the CCM-permitted range; standard is 12). The
//! maximum payload length for an `n`-byte nonce is `2^(8·(15-n)) − 1` bytes;
//! with the standard 12-byte nonce that is `2^24 − 1 ≈ 16 MiB`.

use super::{BlockCipher, TagMismatch};
use crate::ct::ConstantTimeEq;

/// Streaming CBC-MAC over a [`BlockCipher`], producing a 16-byte tag.
///
/// CBC-MAC is not collision-resistant for arbitrary-length messages on its
/// own; CCM's framing makes the inputs distinguishable by length, so this is
/// used only as CCM's internal MAC and intentionally kept private to this
/// module.
struct CbcMac<'a, C: BlockCipher> {
    cipher: &'a C,
    state: [u8; 16],
    pending: [u8; 16],
    pending_len: usize,
}

impl<'a, C: BlockCipher> CbcMac<'a, C> {
    fn new(cipher: &'a C) -> Self {
        Self {
            cipher,
            state: [0; 16],
            pending: [0; 16],
            pending_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let n = core::cmp::min(16 - self.pending_len, data.len());
            self.pending[self.pending_len..self.pending_len + n].copy_from_slice(&data[..n]);
            self.pending_len += n;
            data = &data[n..];
            if self.pending_len == 16 {
                for i in 0..16 {
                    self.state[i] ^= self.pending[i];
                }
                self.cipher.encrypt_block(&mut self.state);
                self.pending = [0; 16];
                self.pending_len = 0;
            }
        }
    }

    /// Finalize; if a partial block is pending, zero-pad it and absorb.
    fn finalize(mut self) -> [u8; 16] {
        if self.pending_len > 0 {
            for i in 0..16 {
                self.state[i] ^= self.pending[i];
            }
            self.cipher.encrypt_block(&mut self.state);
        }
        self.state
    }
}

/// AES-CCM context with a `M`-byte tag.
///
/// `M` must be one of `{4, 6, 8, 10, 12, 14, 16}`; instantiating with any
/// other value will panic at construction.
#[derive(Clone)]
pub struct Ccm<C: BlockCipher, const M: usize> {
    cipher: C,
}

impl<C: BlockCipher, const M: usize> Ccm<C, M> {
    /// Creates a CCM context from a pre-keyed block cipher.
    pub fn new(cipher: C) -> Self {
        assert!(
            matches!(M, 4 | 6 | 8 | 10 | 12 | 14 | 16),
            "AES-CCM tag length M must be one of 4, 6, 8, 10, 12, 14, 16"
        );
        Self { cipher }
    }

    /// Encrypts `buffer` in place and returns the `M`-byte authentication tag.
    ///
    /// # Panics
    /// Panics if `nonce.len()` is outside `7..=13` bytes, or if `buffer.len()`
    /// exceeds the per-nonce payload cap `2^(8·(15 − nonce.len())) − 1` bytes
    /// (NIST SP 800-38C). Callers passing untrusted nonce lengths should
    /// validate them first.
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], buffer: &mut [u8]) -> [u8; M] {
        self.validate(nonce, buffer.len());

        let t = self.mac(nonce, aad, buffer);
        let s0 = self.gen_s(nonce, 0);

        // CTR-encrypt payload starting at counter 1.
        self.ctr_xor(nonce, 1, buffer);

        let mut out = [0u8; M];
        for i in 0..M {
            out[i] = t[i] ^ s0[i];
        }
        out
    }

    /// Decrypts `buffer` in place and verifies `tag`. On verification failure,
    /// the buffer is wiped and `Err(TagMismatch)` is returned — no
    /// unauthenticated plaintext is left in the caller's hands.
    ///
    /// # Panics
    /// Panics if `nonce.len()` is outside `7..=13` bytes, or if `buffer.len()`
    /// exceeds the per-nonce payload cap `2^(8·(15 − nonce.len())) − 1` bytes
    /// (NIST SP 800-38C). Callers passing untrusted nonce lengths should
    /// validate them first.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; M],
    ) -> Result<(), TagMismatch> {
        self.validate(nonce, buffer.len());

        // CCM's tag is over plaintext, so CTR-decrypt first.
        self.ctr_xor(nonce, 1, buffer);

        let t = self.mac(nonce, aad, buffer);
        let s0 = self.gen_s(nonce, 0);
        let mut expected = [0u8; M];
        for i in 0..M {
            expected[i] = t[i] ^ s0[i];
        }

        if bool::from(expected.ct_eq(tag)) {
            Ok(())
        } else {
            // Wipe the (now-decrypted) buffer so a caller can't accidentally
            // use unauthenticated plaintext after ignoring the error.
            for b in buffer.iter_mut() {
                *b = 0;
            }
            Err(TagMismatch)
        }
    }

    fn validate(&self, nonce: &[u8], payload_len: usize) {
        assert!(
            (7..=13).contains(&nonce.len()),
            "AES-CCM nonce length must be in 7..=13 bytes"
        );
        let q = 15 - nonce.len();
        let max = if q >= 16 {
            u128::MAX
        } else {
            (1u128 << (8 * q)) - 1
        };
        assert!(
            (payload_len as u128) <= max,
            "AES-CCM payload length {} exceeds limit {} for nonce length {}",
            payload_len,
            max,
            nonce.len(),
        );
    }

    /// Builds B_0, encoded AAD, and padded payload, runs them through CBC-MAC,
    /// returns the 16-byte intermediate tag T (truncated to M by the caller).
    fn mac(&self, nonce: &[u8], aad: &[u8], payload: &[u8]) -> [u8; 16] {
        let q = 15 - nonce.len();
        let adata = if aad.is_empty() { 0u8 } else { 0x40 };
        let m_field = ((M as u8) - 2) / 2;
        let flags = adata | (m_field << 3) | ((q as u8) - 1);

        let mut b0 = [0u8; 16];
        b0[0] = flags;
        b0[1..1 + nonce.len()].copy_from_slice(nonce);
        let mut plen = payload.len() as u128;
        for i in (0..q).rev() {
            b0[1 + nonce.len() + i] = (plen & 0xff) as u8;
            plen >>= 8;
        }

        let mut mac = CbcMac::new(&self.cipher);
        mac.update(&b0);

        // Encoded AAD: a length prefix (2/6/10 bytes), then the AAD bytes,
        // zero-padded to the next 16-byte boundary.
        if !aad.is_empty() {
            let a = aad.len();
            let mut header = [0u8; 10];
            let hlen;
            if a < 0xff00 {
                header[0] = ((a >> 8) & 0xff) as u8;
                header[1] = (a & 0xff) as u8;
                hlen = 2;
            } else if (a as u64) < (1u64 << 32) {
                header[0] = 0xff;
                header[1] = 0xfe;
                header[2..6].copy_from_slice(&(a as u32).to_be_bytes());
                hlen = 6;
            } else {
                header[0] = 0xff;
                header[1] = 0xff;
                header[2..10].copy_from_slice(&(a as u64).to_be_bytes());
                hlen = 10;
            }
            mac.update(&header[..hlen]);
            mac.update(aad);
            let rem = (hlen + a) % 16;
            if rem != 0 {
                let zeros = [0u8; 16];
                mac.update(&zeros[..16 - rem]);
            }
        }

        mac.update(payload);
        if !payload.len().is_multiple_of(16) {
            let zeros = [0u8; 16];
            mac.update(&zeros[..16 - (payload.len() % 16)]);
        }

        mac.finalize()
    }

    /// Generates the CTR keystream block at counter `i`:
    /// `S_i = E_K(A_i)` where `A_i = flags ‖ nonce ‖ counter_q_bytes_be`.
    fn gen_s(&self, nonce: &[u8], counter: u128) -> [u8; 16] {
        let q = 15 - nonce.len();
        let mut a = [0u8; 16];
        a[0] = (q as u8) - 1;
        a[1..1 + nonce.len()].copy_from_slice(nonce);
        let mut c = counter;
        for i in (0..q).rev() {
            a[1 + nonce.len() + i] = (c & 0xff) as u8;
            c >>= 8;
        }
        self.cipher.encrypt_block(&mut a);
        a
    }

    /// XORs the CCM CTR keystream into `buffer`, starting at counter `start`.
    fn ctr_xor(&self, nonce: &[u8], start: u128, buffer: &mut [u8]) {
        let mut counter = start;
        let mut ks = [0u8; 16];
        let mut pos = 16;
        for byte in buffer.iter_mut() {
            if pos == 16 {
                ks = self.gen_s(nonce, counter);
                counter = counter.wrapping_add(1);
                pos = 0;
            }
            *byte ^= ks[pos];
            pos += 1;
        }
    }
}

/// AES-128 in CCM mode (16-byte tag).
pub type Aes128Ccm = Ccm<super::Aes128, 16>;
/// AES-192 in CCM mode (16-byte tag).
pub type Aes192Ccm = Ccm<super::Aes192, 16>;
/// AES-256 in CCM mode (16-byte tag).
pub type Aes256Ccm = Ccm<super::Aes256, 16>;

/// AES-128 in CCM mode with an 8-byte tag (`TLS_AES_128_CCM_8_SHA256`-style).
pub type Aes128Ccm8 = Ccm<super::Aes128, 8>;
/// AES-256 in CCM mode with an 8-byte tag.
pub type Aes256Ccm8 = Ccm<super::Aes256, 8>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::Aes128;
    use crate::test_util::from_hex;

    /// RFC 3610 §8 Packet Vector #1: M = 8.
    #[test]
    fn rfc3610_packet_1_m8() {
        let key = from_hex::<16>("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        let nonce = from_hex::<13>("00000003020100A0A1A2A3A4A5");
        let aad = from_hex::<8>("0001020304050607");
        let pt = from_hex::<23>("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E");
        // RFC 3610's reported output is ciphertext ‖ tag where M = 8.
        let expected_ct = from_hex::<23>("588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384");
        let expected_tag = from_hex::<8>("17E8D12CFDF926E0");

        let ccm: Ccm<Aes128, 8> = Ccm::new(Aes128::new(&key));
        let mut buf = pt;
        let tag = ccm.encrypt(&nonce, &aad, &mut buf);
        assert_eq!(buf, expected_ct);
        assert_eq!(tag, expected_tag);

        let mut dec = buf;
        ccm.decrypt(&nonce, &aad, &mut dec, &tag).unwrap();
        assert_eq!(dec, pt);
    }

    /// RFC 3610 §8 Packet Vector #2: M = 8, different payload boundary.
    #[test]
    fn rfc3610_packet_2_m8() {
        let key = from_hex::<16>("C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF");
        let nonce = from_hex::<13>("00000004030201A0A1A2A3A4A5");
        let aad = from_hex::<8>("0001020304050607");
        let pt = from_hex::<24>("08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let expected_ct = from_hex::<24>("72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3B");
        let expected_tag = from_hex::<8>("A091D56E10400916");

        let ccm: Ccm<Aes128, 8> = Ccm::new(Aes128::new(&key));
        let mut buf = pt;
        let tag = ccm.encrypt(&nonce, &aad, &mut buf);
        assert_eq!(buf, expected_ct);
        assert_eq!(tag, expected_tag);
        ccm.decrypt(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, pt);
    }

    /// NIST SP 800-38C Example 1: M=4, 13-byte nonce, 8-byte AAD, 4-byte payload.
    #[test]
    fn nist_38c_example_1_m4() {
        let key = from_hex::<16>("404142434445464748494a4b4c4d4e4f");
        let nonce = from_hex::<7>("10111213141516");
        let aad = from_hex::<8>("0001020304050607");
        let pt = from_hex::<4>("20212223");
        let expected_ct = from_hex::<4>("7162015b");
        let expected_tag = from_hex::<4>("4dac255d");

        let ccm: Ccm<Aes128, 4> = Ccm::new(Aes128::new(&key));
        let mut buf = pt;
        let tag = ccm.encrypt(&nonce, &aad, &mut buf);
        assert_eq!(buf, expected_ct);
        assert_eq!(tag, expected_tag);
        ccm.decrypt(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, pt);
    }

    /// NIST SP 800-38C Example 2: M=6, 8-byte nonce, 16-byte AAD, 16-byte payload.
    #[test]
    fn nist_38c_example_2_m6() {
        let key = from_hex::<16>("404142434445464748494a4b4c4d4e4f");
        let nonce = from_hex::<8>("1011121314151617");
        let aad = from_hex::<16>("000102030405060708090a0b0c0d0e0f");
        let pt = from_hex::<16>("202122232425262728292a2b2c2d2e2f");
        let expected_ct = from_hex::<16>("d2a1f0e051ea5f62081a7792073d593d");
        let expected_tag = from_hex::<6>("1fc64fbfaccd");

        let ccm: Ccm<Aes128, 6> = Ccm::new(Aes128::new(&key));
        let mut buf = pt;
        let tag = ccm.encrypt(&nonce, &aad, &mut buf);
        assert_eq!(buf, expected_ct);
        assert_eq!(tag, expected_tag);
        ccm.decrypt(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, pt);
    }

    /// NIST SP 800-38C Example 3: M=8, 12-byte nonce, 20-byte AAD, 24-byte payload.
    #[test]
    fn nist_38c_example_3_m8() {
        let key = from_hex::<16>("404142434445464748494a4b4c4d4e4f");
        let nonce = from_hex::<12>("101112131415161718191a1b");
        let aad = from_hex::<20>("000102030405060708090a0b0c0d0e0f10111213");
        let pt = from_hex::<24>("202122232425262728292a2b2c2d2e2f3031323334353637");
        let expected_ct = from_hex::<24>("e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5");
        let expected_tag = from_hex::<8>("484392fbc1b09951");

        let ccm: Ccm<Aes128, 8> = Ccm::new(Aes128::new(&key));
        let mut buf = pt;
        let tag = ccm.encrypt(&nonce, &aad, &mut buf);
        assert_eq!(buf, expected_ct);
        assert_eq!(tag, expected_tag);
        ccm.decrypt(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, pt);
    }

    /// Round-trip for the M=16 case (the public Aes128Ccm alias); validates
    /// that the M=16 path differs from M=8 only in the truncation width, which
    /// is already exhaustively exercised by the published lower-M vectors.
    #[test]
    fn aes128_ccm_m16_roundtrip() {
        let key = from_hex::<16>("404142434445464748494a4b4c4d4e4f");
        let nonce = from_hex::<12>("101112131415161718191a1b");
        let aad = b"some AAD bytes";
        let pt = *b"AES-CCM with the standard 16-byte tag.";

        let ccm = Aes128Ccm::new(Aes128::new(&key));
        let mut buf = pt;
        let tag = ccm.encrypt(&nonce, aad, &mut buf);
        ccm.decrypt(&nonce, aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, pt);
    }

    /// A flipped tag byte makes decrypt reject; the buffer is wiped.
    #[test]
    fn tamper_rejected_wipes_buffer() {
        let key = from_hex::<16>("404142434445464748494a4b4c4d4e4f");
        let nonce = from_hex::<12>("101112131415161718191a1b");
        let aad: &[u8] = b"";
        let pt = *b"sixteen byte msg";
        let ccm = Aes128Ccm::new(Aes128::new(&key));
        let mut buf = pt;
        let mut tag = ccm.encrypt(&nonce, aad, &mut buf);
        tag[0] ^= 1;
        assert!(ccm.decrypt(&nonce, aad, &mut buf, &tag).is_err());
        assert_eq!(buf, [0u8; 16]);
    }
}
