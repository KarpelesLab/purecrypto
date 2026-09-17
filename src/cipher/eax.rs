//! EAX mode — a two-pass AEAD built from CMAC and CTR
//! (Bellare, Rogaway, Wagner, FSE 2004; ANSI C12.22, ISO/IEC 19772).
//!
//! EAX authenticates with three tweaked CMACs (`OMAC^t(M) = CMAC(K, [t]₁₂₈ ‖ M)`,
//! for `t = 0, 1, 2` over the nonce, the associated data and the ciphertext)
//! and encrypts with CTR mode whose initial counter block is the nonce's
//! OMAC:
//!
//! ```text
//! N = OMAC⁰(nonce)   H = OMAC¹(aad)   C = CTR_N(M)   T = N ⊕ H ⊕ OMAC²(C)
//! ```
//!
//! The nonce may be **any** length, including empty — a distinguishing
//! feature versus GCM — and the CTR counter wraps modulo 2¹²⁸ (the
//! Wycheproof `CounterWrap` vectors exercise this). The tag is the full
//! 128 bits; this implementation does not expose truncated tags.
//!
//! The construction is generic over any 128-bit [`BlockCipher`]; the
//! [`Aes128Eax`] / [`Aes192Eax`] / [`Aes256Eax`] aliases pin it to AES. On
//! the crate's constant-time ciphers the whole mode is constant time; the
//! tag check uses [`ct_eq`](ConstantTimeEq::ct_eq) and a mismatch leaves the
//! buffer untouched.
//!
//! As with every nonce-based AEAD, a `(key, nonce)` pair must never be
//! reused.

use super::{BlockCipher, Cmac, Ctr, TagMismatch};
use crate::ct::ConstantTimeEq;

/// EAX authenticated encryption over a 128-bit block cipher.
///
/// Construct with [`Eax::new`] from a pre-keyed cipher; the CMAC subkeys are
/// derived once and reused across messages.
#[derive(Clone)]
pub struct Eax<C: BlockCipher + Clone> {
    cipher: C,
    /// Freshly keyed CMAC (subkeys derived), cloned for each OMAC.
    cmac: Cmac<C>,
}

impl<C: BlockCipher + Clone> Eax<C> {
    /// Tag size in bytes: EAX here always uses the full 128-bit tag.
    pub const TAG_SIZE: usize = 16;

    /// Creates an EAX context from a pre-keyed block cipher.
    pub fn new(cipher: C) -> Self {
        let cmac = Cmac::new(cipher.clone());
        Eax { cipher, cmac }
    }

    /// `OMAC^t(data) = CMAC([t]₁₂₈ ‖ data)`, the tweak being the 16-byte
    /// big-endian encoding of `t`.
    fn omac(&self, t: u8, data: &[u8]) -> [u8; 16] {
        let mut mac = self.cmac.clone();
        let mut tweak = [0u8; 16];
        tweak[15] = t;
        mac.update(&tweak);
        mac.update(data);
        mac.finalize()
    }

    /// `N ⊕ H ⊕ OMAC²(ciphertext)` for the given nonce block and header MAC.
    fn tag(&self, n: &[u8; 16], h: &[u8; 16], ciphertext: &[u8]) -> [u8; 16] {
        let c = self.omac(2, ciphertext);
        let mut tag = [0u8; 16];
        for i in 0..16 {
            tag[i] = n[i] ^ h[i] ^ c[i];
        }
        tag
    }

    /// Encrypts `buffer` in place, binding `aad`, and returns the 16-byte tag.
    ///
    /// `nonce` may be of any length (including empty) but must be unique per
    /// key.
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        let n = self.omac(0, nonce);
        let h = self.omac(1, aad);
        Ctr::new(self.cipher.clone(), &n).apply_keystream(buffer);
        self.tag(&n, &h, buffer)
    }

    /// Verifies `tag` and, only if it matches, decrypts `buffer` in place.
    ///
    /// EAX is encrypt-then-MAC, so the tag is recomputed over the ciphertext
    /// first and compared in constant time; on mismatch [`TagMismatch`] is
    /// returned and `buffer` still holds the ciphertext, untouched.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        let n = self.omac(0, nonce);
        let h = self.omac(1, aad);
        let expected = self.tag(&n, &h, buffer);
        if !bool::from(expected.ct_eq(tag)) {
            return Err(TagMismatch);
        }
        Ctr::new(self.cipher.clone(), &n).apply_keystream(buffer);
        Ok(())
    }
}

/// AES-128 in EAX mode.
pub type Aes128Eax = Eax<super::Aes128>;
/// AES-192 in EAX mode.
pub type Aes192Eax = Eax<super::Aes192>;
/// AES-256 in EAX mode.
pub type Aes256Eax = Eax<super::Aes256>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::Aes128;
    use crate::test_util::from_hex;

    /// Test vectors from the EAX paper (eprint.iacr.org/2003/069, Appendix).
    struct Kat {
        key: &'static str,
        nonce: &'static str,
        header: &'static str,
        msg: &'static str,
        ct: &'static str,
        tag: &'static str,
    }

    const KATS: [Kat; 4] = [
        Kat {
            key: "233952dee4d5ed5f9b9c6d6ff80ff478",
            nonce: "62ec67f9c3a4a407fcb2a8c49031a8b3",
            header: "6bfb914fd07eae6b",
            msg: "",
            ct: "",
            tag: "e037830e8389f27b025a2d6527e79d01",
        },
        Kat {
            key: "91945d3f4dcbee0bf45ef52255f095a4",
            nonce: "becaf043b0a23d843194ba972c66debd",
            header: "fa3bfd4806eb53fa",
            msg: "f7fb",
            ct: "19dd",
            tag: "5c4c9331049d0bdab0277408f67967e5",
        },
        Kat {
            key: "01f74ad64077f2e704c0f60ada3dd523",
            nonce: "70c3db4f0d26368400a10ed05d2bff5e",
            header: "234a3463c1264ac6",
            msg: "1a47cb4933",
            ct: "d851d5bae0",
            tag: "3a59f238a23e39199dc9266626c40f80",
        },
        Kat {
            key: "8395fcf1e95bebd697bd010bc766aac3",
            nonce: "22e7add93cfc6393c57ec0b3c17d6b44",
            header: "126735fcc320d25a",
            msg: "ca40d7446e545ffaed3bd12a740a659ffbbb3ceab7",
            ct: "cb8920f87a6c75cff39627b56e3ed197c552d295a7",
            tag: "cfc46afc253b4652b1af3795b124ab6e",
        },
    ];

    /// Hex into a fixed scratch buffer (the paper's messages are at most 21
    /// bytes), so the KAT runs without an allocator.
    fn hex_into<'a>(buf: &'a mut [u8; 32], s: &str) -> &'a [u8] {
        let n = s.len() / 2;
        for (i, slot) in buf[..n].iter_mut().enumerate() {
            *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        &buf[..n]
    }

    #[test]
    fn eax_paper_vectors() {
        for kat in &KATS {
            let eax = Aes128Eax::new(Aes128::new(&from_hex::<16>(kat.key)));
            let nonce = from_hex::<16>(kat.nonce);
            let header = from_hex::<8>(kat.header);
            let (mut msg_buf, mut ct_buf) = ([0u8; 32], [0u8; 32]);
            let msg = hex_into(&mut msg_buf, kat.msg);
            let ct = hex_into(&mut ct_buf, kat.ct);
            let tag = from_hex::<16>(kat.tag);

            let mut buf = [0u8; 32];
            let buf = &mut buf[..msg.len()];
            buf.copy_from_slice(msg);
            let t = eax.encrypt(&nonce, &header, buf);
            assert_eq!(buf, ct, "ciphertext for {}", kat.key);
            assert_eq!(t, tag, "tag for {}", kat.key);

            eax.decrypt(&nonce, &header, buf, &tag).unwrap();
            assert_eq!(buf, msg);

            let mut bad = tag;
            bad[3] ^= 0x80;
            buf.copy_from_slice(ct);
            assert_eq!(eax.decrypt(&nonce, &header, buf, &bad), Err(TagMismatch));
            assert_eq!(buf, ct, "buffer must be untouched on failure");
        }
    }

    #[test]
    fn empty_nonce_is_accepted() {
        let eax = Aes128Eax::new(Aes128::new(&[7u8; 16]));
        let mut buf = *b"hello, eax";
        let tag = eax.encrypt(&[], b"", &mut buf);
        assert_ne!(&buf, b"hello, eax");
        eax.decrypt(&[], b"", &mut buf, &tag).unwrap();
        assert_eq!(&buf, b"hello, eax");
    }
}
