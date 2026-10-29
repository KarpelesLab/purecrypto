//! RC2 (RFC 2268): 64-bit block, 1- to 128-byte key, with a separate
//! "effective key bits" parameter.
//!
//! [`Rc2`] implements [`BlockCipher64`], so it composes with
//! [`Cbc64`](super::Cbc64), [`Cfb64`](super::Cfb64) and
//! [`Ofb64`](super::Ofb64) for OpenSSL's `rc2-ecb` / `rc2-cbc` /
//! `rc2-cfb` / `rc2-ofb`, and with [`Cbc64`](super::Cbc64) for the legacy
//! PKCS#5 / PKCS#12 / S/MIME RC2-CBC encryptions.
//!
//! # Effective key bits
//!
//! RC2's key expansion takes the key bytes (`T` = 1 to 128 of them) and,
//! separately, an *effective key length* in bits (`T1` = 1 to 1024) that
//! caps the search space. The two are independent, and interop needs both
//! right:
//!
//! | OpenSSL name | key | effective bits |
//! | --- | --- | --- |
//! | `rc2-cbc` (and `-ecb`, `-cfb`, `-ofb`) | 16 bytes | 128 |
//! | `rc2-64-cbc` | 8 bytes | 64 |
//! | `rc2-40-cbc` | 5 bytes | 40 |
//!
//! [`Rc2::new`] uses `T1 = 8·T` (capped at 1024), which matches those three
//! for their default key lengths; use [`Rc2::with_effective_bits`] whenever
//! the two differ (for example a PKCS#7 `RC2-CBCParameter` version, or
//! `EVP_CTRL_SET_RC2_KEY_BITS`).
//!
//! # Constant time
//!
//! **Not constant time.** The key expansion indexes the 256-byte `PITABLE`
//! with key bytes, and every "mash" round (two per block) indexes the
//! expanded key with the low six bits of a secret data word, so both leak
//! through the data cache. This is inherent to RC2's design.
//!
//! # When to use this module
//!
//! Only to read or write existing RC2 data. It has related-key attacks,
//! a 64-bit block subject to Sweet32-style birthday attacks, and the 40-
//! and 64-bit variants are brute-forceable. Use
//! [`Aes256Gcm`](super::Aes256Gcm) or
//! [`ChaCha20Poly1305`](super::ChaCha20Poly1305) for new designs.
//!
//! References:
//! - R. Rivest, "A Description of the RC2(r) Encryption Algorithm",
//!   RFC 2268, March 1998. `PITABLE` is transcribed mechanically from §2.

use super::{BlockCipher64, InvalidKeyLength};
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// The RC2 block cipher.
///
/// **Not constant time**, unauthenticated, 64-bit block: legacy interop
/// only; see the module-level docs. The expanded key is wiped on drop.
#[derive(Clone)]
pub struct Rc2 {
    /// Expanded key words `K[0..64]`.
    k: [u16; 64],
}

impl Rc2 {
    /// Shortest accepted key, in bytes.
    pub const MIN_KEY_SIZE: usize = 1;
    /// Longest accepted key, in bytes.
    pub const MAX_KEY_SIZE: usize = 128;
    /// Largest effective key length, in bits.
    pub const MAX_EFFECTIVE_BITS: usize = 1024;

    /// Expands `key` (1 to 128 bytes) with effective key bits equal to its
    /// length in bits (`8 · key.len()`, at most 1024).
    ///
    /// # Panics
    /// If `key.len()` is outside `1..=128`; use [`try_new`](Self::try_new)
    /// for keys of untrusted length.
    pub fn new(key: &[u8]) -> Self {
        Self::try_new(key).expect("RC2 key must be 1 to 128 bytes")
    }

    /// Fallible [`new`](Self::new): returns [`InvalidKeyLength`] if `key`
    /// is not 1 to 128 bytes long.
    pub fn try_new(key: &[u8]) -> Result<Self, InvalidKeyLength> {
        Self::try_with_effective_bits(key, (8 * key.len()).min(Self::MAX_EFFECTIVE_BITS))
    }

    /// Expands `key` (1 to 128 bytes) with `effective_bits` (1 to 1024)
    /// effective key bits — RFC 2268's `T1`.
    ///
    /// # Panics
    /// If either parameter is out of range; use
    /// [`try_with_effective_bits`](Self::try_with_effective_bits) for
    /// untrusted input.
    pub fn with_effective_bits(key: &[u8], effective_bits: usize) -> Self {
        Self::try_with_effective_bits(key, effective_bits)
            .expect("RC2 key must be 1 to 128 bytes and effective bits 1 to 1024")
    }

    /// Fallible [`with_effective_bits`](Self::with_effective_bits): returns
    /// [`InvalidKeyLength`] if `key` is not 1 to 128 bytes long or
    /// `effective_bits` is not 1 to 1024.
    pub fn try_with_effective_bits(
        key: &[u8],
        effective_bits: usize,
    ) -> Result<Self, InvalidKeyLength> {
        let t = key.len();
        if !(Self::MIN_KEY_SIZE..=Self::MAX_KEY_SIZE).contains(&t)
            || !(1..=Self::MAX_EFFECTIVE_BITS).contains(&effective_bits)
        {
            return Err(InvalidKeyLength);
        }
        // RFC 2268 §2.
        let mut l = [0u8; 128];
        l[..t].copy_from_slice(key);
        let t8 = effective_bits.div_ceil(8);
        let tm = (0xffu32 >> (8 * t8 - effective_bits)) as u8;
        for i in t..128 {
            l[i] = PITABLE[usize::from(l[i - 1].wrapping_add(l[i - t]))];
        }
        l[128 - t8] = PITABLE[usize::from(l[128 - t8] & tm)];
        for i in (0..128 - t8).rev() {
            l[i] = PITABLE[usize::from(l[i + 1] ^ l[i + t8])];
        }
        let mut k = [0u16; 64];
        for (w, b) in k.iter_mut().zip(l.chunks_exact(2)) {
            *w = u16::from_le_bytes([b[0], b[1]]);
        }
        l.zeroize();
        Ok(Self { k })
    }
}

/// Left-rotation amounts `s[0..4]` of the mix step.
const S: [u32; 4] = [1, 2, 3, 5];

impl BlockCipher64 for Rc2 {
    /// OpenSSL's default `rc2-*` key length (with 128 effective bits).
    const KEY_SIZE: usize = 16;

    fn encrypt_block(&self, block: &mut [u8; 8]) {
        let k = &self.k;
        let mut r: [u16; 4] =
            core::array::from_fn(|i| u16::from_le_bytes([block[2 * i], block[2 * i + 1]]));
        let mut j = 0;
        let mut mix_round = |r: &mut [u16; 4]| {
            for i in 0..4 {
                let (r1, r2, r3) = (r[(i + 3) % 4], r[(i + 2) % 4], r[(i + 1) % 4]);
                r[i] = r[i]
                    .wrapping_add(k[j])
                    .wrapping_add(r1 & r2)
                    .wrapping_add(!r1 & r3)
                    .rotate_left(S[i]);
                j += 1;
            }
        };
        let mash_round = |r: &mut [u16; 4]| {
            for i in 0..4 {
                r[i] = r[i].wrapping_add(k[usize::from(r[(i + 3) % 4] & 63)]);
            }
        };
        for _ in 0..5 {
            mix_round(&mut r);
        }
        mash_round(&mut r);
        for _ in 0..6 {
            mix_round(&mut r);
        }
        mash_round(&mut r);
        for _ in 0..5 {
            mix_round(&mut r);
        }
        for (i, w) in r.iter().enumerate() {
            block[2 * i..2 * i + 2].copy_from_slice(&w.to_le_bytes());
        }
        r.zeroize();
    }

    fn decrypt_block(&self, block: &mut [u8; 8]) {
        let k = &self.k;
        let mut r: [u16; 4] =
            core::array::from_fn(|i| u16::from_le_bytes([block[2 * i], block[2 * i + 1]]));
        let mut j = 64;
        let mut rmix_round = |r: &mut [u16; 4]| {
            for i in (0..4).rev() {
                j -= 1;
                let (r1, r2, r3) = (r[(i + 3) % 4], r[(i + 2) % 4], r[(i + 1) % 4]);
                r[i] = r[i]
                    .rotate_right(S[i])
                    .wrapping_sub(k[j])
                    .wrapping_sub(r1 & r2)
                    .wrapping_sub(!r1 & r3);
            }
        };
        let rmash_round = |r: &mut [u16; 4]| {
            for i in (0..4).rev() {
                r[i] = r[i].wrapping_sub(k[usize::from(r[(i + 3) % 4] & 63)]);
            }
        };
        for _ in 0..5 {
            rmix_round(&mut r);
        }
        rmash_round(&mut r);
        for _ in 0..6 {
            rmix_round(&mut r);
        }
        rmash_round(&mut r);
        for _ in 0..5 {
            rmix_round(&mut r);
        }
        for (i, w) in r.iter().enumerate() {
            block[2 * i..2 * i + 2].copy_from_slice(&w.to_le_bytes());
        }
        r.zeroize();
    }
}

impl Drop for Rc2 {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

impl ZeroizeOnDrop for Rc2 {}

static PITABLE: [u8; 256] = [
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{Cbc64, Cfb64, Ofb64};
    use crate::test_util::{from_hex, from_hex_vec};

    fn block_kat(c: &Rc2, pt: &str, ct: &str) {
        let pt: [u8; 8] = from_hex(pt);
        let ct: [u8; 8] = from_hex(ct);
        let mut b = pt;
        c.encrypt_block(&mut b);
        assert_eq!(b, ct);
        c.decrypt_block(&mut b);
        assert_eq!(b, pt);
    }

    /// All eight RFC 2268 §5 vectors.
    #[test]
    fn rfc2268_section5() {
        for (key, bits, pt, ct) in [
            (
                "0000000000000000",
                63,
                "0000000000000000",
                "ebb773f993278eff",
            ),
            (
                "ffffffffffffffff",
                64,
                "ffffffffffffffff",
                "278b27e42e2f0d49",
            ),
            (
                "3000000000000000",
                64,
                "1000000000000001",
                "30649edf9be7d2c2",
            ),
            ("88", 64, "0000000000000000", "61a8a244adacccf0"),
            ("88bca90e90875a", 64, "0000000000000000", "6ccf4308974c267f"),
            (
                "88bca90e90875a7f0f79c384627bafb2",
                64,
                "0000000000000000",
                "1a807d272bbe5db1",
            ),
            (
                "88bca90e90875a7f0f79c384627bafb2",
                128,
                "0000000000000000",
                "2269552ab0f85ca6",
            ),
            (
                "88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e",
                129,
                "0000000000000000",
                "5b78d3a43dfff1f1",
            ),
        ] {
            block_kat(&Rc2::with_effective_bits(&from_hex_vec(key), bits), pt, ct);
        }
        // `new` uses 8 · len effective bits: the 16-byte / 128-bit vector.
        block_kat(
            &Rc2::new(&from_hex_vec("88bca90e90875a7f0f79c384627bafb2")),
            "0000000000000000",
            "2269552ab0f85ca6",
        );
    }

    /// Cross-checked against OpenSSL 3.5 `RC2_set_key` / `RC2_ecb_encrypt`
    /// (key byte `i` = `37 i + 45 (mod 256)`).
    #[test]
    fn openssl_vectors() {
        let key: [u8; 128] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(45));
        for (len, bits, ct) in [
            (5, 40, "14a1fd21d832ddaf"),
            (8, 64, "3887bd9f756f18c4"),
            (16, 40, "15085439fc527426"),
            (16, 64, "1bea1ff6ad5dab2b"),
            (16, 128, "f5d746386777383d"),
            (128, 1024, "74b499784c9c0c4e"),
            (3, 1000, "98b5719e01ccc6c0"),
        ] {
            block_kat(
                &Rc2::with_effective_bits(&key[..len], bits),
                "0011223344556677",
                ct,
            );
        }
    }

    #[test]
    fn parameter_bounds() {
        assert_eq!(Rc2::try_new(&[]).err(), Some(InvalidKeyLength));
        assert_eq!(Rc2::try_new(&[0; 129]).err(), Some(InvalidKeyLength));
        assert_eq!(
            Rc2::try_with_effective_bits(&[0; 8], 0).err(),
            Some(InvalidKeyLength)
        );
        assert_eq!(
            Rc2::try_with_effective_bits(&[0; 8], 1025).err(),
            Some(InvalidKeyLength)
        );
        assert!(Rc2::try_with_effective_bits(&[0; 1], 1).is_ok());
        assert!(Rc2::try_with_effective_bits(&[0; 128], 1024).is_ok());
        // 128 bytes would be 1024 bits; `new` stays in range.
        assert!(Rc2::try_new(&[0; 128]).is_ok());
    }

    /// `openssl enc -rc2-{ecb,cbc,cfb,ofb}`, `-rc2-40-cbc` and `-rc2-64-cbc`
    /// (OpenSSL 3.5) over Eric Young's "7654321 Now is the time for "
    /// message.
    #[test]
    fn modes_match_openssl() {
        let key = from_hex_vec("0123456789abcdeff0e1d2c3b4a59687");
        let iv: [u8; 8] = from_hex("fedcba9876543210");
        let data: &[u8; 32] = b"7654321 Now is the time for \0\0\0\0";

        let mut buf = *data;
        let c = Rc2::with_effective_bits(&key, 128);
        for blk in buf.chunks_exact_mut(8) {
            c.encrypt_block(blk.try_into().unwrap());
        }
        assert_eq!(
            buf,
            from_hex::<32>("b1bab26dff1f5224d66a20c102a46434b65efd7fb1df69cd72972a2a10bd6196")
        );

        for (key, bits, ct) in [
            (
                &key[..],
                128,
                "791d4237313d820c251ddb05b68acb79641b352bb8676d1107d071827b5faec3",
            ),
            (
                &key[..5],
                40,
                "56a056e4070b9c37b606544653299731d3c7f8448d39dc3f0f4316b6666bafbb",
            ),
            (
                &key[..8],
                64,
                "a245583b837db6d5f9a6a89c8144b9f52a7fd8c84ba7c4969bb331618d14dfe3",
            ),
        ] {
            let mut buf = *data;
            Cbc64::new(Rc2::with_effective_bits(key, bits), &iv)
                .encrypt(&mut buf)
                .unwrap();
            assert_eq!(buf, from_hex::<32>(ct), "{bits} bits");
            Cbc64::new(Rc2::with_effective_bits(key, bits), &iv)
                .decrypt(&mut buf)
                .unwrap();
            assert_eq!(&buf, data);
        }

        let mut buf: [u8; 29] = data[..29].try_into().unwrap();
        Cfb64::new(Rc2::new(&key), &iv).encrypt(&mut buf);
        assert_eq!(
            buf,
            from_hex::<29>("0e62d29a40a7319edc4b15093e85087791059a259463d5c2a2903f20db")
        );
        Cfb64::new(Rc2::new(&key), &iv).decrypt(&mut buf);
        assert_eq!(buf[..], data[..29]);

        let mut buf: [u8; 29] = data[..29].try_into().unwrap();
        Ofb64::new(Rc2::new(&key), &iv).apply_keystream(&mut buf);
        assert_eq!(
            buf,
            from_hex::<29>("0e62d29a40a7319ea72b553118c65c694bb53e0e6917d53cae6171d7f1")
        );
    }
}
