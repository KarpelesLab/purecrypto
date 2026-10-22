//! The TEA family: TEA, XTEA and XXTEA (Wheeler & Needham, 1994–1998).
//!
//! - [`Tea`]: the original Tiny Encryption Algorithm: 64-bit block, 128-bit
//!   key, 32 cycles (64 Feistel rounds).
//! - [`Xtea`]: "extended TEA" (1997), which fixes TEA's key schedule:
//!   same block, key and round count.
//! - [`Xxtea`]: "corrected Block TEA" (1998), a variable-width block cipher
//!   over any message of two or more 32-bit words, with `6 + 52/n` cycles.
//!
//! [`Tea`] and [`Xtea`] implement [`BlockCipher64`], so they compose with
//! [`Cbc64`](super::Cbc64) like DES. [`Xxtea`] encrypts a whole message as a
//! single block and has its own slice API.
//!
//! # Byte order
//!
//! The ciphers are defined on 32-bit words. The byte APIs here read and
//! write those words (key and data alike) **big-endian**, as Crypto++,
//! Botan, Bouncy Castle and Go's `x/crypto/xtea` do. Some deployments use
//! little-endian instead, notably the Linux kernel's `tea`/`xtea` and the
//! common `xxtea` libraries. For those, build the key with `from_words` and
//! convert the data yourself before calling the `*_words` methods.
//!
//! # Constant time
//!
//! All three ciphers use only 32-bit addition, shifts and XOR. The key-word
//! indices in XTEA and XXTEA depend only on the public round sum and
//! position, so there is no secret-dependent branch or memory access.
//!
//! # When to use this module
//!
//! Only to interoperate with existing formats. TEA has equivalent keys
//! (each key has three others that behave identically, so the effective key
//! size is 126 bits) and falls to related-key attacks; this broke the
//! original Xbox's use of it as a hash. XTEA and XXTEA have published
//! related-key and (for XXTEA) chosen-plaintext attacks. All three are
//! unauthenticated, and TEA/XTEA's 64-bit block is subject to Sweet32. Use
//! [`Aes256Gcm`](super::Aes256Gcm) or
//! [`ChaCha20Poly1305`](super::ChaCha20Poly1305) for new designs.
//!
//! References:
//! - D. Wheeler, R. Needham, "TEA, a Tiny Encryption Algorithm", FSE 1994.
//! - D. Wheeler, R. Needham, "Tea extensions", 1997.
//! - D. Wheeler, R. Needham, "Correction to xtea", 1998.

use super::{BlockCipher64, InvalidLength};
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// The key-schedule constant `⌊2³² / φ⌋`.
const DELTA: u32 = 0x9e37_79b9;

/// Cycles (pairs of Feistel rounds) for TEA and XTEA.
const CYCLES: u32 = 32;

#[inline]
fn load_key(key: &[u8; 16]) -> [u32; 4] {
    core::array::from_fn(|i| u32::from_be_bytes(key[4 * i..4 * i + 4].try_into().expect("4 bytes")))
}

#[inline]
fn load_block(block: &[u8; 8]) -> [u32; 2] {
    [
        u32::from_be_bytes(block[..4].try_into().expect("4 bytes")),
        u32::from_be_bytes(block[4..].try_into().expect("4 bytes")),
    ]
}

#[inline]
fn store_block(v: &[u32; 2], block: &mut [u8; 8]) {
    block[..4].copy_from_slice(&v[0].to_be_bytes());
    block[4..].copy_from_slice(&v[1].to_be_bytes());
}

/// Runs a word-level block transform on an 8-byte big-endian block, wiping
/// the intermediate words afterwards.
#[inline]
fn on_block(block: &mut [u8; 8], f: impl FnOnce(&mut [u32; 2])) {
    let mut v = load_block(block);
    f(&mut v);
    store_block(&v, block);
    v.zeroize();
}

// ---- TEA ----------------------------------------------------------------

/// The original Tiny Encryption Algorithm: 64-bit block, 128-bit key.
///
/// **Broken.** It has equivalent keys and related-key attacks. Provided only
/// for legacy interop; see the module-level docs. The key is wiped on drop.
#[derive(Clone)]
pub struct Tea {
    k: [u32; 4],
}

impl Tea {
    /// Creates a TEA context from a 16-byte key, read as four big-endian
    /// words.
    pub fn new(key: &[u8; 16]) -> Self {
        Self { k: load_key(key) }
    }

    /// Creates a TEA context from the four key words `k[0..4]`.
    pub fn from_words(key: [u32; 4]) -> Self {
        Self { k: key }
    }

    /// Encrypts the two-word block `v` in place.
    pub fn encrypt_words(&self, v: &mut [u32; 2]) {
        let [k0, k1, k2, k3] = self.k;
        let [mut v0, mut v1] = *v;
        let mut sum = 0u32;
        for _ in 0..CYCLES {
            sum = sum.wrapping_add(DELTA);
            v0 = v0.wrapping_add(
                (v1 << 4).wrapping_add(k0) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(k1),
            );
            v1 = v1.wrapping_add(
                (v0 << 4).wrapping_add(k2) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(k3),
            );
        }
        *v = [v0, v1];
    }

    /// Decrypts the two-word block `v` in place.
    pub fn decrypt_words(&self, v: &mut [u32; 2]) {
        let [k0, k1, k2, k3] = self.k;
        let [mut v0, mut v1] = *v;
        let mut sum = DELTA.wrapping_mul(CYCLES);
        for _ in 0..CYCLES {
            v1 = v1.wrapping_sub(
                (v0 << 4).wrapping_add(k2) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(k3),
            );
            v0 = v0.wrapping_sub(
                (v1 << 4).wrapping_add(k0) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(k1),
            );
            sum = sum.wrapping_sub(DELTA);
        }
        *v = [v0, v1];
    }
}

impl BlockCipher64 for Tea {
    const KEY_SIZE: usize = 16;

    #[inline]
    fn encrypt_block(&self, block: &mut [u8; 8]) {
        on_block(block, |v| self.encrypt_words(v));
    }

    #[inline]
    fn decrypt_block(&self, block: &mut [u8; 8]) {
        on_block(block, |v| self.decrypt_words(v));
    }
}

impl Drop for Tea {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

impl ZeroizeOnDrop for Tea {}

// ---- XTEA ---------------------------------------------------------------

/// XTEA: 64-bit block, 128-bit key, 32 cycles.
///
/// **Legacy.** Provided only for interop; see the module-level docs. The key
/// is wiped on drop.
#[derive(Clone)]
pub struct Xtea {
    k: [u32; 4],
}

impl Xtea {
    /// Creates an XTEA context from a 16-byte key, read as four big-endian
    /// words.
    pub fn new(key: &[u8; 16]) -> Self {
        Self { k: load_key(key) }
    }

    /// Creates an XTEA context from the four key words `k[0..4]`.
    pub fn from_words(key: [u32; 4]) -> Self {
        Self { k: key }
    }

    /// Encrypts the two-word block `v` in place.
    pub fn encrypt_words(&self, v: &mut [u32; 2]) {
        let k = &self.k;
        let [mut v0, mut v1] = *v;
        let mut sum = 0u32;
        for _ in 0..CYCLES {
            v0 = v0.wrapping_add(
                ((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1) ^ sum.wrapping_add(k[(sum & 3) as usize]),
            );
            sum = sum.wrapping_add(DELTA);
            v1 = v1.wrapping_add(
                ((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0)
                    ^ sum.wrapping_add(k[((sum >> 11) & 3) as usize]),
            );
        }
        *v = [v0, v1];
    }

    /// Decrypts the two-word block `v` in place.
    pub fn decrypt_words(&self, v: &mut [u32; 2]) {
        let k = &self.k;
        let [mut v0, mut v1] = *v;
        let mut sum = DELTA.wrapping_mul(CYCLES);
        for _ in 0..CYCLES {
            v1 = v1.wrapping_sub(
                ((v0 << 4) ^ (v0 >> 5)).wrapping_add(v0)
                    ^ sum.wrapping_add(k[((sum >> 11) & 3) as usize]),
            );
            sum = sum.wrapping_sub(DELTA);
            v0 = v0.wrapping_sub(
                ((v1 << 4) ^ (v1 >> 5)).wrapping_add(v1) ^ sum.wrapping_add(k[(sum & 3) as usize]),
            );
        }
        *v = [v0, v1];
    }
}

impl BlockCipher64 for Xtea {
    const KEY_SIZE: usize = 16;

    #[inline]
    fn encrypt_block(&self, block: &mut [u8; 8]) {
        on_block(block, |v| self.encrypt_words(v));
    }

    #[inline]
    fn decrypt_block(&self, block: &mut [u8; 8]) {
        on_block(block, |v| self.decrypt_words(v));
    }
}

impl Drop for Xtea {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

impl ZeroizeOnDrop for Xtea {}

// ---- XXTEA --------------------------------------------------------------

/// XXTEA (corrected Block TEA): a 128-bit-key block cipher whose block is
/// the whole message, any length of two or more 32-bit words.
///
/// The message is encrypted as one block, so there is no mode of operation
/// and no IV. It is deterministic: equal messages under one key encrypt
/// identically. No padding is applied; callers that need arbitrary lengths
/// must define their own.
///
/// **Legacy.** Provided only for interop; see the module-level docs. The key
/// is wiped on drop.
#[derive(Clone)]
pub struct Xxtea {
    k: [u32; 4],
}

impl Xxtea {
    /// Creates an XXTEA context from a 16-byte key, read as four big-endian
    /// words.
    pub fn new(key: &[u8; 16]) -> Self {
        Self { k: load_key(key) }
    }

    /// Creates an XXTEA context from the four key words `k[0..4]`.
    pub fn from_words(key: [u32; 4]) -> Self {
        Self { k: key }
    }

    /// Encrypts `v` in place as a single block.
    ///
    /// # Errors
    /// [`InvalidLength`] if `v` has fewer than two words; `v` is unchanged.
    pub fn encrypt_words(&self, v: &mut [u32]) -> Result<(), InvalidLength> {
        xxtea_encrypt(&self.k, v)
    }

    /// Decrypts `v` in place as a single block.
    ///
    /// # Errors
    /// [`InvalidLength`] if `v` has fewer than two words; `v` is unchanged.
    pub fn decrypt_words(&self, v: &mut [u32]) -> Result<(), InvalidLength> {
        xxtea_decrypt(&self.k, v)
    }

    /// Encrypts `data` in place as a single block of big-endian words.
    ///
    /// # Errors
    /// [`InvalidLength`] if `data.len()` is not a multiple of 4 or is below
    /// 8; `data` is unchanged.
    pub fn encrypt(&self, data: &mut [u8]) -> Result<(), InvalidLength> {
        xxtea_encrypt(&self.k, &mut BeWords::new(data)?)
    }

    /// Decrypts `data` in place as a single block of big-endian words.
    ///
    /// # Errors
    /// [`InvalidLength`] if `data.len()` is not a multiple of 4 or is below
    /// 8; `data` is unchanged.
    pub fn decrypt(&self, data: &mut [u8]) -> Result<(), InvalidLength> {
        xxtea_decrypt(&self.k, &mut BeWords::new(data)?)
    }
}

impl Drop for Xxtea {
    fn drop(&mut self) {
        self.k.zeroize();
    }
}

impl ZeroizeOnDrop for Xxtea {}

/// Indexed access to the message words, so the XXTEA core runs both on a
/// `[u32]` and directly on a big-endian byte buffer without a scratch copy.
trait Words {
    fn len(&self) -> usize;
    fn get(&self, i: usize) -> u32;
    fn set(&mut self, i: usize, w: u32);
}

impl Words for [u32] {
    #[inline]
    fn len(&self) -> usize {
        <[u32]>::len(self)
    }

    #[inline]
    fn get(&self, i: usize) -> u32 {
        self[i]
    }

    #[inline]
    fn set(&mut self, i: usize, w: u32) {
        self[i] = w;
    }
}

/// A byte buffer viewed as big-endian words; its length is checked to be a
/// whole number of words at construction.
struct BeWords<'a>(&'a mut [u8]);

impl<'a> BeWords<'a> {
    fn new(data: &'a mut [u8]) -> Result<Self, InvalidLength> {
        if data.len().is_multiple_of(4) {
            Ok(Self(data))
        } else {
            Err(InvalidLength)
        }
    }
}

impl Words for BeWords<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.0.len() / 4
    }

    #[inline]
    fn get(&self, i: usize) -> u32 {
        u32::from_be_bytes(self.0[4 * i..4 * i + 4].try_into().expect("4 bytes"))
    }

    #[inline]
    fn set(&mut self, i: usize, w: u32) {
        self.0[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
    }
}

/// The XXTEA mixing function `MX` of the reference code.
#[inline]
fn mx(k: &[u32; 4], sum: u32, y: u32, z: u32, p: usize, e: usize) -> u32 {
    (((z >> 5) ^ (y << 2)).wrapping_add((y >> 3) ^ (z << 4)))
        ^ ((sum ^ y).wrapping_add(k[(p & 3) ^ e] ^ z))
}

fn xxtea_encrypt<W: Words + ?Sized>(k: &[u32; 4], v: &mut W) -> Result<(), InvalidLength> {
    let n = v.len();
    if n < 2 {
        return Err(InvalidLength);
    }
    let rounds = 6 + 52 / n;
    let mut sum = 0u32;
    let mut z = v.get(n - 1);
    for _ in 0..rounds {
        sum = sum.wrapping_add(DELTA);
        let e = ((sum >> 2) & 3) as usize;
        for p in 0..n {
            let y = v.get(if p + 1 == n { 0 } else { p + 1 });
            z = v.get(p).wrapping_add(mx(k, sum, y, z, p, e));
            v.set(p, z);
        }
    }
    z.zeroize();
    Ok(())
}

fn xxtea_decrypt<W: Words + ?Sized>(k: &[u32; 4], v: &mut W) -> Result<(), InvalidLength> {
    let n = v.len();
    if n < 2 {
        return Err(InvalidLength);
    }
    let rounds = 6 + 52 / n;
    // `rounds ≤ 32`, so the cast is lossless.
    let mut sum = DELTA.wrapping_mul(rounds as u32);
    let mut y = v.get(0);
    for _ in 0..rounds {
        let e = ((sum >> 2) & 3) as usize;
        for p in (0..n).rev() {
            let z = v.get(if p == 0 { n - 1 } else { p - 1 });
            y = v.get(p).wrapping_sub(mx(k, sum, y, z, p, e));
            v.set(p, y);
        }
        sum = sum.wrapping_sub(DELTA);
    }
    y.zeroize();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::Cbc64;
    use crate::test_util::{from_hex, from_hex_vec};
    use alloc::vec;
    use alloc::vec::Vec;

    const KEY_0F: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const KEY_K2: [u32; 4] = [0x0123_4567, 0x89ab_cdef, 0xfedc_ba98, 0x7654_3210];

    fn block_kat<C: BlockCipher64>(c: &C, pt: &str, ct: &str) {
        let pt: [u8; 8] = from_hex(pt);
        let ct: [u8; 8] = from_hex(ct);
        let mut b = pt;
        c.encrypt_block(&mut b);
        assert_eq!(b, ct);
        c.decrypt_block(&mut b);
        assert_eq!(b, pt);
    }

    /// The widely published all-zero TEA vector, and one cross-checked
    /// against the Wheeler–Needham reference code.
    #[test]
    fn tea_kat() {
        block_kat(&Tea::new(&[0; 16]), "0000000000000000", "41ea3a0a94baa940");
        block_kat(
            &Tea::from_words(KEY_K2),
            "0123456789abcdef",
            "17b5ba5198581091",
        );
    }

    /// Go `x/crypto/xtea`'s vector (key `00..0f`, plaintext "ABCDEFGH"),
    /// plus reference-code vectors.
    #[test]
    fn xtea_kat() {
        block_kat(&Xtea::new(&KEY_0F), "4142434445464748", "497df3d072612cb5");
        block_kat(&Xtea::new(&[0; 16]), "0000000000000000", "dee9d4d8f7131ed9");
        block_kat(
            &Xtea::from_words(KEY_K2),
            "0123456789abcdef",
            "dd5989ecce6d9490",
        );
    }

    #[test]
    fn words_match_bytes() {
        let tea = Tea::new(&KEY_0F);
        let mut w = [0x4142_4344, 0x4546_4748];
        tea.encrypt_words(&mut w);
        let mut b = *b"ABCDEFGH";
        tea.encrypt_block(&mut b);
        assert_eq!(b[..4], w[0].to_be_bytes());
        assert_eq!(b[4..], w[1].to_be_bytes());
    }

    /// Reference-code vectors for n = 2, 3, 8 and 16 words (n = 2 is the
    /// commonly published all-zero vector).
    #[test]
    fn xxtea_kat() {
        let cases: [(&[u8; 16], &str, &str); 3] = [
            (&[0; 16], "0000000000000000", "053704ab575d8c80"),
            (
                &KEY_0F,
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "f594b8c35f839edd6fb2b1acf447c7d268e76bcae78cb6b8fad8ce171ef6e372",
            ),
            (
                &[
                    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76,
                    0x54, 0x32, 0x10,
                ],
                "0123456789abcdeffedcba98",
                "5031ffb4dd31ee27de68beaa",
            ),
        ];
        for (key, pt, ct) in cases {
            let c = Xxtea::new(key);
            let pt = from_hex_vec(pt);
            let mut b = pt.clone();
            c.encrypt(&mut b).unwrap();
            assert_eq!(b, from_hex_vec(ct));
            c.decrypt(&mut b).unwrap();
            assert_eq!(b, pt);
        }

        let c = Xxtea::from_words(KEY_K2);
        let pt: [u32; 16] = core::array::from_fn(|i| i as u32 * 0x1111_1111);
        let mut v = pt;
        c.encrypt_words(&mut v).unwrap();
        let ct = from_hex_vec(
            "b44422718538b1eb8af3535bb4e7e2326ab21177579e33f305d1fdd26cd349b8\
             94920b8144acdc8b31f545e205b27f868f1f277754ce07461477e5096874dc46",
        );
        let got: Vec<u8> = v.iter().flat_map(|w| w.to_be_bytes()).collect();
        assert_eq!(got, ct);
        c.decrypt_words(&mut v).unwrap();
        assert_eq!(v, pt);
    }

    #[test]
    fn xxtea_rejects_bad_lengths() {
        let c = Xxtea::new(&KEY_0F);
        for len in [0, 1, 4, 7, 9, 13] {
            let mut b = vec![0xa5u8; len];
            assert_eq!(c.encrypt(&mut b), Err(InvalidLength), "len {len}");
            assert_eq!(c.decrypt(&mut b), Err(InvalidLength), "len {len}");
            assert!(b.iter().all(|&x| x == 0xa5));
        }
        assert_eq!(c.encrypt_words(&mut []), Err(InvalidLength));
        assert_eq!(c.encrypt_words(&mut [1]), Err(InvalidLength));
    }

    /// Round-trips every word count up to 64, covering the `6 + 52/n` round
    /// count across its whole range.
    #[test]
    fn xxtea_roundtrip_lengths() {
        let c = Xxtea::new(&KEY_0F);
        for n in 2..=64usize {
            let pt: Vec<u8> = (0..4 * n).map(|i| (i * 7 + n) as u8).collect();
            let mut b = pt.clone();
            c.encrypt(&mut b).unwrap();
            assert_ne!(b, pt, "n = {n}");
            c.decrypt(&mut b).unwrap();
            assert_eq!(b, pt, "n = {n}");
        }
    }

    #[test]
    fn xtea_cbc64_roundtrip() {
        let iv = [7u8; 8];
        let pt = *b"sixteen byte msgand some more!!!";
        let mut buf = pt;
        Cbc64::new(Xtea::new(&KEY_0F), &iv)
            .encrypt(&mut buf)
            .unwrap();
        assert_ne!(buf, pt);
        Cbc64::new(Xtea::new(&KEY_0F), &iv)
            .decrypt(&mut buf)
            .unwrap();
        assert_eq!(buf, pt);
    }
}
