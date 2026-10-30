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
//!
//! # GB/T 17964-2021 tweak variant
//!
//! The Chinese national standard GB/T 17964-2021 specifies XTS (typically
//! over SM4) with the *bit-reversed* tweak arithmetic: the 16-byte tweak is
//! read as a big-endian GHASH-style field element and multiplied by `x` as
//! GCM does — shift right by one bit, folding a carried-out bit back in as
//! `0xE1 ‖ 0¹²⁰`. Everything else (`T₀ = E_{K2}(IV)`, XEX, ciphertext
//! stealing) is as in IEEE 1619. OpenSSL exposes it as `SM4-XTS` with
//! `xts_standard = "GB"`; select it here with [`Xts::with_standard`] and
//! [`XtsStandard::Gb`] (or [`Sm4Xts::from_keys_gb`]). For both standards
//! the OpenSSL / GB IV is `sector_index.to_le_bytes()`, so a raw 16-byte IV
//! is passed as `u128::from_le_bytes(iv)`.
//!
//! # Limits
//!
//! * IEEE 1619-2007 §5.1 and NIST SP 800-38E cap a **data unit** (a "sector"
//!   here) at 2²⁰ blocks — 16 MiB. Beyond that the α-power sequence starts to
//!   give distinguishing advantage, so a caller must split larger objects into
//!   independently-tweaked data units rather than passing one giant `buf`.
//!   [`Xts::encrypt_sector`] / [`Xts::decrypt_sector`] do not enforce it;
//!   [`Xts::encrypt_sector_checked`] / [`Xts::decrypt_sector_checked`] do,
//!   returning [`XtsError::DataUnitTooLong`].
//! * The data key and the tweak key must be **independent**. Reusing one key
//!   for both collapses the XEX construction; [`Xts::new`] takes two already
//!   keyed ciphers and so cannot check it. Prefer the byte-key constructors
//!   ([`Aes128Xts::from_keys`], [`Aes128Xts::new_from_key_bytes`] and their
//!   [`Aes256Xts`] counterparts), which reject `K1 == K2` in constant time.
//!
//! ```
//! use purecrypto::cipher::{Aes128Xts, XtsError};
//!
//! let xts = Aes128Xts::from_keys(&[0x11; 16], &[0x22; 16]).unwrap();
//! let mut sector = [0u8; 512];
//! xts.encrypt_sector_checked(7, &mut sector).unwrap();
//!
//! // The same key for both halves is refused.
//! assert!(matches!(
//!     Aes128Xts::from_keys(&[0x11; 16], &[0x11; 16]),
//!     Err(XtsError::RepeatedKey)
//! ));
//! ```

use super::{BlockCipher, InvalidLength};
use crate::ct::ConstantTimeEq;
use crate::zeroize::Zeroize;

/// Errors from the validating XTS entry points (the byte-key constructors and
/// the `*_checked` sector methods).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum XtsError {
    /// The data key `K1` and the tweak key `K2` are identical, which voids
    /// XTS's security argument (IEEE 1619-2007 §5.1; FIPS 140 implementation
    /// guidance requires rejecting it).
    RepeatedKey,
    /// The data unit is shorter than one 16-byte block.
    InvalidLength,
    /// The data unit is longer than the 2²⁰-block (16 MiB) maximum of IEEE
    /// 1619-2007 §5.1 / NIST SP 800-38E.
    DataUnitTooLong,
}

impl core::fmt::Display for XtsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            XtsError::RepeatedKey => "XTS data key and tweak key must differ",
            XtsError::InvalidLength => "XTS data unit shorter than one block",
            XtsError::DataUnitTooLong => "XTS data unit exceeds 2^20 blocks",
        })
    }
}

impl core::error::Error for XtsError {}

impl From<InvalidLength> for XtsError {
    fn from(_: InvalidLength) -> Self {
        XtsError::InvalidLength
    }
}

/// Doubles a 128-bit XTS tweak in place under the IEEE 1619 polynomial.
///
/// Treats `t` as a little-endian 128-bit value; multiplies by α (= 2) modulo
/// `x¹²⁸ + x⁷ + x² + x + 1` (reduction constant `0x87`). Constant time.
#[inline]
fn double_tweak(t: &mut [u8; 16]) {
    *t = double_tweak_u128(u128::from_le_bytes(*t)).to_le_bytes();
}

/// [`double_tweak`] on the little-endian `u128` form: `t·α` with the carried-out
/// top bit folded back as `0x87` through an all-ones/all-zeros mask, so there
/// is no branch on the (secret) tweak.
#[inline]
fn double_tweak_u128(t: u128) -> u128 {
    (t << 1) ^ (0u128.wrapping_sub(t >> 127) & 0x87)
}

/// Which tweak-update rule an [`Xts`] context applies between blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum XtsStandard {
    /// IEEE 1619-2007 / NIST SP 800-38E: little-endian tweak, multiply by α
    /// modulo `x¹²⁸ + x⁷ + x² + x + 1` (reduction `0x87`). The default.
    #[default]
    Ieee1619,
    /// GB/T 17964-2021: big-endian, bit-reversed tweak, multiplied by `x` as
    /// in GHASH (reduction `0xE1 ‖ 0¹²⁰`). OpenSSL's `xts_standard = "GB"`.
    Gb,
}

/// GB/T 17964 tweak update on the big-endian `u128` form: multiply by `x` in
/// the GHASH bit order (shift right, fold the carry back as `0xE1 ‖ 0¹²⁰`),
/// branch-free like [`double_tweak_u128`].
#[inline]
fn gb_mul_x_u128(t: u128) -> u128 {
    (t >> 1) ^ (0u128.wrapping_sub(t & 1) & (0xe1u128 << 120))
}

/// Advances a tweak by one block position under `std`.
#[inline]
fn step_tweak(std: XtsStandard, t: &mut [u8; 16]) {
    match std {
        XtsStandard::Ieee1619 => double_tweak(t),
        XtsStandard::Gb => *t = gb_mul_x_u128(u128::from_be_bytes(*t)).to_be_bytes(),
    }
}

/// AES-XTS context — uses two independent block-cipher instances (data key
/// and tweak key) of the same type.
#[derive(Clone)]
pub struct Xts<C: BlockCipher> {
    cipher_data: C,
    cipher_tweak: C,
    standard: XtsStandard,
}

impl<C: BlockCipher> Xts<C> {
    /// Creates an XTS context from two pre-keyed block ciphers. XTS-AES-128 has
    /// total key length 256 bits (two 128-bit AES keys), XTS-AES-256 has 512
    /// bits.
    ///
    /// **K1 and K2 must be independent.** With `K1 == K2` the XEX construction
    /// degenerates (the tweak is then a function of the same permutation that
    /// encrypts the data) and the mode loses its security argument; FIPS 140
    /// implementation guidance requires implementations to reject it outright.
    /// This constructor takes two *already keyed* ciphers, which expose no key
    /// material, so it cannot check the condition — the caller must. Note that
    /// IEEE 1619-2007 Annex B vector 1 deliberately violates it (both keys all
    /// zero) purely to pin the arithmetic, which is why this is not a hard
    /// reject here.
    pub fn new(cipher_data: C, cipher_tweak: C) -> Self {
        Self::with_standard(cipher_data, cipher_tweak, XtsStandard::Ieee1619)
    }

    /// Like [`new`](Self::new), but selects the tweak-update rule — e.g.
    /// [`XtsStandard::Gb`] for GB/T 17964 (OpenSSL's SM4-XTS with
    /// `xts_standard = "GB"`). The same `K1 ≠ K2` caveat applies.
    ///
    /// Under either rule the 16-byte IV OpenSSL takes is the sector index's
    /// little-endian encoding, so pass a raw IV as `u128::from_le_bytes(iv)`.
    pub fn with_standard(cipher_data: C, cipher_tweak: C, standard: XtsStandard) -> Self {
        Self {
            cipher_data,
            cipher_tweak,
            standard,
        }
    }

    /// The tweak-update rule this context applies.
    pub fn standard(&self) -> XtsStandard {
        self.standard
    }

    /// Maximum number of 16-byte blocks in one data unit (IEEE 1619-2007
    /// §5.1, NIST SP 800-38E): 2²⁰, i.e. 16 MiB. A trailing partial block
    /// counts as a block.
    pub const MAX_DATA_UNIT_BLOCKS: usize = 1 << 20;

    /// Checks a data-unit length against the IEEE 1619 bounds.
    fn check_data_unit(len: usize) -> Result<(), XtsError> {
        if len < 16 {
            return Err(XtsError::InvalidLength);
        }
        if len.div_ceil(16) > Self::MAX_DATA_UNIT_BLOCKS {
            return Err(XtsError::DataUnitTooLong);
        }
        Ok(())
    }

    /// Like [`encrypt_sector`](Self::encrypt_sector), but also enforces the
    /// 2²⁰-block data-unit limit ([`MAX_DATA_UNIT_BLOCKS`](Self::MAX_DATA_UNIT_BLOCKS)).
    /// `buf` is left untouched on error.
    pub fn encrypt_sector_checked(
        &self,
        sector_index: u128,
        buf: &mut [u8],
    ) -> Result<(), XtsError> {
        Self::check_data_unit(buf.len())?;
        Ok(self.encrypt_sector(sector_index, buf)?)
    }

    /// Like [`decrypt_sector`](Self::decrypt_sector), but also enforces the
    /// 2²⁰-block data-unit limit ([`MAX_DATA_UNIT_BLOCKS`](Self::MAX_DATA_UNIT_BLOCKS)).
    /// `buf` is left untouched on error.
    pub fn decrypt_sector_checked(
        &self,
        sector_index: u128,
        buf: &mut [u8],
    ) -> Result<(), XtsError> {
        Self::check_data_unit(buf.len())?;
        Ok(self.decrypt_sector(sector_index, buf)?)
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
        xex_blocks(
            &self.cipher_data,
            self.standard,
            &mut buf[..full_to_emit * 16],
            &mut t,
            true,
        );
        let mut block = [0u8; 16];

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
        let cc = block;

        // Step the tweak by α: T → T'.
        step_tweak(self.standard, &mut t);

        // PP = P_partial ‖ CC[rem..]
        let mut pp = [0u8; 16];
        pp[..rem].copy_from_slice(&buf[full_off + 16..]);
        pp[rem..].copy_from_slice(&cc[rem..]);

        // Encrypt PP with T'.
        xex(&self.cipher_data, &mut pp, &t, true);

        // Emit C_{n-1} = PP and C_partial = CC[..rem].
        buf[full_off..full_off + 16].copy_from_slice(&pp);
        // The trailing partial bytes get the truncated CC.
        buf[full_off + 16..].copy_from_slice(&cc[..rem]);

        Ok(())
    }

    /// Decrypts a sector in place. Mirrors [`Self::encrypt_sector`].
    pub fn decrypt_sector(&self, sector_index: u128, buf: &mut [u8]) -> Result<(), InvalidLength> {
        if buf.len() < 16 {
            return Err(InvalidLength);
        }

        let mut t = self.initial_tweak(sector_index);
        let n_full = buf.len() / 16;
        let rem = buf.len() % 16;
        let full_to_emit = if rem == 0 { n_full } else { n_full - 1 };

        // Decrypt the first `full_to_emit` complete blocks.
        xex_blocks(
            &self.cipher_data,
            self.standard,
            &mut buf[..full_to_emit * 16],
            &mut t,
            false,
        );

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
        step_tweak(self.standard, &mut t_next);

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
        // `cc` is P_{n-1} and `pp` holds the trailing partial plaintext: wipe
        // the local copies, as the rest of the module does for tweaks.
        cc.zeroize();
        pp.zeroize();

        Ok(())
    }
}

/// XEX over whole blocks in place, a window at a time: the tweaks for the
/// window are generated serially (`t` advances by α per block, ending at the
/// tweak for the block after `buf`), and the masked blocks go through the
/// batched cipher, which feeds the hardware pipeline.
fn xex_blocks<C: BlockCipher>(
    cipher: &C,
    standard: XtsStandard,
    buf: &mut [u8],
    t: &mut [u8; 16],
    encrypt: bool,
) {
    // The tweak advances as a `u128` (one shift, one mask, one XOR per block)
    // in the byte order its standard multiplies in — little-endian for IEEE
    // 1619, big-endian for GB/T 17964. Each rule gets its own monomorphised
    // copy of the loop so the step inlines.
    match standard {
        XtsStandard::Ieee1619 => xex_blocks_with(
            cipher,
            buf,
            t,
            encrypt,
            u128::from_le_bytes,
            u128::to_le_bytes,
            double_tweak_u128,
        ),
        XtsStandard::Gb => xex_blocks_with(
            cipher,
            buf,
            t,
            encrypt,
            u128::from_be_bytes,
            u128::to_be_bytes,
            gb_mul_x_u128,
        ),
    }
}

/// [`xex_blocks`] for one tweak representation: `load` / `store` convert
/// between the tweak bytes and the `u128` that `step` multiplies.
fn xex_blocks_with<C: BlockCipher>(
    cipher: &C,
    buf: &mut [u8],
    t: &mut [u8; 16],
    encrypt: bool,
    load: impl Fn([u8; 16]) -> u128,
    store: impl Fn(u128) -> [u8; 16],
    step: impl Fn(u128) -> u128,
) {
    const W: usize = 64;
    let mut tweaks = [0u8; 16 * W];
    let mut tw = load(*t);
    for window in buf.chunks_mut(16 * W) {
        for (blk, slot) in window.chunks_exact_mut(16).zip(tweaks.chunks_exact_mut(16)) {
            let tb = store(tw);
            slot.copy_from_slice(&tb);
            for (b, k) in blk.iter_mut().zip(tb.iter()) {
                *b ^= *k;
            }
            tw = step(tw);
        }
        if encrypt {
            cipher.encrypt_blocks(window);
        } else {
            cipher.decrypt_blocks(window);
        }
        for (b, k) in window.iter_mut().zip(tweaks.iter()) {
            *b ^= *k;
        }
    }
    *t = store(tw);
    // The tweaks are E_K2(sector) multiples: key-derived masks.
    tweaks.zeroize();
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

macro_rules! xts_byte_key_ctors {
    ($cipher:ty, $half:literal, $full:literal, $alias:literal) => {
        impl Xts<$cipher> {
            #[doc = concat!("Creates an ", $alias, " context from the data key `k1` and the tweak key `k2`.")]
            ///
            /// Returns [`XtsError::RepeatedKey`] if `k1 == k2`; the comparison
            /// is constant time, so it reveals nothing about the keys beyond
            /// the verdict.
            pub fn from_keys(k1: &[u8; $half], k2: &[u8; $half]) -> Result<Self, XtsError> {
                // Declassified (Valgrind harness): the verdict is returned.
                if k1.ct_eq(k2).declassify() {
                    return Err(XtsError::RepeatedKey);
                }
                Ok(Self::new(<$cipher>::new(k1), <$cipher>::new(k2)))
            }

            #[doc = concat!("Creates an ", $alias, " context from the ", stringify!($full), "-byte concatenated key `K1 \u{2016} K2`")]
            /// (data key first, tweak key second — the IEEE 1619 / NIST
            /// SP 800-38E key layout).
            ///
            /// Returns [`XtsError::RepeatedKey`] if the two halves are equal,
            /// compared in constant time.
            pub fn new_from_key_bytes(key: &[u8; $full]) -> Result<Self, XtsError> {
                let (k1, k2) = key.split_at($half);
                let k1: &[u8; $half] = k1.try_into().expect("half-length split");
                let k2: &[u8; $half] = k2.try_into().expect("half-length split");
                Self::from_keys(k1, k2)
            }
        }
    };
}

xts_byte_key_ctors!(super::Aes128, 16, 32, "XTS-AES-128");
xts_byte_key_ctors!(super::Aes256, 32, 64, "XTS-AES-256");

/// SM4-XTS — two 128-bit SM4 keys. Use [`Sm4Xts::from_keys_gb`] (or
/// [`Xts::with_standard`]) for the GB/T 17964 tweak rule.
pub type Sm4Xts = Xts<super::Sm4>;

xts_byte_key_ctors!(super::Sm4, 16, 32, "SM4-XTS");

impl Xts<super::Sm4> {
    /// Creates a GB/T 17964-2021 SM4-XTS context (OpenSSL's `SM4-XTS` with
    /// `xts_standard = "GB"`) from the data key `k1` and tweak key `k2`.
    ///
    /// Returns [`XtsError::RepeatedKey`] if `k1 == k2` (constant-time
    /// comparison), like [`from_keys`](Self::from_keys).
    pub fn from_keys_gb(k1: &[u8; 16], k2: &[u8; 16]) -> Result<Self, XtsError> {
        let mut x = Self::from_keys(k1, k2)?;
        x.standard = XtsStandard::Gb;
        Ok(x)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{Aes128, Aes256};
    use crate::test_util::from_hex;

    /// The byte-key constructors refuse `K1 == K2` and otherwise build the
    /// same context as [`Xts::new`] (checked against IEEE 1619 vectors 2/10).
    #[test]
    fn byte_key_ctors_reject_repeated_key() {
        assert_eq!(
            Aes128Xts::from_keys(&[0u8; 16], &[0u8; 16]).err(),
            Some(XtsError::RepeatedKey)
        );
        assert_eq!(
            Aes128Xts::new_from_key_bytes(&[0x5a; 32]).err(),
            Some(XtsError::RepeatedKey)
        );
        assert_eq!(
            Aes256Xts::from_keys(&[7u8; 32], &[7u8; 32]).err(),
            Some(XtsError::RepeatedKey)
        );
        assert_eq!(
            Aes256Xts::new_from_key_bytes(&[0xa5; 64]).err(),
            Some(XtsError::RepeatedKey)
        );
        // Keys differing in a single bit are accepted.
        let mut k2 = [0u8; 16];
        k2[15] = 1;
        assert!(Aes128Xts::from_keys(&[0u8; 16], &k2).is_ok());
        let mut k = [0u8; 64];
        k[0] = 0x80;
        assert!(Aes256Xts::new_from_key_bytes(&k).is_ok());

        // IEEE 1619-2007 vector 2 through the concatenated-key constructor.
        let key =
            from_hex::<32>("1111111111111111111111111111111122222222222222222222222222222222");
        let xts = Aes128Xts::new_from_key_bytes(&key).unwrap();
        let mut buf =
            from_hex::<32>("4444444444444444444444444444444444444444444444444444444444444444");
        xts.encrypt_sector_checked(0x3333333333, &mut buf).unwrap();
        assert_eq!(
            buf,
            from_hex::<32>("c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0")
        );

        // IEEE 1619-2007 vector 10 (XTS-AES-256) through `from_keys`.
        let k1 = from_hex::<32>("2718281828459045235360287471352662497757247093699959574966967627");
        let k2 = from_hex::<32>("3141592653589793238462643383279502884197169399375105820974944592");
        let xts = Aes256Xts::from_keys(&k1, &k2).unwrap();
        let mut buf =
            from_hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        xts.encrypt_sector(0xff, &mut buf).unwrap();
        assert_eq!(
            buf,
            from_hex::<32>("1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b")
        );
    }

    /// The checked sector methods enforce the 2²⁰-block data-unit cap (a
    /// trailing partial block counts) and the one-block minimum, and leave
    /// the buffer untouched when they refuse.
    #[cfg(feature = "alloc")]
    #[test]
    fn checked_sector_enforces_data_unit_limit() {
        let xts = Aes128Xts::from_keys(&[1u8; 16], &[2u8; 16]).unwrap();
        let max = Aes128Xts::MAX_DATA_UNIT_BLOCKS * 16;

        let mut short = [0u8; 15];
        assert_eq!(
            xts.encrypt_sector_checked(0, &mut short),
            Err(XtsError::InvalidLength)
        );

        let mut over = alloc::vec![0x33u8; max + 1];
        assert_eq!(
            xts.encrypt_sector_checked(0, &mut over),
            Err(XtsError::DataUnitTooLong)
        );
        assert_eq!(
            xts.decrypt_sector_checked(0, &mut over),
            Err(XtsError::DataUnitTooLong)
        );
        assert!(over.iter().all(|&b| b == 0x33), "buffer touched on refusal");

        // Exactly 2²⁰ blocks is allowed and round-trips.
        over.truncate(max);
        xts.encrypt_sector_checked(9, &mut over).unwrap();
        assert!(over.iter().any(|&b| b != 0x33));
        xts.decrypt_sector_checked(9, &mut over).unwrap();
        assert!(over.iter().all(|&b| b == 0x33));
    }

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

    /// IEEE 1619-2007 Annex B Vectors 15–18 (XTS-AES-128, data unit sequence
    /// number `0x123456789a`): 17-, 18-, 19- and 20-byte units, so every one
    /// exercises ciphertext stealing over a single full block plus a 1–4-byte
    /// tail. These are the published CTS vectors; the round-trip test below
    /// covers the remaining tail lengths against the implementation itself.
    ///
    /// The four vectors have four different lengths, so the fixtures are
    /// decoded into `Vec`s; only the test needs the heap, not `Xts` itself.
    #[cfg(feature = "alloc")]
    #[test]
    fn ieee_1619_vectors_15_to_18_ciphertext_stealing() {
        use crate::test_util::from_hex_vec;

        let k1 = from_hex::<16>("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0");
        let k2 = from_hex::<16>("bfbebdbcbbbab9b8b7b6b5b4b3b2b1b0");
        let xts = Aes128Xts::new(Aes128::new(&k1), Aes128::new(&k2));
        // IEEE prints the DUSN as the little-endian tweak bytes `9a 78 56 34
        // 12 …`; as an integer that is 0x123456789a.
        let sector: u128 = 0x12_3456_789a;

        let cases: [(&str, &str); 4] = [
            (
                "000102030405060708090a0b0c0d0e0f10",
                "6c1625db4671522d3d7599601de7ca09ed",
            ),
            (
                "000102030405060708090a0b0c0d0e0f1011",
                "d069444b7a7e0cab09e24447d24deb1fedbf",
            ),
            (
                "000102030405060708090a0b0c0d0e0f101112",
                "e5df1351c0544ba1350b3363cd8ef4beedbf9d",
            ),
            (
                "000102030405060708090a0b0c0d0e0f10111213",
                "9d84c813f719aa2c7be3f66171c7c5c2edbf9dac",
            ),
        ];
        for (i, (pt_hex, ct_hex)) in cases.iter().enumerate() {
            let pt = from_hex_vec(pt_hex);
            let ct = from_hex_vec(ct_hex);
            let mut buf = pt.clone();
            xts.encrypt_sector(sector, &mut buf).unwrap();
            assert_eq!(buf, ct, "vector {}", 15 + i);
            xts.decrypt_sector(sector, &mut buf).unwrap();
            assert_eq!(buf, pt, "vector {} decrypt", 15 + i);
        }
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
    /// GB/T 17964 SM4-XTS against OpenSSL 3.5 (`SM4-XTS` with the
    /// `xts_standard = "GB"` parameter), plus the IEEE rule over SM4 for
    /// contrast. Key, IV and plaintext are those of OpenSSL's
    /// `evpciph_sm4.txt` SM4-XTS entries; every ciphertext here was produced
    /// with OpenSSL 3.5 libcrypto. IV `f0f1…ff` is passed as
    /// `u128::from_le_bytes(iv)`.
    #[cfg(feature = "alloc")]
    #[test]
    fn sm4_xts_gb_matches_openssl() {
        use crate::test_util::from_hex_vec;
        let key =
            from_hex::<32>("2b7e151628aed2a6abf7158809cf4f3c000102030405060708090a0b0c0d0e0f");
        let iv = u128::from_le_bytes(from_hex::<16>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
        let pt = from_hex::<64>(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
             30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        let gb: &[(usize, &str)] = &[
            (16, "e9538251c71d7b80bbe4483fef497bd1"),
            (17, "81496f38c32b1c51380ab419f387b71be9"),
            (
                31,
                "bf79d6ef4d74424b9e33bd542b226451e9538251c71d7b80bbe4483fef497b",
            ),
            (
                33,
                "e9538251c71d7b80bbe4483fef497bd19034da0becda99dc089aa233aec3a62a2c",
            ),
            (
                47,
                "e9538251c71d7b80bbe4483fef497bd160f7d838e533b475e9b0c7127f706797\
                 2c5c581bd6242fc51e08964fb4f60f",
            ),
            (
                64,
                "e9538251c71d7b80bbe4483fef497bd12c5c581bd6242fc51e08964fb4f60fdb\
                 903be7f93a1b3479d04feccfb820302cdd775df32ae47354cf4e925252d50796",
            ),
        ];
        let ieee: &[(usize, &str)] = &[
            (17, "9e1222501a2c11d97b0c7b22f5580d59e9"),
            (
                64,
                "e9538251c71d7b80bbe4483fef497bd1b3db1a3e60408c575d63ff7db39f8326\
                 27d16c0db6d2cfc741314642ed88079d5036738c357cd24d0781c9f477f2d316",
            ),
        ];
        let (k1, k2) = key.split_at(16);
        let (k1, k2): (&[u8; 16], &[u8; 16]) = (k1.try_into().unwrap(), k2.try_into().unwrap());
        let x_gb = Sm4Xts::from_keys_gb(k1, k2).unwrap();
        assert_eq!(x_gb.standard(), XtsStandard::Gb);
        let x_ieee = Sm4Xts::new_from_key_bytes(&key).unwrap();
        assert_eq!(x_ieee.standard(), XtsStandard::Ieee1619);
        for (xts, cases) in [(&x_gb, gb), (&x_ieee, ieee)] {
            for &(len, ct) in cases {
                let mut buf = pt[..len].to_vec();
                xts.encrypt_sector_checked(iv, &mut buf).unwrap();
                assert_eq!(buf, from_hex_vec(ct), "{:?} len {len}", xts.standard());
                xts.decrypt_sector_checked(iv, &mut buf).unwrap();
                assert_eq!(buf, &pt[..len]);
            }
        }
        assert_eq!(
            Sm4Xts::from_keys_gb(k1, k1).err(),
            Some(XtsError::RepeatedKey)
        );
    }

    /// The GB rule through the windowed bulk path (more than one 64-block
    /// window, with stealing): OpenSSL 3.5 GB SM4-XTS of the 1125-byte
    /// message `(7i + 3) mod 256` has the SHA-256 below.
    #[cfg(all(feature = "alloc", feature = "hash"))]
    #[test]
    fn sm4_xts_gb_bulk_matches_openssl() {
        use alloc::vec::Vec;
        let key =
            from_hex::<32>("2b7e151628aed2a6abf7158809cf4f3c000102030405060708090a0b0c0d0e0f");
        let iv = u128::from_le_bytes(from_hex::<16>("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"));
        let pt: Vec<u8> = (0..16 * 70 + 5).map(|i| (i * 7 + 3) as u8).collect();
        let (k1, k2) = key.split_at(16);
        let xts = Xts::with_standard(
            crate::cipher::Sm4::new(k1.try_into().unwrap()),
            crate::cipher::Sm4::new(k2.try_into().unwrap()),
            XtsStandard::Gb,
        );
        let mut buf = pt.clone();
        xts.encrypt_sector(iv, &mut buf).unwrap();
        assert_eq!(
            crate::hash::sha256(&buf),
            from_hex::<32>("f8aee7e656cce364beae149258e4f5712715b2381c650c195de9ed619cb5a704")
        );
        xts.decrypt_sector(iv, &mut buf).unwrap();
        assert_eq!(buf, pt);
    }
}
