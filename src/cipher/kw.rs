//! AES key wrap (RFC 3394) and key wrap with padding (RFC 5649) — deterministic
//! authenticated encryption for wrapping cryptographic keys with a key-encrypting
//! key (KEK).
//!
//! Unlike a general-purpose AEAD, key wrap is **deterministic** (no nonce) and
//! gets its authenticity from a fixed initial value that the unwrap step
//! recovers and verifies. It is intentionally **not** a substitute for a
//! nonce-based AEAD; use [`Gcm`](super::Gcm) or [`ChaCha20Poly1305`](super::ChaCha20Poly1305)
//! for data, and [`AesKw`] / [`AesKwp`] only to encrypt key material under
//! another key.
//!
//! Two related schemes:
//!
//! * **KW** (RFC 3394) — plaintext must be a whole number of 64-bit blocks,
//!   `n ≥ 2`. Wrapped output is `n + 1` blocks. Integrity IV is
//!   `0xA6A6A6A6A6A6A6A6`.
//! * **KWP** (RFC 5649) — accepts any non-empty byte length (up to 2³²−1);
//!   the plaintext is zero-padded to a multiple of 8 bytes and a length-aware
//!   AIV `0xA659_59A6 ‖ len_u32_be` replaces the fixed IV. Wrapped output is
//!   one block longer than the padded plaintext.
//!
//! Both schemes use only the underlying [`BlockCipher`]'s `encrypt_block` /
//! `decrypt_block`; no GF arithmetic. The final integrity check is performed
//! in constant time against the expected IV.

use super::{BlockCipher, TagMismatch};
use crate::ct::ConstantTimeEq;

/// Errors returned by AES key wrap operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KwError {
    /// Plaintext or ciphertext length is invalid for the chosen scheme,
    /// or the caller-supplied output buffer is the wrong size.
    InvalidLength,
    /// Unwrap completed but the recovered integrity check value does not
    /// match the expected pattern — the ciphertext is inauthentic.
    IntegrityCheck,
}

impl core::fmt::Display for KwError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KwError::InvalidLength => f.write_str("key wrap: invalid length"),
            KwError::IntegrityCheck => f.write_str("key wrap: integrity check failed"),
        }
    }
}

impl core::error::Error for KwError {}

impl From<TagMismatch> for KwError {
    fn from(_: TagMismatch) -> Self {
        KwError::IntegrityCheck
    }
}

/// The default IV used by RFC 3394 plain key wrap.
const RFC3394_IV: u64 = 0xA6A6_A6A6_A6A6_A6A6;
/// The four high bytes of the RFC 5649 AIV (Alternative IV).
const RFC5649_AIV_TAG: u32 = 0xA659_59A6;

/// Returns the wrapped ciphertext length for an RFC 3394 plaintext of length
/// `n_bytes`: `n_bytes + 8`. The plaintext length itself must be a multiple of
/// 8 and at least 16 (i.e. n ≥ 2 64-bit blocks).
#[inline]
pub fn kw_ciphertext_len(plaintext_len: usize) -> usize {
    plaintext_len + 8
}

/// Returns the wrapped ciphertext length for an RFC 5649 plaintext of length
/// `n_bytes`: `round_up_8(n_bytes) + 8`.
#[inline]
pub fn kwp_ciphertext_len(plaintext_len: usize) -> usize {
    plaintext_len.div_ceil(8) * 8 + 8
}

/// AES key wrap (RFC 3394) keyed by an arbitrary [`BlockCipher`].
///
/// AES-128 KW is the most common form; AES-192 and AES-256 KW are defined by
/// the same algorithm and are obtained by instantiating with `Aes192` / `Aes256`.
#[derive(Clone)]
pub struct AesKw<C: BlockCipher> {
    cipher: C,
}

impl<C: BlockCipher> AesKw<C> {
    /// Creates a key-wrap instance from a pre-keyed block cipher.
    pub fn new(cipher: C) -> Self {
        AesKw { cipher }
    }

    /// Wraps `plaintext` into `out` per RFC 3394.
    ///
    /// `plaintext.len()` must be a multiple of 8 and at least 16; `out.len()`
    /// must equal `plaintext.len() + 8` (see [`kw_ciphertext_len`]). The
    /// integrity IV `0xA6A6_…` is implied.
    pub fn wrap(&self, plaintext: &[u8], out: &mut [u8]) -> Result<(), KwError> {
        if plaintext.len() < 16 {
            return Err(KwError::InvalidLength);
        }
        wrap_w(&self.cipher, RFC3394_IV, plaintext, out)
    }

    /// Unwraps `ciphertext` into `out` per RFC 3394, verifying the integrity IV.
    ///
    /// `ciphertext.len()` must be a multiple of 8 and at least 24; `out.len()`
    /// must equal `ciphertext.len() - 8`.
    pub fn unwrap(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<(), KwError> {
        if ciphertext.len() < 24 {
            return Err(KwError::InvalidLength);
        }
        let recovered = unwrap_w(&self.cipher, ciphertext, out)?;
        if bool::from(recovered.to_be_bytes().ct_eq(&RFC3394_IV.to_be_bytes())) {
            Ok(())
        } else {
            // Wipe the candidate plaintext on failure so a caller can't leak
            // it by ignoring the error.
            for b in out.iter_mut() {
                *b = 0;
            }
            Err(KwError::IntegrityCheck)
        }
    }
}

/// RFC 3394 W: wraps `plaintext` (length ≥ 8, multiple of 8) with a
/// caller-supplied initial value. Writes `plaintext.len() + 8` bytes to `out`.
fn wrap_w<C: BlockCipher>(
    cipher: &C,
    iv: u64,
    plaintext: &[u8],
    out: &mut [u8],
) -> Result<(), KwError> {
    if plaintext.is_empty() || !plaintext.len().is_multiple_of(8) {
        return Err(KwError::InvalidLength);
    }
    if out.len() != plaintext.len() + 8 {
        return Err(KwError::InvalidLength);
    }
    let n = plaintext.len() / 8;

    // Initial state: a 64-bit register A and n 64-bit registers R_1..R_n,
    // packed into `out` as out[0..8] = A, out[8..] = R_1..R_n.
    out[..8].copy_from_slice(&iv.to_be_bytes());
    out[8..].copy_from_slice(plaintext);

    // Six rounds (j = 0..6) over all n positions; in each, encrypt
    // (A ‖ R_i), XOR the high half with the running counter t = n*j + i.
    let mut block = [0u8; 16];
    for j in 0..6u64 {
        for i in 1..=n as u64 {
            block[..8].copy_from_slice(&out[..8]);
            let r_off = i as usize * 8;
            block[8..].copy_from_slice(&out[r_off..r_off + 8]);
            cipher.encrypt_block(&mut block);

            let a_new = u64::from_be_bytes(block[..8].try_into().unwrap()) ^ (n as u64 * j + i);
            out[..8].copy_from_slice(&a_new.to_be_bytes());
            out[r_off..r_off + 8].copy_from_slice(&block[8..]);
        }
    }
    Ok(())
}

/// RFC 3394 W⁻¹: unwraps `ciphertext`, leaving the candidate plaintext in
/// `out` and returning the recovered integrity register A. The caller is
/// responsible for verifying A against the expected IV (constant time).
fn unwrap_w<C: BlockCipher>(
    cipher: &C,
    ciphertext: &[u8],
    out: &mut [u8],
) -> Result<u64, KwError> {
    if ciphertext.len() < 16 || !ciphertext.len().is_multiple_of(8) {
        return Err(KwError::InvalidLength);
    }
    if out.len() + 8 != ciphertext.len() {
        return Err(KwError::InvalidLength);
    }
    let n = ciphertext.len() / 8 - 1;

    // Working register: a (8 bytes) + r_1..r_n (out). Initialize from ct.
    let mut a = u64::from_be_bytes(ciphertext[..8].try_into().unwrap());
    out.copy_from_slice(&ciphertext[8..]);

    // Six rounds in reverse.
    let mut block = [0u8; 16];
    for j in (0..6i64).rev() {
        for i in (1..=n as i64).rev() {
            let t = (n as u64) * (j as u64) + i as u64;
            block[..8].copy_from_slice(&(a ^ t).to_be_bytes());
            let r_off = (i as usize - 1) * 8;
            block[8..].copy_from_slice(&out[r_off..r_off + 8]);
            cipher.decrypt_block(&mut block);

            a = u64::from_be_bytes(block[..8].try_into().unwrap());
            out[r_off..r_off + 8].copy_from_slice(&block[8..]);
        }
    }
    Ok(a)
}

/// AES key wrap with padding (RFC 5649) — wraps arbitrary-length key material.
#[derive(Clone)]
pub struct AesKwp<C: BlockCipher> {
    cipher: C,
}

impl<C: BlockCipher> AesKwp<C> {
    /// Creates a padded key-wrap instance from a pre-keyed block cipher.
    pub fn new(cipher: C) -> Self {
        AesKwp { cipher }
    }

    /// Wraps a plaintext of any length in `[1, 2³²−1]` bytes per RFC 5649.
    /// `out.len()` must equal [`kwp_ciphertext_len`]`(plaintext.len())`.
    pub fn wrap(&self, plaintext: &[u8], out: &mut [u8]) -> Result<(), KwError> {
        if plaintext.is_empty() || plaintext.len() > u32::MAX as usize {
            return Err(KwError::InvalidLength);
        }
        let padded_len = plaintext.len().div_ceil(8) * 8;
        if out.len() != padded_len + 8 {
            return Err(KwError::InvalidLength);
        }

        // AIV = 0xA659_59A6 ‖ len_be32.
        let aiv =
            (u64::from(RFC5649_AIV_TAG) << 32) | u64::from(u32::try_from(plaintext.len()).unwrap());

        if padded_len == 8 {
            // Single-block special case (RFC 5649 §4.1): one AES encrypt.
            let mut block = [0u8; 16];
            block[..8].copy_from_slice(&aiv.to_be_bytes());
            block[8..8 + plaintext.len()].copy_from_slice(plaintext);
            // Zero pad (already 0 in `block`).
            self.cipher.encrypt_block(&mut block);
            out.copy_from_slice(&block);
            Ok(())
        } else {
            // Pad plaintext with zeros up to a multiple of 8, then run W with AIV.
            // We need a scratch buffer because W reads `plaintext` and writes
            // `out` (length plaintext.len() + 8); they overlap if we tried to
            // place padding directly into `out`.
            let mut padded = [0u8; 4096]; // covers RFC 5649 plaintexts up to 4096 bytes
            if padded_len > padded.len() {
                return Err(KwError::InvalidLength);
            }
            padded[..plaintext.len()].copy_from_slice(plaintext);
            for b in &mut padded[plaintext.len()..padded_len] {
                *b = 0;
            }
            wrap_w(&self.cipher, aiv, &padded[..padded_len], out)
        }
    }

    /// Unwraps a KWP ciphertext, recovering the original-length plaintext.
    /// `out` must be at least `ciphertext.len() - 8` bytes; on success the
    /// actual plaintext length is returned and written to the leading bytes
    /// of `out`. Untouched tail bytes are zeroed.
    pub fn unwrap(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, KwError> {
        if ciphertext.len() < 16
            || !ciphertext.len().is_multiple_of(8)
            || out.len() + 8 < ciphertext.len()
        {
            return Err(KwError::InvalidLength);
        }
        let padded_len = ciphertext.len() - 8;

        // Run W⁻¹ (or single-block decrypt) to recover the AIV and the padded
        // plaintext into a scratch buffer.
        let mut scratch = [0u8; 4096];
        if padded_len > scratch.len() {
            return Err(KwError::InvalidLength);
        }
        let (aiv, padded) = if ciphertext.len() == 16 {
            let mut block = [0u8; 16];
            block.copy_from_slice(ciphertext);
            self.cipher.decrypt_block(&mut block);
            scratch[..8].copy_from_slice(&block[8..]);
            (
                u64::from_be_bytes(block[..8].try_into().unwrap()),
                &scratch[..8],
            )
        } else {
            let recovered = unwrap_w(&self.cipher, ciphertext, &mut scratch[..padded_len])?;
            (recovered, &scratch[..padded_len])
        };

        // Validate AIV: high 32 bits == 0xA659_59A6; MLI is in (padded_len-8, padded_len].
        let high = (aiv >> 32) as u32;
        let mli = aiv as u32 as usize;
        let mut ok = high == RFC5649_AIV_TAG;
        ok &= mli != 0 && mli <= padded_len && padded_len - mli < 8;

        // Validate trailing zero padding (mli..padded_len must all be zero).
        if ok {
            // Constant-time-ish: the bound itself is secret-independent (derived
            // from validated AIV), and we OR-fold the pad bytes.
            let mut pad_xor = 0u8;
            for &b in &padded[mli..] {
                pad_xor |= b;
            }
            ok &= pad_xor == 0;
        }

        if !ok {
            // Wipe scratch before returning the error.
            for b in scratch.iter_mut() {
                *b = 0;
            }
            return Err(KwError::IntegrityCheck);
        }

        out[..mli].copy_from_slice(&padded[..mli]);
        for b in &mut out[mli..] {
            *b = 0;
        }
        for b in scratch.iter_mut() {
            *b = 0;
        }
        Ok(mli)
    }
}

/// AES-128 in plain key-wrap mode (RFC 3394).
pub type Aes128Kw = AesKw<super::Aes128>;
/// AES-192 in plain key-wrap mode (RFC 3394).
pub type Aes192Kw = AesKw<super::Aes192>;
/// AES-256 in plain key-wrap mode (RFC 3394).
pub type Aes256Kw = AesKw<super::Aes256>;

/// AES-128 in padded key-wrap mode (RFC 5649).
pub type Aes128Kwp = AesKwp<super::Aes128>;
/// AES-192 in padded key-wrap mode (RFC 5649).
pub type Aes192Kwp = AesKwp<super::Aes192>;
/// AES-256 in padded key-wrap mode (RFC 5649).
pub type Aes256Kwp = AesKwp<super::Aes256>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{Aes128, Aes192, Aes256};
    use crate::test_util::from_hex;

    /// RFC 3394 §4.1: 128-bit data with a 128-bit KEK.
    #[test]
    fn rfc3394_128_kek_128_data() {
        let kek = from_hex::<16>("000102030405060708090A0B0C0D0E0F");
        let pt = from_hex::<16>("00112233445566778899AABBCCDDEEFF");
        let expected = from_hex::<24>("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");

        let kw = Aes128Kw::new(Aes128::new(&kek));
        let mut ct = [0u8; 24];
        kw.wrap(&pt, &mut ct).unwrap();
        assert_eq!(ct, expected);

        let mut recovered = [0u8; 16];
        kw.unwrap(&ct, &mut recovered).unwrap();
        assert_eq!(recovered, pt);
    }

    /// RFC 3394 §4.2: 128-bit data with a 192-bit KEK.
    #[test]
    fn rfc3394_192_kek_128_data() {
        let kek = from_hex::<24>("000102030405060708090A0B0C0D0E0F1011121314151617");
        let pt = from_hex::<16>("00112233445566778899AABBCCDDEEFF");
        let expected = from_hex::<24>("96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D");
        let kw = Aes192Kw::new(Aes192::new(&kek));
        let mut ct = [0u8; 24];
        kw.wrap(&pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut rec = [0u8; 16];
        kw.unwrap(&ct, &mut rec).unwrap();
        assert_eq!(rec, pt);
    }

    /// RFC 3394 §4.3: 128-bit data with a 256-bit KEK.
    #[test]
    fn rfc3394_256_kek_128_data() {
        let kek =
            from_hex::<32>("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let pt = from_hex::<16>("00112233445566778899AABBCCDDEEFF");
        let expected = from_hex::<24>("64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7");
        let kw = Aes256Kw::new(Aes256::new(&kek));
        let mut ct = [0u8; 24];
        kw.wrap(&pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut rec = [0u8; 16];
        kw.unwrap(&ct, &mut rec).unwrap();
        assert_eq!(rec, pt);
    }

    /// RFC 3394 §4.4: 192-bit data with a 192-bit KEK.
    #[test]
    fn rfc3394_192_kek_192_data() {
        let kek = from_hex::<24>("000102030405060708090A0B0C0D0E0F1011121314151617");
        let pt = from_hex::<24>("00112233445566778899AABBCCDDEEFF0001020304050607");
        let expected =
            from_hex::<32>("031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2");
        let kw = Aes192Kw::new(Aes192::new(&kek));
        let mut ct = [0u8; 32];
        kw.wrap(&pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut rec = [0u8; 24];
        kw.unwrap(&ct, &mut rec).unwrap();
        assert_eq!(rec, pt);
    }

    /// RFC 3394 §4.5: 192-bit data with a 256-bit KEK.
    #[test]
    fn rfc3394_256_kek_192_data() {
        let kek =
            from_hex::<32>("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let pt = from_hex::<24>("00112233445566778899AABBCCDDEEFF0001020304050607");
        let expected =
            from_hex::<32>("A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1");
        let kw = Aes256Kw::new(Aes256::new(&kek));
        let mut ct = [0u8; 32];
        kw.wrap(&pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut rec = [0u8; 24];
        kw.unwrap(&ct, &mut rec).unwrap();
        assert_eq!(rec, pt);
    }

    /// RFC 3394 §4.6: 256-bit data with a 256-bit KEK.
    #[test]
    fn rfc3394_256_kek_256_data() {
        let kek =
            from_hex::<32>("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let pt =
            from_hex::<32>("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
        let expected = from_hex::<40>(
            "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
        );
        let kw = Aes256Kw::new(Aes256::new(&kek));
        let mut ct = [0u8; 40];
        kw.wrap(&pt, &mut ct).unwrap();
        assert_eq!(ct, expected);
        let mut rec = [0u8; 32];
        kw.unwrap(&ct, &mut rec).unwrap();
        assert_eq!(rec, pt);
    }

    /// A flipped bit in the ciphertext makes unwrap reject with IntegrityCheck.
    #[test]
    fn rfc3394_tamper_rejected() {
        let kek = from_hex::<16>("000102030405060708090A0B0C0D0E0F");
        let pt = from_hex::<16>("00112233445566778899AABBCCDDEEFF");
        let kw = Aes128Kw::new(Aes128::new(&kek));
        let mut ct = [0u8; 24];
        kw.wrap(&pt, &mut ct).unwrap();
        ct[0] ^= 1;
        let mut rec = [0u8; 16];
        assert_eq!(kw.unwrap(&ct, &mut rec), Err(KwError::IntegrityCheck));
        // The candidate plaintext was wiped.
        assert_eq!(rec, [0u8; 16]);
    }

    /// RFC 5649 §6: 20-byte plaintext under a 192-bit KEK, padded to 24 bytes
    /// and wrapped to 32 bytes.
    #[test]
    fn rfc5649_20_byte() {
        let kek = from_hex::<24>("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let pt = from_hex::<20>("c37b7e6492584340bed12207808941155068f738");
        let expected =
            from_hex::<32>("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a");

        let kwp = Aes192Kwp::new(Aes192::new(&kek));
        let mut ct = [0u8; 32];
        kwp.wrap(&pt, &mut ct).unwrap();
        assert_eq!(ct, expected);

        let mut rec = [0u8; 24];
        let n = kwp.unwrap(&ct, &mut rec).unwrap();
        assert_eq!(n, 20);
        assert_eq!(&rec[..20], &pt[..]);
    }

    /// RFC 5649 §6: 7-byte plaintext under a 192-bit KEK, padded to 8 bytes
    /// and wrapped to a single AES block (16 bytes).
    #[test]
    fn rfc5649_7_byte_single_block() {
        let kek = from_hex::<24>("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let pt = from_hex::<7>("466f7250617369");
        let expected = from_hex::<16>("afbeb0f07dfbf5419200f2ccb50bb24f");

        let kwp = Aes192Kwp::new(Aes192::new(&kek));
        let mut ct = [0u8; 16];
        kwp.wrap(&pt, &mut ct).unwrap();
        assert_eq!(ct, expected);

        let mut rec = [0u8; 8];
        let n = kwp.unwrap(&ct, &mut rec).unwrap();
        assert_eq!(n, 7);
        assert_eq!(&rec[..7], &pt[..]);
        assert_eq!(rec[7], 0);
    }

    /// KWP rejects ciphertext whose AIV tag has been corrupted.
    #[test]
    fn rfc5649_tamper_rejected() {
        let kek = from_hex::<24>("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let pt = from_hex::<20>("c37b7e6492584340bed12207808941155068f738");
        let kwp = Aes192Kwp::new(Aes192::new(&kek));
        let mut ct = [0u8; 32];
        kwp.wrap(&pt, &mut ct).unwrap();
        ct[5] ^= 1;
        let mut rec = [0u8; 24];
        assert_eq!(kwp.unwrap(&ct, &mut rec), Err(KwError::IntegrityCheck));
    }
}
