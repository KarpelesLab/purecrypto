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
//! * **KWP** (RFC 5649) — accepts any non-empty byte length; the plaintext is
//!   zero-padded to a multiple of 8 bytes and a length-aware AIV
//!   `0xA659_59A6 ‖ len_u32_be` replaces the fixed IV. Wrapped output is one
//!   block longer than the padded plaintext. RFC 5649 allows up to 2³²−1
//!   bytes, but [`AesKwp::wrap`]/[`AesKwp::unwrap`] here run on a 4096-byte
//!   stack scratch buffer (no allocator) and return
//!   [`KwError::InvalidLength`] above that — ample for key material, which is
//!   all KWP is for.
//!
//! Both schemes use only the underlying [`BlockCipher`]'s `encrypt_block` /
//! `decrypt_block`; no GF arithmetic. The final integrity check is performed
//! in constant time against the expected IV.
//!
//! # Custom IVs and the inverse-cipher variants
//!
//! RFC 3394 §2.2.3 lets an application replace the default IV; use
//! [`AesKw::wrap_with_iv`] / [`AesKw::unwrap_with_iv`]. For KWP the
//! equivalent is the 32-bit constant in the high half of the AIV
//! (`0xA65959A6`), which OpenSSL lets a caller replace through the 4-byte IV
//! of `id-aes*-wrap-pad`: [`AesKwp::wrap_with_aiv_prefix`] /
//! [`AesKwp::unwrap_with_aiv_prefix`].
//!
//! SP 800-38F §5.1 also allows running KW / KWP with the *inverse* cipher
//! function as the forward one: the wrap uses `CIPH⁻¹_K` and the unwrap uses
//! `CIPH_K`. OpenSSL calls these `AES-*-WRAP-INV` and `AES-*-WRAP-PAD-INV`.
//! They are obtained here by keying [`AesKw`] / [`AesKwp`] with an
//! [`InverseCipher`] (see [`AesKw::new_inverse`] and the `*KwInv` /
//! `*KwpInv` aliases); the output is not interchangeable with the ordinary
//! modes'.

use super::{BlockCipher, TagMismatch};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater};
use crate::zeroize::Zeroize;

/// Errors returned by AES key wrap operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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

/// A [`BlockCipher`] adapter that swaps the forward and inverse permutations
/// of `C`: its `encrypt_block` is `C::decrypt_block` and vice versa.
///
/// Its only purpose is the SP 800-38F inverse-cipher key-wrap variants
/// (OpenSSL's `AES-*-WRAP-INV` / `AES-*-WRAP-PAD-INV`): [`AesKw`] /
/// [`AesKwp`] over `InverseCipher<C>` wrap with `CIPH⁻¹` and unwrap with
/// `CIPH`. Do not use it to build other modes.
#[derive(Clone)]
pub struct InverseCipher<C: BlockCipher>(C);

impl<C: BlockCipher> InverseCipher<C> {
    /// Wraps `cipher`, exchanging its two directions.
    pub fn new(cipher: C) -> Self {
        InverseCipher(cipher)
    }
}

impl<C: BlockCipher> BlockCipher for InverseCipher<C> {
    const BLOCK_SIZE: usize = C::BLOCK_SIZE;
    const KEY_SIZE: usize = C::KEY_SIZE;

    fn encrypt_block(&self, block: &mut [u8; 16]) {
        self.0.decrypt_block(block);
    }

    fn decrypt_block(&self, block: &mut [u8; 16]) {
        self.0.encrypt_block(block);
    }

    fn encrypt_blocks(&self, blocks: &mut [u8]) {
        self.0.decrypt_blocks(blocks);
    }

    fn decrypt_blocks(&self, blocks: &mut [u8]) {
        self.0.encrypt_blocks(blocks);
    }
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
        self.wrap_with_iv(&RFC3394_IV.to_be_bytes(), plaintext, out)
    }

    /// [`wrap`](Self::wrap) with an application-chosen 64-bit initial value
    /// in place of `0xA6A6_A6A6_A6A6_A6A6` (RFC 3394 §2.2.3.2; OpenSSL's
    /// 8-byte IV for `id-aes*-wrap`). The same `iv` must be given to
    /// [`unwrap_with_iv`](Self::unwrap_with_iv).
    pub fn wrap_with_iv(
        &self,
        iv: &[u8; 8],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<(), KwError> {
        if plaintext.len() < 16 {
            return Err(KwError::InvalidLength);
        }
        wrap_w(&self.cipher, u64::from_be_bytes(*iv), plaintext, out)
    }

    /// Unwraps `ciphertext` into `out` per RFC 3394, verifying the integrity IV.
    ///
    /// `ciphertext.len()` must be a multiple of 8 and at least 24; `out.len()`
    /// must equal `ciphertext.len() - 8`.
    pub fn unwrap(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<(), KwError> {
        self.unwrap_with_iv(&RFC3394_IV.to_be_bytes(), ciphertext, out)
    }

    /// [`unwrap`](Self::unwrap), checking the recovered integrity register
    /// against `iv` (constant time) instead of the default IV. On
    /// [`KwError::IntegrityCheck`] `out` is zeroed.
    pub fn unwrap_with_iv(
        &self,
        iv: &[u8; 8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<(), KwError> {
        if ciphertext.len() < 24 {
            return Err(KwError::InvalidLength);
        }
        let recovered = unwrap_w(&self.cipher, ciphertext, out)?;
        // The accept/reject verdict is the public outcome of decryption.
        if recovered.to_be_bytes().ct_eq(iv).declassify() {
            Ok(())
        } else {
            // Wipe the candidate plaintext on failure so a caller can't leak
            // it by ignoring the error.
            out.zeroize();
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
fn unwrap_w<C: BlockCipher>(cipher: &C, ciphertext: &[u8], out: &mut [u8]) -> Result<u64, KwError> {
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
        self.wrap_with_aiv_prefix(&RFC5649_AIV_TAG.to_be_bytes(), plaintext, out)
    }

    /// [`wrap`](Self::wrap) with `prefix` in place of the RFC 5649 constant
    /// `A6 59 59 A6` as the high 32 bits of the AIV (OpenSSL's 4-byte IV for
    /// `id-aes*-wrap-pad`). The length indicator in the low half is still
    /// derived from `plaintext`. Unwrap with
    /// [`unwrap_with_aiv_prefix`](Self::unwrap_with_aiv_prefix).
    pub fn wrap_with_aiv_prefix(
        &self,
        prefix: &[u8; 4],
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Result<(), KwError> {
        if plaintext.is_empty() || plaintext.len() > u32::MAX as usize {
            return Err(KwError::InvalidLength);
        }
        let padded_len = plaintext.len().div_ceil(8) * 8;
        if out.len() != padded_len + 8 {
            return Err(KwError::InvalidLength);
        }

        // AIV = prefix (0xA659_59A6 by default) ‖ len_be32.
        let aiv = (u64::from(u32::from_be_bytes(*prefix)) << 32)
            | u64::from(u32::try_from(plaintext.len()).unwrap());

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
            let result = wrap_w(&self.cipher, aiv, &padded[..padded_len], out);
            // Best-effort wipe of the scratch buffer regardless of outcome:
            // it held a copy of the plaintext key material.
            padded[..padded_len].zeroize();
            result
        }
    }

    /// Unwraps a KWP ciphertext, recovering the original-length plaintext.
    /// `out` must be at least `ciphertext.len() - 8` bytes; on success the
    /// actual plaintext length is returned and written to the leading bytes
    /// of `out`. Untouched tail bytes are zeroed.
    pub fn unwrap(&self, ciphertext: &[u8], out: &mut [u8]) -> Result<usize, KwError> {
        self.unwrap_with_aiv_prefix(&RFC5649_AIV_TAG.to_be_bytes(), ciphertext, out)
    }

    /// [`unwrap`](Self::unwrap), requiring the high 32 bits of the recovered
    /// AIV to equal `prefix` instead of `A6 59 59 A6` (see
    /// [`wrap_with_aiv_prefix`](Self::wrap_with_aiv_prefix)). All checks stay
    /// constant time and fold into the single [`KwError::IntegrityCheck`].
    pub fn unwrap_with_aiv_prefix(
        &self,
        prefix: &[u8; 4],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, KwError> {
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

        // Validate AIV in constant time, accumulating every failure condition
        // into a single Choice. The three checks RFC 5649 §3 requires are:
        //   (1) high 32 bits of AIV == 0xA659_59A6 (or the caller's prefix)
        //   (2) MLI is in (padded_len - 8, padded_len]
        //   (3) padded[mli..padded_len] is all zero
        // The original implementation short-circuited on (1) and used `mli` as
        // a slice bound for (3), so the loop length leaked which check failed.
        // Here every check is folded into `ok` and (3) always scans the full
        // padded buffer using a per-byte mask derived from `mli`.
        let high = (aiv >> 32) as u32;
        let mli_u32 = aiv as u32;
        // Cast padded_len to u32; padded_len <= 4096 (scratch cap) so this is
        // lossless and a public value.
        let padded_len_u32 = padded_len as u32;

        let tag_ok = high.ct_eq(&u32::from_be_bytes(*prefix));
        // (2a) mli != 0
        let mli_nonzero = !mli_u32.ct_eq(&0u32);
        // (2b) mli <= padded_len  <=>  !(mli > padded_len)
        let mli_in_range = !mli_u32.ct_gt(&padded_len_u32);
        // (2c) padded_len - mli < 8. Compute wrapping_sub; when (2b) fails the
        // wrap is unbounded, but `mli_in_range` will already be 0 so the AND
        // below discards this term's contribution.
        let diff = padded_len_u32.wrapping_sub(mli_u32);
        let pad_short = 8u32.ct_gt(&diff);

        // (3) Walk the entire padded buffer; OR in each byte iff i >= mli.
        // `mli` may be out-of-range here (e.g. wildly large) — we use a
        // constant-time clamp purely to derive the per-byte mask and the
        // post-validation index, never as a control-flow input. The loop
        // length is padded_len (public).
        // mli_clamped = min(mli_u32, padded_len_u32), branchlessly via
        // ConditionallySelectable.
        let mli_clamped =
            u32::conditional_select(&padded_len_u32, &mli_u32, mli_u32.ct_gt(&padded_len_u32));
        let mut pad_acc = 0u8;
        for (i, &b) in padded.iter().enumerate() {
            // mask = 0xFF when i >= mli_clamped, else 0x00.
            let in_pad: Choice = !mli_clamped.ct_gt(&(i as u32));
            let mask = 0u8.wrapping_sub(in_pad.unwrap_u8());
            pad_acc |= b & mask;
        }
        let pad_ok = pad_acc.ct_eq(&0u8);

        let ok: Choice = tag_ok & mli_nonzero & mli_in_range & pad_short & pad_ok;

        // The accept/reject verdict is the public outcome of decryption.
        if !ok.declassify() {
            // Wipe scratch before returning the error. Returning a single
            // generic error variant deliberately does not distinguish prefix /
            // length / padding failure to the caller.
            scratch[..padded_len].zeroize();
            return Err(KwError::IntegrityCheck);
        }

        // Validation succeeded — `mli` is now public (it lives in the
        // authenticated AIV). Bounds (2a/2b/2c) guarantee mli ∈ (padded_len-8,
        // padded_len], so mli_clamped == mli_u32 and the indexing below is safe.
        // Declassified (Valgrind harness): the authenticated plaintext length
        // is the (public) return value.
        let mli = crate::ct::declassify_value(mli_clamped) as usize;
        out[..mli].copy_from_slice(&padded[..mli]);
        for b in &mut out[mli..] {
            *b = 0;
        }
        scratch[..padded_len].zeroize();
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

impl<C: BlockCipher> AesKw<InverseCipher<C>> {
    /// Creates an inverse-cipher key-wrap instance (SP 800-38F §5.1;
    /// OpenSSL's `AES-*-WRAP-INV`): wrap applies `cipher`'s decryption
    /// direction and unwrap its encryption direction.
    pub fn new_inverse(cipher: C) -> Self {
        AesKw::new(InverseCipher::new(cipher))
    }
}

impl<C: BlockCipher> AesKwp<InverseCipher<C>> {
    /// Creates an inverse-cipher padded key-wrap instance (OpenSSL's
    /// `AES-*-WRAP-PAD-INV`); see [`AesKw::new_inverse`].
    pub fn new_inverse(cipher: C) -> Self {
        AesKwp::new(InverseCipher::new(cipher))
    }
}

/// AES-128 key wrap with the inverse cipher (OpenSSL `AES-128-WRAP-INV`).
pub type Aes128KwInv = AesKw<InverseCipher<super::Aes128>>;
/// AES-192 key wrap with the inverse cipher (OpenSSL `AES-192-WRAP-INV`).
pub type Aes192KwInv = AesKw<InverseCipher<super::Aes192>>;
/// AES-256 key wrap with the inverse cipher (OpenSSL `AES-256-WRAP-INV`).
pub type Aes256KwInv = AesKw<InverseCipher<super::Aes256>>;

/// AES-128 padded key wrap with the inverse cipher (OpenSSL `AES-128-WRAP-PAD-INV`).
pub type Aes128KwpInv = AesKwp<InverseCipher<super::Aes128>>;
/// AES-192 padded key wrap with the inverse cipher (OpenSSL `AES-192-WRAP-PAD-INV`).
pub type Aes192KwpInv = AesKwp<InverseCipher<super::Aes192>>;
/// AES-256 padded key wrap with the inverse cipher (OpenSSL `AES-256-WRAP-PAD-INV`).
pub type Aes256KwpInv = AesKwp<InverseCipher<super::Aes256>>;

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
        let pt = from_hex::<32>("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F");
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

    /// KWP unwrap returns the same generic `IntegrityCheck` error for every
    /// kind of AIV malformation — corrupted prefix tag, mli==0, mli too large,
    /// mli too small (padded_len - mli >= 8), and non-zero trailing padding —
    /// and only the well-formed AIV unwraps successfully. The test exercises
    /// each branch by crafting a ciphertext through the raw `wrap_w` with a
    /// hand-picked AIV / padding pattern, then verifies unwrap rejects with
    /// the *same* error variant in every failure mode.
    #[test]
    fn rfc5649_unwrap_validation_branches() {
        let kek = from_hex::<24>("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8");
        let aes = Aes192::new(&kek);
        let kwp = Aes192Kwp::new(aes.clone());
        // 20-byte plaintext → padded_len = 24, total ct = 32.
        let pt = from_hex::<20>("c37b7e6492584340bed12207808941155068f738");
        let good_mli: u32 = 20;
        let good_aiv: u64 = (u64::from(RFC5649_AIV_TAG) << 32) | u64::from(good_mli);

        // Helper: build a wrap_w ciphertext from an AIV and a padded plaintext.
        let build = |aiv: u64, padded: &[u8]| -> [u8; 32] {
            let mut out = [0u8; 32];
            wrap_w(&aes, aiv, padded, &mut out).unwrap();
            out
        };

        // Valid input — sanity check that the happy path still works.
        let mut padded_ok = [0u8; 24];
        padded_ok[..pt.len()].copy_from_slice(&pt);
        let ct_valid = build(good_aiv, &padded_ok);
        let mut rec = [0u8; 24];
        let n = kwp
            .unwrap(&ct_valid, &mut rec)
            .expect("valid input unwraps");
        assert_eq!(n, good_mli as usize);
        assert_eq!(&rec[..n], &pt[..]);

        // (1) Corrupted AIV prefix — high 32 bits != 0xA659_59A6.
        let bad_prefix_aiv: u64 = (0xDEAD_BEEFu64 << 32) | u64::from(good_mli);
        let ct_bad_prefix = build(bad_prefix_aiv, &padded_ok);

        // (2a) MLI = 0.
        let bad_mli_zero_aiv: u64 = u64::from(RFC5649_AIV_TAG) << 32;
        let ct_mli_zero = build(bad_mli_zero_aiv, &padded_ok);

        // (2b) MLI > padded_len.
        let bad_mli_big_aiv: u64 = (u64::from(RFC5649_AIV_TAG) << 32) | 0x0000_0100u64;
        let ct_mli_big = build(bad_mli_big_aiv, &padded_ok);

        // (2c) padded_len - mli >= 8 (mli too small for the chosen padding).
        let bad_mli_small_aiv: u64 = (u64::from(RFC5649_AIV_TAG) << 32) | u64::from(12u32);
        // Padding bytes 12..24 are still zero, so only check (2c) trips.
        let ct_mli_small = build(bad_mli_small_aiv, &padded_ok);

        // (3) Non-zero padding byte (mli=20, but padded[20] = 0xFF).
        let mut padded_badpad = [0u8; 24];
        padded_badpad[..pt.len()].copy_from_slice(&pt);
        padded_badpad[20] = 0xFF;
        let ct_bad_pad = build(good_aiv, &padded_badpad);

        // Every failure must return the same generic error variant, distinct
        // from success. No path is allowed to return `InvalidLength` or panic.
        for (name, ct) in [
            ("bad_prefix", &ct_bad_prefix),
            ("mli_zero", &ct_mli_zero),
            ("mli_big", &ct_mli_big),
            ("mli_small", &ct_mli_small),
            ("bad_pad", &ct_bad_pad),
        ] {
            let mut buf = [0u8; 24];
            let err = kwp.unwrap(ct, &mut buf);
            assert_eq!(
                err,
                Err(KwError::IntegrityCheck),
                "case {name}: expected IntegrityCheck, got {err:?}",
            );
        }
    }
    /// Custom RFC 3394 IVs and custom KWP AIV prefixes, checked against
    /// OpenSSL 3.5 (`AES-*-WRAP` with an 8-byte IV, `AES-*-WRAP-PAD` with a
    /// 4-byte IV). The plaintexts and KEKs are those of RFC 3394 §4.1 / §4.5
    /// and RFC 5649 §6.
    #[test]
    fn custom_iv_matches_openssl() {
        let kek = from_hex::<16>("000102030405060708090A0B0C0D0E0F");
        let kek256 =
            from_hex::<32>("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let pt = from_hex::<16>("00112233445566778899AABBCCDDEEFF");
        let pt24 = from_hex::<24>("00112233445566778899AABBCCDDEEFF0001020304050607");
        let iv = from_hex::<8>("0123456789abcdef");

        let kw = Aes128Kw::new(Aes128::new(&kek));
        let mut ct = [0u8; 24];
        kw.wrap_with_iv(&iv, &pt, &mut ct).unwrap();
        assert_eq!(
            ct,
            from_hex::<24>("a0f76f4b09e1f2191b8d94da2ca57adfd45ee9732992a98f")
        );
        let mut out = [0u8; 16];
        kw.unwrap_with_iv(&iv, &ct, &mut out).unwrap();
        assert_eq!(out, pt);
        // The default-IV unwrap (and any other IV) refuses it, wiping `out`.
        assert_eq!(kw.unwrap(&ct, &mut out), Err(KwError::IntegrityCheck));
        assert_eq!(out, [0u8; 16]);
        // The default IV through the explicit form is plain RFC 3394 §4.1.
        kw.wrap_with_iv(&[0xA6; 8], &pt, &mut ct).unwrap();
        assert_eq!(
            ct,
            from_hex::<24>("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
        );

        let kw = Aes256Kw::new(Aes256::new(&kek256));
        let mut ct = [0u8; 32];
        kw.wrap_with_iv(&iv, &pt24, &mut ct).unwrap();
        assert_eq!(
            ct,
            from_hex::<32>("48faa68c40bd84e5e9fc5549a6753f62820478931f7c19a40092186b83ef94b2")
        );
        let mut out = [0u8; 24];
        kw.unwrap_with_iv(&iv, &ct, &mut out).unwrap();
        assert_eq!(out, pt24);

        let kwp = Aes128Kwp::new(Aes128::new(&kek));
        let prefix = from_hex::<4>("deadbeef");
        let p7 = from_hex::<7>("466f7250617369");
        let mut ct = [0u8; 16];
        kwp.wrap_with_aiv_prefix(&prefix, &p7, &mut ct).unwrap();
        assert_eq!(ct, from_hex::<16>("d6af17aa7c5ae986baed7b77211aabeb"));
        let mut out = [0u8; 8];
        assert_eq!(kwp.unwrap_with_aiv_prefix(&prefix, &ct, &mut out), Ok(7));
        assert_eq!(&out[..7], &p7);
        assert_eq!(kwp.unwrap(&ct, &mut out), Err(KwError::IntegrityCheck));

        let p20 = from_hex::<20>("c37b7e6492584340bed12207808941155068f738");
        let mut ct = [0u8; 32];
        kwp.wrap_with_aiv_prefix(&prefix, &p20, &mut ct).unwrap();
        assert_eq!(
            ct,
            from_hex::<32>("c5fb137245bd3adaf19794c4e7b4e2c94b9e57217ff9f1baff87c498a5e55739")
        );
        let mut out = [0u8; 24];
        assert_eq!(kwp.unwrap_with_aiv_prefix(&prefix, &ct, &mut out), Ok(20));
        assert_eq!(&out[..20], &p20);
    }

    /// The inverse-cipher variants (wrap with AES decryption, unwrap with AES
    /// encryption) against OpenSSL 3.5 `AES-{128,256}-WRAP-INV` and
    /// `AES-128-WRAP-PAD-INV`, with and without custom IVs.
    #[test]
    fn inverse_cipher_matches_openssl() {
        let kek = from_hex::<16>("000102030405060708090A0B0C0D0E0F");
        let kek256 =
            from_hex::<32>("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        let pt = from_hex::<16>("00112233445566778899AABBCCDDEEFF");
        let pt24 = from_hex::<24>("00112233445566778899AABBCCDDEEFF0001020304050607");

        let kw = Aes128KwInv::new_inverse(Aes128::new(&kek));
        let mut ct = [0u8; 24];
        kw.wrap(&pt, &mut ct).unwrap();
        assert_eq!(
            ct,
            from_hex::<24>("88176ec1a7facee6daf9562fc6ca95f894a41b629a6ae5a2")
        );
        let mut out = [0u8; 16];
        kw.unwrap(&ct, &mut out).unwrap();
        assert_eq!(out, pt);
        // Not interchangeable with the forward-cipher mode.
        assert_eq!(
            Aes128Kw::new(Aes128::new(&kek)).unwrap(&ct, &mut out),
            Err(KwError::IntegrityCheck)
        );
        kw.wrap_with_iv(&from_hex::<8>("0123456789abcdef"), &pt, &mut ct)
            .unwrap();
        assert_eq!(
            ct,
            from_hex::<24>("7ccc41e6172fb685f1e52a4f398d00151d23d6af45cca612")
        );

        let kw = Aes256KwInv::new_inverse(Aes256::new(&kek256));
        let mut ct = [0u8; 32];
        kw.wrap(&pt24, &mut ct).unwrap();
        assert_eq!(
            ct,
            from_hex::<32>("f6cca933f72cdc085f5c9d170d93e2babea9225450671f38aaf1ae1a3411b73c")
        );
        let mut out = [0u8; 24];
        kw.unwrap(&ct, &mut out).unwrap();
        assert_eq!(out, pt24);

        let kwp = Aes128KwpInv::new_inverse(Aes128::new(&kek));
        let prefix = from_hex::<4>("deadbeef");
        let p7 = from_hex::<7>("466f7250617369");
        let p20 = from_hex::<20>("c37b7e6492584340bed12207808941155068f738");
        let mut c16 = [0u8; 16];
        kwp.wrap(&p7, &mut c16).unwrap();
        assert_eq!(c16, from_hex::<16>("9bad28ed3a3441d9fae80bb90a94b9b4"));
        let mut out = [0u8; 8];
        assert_eq!(kwp.unwrap(&c16, &mut out), Ok(7));
        assert_eq!(&out[..7], &p7);
        kwp.wrap_with_aiv_prefix(&prefix, &p7, &mut c16).unwrap();
        assert_eq!(c16, from_hex::<16>("20081ee1280eab8829ac26da2ce64eaf"));

        let mut c32 = [0u8; 32];
        kwp.wrap(&p20, &mut c32).unwrap();
        assert_eq!(
            c32,
            from_hex::<32>("e81344ff709e57ef0d19052a1e3cdd7bde4b1311e5a47045dc52d97282fa2c57")
        );
        kwp.wrap_with_aiv_prefix(&prefix, &p20, &mut c32).unwrap();
        assert_eq!(
            c32,
            from_hex::<32>("0e456b17cf86124ccf8cb3db48f72142b22895ee4a45609a04aa651c9df88e59")
        );
        let mut out = [0u8; 24];
        assert_eq!(kwp.unwrap_with_aiv_prefix(&prefix, &c32, &mut out), Ok(20));
        assert_eq!(&out[..20], &p20);
        assert_eq!(
            Aes128Kwp::new(Aes128::new(&kek)).unwrap_with_aiv_prefix(&prefix, &c32, &mut out),
            Err(KwError::IntegrityCheck)
        );
    }
}
