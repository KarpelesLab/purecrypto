//! KBKDF — Key-Based Key Derivation Function (NIST SP 800-108r1).
//!
//! Derives output keying material from an existing key-derivation key `KI`
//! using a pseudorandom function (PRF) keyed by `KI`. Two modes are provided:
//!
//! - **Counter mode** ([`kbkdf_counter`], SP 800-108r1 §4.1)
//! - **Feedback mode** ([`kbkdf_feedback`], SP 800-108r1 §4.2)
//!
//! Both are generic over the [`Prf`] used to instantiate the PRF; impls are
//! provided for HMAC (over any [`Digest`]) and AES-CMAC (128/256-bit keys).
//! Convenience wrappers pin the common choices: HMAC-SHA-256/384/512 and
//! CMAC-AES-128/256.
//!
//! # Fixed-input-block layout
//!
//! Each PRF invocation `i` (a 32-bit big-endian counter, `r = 32`) is fed a
//! byte string assembled from the caller's `label` and `context`. This crate
//! uses the standard NIST construction
//!
//! ```text
//! FixedInput = Label ‖ 0x00 ‖ Context ‖ [L]_32
//! ```
//!
//! where `[L]_32` is the **output length in bits** encoded as a 32-bit
//! big-endian integer, and `0x00` is the single separator octet mandated by
//! SP 800-108r1 when a label/context split is used. The full PRF input is then:
//!
//! - **Counter mode:** `PRF(KI, [i]_32 ‖ FixedInput)` — counter *before* the
//!   fixed data.
//! - **Feedback mode:** `PRF(KI, K(i-1) ‖ [i]_32 ‖ FixedInput)`, with
//!   `K(0) = IV` (which may be empty) — counter placed *after* the iteration
//!   variable `K(i-1)`.
//!
//! The output keying material is `KO = K(1) ‖ K(2) ‖ … ` truncated to the
//! requested `out.len()` bytes.
//!
//! For interop with peers that supply a single pre-assembled fixed-input
//! string (the NIST CAVP `FixedInputData` field), use the lower-level
//! [`kbkdf_counter_fixed`] / [`kbkdf_feedback_fixed`] entry points, which take
//! the fixed data verbatim and do not append `[L]_32` themselves.

use crate::cipher::{Aes128, Aes256, BlockCipher, Cmac};
use crate::hash::{Digest, Hmac};

/// Error returned by the KBKDF entry points.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The requested output length was zero. SP 800-108r1 derives at least one
    /// PRF block, so a zero-length request is rejected as a likely caller bug.
    ZeroLength,
    /// The requested output length cannot be produced because the number of
    /// PRF blocks would overflow the 32-bit counter `i`.
    OutputTooLong,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::ZeroLength => f.write_str("KBKDF output length must be non-zero"),
            Error::OutputTooLong => f.write_str("KBKDF output length exceeds 2^32-1 PRF blocks"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// A pseudorandom function for use as the KBKDF PRF.
///
/// An implementation is keyed once per derivation with `KI`, then driven
/// through a streaming interface so the (potentially multi-part) input block
/// can be fed without allocating a contiguous buffer: [`init`](Prf::init) keys
/// it, [`update`](Prf::update) feeds bytes, and [`finalize`](Prf::finalize)
/// writes exactly [`OUTPUT_LEN`](Prf::OUTPUT_LEN) bytes and resets the instance
/// for the next iteration.
pub trait Prf {
    /// PRF output length in bytes (`h`), e.g. 32 for HMAC-SHA-256 or 16 for
    /// AES-CMAC.
    const OUTPUT_LEN: usize;

    /// Creates a PRF instance keyed with `ki`.
    fn init(ki: &[u8]) -> Self;

    /// Feeds input bytes for the current PRF block.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the current block, writing exactly [`OUTPUT_LEN`](Prf::OUTPUT_LEN)
    /// bytes into `out`, and resets `self` (re-keyed with the original `KI`) so
    /// it is ready for the next block.
    fn finalize(&mut self, out: &mut [u8]);
}

/// HMAC PRF over any [`Digest`] `D` (e.g. SHA-256/384/512).
///
/// Use the [`HmacSha256Prf`] / [`HmacSha384Prf`] / [`HmacSha512Prf`] aliases
/// for the common instantiations.
pub struct HmacPrf<D: Digest> {
    /// A keyed-but-unfed HMAC, cloned once per PRF block. Keeping the keyed
    /// *state* (rather than a copy of the key) is what makes every block use
    /// exactly the key schedule `Hmac::new(KI)` derived — including for hashes
    /// whose block is not 128 bytes, where re-deriving from a stashed,
    /// length-reduced key copy would silently key later blocks differently.
    template: Hmac<D>,
    mac: Hmac<D>,
}

impl<D: Digest> Prf for HmacPrf<D> {
    const OUTPUT_LEN: usize = D::OUTPUT_LEN;

    fn init(ki: &[u8]) -> Self {
        // Key once; `Hmac` reduces an over-long key (> `D::BLOCK_LEN`) to
        // `D::digest(key)` internally, so cloning the keyed state reproduces
        // whatever reduction it applied, for any digest's block length.
        let template = Hmac::<D>::new(ki);
        let mac = template.clone();
        HmacPrf { template, mac }
    }

    fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    fn finalize(&mut self, out: &mut [u8]) {
        // Swap in a freshly keyed MAC for the next block, finalizing the old one.
        let next = self.template.clone();
        let done = core::mem::replace(&mut self.mac, next);
        let tag = done.finalize();
        let t = tag.as_ref();
        debug_assert_eq!(t.len(), Self::OUTPUT_LEN);
        out.copy_from_slice(t);
    }
}

/// HMAC-SHA-256 PRF.
pub type HmacSha256Prf = HmacPrf<crate::hash::Sha256>;
/// HMAC-SHA-384 PRF.
pub type HmacSha384Prf = HmacPrf<crate::hash::Sha384>;
/// HMAC-SHA-512 PRF.
pub type HmacSha512Prf = HmacPrf<crate::hash::Sha512>;

/// Internal CMAC PRF core, generic over the 128-bit block cipher. CMAC cannot
/// satisfy [`Prf::init`] generically (it needs a concrete, correctly-sized
/// cipher key), so the trait is implemented only by the AES-specific
/// [`CmacAes128Prf`] / [`CmacAes256Prf`] wrappers, which delegate here.
struct CmacPrf<C: BlockCipher + Clone> {
    cipher: C,
    mac: Cmac<C>,
}

impl<C: BlockCipher + Clone> CmacPrf<C> {
    fn from_cipher(cipher: C) -> Self {
        let mac = Cmac::new(cipher.clone());
        CmacPrf { cipher, mac }
    }

    fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    fn finalize(&mut self, out: &mut [u8]) {
        let next = Cmac::new(self.cipher.clone());
        let done = core::mem::replace(&mut self.mac, next);
        let tag = done.finalize();
        out.copy_from_slice(&tag);
    }
}

/// AES-128-CMAC PRF (16-byte key, 16-byte output).
pub struct CmacAes128Prf(CmacPrf<Aes128>);
/// AES-256-CMAC PRF (32-byte key, 16-byte output).
pub struct CmacAes256Prf(CmacPrf<Aes256>);

impl Prf for CmacAes128Prf {
    const OUTPUT_LEN: usize = 16;
    fn init(ki: &[u8]) -> Self {
        assert_eq!(ki.len(), 16, "CMAC-AES-128 key must be 16 bytes");
        let mut key = [0u8; 16];
        key.copy_from_slice(ki);
        CmacAes128Prf(CmacPrf::from_cipher(Aes128::new(&key)))
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(&mut self, out: &mut [u8]) {
        self.0.finalize(out);
    }
}

impl Prf for CmacAes256Prf {
    const OUTPUT_LEN: usize = 16;
    fn init(ki: &[u8]) -> Self {
        assert_eq!(ki.len(), 32, "CMAC-AES-256 key must be 32 bytes");
        let mut key = [0u8; 32];
        key.copy_from_slice(ki);
        CmacAes256Prf(CmacPrf::from_cipher(Aes256::new(&key)))
    }
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    fn finalize(&mut self, out: &mut [u8]) {
        self.0.finalize(out);
    }
}

/// The largest PRF output among the supported instantiations (HMAC-SHA-512).
const MAX_PRF_OUTPUT: usize = 64;

/// Validates the requested output length and returns the number of PRF blocks.
fn block_count(out_len: usize, prf_out: usize) -> Result<u32, Error> {
    if out_len == 0 {
        return Err(Error::ZeroLength);
    }
    let blocks = out_len.div_ceil(prf_out);
    if blocks > u32::MAX as usize {
        return Err(Error::OutputTooLong);
    }
    Ok(blocks as u32)
}

/// Counter mode (SP 800-108r1 §4.1) taking a pre-assembled `fixed` input.
///
/// Computes `KO = K(1) ‖ K(2) ‖ …` where
/// `K(i) = PRF(KI, [i]_32 ‖ fixed)` and writes the leading `out.len()` bytes.
/// The caller is responsible for the contents of `fixed` (e.g. the NIST CAVP
/// `FixedInputData`); this function does **not** append `[L]_32`.
///
/// # Errors
/// Returns [`Error::ZeroLength`] for empty output and [`Error::OutputTooLong`]
/// if more than `2^32 - 1` PRF blocks would be required.
pub fn kbkdf_counter_fixed<P: Prf>(ki: &[u8], fixed: &[u8], out: &mut [u8]) -> Result<(), Error> {
    let blocks = block_count(out.len(), P::OUTPUT_LEN)?;
    let mut prf = P::init(ki);
    let mut block = [0u8; MAX_PRF_OUTPUT];
    let h = P::OUTPUT_LEN;
    let mut filled = 0;
    for i in 1..=blocks {
        prf.update(&i.to_be_bytes());
        prf.update(fixed);
        prf.finalize(&mut block[..h]);
        let take = (out.len() - filled).min(h);
        out[filled..filled + take].copy_from_slice(&block[..take]);
        filled += take;
    }
    super::wipe(&mut block);
    Ok(())
}

/// Feedback mode (SP 800-108r1 §4.2) taking a pre-assembled `fixed` input.
///
/// Computes `KO = K(1) ‖ K(2) ‖ …` where `K(0) = iv` (which may be empty) and
/// `K(i) = PRF(KI, K(i-1) ‖ [i]_32 ‖ fixed)`, writing the leading `out.len()`
/// bytes. As with [`kbkdf_counter_fixed`], `fixed` is used verbatim and
/// `[L]_32` is not appended by this function.
///
/// # Errors
/// Returns [`Error::ZeroLength`] for empty output and [`Error::OutputTooLong`]
/// if more than `2^32 - 1` PRF blocks would be required.
pub fn kbkdf_feedback_fixed<P: Prf>(
    ki: &[u8],
    iv: &[u8],
    fixed: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let blocks = block_count(out.len(), P::OUTPUT_LEN)?;
    let mut prf = P::init(ki);
    let h = P::OUTPUT_LEN;
    // K(i-1): K(0) = IV is fed from the caller's slice (any length); every
    // subsequent K(i) is exactly `h` bytes.
    let mut prev = [0u8; MAX_PRF_OUTPUT];
    let mut block = [0u8; MAX_PRF_OUTPUT];
    let mut filled = 0;
    for i in 1..=blocks {
        if i == 1 {
            prf.update(iv);
        } else {
            prf.update(&prev[..h]);
        }
        prf.update(&i.to_be_bytes());
        prf.update(fixed);
        prf.finalize(&mut block[..h]);
        prev[..h].copy_from_slice(&block[..h]);
        let take = (out.len() - filled).min(h);
        out[filled..filled + take].copy_from_slice(&block[..take]);
        filled += take;
    }
    super::wipe(&mut prev);
    super::wipe(&mut block);
    Ok(())
}

/// Assembles the standard fixed-input `Label ‖ 0x00 ‖ Context ‖ [L]_32` and
/// feeds it to the PRF in pieces, avoiding any allocation. This is the
/// per-block tail shared by the high-level counter/feedback entry points.
fn feed_fixed_input<P: Prf>(prf: &mut P, label: &[u8], context: &[u8], l_bits: u32) {
    prf.update(label);
    prf.update(&[0x00]);
    prf.update(context);
    prf.update(&l_bits.to_be_bytes());
}

/// Counter mode (SP 800-108r1 §4.1) with the standard fixed-input layout.
///
/// Derives `out.len()` bytes of keying material from `ki`, binding the result
/// to `label` and `context` via the fixed input
/// `Label ‖ 0x00 ‖ Context ‖ [L]_32`, where `[L]_32` is the output length in
/// bits. Concretely `K(i) = PRF(KI, [i]_32 ‖ Label ‖ 0x00 ‖ Context ‖ [L]_32)`.
///
/// # Errors
/// Returns [`Error::ZeroLength`] for empty output and [`Error::OutputTooLong`]
/// if more than `2^32 - 1` PRF blocks would be required.
///
/// ```
/// use purecrypto::kdf::{kbkdf_counter, HmacSha256Prf};
///
/// let mut okm = [0u8; 32];
/// kbkdf_counter::<HmacSha256Prf>(b"key-derivation key", b"label", b"context", &mut okm)
///     .unwrap();
/// ```
pub fn kbkdf_counter<P: Prf>(
    ki: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let blocks = block_count(out.len(), P::OUTPUT_LEN)?;
    let l_bits = output_len_bits(out.len())?;
    let mut prf = P::init(ki);
    let mut block = [0u8; MAX_PRF_OUTPUT];
    let h = P::OUTPUT_LEN;
    let mut filled = 0;
    for i in 1..=blocks {
        prf.update(&i.to_be_bytes());
        feed_fixed_input(&mut prf, label, context, l_bits);
        prf.finalize(&mut block[..h]);
        let take = (out.len() - filled).min(h);
        out[filled..filled + take].copy_from_slice(&block[..take]);
        filled += take;
    }
    super::wipe(&mut block);
    Ok(())
}

/// Feedback mode (SP 800-108r1 §4.2) with the standard fixed-input layout.
///
/// Derives `out.len()` bytes from `ki` with `K(0) = iv` (which may be empty)
/// and `K(i) = PRF(KI, K(i-1) ‖ [i]_32 ‖ Label ‖ 0x00 ‖ Context ‖ [L]_32)`,
/// where `[L]_32` is the output length in bits.
///
/// # Errors
/// Returns [`Error::ZeroLength`] for empty output and [`Error::OutputTooLong`]
/// if more than `2^32 - 1` PRF blocks would be required.
pub fn kbkdf_feedback<P: Prf>(
    ki: &[u8],
    iv: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    let blocks = block_count(out.len(), P::OUTPUT_LEN)?;
    let l_bits = output_len_bits(out.len())?;
    let mut prf = P::init(ki);
    let h = P::OUTPUT_LEN;
    let mut prev = [0u8; MAX_PRF_OUTPUT];
    let mut block = [0u8; MAX_PRF_OUTPUT];
    let mut filled = 0;
    for i in 1..=blocks {
        if i == 1 {
            prf.update(iv);
        } else {
            prf.update(&prev[..h]);
        }
        prf.update(&i.to_be_bytes());
        feed_fixed_input(&mut prf, label, context, l_bits);
        prf.finalize(&mut block[..h]);
        prev[..h].copy_from_slice(&block[..h]);
        let take = (out.len() - filled).min(h);
        out[filled..filled + take].copy_from_slice(&block[..take]);
        filled += take;
    }
    super::wipe(&mut prev);
    super::wipe(&mut block);
    Ok(())
}

/// Converts an output byte length to its `[L]_32` bit-length field, rejecting
/// lengths whose bit count overflows 32 bits.
fn output_len_bits(out_len: usize) -> Result<u32, Error> {
    out_len
        .checked_mul(8)
        .and_then(|b| u32::try_from(b).ok())
        .ok_or(Error::OutputTooLong)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // -- NIST CAVP Known-Answer Tests ---------------------------------------
    //
    // Counter-mode vectors are from the NIST CAVP "KDF in Counter Mode"
    // package (CounterMode.zip, CAVS 14.4), profile:
    //   [CTRLOCATION = BEFORE_FIXED]  [RLEN = 32_BITS]
    // i.e. a 32-bit big-endian counter prepended to the (monolithic)
    // FixedInputData, matching `kbkdf_counter_fixed`.
    //
    // Feedback-mode vectors are from the NIST CAVP "KDF in Feedback Mode (zero
    // length IV not supported)" package (FeedbackModeNOzeroiv.zip, CAVS 12.0),
    // profile:
    //   [CTRLOCATION = AFTER_ITER]  [RLEN = 32_BITS]  (non-empty IV)
    // i.e. K(i) = PRF(KI, K(i-1) ‖ [i]_32 ‖ FixedInputData), matching
    // `kbkdf_feedback_fixed`.

    // CAVP CounterMode, [PRF=HMAC_SHA256][CTRLOCATION=BEFORE_FIXED][RLEN=32], COUNT=0.
    #[test]
    fn cavp_counter_hmac_sha256_l128() {
        let ki = from_hex::<32>("dd1d91b7d90b2bd3138533ce92b272fbf8a369316aefe242e659cc0ae238afe0");
        let fixed = from_hex::<60>(
            "01322b96b30acd197979444e468e1c5c6859bf1b1cf951b7e725303e237e46b8\
             64a145fab25e517b08f8683d0315bb2911d80a0e8aba17f3b413faac",
        );
        let mut out = [0u8; 16]; // L = 128 bits
        kbkdf_counter_fixed::<HmacSha256Prf>(&ki, &fixed, &mut out).unwrap();
        assert_eq!(out, from_hex::<16>("10621342bfb0fd40046c0e29f2cfdbf0"));
    }

    // CAVP CounterMode, [PRF=HMAC_SHA256][CTRLOCATION=BEFORE_FIXED][RLEN=32], COUNT=30.
    // L = 320 bits spans two SHA-256 PRF blocks, exercising the counter loop.
    #[test]
    fn cavp_counter_hmac_sha256_l320_multiblock() {
        let ki = from_hex::<32>("c4bedbddb66493e7c7259a3bbbc25f8c7e0ca7fe284d92d431d9cd99a0d214ac");
        let fixed = from_hex::<60>(
            "1c69c54766791e315c2cc5c47ecd3ffab87d0d273dd920e70955814c220eacac\
             e6a5946542da3dfe24ff626b4897898cafb7db83bdff3c14fa46fd4b",
        );
        let mut out = [0u8; 40]; // L = 320 bits
        kbkdf_counter_fixed::<HmacSha256Prf>(&ki, &fixed, &mut out).unwrap();
        assert_eq!(
            out,
            from_hex::<40>(
                "1da47638d6c9c4d04d74d4640bbd42ab814d9e8cc22f4326695239f96b0693f1\
                 2d0dd1152cf44430"
            )
        );
    }

    // CAVP CounterMode, [PRF=CMAC_AES128][CTRLOCATION=BEFORE_FIXED][RLEN=32], COUNT=0.
    #[test]
    fn cavp_counter_cmac_aes128_l128() {
        let ki = from_hex::<16>("c10b152e8c97b77e18704e0f0bd38305");
        let fixed = from_hex::<60>(
            "98cd4cbbbebe15d17dc86e6dbad800a2dcbd64f7c7ad0e78e9cf94ffdba89d03\
             e97eadf6c4f7b806caf52aa38f09d0eb71d71f497bcc6906b48d36c4",
        );
        let mut out = [0u8; 16]; // L = 128 bits
        kbkdf_counter_fixed::<CmacAes128Prf>(&ki, &fixed, &mut out).unwrap();
        assert_eq!(out, from_hex::<16>("26faf61908ad9ee881b8305c221db53f"));
    }

    // CAVP CounterMode, [PRF=CMAC_AES128][CTRLOCATION=BEFORE_FIXED][RLEN=32], COUNT=10.
    // L = 256 bits spans two AES-CMAC blocks.
    #[test]
    fn cavp_counter_cmac_aes128_l256_multiblock() {
        let ki = from_hex::<16>("695f1b1a16c949cea51cdf2554ec9d42");
        let fixed = from_hex::<60>(
            "4fce5942832a390aa1cbe8a0bf9d202cb799e986c9d6b51f45e4d597a6b57f06\
             a4ebfec6467335d116b7f5f9c5b954062f661820f5db2a5bbb3e0625",
        );
        let mut out = [0u8; 32]; // L = 256 bits
        kbkdf_counter_fixed::<CmacAes128Prf>(&ki, &fixed, &mut out).unwrap();
        assert_eq!(
            out,
            from_hex::<32>("d34b601ec18c34dfa0f9e0b7523e218bdddb9befe8d08b6c0202d75ace0dba89")
        );
    }

    // CAVP CounterMode, [PRF=CMAC_AES256][CTRLOCATION=BEFORE_FIXED][RLEN=32], COUNT=0.
    #[test]
    fn cavp_counter_cmac_aes256_l128() {
        let ki = from_hex::<32>("d0b1b3b70b2393c48ca05159e7e28cbeadea93f28a7cdae964e5136070c45d5c");
        let fixed = from_hex::<60>(
            "dd2f151a3f173492a6fbbb602189d51ddf8ef79fc8e96b8fcbe6dabe73a35b48\
             104f9dff2d63d48786d2b3af177091d646a9efae005bdfacb61a1214",
        );
        let mut out = [0u8; 16]; // L = 128 bits
        kbkdf_counter_fixed::<CmacAes256Prf>(&ki, &fixed, &mut out).unwrap();
        assert_eq!(out, from_hex::<16>("8c449fb474d1c1d4d2a33827103b656a"));
    }

    // CAVP FeedbackModeNOzeroiv, [PRF=HMAC_SHA256][CTRLOCATION=AFTER_ITER][RLEN=32], COUNT=0.
    // L = 512 bits, 256-bit IV. K(i) = PRF(KI, K(i-1) ‖ [i]_32 ‖ FixedInputData).
    #[test]
    fn cavp_feedback_hmac_sha256_l512() {
        let ki = from_hex::<32>("93f698e842eed75394d629d957e2e89c6e741f810b623c8b901e38376d068e7b");
        let iv = from_hex::<32>("9f575d9059d3e0c0803f08112f8a806de3c3471912cdf42b095388b14b33508e");
        let fixed = from_hex::<51>(
            "53b89c18690e2057a1d167822e636de50be0018532c431f7f5e37f77139220d5\
             e042599ebe266af5767ee18cd2c5c19a1f0f80",
        );
        let mut out = [0u8; 64]; // L = 512 bits
        kbkdf_feedback_fixed::<HmacSha256Prf>(&ki, &iv, &fixed, &mut out).unwrap();
        assert_eq!(
            out,
            from_hex::<64>(
                "bd1476f43a4e315747cf5918e0ea5bc0d98769457477c3ab18b742def0e079a9\
                 33b756365afb5541f253fee43c6fd788a44041038509e9eeb68f7d65ffbb5f95"
            )
        );
    }

    // -- Behavioural tests for the high-level (label/context) API -----------

    // The high-level counter API equals the low-level one when `fixed` is the
    // assembled `Label ‖ 0x00 ‖ Context ‖ [L]_32`.
    #[test]
    fn counter_high_level_matches_assembled_fixed() {
        let ki = b"a 32-byte-ish key-derivation key";
        let label = b"my label";
        let context = b"my context";
        let mut hi = [0u8; 48];
        kbkdf_counter::<HmacSha256Prf>(ki, label, context, &mut hi).unwrap();

        // Assemble the fixed input by hand: label ‖ 0x00 ‖ context ‖ [L]_32.
        let l_bits = (48u32 * 8).to_be_bytes();
        let mut fixed = [0u8; 8 + 1 + 10 + 4];
        fixed[..8].copy_from_slice(label);
        fixed[8] = 0x00;
        fixed[9..19].copy_from_slice(context);
        fixed[19..23].copy_from_slice(&l_bits);
        let mut lo = [0u8; 48];
        kbkdf_counter_fixed::<HmacSha256Prf>(ki, &fixed, &mut lo).unwrap();
        assert_eq!(hi, lo);
    }

    // The high-level feedback API equals the low-level one similarly.
    #[test]
    fn feedback_high_level_matches_assembled_fixed() {
        let ki = b"a 32-byte-ish key-derivation key";
        let iv = b"sixteen-byte iv!";
        let label = b"L";
        let context = b"C";
        let mut hi = [0u8; 40];
        kbkdf_feedback::<HmacSha256Prf>(ki, iv, label, context, &mut hi).unwrap();

        let l_bits = (40u32 * 8).to_be_bytes();
        let mut fixed = [0u8; 1 + 1 + 1 + 4];
        fixed[0] = b'L';
        fixed[1] = 0x00;
        fixed[2] = b'C';
        fixed[3..7].copy_from_slice(&l_bits);
        let mut lo = [0u8; 40];
        kbkdf_feedback_fixed::<HmacSha256Prf>(ki, iv, &fixed, &mut lo).unwrap();
        assert_eq!(hi, lo);
    }

    // Feedback with an empty IV is permitted (K(0) is the empty string).
    #[test]
    fn feedback_empty_iv() {
        let ki = b"key";
        let mut out = [0u8; 32];
        kbkdf_feedback::<HmacSha256Prf>(ki, &[], b"label", b"ctx", &mut out).unwrap();
        // Same as feeding an empty fixed-IV through the low-level path.
        let l_bits = (32u32 * 8).to_be_bytes();
        let mut fixed = [0u8; 5 + 1 + 3 + 4];
        fixed[..5].copy_from_slice(b"label");
        fixed[5] = 0x00;
        fixed[6..9].copy_from_slice(b"ctx");
        fixed[9..13].copy_from_slice(&l_bits);
        let mut lo = [0u8; 32];
        kbkdf_feedback_fixed::<HmacSha256Prf>(ki, &[], &fixed, &mut lo).unwrap();
        assert_eq!(out, lo);
    }

    // A partial trailing block must be a prefix of the full block output, when
    // the fixed input is held constant. (The high-level `kbkdf_counter` binds
    // the output length into `[L]_32`, so different `out.len()` deliberately
    // yield unrelated streams; the low-level `_fixed` path does not, exposing
    // the raw counter-stream prefix property.)
    #[test]
    fn partial_block_is_prefix() {
        let ki = b"prefix key";
        let fixed = b"fixed input bytes";
        let mut full = [0u8; 64];
        kbkdf_counter_fixed::<HmacSha256Prf>(ki, fixed, &mut full).unwrap();
        let mut short = [0u8; 50];
        kbkdf_counter_fixed::<HmacSha256Prf>(ki, fixed, &mut short).unwrap();
        assert_eq!(short, full[..50]);
    }

    // Zero-length output is rejected.
    #[test]
    fn zero_length_rejected() {
        let mut empty = [0u8; 0];
        assert_eq!(
            kbkdf_counter::<HmacSha256Prf>(b"k", b"l", b"c", &mut empty),
            Err(Error::ZeroLength)
        );
        assert_eq!(
            kbkdf_feedback::<HmacSha256Prf>(b"k", b"iv", b"l", b"c", &mut empty),
            Err(Error::ZeroLength)
        );
    }

    // An over-long HMAC key (> one hash block, 128B for SHA-256's 64B block via
    // the 128B stash) must not panic, and must match the pre-hashed key, because
    // HMAC itself reduces an over-long key to `D::digest(key)`.
    #[test]
    fn overlong_hmac_key_matches_prehashed() {
        use crate::hash::{Digest, Sha256};
        let long_key = [0xABu8; 200]; // > MAX_HMAC_BLOCK (128)
        let reduced = Sha256::digest(&long_key);
        let fixed = b"fixed input";

        let mut a = [0u8; 64]; // two blocks, exercises the re-key path
        let mut b = [0u8; 64];
        kbkdf_counter_fixed::<HmacSha256Prf>(&long_key, fixed, &mut a).unwrap();
        kbkdf_counter_fixed::<HmacSha256Prf>(reduced.as_ref(), fixed, &mut b).unwrap();
        assert_eq!(a, b, "over-long key must behave as its digest");
    }

    // Every PRF block must be keyed with the *same* HMAC key, for any digest —
    // including the SHA-3 family, whose block length (144 bytes for SHA3-224,
    // 136 for SHA3-256) is not the 128 bytes of SHA-2. A key between 128 and
    // `D::BLOCK_LEN` bytes is used verbatim by HMAC, so blocks 2.. must not be
    // re-keyed from a hashed copy of it.
    #[test]
    fn sha3_prf_multiblock_matches_plain_hmac() {
        use crate::hash::{Hmac, Sha3_224, Sha3_256};

        // 140 bytes: over SHA-2's 128-byte block, under SHA3-224's 144-byte one.
        let ki: [u8; 140] = core::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
        let fixed = b"fixed input data for the SHA-3 PRF";

        // Reference: K(i) = HMAC(KI, [i]_32 ‖ fixed), keyed straight from `ki`.
        fn reference<D: crate::hash::Digest>(ki: &[u8], fixed: &[u8], out: &mut [u8]) {
            let mut filled = 0;
            let mut i = 1u32;
            while filled < out.len() {
                let mut mac = Hmac::<D>::new(ki);
                mac.update(&i.to_be_bytes());
                mac.update(fixed);
                let tag = mac.finalize();
                let t = tag.as_ref();
                let take = (out.len() - filled).min(t.len());
                out[filled..filled + take].copy_from_slice(&t[..take]);
                filled += take;
                i += 1;
            }
        }

        // SHA3-224: 28-byte blocks, so 96 bytes spans four PRF blocks.
        let mut got = [0u8; 96];
        kbkdf_counter_fixed::<HmacPrf<Sha3_224>>(&ki, fixed, &mut got).unwrap();
        let mut want = [0u8; 96];
        reference::<Sha3_224>(&ki, fixed, &mut want);
        assert_eq!(got, want, "HMAC-SHA3-224 KBKDF re-keyed blocks 2.. wrongly");

        // SHA3-256 (136-byte block) with a 136-byte key: still verbatim.
        let ki136 = &ki[..136];
        let mut got = [0u8; 96];
        kbkdf_counter_fixed::<HmacPrf<Sha3_256>>(ki136, fixed, &mut got).unwrap();
        let mut want = [0u8; 96];
        reference::<Sha3_256>(ki136, fixed, &mut want);
        assert_eq!(got, want, "HMAC-SHA3-256 KBKDF re-keyed blocks 2.. wrongly");

        // Feedback mode shares the PRF, so it is covered by the same fix.
        let mut got = [0u8; 96];
        kbkdf_feedback_fixed::<HmacPrf<Sha3_224>>(&ki, b"iv", fixed, &mut got).unwrap();
        let mut want = [0u8; 96];
        {
            let mut prev: [u8; 28] = [0u8; 28];
            let mut filled = 0;
            let mut i = 1u32;
            while filled < want.len() {
                let mut mac = Hmac::<Sha3_224>::new(&ki);
                if i == 1 {
                    mac.update(b"iv");
                } else {
                    mac.update(&prev);
                }
                mac.update(&i.to_be_bytes());
                mac.update(fixed);
                let tag = mac.finalize();
                prev.copy_from_slice(tag.as_ref());
                let take = (want.len() - filled).min(prev.len());
                want[filled..filled + take].copy_from_slice(&prev[..take]);
                filled += take;
                i += 1;
            }
        }
        assert_eq!(
            got, want,
            "HMAC-SHA3-224 KBKDF feedback mode re-keyed wrongly"
        );
    }
}
