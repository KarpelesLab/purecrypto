//! HPKE setup wrappers for ECH.
//!
//! ECH uses HPKE Base mode with a specific `info` string (draft §6.1):
//! `"tls ech" || 0x00 || ECHConfig`. We provide thin wrappers around
//! [`crate::hpke::setup_sender`] / [`crate::hpke::setup_receiver`]
//! that build the info string and translate HPKE errors into
//! [`crate::tls::Error::EchDecryptionFailed`] (the public surface
//! shouldn't leak HPKE internals).

use super::config::{EchConfig, HpkeSymCipherSuite};
use crate::hpke::{
    self, CipherSuite as HpkeCipherSuite, HpkeAead, HpkeKdf, HpkeKem, ReceiverContext,
    SenderContext,
};
use crate::rng::RngCore;
use crate::tls::Error;
use alloc::vec::Vec;

/// The fixed ECH info prefix (draft §6.1): `"tls ech" || 0x00`.
const INFO_PREFIX: &[u8] = b"tls ech\0";

/// Build the HPKE `info` string for an ECH seal/open: `INFO_PREFIX
/// || ECHConfig` (with `ECHConfig` being the full single-config wire
/// form: version || u16 length || contents).
///
/// Returns [`Error::EchDecodeError`] if `config.raw_contents` is longer
/// than `u16::MAX` bytes — the draft-22 wire length is a `u16`, and
/// silently clamping at 65535 would produce an `info` string that does
/// not match the receiver's reconstruction (the HPKE seal then "fails"
/// with no diagnostic). In practice ECH configs are a few hundred bytes
/// (HPKE public key + cipher suites + public_name<1..255> + a small
/// extension list), so this is unreachable for any well-formed local
/// config.
pub(crate) fn ech_info(config: &EchConfig) -> Result<Vec<u8>, Error> {
    let len = u16::try_from(config.raw_contents.len()).map_err(|_| Error::EchDecodeError)?;
    let mut out = Vec::with_capacity(INFO_PREFIX.len() + 4 + config.raw_contents.len());
    out.extend_from_slice(INFO_PREFIX);
    out.extend_from_slice(&config.version.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&config.raw_contents);
    Ok(out)
}

/// Map an [`HpkeSymCipherSuite`] to typed `(HpkeKdf, HpkeAead)`,
/// rejecting unsupported ids.
pub(crate) fn map_sym_suite(sc: HpkeSymCipherSuite) -> Result<(HpkeKdf, HpkeAead), Error> {
    let kdf = match sc.kdf_id {
        0x0001 => HpkeKdf::HkdfSha256,
        0x0002 => HpkeKdf::HkdfSha384,
        0x0003 => HpkeKdf::HkdfSha512,
        _ => return Err(Error::EchDecodeError),
    };
    let aead = match sc.aead_id {
        0x0001 => HpkeAead::Aes128Gcm,
        0x0002 => HpkeAead::Aes256Gcm,
        0x0003 => HpkeAead::ChaCha20Poly1305,
        // ExportOnly (0xFFFF) is not useful for sealing CHs — reject.
        _ => return Err(Error::EchDecodeError),
    };
    Ok((kdf, aead))
}

/// Map a wire `kem_id` to a typed [`HpkeKem`].
pub(crate) fn map_kem(kem_id: u16) -> Result<HpkeKem, Error> {
    match kem_id {
        0x0010 => Ok(HpkeKem::DhkemP256HkdfSha256),
        0x0011 => Ok(HpkeKem::DhkemP384HkdfSha384),
        0x0012 => Ok(HpkeKem::DhkemP521HkdfSha512),
        0x0020 => Ok(HpkeKem::DhkemX25519HkdfSha256),
        _ => Err(Error::EchDecodeError),
    }
}

/// Client-side `SetupBaseS` for ECH: returns `(enc, sender_context)`.
/// `sym` selects the symmetric suite the outer CH advertises;
/// `config` provides the recipient public key and the ECH info string.
pub(crate) fn setup_sender<R: RngCore>(
    rng: &mut R,
    config: &EchConfig,
    sym: HpkeSymCipherSuite,
) -> Result<(Vec<u8>, SenderContext, HpkeCipherSuite), Error> {
    let contents = config.contents.as_ref().ok_or(Error::EchDecodeError)?;
    let kem = map_kem(contents.key_config.kem_id)?;
    let (kdf, aead) = map_sym_suite(sym)?;
    let suite = HpkeCipherSuite::new(kem, kdf, aead);
    let info = ech_info(config)?;
    let (enc, ctx) = hpke::setup_sender(rng, suite, &contents.key_config.public_key, &info)
        .map_err(|_| Error::EchDecryptionFailed)?;
    Ok((enc, ctx, suite))
}

/// Server-side `SetupBaseR` for ECH.
pub(crate) fn setup_receiver(
    config: &EchConfig,
    sk_r: &[u8],
    enc: &[u8],
    sym: HpkeSymCipherSuite,
) -> Result<(ReceiverContext, HpkeCipherSuite), Error> {
    let contents = config.contents.as_ref().ok_or(Error::EchDecodeError)?;
    let kem = map_kem(contents.key_config.kem_id)?;
    let (kdf, aead) = map_sym_suite(sym)?;
    let suite = HpkeCipherSuite::new(kem, kdf, aead);
    let info = ech_info(config)?;
    let ctx =
        hpke::setup_receiver(suite, enc, sk_r, &info).map_err(|_| Error::EchDecryptionFailed)?;
    Ok((ctx, suite))
}
