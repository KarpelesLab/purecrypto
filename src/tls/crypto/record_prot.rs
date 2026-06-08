//! Record-protection dispatch for the TLS 1.x state machines.
//!
//! The TLS 1.2 server/client connections protect post-handshake records with
//! an AEAD ([`RecordCrypter12`]). The opt-in legacy path (`tls-legacy`,
//! TLS 1.0/1.1) instead uses a MAC-then-encrypt CBC crypter
//! ([`CbcRecordCrypter`]). Both present the same "encrypt a fragment / decrypt
//! a fragment given the 5-byte record header" shape, so the connections hold a
//! single [`RecordProtection`] and let it dispatch on the negotiated cipher.
//!
//! For the AEAD arm the protocol version is irrelevant (the nonce/AAD encode
//! the sequence number, not the record version); for the CBC arm the version
//! is part of the MAC input and the record-framing version, so the connection
//! threads its negotiated version through [`RecordProtection::encrypt`] and the
//! decrypt path recovers it from the record header.

use super::aead12::RecordCrypter12;
#[cfg(feature = "tls-legacy")]
use super::cbc_rec::CbcRecordCrypter;
use crate::tls::{ContentType, Error, ProtocolVersion};
use alloc::boxed::Box;
use alloc::vec::Vec;

/// Post-handshake record protection for a single direction.
///
/// Both arms are boxed to keep the enum pointer-sized: the AEAD and CBC crypter
/// states differ greatly in size, and an unboxed two-variant enum would carry
/// the larger footprint everywhere (and trip `clippy::large_enum_variant`).
pub(crate) enum RecordProtection {
    /// TLS 1.2 AEAD (AES-GCM / ChaCha20-Poly1305).
    Aead(Box<RecordCrypter12>),
    /// Legacy TLS 1.0/1.1 CBC MAC-then-encrypt (opt-in).
    #[cfg(feature = "tls-legacy")]
    Cbc(Box<CbcRecordCrypter>),
}

impl RecordProtection {
    /// Encrypts `payload` (already at most one plaintext fragment) into a
    /// record fragment. `version` is the negotiated protocol version; it is
    /// ignored by the AEAD arm and used as the CBC MAC's version field.
    pub(crate) fn encrypt(
        &mut self,
        ct: ContentType,
        #[cfg_attr(not(feature = "tls-legacy"), allow(unused_variables))] version: ProtocolVersion,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match self {
            RecordProtection::Aead(c) => c.encrypt(ct, payload),
            #[cfg(feature = "tls-legacy")]
            RecordProtection::Cbc(c) => Ok(c.encrypt(ct, version, payload)),
        }
    }

    /// Decrypts one record fragment given its 5-byte `record_header`. Returns
    /// the record's content type and the recovered plaintext. The CBC arm
    /// recovers the content type and version it needs for MAC verification from
    /// the header.
    pub(crate) fn decrypt(
        &mut self,
        record_header: &[u8; 5],
        fragment: &[u8],
    ) -> Result<(ContentType, Vec<u8>), Error> {
        match self {
            RecordProtection::Aead(c) => c.decrypt(record_header, fragment),
            #[cfg(feature = "tls-legacy")]
            RecordProtection::Cbc(c) => {
                let ct = ContentType::from_u8(record_header[0]);
                let version = ProtocolVersion::from_u16(u16::from_be_bytes([
                    record_header[1],
                    record_header[2],
                ]));
                let plain = c.decrypt(ct, version, fragment)?;
                Ok((ct, plain))
            }
        }
    }
}

impl From<RecordCrypter12> for RecordProtection {
    fn from(c: RecordCrypter12) -> Self {
        RecordProtection::Aead(Box::new(c))
    }
}

#[cfg(feature = "tls-legacy")]
impl From<CbcRecordCrypter> for RecordProtection {
    fn from(c: CbcRecordCrypter) -> Self {
        RecordProtection::Cbc(Box::new(c))
    }
}
