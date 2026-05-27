//! TLS protocol version and record content type.
//!
//! [`ProtocolVersion`] is the wire-level discriminant the record and
//! handshake layers branch on. Versions implemented in this crate:
//! TLS 1.2 (RFC 5246, AEAD-only suites per RFC 7905), TLS 1.3
//! (RFC 8446), DTLS 1.2 (RFC 6347), DTLS 1.3 (RFC 9147). QUIC v1
//! (RFC 9000 / 9001) lives in `crate::quic` and reuses the TLS 1.3
//! engine through `tls::quic_hooks`.

/// A TLS protocol version, as carried on the wire (a `u16`).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ProtocolVersion {
    /// SSL 3.0 (0x0300).
    SSLv3,
    /// TLS 1.0 (0x0301).
    TLSv1_0,
    /// TLS 1.1 (0x0302).
    TLSv1_1,
    /// TLS 1.2 (0x0303).
    TLSv1_2,
    /// TLS 1.3 (0x0304).
    TLSv1_3,
    /// DTLS 1.0 (0xfeff). Listed for completeness; not implemented.
    DTLSv1_0,
    /// DTLS 1.2 (0xfefd). RFC 6347.
    DTLSv1_2,
    /// DTLS 1.3 (0xfefc). RFC 9147.
    DTLSv1_3,
    /// An unrecognized version code.
    Unknown(u16),
}

impl ProtocolVersion {
    /// The 16-bit wire encoding.
    pub fn as_u16(self) -> u16 {
        match self {
            ProtocolVersion::SSLv3 => 0x0300,
            ProtocolVersion::TLSv1_0 => 0x0301,
            ProtocolVersion::TLSv1_1 => 0x0302,
            ProtocolVersion::TLSv1_2 => 0x0303,
            ProtocolVersion::TLSv1_3 => 0x0304,
            ProtocolVersion::DTLSv1_0 => 0xfeff,
            ProtocolVersion::DTLSv1_2 => 0xfefd,
            ProtocolVersion::DTLSv1_3 => 0xfefc,
            ProtocolVersion::Unknown(v) => v,
        }
    }

    /// Decodes a 16-bit version code.
    pub fn from_u16(v: u16) -> Self {
        match v {
            0x0300 => ProtocolVersion::SSLv3,
            0x0301 => ProtocolVersion::TLSv1_0,
            0x0302 => ProtocolVersion::TLSv1_1,
            0x0303 => ProtocolVersion::TLSv1_2,
            0x0304 => ProtocolVersion::TLSv1_3,
            0xfeff => ProtocolVersion::DTLSv1_0,
            0xfefd => ProtocolVersion::DTLSv1_2,
            0xfefc => ProtocolVersion::DTLSv1_3,
            other => ProtocolVersion::Unknown(other),
        }
    }
}

/// A TLS record content type (the first byte of a record).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum ContentType {
    /// `change_cipher_spec` (20) — ignored in TLS 1.3 (middlebox compat).
    ChangeCipherSpec,
    /// `alert` (21).
    Alert,
    /// `handshake` (22).
    Handshake,
    /// `application_data` (23) — also the outer type of all encrypted records.
    ApplicationData,
    /// An unrecognized content type.
    Unknown(u8),
}

impl ContentType {
    /// The 8-bit wire encoding.
    pub fn as_u8(self) -> u8 {
        match self {
            ContentType::ChangeCipherSpec => 20,
            ContentType::Alert => 21,
            ContentType::Handshake => 22,
            ContentType::ApplicationData => 23,
            ContentType::Unknown(v) => v,
        }
    }

    /// Decodes an 8-bit content type.
    pub fn from_u8(v: u8) -> Self {
        match v {
            20 => ContentType::ChangeCipherSpec,
            21 => ContentType::Alert,
            22 => ContentType::Handshake,
            23 => ContentType::ApplicationData,
            other => ContentType::Unknown(other),
        }
    }
}
