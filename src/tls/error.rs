//! TLS errors and alerts.

/// A TLS alert: a severity-less description code plus a `fatal` flag.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Alert {
    /// Whether the alert is fatal (level 2) rather than a warning (level 1).
    pub fatal: bool,
    /// The alert description.
    pub description: AlertDescription,
}

/// TLS alert description codes (RFC 8446 §6).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AlertDescription {
    /// `close_notify` (0).
    CloseNotify,
    /// `unexpected_message` (10).
    UnexpectedMessage,
    /// `bad_record_mac` (20).
    BadRecordMac,
    /// `handshake_failure` (40).
    HandshakeFailure,
    /// `bad_certificate` (42).
    BadCertificate,
    /// `unsupported_certificate` (43).
    UnsupportedCertificate,
    /// `certificate_expired` (45).
    CertificateExpired,
    /// `certificate_unknown` (46).
    CertificateUnknown,
    /// `illegal_parameter` (47).
    IllegalParameter,
    /// `decode_error` (50).
    DecodeError,
    /// `decrypt_error` (51).
    DecryptError,
    /// `protocol_version` (70).
    ProtocolVersion,
    /// `internal_error` (80).
    InternalError,
    /// `missing_extension` (109).
    MissingExtension,
    /// `unsupported_extension` (110).
    UnsupportedExtension,
    /// `unrecognized_name` (112).
    UnrecognizedName,
    /// `no_application_protocol` (120).
    NoApplicationProtocol,
    /// An unrecognized alert code.
    Unknown(u8),
}

impl AlertDescription {
    /// The 8-bit wire encoding.
    pub fn as_u8(self) -> u8 {
        match self {
            AlertDescription::CloseNotify => 0,
            AlertDescription::UnexpectedMessage => 10,
            AlertDescription::BadRecordMac => 20,
            AlertDescription::HandshakeFailure => 40,
            AlertDescription::BadCertificate => 42,
            AlertDescription::UnsupportedCertificate => 43,
            AlertDescription::CertificateExpired => 45,
            AlertDescription::CertificateUnknown => 46,
            AlertDescription::IllegalParameter => 47,
            AlertDescription::DecodeError => 50,
            AlertDescription::DecryptError => 51,
            AlertDescription::ProtocolVersion => 70,
            AlertDescription::InternalError => 80,
            AlertDescription::MissingExtension => 109,
            AlertDescription::UnsupportedExtension => 110,
            AlertDescription::UnrecognizedName => 112,
            AlertDescription::NoApplicationProtocol => 120,
            AlertDescription::Unknown(v) => v,
        }
    }

    /// Decodes an 8-bit alert code.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            20 => AlertDescription::BadRecordMac,
            40 => AlertDescription::HandshakeFailure,
            42 => AlertDescription::BadCertificate,
            43 => AlertDescription::UnsupportedCertificate,
            45 => AlertDescription::CertificateExpired,
            46 => AlertDescription::CertificateUnknown,
            47 => AlertDescription::IllegalParameter,
            50 => AlertDescription::DecodeError,
            51 => AlertDescription::DecryptError,
            70 => AlertDescription::ProtocolVersion,
            80 => AlertDescription::InternalError,
            109 => AlertDescription::MissingExtension,
            110 => AlertDescription::UnsupportedExtension,
            112 => AlertDescription::UnrecognizedName,
            120 => AlertDescription::NoApplicationProtocol,
            other => AlertDescription::Unknown(other),
        }
    }
}

/// Errors produced by the TLS state machine.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Error {
    /// A message could not be decoded (maps to `decode_error`).
    Decode,
    /// A message arrived out of sequence (maps to `unexpected_message`).
    UnexpectedMessage,
    /// Record decryption / AEAD authentication failed (`bad_record_mac`).
    BadRecordMac,
    /// The peer offered no acceptable parameters (`handshake_failure`).
    HandshakeFailure,
    /// The negotiated/offered version is unsupported.
    UnsupportedVersion,
    /// The peer's certificate could not be validated.
    BadCertificate,
    /// A signature (CertificateVerify or chain) failed to verify.
    PeerMisbehaved,
    /// A fatal alert was received from the peer.
    AlertReceived(AlertDescription),
    /// Misuse of the API (e.g. writing before the handshake completes).
    InappropriateState,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Decode => f.write_str("TLS decode error"),
            Error::UnexpectedMessage => f.write_str("unexpected TLS message"),
            Error::BadRecordMac => f.write_str("TLS record authentication failed"),
            Error::HandshakeFailure => f.write_str("TLS handshake failure"),
            Error::UnsupportedVersion => f.write_str("unsupported TLS version"),
            Error::BadCertificate => f.write_str("invalid certificate"),
            Error::PeerMisbehaved => f.write_str("peer misbehaved (bad signature)"),
            Error::AlertReceived(a) => write!(f, "received fatal alert: {a:?}"),
            Error::InappropriateState => f.write_str("operation not valid in this state"),
        }
    }
}

impl core::error::Error for Error {}
