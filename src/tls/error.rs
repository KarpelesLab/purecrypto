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
    /// `record_overflow` (22) — RFC 8446 §6: ciphertext > `2^14 + 256` or
    /// post-decrypt plaintext > `2^14` bytes.
    RecordOverflow,
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
    /// `certificate_required` (116) — RFC 8446 §6: server demanded a client
    /// certificate but the client offered none.
    CertificateRequired,
    /// `user_canceled` (90) — RFC 5246 §7.2.1: a warning-level peer notice
    /// indicating no protocol failure, just user-initiated close. In TLS
    /// 1.2 this is non-fatal; TLS 1.3 §6 elides the warning/fatal split.
    UserCanceled,
    /// `no_renegotiation` (100) — RFC 5246 §7.2.1: a warning-level peer
    /// notice that a renegotiation request was refused. Non-fatal.
    NoRenegotiation,
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
            AlertDescription::RecordOverflow => 22,
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
            AlertDescription::CertificateRequired => 116,
            AlertDescription::UserCanceled => 90,
            AlertDescription::NoRenegotiation => 100,
            AlertDescription::Unknown(v) => v,
        }
    }

    /// Decodes an 8-bit alert code.
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => AlertDescription::CloseNotify,
            10 => AlertDescription::UnexpectedMessage,
            20 => AlertDescription::BadRecordMac,
            22 => AlertDescription::RecordOverflow,
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
            116 => AlertDescription::CertificateRequired,
            90 => AlertDescription::UserCanceled,
            100 => AlertDescription::NoRenegotiation,
            other => AlertDescription::Unknown(other),
        }
    }
}

/// Errors produced by the TLS state machine.
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
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
    /// The peer supplied a syntactically valid value that is forbidden by the
    /// spec (e.g. an unknown `KeyUpdate` request byte). Maps to
    /// `illegal_parameter`.
    IllegalParameter,
    /// A record's plaintext exceeded `2^14` bytes (RFC 8446 §5.1) or its
    /// ciphertext exceeded `2^14 + 256` bytes (RFC 8446 §5.2). Maps to
    /// `record_overflow`.
    RecordOverflow,
    /// The per-key record-sequence cap has been reached without a `KeyUpdate`.
    /// Maps to `internal_error`; the connection should rekey before continuing.
    TooManyRecords,
    /// The peer's ALPN list contains nothing acceptable. Maps to
    /// `no_application_protocol` (RFC 7301).
    NoApplicationProtocol,
    /// A PSK binder failed to verify, or another signed handshake-context
    /// authenticator was invalid. Maps to `decrypt_error` (RFC 8446 §6).
    DecryptError,
    /// Server required a client certificate but the client did not present
    /// one. Maps to `certificate_required`.
    CertificateRequired,
    /// A stapled OCSP response (RFC 6066 + RFC 6960) reports the peer's
    /// certificate as `revoked`. Maps to `bad_certificate`.
    CertificateRevoked,
    /// A stapled OCSP response is malformed, signed by an unrecognised
    /// authority, outside its validity window, or reports `unknown` for the
    /// leaf certificate. Maps to `bad_certificate` — the staple cannot be
    /// trusted, so the chain cannot be admitted under stapling.
    OcspResponseInvalid,
    /// The server rejected Encrypted Client Hello: the inner CH was not
    /// accepted, the outer-CH handshake completed with the public-name
    /// certificate, and `EncryptedExtensions` carries an
    /// `ECHConfigList` whose contents are returned here for the
    /// caller to retry with. Maps to `ech_required` (draft §11.2).
    #[cfg(feature = "ech")]
    EchRejected(alloc::vec::Vec<u8>),
    /// An ECH wire structure (extension body, ECHConfig list, retry
    /// configs, inner CH) is malformed or violates a draft constraint
    /// (unknown version, payload longer than HpkeSymmetricCipherSuite
    /// limits, etc.). Maps to `illegal_parameter`.
    #[cfg(feature = "ech")]
    EchDecodeError,
    /// HPKE seal/open in the ECH envelope failed, or the inner CH that
    /// emerged from decryption did not parse as a ClientHello, or its
    /// HRR confirmation signal was wrong. Maps to `decrypt_error`.
    #[cfg(feature = "ech")]
    EchDecryptionFailed,
    /// A `CompressedCertificate` handshake message (RFC 8879 §4) could not
    /// be expanded: the declared `algorithm` is one the receiver does not
    /// support, the compressed body is malformed, decompression aborted
    /// mid-stream, or the produced byte count does not match the declared
    /// `uncompressed_length`. Maps to `bad_certificate` per §4 ("If the
    /// received CompressedCertificate message cannot be decompressed, the
    /// connection MUST be terminated with the bad_certificate alert").
    #[cfg(feature = "cert-compression")]
    CertDecompressionFailed,
    /// A client `Config` was passed to [`crate::tls::Connection::client`]
    /// without a `server_name`. The reference identifier is required both
    /// for the outbound SNI extension (RFC 6066 §3) and as the verification
    /// reference for the peer certificate's SANs (RFC 6125 §6.4), so we
    /// fail-closed at construction rather than silently substituting a
    /// default like `"localhost"` (which would misdirect hostname
    /// verification and surface as an opaque `BadCertificate` later).
    MissingServerName,
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
            Error::IllegalParameter => f.write_str("TLS illegal parameter"),
            Error::RecordOverflow => f.write_str("TLS record-size limit exceeded"),
            Error::TooManyRecords => f.write_str("per-key record-sequence cap reached"),
            Error::NoApplicationProtocol => f.write_str("no ALPN overlap with peer"),
            Error::DecryptError => f.write_str("TLS handshake decrypt error (binder/MAC)"),
            Error::CertificateRequired => f.write_str("server required a client certificate"),
            Error::CertificateRevoked => f.write_str("peer certificate revoked (stapled OCSP)"),
            Error::OcspResponseInvalid => f.write_str("stapled OCSP response invalid"),
            #[cfg(feature = "ech")]
            Error::EchRejected(_) => f.write_str("ECH rejected; retry_configs available"),
            #[cfg(feature = "ech")]
            Error::EchDecodeError => f.write_str("ECH wire structure malformed"),
            #[cfg(feature = "ech")]
            Error::EchDecryptionFailed => f.write_str("ECH HPKE seal/open failed"),
            #[cfg(feature = "cert-compression")]
            Error::CertDecompressionFailed => {
                f.write_str("RFC 8879 CompressedCertificate could not be decompressed")
            }
            Error::MissingServerName => {
                f.write_str("client Config has no server_name (SNI / verify reference)")
            }
        }
    }
}

impl core::error::Error for Error {}
