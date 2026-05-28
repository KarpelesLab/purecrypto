//! TLS wire primitives: identifiers carried as fixed-width integers.

/// The 32-byte ClientHello/ServerHello `Random`.
pub(crate) type Random = [u8; 32];

/// Defines a `u16` newtype identifier with named constants that still
/// round-trips unknown values.
macro_rules! u16_id {
    ($(#[$m:meta])* $name:ident { $($(#[$cm:meta])* $variant:ident = $value:expr),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Copy, Clone, PartialEq, Eq, Debug)]
        pub(crate) struct $name(pub u16);
        impl $name {
            $($(#[$cm])* pub(crate) const $variant: $name = $name($value);)+
        }
    };
}

u16_id!(
    /// A TLS cipher suite code.
    CipherSuite {
        /// TLS_AES_128_GCM_SHA256.
        AES_128_GCM_SHA256 = 0x1301,
        /// TLS_AES_256_GCM_SHA384.
        AES_256_GCM_SHA384 = 0x1302,
        /// TLS_CHACHA20_POLY1305_SHA256.
        CHACHA20_POLY1305_SHA256 = 0x1303,
        /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (TLS 1.2, RFC 5289).
        #[allow(dead_code)]
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xC02B,
        /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (TLS 1.2, RFC 5289).
        #[allow(dead_code)]
        TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xC02C,
        /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (TLS 1.2, RFC 5289).
        #[allow(dead_code)]
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xC02F,
        /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (TLS 1.2, RFC 5289).
        #[allow(dead_code)]
        TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xC030,
        /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 (TLS 1.2, RFC 7905).
        #[allow(dead_code)]
        TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA8,
        /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 (TLS 1.2, RFC 7905).
        #[allow(dead_code)]
        TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xCCA9,
    }
);

u16_id!(
    /// A named (EC)DHE group.
    NamedGroup {
        /// secp256r1 (NIST P-256).
        SECP256R1 = 0x0017,
        /// secp384r1 (NIST P-384). Slower than the other curves we
        /// support, so offered after X25519 and SECP256R1 by default.
        SECP384R1 = 0x0018,
        /// x25519.
        X25519 = 0x001d,
        /// X25519MLKEM768 hybrid (draft-ietf-tls-ecdhe-mlkem): ML-KEM-768
        /// combined with X25519.
        X25519MLKEM768 = 0x11ec,
    }
);

u16_id!(
    /// A signature scheme (RFC 8446 §4.2.3).
    SignatureScheme {
        /// rsa_pkcs1_sha256 (RFC 8446 §4.4.3 forbids in `CertificateVerify`,
        /// retained for the wire-level rejection check in [`Self::is_rsa_pkcs1`]).
        RSA_PKCS1_SHA256 = 0x0401,
        /// ecdsa_secp256r1_sha256.
        ECDSA_SECP256R1_SHA256 = 0x0403,
        /// rsa_pkcs1_sha384 (same rationale as `RSA_PKCS1_SHA256`).
        RSA_PKCS1_SHA384 = 0x0501,
        /// rsa_pkcs1_sha512 (same rationale).
        RSA_PKCS1_SHA512 = 0x0601,
        /// ecdsa_secp384r1_sha384.
        ECDSA_SECP384R1_SHA384 = 0x0503,
        /// ecdsa_secp521r1_sha512.
        ECDSA_SECP521R1_SHA512 = 0x0603,
        /// ed25519 (PureEdDSA).
        ED25519 = 0x0807,
        /// rsa_pss_rsae_sha256.
        RSA_PSS_RSAE_SHA256 = 0x0804,
        /// rsa_pss_rsae_sha384.
        RSA_PSS_RSAE_SHA384 = 0x0805,
        /// ml-dsa-44 (draft-ietf-tls-mldsa). The TLS 1.3 wire format for
        /// these schemes carries the raw ML-DSA signature bytes in the
        /// `CertificateVerify` body (no DER wrapping).
        MLDSA44 = 0x0904,
        /// ml-dsa-65 (draft-ietf-tls-mldsa).
        MLDSA65 = 0x0905,
        /// ml-dsa-87 (draft-ietf-tls-mldsa).
        MLDSA87 = 0x0906,
    }
);

impl SignatureScheme {
    /// Whether this scheme is one of the `rsa_pkcs1_*` family (high byte
    /// `0x04`/`0x05`/`0x06`, low byte `0x01`). RFC 8446 §4.4.3 forbids
    /// these schemes in TLS 1.3 `CertificateVerify`; they may appear only
    /// in `signature_algorithms_cert` for chain signatures.
    pub(crate) fn is_rsa_pkcs1(self) -> bool {
        matches!(
            self,
            Self::RSA_PKCS1_SHA256 | Self::RSA_PKCS1_SHA384 | Self::RSA_PKCS1_SHA512
        )
    }
}

u16_id!(
    /// A handshake extension type.
    ExtensionType {
        /// server_name (SNI).
        SERVER_NAME = 0x0000,
        /// supported_groups.
        SUPPORTED_GROUPS = 0x000a,
        /// ec_point_formats (RFC 4492 §5.1.2). TLS 1.2 ECDHE peers require
        /// this extension; we always offer/answer `uncompressed` (0).
        #[allow(dead_code)]
        EC_POINT_FORMATS = 0x000b,
        /// signature_algorithms.
        SIGNATURE_ALGORITHMS = 0x000d,
        /// application_layer_protocol_negotiation (ALPN).
        ALPN = 0x0010,
        /// record_size_limit (RFC 8449).
        RECORD_SIZE_LIMIT = 0x001c,
        /// extended_master_secret (RFC 7627). Empty-body extension that, when
        /// echoed by both peers in CH/SH, switches the TLS 1.2 master-secret
        /// derivation to `PRF(premaster, "extended master secret",
        /// session_hash)` (RFC 7627 §4) — closing the Triple Handshake
        /// attack class.
        EXTENDED_MASTER_SECRET = 0x0017,
        /// session_ticket (RFC 5077). Empty body in CH advertises ticket
        /// support; empty body in SH signals the server will issue one (and
        /// the NewSessionTicket follows in its plaintext flight); a non-empty
        /// body in CH carries the ticket the client wants to resume.
        #[allow(dead_code)]
        SESSION_TICKET = 0x0023,
        /// pre_shared_key (RFC 8446 §4.2.11).
        PRE_SHARED_KEY = 0x0029,
        /// early_data (RFC 8446 §4.2.10). Empty body in CH/EE; carries a
        /// `uint32 max_early_data_size` in NewSessionTicket.
        EARLY_DATA = 0x002a,
        /// supported_versions.
        SUPPORTED_VERSIONS = 0x002b,
        /// psk_key_exchange_modes (RFC 8446 §4.2.9). Body: a `u8`-length list
        /// of mode bytes (0 = psk_ke, 1 = psk_dhe_ke).
        PSK_KEY_EXCHANGE_MODES = 0x002d,
        /// key_share.
        KEY_SHARE = 0x0033,
        /// quic_transport_parameters (RFC 9001 §8.2 + §18 codepoint registry).
        /// Body: the opaque transport-parameter list defined by RFC 9000 §18,
        /// carried verbatim in TLS — the TLS engine treats it as a byte blob
        /// and delegates encoding/decoding to the QUIC layer via `QuicHooks`.
        QUIC_TRANSPORT_PARAMETERS = 0x0039,
        /// renegotiation_info (RFC 5746). In TLS 1.2 ClientHello/ServerHello,
        /// an empty body advertises support for secure renegotiation. We
        /// never actually renegotiate; we only emit/expect the empty form.
        #[allow(dead_code)]
        RENEGOTIATION_INFO = 0xff01,
        /// CRL stapling, a purecrypto private/experimental extension carried
        /// as a per-certificate extension in the TLS 1.3 `Certificate` message
        /// (RFC 8446 §4.4.2). Body: a DER-encoded RFC 5280 `CertificateList`
        /// (CRL). The unassigned IANA code point `0xFE10` is used.
        CRL_RESPONSE = 0xfe10,
    }
);
