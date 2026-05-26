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
        /// rsa_pkcs1_sha256.
        RSA_PKCS1_SHA256 = 0x0401,
        /// ecdsa_secp256r1_sha256.
        ECDSA_SECP256R1_SHA256 = 0x0403,
        /// rsa_pkcs1_sha384.
        RSA_PKCS1_SHA384 = 0x0501,
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

u16_id!(
    /// A handshake extension type.
    ExtensionType {
        /// server_name (SNI).
        SERVER_NAME = 0x0000,
        /// supported_groups.
        SUPPORTED_GROUPS = 0x000a,
        /// signature_algorithms.
        SIGNATURE_ALGORITHMS = 0x000d,
        /// application_layer_protocol_negotiation (ALPN).
        ALPN = 0x0010,
        /// record_size_limit (RFC 8449).
        RECORD_SIZE_LIMIT = 0x001c,
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
    }
);
