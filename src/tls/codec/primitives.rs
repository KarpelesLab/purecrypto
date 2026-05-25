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
    }
);

u16_id!(
    /// A named (EC)DHE group.
    NamedGroup {
        /// secp256r1 (NIST P-256).
        SECP256R1 = 0x0017,
        /// x25519.
        X25519 = 0x001d,
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
        /// rsa_pss_rsae_sha256.
        RSA_PSS_RSAE_SHA256 = 0x0804,
        /// rsa_pss_rsae_sha384.
        RSA_PSS_RSAE_SHA384 = 0x0805,
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
        /// supported_versions.
        SUPPORTED_VERSIONS = 0x002b,
        /// key_share.
        KEY_SHARE = 0x0033,
    }
);
