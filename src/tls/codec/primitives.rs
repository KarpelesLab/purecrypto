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

        // --- Legacy CBC suites (SSLv3 / TLS 1.0 / 1.1; `tls-legacy` only).
        // Deprecated (RFC 8996); for interop with old devices. ---
        /// TLS_RSA_WITH_3DES_EDE_CBC_SHA (static RSA, 3DES-CBC, HMAC-SHA1).
        #[allow(dead_code)]
        TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000A,
        /// TLS_RSA_WITH_AES_128_CBC_SHA (static RSA, AES-128-CBC, HMAC-SHA1).
        #[allow(dead_code)]
        TLS_RSA_WITH_AES_128_CBC_SHA = 0x002F,
        /// TLS_RSA_WITH_AES_256_CBC_SHA (static RSA, AES-256-CBC, HMAC-SHA1).
        #[allow(dead_code)]
        TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
        /// TLS_RSA_WITH_AES_128_CBC_SHA256 (static RSA, AES-128-CBC, HMAC-SHA256).
        #[allow(dead_code)]
        TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x003C,
        /// TLS_RSA_WITH_AES_256_CBC_SHA256 (static RSA, AES-256-CBC, HMAC-SHA256).
        #[allow(dead_code)]
        TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x003D,
        /// TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (ECDHE-RSA, 3DES-CBC, HMAC-SHA1).
        #[allow(dead_code)]
        TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xC012,
        /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (ECDHE-RSA, AES-128-CBC, HMAC-SHA1).
        #[allow(dead_code)]
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xC013,
        /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (ECDHE-RSA, AES-256-CBC, HMAC-SHA1).
        #[allow(dead_code)]
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xC014,
        /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 (ECDHE-RSA, AES-128-CBC, HMAC-SHA256).
        #[allow(dead_code)]
        TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = 0xC027,
        /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA256 (ECDHE-RSA, AES-256-CBC, HMAC-SHA256).
        #[allow(dead_code)]
        TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA256 = 0xC028,
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
        /// ed448 (PureEdDSA, empty context).
        ED448 = 0x0808,
        /// rsa_pss_rsae_sha256.
        RSA_PSS_RSAE_SHA256 = 0x0804,
        /// rsa_pss_rsae_sha384.
        RSA_PSS_RSAE_SHA384 = 0x0805,
        /// ml-dsa-44 (draft-ietf-tls-mldsa). The TLS 1.3 wire format for
        /// these schemes carries the raw ML-DSA signature bytes in the
        /// `CertificateVerify` body (no DER wrapping).
        #[cfg_attr(not(feature = "mldsa"), allow(dead_code))]
        MLDSA44 = 0x0904,
        /// ml-dsa-65 (draft-ietf-tls-mldsa).
        #[cfg_attr(not(feature = "mldsa"), allow(dead_code))]
        MLDSA65 = 0x0905,
        /// ml-dsa-87 (draft-ietf-tls-mldsa).
        #[cfg_attr(not(feature = "mldsa"), allow(dead_code))]
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

/// IANA `TLS Certificate Types` (RFC 7250 §3). The value is the single byte
/// carried in the `client_certificate_type` / `server_certificate_type`
/// extension lists and, on the server's reply in EncryptedExtensions, as
/// the bare selected byte.
pub(crate) mod cert_type {
    /// `X509 = 0` (RFC 7250 §3) — the default. The TLS 1.3 `Certificate`
    /// message carries DER-encoded X.509 certificates, as in RFC 8446 §4.4.2.
    pub(crate) const X509: u8 = 0;
    /// `RawPublicKey = 2` (RFC 7250 §3). The TLS 1.3 `Certificate` message
    /// carries a single CertificateEntry whose body is the bare
    /// `SubjectPublicKeyInfo` DER, with no surrounding X.509 cert and no
    /// chain. Trust is established out-of-band (a pre-provisioned key, an
    /// allowlist of accepted SPKIs, or DANE).
    pub(crate) const RAW_PUBLIC_KEY: u8 = 2;
}

u16_id!(
    /// A handshake extension type.
    ExtensionType {
        /// server_name (SNI).
        SERVER_NAME = 0x0000,
        /// status_request (OCSP stapling — RFC 6066 §8). In ClientHello, an
        /// empty-ish body (`status_type=1, responder_id_list=[], request_extensions=[]`)
        /// opts the client into stapling. In TLS 1.2 ServerHello, an empty
        /// body signals the server will staple via a subsequent
        /// `CertificateStatus` handshake message (RFC 6066). In TLS 1.3, the
        /// staple is carried as a per-certificate extension on the leaf
        /// CertificateEntry with body equal to the RFC 6066
        /// `CertificateStatus` struct (RFC 8446 §4.4.2.1).
        STATUS_REQUEST = 0x0005,
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
        /// compress_certificate (RFC 8879 §3, IANA 27 = 0x001b). TLS 1.3 only.
        /// Body: a `u8`-length list of `u16` algorithm IDs the sender can
        /// DECOMPRESS. Direction is unidirectional: in `ClientHello` it covers
        /// the SERVER's `Certificate` message; in `CertificateRequest` it
        /// covers the CLIENT's mTLS `Certificate`. When a peer chooses one of
        /// the offered algorithms, it sends a `CompressedCertificate`
        /// handshake message (type 25) in place of `Certificate`.
        #[cfg_attr(not(feature = "cert-compression"), allow(dead_code))]
        COMPRESS_CERTIFICATE = 0x001b,
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
        /// client_certificate_type (RFC 7250 §3). Negotiates the type of
        /// certificate the client will send for mTLS. In ClientHello, a
        /// `u8`-length list of certificate-type IDs the client supports;
        /// in EncryptedExtensions, the server echoes the single byte it
        /// picked. Values: `0 = X509` (the default), `2 = RawPublicKey`.
        CLIENT_CERTIFICATE_TYPE = 0x0013,
        /// server_certificate_type (RFC 7250 §3). Same wire shape as
        /// `client_certificate_type`, but negotiates the type of certificate
        /// the SERVER will send (the common case for raw public keys, e.g.
        /// IoT devices presenting a bare SPKI to clients pre-provisioned
        /// with the device's key).
        SERVER_CERTIFICATE_TYPE = 0x0014,
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
        /// encrypted_client_hello (draft-ietf-tls-esni-22 §5).
        /// Carries the HPKE-sealed inner ClientHello (in the outer CH) or
        /// the empty marker that signals "this is the inner CH"
        /// (in the inner CH). On the server side, EncryptedExtensions
        /// carries the `retry_configs` form when the server rejects ECH.
        #[cfg_attr(not(feature = "ech"), allow(dead_code))]
        ENCRYPTED_CLIENT_HELLO = 0xfe0d,
        /// ech_outer_extensions (draft-ietf-tls-esni-22 §5.1). In the
        /// inner CH only, lists outer-CH extension types that the inner
        /// CH wants to inherit verbatim; the server's decompression step
        /// substitutes the named outer extensions for this entry to
        /// reconstruct the canonical inner CH.
        #[allow(dead_code)]
        ECH_OUTER_EXTENSIONS = 0xfd00,
    }
);
