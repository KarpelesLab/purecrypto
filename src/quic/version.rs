//! QUIC versions — v1 (RFC 9000) and v2 (RFC 9369) — and everything that
//! differs between them.
//!
//! RFC 9369 §3 lists the complete set of differences between the two
//! versions; everything else in the stack is shared:
//!
//! * the long-header Version field (§3.1): `0x00000001` vs `0x6b3343cf`;
//! * the two-bit Long Packet Type code points (§3.2), permuted in v2 so an
//!   observer that hard-codes the v1 table misreads every v2 packet;
//! * the Initial salt (§3.3.1);
//! * the HKDF-Expand-Label labels for packet-protection keys, header
//!   protection and key update (§3.3.2): `quic key` → `quicv2 key`, …;
//! * the Retry Integrity Tag key and nonce (§3.3.3).
//!
//! [`QuicVersion`] carries each of those as a method so the codec and the
//! key schedule never branch on a raw version number, and so a third
//! version would be one more variant rather than one more `if`. RFC 9368
//! (compatible version negotiation) and the [`crate::quic::QuicConnection`]
//! state machine decide *which* version a connection uses; this module only
//! says what each version looks like on the wire.

use super::pkt::LongType;

/// A QUIC version this stack speaks.
///
/// Configure the set a connection may use with
/// [`QuicConfig::versions`](crate::quic::QuicConfig::versions) and read the
/// outcome of version negotiation back with
/// [`QuicConnection::version`](crate::quic::QuicConnection::version).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum QuicVersion {
    /// QUIC version 1, RFC 9000 (`0x00000001`).
    V1,
    /// QUIC version 2, RFC 9369 (`0x6b3343cf`).
    V2,
}

/// The versions this stack implements, oldest first — the default for
/// [`QuicConfig::versions`](crate::quic::QuicConfig::versions) and the set
/// a [`QuicServer`](crate::quic::QuicServer) offers by default.
pub const SUPPORTED_VERSIONS: [QuicVersion; 2] = [QuicVersion::V1, QuicVersion::V2];

impl QuicVersion {
    /// The wire value of the long-header Version field (RFC 8999 §5.1).
    pub const fn wire(self) -> u32 {
        match self {
            Self::V1 => 0x0000_0001,
            Self::V2 => 0x6b33_43cf,
        }
    }

    /// Maps a long-header Version field to a version this stack speaks.
    /// `None` for anything else, including `0` (Version Negotiation) and
    /// the reserved `0x?a?a?a?a` values (see [`Self::is_reserved`]).
    pub const fn from_wire(v: u32) -> Option<Self> {
        match v {
            0x0000_0001 => Some(Self::V1),
            0x6b33_43cf => Some(Self::V2),
            _ => None,
        }
    }

    /// RFC 9000 §15 — `0x?a?a?a?a` versions are reserved to exercise
    /// version negotiation ("GREASE"): an endpoint may list them but must
    /// never select one.
    pub const fn is_reserved(v: u32) -> bool {
        v & 0x0f0f_0f0f == 0x0a0a_0a0a
    }

    /// RFC 9369 §4: version 1 and version 2 are compatible with each other in
    /// the sense of RFC 9368 §2.2 — a first flight of either can be taken as
    /// a first flight of the other — so a server may switch a connection
    /// between them without a round trip (RFC 9368 §2.3). No other
    /// compatibility is defined; RFC 9368 §2.2 forbids assuming any.
    pub const fn is_compatible_with(self, other: Self) -> bool {
        matches!(
            (self, other),
            (Self::V1, Self::V1)
                | (Self::V1, Self::V2)
                | (Self::V2, Self::V1)
                | (Self::V2, Self::V2)
        )
    }

    /// The salt HKDF-Extract mixes with the client's Destination Connection
    /// ID to produce the Initial secret: RFC 9001 §5.2 for v1, RFC 9369
    /// §3.3.1 for v2.
    pub(crate) const fn initial_salt(self) -> &'static [u8; 20] {
        match self {
            Self::V1 => &INITIAL_SALT_V1,
            Self::V2 => &INITIAL_SALT_V2,
        }
    }

    /// HKDF-Expand-Label label for the AEAD key (RFC 9001 §5.1 / RFC 9369
    /// §3.3.2).
    pub(crate) const fn label_key(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic key",
            Self::V2 => b"quicv2 key",
        }
    }

    /// HKDF-Expand-Label label for the AEAD IV.
    pub(crate) const fn label_iv(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic iv",
            Self::V2 => b"quicv2 iv",
        }
    }

    /// HKDF-Expand-Label label for the header-protection key (RFC 9001
    /// §5.4 / RFC 9369 §3.3.2).
    pub(crate) const fn label_hp(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic hp",
            Self::V2 => b"quicv2 hp",
        }
    }

    /// HKDF-Expand-Label label for the key-update secret (RFC 9001 §6.1 /
    /// RFC 9369 §3.3.2).
    pub(crate) const fn label_ku(self) -> &'static [u8] {
        match self {
            Self::V1 => b"quic ku",
            Self::V2 => b"quicv2 ku",
        }
    }

    /// The fixed AES-128-GCM key of the Retry Integrity Tag (RFC 9001 §5.8 /
    /// RFC 9369 §3.3.3).
    pub(crate) const fn retry_integrity_key(self) -> &'static [u8; 16] {
        match self {
            Self::V1 => &RETRY_INTEGRITY_KEY_V1,
            Self::V2 => &RETRY_INTEGRITY_KEY_V2,
        }
    }

    /// The fixed nonce of the Retry Integrity Tag.
    pub(crate) const fn retry_integrity_nonce(self) -> &'static [u8; 12] {
        match self {
            Self::V1 => &RETRY_INTEGRITY_NONCE_V1,
            Self::V2 => &RETRY_INTEGRITY_NONCE_V2,
        }
    }

    /// The two-bit Long Packet Type code point of `typ` (RFC 9000 §17.2
    /// Table 5 for v1; RFC 9369 §3.2 for v2), in the low two bits.
    pub(crate) const fn long_type_bits(self, typ: LongType) -> u8 {
        match (self, typ) {
            (Self::V1, LongType::Initial) => 0b00,
            (Self::V1, LongType::ZeroRtt) => 0b01,
            (Self::V1, LongType::Handshake) => 0b10,
            (Self::V1, LongType::Retry) => 0b11,
            (Self::V2, LongType::Initial) => 0b01,
            (Self::V2, LongType::ZeroRtt) => 0b10,
            (Self::V2, LongType::Handshake) => 0b11,
            (Self::V2, LongType::Retry) => 0b00,
        }
    }

    /// The inverse of [`Self::long_type_bits`]: the packet type a two-bit
    /// code point (low two bits of `bits`) names in this version.
    pub(crate) const fn long_type_from_bits(self, bits: u8) -> LongType {
        match (self, bits & 0b11) {
            (Self::V1, 0b00) | (Self::V2, 0b01) => LongType::Initial,
            (Self::V1, 0b01) | (Self::V2, 0b10) => LongType::ZeroRtt,
            (Self::V1, 0b10) | (Self::V2, 0b11) => LongType::Handshake,
            _ => LongType::Retry,
        }
    }
}

impl core::fmt::Display for QuicVersion {
    /// `v1` / `v2` — the spelling the CLI's `-quic_versions` flag takes.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::V1 => "v1",
            Self::V2 => "v2",
        })
    }
}

/// Why a peer's `version_information` (RFC 9368 §3) was refused, mapped to
/// the two transport error codes §4 prescribes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum VersionError {
    /// A §4 parsing failure: `TRANSPORT_PARAMETER_ERROR`.
    Malformed,
    /// A §4 negotiation failure — the peer chose a version it could not
    /// have, or a downgrade was detected: `VERSION_NEGOTIATION_ERROR`
    /// (0x11, §10.2).
    Negotiation,
}

/// The first of `prefs` (in preference order) that `offered` lists, or
/// `None`. Reserved `0x?a?a?a?a` entries in `offered` never match, since
/// `prefs` holds real versions only. This is the client's choice from a
/// Version Negotiation packet (RFC 9368 §2.1) and the reference choice of
/// the §4 downgrade check.
pub(crate) fn choose_version(prefs: &[QuicVersion], offered: &[u32]) -> Option<QuicVersion> {
    prefs.iter().copied().find(|v| offered.contains(&v.wire()))
}

/// The server's half of RFC 9368 — validates the client's Version
/// Information and performs compatible version negotiation (§2.3, §4).
///
/// `ours` is the server's acceptable versions in preference order; `in_use`
/// is the version of the long header that carried the client's first
/// flight; `client` is the client's `version_information`, if it sent one.
///
/// * No Version Information: "Servers MAY complete the handshake even if
///   the Version Information is missing" — the connection stays in `in_use`.
/// * The client's Chosen Version MUST equal the version in use, else a
///   version negotiation error (§4: "the server MUST validate that the
///   client's Chosen Version matches the version in use for the
///   connection").
/// * The Chosen Version MUST appear in Available Versions, else a parsing
///   failure (§4).
/// * Otherwise the Negotiated Version is the first of `ours` that the
///   client offered and that the client's Chosen Version is compatible
///   with (§2.3: the server "MUST select one of these versions that it (1)
///   supports and (2) knows the client's Chosen Version is compatible
///   with"). The client's own order is advisory only (§3), so the server's
///   preference decides; `in_use` itself is always a candidate.
pub(crate) fn select_server_version(
    ours: &[QuicVersion],
    in_use: QuicVersion,
    client: Option<&super::transport_params::VersionInformation>,
) -> Result<QuicVersion, VersionError> {
    let Some(vi) = client else {
        return Ok(in_use);
    };
    if vi.chosen != in_use.wire() {
        return Err(VersionError::Negotiation);
    }
    if !vi.available.contains(&vi.chosen) {
        return Err(VersionError::Malformed);
    }
    Ok(ours
        .iter()
        .copied()
        .find(|v| vi.available.contains(&v.wire()) && in_use.is_compatible_with(*v))
        .unwrap_or(in_use))
}

/// The client's half of RFC 9368 §4 — validates the server's Version
/// Information once it arrives (in EncryptedExtensions).
///
/// `ours` is what the client sent as Available Versions (its preference
/// order); `negotiated` is the version the server's handshake packets
/// carry (RFC 9369 §4.1: the first long-header Version that differs from
/// the original, else the original); `reacted_to_vn` says whether this
/// connection attempt follows a Version Negotiation packet (§2.1).
///
/// * The server's Chosen Version MUST equal the Negotiated Version (§4:
///   "clients MUST validate that the server's Chosen Version is equal to
///   the Negotiated Version" — a forged long-header Version field cannot
///   steer the connection).
/// * The server's Chosen Version MUST be one the client offered.
/// * After a Version Negotiation packet, the Version Information MUST be
///   present — except that a v1 connection may treat a missing one as
///   `chosen = v1, available = [v1]` (§8) — its Available Versions MUST NOT
///   be empty, and the client MUST confirm it "would have attempted the
///   same version with knowledge of the versions the server supports": the
///   choice it would make from Available Versions plus the Negotiated
///   Version must be the Negotiated Version. Anything else is the downgrade
///   an attacker forging a Version Negotiation packet would produce.
/// * Without a Version Negotiation packet a missing Version Information is
///   tolerated (§4: the client "MAY" complete the handshake) — unless the
///   server switched the connection to another version, which RFC 9369 §4
///   requires it to announce; a silent switch is refused.
pub(crate) fn check_server_version_information(
    ours: &[QuicVersion],
    original: QuicVersion,
    negotiated: QuicVersion,
    reacted_to_vn: bool,
    server: Option<&super::transport_params::VersionInformation>,
) -> Result<(), VersionError> {
    let fallback;
    let vi = match server {
        Some(vi) => vi,
        None if reacted_to_vn && negotiated == QuicVersion::V1 => {
            // RFC 9368 §8 — special handling for a QUIC version 1 server
            // that predates version negotiation.
            fallback = super::transport_params::VersionInformation {
                chosen: QuicVersion::V1.wire(),
                available: alloc::vec![QuicVersion::V1.wire()],
            };
            &fallback
        }
        None if reacted_to_vn || negotiated != original => {
            return Err(VersionError::Negotiation);
        }
        None => return Ok(()),
    };
    if vi.chosen != negotiated.wire() || !ours.iter().any(|v| v.wire() == vi.chosen) {
        return Err(VersionError::Negotiation);
    }
    if reacted_to_vn {
        if vi.available.is_empty() {
            return Err(VersionError::Negotiation);
        }
        let mut candidates = vi.available.clone();
        candidates.push(negotiated.wire());
        if choose_version(ours, &candidates) != Some(negotiated) {
            return Err(VersionError::Negotiation);
        }
    }
    Ok(())
}

/// RFC 9001 §5.2 — the QUIC v1 Initial salt
/// `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`.
pub(crate) const INITIAL_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// RFC 9369 §3.3.1 — the QUIC v2 Initial salt
/// `0x0dede3def700a6db819381be6e269dcbf9bd2ed9` (the first 20 bytes of the
/// SHA-256 of "QUICv2 salt").
pub(crate) const INITIAL_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
];

/// RFC 9001 §5.8 — fixed AES-128-GCM key for the v1 Retry Integrity Tag,
/// `0xbe0c690b9f66575a1d766b54e368c84e`. Derived in the RFC from the
/// retry secret `0xd9c9943e6101fd200021506bcc02814c73030f25c79d71ce876e\
/// ca876e6fca8e` via `HKDF-Expand-Label(secret, "quic key", "", 16)`,
/// but the spec gives the final value directly and we use it as-is.
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// RFC 9001 §5.8 — fixed 96-bit v1 Retry nonce `0x461599d35d632bf2239825bb`.
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// RFC 9369 §3.3.3 — fixed AES-128-GCM key for the v2 Retry Integrity Tag,
/// `0x8fb4b01b56ac48e260fbcbcead7ccc92` (`HKDF-Expand-Label(secret,
/// "quicv2 key", "", 16)` of the SHA-256 of "QUICv2 retry secret").
const RETRY_INTEGRITY_KEY_V2: [u8; 16] = [
    0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
];

/// RFC 9369 §3.3.3 — fixed 96-bit v2 Retry nonce `0xd86969bc2d7c6d9990efb04a`.
const RETRY_INTEGRITY_NONCE_V2: [u8; 12] = [
    0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_values_round_trip() {
        for v in SUPPORTED_VERSIONS {
            assert_eq!(QuicVersion::from_wire(v.wire()), Some(v));
        }
        assert_eq!(QuicVersion::V1.wire(), 1);
        // RFC 9369 §3.1.
        assert_eq!(QuicVersion::V2.wire(), 0x6b33_43cf);
        assert_eq!(QuicVersion::from_wire(0), None);
        // The v2 draft code point (RFC 9369 §9, provisional) is not spoken.
        assert_eq!(QuicVersion::from_wire(0x709a_50c4), None);
    }

    #[test]
    fn reserved_versions() {
        assert!(QuicVersion::is_reserved(0x0a0a_0a0a));
        assert!(QuicVersion::is_reserved(0x1a2a_3a4a));
        assert!(QuicVersion::is_reserved(0xfafa_fafa));
        assert!(!QuicVersion::is_reserved(0x0000_0001));
        assert!(!QuicVersion::is_reserved(0x6b33_43cf));
        assert!(!QuicVersion::is_reserved(0x0a0a_0a0b));
        // Neither real version is reserved, and no reserved value is real.
        for v in SUPPORTED_VERSIONS {
            assert!(!QuicVersion::is_reserved(v.wire()));
        }
    }

    /// RFC 9369 §3.2 — the v2 code points are a permutation of the v1 ones,
    /// and the two tables invert each other.
    #[test]
    fn long_type_code_points() {
        use LongType::*;
        for v in SUPPORTED_VERSIONS {
            for t in [Initial, ZeroRtt, Handshake, Retry] {
                assert_eq!(v.long_type_from_bits(v.long_type_bits(t)), t);
            }
        }
        assert_eq!(QuicVersion::V1.long_type_bits(Initial), 0b00);
        assert_eq!(QuicVersion::V1.long_type_bits(Retry), 0b11);
        assert_eq!(QuicVersion::V2.long_type_bits(Initial), 0b01);
        assert_eq!(QuicVersion::V2.long_type_bits(ZeroRtt), 0b10);
        assert_eq!(QuicVersion::V2.long_type_bits(Handshake), 0b11);
        assert_eq!(QuicVersion::V2.long_type_bits(Retry), 0b00);
        // A v1 Initial's code point names a Retry in v2 (and vice versa):
        // the version field decides how the type bits are read.
        assert_eq!(QuicVersion::V2.long_type_from_bits(0b00), Retry);
        assert_eq!(QuicVersion::V1.long_type_from_bits(0b01), ZeroRtt);
    }

    #[test]
    fn compatibility_is_mutual() {
        assert!(QuicVersion::V1.is_compatible_with(QuicVersion::V2));
        assert!(QuicVersion::V2.is_compatible_with(QuicVersion::V1));
        assert!(QuicVersion::V1.is_compatible_with(QuicVersion::V1));
    }

    #[test]
    fn display_matches_cli_spelling() {
        assert_eq!(QuicVersion::V1.to_string(), "v1");
        assert_eq!(QuicVersion::V2.to_string(), "v2");
    }

    use super::super::transport_params::VersionInformation;
    use QuicVersion::{V1, V2};
    use alloc::string::ToString;

    fn vi(chosen: QuicVersion, available: &[u32]) -> VersionInformation {
        VersionInformation {
            chosen: chosen.wire(),
            available: available.to_vec(),
        }
    }

    #[test]
    fn choose_version_follows_our_preference_and_skips_grease() {
        assert_eq!(choose_version(&[V2, V1], &[V1.wire(), V2.wire()]), Some(V2));
        assert_eq!(choose_version(&[V1, V2], &[V2.wire(), V1.wire()]), Some(V1));
        assert_eq!(choose_version(&[V2], &[V1.wire()]), None);
        assert_eq!(choose_version(&[V1, V2], &[0x1a2a_3a4a, 0xdead_beef]), None);
        assert_eq!(
            choose_version(&[V1, V2], &[0x1a2a_3a4a, V2.wire()]),
            Some(V2)
        );
    }

    /// RFC 9368 §2.3 / §4 — the server's selection.
    #[test]
    fn server_selection() {
        // No version information: stay put (§4, "MAY complete").
        assert_eq!(select_server_version(&[V2, V1], V1, None), Ok(V1));
        // Both offered, server prefers v2: compatible upgrade.
        let offer = vi(V1, &[V1.wire(), V2.wire(), 0x0a0a_0a0a]);
        assert_eq!(select_server_version(&[V2, V1], V1, Some(&offer)), Ok(V2));
        // Server prefers v1: follows its own order, not the client's.
        let offer2 = vi(V1, &[V2.wire(), V1.wire()]);
        assert_eq!(select_server_version(&[V1, V2], V1, Some(&offer2)), Ok(V1));
        // A v1-only server keeps v1 whatever the client prefers.
        assert_eq!(select_server_version(&[V1], V1, Some(&offer2)), Ok(V1));
        // Client in v2 offering only v2 to a server preferring v1: v2.
        let only2 = vi(V2, &[V2.wire()]);
        assert_eq!(select_server_version(&[V1, V2], V2, Some(&only2)), Ok(V2));
        // Chosen Version must match the version in use (§4).
        assert_eq!(
            select_server_version(&[V1, V2], V2, Some(&offer)),
            Err(VersionError::Negotiation)
        );
        // Chosen Version must be in Available Versions (§4: parsing failure).
        let bad = vi(V1, &[V2.wire()]);
        assert_eq!(
            select_server_version(&[V1, V2], V1, Some(&bad)),
            Err(VersionError::Malformed)
        );
    }

    /// RFC 9368 §4 — the client's validation of the server's information.
    #[test]
    fn client_validation() {
        let ours = [V1, V2];
        // Plain v1, no VN: the server's information matches.
        let srv = vi(V1, &[V1.wire(), V2.wire()]);
        assert_eq!(
            check_server_version_information(&ours, V1, V1, false, Some(&srv)),
            Ok(())
        );
        // Compatible upgrade to v2, announced: fine.
        let srv2 = vi(V2, &[V1.wire(), V2.wire()]);
        assert_eq!(
            check_server_version_information(&ours, V1, V2, false, Some(&srv2)),
            Ok(())
        );
        // Server's Chosen Version differs from the header version (a forged
        // long-header Version field): refused.
        assert_eq!(
            check_server_version_information(&ours, V1, V1, false, Some(&srv2)),
            Err(VersionError::Negotiation)
        );
        // Server chose a version we never offered.
        assert_eq!(
            check_server_version_information(&[V1], V1, V1, false, Some(&srv2)),
            Err(VersionError::Negotiation)
        );
        // Missing information without VN: tolerated in the original
        // version, refused after a silent switch.
        assert_eq!(
            check_server_version_information(&ours, V1, V1, false, None),
            Ok(())
        );
        assert_eq!(
            check_server_version_information(&ours, V1, V2, false, None),
            Err(VersionError::Negotiation)
        );
        // After a VN packet: information mandatory (except §8 for v1)...
        assert_eq!(
            check_server_version_information(&ours, V2, V1, true, None),
            Ok(())
        );
        assert_eq!(
            check_server_version_information(&ours, V1, V2, true, None),
            Err(VersionError::Negotiation)
        );
        // ...Available Versions must not be empty...
        let empty = vi(V1, &[]);
        assert_eq!(
            check_server_version_information(&ours, V2, V1, true, Some(&empty)),
            Err(VersionError::Negotiation)
        );
        assert_eq!(
            check_server_version_information(&ours, V1, V1, false, Some(&empty)),
            Ok(())
        );
        // ...and the downgrade check: we prefer v2, were pushed to v1 by a
        // VN packet, and the server turns out to support v2 — the VN packet
        // was forged.
        let prefer2 = [V2, V1];
        let both = vi(V1, &[V1.wire(), V2.wire()]);
        assert_eq!(
            check_server_version_information(&prefer2, V2, V1, true, Some(&both)),
            Err(VersionError::Negotiation)
        );
        // Same server information, but the client's preference agrees with
        // the outcome: genuine.
        assert_eq!(
            check_server_version_information(&ours, V2, V1, true, Some(&both)),
            Ok(())
        );
        // The server only deploys v1: the VN packet told the truth.
        let only1 = vi(V1, &[V1.wire()]);
        assert_eq!(
            check_server_version_information(&prefer2, V2, V1, true, Some(&only1)),
            Ok(())
        );
    }
}
