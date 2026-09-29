//! Public identifiers for TLS (EC)DHE groups used as configuration knobs.
//!
//! The wire-format codepoints live in `super::codec::NamedGroup`, which is
//! intentionally `pub(crate)` — the wire codec is an internal detail. This
//! module exposes a small public enum that user code can name when setting
//! per-connection preferences (e.g.
//! [`super::ConfigBuilder::preferred_key_exchange_group`]), with a
//! one-line conversion to the internal wire identifier.
//!
//! Only the groups the engine actually implements for key exchange are
//! exposed here.
//
// Don't grow this enum by reflex — every variant has to be wired through
// `key_agreement` on both sides before being legal here.

/// A named (EC)DHE group offered for TLS 1.3 key exchange.
///
/// Used as a public configuration handle (e.g. for picking a server-side
/// preferred group that triggers HelloRetryRequest, RFC 8446 §4.1.4).
///
/// `#[non_exhaustive]`: new groups (further PQ hybrids above all) keep
/// arriving, and each one would otherwise break every downstream exhaustive
/// `match`. Match with a wildcard arm, or use [`NamedGroup::name`] /
/// [`NamedGroup::codepoint`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum NamedGroup {
    /// secp256r1 (NIST P-256).
    Secp256r1,
    /// secp384r1 (NIST P-384).
    Secp384r1,
    /// X25519 (RFC 7748).
    X25519,
    /// X25519MLKEM768 PQ-hybrid (RFC 10024).
    X25519MlKem768,
    /// secp521r1 (NIST P-521).
    Secp521r1,
    /// SecP256r1MLKEM768 PQ-hybrid (RFC 10024): secp256r1 ECDH with
    /// ML-KEM-768.
    SecP256r1MlKem768,
    /// SecP384r1MLKEM1024 PQ-hybrid (RFC 10024): secp384r1 ECDH with
    /// ML-KEM-1024.
    SecP384r1MlKem1024,
}

impl NamedGroup {
    /// Every group the engines implement, in the order they are offered
    /// (and, on a server, accepted) when
    /// [`key_exchange_groups`](super::ConfigBuilder::key_exchange_groups)
    /// is not set.
    pub const ALL: [NamedGroup; 7] = [
        NamedGroup::X25519MlKem768,
        NamedGroup::X25519,
        NamedGroup::Secp256r1,
        NamedGroup::Secp384r1,
        NamedGroup::SecP256r1MlKem768,
        NamedGroup::SecP384r1MlKem1024,
        NamedGroup::Secp521r1,
    ];

    /// The IANA registry name (`x25519`, `secp256r1`, `secp384r1`,
    /// `secp521r1`, `X25519MLKEM768`, `SecP256r1MLKEM768`,
    /// `SecP384r1MLKEM1024`), as `openssl -groups` and log lines spell it.
    pub fn name(self) -> &'static str {
        match self {
            NamedGroup::Secp256r1 => "secp256r1",
            NamedGroup::Secp384r1 => "secp384r1",
            NamedGroup::X25519 => "x25519",
            NamedGroup::X25519MlKem768 => "X25519MLKEM768",
            NamedGroup::Secp521r1 => "secp521r1",
            NamedGroup::SecP256r1MlKem768 => "SecP256r1MLKEM768",
            NamedGroup::SecP384r1MlKem1024 => "SecP384r1MLKEM1024",
        }
    }

    /// The group with the given IANA registry name, compared without
    /// regard to case (`X25519MLKEM768` and `x25519mlkem768` both work).
    /// `None` for a name the engines do not implement.
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|g| g.name().eq_ignore_ascii_case(name))
    }

    /// The IANA "TLS Supported Groups" codepoint (`0x001d` for x25519,
    /// `0x11ec` for X25519MLKEM768, …).
    pub fn codepoint(self) -> u16 {
        self.to_wire().0
    }

    /// The group with the given IANA codepoint, when it is one the engines
    /// implement.
    pub fn from_codepoint(codepoint: u16) -> Option<Self> {
        Self::from_wire(super::codec::NamedGroup(codepoint))
    }

    /// The group behind an internal wire codepoint, when it is one the
    /// engines implement.
    pub(crate) fn from_wire(g: super::codec::NamedGroup) -> Option<Self> {
        match g {
            super::codec::NamedGroup::SECP256R1 => Some(NamedGroup::Secp256r1),
            super::codec::NamedGroup::SECP384R1 => Some(NamedGroup::Secp384r1),
            super::codec::NamedGroup::X25519 => Some(NamedGroup::X25519),
            super::codec::NamedGroup::X25519MLKEM768 => Some(NamedGroup::X25519MlKem768),
            super::codec::NamedGroup::SECP521R1 => Some(NamedGroup::Secp521r1),
            super::codec::NamedGroup::SECP256R1MLKEM768 => Some(NamedGroup::SecP256r1MlKem768),
            super::codec::NamedGroup::SECP384R1MLKEM1024 => Some(NamedGroup::SecP384r1MlKem1024),
            _ => None,
        }
    }

    /// Convert to the internal wire codepoint.
    pub(crate) fn to_wire(self) -> super::codec::NamedGroup {
        match self {
            NamedGroup::Secp256r1 => super::codec::NamedGroup::SECP256R1,
            NamedGroup::Secp384r1 => super::codec::NamedGroup::SECP384R1,
            NamedGroup::X25519 => super::codec::NamedGroup::X25519,
            NamedGroup::X25519MlKem768 => super::codec::NamedGroup::X25519MLKEM768,
            NamedGroup::Secp521r1 => super::codec::NamedGroup::SECP521R1,
            NamedGroup::SecP256r1MlKem768 => super::codec::NamedGroup::SECP256R1MLKEM768,
            NamedGroup::SecP384r1MlKem1024 => super::codec::NamedGroup::SECP384R1MLKEM1024,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::NamedGroup;

    /// Codepoints as registered (RFC 8446 §4.2.7, RFC 10024 §7).
    #[test]
    fn codepoints_and_names_round_trip() {
        let expected = [
            (NamedGroup::X25519MlKem768, 0x11ec, "X25519MLKEM768"),
            (NamedGroup::X25519, 0x001d, "x25519"),
            (NamedGroup::Secp256r1, 0x0017, "secp256r1"),
            (NamedGroup::Secp384r1, 0x0018, "secp384r1"),
            (NamedGroup::SecP256r1MlKem768, 0x11eb, "SecP256r1MLKEM768"),
            (NamedGroup::SecP384r1MlKem1024, 0x11ed, "SecP384r1MLKEM1024"),
            (NamedGroup::Secp521r1, 0x0019, "secp521r1"),
        ];
        assert_eq!(expected.map(|(g, _, _)| g), NamedGroup::ALL);
        for (g, cp, name) in expected {
            assert_eq!(g.codepoint(), cp);
            assert_eq!(NamedGroup::from_codepoint(cp), Some(g));
            assert_eq!(g.name(), name);
            assert_eq!(NamedGroup::from_name(name), Some(g));
            assert_eq!(NamedGroup::from_name(&name.to_ascii_lowercase()), Some(g));
        }
        assert_eq!(NamedGroup::from_codepoint(0x001e), None); // x448
        assert_eq!(NamedGroup::from_name("x448"), None);
    }
}
