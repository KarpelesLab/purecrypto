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
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NamedGroup {
    /// secp256r1 (NIST P-256).
    Secp256r1,
    /// secp384r1 (NIST P-384).
    Secp384r1,
    /// X25519 (RFC 7748).
    X25519,
    /// X25519MLKEM768 PQ-hybrid (draft-ietf-tls-ecdhe-mlkem).
    X25519MlKem768,
}

impl NamedGroup {
    /// The IANA registry name (`x25519`, `secp256r1`, `secp384r1`,
    /// `X25519MLKEM768`), as `openssl -groups` and log lines spell it.
    pub fn name(self) -> &'static str {
        match self {
            NamedGroup::Secp256r1 => "secp256r1",
            NamedGroup::Secp384r1 => "secp384r1",
            NamedGroup::X25519 => "x25519",
            NamedGroup::X25519MlKem768 => "X25519MLKEM768",
        }
    }

    /// The group behind an internal wire codepoint, when it is one the
    /// engines implement.
    pub(crate) fn from_wire(g: super::codec::NamedGroup) -> Option<Self> {
        match g {
            super::codec::NamedGroup::SECP256R1 => Some(NamedGroup::Secp256r1),
            super::codec::NamedGroup::SECP384R1 => Some(NamedGroup::Secp384r1),
            super::codec::NamedGroup::X25519 => Some(NamedGroup::X25519),
            super::codec::NamedGroup::X25519MLKEM768 => Some(NamedGroup::X25519MlKem768),
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
        }
    }
}
