//! Typed construction and parsing of the handshake extensions we use.
//!
//! Extensions travel through the codec as raw `(ExtensionType, Vec<u8>)` pairs
//! ([`RawExtension`](super::RawExtension)); these helpers build and interpret
//! the bodies of the specific extensions a TLS 1.3 handshake needs.

use super::{
    ExtensionType, NamedGroup, RawExtension, ReadCursor, SignatureScheme, put_u8, put_u16,
    with_len_u8, with_len_u16,
};
use crate::tls::{Error, ProtocolVersion};
use alloc::vec::Vec;

/// `supported_versions` for a ClientHello: a `u8`-length list holding only
/// TLS 1.3.
pub(crate) fn client_supported_versions() -> RawExtension {
    let mut body = Vec::new();
    with_len_u8(&mut body, |b| put_u16(b, ProtocolVersion::TLSv1_3.as_u16()));
    (ExtensionType::SUPPORTED_VERSIONS, body)
}

/// Parses the server's selected version from a ServerHello `supported_versions`
/// (a bare `u16`).
pub(crate) fn parse_selected_version(body: &[u8]) -> Result<ProtocolVersion, Error> {
    let mut c = ReadCursor::new(body);
    let v = c.u16()?;
    c.expect_empty()?;
    Ok(ProtocolVersion::from_u16(v))
}

/// `supported_groups` listing the groups we implement (x25519, secp256r1).
pub(crate) fn supported_groups() -> RawExtension {
    let groups = [NamedGroup::X25519, NamedGroup::SECP256R1];
    let mut body = Vec::new();
    with_len_u16(&mut body, |b| {
        for g in groups {
            put_u16(b, g.0);
        }
    });
    (ExtensionType::SUPPORTED_GROUPS, body)
}

/// `signature_algorithms` listing the schemes we can verify/produce.
pub(crate) fn signature_algorithms() -> RawExtension {
    let schemes = [
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PSS_RSAE_SHA384,
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
    ];
    let mut body = Vec::new();
    with_len_u16(&mut body, |b| {
        for s in schemes {
            put_u16(b, s.0);
        }
    });
    (ExtensionType::SIGNATURE_ALGORITHMS, body)
}

/// `server_name` (SNI) carrying a single host name.
pub(crate) fn server_name(host: &str) -> RawExtension {
    let mut body = Vec::new();
    with_len_u16(&mut body, |list| {
        put_u8(list, 0); // name_type = host_name
        with_len_u16(list, |b| b.extend_from_slice(host.as_bytes()));
    });
    (ExtensionType::SERVER_NAME, body)
}

/// `key_share` for a ClientHello: a single offered group/public-key entry.
pub(crate) fn client_key_share(group: NamedGroup, public_key: &[u8]) -> RawExtension {
    let mut body = Vec::new();
    with_len_u16(&mut body, |list| {
        encode_key_share_entry(list, group, public_key)
    });
    (ExtensionType::KEY_SHARE, body)
}

/// `key_share` for a ClientHello offering both x25519 and secp256r1 entries
/// (in that preference order), so the server can choose without a retry.
pub(crate) fn client_key_share_pair(x25519: &[u8], secp256r1: &[u8]) -> RawExtension {
    let mut body = Vec::new();
    with_len_u16(&mut body, |list| {
        encode_key_share_entry(list, NamedGroup::X25519, x25519);
        encode_key_share_entry(list, NamedGroup::SECP256R1, secp256r1);
    });
    (ExtensionType::KEY_SHARE, body)
}

/// `key_share` for a ServerHello: a single selected group/public-key entry.
pub(crate) fn server_key_share(group: NamedGroup, public_key: &[u8]) -> RawExtension {
    let mut body = Vec::new();
    encode_key_share_entry(&mut body, group, public_key);
    (ExtensionType::KEY_SHARE, body)
}

fn encode_key_share_entry(out: &mut Vec<u8>, group: NamedGroup, public_key: &[u8]) {
    put_u16(out, group.0);
    with_len_u16(out, |b| b.extend_from_slice(public_key));
}

/// Parses a ServerHello `key_share` (a single `KeyShareEntry`).
pub(crate) fn parse_server_key_share(body: &[u8]) -> Result<(NamedGroup, Vec<u8>), Error> {
    let mut c = ReadCursor::new(body);
    let group = NamedGroup(c.u16()?);
    let key = c.vec_u16()?.to_vec();
    c.expect_empty()?;
    Ok((group, key))
}

/// Parses a ClientHello `key_share` (a list of `KeyShareEntry`).
pub(crate) fn parse_client_key_shares(body: &[u8]) -> Result<Vec<(NamedGroup, Vec<u8>)>, Error> {
    let mut outer = ReadCursor::new(body);
    let list = outer.vec_u16()?;
    outer.expect_empty()?;
    let mut c = ReadCursor::new(list);
    let mut shares = Vec::new();
    while !c.is_empty() {
        let group = NamedGroup(c.u16()?);
        let key = c.vec_u16()?.to_vec();
        shares.push((group, key));
    }
    Ok(shares)
}

/// `supported_versions` for a ServerHello: the bare selected version.
pub(crate) fn server_supported_versions() -> RawExtension {
    let mut body = Vec::new();
    put_u16(&mut body, ProtocolVersion::TLSv1_3.as_u16());
    (ExtensionType::SUPPORTED_VERSIONS, body)
}

/// Finds the first extension of `ty` in a list.
pub(crate) fn find(exts: &[RawExtension], ty: ExtensionType) -> Option<&[u8]> {
    exts.iter()
        .find(|(t, _)| *t == ty)
        .map(|(_, v)| v.as_slice())
}

/// Parses a ClientHello `signature_algorithms` into a scheme list.
pub(crate) fn parse_signature_algorithms(body: &[u8]) -> Result<Vec<SignatureScheme>, Error> {
    let mut outer = ReadCursor::new(body);
    let list = outer.vec_u16()?;
    outer.expect_empty()?;
    let mut c = ReadCursor::new(list);
    let mut out = Vec::new();
    while !c.is_empty() {
        out.push(SignatureScheme(c.u16()?));
    }
    Ok(out)
}

/// Parses a ClientHello `supported_versions` list, returning whether TLS 1.3 is
/// offered.
pub(crate) fn client_offers_tls13(body: &[u8]) -> Result<bool, Error> {
    let mut outer = ReadCursor::new(body);
    let list = outer.vec_u8()?;
    let mut c = ReadCursor::new(list);
    let mut found = false;
    while !c.is_empty() {
        if c.u16()? == ProtocolVersion::TLSv1_3.as_u16() {
            found = true;
        }
    }
    Ok(found)
}
