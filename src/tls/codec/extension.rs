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

/// `supported_groups` listing the given groups.
pub(crate) fn supported_groups_list(groups: &[NamedGroup]) -> RawExtension {
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
        SignatureScheme::ED25519,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
        SignatureScheme::ECDSA_SECP521R1_SHA512,
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

/// `application_layer_protocol_negotiation` (RFC 7301): a list of
/// `ProtocolName` byte strings (e.g. `b"h2"`, `b"http/1.1"`).
pub(crate) fn alpn_protocols(protocols: &[&[u8]]) -> RawExtension {
    let mut body = Vec::new();
    with_len_u16(&mut body, |list| {
        for proto in protocols {
            with_len_u8(list, |b| b.extend_from_slice(proto));
        }
    });
    (ExtensionType::ALPN, body)
}

/// Parses an ALPN extension body. Returns the list of protocol names.
pub(crate) fn parse_alpn(body: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut outer = ReadCursor::new(body);
    let list = outer.vec_u16()?;
    outer.expect_empty()?;
    let mut c = ReadCursor::new(list);
    let mut out = Vec::new();
    while !c.is_empty() {
        let p = c.vec_u8()?;
        if p.is_empty() {
            return Err(Error::IllegalParameter);
        }
        out.push(p.to_vec());
    }
    Ok(out)
}

/// `record_size_limit` (RFC 8449): a single u16 in `64..=2^14+1` advertising
/// the maximum plaintext fragment the peer may send us.
pub(crate) fn record_size_limit(limit: u16) -> RawExtension {
    let mut body = Vec::new();
    put_u16(&mut body, limit);
    (ExtensionType::RECORD_SIZE_LIMIT, body)
}

/// Parses a `record_size_limit` extension body.
pub(crate) fn parse_record_size_limit(body: &[u8]) -> Result<u16, Error> {
    let mut c = ReadCursor::new(body);
    let v = c.u16()?;
    c.expect_empty()?;
    // RFC 8449 §4: limit must be in `64..=2^14+1`. Anything else closes the
    // connection with `illegal_parameter`.
    if !(64..=(1u16 << 14) + 1).contains(&v) {
        return Err(Error::IllegalParameter);
    }
    Ok(v)
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

/// `key_share` for a ClientHello: a list of offered group/public-key entries.
pub(crate) fn client_key_shares(shares: &[(NamedGroup, Vec<u8>)]) -> RawExtension {
    let mut body = Vec::new();
    with_len_u16(&mut body, |list| {
        for (group, key) in shares {
            encode_key_share_entry(list, *group, key);
        }
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

/// Parses a HelloRetryRequest `key_share` (just a `selected_group` u16).
pub(crate) fn parse_hrr_key_share(body: &[u8]) -> Result<NamedGroup, Error> {
    let mut c = ReadCursor::new(body);
    let group = NamedGroup(c.u16()?);
    c.expect_empty()?;
    Ok(group)
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

/// `psk_key_exchange_modes` (RFC 8446 §4.2.9): a `u8`-length list of mode
/// bytes. We use `1 = psk_dhe_ke` (PSK with ECDHE for forward secrecy).
pub(crate) fn psk_key_exchange_modes(modes: &[u8]) -> RawExtension {
    let mut body = Vec::new();
    with_len_u8(&mut body, |b| b.extend_from_slice(modes));
    (ExtensionType::PSK_KEY_EXCHANGE_MODES, body)
}

/// Parses a `psk_key_exchange_modes` body into the list of advertised modes.
pub(crate) fn parse_psk_key_exchange_modes(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut c = ReadCursor::new(body);
    let list = c.vec_u8()?;
    c.expect_empty()?;
    if list.is_empty() {
        return Err(Error::IllegalParameter);
    }
    Ok(list.to_vec())
}

/// `early_data` extension body. In ClientHello / EncryptedExtensions, the body
/// is empty; in NewSessionTicket it carries a `uint32 max_early_data_size`.
// Used by 0-RTT plumbing in a follow-up commit.
#[allow(dead_code)]
pub(crate) fn early_data_empty() -> RawExtension {
    (ExtensionType::EARLY_DATA, Vec::new())
}

/// `early_data` carrying `max_early_data_size` (for NewSessionTicket).
// Used by 0-RTT plumbing in a follow-up commit.
#[allow(dead_code)]
pub(crate) fn early_data_with_size(max: u32) -> RawExtension {
    (ExtensionType::EARLY_DATA, max.to_be_bytes().to_vec())
}

/// Builds a client-side `pre_shared_key` extension carrying `identities` and
/// placeholder zero binders. Each identity is `(ticket_bytes,
/// obfuscated_ticket_age)`. Each binder is `hash_len` bytes of zero.
///
/// Returns `(extension, binders_field_len)` where `binders_field_len` is the
/// number of bytes at the END of the extension body occupied by the binders
/// field (`u16 outer_len ‖ for each binder: u8 inner_len ‖ binder_bytes`).
/// The caller can subtract this length from the assembled ClientHello bytes
/// to obtain the "truncated ClientHello" that the binders are HMAC'd over
/// (RFC 8446 §4.2.11.2).
pub(crate) fn client_pre_shared_key_placeholder(
    identities: &[(Vec<u8>, u32)],
    hash_len: usize,
) -> (RawExtension, usize) {
    let mut body = Vec::new();
    // identities<7..2^16-1>
    with_len_u16(&mut body, |list| {
        for (id, age) in identities {
            with_len_u16(list, |b| b.extend_from_slice(id));
            list.extend_from_slice(&age.to_be_bytes());
        }
    });
    // binders<33..2^16-1>: u16 outer length + for each binder: u8 inner length
    // + `hash_len` zeros.
    let binders_start = body.len();
    with_len_u16(&mut body, |list| {
        for _ in identities {
            with_len_u8(list, |b| b.extend(core::iter::repeat_n(0u8, hash_len)));
        }
    });
    let binders_len = body.len() - binders_start;
    ((ExtensionType::PRE_SHARED_KEY, body), binders_len)
}

/// A parsed `pre_shared_key` extension from a ClientHello: a list of offered
/// `(ticket_bytes, obfuscated_age)` identities and a parallel list of their
/// binders.
pub(crate) type ClientPsk = (Vec<(Vec<u8>, u32)>, Vec<Vec<u8>>);

/// Parses a client-side `pre_shared_key` extension body. Returns
/// `(identities, binders)`. Each identity is `(ticket_bytes, obfuscated_age)`.
pub(crate) fn parse_client_pre_shared_key(body: &[u8]) -> Result<ClientPsk, Error> {
    let mut c = ReadCursor::new(body);
    let identities_bytes = c.vec_u16()?;
    let binders_bytes = c.vec_u16()?;
    c.expect_empty()?;

    let mut id_cur = ReadCursor::new(identities_bytes);
    let mut identities = Vec::new();
    while !id_cur.is_empty() {
        let id = id_cur.vec_u16()?.to_vec();
        if id.is_empty() {
            return Err(Error::IllegalParameter);
        }
        let age = id_cur.u32()?;
        identities.push((id, age));
    }
    if identities.is_empty() {
        return Err(Error::IllegalParameter);
    }

    let mut bin_cur = ReadCursor::new(binders_bytes);
    let mut binders = Vec::new();
    while !bin_cur.is_empty() {
        let b = bin_cur.vec_u8()?.to_vec();
        if b.len() < 32 {
            return Err(Error::IllegalParameter);
        }
        binders.push(b);
    }
    if binders.len() != identities.len() {
        return Err(Error::IllegalParameter);
    }
    Ok((identities, binders))
}

/// Server-side `pre_shared_key` extension: carries only the selected identity
/// index (RFC 8446 §4.2.11).
pub(crate) fn server_pre_shared_key(selected_identity: u16) -> RawExtension {
    let mut body = Vec::with_capacity(2);
    body.extend_from_slice(&selected_identity.to_be_bytes());
    (ExtensionType::PRE_SHARED_KEY, body)
}

/// Parses the server-side `pre_shared_key` extension body (a single u16).
pub(crate) fn parse_server_pre_shared_key(body: &[u8]) -> Result<u16, Error> {
    let mut c = ReadCursor::new(body);
    let v = c.u16()?;
    c.expect_empty()?;
    Ok(v)
}
