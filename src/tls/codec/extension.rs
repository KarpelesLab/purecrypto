//! Typed construction and parsing of the handshake extensions we use.
//!
//! Extensions travel through the codec as raw `(ExtensionType, Vec<u8>)` pairs
//! ([`RawExtension`](super::RawExtension)); these helpers build and interpret
//! the bodies of the specific extensions a TLS 1.3 handshake needs.

use super::{
    ExtensionType, NamedGroup, RawExtension, ReadCursor, SignatureScheme, put_u8, put_u16,
    with_len_u8, with_len_u16, with_len_u24,
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

/// `signature_algorithms` listing the schemes we accept for
/// `CertificateVerify`. RFC 8446 §4.4.3 forbids `rsa_pkcs1_*` from this
/// list — those schemes are reserved for chain signatures and must be
/// offered via `signature_algorithms_cert` (RFC 8446 §4.2.3) if needed.
pub(crate) fn signature_algorithms() -> RawExtension {
    let schemes = [
        SignatureScheme::ED25519,
        SignatureScheme::ECDSA_SECP256R1_SHA256,
        SignatureScheme::ECDSA_SECP384R1_SHA384,
        SignatureScheme::ECDSA_SECP521R1_SHA512,
        SignatureScheme::RSA_PSS_RSAE_SHA256,
        SignatureScheme::RSA_PSS_RSAE_SHA384,
        // ML-DSA (draft-ietf-tls-mldsa). The TLS 1.3 wire format carries
        // the raw FIPS 204 signature in the CertificateVerify body, no
        // DER wrapping.
        SignatureScheme::MLDSA44,
        SignatureScheme::MLDSA65,
        SignatureScheme::MLDSA87,
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

/// `ec_point_formats` (RFC 4492 §5.1.2). Offers/answers `[uncompressed (0)]`,
/// which is required by some TLS 1.2 peers when ECDHE is in use.
// Used by the TLS 1.2 client/server in a follow-up commit.
#[allow(dead_code)]
pub(crate) fn ec_point_formats() -> RawExtension {
    let mut body = Vec::new();
    with_len_u8(&mut body, |b| b.push(0)); // uncompressed
    (ExtensionType::EC_POINT_FORMATS, body)
}

/// Parses an `ec_point_formats` extension body into the list of point-format
/// bytes the peer supports.
// Used by the TLS 1.2 client/server in a follow-up commit.
#[allow(dead_code)]
pub(crate) fn parse_ec_point_formats(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut c = ReadCursor::new(body);
    let list = c.vec_u8()?;
    c.expect_empty()?;
    Ok(list.to_vec())
}

/// `renegotiation_info` (RFC 5746 §3.2). In TLS 1.2 a fresh handshake carries
/// an empty `renegotiated_connection` field (one u8 zero), which advertises
/// support for secure renegotiation. This crate never actually renegotiates;
/// we emit the empty form to keep modern servers from rejecting us, and we
/// expect the server's echo to also be empty.
// Used by the TLS 1.2 client/server in a follow-up commit.
#[allow(dead_code)]
pub(crate) fn renegotiation_info_empty() -> RawExtension {
    let mut body = Vec::new();
    with_len_u8(&mut body, |_| {});
    (ExtensionType::RENEGOTIATION_INFO, body)
}

/// Parses a `renegotiation_info` body, returning the embedded
/// `renegotiated_connection` bytes. For a fresh handshake (the only case this
/// crate handles), the inner vector must be empty — non-empty inputs come
/// from an actual renegotiation, which we never initiate.
// Used by the TLS 1.2 client/server in a follow-up commit.
#[allow(dead_code)]
pub(crate) fn parse_renegotiation_info(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut c = ReadCursor::new(body);
    let inner = c.vec_u8()?;
    c.expect_empty()?;
    Ok(inner.to_vec())
}

/// RFC 7627 §5.1 — `extended_master_secret` extension (codepoint `0x0017`)
/// with an empty body. The client always offers it; the server echoes it
/// only when it also offers EMS. When both peers send the extension, the
/// TLS 1.2 master-secret derivation switches to use the session transcript
/// hash through `ClientKeyExchange` instead of the bare client/server
/// randoms, binding the master secret to the full handshake context and
/// closing the Triple Handshake attack class.
pub(crate) fn extended_master_secret_empty() -> RawExtension {
    (ExtensionType::EXTENDED_MASTER_SECRET, Vec::new())
}

/// RFC 7627 §5.1 — the body of `extended_master_secret` MUST be empty.
/// A non-empty body is a protocol violation; reject with `Decode` so the
/// caller maps it to a `decode_error` alert.
pub(crate) fn parse_extended_master_secret(body: &[u8]) -> Result<(), Error> {
    if !body.is_empty() {
        return Err(Error::Decode);
    }
    Ok(())
}

/// `session_ticket` (RFC 5077) carrying an opaque ticket. In ClientHello an
/// empty body advertises support; a non-empty body resumes. In ServerHello an
/// empty body signals the server will issue a fresh NewSessionTicket (RFC 5077
/// §3.2).
// Used by the TLS 1.2 session-ticket plumbing (commit 5).
#[allow(dead_code)]
pub(crate) fn session_ticket(ticket: &[u8]) -> RawExtension {
    (ExtensionType::SESSION_TICKET, ticket.to_vec())
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

/// `status_request` for a ClientHello opting into OCSP stapling
/// (RFC 6066 §8). Body: `CertificateStatusRequest = { status_type = 1 (ocsp),
/// responder_id_list<0..2^16-1> = [], request_extensions<0..2^16-1> = [] }`.
/// We never name specific responders or extensions — the empty form is the
/// universal "I'll accept whatever OCSP response you have for the leaf" opt-in.
pub(crate) fn status_request_ocsp() -> RawExtension {
    let mut body = Vec::new();
    put_u8(&mut body, 1); // status_type = ocsp
    with_len_u16(&mut body, |_| {}); // responder_id_list = []
    with_len_u16(&mut body, |_| {}); // request_extensions = []
    (ExtensionType::STATUS_REQUEST, body)
}

/// Parses an incoming ClientHello `status_request` body. Returns `Ok(())` if
/// the body advertises stapling support that we can honour (i.e.
/// `status_type = ocsp`; nested lists may be empty or non-empty — we ignore
/// their contents since we always staple the single leaf response we have).
/// Returns `Err(Error::Decode)` on any structural malformation.
///
/// RFC 6066 §8 says the server MAY ignore the responder_id_list /
/// request_extensions; we always do.
pub(crate) fn parse_status_request(body: &[u8]) -> Result<(), Error> {
    let mut c = ReadCursor::new(body);
    let status_type = c.u8()?;
    let _responder_id_list = c.vec_u16()?;
    let _request_extensions = c.vec_u16()?;
    c.expect_empty()?;
    // status_type 1 = ocsp. Any other value (currently none are assigned)
    // is unsupported.
    if status_type != 1 {
        return Err(Error::Decode);
    }
    Ok(())
}

/// `status_request` for a TLS 1.2 ServerHello (RFC 6066 §8): an empty body
/// signals that the server will follow with a `CertificateStatus` handshake
/// message after `Certificate`.
pub(crate) fn status_request_sh_ack() -> RawExtension {
    (ExtensionType::STATUS_REQUEST, Vec::new())
}

/// Parses a TLS 1.2 ServerHello-side `status_request` extension. RFC 6066
/// §8: the body MUST be empty.
pub(crate) fn parse_status_request_sh_ack(body: &[u8]) -> Result<(), Error> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(Error::Decode)
    }
}

/// Encodes a `CertificateStatus` body (RFC 6066 §8). Used in two places:
///
///   - As the body of the TLS 1.2 `CertificateStatus` handshake message
///     (`hs_type::CERTIFICATE_STATUS = 22`).
///   - As the body of the TLS 1.3 per-CertificateEntry `status_request`
///     extension (RFC 8446 §4.4.2.1).
///
/// Wire format: `status_type u8 (=1 for ocsp) ‖ OCSPResponse<u24>` where
/// the `OCSPResponse` length-prefix is a 24-bit big-endian field carrying the
/// length of the DER blob that follows.
pub(crate) fn certificate_status_ocsp(ocsp_der: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    put_u8(&mut body, 1); // status_type = ocsp
    with_len_u24(&mut body, |b| b.extend_from_slice(ocsp_der));
    body
}

/// Parses a `CertificateStatus` body (RFC 6066 §8). Returns the inner OCSP
/// DER bytes on success. Rejects any `status_type` other than `1 (ocsp)`.
pub(crate) fn parse_certificate_status(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut c = ReadCursor::new(body);
    let status_type = c.u8()?;
    if status_type != 1 {
        return Err(Error::Decode);
    }
    let ocsp = c.vec_u24()?.to_vec();
    c.expect_empty()?;
    // Per RFC 6066 §8 the OCSPResponse field is `<1..2^24-1>`; a zero-length
    // staple is a protocol violation we reject outright.
    if ocsp.is_empty() {
        return Err(Error::Decode);
    }
    Ok(ocsp)
}

/// Builds a `client_certificate_type` / `server_certificate_type` extension
/// (RFC 7250 §3) for ClientHello. `ty` selects which of the two codepoints
/// to use; `types` is the ordered preference list of certificate-type IDs
/// (`0 = X509`, `2 = RawPublicKey`). The wire encoding is a `u8`-length list
/// of `u8`s — the RFC 7250 §3 "CertificateTypeList" struct.
pub(crate) fn cert_type_list(ty: ExtensionType, types: &[u8]) -> RawExtension {
    let mut body = Vec::new();
    with_len_u8(&mut body, |b| b.extend_from_slice(types));
    (ty, body)
}

/// Parses a ClientHello `client_certificate_type` / `server_certificate_type`
/// body into the offered preference list. The list MUST be non-empty
/// (RFC 7250 §3 — `CertificateType cert_types<1..2^8-1>`).
pub(crate) fn parse_cert_type_list(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut c = ReadCursor::new(body);
    let list = c.vec_u8()?;
    c.expect_empty()?;
    if list.is_empty() {
        return Err(Error::IllegalParameter);
    }
    Ok(list.to_vec())
}

/// Builds a `client_certificate_type` / `server_certificate_type` extension
/// for an EncryptedExtensions reply (RFC 7250 §3): the bare selected byte.
pub(crate) fn cert_type_selection(ty: ExtensionType, selected: u8) -> RawExtension {
    let body = alloc::vec![selected];
    (ty, body)
}

/// Parses an EncryptedExtensions `client_certificate_type` /
/// `server_certificate_type` body: a single `u8` (RFC 7250 §3).
pub(crate) fn parse_cert_type_selection(body: &[u8]) -> Result<u8, Error> {
    let mut c = ReadCursor::new(body);
    let v = c.u8()?;
    c.expect_empty()?;
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

/// Parses an incoming `server_name` (SNI) extension and returns the first
/// `host_name` entry as a UTF-8 string. RFC 6066 §3 defines the list as
/// `ServerName ServerNameList<1..2^16-1>` with name_type 0 = host_name (no
/// other types are currently defined). Non-UTF-8 host names are rejected
/// per the implicit ASCII restriction.
///
/// Returns `Ok(None)` only for the (RFC-forbidden) empty list case; any
/// structural malformation returns `Err(Error::Decode)`. A non-host_name
/// entry is skipped — RFC 6066 §3 says implementations SHOULD silently
/// ignore unknown name_type values, so we keep the first host_name we find.
pub(crate) fn parse_server_name(body: &[u8]) -> Result<Option<alloc::string::String>, Error> {
    let mut outer = ReadCursor::new(body);
    let list = outer.vec_u16()?;
    outer.expect_empty()?;
    if list.is_empty() {
        // RFC 6066 forbids the empty list; reject explicitly rather than
        // silently returning None.
        return Err(Error::Decode);
    }
    let mut c = ReadCursor::new(list);
    while !c.is_empty() {
        let name_type = c.u8()?;
        let name = c.vec_u16()?;
        if name_type == 0 {
            // host_name. RFC 6066 §3 says trailing-dot and IP literals are
            // invalid here — leave that policy to higher layers; we only
            // confirm the bytes form a valid UTF-8 string.
            let s = core::str::from_utf8(name).map_err(|_| Error::Decode)?;
            return Ok(Some(s.into()));
        }
        // Unknown name_type — skip per RFC 6066 §3.
    }
    Ok(None)
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

/// RFC 9001 §8.2 — `quic_transport_parameters` extension (codepoint 0x0039).
///
/// The body is opaque to the TLS engine: the QUIC layer (Phase 4+) encodes
/// and decodes the actual RFC 9000 §18 transport-parameter list. The TLS
/// engine merely carries the bytes through.
// Used by the QUIC engine path (lands in Phase 4); silent otherwise.
#[allow(dead_code)]
pub(crate) fn quic_transport_parameters(body: &[u8]) -> RawExtension {
    (ExtensionType::QUIC_TRANSPORT_PARAMETERS, body.to_vec())
}

/// Returns the body of a `quic_transport_parameters` extension verbatim.
/// The TLS engine does not interpret it — the QUIC layer does.
// Used by the QUIC engine path (lands in Phase 4); silent otherwise.
#[allow(dead_code)]
pub(crate) fn parse_quic_transport_parameters(body: &[u8]) -> &[u8] {
    body
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Round-trip a single host_name through `server_name` ↔ `parse_server_name`.
    #[test]
    fn server_name_roundtrip() {
        let (_, body) = server_name("example.test");
        assert_eq!(
            parse_server_name(&body).unwrap().as_deref(),
            Some("example.test")
        );
    }

    /// Empty ServerNameList is forbidden by RFC 6066 §3.
    #[test]
    fn parse_server_name_rejects_empty_list() {
        // Outer list-length u16 = 0.
        let body = [0u8, 0];
        assert!(parse_server_name(&body).is_err());
    }

    /// Unknown name_type entries are silently skipped per RFC 6066 §3; if
    /// no host_name follows, we surface `None` without erroring.
    #[test]
    fn parse_server_name_skips_unknown_name_type() {
        // ServerNameList { name_type=99 (unknown), data=2 bytes "hi" }
        // length: u16=5 (=1 + 2 + 2)
        let mut body = Vec::new();
        body.extend_from_slice(&5u16.to_be_bytes());
        body.push(99); // unknown name_type
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(b"hi");
        assert_eq!(parse_server_name(&body).unwrap(), None);
    }

    /// Non-UTF-8 host_name bytes are a malformed SNI extension.
    #[test]
    fn parse_server_name_rejects_non_utf8() {
        // host_name with a lone 0xFF byte (invalid UTF-8).
        let mut body = Vec::new();
        body.extend_from_slice(&4u16.to_be_bytes()); // list length
        body.push(0); // host_name
        body.extend_from_slice(&1u16.to_be_bytes());
        body.push(0xFF);
        assert!(parse_server_name(&body).is_err());
    }
}
