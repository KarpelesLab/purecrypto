//! Inner / outer ClientHello machinery (draft-ietf-tls-esni-22 §5–6).
//!
//! This module is the bridge between the wire-level codec
//! ([`super::config`], [`super::extension`]) and the live
//! [`crate::tls::Connection`] handshake state machine. It hosts:
//!
//! - the **inner-form ECH marker** ([`inner_extension_body`]): the
//!   single `0x01` byte the inner CH carries as its
//!   `encrypted_client_hello` body. After decompression the server
//!   uses this marker to confirm the CH it just reconstructed is
//!   really an ECH inner rather than a plain CH that happened to
//!   parse;
//! - the **`ech_outer_extensions` compressor** (`compress_extensions`):
//!   replaces a contiguous block of inner-CH extensions with a single
//!   `ech_outer_extensions` entry naming them, so the inner CH does
//!   not have to duplicate bytes already present in the outer;
//! - the **`ech_outer_extensions` decompressor** (`decompress_extensions`):
//!   the symmetric server-side reconstruction, substituting outer
//!   extensions back at the placeholder position.
//!
//! The HPKE seal of the inner CH bytes into the outer CH's
//! `encrypted_client_hello` payload and the `ClientHelloOuterAAD`
//! computation are wired through the connection state machine in a
//! follow-up wave under the same Phase 5 banner; this module gives
//! that wave a pre-tested compression/decompression primitive to
//! call.
//!
//! ## Compression rules (draft §5.1)
//!
//! The `ech_outer_extensions` extension carries a `u8`-length list
//! of `ExtensionType` u16 codes. The list MUST NOT contain
//! `encrypted_client_hello` (the inner marker is already there) or
//! `ech_outer_extensions` itself, and MUST NOT contain duplicates.
//! Every referenced type must appear in the `ClientHelloOuter`
//! extension list in the same relative order as in the
//! `ech_outer_extensions` list (otherwise the receiver MUST abort
//! with `illegal_parameter`). The decompressed inner CH places the
//! substituted outer extensions at the position the
//! `ech_outer_extensions` extension occupied, preserving the order
//! of the list.

// The `ech_outer_extensions` compress/decompress primitive below is fully
// implemented and unit-tested but not yet called from the live handshake:
// the HPKE seal of the inner CH and the `ClientHelloOuterAAD` plumbing land
// in a follow-up wave (see the module doc above). Suppress dead_code here
// rather than per-item until that wiring lands. `inner_extension_body` is the
// one live entry point and is `pub`, so it is unaffected.
#![allow(dead_code)]

use super::extension::EchExtension;
use crate::tls::Error;
use crate::tls::codec::{ExtensionType, RawExtension};
use alloc::vec::Vec;

/// The inner-form `encrypted_client_hello` extension body the inner
/// CH carries (draft §5: `ECHClientHelloType inner` = `0x01`, no
/// further bytes). The server uses this marker to confirm a
/// decrypted CH was indeed sent as an ECH inner.
pub fn inner_extension_body() -> Vec<u8> {
    EchExtension::Inner.encode()
}

/// Encodes an `ech_outer_extensions` extension body listing the
/// named types in order.
pub(crate) fn encode_outer_extensions(types: &[ExtensionType]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + types.len() * 2);
    let list_len = types.len() * 2;
    body.push(list_len as u8);
    for t in types {
        body.extend_from_slice(&t.0.to_be_bytes());
    }
    body
}

/// Decodes an `ech_outer_extensions` extension body. Returns the
/// listed types, or an error if the encoding is malformed.
pub(crate) fn decode_outer_extensions(body: &[u8]) -> Result<Vec<ExtensionType>, Error> {
    if body.is_empty() {
        return Err(Error::EchDecodeError);
    }
    let list_len = body[0] as usize;
    if list_len < 2 || !list_len.is_multiple_of(2) || 1 + list_len != body.len() {
        return Err(Error::EchDecodeError);
    }
    // `body[1..]` is exactly `list_len` bytes (checked above) and
    // `list_len` is a non-zero multiple of 2, so `chunks_exact(2)`
    // consumes it with no remainder and no out-of-bounds indexing —
    // the bounds safety no longer depends on a non-local invariant.
    let mut out = Vec::with_capacity(list_len / 2);
    for chunk in body[1..].chunks_exact(2) {
        let t = u16::from_be_bytes([chunk[0], chunk[1]]);
        out.push(ExtensionType(t));
    }
    Ok(out)
}

/// Compresses an inner-CH extension list by substituting a contiguous
/// block of extensions whose types appear in `share_types` (in the
/// given order) with a single `ech_outer_extensions` placeholder.
///
/// `canonical_inner` is the fully expanded inner-CH extension list as
/// it should look to the receiver after decompression. `outer` is the
/// outer-CH extension list (used to validate the relative-order
/// constraint up front so the sender doesn't emit an inner CH a
/// conforming receiver would reject). `share_types` is the contiguous
/// block of types — they must appear in `canonical_inner` in that
/// order at some position, must appear in `outer` in the same relative
/// order, and must not contain duplicates or the two reserved types
/// (`ech_outer_extensions`, `encrypted_client_hello`).
///
/// On success returns the compressed extension list: everything from
/// `canonical_inner` outside the matched block, with the
/// `ech_outer_extensions` placeholder at the block's position.
pub(crate) fn compress_extensions(
    canonical_inner: &[RawExtension],
    outer: &[RawExtension],
    share_types: &[ExtensionType],
) -> Result<Vec<RawExtension>, Error> {
    if share_types.is_empty() {
        return Ok(canonical_inner.to_vec());
    }
    validate_share_types(share_types)?;
    let inner_start =
        find_subsequence(canonical_inner, share_types).ok_or(Error::EchDecodeError)?;
    if find_subsequence(outer, share_types).is_none() {
        return Err(Error::EchDecodeError);
    }
    let inner_end = inner_start + share_types.len();
    let mut out = Vec::with_capacity(canonical_inner.len() - share_types.len() + 1);
    out.extend_from_slice(&canonical_inner[..inner_start]);
    out.push((
        ExtensionType::ECH_OUTER_EXTENSIONS,
        encode_outer_extensions(share_types),
    ));
    out.extend_from_slice(&canonical_inner[inner_end..]);
    Ok(out)
}

/// Reconstructs the canonical inner-CH extension list from its
/// compressed form by expanding `ech_outer_extensions` against the
/// outer extensions.
///
/// Failure modes (each maps to a fatal `illegal_parameter` alert in
/// the caller, surfaced here as [`Error::EchDecodeError`]):
///
/// - the compressed list contains more than one `ech_outer_extensions`
///   entry;
/// - a referenced type is missing from the outer list, or is one of
///   `encrypted_client_hello` / `ech_outer_extensions`;
/// - the referenced outer extensions are not in the order indicated by
///   the placeholder;
/// - the list contains a duplicate type.
pub(crate) fn decompress_extensions(
    compressed_inner: &[RawExtension],
    outer: &[RawExtension],
) -> Result<Vec<RawExtension>, Error> {
    let mut out = Vec::with_capacity(compressed_inner.len());
    let mut seen_placeholder = false;
    for (ty, body) in compressed_inner {
        if *ty != ExtensionType::ECH_OUTER_EXTENSIONS {
            out.push((*ty, body.clone()));
            continue;
        }
        if seen_placeholder {
            return Err(Error::EchDecodeError);
        }
        seen_placeholder = true;
        let types = decode_outer_extensions(body)?;
        validate_share_types(&types)?;
        // Each referenced type must appear in `outer`, and they must
        // appear in `outer` in the same relative order as `types`.
        let outer_positions = resolve_outer_positions(outer, &types)?;
        for &pos in &outer_positions {
            let (oty, obody) = &outer[pos];
            debug_assert_eq!(
                *oty,
                types[outer_positions.iter().position(|&p| p == pos).unwrap()]
            );
            out.push((*oty, obody.clone()));
        }
    }
    Ok(out)
}

/// Picks the longest contiguous block of `inner` extensions that can be
/// compressed against `outer`: each entry must have a **byte-identical** (type
/// *and* body) match in `outer`, those matches must occur at strictly
/// increasing positions (the relative-order constraint `decompress_extensions`
/// enforces), and the two reserved types are excluded. Returns the block's
/// types in order (empty if nothing qualifies).
///
/// Body-identity is essential: `decompress_extensions` rebuilds the inner CH by
/// copying the *outer* body for each referenced type, so a type may only be
/// compressed away when the bodies already match — exactly the extensions an
/// ECH client duplicates verbatim between its inner and outer ClientHello
/// (everything except SNI and the ECH extension itself).
pub(crate) fn longest_shared_block(
    inner: &[RawExtension],
    outer: &[RawExtension],
) -> Vec<ExtensionType> {
    let reserved = |t: ExtensionType| {
        t == ExtensionType::ECH_OUTER_EXTENSIONS || t == ExtensionType::ENCRYPTED_CLIENT_HELLO
    };
    // Outer match position for each inner extension (extension types are unique
    // within a ClientHello, so there is at most one byte-identical match).
    let pos: Vec<Option<usize>> = inner
        .iter()
        .map(|(ty, body)| {
            if reserved(*ty) {
                return None;
            }
            outer
                .iter()
                .position(|(oty, obody)| oty == ty && obody == body)
        })
        .collect();
    let (mut best_start, mut best_len) = (0usize, 0usize);
    let mut k = 0;
    while k < inner.len() {
        if pos[k].is_none() {
            k += 1;
            continue;
        }
        let run_start = k;
        k += 1;
        while k < inner.len() && pos[k].is_some() && pos[k].unwrap() > pos[k - 1].unwrap() {
            k += 1;
        }
        if k - run_start > best_len {
            best_len = k - run_start;
            best_start = run_start;
        }
    }
    if best_len == 0 {
        return Vec::new();
    }
    inner[best_start..best_start + best_len]
        .iter()
        .map(|(t, _)| *t)
        .collect()
}

/// Validates `types`: no duplicates, no reserved entries.
fn validate_share_types(types: &[ExtensionType]) -> Result<(), Error> {
    for (i, t) in types.iter().enumerate() {
        if *t == ExtensionType::ECH_OUTER_EXTENSIONS || *t == ExtensionType::ENCRYPTED_CLIENT_HELLO
        {
            return Err(Error::EchDecodeError);
        }
        if types[..i].contains(t) {
            return Err(Error::EchDecodeError);
        }
    }
    Ok(())
}

/// Finds the start index of the first occurrence of `needle` (matched
/// by extension type only) in `haystack`. Returns `None` if absent.
fn find_subsequence(haystack: &[RawExtension], needle: &[ExtensionType]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    'outer: for start in 0..=haystack.len() - needle.len() {
        for (i, n) in needle.iter().enumerate() {
            if haystack[start + i].0 != *n {
                continue 'outer;
            }
        }
        return Some(start);
    }
    None
}

/// Resolves each requested type to an index into `outer`, enforcing
/// that the indices are strictly increasing (i.e. the outer
/// extensions appear in the requested order).
fn resolve_outer_positions(
    outer: &[RawExtension],
    types: &[ExtensionType],
) -> Result<Vec<usize>, Error> {
    let mut positions = Vec::with_capacity(types.len());
    let mut last = None::<usize>;
    for t in types {
        let mut found = None;
        let start = last.map(|p| p + 1).unwrap_or(0);
        for (i, (oty, _)) in outer.iter().enumerate().skip(start) {
            if oty == t {
                found = Some(i);
                break;
            }
        }
        let pos = found.ok_or(Error::EchDecodeError)?;
        // Also reject reserved types appearing in the outer list at the
        // referenced position (defence-in-depth; the outer should not
        // carry them).
        if *t == ExtensionType::ECH_OUTER_EXTENSIONS || *t == ExtensionType::ENCRYPTED_CLIENT_HELLO
        {
            return Err(Error::EchDecodeError);
        }
        positions.push(pos);
        last = Some(pos);
    }
    Ok(positions)
}
