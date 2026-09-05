//! Non-destructive ClientHello inspection.
//!
//! A TLS server normally binds a single identity at
//! [`Connection::server`](crate::tls::Connection::server). Choosing the
//! certificate (or ALPN) per connection — virtual hosting by SNI, on-demand
//! ACME issuance, or answering a TLS-ALPN-01 (`acme-tls/1`) challenge — needs
//! the SNI and offered ALPN list *before* the connection is built.
//!
//! [`peek_client_hello`] reads those out of the first bytes off the wire
//! without consuming them: the caller buffers the initial read, peeks, picks
//! the right [`Config`](crate::tls::Config), and then feeds the *same* bytes to
//! `Connection::server`.

use alloc::string::String;
use alloc::vec::Vec;

use crate::tls::codec::{ClientHello, ExtensionType, extension as ext, hs_type, read_record};
use crate::tls::{ContentType, Error};

/// SNI and offered ALPN extracted from a ClientHello by [`peek_client_hello`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ClientHelloInfo {
    /// The `server_name` (SNI host_name, RFC 6066 §3), if the client sent one.
    pub server_name: Option<String>,
    /// The offered ALPN protocol IDs (RFC 7301), in the client's order — e.g.
    /// `[b"h2".to_vec(), b"acme-tls/1".to_vec()]`. Empty when no ALPN extension
    /// was offered.
    pub alpn_protocols: Vec<Vec<u8>>,
}

/// Inspects the start of a TLS stream — a (possibly still-incomplete) buffer of
/// TLS records — and extracts the SNI + offered ALPN from the initial
/// ClientHello, **without consuming `buf`**.
///
/// - `Ok(None)` — the ClientHello isn't fully buffered yet; read more bytes and
///   call again with the longer buffer.
/// - `Ok(Some(info))` — the ClientHello is complete; `info` carries its SNI and
///   ALPN. `buf` is untouched, so the caller now feeds the same bytes to
///   [`Connection::server`](crate::tls::Connection::server) of the chosen
///   [`Config`](crate::tls::Config).
/// - `Err(_)` — the bytes are not a well-formed TLS client handshake (e.g. the
///   first record isn't a handshake record, or the first handshake message
///   isn't a ClientHello).
///
/// Works for both TLS 1.2 and TLS 1.3 ClientHellos (the message shape is
/// identical; 1.3 just carries `supported_versions`). The ClientHello is read
/// from one or more plaintext handshake records — the client's first flight is
/// never encrypted — so no keys are involved.
pub fn peek_client_hello(buf: &[u8]) -> Result<Option<ClientHelloInfo>, Error> {
    let Some(ch) = peek_decode_client_hello(buf)? else {
        return Ok(None);
    };
    Ok(Some(extract_client_hello_info(&ch)?))
}

/// Decodes a ClientHello from the raw handshake-message bytes (msg_type(1) ||
/// length(3) || body) and extracts its SNI + ALPN. Unlike [`peek_client_hello`]
/// this takes the bare handshake message with NO TLS record framing — the form
/// QUIC carries in CRYPTO frames (RFC 9001) — so `crate::quic::peek_initial_sni`
/// can reuse the exact same ClientHello parsing. `Ok(None)` = the handshake
/// message isn't fully present yet.
// Used by `crate::quic::peek_initial_sni` (RFC 9001 carries the ClientHello in
// CRYPTO frames, with no TLS record framing); unreferenced in builds without
// the `quic` feature.
#[allow(dead_code)]
pub(crate) fn client_hello_info_from_handshake(
    handshake: &[u8],
) -> Result<Option<ClientHelloInfo>, Error> {
    let Some(ch) = decode_first_client_hello(handshake)? else {
        return Ok(None);
    };
    Ok(Some(extract_client_hello_info(&ch)?))
}

/// Pulls the SNI host name and offered ALPN list out of a decoded ClientHello.
/// Shared by the TCP ([`peek_client_hello`]) and QUIC peek paths.
fn extract_client_hello_info(ch: &ClientHello) -> Result<ClientHelloInfo, Error> {
    let mut info = ClientHelloInfo::default();
    for (ty, body) in &ch.extensions {
        if *ty == ExtensionType::SERVER_NAME {
            info.server_name = ext::parse_server_name(body)?;
        } else if *ty == ExtensionType::ALPN {
            info.alpn_protocols = ext::parse_alpn(body)?;
        }
    }
    Ok(info)
}

/// Selects the TLS server engine version from the first ClientHello, reusing the
/// same non-consuming reassembly as [`peek_client_hello`]. `Ok(None)` = the
/// ClientHello isn't fully buffered yet; `Ok(Some(true))` = the client offered
/// TLS 1.3 in `supported_versions` (use the 1.3 engine); `Ok(Some(false))` = no
/// 1.3 was offered (a legacy 1.2-only client — use the 1.2 / legacy engine).
/// Mirrors the server's own selection: the 1.2 engine deliberately ignores the
/// *content* of `supported_versions` and caps at TLS 1.2, so the only question
/// here is whether 1.3 was offered at all.
pub(crate) fn peek_offers_tls13(buf: &[u8]) -> Result<Option<bool>, Error> {
    let Some(ch) = peek_decode_client_hello(buf)? else {
        return Ok(None);
    };
    let offers13 = match ext::find(&ch.extensions, ExtensionType::SUPPORTED_VERSIONS) {
        Some(sv) => ext::client_offers_tls13(sv)?,
        None => false,
    };
    Ok(Some(offers13))
}

/// Reassembles the first handshake message from the leading handshake records of
/// `buf` and decodes it as a [`ClientHello`], **without consuming `buf`**. A
/// ClientHello may legally span several records (RFC 8446 §5.1). `Ok(None)` =
/// the message isn't fully buffered yet; `Err` = the first record isn't a
/// handshake record or the first message isn't a ClientHello. The client's
/// first flight is never encrypted, so no keys are involved.
///
/// # Work bound
///
/// A version-dispatching server front end calls this on *every* `feed` until
/// the ClientHello resolves, so the incomplete case must stay cheap. It runs
/// in two phases: a header-only pre-scan that walks the record framing without
/// copying anything, and — only once the buffer actually holds the whole first
/// handshake message — a single copy of exactly that message. Copying every
/// buffered fragment on every call instead would be quadratic in the record
/// count: with the caller's 64 KiB peek ceiling, ~10,900 six-byte records cost
/// on the order of 360 MB of `memcpy` for 64 KiB of input.
fn peek_decode_client_hello(buf: &[u8]) -> Result<Option<ClientHello>, Error> {
    // Phase 1 — pre-scan. Walk record headers only: total the handshake bytes
    // buffered so far and pick the 4-byte handshake header (which may itself
    // straddle records) out of the leading fragments.
    let mut header = [0u8; 4];
    let mut header_len = 0usize;
    let mut available = 0usize;
    let mut needed: Option<usize> = None;
    let mut offset = 0usize;
    loop {
        // Not enough bytes for another full record — need more from the wire.
        let Some(rec) = read_record(&buf[offset..])? else {
            return Ok(None);
        };
        // The client's first flight is handshake records only.
        if rec.content_type != ContentType::Handshake {
            return Err(Error::UnexpectedMessage);
        }
        for &b in rec.fragment.iter().take(4 - header_len) {
            header[header_len] = b;
            header_len += 1;
        }
        available += rec.fragment.len();
        offset += rec.len;
        if needed.is_none() && header_len == 4 {
            if header[0] != hs_type::CLIENT_HELLO {
                return Err(Error::UnexpectedMessage);
            }
            let body_len =
                ((header[1] as usize) << 16) | ((header[2] as usize) << 8) | (header[3] as usize);
            needed = Some(4 + body_len);
        }
        if needed.is_some_and(|n| available >= n) {
            break;
        }
    }

    // Phase 2 — the message is fully buffered; copy exactly its bytes.
    let needed = needed.expect("the loop only breaks once `needed` is known");
    let mut handshake: Vec<u8> = Vec::with_capacity(needed);
    let mut offset = 0usize;
    while handshake.len() < needed {
        let rec = read_record(&buf[offset..])?.expect("records already validated in phase 1");
        let take = core::cmp::min(rec.fragment.len(), needed - handshake.len());
        handshake.extend_from_slice(&rec.fragment[..take]);
        offset += rec.len;
    }
    Ok(Some(ClientHello::decode(&handshake[4..])?))
}

/// Decodes a complete ClientHello out of the accumulated handshake bytes.
/// `Ok(None)` means more bytes are needed; `Err` means the first handshake
/// message is malformed or isn't a ClientHello.
// Reached only through `client_hello_info_from_handshake` (the QUIC peek
// path); the record-framed path decodes in place after its pre-scan.
#[allow(dead_code)]
fn decode_first_client_hello(handshake: &[u8]) -> Result<Option<ClientHello>, Error> {
    // Handshake message header: msg_type(1) || length(3) || body.
    if handshake.len() < 4 {
        return Ok(None);
    }
    if handshake[0] != hs_type::CLIENT_HELLO {
        return Err(Error::UnexpectedMessage);
    }
    let body_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);
    if handshake.len() < 4 + body_len {
        return Ok(None);
    }
    Ok(Some(ClientHello::decode(&handshake[4..4 + body_len])?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::codec::CipherSuite;

    /// Wraps an encoded handshake message in one or more TLS handshake records
    /// of at most `chunk` fragment bytes each.
    fn records(msg: &[u8], chunk: usize) -> Vec<u8> {
        let mut out = Vec::new();
        for frag in msg.chunks(chunk.max(1)) {
            out.push(ContentType::Handshake.as_u8());
            out.extend_from_slice(&0x0301u16.to_be_bytes());
            out.extend_from_slice(&(frag.len() as u16).to_be_bytes());
            out.extend_from_slice(frag);
        }
        out
    }

    fn sample_client_hello() -> Vec<u8> {
        ClientHello {
            legacy_version: 0x0303,
            random: [0x42u8; 32],
            session_id: Vec::new(),
            cipher_suites: alloc::vec![CipherSuite(0x1301)],
            extensions: alloc::vec![
                ext::server_name("example.com"),
                ext::alpn_protocols(&[b"h2".as_slice(), b"acme-tls/1".as_slice()]),
            ],
        }
        .encode()
    }

    #[test]
    fn peeks_sni_and_alpn_in_one_record() {
        let buf = records(&sample_client_hello(), 4096);
        let before = buf.clone();
        let info = peek_client_hello(&buf).unwrap().unwrap();
        assert_eq!(info.server_name.as_deref(), Some("example.com"));
        assert_eq!(
            info.alpn_protocols,
            alloc::vec![b"h2".to_vec(), b"acme-tls/1".to_vec()]
        );
        assert_eq!(buf, before, "peek must not consume the buffer");
    }

    #[test]
    fn reassembles_client_hello_split_across_records() {
        // Tiny fragments force the ClientHello to span many handshake records.
        let buf = records(&sample_client_hello(), 7);
        let info = peek_client_hello(&buf).unwrap().unwrap();
        assert_eq!(info.server_name.as_deref(), Some("example.com"));
        assert_eq!(info.alpn_protocols.len(), 2);
    }

    #[test]
    fn incomplete_buffer_needs_more_bytes() {
        let full = records(&sample_client_hello(), 4096);
        // Every strict prefix is "need more bytes", never an error or a result.
        for n in 0..full.len() {
            assert_eq!(
                peek_client_hello(&full[..n]).unwrap(),
                None,
                "prefix of length {n} should ask for more bytes"
            );
        }
        assert!(peek_client_hello(&full).unwrap().is_some());
    }

    #[test]
    fn client_hello_without_sni_or_alpn() {
        let msg = ClientHello {
            legacy_version: 0x0303,
            random: [0u8; 32],
            session_id: Vec::new(),
            cipher_suites: alloc::vec![CipherSuite(0x1301)],
            extensions: Vec::new(),
        }
        .encode();
        let info = peek_client_hello(&records(&msg, 4096)).unwrap().unwrap();
        assert_eq!(info.server_name, None);
        assert!(info.alpn_protocols.is_empty());
    }

    /// The incomplete-buffer path must not re-copy every buffered fragment on
    /// each call (finding: quadratic re-parse). Feeding a long prefix of a
    /// heavily-fragmented ClientHello one record at a time — the pattern the
    /// version-auto server front end produces — has to stay fast; before the
    /// pre-scan this loop copied O(n²) bytes.
    #[test]
    fn incremental_peek_of_a_fragmented_client_hello_is_not_quadratic() {
        // ~1,200 six-byte fragments: enough that a quadratic implementation
        // does hundreds of megabytes of copying and a linear one is instant.
        let mut msg = sample_client_hello();
        msg.resize(7000, 0);
        // Fix up the declared body length so the message stays self-consistent
        // (the trailing zeros are never decoded — we only ever ask for
        // "more bytes" here).
        let body_len = msg.len() - 4;
        msg[1] = (body_len >> 16) as u8;
        msg[2] = (body_len >> 8) as u8;
        msg[3] = body_len as u8;
        let full = records(&msg, 6);
        // Every record boundary is a "need more bytes" call. Only strict
        // prefixes are fed: the padded body is not a decodable ClientHello,
        // and the point of the test is the incomplete path.
        let mut offset = 11usize; // 5-byte record header + 6-byte fragment
        while offset < full.len() {
            assert_eq!(peek_client_hello(&full[..offset]).unwrap(), None);
            offset += 11;
        }
    }

    #[test]
    fn non_handshake_first_record_is_rejected() {
        // An application_data record where a handshake was expected (e.g. a peer
        // speaking the wrong protocol).
        let buf = alloc::vec![23u8, 0x03, 0x03, 0x00, 0x02, 0xAB, 0xCD];
        assert!(peek_client_hello(&buf).is_err());
    }
}
