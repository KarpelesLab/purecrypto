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

/// Whether a decoded ClientHello offers TLS 1.3 in `supported_versions`
/// (RFC 8446 §4.1.1 / Appendix D.1). The deferred server front end feeds a
/// [`ClientHelloPeeker`] and dispatches on this: `true` → the 1.3 engine;
/// `false` → a legacy 1.2-only client → the 1.2 / legacy engine. Mirrors the
/// server's own selection: the 1.2 engine deliberately ignores the *content*
/// of `supported_versions` and caps at TLS 1.2, so the only question is
/// whether 1.3 was offered at all.
pub(crate) fn client_hello_offers_tls13(ch: &ClientHello) -> Result<bool, Error> {
    match ext::find(&ch.extensions, ExtensionType::SUPPORTED_VERSIONS) {
        Some(sv) => ext::client_offers_tls13(sv),
        None => Ok(false),
    }
}

/// Reassembles the first handshake message from the leading handshake records of
/// `buf` and decodes it as a [`ClientHello`], **without consuming `buf`**. A
/// ClientHello may legally span several records (RFC 8446 §5.1). `Ok(None)` =
/// the message isn't fully buffered yet; `Err` = the first record isn't a
/// handshake record or the first message isn't a ClientHello. The client's
/// first flight is never encrypted, so no keys are involved.
///
/// One-shot form of [`ClientHelloPeeker`]: every call starts from offset 0, so
/// a caller that re-invokes it on a growing buffer pays for the whole prefix
/// each time. A front end that feeds bytes incrementally should hold a
/// `ClientHelloPeeker` instead so each byte is scanned exactly once.
fn peek_decode_client_hello(buf: &[u8]) -> Result<Option<ClientHello>, Error> {
    ClientHelloPeeker::default().feed(buf)
}

/// Incremental, non-consuming reassembly of the first ClientHello out of a
/// buffer of TLS records that grows between calls.
///
/// A version-dispatching server front end has to look at the ClientHello
/// before it can pick an engine, and it sees the wire bytes in whatever
/// segments the transport delivers. Re-parsing the whole buffer from offset 0
/// on every segment is quadratic in the record count: with the front end's
/// 64 KiB ceiling, a ClientHello chopped into ~10,900 six-byte records and
/// delivered a byte at a time would cost ~3.5 × 10⁸ record-header parses.
/// This keeps a cursor instead — [`feed`](Self::feed) resumes where the
/// previous call stopped, so every record is parsed once and every handshake
/// byte is copied once.
///
/// The caller's buffer must only ever grow by appending; the cursor indexes
/// into it.
#[derive(Default)]
pub(crate) struct ClientHelloPeeker {
    /// Bytes of the caller's buffer already parsed into complete records.
    scanned: usize,
    /// Handshake bytes gathered so far (never more than `needed`).
    handshake: Vec<u8>,
    /// Total length of the first handshake message (header included), once
    /// its 4-byte header has been seen.
    needed: Option<usize>,
    /// Number of complete records parsed so far (work counter for tests).
    #[cfg(test)]
    records_parsed: usize,
}

impl ClientHelloPeeker {
    /// Continues scanning `buf` from where the previous call stopped. Returns
    /// `Ok(None)` while the first handshake message is incomplete,
    /// `Ok(Some(ch))` once it decodes, and `Err` if the leading bytes are not
    /// a well-formed client first flight (a non-handshake record, a
    /// zero-length handshake fragment — RFC 8446 §5.1 — or a first message
    /// that isn't a ClientHello).
    pub(crate) fn feed(&mut self, buf: &[u8]) -> Result<Option<ClientHello>, Error> {
        loop {
            if let Some(n) = self.needed
                && self.handshake.len() >= n
            {
                return Ok(Some(ClientHello::decode(&self.handshake[4..n])?));
            }
            // Not enough bytes for another full record — need more from the
            // wire. `read_record` only looks at the (at most) 5-byte header
            // in this case, so an incomplete tail costs O(1) per call.
            let Some(rec) = read_record(&buf[self.scanned..])? else {
                return Ok(None);
            };
            // The client's first flight is handshake records only.
            if rec.content_type != ContentType::Handshake {
                return Err(Error::UnexpectedMessage);
            }
            // RFC 8446 §5.1: implementations MUST NOT send zero-length
            // handshake fragments. Accepting them would let a peer spend our
            // per-record parse budget without ever advancing the message.
            if rec.fragment.is_empty() {
                return Err(Error::UnexpectedMessage);
            }
            #[cfg(test)]
            {
                self.records_parsed += 1;
            }
            let take = match self.needed {
                Some(n) => core::cmp::min(rec.fragment.len(), n - self.handshake.len()),
                None => rec.fragment.len(),
            };
            self.handshake.extend_from_slice(&rec.fragment[..take]);
            self.scanned += rec.len;
            if self.needed.is_none() && self.handshake.len() >= 4 {
                if self.handshake[0] != hs_type::CLIENT_HELLO {
                    return Err(Error::UnexpectedMessage);
                }
                let body_len = ((self.handshake[1] as usize) << 16)
                    | ((self.handshake[2] as usize) << 8)
                    | (self.handshake[3] as usize);
                let needed = 4 + body_len;
                // The record that completed the header may carry bytes of
                // whatever follows the ClientHello; keep only the message.
                self.handshake.truncate(needed);
                self.needed = Some(needed);
            }
        }
    }
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

    /// TLS-CORE-5 — RFC 8446 §5.1: zero-length handshake fragments MUST NOT
    /// be sent; a peer that emits them is only spending our parse budget.
    #[test]
    fn zero_length_handshake_fragment_is_rejected() {
        let mut buf = alloc::vec![22u8, 0x03, 0x01, 0x00, 0x00];
        buf.extend_from_slice(&records(&sample_client_hello(), 4096));
        assert!(matches!(
            peek_client_hello(&buf),
            Err(Error::UnexpectedMessage)
        ));
        // Also mid-message, not just as the first record.
        let mut buf = records(&sample_client_hello(), 7);
        let cut = 5 + 7; // after the first record
        buf.splice(cut..cut, [22u8, 0x03, 0x01, 0x00, 0x00]);
        assert!(matches!(
            peek_client_hello(&buf),
            Err(Error::UnexpectedMessage)
        ));
    }

    /// TLS-CORE-5 — the incremental peeker must parse each record exactly
    /// once no matter how the transport segments the bytes. A ClientHello
    /// padded to a few thousand bytes, chopped into one-byte-payload records
    /// and delivered one byte at a time used to be re-scanned from offset 0
    /// on every byte (quadratic in the record count).
    #[test]
    fn incremental_peeker_parses_each_record_once() {
        // Pad with an unknown-type extension so the message stays decodable.
        let msg = ClientHello {
            legacy_version: 0x0303,
            random: [0x42u8; 32],
            session_id: Vec::new(),
            cipher_suites: alloc::vec![CipherSuite(0x1301)],
            extensions: alloc::vec![
                ext::server_name("example.com"),
                (ExtensionType(0x0015), alloc::vec![0u8; 3000]),
            ],
        }
        .encode();
        let full = records(&msg, 1);
        let record_count = msg.len();

        let mut peeker = ClientHelloPeeker::default();
        let mut buffered: Vec<u8> = Vec::new();
        let mut resolved = None;
        for &b in &full {
            buffered.push(b);
            if let Some(ch) = peeker.feed(&buffered).unwrap() {
                resolved = Some(ch);
                break;
            }
        }
        let ch = resolved.expect("the ClientHello must resolve");
        assert_eq!(ch.extensions.len(), 2);
        assert_eq!(
            peeker.records_parsed, record_count,
            "every record is parsed exactly once"
        );
        assert_eq!(peeker.scanned, full.len());
    }

    #[test]
    fn non_handshake_first_record_is_rejected() {
        // An application_data record where a handshake was expected (e.g. a peer
        // speaking the wrong protocol).
        let buf = alloc::vec![23u8, 0x03, 0x03, 0x00, 0x02, 0xAB, 0xCD];
        assert!(peek_client_hello(&buf).is_err());
    }
}
