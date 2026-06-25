//! Non-destructive QUIC **Initial** inspection — read the SNI / ALPN out of the
//! ClientHello *before* building a connection.
//!
//! The HTTP/3 analog of [`crate::tls::peek_client_hello`]. A QUIC server that
//! picks its certificate per connection (SNI virtual hosting, on-demand ACME,
//! TLS-ALPN-01) needs the ClientHello's SNI before the handshake — but in QUIC
//! the ClientHello rides inside the AEAD-protected Initial packet. The Initial
//! keys are derived deterministically from the client's Destination Connection
//! ID via a fixed public salt (RFC 9001 §5.2), so anyone — including this peek —
//! can decrypt an Initial; no secret material is involved.
//!
//! [`peek_initial_sni`] derives those keys from the datagram's DCID, removes
//! header protection, AEAD-opens the payload, reassembles the CRYPTO stream, and
//! parses the ClientHello — **without owning a [`QuicConnection`](super::QuicConnection)**
//! and without mutating the caller's buffer. It reuses the same ClientHello
//! parsing as the TCP peek (`crate::tls::peek`).

use alloc::vec::Vec;

use crate::tls::{ClientHelloInfo, Error};

use super::crypto::{AeadAlg, DirKeys, aead_open, derive_dir_keys, derive_initial_secrets};
use super::crypto_buf::CryptoBuf;
use super::frame::Frame;
use super::pkt::{LongHeader, LongType, QUIC_V1, remove_header_protection};
use super::pn::decode_packet_number;

/// Inspects the first QUIC **Initial** packet in `datagram` and extracts the
/// ClientHello's SNI + offered ALPN, **without consuming or mutating `datagram`**.
///
/// - `Ok(Some(info))` — the Initial decrypted and a complete ClientHello was
///   recovered; `info` carries its SNI and ALPN.
/// - `Ok(None)` — the datagram is too short to hold the whole packet, or the
///   ClientHello's CRYPTO stream isn't complete in this datagram. (A client's
///   first Initial is padded to ≥1200 bytes and the ClientHello virtually always
///   fits in one datagram; feed the first datagram you receive.)
/// - `Err(_)` — not a QUIC v1 Initial long-header packet
///   ([`Error::UnsupportedVersion`] for a non-v1 version), or the AEAD tag failed
///   (wrong DCID / tampered / not actually an Initial we can read), or the frames
///   were malformed.
///
/// Initial AEAD is always AES-128-GCM with SHA-256 keys (RFC 9001 §5.2). The
/// packet number is decoded against a baseline of 0 — correct for a client's
/// first Initial (the cert-selection use case); a coalesced or retransmitted
/// Initial carrying a large packet number is out of scope for this stateless peek.
///
/// This decrypts attacker-controlled bytes with publicly-derivable keys, exactly
/// like the TCP [`peek_client_hello`](crate::tls::peek_client_hello); it touches
/// no secret material, never panics on malformed input, and bounds CRYPTO
/// reassembly (64 KiB / 32 fragments) against a pre-handshake flood.
pub fn peek_initial_sni(datagram: &[u8]) -> Result<Option<ClientHelloInfo>, Error> {
    // The ClientHello's CRYPTO stream can be split across several Initial
    // packets coalesced into one datagram (ngtcp2/curl do this), so walk every
    // coalesced Initial — exactly like the engine's `feed_datagram` — feeding
    // all CRYPTO into one reassembly buffer. The CryptoBuf caps (64 KiB / 32
    // fragments) bound a pre-handshake flood.
    let mut crypto = CryptoBuf::new();
    let mut handshake: Vec<u8> = Vec::new();
    // Coalesced Initials share the client DCID, so the keys are derived once.
    let mut keys: Option<DirKeys> = None;
    let mut off = 0usize;

    while off < datagram.len() {
        let rest = &datagram[off..];
        // A region that no longer parses as a long header ends the walk — e.g.
        // trailing 0x00 datagram padding, or a short header, after the last
        // coalesced packet. Only the very first packet must be a real Initial.
        let hdr = match LongHeader::parse(rest) {
            Ok(h) => h,
            Err(_) if off > 0 => break,
            Err(e) => return Err(e),
        };
        // Only QUIC v1 has a defined Initial salt here (also catches Version
        // Negotiation, version == 0).
        if hdr.version != QUIC_V1 {
            if off == 0 {
                return Err(Error::UnsupportedVersion);
            }
            break;
        }
        if hdr.typ != LongType::Initial {
            // 0-RTT / Handshake / Retry don't carry the ClientHello, and their
            // keys aren't derivable here; stop at the first non-Initial.
            if off == 0 {
                return Err(Error::Decode);
            }
            break;
        }

        // RFC 9000 §17.2: `length` covers PN + payload + tag.
        let pkt_total = hdr
            .payload_off
            .checked_add(hdr.length as usize)
            .ok_or(Error::Decode)?;
        if rest.len() < pkt_total {
            // The (first) packet isn't fully buffered — ask for more.
            if off == 0 {
                return Ok(None);
            }
            break;
        }

        // RFC 9001 §5.2: derive the client's Initial read keys from the DCID.
        let keys = keys.get_or_insert_with(|| {
            let (client_secret, _server_secret) = derive_initial_secrets(hdr.dcid);
            derive_dir_keys(AeadAlg::Aes128Gcm, &client_secret)
        });

        // Owned copy of this packet — header protection and AEAD mutate it, and
        // we must not touch the caller's `datagram`.
        let mut pkt = rest[..pkt_total].to_vec();

        // Remove header protection (RFC 9001 §5.4): sample 16 bytes at pn_offset+4.
        let sample_start = hdr.pn_offset.checked_add(4).ok_or(Error::Decode)?;
        let sample_end = sample_start.checked_add(16).ok_or(Error::Decode)?;
        if sample_end > pkt.len() {
            return Err(Error::Decode);
        }
        let sample: [u8; 16] = pkt[sample_start..sample_end]
            .try_into()
            .expect("16-byte sample slice");
        let mask = keys.hp.mask(&sample)?;
        let pn_len = remove_header_protection(&mut pkt, hdr.pn_offset, &mask, true)?;

        // Recover the (truncated) packet number; decode against a 0 baseline —
        // a client's first-flight Initials use small PNs.
        let mut truncated_pn = 0u64;
        for i in 0..pn_len as usize {
            truncated_pn = (truncated_pn << 8) | pkt[hdr.pn_offset + i] as u64;
        }
        let pn = decode_packet_number(0, truncated_pn, (pn_len as u32) * 8);

        // AEAD: AAD = unprotected header [0 .. pn_offset+pn_len]; ciphertext+tag
        // is the rest, tag = last 16 bytes (RFC 9001 §5.3).
        let aad_end = hdr.pn_offset + pn_len as usize;
        let aad = pkt[..aad_end].to_vec();
        let ct_with_tag = &mut pkt[aad_end..];
        if ct_with_tag.len() < 16 {
            return Err(Error::Decode);
        }
        let tag_start = ct_with_tag.len() - 16;
        let tag: [u8; 16] = ct_with_tag[tag_start..]
            .try_into()
            .expect("16-byte tag slice");
        let payload = &mut ct_with_tag[..tag_start];
        // Tag failure (wrong DCID / tampered / unreadable) surfaces as an error.
        aead_open(keys, pn, &aad, payload, &tag)?;

        // Reassemble CRYPTO from this packet's frames (raw TLS handshake bytes,
        // no record framing). PADDING / PING / ACK are irrelevant.
        let mut p = 0usize;
        while p < payload.len() {
            let (frame, n) = Frame::decode(&payload[p..])?;
            if n == 0 {
                break; // defensive: Frame::decode always consumes ≥1
            }
            p += n;
            if let Frame::Crypto { offset, data } = frame {
                let fresh = crypto.on_crypto(offset, data)?;
                handshake.extend_from_slice(&fresh);
            }
        }

        // A complete ClientHello yet? (Shared with the TCP peek.)
        if let Some(info) = crate::tls::peek::client_hello_info_from_handshake(&handshake)? {
            return Ok(Some(info));
        }

        off += pkt_total;
    }

    // Walked every coalesced packet; the ClientHello isn't complete in this
    // datagram (the rest is in a later one).
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{QuicConfig, QuicConnection};

    /// Build a real client Initial via the QUIC client engine, then prove
    /// `peek_initial_sni` decrypts it and recovers the SNI + ALPN.
    fn client_initial_datagram(server_name: &str, alpn: &[&[u8]]) -> Vec<u8> {
        let tls = crate::tls::Config::builder()
            .rng(alloc::sync::Arc::new(crate::rng::OsRng))
            .tls_only()
            .server_name(server_name)
            .verify_certificates(false)
            .alpn(alpn.iter().map(|p| p.to_vec()).collect())
            .build();
        let cfg = QuicConfig {
            tls,
            ..QuicConfig::default()
        };
        let mut client = QuicConnection::client(cfg, server_name).expect("client");
        // The first emitted datagram carries the Initial with the ClientHello.
        let dg = client.pop_datagram();
        assert!(!dg.is_empty(), "expected an Initial datagram");
        dg
    }

    #[test]
    fn peeks_sni_and_alpn_from_real_initial() {
        let dg = client_initial_datagram("h3.example", &[b"h3"]);
        let before = dg.clone();
        let info = peek_initial_sni(&dg).expect("ok").expect("complete CH");
        assert_eq!(info.server_name.as_deref(), Some("h3.example"));
        assert_eq!(info.alpn_protocols, alloc::vec![b"h3".to_vec()]);
        assert_eq!(dg, before, "peek must not mutate the datagram");
    }

    #[test]
    fn unknown_version_is_rejected() {
        let mut dg = client_initial_datagram("x.example", &[b"h3"]);
        // Flip the version field (bytes 1..5) to a non-v1 value.
        dg[1] = 0x6b;
        dg[2] = 0x33;
        dg[3] = 0x43;
        dg[4] = 0xcf;
        assert!(matches!(
            peek_initial_sni(&dg),
            Err(Error::UnsupportedVersion)
        ));
    }

    #[test]
    fn tampered_ciphertext_fails_aead_no_panic() {
        let mut dg = client_initial_datagram("x.example", &[b"h3"]);
        // Flip a byte near the end (inside the AEAD-protected payload/tag).
        let n = dg.len();
        dg[n - 1] ^= 0xff;
        assert!(peek_initial_sni(&dg).is_err());
    }

    #[test]
    fn short_header_packet_is_rejected() {
        // A short-header (0x40) packet is not an Initial long header.
        let buf = alloc::vec![0x40u8, 0x00, 0x01, 0x02, 0x03];
        assert!(peek_initial_sni(&buf).is_err());
    }

    #[test]
    fn truncated_datagram_does_not_panic() {
        let dg = client_initial_datagram("x.example", &[b"h3"]);
        for n in 0..dg.len() {
            // Every prefix must return cleanly (Ok(None) / Err), never panic.
            let _ = peek_initial_sni(&dg[..n]);
        }
    }

    /// Seal a hand-built Initial payload into a wire packet using v1 Initial
    /// keys derived from `dcid` — lets us drive arbitrary frame layouts.
    fn seal_initial(dcid: &[u8], plaintext: &mut [u8]) -> Vec<u8> {
        use super::super::crypto::aead_seal;
        use super::super::pkt::{apply_header_protection, build_long_header};
        let (cs, _ss) = derive_initial_secrets(dcid);
        let keys = derive_dir_keys(AeadAlg::Aes128Gcm, &cs);
        let pn: u64 = 0;
        let pn_len: u8 = 1;
        let payload_len_field = pn_len as u64 + plaintext.len() as u64 + 16;
        let (hdr, pn_offset) = build_long_header(
            LongType::Initial,
            QUIC_V1,
            dcid,
            &[],
            &[],
            pn,
            pn_len,
            payload_len_field,
        );
        let tag = aead_seal(&keys, pn, &hdr, plaintext); // encrypts in place
        let mut pkt = hdr;
        pkt.extend_from_slice(plaintext);
        pkt.extend_from_slice(&tag);
        let sample: [u8; 16] = pkt[pn_offset + 4..pn_offset + 4 + 16].try_into().unwrap();
        let mask = keys.hp.mask(&sample).unwrap();
        apply_header_protection(&mut pkt, pn_offset, pn_len, &mask, true);
        pkt
    }

    fn sample_client_hello(sni: &str) -> Vec<u8> {
        use crate::tls::codec::extension as ext;
        use crate::tls::codec::{CipherSuite, ClientHello};
        ClientHello {
            legacy_version: 0x0303,
            random: [7u8; 32],
            session_id: Vec::new(),
            cipher_suites: alloc::vec![CipherSuite(0x1301)],
            extensions: alloc::vec![
                ext::server_name(sni),
                ext::alpn_protocols(&[b"h3".as_slice()]),
            ],
        }
        .encode()
    }

    /// curl/ngtcp2 layout: PADDING frames BEFORE the CRYPTO frame. The peek must
    /// skip them and still recover the ClientHello.
    #[test]
    fn padding_before_crypto_is_handled() {
        use super::super::frame::Frame;
        let ch = sample_client_hello("curl.example");
        let dcid = [0x11u8; 8];
        let mut pt = Vec::new();
        pt.extend(core::iter::repeat_n(0u8, 30)); // leading PADDING
        Frame::Crypto {
            offset: 0,
            data: &ch,
        }
        .encode(&mut pt);
        let dg = seal_initial(&dcid, &mut pt);
        let info = peek_initial_sni(&dg).expect("ok").expect("complete CH");
        assert_eq!(info.server_name.as_deref(), Some("curl.example"));
        assert_eq!(info.alpn_protocols, alloc::vec![b"h3".to_vec()]);
    }

    /// The ClientHello split across TWO coalesced Initial packets in a single
    /// datagram (ngtcp2/curl emit this). The peek must process every coalesced
    /// Initial, not just the first.
    #[test]
    fn coalesced_initials_reassemble_split_ch() {
        use super::super::frame::Frame;
        let ch = sample_client_hello("coalesce.example");
        let dcid = [0x33u8; 8];
        let mid = ch.len() / 2;
        let mut pt1 = Vec::new();
        Frame::Crypto {
            offset: 0,
            data: &ch[..mid],
        }
        .encode(&mut pt1);
        let mut dg = seal_initial(&dcid, &mut pt1);
        let mut pt2 = Vec::new();
        Frame::Crypto {
            offset: mid as u64,
            data: &ch[mid..],
        }
        .encode(&mut pt2);
        dg.extend_from_slice(&seal_initial(&dcid, &mut pt2));
        let info = peek_initial_sni(&dg)
            .expect("ok")
            .expect("complete CH across coalesced Initials");
        assert_eq!(info.server_name.as_deref(), Some("coalesce.example"));
    }

    /// ClientHello split across several CRYPTO frames (some out of order),
    /// interleaved with PADDING — another shape real clients emit.
    #[test]
    fn split_and_reordered_crypto_is_reassembled() {
        use super::super::frame::Frame;
        let ch = sample_client_hello("split.example");
        let dcid = [0x22u8; 8];
        let mid = ch.len() / 2;
        let mut pt = Vec::new();
        // Second half first (offset = mid), then PADDING, then first half.
        Frame::Crypto {
            offset: mid as u64,
            data: &ch[mid..],
        }
        .encode(&mut pt);
        pt.extend(core::iter::repeat_n(0u8, 10));
        Frame::Crypto {
            offset: 0,
            data: &ch[..mid],
        }
        .encode(&mut pt);
        let dg = seal_initial(&dcid, &mut pt);
        let info = peek_initial_sni(&dg).expect("ok").expect("complete CH");
        assert_eq!(info.server_name.as_deref(), Some("split.example"));
    }
}
