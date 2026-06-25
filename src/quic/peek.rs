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

use super::crypto::{AeadAlg, aead_open, derive_dir_keys, derive_initial_secrets};
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
    let hdr = LongHeader::parse(datagram)?;
    // Only QUIC v1 has a defined Initial salt here; reject everything else
    // (this also catches Version Negotiation, version == 0).
    if hdr.version != QUIC_V1 {
        return Err(Error::UnsupportedVersion);
    }
    if hdr.typ != LongType::Initial {
        // 0-RTT / Handshake / Retry are not where the ClientHello lives.
        return Err(Error::Decode);
    }

    // RFC 9000 §17.2: `length` covers PN + payload + tag, so the packet ends at
    // `payload_off + length`. If the datagram doesn't hold the whole packet yet,
    // we can't decrypt — ask for more (Ok(None)).
    let pkt_total = hdr
        .payload_off
        .checked_add(hdr.length as usize)
        .ok_or(Error::Decode)?;
    if datagram.len() < pkt_total {
        return Ok(None);
    }

    // RFC 9001 §5.2: derive the client's Initial read keys from the DCID.
    let (client_secret, _server_secret) = derive_initial_secrets(hdr.dcid);
    let keys = derive_dir_keys(AeadAlg::Aes128Gcm, &client_secret);

    // Work on an owned copy of just this packet — header protection and AEAD
    // mutate these bytes, and we must not touch the caller's `datagram`.
    let mut pkt = datagram[..pkt_total].to_vec();

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

    // Recover the (truncated) packet number; decode against a 0 baseline — the
    // client's first Initial uses a small PN.
    let mut truncated_pn = 0u64;
    for i in 0..pn_len as usize {
        truncated_pn = (truncated_pn << 8) | pkt[hdr.pn_offset + i] as u64;
    }
    let pn = decode_packet_number(0, truncated_pn, (pn_len as u32) * 8);

    // AEAD: AAD = unprotected header [0 .. pn_offset+pn_len]; ciphertext+tag is
    // the rest, tag = last 16 bytes (RFC 9001 §5.3).
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
    aead_open(&keys, pn, &aad, payload, &tag)?;

    // Reassemble the CRYPTO stream from the decrypted payload's frames. CRYPTO
    // frames carry the raw TLS handshake bytes (no TLS record framing). The
    // CryptoBuf caps (64 KiB / 32 fragments) bound a pre-handshake flood.
    let mut crypto = CryptoBuf::new();
    let mut handshake: Vec<u8> = Vec::new();
    let mut p = 0usize;
    while p < payload.len() {
        let (frame, n) = Frame::decode(&payload[p..])?;
        if n == 0 {
            break; // defensive: Frame::decode always consumes ≥1, never loop forever
        }
        p += n;
        if let Frame::Crypto { offset, data } = frame {
            let fresh = crypto.on_crypto(offset, data)?;
            handshake.extend_from_slice(&fresh);
        }
        // PADDING / PING / ACK / … are irrelevant to the ClientHello.
    }

    // Parse the ClientHello out of the in-order CRYPTO bytes — shared with the
    // TCP peek. `Ok(None)` if the ClientHello isn't fully present yet.
    crate::tls::peek::client_hello_info_from_handshake(&handshake)
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
}
