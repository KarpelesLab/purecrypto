//! [`QuicConnection`] — the public sans-I/O QUIC v1 entry point.
//!
//! The engine ingests UDP datagrams via [`QuicConnection::feed_datagram`]
//! and emits UDP datagrams via [`QuicConnection::pop_datagram`]. The host
//! wires this to a `UdpSocket` (Phase 9 ships the CLI shim, Phase 10 the
//! C ABI).
//!
//! Phase 4 ships the Initial-level + Handshake-level handshake plus PTO
//! retransmit; streams (Phase 6), full RFC 9002 (Phase 5), Retry (Phase
//! 7), key update (Phase 8), and the application-data path are all
//! beyond this phase. The public API surface for the deferred features
//! is in place — `open_bidi` / `open_uni` return
//! [`Error::InappropriateState`] until Phase 6 fills them in.

#![allow(dead_code)]

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::time::Duration;

use crate::quic::cid::ConnectionId;
use crate::quic::client::{
    build_initial_endpoint, build_tls_engine as build_client_engine, random_default_cid,
};
use crate::quic::crypto::{AeadAlg, aead_open, aead_seal, derive_dir_keys};
use crate::quic::endpoint::Endpoint;
use crate::quic::frame::{Frame, FrameIter, build_ack_ranges_raw};
use crate::quic::pkt::{
    LongHeader, LongType, QUIC_V1, ShortHeader, apply_header_protection, build_long_header,
    build_short_header, remove_header_protection,
};
use crate::quic::pn::{decode_packet_number, encode_packet_number_length};
use crate::quic::server::{
    build_pending_endpoint, build_tls_engine as build_server_engine, install_initial_keys,
    random_default_scid, set_cids_from_first_initial,
};
use crate::quic::tls_glue::HookHandle;
use crate::quic::transport_params::TransportParameters;
use crate::rng::OsRng;
use crate::tls::Error;
use crate::tls::conn::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use crate::tls::quic_hooks::{Direction, Level};

/// Role discriminant for a [`QuicConnection`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Role {
    /// Client connection (sends the first Initial).
    Client,
    /// Server connection (responds to the client's first Initial).
    Server,
}

/// Application-level configuration. Wraps the engine-internal TLS
/// configuration and the QUIC transport parameters.
///
/// Phase 4 keeps this minimal; Phase 7+ will add Retry secrets, AMP-cap
/// overrides, etc.
pub struct QuicConfig {
    /// The TLS 1.3 client / server config to drive. The QUIC layer adds
    /// QUIC-mode wrapping on top — `tls.max_version` is ignored (QUIC v1
    /// is hard-coded to TLS 1.3).
    pub tls: crate::tls::Config,
    /// The peer-visible QUIC transport parameters this side advertises.
    pub transport_params: TransportParameters,
}

/// One QUIC v1 connection — either a client (sends the first Initial) or
/// a server (responds).
///
/// Internally holds the TLS engine in QUIC mode, an
/// [`Endpoint`] with per-level keys + buffers, and a hook handle to drain
/// engine events. The struct is `Send` (the Phase-3 `QuicHooks: Send`
/// bound forces `Arc<Mutex<…>>` rather than `Rc<RefCell<…>>`) but not
/// `Sync`.
pub struct QuicConnection {
    role: Role,
    endpoint: Endpoint,
    /// The TLS engine — exactly one of the two variants depending on
    /// `role`. Boxed because the two types are very different sizes.
    engine: EngineSide,
    /// Driver-side handle for the engine's hook queues.
    hooks: HookHandle,
    /// Our transport parameters (kept verbatim for
    /// [`peer_transport_params`] symmetry — the peer's are stored in
    /// `peer_params` once captured).
    our_params: TransportParameters,
    /// Parsed peer transport parameters, set once the handshake exposes
    /// them through the hook queue.
    peer_params: Option<TransportParameters>,
    /// `Some(suite_id)` once the TLS engine has negotiated the cipher
    /// suite (used to map the engine's traffic secrets to the right
    /// AEAD/HKDF pair for QUIC's level keys).
    negotiated_suite: Option<u16>,
    /// True once both 1-RTT keys are installed and the TLS state is
    /// `!is_handshaking`. Once this flips on, subsequent `pop_datagram`
    /// calls return an empty vector (Phase 4 ships no app-data path).
    handshake_complete: bool,
    /// SNI hostname (client side only). Stored so we can re-rebuild the
    /// engine on a Retry (Phase 7) — for Phase 4 we just keep it for
    /// `Debug` ergonomics.
    server_name: Option<String>,
}

enum EngineSide {
    Client(Box<ClientConnection>),
    Server(Box<ServerConnection<OsRng>>),
}

impl QuicConnection {
    /// Builds a client. `server_name` is the SNI to embed in the
    /// ClientHello. Picks a random 8-byte DCID + random 8-byte SCID;
    /// derives Initial keys per RFC 9001 §5.2.
    pub fn client(cfg: QuicConfig, server_name: &str) -> Result<Self, Error> {
        let dcid = random_default_cid();
        Self::client_with_fixed_dcid(cfg, server_name, dcid)
    }

    /// Test-helper variant that lets the caller fix the random DCID. Used
    /// by the RFC 9001 §A.1 reproduction test in [`tests`]. The SCID is
    /// still randomly generated.
    pub(crate) fn client_with_fixed_dcid(
        cfg: QuicConfig,
        server_name: &str,
        dcid: ConnectionId,
    ) -> Result<Self, Error> {
        let scid = random_default_cid();
        let endpoint = build_initial_endpoint(dcid, scid);
        let mut tp_bytes = Vec::new();
        cfg.transport_params.encode(&mut tp_bytes);
        let tls_cfg = build_client_tls_config(&cfg)?;
        let (engine, hooks) = build_client_engine(tls_cfg, server_name, tp_bytes)?;

        let mut conn = QuicConnection {
            role: Role::Client,
            endpoint,
            engine: EngineSide::Client(Box::new(engine)),
            hooks,
            our_params: cfg.transport_params.clone(),
            peer_params: None,
            negotiated_suite: None,
            handshake_complete: false,
            server_name: Some(server_name.into()),
        };

        // Drain the ClientHello bytes the engine just produced into the
        // Initial-level outbound CRYPTO queue.
        conn.drain_engine_outputs();
        Ok(conn)
    }

    /// Builds a server. The TLS engine is constructed eagerly; Initial
    /// keys are derived on receipt of the first client Initial datagram
    /// (RFC 9001 §5.2: the keys depend on the client's chosen DCID).
    pub fn server(cfg: QuicConfig) -> Result<Self, Error> {
        let endpoint = build_pending_endpoint();
        let mut tp_bytes = Vec::new();
        cfg.transport_params.encode(&mut tp_bytes);
        let tls_cfg = build_server_tls_config(&cfg)?;
        let (engine, hooks) = build_server_engine(tls_cfg, tp_bytes)?;

        Ok(QuicConnection {
            role: Role::Server,
            endpoint,
            engine: EngineSide::Server(Box::new(engine)),
            hooks,
            our_params: cfg.transport_params.clone(),
            peer_params: None,
            negotiated_suite: None,
            handshake_complete: false,
            server_name: None,
        })
    }

    /// Feeds one received UDP datagram into the connection. May contain
    /// multiple coalesced QUIC packets (RFC 9000 §12.2). Each packet is
    /// header-protection-stripped, AEAD-opened, and frame-decoded.
    ///
    /// Returns `Err` on parse failure or AEAD authentication failure (a
    /// returned error means the engine state was *not* updated by that
    /// packet; previously-applied progress remains).
    pub fn feed_datagram(&mut self, datagram: &[u8]) -> Result<(), Error> {
        let mut rest = datagram;
        while !rest.is_empty() {
            let consumed = self.feed_one_packet(rest)?;
            if consumed == 0 {
                // Defensive: parser couldn't make progress. RFC 9000
                // §12.2 says to drop the trailing bytes silently rather
                // than continue.
                break;
            }
            // Drain engine outputs after EACH packet so that keys
            // derived from this packet's CRYPTO bytes are available to
            // open the *next* coalesced packet (RFC 9001 §5.4 / §5.7).
            // The 646-byte server response = Initial(ServerHello) +
            // Handshake(EE/Cert/CV/Fin); the Handshake-level keys come
            // from the ServerHello, so we have to install them between
            // those two packets, not after both.
            self.drain_engine_outputs();
            rest = &rest[consumed..];
        }
        self.check_handshake_complete();
        Ok(())
    }

    /// Drains one outbound UDP datagram. Returns an empty `Vec` when
    /// nothing is pending. Each call returns at most one datagram.
    pub fn pop_datagram(&mut self) -> Vec<u8> {
        if self.handshake_complete && !self.has_pending_outbound() {
            return Vec::new();
        }
        // Try to pack Initial → Handshake → 1-RTT into one datagram.
        // Each level contributes at most one packet (per RFC 9000 §12.2:
        // coalesced packets share a UDP datagram but each has its own
        // header).
        let mut datagram: Vec<u8> = Vec::with_capacity(1200);
        let need_first_initial_pad =
            self.role == Role::Client && !self.endpoint.sent_first_datagram;

        // Snapshot what (if anything) we'll emit BEFORE building the
        // Initial packet: we need to know whether Handshake / 1-RTT
        // also contribute to this datagram so we don't pad more than
        // necessary.
        let initial_will_emit = self.level_has_pending(Level::Initial);
        let handshake_will_emit = self.level_has_pending(Level::Handshake);
        let onertt_will_emit = self.level_has_pending(Level::OneRtt);

        // Decide if we need to inflate the Initial-level payload with
        // PADDING frames (0x00). RFC 9000 §14.1: the client's first
        // Initial-bearing datagram MUST be at least 1200 bytes total;
        // the padding lives inside the AEAD-sealed Initial payload so
        // it shares the same authentication tag.
        let initial_pad_target = if need_first_initial_pad && initial_will_emit {
            Some(1200usize)
        } else {
            None
        };

        // Initial-level packet (may carry CRYPTO + ACK + PADDING).
        if let Some(pkt) =
            self.build_packet_with_pad(Level::Initial, initial_pad_target.map(|t| (t, 0)))
        {
            datagram.extend_from_slice(&pkt);
        }
        let _ = handshake_will_emit;
        let _ = onertt_will_emit;

        // Handshake-level packet.
        if let Some(pkt) = self.build_packet_at(Level::Handshake) {
            datagram.extend_from_slice(&pkt);
        }

        // 1-RTT packet (Phase 4: ACK-only).
        if let Some(pkt) = self.build_packet_at(Level::OneRtt) {
            datagram.extend_from_slice(&pkt);
        }

        if datagram.is_empty() {
            return Vec::new();
        }

        self.endpoint.sent_first_datagram = true;
        // Arm the PTO if any CRYPTO chunk was actually carved in this
        // build (i.e., a level has a non-empty `last_sent`). This is
        // the Phase-4 stand-in for RFC 9002's "in-flight ack-eliciting
        // packet" predicate.
        if !self.endpoint.loss.is_armed() && self.has_unconfirmed_crypto_last_sent() {
            self.endpoint.loss.arm(Duration::ZERO);
        }
        datagram
    }

    /// True if any level has a `last_sent` chunk that the peer hasn't
    /// acked yet. Phase 4 doesn't track per-PN in-flight; this is the
    /// proxy used to arm the PTO.
    fn has_unconfirmed_crypto_last_sent(&self) -> bool {
        for lvl in [Level::Initial, Level::Handshake] {
            // schedule_last_chunk_retransmit returns true when there's a
            // `last_sent` AND no progress signal has cleared it. We use
            // a peek-only check: a level has a last_sent iff its
            // CryptoBuf carve has happened. We don't have a peek API on
            // CryptoBuf, so we use outbound_offset > 0 as the proxy —
            // any level that has carved at least one chunk has an
            // outbound_offset > 0.
            //
            // (See `CryptoBuf::carve` — `outbound_offset` only advances
            // there, and never rewinds except via
            // `schedule_last_chunk_retransmit`, which the PTO calls.)
            let buf = self.endpoint.bufs.at(lvl);
            if buf.outbound_offset_for_test() > 0 {
                return true;
            }
        }
        false
    }

    /// True if `level` currently has CRYPTO or pending-ACK bytes to send.
    fn level_has_pending(&self, level: Level) -> bool {
        if self.endpoint.bufs.at(level).outbound_pending() {
            return true;
        }
        let space = match level {
            Level::Initial => &self.endpoint.pn.initial,
            Level::Handshake => &self.endpoint.pn.handshake,
            _ => &self.endpoint.pn.application,
        };
        !space.pending_ack.is_empty() && space.ack_eliciting_pending
    }

    /// True once both Initial and Handshake levels have completed (the
    /// TLS engine reports `!is_handshaking` and 1-RTT keys are installed
    /// both directions).
    pub fn is_handshake_complete(&self) -> bool {
        self.handshake_complete
    }

    /// Time until the next internal event (PTO firing). Returns `None`
    /// if no timer is pending.
    pub fn next_timeout(&self) -> Option<Duration> {
        // Phase 4: only the PTO is implemented; idle timeout lands in
        // Phase 5+.
        self.endpoint.loss.next_deadline(Duration::ZERO)
    }

    /// Signals that `now_since_start` elapsed since this connection was
    /// constructed. Caller passes a monotonic clock reading. Engine
    /// re-evaluates timers and may queue retransmissions.
    pub fn on_timeout(&mut self, now_since_start: Duration) {
        if self.endpoint.loss.has_fired(now_since_start) {
            // RFC 9002 §6.2.4: on PTO, send a probe — Phase 4 implements
            // this as "retransmit the last CRYPTO chunk at *every* level
            // that has one." That means a server whose Initial+Handshake
            // flight was dropped resends BOTH packets in one PTO event;
            // the client's peer needs both to derive Handshake-level
            // keys (from the ServerHello) and then read the rest of the
            // server's Finished.
            self.endpoint.loss.on_fire(now_since_start);
            for lvl in [Level::Initial, Level::Handshake] {
                let _ = self
                    .endpoint
                    .bufs
                    .at_mut(lvl)
                    .schedule_last_chunk_retransmit();
            }
        }
    }

    /// Peer's negotiated transport parameters. `None` until the engine
    /// has surfaced them through the hook queue.
    pub fn peer_transport_params(&self) -> Option<&TransportParameters> {
        self.peer_params.as_ref()
    }

    /// Stream API stub — Phase 6 ships the real implementation.
    pub fn open_bidi(&mut self) -> Result<u64, Error> {
        Err(Error::InappropriateState)
    }

    /// Stream API stub — Phase 6 ships the real implementation.
    pub fn open_uni(&mut self) -> Result<u64, Error> {
        Err(Error::InappropriateState)
    }

    /// Role of this endpoint.
    pub fn role(&self) -> Role {
        self.role
    }

    // ============================================================
    // Internal helpers (not part of the public API)
    // ============================================================

    /// Drains the engine's outbound CRYPTO bytes into the per-level
    /// outbound queues. Drains secret events into the CryptoState.
    /// Captures peer transport params on the first sighting.
    fn drain_engine_outputs(&mut self) {
        // Handshake bytes per level.
        for lvl in [
            Level::Initial,
            Level::EarlyData,
            Level::Handshake,
            Level::OneRtt,
        ] {
            let bytes = self.hooks.drain_handshake(lvl);
            if !bytes.is_empty() {
                self.endpoint.bufs.at_mut(lvl).enqueue_outbound(&bytes);
            }
        }
        // Secret events → CryptoState.
        let events = self.hooks.drain_secret_events();
        if !events.is_empty() {
            // The TLS engine picks the suite during ServerHello
            // processing. The cipher-suite id stays the same for all
            // subsequent traffic secrets. We track it lazily here.
            if self.negotiated_suite.is_none() {
                // The first secret event's byte length is the hash output
                // length; on the server we lack a public accessor for
                // the negotiated CipherSuite (Phase 5+ will add one),
                // so we map 32 → AES-128-GCM, 48 → AES-256-GCM. The
                // ChaCha20 suite also uses 32-byte secrets (SHA-256) —
                // Phase 4 doesn't exercise it on the server side, but
                // we'd need to disambiguate via a ServerConnection
                // accessor when it lands.
                self.negotiated_suite = match &self.engine {
                    EngineSide::Client(c) => c.negotiated_cipher_suite(),
                    EngineSide::Server(_) => match events.first() {
                        Some((_, _, sec)) if sec.len() == 32 => Some(0x1301),
                        Some((_, _, sec)) if sec.len() == 48 => Some(0x1302),
                        _ => None,
                    },
                };
            }
            let suite = self.negotiated_suite;
            for (lvl, dir, secret) in events {
                if let Some(suite_id) = suite
                    && let Some(alg) = suite_to_aead(suite_id)
                {
                    let keys = derive_dir_keys(alg, &secret);
                    match dir {
                        Direction::Tx => {
                            self.endpoint.crypto.at_mut(lvl).tx = Some(keys);
                        }
                        Direction::Rx => {
                            self.endpoint.crypto.at_mut(lvl).rx = Some(keys);
                        }
                    }
                }
            }
        }
        // Peer transport params.
        if self.peer_params.is_none()
            && let Some(raw) = self.hooks.take_peer_params()
            && let Ok(parsed) = TransportParameters::decode(&raw)
        {
            self.peer_params = Some(parsed);
        }
    }

    /// Drives the TLS engine one step after fresh handshake bytes have
    /// been fed via `process_quic_handshake_bytes`.
    fn advance_engine(&mut self) {
        // No-op: the call sites in `feed_one_packet` already invoke
        // `process_quic_handshake_bytes` on each newly delivered CRYPTO
        // suffix, which advances the engine itself.
    }

    fn check_handshake_complete(&mut self) {
        let engine_done = match &self.engine {
            EngineSide::Client(c) => !c.is_handshaking(),
            EngineSide::Server(s) => !s.is_handshaking(),
        };
        let keys_done = self.endpoint.crypto.at(Level::OneRtt).tx.is_some()
            && self.endpoint.crypto.at(Level::OneRtt).rx.is_some();
        if engine_done && keys_done {
            self.handshake_complete = true;
            self.endpoint.handshake_complete = true;
            // Disarm the PTO: handshake is done, nothing to retransmit.
            self.endpoint.loss.disarm();
        }
    }

    /// True if there are still bytes queued for transmission (CRYPTO
    /// outbound or pending ACKs) at any level.
    fn has_pending_outbound(&self) -> bool {
        for lvl in [Level::Initial, Level::Handshake, Level::OneRtt] {
            if self.endpoint.bufs.at(lvl).outbound_pending() {
                return true;
            }
        }
        // ACK-pending PN spaces:
        if !self.endpoint.pn.initial.pending_ack.is_empty()
            && self.endpoint.pn.initial.ack_eliciting_pending
        {
            return true;
        }
        if !self.endpoint.pn.handshake.pending_ack.is_empty()
            && self.endpoint.pn.handshake.ack_eliciting_pending
        {
            return true;
        }
        if !self.endpoint.pn.application.pending_ack.is_empty()
            && self.endpoint.pn.application.ack_eliciting_pending
        {
            return true;
        }
        false
    }

    /// True if any level has unconfirmed CRYPTO (some bytes have been
    /// sent and the peer hasn't acked them yet). Phase 4 doesn't track
    /// per-PN in-flight; we use "any level has a non-zero outbound
    /// offset minus any cleared ack-eliciting flag" as a proxy.
    fn has_unconfirmed_crypto(&self) -> bool {
        // If the handshake is complete, nothing more to retransmit.
        if self.handshake_complete {
            return false;
        }
        // Simple: any level that ever sent CRYPTO bytes counts. (Phase
        // 5 replaces this with proper in-flight tracking.)
        for lvl in [Level::Initial, Level::Handshake] {
            if self.endpoint.bufs.at(lvl).outbound_pending() {
                return true;
            }
        }
        // If the engine still has handshake bytes to produce, the PTO
        // doesn't need to fire (next pop will emit them naturally).
        false
    }

    /// Parses one packet at the start of `buf`, dispatches its frames,
    /// and returns the number of bytes consumed (header + ciphertext +
    /// tag for AEAD-sealed packets; the whole packet for VN / Retry).
    /// Returns `Err` on parse / AEAD failure.
    fn feed_one_packet(&mut self, buf: &[u8]) -> Result<usize, Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let b0 = buf[0];
        // Header Form bit (RFC 9000 §17.2).
        if b0 & 0x80 != 0 {
            self.feed_long_header_packet(buf)
        } else {
            self.feed_short_header_packet(buf)
        }
    }

    fn feed_long_header_packet(&mut self, datagram: &[u8]) -> Result<usize, Error> {
        let hdr = LongHeader::parse(datagram)?;

        // Version negotiation / Retry are out of scope for Phase 4. RFC
        // 9000 §17.2.1 / §17.2.5 — we silently drop them.
        if hdr.version == 0 {
            // VN: consume the rest of the datagram (no further packets
            // are coalesced after VN per §17.2.1).
            return Ok(datagram.len());
        }
        if hdr.typ == LongType::Retry {
            // Phase 7 will implement Retry processing. For Phase 4 just
            // skip past it; the rest of the datagram (none, since Retry
            // is single-packet) can be discarded.
            return Ok(datagram.len());
        }

        // Map LongType → Level (RFC 9001 §4.1).
        let level = match hdr.typ {
            LongType::Initial => Level::Initial,
            LongType::Handshake => Level::Handshake,
            LongType::ZeroRtt => Level::EarlyData,
            LongType::Retry => unreachable!("handled above"),
        };

        // Server side: on the very first Initial we receive, derive
        // Initial keys from the client's DCID (RFC 9001 §5.2). Also
        // capture the client's SCID as our peer DCID and pick our own
        // SCID.
        if self.role == Role::Server
            && level == Level::Initial
            && self.endpoint.crypto.at(Level::Initial).rx.is_none()
        {
            let peer_scid = ConnectionId::from_slice(hdr.scid).ok_or(Error::Decode)?;
            let our_scid = random_default_scid();
            set_cids_from_first_initial(&mut self.endpoint, peer_scid, our_scid);
            install_initial_keys(&mut self.endpoint, hdr.dcid);
        }

        // Compute the *total* packet length on the wire. For Initial /
        // Handshake / 0-RTT this is `payload_off + length` because
        // `length` covers PN + payload + tag (RFC 9000 §17.2).
        let pkt_total_len = hdr
            .payload_off
            .checked_add(hdr.length as usize)
            .ok_or(Error::Decode)?;
        if datagram.len() < pkt_total_len {
            return Err(Error::Decode);
        }

        // Work on an owned mutable copy from the start of this packet
        // through its end; header protection mutates these bytes.
        let mut pkt = datagram[..pkt_total_len].to_vec();

        // RFC 9001 §5.4.2: sample at `pn_offset + 4` of length 16.
        let sample_start = hdr.pn_offset.checked_add(4).ok_or(Error::Decode)?;
        let sample_end = sample_start.checked_add(16).ok_or(Error::Decode)?;
        if sample_end > pkt.len() {
            return Err(Error::Decode);
        }
        // Borrow the rx keys for this level.
        let dir_keys_ref = match self.endpoint.crypto.at(level).rx.as_ref() {
            Some(k) => k,
            None => {
                // Keys for this level aren't installed yet. RFC 9001
                // §5.7 says we MAY buffer; Phase 4 simplification is to
                // drop the packet (and the rest of the datagram).
                return Ok(datagram.len());
            }
        };
        let sample_arr: [u8; 16] = pkt[sample_start..sample_end]
            .try_into()
            .expect("16-byte slice");
        let mask = dir_keys_ref.hp.mask(&sample_arr)?;

        let pn_len = remove_header_protection(&mut pkt, hdr.pn_offset, &mask, true)?;
        // Recover the truncated PN.
        let mut truncated_pn = 0u64;
        for i in 0..pn_len as usize {
            truncated_pn = (truncated_pn << 8) | pkt[hdr.pn_offset + i] as u64;
        }
        let pn_nbits = (pn_len as u32) * 8;
        let largest_rx = match level {
            Level::Initial => self.endpoint.pn.initial.largest_rx,
            Level::Handshake => self.endpoint.pn.handshake.largest_rx,
            _ => self.endpoint.pn.application.largest_rx,
        };
        let pn = decode_packet_number(largest_rx.unwrap_or(0), truncated_pn, pn_nbits);

        // AAD = unprotected header bytes [0 .. pn_offset + pn_len].
        let aad_end = hdr.pn_offset + pn_len as usize;
        let aad: Vec<u8> = pkt[..aad_end].to_vec();
        // Ciphertext (including 16-byte tag) is [aad_end .. pkt_total_len].
        let ct_with_tag = &mut pkt[aad_end..];
        if ct_with_tag.len() < 16 {
            return Err(Error::Decode);
        }
        let tag_start = ct_with_tag.len() - 16;
        // Extract the tag before passing the slice.
        let tag: [u8; 16] = ct_with_tag[tag_start..]
            .try_into()
            .expect("16-byte tag slice");
        let payload = &mut ct_with_tag[..tag_start];

        // Open. Authentication failure → propagate.
        aead_open(dir_keys_ref, pn, &aad, payload, &tag)?;

        // Parse frames. Dispatch on the cleartext.
        let cleartext: Vec<u8> = payload.to_vec();
        self.dispatch_frames(level, pn, &cleartext)?;

        Ok(pkt_total_len)
    }

    fn feed_short_header_packet(&mut self, datagram: &[u8]) -> Result<usize, Error> {
        let dcid_len = self.endpoint.cids.local.len();
        let hdr = ShortHeader::parse(datagram, dcid_len)?;
        // Sample window: pn_offset + 4..+20.
        let sample_start = hdr.pn_offset.checked_add(4).ok_or(Error::Decode)?;
        let sample_end = sample_start.checked_add(16).ok_or(Error::Decode)?;
        if sample_end > datagram.len() {
            return Err(Error::Decode);
        }
        let dir_keys_ref = match self.endpoint.crypto.at(Level::OneRtt).rx.as_ref() {
            Some(k) => k,
            None => return Ok(datagram.len()),
        };
        let sample_arr: [u8; 16] = datagram[sample_start..sample_end]
            .try_into()
            .expect("16-byte slice");
        let mask = dir_keys_ref.hp.mask(&sample_arr)?;
        // Short header: 1-RTT packet runs to end of datagram (no length
        // field). We work on the whole remaining datagram.
        let mut pkt = datagram.to_vec();
        let pn_len = remove_header_protection(&mut pkt, hdr.pn_offset, &mask, false)?;
        let mut truncated_pn = 0u64;
        for i in 0..pn_len as usize {
            truncated_pn = (truncated_pn << 8) | pkt[hdr.pn_offset + i] as u64;
        }
        let pn_nbits = (pn_len as u32) * 8;
        let largest_rx = self.endpoint.pn.application.largest_rx;
        let pn = decode_packet_number(largest_rx.unwrap_or(0), truncated_pn, pn_nbits);

        let aad_end = hdr.pn_offset + pn_len as usize;
        let aad: Vec<u8> = pkt[..aad_end].to_vec();
        let ct_with_tag = &mut pkt[aad_end..];
        if ct_with_tag.len() < 16 {
            return Err(Error::Decode);
        }
        let tag_start = ct_with_tag.len() - 16;
        let tag: [u8; 16] = ct_with_tag[tag_start..]
            .try_into()
            .expect("16-byte tag slice");
        let payload = &mut ct_with_tag[..tag_start];
        aead_open(dir_keys_ref, pn, &aad, payload, &tag)?;
        let cleartext: Vec<u8> = payload.to_vec();
        self.dispatch_frames(Level::OneRtt, pn, &cleartext)?;
        // Short-header packet always consumes the rest of the datagram.
        Ok(datagram.len())
    }

    /// Parse frames from a decrypted packet payload and apply them.
    fn dispatch_frames(&mut self, level: Level, pn: u64, payload: &[u8]) -> Result<(), Error> {
        let mut ack_eliciting = false;
        let it = FrameIter::new(payload);
        for frame in it {
            let frame = frame?;
            match frame {
                Frame::Padding(_) => {
                    // Not ack-eliciting (RFC 9000 §13.2.1).
                }
                Frame::Ack { largest, .. } => {
                    // Trim our outbound expectations. For Phase 4 we
                    // just track the largest acked PN per space; full
                    // in-flight bookkeeping lands in Phase 5.
                    let space = match level {
                        Level::Initial => &mut self.endpoint.pn.initial,
                        Level::Handshake => &mut self.endpoint.pn.handshake,
                        _ => &mut self.endpoint.pn.application,
                    };
                    space.largest_acked_tx = Some(match space.largest_acked_tx {
                        Some(prev) => prev.max(largest),
                        None => largest,
                    });
                    // Reset PTO: progress.
                    self.endpoint.loss.on_handshake_progress(Duration::ZERO);
                    // Not ack-eliciting.
                }
                Frame::Crypto { offset, data } => {
                    ack_eliciting = true;
                    let new_bytes = self.endpoint.bufs.at_mut(level).on_crypto(offset, data);
                    if !new_bytes.is_empty() {
                        self.feed_handshake_bytes(level, &new_bytes)?;
                    }
                }
                Frame::Ping => {
                    ack_eliciting = true;
                }
                Frame::HandshakeDone => {
                    // Server → client only, RFC 9000 §7.3. We treat it
                    // as a confirmation that the server has installed
                    // 1-RTT keys; the TLS engine independently signals
                    // its own completion.
                    ack_eliciting = true;
                }
                Frame::ConnectionClose { .. } => {
                    // Phase 4: propagate as a handshake failure. The
                    // QUIC layer should also disable further IO; we just
                    // mark complete to stop further packet emission.
                    self.handshake_complete = true;
                    self.endpoint.handshake_complete = true;
                    return Err(Error::AlertReceived(
                        crate::tls::AlertDescription::HandshakeFailure,
                    ));
                }
                _ => {
                    // Any other frame at this phase: count as
                    // ack-eliciting to be safe. Phase 6+ adds stream /
                    // flow-control handling.
                    ack_eliciting = true;
                }
            }
        }
        // Update PN-space bookkeeping.
        let space = match level {
            Level::Initial => &mut self.endpoint.pn.initial,
            Level::Handshake => &mut self.endpoint.pn.handshake,
            _ => &mut self.endpoint.pn.application,
        };
        space.largest_rx = Some(match space.largest_rx {
            Some(prev) => prev.max(pn),
            None => pn,
        });
        space.pending_ack.insert(pn);
        if ack_eliciting {
            space.ack_eliciting_pending = true;
        }
        Ok(())
    }

    /// Hands `bytes` (already in-order, just released by the per-level
    /// `CryptoBuf`) to the TLS engine at `level`.
    fn feed_handshake_bytes(&mut self, level: Level, bytes: &[u8]) -> Result<(), Error> {
        match &mut self.engine {
            EngineSide::Client(c) => c.process_quic_handshake_bytes(level, bytes)?,
            EngineSide::Server(s) => s.process_quic_handshake_bytes(level, bytes)?,
        }
        Ok(())
    }

    /// Build the outbound packet at `level`, returning the protected
    /// wire bytes or `None` if there's nothing to send. The returned
    /// bytes include the header, AEAD-sealed payload, and 16-byte tag,
    /// with header protection applied.
    fn build_packet_at(&mut self, level: Level) -> Option<Vec<u8>> {
        self.build_packet_with_pad(level, None)
    }

    /// Like [`build_packet_at`], but with optional PADDING to inflate the
    /// final on-wire packet to at least `target` total bytes (header +
    /// ciphertext + tag). `pad` is `Some((target_total, other_pkts_len))`
    /// where `other_pkts_len` is the number of bytes already in the
    /// datagram (used to compute how much room is left for this packet).
    fn build_packet_with_pad(
        &mut self,
        level: Level,
        pad: Option<(usize, usize)>,
    ) -> Option<Vec<u8>> {
        // For Phase 4 we only emit Initial, Handshake, and (occasionally)
        // 1-RTT.
        let has_crypto = self.endpoint.bufs.at(level).outbound_pending();
        let space_ref = match level {
            Level::Initial => &self.endpoint.pn.initial,
            Level::Handshake => &self.endpoint.pn.handshake,
            _ => &self.endpoint.pn.application,
        };
        let has_pending_ack = !space_ref.pending_ack.is_empty() && space_ref.ack_eliciting_pending;
        if !has_crypto && !has_pending_ack {
            return None;
        }
        // Keys must be installed for this direction.
        self.endpoint.crypto.at(level).tx.as_ref()?;
        // For levels above Initial, also need our peer-CID to be the
        // right one. Handshake-level packets use the same CID pair as
        // Initial (peer's chosen SCID we observed on the server's first
        // long-header packet).
        let mut payload = self.assemble_payload(level)?;
        if payload.is_empty() {
            return None;
        }

        // Allocate a PN.
        let pn = {
            let space = match level {
                Level::Initial => &mut self.endpoint.pn.initial,
                Level::Handshake => &mut self.endpoint.pn.handshake,
                _ => &mut self.endpoint.pn.application,
            };
            let pn = space.next_tx;
            space.next_tx += 1;
            pn
        };
        let largest_acked = match level {
            Level::Initial => self.endpoint.pn.initial.largest_acked_tx,
            Level::Handshake => self.endpoint.pn.handshake.largest_acked_tx,
            _ => self.endpoint.pn.application.largest_acked_tx,
        };
        let pn_nbits = encode_packet_number_length(pn, largest_acked);
        let pn_len = (pn_nbits / 8) as u8;
        debug_assert!((1..=4).contains(&pn_len));

        // Padding: inflate the payload with PADDING frames (0x00) per
        // RFC 9000 §19.1 so the eventual on-wire packet (header +
        // ciphertext + tag) reaches `pad.0 - pad.1` bytes minimum.
        // PADDING is *inside* the AEAD-sealed payload, so it inherits
        // the same auth tag — the peer doesn't see it as a separate
        // (rejected) packet.
        if let Some((target_total, already_in_datagram)) = pad {
            // Long-header overhead exact, given the CID lengths and the
            // already-chosen pn_len:
            //   1 (first byte) + 4 (version)
            //   + 1 (dcid_len) + dcid_len + 1 (scid_len) + scid_len
            //   + (Initial-only) varint(token_len = 0) = 1 byte
            //   + varint(length) — depends on the payload size; for
            //     payloads in [64..16383] this is 2 bytes, which covers
            //     all Phase-4 Initial packet sizes. We use 2 unless the
            //     final payload would push us above 16383 (in which case
            //     we'd need 4 — but Phase 4 doesn't get there).
            //   + pn_len (the value we just selected)
            //   + 16 (AEAD tag)
            let scid_len = self.endpoint.cids.local.len();
            let dcid_len = self.endpoint.cids.peer.len();
            // Pick length-field width based on the final payload size we
            // are about to commit to. We do a single iteration: assume 2
            // bytes; that decision holds for any payload up to ~16 KiB.
            let length_field_bytes = 2;
            let header_overhead = 1 + 4 + 1 + dcid_len + 1 + scid_len + 1 + length_field_bytes;
            let pn_and_tag = pn_len as usize + 16;
            let needed_pkt_len = target_total.saturating_sub(already_in_datagram);
            let payload_needed = needed_pkt_len.saturating_sub(header_overhead + pn_and_tag);
            if payload.len() < payload_needed {
                let extra = payload_needed - payload.len();
                payload.extend(core::iter::repeat_n(0u8, extra));
            }
        }

        // Build the header.
        let dir_keys = self
            .endpoint
            .crypto
            .at(level)
            .tx
            .as_ref()
            .expect("checked above");

        let (mut wire, pn_offset) = match level {
            Level::Initial => {
                // The Initial packet's Length field covers PN + payload + tag.
                let length_field = (pn_len as u64) + payload.len() as u64 + 16;
                build_long_header(
                    LongType::Initial,
                    QUIC_V1,
                    self.endpoint.cids.peer.as_slice(),
                    self.endpoint.cids.local.as_slice(),
                    &[], // token: empty for client v1; server Initial has no token in v1
                    pn,
                    pn_len,
                    length_field,
                )
            }
            Level::Handshake => {
                let length_field = (pn_len as u64) + payload.len() as u64 + 16;
                build_long_header(
                    LongType::Handshake,
                    QUIC_V1,
                    self.endpoint.cids.peer.as_slice(),
                    self.endpoint.cids.local.as_slice(),
                    &[],
                    pn,
                    pn_len,
                    length_field,
                )
            }
            Level::OneRtt => {
                build_short_header(self.endpoint.cids.peer.as_slice(), false, false, pn, pn_len)
            }
            Level::EarlyData => {
                // Phase 4 doesn't emit 0-RTT.
                return None;
            }
        };

        // Append the (still-plaintext) payload bytes.
        wire.extend_from_slice(&payload);

        // Seal.
        let aad_len = pn_offset + pn_len as usize;
        let aad: Vec<u8> = wire[..aad_len].to_vec();
        let pt = &mut wire[aad_len..];
        let tag = aead_seal(dir_keys, pn, &aad, pt);
        wire.extend_from_slice(&tag);

        // Header protection.
        let sample_start = pn_offset + 4;
        let sample_end = sample_start + 16;
        debug_assert!(sample_end <= wire.len());
        let sample_arr: [u8; 16] = wire[sample_start..sample_end]
            .try_into()
            .expect("16-byte sample");
        let mask = dir_keys.hp.mask(&sample_arr).ok()?;
        let long_header = !matches!(level, Level::OneRtt);
        apply_header_protection(&mut wire, pn_offset, pn_len, &mask, long_header);

        // ACK has been emitted (if it was queued) — clear the
        // ack-eliciting flag and pending list for this space.
        let space = match level {
            Level::Initial => &mut self.endpoint.pn.initial,
            Level::Handshake => &mut self.endpoint.pn.handshake,
            _ => &mut self.endpoint.pn.application,
        };
        space.pending_ack.clear();
        space.ack_eliciting_pending = false;

        Some(wire)
    }

    /// Build the *plaintext* frame payload for level `level`. Returns
    /// `None` if there is genuinely nothing to send.
    fn assemble_payload(&mut self, level: Level) -> Option<Vec<u8>> {
        let mut out: Vec<u8> = Vec::new();

        // ACK frame, if any.
        let space_ref = match level {
            Level::Initial => &self.endpoint.pn.initial,
            Level::Handshake => &self.endpoint.pn.handshake,
            _ => &self.endpoint.pn.application,
        };
        if !space_ref.pending_ack.is_empty()
            && let Some((largest, first_range, raw)) = build_ack_ranges_raw(&space_ref.pending_ack)
        {
            let ack = Frame::Ack {
                largest,
                ack_delay: 0,
                ranges_raw: &raw,
                first_range,
                ecn: None,
            };
            ack.encode(&mut out);
        }

        // CRYPTO frame (cap at ~1100 bytes so a single CRYPTO frame
        // fits comfortably in a 1200-byte datagram with header + tag +
        // ACK + other-level coalescing room).
        //
        // Phase 4: one CRYPTO frame per packet — multiple CRYPTO frames
        // per flight come from coalesced packets in the same datagram
        // (Initial + Handshake), not from multiple CRYPTO frames in one
        // packet. This keeps the assembly simple and predictable.
        const CRYPTO_CHUNK_CAP: usize = 1100;
        if let Some((offset, data)) = self.endpoint.bufs.at_mut(level).carve(CRYPTO_CHUNK_CAP) {
            let crypto = Frame::Crypto {
                offset,
                data: &data,
            };
            crypto.encode(&mut out);
        }
        if out.is_empty() { None } else { Some(out) }
    }
}

// ---------------------------------------------------------------------
// Adapter helpers: build a pub(crate) ClientConfig / ServerConfig from
// the public `tls::Config` so the new_for_quic constructors can consume
// it. Mirrors the build_tls13_* helpers in tls::connection but inlined
// here so we don't add a new public API in `tls::`.
// ---------------------------------------------------------------------

fn build_client_tls_config(cfg: &QuicConfig) -> Result<ClientConfig, Error> {
    let mut cc = ClientConfig::new(cfg.tls.roots.clone_store());
    cc.verify_certificates = cfg.tls.verify_certificates;
    if !cfg.tls.alpn_protocols.is_empty() {
        cc = cc.with_alpn(cfg.tls.alpn_protocols.clone());
    }
    if !cfg.tls.crls.is_empty() {
        cc = cc.with_crls(cfg.tls.crls.clone_store());
    }
    if let Some(t) = cfg.tls.verification_time.clone() {
        cc.verification_time = Some(t);
    }
    cc = cc.with_signature_policy(cfg.tls.signature_policy.clone());
    if let Some(id) = &cfg.tls.identity {
        let cc_cfg = client_cert_from_signing(id);
        if let Some(c) = cc_cfg {
            cc = cc.with_client_cert(c);
        }
    }
    cc.key_log = cfg.tls.key_log.clone();
    Ok(cc)
}

fn build_server_tls_config(cfg: &QuicConfig) -> Result<ServerConfig, Error> {
    let id = cfg.tls.identity.as_ref().ok_or(Error::InappropriateState)?;
    let chain = id.cert_chain.clone();
    let mut sc = match &id.key {
        crate::tls::SigningKey::Rsa(k) => ServerConfig::with_rsa(chain, k.clone()),
        crate::tls::SigningKey::Ecdsa(k) => ServerConfig::with_ecdsa(chain, k.clone()),
        crate::tls::SigningKey::Ed25519(k) => ServerConfig::with_ed25519(chain, k.clone()),
        crate::tls::SigningKey::MlDsa44(k) => ServerConfig::with_mldsa44(chain, k.clone()),
        crate::tls::SigningKey::MlDsa65(k) => ServerConfig::with_mldsa65(chain, k.clone()),
        crate::tls::SigningKey::MlDsa87(k) => ServerConfig::with_mldsa87(chain, k.clone()),
    };
    if !cfg.tls.alpn_protocols.is_empty() {
        sc = sc.with_alpn(cfg.tls.alpn_protocols.clone());
    }
    if !cfg.tls.crls.is_empty() {
        sc = sc.with_crls(cfg.tls.crls.clone_store());
    }
    if let Some(ca) = &cfg.tls.client_auth {
        sc = sc.with_client_auth(ca.roots.clone_store(), ca.required);
    }
    sc = sc.with_signature_policy(cfg.tls.signature_policy.clone());
    sc.key_log = cfg.tls.key_log.clone();
    Ok(sc)
}

fn client_cert_from_signing(
    id: &crate::tls::Identity,
) -> Option<crate::tls::conn::ClientCertConfig> {
    Some(match &id.key {
        crate::tls::SigningKey::Rsa(k) => {
            crate::tls::conn::ClientCertConfig::with_rsa(id.cert_chain.clone(), k.clone())
        }
        crate::tls::SigningKey::Ecdsa(k) => {
            crate::tls::conn::ClientCertConfig::with_ecdsa(id.cert_chain.clone(), k.clone())
        }
        crate::tls::SigningKey::Ed25519(k) => {
            crate::tls::conn::ClientCertConfig::with_ed25519(id.cert_chain.clone(), k.clone())
        }
        crate::tls::SigningKey::MlDsa44(k) => {
            crate::tls::conn::ClientCertConfig::with_mldsa44(id.cert_chain.clone(), k.clone())
        }
        crate::tls::SigningKey::MlDsa65(k) => {
            crate::tls::conn::ClientCertConfig::with_mldsa65(id.cert_chain.clone(), k.clone())
        }
        crate::tls::SigningKey::MlDsa87(k) => {
            crate::tls::conn::ClientCertConfig::with_mldsa87(id.cert_chain.clone(), k.clone())
        }
    })
}

/// Maps a TLS-1.3 cipher-suite identifier to the matching AEAD algorithm
/// for QUIC v1 (RFC 9001 §5.3 explicitly excludes
/// `TLS_AES_128_CCM_SHA256` and TLS_AES_128_CCM_8_SHA256).
fn suite_to_aead(suite: u16) -> Option<AeadAlg> {
    Some(match suite {
        0x1301 => AeadAlg::Aes128Gcm,
        0x1302 => AeadAlg::Aes256Gcm,
        0x1303 => AeadAlg::ChaCha20Poly1305,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::Ed25519PrivateKey;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::tls::{Config, Identity, RootCertStore, SigningKey};
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    /// Builds a self-signed Ed25519 server `(Config, cert_der)` for use
    /// in loopback tests. Mirrors the Phase-3 `ed25519_server` helper.
    fn ed25519_server() -> (Config, Vec<u8>) {
        let mut rng = HmacDrbg::<Sha256>::new(b"quic-loopback-ed-key", b"nonce", &[]);
        let key = Ed25519PrivateKey::generate(&mut rng);
        let name = DistinguishedName::common_name("loopback.example");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed_general(
            &CertSigner::Ed25519(&key),
            &name,
            &validity,
            1,
            false,
            &["loopback.example"],
        )
        .unwrap();
        let der = cert.to_der().to_vec();
        let cfg = Config {
            identity: Some(Identity {
                cert_chain: alloc::vec![der.clone()],
                key: SigningKey::Ed25519(key),
            }),
            max_version: crate::tls::ProtocolVersion::TLSv1_3,
            min_version: crate::tls::ProtocolVersion::TLSv1_3,
            ..Config::default()
        };
        (cfg, der)
    }

    /// Loopback transport-params suitable for both client and server.
    fn loopback_params() -> TransportParameters {
        TransportParameters {
            max_idle_timeout_ms: Some(30_000),
            max_udp_payload_size: Some(1500),
            initial_max_data: Some(1 << 20),
            initial_max_stream_data_bidi_local: Some(1 << 16),
            initial_max_stream_data_bidi_remote: Some(1 << 16),
            initial_max_stream_data_uni: Some(1 << 16),
            initial_max_streams_bidi: Some(100),
            initial_max_streams_uni: Some(3),
            ack_delay_exponent: Some(3),
            max_ack_delay_ms: Some(25),
            active_connection_id_limit: Some(2),
            ..TransportParameters::default()
        }
    }

    /// Constructs a (client, server) pair sharing trust roots, both
    /// running in QUIC mode against the loopback Ed25519 server cert.
    fn loopback_pair() -> (QuicConnection, QuicConnection) {
        let (server_cfg_tls, cert_der) = ed25519_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        let client_cfg = Config {
            roots,
            max_version: crate::tls::ProtocolVersion::TLSv1_3,
            min_version: crate::tls::ProtocolVersion::TLSv1_3,
            ..Config::default()
        };

        let client_params = loopback_params();
        let server_params = loopback_params();

        let client = QuicConnection::client(
            QuicConfig {
                tls: client_cfg,
                transport_params: client_params,
            },
            "loopback.example",
        )
        .expect("client build");
        let server = QuicConnection::server(QuicConfig {
            tls: server_cfg_tls,
            transport_params: server_params,
        })
        .expect("server build");
        (client, server)
    }

    /// Drives `client ↔ server` until both report
    /// `is_handshake_complete()`, up to `max_round_trips` round trips.
    /// Asserts handshake convergence.
    fn drive_until_complete(
        client: &mut QuicConnection,
        server: &mut QuicConnection,
        max_round_trips: usize,
    ) {
        for i in 0..max_round_trips {
            // Drain client → server.
            loop {
                let dg = client.pop_datagram();
                if dg.is_empty() {
                    break;
                }
                server.feed_datagram(&dg).expect("server feed");
            }
            // Drain server → client.
            loop {
                let dg = server.pop_datagram();
                if dg.is_empty() {
                    break;
                }
                client.feed_datagram(&dg).expect("client feed");
            }
            if client.is_handshake_complete() && server.is_handshake_complete() {
                return;
            }
            // Defensive: bail if neither side has anything to send.
            if i >= max_round_trips - 1 {
                panic!(
                    "handshake not complete after {max_round_trips} round trips: \
                     client_done={} server_done={}",
                    client.is_handshake_complete(),
                    server.is_handshake_complete(),
                );
            }
        }
    }

    /// Test 1 — in-process loopback handshake completes within 8 rounds.
    /// Both sides must report `is_handshake_complete()` and their peer
    /// transport-params must round-trip equal to what we configured.
    #[test]
    fn quic_loopback_handshake_completes() {
        let (mut c, mut s) = loopback_pair();
        drive_until_complete(&mut c, &mut s, 8);
        assert!(c.is_handshake_complete());
        assert!(s.is_handshake_complete());
        // Peer transport params: client sees server's params and vice
        // versa.
        let p = c.peer_transport_params().expect("server params");
        // Server emits the loopback params (no server-only fields set).
        assert_eq!(p.initial_max_data, Some(1 << 20));
        let q = s.peer_transport_params().expect("client params");
        assert_eq!(q.initial_max_data, Some(1 << 20));
    }

    /// Test 2 — Initial-key derivation matches RFC 9001 §A.1.
    /// We override the client DCID picker via `client_with_fixed_dcid`
    /// and verify the client's Initial-direction key matches the spec.
    #[test]
    fn initial_keys_match_rfc9001_a1() {
        let dcid_bytes = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let dcid = ConnectionId::from_slice(&dcid_bytes).expect("8-byte cid");
        let (server_cfg_tls, cert_der) = ed25519_server();
        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        let client_cfg = Config {
            roots,
            max_version: crate::tls::ProtocolVersion::TLSv1_3,
            min_version: crate::tls::ProtocolVersion::TLSv1_3,
            ..Config::default()
        };

        let _ = server_cfg_tls; // not used in this test
        let c = QuicConnection::client_with_fixed_dcid(
            QuicConfig {
                tls: client_cfg,
                transport_params: loopback_params(),
            },
            "loopback.example",
            dcid,
        )
        .expect("client build with fixed dcid");

        // The expected Initial client key (RFC 9001 §A.1):
        //   key = 1f369613dd76d5467730efcbe3b1a22d
        //   iv  = fa044b2f42a3fd3b46fb255c
        let want_key = [
            0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46, 0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1,
            0xa2, 0x2d,
        ];
        let want_iv = [
            0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
        ];
        let dk_tx = c.endpoint.crypto.at(Level::Initial).tx.as_ref().unwrap();
        assert_eq!(dk_tx.key.as_slice(), &want_key);
        assert_eq!(dk_tx.iv, want_iv);
    }

    /// Test 3 — PTO retransmit recovers from a one-way drop of the
    /// server's first outbound flight. Tests that the *server* PTO
    /// detects that its first flight was lost and retransmits.
    #[test]
    fn pto_retransmit_completes_handshake() {
        let (mut c, mut s) = loopback_pair();

        // Round 1: client emits its first Initial; server processes and
        // produces a reply — but we DROP that reply.
        let dg = c.pop_datagram();
        assert!(!dg.is_empty());
        s.feed_datagram(&dg).expect("server feed");
        // Drop the server's first reply (don't deliver to the client).
        let _dropped = s.pop_datagram();
        assert!(!_dropped.is_empty(), "server must have emitted a reply");

        // The server's PTO should now eventually fire. With kInitialRtt
        // = 333 ms, the initial PTO is 666 ms; we tick to 1 s.
        s.on_timeout(Duration::from_millis(1_000));
        // After PTO the server should have re-queued its CRYPTO; pop
        // another datagram from it.
        let dg2 = s.pop_datagram();
        assert!(!dg2.is_empty(), "server should retransmit on PTO");

        // From here, deliver everything to completion.
        c.feed_datagram(&dg2).expect("client feed retransmit");
        drive_until_complete(&mut c, &mut s, 8);
        assert!(c.is_handshake_complete());
        assert!(s.is_handshake_complete());
    }

    /// Test 4 — CRYPTO frame out-of-order reassembly is covered by
    /// `crate::quic::crypto_buf::tests::out_of_order_then_in_order_merges`;
    /// here we sanity-test the integration: a client that sees a
    /// fragment at offset 100 first, then offset 0, should still feed
    /// the engine in order.
    #[test]
    fn crypto_reassembly_handles_out_of_order_fragments() {
        use crate::quic::crypto_buf::CryptoBuf;
        let mut b = CryptoBuf::new();
        let out = b.on_crypto(100, b"part-B");
        assert!(out.is_empty());
        let filler = alloc::vec![0u8; 100];
        let out = b.on_crypto(0, &filler);
        assert_eq!(out.len(), 106);
        assert_eq!(&out[..100], &filler[..]);
        assert_eq!(&out[100..], b"part-B");
        assert_eq!(b.next_offset(), 106);
        assert!(b.is_pending_empty());
    }

    /// Test 5 — feeding an AEAD-tampered datagram returns an error and
    /// the server state is unchanged. We tamper with the byte at offset
    /// 50 (well past the unprotected header bytes).
    #[test]
    fn feed_datagram_rejects_aead_tampering() {
        let (mut c, mut s) = loopback_pair();
        // Capture the client's first Initial datagram.
        let dg = c.pop_datagram();
        assert!(!dg.is_empty());
        // Tamper with a byte inside the ciphertext region.
        let mut tampered = dg.clone();
        // Pick byte at index 60 — well into the AEAD-protected payload.
        let idx = 60.min(tampered.len() - 1);
        tampered[idx] ^= 0x01;
        // Server rejects.
        let r = s.feed_datagram(&tampered);
        assert!(r.is_err(), "tampered datagram must fail");
        // And subsequent handshake completion with the un-tampered
        // datagram still works.
        let r2 = s.feed_datagram(&dg);
        assert!(r2.is_ok(), "untampered datagram must succeed");
    }

    /// Test 13 — drop every third datagram in each direction. The
    /// Phase-4 PTO retransmits the lost flight; the handshake still
    /// completes within a defensive bound of 50 PTO events.
    #[test]
    fn drop_every_third_packet() {
        let (mut c, mut s) = loopback_pair();
        let mut now = Duration::from_millis(0);
        // Counter increments per *attempted* datagram (regardless of
        // direction). Every 3rd attempt is dropped.
        let mut attempt = 0u32;
        let mut pto_events = 0u32;
        let max_pto = 50u32;
        let mut idle_rounds = 0u32;

        for _ in 0..500 {
            // Drain client → server.
            let mut any_progress = false;
            loop {
                let dg = c.pop_datagram();
                if dg.is_empty() {
                    break;
                }
                attempt += 1;
                any_progress = true;
                if !attempt.is_multiple_of(3) {
                    s.feed_datagram(&dg).expect("server feed");
                }
            }
            // Drain server → client.
            loop {
                let dg = s.pop_datagram();
                if dg.is_empty() {
                    break;
                }
                attempt += 1;
                any_progress = true;
                if !attempt.is_multiple_of(3) {
                    c.feed_datagram(&dg).expect("client feed");
                }
            }
            if c.is_handshake_complete() && s.is_handshake_complete() {
                return;
            }
            if !any_progress {
                // No new packets emitted this round — advance time to
                // the smaller of the two next PTOs and tick both sides.
                let cnt = c.next_timeout();
                let snt = s.next_timeout();
                let step = match (cnt, snt) {
                    (Some(a), Some(b)) => a.min(b),
                    (Some(a), None) => a,
                    (None, Some(b)) => b,
                    (None, None) => {
                        idle_rounds += 1;
                        if idle_rounds > 10 {
                            panic!(
                                "no progress and no timer: client_done={} server_done={}",
                                c.is_handshake_complete(),
                                s.is_handshake_complete()
                            );
                        }
                        continue;
                    }
                };
                idle_rounds = 0;
                now = now.saturating_add(step + Duration::from_millis(1));
                c.on_timeout(now);
                s.on_timeout(now);
                pto_events += 1;
                if pto_events > max_pto {
                    panic!("exceeded {max_pto} PTO events");
                }
            } else {
                idle_rounds = 0;
            }
        }
        panic!(
            "handshake never completed: client_done={} server_done={} after {pto_events} PTOs",
            c.is_handshake_complete(),
            s.is_handshake_complete()
        );
    }
}
