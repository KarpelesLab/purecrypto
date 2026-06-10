//! QUIC transport parameters — RFC 9000 §18.2 (with §22.3 codepoints) plus
//! RFC 9221 §3 (DATAGRAM extension).
//!
//! Transport parameters are exchanged inside the TLS handshake via the
//! `quic_transport_parameters` extension (codepoint `0x39`). The extension
//! body is a sequence of `(id, length, value)` triples where `id` and
//! `length` are encoded as QUIC varints (RFC 9000 §16) and `value` is
//! `length` bytes — most often itself a varint, but some parameters carry
//! opaque bytes (connection IDs, stateless reset token, preferred address).
//!
//! Per §18.1 a receiver MUST ignore unknown parameter IDs. Per §7.4.1 a
//! parameter MUST NOT appear more than once; [`TransportParameters::decode`]
//! rejects any repeated ID (known or unknown) with a decode error, which
//! the handshake surfaces as TRANSPORT_PARAMETER_ERROR.
//!
//! The struct fields use `Option<…>` for parameters with semantically
//! meaningful defaults (so callers can distinguish "explicit value sent" vs
//! "use the default"). The single zero-length parameter,
//! `disable_active_migration`, is modeled as a `bool` since the absence of
//! the parameter and the value `false` mean the same thing.

use alloc::vec::Vec;

use super::varint;
use crate::tls::Error;

/// QUIC transport parameters exchanged in the TLS handshake.
///
/// All `Option<…>` fields are absent on the wire when set to `None`. The
/// `disable_active_migration` boolean encodes/decodes as a zero-length
/// parameter when `true` and is omitted when `false`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct TransportParameters {
    /// `original_destination_connection_id` (0x00) — server only. The
    /// destination CID from the client's first Initial packet.
    pub original_destination_connection_id: Option<Vec<u8>>,
    /// `max_idle_timeout` (0x01) — milliseconds; 0 disables.
    pub max_idle_timeout_ms: Option<u64>,
    /// `stateless_reset_token` (0x02) — server only; 16 bytes.
    pub stateless_reset_token: Option<[u8; 16]>,
    /// `max_udp_payload_size` (0x03) — default 65527.
    pub max_udp_payload_size: Option<u64>,
    /// `initial_max_data` (0x04) — connection-level flow control credit.
    pub initial_max_data: Option<u64>,
    /// `initial_max_stream_data_bidi_local` (0x05).
    pub initial_max_stream_data_bidi_local: Option<u64>,
    /// `initial_max_stream_data_bidi_remote` (0x06).
    pub initial_max_stream_data_bidi_remote: Option<u64>,
    /// `initial_max_stream_data_uni` (0x07).
    pub initial_max_stream_data_uni: Option<u64>,
    /// `initial_max_streams_bidi` (0x08).
    pub initial_max_streams_bidi: Option<u64>,
    /// `initial_max_streams_uni` (0x09).
    pub initial_max_streams_uni: Option<u64>,
    /// `ack_delay_exponent` (0x0A) — default 3.
    pub ack_delay_exponent: Option<u64>,
    /// `max_ack_delay` (0x0B) — milliseconds, default 25.
    pub max_ack_delay_ms: Option<u64>,
    /// `disable_active_migration` (0x0C) — zero-length on the wire.
    pub disable_active_migration: bool,
    /// `preferred_address` (0x0D) — opaque blob; this phase does not
    /// destructure its internals (RFC 9000 §18.2 has the full layout).
    pub preferred_address: Option<Vec<u8>>,
    /// `active_connection_id_limit` (0x0E) — default 2.
    pub active_connection_id_limit: Option<u64>,
    /// `initial_source_connection_id` (0x0F).
    pub initial_source_connection_id: Option<Vec<u8>>,
    /// `retry_source_connection_id` (0x10) — server only, set when the
    /// server sent a Retry packet.
    pub retry_source_connection_id: Option<Vec<u8>>,
    /// `max_datagram_frame_size` (0x20) — RFC 9221 §3.
    pub max_datagram_frame_size: Option<u64>,
}

// Parameter codepoints — RFC 9000 §22.3 + RFC 9221 §3.
const ID_ORIGINAL_DESTINATION_CONNECTION_ID: u64 = 0x00;
const ID_MAX_IDLE_TIMEOUT: u64 = 0x01;
const ID_STATELESS_RESET_TOKEN: u64 = 0x02;
const ID_MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
const ID_INITIAL_MAX_DATA: u64 = 0x04;
const ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const ID_INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const ID_INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const ID_INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const ID_ACK_DELAY_EXPONENT: u64 = 0x0A;
const ID_MAX_ACK_DELAY: u64 = 0x0B;
const ID_DISABLE_ACTIVE_MIGRATION: u64 = 0x0C;
const ID_PREFERRED_ADDRESS: u64 = 0x0D;
const ID_ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0E;
const ID_INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0F;
const ID_RETRY_SOURCE_CONNECTION_ID: u64 = 0x10;
const ID_MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

fn write_varint_param(out: &mut Vec<u8>, id: u64, value: u64) {
    varint::encode(id, out);
    varint::encode(varint::encoded_len(value) as u64, out);
    varint::encode(value, out);
}

fn write_opaque_param(out: &mut Vec<u8>, id: u64, bytes: &[u8]) {
    varint::encode(id, out);
    varint::encode(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

fn read_varint_value(buf: &[u8]) -> Result<u64, Error> {
    let (v, n) = varint::decode(buf)?;
    if n != buf.len() {
        // RFC 9000 §18.1: the value MUST occupy exactly `length` bytes.
        return Err(Error::Decode);
    }
    Ok(v)
}

impl TransportParameters {
    /// Encodes the parameter list onto `out` per RFC 9000 §18: a flat
    /// sequence of `(id, length, value)` triples where `id` and `length`
    /// are varints. Fields set to `None` are omitted.
    pub fn encode(&self, out: &mut Vec<u8>) {
        if let Some(v) = &self.original_destination_connection_id {
            write_opaque_param(out, ID_ORIGINAL_DESTINATION_CONNECTION_ID, v);
        }
        if let Some(v) = self.max_idle_timeout_ms {
            write_varint_param(out, ID_MAX_IDLE_TIMEOUT, v);
        }
        if let Some(tok) = &self.stateless_reset_token {
            varint::encode(ID_STATELESS_RESET_TOKEN, out);
            varint::encode(16, out);
            out.extend_from_slice(tok);
        }
        if let Some(v) = self.max_udp_payload_size {
            write_varint_param(out, ID_MAX_UDP_PAYLOAD_SIZE, v);
        }
        if let Some(v) = self.initial_max_data {
            write_varint_param(out, ID_INITIAL_MAX_DATA, v);
        }
        if let Some(v) = self.initial_max_stream_data_bidi_local {
            write_varint_param(out, ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, v);
        }
        if let Some(v) = self.initial_max_stream_data_bidi_remote {
            write_varint_param(out, ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, v);
        }
        if let Some(v) = self.initial_max_stream_data_uni {
            write_varint_param(out, ID_INITIAL_MAX_STREAM_DATA_UNI, v);
        }
        if let Some(v) = self.initial_max_streams_bidi {
            write_varint_param(out, ID_INITIAL_MAX_STREAMS_BIDI, v);
        }
        if let Some(v) = self.initial_max_streams_uni {
            write_varint_param(out, ID_INITIAL_MAX_STREAMS_UNI, v);
        }
        if let Some(v) = self.ack_delay_exponent {
            write_varint_param(out, ID_ACK_DELAY_EXPONENT, v);
        }
        if let Some(v) = self.max_ack_delay_ms {
            write_varint_param(out, ID_MAX_ACK_DELAY, v);
        }
        if self.disable_active_migration {
            varint::encode(ID_DISABLE_ACTIVE_MIGRATION, out);
            varint::encode(0, out);
        }
        if let Some(v) = &self.preferred_address {
            write_opaque_param(out, ID_PREFERRED_ADDRESS, v);
        }
        if let Some(v) = self.active_connection_id_limit {
            write_varint_param(out, ID_ACTIVE_CONNECTION_ID_LIMIT, v);
        }
        if let Some(v) = &self.initial_source_connection_id {
            write_opaque_param(out, ID_INITIAL_SOURCE_CONNECTION_ID, v);
        }
        if let Some(v) = &self.retry_source_connection_id {
            write_opaque_param(out, ID_RETRY_SOURCE_CONNECTION_ID, v);
        }
        if let Some(v) = self.max_datagram_frame_size {
            write_varint_param(out, ID_MAX_DATAGRAM_FRAME_SIZE, v);
        }
    }

    /// Decodes a transport-parameter list. Unknown IDs are ignored per
    /// RFC 9000 §18.1; duplicate IDs (known or unknown) are rejected per
    /// §7.4.1 (TRANSPORT_PARAMETER_ERROR).
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut out = TransportParameters::default();
        // RFC 9000 §7.4.1 — an endpoint MUST treat receipt of a
        // duplicate transport parameter as a connection error of type
        // TRANSPORT_PARAMETER_ERROR. The low codepoints (0..64, which
        // cover every parameter we recognize) are tracked in a bitset;
        // higher IDs (e.g. the §18.1 reserved/GREASE codepoints
        // 31·N+27) go into a small ordered set.
        let mut seen_low: u64 = 0;
        let mut seen_high: alloc::collections::BTreeSet<u64> = alloc::collections::BTreeSet::new();
        let mut p = 0;
        while p < buf.len() {
            let (id, n) = varint::decode(&buf[p..])?;
            p += n;
            let fresh = if id < 64 {
                let bit = 1u64 << id;
                let fresh = seen_low & bit == 0;
                seen_low |= bit;
                fresh
            } else {
                seen_high.insert(id)
            };
            if !fresh {
                return Err(Error::Decode);
            }
            let (length, n) = varint::decode(&buf[p..])?;
            p += n;
            let length = length as usize;
            if buf.len() - p < length {
                return Err(Error::Decode);
            }
            let value = &buf[p..p + length];
            p += length;

            match id {
                ID_ORIGINAL_DESTINATION_CONNECTION_ID => {
                    if value.len() > 20 {
                        return Err(Error::Decode);
                    }
                    out.original_destination_connection_id = Some(value.to_vec());
                }
                ID_MAX_IDLE_TIMEOUT => {
                    out.max_idle_timeout_ms = Some(read_varint_value(value)?);
                }
                ID_STATELESS_RESET_TOKEN => {
                    if value.len() != 16 {
                        return Err(Error::Decode);
                    }
                    let mut tok = [0u8; 16];
                    tok.copy_from_slice(value);
                    out.stateless_reset_token = Some(tok);
                }
                ID_MAX_UDP_PAYLOAD_SIZE => {
                    out.max_udp_payload_size = Some(read_varint_value(value)?);
                }
                ID_INITIAL_MAX_DATA => {
                    out.initial_max_data = Some(read_varint_value(value)?);
                }
                ID_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    out.initial_max_stream_data_bidi_local = Some(read_varint_value(value)?);
                }
                ID_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    out.initial_max_stream_data_bidi_remote = Some(read_varint_value(value)?);
                }
                ID_INITIAL_MAX_STREAM_DATA_UNI => {
                    out.initial_max_stream_data_uni = Some(read_varint_value(value)?);
                }
                ID_INITIAL_MAX_STREAMS_BIDI => {
                    out.initial_max_streams_bidi = Some(read_varint_value(value)?);
                }
                ID_INITIAL_MAX_STREAMS_UNI => {
                    out.initial_max_streams_uni = Some(read_varint_value(value)?);
                }
                ID_ACK_DELAY_EXPONENT => {
                    out.ack_delay_exponent = Some(read_varint_value(value)?);
                }
                ID_MAX_ACK_DELAY => {
                    out.max_ack_delay_ms = Some(read_varint_value(value)?);
                }
                ID_DISABLE_ACTIVE_MIGRATION => {
                    if !value.is_empty() {
                        return Err(Error::Decode);
                    }
                    out.disable_active_migration = true;
                }
                ID_PREFERRED_ADDRESS => {
                    out.preferred_address = Some(value.to_vec());
                }
                ID_ACTIVE_CONNECTION_ID_LIMIT => {
                    out.active_connection_id_limit = Some(read_varint_value(value)?);
                }
                ID_INITIAL_SOURCE_CONNECTION_ID => {
                    if value.len() > 20 {
                        return Err(Error::Decode);
                    }
                    out.initial_source_connection_id = Some(value.to_vec());
                }
                ID_RETRY_SOURCE_CONNECTION_ID => {
                    if value.len() > 20 {
                        return Err(Error::Decode);
                    }
                    out.retry_source_connection_id = Some(value.to_vec());
                }
                ID_MAX_DATAGRAM_FRAME_SIZE => {
                    out.max_datagram_frame_size = Some(read_varint_value(value)?);
                }
                _ => {
                    // Unknown parameter — ignored per §18.1.
                }
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_client_shape() {
        // A ClientHello-shaped param set — no server-only fields.
        let tp = TransportParameters {
            max_idle_timeout_ms: Some(30_000),
            max_udp_payload_size: Some(1452),
            initial_max_data: Some(1 << 20),
            initial_max_stream_data_bidi_local: Some(1 << 16),
            initial_max_stream_data_bidi_remote: Some(1 << 16),
            initial_max_stream_data_uni: Some(1 << 16),
            initial_max_streams_bidi: Some(100),
            initial_max_streams_uni: Some(3),
            ack_delay_exponent: Some(3),
            max_ack_delay_ms: Some(25),
            disable_active_migration: false,
            active_connection_id_limit: Some(2),
            initial_source_connection_id: Some(alloc::vec![1, 2, 3, 4, 5, 6, 7, 8]),
            max_datagram_frame_size: Some(1200),
            ..TransportParameters::default()
        };
        let mut buf = Vec::new();
        tp.encode(&mut buf);
        let decoded = TransportParameters::decode(&buf).expect("decode");
        assert_eq!(decoded, tp);
    }

    #[test]
    fn roundtrip_server_shape() {
        let tp = TransportParameters {
            original_destination_connection_id: Some(alloc::vec![0xAB; 8]),
            max_idle_timeout_ms: Some(30_000),
            stateless_reset_token: Some([0x42; 16]),
            max_udp_payload_size: Some(1452),
            initial_max_data: Some(1 << 20),
            initial_max_stream_data_bidi_local: Some(1 << 16),
            initial_max_stream_data_bidi_remote: Some(1 << 16),
            initial_max_stream_data_uni: Some(1 << 16),
            initial_max_streams_bidi: Some(100),
            initial_max_streams_uni: Some(3),
            ack_delay_exponent: Some(3),
            max_ack_delay_ms: Some(25),
            disable_active_migration: true,
            active_connection_id_limit: Some(4),
            initial_source_connection_id: Some(alloc::vec![9; 8]),
            retry_source_connection_id: Some(alloc::vec![7; 8]),
            max_datagram_frame_size: Some(1200),
            ..TransportParameters::default()
        };
        let mut buf = Vec::new();
        tp.encode(&mut buf);
        let decoded = TransportParameters::decode(&buf).expect("decode");
        assert_eq!(decoded, tp);
    }

    #[test]
    fn unknown_id_is_ignored() {
        let mut buf = Vec::new();
        // Recognized: max_idle_timeout_ms = 1000 (varint id=0x01, length=2,
        // value=0x4000 | 0x3E8 = 0x43E8 0x... — let varint::encode produce
        // it for us).
        super::varint::encode(0x01, &mut buf);
        super::varint::encode(super::varint::encoded_len(1000) as u64, &mut buf);
        super::varint::encode(1000, &mut buf);
        // Unknown id 0xFF, length 3, three random bytes:
        super::varint::encode(0xFF, &mut buf);
        super::varint::encode(3, &mut buf);
        buf.extend_from_slice(&[1, 2, 3]);
        let decoded = TransportParameters::decode(&buf).expect("decode");
        assert_eq!(decoded.max_idle_timeout_ms, Some(1000));
    }

    /// RFC 9000 §7.4.1 — duplicate transport parameters MUST be
    /// rejected (TRANSPORT_PARAMETER_ERROR), not accepted last-wins.
    #[test]
    fn duplicate_id_is_rejected() {
        // Known parameter sent twice (max_idle_timeout 0x01).
        let mut buf = Vec::new();
        for v in [1000u64, 2000u64] {
            super::varint::encode(0x01, &mut buf);
            super::varint::encode(super::varint::encoded_len(v) as u64, &mut buf);
            super::varint::encode(v, &mut buf);
        }
        assert!(
            TransportParameters::decode(&buf).is_err(),
            "duplicate known id must be rejected"
        );

        // Unknown / reserved parameter sent twice (id 0xFF > 63 takes
        // the high-id tracking path).
        let mut buf = Vec::new();
        for _ in 0..2 {
            super::varint::encode(0xFF, &mut buf);
            super::varint::encode(3, &mut buf);
            buf.extend_from_slice(&[1, 2, 3]);
        }
        assert!(
            TransportParameters::decode(&buf).is_err(),
            "duplicate unknown id must be rejected"
        );

        // Two DIFFERENT unknown ids remain fine.
        let mut buf = Vec::new();
        for id in [0xFFu64, 0x1FF] {
            super::varint::encode(id, &mut buf);
            super::varint::encode(1, &mut buf);
            buf.push(0);
        }
        assert!(TransportParameters::decode(&buf).is_ok());
    }

    #[test]
    fn disable_active_migration_zero_length() {
        let tp = TransportParameters {
            disable_active_migration: true,
            ..TransportParameters::default()
        };
        let mut buf = Vec::new();
        tp.encode(&mut buf);
        // Single param: id=0x0C, length=0.
        assert_eq!(buf, alloc::vec![0x0C, 0x00]);
        let decoded = TransportParameters::decode(&buf).expect("decode");
        assert!(decoded.disable_active_migration);
    }

    #[test]
    fn datagram_param_codepoint() {
        let tp = TransportParameters {
            max_datagram_frame_size: Some(1200),
            ..TransportParameters::default()
        };
        let mut buf = Vec::new();
        tp.encode(&mut buf);
        // First byte must be the codepoint 0x20 (single-byte varint).
        assert_eq!(buf[0], 0x20);
        let decoded = TransportParameters::decode(&buf).expect("decode");
        assert_eq!(decoded.max_datagram_frame_size, Some(1200));
    }
}
