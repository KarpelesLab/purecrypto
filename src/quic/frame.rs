//! QUIC frames — RFC 9000 §19 plus the DATAGRAM extension from RFC 9221.
//!
//! Every payload carried in a QUIC packet is a sequence of frames. This
//! module defines a single [`Frame`] enum spanning all standard frame types
//! and provides encode/decode plus an iterator that walks a packet payload
//! end-to-end.
//!
//! Most numeric fields are encoded as QUIC varints — see [`super::varint`].
//! The exceptions are:
//! - the 1-byte connection-ID length prefix in NEW_CONNECTION_ID,
//! - the fixed 16-byte stateless reset token in NEW_CONNECTION_ID,
//! - the fixed 8-byte payload of PATH_CHALLENGE / PATH_RESPONSE,
//! - STREAM frame payloads, whose length is implicit when the LEN bit is
//!   clear (data runs to the end of the packet).
//!
//! ACK ranges are kept as a raw slice (`ranges_raw`) at parse time —
//! materializing the ranges requires deciding what to do with them, which
//! is a connection-level concern. Use [`AckRangeIter`] (returned by
//! [`Frame::ack_range_iter`]) to walk the encoded ranges on demand.

#![allow(dead_code)]

use alloc::vec::Vec;

use super::varint;
use crate::tls::Error;

/// Direction of a stream-id-bearing frame. RFC 9000 §2.1.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) enum StreamDir {
    /// Bidirectional stream.
    Bidi,
    /// Unidirectional stream.
    Uni,
}

/// ECN counts carried by the ACK_ECN frame variant. RFC 9000 §19.3.2.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub(crate) struct EcnCounts {
    /// ECT(0) count.
    pub ect0: u64,
    /// ECT(1) count.
    pub ect1: u64,
    /// CE count.
    pub ce: u64,
}

/// One QUIC frame, borrowing from a packet payload where possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Frame<'a> {
    /// PADDING frames (`0x00`), collapsed into a single run-length variant.
    Padding(usize),
    /// PING (`0x01`). Ack-eliciting, no payload.
    Ping,
    /// ACK (`0x02` no ECN, `0x03` with ECN). `ranges_raw` is the encoded
    /// trailing range list — see [`Frame::ack_range_iter`].
    Ack {
        /// Largest acknowledged PN.
        largest: u64,
        /// Raw (unscaled) ACK delay; caller multiplies by
        /// `2^ack_delay_exponent` to get microseconds.
        ack_delay: u64,
        /// Encoded (gap, range_length) pairs after the first range.
        ranges_raw: &'a [u8],
        /// First-range length (PNs immediately below `largest`, *minus one*).
        first_range: u64,
        /// Optional ECN counts (`0x03` frame type).
        ecn: Option<EcnCounts>,
    },
    /// RESET_STREAM (`0x04`).
    ResetStream {
        /// Stream identifier.
        id: u64,
        /// Application error code.
        code: u64,
        /// Final size.
        final_size: u64,
    },
    /// STOP_SENDING (`0x05`).
    StopSending {
        /// Stream identifier.
        id: u64,
        /// Application error code.
        code: u64,
    },
    /// CRYPTO (`0x06`).
    Crypto {
        /// Byte offset into the per-level CRYPTO stream.
        offset: u64,
        /// Crypto data.
        data: &'a [u8],
    },
    /// NEW_TOKEN (`0x07`). Server → client.
    NewToken {
        /// Opaque token to be echoed in subsequent Initial packets.
        token: &'a [u8],
    },
    /// STREAM (`0x08`–`0x0F`). The three low bits of the type byte encode
    /// OFF, LEN, FIN — we materialize them here.
    Stream {
        /// Stream identifier.
        id: u64,
        /// Byte offset (zero if not present on the wire).
        offset: u64,
        /// FIN bit.
        fin: bool,
        /// Stream data.
        data: &'a [u8],
    },
    /// MAX_DATA (`0x10`).
    MaxData(u64),
    /// MAX_STREAM_DATA (`0x11`).
    MaxStreamData {
        /// Stream identifier.
        id: u64,
        /// New limit.
        limit: u64,
    },
    /// MAX_STREAMS (`0x12` bidi, `0x13` uni).
    MaxStreams {
        /// Bidi or uni.
        dir: StreamDir,
        /// New limit on the count of streams the peer may open.
        limit: u64,
    },
    /// DATA_BLOCKED (`0x14`).
    DataBlocked(u64),
    /// STREAM_DATA_BLOCKED (`0x15`).
    StreamDataBlocked {
        /// Stream identifier.
        id: u64,
        /// Stream-data limit that was reached.
        limit: u64,
    },
    /// STREAMS_BLOCKED (`0x16` bidi, `0x17` uni).
    StreamsBlocked {
        /// Bidi or uni.
        dir: StreamDir,
        /// Limit that was reached.
        limit: u64,
    },
    /// NEW_CONNECTION_ID (`0x18`).
    NewConnectionId {
        /// Sequence number.
        seq: u64,
        /// Retire-prior-to value.
        retire_prior_to: u64,
        /// New connection ID bytes (length 0..=20).
        cid: &'a [u8],
        /// Stateless reset token (exactly 16 bytes).
        reset_token: [u8; 16],
    },
    /// RETIRE_CONNECTION_ID (`0x19`).
    RetireConnectionId {
        /// Sequence number to retire.
        seq: u64,
    },
    /// PATH_CHALLENGE (`0x1A`). 8 bytes of opaque data.
    PathChallenge([u8; 8]),
    /// PATH_RESPONSE (`0x1B`). Echo of the most recent PATH_CHALLENGE.
    PathResponse([u8; 8]),
    /// CONNECTION_CLOSE (`0x1C` transport, `0x1D` application). The
    /// transport variant carries the frame type that triggered the close;
    /// the application variant does not.
    ConnectionClose {
        /// Error code.
        error: u64,
        /// Triggering frame type (transport variant only).
        frame_type: Option<u64>,
        /// UTF-8 reason phrase.
        reason: &'a [u8],
    },
    /// HANDSHAKE_DONE (`0x1E`). Server → client.
    HandshakeDone,
    /// DATAGRAM (`0x30` no length, `0x31` with length) — RFC 9221.
    Datagram {
        /// Datagram payload.
        data: &'a [u8],
    },
}

impl<'a> Frame<'a> {
    /// Returns an iterator over the (gap, range_length) pairs of an ACK
    /// frame's tail. Returns an empty iterator (and zero pairs decoded) for
    /// non-ACK variants.
    pub(crate) fn ack_range_iter(&self) -> AckRangeIter<'a> {
        match *self {
            Frame::Ack { ranges_raw, .. } => AckRangeIter { buf: ranges_raw },
            _ => AckRangeIter { buf: &[] },
        }
    }

    /// Decodes the first frame at the start of `buf`. Returns the frame
    /// and the number of bytes consumed.
    pub(crate) fn decode(buf: &'a [u8]) -> Result<(Frame<'a>, usize), Error> {
        if buf.is_empty() {
            return Err(Error::Decode);
        }
        let t = buf[0];
        let mut p = 1usize;

        match t {
            0x00 => {
                // Run-length PADDING.
                let mut n = 1;
                while p < buf.len() && buf[p] == 0x00 {
                    p += 1;
                    n += 1;
                }
                Ok((Frame::Padding(n), p))
            }
            0x01 => Ok((Frame::Ping, 1)),
            0x02 | 0x03 => {
                let (largest, n) = varint::decode(&buf[p..])?;
                p += n;
                let (ack_delay, n) = varint::decode(&buf[p..])?;
                p += n;
                let (range_count, n) = varint::decode(&buf[p..])?;
                p += n;
                let (first_range, n) = varint::decode(&buf[p..])?;
                p += n;
                // Walk `range_count` pairs to determine ranges_raw extent.
                let raw_start = p;
                for _ in 0..range_count {
                    let (_, n) = varint::decode(&buf[p..])?;
                    p += n;
                    let (_, n) = varint::decode(&buf[p..])?;
                    p += n;
                }
                let raw_end = p;
                let ecn = if t == 0x03 {
                    let (ect0, n) = varint::decode(&buf[p..])?;
                    p += n;
                    let (ect1, n) = varint::decode(&buf[p..])?;
                    p += n;
                    let (ce, n) = varint::decode(&buf[p..])?;
                    p += n;
                    Some(EcnCounts { ect0, ect1, ce })
                } else {
                    None
                };
                Ok((
                    Frame::Ack {
                        largest,
                        ack_delay,
                        ranges_raw: &buf[raw_start..raw_end],
                        first_range,
                        ecn,
                    },
                    p,
                ))
            }
            0x04 => {
                let (id, n) = varint::decode(&buf[p..])?;
                p += n;
                let (code, n) = varint::decode(&buf[p..])?;
                p += n;
                let (final_size, n) = varint::decode(&buf[p..])?;
                p += n;
                Ok((
                    Frame::ResetStream {
                        id,
                        code,
                        final_size,
                    },
                    p,
                ))
            }
            0x05 => {
                let (id, n) = varint::decode(&buf[p..])?;
                p += n;
                let (code, n) = varint::decode(&buf[p..])?;
                p += n;
                Ok((Frame::StopSending { id, code }, p))
            }
            0x06 => {
                let (offset, n) = varint::decode(&buf[p..])?;
                p += n;
                let (length, n) = varint::decode(&buf[p..])?;
                p += n;
                let length = length as usize;
                if buf.len() - p < length {
                    return Err(Error::Decode);
                }
                let data = &buf[p..p + length];
                p += length;
                Ok((Frame::Crypto { offset, data }, p))
            }
            0x07 => {
                let (length, n) = varint::decode(&buf[p..])?;
                p += n;
                let length = length as usize;
                if buf.len() - p < length {
                    return Err(Error::Decode);
                }
                let token = &buf[p..p + length];
                p += length;
                Ok((Frame::NewToken { token }, p))
            }
            0x08..=0x0F => {
                // Low 3 bits: bit0 = FIN, bit1 = LEN, bit2 = OFF.
                let fin = (t & 0x01) != 0;
                let has_len = (t & 0x02) != 0;
                let has_off = (t & 0x04) != 0;
                let (id, n) = varint::decode(&buf[p..])?;
                p += n;
                let offset = if has_off {
                    let (off, n) = varint::decode(&buf[p..])?;
                    p += n;
                    off
                } else {
                    0
                };
                let data = if has_len {
                    let (length, n) = varint::decode(&buf[p..])?;
                    p += n;
                    let length = length as usize;
                    if buf.len() - p < length {
                        return Err(Error::Decode);
                    }
                    let d = &buf[p..p + length];
                    p += length;
                    d
                } else {
                    let d = &buf[p..];
                    p = buf.len();
                    d
                };
                Ok((
                    Frame::Stream {
                        id,
                        offset,
                        fin,
                        data,
                    },
                    p,
                ))
            }
            0x10 => {
                let (v, n) = varint::decode(&buf[p..])?;
                p += n;
                Ok((Frame::MaxData(v), p))
            }
            0x11 => {
                let (id, n) = varint::decode(&buf[p..])?;
                p += n;
                let (limit, n) = varint::decode(&buf[p..])?;
                p += n;
                Ok((Frame::MaxStreamData { id, limit }, p))
            }
            0x12 | 0x13 => {
                let (limit, n) = varint::decode(&buf[p..])?;
                p += n;
                let dir = if t == 0x12 {
                    StreamDir::Bidi
                } else {
                    StreamDir::Uni
                };
                Ok((Frame::MaxStreams { dir, limit }, p))
            }
            0x14 => {
                let (v, n) = varint::decode(&buf[p..])?;
                p += n;
                Ok((Frame::DataBlocked(v), p))
            }
            0x15 => {
                let (id, n) = varint::decode(&buf[p..])?;
                p += n;
                let (limit, n) = varint::decode(&buf[p..])?;
                p += n;
                Ok((Frame::StreamDataBlocked { id, limit }, p))
            }
            0x16 | 0x17 => {
                let (limit, n) = varint::decode(&buf[p..])?;
                p += n;
                let dir = if t == 0x16 {
                    StreamDir::Bidi
                } else {
                    StreamDir::Uni
                };
                Ok((Frame::StreamsBlocked { dir, limit }, p))
            }
            0x18 => {
                let (seq, n) = varint::decode(&buf[p..])?;
                p += n;
                let (retire_prior_to, n) = varint::decode(&buf[p..])?;
                p += n;
                if buf.len() - p < 1 {
                    return Err(Error::Decode);
                }
                let cid_len = buf[p] as usize;
                p += 1;
                if cid_len > 20 {
                    return Err(Error::Decode);
                }
                if buf.len() - p < cid_len + 16 {
                    return Err(Error::Decode);
                }
                let cid = &buf[p..p + cid_len];
                p += cid_len;
                let mut reset_token = [0u8; 16];
                reset_token.copy_from_slice(&buf[p..p + 16]);
                p += 16;
                Ok((
                    Frame::NewConnectionId {
                        seq,
                        retire_prior_to,
                        cid,
                        reset_token,
                    },
                    p,
                ))
            }
            0x19 => {
                let (seq, n) = varint::decode(&buf[p..])?;
                p += n;
                Ok((Frame::RetireConnectionId { seq }, p))
            }
            0x1A => {
                if buf.len() - p < 8 {
                    return Err(Error::Decode);
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&buf[p..p + 8]);
                p += 8;
                Ok((Frame::PathChallenge(data), p))
            }
            0x1B => {
                if buf.len() - p < 8 {
                    return Err(Error::Decode);
                }
                let mut data = [0u8; 8];
                data.copy_from_slice(&buf[p..p + 8]);
                p += 8;
                Ok((Frame::PathResponse(data), p))
            }
            0x1C | 0x1D => {
                let (error, n) = varint::decode(&buf[p..])?;
                p += n;
                let frame_type = if t == 0x1C {
                    let (ft, n) = varint::decode(&buf[p..])?;
                    p += n;
                    Some(ft)
                } else {
                    None
                };
                let (reason_len, n) = varint::decode(&buf[p..])?;
                p += n;
                let reason_len = reason_len as usize;
                if buf.len() - p < reason_len {
                    return Err(Error::Decode);
                }
                let reason = &buf[p..p + reason_len];
                p += reason_len;
                Ok((
                    Frame::ConnectionClose {
                        error,
                        frame_type,
                        reason,
                    },
                    p,
                ))
            }
            0x1E => Ok((Frame::HandshakeDone, 1)),
            0x30 => {
                // DATAGRAM without length — runs to end of packet.
                let data = &buf[p..];
                Ok((Frame::Datagram { data }, buf.len()))
            }
            0x31 => {
                let (length, n) = varint::decode(&buf[p..])?;
                p += n;
                let length = length as usize;
                if buf.len() - p < length {
                    return Err(Error::Decode);
                }
                let data = &buf[p..p + length];
                p += length;
                Ok((Frame::Datagram { data }, p))
            }
            _ => Err(Error::Decode),
        }
    }

    /// Encodes the frame into `out`.
    pub(crate) fn encode(&self, out: &mut Vec<u8>) {
        match *self {
            Frame::Padding(n) => {
                for _ in 0..n {
                    out.push(0x00);
                }
            }
            Frame::Ping => out.push(0x01),
            Frame::Ack {
                largest,
                ack_delay,
                ranges_raw,
                first_range,
                ecn,
            } => {
                out.push(if ecn.is_some() { 0x03 } else { 0x02 });
                varint::encode(largest, out);
                varint::encode(ack_delay, out);
                // Range count = number of (gap, range_length) pairs in
                // `ranges_raw`. Count them by walking the encoded form.
                let mut count = 0u64;
                {
                    let mut p = 0;
                    while p < ranges_raw.len() {
                        // gap
                        let (_, n) = varint::decode(&ranges_raw[p..])
                            .expect("ack ranges_raw must be well-formed");
                        p += n;
                        let (_, n) = varint::decode(&ranges_raw[p..])
                            .expect("ack ranges_raw must be well-formed");
                        p += n;
                        count += 1;
                    }
                }
                varint::encode(count, out);
                varint::encode(first_range, out);
                out.extend_from_slice(ranges_raw);
                if let Some(c) = ecn {
                    varint::encode(c.ect0, out);
                    varint::encode(c.ect1, out);
                    varint::encode(c.ce, out);
                }
            }
            Frame::ResetStream {
                id,
                code,
                final_size,
            } => {
                out.push(0x04);
                varint::encode(id, out);
                varint::encode(code, out);
                varint::encode(final_size, out);
            }
            Frame::StopSending { id, code } => {
                out.push(0x05);
                varint::encode(id, out);
                varint::encode(code, out);
            }
            Frame::Crypto { offset, data } => {
                out.push(0x06);
                varint::encode(offset, out);
                varint::encode(data.len() as u64, out);
                out.extend_from_slice(data);
            }
            Frame::NewToken { token } => {
                out.push(0x07);
                varint::encode(token.len() as u64, out);
                out.extend_from_slice(token);
            }
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                // Emit with LEN bit set; OFF set iff offset != 0; FIN bit
                // from the flag. (Callers that want LEN-clear encoding
                // build the bytes manually for the last frame of a packet.)
                let mut t = 0x08u8;
                if offset != 0 {
                    t |= 0x04;
                }
                t |= 0x02; // LEN
                if fin {
                    t |= 0x01;
                }
                out.push(t);
                varint::encode(id, out);
                if offset != 0 {
                    varint::encode(offset, out);
                }
                varint::encode(data.len() as u64, out);
                out.extend_from_slice(data);
            }
            Frame::MaxData(v) => {
                out.push(0x10);
                varint::encode(v, out);
            }
            Frame::MaxStreamData { id, limit } => {
                out.push(0x11);
                varint::encode(id, out);
                varint::encode(limit, out);
            }
            Frame::MaxStreams { dir, limit } => {
                out.push(match dir {
                    StreamDir::Bidi => 0x12,
                    StreamDir::Uni => 0x13,
                });
                varint::encode(limit, out);
            }
            Frame::DataBlocked(v) => {
                out.push(0x14);
                varint::encode(v, out);
            }
            Frame::StreamDataBlocked { id, limit } => {
                out.push(0x15);
                varint::encode(id, out);
                varint::encode(limit, out);
            }
            Frame::StreamsBlocked { dir, limit } => {
                out.push(match dir {
                    StreamDir::Bidi => 0x16,
                    StreamDir::Uni => 0x17,
                });
                varint::encode(limit, out);
            }
            Frame::NewConnectionId {
                seq,
                retire_prior_to,
                cid,
                reset_token,
            } => {
                out.push(0x18);
                varint::encode(seq, out);
                varint::encode(retire_prior_to, out);
                assert!(cid.len() <= 20, "QUIC connection ID exceeds 20 bytes");
                out.push(cid.len() as u8);
                out.extend_from_slice(cid);
                out.extend_from_slice(&reset_token);
            }
            Frame::RetireConnectionId { seq } => {
                out.push(0x19);
                varint::encode(seq, out);
            }
            Frame::PathChallenge(data) => {
                out.push(0x1A);
                out.extend_from_slice(&data);
            }
            Frame::PathResponse(data) => {
                out.push(0x1B);
                out.extend_from_slice(&data);
            }
            Frame::ConnectionClose {
                error,
                frame_type,
                reason,
            } => {
                out.push(if frame_type.is_some() { 0x1C } else { 0x1D });
                varint::encode(error, out);
                if let Some(ft) = frame_type {
                    varint::encode(ft, out);
                }
                varint::encode(reason.len() as u64, out);
                out.extend_from_slice(reason);
            }
            Frame::HandshakeDone => out.push(0x1E),
            Frame::Datagram { data } => {
                // Always emit the length-prefixed form (`0x31`); callers
                // that want the length-less form for the last frame of a
                // packet build the bytes manually.
                out.push(0x31);
                varint::encode(data.len() as u64, out);
                out.extend_from_slice(data);
            }
        }
    }
}

/// Iterator over the (gap, range_length) tail of an ACK frame's range list.
///
/// Each pair is returned as `(gap, range_length)` with the QUIC "value minus
/// one" semantics preserved — callers add 1 when computing the next absolute
/// range start.
#[derive(Debug, Clone)]
pub(crate) struct AckRangeIter<'a> {
    buf: &'a [u8],
}

impl<'a> Iterator for AckRangeIter<'a> {
    type Item = Result<(u64, u64), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        let (gap, n) = match varint::decode(self.buf) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        self.buf = &self.buf[n..];
        let (range_length, n) = match varint::decode(self.buf) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        self.buf = &self.buf[n..];
        Some(Ok((gap, range_length)))
    }
}

/// Iterates over the frames packed end-to-end into a QUIC packet payload.
#[derive(Debug, Clone)]
pub(crate) struct FrameIter<'a> {
    buf: &'a [u8],
}

impl<'a> FrameIter<'a> {
    /// Constructs a new iterator over `buf`.
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }
}

impl<'a> Iterator for FrameIter<'a> {
    type Item = Result<Frame<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        match Frame::decode(self.buf) {
            Ok((f, n)) => {
                self.buf = &self.buf[n..];
                Some(Ok(f))
            }
            Err(e) => {
                // Stop after the error so subsequent calls return None.
                self.buf = &[];
                Some(Err(e))
            }
        }
    }
}

/// Builds the on-wire ACK ranges body for a [`super::pn::AckRanges`] set.
///
/// Returns `(largest, first_range, ranges_raw)`. `largest` is the largest
/// acknowledged PN; `first_range` is the count of *additional* PNs below
/// `largest` covered by the highest range (i.e. `range.end() - range.start()`
/// for the first stored range); `ranges_raw` is the trailing
/// (gap, range_length) pairs encoded as varints. Returns `None` if the input
/// is empty.
pub(crate) fn build_ack_ranges_raw(ranges: &super::pn::AckRanges) -> Option<(u64, u64, Vec<u8>)> {
    let stored = ranges.ranges();
    if stored.is_empty() {
        return None;
    }
    let largest = *stored[0].end();
    let first_range = largest - *stored[0].start();
    let mut raw = Vec::new();
    for i in 1..stored.len() {
        // Gap = prev.start() - current.end() - 2.
        // Range length = current.end() - current.start().
        let prev_start = *stored[i - 1].start();
        let cur_end = *stored[i].end();
        let cur_start = *stored[i].start();
        // prev_start is at least 1 above cur_end (ranges are disjoint).
        // gap in QUIC encoding is (prev_start - cur_end - 2): "the number of
        // contiguous unacknowledged packet numbers preceding the largest
        // packet number in the Range, minus one".
        let gap = prev_start - cur_end - 2;
        let range_length = cur_end - cur_start;
        varint::encode(gap, &mut raw);
        varint::encode(range_length, &mut raw);
    }
    Some((largest, first_range, raw))
}

/// Reconstructs a [`super::pn::AckRanges`] from an ACK frame's encoded
/// fields.
pub(crate) fn parse_ack_ranges(
    largest: u64,
    first_range: u64,
    ranges_raw: &[u8],
) -> Result<super::pn::AckRanges, Error> {
    let mut out = super::pn::AckRanges::new();
    // First range covers [largest - first_range .. largest].
    if first_range > largest {
        return Err(Error::Decode);
    }
    let mut smallest_in_block = largest - first_range;
    // Insert from high to low.
    for pn in smallest_in_block..=largest {
        out.insert(pn);
    }
    let it = AckRangeIter { buf: ranges_raw };
    for pair in it {
        let (gap, range_length) = pair?;
        // Next range's largest = smallest_in_block - gap - 2.
        // Subtract carefully to detect underflow.
        let gap_plus_two = gap.checked_add(2).ok_or(Error::Decode)?;
        if smallest_in_block < gap_plus_two {
            return Err(Error::Decode);
        }
        let next_largest = smallest_in_block - gap_plus_two;
        if range_length > next_largest {
            return Err(Error::Decode);
        }
        let next_smallest = next_largest - range_length;
        for pn in next_smallest..=next_largest {
            out.insert(pn);
        }
        smallest_in_block = next_smallest;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::pn::AckRanges;

    #[test]
    fn roundtrip_every_variant() {
        // Build each variant, encode + decode, assert equality. ACK is
        // covered by a dedicated test below — use an empty ranges_raw here.
        let cases: Vec<Frame<'_>> = alloc::vec![
            Frame::Padding(3),
            Frame::Ping,
            Frame::Ack {
                largest: 42,
                ack_delay: 7,
                ranges_raw: &[],
                first_range: 0,
                ecn: None,
            },
            Frame::Ack {
                largest: 42,
                ack_delay: 7,
                ranges_raw: &[],
                first_range: 0,
                ecn: Some(EcnCounts {
                    ect0: 1,
                    ect1: 2,
                    ce: 3,
                }),
            },
            Frame::ResetStream {
                id: 5,
                code: 7,
                final_size: 100,
            },
            Frame::StopSending { id: 5, code: 7 },
            Frame::Crypto {
                offset: 0,
                data: b"hi",
            },
            Frame::NewToken { token: b"tok" },
            Frame::Stream {
                id: 4,
                offset: 0,
                fin: true,
                data: b"hi",
            },
            Frame::Stream {
                id: 8,
                offset: 64,
                fin: false,
                data: b"abc",
            },
            Frame::MaxData(1024),
            Frame::MaxStreamData { id: 0, limit: 8192 },
            Frame::MaxStreams {
                dir: StreamDir::Bidi,
                limit: 100,
            },
            Frame::MaxStreams {
                dir: StreamDir::Uni,
                limit: 100,
            },
            Frame::DataBlocked(500),
            Frame::StreamDataBlocked { id: 1, limit: 200 },
            Frame::StreamsBlocked {
                dir: StreamDir::Bidi,
                limit: 3,
            },
            Frame::StreamsBlocked {
                dir: StreamDir::Uni,
                limit: 4,
            },
            Frame::NewConnectionId {
                seq: 1,
                retire_prior_to: 0,
                cid: &[1, 2, 3, 4],
                reset_token: [9u8; 16],
            },
            Frame::RetireConnectionId { seq: 2 },
            Frame::PathChallenge([1, 2, 3, 4, 5, 6, 7, 8]),
            Frame::PathResponse([8, 7, 6, 5, 4, 3, 2, 1]),
            Frame::ConnectionClose {
                error: 0,
                frame_type: Some(0x08),
                reason: b"bye",
            },
            Frame::ConnectionClose {
                error: 1,
                frame_type: None,
                reason: b"app",
            },
            Frame::HandshakeDone,
            Frame::Datagram { data: b"hello" },
        ];
        for frame in &cases {
            let mut buf = Vec::new();
            frame.encode(&mut buf);
            let (decoded, used) = Frame::decode(&buf).expect("decode");
            assert_eq!(
                used,
                buf.len(),
                "frame {:?} consumed {} of {}",
                frame,
                used,
                buf.len()
            );
            assert_eq!(&decoded, frame, "frame {:?} roundtrip", frame);
        }
    }

    #[test]
    fn stream_off_len_fin_bit_decoding() {
        // offset = 0 → OFF bit clear; LEN bit set (our encoder always emits
        // length-prefixed); FIN bit set.
        let frame = Frame::Stream {
            id: 4,
            offset: 0,
            fin: true,
            data: b"hi",
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        // type = 0x08 | LEN(0x02) | FIN(0x01) = 0x0B
        assert_eq!(buf[0], 0x0B);

        // offset != 0 → OFF bit set.
        let frame = Frame::Stream {
            id: 4,
            offset: 16,
            fin: false,
            data: b"hi",
        };
        let mut buf = Vec::new();
        frame.encode(&mut buf);
        // type = 0x08 | OFF(0x04) | LEN(0x02) = 0x0E
        assert_eq!(buf[0], 0x0E);
    }

    #[test]
    fn stream_no_length_extends_to_end() {
        // Manually craft a STREAM frame with LEN bit unset.
        // type = 0x08 (no OFF, no LEN, no FIN), id = 4 (1-byte varint), data
        // runs to end-of-packet.
        let buf = [0x08u8, 0x04, b'a', b'b', b'c', b'd'];
        let (frame, used) = Frame::decode(&buf).expect("decode");
        assert_eq!(used, buf.len());
        match frame {
            Frame::Stream {
                id,
                offset,
                fin,
                data,
            } => {
                assert_eq!(id, 4);
                assert_eq!(offset, 0);
                assert!(!fin);
                assert_eq!(data, b"abcd");
            }
            other => panic!("expected STREAM, got {other:?}"),
        }
    }

    fn ack_ranges_from(pns: &[u64]) -> AckRanges {
        let mut r = AckRanges::new();
        for &p in pns {
            r.insert(p);
        }
        r
    }

    #[test]
    fn ack_ranges_roundtrip_via_iter() {
        // Boundary cases per the plan:
        let cases: &[&[u64]] = &[
            &[5],                     // one PN
            &[5, 6],                  // two PNs
            &[5, 9],                  // two single disjoint PNs
            &[1, 2, 5, 6],            // two pairs of two
            &[0],                     // one PN at 0
            &[0, 1, 2, 5, 6, 10, 20], // mixed
        ];
        for pns in cases {
            let ranges = ack_ranges_from(pns);
            let (largest, first_range, raw) = build_ack_ranges_raw(&ranges).expect("non-empty");
            let parsed = parse_ack_ranges(largest, first_range, &raw).expect("parse");
            assert_eq!(
                parsed, ranges,
                "ack-ranges roundtrip failed for {pns:?} (raw={raw:?})"
            );
        }
    }

    #[test]
    fn padding_run_length() {
        // Encode a Padding(7) run.
        let mut buf = Vec::new();
        Frame::Padding(7).encode(&mut buf);
        assert_eq!(buf, alloc::vec![0u8; 7]);

        // Decode a 7-byte 0x00 buffer.
        let (frame, used) = Frame::decode(&buf).expect("decode");
        assert_eq!(used, buf.len());
        assert_eq!(frame, Frame::Padding(7));
    }

    #[test]
    fn connection_close_app_vs_transport() {
        // Transport (0x1C).
        let f1 = Frame::ConnectionClose {
            error: 0,
            frame_type: Some(0x06),
            reason: b"bad CRYPTO",
        };
        let mut buf = Vec::new();
        f1.encode(&mut buf);
        assert_eq!(buf[0], 0x1C);
        let (decoded, _) = Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, f1);

        // Application (0x1D) — no frame_type field.
        let f2 = Frame::ConnectionClose {
            error: 42,
            frame_type: None,
            reason: b"app close",
        };
        let mut buf = Vec::new();
        f2.encode(&mut buf);
        assert_eq!(buf[0], 0x1D);
        let (decoded, _) = Frame::decode(&buf).expect("decode");
        assert_eq!(decoded, f2);
    }

    #[test]
    fn frame_iter_walks_packet() {
        let mut buf = Vec::new();
        Frame::Ping.encode(&mut buf);
        Frame::MaxData(1024).encode(&mut buf);
        Frame::HandshakeDone.encode(&mut buf);
        let mut it = FrameIter::new(&buf);
        assert_eq!(it.next().unwrap().unwrap(), Frame::Ping);
        assert_eq!(it.next().unwrap().unwrap(), Frame::MaxData(1024));
        assert_eq!(it.next().unwrap().unwrap(), Frame::HandshakeDone);
        assert!(it.next().is_none());
    }
}
