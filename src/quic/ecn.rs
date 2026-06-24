//! Explicit Congestion Notification (ECN) — the IP-layer codepoint that the
//! sans-I/O QUIC API carries across its datagram boundary.
//!
//! ECN lives in the two least-significant bits of the IP Traffic Class octet
//! (IPv4 DSCP/ECN, IPv6 Traffic Class). A QUIC sender marks egress datagrams
//! ECT(0); routers experiencing congestion rewrite that to CE; the receiver
//! counts codepoints per packet-number space and echoes the totals in ACK
//! frames, letting the sender treat CE as a congestion signal without waiting
//! for loss (RFC 9000 §13, RFC 9002 §7.3).
//!
//! The engine itself cannot read or write IP headers — that is the host's job
//! (via `recvmsg`/`sendmsg` control messages). So the codepoint rides in and
//! out through [`crate::quic::QuicServer::recv`] / `poll_transmit` and the
//! per-connection feed/transmit calls; a host with no ECN plumbing simply
//! passes [`EcnCodepoint::NotEct`].

/// The IP ECN field of a datagram (RFC 3168 §5): a 2-bit codepoint.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
#[repr(u8)]
pub enum EcnCodepoint {
    /// `00` — Not ECN-Capable Transport.
    #[default]
    NotEct = 0b00,
    /// `01` — ECN-Capable Transport, ECT(1).
    Ect1 = 0b01,
    /// `10` — ECN-Capable Transport, ECT(0). What a QUIC sender marks.
    Ect0 = 0b10,
    /// `11` — Congestion Experienced (set by a router on the path).
    Ce = 0b11,
}

impl EcnCodepoint {
    /// Decodes the low two bits of an IP Traffic Class octet.
    pub fn from_bits(tos: u8) -> Self {
        match tos & 0b11 {
            0b01 => EcnCodepoint::Ect1,
            0b10 => EcnCodepoint::Ect0,
            0b11 => EcnCodepoint::Ce,
            _ => EcnCodepoint::NotEct,
        }
    }

    /// The 2-bit codepoint value (to OR into an IP Traffic Class octet).
    pub fn to_bits(self) -> u8 {
        self as u8
    }

    /// Whether this codepoint marks the datagram as ECN-capable (ECT(0)/ECT(1)).
    pub fn is_ect(self) -> bool {
        matches!(self, EcnCodepoint::Ect0 | EcnCodepoint::Ect1)
    }
}
