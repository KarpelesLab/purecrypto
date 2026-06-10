//! RFC 9000 §17 — packet header serialization and parsing.
//!
//! QUIC v1 packets come in two header flavors:
//!
//! * **Long header** (§17.2) — Initial, 0-RTT, Handshake, Retry, plus the
//!   special Version Negotiation form (§17.2.1, version field = 0).
//! * **Short header** (§17.3) — 1-RTT, after handshake completion.
//!
//! Plus two special long-header variants that carry no AEAD payload and
//! therefore have their own framing rules:
//!
//! * **Retry** (§17.2.5) — has no Length or Packet Number field; ends in a
//!   16-byte Retry Integrity Tag (RFC 9001 §5.8).
//! * **Version Negotiation** (§17.2.1) — version field is 0; payload is a
//!   list of 32-bit supported-version numbers; no Fixed-Bit constraint.
//!
//! This module is sans-I/O: it produces and consumes byte buffers and
//! offsets only. Header protection (RFC 9001 §5.4) is applied as a final
//! pass over the already-assembled packet bytes via
//! [`apply_header_protection`] / [`remove_header_protection`]. AEAD seal
//! and open live in [`super::crypto`].

#![allow(dead_code)]

use alloc::vec::Vec;

use crate::cipher::{Aes128, Gcm};
use crate::quic::varint;
use crate::tls::Error;

/// QUIC version 1 (RFC 9000): the only version this stack speaks.
pub(crate) const QUIC_V1: u32 = 0x0000_0001;

/// Long-header packet type (RFC 9000 §17.2, Table 5).
///
/// The 2-bit Long Packet Type lives in bits 5..4 of byte 0 (mask 0x30);
/// these are the constants `0..3` shifted into that position.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum LongType {
    Initial = 0x00,
    ZeroRtt = 0x01,
    Handshake = 0x02,
    Retry = 0x03,
}

impl LongType {
    /// Maps the raw 2-bit type field (already shifted into 0..=3) to the
    /// enum. Returns `None` if the value is out of range — it cannot be,
    /// but the conversion is total at the type level.
    fn from_bits(bits: u8) -> Option<Self> {
        Some(match bits & 0x03 {
            0x00 => Self::Initial,
            0x01 => Self::ZeroRtt,
            0x02 => Self::Handshake,
            0x03 => Self::Retry,
            _ => return None,
        })
    }

    /// First-byte template for an unprotected long-header packet with this
    /// type. Sets Header Form (0x80), Fixed Bit (0x40), and the 2-bit Long
    /// Packet Type (mask 0x30); the low 4 bits — Reserved (0x0c) and PN
    /// Length (0x03) — are filled in by the caller. RFC 9000 §17.2.
    fn first_byte_template(self) -> u8 {
        0x80 | 0x40 | ((self as u8) << 4)
    }
}

/// Parsed long-header view that borrows from the source datagram.
///
/// The fields `pn_offset` and `payload_off` are offsets into the original
/// buffer the caller used for parsing. After header-protection removal the
/// caller reads the packet-number bytes at `[pn_offset .. pn_offset +
/// pn_len]` (with `pn_len` recovered from the low 2 bits of the first
/// byte) and the protected payload + 16-byte tag at `[payload_off + pn_len
/// .. end]`.
#[derive(Debug)]
pub(crate) struct LongHeader<'a> {
    pub typ: LongType,
    pub version: u32,
    pub dcid: &'a [u8],
    pub scid: &'a [u8],
    /// Initial-only Token field. Empty for 0-RTT / Handshake / Retry.
    pub token: &'a [u8],
    /// Initial / 0-RTT / Handshake only: the value of the Length field.
    /// For Retry this is 0 (no Length field in Retry).
    pub length: u64,
    /// Offset of the start of the (still protected, on receive) packet
    /// number field, relative to the start of the parsed buffer. For Retry
    /// this points past the SCID at the start of the Retry Token; the
    /// caller distinguishes by `typ == Retry`.
    pub pn_offset: usize,
    /// Offset of the start of `{ PN || protected_payload || tag }`. For
    /// Initial / 0-RTT / Handshake this equals `pn_offset`. For Retry it
    /// equals `pn_offset` as well — but in Retry the PN is absent and the
    /// caller should treat the range as `{ token || integrity_tag }`.
    pub payload_off: usize,
}

impl<'a> LongHeader<'a> {
    /// Parses a long header from the start of `buf`. The packet number
    /// itself is left protected — the caller invokes header-protection
    /// removal first (since the encoded PN length lives in the low 2 bits
    /// of the (still-protected on receive) first byte).
    ///
    /// Returns [`Error::Decode`] for any wire-syntax violation (RFC 9000
    /// §17.2: CID lengths > 20 in v1, missing Fixed Bit, truncated buffer,
    /// varint decode failure, …).
    pub(crate) fn parse(buf: &'a [u8]) -> Result<Self, Error> {
        if buf.is_empty() {
            return Err(Error::Decode);
        }
        let b0 = buf[0];
        // Header Form bit (RFC 9000 §17.2).
        if b0 & 0x80 == 0 {
            return Err(Error::Decode); // short header, wrong parser
        }
        // Length sanity for the fixed-position fields: 1 first byte + 4
        // version + 1 dcid_len at minimum.
        if buf.len() < 6 {
            return Err(Error::Decode);
        }
        let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);

        // Version Negotiation: version = 0 (RFC 9000 §17.2.1). The
        // Fixed-Bit constraint and the Long Packet Type are *both* absent;
        // the caller dispatches based on `version == 0` from this point.
        // We still parse DCID / SCID below — but the rest of the §17.2
        // structure (Token, Length, PN) does not apply.
        if version == 0 {
            let mut p = 5usize;
            let dcid_len = *buf.get(p).ok_or(Error::Decode)? as usize;
            p += 1;
            if dcid_len > 20 || buf.len() < p + dcid_len + 1 {
                // §17.2: dcid length ≤ 20 in v1, but VN itself is version-
                // independent — we still cap at 20 here because higher
                // values would be a hostile malformed VN.
                return Err(Error::Decode);
            }
            let dcid = &buf[p..p + dcid_len];
            p += dcid_len;
            let scid_len = *buf.get(p).ok_or(Error::Decode)? as usize;
            p += 1;
            if scid_len > 20 || buf.len() < p + scid_len {
                return Err(Error::Decode);
            }
            let scid = &buf[p..p + scid_len];
            p += scid_len;
            return Ok(LongHeader {
                typ: LongType::Initial, // placeholder — caller checks version==0
                version: 0,
                dcid,
                scid,
                token: &[],
                length: 0,
                pn_offset: p,
                payload_off: p,
            });
        }

        // Non-VN long header: Fixed Bit must be 1 (RFC 9000 §17.2).
        if b0 & 0x40 == 0 {
            return Err(Error::Decode);
        }
        let typ = LongType::from_bits((b0 >> 4) & 0x03).ok_or(Error::Decode)?;

        let mut p = 5usize;
        let dcid_len = *buf.get(p).ok_or(Error::Decode)? as usize;
        p += 1;
        // RFC 9000 §17.2: "In QUIC version 1, this value MUST NOT exceed
        // 20 bytes. Endpoints that receive a version 1 long header with a
        // value larger than 20 MUST drop the packet."
        if dcid_len > 20 {
            return Err(Error::Decode);
        }
        if buf.len() < p + dcid_len + 1 {
            return Err(Error::Decode);
        }
        let dcid = &buf[p..p + dcid_len];
        p += dcid_len;

        let scid_len = *buf.get(p).ok_or(Error::Decode)? as usize;
        p += 1;
        if scid_len > 20 {
            return Err(Error::Decode);
        }
        if buf.len() < p + scid_len {
            return Err(Error::Decode);
        }
        let scid = &buf[p..p + scid_len];
        p += scid_len;

        match typ {
            LongType::Retry => {
                // RFC 9000 §17.2.5 — no Token Length / Length / PN fields.
                // Payload = Retry Token || 16-byte Integrity Tag.
                if buf.len() < p + 16 {
                    return Err(Error::Decode);
                }
                Ok(LongHeader {
                    typ,
                    version,
                    dcid,
                    scid,
                    token: &buf[p..buf.len() - 16],
                    length: 0,
                    pn_offset: p,
                    payload_off: p,
                })
            }
            LongType::Initial => {
                let (tlen, n) = varint::decode(&buf[p..])?;
                p += n;
                let tlen = tlen as usize;
                if buf.len() < p + tlen {
                    return Err(Error::Decode);
                }
                let token = &buf[p..p + tlen];
                p += tlen;
                let (length, n) = varint::decode(&buf[p..])?;
                p += n;
                // p now points at the (protected) first PN byte. We do
                // NOT validate that `buf.len() >= p + length` here — the
                // parser is used both for full packets and for inspecting
                // a header in isolation; the caller's AEAD step will
                // reject a packet whose declared length runs past the
                // buffer.
                Ok(LongHeader {
                    typ,
                    version,
                    dcid,
                    scid,
                    token,
                    length,
                    pn_offset: p,
                    payload_off: p,
                })
            }
            LongType::ZeroRtt | LongType::Handshake => {
                let (length, n) = varint::decode(&buf[p..])?;
                p += n;
                Ok(LongHeader {
                    typ,
                    version,
                    dcid,
                    scid,
                    token: &[],
                    length,
                    pn_offset: p,
                    payload_off: p,
                })
            }
        }
    }
}

/// Builds the bytes of a long-header packet's *unprotected* header.
///
/// Returns `(header_bytes, pn_offset)`. The caller appends the encoded
/// packet number (the function already does this), then the AEAD body
/// plus tag, and then optionally applies header protection.
///
/// `pn_value` is the actual packet number; `pn_len` is the encoded length
/// (must be `1..=4`). `payload_len_for_field` is the value to encode in
/// the Length field — it is the encoded-PN length plus the inner payload
/// length plus the 16-byte AEAD tag (RFC 9000 §17.2: "the length of the
/// remainder of the packet (that is, the Packet Number and Payload
/// fields) in bytes").
///
/// Token must be empty unless `typ == Initial`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_long_header(
    typ: LongType,
    version: u32,
    dcid: &[u8],
    scid: &[u8],
    token: &[u8],
    pn_value: u64,
    pn_len: u8,
    payload_len_for_field: u64,
) -> (Vec<u8>, usize) {
    debug_assert!((1..=4).contains(&pn_len));
    debug_assert!(dcid.len() <= 20);
    debug_assert!(scid.len() <= 20);
    debug_assert!(token.is_empty() || matches!(typ, LongType::Initial));
    debug_assert!(!matches!(typ, LongType::Retry), "use build_retry()");

    let mut out = Vec::with_capacity(32 + token.len());
    // First byte: long-header template plus low 2 bits = pn_len - 1
    // (RFC 9000 §17.2 "Packet Number Length"). The Reserved bits (mask
    // 0x0c) are zero.
    out.push(typ.first_byte_template() | (pn_len - 1));
    out.extend_from_slice(&version.to_be_bytes());
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);

    if matches!(typ, LongType::Initial) {
        varint::encode(token.len() as u64, &mut out);
        out.extend_from_slice(token);
    }

    varint::encode(payload_len_for_field, &mut out);
    let pn_offset = out.len();
    // The PN is encoded big-endian truncated to `pn_len` bytes.
    let pn_bytes = pn_value.to_be_bytes();
    out.extend_from_slice(&pn_bytes[8 - pn_len as usize..]);
    (out, pn_offset)
}

/// Parsed short-header view (RFC 9000 §17.3.1).
///
/// The short header does not include a connection-ID length on the wire —
/// the receiving endpoint must know its own DCID length from connection
/// state. Reserved bits (mask 0x18) and Key Phase (mask 0x04) are
/// header-protected; the caller removes header protection before reading
/// the Key Phase or the PN.
#[derive(Debug)]
pub(crate) struct ShortHeader<'a> {
    pub dcid: &'a [u8],
    pub key_phase: bool,
    pub spin: bool,
    /// Offset of the start of the (still-protected on receive) packet
    /// number field.
    pub pn_offset: usize,
}

impl<'a> ShortHeader<'a> {
    /// Parses the short header at the start of `buf`. `dcid_len` is taken
    /// from connection state (the endpoint chose its own CIDs).
    ///
    /// This is called twice in receive flow: once before header-protection
    /// removal to locate the PN offset (the `key_phase` field is not yet
    /// trustworthy then), and once after to read the unmasked first byte.
    /// Both call sites build the same `ShortHeader`; only the masked vs
    /// unmasked fields differ.
    pub(crate) fn parse(buf: &'a [u8], dcid_len: usize) -> Result<Self, Error> {
        if buf.is_empty() {
            return Err(Error::Decode);
        }
        let b0 = buf[0];
        // Header Form must be 0 (short header) and Fixed Bit must be 1
        // (RFC 9000 §17.3.1).
        if b0 & 0x80 != 0 || b0 & 0x40 == 0 {
            return Err(Error::Decode);
        }
        if dcid_len > 20 {
            return Err(Error::Decode);
        }
        if buf.len() < 1 + dcid_len {
            return Err(Error::Decode);
        }
        let dcid = &buf[1..1 + dcid_len];
        Ok(ShortHeader {
            dcid,
            spin: b0 & 0x20 != 0,
            key_phase: b0 & 0x04 != 0,
            pn_offset: 1 + dcid_len,
        })
    }
}

/// Builds an unprotected short-header (1-RTT) packet (RFC 9000 §17.3.1).
///
/// Returns `(header_bytes, pn_offset)`. `pn_len` is 1..=4. The first byte
/// has the form `0b01SK00PP` where:
/// * `01` (bit 7=0, bit 6=1): Header Form + Fixed Bit
/// * `S`  (bit 5): Spin Bit
/// * `00` (bits 4..3): Reserved (zero before HP)
/// * `K`  (bit 2): Key Phase
/// * `PP` (bits 1..0): Packet Number Length minus one
pub(crate) fn build_short_header(
    dcid: &[u8],
    spin: bool,
    key_phase: bool,
    pn_value: u64,
    pn_len: u8,
) -> (Vec<u8>, usize) {
    debug_assert!((1..=4).contains(&pn_len));
    debug_assert!(dcid.len() <= 20);

    let mut b0 = 0x40u8 | (pn_len - 1);
    if spin {
        b0 |= 0x20;
    }
    if key_phase {
        b0 |= 0x04;
    }
    let mut out = Vec::with_capacity(1 + dcid.len() + 4);
    out.push(b0);
    out.extend_from_slice(dcid);
    let pn_offset = out.len();
    let pn_bytes = pn_value.to_be_bytes();
    out.extend_from_slice(&pn_bytes[8 - pn_len as usize..]);
    (out, pn_offset)
}

/// RFC 9001 §5.4 — apply a 5-byte header-protection mask to an
/// already-assembled packet.
///
/// `packet` must contain `header || ciphertext || tag` with the
/// unprotected first byte and the unprotected packet number; this
/// function XORs the mask into the bits the receiver does not see in
/// cleartext (low 4 bits of byte 0 for long header, low 5 bits for short
/// header, plus all `pn_len` packet-number bytes).
///
/// `pn_offset` is the byte index of the first packet-number byte. `mask`
/// is the 5-byte output of [`super::crypto::HeaderProt::mask`] applied to
/// the 16-byte sample at `&packet[pn_offset + 4 .. pn_offset + 4 + 16]`
/// (RFC 9001 §5.4.2 — the sample is taken assuming a 4-byte PN even when
/// the actual PN is shorter).
pub(crate) fn apply_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    pn_len: u8,
    mask: &[u8; 5],
    long_header: bool,
) {
    debug_assert!((1..=4).contains(&pn_len));
    debug_assert!(packet.len() >= pn_offset + pn_len as usize);

    // RFC 9001 §5.4.1 pseudocode:
    //   if (packet[0] & 0x80) == 0x80:
    //       # Long header: 4 bits masked
    //       packet[0] ^= mask[0] & 0x0f
    //   else:
    //       # Short header: 5 bits masked
    //       packet[0] ^= mask[0] & 0x1f
    let first_byte_mask = if long_header { 0x0f } else { 0x1f };
    packet[0] ^= mask[0] & first_byte_mask;
    for i in 0..pn_len as usize {
        packet[pn_offset + i] ^= mask[1 + i];
    }
}

/// RFC 9001 §5.4 — remove header protection from a received packet.
///
/// XORs `mask` into the protected bits of byte 0 (low 4 for long, low 5
/// for short), then reads the recovered packet-number length from the
/// low 2 bits of byte 0 (RFC 9000 §17.2 / §17.3.1), and unmasks the
/// `pn_len` packet-number bytes accordingly. Returns the recovered
/// `pn_len` (1..=4) so the caller can advance past the PN to the start
/// of the ciphertext.
pub(crate) fn remove_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    mask: &[u8; 5],
    long_header: bool,
) -> Result<u8, Error> {
    let first_byte_mask = if long_header { 0x0f } else { 0x1f };
    packet[0] ^= mask[0] & first_byte_mask;
    let pn_len = (packet[0] & 0x03) + 1;
    if (pn_len as usize) > 4 || packet.len() < pn_offset + pn_len as usize {
        return Err(Error::Decode);
    }
    for i in 0..pn_len as usize {
        packet[pn_offset + i] ^= mask[1 + i];
    }
    Ok(pn_len)
}

/// RFC 9000 §17.2 / §17.3.1 — validate the reserved bits of the first
/// header byte after header-protection removal.
///
/// Long headers reserve bits 0x0c; short headers reserve bits 0x18.
/// Both MUST be zero once header protection is removed; an endpoint
/// that receives a packet with non-zero reserved bits MUST treat it as
/// a connection error of type PROTOCOL_VIOLATION (mapped here to
/// [`Error::IllegalParameter`], which the close path surfaces as
/// PROTOCOL_VIOLATION on the wire).
///
/// IMPORTANT: callers must invoke this only AFTER the packet's AEAD
/// tag has verified. The reserved bits are header-protected, so on a
/// forged or corrupted packet they decode to garbage — checking them
/// pre-authentication would let an off-path attacker tear down the
/// connection with a single spoofed datagram, where the correct
/// behavior is a silent per-packet drop (RFC 9000 §12.2).
pub(crate) fn check_reserved_bits(first_byte: u8, long_header: bool) -> Result<(), Error> {
    let reserved_mask = if long_header { 0x0c } else { 0x18 };
    if first_byte & reserved_mask != 0 {
        return Err(Error::IllegalParameter);
    }
    Ok(())
}

/// RFC 9001 §5.8 — fixed AES-128-GCM key for the Retry Integrity Tag,
/// `0xbe0c690b9f66575a1d766b54e368c84e`. Derived in the RFC from the
/// retry secret `0xd9c9943e6101fd200021506bcc02814c73030f25c79d71ce876e\
/// ca876e6fca8e` via `HKDF-Expand-Label(secret, "quic key", "", 16)`,
/// but the spec gives the final value directly and we use it as-is — the
/// key is constant for QUIC v1.
const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
    0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
];

/// RFC 9001 §5.8 — fixed 96-bit nonce `0x461599d35d632bf2239825bb`.
const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
    0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
];

/// RFC 9001 §5.8 — compute the 16-byte Retry Integrity Tag.
///
/// The pseudo-packet (RFC 9001 §5.8 Figure 8) is:
///
/// ```text
///   ODCID Length (8 bits)
///   Original Destination Connection ID (0..160 bits)
///   Header Form bit + Fixed Bit + Long Packet Type=3 + Unused
///   Version (32)
///   DCID Len (8) + DCID
///   SCID Len (8) + SCID
///   Retry Token
/// ```
///
/// — i.e. exactly the bytes the server is about to send for this Retry
/// packet, *without* the trailing 16-byte integrity-tag slot, prefixed
/// with `ODCID_len || ODCID`.
///
/// `odcid` is the *original* destination connection ID — the one the
/// client put on the Initial packet that triggered this Retry, *not* the
/// DCID inside the Retry itself (which is the new server-chosen CID).
///
/// `retry_unauth` is the unprotected Retry packet up to but excluding
/// the integrity-tag slot — i.e. `first_byte || version || dcid_len ||
/// dcid || scid_len || scid || retry_token`. The function builds the
/// pseudo-packet AAD by prepending `ODCID_len || ODCID`, then runs
/// AES-128-GCM with the fixed retry key+nonce over an empty plaintext.
pub(crate) fn retry_integrity_tag(odcid: &[u8], retry_unauth: &[u8]) -> [u8; 16] {
    let mut aad = Vec::with_capacity(1 + odcid.len() + retry_unauth.len());
    aad.push(odcid.len() as u8);
    aad.extend_from_slice(odcid);
    aad.extend_from_slice(retry_unauth);

    let aes = Aes128::new(&RETRY_INTEGRITY_KEY_V1);
    let g: Gcm<Aes128> = Gcm::new(aes);
    let mut empty: [u8; 0] = [];
    g.encrypt(&RETRY_INTEGRITY_NONCE_V1, &aad, &mut empty)
}

/// Build the unprotected portion of a Retry packet — every byte from the
/// first header byte up to and including the Retry Token. The caller
/// passes this through [`retry_integrity_tag`] to compute the trailing
/// 16-byte tag and concatenate.
///
/// First byte for Retry (RFC 9000 §17.2.5): Header Form (0x80) + Fixed
/// Bit (0x40) + Long Packet Type 3 (0x30). The low 4 bits (Unused per
/// §17.2.5) are arbitrary; we emit zero for determinism in tests.
pub(crate) fn build_retry_unauth(
    version: u32,
    dcid: &[u8],
    scid: &[u8],
    retry_token: &[u8],
) -> Vec<u8> {
    debug_assert!(dcid.len() <= 20);
    debug_assert!(scid.len() <= 20);
    let mut out = Vec::with_capacity(7 + dcid.len() + scid.len() + retry_token.len());
    out.push(0x80 | 0x40 | 0x30); // Retry first byte (Unused bits = 0).
    out.extend_from_slice(&version.to_be_bytes());
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);
    out.extend_from_slice(retry_token);
    out
}

/// Build a full Retry packet — the unprotected portion followed by the
/// 16-byte integrity tag (RFC 9001 §5.8).
pub(crate) fn build_retry(
    version: u32,
    dcid: &[u8],
    scid: &[u8],
    retry_token: &[u8],
    odcid: &[u8],
) -> Vec<u8> {
    let mut pkt = build_retry_unauth(version, dcid, scid, retry_token);
    let tag = retry_integrity_tag(odcid, &pkt);
    pkt.extend_from_slice(&tag);
    pkt
}

/// RFC 9000 §17.2.1 — build a Version Negotiation packet.
///
/// The first byte has the Header Form bit (0x80) set; per the RFC the
/// remaining 7 bits are "arbitrary" but it's RECOMMENDED to set the
/// Fixed-Bit position (0x40) so middleboxes that probe for QUIC see a
/// valid-looking packet. We follow the recommendation.
///
/// Version field is `0x00000000`. The body is a list of 32-bit supported
/// versions in network byte order.
pub(crate) fn build_version_negotiation(dcid: &[u8], scid: &[u8], versions: &[u32]) -> Vec<u8> {
    debug_assert!(dcid.len() <= 20);
    debug_assert!(scid.len() <= 20);
    let mut out = Vec::with_capacity(7 + dcid.len() + scid.len() + 4 * versions.len());
    out.push(0x80 | 0x40); // Header Form set; Fixed Bit position set per §17.2.1.
    out.extend_from_slice(&[0u8; 4]); // Version = 0
    out.push(dcid.len() as u8);
    out.extend_from_slice(dcid);
    out.push(scid.len() as u8);
    out.extend_from_slice(scid);
    for &v in versions {
        out.extend_from_slice(&v.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::crypto::{AeadAlg, derive_dir_keys, derive_initial_secrets};

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    // -------- Reserved-bit validation (RFC 9000 §17.2 / §17.3.1) -------

    #[test]
    fn reserved_bits_long_header() {
        // All long-header first bytes with reserved bits (0x0c) zero
        // pass, regardless of the other bits.
        assert!(check_reserved_bits(0xc3, true).is_ok()); // Initial, pn_len=4
        assert!(check_reserved_bits(0xe0, true).is_ok()); // Handshake
        assert!(check_reserved_bits(0xc3 | 0x30, true).is_ok()); // type bits aren't reserved
        // Each reserved bit set alone, and both together, must fail.
        assert!(check_reserved_bits(0xc3 | 0x04, true).is_err());
        assert!(check_reserved_bits(0xc3 | 0x08, true).is_err());
        assert!(check_reserved_bits(0xc3 | 0x0c, true).is_err());
    }

    #[test]
    fn reserved_bits_short_header() {
        // Short header reserves 0x18; spin (0x20), key-phase (0x04)
        // and pn_len (0x03) bits are all legitimate.
        assert!(check_reserved_bits(0x40, false).is_ok());
        assert!(check_reserved_bits(0x40 | 0x20 | 0x04 | 0x03, false).is_ok());
        assert!(check_reserved_bits(0x40 | 0x08, false).is_err());
        assert!(check_reserved_bits(0x40 | 0x10, false).is_err());
        assert!(check_reserved_bits(0x40 | 0x18, false).is_err());
        // Long-header reserved bits are NOT reserved in short headers
        // (0x04 is the key-phase bit) — masks must not be mixed up.
        assert!(check_reserved_bits(0x40 | 0x04, false).is_ok());
    }

    // -------- Long header build / parse roundtrip ----------------------

    #[test]
    fn long_header_initial_roundtrip() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let scid: [u8; 0] = [];
        let token: [u8; 0] = [];
        let (hdr, pn_off) = build_long_header(
            LongType::Initial,
            QUIC_V1,
            &dcid,
            &scid,
            &token,
            2,    // pn_value
            4,    // pn_len (4 bytes → encoded value is 3 in low bits)
            1182, // payload_len_for_field
        );
        // RFC 9001 §A.2 unprotected header for the client Initial:
        //   c300000001088394c8f03e5157080000449e00000002
        assert_eq!(
            hdr.as_slice(),
            hex("c300000001088394c8f03e5157080000449e00000002").as_slice(),
        );
        // pn_offset for §A.2 = 22 - 4 = 18.
        assert_eq!(pn_off, 18);

        // Parse it back: leaves the protected bits at zero because we
        // never applied HP. The recovered PN length comes from the low
        // 2 bits of byte 0 (= 0b11 → 4 bytes).
        let parsed = LongHeader::parse(&hdr).expect("parse");
        assert_eq!(parsed.typ, LongType::Initial);
        assert_eq!(parsed.version, QUIC_V1);
        assert_eq!(parsed.dcid, &dcid);
        assert_eq!(parsed.scid, &scid);
        assert_eq!(parsed.token, &token);
        assert_eq!(parsed.length, 1182);
        assert_eq!(parsed.pn_offset, 18);
    }

    #[test]
    fn long_header_server_initial_layout() {
        // RFC 9001 §A.3 unprotected server Initial header:
        //   c1000000010008f067a5502a4262b50040750001
        let dcid: [u8; 0] = [];
        let scid = hex("f067a5502a4262b5");
        let (hdr, pn_off) =
            build_long_header(LongType::Initial, QUIC_V1, &dcid, &scid, &[], 1, 2, 117);
        assert_eq!(
            hdr.as_slice(),
            hex("c1000000010008f067a5502a4262b50040750001").as_slice(),
        );
        // For §A.3 the PN occupies bytes 18..20 (header is 20 bytes long
        // and the PN is the last 2).
        assert_eq!(pn_off, 18);

        let parsed = LongHeader::parse(&hdr).expect("parse");
        assert_eq!(parsed.scid, scid.as_slice());
        assert_eq!(parsed.length, 117);
    }

    /// `pn_len` ∈ {1,2,3,4} encode/parse roundtrip — verifies the low-2
    /// bits of byte 0 and the encoded-PN byte count agree.
    #[test]
    fn varint_pn_roundtrip_at_boundaries() {
        for pn_len in 1u8..=4 {
            let (hdr, pn_off) = build_long_header(
                LongType::Handshake,
                QUIC_V1,
                &[1, 2, 3, 4],
                &[5, 6, 7, 8],
                &[],
                0x0a,
                pn_len,
                50,
            );
            let parsed = LongHeader::parse(&hdr).expect("parse");
            // The reserved bits at the top of byte 0 are zero; the
            // low 2 bits encode pn_len-1.
            assert_eq!(hdr[0] & 0x03, pn_len - 1);
            assert_eq!(parsed.pn_offset, pn_off);
            assert_eq!(parsed.dcid, &[1, 2, 3, 4][..]);
            assert_eq!(parsed.scid, &[5, 6, 7, 8][..]);
        }
    }

    // -------- Short header build / parse roundtrip ---------------------

    #[test]
    fn short_header_roundtrip() {
        let dcid = hex("f067a5502a4262b5");
        let (hdr, pn_off) = build_short_header(&dcid, false, false, 7, 2);
        // Spin=0, Reserved=00, KeyPhase=0, PN length-1=01 → first byte
        // 0x40 | 0x01 = 0x41.
        assert_eq!(hdr[0], 0x41);
        assert_eq!(pn_off, 9);
        let parsed = ShortHeader::parse(&hdr, dcid.len()).expect("parse");
        assert_eq!(parsed.dcid, dcid.as_slice());
        assert!(!parsed.key_phase);
        assert!(!parsed.spin);
        assert_eq!(parsed.pn_offset, 9);

        // Spin + KeyPhase set + 4-byte PN:
        let (hdr2, _) = build_short_header(&dcid, true, true, 0x0102_0304, 4);
        // 0x40 | 0x20 | 0x04 | 0x03 = 0x67.
        assert_eq!(hdr2[0], 0x67);
        let p2 = ShortHeader::parse(&hdr2, dcid.len()).expect("parse");
        assert!(p2.key_phase);
        assert!(p2.spin);
    }

    // -------- Header protection apply / remove roundtrip ---------------

    #[test]
    fn header_protection_long_apply_remove_roundtrip() {
        // §A.2 setup — build the unprotected header, apply HP using a
        // synthetic mask, then strip HP and confirm we recover the
        // original bytes plus the original PN length.
        let (mut hdr, pn_off) = build_long_header(
            LongType::Initial,
            QUIC_V1,
            &hex("8394c8f03e515708"),
            &[],
            &[],
            2,
            4,
            1182,
        );
        let orig = hdr.clone();
        // Need enough trailing bytes for the sample window though we
        // don't actually inspect it for this roundtrip test — pad with
        // zeros.
        hdr.resize(orig.len() + 16, 0);
        let mask = [0x43, 0x7b, 0x9a, 0xec, 0x36];
        apply_header_protection(&mut hdr, pn_off, 4, &mask, true);
        let pn_len = remove_header_protection(&mut hdr, pn_off, &mask, true).expect("ok");
        assert_eq!(pn_len, 4);
        // Header bytes back to their pre-HP values.
        assert_eq!(&hdr[..orig.len()], &orig[..]);
    }

    #[test]
    fn header_protection_short_apply_remove_roundtrip() {
        let dcid = hex("f067a5502a4262b5");
        let (mut hdr, pn_off) = build_short_header(&dcid, false, false, 0x010203, 3);
        let orig = hdr.clone();
        hdr.resize(orig.len() + 16, 0);
        let mask = [0x5a, 0x11, 0x22, 0x33, 0x44];
        apply_header_protection(&mut hdr, pn_off, 3, &mask, false);
        let pn_len = remove_header_protection(&mut hdr, pn_off, &mask, false).expect("ok");
        assert_eq!(pn_len, 3);
        assert_eq!(&hdr[..orig.len()], &orig[..]);
    }

    /// RFC 9001 §A.2 step-by-step header-protection encode: apply mask to
    /// the §A.2 *unprotected* header bytes and compare to the spec's
    /// protected header `c000000001088394c8f03e5157080000449e7b9aec34`.
    #[test]
    fn rfc9001_a2_apply_header_protection() {
        // §A.2 unprotected header.
        let mut wire = hex("c300000001088394c8f03e5157080000449e00000002");
        // Mask from §A.2.
        let mask = [0x43, 0x7b, 0x9a, 0xec, 0x36];
        apply_header_protection(&mut wire, 18, 4, &mask, true);
        // §A.2 protected header.
        assert_eq!(
            wire.as_slice(),
            hex("c000000001088394c8f03e5157080000449e7b9aec34").as_slice(),
        );
    }

    /// RFC 9001 §A.3 step-by-step: apply mask, compare to spec.
    #[test]
    fn rfc9001_a3_apply_header_protection() {
        let mut wire = hex("c1000000010008f067a5502a4262b50040750001");
        let mask = [0x2e, 0xc0, 0xd8, 0x35, 0x6a];
        apply_header_protection(&mut wire, 18, 2, &mask, true);
        // §A.3 protected header `cf000000010008f067a5502a4262b5004075c0d9`.
        assert_eq!(
            wire.as_slice(),
            hex("cf000000010008f067a5502a4262b5004075c0d9").as_slice(),
        );
    }

    /// RFC 9001 §A.5 — apply HP to the unprotected short header
    /// `4200bff4` with mask `aefefe7d03`, expect `4cfe4189`.
    #[test]
    fn rfc9001_a5_apply_header_protection() {
        let mut wire = hex("4200bff4");
        let mask = [0xae, 0xfe, 0xfe, 0x7d, 0x03];
        // pn_offset = 1 (empty DCID); pn_len = 3 (low 2 bits of 0x42 are
        // 0b10 → 3-byte PN, per RFC 9000 §17.3.1).
        apply_header_protection(&mut wire, 1, 3, &mask, false);
        assert_eq!(wire.as_slice(), hex("4cfe4189").as_slice());
    }

    // -------- Retry integrity tag --------------------------------------

    /// RFC 9001 §A.4 — build the §A.4 Retry packet and verify the
    /// computed integrity tag matches the spec's `04a265ba2eff4d829058\
    /// fb3f0f2496ba`.
    #[test]
    fn rfc9001_a4_retry_integrity_tag() {
        // §A.4: the Retry is constructed in response to the §A.2 Initial,
        // so ODCID is the §A.2 client DCID 0x8394c8f03e515708.
        let odcid = hex("8394c8f03e515708");

        // §A.4 wire packet:
        //   ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba
        //
        // Layout: first byte 0xff = 0x80|0x40|0x30|0x0f (Header Form +
        // Fixed Bit + Long Packet Type 3 + Unused=1111). Version 1.
        // DCID len 0 (no DCID in this Retry). SCID len 8 = f067a5502a4262b5.
        // Retry Token = "token" (ASCII = 0x746f6b656e). Then 16-byte tag.
        //
        // The fixed retry key+nonce don't depend on the Unused bits, but
        // they DO go into the AAD. We rebuild the same unauth bytes as
        // §A.4 — including the `0x0f` Unused bits — and then call the tag
        // function.
        let mut unauth = Vec::new();
        unauth.push(0xff); // Retry first byte, Unused = 0b1111.
        unauth.extend_from_slice(&QUIC_V1.to_be_bytes());
        unauth.push(0x00); // DCID len = 0.
        unauth.push(0x08); // SCID len = 8.
        unauth.extend_from_slice(&hex("f067a5502a4262b5"));
        unauth.extend_from_slice(b"token");

        let tag = retry_integrity_tag(&odcid, &unauth);
        assert_eq!(
            tag.as_slice(),
            hex("04a265ba2eff4d829058fb3f0f2496ba").as_slice()
        );

        // And the full assembled packet equals the §A.4 wire form.
        let mut full = unauth.clone();
        full.extend_from_slice(&tag);
        assert_eq!(
            full.as_slice(),
            hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba")
                .as_slice(),
        );
    }

    /// Test that the build_retry helper produces a tag matching
    /// retry_integrity_tag when the Unused bits are zero (the default the
    /// helper writes).
    #[test]
    fn build_retry_tag_matches_helper() {
        let odcid = hex("8394c8f03e515708");
        let scid = hex("f067a5502a4262b5");
        let pkt = build_retry(QUIC_V1, &[], &scid, b"token", &odcid);
        // The tag should validate against the same call shape used by
        // peers receiving the packet.
        let unauth_len = pkt.len() - 16;
        let tag_field: [u8; 16] = pkt[unauth_len..].try_into().expect("16");
        let computed = retry_integrity_tag(&odcid, &pkt[..unauth_len]);
        assert_eq!(tag_field, computed);
    }

    // -------- Version Negotiation --------------------------------------

    #[test]
    fn build_vn_layout() {
        let dcid = hex("0102030405");
        let scid = hex("aabbcc");
        let vns = [QUIC_V1, 0x0a0a_0a0a]; // a real version + a GREASE id
        let pkt = build_version_negotiation(&dcid, &scid, &vns);

        // First byte = 0xC0 (Header Form + Fixed-Bit position).
        assert_eq!(pkt[0], 0xc0);
        // Version field = 0 at bytes [1..5].
        assert_eq!(&pkt[1..5], &[0, 0, 0, 0]);
        // DCID len + DCID.
        assert_eq!(pkt[5], 5);
        assert_eq!(&pkt[6..11], dcid.as_slice());
        // SCID len + SCID.
        assert_eq!(pkt[11], 3);
        assert_eq!(&pkt[12..15], scid.as_slice());
        // Supported versions.
        assert_eq!(&pkt[15..19], &QUIC_V1.to_be_bytes());
        assert_eq!(&pkt[19..23], &0x0a0a_0a0au32.to_be_bytes());
        assert_eq!(pkt.len(), 23);

        // Parser identifies it (version == 0).
        let parsed = LongHeader::parse(&pkt).expect("parse");
        assert_eq!(parsed.version, 0);
        assert_eq!(parsed.dcid, dcid.as_slice());
        assert_eq!(parsed.scid, scid.as_slice());
    }

    // -------- Reject malformed long headers ----------------------------

    #[test]
    fn long_header_rejects_oversized_cid() {
        // dcid_len = 21 → invalid in v1.
        let mut buf = Vec::new();
        buf.push(0xc0); // Initial
        buf.extend_from_slice(&QUIC_V1.to_be_bytes());
        buf.push(21);
        buf.resize(buf.len() + 21, 0);
        // scid len:
        buf.push(0);
        assert!(LongHeader::parse(&buf).is_err());
    }

    #[test]
    fn long_header_rejects_missing_fixed_bit() {
        // First byte 0x80 lacks the Fixed Bit (0x40). Version non-zero so
        // we don't fall into the VN branch.
        let mut buf = Vec::new();
        buf.push(0x80);
        buf.extend_from_slice(&QUIC_V1.to_be_bytes());
        buf.push(0); // dcid len
        buf.push(0); // scid len
        assert!(LongHeader::parse(&buf).is_err());
    }

    // -------- Sanity: §A.2 end-to-end seal + HP ------------------------

    /// End-to-end: build §A.2 client Initial, seal with AEAD, derive HP
    /// mask from the spec sample, apply HP, compare the protected header
    /// + sample bytes to the §A.2 wire packet prefix.
    #[test]
    fn rfc9001_a2_end_to_end_protected_header_prefix() {
        let dcid = hex("8394c8f03e515708");
        let (hdr, pn_off) =
            build_long_header(LongType::Initial, QUIC_V1, &dcid, &[], &[], 2, 4, 1182);
        // Construct §A.2 plaintext (1162 bytes).
        let crypto_frame = hex(
            "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868\
             04fe3a47f06a2b69484c000004130113\
             02010000c000000010000e00000b6578\
             616d706c652e636f6dff01000100000a\
             00080006001d00170018001000070005\
             04616c706e000500050100000000\
             003300260024001d00209370b2c9caa47fba\
             baf4559fedba753de171fa71f50f1ce1\
             5d43e994ec74d748002b00030203040\
             00d0010000e040305030603020308040\
             8050806002d00020101001c00024001\
             003900320408ffffffffffffffff050480\
             00ffff07048000ffff080110010480\
             0075300901100f088394c8f03e515708\
             06048000ffff",
        );
        let mut payload = crypto_frame;
        payload.resize(1162, 0);

        let (cs, _) = derive_initial_secrets(&dcid);
        let dk = derive_dir_keys(AeadAlg::Aes128Gcm, &cs);
        let tag = crate::quic::crypto::aead_seal(&dk, 2, &hdr, &mut payload);

        // Now `hdr || payload || tag` is the full unprotected-header wire
        // packet. Concatenate and apply HP.
        let mut wire = hdr.clone();
        wire.extend_from_slice(&payload);
        wire.extend_from_slice(&tag);

        let sample: [u8; 16] = wire[pn_off + 4..pn_off + 4 + 16].try_into().expect("16");
        let mask = dk.hp.mask(&sample).expect("mask");
        apply_header_protection(&mut wire, pn_off, 4, &mask, true);

        // Header prefix should match the §A.2 protected header bytes:
        //   c000000001088394c8f03e5157080000449e7b9aec34
        let expected_header = hex("c000000001088394c8f03e5157080000449e7b9aec34");
        assert_eq!(&wire[..expected_header.len()], expected_header.as_slice());
    }
}
