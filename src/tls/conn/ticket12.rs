//! RFC 5077 session-ticket helpers for the TLS 1.2 path.
//!
//! A ticket is a stateless, AEAD-encrypted blob: the server holds a single
//! AES-256-GCM `ticket_key`, encrypts a small plaintext under a random nonce,
//! and ships the resulting `nonce ‖ ciphertext ‖ tag` to the client. On a
//! later connection the client returns the ticket bytes in a `session_ticket`
//! extension; the server decrypts, recovers the master secret + suite, and
//! resumes via the abbreviated handshake of RFC 5077 §3.4.
//!
//! Wire layout of the ticket plaintext (this module owns the format — the
//! ticket itself is opaque to the peer):
//!
//! ```text
//! cipher_suite      u16
//! master_secret     48 bytes
//! creation_time     u64        // unix seconds (server clock at issuance)
//! alpn_len          u8         // 0 if no ALPN negotiated
//! alpn_bytes        alpn_len bytes
//! ```
//!
//! Tickets have a server-configured lifetime; on decrypt we reject any whose
//! `(now - creation_time) > lifetime` (server-side, with the server's
//! current clock). This keeps the format simple — the client never needs to
//! understand the plaintext layout.

use crate::cipher::{Aes256, Gcm};
use crate::rng::RngCore;
use alloc::vec::Vec;

/// The fixed-size header of the encrypted ticket: 12-byte GCM nonce.
const NONCE_LEN: usize = 12;
/// AES-256-GCM authentication tag length.
const TAG_LEN: usize = 16;
/// Minimum plaintext: 2 (suite) + 48 (master) + 8 (creation) + 1 (alpn_len).
const MIN_PLAIN_LEN: usize = 2 + 48 + 8 + 1;

/// The TLS 1.2 ticket payload — what the server learns when it decrypts a
/// returning client's ticket.
#[derive(Clone, Debug)]
pub(crate) struct Ticket12Plaintext {
    /// The cipher suite the ticket was issued for. The resumed handshake MUST
    /// pick the same suite (RFC 5077 §3.4 / RFC 5246 §F.1.4).
    pub(crate) cipher_suite: u16,
    /// The 48-byte master secret that the resumed handshake's PRF will
    /// expand into a fresh key block.
    pub(crate) master_secret: [u8; 48],
    /// Unix-seconds wall-clock time at issuance (server clock). Compared
    /// against the server's `now` and the configured lifetime to detect
    /// expired tickets.
    pub(crate) creation_time: u64,
    /// The ALPN protocol negotiated on the originating connection. Empty if
    /// none; we don't currently use this for the abbreviated handshake (the
    /// client re-offers ALPN in its CH and the server re-picks), but we keep
    /// it around for visibility and future cross-checks.
    pub(crate) alpn: Option<Vec<u8>>,
}

impl Ticket12Plaintext {
    /// Serialises the plaintext layout described in the module docs.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let alpn = self.alpn.as_deref().unwrap_or(&[]);
        let mut out = Vec::with_capacity(MIN_PLAIN_LEN + alpn.len());
        out.extend_from_slice(&self.cipher_suite.to_be_bytes());
        out.extend_from_slice(&self.master_secret);
        out.extend_from_slice(&self.creation_time.to_be_bytes());
        out.push(alpn.len() as u8);
        out.extend_from_slice(alpn);
        out
    }

    /// Deserialises a plaintext buffer produced by `encode`. Returns `None`
    /// on any structural inconsistency (length mismatch, oversized alpn).
    pub(crate) fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < MIN_PLAIN_LEN {
            return None;
        }
        let cipher_suite = u16::from_be_bytes([buf[0], buf[1]]);
        let mut master_secret = [0u8; 48];
        master_secret.copy_from_slice(&buf[2..50]);
        let creation_time = u64::from_be_bytes([
            buf[50], buf[51], buf[52], buf[53], buf[54], buf[55], buf[56], buf[57],
        ]);
        let alpn_len = buf[58] as usize;
        if buf.len() != MIN_PLAIN_LEN + alpn_len {
            return None;
        }
        let alpn = if alpn_len == 0 {
            None
        } else {
            Some(buf[59..59 + alpn_len].to_vec())
        };
        Some(Ticket12Plaintext {
            cipher_suite,
            master_secret,
            creation_time,
            alpn,
        })
    }
}

/// Encrypts `plain` under `key` with a fresh random nonce. The on-wire layout
/// is `nonce(12) ‖ ciphertext ‖ tag(16)`.
pub(crate) fn seal_ticket<R: RngCore>(rng: &mut R, key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let gcm = Gcm::new(Aes256::new(key));
    let mut buf = plain.to_vec();
    let tag = gcm.encrypt(&nonce, &[], &mut buf);
    let mut ticket = Vec::with_capacity(NONCE_LEN + buf.len() + TAG_LEN);
    ticket.extend_from_slice(&nonce);
    ticket.extend_from_slice(&buf);
    ticket.extend_from_slice(&tag);
    ticket
}

/// Decrypts a ticket sealed by `seal_ticket`. Returns `None` on any
/// structural / AEAD failure — callers fall back to a fresh full handshake.
pub(crate) fn open_ticket(key: &[u8; 32], ticket: &[u8]) -> Option<Vec<u8>> {
    if ticket.len() < NONCE_LEN + TAG_LEN {
        return None;
    }
    let nonce: &[u8; NONCE_LEN] = ticket[..NONCE_LEN].try_into().ok()?;
    let body = &ticket[NONCE_LEN..];
    let (ct, tag_slice) = body.split_at(body.len() - TAG_LEN);
    let tag: &[u8; TAG_LEN] = tag_slice.try_into().ok()?;
    let mut buf = ct.to_vec();
    let gcm = Gcm::new(Aes256::new(key));
    gcm.decrypt(nonce, &[], &mut buf, tag).ok()?;
    Some(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    #[test]
    fn plaintext_roundtrip_no_alpn() {
        let p = Ticket12Plaintext {
            cipher_suite: 0xC02F,
            master_secret: [0xa5; 48],
            creation_time: 0x1122334455667788,
            alpn: None,
        };
        let buf = p.encode();
        let dec = Ticket12Plaintext::decode(&buf).unwrap();
        assert_eq!(dec.cipher_suite, p.cipher_suite);
        assert_eq!(dec.master_secret, p.master_secret);
        assert_eq!(dec.creation_time, p.creation_time);
        assert!(dec.alpn.is_none());
    }

    #[test]
    fn plaintext_roundtrip_with_alpn() {
        let p = Ticket12Plaintext {
            cipher_suite: 0xCCA9,
            master_secret: [0x3c; 48],
            creation_time: 1_700_000_000,
            alpn: Some(b"h2".to_vec()),
        };
        let buf = p.encode();
        let dec = Ticket12Plaintext::decode(&buf).unwrap();
        assert_eq!(dec.cipher_suite, p.cipher_suite);
        assert_eq!(dec.alpn.as_deref(), Some(b"h2".as_ref()));
    }

    #[test]
    fn plaintext_rejects_truncated() {
        assert!(Ticket12Plaintext::decode(&[]).is_none());
        assert!(Ticket12Plaintext::decode(&[0u8; 58]).is_none());
    }

    #[test]
    fn seal_open_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"ticket12", b"nonce", &[]);
        let key = [0x42u8; 32];
        let plain = b"the quick brown fox jumps over the lazy dog";
        let ticket = seal_ticket(&mut rng, &key, plain);
        assert!(ticket.len() > NONCE_LEN + TAG_LEN);
        let recovered = open_ticket(&key, &ticket).unwrap();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn open_ticket_rejects_tampering() {
        let mut rng = HmacDrbg::<Sha256>::new(b"ticket12-tamper", b"nonce", &[]);
        let key = [0x42u8; 32];
        let plain = b"payload";
        let mut ticket = seal_ticket(&mut rng, &key, plain);
        // Flip a byte inside the ciphertext.
        let i = ticket.len() / 2;
        ticket[i] ^= 1;
        assert!(open_ticket(&key, &ticket).is_none());
    }

    #[test]
    fn open_ticket_rejects_short() {
        let key = [0u8; 32];
        assert!(open_ticket(&key, &[]).is_none());
        assert!(open_ticket(&key, &[0u8; 12]).is_none());
    }
}
