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
//! format            u8         // TICKET12_FORMAT
//! cipher_suite      u16
//! master_secret     48 bytes
//! creation_time     u64        // unix seconds (server clock at issuance)
//! ems_used          u8         // 1 if EMS was negotiated, 0 otherwise (RFC 7627 §5.3)
//! alpn_len          u8         // 0 if no ALPN negotiated
//! alpn_bytes        alpn_len bytes
//! client_auth       u8         // 1 if the issuing handshake authenticated the client
//! leaf_len          u16        // present iff client_auth == 1
//! leaf              leaf_len bytes (client leaf certificate, DER)
//! ```
//!
//! The AEAD is bound to [`TICKET12_AAD`]: the TLS 1.3 engine seals its
//! tickets under a different string, so a ticket from one engine can never
//! authenticate under the other even when both are keyed from the same
//! `Config::ticket_key`.
//!
//! Tickets have a server-configured lifetime; on decrypt we reject any whose
//! `(now - creation_time) > lifetime` (server-side, with the server's
//! current clock). This keeps the format simple — the client never needs to
//! understand the plaintext layout.
//!
//! The `ems_used` byte (RFC 7627 §5.3) records whether the originating
//! session derived its master secret via Extended Master Secret; resumption
//! MUST keep the same status (EMS↔EMS or legacy↔legacy). A cross-EMS
//! resumption attempt is rejected with `IllegalParameter`.

use crate::cipher::{Aes256, Gcm};
use crate::rng::RngCore;
use alloc::vec::Vec;

/// The fixed-size header of the encrypted ticket: 12-byte GCM nonce.
const NONCE_LEN: usize = 12;
/// AES-256-GCM authentication tag length.
const TAG_LEN: usize = 16;
/// Associated data every TLS 1.2 ticket is sealed under (see the module
/// docs; the TLS 1.3 counterpart is `server::TICKET13_AAD`).
pub(crate) const TICKET12_AAD: &[u8] = b"purecrypto tls12 ticket v1";
/// Leading byte of the ticket plaintext: format/version tag.
const TICKET12_FORMAT: u8 = 0x12;
/// Minimum plaintext: 1 (format) + 2 (suite) + 48 (master) + 8 (creation)
/// + 1 (ems_used) + 1 (alpn_len) + 1 (client_auth).
const MIN_PLAIN_LEN: usize = 1 + 2 + 48 + 8 + 1 + 1 + 1;

/// The TLS 1.2 ticket payload — what the server learns when it decrypts a
/// returning client's ticket. `Debug` redacts the master secret.
#[derive(Clone)]
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
    /// RFC 7627 §5.3 — whether the originating session derived its master
    /// secret via Extended Master Secret. Resumption MUST keep the same
    /// status (EMS↔EMS or legacy↔legacy); the engine compares this bit
    /// against the resumed handshake's EMS negotiation result.
    pub(crate) ems_used: bool,
    /// The ALPN protocol negotiated on the originating connection. Empty if
    /// none; we don't currently use this for the abbreviated handshake (the
    /// client re-offers ALPN in its CH and the server re-picks), but we keep
    /// it around for visibility and future cross-checks.
    pub(crate) alpn: Option<Vec<u8>>,
    /// The client leaf certificate (DER) the issuing handshake
    /// authenticated, when it did. A resumed handshake performs no client
    /// authentication of its own, so this is the only record of who the
    /// peer is: an mTLS-required listener refuses to resume without it, and
    /// it is restored into `peer_certificates()` on resumption.
    pub(crate) client_leaf: Option<Vec<u8>>,
}

impl core::fmt::Debug for Ticket12Plaintext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Ticket12Plaintext")
            .field("cipher_suite", &format_args!("{:#06x}", self.cipher_suite))
            .field("master_secret", &format_args!("<48 bytes, redacted>"))
            .field("creation_time", &self.creation_time)
            .field("ems_used", &self.ems_used)
            .field("alpn", &self.alpn)
            .field("client_authenticated", &self.client_leaf.is_some())
            .finish_non_exhaustive()
    }
}

// The decoded ticket payload carries the 48-byte master secret; scrub it
// when the payload is dropped so the secret does not linger on the heap /
// stack frame (same overwrite + `black_box` pattern as `X25519PrivateKey`).
impl Drop for Ticket12Plaintext {
    fn drop(&mut self) {
        super::wipe(&mut self.master_secret);
    }
}

impl Ticket12Plaintext {
    /// Serialises the plaintext layout described in the module docs.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let alpn = self.alpn.as_deref().unwrap_or(&[]);
        let leaf = self
            .client_leaf
            .as_deref()
            .filter(|l| l.len() <= u16::MAX as usize);
        let mut out =
            Vec::with_capacity(MIN_PLAIN_LEN + alpn.len() + 2 + leaf.map_or(0, |l| l.len()));
        out.push(TICKET12_FORMAT);
        out.extend_from_slice(&self.cipher_suite.to_be_bytes());
        out.extend_from_slice(&self.master_secret);
        out.extend_from_slice(&self.creation_time.to_be_bytes());
        out.push(if self.ems_used { 1 } else { 0 });
        out.push(alpn.len() as u8);
        out.extend_from_slice(alpn);
        match leaf {
            Some(l) => {
                out.push(1);
                out.extend_from_slice(&(l.len() as u16).to_be_bytes());
                out.extend_from_slice(l);
            }
            None => out.push(0),
        }
        out
    }

    /// Deserialises a plaintext buffer produced by `encode`. Returns `None`
    /// on any structural inconsistency (wrong format tag, length mismatch,
    /// oversized alpn, trailing bytes).
    pub(crate) fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < MIN_PLAIN_LEN {
            return None;
        }
        let mut c = crate::tls::codec::ReadCursor::new(buf);
        if c.u8().ok()? != TICKET12_FORMAT {
            return None;
        }
        let cipher_suite = c.u16().ok()?;
        let mut master_secret = [0u8; 48];
        master_secret.copy_from_slice(c.take(48).ok()?);
        let creation_time = c.u64().ok()?;
        let ems_used = match c.u8().ok()? {
            0 => false,
            1 => true,
            // Reject other values; ems_used is a strict bool on the wire.
            _ => return None,
        };
        let alpn = c.vec_u8().ok()?;
        let alpn = if alpn.is_empty() {
            None
        } else {
            Some(alpn.to_vec())
        };
        let client_leaf = match c.u8().ok()? {
            0 => None,
            1 => Some(c.vec_u16().ok()?.to_vec()),
            _ => return None,
        };
        c.expect_empty().ok()?;
        Some(Ticket12Plaintext {
            cipher_suite,
            master_secret,
            creation_time,
            ems_used,
            alpn,
            client_leaf,
        })
    }
}

/// Encrypts `plain` under `key` with a fresh random nonce, bound to
/// [`TICKET12_AAD`]. The on-wire layout is `nonce(12) ‖ ciphertext ‖ tag(16)`.
///
/// Random 96-bit nonces bound the key's lifetime: the caller must rotate
/// `key` well before 2^32 tickets have been sealed under it (NIST SP
/// 800-38D §8.3).
pub(crate) fn seal_ticket<R: RngCore>(rng: &mut R, key: &[u8; 32], plain: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let gcm = Gcm::new(Aes256::new(key));
    let mut buf = plain.to_vec();
    let tag = gcm.encrypt(&nonce, TICKET12_AAD, &mut buf);
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
    gcm.decrypt(nonce, TICKET12_AAD, &mut buf, tag).ok()?;
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
            ems_used: true,
            alpn: None,
            client_leaf: None,
        };
        let buf = p.encode();
        let dec = Ticket12Plaintext::decode(&buf).unwrap();
        assert_eq!(dec.cipher_suite, p.cipher_suite);
        assert_eq!(dec.master_secret, p.master_secret);
        assert_eq!(dec.creation_time, p.creation_time);
        assert!(dec.ems_used);
        assert!(dec.alpn.is_none());
    }

    #[test]
    fn plaintext_roundtrip_with_alpn() {
        let p = Ticket12Plaintext {
            cipher_suite: 0xCCA9,
            master_secret: [0x3c; 48],
            creation_time: 1_700_000_000,
            ems_used: false,
            alpn: Some(b"h2".to_vec()),
            client_leaf: Some(alloc::vec![0x30u8; 40]),
        };
        let buf = p.encode();
        let dec = Ticket12Plaintext::decode(&buf).unwrap();
        assert_eq!(dec.cipher_suite, p.cipher_suite);
        assert!(!dec.ems_used);
        assert_eq!(dec.alpn.as_deref(), Some(b"h2".as_ref()));
        assert_eq!(dec.client_leaf.as_deref(), Some([0x30u8; 40].as_ref()));
    }

    #[test]
    fn plaintext_rejects_truncated() {
        assert!(Ticket12Plaintext::decode(&[]).is_none());
        assert!(Ticket12Plaintext::decode(&[0u8; 58]).is_none());
    }

    #[test]
    fn plaintext_rejects_bad_ems_flag() {
        // Hand-craft a buffer where the ems_used byte is neither 0 nor 1.
        let p = Ticket12Plaintext {
            cipher_suite: 0xC02F,
            master_secret: [0x11; 48],
            creation_time: 1,
            ems_used: false,
            alpn: None,
            client_leaf: None,
        };
        let mut buf = p.encode();
        buf[59] = 2; // illegal ems_used value
        assert!(Ticket12Plaintext::decode(&buf).is_none());
    }

    /// TLS-CORE-4 — the format tag, the client_auth flag and the exact
    /// length are all enforced; a ticket from a TLS 1.3 server (different
    /// AAD) never opens.
    #[test]
    fn decode_rejects_bad_format_flag_and_trailing_bytes() {
        let p = Ticket12Plaintext {
            cipher_suite: 0xC02F,
            master_secret: [0x11; 48],
            creation_time: 1,
            ems_used: false,
            alpn: None,
            client_leaf: None,
        };
        let good = p.encode();
        assert!(Ticket12Plaintext::decode(&good).is_some());
        let mut bad = good.clone();
        bad[0] = 0x13; // the TLS 1.3 tag
        assert!(Ticket12Plaintext::decode(&bad).is_none());
        let mut bad = good.clone();
        *bad.last_mut().unwrap() = 2; // client_auth must be 0/1
        assert!(Ticket12Plaintext::decode(&bad).is_none());
        let mut bad = good.clone();
        bad.push(0); // trailing byte
        assert!(Ticket12Plaintext::decode(&bad).is_none());
    }

    #[test]
    fn open_ticket_rejects_tls13_aad() {
        use crate::cipher::{Aes256, Gcm};
        let key = [0x42u8; 32];
        let nonce = [7u8; 12];
        let gcm = Gcm::new(Aes256::new(&key));
        let mut buf = b"payload".to_vec();
        let tag = gcm.encrypt(&nonce, super::super::server::TICKET13_AAD, &mut buf);
        let mut ticket = nonce.to_vec();
        ticket.extend_from_slice(&buf);
        ticket.extend_from_slice(&tag);
        assert!(open_ticket(&key, &ticket).is_none());
        // And the pre-v1 empty AAD.
        let mut buf = b"payload".to_vec();
        let tag = gcm.encrypt(&nonce, &[], &mut buf);
        let mut ticket = nonce.to_vec();
        ticket.extend_from_slice(&buf);
        ticket.extend_from_slice(&tag);
        assert!(open_ticket(&key, &ticket).is_none());
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
