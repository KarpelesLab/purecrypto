//! The handshake transcript hash (RFC 8446 §4.4.1).
//!
//! `Transcript-Hash(M1, ..., Mn) = Hash(M1 || ... || Mn)` over the handshake
//! messages exactly as they appear on the wire. The hash function is fixed by
//! the negotiated cipher suite, which is unknown while the first `ClientHello`
//! is processed, so the raw bytes are buffered and the hash is taken on demand
//! once [`set_alg`](Transcript::set_alg) selects the hash.
//!
//! Buffering (rather than streaming into a live hasher) also makes the
//! HelloRetryRequest transcript rewrite — replacing `ClientHello1` with a
//! synthetic `message_hash` message ([`replace_with_message_hash`]) — a simple
//! in-place edit.
//!
//! [`replace_with_message_hash`]: Transcript::replace_with_message_hash

use super::schedule::{HashAlg, Secret};
use alloc::vec::Vec;

/// Accumulates handshake-message bytes and yields `Transcript-Hash` on demand.
pub(crate) struct Transcript {
    alg: Option<HashAlg>,
    buf: Vec<u8>,
    /// Set once the handshake completes: further [`update`](Self::update)
    /// calls are ignored. See [`seal`](Self::seal).
    sealed: bool,
}

impl Transcript {
    /// A new, empty transcript with no hash chosen yet.
    pub(crate) fn new() -> Self {
        Transcript {
            alg: None,
            buf: Vec::new(),
            sealed: false,
        }
    }

    /// Closes the transcript once the handshake is complete: the accumulated
    /// bytes are released and every subsequent [`update`](Self::update) is a
    /// no-op.
    ///
    /// Post-handshake handshake messages — `KeyUpdate` (RFC 8446 §4.6.3) and
    /// `NewSessionTicket` (§4.6.1) — are not inputs to any transcript hash
    /// this implementation computes: the last one needed is
    /// `Hash(CH..client Finished)` for `resumption_master_secret`, taken at
    /// the `Connected` transition. Continuing to buffer them would let a peer
    /// grow our heap for the life of the connection (five bytes per inbound
    /// `KeyUpdate`, never reclaimed) with no ceiling and no backpressure.
    ///
    /// A sealed transcript's [`current_hash`](Self::current_hash) is
    /// meaningless; the state machines only seal at the point where no
    /// further transcript hash is needed.
    pub(crate) fn seal(&mut self) {
        self.sealed = true;
        self.buf = Vec::new();
    }

    /// The number of handshake bytes currently buffered.
    #[cfg(test)]
    pub(crate) fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// Fixes the hash function once the cipher suite is negotiated.
    pub(crate) fn set_alg(&mut self, alg: HashAlg) {
        self.alg = Some(alg);
    }

    /// Appends one handshake message's wire bytes (header included). A no-op
    /// once the transcript has been [`seal`](Self::seal)ed.
    pub(crate) fn update(&mut self, message: &[u8]) {
        if self.sealed {
            return;
        }
        self.buf.extend_from_slice(message);
    }

    /// Returns the buffered handshake-message bytes (in wire order). Used by
    /// the TLS 1.2 `CertificateVerify` path, which signs the raw transcript
    /// (RFC 5246 §7.4.8) — the signer hashes the bytes internally.
    pub(crate) fn buffered_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// `Transcript-Hash` of everything accumulated so far.
    ///
    /// # Panics
    /// Panics if the hash has not been selected with [`set_alg`].
    pub(crate) fn current_hash(&self) -> Secret {
        let alg = self
            .alg
            .expect("transcript hash used before suite negotiated");
        alg.hash(&self.buf)
    }

    /// `Transcript-Hash` over the accumulated bytes followed by `extra`,
    /// without altering the transcript state. Used by ECH (draft-ietf-tls-
    /// esni-22 §7) to compute `Hash(inner_CH || zero-tail SH)` for the
    /// `accept_confirmation` signal, where feeding the zero-tail SH into
    /// the real transcript would clash with the patched SH that
    /// `emit_handshake` adds moments later.
    ///
    /// # Panics
    /// Panics if the hash has not been selected with [`set_alg`].
    #[cfg(feature = "ech")]
    pub(crate) fn hash_with_appended(&self, extra: &[u8]) -> Secret {
        let alg = self
            .alg
            .expect("transcript hash used before suite negotiated");
        let mut tmp = Vec::with_capacity(self.buf.len() + extra.len());
        tmp.extend_from_slice(&self.buf);
        tmp.extend_from_slice(extra);
        alg.hash(&tmp)
    }

    /// Replaces the accumulated handshake bytes with `new_buf`. Used by
    /// ECH (draft-ietf-tls-esni-22 §6.1) on the client when an
    /// in-progress handshake confirms ECH was accepted: the live
    /// transcript was tracking the OUTER ClientHello, and we need to
    /// swap it for the INNER ClientHello before the rest of the
    /// handshake messages get appended. The hash algorithm selection
    /// (set via [`set_alg`]) is preserved.
    #[cfg(feature = "ech")]
    pub(crate) fn replace_buf(&mut self, new_buf: Vec<u8>) {
        debug_assert!(!self.sealed, "transcript rewritten after being sealed");
        self.buf = new_buf;
    }

    /// Rewrites the transcript for HelloRetryRequest: the buffered
    /// `ClientHello1` is replaced by a synthetic `message_hash` handshake
    /// message `[254, 0, 0, Hash.length] || Hash(ClientHello1)` (RFC 8446
    /// §4.4.1).
    ///
    /// # Panics
    /// Panics if the hash has not been selected with [`set_alg`].
    pub(crate) fn replace_with_message_hash(&mut self) {
        let alg = self
            .alg
            .expect("transcript hash used before suite negotiated");
        let h = alg.hash(&self.buf);
        let mut synthetic = Vec::with_capacity(4 + h.as_slice().len());
        synthetic.push(254); // message_hash
        synthetic.extend_from_slice(&[0, 0]);
        synthetic.push(h.as_slice().len() as u8);
        synthetic.extend_from_slice(h.as_slice());
        self.buf = synthetic;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Digest, Sha256};

    #[test]
    fn hash_matches_concatenation() {
        let mut t = Transcript::new();
        t.set_alg(HashAlg::Sha256);
        t.update(b"hello ");
        t.update(b"world");
        assert_eq!(
            t.current_hash().as_slice(),
            Sha256::digest(b"hello world").as_ref()
        );
    }

    /// Sealing the transcript releases the buffer and makes further updates
    /// no-ops, so post-handshake `KeyUpdate` / `NewSessionTicket` traffic
    /// cannot grow the connection's heap without bound.
    #[test]
    fn seal_stops_growth_and_releases_the_buffer() {
        let mut t = Transcript::new();
        t.set_alg(HashAlg::Sha256);
        t.update(b"client hello");
        assert_eq!(t.buffered_len(), 12);
        t.seal();
        assert_eq!(t.buffered_len(), 0);
        // A flood of post-handshake KeyUpdates adds nothing.
        for _ in 0..10_000 {
            t.update(&[24, 0, 0, 1, 1]);
        }
        assert_eq!(t.buffered_len(), 0);
    }

    #[test]
    fn message_hash_rewrite() {
        let mut t = Transcript::new();
        t.set_alg(HashAlg::Sha256);
        t.update(b"client hello 1");
        let inner = Sha256::digest(b"client hello 1");
        t.replace_with_message_hash();

        // The rewritten buffer's hash equals Hash(254||00 00 20||Hash(CH1)).
        let mut expected = alloc::vec![254u8, 0, 0, 32];
        expected.extend_from_slice(inner.as_ref());
        assert_eq!(
            t.current_hash().as_slice(),
            Sha256::digest(&expected).as_ref()
        );
    }
}
