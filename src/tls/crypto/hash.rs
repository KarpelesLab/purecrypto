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
}

impl Transcript {
    /// A new, empty transcript with no hash chosen yet.
    pub(crate) fn new() -> Self {
        Transcript {
            alg: None,
            buf: Vec::new(),
        }
    }

    /// Fixes the hash function once the cipher suite is negotiated.
    pub(crate) fn set_alg(&mut self, alg: HashAlg) {
        self.alg = Some(alg);
    }

    /// Appends one handshake message's wire bytes (header included).
    pub(crate) fn update(&mut self, message: &[u8]) {
        self.buf.extend_from_slice(message);
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
