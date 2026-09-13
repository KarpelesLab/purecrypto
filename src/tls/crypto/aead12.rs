//! TLS 1.2 record protection with explicit-nonce AEAD (RFC 5246 §6.2.3.3,
//! RFC 5288, RFC 7905).
//!
//! TLS 1.2 AEAD cipher suites split the 12-byte AEAD nonce into a 4-byte
//! implicit `salt` (derived from the `key_block` and never sent on the wire)
//! and an 8-byte explicit nonce that the writer chooses per record. Both
//! RFC 5288 (AES-GCM) and RFC 7905 (ChaCha20-Poly1305) prescribe the same
//! `salt || explicit_nonce` framing — RFC 7905 §2 just adds that the
//! explicit_nonce SHOULD be the record sequence number, which is exactly
//! what we emit here.
//!
//! Wire fragment (per record):
//!
//! ```text
//! explicit_nonce (8) || ciphertext || tag (16)
//! ```
//!
//! Additional authenticated data (13 bytes, RFC 5246 §6.2.3.3):
//!
//! ```text
//! seq_num(8) || content_type(1) || version(2) || plaintext_length(2)
//! ```
//!
//! TLS 1.2 does not have a `TLSInnerPlaintext`: the record header's
//! `content_type` is the real content type, so `decrypt` simply hands it
//! back to the caller alongside the recovered plaintext.

use super::aead::Aead;
use super::suite::AeadAlg;
use crate::tls::{ContentType, Error};
use alloc::vec::Vec;

/// AES-GCM's safe per-key record bound, RFC 8446 §5.5 / RFC 9001 §6.6:
/// 2^24.5 ≈ 23 726 566 records. TLS 1.2 has no `KeyUpdate`, so a connection
/// that reaches this must be torn down rather than rekeyed.
const MAX_RECORDS_GCM: u64 = 23_726_566;

/// ChaCha20-Poly1305 has no comparable confidentiality/integrity limit (RFC
/// 8446 §5.5 imposes none); the only ceiling is the 64-bit sequence number
/// itself, which also bounds the unique explicit nonce space.
const MAX_RECORDS_CHACHA: u64 = u64::MAX;

/// The per-key record cap for `alg`.
fn max_records_for(alg: AeadAlg) -> u64 {
    match alg {
        AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => MAX_RECORDS_GCM,
        AeadAlg::ChaCha20Poly1305 => MAX_RECORDS_CHACHA,
    }
}

/// One direction's TLS 1.2 record protection: an AEAD keyed from the
/// `key_block` slice for this direction, the 4-byte implicit `salt`, and a
/// monotonic 64-bit record sequence counter.
///
/// The same struct serves both the client→server and server→client directions;
/// the caller constructs two instances from the `key_block` (`prf::key_block`)
/// it derived for the handshake.
#[allow(dead_code)]
pub(crate) struct RecordCrypter12 {
    aead: Aead,
    /// Per-key record cap for the negotiated AEAD (see `max_records_for`).
    max_records: u64,
    /// 4-byte implicit nonce ("salt") drawn from the `key_block`.
    salt: [u8; 4],
    /// Record sequence number, monotonically incremented per record. In TLS
    /// 1.2 the seq_num is implicit (not on the wire) but appears in the AAD;
    /// it is also what we use as the 8-byte explicit nonce per RFC 7905 §2.
    seq: u64,
}

impl RecordCrypter12 {
    /// Builds a `RecordCrypter12` from a raw AEAD key and the 4-byte implicit
    /// salt. `alg` selects the AEAD; the key length must be 16 for AES-128
    /// or 32 for AES-256 / ChaCha20.
    #[allow(dead_code)]
    pub(crate) fn new(alg: AeadAlg, key: &[u8], salt: [u8; 4]) -> Self {
        RecordCrypter12 {
            aead: Aead::from_key(alg, key),
            max_records: max_records_for(alg),
            salt,
            seq: 0,
        }
    }

    /// The current sequence counter (next record's `seq_num`). Test-only
    /// accessor for asserting the on-wire explicit nonce matches.
    #[cfg(test)]
    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }

    /// Builds the 12-byte AEAD nonce: `salt(4) || explicit_nonce(8)`.
    fn aead_nonce(&self, explicit_nonce: &[u8; 8]) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.salt);
        nonce[4..].copy_from_slice(explicit_nonce);
        nonce
    }

    /// Builds the 13-byte AAD: `seq_num(8) || content_type(1) || version(2)
    /// || plaintext_length(2)` per RFC 5246 §6.2.3.3.
    fn aad(seq: u64, content_type: ContentType, plaintext_len: u16) -> [u8; 13] {
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&seq.to_be_bytes());
        aad[8] = content_type.as_u8();
        aad[9] = 0x03;
        aad[10] = 0x03;
        aad[11..13].copy_from_slice(&plaintext_len.to_be_bytes());
        aad
    }

    /// Builds the 13-byte AAD for DTLS 1.2 (RFC 6347 §4.1.2.1):
    /// `epoch(2) ‖ seq(6) ‖ content_type(1) ‖ version(2) ‖ plaintext_length(2)`.
    /// The `seq_num` slot is interpreted as `epoch ‖ seq` and version is
    /// `0xfefd`.
    #[allow(dead_code)]
    fn aad_dtls(seq_combined: u64, content_type: ContentType, plaintext_len: u16) -> [u8; 13] {
        let mut aad = [0u8; 13];
        aad[..8].copy_from_slice(&seq_combined.to_be_bytes());
        aad[8] = content_type.as_u8();
        aad[9] = 0xfe;
        aad[10] = 0xfd;
        aad[11..13].copy_from_slice(&plaintext_len.to_be_bytes());
        aad
    }

    /// Encrypts one DTLS 1.2 record's payload with a caller-supplied 64-bit
    /// combined `epoch:16 || seq:48` (RFC 6347 §4.1). Returns the on-wire
    /// fragment `explicit_nonce(8) || ciphertext || tag(16)`. Does NOT touch
    /// the internal sequence counter — DTLS sequence numbers are managed by
    /// the caller because retransmits and out-of-order delivery break a
    /// monotonic counter.
    #[allow(dead_code)]
    pub(crate) fn encrypt_dtls(
        &self,
        seq_combined: u64,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if payload.len() > (1usize << 14) {
            return Err(Error::RecordOverflow);
        }
        let explicit_nonce = seq_combined.to_be_bytes();
        let nonce = self.aead_nonce(&explicit_nonce);
        let aad = Self::aad_dtls(seq_combined, content_type, payload.len() as u16);
        let mut buf = payload.to_vec();
        let tag = self.aead.encrypt(&nonce, &aad, &mut buf);
        let mut out = Vec::with_capacity(8 + buf.len() + 16);
        out.extend_from_slice(&explicit_nonce);
        out.extend_from_slice(&buf);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Decrypts one DTLS 1.2 record's fragment. `seq_combined` is
    /// `epoch:16 || seq:48` and `content_type` comes from the DTLS record
    /// header. Returns the plaintext on success.
    #[allow(dead_code)]
    pub(crate) fn decrypt_dtls(
        &self,
        seq_combined: u64,
        content_type: ContentType,
        fragment: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if fragment.len() < 8 + 16 {
            return Err(Error::Decode);
        }
        let mut explicit_nonce = [0u8; 8];
        explicit_nonce.copy_from_slice(&fragment[..8]);
        let body = &fragment[8..];
        let (ct_bytes, tag_bytes) = body.split_at(body.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_bytes);
        let plaintext_len = ct_bytes.len();
        if plaintext_len > (1usize << 14) {
            return Err(Error::RecordOverflow);
        }
        let aad = Self::aad_dtls(seq_combined, content_type, plaintext_len as u16);
        let nonce = self.aead_nonce(&explicit_nonce);
        let mut buf = ct_bytes.to_vec();
        if !self.aead.decrypt(&nonce, &aad, &mut buf, &tag) {
            return Err(Error::BadRecordMac);
        }
        Ok(buf)
    }

    /// Encrypts one record's payload, returning the on-wire fragment:
    ///
    /// ```text
    /// explicit_nonce(8) || ciphertext || tag(16)
    /// ```
    ///
    /// The caller is responsible for the surrounding 5-byte record header.
    /// `content_type` is the true content type — TLS 1.2 records carry it
    /// in the cleartext header (there is no `TLSInnerPlaintext` byte).
    ///
    /// Returns `Err(TooManyRecords)` once the AEAD's per-key record cap is
    /// hit (a closing alert is still allowed through) and
    /// `Err(RecordOverflow)` if the payload is larger than the 2^14 TLS
    /// plaintext fragment limit (RFC 5246 §6.2.1).
    #[allow(dead_code)]
    pub(crate) fn encrypt(
        &mut self,
        content_type: ContentType,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if payload.len() > (1usize << 14) {
            return Err(Error::RecordOverflow);
        }
        // The cap never blocks a closing alert: TLS 1.2 cannot rekey, so the
        // only thing left to do at the limit is shut the connection down —
        // and `close_notify` is exactly how that is signalled (a peer that
        // never sees it must treat the stream as truncated). Two bytes of
        // alert cost nothing against the AEAD's safety margin.
        let closing_alert = content_type == ContentType::Alert && payload.len() == 2;
        if self.seq >= self.max_records && !closing_alert {
            return Err(Error::TooManyRecords);
        }

        // explicit_nonce = seq.to_be_bytes(). RFC 7905 §2 explicitly endorses
        // this; for GCM (RFC 5288) it is the simplest unique-per-key nonce.
        let explicit_nonce = self.seq.to_be_bytes();
        let nonce = self.aead_nonce(&explicit_nonce);
        let aad = Self::aad(self.seq, content_type, payload.len() as u16);

        let mut buf = payload.to_vec();
        let tag = self.aead.encrypt(&nonce, &aad, &mut buf);

        let mut out = Vec::with_capacity(8 + buf.len() + 16);
        out.extend_from_slice(&explicit_nonce);
        out.extend_from_slice(&buf);
        out.extend_from_slice(&tag);

        self.seq += 1;
        Ok(out)
    }

    /// Decrypts one TLS 1.2 record's fragment.
    ///
    /// `record_header` is the 5-byte `TLSCiphertext` header (used to recover
    /// the content type and version for the AAD). `fragment` is the bytes
    /// after the header — `explicit_nonce(8) || ciphertext || tag(16)`.
    ///
    /// Returns the content type recorded in the header (TLS 1.2 has no
    /// inner content type) and the decrypted plaintext.
    #[allow(dead_code)]
    pub(crate) fn decrypt(
        &mut self,
        record_header: &[u8; 5],
        fragment: &[u8],
    ) -> Result<(ContentType, Vec<u8>), Error> {
        // Need at least 8 bytes of explicit nonce + 16 bytes of tag.
        if fragment.len() < 8 + 16 {
            return Err(Error::Decode);
        }
        // Same exception as on the write side: the peer's closing alert must
        // still be readable at the cap.
        let closing_alert = ContentType::from_u8(record_header[0]) == ContentType::Alert
            && fragment.len() == 8 + 2 + 16;
        if self.seq >= self.max_records && !closing_alert {
            return Err(Error::TooManyRecords);
        }

        let mut explicit_nonce = [0u8; 8];
        explicit_nonce.copy_from_slice(&fragment[..8]);
        let body = &fragment[8..];
        let (ct_bytes, tag_bytes) = body.split_at(body.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_bytes);

        let plaintext_len = ct_bytes.len();
        if plaintext_len > (1usize << 14) {
            return Err(Error::RecordOverflow);
        }

        let content_type = ContentType::from_u8(record_header[0]);
        let aad = Self::aad(self.seq, content_type, plaintext_len as u16);
        let nonce = self.aead_nonce(&explicit_nonce);

        let mut buf = ct_bytes.to_vec();
        if !self.aead.decrypt(&nonce, &aad, &mut buf, &tag) {
            return Err(Error::BadRecordMac);
        }

        self.seq += 1;
        Ok((content_type, buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a pair of `RecordCrypter12` instances for one direction's worth
    /// of round-trip testing (encrypter writes, decrypter reads, using the
    /// same key/salt). Sequence counters move in lockstep.
    fn pair(alg: AeadAlg, key: &[u8], salt: [u8; 4]) -> (RecordCrypter12, RecordCrypter12) {
        (
            RecordCrypter12::new(alg, key, salt),
            RecordCrypter12::new(alg, key, salt),
        )
    }

    /// Round-trip a 100-byte payload under each supported AEAD.
    #[test]
    fn round_trip_application_data() {
        let payload = (0..100u8).collect::<Vec<u8>>();
        let salt = [0xa1, 0xa2, 0xa3, 0xa4];

        for (alg, key_len) in [
            (AeadAlg::Aes128Gcm, 16usize),
            (AeadAlg::Aes256Gcm, 32),
            (AeadAlg::ChaCha20Poly1305, 32),
        ] {
            let key: Vec<u8> = (0..key_len as u8).collect();
            let (mut enc, mut dec) = pair(alg, &key, salt);

            let wire = enc.encrypt(ContentType::ApplicationData, &payload).unwrap();
            // wire layout = explicit_nonce(8) || ciphertext(100) || tag(16)
            assert_eq!(wire.len(), 8 + payload.len() + 16);

            let mut header = [0u8; 5];
            header[0] = ContentType::ApplicationData.as_u8();
            header[1] = 0x03;
            header[2] = 0x03;
            let frag_len = wire.len() as u16;
            header[3..5].copy_from_slice(&frag_len.to_be_bytes());

            let (ct, plain) = dec.decrypt(&header, &wire).unwrap();
            assert_eq!(ct, ContentType::ApplicationData);
            assert_eq!(plain, payload);
        }
    }

    /// Tampering with the explicit nonce, ciphertext, or tag must cause
    /// decryption to fail with `BadRecordMac`.
    #[test]
    fn tampering_is_rejected() {
        let payload = alloc::vec![0x42u8; 100];
        let salt = [0xa1, 0xa2, 0xa3, 0xa4];
        let key = alloc::vec![0x33u8; 16];

        // Tamper with the explicit_nonce (first 8 bytes of the fragment).
        {
            let (mut enc, mut dec) = pair(AeadAlg::Aes128Gcm, &key, salt);
            let mut wire = enc.encrypt(ContentType::ApplicationData, &payload).unwrap();
            wire[0] ^= 0x01;
            let mut header = [0u8; 5];
            header[0] = ContentType::ApplicationData.as_u8();
            header[1] = 0x03;
            header[2] = 0x03;
            let frag_len = wire.len() as u16;
            header[3..5].copy_from_slice(&frag_len.to_be_bytes());
            assert!(matches!(
                dec.decrypt(&header, &wire),
                Err(Error::BadRecordMac)
            ));
        }

        // Tamper with the ciphertext body.
        {
            let (mut enc, mut dec) = pair(AeadAlg::Aes128Gcm, &key, salt);
            let mut wire = enc.encrypt(ContentType::ApplicationData, &payload).unwrap();
            wire[20] ^= 0x80;
            let mut header = [0u8; 5];
            header[0] = ContentType::ApplicationData.as_u8();
            header[1] = 0x03;
            header[2] = 0x03;
            let frag_len = wire.len() as u16;
            header[3..5].copy_from_slice(&frag_len.to_be_bytes());
            assert!(matches!(
                dec.decrypt(&header, &wire),
                Err(Error::BadRecordMac)
            ));
        }

        // Tamper with the tag (last byte).
        {
            let (mut enc, mut dec) = pair(AeadAlg::Aes128Gcm, &key, salt);
            let mut wire = enc.encrypt(ContentType::ApplicationData, &payload).unwrap();
            let last = wire.len() - 1;
            wire[last] ^= 0x01;
            let mut header = [0u8; 5];
            header[0] = ContentType::ApplicationData.as_u8();
            header[1] = 0x03;
            header[2] = 0x03;
            let frag_len = wire.len() as u16;
            header[3..5].copy_from_slice(&frag_len.to_be_bytes());
            assert!(matches!(
                dec.decrypt(&header, &wire),
                Err(Error::BadRecordMac)
            ));
        }
    }

    /// The 8-byte explicit nonce written into each record equals the
    /// big-endian sequence counter the writer just held.
    #[test]
    fn explicit_nonce_matches_seq_counter() {
        let payload = alloc::vec![0u8; 4];
        let salt = [0; 4];
        let key = alloc::vec![0u8; 16];
        let mut enc = RecordCrypter12::new(AeadAlg::Aes128Gcm, &key, salt);

        // Emit a few records and check each explicit nonce.
        for expected_seq in 0u64..5 {
            assert_eq!(enc.seq(), expected_seq);
            let wire = enc.encrypt(ContentType::ApplicationData, &payload).unwrap();
            let mut got = [0u8; 8];
            got.copy_from_slice(&wire[..8]);
            assert_eq!(got, expected_seq.to_be_bytes());
        }
        assert_eq!(enc.seq(), 5);
    }

    /// Test hook: fast-forward the sequence counter to exercise the per-key
    /// cap without protecting tens of millions of records first.
    impl RecordCrypter12 {
        fn set_seq_for_test(&mut self, seq: u64) {
            self.seq = seq;
        }
    }

    /// The per-key record cap is the AEAD's own bound: 2^24.5 for AES-GCM,
    /// effectively unbounded for ChaCha20-Poly1305 (RFC 8446 §5.5). A closing
    /// alert is always allowed past the cap so the connection can be shut
    /// down cleanly — TLS 1.2 cannot rekey.
    #[test]
    fn per_aead_record_caps_and_the_closing_alert_exception() {
        let salt = [0u8; 4];
        let key = alloc::vec![0x11u8; 32];

        let mut gcm = RecordCrypter12::new(AeadAlg::Aes256Gcm, &key, salt);
        gcm.set_seq_for_test(MAX_RECORDS_GCM - 1);
        assert!(gcm.encrypt(ContentType::ApplicationData, &[0u8; 8]).is_ok());
        assert!(matches!(
            gcm.encrypt(ContentType::ApplicationData, &[0u8; 8]),
            Err(Error::TooManyRecords)
        ));
        // close_notify (level warning, description 0) still goes out.
        let alert = gcm.encrypt(ContentType::Alert, &[1u8, 0u8]).unwrap();
        assert_eq!(alert.len(), 8 + 2 + 16);

        // ChaCha20-Poly1305 has no such limit: the old shared 2^23 cap does
        // not apply to it.
        let mut chacha = RecordCrypter12::new(AeadAlg::ChaCha20Poly1305, &key, salt);
        chacha.set_seq_for_test((1 << 23) + 1);
        assert!(
            chacha
                .encrypt(ContentType::ApplicationData, &[0u8; 8])
                .is_ok()
        );
        chacha.set_seq_for_test(MAX_RECORDS_GCM + 1);
        assert!(
            chacha
                .encrypt(ContentType::ApplicationData, &[0u8; 8])
                .is_ok()
        );
    }

    /// Decrypting a fragment shorter than `explicit_nonce + tag` (8 + 16
    /// bytes) returns `Decode`, not a panic.
    #[test]
    fn short_fragment_rejected() {
        let salt = [0; 4];
        let key = alloc::vec![0u8; 16];
        let mut dec = RecordCrypter12::new(AeadAlg::Aes128Gcm, &key, salt);
        let header = [ContentType::ApplicationData.as_u8(), 0x03, 0x03, 0x00, 0x10];
        let short = [0u8; 16];
        assert!(matches!(dec.decrypt(&header, &short), Err(Error::Decode)));
    }
}
