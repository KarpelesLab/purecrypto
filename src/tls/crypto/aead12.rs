//! TLS 1.2 record protection with AEAD cipher suites (RFC 5246 §6.2.3.3,
//! RFC 5288, RFC 7905).
//!
//! TLS 1.2 leaves the AEAD nonce construction to each cipher-suite RFC, and
//! the two families we support disagree:
//!
//! - **AES-GCM (RFC 5288 §3)**: the `key_block` yields a 4-byte implicit
//!   `salt` per direction (`fixed_iv_length = 4`) and every record carries an
//!   8-byte explicit nonce chosen by the writer (`record_iv_length = 8`). The
//!   AEAD nonce is `salt(4) || explicit_nonce(8)`; we use the record sequence
//!   number as the explicit nonce. Wire fragment:
//!
//!   ```text
//!   explicit_nonce (8) || ciphertext || tag (16)
//!   ```
//!
//! - **ChaCha20-Poly1305 (RFC 7905 §2)**: the `key_block` yields a 12-byte
//!   write IV per direction (`fixed_iv_length = 12`) and nothing is sent on
//!   the wire (`record_iv_length = 0`). The AEAD nonce is the write IV XORed
//!   with the 64-bit record sequence number, big-endian and left-padded with
//!   four zero bytes — the same construction TLS 1.3 later adopted for every
//!   suite. Wire fragment:
//!
//!   ```text
//!   ciphertext || tag (16)
//!   ```
//!
//! Both families use the same 13-byte additional data (RFC 5246 §6.2.3.3):
//!
//! ```text
//! seq_num(8) || content_type(1) || version(2) || plaintext_length(2)
//! ```
//!
//! In DTLS 1.2 the `seq_num` slot is `epoch(2) || sequence_number(6)` (RFC
//! 6347 §4.1.2.1), for the nonce as well as the AAD.
//!
//! [`RecordCrypter12::derive_pair`] expands the `key_block` (RFC 5246 §6.3)
//! with the right layout for the suite — `client_write_key ||
//! server_write_key || client_write_IV || server_write_IV`, the IVs 4 bytes
//! each for GCM and 12 for ChaCha — so the engines never spell the layout out.
//!
//! TLS 1.2 does not have a `TLSInnerPlaintext`: the record header's
//! `content_type` is the real content type, so `decrypt` simply hands it
//! back to the caller alongside the recovered plaintext.

use super::aead::Aead;
use super::prf;
use super::schedule::HashAlg;
use super::suite::AeadAlg;
use crate::tls::{ContentType, Error};
use alloc::vec::Vec;

/// AES-GCM's safe per-key record bound, RFC 8446 §5.5 / RFC 9001 §6.6:
/// 2^24.5 ≈ 23 726 566 records. TLS 1.2 has no `KeyUpdate`, so a connection
/// that reaches this must be torn down rather than rekeyed.
const MAX_RECORDS_GCM: u64 = 23_726_566;

/// ChaCha20-Poly1305 has no comparable confidentiality/integrity limit (RFC
/// 8446 §5.5 imposes none); the only ceiling is the 64-bit sequence number
/// itself, which is also what keeps the nonce unique per key.
const MAX_RECORDS_CHACHA: u64 = u64::MAX;

/// The per-key record cap for `alg`.
fn max_records_for(alg: AeadAlg) -> u64 {
    match alg {
        AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => MAX_RECORDS_GCM,
        AeadAlg::ChaCha20Poly1305 => MAX_RECORDS_CHACHA,
    }
}

/// `SecurityParameters.fixed_iv_length`: the per-direction IV bytes the
/// `key_block` yields — 4 (the GCM salt, RFC 5288 §3) or 12 (the ChaCha20
/// write IV, RFC 7905 §2).
pub(crate) fn fixed_iv_len(alg: AeadAlg) -> usize {
    match alg {
        AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => 4,
        AeadAlg::ChaCha20Poly1305 => 12,
    }
}

/// `SecurityParameters.record_iv_length`: the explicit nonce bytes at the
/// front of every record fragment — 8 for GCM, none for ChaCha20-Poly1305.
#[allow(dead_code)] // the CT harness hooks and tests; the engines size fragments via the scheme
pub(crate) fn record_iv_len(alg: AeadAlg) -> usize {
    match alg {
        AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => 8,
        AeadAlg::ChaCha20Poly1305 => 0,
    }
}

/// The AEAD tag length; both families use 16-byte tags.
const TAG_LEN: usize = 16;

/// How a suite turns the record sequence number into the 12-byte AEAD nonce.
enum NonceScheme {
    /// RFC 5288: `salt(4) || explicit_nonce(8)`, the explicit nonce on the
    /// wire ahead of the ciphertext.
    Explicit { salt: [u8; 4] },
    /// RFC 7905: `write_iv(12) XOR (0x00^4 || seq(8))`, nothing on the wire.
    Xor { iv: [u8; 12] },
}

/// One direction's TLS 1.2 record protection: an AEAD keyed from the
/// `key_block` slice for this direction, that direction's write IV, and a
/// monotonic 64-bit record sequence counter.
///
/// The same struct serves both the client→server and server→client directions;
/// [`RecordCrypter12::derive_pair`] builds the two instances from the
/// handshake's master secret and randoms.
#[allow(dead_code)]
pub(crate) struct RecordCrypter12 {
    aead: Aead,
    /// Per-key record cap for the negotiated AEAD (see `max_records_for`).
    max_records: u64,
    /// The suite's nonce construction and the write IV it draws on.
    nonce: NonceScheme,
    /// Record sequence number, monotonically incremented per record. In TLS
    /// 1.2 the seq_num is implicit (not on the wire) but appears in the AAD
    /// and — as the explicit nonce for GCM, XORed into the write IV for
    /// ChaCha20 — in the nonce.
    seq: u64,
}

impl RecordCrypter12 {
    /// Builds a `RecordCrypter12` from a raw AEAD key and this direction's
    /// write IV from the `key_block`. `alg` selects the AEAD; the key length
    /// must be 16 for AES-128 or 32 for AES-256 / ChaCha20, and `write_iv`
    /// must be exactly [`fixed_iv_len`]`(alg)` bytes (4 for GCM, 12 for
    /// ChaCha20-Poly1305).
    #[allow(dead_code)]
    pub(crate) fn new(alg: AeadAlg, key: &[u8], write_iv: &[u8]) -> Self {
        assert_eq!(
            write_iv.len(),
            fixed_iv_len(alg),
            "TLS 1.2 write IV length does not match the suite's fixed_iv_length"
        );
        let nonce = match alg {
            AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => {
                let mut salt = [0u8; 4];
                salt.copy_from_slice(write_iv);
                NonceScheme::Explicit { salt }
            }
            AeadAlg::ChaCha20Poly1305 => {
                let mut iv = [0u8; 12];
                iv.copy_from_slice(write_iv);
                NonceScheme::Xor { iv }
            }
        };
        RecordCrypter12 {
            aead: Aead::from_key(alg, key),
            max_records: max_records_for(alg),
            nonce,
            seq: 0,
        }
    }

    /// Expands the RFC 5246 §6.3 `key_block` for a suite and returns the
    /// `(client_write, server_write)` crypters. The block is laid out as
    /// `client_write_key || server_write_key || client_write_IV ||
    /// server_write_IV` with `key_len`-byte keys and [`fixed_iv_len`]-byte
    /// IVs (RFC 5288 §3 for GCM, RFC 7905 §2 for ChaCha20-Poly1305); the
    /// expansion buffer is wiped before returning.
    ///
    /// Note the PRF seed order is `server_random || client_random`, the
    /// opposite of the master secret's — `prf::key_block` takes the randoms
    /// in that order.
    #[allow(dead_code)]
    pub(crate) fn derive_pair(
        hash: HashAlg,
        alg: AeadAlg,
        key_len: usize,
        master: &[u8; 48],
        server_random: &[u8; 32],
        client_random: &[u8; 32],
    ) -> (Self, Self) {
        let iv_len = fixed_iv_len(alg);
        let mut kb = alloc::vec![0u8; 2 * key_len + 2 * iv_len];
        prf::key_block(hash, master, server_random, client_random, &mut kb);
        let (c_key, rest) = kb.split_at(key_len);
        let (s_key, rest) = rest.split_at(key_len);
        let (c_iv, s_iv) = rest.split_at(iv_len);
        let client = Self::new(alg, c_key, c_iv);
        let server = Self::new(alg, s_key, s_iv);
        // The crypters own copies of the keys and IVs now; scrub the
        // derivation buffer.
        crate::tls::conn::wipe(&mut kb);
        (client, server)
    }

    /// The current sequence counter (next record's `seq_num`). Test-only
    /// accessor for asserting the on-wire explicit nonce matches.
    #[cfg(test)]
    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }

    /// The bytes of explicit nonce at the front of each record fragment for
    /// this suite (8 for GCM, 0 for ChaCha20-Poly1305).
    fn explicit_len(&self) -> usize {
        match self.nonce {
            NonceScheme::Explicit { .. } => 8,
            NonceScheme::Xor { .. } => 0,
        }
    }

    /// Builds the 12-byte AEAD nonce for the record numbered `seq` (the
    /// 64-bit TLS sequence number, or `epoch || seq` for DTLS).
    ///
    /// For GCM `explicit` is the 8-byte explicit nonce — the record's own on
    /// the read side, `seq` on the write side — and the nonce is `salt ||
    /// explicit`. For ChaCha20-Poly1305 `explicit` is ignored and the nonce
    /// is `write_iv XOR (0^4 || seq)` (RFC 7905 §2).
    fn aead_nonce(&self, seq: u64, explicit: &[u8]) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        match &self.nonce {
            NonceScheme::Explicit { salt } => {
                nonce[..4].copy_from_slice(salt);
                nonce[4..].copy_from_slice(explicit);
            }
            NonceScheme::Xor { iv } => {
                nonce.copy_from_slice(iv);
                for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
                    *n ^= s;
                }
            }
        }
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

    /// Seals `payload` as the record numbered `seq` under `aad`, returning
    /// the fragment: the explicit nonce (GCM only) followed by the
    /// ciphertext and tag.
    fn seal(&self, seq: u64, aad: &[u8; 13], payload: &[u8]) -> Vec<u8> {
        let explicit = seq.to_be_bytes();
        let explicit = &explicit[..self.explicit_len()];
        let nonce = self.aead_nonce(seq, explicit);
        let mut out = Vec::with_capacity(explicit.len() + payload.len() + TAG_LEN);
        out.extend_from_slice(explicit);
        out.extend_from_slice(payload);
        let tag = self.aead.encrypt(&nonce, aad, &mut out[explicit.len()..]);
        out.extend_from_slice(&tag);
        out
    }

    /// Opens the record numbered `seq`. `fragment` is the bytes after the
    /// record header; `aad_for(plaintext_len)` supplies the AAD once the
    /// ciphertext length is known. Fails with `Decode` on a fragment too
    /// short to hold the explicit nonce and tag, `RecordOverflow` past the
    /// 2^14 plaintext limit, and `BadRecordMac` on an authentication failure.
    fn open(
        &self,
        seq: u64,
        fragment: &[u8],
        aad_for: impl FnOnce(u16) -> [u8; 13],
    ) -> Result<Vec<u8>, Error> {
        let explicit_len = self.explicit_len();
        if fragment.len() < explicit_len + TAG_LEN {
            return Err(Error::Decode);
        }
        let (explicit, body) = fragment.split_at(explicit_len);
        let (ct_bytes, tag_bytes) = body.split_at(body.len() - TAG_LEN);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(tag_bytes);
        let plaintext_len = ct_bytes.len();
        if plaintext_len > (1usize << 14) {
            return Err(Error::RecordOverflow);
        }
        let aad = aad_for(plaintext_len as u16);
        let nonce = self.aead_nonce(seq, explicit);
        let mut buf = ct_bytes.to_vec();
        if !self.aead.decrypt(&nonce, &aad, &mut buf, &tag) {
            return Err(Error::BadRecordMac);
        }
        Ok(buf)
    }

    /// Encrypts one DTLS 1.2 record's payload with a caller-supplied 64-bit
    /// combined `epoch:16 || seq:48` (RFC 6347 §4.1). Returns the on-wire
    /// fragment — `explicit_nonce(8) || ciphertext || tag(16)` for GCM,
    /// `ciphertext || tag(16)` for ChaCha20-Poly1305. Does NOT touch the
    /// internal sequence counter — DTLS sequence numbers are managed by the
    /// caller because retransmits and out-of-order delivery break a monotonic
    /// counter.
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
        let aad = Self::aad_dtls(seq_combined, content_type, payload.len() as u16);
        Ok(self.seal(seq_combined, &aad, payload))
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
        self.open(seq_combined, fragment, |len| {
            Self::aad_dtls(seq_combined, content_type, len)
        })
    }

    /// Encrypts one record's payload, returning the on-wire fragment:
    ///
    /// ```text
    /// explicit_nonce(8) || ciphertext || tag(16)    (AES-GCM)
    /// ciphertext || tag(16)                         (ChaCha20-Poly1305)
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

        let aad = Self::aad(self.seq, content_type, payload.len() as u16);
        let out = self.seal(self.seq, &aad, payload);
        self.seq += 1;
        Ok(out)
    }

    /// Decrypts one TLS 1.2 record's fragment.
    ///
    /// `record_header` is the 5-byte `TLSCiphertext` header (used to recover
    /// the content type and version for the AAD). `fragment` is the bytes
    /// after the header — `explicit_nonce(8) || ciphertext || tag(16)` for
    /// GCM, `ciphertext || tag(16)` for ChaCha20-Poly1305.
    ///
    /// Returns the content type recorded in the header (TLS 1.2 has no
    /// inner content type) and the decrypted plaintext.
    #[allow(dead_code)]
    pub(crate) fn decrypt(
        &mut self,
        record_header: &[u8; 5],
        fragment: &[u8],
    ) -> Result<(ContentType, Vec<u8>), Error> {
        let content_type = ContentType::from_u8(record_header[0]);
        // Same exception as on the write side: the peer's closing alert must
        // still be readable at the cap.
        let closing_alert = content_type == ContentType::Alert
            && fragment.len() == self.explicit_len() + 2 + TAG_LEN;
        if self.seq >= self.max_records && !closing_alert {
            return Err(Error::TooManyRecords);
        }

        let seq = self.seq;
        let buf = self.open(seq, fragment, |len| Self::aad(seq, content_type, len))?;
        self.seq += 1;
        Ok((content_type, buf))
    }
}

impl Drop for RecordCrypter12 {
    /// Wipes the write IV on teardown: the ChaCha20 IV is 12 bytes of key
    /// material, and even the GCM salt is a `key_block` secret. The AEAD's
    /// expanded key schedule is owned by `crate::cipher` and wiped there.
    fn drop(&mut self) {
        match &mut self.nonce {
            NonceScheme::Explicit { salt } => crate::tls::conn::wipe(salt),
            NonceScheme::Xor { iv } => crate::tls::conn::wipe(iv),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a pair of `RecordCrypter12` instances for one direction's worth
    /// of round-trip testing (encrypter writes, decrypter reads, using the
    /// same key/IV). Sequence counters move in lockstep.
    fn pair(alg: AeadAlg, key: &[u8], iv: &[u8]) -> (RecordCrypter12, RecordCrypter12) {
        (
            RecordCrypter12::new(alg, key, iv),
            RecordCrypter12::new(alg, key, iv),
        )
    }

    /// A 5-byte TLS 1.2 record header for `fragment`.
    fn header(content_type: ContentType, fragment: &[u8]) -> [u8; 5] {
        let len = (fragment.len() as u16).to_be_bytes();
        [content_type.as_u8(), 0x03, 0x03, len[0], len[1]]
    }

    /// The per-direction IV the key block yields for `alg`, as test filler.
    fn iv_for(alg: AeadAlg) -> Vec<u8> {
        (0xa1..).take(fixed_iv_len(alg)).collect()
    }

    /// Round-trip a 100-byte payload under each supported AEAD; the wire
    /// fragment carries an 8-byte explicit nonce for GCM and none for
    /// ChaCha20-Poly1305.
    #[test]
    fn round_trip_application_data() {
        let payload = (0..100u8).collect::<Vec<u8>>();

        for (alg, key_len) in [
            (AeadAlg::Aes128Gcm, 16usize),
            (AeadAlg::Aes256Gcm, 32),
            (AeadAlg::ChaCha20Poly1305, 32),
        ] {
            let key: Vec<u8> = (0..key_len as u8).collect();
            let (mut enc, mut dec) = pair(alg, &key, &iv_for(alg));

            let wire = enc.encrypt(ContentType::ApplicationData, &payload).unwrap();
            assert_eq!(wire.len(), record_iv_len(alg) + payload.len() + 16);

            let (ct, plain) = dec
                .decrypt(&header(ContentType::ApplicationData, &wire), &wire)
                .unwrap();
            assert_eq!(ct, ContentType::ApplicationData);
            assert_eq!(plain, payload);
        }
    }

    /// Tampering with the explicit nonce, ciphertext, or tag must cause
    /// decryption to fail with `BadRecordMac`, under both nonce schemes.
    #[test]
    fn tampering_is_rejected() {
        let payload = alloc::vec![0x42u8; 100];

        for alg in [AeadAlg::Aes128Gcm, AeadAlg::ChaCha20Poly1305] {
            let key = alloc::vec![0x33u8; if alg == AeadAlg::Aes128Gcm { 16 } else { 32 }];
            let iv = iv_for(alg);
            // The first fragment byte: the explicit nonce for GCM, the
            // ciphertext for ChaCha20. Then a body byte, then the tag.
            for flip in [0usize, 20, 8 + 100 + 15] {
                let (mut enc, mut dec) = pair(alg, &key, &iv);
                let mut wire = enc.encrypt(ContentType::ApplicationData, &payload).unwrap();
                let flip = flip.min(wire.len() - 1);
                wire[flip] ^= 0x01;
                assert!(matches!(
                    dec.decrypt(&header(ContentType::ApplicationData, &wire), &wire),
                    Err(Error::BadRecordMac)
                ));
            }
        }
    }

    /// The 8-byte explicit nonce written into each GCM record equals the
    /// big-endian sequence counter the writer just held.
    #[test]
    fn explicit_nonce_matches_seq_counter() {
        let payload = alloc::vec![0u8; 4];
        let key = alloc::vec![0u8; 16];
        let mut enc = RecordCrypter12::new(AeadAlg::Aes128Gcm, &key, &[0; 4]);

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

    /// RFC 7905 §2: the ChaCha20-Poly1305 nonce is the 12-byte write IV
    /// XORed with the sequence number left-padded to 12 bytes, and the
    /// fragment carries no explicit nonce. Pinned against the raw AEAD with
    /// the nonce built by hand, for the TLS counter and a DTLS `epoch ||
    /// seq`.
    #[test]
    fn chacha_nonce_is_write_iv_xor_padded_seq() {
        let key: Vec<u8> = (0..32u8).collect();
        let iv = [
            0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4,
        ];
        let payload = b"RFC 7905 nonce construction";
        let aead = Aead::from_key(AeadAlg::ChaCha20Poly1305, &key);

        // TLS: records 0, 1, 2 under one crypter.
        let mut enc = RecordCrypter12::new(AeadAlg::ChaCha20Poly1305, &key, &iv);
        for seq in 0u64..3 {
            let wire = enc.encrypt(ContentType::ApplicationData, payload).unwrap();
            assert_eq!(wire.len(), payload.len() + 16, "no explicit nonce");

            let mut nonce = iv;
            for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
                *n ^= s;
            }
            let aad = RecordCrypter12::aad(seq, ContentType::ApplicationData, payload.len() as u16);
            let mut expect = payload.to_vec();
            let tag = aead.encrypt(&nonce, &aad, &mut expect);
            expect.extend_from_slice(&tag);
            assert_eq!(wire, expect, "record {seq}");
        }

        // DTLS: epoch 1, sequence number 0x2a.
        let seq = (1u64 << 48) | 0x2a;
        let wire = enc
            .encrypt_dtls(seq, ContentType::ApplicationData, payload)
            .unwrap();
        let mut nonce = iv;
        for (n, s) in nonce[4..].iter_mut().zip(seq.to_be_bytes()) {
            *n ^= s;
        }
        // (0^4 || 00 01 00 00 00 00 00 2a) XOR iv
        assert_eq!(
            nonce,
            [
                0x0f,
                0x1e,
                0x2d,
                0x3c,
                0x4b,
                0x5a ^ 0x01,
                0x69,
                0x78,
                0x87,
                0x96,
                0xa5,
                0xb4 ^ 0x2a
            ]
        );
        let aad =
            RecordCrypter12::aad_dtls(seq, ContentType::ApplicationData, payload.len() as u16);
        let mut expect = payload.to_vec();
        let tag = aead.encrypt(&nonce, &aad, &mut expect);
        expect.extend_from_slice(&tag);
        assert_eq!(wire, expect);
    }

    /// Decodes a hex string.
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Records captured from an OpenSSL 3.6.4 `s_client` ↔ `s_server`
    /// TLS 1.2 handshake under `ECDHE-RSA-CHACHA20-POLY1305` (0xCCA8), with
    /// the master secret from `-keylogfile`: the encrypted Finished (record
    /// 0) and `close_notify` (record 1) of each direction, opened with keys
    /// derived from the master secret. A key-block layout or nonce
    /// construction that differs from RFC 7905 fails the tag check.
    #[test]
    fn openssl_chacha20_poly1305_capture() {
        let client_random = hex("05685d32ae4656d9bc57b316381384366ddc5ba7ff9d569bff061df32727a108");
        let server_random = hex("b8df4e027cebe47b226cb0208d56a1764d879befe31815ac8d0bdb3771f475d5");
        let master = hex(
            "e8e28391119fef9c3476f3d04aaa22f0dba4b71040a9349161b4e8da0c6595b2\
             2d532f486fafcc8e8628b6db7b77fc1b",
        );
        let (mut client, mut server) = RecordCrypter12::derive_pair(
            HashAlg::Sha256,
            AeadAlg::ChaCha20Poly1305,
            32,
            master.as_slice().try_into().unwrap(),
            server_random.as_slice().try_into().unwrap(),
            client_random.as_slice().try_into().unwrap(),
        );
        // Client → server: Finished, then close_notify — under the client
        // write keys, which are the server's read side.
        let records = [
            (
                "1603030020",
                "c4c795d95c7a73b608fe701473382d656f1c201ea771c6c9fe67bbdd8b799cd9",
                "1400000c45ee8e8639b1877661c2d3f7",
            ),
            ("1503030012", "a7ebff71130d181113f922d47b0990c8b8fc", "0100"),
        ];
        for (hdr, frag, plain) in records {
            let hdr: [u8; 5] = hex(hdr).try_into().unwrap();
            let (ct, got) = client.decrypt(&hdr, &hex(frag)).expect("authentic");
            assert_eq!(ct, ContentType::from_u8(hdr[0]));
            assert_eq!(got, hex(plain));
        }
        // Server → client: Finished, then close_notify.
        let records = [
            (
                "1603030020",
                "5cb0cc145e86ea758ad680665c5ffc44d4dbc21cd59d41b80f4c936e99a22aec",
                "1400000c5c39bdf06ed0f7846ba5366c",
            ),
            ("1503030012", "a29863441bc4748db492dd2a48d13f1c22df", "0100"),
        ];
        for (hdr, frag, plain) in records {
            let hdr: [u8; 5] = hex(hdr).try_into().unwrap();
            let (ct, got) = server.decrypt(&hdr, &hex(frag)).expect("authentic");
            assert_eq!(ct, ContentType::from_u8(hdr[0]));
            assert_eq!(got, hex(plain));
        }

        // And the same keys seal what OpenSSL sent, byte for byte: the
        // construction is deterministic in the sequence number.
        let (mut client, mut server) = RecordCrypter12::derive_pair(
            HashAlg::Sha256,
            AeadAlg::ChaCha20Poly1305,
            32,
            master.as_slice().try_into().unwrap(),
            server_random.as_slice().try_into().unwrap(),
            client_random.as_slice().try_into().unwrap(),
        );
        assert_eq!(
            client
                .encrypt(
                    ContentType::Handshake,
                    &hex("1400000c45ee8e8639b1877661c2d3f7")
                )
                .unwrap(),
            hex("c4c795d95c7a73b608fe701473382d656f1c201ea771c6c9fe67bbdd8b799cd9")
        );
        assert_eq!(
            client.encrypt(ContentType::Alert, &hex("0100")).unwrap(),
            hex("a7ebff71130d181113f922d47b0990c8b8fc")
        );
        assert_eq!(
            server
                .encrypt(
                    ContentType::Handshake,
                    &hex("1400000c5c39bdf06ed0f7846ba5366c")
                )
                .unwrap(),
            hex("5cb0cc145e86ea758ad680665c5ffc44d4dbc21cd59d41b80f4c936e99a22aec")
        );
        assert_eq!(
            server.encrypt(ContentType::Alert, &hex("0100")).unwrap(),
            hex("a29863441bc4748db492dd2a48d13f1c22df")
        );
    }

    /// `derive_pair` lays the key block out per suite: keys first, then the
    /// IVs — 4 bytes each for GCM, 12 for ChaCha20 — and the two directions
    /// interoperate.
    #[test]
    fn derive_pair_layout_per_suite() {
        let master = [0x5au8; 48];
        let sr = [0x01u8; 32];
        let cr = [0x02u8; 32];
        for (hash, alg, key_len) in [
            (HashAlg::Sha256, AeadAlg::Aes128Gcm, 16usize),
            (HashAlg::Sha384, AeadAlg::Aes256Gcm, 32),
            (HashAlg::Sha256, AeadAlg::ChaCha20Poly1305, 32),
        ] {
            let iv_len = fixed_iv_len(alg);
            let mut kb = alloc::vec![0u8; 2 * key_len + 2 * iv_len];
            prf::key_block(hash, &master, &sr, &cr, &mut kb);
            let (c_key, s_key) = (&kb[..key_len], &kb[key_len..2 * key_len]);
            let (c_iv, s_iv) = kb[2 * key_len..].split_at(iv_len);
            // One by-hand instance per direction to write, one to read.
            let mut by_hand_client = RecordCrypter12::new(alg, c_key, c_iv);
            let mut by_hand_server = RecordCrypter12::new(alg, s_key, s_iv);
            let mut reads_client = RecordCrypter12::new(alg, c_key, c_iv);
            let mut reads_server = RecordCrypter12::new(alg, s_key, s_iv);

            let (mut client, mut server) =
                RecordCrypter12::derive_pair(hash, alg, key_len, &master, &sr, &cr);
            let payload = b"layout";
            let a = client
                .encrypt(ContentType::ApplicationData, payload)
                .unwrap();
            let b = by_hand_client
                .encrypt(ContentType::ApplicationData, payload)
                .unwrap();
            assert_eq!(a, b);
            let (_, plain) = reads_client
                .decrypt(&header(ContentType::ApplicationData, &a), &a)
                .unwrap();
            assert_eq!(plain, payload);
            let s = server
                .encrypt(ContentType::ApplicationData, payload)
                .unwrap();
            let t = by_hand_server
                .encrypt(ContentType::ApplicationData, payload)
                .unwrap();
            assert_eq!(s, t);
            let (_, plain) = reads_server
                .decrypt(&header(ContentType::ApplicationData, &s), &s)
                .unwrap();
            assert_eq!(plain, payload);
        }
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
        let key = alloc::vec![0x11u8; 32];

        let mut gcm = RecordCrypter12::new(AeadAlg::Aes256Gcm, &key, &[0; 4]);
        gcm.set_seq_for_test(MAX_RECORDS_GCM - 1);
        assert!(gcm.encrypt(ContentType::ApplicationData, &[0u8; 8]).is_ok());
        assert!(matches!(
            gcm.encrypt(ContentType::ApplicationData, &[0u8; 8]),
            Err(Error::TooManyRecords)
        ));
        // close_notify (level warning, description 0) still goes out.
        let alert = gcm.encrypt(ContentType::Alert, &[1u8, 0u8]).unwrap();
        assert_eq!(alert.len(), 8 + 2 + 16);
        // ... and is still read at the cap, under either nonce scheme.
        let mut gcm_reader = RecordCrypter12::new(AeadAlg::Aes256Gcm, &key, &[0; 4]);
        gcm_reader.set_seq_for_test(MAX_RECORDS_GCM);
        assert!(
            gcm_reader
                .decrypt(&header(ContentType::Alert, &alert), &alert)
                .is_ok()
        );

        // ChaCha20-Poly1305 has no such limit: the old shared 2^23 cap does
        // not apply to it.
        let mut chacha = RecordCrypter12::new(AeadAlg::ChaCha20Poly1305, &key, &[0; 12]);
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

    /// Decrypting a fragment shorter than `explicit_nonce + tag` returns
    /// `Decode`, not a panic: 24 bytes for GCM, 16 for ChaCha20-Poly1305.
    #[test]
    fn short_fragment_rejected() {
        let key = alloc::vec![0u8; 32];
        let mut gcm = RecordCrypter12::new(AeadAlg::Aes256Gcm, &key, &[0; 4]);
        let short = [0u8; 23];
        assert!(matches!(
            gcm.decrypt(&header(ContentType::ApplicationData, &short), &short),
            Err(Error::Decode)
        ));
        let mut chacha = RecordCrypter12::new(AeadAlg::ChaCha20Poly1305, &key, &[0; 12]);
        let short = [0u8; 15];
        assert!(matches!(
            chacha.decrypt(&header(ContentType::ApplicationData, &short), &short),
            Err(Error::Decode)
        ));
        // A bare tag is the minimum ChaCha20 fragment: rejected by the MAC,
        // not by the length check.
        let tag_only = [0u8; 16];
        assert!(matches!(
            chacha.decrypt(&header(ContentType::ApplicationData, &tag_only), &tag_only),
            Err(Error::BadRecordMac)
        ));
    }

    /// A write IV of the wrong length for the suite is a programming error.
    #[test]
    #[should_panic(expected = "fixed_iv_length")]
    fn wrong_iv_length_panics() {
        let key = alloc::vec![0u8; 32];
        let _ = RecordCrypter12::new(AeadAlg::ChaCha20Poly1305, &key, &[0; 4]);
    }
}
