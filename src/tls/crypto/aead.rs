//! TLS 1.3 record protection (RFC 8446 §5.2).
//!
//! Each protected record is a `TLSCiphertext`:
//!
//! ```text
//! opaque_type = application_data (23)
//! legacy_record_version = 0x0303
//! length
//! encrypted_record = AEAD-Encrypt(key, nonce, additional_data, plaintext)
//! ```
//!
//! where `plaintext` is the `TLSInnerPlaintext` — the real content, followed by
//! a one-byte true content type, followed by zero or more zero padding bytes —
//! and `additional_data` is the 5-byte `TLSCiphertext` header. The per-record
//! nonce is the static IV XORed with the big-endian record sequence number
//! (RFC 8446 §5.3).

use super::schedule::{HashAlg, Secret, traffic_key_iv};
use super::suite::AeadAlg;
use crate::cipher::{Aes128, Aes256, ChaCha20Poly1305, Gcm};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::tls::{ContentType, Error};
use alloc::vec::Vec;

/// The record-protection AEAD, keyed for the negotiated suite.
pub(crate) enum Aead {
    Aes128(Gcm<Aes128>),
    Aes256(Gcm<Aes256>),
    ChaCha20Poly1305(ChaCha20Poly1305),
}

impl Aead {
    pub(crate) fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        match self {
            Aead::Aes128(g) => g.encrypt(nonce, aad, buf),
            Aead::Aes256(g) => g.encrypt(nonce, aad, buf),
            Aead::ChaCha20Poly1305(c) => c.encrypt(nonce, aad, buf),
        }
    }

    pub(crate) fn decrypt(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> bool {
        let r = match self {
            Aead::Aes128(g) => g.decrypt(nonce, aad, buf, tag),
            Aead::Aes256(g) => g.decrypt(nonce, aad, buf, tag),
            Aead::ChaCha20Poly1305(c) => c.decrypt(nonce, aad, buf, tag),
        };
        r.is_ok()
    }

    /// Builds an AEAD for the given algorithm from a raw key. The key length
    /// must match `alg` (16 for AES-128, 32 for AES-256/ChaCha20).
    pub(crate) fn from_key(alg: AeadAlg, key: &[u8]) -> Self {
        match alg {
            AeadAlg::Aes128Gcm => {
                let mut k = [0u8; 16];
                k.copy_from_slice(&key[..16]);
                Aead::Aes128(Gcm::new(Aes128::new(&k)))
            }
            AeadAlg::Aes256Gcm => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&key[..32]);
                Aead::Aes256(Gcm::new(Aes256::new(&k)))
            }
            AeadAlg::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&key[..32]);
                Aead::ChaCha20Poly1305(ChaCha20Poly1305::new(&k))
            }
        }
    }
}

/// Per-key record-sequence cap. RFC 8446 §5.5 mandates that implementations
/// initiate a `KeyUpdate` before the AEAD's safe-record limit is reached:
/// AES-GCM ≈ 2²⁴·⁵, AES-CCM_8 ≈ 2²³, ChaCha20-Poly1305 ≈ 2⁴⁸. We pick the
/// most conservative bound that still leaves room for normal traffic.
const MAX_RECORDS_PER_KEY: u64 = 1 << 23;

/// One direction's record protection: an AEAD keyed from a traffic secret,
/// plus the static IV and a record sequence counter.
pub(crate) struct RecordCrypter {
    aead: Aead,
    iv: [u8; 12],
    seq: u64,
}

impl RecordCrypter {
    /// Derives the write/read key and IV from a traffic secret (RFC 8446 §7.3)
    /// and starts the sequence counter at zero. `alg` selects the AEAD; `key_len`
    /// is its key size in bytes (16 for AES-128, 32 for AES-256/ChaCha20).
    pub(crate) fn new(hash: HashAlg, alg: AeadAlg, key_len: usize, secret: &Secret) -> Self {
        let (key, iv) = traffic_key_iv(hash, secret, key_len);
        let aead = match alg {
            AeadAlg::Aes128Gcm => {
                let mut k = [0u8; 16];
                k.copy_from_slice(&key[..16]);
                Aead::Aes128(Gcm::new(Aes128::new(&k)))
            }
            AeadAlg::Aes256Gcm => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&key[..32]);
                Aead::Aes256(Gcm::new(Aes256::new(&k)))
            }
            AeadAlg::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&key[..32]);
                Aead::ChaCha20Poly1305(ChaCha20Poly1305::new(&k))
            }
        };
        RecordCrypter { aead, iv, seq: 0 }
    }

    /// The per-record nonce: static IV XOR the 64-bit big-endian sequence
    /// number (right-aligned), then increments the counter. Returns
    /// `Err(TooManyRecords)` if the per-key cap (RFC 8446 §5.5) has been
    /// reached; callers should `KeyUpdate` first.
    fn next_nonce(&mut self) -> Result<[u8; 12], Error> {
        if self.seq >= MAX_RECORDS_PER_KEY {
            return Err(Error::TooManyRecords);
        }
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq[i];
        }
        self.seq += 1;
        Ok(nonce)
    }

    /// Encrypts one record, returning the complete wire `TLSCiphertext`
    /// (5-byte header included). `content_type` is the true inner content type;
    /// no padding is added.
    ///
    /// Returns `Err(TooManyRecords)` once the per-key record cap is hit and
    /// `Err(RecordOverflow)` if `content` would exceed the `2^14` plaintext
    /// fragment limit (RFC 8446 §5.1).
    pub(crate) fn encrypt(
        &mut self,
        content_type: ContentType,
        content: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if content.len() > (1usize << 14) {
            return Err(Error::RecordOverflow);
        }
        let fragment_len = content.len() + 1 + 16; // inner + type byte + tag
        let mut header = [0u8; 5];
        header[0] = ContentType::ApplicationData.as_u8();
        header[1] = 0x03;
        header[2] = 0x03;
        header[3..5].copy_from_slice(&(fragment_len as u16).to_be_bytes());

        let mut inner = Vec::with_capacity(content.len() + 1);
        inner.extend_from_slice(content);
        inner.push(content_type.as_u8());

        let nonce = self.next_nonce()?;
        let tag = self.aead.encrypt(&nonce, &header, &mut inner);

        let mut out = Vec::with_capacity(5 + fragment_len);
        out.extend_from_slice(&header);
        out.extend_from_slice(&inner);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Per-record nonce for an externally-supplied sequence number. Mirrors
    /// [`Self::next_nonce`] but does not advance the internal counter — used
    /// by DTLS and QUIC where seq is record-layer state, not crypter state.
    #[cfg(any(feature = "dtls", feature = "quic"))]
    fn nonce_for(&self, seq: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        let s = seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= s[i];
        }
        nonce
    }

    /// Raw-AEAD encrypt: nonce derived from `seq`, AAD supplied verbatim,
    /// plaintext in `buf` (encrypted in place), returns the 16-byte tag.
    ///
    /// Intended for DTLS 1.3 (RFC 9147 §4.2.1), where the AAD is the
    /// caller-supplied unified-header bytes and the per-record sequence
    /// number is tracked by the record layer instead of the crypter.
    #[cfg(any(feature = "dtls", feature = "quic"))]
    pub(crate) fn encrypt_raw(
        &mut self,
        seq: u64,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Result<[u8; 16], Error> {
        let nonce = self.nonce_for(seq);
        Ok(self.aead.encrypt(&nonce, aad, buf))
    }

    /// Raw-AEAD decrypt mirroring [`Self::encrypt_raw`]. The seq is supplied
    /// by the caller (DTLS reconstructs it from the masked wire value);
    /// `aad` is the unified-header bytes; `buf` carries the ciphertext and
    /// is decrypted in place.
    #[cfg(any(feature = "dtls", feature = "quic"))]
    pub(crate) fn decrypt_raw(
        &mut self,
        seq: u64,
        aad: &[u8],
        buf: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), Error> {
        let nonce = self.nonce_for(seq);
        if !self.aead.decrypt(&nonce, aad, buf, tag) {
            return Err(Error::BadRecordMac);
        }
        Ok(())
    }

    /// Decrypts one record. `header` is the 5-byte `TLSCiphertext` header
    /// (used as AEAD additional data) and `fragment` is the encrypted record
    /// (ciphertext followed by the 16-byte tag). Returns the true content type
    /// and the recovered content (padding stripped).
    pub(crate) fn decrypt(
        &mut self,
        header: &[u8; 5],
        fragment: &[u8],
    ) -> Result<(ContentType, Vec<u8>), Error> {
        if fragment.len() < 16 {
            return Err(Error::Decode);
        }
        let (ct, tag_bytes) = fragment.split_at(fragment.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_bytes);

        let mut buf = ct.to_vec();
        let nonce = self.next_nonce()?;
        if !self.aead.decrypt(&nonce, header, &mut buf, &tag) {
            return Err(Error::BadRecordMac);
        }

        // TLSInnerPlaintext: content || true_type || zeros*. The true
        // content type is the last non-zero byte. A naive backward
        // search leaks the padding length via timing — a CDN co-tenant
        // or on-path attacker can build a decryption oracle from that
        // (TLS-2 audit finding). Walk the buffer ONCE front-to-back,
        // tracking the most recent non-zero position and value in
        // constant time.
        let (content_type_byte, end) = ct_find_last_nonzero(&buf)?;
        let content_type = ContentType::from_u8(content_type_byte);
        buf.truncate(end);
        // RFC 8446 §5.2: the recovered TLSPlaintext.fragment must not exceed
        // 2^14 bytes (the type byte and padding are already stripped).
        if buf.len() > (1usize << 14) {
            return Err(Error::RecordOverflow);
        }
        Ok((content_type, buf))
    }
}

/// Scans `buf` front-to-back in constant time and returns
/// `(value, index)` of the last non-zero byte — the true content type
/// of a TLS 1.3 `TLSInnerPlaintext` and the position the buffer
/// truncates to once the type and trailing zero padding are stripped.
///
/// Constant-time properties (RFC 8446 §5.4 traffic-analysis note):
///
/// - Every byte of `buf` is visited exactly once.
/// - The per-byte branch decides which of `(0, 0)` and `(byte, idx+1)`
///   to keep using [`u8::conditional_select`], which is data-flow only.
/// - No early exit; the running candidate is updated on every iteration
///   regardless of value.
///
/// The all-zero / empty-buffer case still produces a public error —
/// such records are protocol violations (RFC 8446 §5.4: every inner
/// plaintext carries at least the content-type byte). Surfacing the
/// error is itself a public signal, so the early `if` here is fine.
fn ct_find_last_nonzero(buf: &[u8]) -> Result<(u8, usize), Error> {
    if buf.is_empty() {
        return Err(Error::PeerMisbehaved);
    }
    let mut found_any = Choice::from(0);
    let mut cur_byte: u8 = 0;
    let mut cur_end: usize = 0;
    for (i, &b) in buf.iter().enumerate() {
        let nonzero = !b.ct_eq(&0u8);
        // Conditionally promote (b, i+1) as the new "last non-zero"
        // candidate. `i+1` is the truncation index (one past the
        // content-type byte position).
        cur_byte = u8::conditional_select(&b, &cur_byte, nonzero);
        cur_end = usize::conditional_select(&(i + 1), &cur_end, nonzero);
        found_any |= nonzero;
    }
    if !bool::from(found_any) {
        return Err(Error::PeerMisbehaved);
    }
    // `cur_end` is the index immediately after the content-type byte;
    // truncating to `cur_end - 1` drops the type byte and the padding.
    Ok((cur_byte, cur_end - 1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex_vec;

    // RFC 8448 §3: the server's first encrypted handshake record (the flight
    // carrying EncryptedExtensions, Certificate, CertificateVerify, Finished),
    // protected under server_handshake_traffic_secret with AES-128-GCM-SHA256.
    fn server_hs_secret() -> Secret {
        Secret::new(&from_hex_vec(
            "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
        ))
    }

    #[test]
    fn rfc8448_server_flight_encrypt() {
        let payload = from_hex_vec(include_str!(
            "../../../testdata/rfc8448_server_flight_payload.hex"
        ));
        let record = from_hex_vec(include_str!(
            "../../../testdata/rfc8448_server_flight_record.hex"
        ));

        let mut c =
            RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &server_hs_secret());
        let out = c.encrypt(ContentType::Handshake, &payload).unwrap();
        assert_eq!(out, record);
    }

    #[test]
    fn rfc8448_server_flight_decrypt() {
        let payload = from_hex_vec(include_str!(
            "../../../testdata/rfc8448_server_flight_payload.hex"
        ));
        let record = from_hex_vec(include_str!(
            "../../../testdata/rfc8448_server_flight_record.hex"
        ));

        let mut c =
            RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &server_hs_secret());
        let mut header = [0u8; 5];
        header.copy_from_slice(&record[..5]);
        let (ct, content) = c.decrypt(&header, &record[5..]).unwrap();
        assert_eq!(ct, ContentType::Handshake);
        assert_eq!(content, payload);
    }

    #[test]
    fn tampered_tag_is_rejected() {
        let record = from_hex_vec(include_str!(
            "../../../testdata/rfc8448_server_flight_record.hex"
        ));
        let mut bad = record.clone();
        *bad.last_mut().unwrap() ^= 0x01;

        let mut c =
            RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &server_hs_secret());
        let mut header = [0u8; 5];
        header.copy_from_slice(&bad[..5]);
        assert!(matches!(
            c.decrypt(&header, &bad[5..]),
            Err(Error::BadRecordMac)
        ));
    }

    // ----- TLS-2 ct padding strip regression tests -----
    //
    // We can't measure timing here; what we can pin is functional
    // correctness across the corner cases the constant-time helper
    // must handle. The helper walks the buffer ONCE front-to-back,
    // updating its running `(byte, idx)` candidate via
    // `ConditionallySelectable` — so a regression that re-introduces
    // a backward / short-circuit scan would break either (a) the
    // mid-buffer-zero case (last non-zero, not first) or (b) the
    // all-zero malformed-record case.

    #[test]
    fn ct_padding_strip_no_padding() {
        // content (3 bytes) || type=Handshake(22) || no padding.
        let buf = alloc::vec![0xAA, 0xBB, 0xCC, 22u8];
        let (ty, end) = super::ct_find_last_nonzero(&buf).expect("nonzero present");
        assert_eq!(ty, 22);
        assert_eq!(end, 3);
    }

    #[test]
    fn ct_padding_strip_with_padding() {
        // content (2 bytes) || type=ApplicationData(23) || 10 zero pad.
        let mut buf = alloc::vec![0x11, 0x22, 23u8];
        buf.extend(core::iter::repeat_n(0u8, 10));
        let (ty, end) = super::ct_find_last_nonzero(&buf).expect("nonzero present");
        assert_eq!(ty, 23);
        assert_eq!(end, 2);
    }

    #[test]
    fn ct_padding_strip_all_zero_signals_error() {
        // All-zero plaintext (no type byte) — protocol violation per
        // RFC 8446 §5.4. The helper returns PeerMisbehaved.
        let buf = alloc::vec![0u8; 32];
        assert!(matches!(
            super::ct_find_last_nonzero(&buf),
            Err(Error::PeerMisbehaved)
        ));
    }

    #[test]
    fn ct_padding_strip_empty_signals_error() {
        // Empty buffer: same protocol violation. Helper rejects early.
        let buf: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
        assert!(matches!(
            super::ct_find_last_nonzero(&buf),
            Err(Error::PeerMisbehaved)
        ));
    }

    #[test]
    fn ct_padding_strip_zero_byte_in_content_still_finds_last_nonzero() {
        // Content has an internal zero — the helper MUST identify
        // the LAST non-zero byte (the type), not the first. This is
        // the regression a forward-scan with early-exit could break.
        let buf = alloc::vec![0xAA, 0u8, 0xBB, 0u8, 23u8, 0u8, 0u8];
        let (ty, end) = super::ct_find_last_nonzero(&buf).expect("nonzero present");
        assert_eq!(ty, 23);
        assert_eq!(end, 4);
    }
}
