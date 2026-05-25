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
use crate::cipher::{Aes128, Aes256, Gcm};
use crate::tls::{ContentType, Error};
use alloc::vec::Vec;

/// The record-protection AEAD (AES-GCM, keyed for the negotiated suite).
enum Aead {
    Aes128(Gcm<Aes128>),
    Aes256(Gcm<Aes256>),
}

impl Aead {
    fn encrypt(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        match self {
            Aead::Aes128(g) => g.encrypt(nonce, aad, buf),
            Aead::Aes256(g) => g.encrypt(nonce, aad, buf),
        }
    }

    fn decrypt(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8; 16]) -> bool {
        let r = match self {
            Aead::Aes128(g) => g.decrypt(nonce, aad, buf, tag),
            Aead::Aes256(g) => g.decrypt(nonce, aad, buf, tag),
        };
        r.is_ok()
    }
}

/// One direction's record protection: an AEAD keyed from a traffic secret,
/// plus the static IV and a record sequence counter.
pub(crate) struct RecordCrypter {
    aead: Aead,
    iv: [u8; 12],
    seq: u64,
}

impl RecordCrypter {
    /// Derives the write/read key and IV from a traffic secret (RFC 8446 §7.3)
    /// and starts the sequence counter at zero. `key_len` is 16 for
    /// `AES_128_GCM` or 32 for `AES_256_GCM`.
    pub(crate) fn new(alg: HashAlg, key_len: usize, secret: &Secret) -> Self {
        let (key, iv) = traffic_key_iv(alg, secret, key_len);
        let aead = match key_len {
            16 => {
                let mut k = [0u8; 16];
                k.copy_from_slice(&key);
                Aead::Aes128(Gcm::new(Aes128::new(&k)))
            }
            32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&key);
                Aead::Aes256(Gcm::new(Aes256::new(&k)))
            }
            _ => panic!("unsupported AEAD key length {key_len}"),
        };
        RecordCrypter { aead, iv, seq: 0 }
    }

    /// The per-record nonce: static IV XOR the 64-bit big-endian sequence
    /// number (right-aligned), then increments the counter.
    fn next_nonce(&mut self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq[i];
        }
        self.seq += 1;
        nonce
    }

    /// Encrypts one record, returning the complete wire `TLSCiphertext`
    /// (5-byte header included). `content_type` is the true inner content type;
    /// no padding is added.
    pub(crate) fn encrypt(&mut self, content_type: ContentType, content: &[u8]) -> Vec<u8> {
        let fragment_len = content.len() + 1 + 16; // inner + type byte + tag
        let mut header = [0u8; 5];
        header[0] = ContentType::ApplicationData.as_u8();
        header[1] = 0x03;
        header[2] = 0x03;
        header[3..5].copy_from_slice(&(fragment_len as u16).to_be_bytes());

        let mut inner = Vec::with_capacity(content.len() + 1);
        inner.extend_from_slice(content);
        inner.push(content_type.as_u8());

        let nonce = self.next_nonce();
        let tag = self.aead.encrypt(&nonce, &header, &mut inner);

        let mut out = Vec::with_capacity(5 + fragment_len);
        out.extend_from_slice(&header);
        out.extend_from_slice(&inner);
        out.extend_from_slice(&tag);
        out
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
        let nonce = self.next_nonce();
        if !self.aead.decrypt(&nonce, header, &mut buf, &tag) {
            return Err(Error::BadRecordMac);
        }

        // TLSInnerPlaintext: content || true_type || zeros*. Strip trailing
        // zero padding; the last non-zero byte is the true content type.
        let end = match buf.iter().rposition(|&b| b != 0) {
            Some(p) => p,
            None => return Err(Error::PeerMisbehaved), // all-zero / empty inner
        };
        let content_type = ContentType::from_u8(buf[end]);
        buf.truncate(end);
        Ok((content_type, buf))
    }
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

        let mut c = RecordCrypter::new(HashAlg::Sha256, 16, &server_hs_secret());
        let out = c.encrypt(ContentType::Handshake, &payload);
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

        let mut c = RecordCrypter::new(HashAlg::Sha256, 16, &server_hs_secret());
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

        let mut c = RecordCrypter::new(HashAlg::Sha256, 16, &server_hs_secret());
        let mut header = [0u8; 5];
        header.copy_from_slice(&bad[..5]);
        assert!(matches!(
            c.decrypt(&header, &bad[5..]),
            Err(Error::BadRecordMac)
        ));
    }
}
