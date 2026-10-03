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

use super::schedule::{HashAlg, LabelPrefix, Secret, traffic_key_iv_with};
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
    ///
    /// The stack copy of the key is wiped once the cipher has absorbed it, so
    /// the raw record key is not left behind on the stack frame.
    pub(crate) fn from_key(alg: AeadAlg, key: &[u8]) -> Self {
        match alg {
            AeadAlg::Aes128Gcm => {
                let mut k = [0u8; 16];
                k.copy_from_slice(&key[..16]);
                let a = Aead::Aes128(Gcm::new(Aes128::new(&k)));
                wipe(&mut k);
                a
            }
            AeadAlg::Aes256Gcm => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&key[..32]);
                let a = Aead::Aes256(Gcm::new(Aes256::new(&k)));
                wipe(&mut k);
                a
            }
            AeadAlg::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&key[..32]);
                let a = Aead::ChaCha20Poly1305(ChaCha20Poly1305::new(&k));
                wipe(&mut k);
                a
            }
        }
    }
}

/// Per-key record-sequence cap. RFC 8446 §5.5 mandates that implementations
/// initiate a `KeyUpdate` before the AEAD's safe-record limit is reached:
/// AES-GCM ≈ 2²⁴·⁵, AES-CCM_8 ≈ 2²³, ChaCha20-Poly1305 ≈ 2⁴⁸. We pick the
/// most conservative bound that still leaves room for normal traffic.
const MAX_RECORDS_PER_KEY: u64 = 1 << 23;

/// Read-side ceiling on the record sequence number. RFC 8446 §5.5 bounds
/// what a *sender* may protect under one key (it is the sender's plaintext
/// the AES-GCM confidentiality bound protects, and the sender's job to
/// rekey); the receiver's only hard requirement is §5.3's "the sequence
/// number MUST NOT wrap". Enforcing the sender's cap on the read side used
/// to fail the connection after 2²³ inbound records against peers that never
/// initiate `KeyUpdate` on their own (OpenSSL, Go), which a long-lived bulk
/// transfer reaches in a few GiB of small records.
const MAX_READ_SEQ: u64 = u64::MAX;

/// Soft threshold at which the write side should initiate a `KeyUpdate`
/// (RFC 8446 §5.5: "before reaching" the limit). Leaving a margin of 2¹⁶
/// records below [`MAX_RECORDS_PER_KEY`] gives the peer ample time to
/// process our `KeyUpdate` while we keep transmitting under the old key.
pub(crate) const KEY_UPDATE_SOFT_LIMIT: u64 = MAX_RECORDS_PER_KEY - (1 << 16);

/// Authentication-tag length of every TLS 1.3 AEAD this crate negotiates
/// (AES-GCM and ChaCha20-Poly1305 both use 16-byte tags).
pub(crate) const AEAD_TAG_LEN: usize = 16;

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
    ///
    /// The derived key bytes are wiped as soon as the AEAD has absorbed them
    /// (the heap `Vec` from `traffic_key_iv` and the stack copy alike), so a
    /// `KeyUpdate` does not strew successive record keys through freed heap;
    /// the static IV is wiped by [`RecordCrypter`]'s `Drop`.
    pub(crate) fn new(hash: HashAlg, alg: AeadAlg, key_len: usize, secret: &Secret) -> Self {
        Self::new_with(LabelPrefix::Tls13, hash, alg, key_len, secret)
    }

    /// [`new`](Self::new) with an explicit `HkdfLabel` prefix: DTLS 1.3
    /// derives its record keys under `"dtls13"` (RFC 9147 §5.9).
    pub(crate) fn new_with(
        prefix: LabelPrefix,
        hash: HashAlg,
        alg: AeadAlg,
        key_len: usize,
        secret: &Secret,
    ) -> Self {
        let (mut key, iv) = traffic_key_iv_with(prefix, hash, secret, key_len);
        let aead = Aead::from_key(alg, &key);
        wipe(&mut key);
        RecordCrypter { aead, iv, seq: 0 }
    }

    /// The per-record nonce for the *current* sequence number — static IV XOR
    /// the 64-bit big-endian sequence number (right-aligned) — WITHOUT
    /// advancing the counter. Returns `Err(TooManyRecords)` once the sequence
    /// number reaches `cap`: the write side passes the RFC 8446 §5.5 per-key
    /// limit ([`MAX_RECORDS_PER_KEY`], "`KeyUpdate` first"), the read side the
    /// wrap-around guard ([`MAX_READ_SEQ`]).
    ///
    /// The read path deliberately peeks rather than consumes: a record that
    /// fails the AEAD check was never accepted, and the RFC 8446 §4.2.10
    /// "skip rejected early data" path must be able to discard it and try the
    /// *same* sequence number against the next record.
    fn peek_nonce(&self, cap: u64) -> Result<[u8; 12], Error> {
        if self.seq >= cap {
            return Err(Error::TooManyRecords);
        }
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce[4 + i] ^= seq[i];
        }
        Ok(nonce)
    }

    /// [`Self::peek_nonce`] followed by the counter increment (the write-side
    /// behaviour: a record we emit always consumes its sequence number).
    fn next_nonce(&mut self) -> Result<[u8; 12], Error> {
        let nonce = self.peek_nonce(MAX_RECORDS_PER_KEY)?;
        self.seq += 1;
        Ok(nonce)
    }

    /// The number of records already protected/accepted under this key. Used
    /// by the state machines to initiate a `KeyUpdate` before the per-key cap
    /// ([`KEY_UPDATE_SOFT_LIMIT`]) turns every further `encrypt` into
    /// `Err(TooManyRecords)`.
    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }

    /// Test hook: fast-forward the sequence counter so the per-key cap and
    /// the automatic-`KeyUpdate` threshold can be exercised without actually
    /// protecting 2²³ records.
    #[cfg(test)]
    pub(crate) fn set_seq_for_test(&mut self, seq: u64) {
        self.seq = seq;
    }

    /// Encrypts one record, returning the complete wire `TLSCiphertext`
    /// (5-byte header included). `content_type` is the true inner content type;
    /// no padding is added.
    ///
    /// Returns `Err(TooManyRecords)` once the per-key record cap is hit and
    /// `Err(RecordOverflow)` if `content` would exceed the `2^14` plaintext
    /// fragment limit (RFC 8446 §5.1). The engines use
    /// [`Self::encrypt_into`]; this wrapper serves the tests and the
    /// Valgrind hooks.
    #[cfg(any(test, feature = "__ct-check"))]
    pub(crate) fn encrypt(
        &mut self,
        content_type: ContentType,
        content: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        self.encrypt_into(content_type, content, &mut out)?;
        Ok(out)
    }

    /// [`Self::encrypt`], appending the record to `out` and encrypting it
    /// there in place (no intermediate buffers). On error nothing is
    /// appended.
    pub(crate) fn encrypt_into(
        &mut self,
        content_type: ContentType,
        content: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), Error> {
        if content.len() > (1usize << 14) {
            return Err(Error::RecordOverflow);
        }
        let fragment_len = content.len() + 1 + AEAD_TAG_LEN; // inner + type byte + tag
        let mut header = [0u8; 5];
        header[0] = ContentType::ApplicationData.as_u8();
        header[1] = 0x03;
        header[2] = 0x03;
        header[3..5].copy_from_slice(&(fragment_len as u16).to_be_bytes());

        let nonce = self.next_nonce()?;

        out.reserve(5 + fragment_len);
        out.extend_from_slice(&header);
        let inner_start = out.len();
        out.extend_from_slice(content);
        out.push(content_type.as_u8());
        let tag = self.aead.encrypt(&nonce, &header, &mut out[inner_start..]);
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// Per-record nonce for an externally-supplied sequence number. Mirrors
    /// [`Self::next_nonce`] but does not advance the internal counter — used
    /// by DTLS, where seq is record-layer state rather than crypter state.
    /// (QUIC derives its own nonce in `quic::crypto`.)
    #[cfg(feature = "dtls")]
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
    #[cfg(feature = "dtls")]
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
    #[cfg(feature = "dtls")]
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
    /// and the recovered content (padding stripped). The engines use
    /// [`Self::decrypt_in_place`]; this wrapper serves the tests and the
    /// Valgrind hooks.
    #[cfg(any(test, feature = "__ct-check"))]
    pub(crate) fn decrypt(
        &mut self,
        header: &[u8; 5],
        fragment: &[u8],
    ) -> Result<(ContentType, Vec<u8>), Error> {
        let mut buf = fragment.to_vec();
        let (content_type, len) = self.decrypt_in_place(header, &mut buf)?;
        buf.truncate(len);
        Ok((content_type, buf))
    }

    /// [`Self::decrypt`] in place: `fragment` (ciphertext ‖ tag) is
    /// decrypted where it lies, and the content is `fragment[..len]` for the
    /// returned `(content type, len)`. On an authentication failure the
    /// bytes are left as they were.
    pub(crate) fn decrypt_in_place(
        &mut self,
        header: &[u8; 5],
        fragment: &mut [u8],
    ) -> Result<(ContentType, usize), Error> {
        if fragment.len() < AEAD_TAG_LEN {
            return Err(Error::Decode);
        }
        let tag_at = fragment.len() - AEAD_TAG_LEN;
        let (buf, tag_bytes) = fragment.split_at_mut(tag_at);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_bytes);

        // Peek, don't consume: the sequence number advances only once the
        // AEAD has actually accepted the record (see `peek_nonce`).
        let nonce = self.peek_nonce(MAX_READ_SEQ)?;
        if !self.aead.decrypt(&nonce, header, buf, &tag) {
            return Err(Error::BadRecordMac);
        }
        self.seq += 1;

        // TLSInnerPlaintext: content || true_type || zeros*. The true
        // content type is the last non-zero byte. A naive backward
        // search leaks the padding length via timing — a CDN co-tenant
        // or on-path attacker can build a decryption oracle from that
        // (TLS-2 audit finding). Walk the buffer ONCE front-to-back,
        // tracking the most recent non-zero position and value in
        // constant time.
        let (content_type_byte, end) = ct_find_last_nonzero(buf)?;
        let content_type = ContentType::from_u8(content_type_byte);
        // RFC 8446 §5.2: the recovered TLSPlaintext.fragment must not exceed
        // 2^14 bytes (the type byte and padding are already stripped).
        if end > (1usize << 14) {
            return Err(Error::RecordOverflow);
        }
        Ok((content_type, end))
    }
}

impl Drop for RecordCrypter {
    /// Wipes the static per-direction IV on teardown (and on every
    /// `KeyUpdate`, which drops the superseded crypter). The AEAD's own
    /// expanded key schedule is owned by `crate::cipher` and wiped there.
    fn drop(&mut self) {
        wipe(&mut self.iv);
    }
}

/// Best-effort zeroing of a key buffer with the crate's volatile
/// [`zeroize`](crate::zeroize) stores, which are not elided.
fn wipe(buf: &mut [u8]) {
    crate::tls::conn::wipe(buf);
}

/// Scans `buf` front-to-back in constant time and returns
/// `(value, index)` of the last non-zero byte — the true content type
/// of a TLS 1.3 `TLSInnerPlaintext` and the position the buffer
/// truncates to once the type and trailing zero padding are stripped.
///
/// Constant-time properties (RFC 8446 §5.4 traffic-analysis note):
///
/// - Every byte of `buf` is visited exactly once, eight at a time: each
///   little-endian word's nonzero bytes are flagged with a carry-free
///   SWAR test, and the highest flagged byte (value and position) is
///   located by three branch-free halvings ([`u64::conditional_select`]
///   on constant shifts — no secret-dependent shift or index). The
///   trailing `len % 8` bytes are scanned one at a time.
/// - Whether a word or byte holds the new candidate is applied with
///   [`ConditionallySelectable::conditional_select`], which is data-flow
///   only.
/// - No early exit; the running candidate is updated on every iteration
///   regardless of value.
///
/// The all-zero / empty-buffer case still produces a public error —
/// such records are protocol violations (RFC 8446 §5.4: every inner
/// plaintext carries at least the content-type byte). Surfacing the
/// error is itself a public signal, so the early `if` here is fine.
pub(crate) fn ct_find_last_nonzero(buf: &[u8]) -> Result<(u8, usize), Error> {
    if buf.is_empty() {
        return Err(Error::PeerMisbehaved);
    }
    /// `Choice` of `x != 0`, branch-free: `x | -x` has its top bit set
    /// exactly when `x` is nonzero.
    #[inline(always)]
    fn nonzero(x: u64) -> Choice {
        Choice::from(((x | x.wrapping_neg()) >> 63) as u8)
    }
    const LOW7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
    const HIGH: u64 = 0x8080_8080_8080_8080;
    let mut found_any = Choice::from(0);
    let mut cur_byte: u8 = 0;
    let mut cur_end: usize = 0;
    let words = buf.chunks_exact(8);
    let tail = words.remainder();
    for (wi, chunk) in words.enumerate() {
        let w = u64::from_le_bytes(chunk.try_into().expect("8-byte chunk"));
        // The top bit of each byte of `f` is set iff that byte of `w` is
        // nonzero: `(b & 0x7f) + 0x7f` reaches 0x80 iff the low seven bits
        // are nonzero, and never carries into the next byte.
        let f = (((w & LOW7) + LOW7) | w) & HIGH;
        let word_nz = nonzero(f);
        // Narrow to the half holding the highest flagged byte, three
        // times; `v` keeps that byte's value in its low eight bits.
        let (mut v, mut f, mut pos) = (w, f, 0usize);
        for shift in [32u32, 16, 8] {
            let low_mask = (1u64 << shift) - 1;
            let up = nonzero(f >> shift);
            v = u64::conditional_select(&(v >> shift), &(v & low_mask), up);
            f = u64::conditional_select(&(f >> shift), &(f & low_mask), up);
            pos += (shift as usize / 8) * usize::from(up.unwrap_u8());
        }
        // Conditionally promote (byte, index+1) as the new "last non-zero"
        // candidate. `index+1` is the truncation index (one past the
        // content-type byte position).
        cur_byte = u8::conditional_select(&(v as u8), &cur_byte, word_nz);
        cur_end = usize::conditional_select(&(wi * 8 + pos + 1), &cur_end, word_nz);
        found_any |= word_nz;
    }
    let base = buf.len() - tail.len();
    for (i, &b) in tail.iter().enumerate() {
        let nonzero = !b.ct_eq(&0u8);
        cur_byte = u8::conditional_select(&b, &cur_byte, nonzero);
        cur_end = usize::conditional_select(&(base + i + 1), &cur_end, nonzero);
        found_any |= nonzero;
    }
    // Declassified (Valgrind harness): an all-zero inner plaintext is a
    // protocol violation answered with an alert, so whether one was found
    // is public.
    if !found_any.declassify() {
        return Err(Error::PeerMisbehaved);
    }
    // `cur_end` is the index immediately after the content-type byte;
    // truncating to `cur_end - 1` drops the type byte and the padding.
    // Declassified (Valgrind harness): the true content type and length are
    // this function's outputs — the engine dispatches on the type and every
    // later step (handshake parsing, delivery to the application) is shaped
    // by the length. What must not leak is the time taken to *find* them,
    // which the scan above keeps independent of the padding.
    Ok((
        crate::ct::declassify_value(cur_byte),
        crate::ct::declassify_value(cur_end) - 1,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The original byte-at-a-time scan, kept as the oracle for the
    /// word-at-a-time [`ct_find_last_nonzero`].
    fn ct_find_last_nonzero_bytewise(buf: &[u8]) -> Result<(u8, usize), Error> {
        if buf.is_empty() {
            return Err(Error::PeerMisbehaved);
        }
        let mut found_any = Choice::from(0);
        let mut cur_byte: u8 = 0;
        let mut cur_end: usize = 0;
        for (i, &b) in buf.iter().enumerate() {
            let nonzero = !b.ct_eq(&0u8);
            cur_byte = u8::conditional_select(&b, &cur_byte, nonzero);
            cur_end = usize::conditional_select(&(i + 1), &cur_end, nonzero);
            found_any |= nonzero;
        }
        if !bool::from(found_any) {
            return Err(Error::PeerMisbehaved);
        }
        Ok((cur_byte, cur_end - 1))
    }

    fn same_result(buf: &[u8]) {
        let got = ct_find_last_nonzero(buf);
        let want = ct_find_last_nonzero_bytewise(buf);
        match (got, want) {
            (Ok(g), Ok(w)) => assert_eq!(g, w, "buf = {buf:02x?}"),
            (Err(g), Err(w)) => assert_eq!(g, w),
            (g, w) => panic!("{g:?} vs {w:?} for {buf:02x?}"),
        }
    }

    /// Edge values: every length up to four words, the last nonzero byte at
    /// every position, and byte values that probe the SWAR flag (0x01,
    /// 0x7f, 0x80, 0xff) with zero and nonzero bytes around them.
    #[test]
    fn last_nonzero_matches_bytewise_on_edges() {
        same_result(&[]);
        for len in 1..=32usize {
            same_result(&alloc::vec![0u8; len]);
            for pos in 0..len {
                for v in [0x01u8, 0x7f, 0x80, 0xff, 0x17] {
                    let mut b = alloc::vec![0u8; len];
                    b[pos] = v;
                    same_result(&b);
                    // Earlier nonzero bytes in the same and previous words.
                    for q in 0..pos {
                        let mut c = b.clone();
                        c[q] = 0x80;
                        same_result(&c);
                    }
                }
            }
        }
    }

    /// Deterministic random sweep over lengths and sparsities.
    #[test]
    fn last_nonzero_matches_bytewise_random() {
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..20_000 {
            let len = (next() % 300) as usize;
            let density = next() % 5;
            let buf: Vec<u8> = (0..len)
                .map(|_| {
                    let r = next();
                    if r % 8 < density { (r >> 8) as u8 } else { 0 }
                })
                .collect();
            same_result(&buf);
        }
    }
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

    /// RFC 8446 §5.5 caps what a *sender* protects under one key; a receiver
    /// that enforced the same cap failed the connection after 2²³ inbound
    /// records against peers that never rekey on their own. The read side
    /// must keep decrypting past the write-side cap (up to the §5.3 wrap
    /// guard), while the write side still refuses to go past it.
    #[test]
    fn read_side_accepts_records_past_the_write_side_cap() {
        let secret = Secret::new(&[0x77u8; 32]);
        let (key, iv) = traffic_key_iv_with(LabelPrefix::Tls13, HashAlg::Sha256, &secret, 16);
        let aead = Aead::from_key(AeadAlg::Aes128Gcm, &key);

        // A peer that never rekeyed: its record at sequence number 2^23 + 5.
        let seq: u64 = MAX_RECORDS_PER_KEY + 5;
        let mut nonce = iv;
        for (i, b) in seq.to_be_bytes().iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        let mut inner = b"still readable".to_vec();
        inner.push(ContentType::ApplicationData.as_u8());
        let header = [23u8, 3, 3, 0, (inner.len() + 16) as u8];
        let tag = aead.encrypt(&nonce, &header, &mut inner);
        let mut fragment = inner;
        fragment.extend_from_slice(&tag);

        let mut reader = RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &secret);
        reader.set_seq_for_test(seq);
        let (ct, content) = reader
            .decrypt(&header, &fragment)
            .expect("past the write cap");
        assert_eq!(ct, ContentType::ApplicationData);
        assert_eq!(content, b"still readable");
        assert_eq!(reader.seq(), seq + 1);

        // The write side still stops at the per-key cap.
        let mut writer = RecordCrypter::new(HashAlg::Sha256, AeadAlg::Aes128Gcm, 16, &secret);
        writer.set_seq_for_test(MAX_RECORDS_PER_KEY);
        assert!(matches!(
            writer.encrypt(ContentType::ApplicationData, b"x"),
            Err(Error::TooManyRecords)
        ));
        // And the read side refuses to let the sequence number wrap.
        reader.set_seq_for_test(u64::MAX);
        assert!(matches!(
            reader.decrypt(&header, &fragment),
            Err(Error::TooManyRecords)
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
