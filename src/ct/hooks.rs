//! Entry points into crate-private code for the Valgrind constant-time
//! harness.
//!
//! INTERNAL. Compiled only under the hidden `__ct-check` cargo feature, which
//! exists for `tests/ct_valgrind.rs` and nothing else; nothing here is part
//! of the public API and it may change or vanish without notice.
//!
//! The record layers of TLS, DTLS and QUIC run on keys a handshake derives
//! and are reachable publicly only through a full connection, whose
//! handshake would drag public values (randoms, transcript, certificates)
//! through the same code as the secrets. Each hook here instead runs one
//! protection step on caller-supplied bytes, so the harness can classify
//! exactly the secret inputs (traffic secrets, keys, plaintexts). The hooks
//! add no cryptographic logic of their own: they call the same crate
//! functions the engines call, and the receive-side glue (sequence-number /
//! header-protection removal, AAD reconstruction, packet-number decoding)
//! mirrors the engines' receive paths step for step, citing where.
//!
//! `falcon_classify_private_key` is the other kind of hook: it marks the
//! heap-held secret buffers of an imported Falcon key as secret, which the
//! harness cannot reach through the key's public API.

#[cfg(feature = "tls")]
pub use self::suite::Suite;

#[cfg(feature = "tls")]
mod suite {
    use crate::tls::crypto::{SuiteParams, supported_suites};

    /// The three TLS 1.3 / DTLS 1.3 / QUIC cipher suites. The TLS 1.2 and
    /// DTLS 1.2 hooks take the same enum and use the suite's hash (for the
    /// PRF) and AEAD, as `TLS_ECDHE_*_WITH_AES_128_GCM_SHA256` and friends
    /// do.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Suite {
        /// `TLS_AES_128_GCM_SHA256`.
        Aes128GcmSha256,
        /// `TLS_AES_256_GCM_SHA384`.
        Aes256GcmSha384,
        /// `TLS_CHACHA20_POLY1305_SHA256`.
        ChaCha20Poly1305Sha256,
    }

    impl Suite {
        /// The crate's parameters for this suite.
        pub(crate) fn params(self) -> SuiteParams {
            let i = match self {
                Suite::Aes128GcmSha256 => 0,
                Suite::Aes256GcmSha384 => 1,
                Suite::ChaCha20Poly1305Sha256 => 2,
            };
            supported_suites()[i]
        }
    }
}

/// TLS 1.3 and TLS 1.2 key schedules, Finished MACs and record protection.
#[cfg(feature = "tls")]
pub mod tls {
    use super::Suite;
    use crate::ct::{Choice, ConstantTimeEq};
    use crate::tls::crypto::aead12::{self, RecordCrypter12};
    use crate::tls::crypto::{
        Aead, KeySchedule, Secret, binder_finished_key, finished_verify_data, next_traffic_secret,
        prf, psk_from_resumption, tls_exporter, traffic_key_iv,
    };
    use crate::tls::{ContentType, Error};
    use alloc::vec::Vec;

    /// The RFC 8446 §7.1 key schedule: with a PSK, the binder key (the
    /// resumption one, or the external one when `external_psk`) and its
    /// Finished key; then from the (EC)DHE shared secret — or, for `psk_ke`
    /// (`ecdhe == None`), from the zero string (§7.1) — the client and
    /// server handshake traffic secrets (over `th_hello`), the client and
    /// server application traffic secrets and the exporter master secret
    /// (over `th_server_finished`), a 32-byte exporter output, the
    /// resumption master secret (over `th_client_finished`) and a resumption
    /// PSK. Returns every derived secret, concatenated.
    pub fn tls13_key_schedule(
        suite: Suite,
        psk: Option<&[u8]>,
        external_psk: bool,
        ecdhe: Option<&[u8]>,
        th_hello: &[u8],
        th_server_finished: &[u8],
        th_client_finished: &[u8],
    ) -> Vec<u8> {
        let p = suite.params();
        let mut out = Vec::new();
        let mut ks = match psk {
            Some(psk) => {
                let ks = KeySchedule::with_psk(p.hash, psk);
                let label: &[u8] = if external_psk {
                    b"ext binder"
                } else {
                    b"res binder"
                };
                let binder = ks.binder_key(label);
                out.extend_from_slice(binder.as_slice());
                out.extend_from_slice(binder_finished_key(p.hash, &binder).as_slice());
                ks
            }
            None => KeySchedule::new(p.hash),
        };
        match ecdhe {
            Some(ecdhe) => ks.enter_handshake(ecdhe),
            None => ks.enter_handshake_psk_only(),
        }
        out.extend_from_slice(ks.client_handshake_traffic_secret(th_hello).as_slice());
        out.extend_from_slice(ks.server_handshake_traffic_secret(th_hello).as_slice());
        ks.enter_master();
        out.extend_from_slice(
            ks.client_application_traffic_secret(th_server_finished)
                .as_slice(),
        );
        out.extend_from_slice(
            ks.server_application_traffic_secret(th_server_finished)
                .as_slice(),
        );
        let ems = ks.exporter_master_secret(th_server_finished);
        out.extend_from_slice(ems.as_slice());
        let mut export = [0u8; 32];
        tls_exporter(p.hash, &ems, b"EXPORTER-ct", b"context", &mut export)
            .expect("in-range exporter request");
        out.extend_from_slice(&export);
        let rms = ks.resumption_master_secret(th_client_finished);
        out.extend_from_slice(rms.as_slice());
        let mut psk_out = [0u8; 48];
        let n = p.hash.output_len();
        psk_from_resumption(p.hash, &rms, &[0, 1], &mut psk_out[..n]);
        out.extend_from_slice(&psk_out[..n]);
        out
    }

    /// The TLS 1.3 `KeyUpdate` step: `application_traffic_secret_{N+1}`
    /// (RFC 8446 §7.2).
    pub fn tls13_next_traffic_secret(suite: Suite, secret: &[u8]) -> Vec<u8> {
        let p = suite.params();
        next_traffic_secret(p.hash, &Secret::new(secret))
            .as_slice()
            .to_vec()
    }

    /// A TLS 1.3 Finished (RFC 8446 §4.4.4): the `verify_data` for
    /// `base_key` over `transcript_hash`, and the constant-time comparison
    /// of it against a `received` Finished body — the same
    /// `finished_verify_data` + `ct_eq` pair the handshake engines run
    /// before branching on the (public) verdict.
    pub fn tls13_finished(
        suite: Suite,
        base_key: &[u8],
        transcript_hash: &[u8],
        received: &[u8],
    ) -> (Vec<u8>, Choice) {
        let p = suite.params();
        let expected = finished_verify_data(p.hash, &Secret::new(base_key), transcript_hash);
        let ok = expected.as_slice().ct_eq(received);
        (expected.as_slice().to_vec(), ok)
    }

    /// Protects one TLS 1.3 record (sequence number 0) under the traffic
    /// secret `secret`, returning the wire `TLSCiphertext`. With
    /// `padding == 0` this is exactly the engines' write path
    /// (`RecordCrypter::encrypt`); otherwise the `TLSInnerPlaintext` carries
    /// that many zero padding bytes (RFC 8446 §5.4), which the crate never
    /// sends but must strip on receipt.
    pub fn tls13_seal(
        suite: Suite,
        secret: &[u8],
        content_type: u8,
        content: &[u8],
        padding: usize,
    ) -> Result<Vec<u8>, Error> {
        let p = suite.params();
        let secret = Secret::new(secret);
        if padding == 0 {
            return p
                .crypter(&secret)
                .encrypt(ContentType::from_u8(content_type), content);
        }
        let (key, iv) = traffic_key_iv(p.hash, &secret, p.key_len);
        let aead = Aead::from_key(p.aead, &key);
        let mut inner = Vec::with_capacity(content.len() + 1 + padding);
        inner.extend_from_slice(content);
        inner.push(content_type);
        inner.resize(content.len() + 1 + padding, 0);
        let len = (inner.len() + 16) as u16;
        let mut out = alloc::vec![23u8, 3, 3];
        out.extend_from_slice(&len.to_be_bytes());
        // Sequence number 0: the nonce is the static IV itself.
        let tag = aead.encrypt(&iv, &out, &mut inner);
        out.extend_from_slice(&inner);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Removes TLS 1.3 record protection (sequence number 0): the engines'
    /// read path (`RecordCrypter::decrypt`), including the constant-time
    /// scan for the true content type under the padding. Returns the
    /// content type byte and the content.
    pub fn tls13_open(suite: Suite, secret: &[u8], record: &[u8]) -> Result<(u8, Vec<u8>), Error> {
        let p = suite.params();
        if record.len() < 5 {
            return Err(Error::Decode);
        }
        let mut header = [0u8; 5];
        header.copy_from_slice(&record[..5]);
        let (ct, content) = p
            .crypter(&Secret::new(secret))
            .decrypt(&header, &record[5..])?;
        Ok((ct.as_u8(), content))
    }

    /// `SecurityParameters.fixed_iv_length` for `suite`'s AEAD in TLS 1.2:
    /// the per-direction write IV the key block yields — 4 bytes (the GCM
    /// salt, RFC 5288 §3) or 12 (the ChaCha20-Poly1305 write IV, RFC 7905
    /// §2).
    pub fn tls12_fixed_iv_len(suite: Suite) -> usize {
        aead12::fixed_iv_len(suite.params().aead)
    }

    /// `SecurityParameters.record_iv_length` for `suite`'s AEAD in TLS 1.2:
    /// the explicit nonce at the front of each record fragment — 8 bytes for
    /// GCM, none for ChaCha20-Poly1305.
    pub fn tls12_record_iv_len(suite: Suite) -> usize {
        aead12::record_iv_len(suite.params().aead)
    }

    /// The TLS 1.2 key derivation (RFC 5246 §8.1 / §6.3, RFC 7627): the
    /// master secret from `premaster` — the extended master secret over
    /// `session_hash` when given — and the key block for `suite`'s AEAD
    /// (two keys, then two write IVs of [`tls12_fixed_iv_len`] bytes).
    /// Returns `master ‖ key_block`.
    pub fn tls12_key_block(
        suite: Suite,
        premaster: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        session_hash: Option<&[u8]>,
    ) -> Vec<u8> {
        let p = suite.params();
        let master = match session_hash {
            Some(h) => prf::extended_master_secret(p.hash, premaster, h),
            None => prf::master_secret(p.hash, premaster, client_random, server_random),
        };
        let mut kb = alloc::vec![0u8; 2 * p.key_len + 2 * aead12::fixed_iv_len(p.aead)];
        prf::key_block(p.hash, &master, server_random, client_random, &mut kb);
        let mut out = master.to_vec();
        out.extend_from_slice(&kb);
        out
    }

    /// A TLS 1.2 Finished (RFC 5246 §7.4.9): the 12-byte `verify_data` and
    /// its constant-time comparison against `received`, as the engines run
    /// it.
    pub fn tls12_finished(
        suite: Suite,
        master: &[u8; 48],
        label: &[u8],
        transcript_hash: &[u8],
        received: &[u8],
    ) -> ([u8; 12], Choice) {
        let p = suite.params();
        let expected = prf::finished_verify_data(p.hash, master, label, transcript_hash);
        let ok = expected.as_slice().ct_eq(received);
        (expected, ok)
    }

    /// Protects one TLS 1.2 AEAD record (sequence number 0) under `key` and
    /// the direction's `write_iv` ([`tls12_fixed_iv_len`] bytes), returning
    /// the fragment — `explicit_nonce ‖ ciphertext ‖ tag` for GCM,
    /// `ciphertext ‖ tag` for ChaCha20-Poly1305 (`RecordCrypter12`).
    pub fn tls12_seal(
        suite: Suite,
        key: &[u8],
        write_iv: &[u8],
        content_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        RecordCrypter12::new(suite.params().aead, key, write_iv)
            .encrypt(ContentType::from_u8(content_type), payload)
    }

    /// Removes TLS 1.2 AEAD record protection (sequence number 0) from
    /// `fragment` under the 5-byte record `header`.
    pub fn tls12_open(
        suite: Suite,
        key: &[u8],
        write_iv: &[u8],
        header: &[u8; 5],
        fragment: &[u8],
    ) -> Result<Vec<u8>, Error> {
        RecordCrypter12::new(suite.params().aead, key, write_iv)
            .decrypt(header, fragment)
            .map(|(_, plain)| plain)
    }
}

/// DTLS 1.2 and DTLS 1.3 record protection.
#[cfg(feature = "dtls")]
pub mod dtls {
    use super::Suite;
    use crate::dtls::client13::{decrypt_dtls13_record, encrypt_protected_record_with};
    use crate::dtls::epoch13::ReadEpoch;
    use crate::dtls::record13::{
        self, header_aad, peek_header_layout, reconstruct_seq, sn_mask_for,
    };
    use crate::tls::crypto::Secret;
    use crate::tls::crypto::aead12::RecordCrypter12;
    use crate::tls::{ContentType, Error};
    use alloc::vec::Vec;

    /// Protects one DTLS 1.2 AEAD record payload at `epoch_seq`
    /// (`epoch:16 ‖ seq:48`) under `key` and the direction's `write_iv`
    /// ([`super::tls::tls12_fixed_iv_len`] bytes), returning the fragment.
    pub fn dtls12_seal(
        suite: Suite,
        key: &[u8],
        write_iv: &[u8],
        epoch_seq: u64,
        content_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        RecordCrypter12::new(suite.params().aead, key, write_iv).encrypt_dtls(
            epoch_seq,
            ContentType::from_u8(content_type),
            payload,
        )
    }

    /// Removes DTLS 1.2 AEAD record protection.
    pub fn dtls12_open(
        suite: Suite,
        key: &[u8],
        write_iv: &[u8],
        epoch_seq: u64,
        content_type: u8,
        fragment: &[u8],
    ) -> Result<Vec<u8>, Error> {
        RecordCrypter12::new(suite.params().aead, key, write_iv).decrypt_dtls(
            epoch_seq,
            ContentType::from_u8(content_type),
            fragment,
        )
    }

    /// Protects one DTLS 1.2 record carrying the connection ID `cid`
    /// (RFC 9146 §4, §5.3): the `DTLSInnerPlaintext` wrapping and the CID
    /// additional data of `RecordCrypter12::encrypt_dtls_cid`.
    pub fn dtls12_cid_seal(
        suite: Suite,
        key: &[u8],
        write_iv: &[u8],
        epoch_seq: u64,
        cid: &[u8],
        content_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        RecordCrypter12::new(suite.params().aead, key, write_iv).encrypt_dtls_cid(
            epoch_seq,
            cid,
            ContentType::from_u8(content_type),
            payload,
        )
    }

    /// Removes DTLS 1.2 CID record protection and strips the inner type
    /// and padding (constant-time scan). Returns `(content_type, content)`.
    pub fn dtls12_cid_open(
        suite: Suite,
        key: &[u8],
        write_iv: &[u8],
        epoch_seq: u64,
        cid: &[u8],
        fragment: &[u8],
    ) -> Result<(u8, Vec<u8>), Error> {
        let (ct, content) = RecordCrypter12::new(suite.params().aead, key, write_iv)
            .decrypt_dtls_cid(epoch_seq, cid, fragment)?;
        Ok((ct.as_u8(), content))
    }

    /// Protects one DTLS 1.3 record under the traffic secret `secret` at
    /// `(epoch, seq)`, with sequence-number encryption (RFC 9147 §4.2.3)
    /// and the connection ID `cid` in the header (empty for none, RFC 9147
    /// §4): the engines' `encrypt_protected_record_with`, keyed as a write
    /// epoch is (record keys and `sn_key` both from `secret`).
    pub fn dtls13_seal(
        suite: Suite,
        secret: &[u8],
        epoch: u16,
        seq: u64,
        cid: &[u8],
        content_type: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let p = suite.params();
        // `ReadEpoch::new` derives exactly the write side's crypter and
        // sn_key from a traffic secret; only the direction differs.
        let mut e = ReadEpoch::new(p, epoch, &Secret::new(secret));
        encrypt_protected_record_with(
            p,
            &mut e.crypter,
            &e.sn_key,
            epoch,
            seq,
            cid,
            ContentType::from_u8(content_type),
            payload,
        )
    }

    /// Removes DTLS 1.3 record protection from the first record in
    /// `datagram`, mirroring the engines' receive path
    /// (`dtls::client13` / `dtls::server13` `process_protected_record`):
    /// locate the body (parsing the header with the receiver's CID
    /// length `cid_len`), compute the sequence-number mask from it, unmask
    /// and reconstruct the sequence number against `high_water`, rebuild the
    /// AAD, then open the AEAD and strip the inner type and padding.
    /// Returns `(seq, content_type, content)`.
    pub fn dtls13_open(
        suite: Suite,
        secret: &[u8],
        epoch: u16,
        high_water: u64,
        cid_len: usize,
        datagram: &[u8],
    ) -> Result<(u64, u8, Vec<u8>), Error> {
        let p = suite.params();
        let mut ctx = ReadEpoch::new(p, epoch, &Secret::new(secret));
        ctx.seq = high_water;
        let (hdr_len, body_len) = peek_header_layout(datagram, cid_len)?;
        let total = hdr_len + body_len;
        if datagram.len() < total || body_len < 16 {
            return Err(Error::Decode);
        }
        let body = &datagram[hdr_len..total];
        let mask_full = sn_mask_for(p, ctx.sn_key.as_slice(), body)?;
        let mask: &[u8] = if (datagram[0] & 0b0000_1000) != 0 {
            &mask_full[..2]
        } else {
            &mask_full[..1]
        };
        let (hdr, ct_body) = record13::decode_record(datagram, mask, cid_len)?;
        let seq = reconstruct_seq(hdr.seq_low, hdr.seq_is_16bit, ctx.seq.wrapping_add(1));
        let aad = header_aad(datagram, &hdr, mask);
        let (ct, content) = decrypt_dtls13_record(&mut ctx.crypter, seq, &aad, ct_body)?;
        Ok((seq, ct.as_u8(), content))
    }
}

/// QUIC packet protection (RFC 9001 §5): AEAD and header protection of a
/// 1-RTT (short-header) packet, and the key update derivation (§6).
#[cfg(feature = "quic")]
pub mod quic {
    use super::Suite;
    use crate::quic::crypto::{
        AeadAlg, aead_open, aead_seal, derive_dir_keys, derive_dir_keys_preserve_hp,
        derive_hp_key_bytes, derive_next_application_secret,
    };
    use crate::quic::pkt::{
        ShortHeader, apply_header_protection, build_short_header, check_reserved_bits,
        remove_header_protection,
    };
    use crate::quic::pn::decode_packet_number;
    use crate::quic::version::QuicVersion;
    use crate::tls::Error;
    use alloc::vec::Vec;

    fn alg(suite: Suite) -> AeadAlg {
        match suite {
            Suite::Aes128GcmSha256 => AeadAlg::Aes128Gcm,
            Suite::Aes256GcmSha384 => AeadAlg::Aes256Gcm,
            Suite::ChaCha20Poly1305Sha256 => AeadAlg::ChaCha20Poly1305,
        }
    }

    /// Protects a 1-RTT packet with packet number `pn` (encoded in `pn_len`
    /// bytes) under the traffic secret `secret`: build the short header,
    /// seal the payload with the header as AAD, then apply header
    /// protection with the mask of the ciphertext sample (the engines'
    /// send path).
    #[allow(clippy::too_many_arguments)]
    pub fn protect(
        version: QuicVersion,
        suite: Suite,
        secret: &[u8],
        dcid: &[u8],
        pn: u64,
        pn_len: u8,
        key_phase: bool,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let keys = derive_dir_keys(version, alg(suite), secret);
        let (mut pkt, pn_offset) = build_short_header(dcid, false, key_phase, pn, pn_len);
        let mut body = payload.to_vec();
        let tag = aead_seal(&keys, pn, &pkt, &mut body);
        pkt.extend_from_slice(&body);
        pkt.extend_from_slice(&tag);
        let sample_start = pn_offset + 4;
        if pkt.len() < sample_start + 16 {
            return Err(Error::Decode);
        }
        let mask = keys.hp.mask(&pkt[sample_start..sample_start + 16])?;
        apply_header_protection(&mut pkt, pn_offset, pn_len, &mask, false);
        Ok(pkt)
    }

    /// Removes 1-RTT packet protection, mirroring the engines' receive path
    /// (`QuicConnection`'s short-header branch): sample, header-protection
    /// mask, unmask the first byte and the packet number, decode it against
    /// `largest_rx`, open the AEAD over the unprotected header, then check
    /// the reserved bits. Returns `(packet_number, first_byte, payload)`.
    pub fn unprotect(
        version: QuicVersion,
        suite: Suite,
        secret: &[u8],
        dcid_len: usize,
        largest_rx: u64,
        datagram: &[u8],
    ) -> Result<(u64, u8, Vec<u8>), Error> {
        let keys = derive_dir_keys(version, alg(suite), secret);
        let hdr = ShortHeader::parse(datagram, dcid_len)?;
        let sample_start = hdr.pn_offset.checked_add(4).ok_or(Error::Decode)?;
        let sample_end = sample_start.checked_add(16).ok_or(Error::Decode)?;
        if sample_end > datagram.len() {
            return Err(Error::Decode);
        }
        let mask = keys.hp.mask(&datagram[sample_start..sample_end])?;
        let mut pkt = datagram.to_vec();
        let pn_len = remove_header_protection(&mut pkt, hdr.pn_offset, &mask, false)?;
        let mut truncated_pn = 0u64;
        for i in 0..pn_len as usize {
            truncated_pn = (truncated_pn << 8) | pkt[hdr.pn_offset + i] as u64;
        }
        let pn = decode_packet_number(largest_rx, truncated_pn, (pn_len as u32) * 8);
        let aad_end = hdr.pn_offset + pn_len as usize;
        let aad = pkt[..aad_end].to_vec();
        let first_byte = pkt[0];
        let ct_with_tag = &mut pkt[aad_end..];
        if ct_with_tag.len() < 16 {
            return Err(Error::Decode);
        }
        let tag_start = ct_with_tag.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&ct_with_tag[tag_start..]);
        let payload = &mut ct_with_tag[..tag_start];
        aead_open(&keys, pn, &aad, payload, &tag)?;
        check_reserved_bits(first_byte, false)?;
        Ok((pn, first_byte, payload.to_vec()))
    }

    /// The RFC 9001 §6 key update: the next application secret (`"quic
    /// ku"`) and its AEAD key and IV, keeping the header-protection key of
    /// the current secret. Returns `next_secret ‖ key ‖ iv`.
    pub fn key_update(version: QuicVersion, suite: Suite, secret: &[u8]) -> Vec<u8> {
        let a = alg(suite);
        let hp = derive_hp_key_bytes(version, a, secret);
        let next = derive_next_application_secret(version, a, secret);
        let keys = derive_dir_keys_preserve_hp(version, a, &next, &hp);
        let mut out = next;
        out.extend_from_slice(&keys.key);
        out.extend_from_slice(&keys.iv);
        out
    }
}

/// The TLS 1.3 key exchanges that concatenate two primitives, and secp521r1
/// ECDHE: the `key_agreement` arms the TLS 1.3, DTLS 1.3 and QUIC engines
/// share (`tls::crypto::kex`), run on caller-supplied keys so the harness
/// can classify the private scalar, the ML-KEM decapsulation key and the
/// randomness the server side draws.
#[cfg(feature = "tls")]
pub mod kex {
    use crate::ec::BoxedEcdhPrivateKey;
    use crate::mlkem::{MlKem768DecapsKey, MlKem1024DecapsKey};
    use crate::rng::RngCore;
    use crate::tls::Error;
    use crate::tls::crypto::kex;
    use alloc::vec::Vec;

    /// Client share (RFC 10024 §4.1) of SecP256r1MLKEM768.
    pub fn p256_mlkem768_client_share(ec: &BoxedEcdhPrivateKey, dk: &MlKem768DecapsKey) -> Vec<u8> {
        kex::p256_mlkem768_client_share(ec, dk)
    }

    /// Server side of SecP256r1MLKEM768: `(server share, shared secret)`.
    pub fn p256_mlkem768_server<R: RngCore>(
        rng: &mut R,
        client_share: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        kex::p256_mlkem768_server(rng, client_share)
            .map(|(share, s)| (share, s.as_slice().to_vec()))
    }

    /// Client side of SecP256r1MLKEM768: the shared secret.
    pub fn p256_mlkem768_client(
        ec: &BoxedEcdhPrivateKey,
        dk: &MlKem768DecapsKey,
        server_share: &[u8],
    ) -> Result<Vec<u8>, Error> {
        kex::p256_mlkem768_client(ec, dk, server_share).map(|s| s.as_slice().to_vec())
    }

    /// Client share (RFC 10024 §4.1) of SecP384r1MLKEM1024.
    pub fn p384_mlkem1024_client_share(
        ec: &BoxedEcdhPrivateKey,
        dk: &MlKem1024DecapsKey,
    ) -> Vec<u8> {
        kex::p384_mlkem1024_client_share(ec, dk)
    }

    /// Server side of SecP384r1MLKEM1024: `(server share, shared secret)`.
    pub fn p384_mlkem1024_server<R: RngCore>(
        rng: &mut R,
        client_share: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        kex::p384_mlkem1024_server(rng, client_share)
            .map(|(share, s)| (share, s.as_slice().to_vec()))
    }

    /// Client side of SecP384r1MLKEM1024: the shared secret.
    pub fn p384_mlkem1024_client(
        ec: &BoxedEcdhPrivateKey,
        dk: &MlKem1024DecapsKey,
        server_share: &[u8],
    ) -> Result<Vec<u8>, Error> {
        kex::p384_mlkem1024_client(ec, dk, server_share).map(|s| s.as_slice().to_vec())
    }

    /// Server side of secp521r1 ECDHE (RFC 8446 §4.2.8.2):
    /// `(server share, shared secret)`.
    pub fn secp521r1_server<R: RngCore>(
        rng: &mut R,
        client_share: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        kex::ecdhe_server(crate::ec::CurveId::P521, rng, client_share)
            .map(|(share, s)| (share, s.as_slice().to_vec()))
    }

    /// Client side of secp521r1 ECDHE: the shared secret.
    pub fn secp521r1_client(
        ec: &BoxedEcdhPrivateKey,
        server_share: &[u8],
    ) -> Result<Vec<u8>, Error> {
        kex::ecdhe_client(ec, server_share).map(|s| s.as_slice().to_vec())
    }
}

/// Marks the secret buffers of an imported Falcon private key as secret:
/// the NTRU basis `f, g, F, G`, its FFT form and the LDL tree the signer
/// walks. The public `h` and the key's shape (degree, buffer lengths and
/// pointers) stay public. Key import itself is the documented
/// variable-time residual, so the harness classifies after it.
#[cfg(all(feature = "falcon", feature = "alloc"))]
pub fn falcon_classify_private_key(key: &crate::falcon::FalconPrivateKey) {
    key.ct_classify_secrets();
}
