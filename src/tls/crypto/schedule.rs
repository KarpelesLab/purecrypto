//! The TLS 1.3 key schedule (RFC 8446 §7.1).
//!
//! The schedule is a chain of HKDF `Extract` and `Derive-Secret` steps:
//!
//! ```text
//!              0
//!              |
//!   PSK ->  HKDF-Extract = Early Secret
//!              |  +-> Derive-Secret(., "derived", "")
//!              v
//!  (EC)DHE -> HKDF-Extract = Handshake Secret
//!              |  +-> Derive-Secret(., "c hs traffic", CH..SH)
//!              |  +-> Derive-Secret(., "s hs traffic", CH..SH)
//!              |  +-> Derive-Secret(., "derived", "")
//!              v
//!      0 -> HKDF-Extract = Master Secret
//!                 +-> Derive-Secret(., "c ap traffic", CH..server Finished)
//!                 +-> Derive-Secret(., "s ap traffic", CH..server Finished)
//! ```
//!
//! The negotiated cipher suite fixes the hash (SHA-256 or SHA-384), but that is
//! not known until the `ServerHello` is processed. The primitives below are
//! generic over [`Digest`]; the runtime [`KeySchedule`] dispatches to the right
//! monomorphization and stores secrets in a length-tagged [`Secret`] buffer so
//! a single type holds either a 32- or 48-byte secret.

use crate::hash::{Digest, Hmac, Sha256, Sha384};
use crate::kdf::{hkdf_expand, hkdf_extract};
use alloc::vec::Vec;

/// The largest secret the schedule holds: the 64-byte concatenated shared
/// secret of the X25519MLKEM768 hybrid (32 + 32). Hash outputs and traffic
/// secrets are at most a SHA-384 (48-byte) value.
const MAX_SECRET: usize = 64;

/// A short byte string held inline: a key-schedule secret, a transcript hash,
/// or a (possibly hybrid) (EC)DHE shared secret (≤ 64 bytes). Avoids heap
/// allocation.
#[derive(Clone, Copy)]
pub(crate) struct Secret {
    buf: [u8; MAX_SECRET],
    len: u8,
}

impl Secret {
    /// Builds a secret from `bytes` (which must be ≤ 48 bytes long).
    pub(crate) fn new(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() <= MAX_SECRET);
        let mut buf = [0u8; MAX_SECRET];
        buf[..bytes.len()].copy_from_slice(bytes);
        Secret {
            buf,
            len: bytes.len() as u8,
        }
    }

    /// The secret as a byte slice.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }
}

/// The hash function fixed by the negotiated cipher suite.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HashAlg {
    /// SHA-256 (for `TLS_AES_128_GCM_SHA256`).
    Sha256,
    /// SHA-384 (for `TLS_AES_256_GCM_SHA384`).
    Sha384,
}

impl HashAlg {
    /// The digest output length in bytes.
    pub(crate) fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => 32,
            HashAlg::Sha384 => 48,
        }
    }

    /// `Transcript-Hash(messages)` for the given bytes.
    pub(crate) fn hash(self, messages: &[u8]) -> Secret {
        match self {
            HashAlg::Sha256 => Secret::new(Sha256::digest(messages).as_ref()),
            HashAlg::Sha384 => Secret::new(Sha384::digest(messages).as_ref()),
        }
    }
}

/// HKDF-Expand-Label (RFC 8446 §7.1), generic over the hash.
///
/// ```text
/// struct {
///   uint16 length = out.len();
///   opaque label<7..255> = "tls13 " + Label;
///   opaque context<0..255> = Context;
/// } HkdfLabel;
/// ```
fn expand_label<D: Digest>(secret: &[u8], label: &[u8], context: &[u8], out: &mut [u8]) {
    // RFC 8446 §7.1: HkdfLabel.length is a u16. Every in-tree caller of
    // `expand_label{,_dyn}` allocates `out` into a buffer bounded by a hash
    // output (≤ 48 bytes) or a fixed array (≤ MAX_SECRET = 64 bytes), so
    // this conversion is structurally infallible. Use a checked conversion
    // so a future caller wiring a longer keystream gets a loud panic at the
    // boundary rather than a silent on-wire length truncation that would
    // produce an HKDF stream disagreeing with the peer's (tag-mismatch
    // failure modes that are very hard to debug).
    let label_length = u16::try_from(out.len())
        .expect("HKDF output length must fit in u16 (RFC 8446 §7.1 HkdfLabel.length)");
    let mut info = Vec::with_capacity(4 + 6 + label.len() + context.len());
    info.extend_from_slice(&label_length.to_be_bytes());
    info.push((6 + label.len()) as u8);
    info.extend_from_slice(b"tls13 ");
    info.extend_from_slice(label);
    info.push(context.len() as u8);
    info.extend_from_slice(context);

    // The schedule's secrets are always exactly one hash output long
    // (`Derive-Secret`/`extract` produce a `Secret` of `D::OUTPUT_LEN`), so
    // this PRK copy is exact. Guard the copy defensively: a `copy_from_slice`
    // panics on any length mismatch, and a future caller passing a shorter or
    // longer `secret` should hit a loud debug assertion rather than a release
    // panic. PRECONDITION: `secret.len() == D::OUTPUT_LEN`.
    debug_assert_eq!(
        secret.len(),
        D::OUTPUT_LEN,
        "HKDF-Expand-Label PRK must be exactly one hash output long"
    );
    let mut prk = D::zeroed_output();
    let prk_buf = prk.as_mut();
    let n = core::cmp::min(secret.len(), prk_buf.len());
    prk_buf[..n].copy_from_slice(&secret[..n]);
    hkdf_expand::<D>(&prk, &info, out);
}

/// Runtime HKDF-Expand-Label dispatched on the negotiated hash.
pub(crate) fn expand_label_dyn(
    alg: HashAlg,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) {
    match alg {
        HashAlg::Sha256 => expand_label::<Sha256>(secret, label, context, out),
        HashAlg::Sha384 => expand_label::<Sha384>(secret, label, context, out),
    }
}

/// `Derive-Secret(secret, label, transcript_hash)` — an HKDF-Expand-Label whose
/// context is the transcript hash and whose output is one hash long.
pub(crate) fn derive_secret(
    alg: HashAlg,
    secret: &[u8],
    label: &[u8],
    transcript_hash: &[u8],
) -> Secret {
    let mut out = [0u8; MAX_SECRET];
    let n = alg.output_len();
    expand_label_dyn(alg, secret, label, transcript_hash, &mut out[..n]);
    Secret::new(&out[..n])
}

/// `HKDF-Extract(salt, ikm)` dispatched on the negotiated hash.
pub(crate) fn extract(alg: HashAlg, salt: &[u8], ikm: &[u8]) -> Secret {
    match alg {
        HashAlg::Sha256 => Secret::new(hkdf_extract::<Sha256>(salt, ikm).as_ref()),
        HashAlg::Sha384 => Secret::new(hkdf_extract::<Sha384>(salt, ikm).as_ref()),
    }
}

/// The TLS 1.3 key schedule, carried through the handshake.
///
/// Built at the `ServerHello` boundary (when the suite is known); each method
/// advances the secret chain or derives a leaf secret.
pub(crate) struct KeySchedule {
    alg: HashAlg,
    /// The current chaining secret (early → handshake → master).
    secret: Secret,
}

impl KeySchedule {
    /// Starts the schedule at the Early Secret with no PSK
    /// (`HKDF-Extract(0, 0)`).
    pub(crate) fn new(alg: HashAlg) -> Self {
        let zeros = [0u8; MAX_SECRET];
        let n = alg.output_len();
        let early = extract(alg, &[], &zeros[..n]);
        KeySchedule { alg, secret: early }
    }

    /// Starts the schedule with a pre-shared key (`HKDF-Extract(0, psk)`).
    /// Used by both PSK-only and PSK-with-ECDHE resumption flows.
    pub(crate) fn with_psk(alg: HashAlg, psk: &[u8]) -> Self {
        let early = extract(alg, &[], psk);
        KeySchedule { alg, secret: early }
    }

    /// The current Early Secret (only meaningful right after `new`).
    #[cfg(test)]
    pub(crate) fn early_secret(&self) -> Secret {
        self.secret
    }

    /// `binder_key = Derive-Secret(Early Secret, label, "")` (RFC 8446
    /// §4.2.11.2). `label` is `"res binder"` for resumption PSKs and
    /// `"ext binder"` for external PSKs.
    pub(crate) fn binder_key(&self, label: &[u8]) -> Secret {
        let empty_hash = self.alg.hash(&[]);
        derive_secret(
            self.alg,
            self.secret.as_slice(),
            label,
            empty_hash.as_slice(),
        )
    }

    /// `client_early_traffic_secret` from `Hash(ClientHello)` — used by
    /// 0-RTT writes before ServerHello arrives.
    // Wired in by the 0-RTT commit.
    #[allow(dead_code)]
    pub(crate) fn client_early_traffic_secret(&self, transcript: &[u8]) -> Secret {
        derive_secret(self.alg, self.secret.as_slice(), b"c e traffic", transcript)
    }

    /// Advances Early → Handshake Secret with the (EC)DHE shared secret.
    pub(crate) fn enter_handshake(&mut self, ecdhe: &[u8]) {
        let derived = self.derive_for_next();
        self.secret = extract(self.alg, derived.as_slice(), ecdhe);
    }

    /// Advances Handshake → Master Secret (extract with a zero IKM).
    pub(crate) fn enter_master(&mut self) {
        let derived = self.derive_for_next();
        let zeros = [0u8; MAX_SECRET];
        let n = self.alg.output_len();
        self.secret = extract(self.alg, derived.as_slice(), &zeros[..n]);
    }

    /// `Derive-Secret(current, "derived", "")` — the chaining step between
    /// extracts.
    fn derive_for_next(&self) -> Secret {
        let empty = self.alg.hash(&[]);
        derive_secret(
            self.alg,
            self.secret.as_slice(),
            b"derived",
            empty.as_slice(),
        )
    }

    /// `client_handshake_traffic_secret` from `Hash(CH..SH)`.
    pub(crate) fn client_handshake_traffic_secret(&self, transcript: &[u8]) -> Secret {
        derive_secret(
            self.alg,
            self.secret.as_slice(),
            b"c hs traffic",
            transcript,
        )
    }

    /// `server_handshake_traffic_secret` from `Hash(CH..SH)`.
    pub(crate) fn server_handshake_traffic_secret(&self, transcript: &[u8]) -> Secret {
        derive_secret(
            self.alg,
            self.secret.as_slice(),
            b"s hs traffic",
            transcript,
        )
    }

    /// `client_application_traffic_secret_0` from `Hash(CH..server Finished)`.
    pub(crate) fn client_application_traffic_secret(&self, transcript: &[u8]) -> Secret {
        derive_secret(
            self.alg,
            self.secret.as_slice(),
            b"c ap traffic",
            transcript,
        )
    }

    /// `server_application_traffic_secret_0` from `Hash(CH..server Finished)`.
    pub(crate) fn server_application_traffic_secret(&self, transcript: &[u8]) -> Secret {
        derive_secret(
            self.alg,
            self.secret.as_slice(),
            b"s ap traffic",
            transcript,
        )
    }

    /// `exporter_master_secret` from `Hash(CH..server Finished)` — the seed
    /// for the application-layer [`tls_exporter`] (RFC 8446 §7.5).
    pub(crate) fn exporter_master_secret(&self, transcript: &[u8]) -> Secret {
        derive_secret(self.alg, self.secret.as_slice(), b"exp master", transcript)
    }

    /// `resumption_master_secret` from `Hash(CH..client Finished)` — the
    /// seed for future-session PSKs (RFC 8446 §7.1). The actual PSK is
    /// `HKDF-Expand-Label(rms, "resumption", ticket_nonce, Hash.length)`.
    pub(crate) fn resumption_master_secret(&self, transcript: &[u8]) -> Secret {
        derive_secret(self.alg, self.secret.as_slice(), b"res master", transcript)
    }
}

/// Derives a PSK from a `resumption_master_secret` and a per-ticket nonce.
pub(crate) fn psk_from_resumption(alg: HashAlg, rms: &Secret, ticket_nonce: &[u8], out: &mut [u8]) {
    expand_label_dyn(alg, rms.as_slice(), b"resumption", ticket_nonce, out);
}

/// Derives the per-binder "finished" key used to MAC the truncated
/// ClientHello: `HKDF-Expand-Label(binder_key, "finished", "", Hash.length)`.
pub(crate) fn binder_finished_key(alg: HashAlg, binder_key: &Secret) -> Secret {
    let mut out = [0u8; MAX_SECRET];
    let n = alg.output_len();
    expand_label_dyn(alg, binder_key.as_slice(), b"finished", &[], &mut out[..n]);
    Secret::new(&out[..n])
}

/// RFC 8446 §7.5 TLS-Exporter: derives application-layer keying material
/// from `exporter_master_secret`. Two-step HKDF: first an intermediate
/// `Secret_export`, then the caller-controlled output.
pub(crate) fn tls_exporter(
    alg: HashAlg,
    exporter_master_secret: &Secret,
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) {
    let empty_hash = alg.hash(&[]);
    // Secret_export = HKDF-Expand-Label(EMS, label, Hash(""), Hash.length)
    let mut export = [0u8; MAX_SECRET];
    let n = alg.output_len();
    expand_label_dyn(
        alg,
        exporter_master_secret.as_slice(),
        label,
        empty_hash.as_slice(),
        &mut export[..n],
    );
    // Output = HKDF-Expand-Label(Secret_export, "exporter", Hash(context), L)
    let ctx_hash = alg.hash(context);
    expand_label_dyn(alg, &export[..n], b"exporter", ctx_hash.as_slice(), out);
}

/// Derives `application_traffic_secret_{N+1}` from the previous-generation
/// traffic secret (RFC 8446 §7.2): `HKDF-Expand-Label(prev, "traffic upd",
/// "", Hash.length)`. Used by `KeyUpdate` re-keying.
pub(crate) fn next_traffic_secret(alg: HashAlg, prev: &Secret) -> Secret {
    let mut next = [0u8; MAX_SECRET];
    let n = alg.output_len();
    expand_label_dyn(alg, prev.as_slice(), b"traffic upd", &[], &mut next[..n]);
    Secret::new(&next[..n])
}

/// Derives the AEAD write key and IV from a traffic secret (RFC 8446 §7.3).
pub(crate) fn traffic_key_iv(alg: HashAlg, secret: &Secret, key_len: usize) -> (Vec<u8>, [u8; 12]) {
    let mut key = alloc::vec![0u8; key_len];
    expand_label_dyn(alg, secret.as_slice(), b"key", &[], &mut key);
    let mut iv = [0u8; 12];
    expand_label_dyn(alg, secret.as_slice(), b"iv", &[], &mut iv);
    (key, iv)
}

/// The `finished_key` for a traffic secret (RFC 8446 §4.4.4).
pub(crate) fn finished_key(alg: HashAlg, secret: &Secret) -> Secret {
    let mut out = [0u8; MAX_SECRET];
    let n = alg.output_len();
    expand_label_dyn(alg, secret.as_slice(), b"finished", &[], &mut out[..n]);
    Secret::new(&out[..n])
}

/// The Finished message `verify_data`:
/// `HMAC(finished_key, Transcript-Hash(handshake))` (RFC 8446 §4.4.4).
pub(crate) fn finished_verify_data(
    alg: HashAlg,
    traffic_secret: &Secret,
    transcript_hash: &[u8],
) -> Secret {
    let fk = finished_key(alg, traffic_secret);
    match alg {
        HashAlg::Sha256 => {
            Secret::new(Hmac::<Sha256>::mac(fk.as_slice(), transcript_hash).as_ref())
        }
        HashAlg::Sha384 => {
            Secret::new(Hmac::<Sha384>::mac(fk.as_slice(), transcript_hash).as_ref())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // RFC 8448 §3 "Simple 1-RTT Handshake" key-schedule trace (SHA-256 /
    // TLS_AES_128_GCM_SHA256).
    #[test]
    fn rfc8448_key_schedule() {
        let alg = HashAlg::Sha256;
        let ecdhe =
            from_hex::<32>("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let transcript_ch_sh =
            from_hex::<32>("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");

        let mut ks = KeySchedule::new(alg);

        // Early Secret.
        assert_eq!(
            ks.early_secret().as_slice(),
            &from_hex::<32>("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")[..]
        );

        // Handshake Secret (after the "derived" step + Extract(ECDHE)).
        ks.enter_handshake(&ecdhe);
        assert_eq!(
            ks.secret.as_slice(),
            &from_hex::<32>("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")[..]
        );

        // Handshake traffic secrets.
        let chts = ks.client_handshake_traffic_secret(&transcript_ch_sh);
        let shts = ks.server_handshake_traffic_secret(&transcript_ch_sh);
        assert_eq!(
            chts.as_slice(),
            &from_hex::<32>("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")[..]
        );
        assert_eq!(
            shts.as_slice(),
            &from_hex::<32>("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")[..]
        );

        // Server handshake key/iv (AES-128 → 16-byte key).
        let (skey, siv) = traffic_key_iv(alg, &shts, 16);
        assert_eq!(skey, from_hex::<16>("3fce516009c21727d0f2e4e86ee403bc"));
        assert_eq!(siv, from_hex::<12>("5d313eb2671276ee13000b30"));

        // Client handshake key/iv.
        let (ckey, civ) = traffic_key_iv(alg, &chts, 16);
        assert_eq!(ckey, from_hex::<16>("dbfaa693d1762c5b666af5d950258d01"));
        assert_eq!(civ, from_hex::<12>("5bd3c71b836e0b76bb73265f"));

        // Server finished_key.
        let sfin = finished_key(alg, &shts);
        assert_eq!(
            sfin.as_slice(),
            &from_hex::<32>("008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8")[..]
        );

        // Master Secret.
        ks.enter_master();
        assert_eq!(
            ks.secret.as_slice(),
            &from_hex::<32>("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")[..]
        );
    }

    /// PSK / resumption plumbing self-consistency: with a fixed PSK and
    /// transcript, the derived `binder_key`, `client_early_traffic_secret`,
    /// `resumption_master_secret`, and `psk_from_resumption` are all
    /// deterministic and distinct.
    #[test]
    fn psk_resumption_plumbing_self_consistent() {
        let alg = HashAlg::Sha256;
        let psk = [0x42u8; 32];
        let transcript_ch = [0xa1u8; 32];
        let transcript_ch_cf = [0xb2u8; 32];

        let mut ks = KeySchedule::with_psk(alg, &psk);

        // Binder keys differ for resumption vs external PSKs.
        let res_bk = ks.binder_key(b"res binder");
        let ext_bk = ks.binder_key(b"ext binder");
        assert_ne!(res_bk.as_slice(), ext_bk.as_slice());

        // `binder_finished_key` derives a different secret again.
        let bfk = binder_finished_key(alg, &res_bk);
        assert_ne!(bfk.as_slice(), res_bk.as_slice());

        // client_early_traffic_secret over Hash(CH).
        let cets = ks.client_early_traffic_secret(&transcript_ch);
        assert_ne!(cets.as_slice(), res_bk.as_slice());

        // Advance through the normal handshake (ECDHE = zeros for the test).
        ks.enter_handshake(&[0u8; 32]);
        ks.enter_master();

        // resumption_master_secret over Hash(CH..client Finished).
        let rms = ks.resumption_master_secret(&transcript_ch_cf);

        // Derive a per-ticket PSK from RMS with a known nonce.
        let mut psk_out = [0u8; 32];
        psk_from_resumption(alg, &rms, &[1, 2, 3, 4], &mut psk_out);
        // Same nonce -> same PSK; different nonce -> different PSK.
        let mut psk_out2 = [0u8; 32];
        psk_from_resumption(alg, &rms, &[1, 2, 3, 4], &mut psk_out2);
        assert_eq!(psk_out, psk_out2);
        let mut psk_other = [0u8; 32];
        psk_from_resumption(alg, &rms, &[1, 2, 3, 5], &mut psk_other);
        assert_ne!(psk_out, psk_other);
    }
}
