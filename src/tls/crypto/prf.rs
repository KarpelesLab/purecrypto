//! TLS 1.2 PRF (RFC 5246 §5).
//!
//! The TLS 1.2 PRF is built on HMAC of the negotiated handshake hash:
//!
//! ```text
//! P_hash(secret, seed) = HMAC(secret, A(1) || seed) ||
//!                        HMAC(secret, A(2) || seed) || ...
//! A(0) = seed
//! A(i) = HMAC(secret, A(i-1))
//!
//! PRF(secret, label, seed) = P_hash(secret, label || seed)
//! ```
//!
//! The hash is fixed by the cipher suite: SHA-256 for the AEAD-with-SHA256
//! suites and SHA-384 for the SHA384 ones. SHA-1 / MD5 PRFs from TLS 1.0/1.1
//! are not implemented — we only ever negotiate TLS 1.2 AEAD suites.
//!
//! This module is the building block for the TLS 1.2 handshake's master
//! secret derivation, `key_block` expansion (writing the read/write keys and
//! salts for `RecordCrypter12`), and Finished `verify_data`.

use super::schedule::HashAlg;
use crate::hash::{Digest, Hmac, Sha256, Sha384};

/// Runs `P_hash` for one digest `D`, writing exactly `out.len()` bytes.
///
/// `P_hash(secret, seed) = HMAC(secret, A(1) || seed) || HMAC(secret,
/// A(2) || seed) || …` where `A(0) = seed`, `A(i) = HMAC(secret, A(i-1))`.
fn p_hash_impl<D: Digest>(secret: &[u8], seed: &[u8], out: &mut [u8]) {
    // A(1) = HMAC(secret, seed)
    let mut a = Hmac::<D>::new(secret).chain(seed).finalize();
    let mut written = 0usize;
    while written < out.len() {
        // HMAC(secret, A(i) || seed) gives one block of output.
        let block = Hmac::<D>::new(secret)
            .chain(a.as_ref())
            .chain(seed)
            .finalize();
        let take = (out.len() - written).min(block.as_ref().len());
        out[written..written + take].copy_from_slice(&block.as_ref()[..take]);
        written += take;
        if written >= out.len() {
            break;
        }
        // A(i+1) = HMAC(secret, A(i))
        a = Hmac::<D>::new(secret).chain(a.as_ref()).finalize();
    }
}

/// `P_hash(secret, seed)` dispatched on the negotiated hash, writing exactly
/// `out.len()` bytes.
#[allow(dead_code)]
pub(crate) fn p_hash(hash: HashAlg, secret: &[u8], seed: &[u8], out: &mut [u8]) {
    match hash {
        HashAlg::Sha256 => p_hash_impl::<Sha256>(secret, seed, out),
        HashAlg::Sha384 => p_hash_impl::<Sha384>(secret, seed, out),
    }
}

/// `PRF(secret, label, seed) = P_hash(secret, label || seed)` (RFC 5246 §5).
///
/// `out.len()` bytes are written; callers size the buffer to what they need
/// (48 bytes for the master secret, the key-block size for key expansion,
/// 12 bytes for Finished verify_data).
#[allow(dead_code)]
pub(crate) fn prf(hash: HashAlg, secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    // Build label || seed in a contiguous buffer. The labels we use ("master
    // secret", "key expansion", "client finished", "server finished") are all
    // short, and the seeds are at most 64 bytes (two 32-byte randoms) or 48
    // bytes (a SHA-384 transcript hash). A single heap allocation is fine.
    let mut combined = alloc::vec::Vec::with_capacity(label.len() + seed.len());
    combined.extend_from_slice(label);
    combined.extend_from_slice(seed);
    p_hash(hash, secret, &combined, out);
}

/// Derives the 48-byte `master_secret` (RFC 5246 §8.1):
///
/// ```text
/// master_secret = PRF(pre_master_secret, "master secret",
///                     client_random || server_random)[0..48]
/// ```
///
/// This is the classic derivation; extended master secret (RFC 7627) is a
/// separate computation and is not implemented here.
#[allow(dead_code)]
pub(crate) fn master_secret(
    hash: HashAlg,
    premaster: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);
    let mut out = [0u8; 48];
    prf(hash, premaster, b"master secret", &seed, &mut out);
    out
}

/// RFC 7627 §4 — Extended Master Secret derivation.
///
/// ```text
/// master_secret = PRF(pre_master_secret, "extended master secret",
///                     session_hash)[0..48]
/// ```
///
/// where `session_hash = Hash(handshake_messages from ClientHello up to and
/// including ClientKeyExchange)` using the negotiated PRF hash. This binds
/// the master secret to the full handshake transcript, closing the Triple
/// Handshake attack class.
#[allow(dead_code)]
pub(crate) fn extended_master_secret(
    hash: HashAlg,
    premaster: &[u8],
    session_hash: &[u8],
) -> [u8; 48] {
    let mut out = [0u8; 48];
    prf(
        hash,
        premaster,
        b"extended master secret",
        session_hash,
        &mut out,
    );
    out
}

/// Derives the `key_block` (RFC 5246 §6.3):
///
/// ```text
/// key_block = PRF(master_secret, "key expansion",
///                 server_random || client_random)
/// ```
///
/// Note the seed order is `server_random || client_random` — the opposite of
/// `master_secret`. `out.len()` is the total number of key-block bytes the
/// caller wants; for our AEAD-only suites that is `2 * (key_len + 4)` (two
/// AEAD keys + two 4-byte implicit-nonce salts).
#[allow(dead_code)]
pub(crate) fn key_block(
    hash: HashAlg,
    master: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    out: &mut [u8],
) {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);
    prf(hash, master, b"key expansion", &seed, out);
}

/// RFC 5705 §4 — TLS 1.2 exporter: derives application-layer keying material
/// from the negotiated master secret.
///
/// ```text
///   without context: PRF(master_secret, label, client_random ‖ server_random)
///   with    context: PRF(master_secret, label, client_random ‖ server_random ‖
///                        uint16(len(context)) ‖ context)
/// ```
///
/// The two branches produce different outputs even when `context = Some(&[])`
/// — supplying an empty context is *not* equivalent to omitting it (RFC 5705
/// §4). `context = None` matches openssl's `SSL_export_keying_material` with
/// `use_context = 0`; `context = Some(_)` matches `use_context = 1`. Modern
/// over-TLS protocols (DTLS-SRTP, EAP-TLS, IEEE 802.1AR, …) use the
/// with-context form.
///
/// Label validation is left to the caller; RFC 5705 §6 forbids the
/// handshake-internal labels (`"client finished"`, `"server finished"`,
/// `"master secret"`, `"key expansion"`, `"extended master secret"`).
#[allow(dead_code)]
pub(crate) fn tls12_exporter(
    hash: HashAlg,
    master: &[u8; 48],
    label: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    context: Option<&[u8]>,
    out: &mut [u8],
) {
    // seed = client_random ‖ server_random [‖ uint16(len(context)) ‖ context]
    let extra = match context {
        Some(c) => 2 + c.len(),
        None => 0,
    };
    let mut seed = alloc::vec::Vec::with_capacity(64 + extra);
    seed.extend_from_slice(client_random);
    seed.extend_from_slice(server_random);
    if let Some(c) = context {
        let len = c.len() as u16;
        seed.extend_from_slice(&len.to_be_bytes());
        seed.extend_from_slice(c);
    }
    prf(hash, master, label, &seed, out);
}

/// Computes a TLS 1.2 Finished `verify_data` (RFC 5246 §7.4.9):
///
/// ```text
/// verify_data = PRF(master_secret, finished_label,
///                   Hash(handshake_messages))[0..12]
/// ```
///
/// `label` is `"client finished"` for the client's Finished message and
/// `"server finished"` for the server's. The transcript hash is the full
/// concatenation of every handshake message exchanged up to (but not
/// including) the Finished being produced.
#[allow(dead_code)]
pub(crate) fn finished_verify_data(
    hash: HashAlg,
    master: &[u8; 48],
    label: &[u8],
    transcript_hash: &[u8],
) -> [u8; 12] {
    let mut out = [0u8; 12];
    prf(hash, master, label, transcript_hash, &mut out);
    out
}

/// TLS 1.0 / 1.1 PRF (RFC 2246 §5 / RFC 4346 §5).
///
/// ```text
/// PRF(secret, label, seed) = P_MD5 (S1, label || seed)
///                          XOR P_SHA1(S2, label || seed)
/// ```
///
/// where the secret is split into two halves `S1 || S2`, each `ceil(len/2)`
/// bytes (so they overlap by one byte when the length is odd). MD5 and SHA-1
/// are both cryptographically broken; this exists only for legacy interop and
/// is gated behind `tls-legacy`.
#[cfg(feature = "tls-legacy")]
#[allow(dead_code)] // wired up in the legacy handshake (Phase 4)
pub(crate) fn prf_legacy(secret: &[u8], label: &[u8], seed: &[u8], out: &mut [u8]) {
    use crate::hash::{Md5, Sha1};
    let half = secret.len().div_ceil(2);
    let s1 = &secret[..half];
    let s2 = &secret[secret.len() - half..];

    let mut combined = alloc::vec::Vec::with_capacity(label.len() + seed.len());
    combined.extend_from_slice(label);
    combined.extend_from_slice(seed);

    // P_SHA1 into `out`, P_MD5 into a scratch buffer, then XOR them together.
    let mut md5 = alloc::vec![0u8; out.len()];
    p_hash_impl::<Md5>(s1, &combined, &mut md5);
    p_hash_impl::<Sha1>(s2, &combined, out);
    for (o, m) in out.iter_mut().zip(md5.iter()) {
        *o ^= *m;
    }
}

/// TLS 1.0/1.1 `master_secret` (RFC 2246 §8.1) using the legacy PRF.
#[cfg(feature = "tls-legacy")]
#[allow(dead_code)] // wired up in the legacy handshake (Phase 4)
pub(crate) fn master_secret_legacy(
    premaster: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(client_random);
    seed[32..].copy_from_slice(server_random);
    let mut out = [0u8; 48];
    prf_legacy(premaster, b"master secret", &seed, &mut out);
    out
}

/// TLS 1.0/1.1 `key_block` (RFC 2246 §6.3) using the legacy PRF. Seed order is
/// `server_random || client_random`.
#[cfg(feature = "tls-legacy")]
#[allow(dead_code)] // wired up in the legacy handshake (Phase 4)
pub(crate) fn key_block_legacy(
    master: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    out: &mut [u8],
) {
    let mut seed = [0u8; 64];
    seed[..32].copy_from_slice(server_random);
    seed[32..].copy_from_slice(client_random);
    prf_legacy(master, b"key expansion", &seed, out);
}

/// TLS 1.0/1.1 Finished `verify_data` (RFC 2246 §7.4.9): 12 bytes of
/// `PRF(master, label, MD5(transcript) || SHA1(transcript))`. The caller passes
/// the 36-byte `MD5 || SHA1` transcript hash as `md5_sha1_seed`.
#[cfg(feature = "tls-legacy")]
#[allow(dead_code)] // wired up in the legacy handshake (Phase 4)
pub(crate) fn finished_verify_data_legacy(
    master: &[u8; 48],
    label: &[u8],
    md5_sha1_seed: &[u8],
) -> [u8; 12] {
    let mut out = [0u8; 12];
    prf_legacy(master, label, md5_sha1_seed, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `master_secret` is deterministic, returns exactly 48 bytes, and a
    /// changed premaster shifts the output.
    #[test]
    fn master_secret_deterministic_and_48_bytes() {
        let premaster = [0x42u8; 48];
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];

        let ms1 = master_secret(HashAlg::Sha256, &premaster, &cr, &sr);
        let ms2 = master_secret(HashAlg::Sha256, &premaster, &cr, &sr);
        assert_eq!(ms1, ms2, "master_secret must be deterministic");
        assert_eq!(ms1.len(), 48);

        // Different premaster -> different secret.
        let other_pm = [0x43u8; 48];
        let ms3 = master_secret(HashAlg::Sha256, &other_pm, &cr, &sr);
        assert_ne!(ms1, ms3);

        // Swapping client_random and server_random changes the result (the
        // master-secret seed is cr||sr, so order matters).
        let ms4 = master_secret(HashAlg::Sha256, &premaster, &sr, &cr);
        assert_ne!(ms1, ms4);

        // SHA-384 dispatch gives a different (still 48-byte) value.
        let ms_sha384 = master_secret(HashAlg::Sha384, &premaster, &cr, &sr);
        assert_ne!(ms1, ms_sha384);
    }

    /// `extended_master_secret` is deterministic, 48 bytes, and differs from
    /// the legacy `master_secret` for the same premaster (RFC 7627 §4).
    #[test]
    fn extended_master_secret_differs_from_legacy() {
        let premaster = [0x42u8; 48];
        // 32-byte SHA-256 session hash.
        let session_hash = [0xa5u8; 32];

        let ems1 = extended_master_secret(HashAlg::Sha256, &premaster, &session_hash);
        let ems2 = extended_master_secret(HashAlg::Sha256, &premaster, &session_hash);
        assert_eq!(ems1, ems2, "EMS must be deterministic");
        assert_eq!(ems1.len(), 48);

        // A different session_hash flips the output.
        let mut other = session_hash;
        other[0] ^= 1;
        let ems3 = extended_master_secret(HashAlg::Sha256, &premaster, &other);
        assert_ne!(ems1, ems3);

        // Legacy and EMS derivations must differ for the same inputs that
        // happen to map onto each other (cr||sr = 64B; we just compare label
        // separation — the labels are different so the PRF streams diverge).
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];
        let legacy = master_secret(HashAlg::Sha256, &premaster, &cr, &sr);
        // Use a 48-byte SHA-384 session hash for a sanity check across hashes.
        let ems_sha384 = extended_master_secret(HashAlg::Sha384, &premaster, &[0xa5u8; 48]);
        assert_ne!(ems1, legacy);
        assert_ne!(ems1, ems_sha384);
    }

    /// `finished_verify_data` is exactly 12 bytes and depends on its inputs.
    #[test]
    fn finished_verify_data_is_12_bytes() {
        let master = [0x55u8; 48];
        let transcript = [0xaau8; 32];

        let vd_client =
            finished_verify_data(HashAlg::Sha256, &master, b"client finished", &transcript);
        let vd_server =
            finished_verify_data(HashAlg::Sha256, &master, b"server finished", &transcript);
        assert_eq!(vd_client.len(), 12);
        assert_eq!(vd_server.len(), 12);
        // Different labels must produce different verify_data.
        assert_ne!(vd_client, vd_server);

        // Deterministic.
        let vd_client_again =
            finished_verify_data(HashAlg::Sha256, &master, b"client finished", &transcript);
        assert_eq!(vd_client, vd_client_again);

        // A changed transcript flips the output.
        let mut transcript2 = transcript;
        transcript2[0] ^= 1;
        let vd_other =
            finished_verify_data(HashAlg::Sha256, &master, b"client finished", &transcript2);
        assert_ne!(vd_client, vd_other);
    }

    /// `key_block` expands to the requested number of bytes deterministically,
    /// and the seed order is `server_random || client_random` (opposite of
    /// `master_secret`).
    #[test]
    fn key_block_expansion() {
        let master = [0x33u8; 48];
        let cr = [0x77u8; 32];
        let sr = [0x88u8; 32];

        let mut kb1 = [0u8; 40];
        key_block(HashAlg::Sha256, &master, &sr, &cr, &mut kb1);
        let mut kb2 = [0u8; 40];
        key_block(HashAlg::Sha256, &master, &sr, &cr, &mut kb2);
        assert_eq!(kb1, kb2);

        // Swapping sr and cr changes the result.
        let mut kb3 = [0u8; 40];
        key_block(HashAlg::Sha256, &master, &cr, &sr, &mut kb3);
        assert_ne!(kb1, kb3);

        // Longer expansion is a prefix-extension of the shorter call (since
        // both invocations start with the same A(1) chain).
        let mut kb_long = [0u8; 80];
        key_block(HashAlg::Sha256, &master, &sr, &cr, &mut kb_long);
        assert_eq!(&kb_long[..40], &kb1[..]);

        // SHA-384 path produces a different stream.
        let mut kb_sha384 = [0u8; 40];
        key_block(HashAlg::Sha384, &master, &sr, &cr, &mut kb_sha384);
        assert_ne!(kb1, kb_sha384);
    }

    /// RFC 5705 §4 — exporter output is deterministic, length-flexible, and
    /// the with-context / without-context branches produce distinct streams
    /// even for an empty context.
    #[test]
    fn tls12_exporter_branches_and_determinism() {
        let master = [0x42u8; 48];
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];

        // Determinism + length flexibility.
        let mut a = [0u8; 32];
        tls12_exporter(
            HashAlg::Sha256,
            &master,
            b"EXPERIMENTAL-test",
            &cr,
            &sr,
            None,
            &mut a,
        );
        let mut b = [0u8; 32];
        tls12_exporter(
            HashAlg::Sha256,
            &master,
            b"EXPERIMENTAL-test",
            &cr,
            &sr,
            None,
            &mut b,
        );
        assert_eq!(a, b);
        let mut long = [0u8; 80];
        tls12_exporter(
            HashAlg::Sha256,
            &master,
            b"EXPERIMENTAL-test",
            &cr,
            &sr,
            None,
            &mut long,
        );
        // Prefix-extension property of P_hash.
        assert_eq!(&long[..32], &a[..]);

        // Different labels diverge.
        let mut other_label = [0u8; 32];
        tls12_exporter(
            HashAlg::Sha256,
            &master,
            b"EXPERIMENTAL-other",
            &cr,
            &sr,
            None,
            &mut other_label,
        );
        assert_ne!(a, other_label);

        // RFC 5705 §4: `None` vs `Some(&[])` MUST differ (the latter adds the
        // 2-byte zero length to the seed).
        let mut no_ctx = [0u8; 32];
        let mut empty_ctx = [0u8; 32];
        tls12_exporter(
            HashAlg::Sha256,
            &master,
            b"EXPERIMENTAL-test",
            &cr,
            &sr,
            None,
            &mut no_ctx,
        );
        tls12_exporter(
            HashAlg::Sha256,
            &master,
            b"EXPERIMENTAL-test",
            &cr,
            &sr,
            Some(&[]),
            &mut empty_ctx,
        );
        assert_ne!(
            no_ctx, empty_ctx,
            "empty-context branch must differ from no-context branch"
        );

        // Distinct contexts diverge.
        let mut ctx1 = [0u8; 32];
        let mut ctx2 = [0u8; 32];
        tls12_exporter(
            HashAlg::Sha256,
            &master,
            b"EXPERIMENTAL-test",
            &cr,
            &sr,
            Some(b"alpha"),
            &mut ctx1,
        );
        tls12_exporter(
            HashAlg::Sha256,
            &master,
            b"EXPERIMENTAL-test",
            &cr,
            &sr,
            Some(b"beta"),
            &mut ctx2,
        );
        assert_ne!(ctx1, ctx2);

        // Hash dispatch covers SHA-384.
        let mut sha384 = [0u8; 32];
        tls12_exporter(
            HashAlg::Sha384,
            &master,
            b"EXPERIMENTAL-test",
            &cr,
            &sr,
            None,
            &mut sha384,
        );
        assert_ne!(a, sha384);
    }

    /// `P_hash` self-consistency: two calls with the same inputs match, and
    /// the output streams of two different output lengths share the prefix.
    #[test]
    fn p_hash_prefix_extension() {
        let secret = b"secret";
        let seed = b"seed-bytes";
        let mut short = [0u8; 16];
        let mut long = [0u8; 64];
        p_hash(HashAlg::Sha256, secret, seed, &mut short);
        p_hash(HashAlg::Sha256, secret, seed, &mut long);
        assert_eq!(&long[..16], &short[..]);

        let mut short_sha384 = [0u8; 16];
        p_hash(HashAlg::Sha384, secret, seed, &mut short_sha384);
        assert_ne!(short, short_sha384);
    }

    /// TLS 1.0/1.1 PRF (`P_MD5 ⊕ P_SHA1`) against an independent Python
    /// `hmac`+`hashlib` reference. The 13-byte (odd-length) secret exercises the
    /// one-byte overlap of the two secret halves.
    #[cfg(feature = "tls-legacy")]
    #[test]
    fn prf_legacy_known_answer() {
        let secret = [
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, // odd length → halves overlap
        ];
        let seed = [0xaau8; 16];
        let mut out = [0u8; 32];
        prf_legacy(&secret, b"test label", &seed, &mut out);
        let expected = [
            0x17, 0x6c, 0x29, 0x12, 0x66, 0xfb, 0x5e, 0xba, 0x61, 0xf1, 0x3f, 0xfb, 0xd7, 0x07,
            0xeb, 0x0d, 0xdd, 0x55, 0xe9, 0xb9, 0x9e, 0xcd, 0xd5, 0x3b, 0x6d, 0x51, 0x5d, 0xe6,
            0xd4, 0x69, 0x34, 0xd7,
        ];
        assert_eq!(out, expected);

        // master_secret_legacy against the same reference.
        let ms = master_secret_legacy(&[0x42u8; 48], &[0x11u8; 32], &[0x22u8; 32]);
        let ms_expected = [
            0x32, 0x62, 0xd9, 0x1d, 0x8c, 0xc8, 0x75, 0xa4, 0x9b, 0x09, 0x20, 0x26, 0xc1, 0x9e,
            0xe4, 0x7d, 0x09, 0xa5, 0x07, 0xa5, 0xcf, 0x5d, 0xc5, 0x02, 0x09, 0x64, 0x64, 0x12,
            0x48, 0x48, 0xf7, 0xf3, 0x22, 0xa2, 0x9e, 0x26, 0x56, 0xaa, 0x91, 0xd4, 0xa2, 0x70,
            0x8f, 0xee, 0x8e, 0xf3, 0x7b, 0x8b,
        ];
        assert_eq!(ms, ms_expected);
    }

    /// Legacy PRF structural properties: deterministic, prefix-extension, and
    /// the secret split actually uses both halves.
    #[cfg(feature = "tls-legacy")]
    #[test]
    fn prf_legacy_structure() {
        let secret = [0x9bu8; 20];
        let seed = [0x33u8; 24];
        let mut a = [0u8; 48];
        let mut b = [0u8; 48];
        prf_legacy(&secret, b"key expansion", &seed, &mut a);
        prf_legacy(&secret, b"key expansion", &seed, &mut b);
        assert_eq!(a, b, "deterministic");
        let mut long = [0u8; 96];
        prf_legacy(&secret, b"key expansion", &seed, &mut long);
        assert_eq!(&long[..48], &a[..], "prefix-extension");
        // Flipping a byte in the *second* half of the secret changes the output
        // (proves P_SHA1 over S2 contributes).
        let mut s2 = secret;
        s2[19] ^= 1;
        let mut c = [0u8; 48];
        prf_legacy(&s2, b"key expansion", &seed, &mut c);
        assert_ne!(a, c);
    }

    /// Cross-check: `prf(secret, label, seed)` is `p_hash(secret, label||seed)`.
    #[test]
    fn prf_equals_p_hash_of_label_concat_seed() {
        let secret = b"secret";
        let label = b"master secret";
        let seed = [0x99u8; 64];

        let mut via_prf = [0u8; 48];
        prf(HashAlg::Sha256, secret, label, &seed, &mut via_prf);

        let mut combined = alloc::vec::Vec::with_capacity(label.len() + seed.len());
        combined.extend_from_slice(label);
        combined.extend_from_slice(&seed);
        let mut via_p_hash = [0u8; 48];
        p_hash(HashAlg::Sha256, secret, &combined, &mut via_p_hash);

        assert_eq!(via_prf, via_p_hash);
    }
}
