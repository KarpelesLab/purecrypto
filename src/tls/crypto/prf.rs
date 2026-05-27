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
