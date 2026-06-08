//! SSL 3.0 cryptographic profile (RFC 6101 §6 + §5.6.9), opt-in via
//! `tls-legacy`.
//!
//! SSL 3.0 predates HMAC and the TLS PRF, so it derives keys and authenticates
//! records with ad-hoc MD5/SHA-1 cascades:
//!
//! * **MAC** — `hash(secret ‖ pad2 ‖ hash(secret ‖ pad1 ‖ seq ‖ type ‖ len ‖
//!   data))`, with `pad1 = 0x36·n`, `pad2 = 0x5c·n` (`n` = 48 for MD5, 40 for
//!   SHA-1). Note there is **no version byte** in the MAC input (unlike TLS).
//! * **Key derivation** — `master_secret` and `key_block` are MD5-of-SHA
//!   cascades salted with `"A"`, `"BB"`, `"CCC"`, … rather than a PRF.
//! * **Finished** — `MD5(master ‖ pad2 ‖ MD5(handshake ‖ Sender ‖ master ‖
//!   pad1)) ‖ SHA(master ‖ pad2 ‖ SHA(handshake ‖ Sender ‖ master ‖ pad1))`,
//!   a 36-byte value (not the 12-byte TLS `verify_data`).
//!
//! # Security
//!
//! SSL 3.0 is comprehensively broken — most importantly **POODLE**
//! (CVE-2014-3566): its CBC padding bytes are unauthenticated and may hold any
//! value, so the constant-time padding checks that protect TLS 1.0+ cannot be
//! applied. This profile exists purely to interoperate with ancient devices
//! that speak nothing newer, is gated off by default, and must never be exposed
//! where an adversary can replay records against a chosen-plaintext oracle.
//! Prefer TLS 1.2+ AEAD whenever the peer supports it.

#![allow(dead_code)]

use crate::hash::{Digest, Md5, Sha1};
use crate::tls::ContentType;
use alloc::vec::Vec;

/// `pad1`/`pad2` repetition count for each hash (RFC 6101 §5.2.3.1).
const MD5_PAD_LEN: usize = 48;
const SHA_PAD_LEN: usize = 40;

/// Finished `Sender` constants (RFC 6101 §5.6.9).
pub(crate) const SENDER_CLIENT: [u8; 4] = [0x43, 0x4c, 0x4e, 0x54]; // "CLNT"
pub(crate) const SENDER_SERVER: [u8; 4] = [0x53, 0x52, 0x56, 0x52]; // "SRVR"

/// The `i`-th key-expansion salt: the `(i+1)`-th uppercase letter repeated
/// `i+1` times (`"A"`, `"BB"`, `"CCC"`, …). SSL 3.0 caps derivations well
/// before the alphabet runs out.
fn salt(i: usize) -> Vec<u8> {
    let letter = b'A' + (i as u8);
    alloc::vec![letter; i + 1]
}

/// One MD5-of-SHA cascade block (RFC 6101 §6.1):
/// `MD5(secret ‖ SHA(salt ‖ secret ‖ rand_a ‖ rand_b))`.
fn cascade_block(secret: &[u8], salt: &[u8], rand_a: &[u8; 32], rand_b: &[u8; 32]) -> [u8; 16] {
    let mut inner = Sha1::new();
    inner.update(salt);
    inner.update(secret);
    inner.update(rand_a);
    inner.update(rand_b);
    let inner = inner.finalize();
    let mut outer = Md5::new();
    outer.update(secret);
    outer.update(inner.as_ref());
    let mut out = [0u8; 16];
    out.copy_from_slice(outer.finalize().as_ref());
    out
}

/// SSL 3.0 `master_secret` (RFC 6101 §6.1): three cascade blocks salted
/// `"A"`/`"BB"`/`"CCC"`, with the randoms in client-then-server order.
pub(crate) fn ssl3_master_secret(
    premaster: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> [u8; 48] {
    let mut out = [0u8; 48];
    for i in 0..3 {
        let block = cascade_block(premaster, &salt(i), client_random, server_random);
        out[i * 16..i * 16 + 16].copy_from_slice(&block);
    }
    out
}

/// SSL 3.0 `key_block` (RFC 6101 §6.2.2): the same cascade, keyed by the master
/// secret with the randoms in **server-then-client** order, emitting as many
/// 16-byte blocks as needed to fill `out`.
pub(crate) fn ssl3_key_block(
    master: &[u8; 48],
    server_random: &[u8; 32],
    client_random: &[u8; 32],
    out: &mut [u8],
) {
    let mut written = 0;
    let mut i = 0;
    while written < out.len() {
        let block = cascade_block(master, &salt(i), server_random, client_random);
        let n = core::cmp::min(16, out.len() - written);
        out[written..written + n].copy_from_slice(&block[..n]);
        written += n;
        i += 1;
    }
}

/// Which digest an SSL 3.0 CBC suite uses for its record MAC and Finished.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ssl3Mac {
    Md5,
    Sha1,
}

impl Ssl3Mac {
    /// MAC output length (16 for MD5, 20 for SHA-1).
    pub(crate) fn len(self) -> usize {
        match self {
            Ssl3Mac::Md5 => 16,
            Ssl3Mac::Sha1 => 20,
        }
    }
    /// `pad1`/`pad2` repetition count.
    fn pad_len(self) -> usize {
        match self {
            Ssl3Mac::Md5 => MD5_PAD_LEN,
            Ssl3Mac::Sha1 => SHA_PAD_LEN,
        }
    }
}

/// SSL 3.0 record MAC (RFC 6101 §5.2.3.1):
/// `hash(secret ‖ pad2 ‖ hash(secret ‖ pad1 ‖ seq ‖ type ‖ len ‖ content))`.
/// The MAC input carries **no protocol version**.
pub(crate) fn ssl3_record_mac(
    mac: Ssl3Mac,
    secret: &[u8],
    seq: u64,
    ct: ContentType,
    content: &[u8],
) -> Vec<u8> {
    let pad1 = alloc::vec![0x36u8; mac.pad_len()];
    let pad2 = alloc::vec![0x5cu8; mac.pad_len()];
    let mut header = [0u8; 11];
    header[..8].copy_from_slice(&seq.to_be_bytes());
    header[8] = ct.as_u8();
    header[9..11].copy_from_slice(&(content.len() as u16).to_be_bytes());
    match mac {
        Ssl3Mac::Md5 => {
            let mut inner = Md5::new();
            inner.update(secret);
            inner.update(&pad1);
            inner.update(&header);
            inner.update(content);
            let inner = inner.finalize();
            let mut outer = Md5::new();
            outer.update(secret);
            outer.update(&pad2);
            outer.update(inner.as_ref());
            outer.finalize().as_ref().to_vec()
        }
        Ssl3Mac::Sha1 => {
            let mut inner = Sha1::new();
            inner.update(secret);
            inner.update(&pad1);
            inner.update(&header);
            inner.update(content);
            let inner = inner.finalize();
            let mut outer = Sha1::new();
            outer.update(secret);
            outer.update(&pad2);
            outer.update(inner.as_ref());
            outer.finalize().as_ref().to_vec()
        }
    }
}

/// One half of the SSL 3.0 Finished (RFC 6101 §5.6.9), for a single hash:
/// `hash(master ‖ pad2 ‖ hash(handshake ‖ sender ‖ master ‖ pad1))`.
fn finished_half_md5(handshake: &[u8], sender: &[u8; 4], master: &[u8; 48]) -> [u8; 16] {
    let pad1 = [0x36u8; MD5_PAD_LEN];
    let pad2 = [0x5cu8; MD5_PAD_LEN];
    let mut inner = Md5::new();
    inner.update(handshake);
    inner.update(sender);
    inner.update(master);
    inner.update(&pad1);
    let inner = inner.finalize();
    let mut outer = Md5::new();
    outer.update(master);
    outer.update(&pad2);
    outer.update(inner.as_ref());
    let mut out = [0u8; 16];
    out.copy_from_slice(outer.finalize().as_ref());
    out
}

fn finished_half_sha1(handshake: &[u8], sender: &[u8; 4], master: &[u8; 48]) -> [u8; 20] {
    let pad1 = [0x36u8; SHA_PAD_LEN];
    let pad2 = [0x5cu8; SHA_PAD_LEN];
    let mut inner = Sha1::new();
    inner.update(handshake);
    inner.update(sender);
    inner.update(master);
    inner.update(&pad1);
    let inner = inner.finalize();
    let mut outer = Sha1::new();
    outer.update(master);
    outer.update(&pad2);
    outer.update(inner.as_ref());
    let mut out = [0u8; 20];
    out.copy_from_slice(outer.finalize().as_ref());
    out
}

/// SSL 3.0 Finished `verify_data` (36 bytes): the MD5 half followed by the
/// SHA-1 half, over all `handshake` messages so far plus the role `sender`.
pub(crate) fn ssl3_finished(handshake: &[u8], sender: &[u8; 4], master: &[u8; 48]) -> [u8; 36] {
    let mut out = [0u8; 36];
    out[..16].copy_from_slice(&finished_half_md5(handshake, sender, master));
    out[16..].copy_from_slice(&finished_half_sha1(handshake, sender, master));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salts_grow() {
        assert_eq!(salt(0), b"A");
        assert_eq!(salt(1), b"BB");
        assert_eq!(salt(2), b"CCC");
    }

    #[test]
    fn master_secret_is_48_and_deterministic() {
        let pm = [0x11u8; 48];
        let cr = [0x22u8; 32];
        let sr = [0x33u8; 32];
        let m1 = ssl3_master_secret(&pm, &cr, &sr);
        let m2 = ssl3_master_secret(&pm, &cr, &sr);
        assert_eq!(m1, m2);
        // Swapping the randoms changes the secret (order matters).
        let m3 = ssl3_master_secret(&pm, &sr, &cr);
        assert_ne!(m1, m3);
    }

    #[test]
    fn key_block_fills_and_chains() {
        let master = [0x44u8; 48];
        let cr = [0x55u8; 32];
        let sr = [0x66u8; 32];
        let mut kb = [0u8; 72]; // spans 5 cascade blocks (16 each)
        ssl3_key_block(&master, &sr, &cr, &mut kb);
        // First 16 bytes equal the first cascade block exactly.
        let first = cascade_block(&master, b"A", &sr, &cr);
        assert_eq!(&kb[..16], &first);
        // Output is not all-zero (the tail was filled).
        assert!(kb[64..].iter().any(|&b| b != 0));
    }

    #[test]
    fn record_mac_lengths_and_seq_sensitivity() {
        let secret = [0x77u8; 20];
        let a = ssl3_record_mac(
            Ssl3Mac::Sha1,
            &secret,
            0,
            ContentType::ApplicationData,
            b"hi",
        );
        let b = ssl3_record_mac(
            Ssl3Mac::Sha1,
            &secret,
            1,
            ContentType::ApplicationData,
            b"hi",
        );
        assert_eq!(a.len(), 20);
        assert_ne!(a, b, "sequence number must enter the MAC");
        let m = ssl3_record_mac(
            Ssl3Mac::Md5,
            &[0x77u8; 16],
            0,
            ContentType::Handshake,
            b"hi",
        );
        assert_eq!(m.len(), 16);
    }

    #[test]
    fn finished_differs_by_sender() {
        let master = [0x88u8; 48];
        let hs = b"handshake transcript bytes";
        let c = ssl3_finished(hs, &SENDER_CLIENT, &master);
        let s = ssl3_finished(hs, &SENDER_SERVER, &master);
        assert_ne!(c, s, "client and server Finished must differ");
        assert_eq!(c.len(), 36);
    }
}
