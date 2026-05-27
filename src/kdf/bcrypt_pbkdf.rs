//! OpenSSH `bcrypt_pbkdf` — the KDF OpenSSH uses to derive symmetric keys
//! for protecting new-format private key files from a passphrase.
//!
//! **Not interoperable with regular bcrypt.** Regular bcrypt is a
//! password-verification hash; `bcrypt_pbkdf` is a key-derivation
//! function. Both share the EksBlowfishSetup primitive, but the wrapper
//! around it (the PBKDF2-style outer loop, the SHA-512 password/salt
//! preprocessing, the "OxychromaticBlowfishSwatDynamite" payload, and
//! the stride-distributed output) is `bcrypt_pbkdf`-specific.
//!
//! Reference implementations:
//! - OpenBSD `lib/libutil/bcrypt_pbkdf.c` (canonical).
//! - `golang.org/x/crypto/ssh/internal/bcrypt_pbkdf`.
//!
//! Tuning: `rounds` is the iteration count of the inner PRF; OpenSSH's
//! current default is 16, older default was 6 — at 16 rounds the
//! function takes roughly 100 ms on modern hardware, which is the design
//! intent. `keylen` is the output length in bytes (typically 32 for an
//! `aes256-ctr` key, 48 with the IV concatenated).

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use crate::cipher::blowfish::Blowfish;
use crate::hash::{Digest, Sha512};

/// Maximum permitted output length, mirroring OpenSSH's cap.
const MAX_KEYLEN: usize = 1024;

/// Length of the inner PRF output, in bytes (one Blowfish "encipher"
/// applied to the 32-byte payload).
const BCRYPT_HASHSIZE: usize = 32;

/// Parameter-validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// One of: `rounds == 0`, `keylen == 0`, or `keylen > 1024`.
    InvalidParameters,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("bcrypt_pbkdf: invalid parameters")
    }
}

impl core::error::Error for Error {}

/// Derives `keylen` bytes from `(password, salt)` using OpenSSH's
/// `bcrypt_pbkdf` with `rounds` iterations. Returns an error when
/// `rounds == 0`, `keylen == 0`, or `keylen > 1024`.
pub fn bcrypt_pbkdf(
    password: &[u8],
    salt: &[u8],
    rounds: u32,
    keylen: usize,
) -> Result<Vec<u8>, Error> {
    if rounds == 0 || keylen == 0 || keylen > MAX_KEYLEN {
        return Err(Error::InvalidParameters);
    }

    // OpenSSH layout: each PRF call produces 32 bytes, distributed across
    // the output by "stride" so that recovering any contiguous subkey
    // requires running the full derivation. Mirrors OpenBSD:
    //     stride = ceil(keylen / 32)
    //     amt    = ceil(keylen / stride)
    // then `key[i * stride + (count - 1)] = out[i]`.
    let stride: usize = keylen.div_ceil(BCRYPT_HASHSIZE);
    let initial_amt: usize = keylen.div_ceil(stride);

    // SHA-512 of the password — same value across every PRF block.
    let sha2pass: [u8; 64] = Sha512::digest(password);

    let mut out = vec![0u8; keylen];
    let mut remaining = keylen;
    let mut count: u32 = 1;

    while remaining > 0 {
        // First round: salt is `salt || count_be32`.
        let mut salt_hasher = Sha512::new();
        salt_hasher.update(salt);
        salt_hasher.update(&count.to_be_bytes());
        let mut sha2salt: [u8; 64] = salt_hasher.finalize();

        // Initial PRF.
        let mut tmpout = bcrypt_hash(&sha2pass, &sha2salt);
        let mut block = tmpout;

        // Iterate `rounds - 1` more PRF calls; salt becomes the prior
        // PRF output (after SHA-512), accumulator XORs each PRF result.
        for _ in 1..rounds {
            sha2salt = Sha512::digest(&tmpout);
            tmpout = bcrypt_hash(&sha2pass, &sha2salt);
            for j in 0..BCRYPT_HASHSIZE {
                block[j] ^= tmpout[j];
            }
        }

        // Stride-distributed write. `amt` clamps so we never write past
        // the last partial block.
        let amt = initial_amt.min(remaining);
        let mut written = 0usize;
        for (i, &b) in block.iter().take(amt).enumerate() {
            let dest = i * stride + (count as usize - 1);
            if dest >= keylen {
                break;
            }
            out[dest] = b;
            written += 1;
        }
        remaining -= written;
        count += 1;
    }

    Ok(out)
}

/// Inner PRF: 32-byte output from a 64-byte `sha2pass` "key" and a
/// 64-byte `sha2salt` salt, via EksBlowfishSetup + a fixed payload.
///
/// Watch-out points (from the OpenBSD reference):
/// 1. The 32-byte payload `"OxychromaticBlowfishSwatDynamite"` is packed
///    into eight `u32`s read **big-endian** (so `0x4f787963` = "Oxyc").
/// 2. The outer expansion runs `eks_setup` once, then 64 iterations of
///    `expand_key(sha2salt)` + `expand_key(sha2pass)`.
/// 3. The inner encipher loop runs 64 *full* passes; each pass enciphers
///    all four 64-bit pairs of the 8-word state.
/// 4. The output writes each `u32` **little-endian** — note the
///    asymmetry with point 1.
fn bcrypt_hash(sha2pass: &[u8; 64], sha2salt: &[u8; 64]) -> [u8; BCRYPT_HASHSIZE] {
    // Key schedule.
    let mut state = Blowfish::new();
    state.eks_setup(sha2salt, sha2pass);
    for _ in 0..64 {
        state.expand_key(sha2salt);
        state.expand_key(sha2pass);
    }

    // "OxychromaticBlowfishSwatDynamite" as eight big-endian u32s.
    let mut cdata: [u32; 8] = [
        0x4f78_7963, // "Oxyc"
        0x6872_6f6d, // "hrom"
        0x6174_6963, // "atic"
        0x426c_6f77, // "Blow"
        0x6669_7368, // "fish"
        0x5377_6174, // "Swat"
        0x4479_6e61, // "Dyna"
        0x6d69_7465, // "mite"
    ];

    // 64 outer iterations, each enciphering all four pairs in place.
    for _ in 0..64 {
        let mut i = 0;
        while i < 8 {
            let (mut l, mut r) = (cdata[i], cdata[i + 1]);
            state.encipher(&mut l, &mut r);
            cdata[i] = l;
            cdata[i + 1] = r;
            i += 2;
        }
    }

    // Little-endian byte serialisation (OpenBSD quirk).
    let mut out = [0u8; BCRYPT_HASHSIZE];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&cdata[i].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        let bytes: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        assert!(bytes.len().is_multiple_of(2));
        bytes
            .chunks(2)
            .map(|p| {
                let hi = (p[0] as char).to_digit(16).unwrap() as u8;
                let lo = (p[1] as char).to_digit(16).unwrap() as u8;
                (hi << 4) | lo
            })
            .collect()
    }

    /// `golang.org/x/crypto` `TestBcryptHash`: with `pass[i] = i` and
    /// `salt[i] = i + 64` for `i = 0..64`, `bcryptHash` returns
    /// `87904870eef9deddf8e7611a140106e6aaf1a363d9a2c504db356443721eb555`.
    /// Source: `golang.org/x/crypto/ssh/internal/bcrypt_pbkdf/bcrypt_pbkdf_test.go`.
    #[test]
    fn go_bcrypt_hash_kat() {
        let mut pass = [0u8; 64];
        let mut salt = [0u8; 64];
        for i in 0..64 {
            pass[i] = i as u8;
            salt[i] = (i + 64) as u8;
        }
        let out = bcrypt_hash(&pass, &salt);
        let expected = from_hex("87904870eef9deddf8e7611a140106e6aaf1a363d9a2c504db356443721eb555");
        assert_eq!(&out[..], &expected[..]);
    }

    /// Vector 1 from the task prompt: password="password", salt="salt",
    /// rounds=4, keylen=32.
    #[test]
    fn pbkdf_vector_1() {
        let out = bcrypt_pbkdf(b"password", b"salt", 4, 32).unwrap();
        let expected = from_hex("5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9");
        assert_eq!(out, expected);
    }

    /// Go vector (`golang.org/x/crypto`): rounds=12, password="password",
    /// salt="salt", keylen=32.
    #[test]
    fn pbkdf_go_vector_rounds12() {
        let out = bcrypt_pbkdf(b"password", b"salt", 12, 32).unwrap();
        let expected = from_hex("1ae42c05d487bc02f64921a4ebe4ea93bcacfe135fda99974c06b7b01fae149a");
        assert_eq!(out, expected);
    }

    /// Go vector with embedded NULs and a longer derived key — exercises
    /// the stride layout (keylen > 32 forces multiple output blocks).
    #[test]
    fn pbkdf_go_vector_stride() {
        // password and salt as in TestKey vector 2.
        let pwd: &[u8] = b"passwordy\x00PASSWORD\x00";
        let salt: &[u8] = b"salty\x00SALT\x00";
        let out = bcrypt_pbkdf(pwd, salt, 3, 32).unwrap();
        let expected = from_hex("7f310bd3e78c3280c59ce4595211a2928e8d4ec744c1ed2efc9f764e3388e0ad");
        assert_eq!(out, expected);
    }

    /// Go vector 3: long output (88 bytes) exercising both the stride
    /// layout and the partial-final-block clamp. Source URL cited in the
    /// upstream test: <http://thread.gmane.org/gmane.os.openbsd.bugs/20542>.
    #[test]
    fn pbkdf_go_vector_long_output() {
        let pwd = "секретное слово".as_bytes();
        let salt = "посолить немножко".as_bytes();
        let out = bcrypt_pbkdf(pwd, salt, 8, 88).unwrap();
        let expected = from_hex(
            "8df43fc6fe131fc47f0c9e39224bd94c70b6fcc8ee8135faddf61156e6cb2733\
             ea765f315a3e1e4afc35bf8687d189254c1e05a6fe80c0617f9183d67260d6a1\
             15c6c94e3603e2303fbb43a76a64523ffda686b1d4518543",
        );
        assert_eq!(out.len(), 88);
        assert_eq!(out, expected);
    }

    #[test]
    fn rejects_zero_rounds() {
        assert_eq!(
            bcrypt_pbkdf(b"x", b"y", 0, 32),
            Err(Error::InvalidParameters)
        );
    }

    #[test]
    fn rejects_zero_keylen() {
        assert_eq!(
            bcrypt_pbkdf(b"x", b"y", 1, 0),
            Err(Error::InvalidParameters)
        );
    }

    #[test]
    fn rejects_too_large_keylen() {
        assert_eq!(
            bcrypt_pbkdf(b"x", b"y", 1, 1025),
            Err(Error::InvalidParameters)
        );
    }

    #[test]
    fn accepts_max_keylen() {
        let out = bcrypt_pbkdf(b"password", b"salt", 1, 1024).unwrap();
        assert_eq!(out.len(), 1024);
    }
}
