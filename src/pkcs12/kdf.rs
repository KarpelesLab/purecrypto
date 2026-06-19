//! RFC 7292 Appendix B — the PKCS#12 SHA-based key-derivation function.
//!
//! This is the iterated hash construction OpenSSL uses for the integrity
//! MAC of a `.p12` file (and, in legacy archives, for the
//! `pbeWithSHAAnd3-KeyTripleDES-CBC` content encryption). It is *not*
//! PBKDF2: it predates PKCS#5 v2 and has its own block-stuffing scheme.
//!
//! # The construction (RFC 7292 §B.2)
//!
//! Inputs: a password `P`, a salt `S`, an iteration count `c`, an output
//! length `n`, and an *ID byte* that domain-separates the three uses:
//!
//! * ID = 1 → derive an encryption/decryption key,
//! * ID = 2 → derive an IV,
//! * ID = 3 → derive a MAC key.
//!
//! The password is first converted to a big-endian UTF-16 (BMP) string
//! **with a trailing two-byte NUL terminator** — this terminator is the
//! single most common interop trap. Then, with `u` the hash output size
//! and `v` the hash block size (both in bytes):
//!
//! 1. `D` = `v` copies of the ID byte (the "diversifier").
//! 2. `S` is concatenated with itself to fill `ceil(|salt|/v) * v` bytes
//!    (or empty if the salt is empty); likewise `P` → `ceil(|pw|/v)*v`.
//!    `I = S || P`.
//! 3. For each `u`-byte output chunk `A`:
//!    a. `A = H^c(D || I)` — hash `D||I`, then re-hash the digest `c-1`
//!    more times.
//!    b. Form `B` by repeating `A` to `v` bytes.
//!    c. Treat `I` as `k = |I|/v` blocks of `v` bytes; for each block
//!    `I_j`, set `I_j = (I_j + B + 1) mod 2^(v*8)` (big-endian add).
//! 4. Concatenate the `A` chunks and truncate to `n` bytes.
//!
//! Only SHA-1 (`u=20, v=64`) and SHA-256 (`u=32, v=64`) are wired here —
//! the two PRFs OpenSSL emits for the file MAC.

use crate::hash::{Digest, Sha1, Sha256};
use alloc::vec;
use alloc::vec::Vec;

/// Which hash backs the derivation. The block size `v` is 64 for both.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PkcsHash {
    /// SHA-1 (`u = 20`).
    Sha1,
    /// SHA-256 (`u = 32`).
    Sha256,
}

impl PkcsHash {
    /// Hash output length `u`, in bytes.
    fn u(self) -> usize {
        match self {
            PkcsHash::Sha1 => 20,
            PkcsHash::Sha256 => 32,
        }
    }
    /// Hash block length `v`, in bytes (64 for both).
    fn v(self) -> usize {
        64
    }
}

/// The diversifier ID for a MAC key (RFC 7292 §B.3).
pub(crate) const ID_MAC: u8 = 3;
/// The diversifier ID for an encryption key.
pub(crate) const ID_KEY: u8 = 1;
/// The diversifier ID for an IV.
pub(crate) const ID_IV: u8 = 2;

/// Converts an ASCII/UTF-8 password to the big-endian UTF-16 (BMP) form
/// **including the trailing two-byte NUL** that RFC 7292 §B.1 mandates.
///
/// Note: code points outside the BMP (needing surrogate pairs) are encoded
/// per UTF-16; OpenSSL does the same. An empty password becomes just the
/// two NUL bytes (`[0x00, 0x00]`), matching OpenSSL.
pub(crate) fn password_to_bmp(password: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(password.len() * 2 + 2);
    for unit in password.encode_utf16() {
        out.extend_from_slice(&unit.to_be_bytes());
    }
    out.extend_from_slice(&[0x00, 0x00]); // trailing NUL terminator
    out
}

/// Runs the RFC 7292 Appendix B derivation, writing `out.len()` bytes.
///
/// `password_bmp` must already be the BE-UTF16-with-NUL encoding from
/// [`password_to_bmp`]. `id` is one of [`ID_KEY`] / [`ID_IV`] / [`ID_MAC`].
pub(crate) fn derive(
    hash: PkcsHash,
    password_bmp: &[u8],
    salt: &[u8],
    iterations: u32,
    id: u8,
    out: &mut [u8],
) {
    match hash {
        PkcsHash::Sha1 => derive_with::<Sha1>(hash, password_bmp, salt, iterations, id, out),
        PkcsHash::Sha256 => derive_with::<Sha256>(hash, password_bmp, salt, iterations, id, out),
    }
}

/// Monomorphised core, generic over the concrete [`Digest`].
fn derive_with<D: Digest>(
    hash: PkcsHash,
    password_bmp: &[u8],
    salt: &[u8],
    iterations: u32,
    id: u8,
    out: &mut [u8],
) {
    let u = hash.u();
    let v = hash.v();
    debug_assert_eq!(u, D::OUTPUT_LEN);

    // Step 1: D = v copies of the ID byte.
    let d = vec![id; v];

    // Step 2: S and P padded to multiples of v, then I = S || P.
    let s = fill_blocks(salt, v);
    let p = fill_blocks(password_bmp, v);
    let mut i_buf = Vec::with_capacity(s.len() + p.len());
    i_buf.extend_from_slice(&s);
    i_buf.extend_from_slice(&p);

    let n = out.len();
    let mut produced = 0;

    while produced < n {
        // Step 3a: A = H^c(D || I).
        let mut hasher = D::new();
        hasher.update(&d);
        hasher.update(&i_buf);
        let mut a = hasher.finalize();
        let iters = iterations.max(1); // c >= 1
        for _ in 1..iters {
            let mut h = D::new();
            h.update(a.as_ref());
            a = h.finalize();
        }
        let a_bytes = a.as_ref();

        // Copy this chunk into the output.
        let take = core::cmp::min(u, n - produced);
        out[produced..produced + take].copy_from_slice(&a_bytes[..take]);
        produced += take;
        if produced >= n {
            break;
        }

        // Step 3b: B = v bytes formed by repeating A.
        let mut b = vec![0u8; v];
        for (j, slot) in b.iter_mut().enumerate() {
            *slot = a_bytes[j % u];
        }

        // Step 3c: I_j = (I_j + B + 1) mod 2^(v*8) for each v-byte block.
        let k = i_buf.len() / v;
        for j in 0..k {
            let block = &mut i_buf[j * v..(j + 1) * v];
            add_block(block, &b);
        }
    }

    // Best-effort wipe of the working buffer (holds password-derived state).
    for byte in i_buf.iter_mut() {
        *byte = 0;
    }
    let _ = core::hint::black_box(&i_buf);
}

/// Pads `data` by repeating it (truncating the last copy) to the smallest
/// nonzero multiple of `v`. An empty input yields an empty vector (the salt
/// or password is then absent from `I`, per RFC 7292 §B.2).
fn fill_blocks(data: &[u8], v: usize) -> Vec<u8> {
    if data.is_empty() {
        return Vec::new();
    }
    let blocks = data.len().div_ceil(v);
    let total = blocks * v;
    let mut out = Vec::with_capacity(total);
    for i in 0..total {
        out.push(data[i % data.len()]);
    }
    out
}

/// Big-endian in-place `block = (block + addend + 1) mod 2^(len*8)`.
/// `block` and `addend` are the same length (`v`).
fn add_block(block: &mut [u8], addend: &[u8]) {
    debug_assert_eq!(block.len(), addend.len());
    let mut carry: u16 = 1; // the "+ 1" of the spec
    for idx in (0..block.len()).rev() {
        let sum = block[idx] as u16 + addend[idx] as u16 + carry;
        block[idx] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    // Any final carry beyond the top byte is discarded (mod 2^(v*8)).
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_bmp_has_trailing_nul() {
        assert_eq!(password_to_bmp(""), vec![0x00, 0x00]);
        // "ab" -> 00 61 00 62 00 00
        assert_eq!(
            password_to_bmp("ab"),
            vec![0x00, 0x61, 0x00, 0x62, 0x00, 0x00]
        );
    }

    #[test]
    fn fill_blocks_repeats_and_pads() {
        assert_eq!(fill_blocks(&[], 4), Vec::<u8>::new());
        // 3 bytes -> 1 block of 4 (repeats first byte).
        assert_eq!(fill_blocks(&[1, 2, 3], 4), vec![1, 2, 3, 1]);
        // exactly one block stays put.
        assert_eq!(fill_blocks(&[1, 2, 3, 4], 4), vec![1, 2, 3, 4]);
    }

    #[test]
    fn add_block_carries() {
        // [0xff] + [0x00] + 1 = 0x00 (carry discarded).
        let mut b = [0xffu8];
        add_block(&mut b, &[0x00]);
        assert_eq!(b, [0x00]);
        // [0x00,0xff] + [0x00,0x00] + 1 = [0x01,0x00].
        let mut b = [0x00u8, 0xff];
        add_block(&mut b, &[0x00, 0x00]);
        assert_eq!(b, [0x01, 0x00]);
    }
}
