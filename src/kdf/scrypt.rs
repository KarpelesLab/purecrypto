//! scrypt — memory-hard password-based key-derivation function (RFC 7914).
//!
//! scrypt's cost parameters (`N = 2^log_n`, `r`, `p`) tune CPU and memory
//! usage. The function allocates `128 · r · N` bytes once for ROMix; at the
//! commonly-recommended `(log_n=14, r=8, p=1)` that is ~16 MiB. This makes
//! scrypt only available with the `alloc` feature.
//!
//! Parameter errors return [`Error::InvalidParam`] rather than panicking,
//! because the parameters are usually runtime-supplied (parsed from PHC
//! strings, config, etc.).
//!
//! Internally: outer `PBKDF2-HMAC-SHA256` envelope, inner [`crate::cipher`]
//! Salsa20/8 BlockMix on `128·r`-byte sub-blocks.
//!
//! _Not constant time in the password._ scrypt's design fundamentally
//! depends on its memory access pattern (controlled by the password via
//! the data-dependent `j` indexing in ROMix's second loop), so scrypt's
//! side-channel posture is the same as the reference implementation.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::cipher::salsa20::salsa20_8;
use crate::hash::Sha256;
use crate::kdf::pbkdf2;

/// scrypt parameter-validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// One of `log_n`, `r`, `p`, or `dkLen` is outside RFC 7914 §1's range:
    /// `log_n` must be in `1..64`, `r ≥ 1`, `p ≥ 1`, `r·N < 2³⁰`, and
    /// `p · ⌈dkLen/32⌉ ≤ (2³² − 1)`.
    InvalidParam,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("scrypt: invalid parameter")
    }
}

impl core::error::Error for Error {}

/// Derives `out.len()` key bytes from `(password, salt)` using scrypt with
/// parameters `(log_n, r, p)` (so `N = 2^log_n`).
pub fn scrypt(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
    out: &mut [u8],
) -> Result<(), Error> {
    // --- Parameter validation (RFC 7914 §1) ---
    if log_n == 0 || log_n >= 64 || r == 0 || p == 0 {
        return Err(Error::InvalidParam);
    }
    let n: u64 = 1u64 << log_n;
    // r · N < 2³⁰
    let rn = (r as u64).checked_mul(n).ok_or(Error::InvalidParam)?;
    if rn >= (1u64 << 30) {
        return Err(Error::InvalidParam);
    }
    // p · (128 · r) must fit in usize for the buffer.
    let block_size = 128usize
        .checked_mul(r as usize)
        .ok_or(Error::InvalidParam)?;
    let b_len = block_size
        .checked_mul(p as usize)
        .ok_or(Error::InvalidParam)?;
    if out.is_empty() {
        return Err(Error::InvalidParam);
    }

    // --- First PBKDF2 expansion: B = PBKDF2-HMAC-SHA256(P, S, 1, p·128·r) ---
    let mut b: Vec<u8> = vec![0u8; b_len];
    pbkdf2::<Sha256>(password, salt, 1, &mut b);

    // --- ROMix on each p block in turn, reusing one V scratch ---
    let n_us = n as usize;
    let mut v: Vec<u8> = vec![0u8; n_us * block_size];
    let mut x: Vec<u8> = vec![0u8; block_size];

    for i in 0..p as usize {
        let off = i * block_size;
        x.copy_from_slice(&b[off..off + block_size]);
        romix(&mut x, n_us, r as usize, &mut v);
        b[off..off + block_size].copy_from_slice(&x);
    }

    // --- Second PBKDF2 expansion: DK = PBKDF2-HMAC-SHA256(P, B, 1, dkLen) ---
    pbkdf2::<Sha256>(password, &b, 1, out);
    Ok(())
}

/// ROMix(X, N, r) — the memory-hard core (RFC 7914 §4).
fn romix(x: &mut [u8], n: usize, r: usize, v: &mut [u8]) {
    let block_size = 128 * r;

    // V_i = X^{(i)} for i = 0..N
    for i in 0..n {
        v[i * block_size..(i + 1) * block_size].copy_from_slice(x);
        block_mix(x, r);
    }

    // Second loop: data-dependent indexing.
    for _ in 0..n {
        let j = integerify(x, r) % n as u64;
        let j_off = j as usize * block_size;
        for k in 0..block_size {
            x[k] ^= v[j_off + k];
        }
        block_mix(x, r);
    }
}

/// BlockMix(B, r) — applies Salsa20/8 sequentially over `2r` 64-byte sub-blocks
/// and reorders the result (RFC 7914 §3).
fn block_mix(b: &mut [u8], r: usize) {
    let two_r = 2 * r;
    // X = B_{2r-1}.
    let mut x = [0u8; 64];
    x.copy_from_slice(&b[(two_r - 1) * 64..two_r * 64]);

    // Y_i = Salsa20/8(X ⊕ B_i); X' = Y_i for the next iteration.
    let mut y: Vec<u8> = vec![0u8; 128 * r];
    for i in 0..two_r {
        for k in 0..64 {
            x[k] ^= b[i * 64 + k];
        }
        salsa20_8(&mut x);
        y[i * 64..(i + 1) * 64].copy_from_slice(&x);
    }

    // Reorder: Y_0, Y_2, ..., Y_{2r-2}, Y_1, Y_3, ..., Y_{2r-1}.
    for i in 0..r {
        b[i * 64..(i + 1) * 64].copy_from_slice(&y[(2 * i) * 64..(2 * i + 1) * 64]);
        b[(r + i) * 64..(r + i + 1) * 64].copy_from_slice(&y[(2 * i + 1) * 64..(2 * i + 2) * 64]);
    }
}

/// Integerify(B) — read the first 8 bytes of the last 64-byte sub-block as a
/// little-endian u64.
fn integerify(b: &[u8], r: usize) -> u64 {
    let off = (2 * r - 1) * 64;
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// RFC 7914 §11 Test Vector 1: `scrypt("", "", N=16, r=1, p=1, dkLen=64)`.
    #[test]
    fn rfc7914_vector_1() {
        let expected = from_hex::<64>(
            "77d6576238657b203b19ca42c18a0497\
             f16b4844e3074ae8dfdffa3fede21442\
             fcd0069ded0948f8326a753a0fc81f17\
             e8d3e0fb2e0d3628cf35e20c38d18906",
        );
        let mut out = [0u8; 64];
        scrypt(b"", b"", 4, 1, 1, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    /// RFC 7914 §11 Test Vector 2: `scrypt("password", "NaCl", N=1024, r=8, p=16, 64)`.
    #[test]
    fn rfc7914_vector_2() {
        let expected = from_hex::<64>(
            "fdbabe1c9d3472007856e7190d01e9fe\
             7c6ad7cbc8237830e77376634b373162\
             2eaf30d92e22a3886ff109279d9830da\
             c727afb94a83ee6d8360cbdfa2cc0640",
        );
        let mut out = [0u8; 64];
        scrypt(b"password", b"NaCl", 10, 8, 16, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    /// RFC 7914 §11 Test Vector 3: `scrypt("pleaseletmein", "SodiumChloride", N=16384, r=8, p=1, 64)`.
    #[test]
    #[ignore = "16-MiB allocation; slow in debug — `cargo test --release -- --ignored`"]
    fn rfc7914_vector_3() {
        let expected = from_hex::<64>(
            "7023bdcb3afd7348461c06cd81fd38eb\
             fda8fbba904f8e3ea9b543f6545da1f2\
             d5432955613f0fcf62d49705242a9af9\
             e61e85dc0d651e40dfcf017b45575887",
        );
        let mut out = [0u8; 64];
        scrypt(b"pleaseletmein", b"SodiumChloride", 14, 8, 1, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn rejects_invalid_parameters() {
        let mut out = [0u8; 32];
        assert_eq!(
            scrypt(b"p", b"s", 0, 1, 1, &mut out),
            Err(Error::InvalidParam)
        );
        assert_eq!(
            scrypt(b"p", b"s", 4, 0, 1, &mut out),
            Err(Error::InvalidParam)
        );
        assert_eq!(
            scrypt(b"p", b"s", 4, 1, 0, &mut out),
            Err(Error::InvalidParam)
        );
        assert_eq!(
            scrypt(b"p", b"s", 4, 1, 1, &mut []),
            Err(Error::InvalidParam)
        );
        // r·N ≥ 2³⁰ → reject.
        assert_eq!(
            scrypt(b"p", b"s", 30, 1, 1, &mut out),
            Err(Error::InvalidParam)
        );
    }
}
