//! The keyed hash functions and PRFs for XMSS (RFC 8391 §2.7, §5.1) plus the
//! `prf_keygen` extension from NIST SP 800-208 (used by the deployed XMSS
//! reference implementation to derive WOTS+ secret values).
//!
//! Every function prefixes a domain-separation tag `toByte(X, padding_len)`:
//! `0 = F`, `1 = H`, `2 = H_msg`, `3 = PRF`, `4 = PRF_keygen`. The underlying
//! primitive is selected per parameter set: SHA-256 (truncated to `n`),
//! SHAKE128, or SHAKE256.

use super::params::{HashFamily, MAX_N, Params};
use crate::hash::{Digest, ExtendableOutput, Sha256, Shake128, Shake256};

/// Largest `padding_len` across the supported sets (`n = 32`).
const MAX_PAD: usize = 32;

const PAD_F: u64 = 0;
const PAD_H: u64 = 1;
const PAD_HASH: u64 = 2;
const PAD_PRF: u64 = 3;
const PAD_PRF_KEYGEN: u64 = 4;

/// Big-endian `outlen`-byte encoding of `x` (RFC 8391 `toByte`).
fn to_byte(x: u64, outlen: usize, out: &mut [u8]) {
    out[..outlen].fill(0);
    let mut v = x;
    for i in (0..outlen).rev() {
        out[i] = (v & 0xff) as u8;
        v >>= 8;
    }
}

/// The raw hash primitive for the family, producing `n` bytes from the
/// concatenated `parts`.
fn core_hash(p: &Params, parts: &[&[u8]], out: &mut [u8]) {
    let n = p.n;
    match p.family {
        HashFamily::Sha2_256 => {
            let mut h = Sha256::new();
            for part in parts {
                h.update(part);
            }
            let d = h.finalize();
            out[..n].copy_from_slice(&d.as_ref()[..n]);
        }
        HashFamily::Shake128 => {
            let mut h = Shake128::new();
            for part in parts {
                h.update(part);
            }
            h.finalize_into(&mut out[..n]);
        }
        HashFamily::Shake256 => {
            let mut h = Shake256::new();
            for part in parts {
                h.update(part);
            }
            h.finalize_into(&mut out[..n]);
        }
    }
}

/// `PRF(key, in)`: `hash(toByte(3, pad) ‖ key ‖ in)`, with a 32-byte `input`.
/// Used to derive hash keys and bitmasks from `PUB_SEED` and an address.
pub(crate) fn prf(p: &Params, key: &[u8], input: &[u8; 32], out: &mut [u8]) {
    let mut pad = [0u8; MAX_PAD];
    to_byte(PAD_PRF, p.padding_len, &mut pad);
    core_hash(p, &[&pad[..p.padding_len], &key[..p.n], input], out);
}

/// `PRF_keygen(key, in)`: `hash(toByte(4, pad) ‖ key ‖ in)`, with an
/// `(n + 32)`-byte `input` (`PUB_SEED ‖ ADRS`). Derives WOTS+ secret values.
pub(crate) fn prf_keygen(p: &Params, key: &[u8], input: &[u8], out: &mut [u8]) {
    let mut pad = [0u8; MAX_PAD];
    to_byte(PAD_PRF_KEYGEN, p.padding_len, &mut pad);
    core_hash(p, &[&pad[..p.padding_len], &key[..p.n], input], out);
}

/// Tweakable hash `F` (RFC 8391): `hash(toByte(0, pad) ‖ key ‖ (m XOR mask))`.
pub(crate) fn f(p: &Params, key: &[u8], masked: &[u8], out: &mut [u8]) {
    let mut pad = [0u8; MAX_PAD];
    to_byte(PAD_F, p.padding_len, &mut pad);
    core_hash(
        p,
        &[&pad[..p.padding_len], &key[..p.n], &masked[..p.n]],
        out,
    );
}

/// Tweakable hash `H` (RFC 8391): `hash(toByte(1, pad) ‖ key ‖ (m XOR mask))`,
/// where the masked input is `2n` bytes.
pub(crate) fn h(p: &Params, key: &[u8], masked: &[u8], out: &mut [u8]) {
    let mut pad = [0u8; MAX_PAD];
    to_byte(PAD_H, p.padding_len, &mut pad);
    core_hash(
        p,
        &[&pad[..p.padding_len], &key[..p.n], &masked[..2 * p.n]],
        out,
    );
}

/// Message hash `H_msg` (RFC 8391):
/// `hash(toByte(2, pad) ‖ R ‖ root ‖ toByte(idx, n) ‖ M)`.
pub(crate) fn h_msg(p: &Params, r: &[u8], root: &[u8], idx: u64, msg: &[u8], out: &mut [u8]) {
    let mut pad = [0u8; MAX_PAD];
    to_byte(PAD_HASH, p.padding_len, &mut pad);
    let mut idx_bytes = [0u8; MAX_N];
    to_byte(idx, p.n, &mut idx_bytes);
    core_hash(
        p,
        &[
            &pad[..p.padding_len],
            &r[..p.n],
            &root[..p.n],
            &idx_bytes[..p.n],
            msg,
        ],
        out,
    );
}
