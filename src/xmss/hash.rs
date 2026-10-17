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
#[cfg(feature = "alloc")]
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

/// SHAKE of `parts` into `out` when both fit one `RATE`-byte block (every
/// `F` / `H` / `PRF` / `PRF_keygen` preimage is at most `pad + 3n ≤ 128`
/// bytes and `n ≤ 32`): pad the block, load it as the fresh sponge state,
/// permute once, read `out` — no sponge bookkeeping. Returns `false` (and
/// does nothing) when the input or output is too long for the fast path.
fn shake_block<const RATE: usize>(parts: &[&[u8]], out: &mut [u8]) -> bool {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    if total >= RATE || out.len() > RATE {
        return false;
    }
    let mut block = [0u8; RATE];
    let mut off = 0;
    for p in parts {
        block[off..off + p.len()].copy_from_slice(p);
        off += p.len();
    }
    block[off] = 0x1F;
    block[RATE - 1] |= 0x80;
    let mut st = [0u64; 25];
    for (lane, chunk) in st.iter_mut().zip(block.chunks_exact(8)) {
        *lane = u64::from_le_bytes(chunk.try_into().unwrap());
    }
    crate::hash::keccak::keccak_p(&mut st, 24);
    for (o, lane) in out.chunks_mut(8).zip(st.iter()) {
        o.copy_from_slice(&lane.to_le_bytes()[..o.len()]);
    }
    // The preimage may carry SK_SEED (PRF_keygen) or a secret chain value
    // (F), and the state is a function of it.
    crate::zeroize::Zeroize::zeroize(&mut block);
    crate::zeroize::Zeroize::zeroize(&mut st);
    true
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
            if shake_block::<168>(parts, &mut out[..n]) {
                return;
            }
            let mut h = Shake128::new();
            for part in parts {
                h.update(part);
            }
            h.finalize_into(&mut out[..n]);
        }
        HashFamily::Shake256 => {
            if shake_block::<136>(parts, &mut out[..n]) {
                return;
            }
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
#[cfg(feature = "alloc")]
pub(crate) fn prf_keygen(p: &Params, key: &[u8], input: &[u8], out: &mut [u8]) {
    let mut pad = [0u8; MAX_PAD];
    to_byte(PAD_PRF_KEYGEN, p.padding_len, &mut pad);
    core_hash(p, &[&pad[..p.padding_len], &key[..p.n], input], out);
}

/// A reusable SHA-2 PRF base: a [`Sha256`] already fed `toByte(3, pad) ‖ key`.
///
/// Returns `Some` only for the SHA-256 family with `padding_len + n == 64` (the
/// `n = 32` sets), where `pad ‖ key` is exactly one 64-byte block and is thus
/// already compressed into the returned state. Each [`prf_with`] is then a clone
/// plus a single extra block, instead of compressing `pad ‖ key` afresh every
/// call — and within a subtree `key = PUB_SEED` is constant across the millions
/// of WOTS+/tree `prf` calls. SHAKE and the `n = 24` sets return `None`, and the
/// caller falls back to [`prf`] (a sponge has no comparably cheap midstate).
pub(crate) fn prf_base(p: &Params, key: &[u8]) -> Option<Sha256> {
    if matches!(p.family, HashFamily::Sha2_256) && p.padding_len + p.n == 64 {
        let mut pad = [0u8; MAX_PAD];
        to_byte(PAD_PRF, p.padding_len, &mut pad);
        let mut h = Sha256::new();
        h.update(&pad[..p.padding_len]);
        h.update(&key[..p.n]);
        Some(h)
    } else {
        None
    }
}

/// `PRF(key, input)` using a [`prf_base`] when present (one block cheaper), else
/// the full [`prf`] path. `base`, when `Some`, MUST have been built from `key`.
pub(crate) fn prf_with(
    p: &Params,
    base: &Option<Sha256>,
    key: &[u8],
    input: &[u8; 32],
    out: &mut [u8],
) {
    match base {
        Some(b) => {
            let mut h = b.clone();
            h.update(input);
            let d = h.finalize();
            out[..p.n].copy_from_slice(&d[..p.n]);
        }
        None => prf(p, key, input, out),
    }
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
