//! XMSS / XMSS^MT stateful hash-based signatures (RFC 8391, NIST SP 800-208).
//!
//! XMSS is a stateful hash-based signature scheme: each signature consumes one
//! WOTS+ one-time key, indexed by a leaf counter `idx` carried *inside* the
//! private key. The scheme is built entirely from this crate's hash primitives
//! (SHA-256 / SHAKE) and needs `alloc` only for the multi-kilobyte signatures.
//!
//! # Statefulness — read this before using the signing API
//!
//! **The private key is single-use per index, and reusing an index destroys
//! all security.** Two distinct messages signed from the same `idx` let an
//! attacker forge signatures. To use XMSS safely you MUST:
//!
//! - **Persist the serialized key after *every* [`sign`](XmssPrivateKey::sign)**
//!   — `sign` takes `&mut self`, advances `idx`, and the new `idx` must reach
//!   stable storage *before* the produced signature is released. Serialize with
//!   [`to_bytes`](XmssPrivateKey::to_bytes) and write it out on each signature.
//! - **Never sign twice from the same `idx`.** Do not roll the index back, do
//!   not restore an old serialized copy and keep signing, and do not run two
//!   signers from the same key file.
//! - **Never clone a key and sign from both copies.** This type is deliberately
//!   *not* [`Clone`]; copying the secret material and signing from each copy
//!   reuses indices. Keep exactly one live signer per key.
//! - **Handle exhaustion.** After `2^h` signatures the key is spent;
//!   [`sign`](XmssPrivateKey::sign) returns [`Error::KeyExhausted`] rather than
//!   reusing the final index. Check [`remaining`](XmssPrivateKey::remaining).
//!
//! Secret material is wiped on drop.
//!
//! # Example
//!
//! ```
//! # #[cfg(feature = "xmss")] {
//! use purecrypto::xmss::{XmssParamSet, XmssPrivateKey};
//! use purecrypto::rng::HmacDrbg;
//! use purecrypto::hash::Sha256;
//!
//! let mut rng = HmacDrbg::<Sha256>::new(b"seed", b"nonce", &[]);
//! let mut sk = XmssPrivateKey::generate(XmssParamSet::Sha2_10_256, &mut rng);
//! let pk = sk.public_key();
//!
//! let sig = sk.sign(b"hello").unwrap();
//! // Persist sk.to_bytes() here, before using `sig`.
//! assert!(pk.verify(b"hello", &sig));
//! # }
//! ```

// The tree routines thread params, seeds, addresses, and several buffers
// explicitly, as faithful ports of the reference C.
#![allow(clippy::too_many_arguments)]

mod adrs;
mod hash;
#[cfg(feature = "key")]
mod key_impl;
mod params;

use adrs::{Adrs, AdrsType};
use alloc::vec;
use alloc::vec::Vec;
use params::{MAX_N, MAX_WOTS_LEN, Params};

pub use params::{XmssMtParamSet, XmssParamSet};

use crate::ct::ConstantTimeEq;
use crate::rng::{CryptoRng, RngCore};

/// Errors from XMSS / XMSS^MT operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A key or signature had the wrong length, or a serialized key was for a
    /// different parameter set.
    InvalidKey,
    /// The signing key has no one-time keys left (`idx` reached `2^h`). The key
    /// MUST NOT be used again; signing was refused rather than reuse an index.
    KeyExhausted,
}

// ---------------------------------------------------------------------------
// WOTS+ (RFC 8391 §3)
// ---------------------------------------------------------------------------

/// Derives the `len` WOTS+ secret chain starts from `SK_SEED` via `PRF_keygen`
/// (SP 800-208), writing `len·n` bytes into `out`. Mirrors `expand_seed`.
fn wots_expand_seed(p: &Params, sk_seed: &[u8], pub_seed: &[u8], addr: &mut Adrs, out: &mut [u8]) {
    // The `wots_len` (~67) PRF_keygen calls are mutually independent, so on
    // x86_64+AVX2 (SHA-256 sets) derive them eight at a time through the
    // multi-buffer SHA-256 kernel — this is on the hot keygen/tree-build path.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    if wots_x8::eligible(p) && crate::hash::sha256_mb::supported() {
        wots_x8::expand_seed_x8(p, sk_seed, pub_seed, addr, out);
        return;
    }
    wots_expand_seed_scalar(p, sk_seed, pub_seed, addr, out);
}

/// Scalar reference path for [`wots_expand_seed`]: one `PRF_keygen` per chain.
fn wots_expand_seed_scalar(
    p: &Params,
    sk_seed: &[u8],
    pub_seed: &[u8],
    addr: &mut Adrs,
    out: &mut [u8],
) {
    let n = p.n;
    addr.set_hash(0);
    addr.set_key_and_mask(0);
    // Input to PRF_keygen is PUB_SEED ‖ ADRS (n + 32 bytes).
    let mut buf = [0u8; MAX_N + 32];
    buf[..n].copy_from_slice(&pub_seed[..n]);
    for i in 0..p.wots_len {
        addr.set_chain(i as u32);
        buf[n..n + 32].copy_from_slice(&addr.to_bytes());
        hash::prf_keygen(p, sk_seed, &buf[..n + 32], &mut out[i * n..i * n + n]);
    }
}

/// WOTS+ chaining function (RFC 8391 §3.1.2): apply `F` `steps` times starting
/// from chain position `start`, keying `F` and its bitmask from `PUB_SEED`.
fn wots_chain(
    p: &Params,
    pub_seed: &[u8],
    inout: &mut [u8],
    start: u32,
    steps: u32,
    addr: &mut Adrs,
) {
    let n = p.n;
    let end = (start + steps).min(p.wots_w);
    // PUB_SEED is fixed across the whole chain, so precompute the PRF midstate
    // once and clone it per call (see `hash::prf_base`).
    let base = hash::prf_base(p, pub_seed);
    for i in start..end {
        addr.set_hash(i);
        // KEY = PRF(PUB_SEED, ADRS@keyAndMask=0); BM = PRF(.. keyAndMask=1).
        let mut key = [0u8; MAX_N];
        let mut bm = [0u8; MAX_N];
        addr.set_key_and_mask(0);
        hash::prf_with(p, &base, pub_seed, &addr.to_bytes(), &mut key);
        addr.set_key_and_mask(1);
        hash::prf_with(p, &base, pub_seed, &addr.to_bytes(), &mut bm);
        let mut masked = [0u8; MAX_N];
        for j in 0..n {
            masked[j] = inout[j] ^ bm[j];
        }
        hash::f(p, &key, &masked, inout);
    }
}

/// WOTS+ public key generation (RFC 8391 §3.1.4): full chains over the secret.
fn wots_pkgen(p: &Params, sk_seed: &[u8], pub_seed: &[u8], addr: &mut Adrs, pk: &mut [u8]) {
    let n = p.n;
    wots_expand_seed(p, sk_seed, pub_seed, addr, pk);
    // Every chain runs the full 0..w-1 range here and the chains are mutually
    // independent, so on x86_64+AVX2 (SHA-256 sets) run them 8 at a time through
    // the multi-buffer SHA-256 kernel — this dominates keygen and tree building.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    if wots_x8::eligible(p) && crate::hash::sha256_mb::supported() {
        wots_x8::full_chains(p, pub_seed, addr, pk);
        return;
    }
    for i in 0..p.wots_len {
        addr.set_chain(i as u32);
        wots_chain(
            p,
            pub_seed,
            &mut pk[i * n..i * n + n],
            0,
            p.wots_w - 1,
            addr,
        );
    }
}

/// Fast differential test: the batched WOTS+ chains must equal the scalar
/// `wots_chain` loop over the same chain-start values (a single WOTS+ key, so it
/// avoids the multi-second RFC KAT tree builds).
#[cfg(all(test, feature = "std", target_arch = "x86_64"))]
mod wots_x8_tests {
    use super::*;

    #[test]
    fn batched_matches_scalar() {
        if !crate::hash::sha256_mb::supported() {
            return;
        }
        let p = XmssParamSet::Sha2_10_256.params();
        let n = p.n;
        let mut starts = vec![0u8; p.wots_len * n];
        for (i, b) in starts.iter_mut().enumerate() {
            *b = (i * 7 + 1) as u8;
        }
        let pub_seed: Vec<u8> = (0..n).map(|i| (i * 3 + 5) as u8).collect();
        let mut base = Adrs::new();
        base.set_type(AdrsType::Ots);
        base.set_ots(42);

        let mut pk_scalar = starts.clone();
        for i in 0..p.wots_len {
            let mut a = base;
            a.set_chain(i as u32);
            wots_chain(
                &p,
                &pub_seed,
                &mut pk_scalar[i * n..i * n + n],
                0,
                p.wots_w - 1,
                &mut a,
            );
        }

        let mut pk_batched = starts.clone();
        wots_x8::full_chains(&p, &pub_seed, &base, &mut pk_batched);

        assert_eq!(pk_scalar, pk_batched);
    }

    #[test]
    fn expand_seed_batched_matches_scalar() {
        if !crate::hash::sha256_mb::supported() {
            return;
        }
        let p = XmssParamSet::Sha2_10_256.params();
        let n = p.n;
        let sk_seed: Vec<u8> = (0..n).map(|i| (i * 11 + 3) as u8).collect();
        let pub_seed: Vec<u8> = (0..n).map(|i| (i * 5 + 9) as u8).collect();
        let mut base = Adrs::new();
        base.set_type(AdrsType::Ots);
        base.set_ots(7);

        let mut out_scalar = vec![0u8; p.wots_len * n];
        let mut a_scalar = base;
        wots_expand_seed_scalar(&p, &sk_seed, &pub_seed, &mut a_scalar, &mut out_scalar);

        let mut out_batched = vec![0u8; p.wots_len * n];
        let mut a_batched = base;
        wots_x8::expand_seed_x8(&p, &sk_seed, &pub_seed, &mut a_batched, &mut out_batched);

        assert_eq!(out_scalar, out_batched);
        // The dispatcher and scalar fallback must leave `addr` in the same state.
        assert_eq!(a_scalar.to_bytes(), a_batched.to_bytes());
    }
}

/// Multi-buffer (AVX2) WOTS+ chain evaluation: eight independent chains hashed
/// in lockstep through the 8-way SHA-256 kernel. Produces byte-identical output
/// to the scalar [`wots_chain`] loop (pinned by a differential test); used only
/// for the SHA-256 `n = 32` sets, where `F`/`PRF` are exactly two 64-byte blocks
/// of a 96-byte message.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
mod wots_x8 {
    use super::Adrs;
    use super::params::{HashFamily, Params};
    use crate::hash::sha256::{H256, compress256_soft};
    use crate::hash::sha256_mb::{LANES, compress8};

    /// The batcher handles only the SHA-256, `n = 32`, `padding_len = 32` sets,
    /// where `pad‖key` is exactly one block and `F`/`PRF` are 96-byte messages.
    pub(super) fn eligible(p: &Params) -> bool {
        matches!(p.family, HashFamily::Sha2_256) && p.n == 32 && p.padding_len == 32
    }

    /// Second block of a 96-byte (2-block) SHA-256 message: `data ‖ 0x80 ‖
    /// 0…0 ‖ len`, with `len = 768` bits.
    #[inline]
    fn block1_96(data: &[u8; 32]) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(data);
        b[32] = 0x80;
        b[56..64].copy_from_slice(&768u64.to_be_bytes());
        b
    }

    /// Big-endian serialization of a SHA-256 state into its 32-byte digest.
    #[inline]
    fn state_be(s: &[u32; 8]) -> [u8; 32] {
        let mut o = [0u8; 32];
        for (i, w) in s.iter().enumerate() {
            o[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        o
    }

    /// Runs every WOTS+ chain over its full `0..w-1` range, eight chains at a
    /// time. `pk` enters holding the chain start values and leaves holding the
    /// chain ends. `addr` supplies the layer/tree/OTS fields (chain/hash/keymask
    /// are set per lane).
    pub(super) fn full_chains(p: &Params, pub_seed: &[u8], addr: &Adrs, pk: &mut [u8]) {
        const N: usize = 32;
        // PRF shared block 0 = toByte(3, 32) ‖ PUB_SEED → a single midstate
        // reused for every key/bitmask PRF (PUB_SEED is constant).
        let mut b0 = [0u8; 64];
        b0[31] = 3;
        b0[32..64].copy_from_slice(&pub_seed[..N]);
        let mut prf_mid = H256;
        compress256_soft(&mut prf_mid, &b0);

        let steps = p.wots_w - 1;
        let mut c0 = 0usize;
        while c0 < p.wots_len {
            let lanes = (p.wots_len - c0).min(LANES);
            let mut inout = [[0u8; N]; LANES];
            for (l, io) in inout.iter_mut().enumerate().take(lanes) {
                io.copy_from_slice(&pk[(c0 + l) * N..(c0 + l) * N + N]);
            }

            for step in 0..steps {
                // KEY = PRF(.., keyAndMask=0); BM = PRF(.., keyAndMask=1).
                let mut keyb1 = [[0u8; 64]; LANES];
                let mut bmb1 = [[0u8; 64]; LANES];
                for l in 0..LANES {
                    let chain = if l < lanes { c0 + l } else { c0 };
                    let mut a = *addr;
                    a.set_chain(chain as u32);
                    a.set_hash(step);
                    a.set_key_and_mask(0);
                    keyb1[l] = block1_96(&a.to_bytes());
                    a.set_key_and_mask(1);
                    bmb1[l] = block1_96(&a.to_bytes());
                }
                let mut ks = [prf_mid; LANES];
                compress8(&mut ks, &keyb1);
                let mut bs = [prf_mid; LANES];
                compress8(&mut bs, &bmb1);

                // F(KEY, inout ⊕ BM) = SHA-256(toByte(0,32) ‖ KEY ‖ masked).
                let mut fb0 = [[0u8; 64]; LANES];
                let mut fb1 = [[0u8; 64]; LANES];
                for l in 0..LANES {
                    let key = state_be(&ks[l]);
                    let bm = state_be(&bs[l]);
                    fb0[l][32..64].copy_from_slice(&key);
                    let mut masked = [0u8; N];
                    for j in 0..N {
                        masked[j] = inout[l][j] ^ bm[j];
                    }
                    fb1[l] = block1_96(&masked);
                }
                let mut fs = [H256; LANES];
                compress8(&mut fs, &fb0);
                compress8(&mut fs, &fb1);
                for (l, io) in inout.iter_mut().enumerate().take(lanes) {
                    *io = state_be(&fs[l]);
                }
            }

            for (l, io) in inout.iter().enumerate().take(lanes) {
                pk[(c0 + l) * N..(c0 + l) * N + N].copy_from_slice(io);
            }
            c0 += lanes;
        }
    }

    /// Derives every WOTS+ secret chain start via `PRF_keygen`, eight chains at
    /// a time. Byte-identical to the scalar `wots_expand_seed` loop (pinned by a
    /// differential test); SHA-256 `n = 32` sets only.
    ///
    /// `PRF_keygen(SK_SEED, PUB_SEED ‖ ADRS_i)` = SHA-256 over a 128-byte
    /// (3-block) message `toByte(4,32) ‖ SK_SEED ‖ PUB_SEED ‖ ADRS_i`:
    /// - block0 = `toByte(4,32) ‖ SK_SEED` — constant (SK_SEED fixed) → one
    ///   precomputed midstate, reused for every chain;
    /// - block1 = `PUB_SEED ‖ ADRS_i` — a full 64-byte block, ADRS differs per
    ///   lane (chain index);
    /// - block2 = padding only (`0x80 …  len=1024` bits), identical for all lanes.
    pub(super) fn expand_seed_x8(
        p: &Params,
        sk_seed: &[u8],
        pub_seed: &[u8],
        addr: &mut Adrs,
        out: &mut [u8],
    ) {
        const N: usize = 32;
        // block0 = toByte(4, 32) ‖ SK_SEED → one midstate (SK_SEED is constant).
        let mut b0 = [0u8; 64];
        b0[31] = 4;
        b0[32..64].copy_from_slice(&sk_seed[..N]);
        let mut keygen_mid = H256;
        compress256_soft(&mut keygen_mid, &b0);

        // block2 = padding for a 128-byte message: 0x80 then the bit length
        // (1024) in the trailing u64. Identical across all eight lanes.
        let mut block2 = [0u8; 64];
        block2[0] = 0x80;
        block2[56..64].copy_from_slice(&1024u64.to_be_bytes());

        // Mirror the scalar address state: hash = 0, keyAndMask = 0 (chain set
        // per lane). Leaves `addr` with chain = wots_len - 1, matching the
        // scalar path so any later reader sees the same address.
        addr.set_hash(0);
        addr.set_key_and_mask(0);

        let mut c0 = 0usize;
        while c0 < p.wots_len {
            let lanes = (p.wots_len - c0).min(LANES);
            // block1 = PUB_SEED ‖ ADRS_i per lane.
            let mut b1 = [[0u8; 64]; LANES];
            for (l, b) in b1.iter_mut().enumerate() {
                let chain = if l < lanes { c0 + l } else { c0 };
                addr.set_chain(chain as u32);
                b[..N].copy_from_slice(&pub_seed[..N]);
                b[N..64].copy_from_slice(&addr.to_bytes());
            }
            let mut states = [keygen_mid; LANES];
            compress8(&mut states, &b1);
            let block2s = [block2; LANES];
            compress8(&mut states, &block2s);

            for (l, st) in states.iter().enumerate().take(lanes) {
                out[(c0 + l) * N..(c0 + l) * N + N].copy_from_slice(&state_be(st));
            }
            c0 += lanes;
        }

        // Leave `addr` exactly as the scalar loop does: chain = wots_len - 1
        // (padding lanes above rolled it back to a group start).
        if p.wots_len > 0 {
            addr.set_chain((p.wots_len - 1) as u32);
        }
    }
}

/// `base_w` (RFC 8391 §2.6): decompose `input` into `out.len()` base-`w` digits.
fn base_w(p: &Params, input: &[u8], out: &mut [u32]) {
    let mut total = 0u8;
    let mut bits = 0i32;
    let mut in_idx = 0usize;
    for o in out.iter_mut() {
        if bits == 0 {
            total = input[in_idx];
            in_idx += 1;
            bits = 8;
        }
        bits -= p.wots_log_w as i32;
        *o = ((total >> bits) as u32) & (p.wots_w - 1);
    }
}

/// Computes the `len` WOTS+ chain lengths for an `n`-byte message digest:
/// `base_w(msg)` followed by the base-`w` checksum (RFC 8391 §3.1.5).
fn chain_lengths(p: &Params, msg: &[u8]) -> [u32; MAX_WOTS_LEN] {
    let mut lengths = [0u32; MAX_WOTS_LEN];
    base_w(p, msg, &mut lengths[..p.wots_len1]);

    let mut csum: u32 = 0;
    for &l in &lengths[..p.wots_len1] {
        csum += p.wots_w - 1 - l;
    }
    // Left-shift so the meaningful bits are MSB-aligned in the byte string.
    let shift = (8 - ((p.wots_len2 * p.wots_log_w as usize) % 8)) % 8;
    csum <<= shift;
    let csum_bytes_len = (p.wots_len2 * p.wots_log_w as usize).div_ceil(8);
    let mut csum_bytes = [0u8; 4];
    for (i, b) in csum_bytes.iter_mut().enumerate().take(csum_bytes_len) {
        *b = (csum >> (8 * (csum_bytes_len - 1 - i))) as u8;
    }
    base_w(
        p,
        &csum_bytes[..csum_bytes_len],
        &mut lengths[p.wots_len1..p.wots_len1 + p.wots_len2],
    );
    lengths
}

/// WOTS+ sign (RFC 8391 §3.1.5): partial chains to the message lengths.
fn wots_sign(
    p: &Params,
    msg: &[u8],
    sk_seed: &[u8],
    pub_seed: &[u8],
    addr: &mut Adrs,
    sig: &mut [u8],
) {
    let n = p.n;
    let lengths = chain_lengths(p, msg);
    wots_expand_seed(p, sk_seed, pub_seed, addr, sig);
    for i in 0..p.wots_len {
        addr.set_chain(i as u32);
        wots_chain(p, pub_seed, &mut sig[i * n..i * n + n], 0, lengths[i], addr);
    }
}

/// WOTS+ public key from a signature (RFC 8391 §3.1.6).
fn wots_pk_from_sig(
    p: &Params,
    sig: &[u8],
    msg: &[u8],
    pub_seed: &[u8],
    addr: &mut Adrs,
    pk: &mut [u8],
) {
    let n = p.n;
    let lengths = chain_lengths(p, msg);
    for i in 0..p.wots_len {
        addr.set_chain(i as u32);
        pk[i * n..i * n + n].copy_from_slice(&sig[i * n..i * n + n]);
        wots_chain(
            p,
            pub_seed,
            &mut pk[i * n..i * n + n],
            lengths[i],
            p.wots_w - 1 - lengths[i],
            addr,
        );
    }
}

// ---------------------------------------------------------------------------
// Randomized tree hashing (RFC 8391 §4.1.4 RAND_HASH)
// ---------------------------------------------------------------------------

/// `RAND_HASH(left, right, PUB_SEED, ADRS)` = `H(KEY, (L⊕BM0)‖(R⊕BM1))` with
/// KEY/BM0/BM1 derived from `PUB_SEED` and the address via PRF.
fn rand_hash(
    p: &Params,
    left: &[u8],
    right: &[u8],
    pub_seed: &[u8],
    addr: &mut Adrs,
    out: &mut [u8],
) {
    let n = p.n;
    let mut key = [0u8; MAX_N];
    let mut bm = [0u8; 2 * MAX_N];
    let base = hash::prf_base(p, pub_seed);
    addr.set_key_and_mask(0);
    hash::prf_with(p, &base, pub_seed, &addr.to_bytes(), &mut key);
    addr.set_key_and_mask(1);
    hash::prf_with(p, &base, pub_seed, &addr.to_bytes(), &mut bm[..n]);
    addr.set_key_and_mask(2);
    hash::prf_with(p, &base, pub_seed, &addr.to_bytes(), &mut bm[n..2 * n]);

    let mut masked = [0u8; 2 * MAX_N];
    for i in 0..n {
        masked[i] = left[i] ^ bm[i];
        masked[n + i] = right[i] ^ bm[n + i];
    }
    hash::h(p, &key, &masked, out);
}

/// L-tree (RFC 8391 §4.1.5): compresses a WOTS+ public key to a single leaf.
/// Operates in place over `wots_pk` (which it consumes).
fn l_tree(p: &Params, wots_pk: &mut [u8], pub_seed: &[u8], addr: &mut Adrs, leaf: &mut [u8]) {
    let n = p.n;
    let mut l = p.wots_len;
    let mut height = 0u32;
    addr.set_tree_height(0);
    while l > 1 {
        let parents = l / 2;
        for i in 0..parents {
            addr.set_tree_index(i as u32);
            let mut node = [0u8; MAX_N];
            let mut left = [0u8; MAX_N];
            let mut right = [0u8; MAX_N];
            left[..n].copy_from_slice(&wots_pk[2 * i * n..2 * i * n + n]);
            right[..n].copy_from_slice(&wots_pk[(2 * i + 1) * n..(2 * i + 1) * n + n]);
            rand_hash(p, &left[..n], &right[..n], pub_seed, addr, &mut node);
            wots_pk[i * n..i * n + n].copy_from_slice(&node[..n]);
        }
        if l & 1 == 1 {
            let (lo, hi) = ((l / 2) * n, (l - 1) * n);
            wots_pk.copy_within(hi..hi + n, lo);
            l = l / 2 + 1;
        } else {
            l /= 2;
        }
        height += 1;
        addr.set_tree_height(height);
    }
    leaf[..n].copy_from_slice(&wots_pk[..n]);
}

/// Computes the leaf (L-tree root) for the WOTS+ key pair addressed by
/// `ltree_addr` / `ots_addr` (RFC 8391 §4.1.6).
fn gen_leaf(
    p: &Params,
    sk_seed: &[u8],
    pub_seed: &[u8],
    ltree_addr: &mut Adrs,
    ots_addr: &mut Adrs,
    leaf: &mut [u8],
) {
    let mut pk = vec![0u8; p.wots_sig_bytes()];
    wots_pkgen(p, sk_seed, pub_seed, ots_addr, &mut pk);
    l_tree(p, &mut pk, pub_seed, ltree_addr, leaf);
}

/// All nodes of a subtree, returned level-by-level.
type SubtreeNodes = Vec<Vec<u8>>;

/// Builds **all** nodes of the subtree addressed by `subtree_addr` (its layer +
/// tree fields), level-by-level: `levels[0]` holds the `2^h` leaves, `levels[L]`
/// the `2^{h-L}` nodes at height `L`, and `levels[h]` the single subtree root.
///
/// A subtree depends only on `(sk_seed, pub_seed, layer, tree)` — never on the
/// message or the leaf index — so a signer builds it once and reads every
/// authentication path out of it in `O(h)` (see [`SubtreeCache`]) rather than
/// re-hashing all `2^h` leaves per signature.
fn build_subtree(p: &Params, sk_seed: &[u8], pub_seed: &[u8], subtree_addr: &Adrs) -> SubtreeNodes {
    let n = p.n;
    let th = p.tree_height as usize;

    let mut ots_addr = Adrs::new();
    let mut ltree_addr = Adrs::new();
    let mut node_addr = Adrs::new();
    ots_addr.copy_subtree(subtree_addr);
    ltree_addr.copy_subtree(subtree_addr);
    node_addr.copy_subtree(subtree_addr);
    ots_addr.set_type(AdrsType::Ots);
    ltree_addr.set_type(AdrsType::Ltree);
    node_addr.set_type(AdrsType::HashTree);

    // Level 0: the 2^h WOTS+ leaves.
    let leaf_count = 1usize << th;
    let mut leaves = vec![0u8; leaf_count * n];
    for idx in 0..leaf_count {
        ltree_addr.set_ltree(idx as u32);
        ots_addr.set_ots(idx as u32);
        gen_leaf(
            p,
            sk_seed,
            pub_seed,
            &mut ltree_addr,
            &mut ots_addr,
            &mut leaves[idx * n..idx * n + n],
        );
    }
    let mut levels: SubtreeNodes = Vec::with_capacity(th + 1);
    levels.push(leaves);

    // Internal levels: node `i` at height `L` hashes children `2i`, `2i+1` at
    // height `L-1` under ADRS{tree_height = L-1, tree_index = i} — the same
    // addressing `root_from_sig` (the verifier) uses.
    for level in 1..=th {
        let count = 1usize << (th - level);
        let mut nodes = vec![0u8; count * n];
        let child = &levels[level - 1];
        for i in 0..count {
            node_addr.set_tree_height((level - 1) as u32);
            node_addr.set_tree_index(i as u32);
            let mut parent = [0u8; MAX_N];
            rand_hash(
                p,
                &child[2 * i * n..2 * i * n + n],
                &child[(2 * i + 1) * n..(2 * i + 1) * n + n],
                pub_seed,
                &mut node_addr,
                &mut parent,
            );
            nodes[i * n..i * n + n].copy_from_slice(&parent[..n]);
        }
        levels.push(nodes);
    }
    levels
}

/// Writes the height-`h` authentication path for `idx_leaf` out of a subtree
/// built by [`build_subtree`]: `auth_path[j]` is the sibling of the path node at
/// height `j`, i.e. node `(idx_leaf >> j) ^ 1` of `levels[j]`.
fn auth_path_from_subtree(p: &Params, levels: &[Vec<u8>], idx_leaf: u32, auth_path: &mut [u8]) {
    let n = p.n;
    for j in 0..p.tree_height as usize {
        let sib = ((idx_leaf >> j) ^ 1) as usize;
        auth_path[j * n..j * n + n].copy_from_slice(&levels[j][sib * n..sib * n + n]);
    }
}

/// A signer-side cache of fully-built subtrees, keyed by `(layer, tree)`.
///
/// XMSS / XMSS^MT consume leaves sequentially, so at any moment only the `d`
/// subtrees on the current index path are live; this keeps at most one entry per
/// layer (signing into a new tree at a layer evicts the old one), bounding the
/// cache to `d` subtrees. Cached nodes are public Merkle hashes — the cache holds
/// no secret material and is never serialized; it is rebuilt lazily from the
/// seeds after [`XmssPrivateKey::from_bytes`].
#[derive(Default)]
struct SubtreeCache {
    entries: Vec<(u32, u64, SubtreeNodes)>,
}

impl SubtreeCache {
    /// A cache pre-populated with one already-built subtree (used to hand the
    /// top subtree built during key generation straight to the signer, so the
    /// first signature doesn't rebuild it).
    fn seeded(layer: u32, tree: u64, nodes: SubtreeNodes) -> Self {
        SubtreeCache {
            entries: alloc::vec![(layer, tree, nodes)],
        }
    }

    /// Returns the cached subtree for `(layer, tree)`, building it on first use.
    fn get_or_build(
        &mut self,
        p: &Params,
        sk_seed: &[u8],
        pub_seed: &[u8],
        layer: u32,
        tree: u64,
    ) -> &[Vec<u8>] {
        let pos = match self
            .entries
            .iter()
            .position(|(l, t, _)| *l == layer && *t == tree)
        {
            Some(pos) => pos,
            None => {
                // Only one active subtree per layer; drop any stale sibling.
                self.entries.retain(|(l, _, _)| *l != layer);
                let mut subtree_addr = Adrs::new();
                subtree_addr.set_layer(layer);
                subtree_addr.set_tree(tree);
                let nodes = build_subtree(p, sk_seed, pub_seed, &subtree_addr);
                self.entries.push((layer, tree, nodes));
                self.entries.len() - 1
            }
        };
        &self.entries[pos].2
    }
}

/// Computes a subtree root from a leaf and an authentication path
/// (RFC 8391 §4.1.10, XMSS_rootFromSig inner loop).
fn root_from_sig(
    p: &Params,
    mut leaf_idx: u32,
    leaf: &[u8],
    auth_path: &[u8],
    pub_seed: &[u8],
    node_addr: &mut Adrs,
    root: &mut [u8],
) {
    let n = p.n;
    let th = p.tree_height;
    let mut buffer = [0u8; 2 * MAX_N];
    if leaf_idx & 1 == 1 {
        buffer[..n].copy_from_slice(&auth_path[..n]);
        buffer[n..2 * n].copy_from_slice(&leaf[..n]);
    } else {
        buffer[..n].copy_from_slice(&leaf[..n]);
        buffer[n..2 * n].copy_from_slice(&auth_path[..n]);
    }
    let mut ap = &auth_path[n..];

    for i in 0..th - 1 {
        node_addr.set_tree_height(i);
        leaf_idx >>= 1;
        node_addr.set_tree_index(leaf_idx);
        let mut out = [0u8; MAX_N];
        let mut left = [0u8; MAX_N];
        let mut right = [0u8; MAX_N];
        left[..n].copy_from_slice(&buffer[..n]);
        right[..n].copy_from_slice(&buffer[n..2 * n]);
        rand_hash(p, &left[..n], &right[..n], pub_seed, node_addr, &mut out);
        if leaf_idx & 1 == 1 {
            buffer[n..2 * n].copy_from_slice(&out[..n]);
            buffer[..n].copy_from_slice(&ap[..n]);
        } else {
            buffer[..n].copy_from_slice(&out[..n]);
            buffer[n..2 * n].copy_from_slice(&ap[..n]);
        }
        ap = &ap[n..];
    }
    node_addr.set_tree_height(th - 1);
    leaf_idx >>= 1;
    node_addr.set_tree_index(leaf_idx);
    let mut left = [0u8; MAX_N];
    let mut right = [0u8; MAX_N];
    left[..n].copy_from_slice(&buffer[..n]);
    right[..n].copy_from_slice(&buffer[n..2 * n]);
    rand_hash(p, &left[..n], &right[..n], pub_seed, node_addr, root);
}

// ---------------------------------------------------------------------------
// Core sign / verify (XMSS^MT, with d=1 covering plain XMSS)
// ---------------------------------------------------------------------------

/// Raw secret-key view: `idx ‖ SK_SEED ‖ SK_PRF ‖ root ‖ PUB_SEED`.
struct SkView<'a> {
    p: &'a Params,
    bytes: &'a [u8],
}

impl SkView<'_> {
    fn sk_seed(&self) -> &[u8] {
        &self.bytes[self.p.index_bytes..self.p.index_bytes + self.p.n]
    }
    fn sk_prf(&self) -> &[u8] {
        let o = self.p.index_bytes + self.p.n;
        &self.bytes[o..o + self.p.n]
    }
    fn root(&self) -> &[u8] {
        let o = self.p.index_bytes + 2 * self.p.n;
        &self.bytes[o..o + self.p.n]
    }
    fn pub_seed(&self) -> &[u8] {
        let o = self.p.index_bytes + 3 * self.p.n;
        &self.bytes[o..o + self.p.n]
    }
}

/// Big-endian decode of `len` index bytes.
fn bytes_to_idx(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |acc, &v| (acc << 8) | v as u64)
}

/// Big-endian encode an index into `out` (length `out.len()`).
fn idx_to_bytes(idx: u64, out: &mut [u8]) {
    let len = out.len();
    let mut v = idx;
    for i in (0..len).rev() {
        out[i] = (v & 0xff) as u8;
        v >>= 8;
    }
}

/// Produces a full XMSS / XMSS^MT signature for leaf `idx` over `msg`. The
/// signature buffer layout is `idx ‖ R ‖ (WOTS_sig ‖ auth_path)^d`.
fn core_sign(p: &Params, sk: &SkView, idx: u64, msg: &[u8], cache: &mut SubtreeCache) -> Vec<u8> {
    let n = p.n;
    let mut sig = vec![0u8; p.sig_bytes()];

    // idx
    idx_to_bytes(idx, &mut sig[..p.index_bytes]);

    // R = PRF(SK_PRF, toByte(idx, 32)).
    let mut idx32 = [0u8; 32];
    idx32[24..32].copy_from_slice(&idx.to_be_bytes());
    hash::prf(
        p,
        sk.sk_prf(),
        &idx32,
        &mut sig[p.index_bytes..p.index_bytes + n],
    );

    // mhash = H_msg(R, root, idx, msg).
    let mut mhash = [0u8; MAX_N];
    {
        let r = sig[p.index_bytes..p.index_bytes + n].to_vec();
        hash::h_msg(p, &r, sk.root(), idx, msg, &mut mhash);
    }

    let mut off = p.index_bytes + n;
    let leaf_mask = (1u64 << p.tree_height) - 1;
    let mut cur_idx = idx;
    let mut root = [0u8; MAX_N];
    root[..n].copy_from_slice(&mhash[..n]);

    let mut ots_addr = Adrs::new();
    ots_addr.set_type(AdrsType::Ots);

    for layer in 0..p.d {
        let idx_leaf = (cur_idx & leaf_mask) as u32;
        let tree = cur_idx >> p.tree_height;

        ots_addr.set_layer(layer);
        ots_addr.set_tree(tree);
        ots_addr.set_ots(idx_leaf);

        // WOTS+ signature over the current root (mhash for layer 0).
        wots_sign(
            p,
            &root[..n],
            sk.sk_seed(),
            sk.pub_seed(),
            &mut ots_addr,
            &mut sig[off..off + p.wots_sig_bytes()],
        );
        off += p.wots_sig_bytes();

        // Authentication path + new (upper) root, read from the cached subtree
        // (built once per (layer, tree) instead of rebuilt every signature).
        let th = p.tree_height as usize;
        let nodes = cache.get_or_build(p, sk.sk_seed(), sk.pub_seed(), layer, tree);
        auth_path_from_subtree(p, nodes, idx_leaf, &mut sig[off..off + th * n]);
        // The subtree root becomes the message signed at the next layer up.
        root[..n].copy_from_slice(&nodes[th][..n]);
        off += th * n;

        cur_idx = tree;
    }
    sig
}

/// Verifies a full XMSS / XMSS^MT signature against `pub_root ‖ pub_seed`.
fn core_verify(p: &Params, pub_root: &[u8], pub_seed: &[u8], sig: &[u8], msg: &[u8]) -> bool {
    let n = p.n;
    if sig.len() != p.sig_bytes() {
        return false;
    }
    let idx = bytes_to_idx(&sig[..p.index_bytes]);
    // A valid signature is always produced at a leaf strictly below the tree;
    // reject an out-of-range index early instead of relying on the final ct_eq.
    if p.full_height < 64 && idx >= (1u64 << p.full_height) {
        return false;
    }
    let r = &sig[p.index_bytes..p.index_bytes + n];

    let mut mhash = [0u8; MAX_N];
    hash::h_msg(p, r, pub_root, idx, msg, &mut mhash);

    let mut off = p.index_bytes + n;
    let leaf_mask = (1u64 << p.tree_height) - 1;
    let mut cur_idx = idx;
    let mut root = [0u8; MAX_N];
    root[..n].copy_from_slice(&mhash[..n]);

    let mut ots_addr = Adrs::new();
    let mut ltree_addr = Adrs::new();
    let mut node_addr = Adrs::new();
    ots_addr.set_type(AdrsType::Ots);
    ltree_addr.set_type(AdrsType::Ltree);
    node_addr.set_type(AdrsType::HashTree);

    for layer in 0..p.d {
        let idx_leaf = (cur_idx & leaf_mask) as u32;
        let tree = cur_idx >> p.tree_height;

        ots_addr.set_layer(layer);
        ltree_addr.set_layer(layer);
        node_addr.set_layer(layer);
        ots_addr.set_tree(tree);
        ltree_addr.set_tree(tree);
        node_addr.set_tree(tree);
        ots_addr.set_ots(idx_leaf);

        // Recover the WOTS+ public key, then the leaf via L-tree.
        let mut wots_pk = vec![0u8; p.wots_sig_bytes()];
        wots_pk_from_sig(
            p,
            &sig[off..off + p.wots_sig_bytes()],
            &root[..n],
            pub_seed,
            &mut ots_addr,
            &mut wots_pk,
        );
        off += p.wots_sig_bytes();

        ltree_addr.set_ltree(idx_leaf);
        let mut leaf = [0u8; MAX_N];
        l_tree(p, &mut wots_pk, pub_seed, &mut ltree_addr, &mut leaf);

        let auth_path = &sig[off..off + p.tree_height as usize * n];
        off += p.tree_height as usize * n;
        let mut new_root = [0u8; MAX_N];
        root_from_sig(
            p,
            idx_leaf,
            &leaf[..n],
            auth_path,
            pub_seed,
            &mut node_addr,
            &mut new_root,
        );
        root[..n].copy_from_slice(&new_root[..n]);
        cur_idx = tree;
    }
    bool::from(root[..n].ct_eq(&pub_root[..n]))
}

/// Generates the raw secret/public key payloads from a `3n`-byte seed
/// (`SK_SEED ‖ SK_PRF ‖ PUB_SEED`). Returns `(sk_bytes, pk_bytes, top_subtree)`,
/// where `top_subtree` is the fully-built layer-`(d-1)` tree (for seeding the
/// signer's [`SubtreeCache`]).
fn core_keygen(p: &Params, seed: &[u8]) -> (Vec<u8>, Vec<u8>, SubtreeNodes) {
    let n = p.n;
    let mut sk = vec![0u8; p.sk_bytes()];
    // idx = 0 (already zero).
    sk[p.index_bytes..p.index_bytes + 2 * n].copy_from_slice(&seed[..2 * n]); // SK_SEED ‖ SK_PRF
    sk[p.index_bytes + 3 * n..p.index_bytes + 4 * n].copy_from_slice(&seed[2 * n..3 * n]); // PUB_SEED

    // Compute the top-most subtree root.
    let sk_seed = seed[..n].to_vec();
    let pub_seed = seed[2 * n..3 * n].to_vec();
    let mut top_addr = Adrs::new();
    top_addr.set_layer(p.d - 1);
    let levels = build_subtree(p, &sk_seed, &pub_seed, &top_addr);
    let th = p.tree_height as usize;
    sk[p.index_bytes + 2 * n..p.index_bytes + 3 * n].copy_from_slice(&levels[th][..n]);

    let mut pk = vec![0u8; p.pk_bytes()];
    pk[..n].copy_from_slice(&levels[th][..n]);
    pk[n..2 * n].copy_from_slice(&pub_seed);
    // Hand the just-built top subtree to the caller so it can seed the signer's
    // cache (the top layer's tree is always tree 0, so this is reused on every
    // signature; for single-tree XMSS it means signing never rebuilds the tree).
    (sk, pk, levels)
}

// ---------------------------------------------------------------------------
// Serialization helpers (raw, self-describing format)
// ---------------------------------------------------------------------------

const SK_MAGIC: &[u8; 4] = b"XMSk";
const MTSK_MAGIC: &[u8; 4] = b"XMTk";

/// Maximum per-layer subtree height for which [`validate_raw_sk`] recomputes
/// the top-layer Merkle root from the stored seeds as a defense-in-depth check
/// against a tampered `root` field.
///
/// The recompute is a full `O(2^tree_height)` subtree build (each leaf is a
/// WOTS+ keygen plus an L-tree), and `tree_height` reaches 20 for
/// `Sha2_20_256` / `Shake_20_256` / `Sha2_40_2_256` / `Sha2_60_3_256` etc. —
/// roughly `10^9` hash compressions from a hostile blob whose parameter OID
/// the attacker controls, i.e. a CPU-DoS on load. `tree_height <= 15` (`2^15`
/// leaves) recomputes in well under a second on the worst supported set and
/// covers all `tree_height ∈ {5, 10}` XMSS^MT splits plus `Sha2_10_256` /
/// `Shake_10_256`; taller trees trust the stored root instead (see
/// [`validate_raw_sk`] for why that is fail-closed). Mirrors
/// `lms::LEGACY_RECOMPUTE_MAX_H`.
const RECOMPUTE_MAX_TREE_HEIGHT: u32 = 15;

/// Validates a parsed raw signing key (`idx ‖ SK_SEED ‖ SK_PRF ‖ root ‖
/// PUB_SEED`) before it is trusted for signing — the integrity check that
/// stateful schemes need so a corrupted or rewound persisted key cannot lead to
/// one-time-key reuse (mirrors `lms::*::from_bytes` index bounds and root
/// handling).
///
/// Rejects:
/// 1. An out-of-range leaf index. The signer treats `idx == 2^full_height` as
///    the exhausted sentinel (see `XmssPrivateKey::sign`), so that value is a
///    legitimate persisted state and is accepted; only `idx > 2^full_height` is
///    rejected.
/// 2. For `tree_height <= RECOMPUTE_MAX_TREE_HEIGHT` only: a stored root that
///    does not match the one recomputed from the seeds, so a tampered `root`
///    (or a seed/root pair that never belonged together) fails.
///
/// # Trusting the stored root is safe (tall trees)
///
/// Above the cap the stored root is taken as-is — recomputing it would be the
/// `O(2^tree_height)` CPU-DoS described at [`RECOMPUTE_MAX_TREE_HEIGHT`]. The
/// root is NOT secret: it is the first half of the public key (`root ‖
/// PUB_SEED`) and is only ever fed to `H_msg` randomization and
/// `public_key()`; authentication paths and WOTS+ chains are always recomputed
/// from `SK_SEED`, never read from `root`. A tampered root therefore yields a
/// wrong public key under which the genuine signatures simply fail to verify —
/// a fail-closed self-DoS, never a forgery (the attacker lacks the seeds). An
/// attacker able to rewrite the key file could instead rewind `idx` and force
/// catastrophic one-time-key reuse, which is strictly worse — so burning a
/// full keygen on every load to validate a public value buys nothing. Same
/// policy as `lms::LmsPrivateKey::from_bytes` (root-bearing format).
fn validate_raw_sk(p: &Params, raw: &[u8]) -> Result<(), Error> {
    let n = p.n;
    let idx = bytes_to_idx(&raw[..p.index_bytes]);
    // Match the signer's exhaustion convention exactly: `full_height >= 64`
    // never exhausts (the index can never overflow the tree), otherwise the
    // valid range is `0..=exhausted_index()` (inclusive of the exhausted
    // sentinel). For the h=40 sets that sentinel is `2^h - 1` rather than `2^h`,
    // so a wrapped/edge state above it cannot be reloaded as usable.
    if let Some(max) = p.exhausted_index()
        && idx > max
    {
        return Err(Error::InvalidKey);
    }

    if p.tree_height > RECOMPUTE_MAX_TREE_HEIGHT {
        // Trust the stored (public) root — see the method docs above for the
        // fail-closed argument.
        return Ok(());
    }

    // Recompute the top (layer `d-1`) subtree root from the stored seeds and
    // compare it against the persisted root, the same way `core_keygen` derives
    // it. Tree 0 of the top layer is the public root for both XMSS and XMSS^MT.
    let sk_seed = &raw[p.index_bytes..p.index_bytes + n];
    let stored_root = &raw[p.index_bytes + 2 * n..p.index_bytes + 3 * n];
    let pub_seed = &raw[p.index_bytes + 3 * n..p.index_bytes + 4 * n];
    let mut top_addr = Adrs::new();
    top_addr.set_layer(p.d - 1);
    let levels = build_subtree(p, sk_seed, pub_seed, &top_addr);
    let th = p.tree_height as usize;
    if !bool::from(levels[th][..n].ct_eq(stored_root)) {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

fn wipe(v: &mut [u8]) {
    for b in v.iter_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(&v);
}

// ---------------------------------------------------------------------------
// Public XMSS key API
// ---------------------------------------------------------------------------

/// A stateful XMSS signing key (RFC 8391 §4.1).
///
/// Holds the secret seeds and the next leaf index. See the [module
/// docs](self) for the mandatory persist-after-every-sign discipline; this type
/// is intentionally not [`Clone`].
pub struct XmssPrivateKey {
    set: XmssParamSet,
    /// `idx ‖ SK_SEED ‖ SK_PRF ‖ root ‖ PUB_SEED`.
    bytes: Vec<u8>,
    /// In-memory, non-serialized cache of built subtrees (public node hashes),
    /// so each signature reads its authentication path in `O(h)`.
    cache: SubtreeCache,
}

/// An XMSS verification key (`root ‖ PUB_SEED`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct XmssPublicKey {
    set: XmssParamSet,
    bytes: Vec<u8>,
}

impl XmssPrivateKey {
    /// The parameter set this key was generated for.
    pub fn parameter_set(&self) -> XmssParamSet {
        self.set
    }

    /// Deterministically derives a key pair from a `3n`-byte seed
    /// (`SK_SEED ‖ SK_PRF ‖ PUB_SEED`). The seed is caller-supplied local key
    /// material.
    ///
    /// # Panics
    ///
    /// Panics if `seed` is shorter than `3n` bytes.
    pub fn from_seed(set: XmssParamSet, seed: &[u8]) -> Self {
        let p = set.params();
        assert!(
            seed.len() >= 3 * p.n,
            "XMSS from_seed: seed must be 3n bytes"
        );
        let (bytes, _pk, top) = core_keygen(&p, &seed[..3 * p.n]);
        XmssPrivateKey {
            set,
            bytes,
            cache: SubtreeCache::seeded(p.d - 1, 0, top),
        }
    }

    /// Generates a fresh key pair from a cryptographically secure `rng`.
    pub fn generate<R: RngCore + CryptoRng>(set: XmssParamSet, rng: &mut R) -> Self {
        let p = set.params();
        let mut seed = vec![0u8; 3 * p.n];
        rng.fill_bytes(&mut seed);
        let sk = Self::from_seed(set, &seed);
        wipe(&mut seed);
        sk
    }

    /// The matching public key (`root ‖ PUB_SEED`).
    pub fn public_key(&self) -> XmssPublicKey {
        let p = self.set.params();
        let n = p.n;
        let mut bytes = vec![0u8; 2 * n];
        bytes[..n].copy_from_slice(&self.bytes[p.index_bytes + 2 * n..p.index_bytes + 3 * n]);
        bytes[n..2 * n].copy_from_slice(&self.bytes[p.index_bytes + 3 * n..p.index_bytes + 4 * n]);
        XmssPublicKey {
            set: self.set,
            bytes,
        }
    }

    /// The next leaf index that will be consumed by [`sign`](Self::sign).
    pub fn index(&self) -> u64 {
        let p = self.set.params();
        bytes_to_idx(&self.bytes[..p.index_bytes])
    }

    /// The number of one-time keys still available (`2^h − idx`).
    pub fn remaining(&self) -> u64 {
        let p = self.set.params();
        let total = 1u64 << p.full_height;
        total.saturating_sub(self.index())
    }

    /// Signs `msg`, consuming the current one-time key and advancing the index.
    ///
    /// **Persist `self.to_bytes()` to durable storage before releasing the
    /// returned signature**, and never sign twice from the same index — see the
    /// [module docs](self). Returns [`Error::KeyExhausted`] when no one-time
    /// keys remain (the key MUST NOT be reused after that).
    pub fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let p = self.set.params();
        let idx = self.index();
        if idx >= (1u64 << p.full_height) {
            return Err(Error::KeyExhausted);
        }
        let sig = {
            let view = SkView {
                p: &p,
                bytes: &self.bytes,
            };
            core_sign(&p, &view, idx, msg, &mut self.cache)
        };
        // Advance the stored index only after the signature is produced.
        idx_to_bytes(idx + 1, &mut self.bytes[..p.index_bytes]);
        Ok(sig)
    }

    /// The serialized signing key: `magic ‖ oid ‖ raw_sk`, where `raw_sk` is
    /// `idx ‖ SK_SEED ‖ SK_PRF ‖ root ‖ PUB_SEED`. The embedded `idx` is what
    /// makes the state recoverable — persist this after every sign.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.bytes.len());
        out.extend_from_slice(SK_MAGIC);
        out.extend_from_slice(&self.set.oid().to_be_bytes());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Parses a signing key previously produced by [`to_bytes`](Self::to_bytes),
    /// resuming from its stored index.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 8 || &bytes[..4] != SK_MAGIC {
            return Err(Error::InvalidKey);
        }
        let oid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let set = XmssParamSet::from_oid(oid).ok_or(Error::InvalidKey)?;
        let p = set.params();
        let raw = &bytes[8..];
        if raw.len() != p.sk_bytes() {
            return Err(Error::InvalidKey);
        }
        validate_raw_sk(&p, raw)?;
        Ok(XmssPrivateKey {
            set,
            bytes: raw.to_vec(),
            cache: SubtreeCache::default(),
        })
    }
}

impl Drop for XmssPrivateKey {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl XmssPublicKey {
    /// The parameter set this key belongs to.
    pub fn parameter_set(&self) -> XmssParamSet {
        self.set
    }

    /// Verifies `sig` over `msg`.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let p = self.set.params();
        let n = p.n;
        core_verify(&p, &self.bytes[..n], &self.bytes[n..2 * n], sig, msg)
    }

    /// The raw public key bytes (`root ‖ PUB_SEED`).
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parses a raw public key (`root ‖ PUB_SEED`) for parameter `set`.
    pub fn from_bytes(set: XmssParamSet, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != set.params().pk_bytes() {
            return Err(Error::InvalidKey);
        }
        Ok(XmssPublicKey {
            set,
            bytes: bytes.to_vec(),
        })
    }
}

// ---------------------------------------------------------------------------
// Public XMSS^MT key API
// ---------------------------------------------------------------------------

/// A stateful XMSS^MT signing key (RFC 8391 §4.2).
///
/// Same single-use-per-index discipline as [`XmssPrivateKey`]; see the [module
/// docs](self). Not [`Clone`].
pub struct XmssMtPrivateKey {
    set: XmssMtParamSet,
    bytes: Vec<u8>,
    /// In-memory, non-serialized cache of built subtrees (public node hashes);
    /// holds at most one subtree per layer along the current index path.
    cache: SubtreeCache,
}

/// An XMSS^MT verification key (`root ‖ PUB_SEED`).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct XmssMtPublicKey {
    set: XmssMtParamSet,
    bytes: Vec<u8>,
}

impl XmssMtPrivateKey {
    /// The parameter set this key was generated for.
    pub fn parameter_set(&self) -> XmssMtParamSet {
        self.set
    }

    /// Deterministically derives a key pair from a `3n`-byte seed
    /// (`SK_SEED ‖ SK_PRF ‖ PUB_SEED`).
    ///
    /// # Panics
    ///
    /// Panics if `seed` is shorter than `3n` bytes.
    pub fn from_seed(set: XmssMtParamSet, seed: &[u8]) -> Self {
        let p = set.params();
        assert!(
            seed.len() >= 3 * p.n,
            "XMSS^MT from_seed: seed must be 3n bytes"
        );
        let (bytes, _pk, top) = core_keygen(&p, &seed[..3 * p.n]);
        XmssMtPrivateKey {
            set,
            bytes,
            cache: SubtreeCache::seeded(p.d - 1, 0, top),
        }
    }

    /// Generates a fresh key pair from a cryptographically secure `rng`.
    pub fn generate<R: RngCore + CryptoRng>(set: XmssMtParamSet, rng: &mut R) -> Self {
        let p = set.params();
        let mut seed = vec![0u8; 3 * p.n];
        rng.fill_bytes(&mut seed);
        let sk = Self::from_seed(set, &seed);
        wipe(&mut seed);
        sk
    }

    /// The matching public key.
    pub fn public_key(&self) -> XmssMtPublicKey {
        let p = self.set.params();
        let n = p.n;
        let mut bytes = vec![0u8; 2 * n];
        bytes[..n].copy_from_slice(&self.bytes[p.index_bytes + 2 * n..p.index_bytes + 3 * n]);
        bytes[n..2 * n].copy_from_slice(&self.bytes[p.index_bytes + 3 * n..p.index_bytes + 4 * n]);
        XmssMtPublicKey {
            set: self.set,
            bytes,
        }
    }

    /// The next leaf index that will be consumed by [`sign`](Self::sign).
    pub fn index(&self) -> u64 {
        let p = self.set.params();
        bytes_to_idx(&self.bytes[..p.index_bytes])
    }

    /// The number of one-time keys still available (`2^h − idx`).
    pub fn remaining(&self) -> u64 {
        let p = self.set.params();
        let total = if p.full_height >= 64 {
            u64::MAX
        } else {
            1u64 << p.full_height
        };
        total.saturating_sub(self.index())
    }

    /// Signs `msg`, consuming the current one-time key and advancing the index.
    ///
    /// **Persist `self.to_bytes()` before releasing the returned signature.**
    /// Returns [`Error::KeyExhausted`] when no one-time keys remain.
    pub fn sign(&mut self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let p = self.set.params();
        let idx = self.index();
        // `exhausted_index()` is `None` for h >= 64 (no overflow possible) and,
        // crucially, returns `2^h - 1` instead of `2^h` for the h=40 sets whose
        // index field is exactly `h` bits wide — there `2^h` would wrap to 0 on
        // store and reuse leaf 0's one-time key.
        if p.exhausted_index().is_some_and(|max| idx >= max) {
            return Err(Error::KeyExhausted);
        }
        let sig = {
            let view = SkView {
                p: &p,
                bytes: &self.bytes,
            };
            core_sign(&p, &view, idx, msg, &mut self.cache)
        };
        idx_to_bytes(idx + 1, &mut self.bytes[..p.index_bytes]);
        Ok(sig)
    }

    /// The serialized signing key: `magic ‖ oid ‖ raw_sk`. Persist after every
    /// sign; the embedded index makes the state recoverable.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.bytes.len());
        out.extend_from_slice(MTSK_MAGIC);
        out.extend_from_slice(&self.set.oid().to_be_bytes());
        out.extend_from_slice(&self.bytes);
        out
    }

    /// Parses a signing key previously produced by [`to_bytes`](Self::to_bytes).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 8 || &bytes[..4] != MTSK_MAGIC {
            return Err(Error::InvalidKey);
        }
        let oid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let set = XmssMtParamSet::from_oid(oid).ok_or(Error::InvalidKey)?;
        let p = set.params();
        let raw = &bytes[8..];
        if raw.len() != p.sk_bytes() {
            return Err(Error::InvalidKey);
        }
        validate_raw_sk(&p, raw)?;
        Ok(XmssMtPrivateKey {
            set,
            bytes: raw.to_vec(),
            cache: SubtreeCache::default(),
        })
    }
}

impl Drop for XmssMtPrivateKey {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

impl XmssMtPublicKey {
    /// The parameter set this key belongs to.
    pub fn parameter_set(&self) -> XmssMtParamSet {
        self.set
    }

    /// Verifies `sig` over `msg`.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        let p = self.set.params();
        let n = p.n;
        core_verify(&p, &self.bytes[..n], &self.bytes[n..2 * n], sig, msg)
    }

    /// The raw public key bytes (`root ‖ PUB_SEED`).
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parses a raw public key for parameter `set`.
    pub fn from_bytes(set: XmssMtParamSet, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != set.params().pk_bytes() {
            return Err(Error::InvalidKey);
        }
        Ok(XmssMtPublicKey {
            set,
            bytes: bytes.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests;
