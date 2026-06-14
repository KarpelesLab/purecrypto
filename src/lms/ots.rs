//! LM-OTS one-time signatures (RFC 8554 §4).
//!
//! All routines thread the LMS identifier `I` (16 bytes) and leaf index `q`
//! explicitly, since an LM-OTS key is always used as part of an LMS tree.

use super::params::{D_MESG, D_PBLC, LmotsType, MAX_P, N};
use crate::hash::{Digest, Sha256};

/// `coef(S, i, w)`: the i-th `w`-bit coefficient of byte string `S`
/// (RFC 8554 §3.1.3).
fn coef(s: &[u8], i: usize, w: u32) -> u32 {
    // (2^w - 1) AND (S[floor(i*w/8)] >> (8 - (w*(i mod (8/w)) + w)))
    let per_byte = 8 / w as usize; // coefficients per byte
    let byte = s[i * w as usize / 8];
    let shift = 8 - (w * (i % per_byte) as u32 + w);
    let mask = (1u32 << w) - 1;
    (byte as u32 >> shift) & mask
}

/// `Cksm(S)` (RFC 8554 §4.4, Algorithm 2): a 16-bit checksum of the digest.
fn cksm(s: &[u8], t: LmotsType) -> u16 {
    let w = t.w();
    let max = t.max_digit();
    let count = N * 8 / w as usize;
    let mut sum: u16 = 0;
    for i in 0..count {
        sum = sum.wrapping_add((max - coef(s, i, w)) as u16);
    }
    sum << t.ls()
}

/// Builds `Q || Cksm(Q)` (digest followed by the big-endian checksum) so the
/// signing/verifying loops can index Winternitz coefficients uniformly.
fn q_with_checksum(t: LmotsType, q_digest: &[u8; N]) -> [u8; N + 2] {
    let mut buf = [0u8; N + 2];
    buf[..N].copy_from_slice(q_digest);
    let c = cksm(q_digest, t);
    buf[N] = (c >> 8) as u8;
    buf[N + 1] = c as u8;
    buf
}

/// `Q = H(I || u32str(q) || u16str(D_MESG) || C || message)` (RFC 8554 §4.5).
fn compute_q(i_id: &[u8; 16], q: u32, c: &[u8; N], message: &[u8]) -> [u8; N] {
    let mut h = Sha256::new();
    h.update(i_id);
    h.update(&q.to_be_bytes());
    h.update(&D_MESG.to_be_bytes());
    h.update(c);
    h.update(message);
    h.finalize()
}

/// One Winternitz-chain step: `H(I || u32str(q) || u16str(i) || u8str(j) || tmp)`.
fn chain_step(i_id: &[u8; 16], q: u32, chain: u16, j: u8, tmp: &mut [u8; N]) {
    let mut h = Sha256::new();
    h.update(i_id);
    h.update(&q.to_be_bytes());
    h.update(&chain.to_be_bytes());
    h.update(&[j]);
    h.update(&*tmp);
    *tmp = h.finalize();
}

/// Derives the LM-OTS private element `x[chain]` pseudorandomly from the LMS
/// master `seed` (RFC 8554 Appendix A; the variant standardized in
/// NIST SP 800-208 §6.2): `x_q[i] = H(I || u32str(q) || u16str(i) || 0xff || SEED)`.
pub(crate) fn derive_x(i_id: &[u8; 16], seed: &[u8; N], q: u32, chain: u16, out: &mut [u8; N]) {
    let mut h = Sha256::new();
    h.update(i_id);
    h.update(&q.to_be_bytes());
    h.update(&chain.to_be_bytes());
    h.update(&[0xffu8]);
    h.update(seed);
    *out = h.finalize();
}

/// Derives a deterministic LM-OTS message randomizer
/// `C = H(I || u32str(q) || u16str(0xfffd) || 0xff || SEED || message)`.
///
/// Used for the *pinned* (non-bottom) levels of a multi-level HSS key, which
/// re-emit the signature of the same fixed leaf over the same child public key
/// on every `sign()` call. An LM-OTS key is one-time: re-signing it with a
/// *different* `C` changes `Q = H(I || q || D_MESG || C || message)` and
/// exposes the Winternitz chains at new coefficient vectors — catastrophic key
/// reuse enabling forgery. Deriving `C` from the secret seed and the signed
/// bytes makes every re-emission byte-identical.
///
/// The chain index `0xfffd` cannot collide with [`derive_x`] (whose chain
/// indices are `< p <= 265`) and matches the C-randomizer index used by the
/// RFC 8554 reference implementation.
pub(crate) fn derive_c(i_id: &[u8; 16], seed: &[u8; N], q: u32, message: &[u8]) -> [u8; N] {
    let mut h = Sha256::new();
    h.update(i_id);
    h.update(&q.to_be_bytes());
    h.update(&0xfffdu16.to_be_bytes());
    h.update(&[0xffu8]);
    h.update(seed);
    h.update(message);
    h.finalize()
}

/// Computes the LM-OTS public key `K` for leaf `q` from the master `seed`
/// (RFC 8554 §4.3, Algorithm 1, with the Appendix A private-element derivation).
///
/// On x86_64 with AVX2 this dispatches to a multi-buffer SHA-256 batcher
/// ([`lmots_x8::public_key_x8`]) that evaluates the `p` Winternitz chains eight
/// at a time; the scalar [`public_key_scalar`] is the fallback and the
/// reference for the differential test.
pub(crate) fn public_key(t: LmotsType, i_id: &[u8; 16], seed: &[u8; N], q: u32) -> [u8; N] {
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    if crate::hash::sha256_mb::supported() {
        return lmots_x8::public_key_x8(t, i_id, seed, q);
    }
    public_key_scalar(t, i_id, seed, q)
}

/// Scalar reference implementation of [`public_key`]: runs each of the `p`
/// Winternitz chains over its full `0..max` range one at a time, then folds the
/// chain outputs into `K = H(I ‖ q ‖ D_PBLC ‖ K_0 ‖ … ‖ K_{p-1})`.
pub(crate) fn public_key_scalar(t: LmotsType, i_id: &[u8; 16], seed: &[u8; N], q: u32) -> [u8; N] {
    let p = t.p();
    let max = t.max_digit();
    let mut k_hash = Sha256::new();
    k_hash.update(i_id);
    k_hash.update(&q.to_be_bytes());
    k_hash.update(&D_PBLC.to_be_bytes());
    let mut tmp = [0u8; N];
    for chain in 0..p {
        derive_x(i_id, seed, q, chain as u16, &mut tmp);
        for j in 0..max {
            chain_step(i_id, q, chain as u16, j as u8, &mut tmp);
        }
        k_hash.update(&tmp);
    }
    k_hash.finalize()
}

/// Multi-buffer batcher for [`public_key`]: evaluates the LM-OTS Winternitz
/// chains eight at a time through the AVX2 multi-buffer SHA-256 kernel.
///
/// Every chain runs the full `0..max` range in lockstep, so all eight lanes
/// share the same `j` schedule. Each `derive_x` / `chain_step` is a single
/// 55-byte (one-block) SHA-256 message; the layouts here are byte-for-byte the
/// scalar [`derive_x`] / [`chain_step`] in this module. The final
/// `K = H(I ‖ q ‖ D_PBLC ‖ K_0 ‖ … ‖ K_{p-1})` stays scalar and absorbs the
/// chain outputs in strict order `0..p`.
#[cfg(all(feature = "std", target_arch = "x86_64"))]
mod lmots_x8 {
    use super::{D_PBLC, LmotsType, N};
    use crate::hash::sha256::H256;
    use crate::hash::sha256_mb::{LANES, compress8};
    use crate::hash::{Digest, Sha256};

    /// Builds the single padded SHA-256 block for a 55-byte LM-OTS message
    /// `I(16) ‖ u32be(q) ‖ u16be(chain) ‖ byte22 ‖ tail(32)`. `byte22` is `0xff`
    /// for `derive_x` and the chain index `j` for `chain_step`.
    #[inline]
    fn block55(i_id: &[u8; 16], q: u32, chain: u16, byte22: u8, tail: &[u8; N]) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[..16].copy_from_slice(i_id);
        b[16..20].copy_from_slice(&q.to_be_bytes());
        b[20..22].copy_from_slice(&chain.to_be_bytes());
        b[22] = byte22;
        b[23..55].copy_from_slice(tail);
        b[55] = 0x80;
        // Message length in bits: 55 * 8 = 440.
        b[56..64].copy_from_slice(&440u64.to_be_bytes());
        b
    }

    /// Big-endian serialization of a SHA-256 state into its 32-byte digest.
    #[inline]
    fn state_be(s: &[u32; 8]) -> [u8; N] {
        let mut o = [0u8; N];
        for (i, w) in s.iter().enumerate() {
            o[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        o
    }

    /// Computes the LM-OTS public key `K` for leaf `q`, batching the `p`
    /// Winternitz chains eight at a time. Equivalent to [`super::public_key_scalar`].
    pub(super) fn public_key_x8(t: LmotsType, i_id: &[u8; 16], seed: &[u8; N], q: u32) -> [u8; N] {
        let p = t.p();
        let max = t.max_digit();

        let mut k_hash = Sha256::new();
        k_hash.update(i_id);
        k_hash.update(&q.to_be_bytes());
        k_hash.update(&D_PBLC.to_be_bytes());

        let mut c0 = 0usize;
        while c0 < p {
            let lanes = (p - c0).min(LANES);

            // derive_x for the eight lanes. Lanes beyond `lanes` duplicate the
            // first chain of the group so compress8 stays in bounds; their
            // outputs are never consumed.
            let mut blocks = [[0u8; 64]; LANES];
            for (l, blk) in blocks.iter_mut().enumerate() {
                let chain = if l < lanes { c0 + l } else { c0 };
                *blk = block55(i_id, q, chain as u16, 0xff, seed);
            }
            let mut states = [H256; LANES];
            compress8(&mut states, &blocks);
            let mut tmps = [[0u8; N]; LANES];
            for (l, tmp) in tmps.iter_mut().enumerate() {
                *tmp = state_be(&states[l]);
            }

            // Run the chains in lockstep over the full 0..max range.
            for j in 0..max {
                let mut blocks = [[0u8; 64]; LANES];
                for (l, blk) in blocks.iter_mut().enumerate() {
                    let chain = if l < lanes { c0 + l } else { c0 };
                    *blk = block55(i_id, q, chain as u16, j as u8, &tmps[l]);
                }
                let mut states = [H256; LANES];
                compress8(&mut states, &blocks);
                for (l, tmp) in tmps.iter_mut().enumerate() {
                    *tmp = state_be(&states[l]);
                }
            }

            // Absorb the valid lanes' chain outputs into K in chain order.
            for tmp in tmps.iter().take(lanes) {
                k_hash.update(tmp);
            }
            c0 += lanes;
        }

        k_hash.finalize()
    }
}

/// Differential test: the AVX2 multi-buffer batcher must reproduce the scalar
/// public key byte-for-byte across LM-OTS parameter sets and random inputs.
#[cfg(all(test, feature = "std", target_arch = "x86_64"))]
mod lmots_x8_tests {
    use super::{LmotsType, N, lmots_x8, public_key_scalar};

    #[test]
    fn batched_matches_scalar() {
        if !crate::hash::sha256_mb::supported() {
            return;
        }
        // Cheap xorshift PRNG for random-but-deterministic I/seed/q.
        let mut s = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        // Include the w=8 default and one other set (w=4); cover w=1/w=2 too.
        let types = [
            LmotsType::Sha256N32W8,
            LmotsType::Sha256N32W4,
            LmotsType::Sha256N32W2,
            LmotsType::Sha256N32W1,
        ];
        for t in types {
            for _ in 0..8 {
                let mut i_id = [0u8; 16];
                for b in i_id.iter_mut() {
                    *b = (next() >> 24) as u8;
                }
                let mut seed = [0u8; N];
                for b in seed.iter_mut() {
                    *b = (next() >> 24) as u8;
                }
                let q = next() as u32;
                let want = public_key_scalar(t, &i_id, &seed, q);
                let got = lmots_x8::public_key_x8(t, &i_id, &seed, q);
                assert_eq!(got, want, "type {t:?}, q={q}");
            }
        }
    }
}

/// Generates an LM-OTS signature into `out` (RFC 8554 §4.5, Algorithm 3).
///
/// `out` receives `u32str(type) || C || y[0] || ... || y[p-1]`
/// (`t.sig_len()` bytes). `c` is the per-signature randomizer.
pub(crate) fn sign(
    t: LmotsType,
    i_id: &[u8; 16],
    seed: &[u8; N],
    q: u32,
    c: &[u8; N],
    message: &[u8],
    out: &mut [u8],
) {
    let p = t.p();
    let q_digest = compute_q(i_id, q, c, message);
    let qc = q_with_checksum(t, &q_digest);

    out[..4].copy_from_slice(&t.typecode().to_be_bytes());
    out[4..4 + N].copy_from_slice(c);
    let w = t.w();
    let mut tmp = [0u8; N];
    for chain in 0..p {
        let a = coef(&qc, chain, w);
        derive_x(i_id, seed, q, chain as u16, &mut tmp);
        for j in 0..a {
            chain_step(i_id, q, chain as u16, j as u8, &mut tmp);
        }
        let off = 4 + N + chain * N;
        out[off..off + N].copy_from_slice(&tmp);
    }
}

/// Computes the LM-OTS public-key candidate `Kc` from a signature and message
/// (RFC 8554 §4.6, Algorithm 4b). Returns `None` on a malformed signature.
///
/// `pubtype` is the LM-OTS typecode bound by the enclosing LMS public key.
pub(crate) fn recover_public_key(
    pubtype: LmotsType,
    i_id: &[u8; 16],
    q: u32,
    message: &[u8],
    sig: &[u8],
) -> Option<[u8; N]> {
    if sig.len() < 4 {
        return None;
    }
    let sigtype = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]);
    if sigtype != pubtype.typecode() {
        return None;
    }
    let t = pubtype;
    let p = t.p();
    if sig.len() != t.sig_len() {
        return None;
    }
    let mut c = [0u8; N];
    c.copy_from_slice(&sig[4..4 + N]);
    let q_digest = compute_q(i_id, q, &c, message);
    let qc = q_with_checksum(t, &q_digest);

    let max = t.max_digit();
    let w = t.w();
    let mut k_hash = Sha256::new();
    k_hash.update(i_id);
    k_hash.update(&q.to_be_bytes());
    k_hash.update(&D_PBLC.to_be_bytes());
    let mut tmp = [0u8; N];
    debug_assert!(p <= MAX_P);
    for chain in 0..p {
        let a = coef(&qc, chain, w);
        let off = 4 + N + chain * N;
        tmp.copy_from_slice(&sig[off..off + N]);
        for j in a..max {
            chain_step(i_id, q, chain as u16, j as u8, &mut tmp);
        }
        k_hash.update(&tmp);
    }
    Some(k_hash.finalize())
}
