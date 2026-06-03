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

/// Computes the LM-OTS public key `K` for leaf `q` from the master `seed`
/// (RFC 8554 §4.3, Algorithm 1, with the Appendix A private-element derivation).
pub(crate) fn public_key(t: LmotsType, i_id: &[u8; 16], seed: &[u8; N], q: u32) -> [u8; N] {
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
