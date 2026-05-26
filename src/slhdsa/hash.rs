//! The tweakable hash functions and PRFs (FIPS 205 §11), in both the SHAKE and
//! SHA-2 instantiations. A fresh hasher is built per call (the reference resets
//! a cached one — equivalent).

use super::params::Params;
use crate::hash::{Digest, ExtendableOutput, Hmac, Sha256, Sha512, Shake256};

const ZEROS: [u8; 128] = [0u8; 128];

/// `SHAKE256(parts...)` into `out`.
fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize_into(out);
}

/// `D(pk_seed[..n] ‖ 0^(block−n) ‖ addr ‖ parts...)[..n]`.
fn sha2_compress<D: Digest>(
    pk_seed: &[u8],
    n: usize,
    addr: &[u8],
    parts: &[&[u8]],
    out: &mut [u8],
) {
    let mut h = D::new();
    h.update(&pk_seed[..n]);
    h.update(&ZEROS[..D::BLOCK_LEN - n]);
    h.update(addr);
    for p in parts {
        h.update(p);
    }
    let d = h.finalize();
    out[..n].copy_from_slice(&d.as_ref()[..n]);
}

/// MGF1 mask generation using digest `D`.
fn mgf1<D: Digest>(seeds: &[&[u8]], out: &mut [u8]) {
    let mut counter: u32 = 0;
    let mut i = 0;
    while i < out.len() {
        let mut h = D::new();
        for s in seeds {
            h.update(s);
        }
        h.update(&counter.to_be_bytes());
        let d = h.finalize();
        let take = (out.len() - i).min(D::OUTPUT_LEN);
        out[i..i + take].copy_from_slice(&d.as_ref()[..take]);
        i += take;
        counter += 1;
    }
}

/// Tweakable hash `F` (one n-byte input).
pub(crate) fn f(p: &Params, pk_seed: &[u8], addr: &[u8], m1: &[u8], out: &mut [u8]) {
    let n = p.n as usize;
    if p.is_shake {
        shake(&[&pk_seed[..n], addr, &m1[..n]], &mut out[..n]);
    } else {
        sha2_compress::<Sha256>(pk_seed, n, addr, &[&m1[..n]], out);
    }
}

/// Tweakable hash `H` (two n-byte inputs).
pub(crate) fn h(p: &Params, pk_seed: &[u8], addr: &[u8], m1: &[u8], m2: &[u8], out: &mut [u8]) {
    let n = p.n as usize;
    if p.is_shake {
        shake(&[&pk_seed[..n], addr, &m1[..n], &m2[..n]], &mut out[..n]);
    } else if n == 16 {
        sha2_compress::<Sha256>(pk_seed, n, addr, &[&m1[..n], &m2[..n]], out);
    } else {
        sha2_compress::<Sha512>(pk_seed, n, addr, &[&m1[..n], &m2[..n]], out);
    }
}

/// Tweakable hash `T_l` (arbitrary-length input).
pub(crate) fn t(p: &Params, pk_seed: &[u8], addr: &[u8], ml: &[u8], out: &mut [u8]) {
    let n = p.n as usize;
    if p.is_shake {
        shake(&[&pk_seed[..n], addr, ml], &mut out[..n]);
    } else if n == 16 {
        sha2_compress::<Sha256>(pk_seed, n, addr, &[ml], out);
    } else {
        sha2_compress::<Sha512>(pk_seed, n, addr, &[ml], out);
    }
}

/// Message hash `H_msg`, producing `m` digest bytes.
pub(crate) fn h_msg(
    p: &Params,
    pk_seed: &[u8],
    pk_root: &[u8],
    r: &[u8],
    m_prefix: &[u8],
    msg: &[u8],
    out: &mut [u8],
) {
    let n = p.n as usize;
    let m = p.m as usize;
    if p.is_shake {
        shake(
            &[&r[..n], &pk_seed[..n], &pk_root[..n], m_prefix, msg],
            &mut out[..m],
        );
        return;
    }
    // SHA-2: digest then MGF1 over (R ‖ pk_seed ‖ digest).
    if n == 16 {
        let d = {
            let mut hh = Sha256::new();
            hh.update(&r[..n]);
            hh.update(&pk_seed[..n]);
            hh.update(&pk_root[..n]);
            hh.update(m_prefix);
            hh.update(msg);
            hh.finalize()
        };
        mgf1::<Sha256>(&[&r[..n], &pk_seed[..n], d.as_ref()], &mut out[..m]);
    } else {
        let d = {
            let mut hh = Sha512::new();
            hh.update(&r[..n]);
            hh.update(&pk_seed[..n]);
            hh.update(&pk_root[..n]);
            hh.update(m_prefix);
            hh.update(msg);
            hh.finalize()
        };
        mgf1::<Sha512>(&[&r[..n], &pk_seed[..n], d.as_ref()], &mut out[..m]);
    }
}

/// PRF for secret-value generation.
pub(crate) fn prf(p: &Params, pk_seed: &[u8], sk_seed: &[u8], addr: &[u8], out: &mut [u8]) {
    let n = p.n as usize;
    if p.is_shake {
        shake(&[&pk_seed[..n], addr, &sk_seed[..n]], &mut out[..n]);
    } else {
        sha2_compress::<Sha256>(pk_seed, n, addr, &[&sk_seed[..n]], out);
    }
}

/// PRF for the message randomizer `R`.
pub(crate) fn prf_msg(
    p: &Params,
    sk_prf: &[u8],
    opt_rand: &[u8],
    m_prefix: &[u8],
    msg: &[u8],
    out: &mut [u8],
) {
    let n = p.n as usize;
    if p.is_shake {
        shake(&[&sk_prf[..n], opt_rand, m_prefix, msg], &mut out[..n]);
    } else if n == 16 {
        let mut mac = Hmac::<Sha256>::new(&sk_prf[..n]);
        mac.update(opt_rand);
        mac.update(m_prefix);
        mac.update(msg);
        out[..n].copy_from_slice(&mac.finalize().as_ref()[..n]);
    } else {
        let mut mac = Hmac::<Sha512>::new(&sk_prf[..n]);
        mac.update(opt_rand);
        mac.update(m_prefix);
        mac.update(msg);
        out[..n].copy_from_slice(&mac.finalize().as_ref()[..n]);
    }
}
