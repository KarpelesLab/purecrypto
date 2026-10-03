//! The tweakable hash functions and PRFs (FIPS 205 §11), in both the SHAKE and
//! SHA-2 instantiations. For SHA-2 the constant first block
//! `PK.seed ‖ 0^(block−n)` is absorbed once per operation into a [`Seed`] and
//! cloned per call, so each F / H / PRF costs one compression instead of two
//! (the reference implementation's "seeded state"). SHAKE builds a fresh
//! sponge per call: its whole input fits one permutation, so a prefix state
//! would save nothing.

use super::params::Params;
use crate::hash::{Digest, ExtendableOutput, Hmac, Sha256, Sha512, Shake256};

const ZEROS: [u8; 128] = [0u8; 128];

/// `PK.seed` together with, for the SHA-2 sets, the hasher states that have
/// already absorbed `PK.seed ‖ 0^(block−n)`. Derefs to the seed bytes.
pub(crate) struct Seed<'a> {
    bytes: &'a [u8],
    /// SHA-256 seeded state (every SHA-2 set: F and PRF always use SHA-256).
    sha256: Option<Sha256>,
    /// SHA-512 seeded state (SHA-2 sets with `n > 16`, for H and T).
    sha512: Option<Sha512>,
}

impl<'a> Seed<'a> {
    /// Absorbs the seed block for `p`'s hash family (no-op for SHAKE).
    pub(crate) fn new(p: &Params, bytes: &'a [u8]) -> Self {
        let n = p.n as usize;
        let (sha256, sha512) = if p.is_shake {
            (None, None)
        } else {
            let wide = (n > 16).then(|| seeded::<Sha512>(&bytes[..n]));
            (Some(seeded::<Sha256>(&bytes[..n])), wide)
        };
        Seed {
            bytes,
            sha256,
            sha512,
        }
    }
}

impl core::ops::Deref for Seed<'_> {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.bytes
    }
}

/// A `D` state that has absorbed `seed ‖ 0^(block−n)` (one full block).
fn seeded<D: Digest>(seed: &[u8]) -> D {
    let mut h = D::new();
    h.update(seed);
    h.update(&ZEROS[..D::BLOCK_LEN - seed.len()]);
    h
}

/// `SHAKE256(parts...)` into `out`.
fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize_into(out);
}

/// `D(pk_seed[..n] ‖ 0^(block−n) ‖ addr ‖ parts...)[..n]`, resumed from the
/// seeded state `mid`.
fn sha2_compress<D: Digest + Clone>(
    mid: &Option<D>,
    n: usize,
    addr: &[u8],
    parts: &[&[u8]],
    out: &mut [u8],
) {
    let mut h = mid.clone().expect("SHA-2 parameter set has a seeded state");
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
pub(crate) fn f(p: &Params, pk_seed: &Seed, addr: &[u8], m1: &[u8], out: &mut [u8]) {
    let n = p.n as usize;
    if p.is_shake {
        shake(&[&pk_seed[..n], addr, &m1[..n]], &mut out[..n]);
    } else {
        sha2_compress(&pk_seed.sha256, n, addr, &[&m1[..n]], out);
    }
}

/// Tweakable hash `H` (two n-byte inputs).
pub(crate) fn h(p: &Params, pk_seed: &Seed, addr: &[u8], m1: &[u8], m2: &[u8], out: &mut [u8]) {
    let n = p.n as usize;
    if p.is_shake {
        shake(&[&pk_seed[..n], addr, &m1[..n], &m2[..n]], &mut out[..n]);
    } else if n == 16 {
        sha2_compress(&pk_seed.sha256, n, addr, &[&m1[..n], &m2[..n]], out);
    } else {
        sha2_compress(&pk_seed.sha512, n, addr, &[&m1[..n], &m2[..n]], out);
    }
}

/// Tweakable hash `T_l` (arbitrary-length input).
pub(crate) fn t(p: &Params, pk_seed: &Seed, addr: &[u8], ml: &[u8], out: &mut [u8]) {
    let n = p.n as usize;
    if p.is_shake {
        shake(&[&pk_seed[..n], addr, ml], &mut out[..n]);
    } else if n == 16 {
        sha2_compress(&pk_seed.sha256, n, addr, &[ml], out);
    } else {
        sha2_compress(&pk_seed.sha512, n, addr, &[ml], out);
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
pub(crate) fn prf(p: &Params, pk_seed: &Seed, sk_seed: &[u8], addr: &[u8], out: &mut [u8]) {
    let n = p.n as usize;
    if p.is_shake {
        shake(&[&pk_seed[..n], addr, &sk_seed[..n]], &mut out[..n]);
    } else {
        sha2_compress(&pk_seed.sha256, n, addr, &[&sk_seed[..n]], out);
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
