//! SLH-DSA — the Stateless Hash-Based Digital Signature Algorithm (FIPS 205),
//! the standardized form of SPHINCS+.
//!
//! All twelve parameter sets are supported (SHA-2 / SHAKE × 128/192/256 × s/f)
//! through a runtime [`ParamSet`]. The scheme is built purely from the hash
//! primitives this crate already provides; it needs `alloc` for the large
//! signatures (up to ~50 KB) but no other foreign code.
//!
//! Signing is hedged by default and has a deterministic variant; both are
//! validated against the FIPS 205 ACVP vectors.

// The tree algorithms are faithful ports that thread the params, seeds, address,
// and several buffers explicitly.
#![allow(clippy::too_many_arguments)]

mod adrs;
mod hash;
mod params;
#[cfg(feature = "x509")]
pub(crate) mod registry;

use adrs::{Adrs, AdrsType};
use alloc::vec;
use alloc::vec::Vec;
use params::{MAX_CONTEXT, MAX_K, MAX_M, MAX_N, MAX_WOTS_LEN, Params, SETS};

use crate::ct::ConstantTimeEq;
use crate::rng::RngCore;

/// Errors from SLH-DSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A key had the wrong length or its root did not check out.
    InvalidKey,
    /// The context string exceeded 255 bytes.
    ContextTooLong,
    /// The message was empty (SLH-DSA does not sign empty messages here).
    EmptyMessage,
    /// A DER/PEM structure was malformed.
    Malformed,
}

/// An SLH-DSA parameter set (FIPS 205). Variant names mirror the standard set
/// names (e.g. `SLH-DSA-SHA2-128s`).
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(usize)]
pub enum ParamSet {
    /// SLH-DSA-SHA2-128s.
    Sha2_128s = 0,
    /// SLH-DSA-SHA2-128f.
    Sha2_128f = 1,
    /// SLH-DSA-SHA2-192s.
    Sha2_192s = 2,
    /// SLH-DSA-SHA2-192f.
    Sha2_192f = 3,
    /// SLH-DSA-SHA2-256s.
    Sha2_256s = 4,
    /// SLH-DSA-SHA2-256f.
    Sha2_256f = 5,
    /// SLH-DSA-SHAKE-128s.
    Shake_128s = 6,
    /// SLH-DSA-SHAKE-128f.
    Shake_128f = 7,
    /// SLH-DSA-SHAKE-192s.
    Shake_192s = 8,
    /// SLH-DSA-SHAKE-192f.
    Shake_192f = 9,
    /// SLH-DSA-SHAKE-256s.
    Shake_256s = 10,
    /// SLH-DSA-SHAKE-256f.
    Shake_256f = 11,
}

impl ParamSet {
    fn params(self) -> &'static Params {
        &SETS[self as usize]
    }

    /// The signature size for this set, in bytes.
    pub fn signature_size(self) -> usize {
        self.params().sig_size
    }

    /// The PKIX algorithm OID arcs for this parameter set (FIPS 205 / NIST).
    /// Used for both SPKI and the X.509 certificate signatureAlgorithm.
    pub fn oid(self) -> &'static [u64] {
        self.params().oid
    }
}

// --- internal helpers operating on raw seeds (all slices are n-byte views) ---

/// Big-endian bytes → integer.
fn to_int(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |acc, &v| (acc << 8) | v as u64)
}

/// FIPS 205 Algorithm 4: base-2^b decomposition.
fn base_2b(input: &[u8], b: u32, out: &mut [u32]) {
    let mask = (1u32 << b) - 1;
    let mut bits = 0u32;
    let mut total = 0u32;
    let mut idx = 0;
    for o in out.iter_mut() {
        while bits < b {
            total = (total << 8) | input[idx] as u32;
            idx += 1;
            bits += 8;
        }
        bits -= b;
        *o = (total >> bits) & mask;
    }
}

/// Bytes → base-16 nibbles.
fn bytes_to_nibbles(input: &[u8], out: &mut [u8]) {
    for (i, &x) in input.iter().enumerate() {
        out[2 * i] = x >> 4;
        out[2 * i + 1] = x & 0x0f;
    }
}

/// WOTS+ chaining (Algorithm 5): apply `F` `steps` times from `start`.
fn wots_chain(p: &Params, pk_seed: &[u8], inout: &mut [u8], start: u8, steps: u8, addr: &mut Adrs) {
    let n = p.n as usize;
    for i in start..start + steps {
        addr.set_hash(i as u32);
        let mut tmp = [0u8; MAX_N];
        hash::f(p, pk_seed, addr.bytes(), &inout[..n], &mut tmp);
        inout[..n].copy_from_slice(&tmp[..n]);
    }
}

/// WOTS+ public-key generation (Algorithm 6).
fn wots_pk_gen(
    p: &Params,
    pk_seed: &[u8],
    sk_seed: &[u8],
    out: &mut [u8],
    tmp: &mut [u8],
    addr: &mut Adrs,
) {
    let n = p.n as usize;
    let mut sk_addr = *addr;
    sk_addr.set_type_and_clear(AdrsType::WotsPrf);
    sk_addr.copy_key_pair(addr);
    for i in 0..p.len {
        sk_addr.set_chain(i);
        hash::prf(
            p,
            pk_seed,
            sk_seed,
            sk_addr.bytes(),
            &mut tmp[i as usize * n..],
        );
        addr.set_chain(i);
        let lo = i as usize * n;
        wots_chain(p, pk_seed, &mut tmp[lo..lo + n], 0, 15, addr);
    }
    let mut pk_addr = *addr;
    pk_addr.set_type_and_clear(AdrsType::WotsPk);
    pk_addr.copy_key_pair(addr);
    let total = p.len as usize * n;
    hash::t(p, pk_seed, pk_addr.bytes(), &tmp[..total], out);
}

/// Computes the WOTS+ message-and-checksum nibbles for an n-byte message.
fn wots_msg_csum(p: &Params, msg: &[u8]) -> [u8; MAX_WOTS_LEN] {
    let mut mc = [0u8; MAX_WOTS_LEN];
    bytes_to_nibbles(&msg[..p.n as usize], &mut mc);
    let len1 = (p.n * 2) as usize;
    let mut csum: u16 = 0;
    for &x in &mc[..len1] {
        csum += x as u16;
    }
    csum = 15 * len1 as u16 - csum;
    mc[len1] = (csum >> 8) as u8 & 0x0f;
    mc[len1 + 1] = (csum >> 4) as u8 & 0x0f;
    mc[len1 + 2] = csum as u8 & 0x0f;
    mc
}

/// WOTS+ sign (Algorithm 7): writes `len·n` bytes into `sig`.
fn wots_sign(
    p: &Params,
    pk_seed: &[u8],
    sk_seed: &[u8],
    msg: &[u8],
    addr: &mut Adrs,
    sig: &mut [u8],
) {
    let n = p.n as usize;
    let mc = wots_msg_csum(p, msg);
    let mut sk_addr = *addr;
    sk_addr.set_type_and_clear(AdrsType::WotsPrf);
    sk_addr.copy_key_pair(addr);
    for i in 0..p.len {
        sk_addr.set_chain(i);
        let lo = i as usize * n;
        hash::prf(p, pk_seed, sk_seed, sk_addr.bytes(), &mut sig[lo..]);
        addr.set_chain(i);
        wots_chain(p, pk_seed, &mut sig[lo..lo + n], 0, mc[i as usize], addr);
    }
}

/// WOTS+ public key from a signature (Algorithm 8).
fn wots_pk_from_sig(
    p: &Params,
    pk_seed: &[u8],
    sig: &[u8],
    msg: &[u8],
    tmp: &mut [u8],
    addr: &mut Adrs,
    out: &mut [u8],
) {
    let n = p.n as usize;
    let mc = wots_msg_csum(p, msg);
    let total = p.len as usize * n;
    tmp[..total].copy_from_slice(&sig[..total]);
    for i in 0..p.len {
        addr.set_chain(i);
        let lo = i as usize * n;
        let step = mc[i as usize];
        wots_chain(p, pk_seed, &mut tmp[lo..lo + n], step, 15 - step, addr);
    }
    let mut pk_addr = *addr;
    pk_addr.set_type_and_clear(AdrsType::WotsPk);
    pk_addr.copy_key_pair(addr);
    hash::t(p, pk_seed, pk_addr.bytes(), &tmp[..total], out);
}

/// XMSS node computation (Algorithm 9).
fn xmss_node(
    p: &Params,
    pk_seed: &[u8],
    sk_seed: &[u8],
    out: &mut [u8],
    tmp: &mut [u8],
    i: u32,
    z: u32,
    addr: &mut Adrs,
) {
    let n = p.n as usize;
    if z == 0 {
        addr.set_type_and_clear(AdrsType::WotsHash);
        addr.set_key_pair(i);
        wots_pk_gen(p, pk_seed, sk_seed, out, tmp, addr);
    } else {
        let mut lnode = [0u8; MAX_N];
        let mut rnode = [0u8; MAX_N];
        xmss_node(p, pk_seed, sk_seed, &mut lnode, tmp, 2 * i, z - 1, addr);
        xmss_node(p, pk_seed, sk_seed, &mut rnode, tmp, 2 * i + 1, z - 1, addr);
        addr.set_type_and_clear(AdrsType::Tree);
        addr.set_tree_height(z);
        addr.set_tree_index(i);
        hash::h(p, pk_seed, addr.bytes(), &lnode[..n], &rnode[..n], out);
    }
}

/// XMSS sign (Algorithm 10): WOTS+ signature followed by the authentication path.
fn xmss_sign(
    p: &Params,
    pk_seed: &[u8],
    sk_seed: &[u8],
    msg: &[u8],
    tmp: &mut [u8],
    leaf_idx: u32,
    addr: &mut Adrs,
    sig: &mut [u8],
) {
    let n = p.n as usize;
    let auth_start = n * p.len as usize;
    let mut idx = leaf_idx;
    for j in 0..p.h_prime {
        let off = auth_start + j as usize * n;
        xmss_node(
            p,
            pk_seed,
            sk_seed,
            &mut sig[off..off + n],
            tmp,
            idx ^ 1,
            j,
            addr,
        );
        idx >>= 1;
    }
    addr.set_type_and_clear(AdrsType::WotsHash);
    addr.set_key_pair(leaf_idx);
    wots_sign(p, pk_seed, sk_seed, msg, addr, sig);
}

/// XMSS public key from a signature (Algorithm 11).
fn xmss_pk_from_sig(
    p: &Params,
    pk_seed: &[u8],
    mut leaf_idx: u32,
    sig: &[u8],
    msg: &[u8],
    tmp: &mut [u8],
    addr: &mut Adrs,
    out: &mut [u8],
) {
    let n = p.n as usize;
    addr.set_type_and_clear(AdrsType::WotsHash);
    addr.set_key_pair(leaf_idx);
    wots_pk_from_sig(p, pk_seed, sig, msg, tmp, addr, out);

    addr.set_type_and_clear(AdrsType::Tree);
    let mut ap = &sig[p.len as usize * n..]; // authentication path
    for k in 0..p.h_prime {
        addr.set_tree_height(k + 1);
        let node = &ap[..n];
        if leaf_idx & 1 == 0 {
            leaf_idx >>= 1;
            addr.set_tree_index(leaf_idx);
            let mut tmp_out = [0u8; MAX_N];
            hash::h(p, pk_seed, addr.bytes(), &out[..n], node, &mut tmp_out);
            out[..n].copy_from_slice(&tmp_out[..n]);
        } else {
            leaf_idx = (leaf_idx - 1) >> 1;
            addr.set_tree_index(leaf_idx);
            let mut tmp_out = [0u8; MAX_N];
            hash::h(p, pk_seed, addr.bytes(), node, &out[..n], &mut tmp_out);
            out[..n].copy_from_slice(&tmp_out[..n]);
        }
        ap = &ap[n..];
    }
}

/// Hypertree sign (Algorithm 12).
fn ht_sign(
    p: &Params,
    pk_seed: &[u8],
    sk_seed: &[u8],
    pk_fors: &[u8],
    mut tree_idx: u64,
    mut leaf_idx: u32,
    sig: &mut [u8],
) {
    let n = p.n as usize;
    let per_layer = (p.h_prime + p.len) as usize * n;
    let mask = p.leaf_idx_mask();
    let mut root = [0u8; MAX_N];
    root[..n].copy_from_slice(&pk_fors[..n]);
    let mut tmp = vec![0u8; n * p.len as usize];
    let mut off = 0;

    let mut addr = Adrs::new(p.is_shake);
    for j in 0..p.d {
        addr.set_layer(j);
        addr.set_tree(tree_idx);
        xmss_sign(
            p,
            pk_seed,
            sk_seed,
            &root[..n],
            &mut tmp,
            leaf_idx,
            &mut addr,
            &mut sig[off..],
        );
        if j < p.d - 1 {
            let mut new_root = [0u8; MAX_N];
            xmss_pk_from_sig(
                p,
                pk_seed,
                leaf_idx,
                &sig[off..],
                &root[..n],
                &mut tmp,
                &mut addr,
                &mut new_root,
            );
            root[..n].copy_from_slice(&new_root[..n]);
            leaf_idx = (tree_idx & mask) as u32;
            tree_idx >>= p.h_prime;
            off += per_layer;
        }
    }
}

/// Hypertree verify (Algorithm 13).
fn ht_verify(
    p: &Params,
    pk_seed: &[u8],
    pk_root: &[u8],
    pk_fors: &[u8],
    sig: &[u8],
    mut tree_idx: u64,
    mut leaf_idx: u32,
) -> bool {
    let n = p.n as usize;
    let per_layer = (p.h_prime + p.len) as usize * n;
    let mask = p.leaf_idx_mask();
    let mut root = [0u8; MAX_N];
    root[..n].copy_from_slice(&pk_fors[..n]);
    let mut tmp = vec![0u8; n * p.len as usize];

    let mut addr = Adrs::new(p.is_shake);
    let mut off = 0;
    for j in 0..p.d {
        addr.set_layer(j);
        addr.set_tree(tree_idx);
        let mut new_root = [0u8; MAX_N];
        xmss_pk_from_sig(
            p,
            pk_seed,
            leaf_idx,
            &sig[off..],
            &root[..n],
            &mut tmp,
            &mut addr,
            &mut new_root,
        );
        root[..n].copy_from_slice(&new_root[..n]);
        leaf_idx = (tree_idx & mask) as u32;
        tree_idx >>= p.h_prime;
        off += per_layer;
    }
    bool::from(root[..n].ct_eq(&pk_root[..n]))
}

/// FORS private value (Algorithm 14).
fn fors_gen_sk(p: &Params, pk_seed: &[u8], sk_seed: &[u8], idx: u32, addr: &Adrs, out: &mut [u8]) {
    let mut sk_addr = *addr;
    sk_addr.set_type_and_clear(AdrsType::ForsPrf);
    sk_addr.copy_key_pair(addr);
    sk_addr.set_tree_index(idx);
    hash::prf(p, pk_seed, sk_seed, sk_addr.bytes(), out);
}

/// FORS node (Algorithm 15).
fn fors_node(
    p: &Params,
    pk_seed: &[u8],
    sk_seed: &[u8],
    node_id: u32,
    layer: u32,
    addr: &mut Adrs,
    out: &mut [u8],
) {
    let n = p.n as usize;
    if layer == 0 {
        let mut sk = [0u8; MAX_N];
        fors_gen_sk(p, pk_seed, sk_seed, node_id, addr, &mut sk);
        addr.set_tree_height(0);
        addr.set_tree_index(node_id);
        hash::f(p, pk_seed, addr.bytes(), &sk[..n], out);
    } else {
        let mut lnode = [0u8; MAX_N];
        let mut rnode = [0u8; MAX_N];
        fors_node(
            p,
            pk_seed,
            sk_seed,
            node_id * 2,
            layer - 1,
            addr,
            &mut lnode,
        );
        fors_node(
            p,
            pk_seed,
            sk_seed,
            node_id * 2 + 1,
            layer - 1,
            addr,
            &mut rnode,
        );
        addr.set_tree_height(layer);
        addr.set_tree_index(node_id);
        hash::h(p, pk_seed, addr.bytes(), &lnode[..n], &rnode[..n], out);
    }
}

/// FORS sign (Algorithm 16).
fn fors_sign(
    p: &Params,
    pk_seed: &[u8],
    sk_seed: &[u8],
    md: &[u8],
    addr: &mut Adrs,
    sig: &mut [u8],
) {
    let n = p.n as usize;
    let mut indices = [0u32; MAX_K];
    base_2b(md, p.a, &mut indices[..p.k as usize]);
    let two_a = 1u32 << p.a;
    let mut tree_base = 0u32;
    let mut off = 0;
    for tree_id in 0..p.k {
        let mut node_id = indices[tree_id as usize];
        fors_gen_sk(
            p,
            pk_seed,
            sk_seed,
            node_id + tree_base,
            addr,
            &mut sig[off..],
        );
        off += n;
        let mut tree_off = tree_base;
        for j in 0..p.a {
            fors_node(
                p,
                pk_seed,
                sk_seed,
                (node_id ^ 1) + tree_off,
                j,
                addr,
                &mut sig[off..],
            );
            node_id >>= 1;
            tree_off >>= 1;
            off += n;
        }
        tree_base += two_a;
    }
}

/// FORS public key from a signature (Algorithm 17). Returns the bytes consumed.
fn fors_pk_from_sig(
    p: &Params,
    pk_seed: &[u8],
    md: &[u8],
    sig: &[u8],
    addr: &mut Adrs,
    out: &mut [u8],
) -> usize {
    let n = p.n as usize;
    let mut indices = [0u32; MAX_K];
    base_2b(md, p.a, &mut indices[..p.k as usize]);
    let two_a = 1u32 << p.a;
    let mut tree_base = 0u32;
    let mut roots = vec![0u8; n * p.k as usize];
    let mut off = 0;
    for tree_id in 0..p.k {
        let rp = tree_id as usize * n;
        let mut node_id = indices[tree_id as usize];
        let mut tree_idx = node_id + tree_base;
        addr.set_tree_height(0);
        addr.set_tree_index(tree_idx);
        hash::f(
            p,
            pk_seed,
            addr.bytes(),
            &sig[off..off + n],
            &mut roots[rp..],
        );
        off += n;
        for layer in 0..p.a {
            addr.set_tree_height(layer + 1);
            let node = &sig[off..off + n];
            let mut tmp_out = [0u8; MAX_N];
            if node_id & 1 == 0 {
                tree_idx >>= 1;
                addr.set_tree_index(tree_idx);
                hash::h(
                    p,
                    pk_seed,
                    addr.bytes(),
                    &roots[rp..rp + n],
                    node,
                    &mut tmp_out,
                );
            } else {
                tree_idx = (tree_idx - 1) >> 1;
                addr.set_tree_index(tree_idx);
                hash::h(
                    p,
                    pk_seed,
                    addr.bytes(),
                    node,
                    &roots[rp..rp + n],
                    &mut tmp_out,
                );
            }
            roots[rp..rp + n].copy_from_slice(&tmp_out[..n]);
            off += n;
            node_id >>= 1;
        }
        tree_base += two_a;
    }
    let mut pk_addr = *addr;
    pk_addr.set_type_and_clear(AdrsType::ForsRoots);
    pk_addr.copy_key_pair(addr);
    hash::t(p, pk_seed, pk_addr.bytes(), &roots, out);
    off
}

/// Computes the top-tree root (FIPS 205 Algorithm 18, slh_keygen step).
fn compute_root(p: &Params, pk_seed: &[u8], sk_seed: &[u8], out: &mut [u8]) {
    let mut addr = Adrs::new(p.is_shake);
    addr.set_layer(p.d - 1);
    let mut tmp = vec![0u8; p.n as usize * p.len as usize];
    xmss_node(p, pk_seed, sk_seed, out, &mut tmp, 0, p.h_prime, &mut addr);
}

/// Splits the message digest into FORS message, tree index, and leaf index.
fn split_digest(p: &Params, digest: &[u8]) -> (usize, u64, u32) {
    let md_len = p.md_len();
    let rest = &digest[md_len..];
    let til = p.tree_idx_len();
    let lil = p.leaf_idx_len();
    let tree_idx = to_int(&rest[..til]) & p.tree_idx_mask();
    let leaf_idx = (to_int(&rest[til..til + lil]) & p.leaf_idx_mask()) as u32;
    (md_len, tree_idx, leaf_idx)
}

/// slh_sign_internal (FIPS 205 Algorithm 19). `m_prefix` is `0x00 ‖ |ctx| ‖ ctx`.
fn sign_internal(
    p: &Params,
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
    pk_root: &[u8],
    m_prefix: &[u8],
    msg: &[u8],
    opt_rand: &[u8],
) -> Vec<u8> {
    let n = p.n as usize;
    let mut sig = vec![0u8; p.sig_size];

    // Randomizer R = PRF_msg(opt_rand, m_prefix, msg) into sig[..n].
    hash::prf_msg(p, sk_prf, opt_rand, m_prefix, msg, &mut sig);
    let mut r = [0u8; MAX_N];
    r[..n].copy_from_slice(&sig[..n]);

    // Message digest.
    let mut digest = [0u8; MAX_M];
    hash::h_msg(p, pk_seed, pk_root, &r[..n], m_prefix, msg, &mut digest);
    let (md_len, tree_idx, leaf_idx) = split_digest(p, &digest);
    let md = &digest[..md_len];

    // FORS signature over the digest.
    let mut addr = Adrs::new(p.is_shake);
    addr.set_tree(tree_idx);
    addr.set_type_and_clear(AdrsType::ForsTree);
    addr.set_key_pair(leaf_idx);
    fors_sign(p, pk_seed, sk_seed, md, &mut addr, &mut sig[n..]);

    // FORS public key, then hypertree signature over it.
    let mut pk_fors = [0u8; MAX_N];
    let consumed = fors_pk_from_sig(p, pk_seed, md, &sig[n..], &mut addr, &mut pk_fors);
    let ht_off = n + consumed;
    ht_sign(
        p,
        pk_seed,
        sk_seed,
        &pk_fors[..n],
        tree_idx,
        leaf_idx,
        &mut sig[ht_off..],
    );
    sig
}

/// slh_verify_internal (FIPS 205 Algorithm 20).
fn verify_internal(
    p: &Params,
    pk_seed: &[u8],
    pk_root: &[u8],
    sig: &[u8],
    m_prefix: &[u8],
    msg: &[u8],
) -> bool {
    let n = p.n as usize;
    let r = &sig[..n];

    let mut digest = [0u8; MAX_M];
    hash::h_msg(p, pk_seed, pk_root, r, m_prefix, msg, &mut digest);
    let (md_len, tree_idx, leaf_idx) = split_digest(p, &digest);
    let md = &digest[..md_len];

    let mut addr = Adrs::new(p.is_shake);
    addr.set_tree(tree_idx);
    addr.set_type_and_clear(AdrsType::ForsTree);
    addr.set_key_pair(leaf_idx);

    let mut pk_fors = [0u8; MAX_N];
    let consumed = fors_pk_from_sig(p, pk_seed, md, &sig[n..], &mut addr, &mut pk_fors);
    let ht_sig = &sig[n + consumed..];
    ht_verify(
        p,
        pk_seed,
        pk_root,
        &pk_fors[..n],
        ht_sig,
        tree_idx,
        leaf_idx,
    )
}

/// Builds `0x00 ‖ |ctx| ‖ ctx`.
fn m_prefix(ctx: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + ctx.len());
    v.push(0);
    v.push(ctx.len() as u8);
    v.extend_from_slice(ctx);
    v
}

/// An SLH-DSA private (signing) key.
#[derive(Clone)]
pub struct PrivateKey {
    set: ParamSet,
    /// `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`.
    bytes: Vec<u8>,
}

/// An SLH-DSA public (verification) key.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
    set: ParamSet,
    /// `PK.seed ‖ PK.root`.
    bytes: Vec<u8>,
}

impl PrivateKey {
    /// The parameter set this key was generated for.
    pub fn parameter_set(&self) -> ParamSet {
        self.set
    }

    /// Deterministically derives a key pair from the three n-byte seeds.
    pub fn from_seeds(
        set: ParamSet,
        sk_seed: &[u8],
        sk_prf: &[u8],
        pk_seed: &[u8],
    ) -> (PrivateKey, PublicKey) {
        let p = set.params();
        let n = p.n as usize;
        let mut root = [0u8; MAX_N];
        compute_root(p, &pk_seed[..n], &sk_seed[..n], &mut root);

        let mut bytes = Vec::with_capacity(4 * n);
        bytes.extend_from_slice(&sk_seed[..n]);
        bytes.extend_from_slice(&sk_prf[..n]);
        bytes.extend_from_slice(&pk_seed[..n]);
        bytes.extend_from_slice(&root[..n]);

        let mut pk = Vec::with_capacity(2 * n);
        pk.extend_from_slice(&pk_seed[..n]);
        pk.extend_from_slice(&root[..n]);
        (PrivateKey { set, bytes }, PublicKey { set, bytes: pk })
    }

    /// Generates a fresh key pair from `rng`.
    pub fn generate<R: RngCore>(set: ParamSet, rng: &mut R) -> (PrivateKey, PublicKey) {
        let n = set.params().n as usize;
        let mut seeds = [0u8; 3 * MAX_N];
        rng.fill_bytes(&mut seeds[..3 * n]);
        Self::from_seeds(set, &seeds[..n], &seeds[n..2 * n], &seeds[2 * n..3 * n])
    }

    /// The matching public key.
    pub fn public_key(&self) -> PublicKey {
        let n = self.set.params().n as usize;
        let mut pk = Vec::with_capacity(2 * n);
        pk.extend_from_slice(&self.bytes[2 * n..3 * n]); // PK.seed
        pk.extend_from_slice(&self.bytes[3 * n..4 * n]); // PK.root
        PublicKey {
            set: self.set,
            bytes: pk,
        }
    }

    /// Signs `msg` with optional `ctx` (≤ 255 bytes), hedged with `rng`.
    pub fn sign<R: RngCore>(&self, rng: &mut R, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, Error> {
        if msg.is_empty() {
            return Err(Error::EmptyMessage);
        }
        if ctx.len() > MAX_CONTEXT {
            return Err(Error::ContextTooLong);
        }
        let n = self.set.params().n as usize;
        let mut rnd = [0u8; MAX_N];
        rng.fill_bytes(&mut rnd[..n]);
        Ok(self.do_sign(msg, ctx, &rnd[..n]))
    }

    /// Signs `msg` deterministically (the public seed is the randomizer).
    pub fn sign_deterministic(&self, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, Error> {
        if msg.is_empty() {
            return Err(Error::EmptyMessage);
        }
        if ctx.len() > MAX_CONTEXT {
            return Err(Error::ContextTooLong);
        }
        let n = self.set.params().n as usize;
        let pk_seed = self.bytes[2 * n..3 * n].to_vec();
        Ok(self.do_sign(msg, ctx, &pk_seed))
    }

    fn do_sign(&self, msg: &[u8], ctx: &[u8], opt_rand: &[u8]) -> Vec<u8> {
        let p = self.set.params();
        let n = p.n as usize;
        sign_internal(
            p,
            &self.bytes[..n],
            &self.bytes[n..2 * n],
            &self.bytes[2 * n..3 * n],
            &self.bytes[3 * n..4 * n],
            &m_prefix(ctx),
            msg,
            opt_rand,
        )
    }

    /// The encoded private key.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parses a private key, recomputing and checking the embedded root.
    pub fn from_bytes(set: ParamSet, bytes: &[u8]) -> Result<Self, Error> {
        let p = set.params();
        let n = p.n as usize;
        if bytes.len() != p.sk_size {
            return Err(Error::InvalidKey);
        }
        let mut root = [0u8; MAX_N];
        compute_root(p, &bytes[2 * n..3 * n], &bytes[..n], &mut root);
        if !bool::from(root[..n].ct_eq(&bytes[3 * n..4 * n])) {
            return Err(Error::InvalidKey);
        }
        Ok(PrivateKey {
            set,
            bytes: bytes.to_vec(),
        })
    }

    /// Encodes the private key as a PKCS#8 `PrivateKeyInfo` DER (matches the
    /// OpenSSL 3.5 SLH-DSA layout: `privateKey` OCTET STRING holds the raw
    /// `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` bytes).
    #[cfg(feature = "der")]
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let algid = encode_sequence(&oid_tlv(self.set.params().oid));
        encode_sequence(
            &[
                encode_integer(&[0]),
                algid,
                encode_octet_string(&self.bytes),
            ]
            .concat(),
        )
    }

    /// Encodes the private key as a PKCS#8 PEM document.
    #[cfg(feature = "der")]
    pub fn to_pkcs8_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("PRIVATE KEY", &self.to_pkcs8_der())
    }

    /// Parses a PKCS#8 `PrivateKeyInfo` DER, returning `(set, key)`. The set is
    /// inferred from the embedded OID. Validates the key's root against the
    /// encoded `PK.root`.
    #[cfg(feature = "der")]
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        use crate::der::{Reader, parse_oid};
        let mut r = Reader::new(der);
        let mut seq = r.read_sequence().map_err(|_| Error::Malformed)?;
        seq.read_integer_bytes().map_err(|_| Error::Malformed)?;
        let mut algid = seq.read_sequence().map_err(|_| Error::Malformed)?;
        let oid = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        let set = ParamSet::from_oid(oid.as_slice()).ok_or(Error::Malformed)?;
        let inner = seq.read_octet_string().map_err(|_| Error::Malformed)?;
        Self::from_bytes(set, inner)
    }

    /// Parses a PKCS#8 PEM private key.
    #[cfg(feature = "der")]
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        let der = crate::der::pem_decode(pem, "PRIVATE KEY").map_err(|_| Error::Malformed)?;
        Self::from_pkcs8_der(&der)
    }

    /// Encrypts the PKCS#8 encoding under PBES2 (RFC 5958 §3 + RFC 8018
    /// §6.2), returning the DER-encoded `EncryptedPrivateKeyInfo`.
    #[cfg(all(feature = "der", feature = "kdf"))]
    pub fn to_pkcs8_der_encrypted(
        &self,
        password: &[u8],
        params: &crate::kdf::pbes2::Pbes2Params,
        rng: &mut impl crate::rng::RngCore,
    ) -> Vec<u8> {
        crate::kdf::pbes2::encrypt(&self.to_pkcs8_der(), password, params, rng)
    }

    /// PEM-wrapped variant of [`Self::to_pkcs8_der_encrypted`].
    #[cfg(all(feature = "der", feature = "kdf"))]
    pub fn to_pkcs8_pem_encrypted(
        &self,
        password: &[u8],
        params: &crate::kdf::pbes2::Pbes2Params,
        rng: &mut impl crate::rng::RngCore,
    ) -> alloc::string::String {
        crate::kdf::pbes2::encrypt_pem(&self.to_pkcs8_der(), password, params, rng)
    }

    /// Parses an `EncryptedPrivateKeyInfo` DER and decrypts it back to a
    /// PKCS#8 SLH-DSA private key.
    #[cfg(all(feature = "der", feature = "kdf"))]
    pub fn from_pkcs8_der_encrypted(der: &[u8], password: &[u8]) -> Result<Self, Error> {
        let inner = crate::kdf::pbes2::decrypt(der, password).map_err(|_| Error::Malformed)?;
        Self::from_pkcs8_der(&inner)
    }

    /// PEM-wrapped variant of [`Self::from_pkcs8_der_encrypted`].
    #[cfg(all(feature = "der", feature = "kdf"))]
    pub fn from_pkcs8_pem_encrypted(pem: &str, password: &[u8]) -> Result<Self, Error> {
        let inner = crate::kdf::pbes2::decrypt_pem(pem, password).map_err(|_| Error::Malformed)?;
        Self::from_pkcs8_der(&inner)
    }
}

// FIPS 205 expects the SLH-DSA private key (`SK.seed ‖ SK.prf ‖
// PK.seed ‖ PK.root`) to be wiped before deallocation. Overwrite the
// bytes and pass them through `core::hint::black_box` so LLVM cannot
// eliminate the writes as dead stores. We avoid adding the `zeroize`
// crate as a dependency.
impl Drop for PrivateKey {
    fn drop(&mut self) {
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(&self.bytes);
    }
}

impl ParamSet {
    /// Finds the parameter set matching an algorithm OID, if any.
    pub fn from_oid(oid: &[u64]) -> Option<Self> {
        use ParamSet::*;
        const SETS: &[ParamSet] = &[
            Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f, Shake_128s,
            Shake_128f, Shake_192s, Shake_192f, Shake_256s, Shake_256f,
        ];
        SETS.iter().copied().find(|s| s.params().oid == oid)
    }
}

impl PublicKey {
    /// The parameter set this key was generated for.
    pub fn parameter_set(&self) -> ParamSet {
        self.set
    }

    /// Verifies `sig` over `msg` with optional `ctx`.
    pub fn verify(&self, sig: &[u8], msg: &[u8], ctx: &[u8]) -> bool {
        let p = self.set.params();
        if msg.is_empty() || ctx.len() > MAX_CONTEXT || sig.len() != p.sig_size {
            return false;
        }
        let n = p.n as usize;
        verify_internal(
            p,
            &self.bytes[..n],
            &self.bytes[n..2 * n],
            sig,
            &m_prefix(ctx),
            msg,
        )
    }

    /// The encoded public key (`PK.seed ‖ PK.root`).
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parses a raw public key.
    pub fn from_bytes(set: ParamSet, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != set.params().pk_size {
            return Err(Error::InvalidKey);
        }
        Ok(PublicKey {
            set,
            bytes: bytes.to_vec(),
        })
    }

    /// Encodes the key as a PKIX `SubjectPublicKeyInfo` DER structure
    /// (draft-ietf-lamps-x509-slhdsa).
    #[cfg(feature = "der")]
    pub fn to_spki_der(&self) -> Vec<u8> {
        use crate::der::{encode_bit_string, encode_sequence, oid_tlv};
        let algid = encode_sequence(&oid_tlv(self.set.params().oid));
        encode_sequence(&[algid, encode_bit_string(&self.bytes)].concat())
    }

    /// Encodes the key as a PKIX PEM document.
    #[cfg(feature = "der")]
    pub fn to_spki_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("PUBLIC KEY", &self.to_spki_der())
    }

    /// Parses a PKIX `SubjectPublicKeyInfo` DER structure for parameter `set`.
    #[cfg(feature = "der")]
    pub fn from_spki_der(set: ParamSet, der: &[u8]) -> Result<Self, Error> {
        use crate::der::{Reader, parse_oid};
        let mut reader = Reader::new(der);
        let mut spki = reader.read_sequence().map_err(|_| Error::Malformed)?;
        let mut algid = spki.read_sequence().map_err(|_| Error::Malformed)?;
        let oid = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        if oid.as_slice() != set.params().oid {
            return Err(Error::Malformed);
        }
        let bits = spki.read_bit_string().map_err(|_| Error::Malformed)?;
        Self::from_bytes(set, bits).map_err(|_| Error::Malformed)
    }

    /// Parses a PKIX PEM public key for parameter `set`.
    #[cfg(feature = "der")]
    pub fn from_spki_pem(set: ParamSet, pem: &str) -> Result<Self, Error> {
        let der = crate::der::pem_decode(pem, "PUBLIC KEY").map_err(|_| Error::Malformed)?;
        Self::from_spki_der(set, &der)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn unhex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut v = Vec::with_capacity(b.len() / 2);
        let mut i = 0;
        while i < b.len() {
            let hi = (b[i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
            v.push((hi << 4) | lo);
            i += 2;
        }
        v
    }

    fn pset(i: usize) -> ParamSet {
        use ParamSet::*;
        [
            Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f, Shake_128s,
            Shake_128f, Shake_192s, Shake_192f, Shake_256s, Shake_256f,
        ][i]
    }

    /// Empty context is encoded as "-".
    fn ctx(tok: &str) -> Vec<u8> {
        if tok == "-" { Vec::new() } else { unhex(tok) }
    }

    fn check_keygen(only_fast: bool) {
        for line in include_str!("../../testdata/slhdsa_keygen.kat").lines() {
            let mut it = line.split_whitespace();
            let idx: usize = it.next().unwrap().parse().unwrap();
            if only_fast && idx.is_multiple_of(2) {
                continue; // skip the slow 's' sets
            }
            let set = pset(idx);
            let sk_seed = unhex(it.next().unwrap());
            let sk_prf = unhex(it.next().unwrap());
            let pk_seed = unhex(it.next().unwrap());
            let sk_exp = unhex(it.next().unwrap());
            let pk_exp = unhex(it.next().unwrap());
            let (sk, pk) = PrivateKey::from_seeds(set, &sk_seed, &sk_prf, &pk_seed);
            assert_eq!(sk.to_bytes(), sk_exp, "sk set {idx}");
            assert_eq!(pk.to_bytes(), pk_exp, "pk set {idx}");
        }
    }

    fn check_siggen(only_fast: bool) {
        for line in include_str!("../../testdata/slhdsa_siggen.kat").lines() {
            let mut it = line.split_whitespace();
            let idx: usize = it.next().unwrap().parse().unwrap();
            if only_fast && idx.is_multiple_of(2) {
                continue;
            }
            let set = pset(idx);
            let sk = unhex(it.next().unwrap());
            let context = ctx(it.next().unwrap());
            let msg = unhex(it.next().unwrap());
            let sig_exp = unhex(it.next().unwrap());
            let key = PrivateKey::from_bytes(set, &sk).unwrap();
            let sig = key.sign_deterministic(&msg, &context).unwrap();
            assert_eq!(sig, sig_exp, "signature set {idx}");
        }
    }

    #[test]
    fn acvp_keygen_fast() {
        check_keygen(true);
    }

    #[test]
    fn acvp_siggen_fast() {
        check_siggen(true);
    }

    #[test]
    fn acvp_sigver() {
        for line in include_str!("../../testdata/slhdsa_sigver.kat").lines() {
            let mut it = line.split_whitespace();
            let idx: usize = it.next().unwrap().parse().unwrap();
            let set = pset(idx);
            let pk = unhex(it.next().unwrap());
            let context = ctx(it.next().unwrap());
            let msg = unhex(it.next().unwrap());
            let sig = unhex(it.next().unwrap());
            let want = it.next().unwrap() == "1";
            let key = PublicKey::from_bytes(set, &pk).unwrap();
            assert_eq!(key.verify(&sig, &msg, &context), want, "verify set {idx}");
        }
    }

    #[cfg(feature = "der")]
    #[test]
    fn spki_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa-spki", b"n", &[]);
        let (_sk, pk) = PrivateKey::generate(ParamSet::Sha2_128f, &mut rng);
        let pem = pk.to_spki_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let parsed = PublicKey::from_spki_pem(ParamSet::Sha2_128f, &pem).unwrap();
        assert_eq!(parsed, pk);
    }

    #[test]
    fn roundtrip_and_reject() {
        let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa", b"nonce", &[]);
        let (sk, pk) = PrivateKey::generate(ParamSet::Sha2_128f, &mut rng);
        let sig = sk.sign(&mut rng, b"hello purecrypto", b"ctx").unwrap();
        assert!(pk.verify(&sig, b"hello purecrypto", b"ctx"));
        assert!(!pk.verify(&sig, b"other", b"ctx"));
        assert!(!pk.verify(&sig, b"hello purecrypto", b"x"));
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(!pk.verify(&bad, b"hello purecrypto", b"ctx"));

        // Deterministic signing is reproducible.
        let d1 = sk.sign_deterministic(b"abc", b"").unwrap();
        let d2 = sk.sign_deterministic(b"abc", b"").unwrap();
        assert_eq!(d1, d2);
        assert!(pk.verify(&d1, b"abc", b""));
    }

    // Slow paths (the 's' parameter sets and their signing): run with
    // `cargo test --release -- --ignored`.
    #[test]
    #[ignore = "slow in debug; run with --release --ignored"]
    fn acvp_keygen_all() {
        check_keygen(false);
    }

    #[test]
    #[ignore = "slow in debug; run with --release --ignored"]
    fn acvp_siggen_all() {
        check_siggen(false);
    }

    /// Deterministic keygen + sign + verify roundtrip on every fast
    /// (`f`-flavored) parameter set. Regression guard for the
    /// `tree_idx_mask` shift overflow (audit C-1): `Sha2_256f` and
    /// `Shake_256f` panic in a debug build before the fix because
    /// `h - h_prime = 64`.
    #[test]
    fn roundtrip_all_fast_param_sets() {
        use ParamSet::*;
        let fast = [
            Sha2_128f, Sha2_192f, Sha2_256f, Shake_128f, Shake_192f, Shake_256f,
        ];
        for set in fast {
            let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa-roundtrip", set.oid_label(), &[]);
            let (sk, pk) = PrivateKey::generate(set, &mut rng);

            // Hedged sign + verify.
            let sig = sk.sign(&mut rng, b"purecrypto-kat", b"ctx").unwrap();
            assert!(pk.verify(&sig, b"purecrypto-kat", b"ctx"), "verify {set:?}");
            assert!(
                !pk.verify(&sig, b"other-msg", b"ctx"),
                "wrong msg verifies {set:?}"
            );
            assert!(
                !pk.verify(&sig, b"purecrypto-kat", b"x"),
                "wrong ctx verifies {set:?}"
            );
            let mut tampered = sig.clone();
            *tampered.last_mut().unwrap() ^= 1;
            assert!(
                !pk.verify(&tampered, b"purecrypto-kat", b"ctx"),
                "tampered sig verifies {set:?}"
            );

            // Deterministic sign is reproducible and self-consistent.
            let d1 = sk.sign_deterministic(b"abc", b"").unwrap();
            let d2 = sk.sign_deterministic(b"abc", b"").unwrap();
            assert_eq!(d1, d2, "deterministic mismatch {set:?}");
            assert!(pk.verify(&d1, b"abc", b""), "det verify {set:?}");

            // Signature length matches the spec.
            assert_eq!(sig.len(), set.signature_size(), "sig size {set:?}");
        }
    }

    /// Roundtrip across every parameter set including the slow `s`-flavored
    /// ones. Ignored by default because signing for the `s` sets takes
    /// minutes in debug builds.
    #[test]
    #[ignore = "slow in debug; run with --release --ignored"]
    fn roundtrip_all_param_sets() {
        use ParamSet::*;
        let all = [
            Sha2_128s, Sha2_128f, Sha2_192s, Sha2_192f, Sha2_256s, Sha2_256f, Shake_128s,
            Shake_128f, Shake_192s, Shake_192f, Shake_256s, Shake_256f,
        ];
        for set in all {
            let mut rng = HmacDrbg::<Sha256>::new(b"slhdsa-roundtrip-all", set.oid_label(), &[]);
            let (sk, pk) = PrivateKey::generate(set, &mut rng);
            let sig = sk.sign_deterministic(b"purecrypto-kat", b"ctx").unwrap();
            assert!(pk.verify(&sig, b"purecrypto-kat", b"ctx"), "verify {set:?}");
            assert_eq!(sig.len(), set.signature_size(), "sig size {set:?}");
        }
    }

    impl ParamSet {
        /// Stable byte label used to personalize the test DRBG per set.
        fn oid_label(self) -> &'static [u8] {
            match self {
                ParamSet::Sha2_128s => b"sha2-128s",
                ParamSet::Sha2_128f => b"sha2-128f",
                ParamSet::Sha2_192s => b"sha2-192s",
                ParamSet::Sha2_192f => b"sha2-192f",
                ParamSet::Sha2_256s => b"sha2-256s",
                ParamSet::Sha2_256f => b"sha2-256f",
                ParamSet::Shake_128s => b"shake-128s",
                ParamSet::Shake_128f => b"shake-128f",
                ParamSet::Shake_192s => b"shake-192s",
                ParamSet::Shake_192f => b"shake-192f",
                ParamSet::Shake_256s => b"shake-256s",
                ParamSet::Shake_256f => b"shake-256f",
            }
        }
    }
}
