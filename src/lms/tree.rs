//! LMS Merkle-tree construction, signing, and verification (RFC 8554 §5).

use super::ots;
use super::params::{D_INTR, D_LEAF, LmotsType, LmsType, N};
use crate::ct::ConstantTimeEq;
use crate::hash::{Digest, Sha256};
use alloc::vec;
use alloc::vec::Vec;

/// Computes the LMS leaf hash for leaf `q`
/// (`H(I || u32str(2^h + q) || u16str(D_LEAF) || K)`), where `K` is the LM-OTS
/// public key for that leaf.
fn leaf_hash(
    lms: LmsType,
    ots_type: LmotsType,
    i_id: &[u8; 16],
    seed: &[u8; N],
    q: u32,
) -> [u8; N] {
    let k = ots::public_key(ots_type, i_id, seed, q);
    let node_num = (1u64 << lms.h()) as u32 + q;
    let mut h = Sha256::new();
    h.update(i_id);
    h.update(&node_num.to_be_bytes());
    h.update(&D_LEAF.to_be_bytes());
    h.update(&k);
    h.finalize()
}

/// Hashes two child nodes into their parent at `node_num`
/// (`H(I || u32str(node_num) || u16str(D_INTR) || left || right)`).
fn interior_hash(i_id: &[u8; 16], node_num: u32, left: &[u8; N], right: &[u8; N]) -> [u8; N] {
    let mut h = Sha256::new();
    h.update(i_id);
    h.update(&node_num.to_be_bytes());
    h.update(&D_INTR.to_be_bytes());
    h.update(left);
    h.update(right);
    h.finalize()
}

/// Recursively computes the value of tree node `node_num`
/// (RFC 8554 §5.3). Leaf nodes are numbered `2^h .. 2^(h+1)`.
fn node_value(
    lms: LmsType,
    ots_type: LmotsType,
    i_id: &[u8; 16],
    seed: &[u8; N],
    node_num: u32,
) -> [u8; N] {
    let leaf_base = (1u64 << lms.h()) as u32;
    if node_num >= leaf_base {
        leaf_hash(lms, ots_type, i_id, seed, node_num - leaf_base)
    } else {
        let left = node_value(lms, ots_type, i_id, seed, 2 * node_num);
        let right = node_value(lms, ots_type, i_id, seed, 2 * node_num + 1);
        interior_hash(i_id, node_num, &left, &right)
    }
}

/// Computes the LMS public-key root `T[1]` from the master `seed`
/// (RFC 8554 §5.3 / Appendix C).
pub(crate) fn compute_root(
    lms: LmsType,
    ots_type: LmotsType,
    i_id: &[u8; 16],
    seed: &[u8; N],
) -> [u8; N] {
    node_value(lms, ots_type, i_id, seed, 1)
}

/// Serializes the LMS public key:
/// `u32str(lms_type) || u32str(ots_type) || I || T[1]` (24 + n bytes).
pub(crate) fn encode_public_key(
    lms: LmsType,
    ots_type: LmotsType,
    i_id: &[u8; 16],
    root: &[u8; N],
) -> Vec<u8> {
    let mut v = Vec::with_capacity(24 + N);
    v.extend_from_slice(&lms.typecode().to_be_bytes());
    v.extend_from_slice(&ots_type.typecode().to_be_bytes());
    v.extend_from_slice(i_id);
    v.extend_from_slice(root);
    v
}

/// Generates an LMS signature for leaf `q` (RFC 8554 §5.4, Algorithm 5 + D).
///
/// Returns `u32str(q) || lmots_signature || u32str(lms_type) || path[0..h]`.
pub(crate) fn sign(
    lms: LmsType,
    ots_type: LmotsType,
    i_id: &[u8; 16],
    seed: &[u8; N],
    q: u32,
    c: &[u8; N],
    message: &[u8],
) -> Vec<u8> {
    let h = lms.h();
    let ots_len = ots_type.sig_len();
    let mut sig = vec![0u8; 4 + ots_len + 4 + h as usize * N];

    sig[..4].copy_from_slice(&q.to_be_bytes());
    ots::sign(
        ots_type,
        i_id,
        seed,
        q,
        c,
        message,
        &mut sig[4..4 + ots_len],
    );
    let lms_type_off = 4 + ots_len;
    sig[lms_type_off..lms_type_off + 4].copy_from_slice(&lms.typecode().to_be_bytes());

    // Authentication path: path[i] = T[(2^h + q)/2^i xor 1].
    let mut path_off = lms_type_off + 4;
    let r = (1u64 << h) as u32 + q;
    for i in 0..h {
        let node = (r >> i) ^ 1;
        let val = node_value(lms, ots_type, i_id, seed, node);
        sig[path_off..path_off + N].copy_from_slice(&val);
        path_off += N;
    }
    sig
}

/// Computes the candidate LMS root `Tc` from a signature and message
/// (RFC 8554 §5.4.2, Algorithm 6a). Returns `None` on any structural error.
///
/// `pubtype`/`ots_pubtype` are the typecodes bound by the LMS public key.
pub(crate) fn recover_root(
    pubtype: LmsType,
    ots_pubtype: LmotsType,
    i_id: &[u8; 16],
    message: &[u8],
    sig: &[u8],
) -> Option<[u8; N]> {
    if sig.len() < 8 {
        return None;
    }
    let q = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]);
    let otssigtype = u32::from_be_bytes([sig[4], sig[5], sig[6], sig[7]]);
    if otssigtype != ots_pubtype.typecode() {
        return None;
    }
    let ots_len = ots_pubtype.sig_len();
    // 4 (q) + ots_len + 4 (lms type) + h*n.
    let h = pubtype.h();
    let expected = 4 + ots_len + 4 + h as usize * N;
    if sig.len() != expected {
        return None;
    }
    let ots_sig = &sig[4..4 + ots_len];
    let lms_type_off = 4 + ots_len;
    let sigtype = u32::from_be_bytes([
        sig[lms_type_off],
        sig[lms_type_off + 1],
        sig[lms_type_off + 2],
        sig[lms_type_off + 3],
    ]);
    if sigtype != pubtype.typecode() {
        return None;
    }
    if q as u64 >= pubtype.leaves() {
        return None;
    }

    let kc = ots::recover_public_key(ots_pubtype, i_id, q, message, ots_sig)?;

    // node_num = 2^h + q; fold up using the path.
    let mut node_num = (1u64 << h) as u32 + q;
    let mut tmp = {
        let mut hh = Sha256::new();
        hh.update(i_id);
        hh.update(&node_num.to_be_bytes());
        hh.update(&D_LEAF.to_be_bytes());
        hh.update(&kc);
        hh.finalize()
    };
    let path_base = lms_type_off + 4;
    let mut i = 0usize;
    while node_num > 1 {
        let off = path_base + i * N;
        let path_node = &sig[off..off + N];
        let parent = node_num / 2;
        if node_num & 1 == 1 {
            // odd: path[i] is the left sibling.
            let mut hh = Sha256::new();
            hh.update(i_id);
            hh.update(&parent.to_be_bytes());
            hh.update(&D_INTR.to_be_bytes());
            hh.update(path_node);
            hh.update(&tmp);
            tmp = hh.finalize();
        } else {
            let mut hh = Sha256::new();
            hh.update(i_id);
            hh.update(&parent.to_be_bytes());
            hh.update(&D_INTR.to_be_bytes());
            hh.update(&tmp);
            hh.update(path_node);
            tmp = hh.finalize();
        }
        node_num = parent;
        i += 1;
    }
    Some(tmp)
}

/// Verifies an LMS signature against a serialized LMS public key
/// (RFC 8554 §5.4.2, Algorithm 6). Constant-time root comparison.
pub(crate) fn verify(public_key: &[u8], message: &[u8], sig: &[u8]) -> bool {
    if public_key.len() < 8 {
        return false;
    }
    let pubtype = match LmsType::from_u32(u32::from_be_bytes([
        public_key[0],
        public_key[1],
        public_key[2],
        public_key[3],
    ])) {
        Some(t) => t,
        None => return false,
    };
    let ots_pubtype = match LmotsType::from_u32(u32::from_be_bytes([
        public_key[4],
        public_key[5],
        public_key[6],
        public_key[7],
    ])) {
        Some(t) => t,
        None => return false,
    };
    if public_key.len() != 24 + N {
        return false;
    }
    let mut i_id = [0u8; 16];
    i_id.copy_from_slice(&public_key[8..24]);
    let t1 = &public_key[24..24 + N];

    match recover_root(pubtype, ots_pubtype, &i_id, message, sig) {
        Some(tc) => bool::from(tc[..].ct_eq(t1)),
        None => false,
    }
}
