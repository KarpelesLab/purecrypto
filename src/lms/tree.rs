//! LMS Merkle-tree construction, signing, and verification (RFC 8554 §5).
//!
//! Node numbering follows RFC 8554 §5.3: the root is node `1`, node `k` has
//! children `2k` and `2k + 1`, and the `2^h` leaves are nodes
//! `2^h .. 2^(h+1)`. "Level" `d` (`0 <= d <= h`) is the set of nodes
//! `2^d .. 2^(d+1)`, so level `0` is the root and level `h` the leaves.

use super::ots;
use super::params::{D_INTR, D_LEAF, LmotsType, LmsType, N};
use crate::ct::ConstantTimeEq;
use crate::hash::{Digest, Sha256};
#[cfg(feature = "alloc")]
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
///
/// This is the naive `O(2^(h - level))` evaluation: it re-derives every leaf
/// under the node. It is the reference the cached path is tested against, the
/// root computation for allocator-less builds, and the authentication-path
/// source of the allocator-less signer (which has nowhere to keep a cache).
pub(crate) fn node_value(
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
) -> [u8; super::PUBKEY_LEN] {
    let mut v = [0u8; super::PUBKEY_LEN];
    v[..4].copy_from_slice(&lms.typecode().to_be_bytes());
    v[4..8].copy_from_slice(&ots_type.typecode().to_be_bytes());
    v[8..24].copy_from_slice(i_id);
    v[24..].copy_from_slice(root);
    v
}

// ===================================================================
// Signer-side Merkle node cache
// ===================================================================

/// Number of top levels (`0 ..= TOP_LEVELS`) of a tree that [`NodeCache`]
/// keeps resident, counting the root as level `0`.
///
/// A tree of height `h <= TOP_LEVELS` is therefore cached in full. For the
/// taller `H20` / `H25` sets only levels `0 ..= 15` are resident and the
/// subtree of height `h - 15` that contains the current leaf is regenerated
/// on demand. See [`NodeCache`] for the resulting memory bound.
#[cfg(feature = "alloc")]
const TOP_LEVELS: u32 = 15;

/// A signer-side cache of Merkle nodes so that an authentication path costs
/// `O(h)` array reads instead of a full `O(2^h)` re-derivation of the tree.
///
/// The cache has two tiers:
///
/// * **Top tier** — every node of levels `0 ..= T`, `T = min(h, TOP_LEVELS)`,
///   stored as a heap array indexed by RFC 8554 node number
///   (`2^(T+1)` slots of `N` bytes; slot `0` is unused). It is built once —
///   this *is* key generation, since the root falls out of it — and never
///   changes. For `h <= 15` the top tier is the whole tree.
/// * **Bottom tier** (`h > T` only) — the subtree of height `B = h - T` whose
///   root is the current leaf's ancestor at level `T`, stored in the same
///   heap layout with `2^(B+1)` slots. Leaves are consumed sequentially, so
///   at most one bottom subtree is live; entering the next one rebuilds it
///   from the seed (`2^B` leaf computations, once every `2^B` signatures).
///
/// # Memory bound
///
/// Top tier: `2^(T+1) * 32` bytes = **2 MiB** for `T = 15` (`H15`, `H20`,
/// `H25`); 64 KiB for `H10`; 2 KiB for `H5`. Bottom tier: `2^(B+1) * 32`
/// bytes = 2 KiB for `H20` (`B = 5`) and 64 KiB for `H25` (`B = 10`). So a
/// signer never holds more than about **2.1 MiB** of cached nodes per tree,
/// whatever the parameter set.
///
/// # Amortized cost
///
/// Over a tree's whole life every leaf is derived exactly twice (once for the
/// top tier, once when its bottom subtree is built) — the same order of work
/// as a single key generation, spread over `2^h` signatures — versus one
/// full key generation *per signature* without the cache. The worst-case
/// latency of a single signature is one bottom-subtree rebuild: 32 leaves
/// for `H20`, 1024 for `H25`.
///
/// Cached nodes are public Merkle hashes (they are exactly what signatures
/// carry), so the cache holds no secret material, is never serialized, and is
/// rebuilt lazily from the seed after a key is loaded from bytes.
#[cfg(feature = "alloc")]
pub(crate) struct NodeCache {
    /// Tree height `h`.
    h: u32,
    /// Lowest level held by the top tier (`T`).
    top_levels: u32,
    /// Top tier, indexed by node number; `2^(T+1)` slots.
    top: Vec<[u8; N]>,
    /// Bottom tier: `(root node number at level T, nodes in local heap
    /// layout)`. `None` until the first signature of a tree taller than `T`.
    bottom: Option<(u32, Vec<[u8; N]>)>,
}

#[cfg(feature = "alloc")]
impl NodeCache {
    /// Builds the top tier — a full `O(2^h)` leaf derivation, i.e. key
    /// generation. The root is `self.root()` afterwards.
    pub(crate) fn build(
        lms: LmsType,
        ots_type: LmotsType,
        i_id: &[u8; 16],
        seed: &[u8; N],
    ) -> Self {
        let h = lms.h();
        let top_levels = h.min(TOP_LEVELS);
        let top = build_subtree(lms, ots_type, i_id, seed, 1, h, top_levels);
        NodeCache {
            h,
            top_levels,
            top,
            bottom: None,
        }
    }

    /// The tree root `T[1]`.
    pub(crate) fn root(&self) -> [u8; N] {
        self.top[1]
    }

    /// Makes every node on leaf `q`'s authentication path available to
    /// [`node`](Self::node): a no-op unless the tree is taller than the top
    /// tier and `q` lies outside the currently built bottom subtree, in which
    /// case that subtree is (re)built.
    pub(crate) fn prepare(
        &mut self,
        lms: LmsType,
        ots_type: LmotsType,
        i_id: &[u8; 16],
        seed: &[u8; N],
        q: u32,
    ) {
        let b = self.h - self.top_levels;
        if b == 0 {
            return;
        }
        // The ancestor of leaf `q` at level `T` roots the subtree we need.
        let sub_root = ((1u64 << self.h) as u32 + q) >> b;
        if matches!(self.bottom, Some((r, _)) if r == sub_root) {
            return;
        }
        // Drop the stale subtree before building the new one so the peak is a
        // single bottom tier.
        self.bottom = None;
        let nodes = build_subtree(lms, ots_type, i_id, seed, sub_root, b, b);
        self.bottom = Some((sub_root, nodes));
    }

    /// The value of node `node_num`, which must be in the top tier or in the
    /// bottom subtree selected by the last [`prepare`](Self::prepare).
    ///
    /// # Panics
    ///
    /// If the node is not cached — a signer bug, never reachable through the
    /// public API, which always prepares the leaf's subtree first.
    pub(crate) fn node(&self, node_num: u32) -> [u8; N] {
        let level = 31 - node_num.leading_zeros();
        if level <= self.top_levels {
            return self.top[node_num as usize];
        }
        let (sub_root, nodes) = self
            .bottom
            .as_ref()
            .expect("LMS node cache: bottom subtree not prepared");
        let d = level - self.top_levels;
        assert_eq!(
            node_num >> d,
            *sub_root,
            "LMS node cache: node outside the prepared bottom subtree"
        );
        nodes[((1u32 << d) | (node_num & ((1u32 << d) - 1))) as usize]
    }
}

/// Derives every node of the subtree rooted at `root_node` whose leaves are
/// the `2^depth` tree leaves `depth` levels below it, and returns the nodes of
/// its top `keep` levels (`0 ..= keep` below the root) in heap layout: slot
/// `(1 << d) | j` holds the `j`-th node at depth `d` below `root_node`, and
/// slot `1` the subtree root. Slot `0` is unused.
///
/// `root_node`'s level plus `depth` must equal the tree height, so that the
/// subtree bottoms out on real leaves. Runs the classic treehash fold with a
/// `depth + 1`-entry stack, so it needs no more than that of scratch space
/// beyond the returned nodes.
#[cfg(feature = "alloc")]
fn build_subtree(
    lms: LmsType,
    ots_type: LmotsType,
    i_id: &[u8; 16],
    seed: &[u8; N],
    root_node: u32,
    depth: u32,
    keep: u32,
) -> Vec<[u8; N]> {
    debug_assert!(keep <= depth);
    debug_assert_eq!((31 - root_node.leading_zeros()) + depth, lms.h());
    let leaf_base = (1u64 << lms.h()) as u32;
    let first_leaf = root_node << depth;
    let mut out = alloc::vec![[0u8; N]; 1usize << (keep + 1)];
    // Treehash stack of `(global node number, value)`; two entries at the same
    // depth are always adjacent siblings, so they fold as soon as they meet.
    let mut stack: Vec<(u32, [u8; N])> = Vec::with_capacity(depth as usize + 1);
    let store = |node: u32, val: &[u8; N], out: &mut Vec<[u8; N]>| {
        let d = (31 - node.leading_zeros()) - (31 - root_node.leading_zeros());
        if d <= keep {
            out[((1u32 << d) | (node - (root_node << d))) as usize] = *val;
        }
    };
    for j in 0..(1u32 << depth) {
        let node = first_leaf + j;
        let val = leaf_hash(lms, ots_type, i_id, seed, node - leaf_base);
        store(node, &val, &mut out);
        stack.push((node, val));
        while stack.len() >= 2 {
            let (rn, rv) = stack[stack.len() - 1];
            let (ln, lv) = stack[stack.len() - 2];
            if ln >> 1 != rn >> 1 || ln & 1 != 0 {
                break;
            }
            stack.truncate(stack.len() - 2);
            let parent = ln >> 1;
            let pv = interior_hash(i_id, parent, &lv, &rv);
            store(parent, &pv, &mut out);
            stack.push((parent, pv));
        }
    }
    debug_assert_eq!(stack.len(), 1);
    debug_assert_eq!(stack[0].0, root_node);
    out
}

/// Generates an LMS signature for leaf `q` (RFC 8554 §5.4, Algorithm 5 + D).
///
/// Writes `u32str(q) || lmots_signature || u32str(lms_type) || path[0..h]` into
/// `sig`, which must be exactly [`signature_len`](super::signature_len) octets,
/// and returns the number written. Allocation-free so that signing works on
/// allocator-less targets; the `Vec`-returning wrapper lives in `super`.
///
/// `node(node_num)` supplies the authentication-path nodes: the signer passes
/// a [`NodeCache`] lookup when it has one, or [`node_value`] on allocator-less
/// targets.
// One argument over clippy's default threshold: the RFC 8554 signing inputs
// (parameter pair, I, seed, q, randomizer, message) plus the caller's output
// buffer and the node source. Bundling them into a struct would only move the
// same fields around.
#[allow(clippy::too_many_arguments)]
pub(crate) fn sign(
    lms: LmsType,
    ots_type: LmotsType,
    i_id: &[u8; 16],
    seed: &[u8; N],
    q: u32,
    c: &[u8; N],
    message: &[u8],
    sig: &mut [u8],
    mut node: impl FnMut(u32) -> [u8; N],
) -> usize {
    let h = lms.h();
    let ots_len = ots_type.sig_len();
    debug_assert_eq!(sig.len(), 4 + ots_len + 4 + h as usize * N);
    sig.fill(0);

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
        let val = node((r >> i) ^ 1);
        sig[path_off..path_off + N].copy_from_slice(&val);
        path_off += N;
    }
    path_off
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

/// The cached authentication path must be byte-identical to the naive
/// recursive derivation, including across bottom-subtree boundaries.
#[cfg(all(test, feature = "alloc"))]
mod cache_tests {
    use super::*;

    /// Collects `path[0..h]` for leaf `q` from a node source.
    fn path(h: u32, q: u32, mut node: impl FnMut(u32) -> [u8; N]) -> Vec<[u8; N]> {
        let r = (1u64 << h) as u32 + q;
        (0..h).map(|i| node((r >> i) ^ 1)).collect()
    }

    fn check(lms: LmsType, ots: LmotsType, qs: &[u32]) {
        let i_id = [0x11u8; 16];
        let seed = [0x22u8; N];
        let mut cache = NodeCache::build(lms, ots, &i_id, &seed);
        assert_eq!(cache.root(), compute_root(lms, ots, &i_id, &seed));
        for &q in qs {
            cache.prepare(lms, ots, &i_id, &seed, q);
            let cached = path(lms.h(), q, |n| cache.node(n));
            let naive = path(lms.h(), q, |n| node_value(lms, ots, &i_id, &seed, n));
            assert_eq!(cached, naive, "{lms:?} leaf {q}");
        }
    }

    /// Full-tree cache (`h <= TOP_LEVELS`): every path node is resident.
    #[test]
    fn full_tree_paths_match_naive() {
        check(
            LmsType::Sha256M32H5,
            LmotsType::Sha256N32W8,
            &[0, 1, 2, 15, 16, 30, 31],
        );
        check(
            LmsType::Sha256M32H10,
            LmotsType::Sha256N32W1,
            &[0, 511, 512, 1023],
        );
    }

    /// Two-tier cache: exercised on a tree whose height exceeds a small
    /// forced top tier, so the bottom subtree is rebuilt as `q` crosses
    /// subtree boundaries (both forwards and, for a reload, backwards).
    #[test]
    fn two_tier_paths_match_naive_across_boundaries() {
        let lms = LmsType::Sha256M32H10;
        let ots = LmotsType::Sha256N32W1;
        let i_id = [0x33u8; 16];
        let seed = [0x44u8; N];
        // Top tier holds levels 0..=7; bottom subtrees have height 3 (8 leaves).
        let top_levels = 7;
        let top = build_subtree(lms, ots, &i_id, &seed, 1, 10, top_levels);
        let mut cache = NodeCache {
            h: 10,
            top_levels,
            top,
            bottom: None,
        };
        assert_eq!(cache.root(), compute_root(lms, ots, &i_id, &seed));
        for q in [0u32, 7, 8, 9, 15, 16, 500, 511, 512, 1016, 1023, 3, 1023, 0] {
            cache.prepare(lms, ots, &i_id, &seed, q);
            let cached = path(10, q, |n| cache.node(n));
            let naive = path(10, q, |n| node_value(lms, ots, &i_id, &seed, n));
            assert_eq!(cached, naive, "leaf {q}");
            let (root, _) = cache.bottom.as_ref().unwrap();
            assert_eq!(*root, (1024 + q) >> 3, "bottom subtree root for {q}");
        }
    }

    /// `build_subtree` with `keep < depth` stores exactly the top levels, and
    /// a subtree rooted below the tree root agrees with the naive values.
    #[test]
    fn build_subtree_partial_keep_matches_naive() {
        let lms = LmsType::Sha256M32H5;
        let ots = LmotsType::Sha256N32W4;
        let i_id = [0x55u8; 16];
        let seed = [0x66u8; N];
        // Subtree rooted at node 5 (level 2), depth 3, keep 2.
        let nodes = build_subtree(lms, ots, &i_id, &seed, 5, 3, 2);
        assert_eq!(nodes.len(), 8);
        for d in 0..=2u32 {
            for j in 0..(1u32 << d) {
                let global = (5u32 << d) + j;
                assert_eq!(
                    nodes[((1 << d) | j) as usize],
                    node_value(lms, ots, &i_id, &seed, global),
                    "depth {d} index {j}"
                );
            }
        }
    }
}
