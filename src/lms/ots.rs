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
#[cfg(any(test, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
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
///
/// Used by the scalar chain walks and by the HSS child derivation; on the
/// batched targets the chains derive their `x` through the kernel.
#[cfg(any(
    test,
    feature = "alloc",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
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
/// Used by the non-bottom levels of an HSS key when they sign a child tree's
/// public key. Each such leaf signs exactly one child, so a random `C` would
/// be equally safe; the deterministic one has two extra properties the HSS
/// layer relies on: a regeneration interrupted before the state was persisted
/// re-emits a *byte-identical* signature when it is retried (the child key is
/// derived deterministically too, see [`derive_child`]), and the upper-level
/// signature a pre-v3 serialized key implied (leaf `0`, this `C`) can be
/// reproduced exactly when such a key is loaded, so no one-time key is ever
/// exposed twice under different randomizers.
///
/// The chain index `0xfffd` cannot collide with [`derive_x`] (whose chain
/// indices are `< p <= 265`) and matches the C-randomizer index used by the
/// RFC 8554 reference implementation.
// Only the HSS layer derives a deterministic randomizer, and that layer is
// `alloc`-gated (its level vectors are runtime-sized).
#[cfg(feature = "alloc")]
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

/// Derives the `(I, SEED)` of the child LMS tree that leaf `q` of the tree
/// `(i_id, seed)` signs in an HSS hierarchy:
///
/// * `SEED_child = H(I || u32str(q) || u16str(0xfffe) || 0xff || SEED)`
/// * `I_child    = H(I || u32str(q) || u16str(0xffff) || 0xff || SEED)[0..16]`
///
/// This is the derivation of the RFC 8554 reference implementation
/// (`SEED_CHILD_SEED` / `SEED_CHILD_I`), in the same `H(I || q || j || 0xff
/// || SEED)` family as [`derive_x`] (`j < 265`) and [`derive_c`]
/// (`j = 0xfffd`), so no two derivations share a preimage. Deriving children
/// deterministically means a parent leaf always signs the *same* child key,
/// whether the regeneration completes on the first attempt or is repeated
/// after a crash — the leaf can never be found signing two different messages.
#[cfg(feature = "alloc")]
pub(crate) fn derive_child(i_id: &[u8; 16], seed: &[u8; N], q: u32) -> ([u8; 16], [u8; N]) {
    let mut child_seed = [0u8; N];
    derive_x(i_id, seed, q, 0xfffe, &mut child_seed);
    let mut full_i = [0u8; N];
    derive_x(i_id, seed, q, 0xffff, &mut full_i);
    let mut child_i = [0u8; 16];
    child_i.copy_from_slice(&full_i[..16]);
    super::wipe(&mut full_i);
    (child_i, child_seed)
}

/// `K = H(I ‖ u32str(q) ‖ u16str(D_PBLC) ‖ K_0 ‖ … ‖ K_{p-1})` over the
/// concatenated chain ends `ks` (RFC 8554 §4.3 step 4).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn k_hash(i_id: &[u8; 16], q: u32, ks: &[u8]) -> [u8; N] {
    let mut h = Sha256::new();
    h.update(i_id);
    h.update(&q.to_be_bytes());
    h.update(&D_PBLC.to_be_bytes());
    h.update(ks);
    h.finalize()
}

/// The `p` Winternitz digits `coef(Q ‖ Cksm(Q), i, w)` of a message digest.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn digits(t: LmotsType, qc: &[u8; N + 2]) -> [u16; MAX_P] {
    let w = t.w();
    let mut d = [0u16; MAX_P];
    for (i, x) in d.iter_mut().enumerate().take(t.p()) {
        *x = coef(qc, i, w) as u16;
    }
    d
}

/// Computes the LM-OTS public key `K` for leaf `q` from the master `seed`
/// (RFC 8554 §4.3, Algorithm 1, with the Appendix A private-element derivation).
///
/// On x86_64 and aarch64 the `p` Winternitz chains are evaluated several at a
/// time through a multi-buffer SHA-256 kernel ([`lmots_mb`]); the scalar
/// [`public_key_scalar`] is the fallback elsewhere and the reference for the
/// differential tests.
pub(crate) fn public_key(t: LmotsType, i_id: &[u8; 16], seed: &[u8; N], q: u32) -> [u8; N] {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        lmots_mb::public_key(t, i_id, seed, q)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        public_key_scalar(t, i_id, seed, q)
    }
}

/// Scalar reference implementation of [`public_key`]: runs each of the `p`
/// Winternitz chains over its full `0..max` range one at a time, then folds the
/// chain outputs into `K = H(I ‖ q ‖ D_PBLC ‖ K_0 ‖ … ‖ K_{p-1})`.
#[cfg(any(test, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
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
    // `tmp` last held a chain end (public), but it walked through every private
    // element `x[chain]` on the way; wipe it once, outside the hash loops.
    super::wipe(&mut tmp);
    k_hash.finalize()
}

/// The chain walks of [`sign`]: writes `y[0] ‖ … ‖ y[p-1]` (`p · N` bytes)
/// into `ys`, where `y[i]` is `x[i]` advanced `coef(Q ‖ Cksm(Q), i, w)` steps.
fn sign_chains(
    t: LmotsType,
    i_id: &[u8; 16],
    seed: &[u8; N],
    q: u32,
    qc: &[u8; N + 2],
    ys: &mut [u8],
) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        lmots_mb::sign_chains(t, i_id, seed, q, qc, ys)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        sign_chains_scalar(t, i_id, seed, q, qc, ys)
    }
}

/// Scalar reference for [`sign_chains`].
#[cfg(any(test, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn sign_chains_scalar(
    t: LmotsType,
    i_id: &[u8; 16],
    seed: &[u8; N],
    q: u32,
    qc: &[u8; N + 2],
    ys: &mut [u8],
) {
    let p = t.p();
    let w = t.w();
    let mut tmp = [0u8; N];
    for chain in 0..p {
        let a = coef(qc, chain, w);
        derive_x(i_id, seed, q, chain as u16, &mut tmp);
        for j in 0..a {
            chain_step(i_id, q, chain as u16, j as u8, &mut tmp);
        }
        ys[chain * N..chain * N + N].copy_from_slice(&tmp);
    }
    // Each iteration loaded the private element `x[chain]` into `tmp` before
    // walking it forward `a` steps; the last one is still there. Wipe once per
    // signature rather than inside the per-hash loop.
    super::wipe(&mut tmp);
}

/// The chain walks of [`recover_public_key`]: advances each `y[i]` of `ys`
/// (`p · N` bytes) from `coef(Q ‖ Cksm(Q), i, w)` to `max`, returning the
/// public-key candidate `Kc`.
fn recover_chains(t: LmotsType, i_id: &[u8; 16], q: u32, qc: &[u8; N + 2], ys: &[u8]) -> [u8; N] {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        lmots_mb::recover_chains(t, i_id, q, qc, ys)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        recover_chains_scalar(t, i_id, q, qc, ys)
    }
}

/// Scalar reference for [`recover_chains`].
#[cfg(any(test, not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
fn recover_chains_scalar(
    t: LmotsType,
    i_id: &[u8; 16],
    q: u32,
    qc: &[u8; N + 2],
    ys: &[u8],
) -> [u8; N] {
    let p = t.p();
    let max = t.max_digit();
    let w = t.w();
    let mut k_hash = Sha256::new();
    k_hash.update(i_id);
    k_hash.update(&q.to_be_bytes());
    k_hash.update(&D_PBLC.to_be_bytes());
    let mut tmp = [0u8; N];
    for chain in 0..p {
        let a = coef(qc, chain, w);
        tmp.copy_from_slice(&ys[chain * N..chain * N + N]);
        for j in a..max {
            chain_step(i_id, q, chain as u16, j as u8, &mut tmp);
        }
        k_hash.update(&tmp);
    }
    k_hash.finalize()
}

/// Multi-buffer LM-OTS: the Winternitz chains evaluated several at a time
/// through a SHA-256 kernel — the AVX2 / AVX-512 multi-buffer kernels on
/// x86_64, and otherwise (aarch64) four single-stream compressions issued
/// back-to-back, which the out-of-order core overlaps (measured on Apple
/// M-series: 51.6 → 22.9 ns per hardware SHA-256 compression).
///
/// Each `derive_x` / `chain_step` is a single 55-byte (one-block) SHA-256
/// message; the layouts here are byte-for-byte the scalar [`derive_x`] /
/// [`chain_step`] in this module, and every routine is byte-identical to its
/// scalar reference (pinned by differential tests). The final `K = H(I ‖ q ‖
/// D_PBLC ‖ K_0 ‖ … ‖ K_{p-1})` stays scalar and absorbs the chain outputs in
/// strict order `0..p`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod lmots_mb {
    use super::{LmotsType, MAX_P, N, digits, k_hash};
    use crate::hash::sha256::H256;

    /// Lanes of the lockstep (non-SIMD) kernel.
    pub(super) const LOCKSTEP: usize = 4;

    /// An `L`-lane SHA-256 kernel: compresses `blocks[l]` into `states[l]` for
    /// every `l < lanes` (the SIMD kernels process all `L` lanes regardless).
    pub(super) type Sha256Kernel<const L: usize> = fn(&mut [[u32; 8]; L], &[[u8; 64]; L], usize);

    pub(super) fn lockstep256<const L: usize>(
        states: &mut [[u32; 8]; L],
        blocks: &[[u8; 64]; L],
        lanes: usize,
    ) {
        for (s, b) in states.iter_mut().zip(blocks).take(lanes) {
            crate::hash::sha256::compress256(s, b);
        }
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    fn sha256_x8(
        states: &mut [[u32; 8]; crate::hash::sha256_mb::LANES],
        blocks: &[[u8; 64]; crate::hash::sha256_mb::LANES],
        _lanes: usize,
    ) {
        crate::hash::sha256_mb::compress8(states, blocks);
    }

    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    fn sha256_x16(
        states: &mut [[u32; 8]; crate::hash::sha256_mb::LANES16],
        blocks: &[[u8; 64]; crate::hash::sha256_mb::LANES16],
        _lanes: usize,
    ) {
        crate::hash::sha256_mb::compress16(states, blocks);
    }

    /// Expands to `$f::<L>($args…, kernel)` with the widest available
    /// SHA-256 kernel: 16 lanes on AVX-512, 8 on AVX2, else the lockstep
    /// kernel. Must be the tail expression of a function returning what `$f`
    /// returns.
    macro_rules! sha256_dispatch {
        ($f:ident($($a:expr),* $(,)?)) => {{
            #[cfg(all(feature = "std", target_arch = "x86_64"))]
            {
                if crate::hash::sha256_mb::supported16() {
                    return $f::<{ crate::hash::sha256_mb::LANES16 }>($($a,)* sha256_x16);
                }
                if crate::hash::sha256_mb::supported() {
                    return $f::<{ crate::hash::sha256_mb::LANES }>($($a,)* sha256_x8);
                }
            }
            $f::<LOCKSTEP>($($a,)* lockstep256::<LOCKSTEP>)
        }};
    }

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
    fn state_be(s: &[u32; 8], o: &mut [u8; N]) {
        for (i, w) in s.iter().enumerate() {
            o[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
    }

    /// Fills `vals[c·N..]` with `x[c] = derive_x(c)` for `c < p`, `L` at a time.
    fn derive_x_n<const L: usize>(
        i_id: &[u8; 16],
        seed: &[u8; N],
        q: u32,
        p: usize,
        vals: &mut [u8],
        kernel: Sha256Kernel<L>,
    ) {
        let mut blocks = [[0u8; 64]; L];
        let mut states = [H256; L];
        let mut c0 = 0usize;
        while c0 < p {
            let lanes = (p - c0).min(L);
            for (l, blk) in blocks.iter_mut().enumerate().take(lanes) {
                *blk = block55(i_id, q, (c0 + l) as u16, 0xff, seed);
            }
            states = [H256; L];
            kernel(&mut states, &blocks, lanes);
            for (l, s) in states.iter().enumerate().take(lanes) {
                let o: &mut [u8; N] = (&mut vals[(c0 + l) * N..(c0 + l) * N + N])
                    .try_into()
                    .unwrap();
                state_be(s, o);
            }
            c0 += lanes;
        }
        // `blocks` embedded the master seed; `states` are the private x values
        // (the caller owns the copies in `vals`).
        super::super::wipe(blocks.as_flattened_mut());
        crate::zeroize::Zeroize::zeroize(states.as_flattened_mut());
    }

    /// Advances chain `c` (the value at `vals[c·N..]`, `c < p`) from position
    /// `pos[c]` to `end[c]` (`<= 255`) in place, `L` chains in lockstep.
    ///
    /// Lanes are refilled as chains finish, so the kernel runs with every
    /// lane active until the last `L − 1` chains drain — the total work is
    /// `⌈Σ steps / L⌉` kernel calls rather than `Σ max-of-group`. Chain
    /// positions are public (they are the signature's Winternitz digits), so
    /// the scheduling may depend on them.
    fn chains_n<const L: usize>(
        i_id: &[u8; 16],
        q: u32,
        p: usize,
        vals: &mut [u8],
        pos: &[u16],
        end: &[u16],
        kernel: Sha256Kernel<L>,
    ) {
        let mut chain = [0u16; L];
        let mut at = [0u16; L];
        let mut stop = [0u16; L];
        let mut inout = [[0u8; N]; L];
        let mut blocks = [[0u8; 64]; L];
        let mut states = [H256; L];
        let mut active = 0usize;
        let mut next = 0usize;
        loop {
            // Fill idle lanes with the next chains that have steps left.
            while active < L && next < p {
                let c = next;
                next += 1;
                if pos[c] >= end[c] {
                    continue;
                }
                chain[active] = c as u16;
                at[active] = pos[c];
                stop[active] = end[c];
                inout[active].copy_from_slice(&vals[c * N..c * N + N]);
                active += 1;
            }
            if active == 0 {
                break;
            }
            for l in 0..active {
                blocks[l] = block55(i_id, q, chain[l], at[l] as u8, &inout[l]);
            }
            states = [H256; L];
            kernel(&mut states, &blocks, active);
            for l in 0..active {
                state_be(&states[l], &mut inout[l]);
                at[l] += 1;
            }
            // Retire finished lanes, moving the last active lane into the gap
            // so the active lanes stay a prefix.
            let mut l = 0;
            while l < active {
                if at[l] == stop[l] {
                    let c = chain[l] as usize;
                    vals[c * N..c * N + N].copy_from_slice(&inout[l]);
                    active -= 1;
                    chain[l] = chain[active];
                    at[l] = at[active];
                    stop[l] = stop[active];
                    inout[l] = inout[active];
                } else {
                    l += 1;
                }
            }
        }
        // The lanes and blocks carried the private x values and every chain
        // intermediate.
        super::super::wipe(inout.as_flattened_mut());
        super::super::wipe(blocks.as_flattened_mut());
        crate::zeroize::Zeroize::zeroize(states.as_flattened_mut());
    }

    /// [`super::public_key`] through the SHA-256 kernel.
    pub(super) fn public_key(t: LmotsType, i_id: &[u8; 16], seed: &[u8; N], q: u32) -> [u8; N] {
        sha256_dispatch!(public_key_n(t, i_id, seed, q))
    }

    pub(super) fn public_key_n<const L: usize>(
        t: LmotsType,
        i_id: &[u8; 16],
        seed: &[u8; N],
        q: u32,
        kernel: Sha256Kernel<L>,
    ) -> [u8; N] {
        let p = t.p();
        let max = [t.max_digit() as u16; MAX_P];
        let mut vals = [0u8; MAX_P * N];
        derive_x_n::<L>(i_id, seed, q, p, &mut vals, kernel);
        chains_n::<L>(i_id, q, p, &mut vals, &[0u16; MAX_P], &max, kernel);
        let k = k_hash(i_id, q, &vals[..p * N]);
        // `vals` held the private x values before the chains ran.
        super::super::wipe(&mut vals);
        k
    }

    /// [`super::sign_chains`] through the SHA-256 kernel.
    pub(super) fn sign_chains(
        t: LmotsType,
        i_id: &[u8; 16],
        seed: &[u8; N],
        q: u32,
        qc: &[u8; N + 2],
        ys: &mut [u8],
    ) {
        sha256_dispatch!(sign_chains_n(t, i_id, seed, q, qc, ys))
    }

    pub(super) fn sign_chains_n<const L: usize>(
        t: LmotsType,
        i_id: &[u8; 16],
        seed: &[u8; N],
        q: u32,
        qc: &[u8; N + 2],
        ys: &mut [u8],
        kernel: Sha256Kernel<L>,
    ) {
        let p = t.p();
        let end = digits(t, qc);
        derive_x_n::<L>(i_id, seed, q, p, ys, kernel);
        chains_n::<L>(i_id, q, p, ys, &[0u16; MAX_P], &end, kernel);
    }

    /// [`super::recover_chains`] through the SHA-256 kernel.
    pub(super) fn recover_chains(
        t: LmotsType,
        i_id: &[u8; 16],
        q: u32,
        qc: &[u8; N + 2],
        ys: &[u8],
    ) -> [u8; N] {
        sha256_dispatch!(recover_chains_n(t, i_id, q, qc, ys))
    }

    pub(super) fn recover_chains_n<const L: usize>(
        t: LmotsType,
        i_id: &[u8; 16],
        q: u32,
        qc: &[u8; N + 2],
        ys: &[u8],
        kernel: Sha256Kernel<L>,
    ) -> [u8; N] {
        let p = t.p();
        let pos = digits(t, qc);
        let max = [t.max_digit() as u16; MAX_P];
        let mut vals = [0u8; MAX_P * N];
        vals[..p * N].copy_from_slice(&ys[..p * N]);
        chains_n::<L>(i_id, q, p, &mut vals, &pos, &max, kernel);
        k_hash(i_id, q, &vals[..p * N])
    }
}

/// Differential tests: the multi-buffer batchers must reproduce the scalar
/// routines byte-for-byte across LM-OTS parameter sets and random inputs,
/// through the dispatched kernel and the lockstep kernel explicitly.
#[cfg(all(test, any(target_arch = "x86_64", target_arch = "aarch64")))]
mod lmots_mb_tests {
    use super::{LmotsType, MAX_P, N, lmots_mb, q_with_checksum};

    #[test]
    fn batched_matches_scalar() {
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
            let p = t.p();
            for _ in 0..6 {
                let mut i_id = [0u8; 16];
                for b in i_id.iter_mut() {
                    *b = (next() >> 24) as u8;
                }
                let mut seed = [0u8; N];
                for b in seed.iter_mut() {
                    *b = (next() >> 24) as u8;
                }
                let q = next() as u32;
                let mut q_digest = [0u8; N];
                for b in q_digest.iter_mut() {
                    *b = (next() >> 24) as u8;
                }
                let qc = q_with_checksum(t, &q_digest);

                let want = super::public_key_scalar(t, &i_id, &seed, q);
                assert_eq!(
                    super::public_key(t, &i_id, &seed, q),
                    want,
                    "pk {t:?} q={q}"
                );
                assert_eq!(
                    lmots_mb::public_key_n::<4>(t, &i_id, &seed, q, lmots_mb::lockstep256::<4>),
                    want,
                    "pk lockstep {t:?} q={q}"
                );

                let mut want_ys = [0u8; MAX_P * N];
                super::sign_chains_scalar(t, &i_id, &seed, q, &qc, &mut want_ys[..p * N]);
                let mut got_ys = [0u8; MAX_P * N];
                super::sign_chains(t, &i_id, &seed, q, &qc, &mut got_ys[..p * N]);
                assert_eq!(got_ys[..p * N], want_ys[..p * N], "sign {t:?} q={q}");
                let mut got_ys = [0u8; MAX_P * N];
                lmots_mb::sign_chains_n::<4>(
                    t,
                    &i_id,
                    &seed,
                    q,
                    &qc,
                    &mut got_ys[..p * N],
                    lmots_mb::lockstep256::<4>,
                );
                assert_eq!(
                    got_ys[..p * N],
                    want_ys[..p * N],
                    "sign lockstep {t:?} q={q}"
                );

                let want_kc = super::recover_chains_scalar(t, &i_id, q, &qc, &want_ys[..p * N]);
                assert_eq!(want_kc, want, "recover scalar {t:?} q={q}");
                assert_eq!(
                    super::recover_chains(t, &i_id, q, &qc, &want_ys[..p * N]),
                    want,
                    "recover {t:?} q={q}"
                );
                assert_eq!(
                    lmots_mb::recover_chains_n::<4>(
                        t,
                        &i_id,
                        q,
                        &qc,
                        &want_ys[..p * N],
                        lmots_mb::lockstep256::<4>
                    ),
                    want,
                    "recover lockstep {t:?} q={q}"
                );
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
    sign_chains(t, i_id, seed, q, &qc, &mut out[4 + N..4 + N + p * N]);
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
    debug_assert!(p <= MAX_P);
    Some(recover_chains(t, i_id, q, &qc, &sig[4 + N..4 + N + p * N]))
}
