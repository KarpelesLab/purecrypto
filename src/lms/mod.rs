//! LMS / HSS stateful hash-based signatures (RFC 8554, NIST SP 800-208).
//!
//! This module implements the Leighton-Micali Signature scheme (LMS), its
//! one-time-signature building block (LM-OTS), and the Hierarchical Signature
//! System (HSS) that composes LMS trees into a multi-level key. Everything is
//! built from SHA-256 (`n = m = 32`); the supported parameter sets are
//! [`LmotsType`] `W{1,2,4,8}` and [`LmsType`] `H{5,10,15,20,25}`.
//!
//! # Statefulness — read this before using a private key
//!
//! LMS/HSS are **stateful** signature schemes. Each signature consumes a
//! one-time LM-OTS key identified by a leaf index `q`. **Signing twice with
//! the same `q` is catastrophic**: it lets an attacker forge signatures on
//! arbitrary messages. To use these keys safely you MUST observe all of:
//!
//! * **Persist after every sign.** [`LmsPrivateKey::sign`] /
//!   [`HssPrivateKey::sign`] advance `q` in place. Serialize the key with
//!   [`LmsPrivateKey::to_bytes`] / [`HssPrivateKey::to_bytes`] and durably
//!   store it *before* releasing the signature, so a crash cannot replay `q`.
//! * **Never clone-then-sign both copies.** [`Clone`] is intentionally **not**
//!   implemented for the private-key types. Reloading the *same* serialized
//!   state into two live keys and signing from each reuses `q` — do not do it.
//! * **Treat exhaustion as terminal.** When [`LmsPrivateKey::remaining`] /
//!   [`HssPrivateKey::remaining`] reaches zero, signing returns
//!   [`Error::Exhausted`]; the key MUST be retired, never wrapped around.
//!
//! Secret material (the seed and identifier) is wiped on drop.
//!
//! # Signing cost
//!
//! With the `alloc` feature a private key keeps a cache of Merkle nodes (a
//! signer-side structure that holds only public hashes and is never
//! serialized), so a signature costs one LM-OTS signature plus `O(h)` cached
//! reads. The cache is built at key generation — it *is* key generation — or
//! lazily on the first signature after [`LmsPrivateKey::from_bytes`] /
//! [`HssPrivateKey::from_bytes`], which therefore costs one full `O(2^h)`
//! tree derivation once per process for each level that signs. For `H20` and
//! `H25` only the top 16 levels stay resident and the bottom subtree
//! containing the current leaf is regenerated every `2^5` / `2^10`
//! signatures; the cache never exceeds about 2.1 MiB per tree. The
//! allocator-less build (no `alloc`) has nowhere to keep such a cache and
//! derives each authentication path from the seed, i.e. an `O(2^h)` pass per
//! signature — fine for `H5`/`H10`, impractical above that.
//!
//! # Validation
//!
//! Verified against the RFC 8554 Appendix F test vectors: Test Case 1 (a
//! single LMS tree, `H5`/`W8`) and Test Case 2 (a two-level HSS key,
//! `H10`/`W4` over `H5`/`W8`). Both the public-key/root derivation and the
//! full signature bytes are reproduced from the vectors' seed material.
#![cfg_attr(
    not(feature = "alloc"),
    doc = "",
    doc = "[`LmsPrivateKey::sign`]: crate#no_std",
    doc = "[`HssPrivateKey::sign`]: crate#no_std",
    doc = "[`HssPrivateKey::to_bytes`]: crate#no_std",
    doc = "[`HssPrivateKey::from_bytes`]: crate#no_std",
    doc = "[`LmsPrivateKey::to_bytes`]: crate#no_std",
    doc = "[`HssPrivateKey::remaining`]: crate#no_std"
)]

#[cfg(feature = "key")]
mod key_impl;
mod ots;
mod params;
mod tree;

pub use params::{LmotsType, LmsType};

#[cfg(feature = "alloc")]
use crate::ct::ConstantTimeEq;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use params::N;

use crate::rng::{CryptoRng, RngCore};

/// Errors from LMS / HSS operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A key or signature had the wrong length or an unknown typecode.
    InvalidKey,
    /// The private key has signed all `2^h` (LMS) or all leaves across every
    /// level (HSS) and MUST NOT be used again.
    Exhausted,
    /// An HSS key was constructed with an out-of-range level count
    /// (`L` must be between 1 and 8 inclusive).
    InvalidLevels,
    /// Serialized key/signature bytes were malformed.
    Malformed,
    /// A legacy (pre-`v3` HSS, or root-less LMS) serialized private key
    /// encodes a tree taller than the legacy load cap (`H15`) at a level that
    /// loading must fully derive from its seed — an `O(2^h)` key-generation
    /// pass (tens of seconds to minutes for `H20`/`H25`) that an attacker
    /// could trigger as a CPU-DoS by feeding an untrusted, unauthenticated
    /// file. Re-saving such a key with this build (load it once on a host you
    /// control, then call `to_bytes`) — or regenerating it — removes the
    /// limit: the current formats are authenticated or carry every value the
    /// loader needs, so they load any height without derivation.
    LegacyKeyTooTall,
    /// A serialized private key failed its integrity check: the authentication
    /// tag of a tagged HSS format did not verify, a stored upper-level
    /// signature does not verify against the level it signs, or a stored tree
    /// root disagrees with the root that tree's own seed derives (detected when
    /// the tree is first built for signing). Each means the key file was
    /// modified after it was written, which for a multi-level key is a
    /// *forgery* vector (see [`HssPrivateKey::from_bytes`]), so the key is
    /// refused rather than used.
    #[cfg_attr(
        not(feature = "alloc"),
        doc = "",
        doc = "[`HssPrivateKey::from_bytes`]: crate#no_std"
    )]
    Tampered,
}

/// Maximum tree height that an UNAUTHENTICATED legacy private-key
/// serialization (root-less LMS; root-less or untagged HSS) may ask the loader
/// to derive from its seed.
///
/// `H15` (`2^15 = 32768` leaves) derives in well under a second on the worst
/// supported LM-OTS set and covers the common `H5`/`H10`/`H15` deployments.
/// Taller legacy trees are rejected with [`Error::LegacyKeyTooTall`] to deny a
/// CPU-DoS via an untrusted file. Authenticated (tagged) formats verify their
/// tag before any derivation and impose no height limit.
const LEGACY_RECOMPUTE_MAX_H: u32 = 15;

/// Wipes a byte buffer through [`crate::zeroize::Zeroize`]: volatile stores
/// plus a compiler fence, so the optimizer cannot elide them.
#[inline]
fn wipe(buf: &mut [u8]) {
    crate::zeroize::Zeroize::zeroize(buf);
}

// ===================================================================
// LMS — single-tree stateful key
// ===================================================================

/// Length of an encoded single-tree LMS public key:
/// `u32(lms_type) || u32(ots_type) || I(16) || T[1](N)`.
pub const PUBKEY_LEN: usize = 24 + N;

/// Length of an encoded single-tree LMS private key (including the live leaf
/// index `q` and the cached root).
pub const PRIVKEY_LEN: usize = 4 + 4 + 16 + N + 4 + N;

/// Byte length of an LMS signature for the given parameter pair.
///
/// Use this to size the buffer for
/// [`LmsPrivateKey::sign_into`](LmsPrivateKey::sign_into) on allocator-free
/// targets. Ranges from 1 KiB (`W8`/`H5`) to roughly 9 KiB (`W1`/`H25`).
pub const fn signature_len(lms: LmsType, ots: LmotsType) -> usize {
    4 + ots.sig_len() + 4 + (lms.h() as usize) * N
}

/// A single-tree LMS public (verification) key.
///
/// Wraps the wire encoding `u32(lms_type) || u32(ots_type) || I || T[1]`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LmsPublicKey {
    bytes: [u8; PUBKEY_LEN],
}

/// A single-tree LMS private (signing) key.
///
/// **Stateful** — see the [module documentation](crate::lms). The next unused
/// leaf index `q` is part of the key state and is advanced by every
/// [`sign`][Self::sign]. Re-persist [`to_bytes`][Self::to_bytes] after each
/// signature. Not [`Clone`] by design.
///
/// With `alloc`, the key carries an in-memory Merkle node cache so signing is
/// `O(h)` (see the module documentation's *Signing cost*); the cache holds
/// public hashes only and is not part of the serialization.
#[cfg_attr(
    not(feature = "alloc"),
    doc = "",
    doc = "[Self::sign]: crate#no_std",
    doc = "[Self::to_bytes]: crate#no_std"
)]
pub struct LmsPrivateKey {
    lms_type: LmsType,
    ots_type: LmotsType,
    i_id: [u8; 16],
    seed: [u8; N],
    /// Next unused leaf index.
    q: u32,
    /// Cached tree root (so signing and `public_key` need not recompute it).
    root: [u8; N],
    /// Merkle node cache; `None` after [`from_bytes`](Self::from_bytes) until
    /// the first signature builds it.
    #[cfg(feature = "alloc")]
    cache: Option<tree::NodeCache>,
}

impl LmsPrivateKey {
    /// Deterministically derives an LMS key pair from the identifier `i_id`
    /// (16 bytes) and master `seed` (32 bytes), starting at leaf `q = 0`.
    ///
    /// This is the seeded constructor used to reproduce RFC 8554 vectors; the
    /// per-leaf LM-OTS secrets are derived as in RFC 8554 Appendix A /
    /// SP 800-208 §6.2.
    pub fn from_seed(
        lms_type: LmsType,
        ots_type: LmotsType,
        i_id: &[u8; 16],
        seed: &[u8; N],
    ) -> Self {
        #[cfg(feature = "alloc")]
        let (root, cache) = {
            let cache = tree::NodeCache::build(lms_type, ots_type, i_id, seed);
            (cache.root(), Some(cache))
        };
        #[cfg(not(feature = "alloc"))]
        let root = tree::compute_root(lms_type, ots_type, i_id, seed);
        LmsPrivateKey {
            lms_type,
            ots_type,
            i_id: *i_id,
            seed: *seed,
            q: 0,
            root,
            #[cfg(feature = "alloc")]
            cache,
        }
    }

    /// Generates a fresh LMS key pair from a cryptographically secure RNG.
    pub fn generate<R: RngCore + CryptoRng>(
        lms_type: LmsType,
        ots_type: LmotsType,
        rng: &mut R,
    ) -> Self {
        let mut i_id = [0u8; 16];
        let mut seed = [0u8; N];
        rng.fill_bytes(&mut i_id);
        rng.fill_bytes(&mut seed);
        let sk = Self::from_seed(lms_type, ots_type, &i_id, &seed);
        // `seed` (with `i_id`) reconstructs every leaf's signing capability;
        // wipe both before they drop, matching the sibling modules.
        wipe(&mut seed);
        wipe(&mut i_id);
        sk
    }

    /// The LMS parameter set.
    pub fn lms_type(&self) -> LmsType {
        self.lms_type
    }

    /// The LM-OTS parameter set used for each leaf.
    pub fn ots_type(&self) -> LmotsType {
        self.ots_type
    }

    /// The matching public key.
    pub fn public_key(&self) -> LmsPublicKey {
        LmsPublicKey {
            bytes: tree::encode_public_key(self.lms_type, self.ots_type, &self.i_id, &self.root),
        }
    }

    /// The number of signatures still available before exhaustion.
    pub fn remaining(&self) -> u64 {
        self.lms_type.leaves().saturating_sub(self.q as u64)
    }

    /// True once every leaf has been consumed.
    fn is_exhausted(&self) -> bool {
        self.q as u64 >= self.lms_type.leaves()
    }

    /// Signs `message`, advancing the internal leaf index `q`.
    ///
    /// `rng` supplies the per-signature LM-OTS randomizer `C`; it SHOULD be a
    /// CSPRNG. **Persist [`to_bytes`](Self::to_bytes) before using the returned
    /// signature** — see the [module documentation](crate::lms).
    #[cfg(feature = "alloc")]
    pub fn sign<R: RngCore>(&mut self, rng: &mut R, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut c = [0u8; N];
        rng.fill_bytes(&mut c);
        self.sign_with_c(message, &c)
    }

    /// Makes leaf `q`'s authentication path available to
    /// [`sign_reserved_into`](Self::sign_reserved_into).
    ///
    /// With `alloc` this builds the node cache on first use (after a
    /// [`from_bytes`](Self::from_bytes) load) — a full `O(2^h)` derivation —
    /// and refuses with [`Error::Tampered`] if the derived root disagrees with
    /// the stored one, so a key file with a corrupted root fails closed instead
    /// of burning leaves on signatures that could never verify. It then makes
    /// sure the bottom subtree holding `q` is built. Without `alloc` there is
    /// nothing to prepare.
    ///
    /// Produces no signature material, so it runs *before* the leaf is
    /// reserved; an error here leaves the state untouched.
    fn prepare_leaf(&mut self, q: u32) -> Result<(), Error> {
        #[cfg(feature = "alloc")]
        {
            if self.cache.is_none() {
                let cache =
                    tree::NodeCache::build(self.lms_type, self.ots_type, &self.i_id, &self.seed);
                let same: bool = cache.root()[..].ct_eq(&self.root[..]).into();
                if !same {
                    return Err(Error::Tampered);
                }
                self.cache = Some(cache);
            }
            let cache = self.cache.as_mut().expect("just built");
            cache.prepare(self.lms_type, self.ots_type, &self.i_id, &self.seed, q);
        }
        #[cfg(not(feature = "alloc"))]
        let _ = q;
        Ok(())
    }

    /// Reserves the next leaf: advances `q` past it and returns it.
    ///
    /// This is the SP 800-208 §8.1 order — the index is consumed *before* any
    /// signature byte exists. If signing then aborts part-way (a panic
    /// unwinding through the caller's buffer), the state has already moved
    /// past the leaf, so no later call can re-sign a leaf whose partial
    /// signature the caller may still hold.
    fn reserve_leaf(&mut self) -> Result<u32, Error> {
        if self.is_exhausted() {
            return Err(Error::Exhausted);
        }
        let q = self.q;
        self.q += 1;
        Ok(q)
    }

    /// Signs `message` with the already-reserved leaf `q` and randomizer `c`
    /// into `out` (exactly [`signature_len`](Self::signature_len) octets).
    ///
    /// [`prepare_leaf`](Self::prepare_leaf)`(q)` must have succeeded first.
    fn sign_reserved_into(&self, q: u32, c: &[u8; N], message: &[u8], out: &mut [u8]) -> usize {
        #[cfg(feature = "alloc")]
        {
            let cache = self.cache.as_ref().expect("prepare_leaf builds the cache");
            tree::sign(
                self.lms_type,
                self.ots_type,
                &self.i_id,
                &self.seed,
                q,
                c,
                message,
                out,
                |node| cache.node(node),
            )
        }
        #[cfg(not(feature = "alloc"))]
        {
            let (lms, ots, i_id, seed) = (self.lms_type, self.ots_type, &self.i_id, &self.seed);
            tree::sign(lms, ots, i_id, seed, q, c, message, out, |node| {
                tree::node_value(lms, ots, i_id, seed, node)
            })
        }
    }

    /// Heap-allocating counterpart of [`sign_reserved_into`](Self::sign_reserved_into).
    #[cfg(feature = "alloc")]
    fn sign_reserved(&self, q: u32, c: &[u8; N], message: &[u8]) -> Vec<u8> {
        let mut out = alloc::vec![0u8; self.signature_len()];
        self.sign_reserved_into(q, c, message, &mut out);
        out
    }

    /// Signs with a caller-supplied randomizer `c` (used to reproduce the RFC
    /// 8554 vectors, which fix `C`). Advances `q`.
    fn sign_with_c_into(
        &mut self,
        message: &[u8],
        c: &[u8; N],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if self.is_exhausted() {
            return Err(Error::Exhausted);
        }
        if out.len() != self.signature_len() {
            return Err(Error::InvalidKey);
        }
        self.prepare_leaf(self.q)?;
        let q = self.reserve_leaf()?;
        Ok(self.sign_reserved_into(q, c, message, out))
    }

    /// Signs with a caller-supplied randomizer, returning a heap signature.
    #[cfg(feature = "alloc")]
    fn sign_with_c(&mut self, message: &[u8], c: &[u8; N]) -> Result<Vec<u8>, Error> {
        let mut out = alloc::vec![0u8; self.signature_len()];
        self.sign_with_c_into(message, c, &mut out)?;
        Ok(out)
    }

    /// Byte length of the signatures this key produces — the exact size the
    /// `out` buffer of [`sign_into`](Self::sign_into) must have.
    pub const fn signature_len(&self) -> usize {
        signature_len(self.lms_type, self.ots_type)
    }

    /// Signs `message` into `out` (exactly [`signature_len`](Self::signature_len)
    /// octets), advancing `q`. Allocation-free counterpart of
    /// [`sign`][Self::sign].
    ///
    /// **Persist [`to_bytes_array`](Self::to_bytes_array) before releasing the
    /// signature** — see the [module documentation](crate::lms).
    #[cfg_attr(not(feature = "alloc"), doc = "", doc = "[Self::sign]: crate#no_std")]
    pub fn sign_into<R: RngCore>(
        &mut self,
        rng: &mut R,
        message: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut c = [0u8; N];
        rng.fill_bytes(&mut c);
        self.sign_with_c_into(message, &c, out)
    }

    /// Serializes the private key **including the live leaf index `q`** and the
    /// cached public root:
    /// `u32(lms_type) || u32(ots_type) || I(16) || seed(32) || u32(q) || root(32)`
    /// (92 bytes). This embeds the state that MUST be persisted after each
    /// signature.
    ///
    /// The appended root is exactly the public key value `T[1]` (not secret);
    /// storing it lets [`from_bytes`](Self::from_bytes) load any tree height
    /// instantly instead of recomputing the root via a full `O(2^h)` keygen
    /// pass. The layout is a pure superset of the legacy 60-byte form (the root
    /// is appended at the end), so older builds' parsers are unaffected and this
    /// build still reads legacy bytes (see [`from_bytes`](Self::from_bytes)).
    /// The Merkle node cache is deliberately not serialized: it is public data
    /// the seed regenerates.
    #[cfg(feature = "alloc")]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.to_bytes_array().to_vec()
    }

    /// Allocation-free counterpart of [`to_bytes`][Self::to_bytes]: the encoding
    /// is a fixed [`PRIVKEY_LEN`] octets, so it needs no heap at all.
    ///
    /// This is the value to persist after **every** signature — see the
    /// [module documentation](crate::lms).
    #[cfg_attr(
        not(feature = "alloc"),
        doc = "",
        doc = "[Self::to_bytes]: crate#no_std"
    )]
    pub fn to_bytes_array(&self) -> [u8; PRIVKEY_LEN] {
        let mut v = [0u8; PRIVKEY_LEN];
        v[..4].copy_from_slice(&self.lms_type.typecode().to_be_bytes());
        v[4..8].copy_from_slice(&self.ots_type.typecode().to_be_bytes());
        v[8..24].copy_from_slice(&self.i_id);
        v[24..24 + N].copy_from_slice(&self.seed);
        v[24 + N..28 + N].copy_from_slice(&self.q.to_be_bytes());
        v[28 + N..].copy_from_slice(&self.root);
        v
    }

    /// Parses a private key produced by [`to_bytes`][Self::to_bytes], resuming
    /// at the persisted `q`.
    ///
    /// Length-discriminated and backward compatible:
    /// * **92 bytes** — the current root-bearing format. The stored root is
    ///   read directly (no recompute), so a key of any height loads in constant
    ///   time.
    /// * **60 bytes** — the LEGACY root-less format. The root is recomputed via
    ///   an `O(2^h)` keygen-equivalent pass; to deny a CPU-DoS from an untrusted
    ///   file this path is capped at `H15` (`LEGACY_RECOMPUTE_MAX_H`) and returns
    ///   [`Error::LegacyKeyTooTall`] above it.
    /// * any other length — [`Error::Malformed`].
    ///
    /// # The stored root is public, and checked before it matters
    ///
    /// The root is NOT secret — it is the public key value `T[1]`
    /// (`encode_public_key` = `type || type || I || T[1]`). Loading trusts it
    /// so that `from_bytes` stays constant-time. The first signature after a
    /// load rebuilds the Merkle node cache from the seed (with `alloc`) and
    /// compares the derived root with the stored one, refusing with
    /// [`Error::Tampered`] on a mismatch — before any leaf is consumed. A
    /// tampered root can therefore only cause a fail-closed self-DoS, never a
    /// forgery (the attacker lacks the seed) and never a wasted one-time key.
    /// Re-deriving the root on every load would cost a full keygen and buy
    /// nothing more: an attacker able to rewrite the key file could already
    /// force catastrophic LM-OTS reuse by rewinding `q`, which is far worse.
    #[cfg_attr(
        not(feature = "alloc"),
        doc = "",
        doc = "[Self::to_bytes]: crate#no_std"
    )]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        const LEGACY_LEN: usize = 4 + 4 + 16 + N + 4;
        const NEW_LEN: usize = LEGACY_LEN + N;
        if bytes.len() != LEGACY_LEN && bytes.len() != NEW_LEN {
            return Err(Error::Malformed);
        }
        let lms_type =
            LmsType::from_u32(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                .ok_or(Error::Malformed)?;
        let ots_type =
            LmotsType::from_u32(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
                .ok_or(Error::Malformed)?;
        let mut i_id = [0u8; 16];
        i_id.copy_from_slice(&bytes[8..24]);
        let mut seed = [0u8; N];
        seed.copy_from_slice(&bytes[24..24 + N]);
        let q = u32::from_be_bytes([bytes[24 + N], bytes[25 + N], bytes[26 + N], bytes[27 + N]]);
        if q as u64 > lms_type.leaves() {
            return Err(Error::Malformed);
        }
        let root = if bytes.len() == NEW_LEN {
            // Fast path: trust the stored public root (see method docs).
            let mut r = [0u8; N];
            r.copy_from_slice(&bytes[28 + N..28 + N + N]);
            r
        } else {
            // Legacy path: recompute the root, but refuse a CPU-DoS-sized tree.
            if lms_type.h() > LEGACY_RECOMPUTE_MAX_H {
                return Err(Error::LegacyKeyTooTall);
            }
            tree::compute_root(lms_type, ots_type, &i_id, &seed)
        };
        Ok(LmsPrivateKey {
            lms_type,
            ots_type,
            i_id,
            seed,
            q,
            root,
            #[cfg(feature = "alloc")]
            cache: None,
        })
    }
}

impl Drop for LmsPrivateKey {
    fn drop(&mut self) {
        wipe(&mut self.seed);
        wipe(&mut self.i_id);
    }
}

impl crate::zeroize::ZeroizeOnDrop for LmsPrivateKey {}

impl LmsPublicKey {
    /// The encoded public key (`u32(lms_type) || u32(ots_type) || I || T[1]`).
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parses a raw LMS public key, validating its length and typecodes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBKEY_LEN {
            return Err(Error::InvalidKey);
        }
        let lms_ok =
            LmsType::from_u32(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
                .is_some();
        let ots_ok =
            LmotsType::from_u32(u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]))
                .is_some();
        if !lms_ok || !ots_ok {
            return Err(Error::InvalidKey);
        }
        let mut b = [0u8; PUBKEY_LEN];
        b.copy_from_slice(bytes);
        Ok(LmsPublicKey { bytes: b })
    }

    /// Verifies an LMS `signature` over `message` (RFC 8554 §5.4.2).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        tree::verify(&self.bytes, message, signature)
    }
}

/// Verifies a single-tree LMS signature against a raw LMS public key.
pub fn verify_lms(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    tree::verify(public_key, message, signature)
}

// ===================================================================
// HSS — multi-level stateful key
// ===================================================================

/// Length of the integrity tag appended by [`HssPrivateKey::to_bytes`].
#[cfg(feature = "alloc")]
const HSS_TAG_LEN: usize = 32;

/// Leading magic of the current (`v3`) HSS private-key serialization. As a
/// big-endian `u32` it is far outside the `1..=8` level count that opens every
/// earlier format, so the two framings can never be confused.
#[cfg(feature = "alloc")]
const HSS_V3_MAGIC: &[u8; 4] = b"HSS3";

/// Domain separator for the `v3` HSS private-key integrity tag, so the tag can
/// never be confused with any other value derived from the same seed (the RFC
/// 8554 `derive_x` / `derive_c` / `derive_child` preimages all start with
/// `I(16) || u32(q)` and are plain SHA-256, not HMAC) nor with a `v2` tag.
#[cfg(feature = "alloc")]
const HSS_TAG_DOMAIN_V3: &[u8] = b"purecrypto/lms/hss-privkey-v3";

/// Domain separator of the `v2` tag, kept to authenticate `v2` files on load.
#[cfg(feature = "alloc")]
const HSS_TAG_DOMAIN_V2: &[u8] = b"purecrypto/lms/hss-privkey-v2";

/// Per-level block of every HSS private-key format since `v1`:
/// `u32(lms_type) || u32(ots_type) || I(16) || seed(32) || u32(q) || root(32)`.
#[cfg(feature = "alloc")]
const HSS_LEVEL_LEN: usize = 4 + 4 + 16 + N + 4 + N;

/// The root-less legacy per-level block (`HSS_LEVEL_LEN` without the root).
#[cfg(feature = "alloc")]
const HSS_LEGACY_LEVEL_LEN: usize = HSS_LEVEL_LEN - N;

/// `HMAC-SHA-256(seed0, domain || I0 || body)` — the integrity tag of a
/// serialized [`HssPrivateKey`].
///
/// The key is the **top** level's seed, deliberately: it is the only secret in
/// the file that an attacker cannot substitute, because replacing it changes the
/// top-level root and therefore the HSS public key (signatures then simply fail
/// to verify — a self-DoS, not a forgery). Every other byte of the file,
/// including each lower level's `(typecodes, I, seed, q, root)` and the cached
/// upper-level signatures, is covered by the tag, so an adversary who can write
/// the file but not read it can neither substitute a level nor rewind a leaf
/// index. An adversary who *can* read the file already holds every seed and
/// needs no attack at all, so keying the tag from in-file material loses
/// nothing.
#[cfg(feature = "alloc")]
fn hss_tag(domain: &[u8], body: &[u8], i0: &[u8; 16], seed0: &[u8; N]) -> [u8; HSS_TAG_LEN] {
    use crate::hash::{Hmac, Sha256};
    let mut m = Hmac::<Sha256>::new(seed0);
    m.update(domain);
    m.update(i0);
    m.update(body);
    m.finalize()
}

#[cfg(feature = "alloc")]
/// An HSS public (verification) key: `u32(L) || lms_public_key`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HssPublicKey {
    bytes: Vec<u8>,
}

#[cfg(feature = "alloc")]
/// A multi-level HSS private (signing) key (RFC 8554 §6).
///
/// **Stateful** — see the [module documentation](crate::lms). Every
/// [`sign`](Self::sign) advances the bottom level's leaf index and, when that
/// level's tree is used up, replaces it (see below); re-persist
/// [`to_bytes`](Self::to_bytes) afterwards. Not [`Clone`] by design.
///
/// # Structure
///
/// Each of the `L` levels owns a live [`LmsPrivateKey`] with its own leaf
/// index `q_i`. Level `i` (`i < L - 1`) does not sign messages: each of its
/// leaves signs the public key of one tree at level `i + 1`. The signature
/// over the *current* child tree is produced once and cached in the key (and
/// in its serialization), so a message signature costs exactly one bottom-level
/// LMS signature plus copying the `L - 1` cached upper-level signatures.
///
/// When the bottom tree is exhausted, the next signature first replaces it: a
/// fresh tree is derived from the parent's next leaf (`(I, SEED)` per the RFC
/// 8554 reference implementation's child derivation, see `ots::derive_child`),
/// that leaf signs the new public key (advancing the parent's `q`), and
/// signing continues in the new tree. Exhausted parents are replaced the same
/// way from their own parents, so the key issues `prod_i 2^h_i` signatures
/// and reports [`Error::Exhausted`] only once the top tree has no leaf left.
/// Replacing a tree costs one key generation of that height (`O(2^h)`); it
/// happens once per `2^h_bottom` signatures for the bottom level and
/// correspondingly rarer above.
///
/// No one-time key is ever used twice: leaves are reserved before they sign,
/// every parent leaf signs exactly one child tree, and because child keys are
/// derived deterministically a replacement interrupted before the state was
/// persisted re-derives and re-signs the *same* child when retried.
pub struct HssPrivateKey {
    /// Live LMS key of each level, top level first.
    levels: Vec<LmsPrivateKey>,
    /// `signed_pubs[i]` is the LMS signature by level `i` over
    /// `levels[i + 1].public_key()` (`L - 1` entries).
    signed_pubs: Vec<Vec<u8>>,
}

#[cfg(feature = "alloc")]
impl HssPrivateKey {
    /// Builds an HSS key from a fixed `(lms_type, ots_type, I, seed)` per level
    /// (top level first). `L = levels.len()` must be 1..=8.
    ///
    /// Each non-bottom level signs the level below with its leaf `0`, so the
    /// returned key has `q = 1` at every level but the bottom. Trees that are
    /// generated later, when one of these initial trees is exhausted, derive
    /// their `(I, seed)` from the parent (see the type documentation).
    ///
    /// This is the seeded constructor used to reproduce RFC 8554 Test Case 2.
    pub fn from_levels(levels: &[(LmsType, LmotsType, [u8; 16], [u8; N])]) -> Result<Self, Error> {
        let l = levels.len();
        if !(1..=8).contains(&l) {
            return Err(Error::InvalidLevels);
        }
        let mut lv: Vec<LmsPrivateKey> = Vec::with_capacity(l);
        for &(lms_type, ots_type, i_id, seed) in levels {
            lv.push(LmsPrivateKey::from_seed(lms_type, ots_type, &i_id, &seed));
        }
        let mut signed_pubs = Vec::with_capacity(l - 1);
        for i in 0..l - 1 {
            let (upper, lower) = lv.split_at_mut(i + 1);
            signed_pubs.push(Self::sign_child(&mut upper[i], &lower[0])?);
        }
        Ok(HssPrivateKey {
            levels: lv,
            signed_pubs,
        })
    }

    /// Generates a fresh `L`-level HSS key from a CSPRNG, using `params[i]` as
    /// the `(lms_type, ots_type)` for level `i` (top level first).
    ///
    /// The top level's `(I, seed)` come from `rng`; every lower level's initial
    /// tree is derived from its parent's leaf `0` exactly as later replacement
    /// trees are derived from later leaves, so the whole hierarchy is a
    /// function of the top-level secret.
    pub fn generate<R: RngCore + CryptoRng>(
        params: &[(LmsType, LmotsType)],
        rng: &mut R,
    ) -> Result<Self, Error> {
        let l = params.len();
        if !(1..=8).contains(&l) {
            return Err(Error::InvalidLevels);
        }
        let mut levels = Vec::with_capacity(l);
        let mut i_id = [0u8; 16];
        let mut seed = [0u8; N];
        rng.fill_bytes(&mut i_id);
        rng.fill_bytes(&mut seed);
        for &(lms_type, ots_type) in params {
            levels.push((lms_type, ots_type, i_id, seed));
            (i_id, seed) = ots::derive_child(&i_id, &seed, 0);
        }
        wipe(&mut i_id);
        wipe(&mut seed);
        let sk = Self::from_levels(&levels);
        // `from_levels` has copied every level's `(i_id, seed)`; wipe the master
        // seeds left in the heap `Vec` before it frees — each reconstructs that
        // level's signing capability. (`wipe` uses volatile stores, so the
        // writes survive the imminent drop.)
        for lvl in levels.iter_mut() {
            wipe(&mut lvl.2);
            wipe(&mut lvl.3);
        }
        sk
    }

    /// Signs `child`'s public key with `parent`'s next leaf (reserved first),
    /// using the deterministic randomizer, and returns the LMS signature.
    fn sign_child(parent: &mut LmsPrivateKey, child: &LmsPrivateKey) -> Result<Vec<u8>, Error> {
        let pk = child.public_key();
        parent.prepare_leaf(parent.q)?;
        let q = parent.reserve_leaf()?;
        let c = ots::derive_c(&parent.i_id, &parent.seed, q, pk.to_bytes());
        Ok(parent.sign_reserved(q, &c, pk.to_bytes()))
    }

    /// The number of levels `L`.
    pub fn levels(&self) -> usize {
        self.levels.len()
    }

    /// The matching HSS public key: `u32(L) || pub[0]`.
    pub fn public_key(&self) -> HssPublicKey {
        let pub0 = self.levels[0].public_key();
        let mut bytes = Vec::with_capacity(4 + pub0.to_bytes().len());
        bytes.extend_from_slice(&(self.levels.len() as u32).to_be_bytes());
        bytes.extend_from_slice(pub0.to_bytes());
        HssPublicKey { bytes }
    }

    /// Byte length of the signatures this key produces:
    /// `u32(Nspk)`, then for each level its LMS signature, interleaved with the
    /// `L - 1` signed child public keys (RFC 8554 §6.2). Constant for a given
    /// parameter configuration, so callers can size buffers before signing.
    pub fn signature_len(&self) -> usize {
        let l = self.levels.len();
        4 + self
            .levels
            .iter()
            .map(|lv| lv.signature_len())
            .sum::<usize>()
            + (l - 1) * PUBKEY_LEN
    }

    /// Total signatures still available before the whole key is exhausted,
    /// saturating at `u64::MAX`.
    ///
    /// Every unused leaf of level `i` is worth `prod_{j > i} 2^h_j` message
    /// signatures (one whole subtree of fresh lower trees), so this is the
    /// mixed-radix sum over the levels of `unused_leaves_i * prod_{j > i} 2^h_j`.
    /// A fresh key reports `prod_i 2^h_i`.
    pub fn remaining(&self) -> u64 {
        let mut total: u64 = 0;
        let mut per_leaf: u64 = 1;
        for lv in self.levels.iter().rev() {
            total = total.saturating_add(lv.remaining().saturating_mul(per_leaf));
            per_leaf = per_leaf.saturating_mul(lv.lms_type.leaves());
        }
        total
    }

    /// Replaces every exhausted tree below the lowest level that still has a
    /// leaf (RFC 8554 §6.2 step "if the bottom tree is exhausted").
    ///
    /// Walking down from that level, each replacement reserves the parent's
    /// next leaf, derives the child `(I, seed)` from it, generates the child
    /// tree (`O(2^h)`), and caches the parent's signature over the new public
    /// key. Returns [`Error::Exhausted`] if even the top tree has no leaf left.
    fn replace_exhausted(&mut self) -> Result<(), Error> {
        let l = self.levels.len();
        let mut live = l - 1;
        while self.levels[live].is_exhausted() {
            if live == 0 {
                return Err(Error::Exhausted);
            }
            live -= 1;
        }
        for j in live + 1..l {
            let child = {
                let (upper, lower) = self.levels.split_at_mut(j);
                let parent = &mut upper[j - 1];
                let old = &lower[0];
                parent.prepare_leaf(parent.q)?;
                let q = parent.reserve_leaf()?;
                let (mut ci, mut cs) = ots::derive_child(&parent.i_id, &parent.seed, q);
                let child = LmsPrivateKey::from_seed(old.lms_type, old.ots_type, &ci, &cs);
                wipe(&mut ci);
                wipe(&mut cs);
                let pk = child.public_key();
                let c = ots::derive_c(&parent.i_id, &parent.seed, q, pk.to_bytes());
                self.signed_pubs[j - 1] = parent.sign_reserved(q, &c, pk.to_bytes());
                child
            };
            // The exhausted tree is dropped here, wiping its seed.
            self.levels[j] = child;
        }
        Ok(())
    }

    /// Signs `message` (RFC 8554 §6.2). Advances the internal state.
    ///
    /// `rng` supplies the bottom level's LM-OTS randomizer `C`; it SHOULD be a
    /// CSPRNG. If the bottom tree is exhausted it is replaced first (see the
    /// type documentation), which costs a key generation of the bottom height.
    /// **Persist [`to_bytes`](Self::to_bytes) before using the returned
    /// signature** — see the [module documentation](crate::lms).
    pub fn sign<R: RngCore>(&mut self, rng: &mut R, message: &[u8]) -> Result<Vec<u8>, Error> {
        if self.remaining() == 0 {
            return Err(Error::Exhausted);
        }
        self.replace_exhausted()?;
        let l = self.levels.len();
        let bottom = &mut self.levels[l - 1];
        bottom.prepare_leaf(bottom.q)?;
        // Reserve the bottom leaf BEFORE any signature byte exists and BEFORE
        // touching the caller's RNG (SP 800-208 §8.1): an abort part-way
        // through signing can never be followed by a second signature on the
        // same one-time key.
        let q = bottom.reserve_leaf()?;
        let mut c = [0u8; N];
        rng.fill_bytes(&mut c);
        Ok(self.assemble(q, &c, message))
    }

    /// Assembles `u32(Nspk) || sig[0] || pub[1] || ... || sig[L-1]` for the
    /// already-reserved bottom leaf `q` and randomizer `c`.
    fn assemble(&self, q: u32, c: &[u8; N], message: &[u8]) -> Vec<u8> {
        let l = self.levels.len();
        let mut out = Vec::with_capacity(self.signature_len());
        out.extend_from_slice(&((l - 1) as u32).to_be_bytes());
        for i in 0..l - 1 {
            out.extend_from_slice(&self.signed_pubs[i]);
            out.extend_from_slice(self.levels[i + 1].public_key().to_bytes());
        }
        out.extend_from_slice(&self.levels[l - 1].sign_reserved(q, c, message));
        out
    }

    /// Test hook: moves level `i` to leaf `q` (the vectors pin the leaf indices).
    #[cfg(test)]
    fn set_q(&mut self, i: usize, q: u32) {
        self.levels[i].q = q;
    }

    /// Test hook: re-signs level `i + 1`'s public key with level `i`'s next
    /// leaf and the caller-supplied randomizer `c` (the vectors pin `C`).
    #[cfg(test)]
    fn resign_child_with_c(&mut self, i: usize, c: &[u8; N]) {
        let pk = self.levels[i + 1].public_key();
        let parent = &mut self.levels[i];
        parent.prepare_leaf(parent.q).unwrap();
        let q = parent.reserve_leaf().unwrap();
        self.signed_pubs[i] = parent.sign_reserved(q, c, pk.to_bytes());
    }

    /// Like [`sign`](Self::sign) but with a caller-supplied bottom-level
    /// randomizer (used to reproduce the RFC 8554 vectors). Advances state.
    #[cfg(test)]
    fn sign_with_c(&mut self, message: &[u8], c: &[u8; N]) -> Result<Vec<u8>, Error> {
        if self.remaining() == 0 {
            return Err(Error::Exhausted);
        }
        self.replace_exhausted()?;
        let l = self.levels.len();
        let bottom = &mut self.levels[l - 1];
        bottom.prepare_leaf(bottom.q)?;
        let q = bottom.reserve_leaf()?;
        Ok(self.assemble(q, c, message))
    }

    /// Serializes the private key **including every level's live leaf index**,
    /// each level's cached public root, the cached upper-level signatures, and
    /// a trailing integrity tag.
    ///
    /// Layout (`v3`): `"HSS3" || u32(L) || for each level { u32(lms_type) ||
    /// u32(ots_type) || I(16) || seed(32) || u32(q) || root(32) } || for each
    /// level but the last { sig_i } || tag(32)`, where `sig_i` is level `i`'s
    /// LMS signature over level `i + 1`'s public key (its length follows from
    /// level `i`'s parameter sets). This embeds the full state that MUST be
    /// persisted after each signature; loading it never derives a tree, so a
    /// key of any height loads instantly and only the first signature of a
    /// level pays that level's cache build.
    ///
    /// # The tag (and why it is not optional)
    ///
    /// `tag` is `HMAC-SHA-256` over every preceding byte, keyed by the **top
    /// level's secret seed** — the one piece of the file an attacker cannot
    /// replace without also invalidating the public key. It stops an adversary
    /// who can *write* the key file (but not read it) from rewinding a leaf
    /// index or substituting a level; see [`from_bytes`](Self::from_bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let l = self.levels.len();
        let sigs: usize = self.signed_pubs.iter().map(Vec::len).sum();
        let mut v = Vec::with_capacity(8 + l * HSS_LEVEL_LEN + sigs + HSS_TAG_LEN);
        v.extend_from_slice(HSS_V3_MAGIC);
        v.extend_from_slice(&(l as u32).to_be_bytes());
        for lv in &self.levels {
            v.extend_from_slice(&lv.to_bytes_array());
        }
        for sig in &self.signed_pubs {
            v.extend_from_slice(sig);
        }
        let top = &self.levels[0];
        let tag = hss_tag(HSS_TAG_DOMAIN_V3, &v, &top.i_id, &top.seed);
        v.extend_from_slice(&tag);
        v
    }

    /// Parses a private key produced by [`to_bytes`](Self::to_bytes), resuming
    /// at each persisted per-level `q`.
    ///
    /// Format-discriminated and backward compatible:
    /// * **`v3`** (`"HSS3"` magic) — the current format. The trailing tag is
    ///   verified first (against the top level's seed); a modified file is
    ///   rejected with [`Error::Tampered`]. Every cached upper-level signature
    ///   is then verified against the levels it links and must use a leaf
    ///   below that level's `q` (i.e. one already reserved). No tree is
    ///   derived, so a key of any height loads in `O(L)` signature checks.
    /// * **`v2`** (`4 + L*92 + 32` bytes, tagged) — the previous format, in
    ///   which every non-bottom level was pinned at leaf `0` and re-signed its
    ///   fixed child on every call. It is mapped onto the current structure:
    ///   each non-bottom level's child signature — leaf `0`, deterministic
    ///   randomizer, exactly the bytes the previous format emitted, so no
    ///   one-time key is exposed twice — is produced now and that level's `q`
    ///   becomes `1`. Producing it builds each non-bottom level's tree
    ///   (`O(2^h)`); the tag is verified beforehand so this cannot be
    ///   triggered by an untrusted file, and no height cap applies.
    /// * **`v1`** (`4 + L*92`, untagged root-bearing) and **legacy**
    ///   (`4 + L*60`, root-less) — mapped like `v2`, but with no tag to check
    ///   every level that loading must derive (all non-bottom levels; every
    ///   level of a root-less file; every non-top level of a `v1` file, whose
    ///   stored root is recomputed and compared) is capped at `H15`
    ///   (`LEGACY_RECOMPUTE_MAX_H`) and rejected with
    ///   [`Error::LegacyKeyTooTall`] above it, to deny a CPU-DoS from an
    ///   untrusted file. A non-bottom `q != 0` in these formats is
    ///   [`Error::Malformed`]: they never produced one, and resuming it would
    ///   pin a leaf that may already have signed something else.
    /// * anything else — [`Error::Malformed`].
    ///
    /// Re-save any key loaded from an older format: `to_bytes` always emits
    /// `v3`, which loads instantly and is the only form that carries the
    /// cached upper-level signatures.
    ///
    /// # Why the stored state must be authenticated
    ///
    /// The upper-level signatures and the child public keys they cover are
    /// public, and the current design signs each child exactly once, so a
    /// flipped child byte can no longer make a parent leaf sign twice as it
    /// could in `v2`. The tag still matters, for two reasons that no
    /// per-field check can replace:
    ///
    /// 1. **Index rewind.** Every `q` in the file is one-time-key state. An
    ///    adversary who can write the file could decrement any of them, and
    ///    the next signature would re-use a leaf. Only a tag keyed by a secret
    ///    the adversary does not have makes such an edit detectable.
    /// 2. **Level substitution.** Replacing a lower level with one whose seed
    ///    the adversary holds would, in the older formats, be *signed* by the
    ///    parent on load; with `v3` the stored parent signature would not
    ///    verify — but only because the tag also prevents the adversary from
    ///    supplying a fresh, self-consistent state of their own.
    ///
    /// No tag can stop a *wholesale rollback* to an older file that this code
    /// genuinely wrote (its indices would replay used leaves); preventing that
    /// is the storage layer's job and inherent to every stateful scheme.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() >= 4 && &bytes[..4] == HSS_V3_MAGIC {
            return Self::from_bytes_v3(bytes);
        }
        Self::from_bytes_legacy(bytes)
    }

    /// Parses the `u32(L)` level count that opens every format.
    fn parse_level_count(bytes: &[u8]) -> Result<usize, Error> {
        if bytes.len() < 4 {
            return Err(Error::Malformed);
        }
        let l = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if !(1..=8).contains(&l) {
            return Err(Error::Malformed);
        }
        Ok(l)
    }

    /// Parses one `(lms_type, ots_type, I, seed, q, root?)` level block,
    /// validating the typecodes and `q <= 2^h`.
    #[allow(clippy::type_complexity)]
    fn parse_level(
        block: &[u8],
        has_root: bool,
    ) -> Result<(LmsType, LmotsType, [u8; 16], [u8; N], u32, Option<[u8; N]>), Error> {
        let lms_type =
            LmsType::from_u32(u32::from_be_bytes([block[0], block[1], block[2], block[3]]))
                .ok_or(Error::Malformed)?;
        let ots_type =
            LmotsType::from_u32(u32::from_be_bytes([block[4], block[5], block[6], block[7]]))
                .ok_or(Error::Malformed)?;
        let mut i_id = [0u8; 16];
        i_id.copy_from_slice(&block[8..24]);
        let mut seed = [0u8; N];
        seed.copy_from_slice(&block[24..24 + N]);
        let q = u32::from_be_bytes([block[24 + N], block[25 + N], block[26 + N], block[27 + N]]);
        if q as u64 > lms_type.leaves() {
            return Err(Error::Malformed);
        }
        let root = has_root.then(|| {
            let mut r = [0u8; N];
            r.copy_from_slice(&block[28 + N..28 + N + N]);
            r
        });
        Ok((lms_type, ots_type, i_id, seed, q, root))
    }

    /// Verifies a serialized tag against the body it covers, keyed by the top
    /// level's `(I, seed)` found at the given body offset.
    fn check_tag(domain: &[u8], body: &[u8], tag: &[u8], top_block: usize) -> Result<(), Error> {
        let mut i0 = [0u8; 16];
        i0.copy_from_slice(&body[top_block + 8..top_block + 24]);
        let mut seed0 = [0u8; N];
        seed0.copy_from_slice(&body[top_block + 24..top_block + 24 + N]);
        let want = hss_tag(domain, body, &i0, &seed0);
        wipe(&mut seed0);
        let ok: bool = want[..].ct_eq(tag).into();
        if ok { Ok(()) } else { Err(Error::Tampered) }
    }

    /// The `v3` loader — see [`from_bytes`](Self::from_bytes).
    fn from_bytes_v3(bytes: &[u8]) -> Result<Self, Error> {
        let l = Self::parse_level_count(&bytes[4..])?;
        let levels_end = 8 + l * HSS_LEVEL_LEN;
        if bytes.len() < levels_end + HSS_TAG_LEN {
            return Err(Error::Malformed);
        }
        // Parse the level blocks first: the signature lengths that follow
        // depend on their parameter sets. Nothing here derives a tree.
        let mut levels = Vec::with_capacity(l);
        for i in 0..l {
            let off = 8 + i * HSS_LEVEL_LEN;
            let (lms_type, ots_type, i_id, seed, q, root) =
                Self::parse_level(&bytes[off..off + HSS_LEVEL_LEN], true)?;
            levels.push(LmsPrivateKey {
                lms_type,
                ots_type,
                i_id,
                seed,
                q,
                root: root.expect("v3 blocks carry the root"),
                cache: None,
            });
        }
        let sigs_len: usize = levels[..l - 1].iter().map(|lv| lv.signature_len()).sum();
        if bytes.len() != levels_end + sigs_len + HSS_TAG_LEN {
            return Err(Error::Malformed);
        }
        // Authenticate the whole body before trusting any of it.
        let body = &bytes[..bytes.len() - HSS_TAG_LEN];
        Self::check_tag(HSS_TAG_DOMAIN_V3, body, &bytes[body.len()..], 8)?;

        // The cached upper-level signatures must each verify under the level
        // that produced them, over the public key of the level below, and
        // must use a leaf that level has already reserved (`q_sig < q_i`).
        let mut signed_pubs = Vec::with_capacity(l - 1);
        let mut off = levels_end;
        for i in 0..l - 1 {
            let sig = &bytes[off..off + levels[i].signature_len()];
            off += sig.len();
            let parent_pk = levels[i].public_key();
            let child_pk = levels[i + 1].public_key();
            if !tree::verify(parent_pk.to_bytes(), child_pk.to_bytes(), sig) {
                return Err(Error::Tampered);
            }
            let sig_q = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]);
            if sig_q >= levels[i].q {
                return Err(Error::Tampered);
            }
            signed_pubs.push(sig.to_vec());
        }
        Ok(HssPrivateKey {
            levels,
            signed_pubs,
        })
    }

    /// The `v2` / `v1` / legacy loader — see [`from_bytes`](Self::from_bytes).
    fn from_bytes_legacy(bytes: &[u8]) -> Result<Self, Error> {
        let l = Self::parse_level_count(bytes)?;
        let (per, has_root, tagged) = if bytes.len() == 4 + l * HSS_LEVEL_LEN + HSS_TAG_LEN {
            (HSS_LEVEL_LEN, true, true)
        } else if bytes.len() == 4 + l * HSS_LEVEL_LEN {
            (HSS_LEVEL_LEN, true, false)
        } else if bytes.len() == 4 + l * HSS_LEGACY_LEVEL_LEN {
            (HSS_LEGACY_LEVEL_LEN, false, false)
        } else {
            return Err(Error::Malformed);
        };
        let body = &bytes[..bytes.len() - if tagged { HSS_TAG_LEN } else { 0 }];
        if tagged {
            Self::check_tag(HSS_TAG_DOMAIN_V2, body, &bytes[body.len()..], 4)?;
        }
        let mut levels = Vec::with_capacity(l);
        for level in 0..l {
            let off = 4 + level * per;
            let (lms_type, ots_type, i_id, seed, q, root) =
                Self::parse_level(&body[off..off + per], has_root)?;
            let is_bottom = level + 1 == l;
            // Pre-v3 formats never advanced a non-bottom level. A non-zero
            // index there can only come from a pre-mitigation key that has
            // already wrapped into one-time-key reuse, or from tampering.
            if !is_bottom && q != 0 {
                return Err(Error::Malformed);
            }
            // Which levels must loading derive from the seed? Non-bottom
            // levels, to produce their child signature; root-less levels, to
            // recover the root; and non-top levels of an untagged file, whose
            // stored root is the message the parent signs and so must be
            // checked against the seed. Without a tag to vouch for the file,
            // each such derivation is capped to deny a CPU-DoS.
            let derives = !is_bottom || root.is_none() || (!tagged && level > 0);
            if !tagged && derives && lms_type.h() > LEGACY_RECOMPUTE_MAX_H {
                return Err(Error::LegacyKeyTooTall);
            }
            let key = match root {
                Some(r) if tagged || level == 0 => LmsPrivateKey {
                    lms_type,
                    ots_type,
                    i_id,
                    seed,
                    q,
                    root: r,
                    cache: None,
                },
                Some(r) => {
                    // Untagged non-top level: derive and compare the root.
                    let mut key = LmsPrivateKey::from_seed(lms_type, ots_type, &i_id, &seed);
                    let same: bool = key.root[..].ct_eq(&r[..]).into();
                    if !same {
                        return Err(Error::Tampered);
                    }
                    key.q = q;
                    key
                }
                None => {
                    let mut key = LmsPrivateKey::from_seed(lms_type, ots_type, &i_id, &seed);
                    key.q = q;
                    key
                }
            };
            levels.push(key);
        }
        // Map onto the current structure: every non-bottom level signs its
        // child with leaf 0 and the deterministic randomizer — byte-identical
        // to what the older format emitted on every call — and moves to q = 1.
        // (`prepare_leaf` inside `sign_child` builds any level not derived
        // above and refuses a stored root the seed does not reproduce.)
        let mut signed_pubs = Vec::with_capacity(l - 1);
        for i in 0..l - 1 {
            let (upper, lower) = levels.split_at_mut(i + 1);
            signed_pubs.push(Self::sign_child(&mut upper[i], &lower[0])?);
        }
        Ok(HssPrivateKey {
            levels,
            signed_pubs,
        })
    }
}

#[cfg(feature = "alloc")]
impl HssPublicKey {
    /// The encoded public key (`u32(L) || lms_public_key`).
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parses a raw HSS public key.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 4 + 24 + N {
            return Err(Error::InvalidKey);
        }
        let l = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if !(1..=8).contains(&l) {
            return Err(Error::InvalidKey);
        }
        LmsPublicKey::from_bytes(&bytes[4..])?;
        Ok(HssPublicKey {
            bytes: bytes.to_vec(),
        })
    }

    /// Verifies an HSS `signature` over `message` (RFC 8554 §6.3).
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        verify_hss(&self.bytes, message, signature)
    }
}

#[cfg(feature = "alloc")]
/// Verifies an HSS signature against a raw HSS public key (RFC 8554 §6.3).
pub fn verify_hss(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    if public_key.len() != 4 + 24 + N || signature.len() < 4 {
        return false;
    }
    let levels = u32::from_be_bytes([public_key[0], public_key[1], public_key[2], public_key[3]]);
    // RFC 8554 §6: 1 <= L <= 8 (same bound `HssPublicKey::from_bytes`
    // enforces) — reject out-of-range level counts from raw key bytes too.
    if !(1..=8).contains(&levels) {
        return false;
    }
    let nspk = u32::from_be_bytes([signature[0], signature[1], signature[2], signature[3]]);
    if nspk.checked_add(1) != Some(levels) {
        return false;
    }
    let nspk = nspk as usize;

    // key starts as the top LMS public key (everything after the u32(L)).
    let mut key: Vec<u8> = public_key[4..].to_vec();
    let mut off = 4usize;

    for _ in 0..nspk {
        let sig_len = match lms_sig_len(&signature[off..]) {
            Some(n) => n,
            None => return false,
        };
        if off + sig_len > signature.len() {
            return false;
        }
        let sig = &signature[off..off + sig_len];
        off += sig_len;

        // The signed message is the next LMS public key (24 + N bytes).
        if off + 24 + N > signature.len() {
            return false;
        }
        let next_pub = &signature[off..off + 24 + N];
        off += 24 + N;

        if !tree::verify(&key, next_pub, sig) {
            return false;
        }
        key = next_pub.to_vec();
    }

    // Final signature over the message.
    let sig_len = match lms_sig_len(&signature[off..]) {
        Some(n) => n,
        None => return false,
    };
    if off + sig_len != signature.len() {
        return false;
    }
    tree::verify(&key, message, &signature[off..off + sig_len])
}

#[cfg(feature = "alloc")]
/// Returns the byte length of the LMS signature that prefixes `buf`, parsing
/// just enough of it to determine the length, or `None` if malformed.
fn lms_sig_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < 8 {
        return None;
    }
    let otssigtype = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let ots_type = LmotsType::from_u32(otssigtype)?;
    let ots_len = ots_type.sig_len();
    let lms_type_off = 4 + ots_len;
    if buf.len() < lms_type_off + 4 {
        return None;
    }
    let sigtype = u32::from_be_bytes([
        buf[lms_type_off],
        buf[lms_type_off + 1],
        buf[lms_type_off + 2],
        buf[lms_type_off + 3],
    ]);
    let lms_type = LmsType::from_u32(sigtype)?;
    Some(4 + ots_len + 4 + lms_type.h() as usize * N)
}

// The RFC 8554 vector suite drives the `Vec`-returning APIs and the HSS layer,
// both of which need `alloc`; `nobuf_tests` covers the allocator-free path.
#[cfg(all(test, feature = "alloc"))]
mod tests;

#[cfg(test)]
mod nobuf_tests {
    use super::*;
    use crate::rng::HmacDrbg;

    fn drbg(tag: &[u8]) -> HmacDrbg<crate::hash::Sha256> {
        HmacDrbg::<crate::hash::Sha256>::new(tag, b"nonce", &[])
    }

    /// Signing into a caller buffer and verifying, with no allocator in play.
    #[test]
    fn sign_into_verify_roundtrip_no_alloc() {
        let mut rng = drbg(b"lms-nobuf");
        let mut sk =
            LmsPrivateKey::generate(LmsType::Sha256M32H5, LmotsType::Sha256N32W8, &mut rng);
        let pk = sk.public_key();

        let mut sig = [0u8; 1292];
        let n = sk.signature_len();
        assert_eq!(
            n,
            signature_len(LmsType::Sha256M32H5, LmotsType::Sha256N32W8)
        );
        let written = sk
            .sign_into(&mut rng, b"firmware image", &mut sig[..n])
            .expect("sign");
        assert_eq!(written, n);

        assert!(pk.verify(b"firmware image", &sig[..n]));
        assert!(!pk.verify(b"other image", &sig[..n]));
        assert!(verify_lms(pk.to_bytes(), b"firmware image", &sig[..n]));
    }

    /// The fixed-size private-key encoding round-trips and carries the live
    /// leaf index, which is the whole point of persisting it.
    #[test]
    fn privkey_array_roundtrip_carries_q_no_alloc() {
        let mut rng = drbg(b"lms-state");
        let mut sk =
            LmsPrivateKey::generate(LmsType::Sha256M32H5, LmotsType::Sha256N32W8, &mut rng);
        let before = sk.remaining();
        let mut sig = [0u8; 1292];
        let n = sk.signature_len();
        sk.sign_into(&mut rng, b"m", &mut sig[..n]).expect("sign");
        assert_eq!(sk.remaining(), before - 1);

        let enc = sk.to_bytes_array();
        assert_eq!(enc.len(), PRIVKEY_LEN);
        let restored = LmsPrivateKey::from_bytes(&enc).expect("reload");
        assert_eq!(restored.remaining(), sk.remaining());
        assert_eq!(restored.public_key().to_bytes(), sk.public_key().to_bytes());
    }

    /// A wrong-size output buffer is rejected rather than silently truncating.
    #[test]
    fn sign_into_rejects_wrong_buffer_len() {
        let mut rng = drbg(b"lms-len");
        let mut sk =
            LmsPrivateKey::generate(LmsType::Sha256M32H5, LmotsType::Sha256N32W8, &mut rng);
        let mut short = [0u8; 16];
        assert!(sk.sign_into(&mut rng, b"m", &mut short).is_err());
    }
}
