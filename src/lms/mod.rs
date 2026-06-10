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
//! # Validation
//!
//! Verified against the RFC 8554 Appendix F test vectors: Test Case 1 (a
//! single LMS tree, `H5`/`W8`) and Test Case 2 (a two-level HSS key,
//! `H10`/`W4` over `H5`/`W8`). Both the public-key/root derivation and the
//! full signature bytes are reproduced from the vectors' seed material.

mod ots;
mod params;
mod tree;

pub use params::{LmotsType, LmsType};

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
    /// A legacy (pre-root-bearing) serialized private key encodes a tree taller
    /// than the legacy recompute cap (`H15`). Loading it would require
    /// recomputing the Merkle root from the seed — an `O(2^h)` full-keygen pass
    /// (tens of seconds to minutes for `H20`/`H25`) that an attacker could
    /// trigger as a CPU-DoS by feeding an untrusted file. The current
    /// serialization stores the public root, so re-saving such a key with this
    /// build (load it once on a host you control, then call `to_bytes`) — or
    /// regenerating it — removes the limit; the new format loads any height
    /// instantly.
    LegacyKeyTooTall,
}

/// Maximum tree height for which the LEGACY (root-less, 60-byte / `4 + L*60`)
/// private-key serialization will recompute the Merkle root on load.
///
/// `H15` (`2^15 = 32768` leaves) recomputes in well under a second on the worst
/// supported LM-OTS set and covers the common `H5`/`H10`/`H15` deployments.
/// Taller legacy keys are rejected with [`Error::LegacyKeyTooTall`] to deny a
/// CPU-DoS via an untrusted file. The NEW (root-bearing) format carries the
/// public root and imposes no height limit.
const LEGACY_RECOMPUTE_MAX_H: u32 = 15;

/// Wipes a byte buffer in a way the optimizer cannot elide.
fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(&buf);
}

// ===================================================================
// LMS — single-tree stateful key
// ===================================================================

/// A single-tree LMS public (verification) key.
///
/// Wraps the wire encoding `u32(lms_type) || u32(ots_type) || I || T[1]`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct LmsPublicKey {
    bytes: Vec<u8>,
}

/// A single-tree LMS private (signing) key.
///
/// **Stateful** — see the [module documentation](crate::lms). The next unused
/// leaf index `q` is part of the key state and is advanced by every
/// [`sign`](Self::sign). Re-persist [`to_bytes`](Self::to_bytes) after each
/// signature. Not [`Clone`] by design.
pub struct LmsPrivateKey {
    lms_type: LmsType,
    ots_type: LmotsType,
    i_id: [u8; 16],
    seed: [u8; N],
    /// Next unused leaf index.
    q: u32,
    /// Cached tree root (so signing and `public_key` need not recompute it).
    root: [u8; N],
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
        let root = tree::compute_root(lms_type, ots_type, i_id, seed);
        LmsPrivateKey {
            lms_type,
            ots_type,
            i_id: *i_id,
            seed: *seed,
            q: 0,
            root,
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
        Self::from_seed(lms_type, ots_type, &i_id, &seed)
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

    /// Signs `message`, advancing the internal leaf index `q`.
    ///
    /// `rng` supplies the per-signature LM-OTS randomizer `C`; it SHOULD be a
    /// CSPRNG. **Persist [`to_bytes`](Self::to_bytes) before using the returned
    /// signature** — see the [module documentation](crate::lms).
    pub fn sign<R: RngCore>(&mut self, rng: &mut R, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut c = [0u8; N];
        rng.fill_bytes(&mut c);
        self.sign_with_c(message, &c)
    }

    /// Signs with a caller-supplied randomizer `c` (used to reproduce the RFC
    /// 8554 vectors, which fix `C`). Advances `q`.
    fn sign_with_c(&mut self, message: &[u8], c: &[u8; N]) -> Result<Vec<u8>, Error> {
        if self.q as u64 >= self.lms_type.leaves() {
            return Err(Error::Exhausted);
        }
        let sig = tree::sign(
            self.lms_type,
            self.ots_type,
            &self.i_id,
            &self.seed,
            self.q,
            c,
            message,
        );
        self.q += 1;
        Ok(sig)
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
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(4 + 4 + 16 + N + 4 + N);
        v.extend_from_slice(&self.lms_type.typecode().to_be_bytes());
        v.extend_from_slice(&self.ots_type.typecode().to_be_bytes());
        v.extend_from_slice(&self.i_id);
        v.extend_from_slice(&self.seed);
        v.extend_from_slice(&self.q.to_be_bytes());
        v.extend_from_slice(&self.root);
        v
    }

    /// Parses a private key produced by [`to_bytes`](Self::to_bytes), resuming
    /// at the persisted `q`.
    ///
    /// Length-discriminated and backward compatible:
    /// * **92 bytes** — the current root-bearing format. The stored root is
    ///   read directly and **trusted** (no recompute), so a key of any height
    ///   loads in constant time.
    /// * **60 bytes** — the LEGACY root-less format. The root is recomputed via
    ///   an `O(2^h)` keygen-equivalent pass; to deny a CPU-DoS from an untrusted
    ///   file this path is capped at `H15` (`LEGACY_RECOMPUTE_MAX_H`) and returns
    ///   [`Error::LegacyKeyTooTall`] above it.
    /// * any other length — [`Error::Malformed`].
    ///
    /// # Trusting the stored root is safe (fast path)
    ///
    /// The root is NOT secret — it is the public key value `T[1]`
    /// (`encode_public_key` = `type || type || I || T[1]`). It is used only by
    /// [`public_key`](Self::public_key); signing recomputes the authentication
    /// path from the seed and never reads `self.root`. A tampered root therefore
    /// yields a wrong public key under which genuine signatures simply fail to
    /// verify — a fail-closed self-DoS, never a forgery (the attacker lacks the
    /// seed). Re-deriving the root on every load to validate a public value
    /// would cost a full keygen and buy nothing: an attacker able to rewrite the
    /// key file could already force catastrophic LM-OTS reuse, which is far
    /// worse. So the stored root is taken as-is and deliberately NOT recomputed.
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
        })
    }
}

impl Drop for LmsPrivateKey {
    fn drop(&mut self) {
        wipe(&mut self.seed);
        wipe(&mut self.i_id);
    }
}

impl LmsPublicKey {
    /// The encoded public key (`u32(lms_type) || u32(ots_type) || I || T[1]`).
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Parses a raw LMS public key, validating its length and typecodes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 24 + N {
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
        Ok(LmsPublicKey {
            bytes: bytes.to_vec(),
        })
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

/// One level of an HSS key: its parameter sets, identifier, and master seed.
struct HssLevel {
    lms_type: LmsType,
    ots_type: LmotsType,
    i_id: [u8; 16],
    seed: [u8; N],
}

impl Drop for HssLevel {
    fn drop(&mut self) {
        wipe(&mut self.seed);
        wipe(&mut self.i_id);
    }
}

/// An HSS public (verification) key: `u32(L) || lms_public_key`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct HssPublicKey {
    bytes: Vec<u8>,
}

/// A multi-level HSS private (signing) key.
///
/// **Stateful** — see the [module documentation](crate::lms). Internally each
/// of the `L` levels owns a *fixed* `(I, seed)`. Every [`sign`](Self::sign)
/// advances the bottom level's leaf index; re-persist
/// [`to_bytes`](Self::to_bytes) afterwards. Not [`Clone`] by design.
///
/// # Capacity and the fail-closed multi-level mitigation
///
/// A literal RFC 8554 HSS regenerates each lower-level tree (a fresh `(I, seed)`
/// signed by the next parent leaf) as it is exhausted, so the key can sign
/// `prod(2^h_i)` messages with no LM-OTS key ever reused. This implementation
/// does **not** regenerate lower trees — the per-level `(I, seed)` are fixed so
/// it can reproduce the Appendix F Test Case 2 vector.
///
/// Because the lower trees are fixed, advancing a higher level would reset the
/// bottom leaf index while the bottom `(I, seed)` is unchanged, re-using the
/// bottom tree's one-time keys on different messages — a catastrophic forgery
/// vector. To prevent that, a multi-level key (`L >= 2`) is **capped at one
/// bottom tree**: it issues only `2^h_bottom` signatures (every higher level
/// pinned at leaf 0) and then returns [`Error::Exhausted`]. No LM-OTS key is
/// ever used twice. This is a conservative fail-closed mitigation; the full
/// multi-level HSS regeneration is flagged for future work. The bottom level's
/// signing randomizer `C` is drawn from the RNG per signature; the pinned
/// higher levels derive theirs deterministically so their fixed one-time keys
/// always re-emit byte-identical signatures (see `append_level_signature`).
pub struct HssPrivateKey {
    levels: Vec<HssLevel>,
    /// Cached root of each level's tree (`roots[i] = T[1]` of level i).
    roots: Vec<[u8; N]>,
    /// Per-level next-unused leaf index.
    q: Vec<u32>,
}

impl HssPrivateKey {
    /// Builds an HSS key from a fixed `(lms_type, ots_type, I, seed)` per level
    /// (top level first). `L = levels.len()` must be 1..=8.
    ///
    /// This is the seeded constructor used to reproduce RFC 8554 Test Case 2.
    pub fn from_levels(levels: &[(LmsType, LmotsType, [u8; 16], [u8; N])]) -> Result<Self, Error> {
        let l = levels.len();
        if !(1..=8).contains(&l) {
            return Err(Error::InvalidLevels);
        }
        let mut lv = Vec::with_capacity(l);
        let mut roots = Vec::with_capacity(l);
        for &(lms_type, ots_type, i_id, seed) in levels {
            roots.push(tree::compute_root(lms_type, ots_type, &i_id, &seed));
            lv.push(HssLevel {
                lms_type,
                ots_type,
                i_id,
                seed,
            });
        }
        Ok(HssPrivateKey {
            levels: lv,
            roots,
            q: alloc::vec![0u32; l],
        })
    }

    /// Generates a fresh `L`-level HSS key from a CSPRNG, using `params[i]` as
    /// the `(lms_type, ots_type)` for level `i` (top level first).
    pub fn generate<R: RngCore + CryptoRng>(
        params: &[(LmsType, LmotsType)],
        rng: &mut R,
    ) -> Result<Self, Error> {
        let l = params.len();
        if !(1..=8).contains(&l) {
            return Err(Error::InvalidLevels);
        }
        let mut levels = Vec::with_capacity(l);
        for &(lms_type, ots_type) in params {
            let mut i_id = [0u8; 16];
            let mut seed = [0u8; N];
            rng.fill_bytes(&mut i_id);
            rng.fill_bytes(&mut seed);
            levels.push((lms_type, ots_type, i_id, seed));
        }
        Self::from_levels(&levels)
    }

    /// The number of levels `L`.
    pub fn levels(&self) -> usize {
        self.levels.len()
    }

    /// The matching HSS public key: `u32(L) || pub[0]`.
    pub fn public_key(&self) -> HssPublicKey {
        let top = &self.levels[0];
        let pub0 = tree::encode_public_key(top.lms_type, top.ots_type, &top.i_id, &self.roots[0]);
        let mut bytes = Vec::with_capacity(4 + pub0.len());
        bytes.extend_from_slice(&(self.levels.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&pub0);
        HssPublicKey { bytes }
    }

    /// Total signatures still available before the whole key is exhausted.
    ///
    /// For a single-level key (`L == 1`) this is `2^h - q`, the number of unused
    /// leaves of the one tree.
    ///
    /// For a multi-level key (`L >= 2`) it is `2^h_bottom - q_bottom`, the unused
    /// leaves of the *bottom* tree only. See `advance` for why
    /// the higher levels are deliberately pinned at leaf 0: advancing a higher
    /// level would re-use the bottom tree's fixed LM-OTS keys, which is a
    /// catastrophic key reuse. This conservative cap (one bottom tree's worth of
    /// signatures) is the fail-closed mitigation for that finding.
    pub fn remaining(&self) -> u64 {
        let l = self.levels.len();
        let bottom = l - 1;
        self.levels[bottom]
            .lms_type
            .leaves()
            .saturating_sub(self.q[bottom] as u64)
    }

    /// Advances the leaf-index state by one signature.
    ///
    /// # Fail-closed multi-level behaviour (security mitigation)
    ///
    /// Each HSS level here owns a *fixed* `(I, seed)`. A full RFC 8554 HSS would
    /// replace an exhausted lower-level tree with a freshly-keyed one signed by
    /// the next parent leaf, so every signature uses unique LM-OTS material.
    /// This implementation does not regenerate lower trees, so allowing the
    /// mixed-radix odometer to *carry* out of the bottom level would reset
    /// `q_bottom` to 0 while the bottom `(I, seed)` is unchanged — re-using the
    /// bottom tree's one-time keys to sign different messages. LM-OTS reuse
    /// reveals Winternitz pre-images and permits universal forgery.
    ///
    /// To make reuse impossible, a multi-level key (`L >= 2`) is treated as
    /// exhausted the moment the bottom tree would wrap: only the first
    /// `2^h_bottom` signatures (with every higher level pinned at leaf 0) are
    /// ever issued. The higher levels are never advanced. This caps capacity at
    /// one bottom tree but guarantees no LM-OTS key is ever used twice.
    ///
    /// `L == 1` is an ordinary single LMS tree and simply advances `q[0]`.
    ///
    /// This only increments the bottom leaf index; it never carries into a
    /// higher level. When the bottom tree is consumed, `q[bottom]` is left at
    /// `leaves()` (the exhausted sentinel) so `remaining()` becomes 0 and the
    /// *next* [`sign`](Self::sign) returns [`Error::Exhausted`]. It does not
    /// itself return an error, so the signature for the just-consumed leaf
    /// (including the final one) is always emitted.
    fn advance(&mut self) {
        let bottom = self.levels.len() - 1;
        self.q[bottom] += 1;
    }

    /// Signs `message` (RFC 8554 §6.2). Advances the internal state.
    ///
    /// `rng` supplies the bottom level's LM-OTS randomizer `C`; it SHOULD be a
    /// CSPRNG. The pinned higher levels derive their `C` deterministically —
    /// see `append_level_signature` for why that is mandatory.
    /// **Persist [`to_bytes`](Self::to_bytes) before using the returned
    /// signature** — see the [module documentation](crate::lms).
    pub fn sign<R: RngCore>(&mut self, rng: &mut R, message: &[u8]) -> Result<Vec<u8>, Error> {
        let l = self.levels.len();
        if self.remaining() == 0 {
            return Err(Error::Exhausted);
        }

        let mut out = Vec::new();
        out.extend_from_slice(&((l - 1) as u32).to_be_bytes());

        for i in 0..l {
            if i + 1 < l {
                // Pinned non-bottom level: its one-time key re-signs the same
                // child public key on every call, so `C` MUST be deterministic
                // (`None` selects the seed-derived randomizer).
                self.append_level_signature(&mut out, i, message, None);
            } else {
                // Bottom level: `q` advances with every signature, so a fresh
                // random `C` never re-randomizes an already-used one-time key.
                let mut c = [0u8; N];
                rng.fill_bytes(&mut c);
                self.append_level_signature(&mut out, i, message, Some(&c));
            }
        }

        self.advance();
        Ok(out)
    }

    /// Appends `sig[i]` (signing either `pub[i+1]` or the message) and, for
    /// non-final levels, the signed public key `pub[i+1]`.
    ///
    /// `c` is the LM-OTS randomizer; `None` derives it deterministically from
    /// the level's secret seed and the signed bytes via [`ots::derive_c`].
    ///
    /// # Why pinned levels MUST use the deterministic randomizer
    ///
    /// Non-bottom levels are pinned at leaf 0 and sign the *fixed* child public
    /// key, so the same LM-OTS key is re-emitted by every `sign()` call. Were a
    /// fresh `C` drawn per call, `Q = H(I || q || D_MESG || C || pub[i+1])`
    /// would change each time and the one-time Winternitz chains would be
    /// exposed at different coefficient vectors — textbook LM-OTS reuse,
    /// enabling offline forgery. With the seed-derived `C`, every emission of
    /// an upper-level signature is byte-identical.
    fn append_level_signature(
        &self,
        out: &mut Vec<u8>,
        i: usize,
        message: &[u8],
        c: Option<&[u8; N]>,
    ) {
        let l = self.levels.len();
        let lv = &self.levels[i];
        let signed = if i + 1 < l {
            let child = &self.levels[i + 1];
            tree::encode_public_key(
                child.lms_type,
                child.ots_type,
                &child.i_id,
                &self.roots[i + 1],
            )
        } else {
            message.to_vec()
        };
        let c = match c {
            Some(c) => *c,
            None => ots::derive_c(&lv.i_id, &lv.seed, self.q[i], &signed),
        };
        let sig = tree::sign(
            lv.lms_type,
            lv.ots_type,
            &lv.i_id,
            &lv.seed,
            self.q[i],
            &c,
            &signed,
        );
        out.extend_from_slice(&sig);
        if i + 1 < l {
            out.extend_from_slice(&signed); // pub[i+1]
        }
    }

    /// Like [`sign`](Self::sign) but with caller-supplied per-level randomizers
    /// `c_per_level[i]` (used to reproduce the RFC 8554 vectors). Advances state.
    #[cfg(test)]
    fn sign_with_cs(&mut self, message: &[u8], c_per_level: &[[u8; N]]) -> Result<Vec<u8>, Error> {
        let l = self.levels.len();
        if self.remaining() == 0 {
            return Err(Error::Exhausted);
        }
        let mut out = Vec::new();
        out.extend_from_slice(&((l - 1) as u32).to_be_bytes());
        for (i, c) in c_per_level.iter().enumerate().take(l) {
            self.append_level_signature(&mut out, i, message, Some(c));
        }
        self.advance();
        Ok(out)
    }

    /// Serializes the private key **including every level's live leaf index**
    /// and that level's cached public root.
    ///
    /// Layout: `u32(L) || for each level { u32(lms_type) || u32(ots_type) ||
    /// I(16) || seed(32) || u32(q) || root(32) }`. This embeds the full state
    /// that MUST be persisted after each signature.
    ///
    /// Each appended root is the public value `T[1]` of that level's tree (the
    /// child key the parent level signs); storing it lets
    /// [`from_bytes`](Self::from_bytes) load any height instantly instead of
    /// recomputing every level's root via a full `O(2^h)` keygen pass. The
    /// per-level block is a pure superset of the legacy 60-byte block (the root
    /// is appended at its end).
    pub fn to_bytes(&self) -> Vec<u8> {
        let l = self.levels.len();
        let mut v = Vec::with_capacity(4 + l * (4 + 4 + 16 + N + 4 + N));
        v.extend_from_slice(&(l as u32).to_be_bytes());
        for (i, lv) in self.levels.iter().enumerate() {
            v.extend_from_slice(&lv.lms_type.typecode().to_be_bytes());
            v.extend_from_slice(&lv.ots_type.typecode().to_be_bytes());
            v.extend_from_slice(&lv.i_id);
            v.extend_from_slice(&lv.seed);
            v.extend_from_slice(&self.q[i].to_be_bytes());
            v.extend_from_slice(&self.roots[i]);
        }
        v
    }

    /// Parses a private key produced by [`to_bytes`](Self::to_bytes), resuming
    /// at each persisted per-level `q`.
    ///
    /// Length-discriminated and backward compatible (per-level stride):
    /// * `4 + L*92` — the current root-bearing format. Each level's stored root
    ///   is read directly and **trusted** (no recompute); a key of any height
    ///   loads in constant time.
    /// * `4 + L*60` — the LEGACY root-less format. Each level's root is
    ///   recomputed (an `O(2^h)` pass), capped per level at `H15`
    ///   (`LEGACY_RECOMPUTE_MAX_H`) — taller levels return
    ///   [`Error::LegacyKeyTooTall`] to deny a CPU-DoS from an untrusted file.
    /// * any other length — [`Error::Malformed`].
    ///
    /// # Trusting the stored roots is safe (fast path)
    ///
    /// A root is NOT secret — `roots[i]` is the public value `T[1]` of level
    /// `i`'s tree, and for `i + 1` it is exactly the child public key the parent
    /// level signs. A tampered `roots[i+1]` makes the HSS signature's embedded
    /// child key disagree with the seed-derived subtree, so verification fails:
    /// fail-closed, never a forgery (the attacker lacks the seeds). Re-deriving
    /// every root on load to validate a public value would cost a full keygen
    /// and buy nothing — an attacker able to rewrite the file could already
    /// force catastrophic LM-OTS reuse — so the stored roots are taken as-is and
    /// deliberately NOT recomputed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < 4 {
            return Err(Error::Malformed);
        }
        let l = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if !(1..=8).contains(&l) {
            return Err(Error::Malformed);
        }
        const LEGACY_PER: usize = 4 + 4 + 16 + N + 4;
        const NEW_PER: usize = LEGACY_PER + N;
        let (per, has_root) = if bytes.len() == 4 + l * NEW_PER {
            (NEW_PER, true)
        } else if bytes.len() == 4 + l * LEGACY_PER {
            (LEGACY_PER, false)
        } else {
            return Err(Error::Malformed);
        };
        let mut levels = Vec::with_capacity(l);
        let mut roots = Vec::with_capacity(l);
        let mut q = Vec::with_capacity(l);
        let mut off = 4;
        for _ in 0..l {
            let lms_type = LmsType::from_u32(u32::from_be_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
            ]))
            .ok_or(Error::Malformed)?;
            let ots_type = LmotsType::from_u32(u32::from_be_bytes([
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ]))
            .ok_or(Error::Malformed)?;
            let mut i_id = [0u8; 16];
            i_id.copy_from_slice(&bytes[off + 8..off + 24]);
            let mut seed = [0u8; N];
            seed.copy_from_slice(&bytes[off + 24..off + 24 + N]);
            let qi = u32::from_be_bytes([
                bytes[off + 24 + N],
                bytes[off + 25 + N],
                bytes[off + 26 + N],
                bytes[off + 27 + N],
            ]);
            if qi as u64 > lms_type.leaves() {
                return Err(Error::Malformed);
            }
            let root = if has_root {
                // Fast path: trust the stored public root (see method docs).
                let mut r = [0u8; N];
                r.copy_from_slice(&bytes[off + 28 + N..off + 28 + N + N]);
                r
            } else {
                // Legacy path: recompute, but refuse a CPU-DoS-sized tree.
                if lms_type.h() > LEGACY_RECOMPUTE_MAX_H {
                    return Err(Error::LegacyKeyTooTall);
                }
                tree::compute_root(lms_type, ots_type, &i_id, &seed)
            };
            roots.push(root);
            levels.push(HssLevel {
                lms_type,
                ots_type,
                i_id,
                seed,
            });
            q.push(qi);
            off += per;
        }
        // Fail-closed invariant: under the multi-level mitigation every higher
        // level stays pinned at leaf 0 (only the bottom level advances). A
        // persisted multi-level key with any non-bottom q != 0 can only be a
        // pre-mitigation key that has already wrapped — i.e. one that has, or is
        // about to, re-use the bottom tree's LM-OTS keys. Reject it rather than
        // resume into reuse.
        if l >= 2 && q[..l - 1].iter().any(|&qi| qi != 0) {
            return Err(Error::Malformed);
        }
        Ok(HssPrivateKey { levels, roots, q })
    }
}

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

#[cfg(test)]
mod tests;
