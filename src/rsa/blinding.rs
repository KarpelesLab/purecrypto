//! Cached base-blinding pairs for the runtime-sized private key's CRT path.
//!
//! Coron base blinding needs, per operation, a secret `r` together with
//! `rᵉ` (to blind the input) and `r⁻¹` (to unblind the output). Deriving a
//! fresh `r` every time means a fresh inversion every time — about a fifth
//! of an RSA-2048 signature even when the Fermat inverse is folded into the
//! exponentiation's squarings. Like OpenSSL's `BN_BLINDING`, the key instead
//! keeps a pair `(A, B) = (rᵉ, r⁻¹) mod n` and *updates* it after each use,
//! which costs a few modular multiplications.
//!
//! The update is not a bare squaring (OpenSSL's `r ← r²`): every operation
//! also multiplies in a power `xᵗ` of the refresh-time base `x`, with
//! `t ∈ 0..16` drawn fresh per operation, so the blinder walks
//! `rₖ₊₁ = rₖ² · x^tₖ`. The table `xᵗ`, `x^(−t)` (both kept with the
//! `e`-th power where needed) is built once per refresh, the multiplier is
//! picked by a constant-time scan, so the update is a fixed sequence of two
//! squarings, two multiplications and two table scans. The fresh `t` is what
//! keeps two copies of the same state — a key inherited across `fork(2)` —
//! from replaying each other's blinders: they diverge with probability
//! 15/16 at every operation. A clone starts with an empty cache.
//!
//! Every [`REFRESH_INTERVAL`] operations the pair is re-derived from scratch
//! (a fresh HMAC-derived `x` and its Fermat inverse through the CRT).
//!
//! The state is guarded by a try-lock built from atomics (no `unsafe`, no
//! `std`): an operation that finds the cache busy — another thread is using
//! the same key — takes the stateless path (fresh blinder, inverse folded
//! into the exponentiation) instead of waiting.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::bignum::{BoxedMontModulus, BoxedUint};
use crate::ct::ConstantTimeEq;

/// Operations between two full re-derivations of the blinding pair.
pub(super) const REFRESH_INTERVAL: u32 = 64;

/// Size of the per-operation multiplier table (`t ∈ 0..TABLE`).
const TABLE: usize = 16;

/// Slots in [`BlindingCache::words`], each `limbs` 64-bit limbs.
const SLOT_A: usize = 0;
const SLOT_B: usize = 1;
const fn slot_x(t: usize) -> usize {
    2 + t
}
const fn slot_y(t: usize) -> usize {
    2 + TABLE + t
}
const SLOTS: usize = 2 + 2 * TABLE;

/// The cached blinding state of one key instance (see the module docs).
///
/// Values are stored in the Montgomery form of the key's modulus, as
/// `AtomicU32` halves of each limb — atomics because the cache is mutated
/// through `&self` from any thread (the try-lock orders the accesses), and
/// 32-bit ones because 64-bit atomics do not exist on every target.
pub(super) struct BlindingCache {
    lock: AtomicBool,
    /// Operations left before the next refresh; 0 means "empty".
    uses_left: AtomicU32,
    /// `SLOTS` values of `limbs` limbs: `A = rᵉ`, `B = r⁻¹`, then the
    /// multiplier tables `Xₜ = x^(e·t)` and `Yₜ = x^(−t)`.
    words: Vec<AtomicU32>,
    limbs: usize,
}

impl BlindingCache {
    /// An empty cache for a modulus of `limbs` limbs.
    pub(super) fn new(limbs: usize) -> Self {
        let mut words = Vec::with_capacity(SLOTS * limbs * 2);
        words.resize_with(SLOTS * limbs * 2, || AtomicU32::new(0));
        BlindingCache {
            lock: AtomicBool::new(false),
            uses_left: AtomicU32::new(0),
            words,
            limbs,
        }
    }

    fn load(&self, slot: usize) -> BoxedUint {
        let base = slot * self.limbs * 2;
        let w = &self.words[base..base + self.limbs * 2];
        let limbs = w
            .chunks_exact(2)
            .map(|p| {
                p[0].load(Ordering::Relaxed) as u64 | ((p[1].load(Ordering::Relaxed) as u64) << 32)
            })
            .collect();
        BoxedUint::from_limbs(limbs)
    }

    fn store(&self, slot: usize, v: &BoxedUint) {
        let base = slot * self.limbs * 2;
        let w = &self.words[base..base + self.limbs * 2];
        let src = v.as_limbs();
        for (j, p) in w.chunks_exact(2).enumerate() {
            let x = src.get(j).copied().unwrap_or(0);
            p[0].store(x as u32, Ordering::Relaxed);
            p[1].store((x >> 32) as u32, Ordering::Relaxed);
        }
    }

    /// Constant-time `table[t]` over the `TABLE` slots starting at
    /// `first(0)`: every entry is read, the match kept by a mask.
    fn gather(&self, first: fn(usize) -> usize, t: usize) -> BoxedUint {
        let mut acc = alloc::vec![0u64; self.limbs];
        for i in 0..TABLE {
            let mask = crate::ct::limb_mask(i.ct_eq(&t));
            let base = first(i) * self.limbs * 2;
            let w = &self.words[base..base + self.limbs * 2];
            for (a, p) in acc.iter_mut().zip(w.chunks_exact(2)) {
                let x = p[0].load(Ordering::Relaxed) as u64
                    | ((p[1].load(Ordering::Relaxed) as u64) << 32);
                *a |= x & mask;
            }
        }
        BoxedUint::from_limbs(acc)
    }

    /// Takes one blinding pair `(rᵉ·R, r⁻¹·R) mod n` (Montgomery form of
    /// `mont`), refreshing the cache with `refresh` when it is empty or due.
    /// `t` is this operation's fresh multiplier index (`< 16`).
    ///
    /// Returns `None` when the cache is busy (another thread holds it) or
    /// the refresh failed; the caller then takes the stateless path.
    ///
    /// `refresh` returns `(xᵉ, x⁻¹)` (plain values `< n`) for a freshly
    /// derived `x`, or `None` when it could not invert one.
    pub(super) fn take(
        &self,
        mont: &BoxedMontModulus,
        t: usize,
        refresh: impl FnOnce() -> Option<(BoxedUint, BoxedUint)>,
    ) -> Option<(BoxedUint, BoxedUint)> {
        if mont.limbs() != self.limbs {
            return None;
        }
        if self
            .lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return None;
        }
        let out = self.take_locked(mont, t, refresh);
        self.lock.store(false, Ordering::Release);
        out
    }

    fn take_locked(
        &self,
        mont: &BoxedMontModulus,
        t: usize,
        refresh: impl FnOnce() -> Option<(BoxedUint, BoxedUint)>,
    ) -> Option<(BoxedUint, BoxedUint)> {
        let left = self.uses_left.load(Ordering::Relaxed);
        if left == 0 {
            let (mut xe, mut xi) = refresh()?;
            // X₀ = Y₀ = 1, X₁ = xᵉ, Y₁ = x⁻¹, then powers.
            let one = mont.to_mont(&BoxedUint::from_u64(1));
            let x1 = mont.to_mont(&xe);
            let y1 = mont.to_mont(&xi);
            xe.zeroize();
            xi.zeroize();
            self.store(slot_x(0), &one);
            self.store(slot_y(0), &one);
            let (mut xp, mut yp) = (x1.clone(), y1.clone());
            for i in 1..TABLE {
                if i > 1 {
                    xp = mont.mont_mul(&xp, &x1);
                    yp = mont.mont_mul(&yp, &y1);
                }
                self.store(slot_x(i), &xp);
                self.store(slot_y(i), &yp);
            }
            xp.zeroize();
            yp.zeroize();
            self.store(SLOT_A, &x1);
            self.store(SLOT_B, &y1);
            self.uses_left
                .store(REFRESH_INTERVAL - 1, Ordering::Relaxed);
            return Some((x1, y1));
        }
        // A ← A²·Xₜ, B ← B²·Yₜ: still a valid pair, since
        // (r²·xᵗ)ᵉ = (rᵉ)²·x^(e·t) and (r²·xᵗ)⁻¹ = (r⁻¹)²·x^(−t).
        let mut a = self.load(SLOT_A);
        let mut b = self.load(SLOT_B);
        let mut xt = self.gather(slot_x, t);
        let mut yt = self.gather(slot_y, t);
        let mut a2 = mont.mont_sqr(&a);
        let mut b2 = mont.mont_sqr(&b);
        let na = mont.mont_mul(&a2, &xt);
        let nb = mont.mont_mul(&b2, &yt);
        for v in [&mut a, &mut b, &mut xt, &mut yt, &mut a2, &mut b2] {
            v.zeroize();
        }
        self.store(SLOT_A, &na);
        self.store(SLOT_B, &nb);
        self.uses_left.store(left - 1, Ordering::Relaxed);
        Some((na, nb))
    }
}

#[cfg(test)]
impl BlindingCache {
    /// Holds (or releases) the try-lock, as a concurrent user would.
    pub(super) fn set_busy(&self, busy: bool) {
        self.lock.store(busy, Ordering::SeqCst);
    }

    /// Operations left before the next refresh (0: empty).
    pub(super) fn uses_left(&self) -> u32 {
        self.uses_left.load(Ordering::SeqCst)
    }
}

impl Drop for BlindingCache {
    fn drop(&mut self) {
        for w in self.words.iter_mut() {
            crate::zeroize::Zeroize::zeroize(w.get_mut());
        }
    }
}
