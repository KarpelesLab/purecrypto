//! Constant-time Montgomery modular arithmetic for [`BoxedUint`].
//!
//! A runtime-width port of [`MontModulus`](super::MontModulus): same CIOS
//! multiplication and square-and-multiply-always exponentiation, over
//! `Vec<Limb>` scratch so the modulus width is chosen at runtime.

use super::boxed::{BoxedUint, adc_limbs, sbb_limbs, select_limbs};
use super::montgomery::inv_mod_2_64;
use super::mul::mac;
use super::uint::{Limb, adc, sbb};
use crate::ct::{Choice, ConditionallySelectable};
use alloc::vec;
use alloc::vec::Vec;

/// Best-effort wipe of a secret-dependent `Vec<Limb>` scratch buffer.
///
/// Mirrors the `core::hint::black_box`-guarded zeroing used by
/// [`BoxedUint::zeroize`](super::boxed::BoxedUint) and the AEAD/MAC drop paths
/// in `src/cipher`: the writes are unconditional (no data-dependent branch, so
/// the constant-time property is preserved) and the `black_box` fence prevents
/// LLVM from eliding them as a dead store.
#[inline]
fn zeroize_limbs(v: &mut [Limb]) {
    for limb in v.iter_mut() {
        *limb = 0;
    }
    let _ = core::hint::black_box(&v);
}

/// `(a + b) mod n` for equal-length `a, b < n`.
fn add_mod_limbs(n: &[Limb], a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let (sum, carry) = adc_limbs(a, b, 0);
    let (diff, borrow) = sbb_limbs(&sum, n, 0);
    let subtract = carry | (borrow ^ 1);
    select_limbs(&diff, &sum, Choice::from(subtract as u8))
}

/// `(a - b) mod n` for equal-length `a, b < n`.
fn sub_mod_limbs(n: &[Limb], a: &[Limb], b: &[Limb]) -> Vec<Limb> {
    let (diff, borrow) = sbb_limbs(a, b, 0);
    let (wrapped, _) = adc_limbs(&diff, n, 0);
    select_limbs(&wrapped, &diff, Choice::from(borrow as u8))
}

/// Runtime-width Montgomery parameters for an odd modulus.
#[derive(Clone, Debug)]
pub struct BoxedMontModulus {
    n: Vec<Limb>,
    n_prime: Limb,
    r2: Vec<Limb>,
    limbs: usize,
}

impl BoxedMontModulus {
    /// Builds parameters for an odd `modulus`.
    ///
    /// # Panics
    /// Panics if `modulus` is even or zero.
    pub fn new(modulus: &BoxedUint) -> Self {
        // Zero is even, so the odd-modulus assertion below also catches it;
        // we check explicitly first to give a precise diagnostic and to
        // document that a zero modulus is rejected rather than silently
        // producing a meaningless parameter set.
        assert!(
            !modulus.is_zero(),
            "BoxedMontModulus::new: modulus must be nonzero"
        );
        let limbs = modulus.significant_limbs();
        let n = modulus.limbs_resized(limbs);
        assert!(n[0] & 1 == 1, "Montgomery modulus must be odd");
        let n_prime = inv_mod_2_64(n[0]).wrapping_neg();

        // r2 = 2^(2*64*limbs) mod n, by doubling 1 that many times.
        let mut r2 = vec![0 as Limb; limbs];
        r2[0] = 1;
        let bits = 2 * 64 * limbs;
        for _ in 0..bits {
            r2 = add_mod_limbs(&n, &r2, &r2);
        }

        BoxedMontModulus {
            n,
            n_prime,
            r2,
            limbs,
        }
    }

    /// The modulus width in limbs.
    #[inline]
    pub fn limbs(&self) -> usize {
        self.limbs
    }

    /// CIOS Montgomery multiplication of two `limbs`-wide values into `out`,
    /// with caller-provided scratch `t` — no allocation, so the
    /// exponentiation ladders can reuse two buffers across their thousands
    /// of multiplies instead of hitting the allocator on each one.
    ///
    /// `out` may alias `a` and/or `b`: the accumulation only reads them, and
    /// `out` is written exclusively in the final-subtraction step, after the
    /// last read. (Rust's borrow rules forbid literal aliasing anyway;
    /// callers ping-pong two buffers and `mem::swap`.) `t` must not alias
    /// anything. The operation sequence is identical to the previous
    /// allocating version — same mask-based conditional subtraction, no new
    /// branches — so the constant-time property is unchanged.
    fn mont_mul_to(&self, a: &[Limb], b: &[Limb], t: &mut [Limb], out: &mut [Limb]) {
        let l = self.limbs;
        let n = &self.n;
        // Only the low `l` limbs of `t` are used; the exponentiation ladders
        // hand in the wider squaring scratch and share it with `mont_sqr_to`.
        t[..l].fill(0);
        let mut ts: Limb = 0;

        for &bi in b.iter().take(l) {
            let mut carry = 0;
            for j in 0..l {
                let (s, c) = mac(t[j], a[j], bi, carry);
                t[j] = s;
                carry = c;
            }
            let (s, c) = adc(ts, carry, 0);
            ts = s;
            let ts1 = c;

            let m = t[0].wrapping_mul(self.n_prime);
            let (_, mut carry) = mac(t[0], m, n[0], 0);
            for j in 1..l {
                let (s, c) = mac(t[j], m, n[j], carry);
                t[j - 1] = s;
                carry = c;
            }
            let (s, c) = adc(ts, carry, 0);
            t[l - 1] = s;
            ts = ts1 + c;
        }

        // Conditional final subtraction (result < 2N): out = t - n, kept only
        // when the subtraction doesn't underflow the (l+1)-limb value.
        let mut bo: Limb = 0;
        for j in 0..l {
            let (d, b) = sbb(t[j], n[j], bo);
            out[j] = d;
            bo = b;
        }
        let (_, borrow) = sbb(ts, 0, bo);
        let ge = Choice::from((borrow ^ 1) as u8);
        for j in 0..l {
            out[j] = Limb::conditional_select(&out[j], &t[j], ge);
        }
    }

    /// Montgomery squaring of a `limbs`-wide value into `out`, with
    /// caller-provided scratch `t` of at least `2 * limbs` limbs.
    ///
    /// Produces exactly the same value as `mont_mul_to(a, a, ..)` but uses the
    /// standard squaring optimization: each off-diagonal partial product
    /// `a[i]·a[j]` (`i < j`) is computed once and doubled, then the diagonal
    /// `a[i]²` terms are added — roughly halving the `mac` count of the
    /// schoolbook phase. The Montgomery reduction is then done as a separate
    /// SOS pass over the full `2·limbs`-limb square (CIOS interleaving is not
    /// possible once the product is formed up front).
    ///
    /// Constant time: every loop bound is a function of `self.limbs` only (a
    /// public quantity), the doubling is an unconditional shift across the
    /// whole product, and the final subtraction uses the same mask-based
    /// select as `mont_mul_to` — no data-dependent branch anywhere.
    ///
    /// `out` may alias `a`: `a` is only read while the square is accumulated
    /// into `t`, and `out` is written exclusively in the final-subtraction
    /// step. `t` must not alias anything.
    fn mont_sqr_to(&self, a: &[Limb], t: &mut [Limb], out: &mut [Limb]) {
        let l = self.limbs;
        let n = &self.n;
        let p = &mut t[..2 * l];
        p.fill(0);

        // Off-diagonal partial products a[i]·a[j] for i < j, each computed
        // once. Iteration i writes p[2i+1 ..= i+l-1] and drops its carry into
        // p[i+l], which iteration i+1 then accumulates into — the ordinary
        // schoolbook triangle.
        for i in 0..l {
            let mut carry = 0;
            for j in (i + 1)..l {
                let (s, c) = mac(p[i + j], a[i], a[j], carry);
                p[i + j] = s;
                carry = c;
            }
            p[i + l] = carry;
        }

        // Double the off-diagonal sum S. 2S <= a² < 2^(128·l), so the shift
        // cannot carry out of the 2l-limb product.
        let mut carry: Limb = 0;
        for w in p.iter_mut() {
            let next = *w >> 63;
            *w = (*w << 1) | carry;
            carry = next;
        }

        // Add the diagonal a[i]² terms at positions (2i, 2i+1). The high half
        // of each square lands on an odd position whose add can carry into the
        // next even position, which is exactly where the next mac's carry-in
        // goes. The total is a², which fits in 2l limbs, so the last carry
        // out is zero.
        let mut carry: Limb = 0;
        for i in 0..l {
            let (s, c) = mac(p[2 * i], a[i], a[i], carry);
            p[2 * i] = s;
            let (s, c2) = adc(p[2 * i + 1], c, 0);
            p[2 * i + 1] = s;
            carry = c2;
        }

        // Montgomery reduction, SOS style: for each of the l low limbs, add
        // m·N so the limb cancels, then shift the window up one limb (done
        // implicitly by indexing from i). `hi` carries the overflow of
        // iteration i's top-limb add into position i+l+1, which is where
        // iteration i+1 adds its own top carry — so a single riding limb
        // suffices and the loop shape stays independent of the data.
        let mut hi: Limb = 0;
        for i in 0..l {
            let m = p[i].wrapping_mul(self.n_prime);
            let mut carry = 0;
            for j in 0..l {
                let (s, c) = mac(p[i + j], m, n[j], carry);
                p[i + j] = s;
                carry = c;
            }
            let (s, c) = adc(p[i + l], carry, hi);
            p[i + l] = s;
            hi = c;
        }

        // Result is the (l+1)-limb value (p[l..2l], hi) and is < 2N; same
        // mask-based conditional final subtraction as `mont_mul_to`.
        let mut bo: Limb = 0;
        for j in 0..l {
            let (d, b) = sbb(p[l + j], n[j], bo);
            out[j] = d;
            bo = b;
        }
        let (_, borrow) = sbb(hi, 0, bo);
        let ge = Choice::from((borrow ^ 1) as u8);
        for j in 0..l {
            out[j] = Limb::conditional_select(&out[j], &p[l + j], ge);
        }
    }

    /// CIOS Montgomery multiplication of two `limbs`-wide values.
    fn mont_mul_limbs(&self, a: &[Limb], b: &[Limb]) -> Vec<Limb> {
        let mut t = vec![0 as Limb; self.limbs];
        let mut out = vec![0 as Limb; self.limbs];
        self.mont_mul_to(a, b, &mut t, &mut out);
        // Scrub the secret-dependent CIOS scratch before it drops.
        zeroize_limbs(&mut t);
        out
    }

    fn to_mont_limbs(&self, x: &[Limb]) -> Vec<Limb> {
        self.mont_mul_limbs(x, &self.r2)
    }

    fn demont_limbs(&self, x: &[Limb]) -> Vec<Limb> {
        let mut one = vec![0 as Limb; self.limbs];
        one[0] = 1;
        self.mont_mul_limbs(x, &one)
    }

    /// The modulus as a [`BoxedUint`].
    pub fn modulus(&self) -> BoxedUint {
        BoxedUint::from_limbs(self.n.clone())
    }

    /// Converts a plain value `< n` into the Montgomery domain.
    pub fn to_mont(&self, x: &BoxedUint) -> BoxedUint {
        BoxedUint::from_limbs(self.to_mont_limbs(&x.limbs_resized(self.limbs)))
    }

    /// Converts a Montgomery-domain value back to a plain value.
    pub fn from_mont(&self, x: &BoxedUint) -> BoxedUint {
        BoxedUint::from_limbs(self.demont_limbs(&x.limbs_resized(self.limbs)))
    }

    /// Montgomery-domain multiply: given `a, b` in Montgomery form, returns
    /// `a·b` in Montgomery form (a single CIOS reduction).
    pub fn mont_mul(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        BoxedUint::from_limbs(
            self.mont_mul_limbs(&a.limbs_resized(self.limbs), &b.limbs_resized(self.limbs)),
        )
    }

    /// Returns `(a * b) mod n` for `a, b < n`.
    pub fn mul_mod(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        let a = a.limbs_resized(self.limbs);
        let b = b.limbs_resized(self.limbs);
        let t = self.mont_mul_limbs(&a, &b);
        BoxedUint::from_limbs(self.mont_mul_limbs(&t, &self.r2))
    }

    /// Computes `base^exp mod n` in constant time (square-and-multiply-always
    /// over all bits of `exp`).
    ///
    /// The exponent is zero-padded to at least `self.limbs` 64-bit limbs
    /// before the loop. The RSA case (`d < n`) hits this branch directly;
    /// callers that need a wider exponent (e.g. Diffie-Hellman with a
    /// secret exponent unrelated to the modulus width) get a loop sized to
    /// the larger of the two, never the silent truncation that an
    /// unconditional `limbs_resized(self.limbs)` would impose.
    ///
    /// Iteration count is a function of `max(self.limbs, exp.limbs())` —
    /// both public quantities (the modulus width is public, and a caller
    /// passing an exponent wider than the modulus is exposing the width by
    /// construction). Two secret exponents of the same width through the
    /// same modulus therefore still take the same time.
    pub fn pow(&self, base: &BoxedUint, exp: &BoxedUint) -> BoxedUint {
        let base_m = self.to_mont_limbs(&base.limbs_resized(self.limbs));
        let mut one = vec![0 as Limb; self.limbs];
        one[0] = 1;
        let r_mod_n = self.to_mont_limbs(&one); // R mod N (= 1 in Montgomery form)

        // Fixed 4-bit window: precompute `base^0 … base^15` (Montgomery form)
        // once, then consume the exponent four bits at a time — four squarings
        // and one multiply by the window's value per nibble, versus the eight
        // squarings + four multiplies a bit-by-bit ladder would do over the same
        // four bits. The table value is chosen by scanning all 16 entries with a
        // constant-time select (no secret-indexed memory access) and the per-
        // nibble multiply is unconditional, so this stays square-and-multiply-
        // *always*: the operation count is a function of the (public) exponent
        // width only, leaking nothing about `base` or the exponent's bits.
        let mut table: Vec<Vec<Limb>> = Vec::with_capacity(16);
        table.push(r_mod_n.clone());
        table.push(base_m);
        for i in 2..16 {
            table.push(self.mont_mul_limbs(&table[i - 1], &table[1]));
        }

        let mut acc = r_mod_n;
        // Reused scratch: accumulator `t` (sized 2·limbs for the squaring's
        // full product; `mont_mul_to` uses its low half), ping-pong output
        // `nxt`, and the per-nibble gather buffer `sel`. All hold base-derived
        // secrets during the loop and are scrubbed once at the end — reusing
        // them (instead of a fresh allocation per multiply) changes where the
        // intermediate values live, not what is computed.
        let mut t = vec![0 as Limb; 2 * self.limbs];
        let mut nxt = vec![0 as Limb; self.limbs];
        let mut sel = vec![0 as Limb; self.limbs];

        // Pad the exponent to at least `self.limbs` 64-bit words; if the
        // caller hands in a wider exponent we keep every bit. `limbs_resized`
        // would silently truncate the high limbs of an over-wide exponent,
        // turning the computation into `base^(exp mod 2^(64·self.limbs))` —
        // the precise foot-gun called out in the foundations audit.
        let exp_width = exp.significant_limbs().max(self.limbs);
        let exp_limbs = exp.limbs_resized(exp_width);
        let mut i = exp_limbs.len();
        while i > 0 {
            i -= 1;
            let limb = exp_limbs[i];
            let mut shift = 64;
            while shift > 0 {
                shift -= 4;
                for _ in 0..4 {
                    self.mont_sqr_to(&acc, &mut t, &mut nxt);
                    core::mem::swap(&mut acc, &mut nxt);
                }

                let digit = ((limb >> shift) & 0xf) as usize;
                // Constant-time gather of table[digit].
                sel.copy_from_slice(&table[0]);
                for (j, entry) in table.iter().enumerate() {
                    let hit = Choice::from((j == digit) as u8);
                    for (s, e) in sel.iter_mut().zip(entry.iter()) {
                        *s = Limb::conditional_select(e, s, hit);
                    }
                }
                self.mont_mul_to(&acc, &sel, &mut t, &mut nxt);
                core::mem::swap(&mut acc, &mut nxt);
            }
        }
        // Construct the result first, then scrub the Montgomery accumulator,
        // the scratch buffers, and the precomputed window table (all
        // base-derived secrets). The returned `BoxedUint` owns a fresh Vec
        // from `demont_limbs`, so the zeroing below cannot corrupt it.
        let result = BoxedUint::from_limbs(self.demont_limbs(&acc));
        zeroize_limbs(&mut acc);
        zeroize_limbs(&mut t);
        zeroize_limbs(&mut nxt);
        zeroize_limbs(&mut sel);
        for entry in table.iter_mut() {
            zeroize_limbs(entry);
        }
        result
    }

    /// Computes `base^exp mod n` for a **public** exponent, sized to the
    /// exponent's actual bit length rather than the modulus width.
    ///
    /// This is square-and-multiply-*always* exactly like [`pow`](Self::pow) — it
    /// is branchless and leaks nothing about `base`. It differs only in the loop
    /// length: it iterates `exp.bit_len()` times instead of padding to the
    /// modulus width, so its running time depends on `exp`. **`exp` must be
    /// public** (e.g. an RSA public exponent in verify/encrypt, where both `exp`
    /// and `base` are public). Never call it with a secret exponent — use
    /// [`pow`](Self::pow) for those. For RSA `e = 65537` this replaces ~2048
    /// squarings with ~17.
    pub fn pow_public(&self, base: &BoxedUint, exp: &BoxedUint) -> BoxedUint {
        let base_m = self.to_mont_limbs(&base.limbs_resized(self.limbs));
        let mut one = vec![0 as Limb; self.limbs];
        one[0] = 1;
        let mut acc = self.to_mont_limbs(&one); // R mod N

        let bits = exp.bit_len();
        if bits == 0 {
            // base^0 = 1.
            return BoxedUint::from_limbs(self.demont_limbs(&acc));
        }
        // Reused scratch, as in `pow` (`t` again sized 2·limbs for the
        // squaring): `acc` still holds a base-derived secret even though the
        // exponent is public.
        let mut t = vec![0 as Limb; 2 * self.limbs];
        let mut nxt = vec![0 as Limb; self.limbs];
        let exp_limbs = exp.limbs_resized(exp.significant_limbs().max(1));
        let mut i = bits;
        while i > 0 {
            i -= 1;
            self.mont_sqr_to(&acc, &mut t, &mut nxt);
            core::mem::swap(&mut acc, &mut nxt);
            self.mont_mul_to(&acc, &base_m, &mut t, &mut nxt);
            let limb = exp_limbs[i / 64];
            let set = Choice::from(((limb >> (i % 64)) & 1) as u8);
            for (a, m) in acc.iter_mut().zip(nxt.iter()) {
                *a = Limb::conditional_select(m, a, set);
            }
        }
        let result = BoxedUint::from_limbs(self.demont_limbs(&acc));
        zeroize_limbs(&mut acc);
        zeroize_limbs(&mut t);
        zeroize_limbs(&mut nxt);
        result
    }

    /// Returns `(a + b) mod n`.
    pub fn add_mod(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        BoxedUint::from_limbs(add_mod_limbs(
            &self.n,
            &a.limbs_resized(self.limbs),
            &b.limbs_resized(self.limbs),
        ))
    }

    /// Returns `(a - b) mod n`.
    pub fn sub_mod(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        BoxedUint::from_limbs(sub_mod_limbs(
            &self.n,
            &a.limbs_resized(self.limbs),
            &b.limbs_resized(self.limbs),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::{MontModulus, Uint};

    #[test]
    fn pow_public_matches_pow() {
        // The public-exponent modexp must return exactly the same value as the
        // constant-time `pow` for every (base, exp); it only changes timing.
        let modulus = BoxedUint::from_be_bytes(&[
            0xC0, 0x05, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x00, 0x11, 0x22,
            0x33, 0x45,
        ]); // odd 128-bit
        let m = BoxedMontModulus::new(&modulus);
        let exps: [u64; 7] = [0, 1, 2, 3, 65537, 0x1_0001, u32::MAX as u64];
        for be in 1u64..=9 {
            let base = BoxedUint::from_u64(be.wrapping_mul(0x9E37_79B9));
            for &e in &exps {
                let exp = BoxedUint::from_u64(e);
                assert_eq!(
                    m.pow(&base, &exp),
                    m.pow_public(&base, &exp),
                    "base={be} e={e}"
                );
            }
        }
    }

    #[test]
    fn modexp_matches_u128() {
        // Cross-check against the const-generic path for 64-bit moduli.
        let moduli: [u64; 3] = [0xFFFF_FFFF_FFFF_FFFF, 0x8000_0000_0000_0001, 1_000_003];
        let bases: [u64; 3] = [2, 3, 0x1234_5678_9abc_def1];
        let exps: [u64; 3] = [1, 17, 0xdead_beef];
        for &nv in &moduli {
            let m = BoxedMontModulus::new(&BoxedUint::from_u64(nv));
            for &b in &bases {
                for &e in &exps {
                    let got = m
                        .pow(&BoxedUint::from_u64(b % nv), &BoxedUint::from_u64(e))
                        .to_be_bytes(8);
                    let nn = nv as u128;
                    let mut r: u128 = 1 % nn;
                    let mut base = (b % nv) as u128 % nn;
                    let mut exp = e;
                    while exp > 0 {
                        if exp & 1 == 1 {
                            r = r * base % nn;
                        }
                        base = base * base % nn;
                        exp >>= 1;
                    }
                    let mut expected = [0u8; 8];
                    expected.copy_from_slice(&(r as u64).to_be_bytes());
                    assert_eq!(got, expected, "n={nv} b={b} e={e}");
                }
            }
        }
    }

    #[test]
    fn textbook_rsa() {
        // n=3233, e=17, d=2753; encrypt/decrypt 65.
        let m = BoxedMontModulus::new(&BoxedUint::from_u64(3233));
        let msg = BoxedUint::from_u64(65);
        let ct = m.pow(&msg, &BoxedUint::from_u64(17));
        assert_eq!(ct, BoxedUint::from_u64(2790));
        assert_eq!(m.pow(&ct, &BoxedUint::from_u64(2753)), msg);
    }

    #[test]
    #[should_panic(expected = "modulus must be nonzero")]
    fn new_zero_modulus_panics() {
        // Zero is also even, but the explicit nonzero check fires first
        // and gives the diagnostic that matches the documented contract.
        let _ = BoxedMontModulus::new(&BoxedUint::zero(2));
    }

    #[test]
    fn pow_does_not_truncate_overwide_exponent() {
        // Modulus is a single 64-bit limb but the exponent spans two limbs:
        // the silent-truncation bug would reduce `exp mod 2^64`, dropping
        // the bottom 64 bits to zero and computing `base^0 = 1`. With the
        // fix the full exponent is honoured.
        let n: u64 = 0xFFFF_FFFF_FFFF_FFC5; // small odd prime-like
        let m = BoxedMontModulus::new(&BoxedUint::from_u64(n));
        // exp = 2^64 (only the high limb is set). `base^(2^64) mod n` for
        // base=3 must equal the iterated 64-square of 3 mod n.
        let exp = BoxedUint::from_limbs(vec![0, 1]);
        let got = m.pow(&BoxedUint::from_u64(3), &exp).to_be_bytes(8);

        // Reference: square 3 sixty-four times mod n via u128.
        let mut r: u128 = 3;
        for _ in 0..64 {
            r = (r * r) % n as u128;
        }
        let expected = (r as u64).to_be_bytes();
        assert_eq!(got, expected);

        // Sanity: the truncation bug would have produced 1.
        assert_ne!(got, [0, 0, 0, 0, 0, 0, 0, 1]);
    }

    /// SplitMix64 — deterministic test-only RNG.
    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    #[test]
    fn mont_sqr_matches_mont_mul() {
        // Differential: the dedicated squaring must produce bit-identical
        // output to the general multiply with both operands equal, across
        // every limb width the RSA/DH paths use, random odd moduli, random
        // residues, and the edge values 0, 1, n-1, and all-limbs-set
        // (reduced). Both routines require inputs < n.
        let mut rng: u64 = 0x5EED_CAFE_F00D_D00D;
        for limbs in 1..=64usize {
            // More modulus/value samples at the small widths where edge
            // cases concentrate; keep the total runtime sane at width 64.
            let moduli_per_width = if limbs <= 8 { 4 } else { 2 };
            for _ in 0..moduli_per_width {
                let mut n_limbs: Vec<Limb> = (0..limbs).map(|_| splitmix64(&mut rng)).collect();
                n_limbs[0] |= 1; // odd
                n_limbs[limbs - 1] |= 1 << 63; // full width
                let n = BoxedUint::from_limbs(n_limbs);
                let m = BoxedMontModulus::new(&n);
                assert_eq!(m.limbs(), limbs);

                let mut values: Vec<BoxedUint> = Vec::new();
                // Edge values: 0, 1, n-1, all-ones (reduced mod n).
                values.push(BoxedUint::zero(limbs));
                values.push(BoxedUint::from_u64(1));
                values.push(n.sub(&BoxedUint::from_u64(1)));
                let ones = BoxedUint::from_limbs(vec![Limb::MAX; limbs]);
                values.push(ones.reduce(&n));
                // Random residues, including some with only high limbs set.
                for k in 0..6 {
                    let v: Vec<Limb> = (0..limbs)
                        .map(|j| {
                            if k >= 4 && j < limbs / 2 {
                                0 // top-heavy value
                            } else {
                                splitmix64(&mut rng)
                            }
                        })
                        .collect();
                    values.push(BoxedUint::from_limbs(v).reduce(&n));
                }

                let mut t_mul = vec![0 as Limb; limbs];
                let mut t_sqr = vec![0 as Limb; 2 * limbs];
                let mut out_mul = vec![0 as Limb; limbs];
                let mut out_sqr = vec![0 as Limb; limbs];
                for v in &values {
                    let a = v.limbs_resized(limbs);
                    m.mont_mul_to(&a, &a, &mut t_mul, &mut out_mul);
                    m.mont_sqr_to(&a, &mut t_sqr, &mut out_sqr);
                    assert_eq!(out_sqr, out_mul, "limbs={limbs} a={a:x?}");
                }
            }
        }
    }

    #[test]
    fn matches_const_generic_256bit() {
        // Boxed modexp must equal the fixed-width path on a 256-bit modulus.
        let n4 = Uint::<4>::from_limbs([
            0x1234_5678_9abc_def1,
            0xfedc_ba98_7654_3211,
            0x0f0f_0f0f_0f0f_0f0f,
            0x8000_0000_0000_0001,
        ]);
        let mut n_bytes = [0u8; 32];
        n4.write_be_bytes(&mut n_bytes);

        let base4 = Uint::<4>::from_u64(0xdead_beef);
        let exp4 = Uint::<4>::from_u64(65537);
        let fixed = MontModulus::new(n4).pow(&base4, &exp4);
        let mut fixed_bytes = [0u8; 32];
        fixed.write_be_bytes(&mut fixed_bytes);

        let boxed = BoxedMontModulus::new(&BoxedUint::from_be_bytes(&n_bytes)).pow(
            &BoxedUint::from_u64(0xdead_beef),
            &BoxedUint::from_u64(65537),
        );
        assert_eq!(boxed.to_be_bytes(32), fixed_bytes);
    }
}
