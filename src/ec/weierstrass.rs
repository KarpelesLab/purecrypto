//! Short-Weierstrass curve arithmetic for the runtime-curve API, on the stack.
//!
//! Every supported prime-order curve is a [`CurveParams`] implementor: a
//! zero-sized marker type whose associated constants are the field modulus,
//! coefficients, generator and order (plus the Montgomery constants derived
//! from them at compile time). [`Engine<L>`] is the arithmetic over
//! `L`-limb [`Uint`] field elements on the stack: its formulas, ladders and
//! inversions are instantiated once per limb width and read the curve's
//! parameters as data, while the field multiplication — the hot kernel — is
//! instantiated per curve with the modulus as immediates and reached
//! through a function pointer. No point operation allocates. The
//! object-safe [`Curve`] trait is the `BoxedUint`-at-the-boundary view the
//! [`boxed`](super::boxed) and [`sm2`](super::sm2) layers use;
//! [`CurveId::curve`](super::curves::CurveId::curve) hands out the
//! `&'static dyn Curve` for a curve.
//!
//! Point addition uses the Renes–Costello–Batina **complete** formulas
//! (Algorithms 1 / 3 for general `a`, 4 / 6 for `a = −3`, 7 / 9 for
//! `a = 0`), correct for all inputs including the identity and equal points,
//! so the constant-time ladder has one fixed operation sequence.

use crate::bignum::{BoxedUint, Limb, MontModulus, Uint};
use crate::ct::{Choice, ConstantTimeEq};
use crate::zeroize::Zeroize;

/// Limbs of the widest field (P-521: 521 bits → 9 × 64).
pub(crate) const MAX_LIMBS: usize = 9;

/// Which specialised Renes–Costello–Batina formulas the coefficient `a`
/// admits. Public curve data: the choice is fixed per curve.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum ACoeff {
    /// `a = 0` (secp256k1, the Koblitz curves): Algorithms 7 / 9.
    Zero,
    /// `a = −3` (NIST, SM2, the SEC 2 `r` curves): Algorithms 4 / 6.
    MinusThree,
    /// Anything else (Brainpool): the general Algorithms 1 / 3.
    General,
}

/// The parameters of one prime-order short-Weierstrass curve
/// `y² = x³ + a·x + b (mod p)` over `L` limbs, as compile-time constants
/// (the source [`Engine::new`] builds an engine from).
///
/// Implementors give the six SEC 1 parameters; everything else has a
/// default computed from them at compile time (the Montgomery constants via
/// [`MontModulus::new`], which is `const`). `L` must cover both `p` and `n`
/// — one limb more than the field where the order is wider (secp160k1/r1/r2,
/// secp224k1 — all of which round to the same limb count as the field).
pub(crate) trait CurveParams<const L: usize>: 'static + Sync {
    /// The field modulus `p`.
    const P: Uint<L>;
    /// The coefficient `a`.
    const A: Uint<L>;
    /// The coefficient `b`.
    const B: Uint<L>;
    /// The generator's affine x-coordinate.
    const GX: Uint<L>;
    /// The generator's affine y-coordinate.
    const GY: Uint<L>;
    /// The (prime) group order `n`.
    const N: Uint<L>;

    /// Which RCB formulas `a` admits.
    const A_KIND: ACoeff = a_kind(&Self::P, &Self::A);
    /// Montgomery context for `p` — used at compile time only, to derive the
    /// constants below; the field kernel takes `P` and `P_INV` as
    /// immediates.
    const FP: MontModulus<L> = MontModulus::new(Self::P);
    /// Montgomery context for `n` (compile time only, as `FP`).
    const FQ: MontModulus<L> = MontModulus::new(Self::N);
    /// `−p⁻¹ mod 2⁶⁴`.
    const P_INV: Limb = neg_inv_mod_2_64(Self::P.as_limbs()[0]);
    /// `−n⁻¹ mod 2⁶⁴`.
    const N_INV: Limb = neg_inv_mod_2_64(Self::N.as_limbs()[0]);
    /// `R mod p`: the Montgomery form of 1.
    const ONE_MONT: Uint<L> = Self::FP.to_mont(&Uint::ONE);
    /// `R² mod p`: multiplying by it converts into Montgomery form.
    const R2_P: Uint<L> = Self::FP.to_mont(&Self::ONE_MONT);
    /// `R mod n`.
    const ONE_MONT_N: Uint<L> = Self::FQ.to_mont(&Uint::ONE);
    /// `R² mod n`.
    const R2_N: Uint<L> = Self::FQ.to_mont(&Self::ONE_MONT_N);
    /// `a` in Montgomery form.
    const A_MONT: Uint<L> = Self::FP.to_mont(&Self::A);
    /// `b` in Montgomery form.
    const B_MONT: Uint<L> = Self::FP.to_mont(&Self::B);
    /// `3b` in Montgomery form.
    const B3_MONT: Uint<L> =
        Self::FP.to_mont(&Self::FP.add_mod(&Self::FP.add_mod(&Self::B, &Self::B), &Self::B));
    /// `p − 2`, the Fermat inversion exponent.
    const P_MINUS_2: Uint<L> = Self::P.wrapping_sub(&Uint::from_u64(2));
    /// `n − 2`.
    const N_MINUS_2: Uint<L> = Self::N.wrapping_sub(&Uint::from_u64(2));
    /// `(p + 1) / 4`, the square-root exponent when `p ≡ 3 (mod 4)`.
    const SQRT_EXP: Uint<L> = Self::P.adc(&Uint::ONE, 0).0.shr1().shr1();
    /// Bit length of `p`.
    const P_BITS: usize = bit_len(&Self::P);
    /// Bit length of `n`.
    const N_BITS: usize = bit_len(&Self::N);
}

/// `−n⁻¹ mod 2⁶⁴` for odd `n` (Newton: each step doubles the correct bits).
const fn neg_inv_mod_2_64(n: Limb) -> Limb {
    let mut x = 1 as Limb;
    let mut i = 0;
    while i < 6 {
        x = x.wrapping_mul(2u64.wrapping_sub(n.wrapping_mul(x)));
        i += 1;
    }
    x.wrapping_neg()
}

/// Bit length of a `Uint` (compile-time helper; `Uint::bit_len` is not
/// `const`).
const fn bit_len<const L: usize>(v: &Uint<L>) -> usize {
    let limbs = v.as_limbs();
    let mut i = L;
    while i > 0 {
        i -= 1;
        if limbs[i] != 0 {
            return 64 * i + (64 - limbs[i].leading_zeros() as usize);
        }
    }
    0
}

/// Classifies the coefficient `a` (compile time; public curve data).
const fn a_kind<const L: usize>(p: &Uint<L>, a: &Uint<L>) -> ACoeff {
    let (p_minus_3, _) = p.sbb(&Uint::from_u64(3), 0);
    let (a, p3) = (a.as_limbs(), p_minus_3.as_limbs());
    let mut zero = true;
    let mut minus_three = true;
    let mut i = 0;
    while i < L {
        zero &= a[i] == 0;
        minus_three &= a[i] == p3[i];
        i += 1;
    }
    if zero {
        ACoeff::Zero
    } else if minus_three {
        ACoeff::MinusThree
    } else {
        ACoeff::General
    }
}

// --- limb helpers -----------------------------------------------------------

#[inline(always)]
fn mac(a: Limb, b: Limb, c: Limb, carry: Limb) -> (Limb, Limb) {
    let r = (a as u128) + (b as u128) * (c as u128) + (carry as u128);
    (r as Limb, (r >> 64) as Limb)
}

#[inline(always)]
fn adc(a: Limb, b: Limb, carry: Limb) -> (Limb, Limb) {
    let r = (a as u128) + (b as u128) + (carry as u128);
    (r as Limb, (r >> 64) as Limb)
}

#[inline(always)]
fn sbb(a: Limb, b: Limb, borrow: Limb) -> (Limb, Limb) {
    let r = (a as u128).wrapping_sub((b as u128) + (borrow as u128));
    (r as Limb, ((r >> 64) as Limb) & 1)
}

/// All-ones when `bit` is 1, all-zeros when 0 (`bit ∈ {0, 1}`). The field
/// kernels apply it with plain `&`/`^` across the limbs, the discipline of
/// the native P-256 field (`p256_field::mask_from_bit`); a `black_box`
/// here would be a compiler barrier inside every multiplication (measured
/// +12% at 6 limbs, +30% at 9), so only the point-table gather, which runs
/// once per window, pays for an opaque mask.
#[inline(always)]
fn mask(bit: Limb) -> Limb {
    bit.wrapping_neg()
}

/// Montgomery multiplication `a·b·R⁻¹ mod m` (CIOS) for `a, b < m`, with the
/// modulus `m` and `−m⁻¹ mod 2⁶⁴` as parameters. Always inlined into its
/// per-curve callers, where both are compile-time constants, so the limb
/// loop specialises to the curve's immediates. The final subtraction is a
/// masked select (no branch on the value).
#[inline(always)]
pub(crate) fn mont_mul<const L: usize>(
    a: &Uint<L>,
    b: &Uint<L>,
    m: &Uint<L>,
    m_inv: Limb,
) -> Uint<L> {
    let (a, b, m) = (a.as_limbs(), b.as_limbs(), m.as_limbs());
    // t spans L + 2 words: t[0..L] in the array, t[L] in `ts`, t[L + 1] in
    // `ts1` (which only lives within one iteration).
    let mut t = [0 as Limb; L];
    let mut ts: Limb = 0;
    for &bi in b.iter() {
        let mut carry = 0;
        for j in 0..L {
            let (s, c) = mac(t[j], a[j], bi, carry);
            t[j] = s;
            carry = c;
        }
        let (s, ts1) = adc(ts, carry, 0);
        ts = s;
        let q = t[0].wrapping_mul(m_inv);
        let (_, mut carry) = mac(t[0], q, m[0], 0);
        for j in 1..L {
            let (s, c) = mac(t[j], q, m[j], carry);
            t[j - 1] = s;
            carry = c;
        }
        let (s, c) = adc(ts, carry, 0);
        t[L - 1] = s;
        ts = ts1 + c;
    }
    // (t, ts) < 2m: subtract m once when it is >= m.
    let mut diff = [0 as Limb; L];
    let mut borrow = 0;
    for j in 0..L {
        let (d, b) = sbb(t[j], m[j], borrow);
        diff[j] = d;
        borrow = b;
    }
    let (_, borrow) = sbb(ts, 0, borrow);
    // borrow == 1: the value was below m, keep t.
    let keep_t = mask(borrow);
    for j in 0..L {
        diff[j] ^= keep_t & (diff[j] ^ t[j]);
    }
    Uint::from_limbs(diff)
}

/// `(a + b) mod m` for `a, b < m`, branch-free.
#[inline(always)]
pub(crate) fn add_mod<const L: usize>(a: &Uint<L>, b: &Uint<L>, m: &Uint<L>) -> Uint<L> {
    let (sum, carry) = a.adc(b, 0);
    let (diff, borrow) = sum.sbb(m, 0);
    // Keep the sum iff it neither overflowed nor reached m.
    let keep_sum = mask(borrow & (carry ^ 1));
    let (s, d) = (sum.as_limbs(), diff.as_limbs());
    let mut out = [0 as Limb; L];
    for j in 0..L {
        out[j] = d[j] ^ (keep_sum & (d[j] ^ s[j]));
    }
    Uint::from_limbs(out)
}

/// `(a − b) mod m` for `a, b < m`, branch-free.
#[inline(always)]
fn sub_mod<const L: usize>(a: &Uint<L>, b: &Uint<L>, m: &Uint<L>) -> Uint<L> {
    let (diff, borrow) = a.sbb(b, 0);
    let (wrapped, _) = diff.adc(m, 0);
    // A borrow means the true difference was negative: add m back.
    let add_m = mask(borrow);
    let (d, w) = (diff.as_limbs(), wrapped.as_limbs());
    let mut out = [0 as Limb; L];
    for j in 0..L {
        out[j] = d[j] ^ (add_m & (d[j] ^ w[j]));
    }
    Uint::from_limbs(out)
}

/// Constant-time `a < b` as a [`Choice`] (one borrow chain).
#[inline]
fn ct_lt<const L: usize>(a: &Uint<L>, b: &Uint<L>) -> Choice {
    Choice::from(a.sbb(b, 0).1 as u8)
}

/// The low `L` limbs of `v` — a straight copy, so `v` may be secret.
/// Every value crossing into the engine is bounded by `p` or `n` (validated
/// at import, reduced by the scalar arithmetic), so nothing above limb `L`
/// is ever set; a wider *allocation* with zero high limbs is still exact.
fn narrow<const L: usize>(v: &BoxedUint) -> Uint<L> {
    let mut limbs = [0 as Limb; L];
    for (dst, src) in limbs.iter_mut().zip(v.as_limbs()) {
        *dst = *src;
    }
    let out = Uint::from_limbs(limbs);
    limbs.zeroize();
    out
}

/// [`narrow`] for a **public** value whose width is not guaranteed: `None`
/// if any limb at or above `L` is set (so the value cannot be `< p`).
fn narrow_checked<const L: usize>(v: &BoxedUint) -> Option<Uint<L>> {
    let limbs = v.as_limbs();
    if limbs.len() > L && limbs[L..].iter().any(|&l| l != 0) {
        return None;
    }
    Some(narrow(v))
}

/// `v` as an `L`-limb `BoxedUint` — the width the heap arithmetic produced
/// for this curve, so byte encoders and widths downstream see no change.
fn widen<const L: usize>(v: &Uint<L>) -> BoxedUint {
    BoxedUint::from_limbs(v.as_limbs().to_vec())
}

/// A projective point `(X : Y : Z)` over `L` limbs, coordinates in
/// Montgomery form. The identity is `(0 : R : 0)`.
#[derive(Clone, Copy)]
pub(crate) struct Point<const L: usize> {
    x: Uint<L>,
    y: Uint<L>,
    z: Uint<L>,
}

impl<const L: usize> Zeroize for Point<L> {
    /// Wipes the coordinates: a scalar-multiplication intermediate is as
    /// secret as the scalar that produced it.
    #[inline]
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}

impl<const L: usize> Point<L> {
    /// Constant-time `table[digit]`: every entry is read in a fixed order
    /// and OR-masked into the result with one opaque mask per entry, so
    /// neither the access pattern nor the timing depends on `digit` (the
    /// index test is `ct_eq`, not a `==` the compiler may lower to a
    /// branch). Exactly one entry matches (`digit < 16`), so accumulating
    /// from zero is sound.
    fn ct_lookup(table: &[Point<L>; 16], digit: usize) -> Point<L> {
        let mut x = [0 as Limb; L];
        let mut y = [0 as Limb; L];
        let mut z = [0 as Limb; L];
        for (j, entry) in table.iter().enumerate() {
            let hit = core::hint::black_box(mask(j.ct_eq(&digit).unwrap_u8() as Limb));
            let (ex, ey, ez) = (entry.x.as_limbs(), entry.y.as_limbs(), entry.z.as_limbs());
            for i in 0..L {
                x[i] |= ex[i] & hit;
                y[i] |= ey[i] & hit;
                z[i] |= ez[i] & hit;
            }
        }
        Point {
            x: Uint::from_limbs(x),
            y: Uint::from_limbs(y),
            z: Uint::from_limbs(z),
        }
    }
}

/// Maximum width of a width-5 wNAF recoding (`64·MAX_LIMBS` bits plus the
/// carry digit).
const MAX_NAF: usize = 64 * MAX_LIMBS + 1;

/// The field multiplication of curve `C`, with its modulus as immediates:
/// the one piece of the engine instantiated per curve (reached through the
/// function pointer in [`Engine`], so every curve of one width shares the
/// formulas, ladders and inversions).
fn field_mul<C: CurveParams<L>, const L: usize>(a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
    mont_mul(a, b, &C::P, C::P_INV)
}

/// A complete point addition formula of an [`Engine`].
type AddFn<const L: usize> = fn(&Engine<L>, &Point<L>, &Point<L>) -> Point<L>;
/// A complete point doubling formula of an [`Engine`].
type DblFn<const L: usize> = fn(&Engine<L>, &Point<L>) -> Point<L>;

/// The arithmetic engine of one curve over `L` limbs: its parameters as
/// plain data (built at compile time from a [`CurveParams`] by
/// [`Engine::new`]) plus the curve's const-modulus multiply. The methods
/// are generic over the width only, so the code is shared by every curve
/// of that width — per-curve monomorphisation of the whole engine cost a
/// megabyte of text across the seventeen curves.
pub(crate) struct Engine<const L: usize> {
    p: Uint<L>,
    n: Uint<L>,
    /// `−n⁻¹ mod 2⁶⁴`.
    n_inv: Limb,
    /// `R mod p`, `R² mod p`, `R mod n`, `R² mod n`.
    one_mont: Uint<L>,
    r2_p: Uint<L>,
    one_mont_n: Uint<L>,
    r2_n: Uint<L>,
    a: Uint<L>,
    b: Uint<L>,
    gx: Uint<L>,
    gy: Uint<L>,
    a_mont: Uint<L>,
    b_mont: Uint<L>,
    b3_mont: Uint<L>,
    #[cfg(test)]
    a_kind: ACoeff,
    p_minus_2: Uint<L>,
    n_minus_2: Uint<L>,
    sqrt_exp: Uint<L>,
    p_bits: usize,
    n_bits: usize,
    /// [`field_mul`] for this curve.
    mul: fn(&Uint<L>, &Uint<L>) -> Uint<L>,
    /// The complete addition and doubling formulas the curve's `a` admits
    /// (RCB Algorithms 4/6, 7/9 or 1/3), chosen at compile time; a variant
    /// no curve of this width uses is never instantiated.
    add_fn: AddFn<L>,
    dbl_fn: DblFn<L>,
}

impl<const L: usize> Engine<L> {
    /// The engine of curve `C`.
    pub(crate) const fn new<C: CurveParams<L>>() -> Self {
        let (add_fn, dbl_fn): (AddFn<L>, DblFn<L>) = match C::A_KIND {
            ACoeff::MinusThree => (Self::add_a_minus_3, Self::double_a_minus_3),
            ACoeff::Zero => (Self::add_a_zero, Self::double_a_zero),
            ACoeff::General => (Self::add_general, Self::double_general),
        };
        Engine {
            p: C::P,
            n: C::N,
            n_inv: C::N_INV,
            one_mont: C::ONE_MONT,
            r2_p: C::R2_P,
            one_mont_n: C::ONE_MONT_N,
            r2_n: C::R2_N,
            a: C::A,
            b: C::B,
            gx: C::GX,
            gy: C::GY,
            a_mont: C::A_MONT,
            b_mont: C::B_MONT,
            b3_mont: C::B3_MONT,
            #[cfg(test)]
            a_kind: C::A_KIND,
            p_minus_2: C::P_MINUS_2,
            n_minus_2: C::N_MINUS_2,
            sqrt_exp: C::SQRT_EXP,
            p_bits: C::P_BITS,
            n_bits: C::N_BITS,
            mul: field_mul::<C, L>,
            add_fn,
            dbl_fn,
        }
    }

    // --- field arithmetic (Montgomery form) ---------------------------------

    #[inline(always)]
    pub(crate) fn mul(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        (self.mul)(a, b)
    }

    #[inline(always)]
    pub(crate) fn add(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        add_mod(a, b, &self.p)
    }

    #[inline(always)]
    fn sub(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        sub_mod(a, b, &self.p)
    }

    /// Plain residue `x < p` into Montgomery form.
    #[inline]
    fn to_mont(&self, x: &Uint<L>) -> Uint<L> {
        self.mul(x, &self.r2_p)
    }

    /// Montgomery form back to the plain residue.
    #[inline]
    fn to_plain(&self, x: &Uint<L>) -> Uint<L> {
        self.mul(x, &Uint::ONE)
    }

    /// `base^exp` in Montgomery form under `mul` (identity `one`), for a
    /// **public** exponent of at most `bits` bits: fixed 4-bit windows, the
    /// table indexed directly (the index is a function of the public
    /// exponent alone), so the operation sequence and access pattern never
    /// depend on the (possibly secret) base. Every exponent here is a curve
    /// constant (`p − 2`, `n − 2`, `(p + 1) / 4`) or derived from `p`.
    fn pow_mont<F: Fn(&Uint<L>, &Uint<L>) -> Uint<L>>(
        base: &Uint<L>,
        exp: &Uint<L>,
        bits: usize,
        mul: F,
        one: &Uint<L>,
    ) -> Uint<L> {
        let mut table = [*one; 16];
        table[1] = *base;
        for i in 2..16 {
            table[i] = mul(&table[i - 1], base);
        }
        let exp = exp.as_limbs();
        let mut acc = *one;
        let mut w = bits.div_ceil(4);
        while w > 0 {
            w -= 1;
            for _ in 0..4 {
                acc = mul(&acc, &acc);
            }
            let bit = 4 * w;
            let idx = ((exp[bit / 64] >> (bit % 64)) & 0xf) as usize;
            acc = mul(&acc, &table[idx]);
        }
        table.zeroize();
        acc
    }

    /// `x⁻¹` in Montgomery form by Fermat (`x^(p−2)`; `0 ↦ 0`), constant
    /// time in `x`.
    fn invert_mont(&self, x: &Uint<L>) -> Uint<L> {
        Self::pow_mont(
            x,
            &self.p_minus_2,
            self.p_bits,
            |a, b| self.mul(a, b),
            &self.one_mont,
        )
    }

    // --- scalar (mod n) arithmetic, plain residues --------------------------

    /// Montgomery multiplication modulo the order (the modulus from memory:
    /// the scalar ring is a few operations per signature).
    #[inline]
    fn mul_n(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        mont_mul(a, b, &self.n, self.n_inv)
    }

    /// `a·b mod n` for plain residues `a, b < n`.
    fn mul_mod_n(&self, a: &Uint<L>, b: &Uint<L>) -> Uint<L> {
        // mont_mul(a, b) = ab·R⁻¹; a second multiply by R² restores ab.
        self.mul_n(&self.mul_n(a, b), &self.r2_n)
    }

    /// `a⁻¹ mod n` (Fermat, `n` prime), constant time in `a`.
    fn invert_mod_n(&self, a: &Uint<L>) -> Uint<L> {
        let a_m = self.mul_n(a, &self.r2_n);
        let inv_m = Self::pow_mont(
            &a_m,
            &self.n_minus_2,
            self.n_bits,
            |x, y| self.mul_n(x, y),
            &self.one_mont_n,
        );
        self.mul_n(&inv_m, &Uint::ONE)
    }

    // --- points --------------------------------------------------------------

    /// The identity `(0 : 1 : 0)`.
    #[inline]
    pub(crate) fn identity(&self) -> Point<L> {
        Point {
            x: Uint::ZERO,
            y: self.one_mont,
            z: Uint::ZERO,
        }
    }

    /// Lifts affine `(x, y)` (plain residues) to projective form.
    #[inline]
    fn lift_affine(&self, x: &Uint<L>, y: &Uint<L>) -> Point<L> {
        Point {
            x: self.to_mont(x),
            y: self.to_mont(y),
            z: self.one_mont,
        }
    }

    /// The base point `G`.
    #[inline]
    pub(crate) fn generator(&self) -> Point<L> {
        self.lift_affine(&self.gx, &self.gy)
    }

    /// Affine `(x, y)` as plain residues, or `None` for the identity.
    ///
    /// `z` is secret-derived (the tail of a scalar multiplication), so the
    /// identity test folds every limb before the verdict, which is public in
    /// every caller: on these prime-order curves `[k]P` is the identity iff
    /// `k ≡ 0 (mod n)` or `P` is — a degenerate scalar or peer the caller
    /// rejects as an error. The inversion is the constant-time Fermat
    /// ladder.
    pub(crate) fn to_affine(&self, p: &Point<L>) -> Option<(Uint<L>, Uint<L>)> {
        if p.z.is_zero().declassify() {
            return None;
        }
        let mut z_inv = self.invert_mont(&p.z);
        let x = self.to_plain(&self.mul(&p.x, &z_inv));
        let y = self.to_plain(&self.mul(&p.y, &z_inv));
        z_inv.zeroize();
        Some((x, y))
    }

    /// `-p`: `(X : −Y : Z)`.
    #[inline]
    fn negate(&self, p: &Point<L>) -> Point<L> {
        Point {
            x: p.x,
            y: self.sub(&Uint::ZERO, &p.y),
            z: p.z,
        }
    }

    /// Complete projective addition `p + q`, correct for all inputs
    /// (including `p == q` and the identity), through the cheapest RCB
    /// formula the curve's `a` admits. Which one runs is a public property
    /// of the curve.
    #[inline]
    pub(crate) fn point_add(&self, p: &Point<L>, q: &Point<L>) -> Point<L> {
        (self.add_fn)(self, p, q)
    }

    /// Complete doubling `2·p`, correct for all inputs including the
    /// identity: RCB Algorithm 6 (`a = −3`, 8M + 3S + 2·m_b), 9 (`a = 0`,
    /// 6M + 2S + m_3b) or 3 (any `a`), against the 12M + 5·m_a,b of
    /// `point_add(p, p)`.
    #[inline]
    pub(crate) fn double(&self, p: &Point<L>) -> Point<L> {
        (self.dbl_fn)(self, p)
    }

    /// RCB Algorithm 4: complete addition for `a = −3`.
    fn add_a_minus_3(&self, p: &Point<L>, q: &Point<L>) -> Point<L> {
        let b = &self.b_mont;
        let m = |x: &Uint<L>, y: &Uint<L>| self.mul(x, y);
        let add = |x: &Uint<L>, y: &Uint<L>| self.add(x, y);
        let sub = |x: &Uint<L>, y: &Uint<L>| self.sub(x, y);

        let t0 = m(&p.x, &q.x);
        let t1 = m(&p.y, &q.y);
        let t2 = m(&p.z, &q.z);
        let t3 = add(&p.x, &p.y);
        let t4 = add(&q.x, &q.y);
        let t3 = m(&t3, &t4);
        let t4 = add(&t0, &t1);
        let t3 = sub(&t3, &t4);
        let t4 = add(&p.y, &p.z);
        let x3 = add(&q.y, &q.z);
        let t4 = m(&t4, &x3);
        let x3 = add(&t1, &t2);
        let t4 = sub(&t4, &x3);
        let x3 = add(&p.x, &p.z);
        let y3 = add(&q.x, &q.z);
        let x3 = m(&x3, &y3);
        let y3 = add(&t0, &t2);
        let y3 = sub(&x3, &y3);
        let z3 = m(b, &t2);
        let x3 = sub(&y3, &z3);
        let z3 = add(&x3, &x3);
        let x3 = add(&x3, &z3);
        let z3 = sub(&t1, &x3);
        let x3 = add(&t1, &x3);
        let y3 = m(b, &y3);
        let t1 = add(&t2, &t2);
        let t2 = add(&t1, &t2);
        let y3 = sub(&y3, &t2);
        let y3 = sub(&y3, &t0);
        let t1 = add(&y3, &y3);
        let y3 = add(&t1, &y3);
        let t1 = add(&t0, &t0);
        let t0 = add(&t1, &t0);
        let t0 = sub(&t0, &t2);
        let t1 = m(&t4, &y3);
        let t2 = m(&t0, &y3);
        let y3 = m(&x3, &z3);
        let y3 = add(&y3, &t2);
        let x3 = m(&t3, &x3);
        let x3 = sub(&x3, &t1);
        let z3 = m(&t4, &z3);
        let t1 = m(&t3, &t0);
        let z3 = add(&z3, &t1);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// RCB Algorithm 7: complete addition for `a = 0`.
    fn add_a_zero(&self, p: &Point<L>, q: &Point<L>) -> Point<L> {
        let b3 = &self.b3_mont;
        let m = |x: &Uint<L>, y: &Uint<L>| self.mul(x, y);
        let add = |x: &Uint<L>, y: &Uint<L>| self.add(x, y);
        let sub = |x: &Uint<L>, y: &Uint<L>| self.sub(x, y);

        let t0 = m(&p.x, &q.x);
        let t1 = m(&p.y, &q.y);
        let t2 = m(&p.z, &q.z);
        let t3 = add(&p.x, &p.y);
        let t4 = add(&q.x, &q.y);
        let t3 = m(&t3, &t4);
        let t4 = add(&t0, &t1);
        let t3 = sub(&t3, &t4);
        let t4 = add(&p.y, &p.z);
        let x3 = add(&q.y, &q.z);
        let t4 = m(&t4, &x3);
        let x3 = add(&t1, &t2);
        let t4 = sub(&t4, &x3);
        let x3 = add(&p.x, &p.z);
        let y3 = add(&q.x, &q.z);
        let x3 = m(&x3, &y3);
        let y3 = add(&t0, &t2);
        let y3 = sub(&x3, &y3);
        let x3 = add(&t0, &t0);
        let t0 = add(&x3, &t0);
        let t2 = m(b3, &t2);
        let z3 = add(&t1, &t2);
        let t1 = sub(&t1, &t2);
        let y3 = m(b3, &y3);
        let x3 = m(&t4, &y3);
        let t2 = m(&t3, &t1);
        let x3 = sub(&t2, &x3);
        let y3 = m(&y3, &t0);
        let t1 = m(&t1, &z3);
        let y3 = add(&t1, &y3);
        let t0 = m(&t0, &t3);
        let z3 = m(&z3, &t4);
        let z3 = add(&z3, &t0);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// RCB Algorithm 6: complete doubling for `a = −3`.
    fn double_a_minus_3(&self, p: &Point<L>) -> Point<L> {
        let b = &self.b_mont;
        let m = |x: &Uint<L>, y: &Uint<L>| self.mul(x, y);
        let add = |x: &Uint<L>, y: &Uint<L>| self.add(x, y);
        let sub = |x: &Uint<L>, y: &Uint<L>| self.sub(x, y);

        let t0 = m(&p.x, &p.x);
        let t1 = m(&p.y, &p.y);
        let t2 = m(&p.z, &p.z);
        let t3 = m(&p.x, &p.y);
        let t3 = add(&t3, &t3);
        let z3 = m(&p.x, &p.z);
        let z3 = add(&z3, &z3);
        let y3 = m(b, &t2);
        let y3 = sub(&y3, &z3);
        let x3 = add(&y3, &y3);
        let y3 = add(&x3, &y3);
        let x3 = sub(&t1, &y3);
        let y3 = add(&t1, &y3);
        let y3 = m(&x3, &y3);
        let x3 = m(&x3, &t3);
        let t3 = add(&t2, &t2);
        let t2 = add(&t2, &t3);
        let z3 = m(b, &z3);
        let z3 = sub(&z3, &t2);
        let z3 = sub(&z3, &t0);
        let t3 = add(&z3, &z3);
        let z3 = add(&z3, &t3);
        let t3 = add(&t0, &t0);
        let t0 = add(&t3, &t0);
        let t0 = sub(&t0, &t2);
        let t0 = m(&t0, &z3);
        let y3 = add(&y3, &t0);
        let t0 = m(&p.y, &p.z);
        let t0 = add(&t0, &t0);
        let z3 = m(&t0, &z3);
        let x3 = sub(&x3, &z3);
        let z3 = m(&t0, &t1);
        let z3 = add(&z3, &z3);
        let z3 = add(&z3, &z3);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// RCB Algorithm 9: complete doubling for `a = 0`.
    fn double_a_zero(&self, p: &Point<L>) -> Point<L> {
        let b3 = &self.b3_mont;
        let m = |x: &Uint<L>, y: &Uint<L>| self.mul(x, y);
        let add = |x: &Uint<L>, y: &Uint<L>| self.add(x, y);
        let sub = |x: &Uint<L>, y: &Uint<L>| self.sub(x, y);

        let t0 = m(&p.y, &p.y);
        let z3 = add(&t0, &t0);
        let z3 = add(&z3, &z3);
        let z3 = add(&z3, &z3);
        let t1 = m(&p.y, &p.z);
        let t2 = m(&p.z, &p.z);
        let t2 = m(b3, &t2);
        let x3 = m(&t2, &z3);
        let y3 = add(&t0, &t2);
        let z3 = m(&t1, &z3);
        let t1 = add(&t2, &t2);
        let t2 = add(&t1, &t2);
        let t0 = sub(&t0, &t2);
        let y3 = m(&t0, &y3);
        let y3 = add(&x3, &y3);
        let t1 = m(&p.x, &p.y);
        let x3 = m(&t0, &t1);
        let x3 = add(&x3, &x3);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// RCB Algorithm 3: complete doubling for any `a`.
    fn double_general(&self, p: &Point<L>) -> Point<L> {
        let a = &self.a_mont;
        let b3 = &self.b3_mont;
        let m = |x: &Uint<L>, y: &Uint<L>| self.mul(x, y);
        let add = |x: &Uint<L>, y: &Uint<L>| self.add(x, y);
        let sub = |x: &Uint<L>, y: &Uint<L>| self.sub(x, y);

        let t0 = m(&p.x, &p.x);
        let t1 = m(&p.y, &p.y);
        let t2 = m(&p.z, &p.z);
        let t3 = m(&p.x, &p.y);
        let t3 = add(&t3, &t3);
        let z3 = m(&p.x, &p.z);
        let z3 = add(&z3, &z3);
        let x3 = m(a, &z3);
        let y3 = m(b3, &t2);
        let y3 = add(&x3, &y3);
        let x3 = sub(&t1, &y3);
        let y3 = add(&t1, &y3);
        let y3 = m(&x3, &y3);
        let x3 = m(&t3, &x3);
        let z3 = m(b3, &z3);
        let t2 = m(a, &t2);
        let t3 = sub(&t0, &t2);
        let t3 = m(a, &t3);
        let t3 = add(&t3, &z3);
        let z3 = add(&t0, &t0);
        let t0 = add(&z3, &t0);
        let t0 = add(&t0, &t2);
        let t0 = m(&t0, &t3);
        let y3 = add(&y3, &t0);
        let t2 = m(&p.y, &p.z);
        let t2 = add(&t2, &t2);
        let t0 = m(&t2, &t3);
        let x3 = sub(&x3, &t0);
        let z3 = m(&t2, &t1);
        let z3 = add(&z3, &z3);
        let z3 = add(&z3, &z3);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Complete projective addition (RCB Algorithm 1), correct for all
    /// inputs and any `a`; also the tests' oracle for the specialised
    /// formulas.
    pub(crate) fn add_general(&self, p: &Point<L>, q: &Point<L>) -> Point<L> {
        let a = &self.a_mont;
        let b3 = &self.b3_mont;
        let m = |x: &Uint<L>, y: &Uint<L>| self.mul(x, y);
        let add = |x: &Uint<L>, y: &Uint<L>| self.add(x, y);
        let sub = |x: &Uint<L>, y: &Uint<L>| self.sub(x, y);

        // Renes–Costello–Batina "add-2015-rcb", transcribed verbatim.
        let t0 = m(&p.x, &q.x);
        let t1 = m(&p.y, &q.y);
        let t2 = m(&p.z, &q.z);
        let t3 = add(&p.x, &p.y);
        let t4 = add(&q.x, &q.y);
        let t3 = m(&t3, &t4);
        let t4 = add(&t0, &t1);
        let t3 = sub(&t3, &t4);
        let t4 = add(&p.x, &p.z);
        let t5 = add(&q.x, &q.z);
        let t4 = m(&t4, &t5);
        let t5 = add(&t0, &t2);
        let t4 = sub(&t4, &t5);
        let t5 = add(&p.y, &p.z);
        let x3 = add(&q.y, &q.z);
        let t5 = m(&t5, &x3);
        let x3 = add(&t1, &t2);
        let t5 = sub(&t5, &x3);
        let z3 = m(a, &t4);
        let x3 = m(b3, &t2);
        let z3 = add(&x3, &z3);
        let x3 = sub(&t1, &z3);
        let z3 = add(&t1, &z3);
        let y3 = m(&x3, &z3);
        let t1 = add(&t0, &t0);
        let t1 = add(&t1, &t0);
        let t2 = m(a, &t2);
        let t4 = m(b3, &t4);
        let t1 = add(&t1, &t2);
        let t2 = sub(&t0, &t2);
        let t2 = m(a, &t2);
        let t4 = add(&t4, &t2);
        let t0 = m(&t1, &t4);
        let y3 = add(&y3, &t0);
        let t0 = m(&t5, &t4);
        let x3 = m(&t3, &x3);
        let x3 = sub(&x3, &t0);
        let t0 = m(&t3, &t1);
        let z3 = m(&t5, &z3);
        let z3 = add(&z3, &t0);
        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Constant-time `scalar · point` over the full `64·L`-bit scalar
    /// width, via a fixed 4-bit window: 4 doublings and one *unconditional*
    /// addition per nibble, the window value fetched by a masked scan of all
    /// 16 table entries (no secret-indexed memory access). A zero nibble
    /// adds the identity — a no-op with the same operation sequence, since
    /// the RCB formulas are complete — so the schedule depends only on the
    /// public width. Any `scalar < 2^(64·L)` is multiplied exactly (the
    /// result is `[scalar mod n]P`), so nothing is silently truncated.
    pub(crate) fn scalar_mul(&self, scalar: &Uint<L>, point: &Point<L>) -> Point<L> {
        // table[j] = [j]P; table[0] is the identity.
        let mut table = [self.identity(); 16];
        table[1] = *point;
        for i in 2..16 {
            table[i] = self.point_add(&table[i - 1], point);
        }

        let limbs = scalar.as_limbs();
        let mut acc = self.identity();
        let mut i = L;
        while i > 0 {
            i -= 1;
            let limb = limbs[i];
            let mut shift = 64;
            while shift > 0 {
                shift -= 4;
                acc = self.double(&acc);
                acc = self.double(&acc);
                acc = self.double(&acc);
                acc = self.double(&acc);

                let digit = ((limb >> shift) & 0xf) as usize;
                let mut sel = Point::ct_lookup(&table, digit);
                acc = self.point_add(&acc, &sel);
                sel.zeroize();
            }
        }
        // The multiples of `P` are secret whenever the scalar is; do not
        // leave them on the stack.
        table.zeroize();
        acc
    }

    /// `scalar · G`.
    #[inline]
    pub(crate) fn mul_generator(&self, scalar: &Uint<L>) -> Point<L> {
        self.scalar_mul(scalar, &self.generator())
    }

    /// The odd multiples `[1]P, [3]P, …, [15]P` for a width-5 wNAF ladder.
    fn odd_multiples(&self, p: &Point<L>) -> [Point<L>; 8] {
        let two_p = self.double(p);
        let mut table = [*p; 8];
        for i in 1..8 {
            table[i] = self.point_add(&table[i - 1], &two_p);
        }
        table
    }

    /// Adds the wNAF digit `d` (odd, `|d| ≤ 15`, or zero for a no-op) times
    /// the point whose odd multiples are `odd`. **Variable time.**
    #[inline]
    fn add_naf_digit(&self, acc: &Point<L>, d: i8, odd: &[Point<L>; 8]) -> Point<L> {
        if d > 0 {
            self.point_add(acc, &odd[(d as usize - 1) / 2])
        } else if d < 0 {
            self.point_add(acc, &self.negate(&odd[((-d) as usize - 1) / 2]))
        } else {
            *acc
        }
    }

    /// **VARIABLE-TIME** `u1·G + u2·Q`: width-5 wNAF recodings of both
    /// scalars interleaved over one run of doublings (Straus–Shamir), with
    /// zero digits skipped and the tables indexed directly.
    ///
    /// Only for **public** inputs — signature verification and public-key
    /// recovery, where the scalars, the point and the result are all known
    /// to (or computable by) an observer, so timing reveals nothing.
    /// Signing, key derivation and ECDH keep the constant-time
    /// [`Self::scalar_mul`]. Both scalars must be `< n`.
    pub(crate) fn mul_double_vartime(&self, u1: &Uint<L>, u2: &Uint<L>, q: &Point<L>) -> Point<L> {
        let (naf1, len1) = wnaf5(u1);
        let (naf2, len2) = wnaf5(u2);
        let len = len1.max(len2);
        if len == 0 {
            return self.identity();
        }
        let odd_g = self.odd_multiples(&self.generator());
        let odd_q = self.odd_multiples(q);
        let mut acc = self.identity();
        for i in (0..len).rev() {
            acc = self.double(&acc);
            acc = self.add_naf_digit(&acc, naf1[i], &odd_g);
            acc = self.add_naf_digit(&acc, naf2[i], &odd_q);
        }
        acc
    }

    /// **VARIABLE-TIME** test that `point`'s affine x-coordinate is
    /// congruent to `v` modulo the group order (`v < n`), without the field
    /// inversion of [`Self::to_affine`]: `x = X/Z ≡ v (mod n)` with
    /// `x < p < 2n` (cofactor 1, so Hasse gives `n > p/2`) means
    /// `x ∈ {v, v + n}`, and each candidate `c < p` is checked as
    /// `c·Z == X`. The identity never matches. Public inputs only (the
    /// ECDSA / SM2 verification equations).
    pub(crate) fn affine_x_eq_mod_n(&self, point: &Point<L>, v: &Uint<L>) -> bool {
        if bool::from(point.z.is_zero()) {
            return false;
        }
        let check = |c: &Uint<L>| bool::from(self.mul(&self.to_mont(c), &point.z).ct_eq(&point.x));
        if bool::from(ct_lt(v, &self.p)) && check(v) {
            return true;
        }
        let (v_n, carry) = v.adc(&self.n, 0);
        carry == 0 && bool::from(ct_lt(&v_n, &self.p)) && check(&v_n)
    }

    /// Whether affine `(x, y)` (plain residues `< p`) satisfies
    /// `y² = x³ + a·x + b (mod p)`.
    pub(crate) fn is_on_curve(&self, x: &Uint<L>, y: &Uint<L>) -> bool {
        let (xm, ym) = (self.to_mont(x), self.to_mont(y));
        let lhs = self.mul(&ym, &ym);
        bool::from(lhs.ct_eq(&self.rhs_mont(&xm)))
    }

    /// `x³ + a·x + b` in Montgomery form.
    fn rhs_mont(&self, xm: &Uint<L>) -> Uint<L> {
        let x2 = self.mul(xm, xm);
        let x3 = self.mul(&x2, xm);
        let ax = self.mul(&self.a_mont, xm);
        self.add(&self.add(&x3, &ax), &self.b_mont)
    }

    /// Recovers the affine point `(x, y)` with the requested Y parity from a
    /// compressed x-coordinate (`x < p`), or `None` if `x` is not on the
    /// curve. The root of `rhs = x³ + a·x + b` is `rhs^((p+1)/4)` when
    /// `p ≡ 3 (mod 4)` (every curve but P-224 and secp224k1) and a
    /// Tonelli–Shanks root otherwise; either way the result is verified
    /// (`y² == rhs`, which also rejects an `x` that is not a valid abscissa)
    /// and the root of the requested parity is returned (`p − y` flips it).
    /// The x-coordinate of a public key is not secret, so the variable-time
    /// pieces are fine.
    pub(crate) fn decompress(&self, x: &Uint<L>, y_odd: bool) -> Option<(Uint<L>, Uint<L>)> {
        let xm = self.to_mont(x);
        let rhs = self.rhs_mont(&xm);
        let ym = if self.p.as_limbs()[0] & 3 == 3 {
            Self::pow_mont(
                &rhs,
                &self.sqrt_exp,
                self.p_bits,
                |a, b| self.mul(a, b),
                &self.one_mont,
            )
        } else {
            self.sqrt_tonelli_shanks(&rhs)?
        };
        if !bool::from(self.mul(&ym, &ym).ct_eq(&rhs)) {
            return None;
        }
        let y = self.to_plain(&ym);
        if bool::from(y.is_odd()) == y_odd {
            return Some((*x, y));
        }
        // The other root; only `y = 0` has no root of the other parity, and
        // it cannot occur on a curve of odd prime order (no 2-torsion).
        let neg = self.p.wrapping_sub(&y);
        (!bool::from(y.is_zero())).then_some((*x, neg))
    }

    /// Tonelli–Shanks square root of `a` (Montgomery form) modulo `p`, for
    /// any odd `p` (needed for `p ≡ 1 (mod 4)`: P-224 has `p − 1 = 2⁹⁶·q`,
    /// secp224k1 `p ≡ 5 (mod 8)`). Returns `None` when `a` is a
    /// non-residue. Variable-time: the input is a public abscissa and the
    /// loop structure depends only on `p`.
    fn sqrt_tonelli_shanks(&self, a: &Uint<L>) -> Option<Uint<L>> {
        let one = self.one_mont;
        let pow = |b: &Uint<L>, e: &Uint<L>| {
            Self::pow_mont(b, e, self.p_bits, |x, y| self.mul(x, y), &one)
        };
        if bool::from(a.is_zero()) {
            return Some(Uint::ZERO);
        }
        // p − 1 = q · 2^s with q odd.
        let p_minus_1 = self.p.wrapping_sub(&Uint::ONE);
        let mut q = p_minus_1;
        let mut s = 0usize;
        while !bool::from(q.is_odd()) {
            q = q.shr1();
            s += 1;
        }
        // Euler's criterion on `a` first: a^((p−1)/2) must be 1.
        let half = p_minus_1.shr1();
        if pow(a, &half) != one {
            return None;
        }
        // A quadratic non-residue z (the smallest integer works; there is
        // one below 2·ln²p, so the scan is short and depends only on p).
        let mut z = self.to_mont(&Uint::from_u64(2));
        while pow(&z, &half) == one {
            z = self.add(&z, &one);
        }
        let mut c = pow(&z, &q);
        let mut t = pow(a, &q);
        let mut r = pow(a, &q.adc(&Uint::ONE, 0).0.shr1());
        let mut m = s;
        while t != one {
            // Least i in (0, m) with t^(2^i) == 1.
            let mut i = 0usize;
            let mut t2 = t;
            while t2 != one {
                t2 = self.mul(&t2, &t2);
                i += 1;
                if i >= m {
                    return None;
                }
            }
            // b = c^(2^(m − i − 1)).
            let mut b = c;
            for _ in 0..(m - i - 1) {
                b = self.mul(&b, &b);
            }
            m = i;
            c = self.mul(&b, &b);
            t = self.mul(&t, &c);
            r = self.mul(&r, &b);
        }
        Some(r)
    }

    // --- runtime boundary ----------------------------------------------------

    /// A (possibly secret) scalar for the constant-time ladder. One
    /// allocated wider than the curve (never produced in-tree: every scalar
    /// is validated `< n` or reduced) is reduced first so its high limbs are
    /// not silently dropped; that branch is on the public allocation width,
    /// not the value.
    fn narrow_scalar(&self, scalar: &BoxedUint) -> Uint<L> {
        if scalar.limbs() > L {
            narrow::<L>(&scalar.reduce(&widen(&self.n)))
        } else {
            narrow::<L>(scalar)
        }
    }

    #[inline]
    fn from_any(p: &AnyPoint) -> Point<L> {
        let take = |v: &[Limb; MAX_LIMBS]| {
            let mut limbs = [0 as Limb; L];
            limbs.copy_from_slice(&v[..L]);
            Uint::from_limbs(limbs)
        };
        Point {
            x: take(&p.x),
            y: take(&p.y),
            z: take(&p.z),
        }
    }

    #[inline]
    fn to_any(p: &Point<L>) -> AnyPoint {
        let put = |v: &Uint<L>| {
            let mut limbs = [0 as Limb; MAX_LIMBS];
            limbs[..L].copy_from_slice(v.as_limbs());
            limbs
        };
        AnyPoint {
            x: put(&p.x),
            y: put(&p.y),
            z: put(&p.z),
        }
    }
}

/// Width-5 wNAF recoding of `k`, least-significant digit first: digits in
/// `{0, ±1, ±3, …, ±15}`, any two nonzero digits at least five positions
/// apart; returns the digits and the position past the last nonzero one.
/// **Variable time** in `k` — public scalars only. `k` must be below
/// `2^(64·L) − 16` (every group order is), so adding `−d` back never wraps.
fn wnaf5<const L: usize>(k: &Uint<L>) -> ([i8; MAX_NAF], usize) {
    let mut naf = [0i8; MAX_NAF];
    let mut k = *k;
    let mut i = 0;
    while !bool::from(k.is_zero()) {
        if bool::from(k.is_odd()) {
            let low = (k.as_limbs()[0] & 31) as i8;
            let d = if low > 16 { low - 32 } else { low };
            naf[i] = d;
            // k -= d, making the low five bits zero.
            if d > 0 {
                k = k.wrapping_sub(&Uint::from_u64(d as u64));
            } else {
                k = k.wrapping_add(&Uint::from_u64((-d) as u64));
            }
        }
        k = k.shr1();
        i += 1;
    }
    (naf, i)
}

/// A projective point of any supported curve, as seen across the
/// `BoxedUint` API boundary: the coordinates (in the curve's Montgomery
/// form) padded to the widest field. Opaque to callers; only the [`Curve`]
/// that produced it can interpret it.
#[derive(Clone)]
pub(crate) struct AnyPoint {
    x: [Limb; MAX_LIMBS],
    y: [Limb; MAX_LIMBS],
    z: [Limb; MAX_LIMBS],
}

impl Zeroize for AnyPoint {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
        self.z.zeroize();
    }
}

/// A prime-order short-Weierstrass curve, as the runtime-curve layers see
/// it: `BoxedUint` in and out, the arithmetic dispatched to the curve's
/// [`Engine`]. Plain residues everywhere; points are opaque [`AnyPoint`]s.
pub(crate) trait Curve: Sync {
    /// The group order `n`.
    fn order(&self) -> BoxedUint;
    /// The field modulus `p`.
    #[cfg(test)]
    fn field_modulus(&self) -> BoxedUint;
    /// The curve coefficients `(a, b)`. Used by SM2's `ZA` computation,
    /// which hashes the 32-byte big-endian `a`/`b`.
    fn coefficients(&self) -> (BoxedUint, BoxedUint);
    /// The base point's affine coordinates `(gx, gy)`.
    fn generator_affine(&self) -> (BoxedUint, BoxedUint);
    /// `a⁻¹ mod n` via Fermat (`a^(n-2)`, `n` prime), constant time in `a`
    /// (a nonce).
    fn invert_scalar(&self, a: &BoxedUint) -> BoxedUint;
    /// `a·b mod n` for `a, b < n`, constant time.
    fn mul_mod_n(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint;
    /// `a + b mod n` for `a, b < n`, constant time.
    fn add_mod_n(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint;
    /// `a − b mod n` for `a, b < n`, constant time.
    fn sub_mod_n(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint;
    /// The identity point.
    #[cfg(test)]
    fn identity(&self) -> AnyPoint;
    /// Lifts an affine point `(x, y)` (plain coordinates `< p`) to
    /// projective form.
    fn lift_affine(&self, x: &BoxedUint, y: &BoxedUint) -> AnyPoint;
    /// The base point `G`.
    #[cfg(test)]
    fn generator(&self) -> AnyPoint;
    /// Converts a point to affine `(x, y)` (plain coordinates), or `None`
    /// for the identity (a public verdict; see [`Engine::to_affine`]).
    fn to_affine(&self, point: &AnyPoint) -> Option<(BoxedUint, BoxedUint)>;
    /// Recovers the affine point with the requested Y parity from a
    /// compressed x-coordinate, or `None` if `x ≥ p` or not on the curve.
    /// Public inputs only.
    fn decompress(&self, x: &BoxedUint, y_odd: bool) -> Option<(BoxedUint, BoxedUint)>;
    /// Complete projective addition `p + q` (any inputs).
    fn point_add(&self, p: &AnyPoint, q: &AnyPoint) -> AnyPoint;
    /// Constant-time `scalar · point`; `scalar` must fit the curve's limb
    /// width (every scalar `< n` does; a wider allocation is reduced first).
    fn scalar_mul(&self, scalar: &BoxedUint, point: &AnyPoint) -> AnyPoint;
    /// Constant-time `scalar · G`.
    fn mul_generator(&self, scalar: &BoxedUint) -> AnyPoint;
    /// **VARIABLE-TIME** `u1·G + u2·Q` for public `u1, u2 < n`.
    fn mul_double_vartime(&self, u1: &BoxedUint, u2: &BoxedUint, q: &AnyPoint) -> AnyPoint;
    /// **VARIABLE-TIME** `x(point) ≡ v (mod n)` for public inputs, `v < n`.
    fn affine_x_eq_mod_n(&self, point: &AnyPoint, v: &BoxedUint) -> bool;
    /// Whether affine `(x, y)` (each `< p`) lies on the curve.
    fn is_on_curve(&self, x: &BoxedUint, y: &BoxedUint) -> bool;
    /// Whether `v < p` (`v` public).
    fn in_field(&self, v: &BoxedUint) -> bool;

    // Test hooks: the pieces the differential tests need that the library
    // itself does not reach through the trait.
    /// Complete doubling.
    #[cfg(test)]
    fn double(&self, p: &AnyPoint) -> AnyPoint;
    /// The general RCB addition (the oracle for the specialised formulas).
    #[cfg(test)]
    fn add_general(&self, p: &AnyPoint, q: &AnyPoint) -> AnyPoint;
    /// `(λX : λY : λZ)` for a plain residue `λ`.
    #[cfg(test)]
    fn scale(&self, p: &AnyPoint, lambda: &BoxedUint) -> AnyPoint;
    /// `−p`.
    #[cfg(test)]
    fn negate(&self, p: &AnyPoint) -> AnyPoint;
    /// Which RCB formulas the curve's `a` selects.
    #[cfg(test)]
    fn a_kind(&self) -> ACoeff;
}

impl<const L: usize> Curve for Engine<L> {
    fn order(&self) -> BoxedUint {
        widen(&self.n)
    }

    #[cfg(test)]
    fn field_modulus(&self) -> BoxedUint {
        widen(&self.p)
    }

    fn coefficients(&self) -> (BoxedUint, BoxedUint) {
        (widen(&self.a), widen(&self.b))
    }

    fn generator_affine(&self) -> (BoxedUint, BoxedUint) {
        (widen(&self.gx), widen(&self.gy))
    }

    fn invert_scalar(&self, a: &BoxedUint) -> BoxedUint {
        let mut a = narrow::<L>(a);
        let mut inv = self.invert_mod_n(&a);
        let out = widen(&inv);
        a.zeroize();
        inv.zeroize();
        out
    }

    fn mul_mod_n(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        let (mut a, mut b) = (narrow::<L>(a), narrow::<L>(b));
        let mut r = self.mul_mod_n(&a, &b);
        let out = widen(&r);
        a.zeroize();
        b.zeroize();
        r.zeroize();
        out
    }

    fn add_mod_n(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        let (mut a, mut b) = (narrow::<L>(a), narrow::<L>(b));
        let mut r = add_mod(&a, &b, &self.n);
        let out = widen(&r);
        a.zeroize();
        b.zeroize();
        r.zeroize();
        out
    }

    fn sub_mod_n(&self, a: &BoxedUint, b: &BoxedUint) -> BoxedUint {
        let (mut a, mut b) = (narrow::<L>(a), narrow::<L>(b));
        let mut r = sub_mod(&a, &b, &self.n);
        let out = widen(&r);
        a.zeroize();
        b.zeroize();
        r.zeroize();
        out
    }

    #[cfg(test)]
    fn identity(&self) -> AnyPoint {
        Self::to_any(&Engine::identity(self))
    }

    fn lift_affine(&self, x: &BoxedUint, y: &BoxedUint) -> AnyPoint {
        Self::to_any(&Engine::lift_affine(self, &narrow(x), &narrow(y)))
    }

    #[cfg(test)]
    fn generator(&self) -> AnyPoint {
        Self::to_any(&Engine::generator(self))
    }

    fn to_affine(&self, point: &AnyPoint) -> Option<(BoxedUint, BoxedUint)> {
        let mut p = Self::from_any(point);
        let out = Engine::to_affine(self, &p).map(|(mut x, mut y)| {
            let out = (widen(&x), widen(&y));
            x.zeroize();
            y.zeroize();
            out
        });
        p.zeroize();
        out
    }

    fn decompress(&self, x: &BoxedUint, y_odd: bool) -> Option<(BoxedUint, BoxedUint)> {
        let x = narrow_checked::<L>(x)?;
        if !bool::from(ct_lt(&x, &self.p)) {
            return None;
        }
        Engine::decompress(self, &x, y_odd).map(|(x, y)| (widen(&x), widen(&y)))
    }

    fn point_add(&self, p: &AnyPoint, q: &AnyPoint) -> AnyPoint {
        Self::to_any(&Engine::point_add(
            self,
            &Self::from_any(p),
            &Self::from_any(q),
        ))
    }

    fn scalar_mul(&self, scalar: &BoxedUint, point: &AnyPoint) -> AnyPoint {
        let mut k = self.narrow_scalar(scalar);
        let mut p = Self::from_any(point);
        let mut r = Engine::scalar_mul(self, &k, &p);
        let out = Self::to_any(&r);
        k.zeroize();
        p.zeroize();
        r.zeroize();
        out
    }

    fn mul_generator(&self, scalar: &BoxedUint) -> AnyPoint {
        let mut k = self.narrow_scalar(scalar);
        let mut r = Engine::mul_generator(self, &k);
        let out = Self::to_any(&r);
        k.zeroize();
        r.zeroize();
        out
    }

    fn mul_double_vartime(&self, u1: &BoxedUint, u2: &BoxedUint, q: &AnyPoint) -> AnyPoint {
        Self::to_any(&Engine::mul_double_vartime(
            self,
            &narrow(u1),
            &narrow(u2),
            &Self::from_any(q),
        ))
    }

    fn affine_x_eq_mod_n(&self, point: &AnyPoint, v: &BoxedUint) -> bool {
        match narrow_checked::<L>(v) {
            Some(v) => Engine::affine_x_eq_mod_n(self, &Self::from_any(point), &v),
            None => false,
        }
    }

    fn is_on_curve(&self, x: &BoxedUint, y: &BoxedUint) -> bool {
        match (narrow_checked::<L>(x), narrow_checked::<L>(y)) {
            (Some(x), Some(y)) => Engine::is_on_curve(self, &x, &y),
            _ => false,
        }
    }

    fn in_field(&self, v: &BoxedUint) -> bool {
        narrow_checked::<L>(v).is_some_and(|v| bool::from(ct_lt(&v, &self.p)))
    }

    #[cfg(test)]
    fn double(&self, p: &AnyPoint) -> AnyPoint {
        Self::to_any(&Engine::double(self, &Self::from_any(p)))
    }

    #[cfg(test)]
    fn add_general(&self, p: &AnyPoint, q: &AnyPoint) -> AnyPoint {
        Self::to_any(&Engine::add_general(
            self,
            &Self::from_any(p),
            &Self::from_any(q),
        ))
    }

    #[cfg(test)]
    fn scale(&self, p: &AnyPoint, lambda: &BoxedUint) -> AnyPoint {
        let l = self.to_mont(&narrow(lambda));
        let p = Self::from_any(p);
        Self::to_any(&Point {
            x: self.mul(&p.x, &l),
            y: self.mul(&p.y, &l),
            z: self.mul(&p.z, &l),
        })
    }

    #[cfg(test)]
    fn negate(&self, p: &AnyPoint) -> AnyPoint {
        Self::to_any(&Engine::negate(self, &Self::from_any(p)))
    }

    #[cfg(test)]
    fn a_kind(&self) -> ACoeff {
        self.a_kind
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::curves::CurveId;
    use alloc::vec;
    use alloc::vec::Vec;

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A random non-zero residue below `m`.
    fn rand_below(m: &BoxedUint, st: &mut u64) -> BoxedUint {
        loop {
            let limbs = (0..m.limbs()).map(|_| splitmix64(st)).collect();
            let v = BoxedUint::from_limbs(limbs).reduce(m);
            if !v.is_zero() {
                return v;
            }
        }
    }

    /// The same point under a random projective scaling `(λX : λY : λZ)`.
    fn rescale(c: &dyn Curve, p: &AnyPoint, st: &mut u64) -> AnyPoint {
        c.scale(p, &rand_below(&c.field_modulus(), st))
    }

    /// The masked gather returns exactly `table[digit]`.
    #[test]
    fn ct_lookup_selects_the_entry() {
        let f = Engine::<6>::new::<crate::ec::curves::P384Params>();
        let mut st = 0x100c_u64;
        let mut table = [f.identity(); 16];
        let mut acc = f.generator();
        for entry in table.iter_mut().skip(1) {
            acc = f.point_add(&acc, &f.generator());
            let l = Uint::from_limbs([splitmix64(&mut st); 6]);
            *entry = Point {
                x: f.mul(&acc.x, &l),
                y: f.mul(&acc.y, &l),
                z: f.mul(&acc.z, &l),
            };
        }
        for (d, e) in table.iter().enumerate() {
            let got = Point::ct_lookup(&table, d);
            assert!(got.x == e.x && got.y == e.y && got.z == e.z, "digit {d}");
        }
    }

    /// The stack field kernel against the heap Montgomery arithmetic on
    /// every curve: products, sums, differences, inversion and the scalar
    /// ring, including the edge residues `0`, `1` and `m − 1`.
    #[test]
    fn field_and_scalar_ops_match_boxed() {
        use crate::bignum::BoxedMontModulus;
        let mut st = 0xf1e1_u64;
        for &id in CurveId::ALL {
            let c = id.curve();
            let n = c.order();
            let fq = BoxedMontModulus::new(&n);
            let one = BoxedUint::from_u64(1);
            let mut vals = vec![BoxedUint::zero(1), one.clone(), n.sub(&one)];
            for _ in 0..4 {
                vals.push(rand_below(&n, &mut st));
            }
            for a in &vals {
                for b in &vals {
                    assert_eq!(c.mul_mod_n(a, b), fq.mul_mod(a, b), "{id:?} mul");
                    assert_eq!(c.add_mod_n(a, b), fq.add_mod(a, b), "{id:?} add");
                    assert_eq!(c.sub_mod_n(a, b), fq.sub_mod(a, b), "{id:?} sub");
                }
                if !a.is_zero() {
                    let inv = c.invert_scalar(a);
                    assert_eq!(c.mul_mod_n(a, &inv), one, "{id:?} inverse");
                }
            }
            // The field: a random point rescaled by λ then normalised is the
            // same affine point (exercises mul, inversion and conversions).
            let g = c.generator();
            let gl = rescale(c, &g, &mut st);
            assert_eq!(c.to_affine(&gl), c.to_affine(&g), "{id:?} rescale");
            let (gx, gy) = c.generator_affine();
            assert_eq!(c.to_affine(&g), Some((gx, gy)), "{id:?} generator");
        }
    }

    /// The variable-time double-scalar multiplication against the
    /// constant-time ladder, and the inversion-free x-coordinate test
    /// against `to_affine`, on every curve with edge and random scalars.
    #[test]
    fn vartime_double_mul_matches_constant_time() {
        let mut st = 0xd0b1_u64;
        for &id in CurveId::ALL {
            let c = id.curve();
            let n = c.order();
            let one = BoxedUint::from_u64(1);
            let q = c.scalar_mul(&rand_below(&n, &mut st), &c.generator());
            let q = rescale(c, &q, &mut st);
            let mut pairs = vec![
                (BoxedUint::zero(1), BoxedUint::zero(1)),
                (one.clone(), BoxedUint::zero(1)),
                (BoxedUint::zero(1), n.sub(&one)),
                (n.sub(&one), n.sub(&one)),
            ];
            pairs.push((rand_below(&n, &mut st), rand_below(&n, &mut st)));
            for (u1, u2) in &pairs {
                let fast = c.mul_double_vartime(u1, u2, &q);
                let slow = c.point_add(&c.mul_generator(u1), &c.scalar_mul(u2, &q));
                let aff = c.to_affine(&slow);
                assert_eq!(c.to_affine(&fast), aff, "{id:?}");
                // x mod n against the affine value, plus a near miss.
                for v in [BoxedUint::zero(1), one.clone(), n.sub(&one)] {
                    let want = aff.as_ref().is_some_and(|(x, _)| x.reduce(&n) == v);
                    assert_eq!(c.affine_x_eq_mod_n(&fast, &v), want, "{id:?}");
                }
                if let Some((x, _)) = &aff {
                    let v = x.reduce(&n);
                    assert!(c.affine_x_eq_mod_n(&fast, &v), "{id:?}");
                    let off = v.add(&one).reduce(&n);
                    assert!(!c.affine_x_eq_mod_n(&fast, &off), "{id:?}");
                }
            }
        }
    }

    /// A scalar allocated wider than the curve is reduced, not truncated:
    /// `[k + n]P == [k]P` with `k + n` stored in extra limbs.
    #[test]
    fn wide_scalar_is_reduced() {
        let c = CurveId::P224.curve();
        let n = c.order();
        let k = BoxedUint::from_u64(12345);
        let mut limbs = k.add(&n).as_limbs().to_vec();
        limbs.extend_from_slice(&[0, 0, 0]);
        let wide = BoxedUint::from_limbs(limbs);
        assert!(wide.limbs() > 4);
        assert_eq!(
            c.to_affine(&c.mul_generator(&wide)),
            c.to_affine(&c.mul_generator(&k))
        );
    }

    /// wNAF digits reconstruct the scalar and respect the window rules.
    #[test]
    fn wnaf5_reconstructs() {
        let mut st = 0x7a7a_u64;
        for _ in 0..40 {
            let k = Uint::<9>::from_limbs([
                splitmix64(&mut st),
                splitmix64(&mut st),
                splitmix64(&mut st),
                splitmix64(&mut st),
                splitmix64(&mut st),
                splitmix64(&mut st),
                splitmix64(&mut st),
                splitmix64(&mut st),
                splitmix64(&mut st) >> 8,
            ]);
            let (naf, len) = wnaf5(&k);
            assert!(naf[len..].iter().all(|&d| d == 0));
            // Horner from the top digit: acc = 2·acc + d, tracked as
            // (positive part, negative part) to stay unsigned.
            let (mut pos, mut neg) = (Uint::<9>::ZERO, Uint::<9>::ZERO);
            let mut last = None;
            for (i, &d) in naf[..len].iter().enumerate().rev() {
                pos = pos.wrapping_add(&pos);
                neg = neg.wrapping_add(&neg);
                if d != 0 {
                    assert!(d % 2 != 0 && (-15..=15).contains(&d));
                    if let Some(j) = last {
                        assert!(j - i >= 5);
                    }
                    last = Some(i);
                    if d > 0 {
                        pos = pos.wrapping_add(&Uint::from_u64(d as u64));
                    } else {
                        neg = neg.wrapping_add(&Uint::from_u64((-d) as u64));
                    }
                }
            }
            assert_eq!(pos.wrapping_sub(&neg), k);
        }
        assert_eq!(wnaf5(&Uint::<4>::ZERO).1, 0);
    }

    #[test]
    fn coefficient_classes() {
        for (id, kind) in [
            (CurveId::P256, ACoeff::MinusThree),
            (CurveId::P384, ACoeff::MinusThree),
            (CurveId::P521, ACoeff::MinusThree),
            (CurveId::Sm2p256v1, ACoeff::MinusThree),
            (CurveId::Secp256k1, ACoeff::Zero),
            (CurveId::BrainpoolP256r1, ACoeff::General),
        ] {
            assert_eq!(id.curve().a_kind(), kind, "{id:?}");
        }
    }

    /// The specialised RCB formulas (Algorithms 3/4/6/7/9) against the
    /// general complete addition (Algorithm 1), on every curve: identity,
    /// equal, opposite and unrelated points, each under random projective
    /// representatives.
    #[test]
    fn specialised_formulas_match_general_addition() {
        let mut st = 0xadd5_u64;
        for &id in CurveId::ALL {
            let c = id.curve();
            let g = c.generator();
            let mut pts = vec![c.identity(), g.clone()];
            let mut acc = g.clone();
            for _ in 0..6 {
                acc = c.add_general(&c.add_general(&acc, &acc), &g);
                pts.push(rescale(c, &acc, &mut st));
            }
            let negs: Vec<AnyPoint> = pts.iter().map(|p| c.negate(p)).collect();
            pts.extend(negs);
            let aff = |p: &AnyPoint| c.to_affine(p);
            for p in &pts {
                assert_eq!(
                    aff(&c.double(p)),
                    aff(&c.add_general(p, p)),
                    "{id:?} double"
                );
                for q in &pts {
                    let q = rescale(c, q, &mut st);
                    assert_eq!(
                        aff(&c.point_add(p, &q)),
                        aff(&c.add_general(p, &q)),
                        "{id:?} add"
                    );
                }
            }
        }
    }

    /// Point decompression recovers both parities of every small multiple
    /// of `G` and rejects abscissae off the curve, on every curve
    /// (including the Tonelli–Shanks fields of P-224 and secp224k1).
    #[test]
    fn decompress_round_trips() {
        for &id in CurveId::ALL {
            let c = id.curve();
            let p = c.field_modulus();
            let mut acc = c.generator();
            for k in 1..6u64 {
                let (x, y) = c.to_affine(&acc).unwrap();
                let odd = y.is_odd();
                assert_eq!(
                    c.decompress(&x, odd),
                    Some((x.clone(), y.clone())),
                    "{id:?} k={k}"
                );
                let (x2, y2) = c.decompress(&x, !odd).unwrap();
                assert_eq!(x2, x, "{id:?}");
                assert_eq!(y2, p.sub(&y), "{id:?}");
                acc = c.point_add(&acc, &c.generator());
            }
            // x ≥ p is rejected outright; an x off the curve has no root.
            assert_eq!(c.decompress(&p, false), None, "{id:?} x = p");
            let mut misses = 0;
            for x in 0..20u64 {
                if c.decompress(&BoxedUint::from_u64(x), false).is_none() {
                    misses += 1;
                }
            }
            assert!(misses > 0, "{id:?}: every small x had a root");
        }
    }
}
