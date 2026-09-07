//! Pedersen commitments over secp256k1, with the second generator `H` and the
//! per-asset generators of Confidential Assets.
//!
//! **EXPERIMENTAL** — no semver-stability guarantee. See the [module-level
//! documentation](super) for the clean-room policy and interop caveats.
//!
//! # Source of truth
//!
//! Confidential Transactions (Maxwell) and *Confidential Assets* (Poelstra,
//! Back, Friedenbach, Maxwell, Wuille, FC 2017).
//!
//! # The commitment
//!
//! A Pedersen commitment to a value `v` under a blinding factor `r` is the
//! curve point
//!
//! ```text
//! C(v, r) = v·H + r·G
//! ```
//!
//! where `G` is the secp256k1 base point and `H` is a second generator whose
//! discrete logarithm with respect to `G` is unknown. The commitment is
//! *perfectly hiding* (for uniform `r`, `C` is uniform on the group and reveals
//! nothing about `v`) and *computationally binding* (opening one `C` to two
//! different values would yield `log_G H`).
//!
//! It is additively homomorphic:
//!
//! ```text
//! C(v₁, r₁) + C(v₂, r₂) = C(v₁ + v₂, r₁ + r₂)
//! ```
//!
//! which is what Confidential Transactions is built on: a verifier who cannot
//! read any amount can still check that a transaction balances, by testing
//! that the inputs minus the outputs minus the (public) fee sum to the point at
//! infinity. That is [`verify_sum`].
//!
//! Homomorphism alone does not make a transaction sound — the values live in
//! `Z/nZ`, so an "output" of `n − 1` behaves like `−1`. Confidential
//! Transactions closes that with a range proof per output, which is the
//! companion `zkp-rangeproof` module. This module deliberately stops at the
//! commitment algebra.
//!
//! # The second generator `H`
//!
//! `H` is chosen nothing-up-my-sleeve, by hashing the encoding of `G` and
//! reading the digest as an x-coordinate:
//!
//! ```text
//! H = lift_x( SHA-256( 0x04 ‖ G.x ‖ G.y ) )
//! ```
//!
//! The hash input is the **65-byte uncompressed SEC1 encoding** of `G`
//! (`0x04` ‖ 32-byte big-endian x ‖ 32-byte big-endian y), and `lift_x` takes
//! the root with **even** `y`, i.e. the point whose compressed SEC1 form is
//! `0x02 ‖ x`. The digest happens to be a valid x-coordinate on the first try,
//! so no counter or increment is involved.
//!
//! The resulting point is hard-coded as [`Generator::H_BYTES`] so that using it
//! costs no hashing, and [`Generator::h`] returns it. The test
//! `h_matches_derivation` re-derives it from `G` and asserts equality, so the
//! constant stays auditable.
//!
//! # Serialization
//!
//! Both commitments and generators serialize to **33 bytes**: a prefix byte
//! followed by the 32-byte big-endian x-coordinate. Confidential Transactions
//! does not reuse SEC1's `0x02`/`0x03`, and the bit it stores is **not** the
//! parity of `y`:
//!
//! | Object       | prefix, `y` a quadratic residue | prefix, `y` a non-residue |
//! |--------------|--------------------------------|---------------------------|
//! | [`Commitment`] | `0x08`                        | `0x09`                    |
//! | [`Generator`]  | `0x0a`                        | `0x0b`                    |
//!
//! So the low bit of the prefix says "`y` is a non-residue", and the upper bits
//! tag the object type — which is what stops a commitment from being parsed as
//! a generator, or either from being mistaken for a SEC1 public key.
//!
//! Because secp256k1's `p ≡ 7 (mod 8)`, the exponent `(p+1)/4` is even, so the
//! principal square root `y = (x³+7)^((p+1)/4)` is *itself* always a quadratic
//! residue. Recovering `y` is therefore: take the principal root, and negate it
//! iff the prefix's low bit is set.
//!
//! # Confidential Assets generators
//!
//! *Confidential Assets* replaces the single `H` with a per-asset generator
//! `H_a`, so that a commitment `v·H_a + r·G` binds to an asset as well as an
//! amount, and the balance check is per asset. `H_a` is derived from a 32-byte
//! asset tag by hashing to the curve — see [`Generator::from_asset_tag`] for
//! the exact construction — and may then be *blinded* as
//!
//! ```text
//! H_a' = H_a + r'·G
//! ```
//!
//! ([`Generator::blinded`]) so that the generator itself does not reveal which
//! asset it belongs to. Blinding shifts the commitment's blinding factor:
//! `v·H_a' + r·G = v·H_a + (v·r' + r)·G`, which is why balancing a
//! blinded-generator transaction needs
//! [`last_blind_with_generator_blinds`] rather than plain [`last_blind`].
//!
//! # Constant time
//!
//! Values and blinding factors are secret. Scalar arithmetic and scalar
//! multiplication go through the constant-time
//! [`secp256k1`](crate::ec::secp256k1) hazmat layer, the `u64` value is widened
//! to a full scalar and multiplied with the same 256-bit ladder regardless of
//! its magnitude, and the hash-to-curve candidate selection uses constant-time
//! selects rather than branches. Blinding factors held in local buffers are
//! wiped with a [`core::hint::black_box`] barrier.
//!
//! Parsing branches on attacker-supplied bytes, which are public by
//! construction, and never panics: every 33-byte input either parses or returns
//! an error.
//!
//! # Interop
//!
//! **Verified byte-for-byte** against the `secp256k1-zkp` black-box oracle
//! (driven through `include/secp256k1_generator.h` only — see
//! `tools/zkp-interop/README.md`), from the vectors committed at
//! `tools/zkp-interop/vectors/pedersen.json`:
//!
//! * `secp256k1_generator_h` equals [`Generator::H_BYTES`].
//! * 12 commitments over `H` (`secp256k1_pedersen_commit`), including
//!   `v = 0` and `v = 2⁶⁴−1`.
//! * 64 asset generators (`secp256k1_generator_generate`).
//! * 16 blinded asset generators (`secp256k1_generator_generate_blinded`).
//! * 8 commitments against per-asset generators.
//! * 5 blind sums (`secp256k1_pedersen_blind_sum`) and 4 generator-blind sums
//!   (`secp256k1_pedersen_blind_generator_blind_sum`).
//! * 102 malformed 33-byte encodings that the oracle rejects and so do we.
//!
//! The crate's tests read that JSON; they never link against the oracle.
//!
//! **Not verified.** The behaviour when a `SHA-256` output used as a
//! hash-to-curve input is `≥ p` (probability ≈ 2⁻²²⁴ per hash, so unreachable
//! in practice): this module reduces it modulo `p`, and no vector exercises
//! that path. Nothing else in the wire format is left unchecked.

use crate::bignum::{MontModulus, Uint};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use crate::ec::Error;
use crate::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use crate::hash::sha256;

// =====================================================================
// Constants
// =====================================================================

/// Decodes a 64-character hex literal at compile time.
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    assert!(b.len() == 64, "expected a 64-character hex literal");
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_digit(b[2 * i]) << 4) | hex_digit(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// Decodes a 66-character hex literal at compile time.
const fn hex33(s: &str) -> [u8; 33] {
    let b = s.as_bytes();
    assert!(b.len() == 66, "expected a 66-character hex literal");
    let mut out = [0u8; 33];
    let mut i = 0;
    while i < 33 {
        out[i] = (hex_digit(b[2 * i]) << 4) | hex_digit(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// Maps one lowercase hex digit to its value.
const fn hex_digit(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("invalid hex digit"),
    }
}

/// The base field prime `p = 2²⁵⁶ − 2³² − 977`.
const P_BYTES: [u8; 32] = hex32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

/// `(p + 1) / 4`, the square-root exponent for `p ≡ 3 (mod 4)`.
const SQRT_EXP_BYTES: [u8; 32] =
    hex32("3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c");

/// `√-3 mod p`, the principal (quadratic-residue) root. Used by the
/// Shallue–van de Woestijne map; see [`Generator::from_asset_tag`].
const SQRT_MINUS3_BYTES: [u8; 32] =
    hex32("0a2d2ba93507f1df233770c2a797962cc61f6d15da14ecd47d8d27ae1cd5f852");

/// `(√-3 − 1) / 2 mod p`, the `ζ` constant of the Shallue–van de Woestijne map.
const SVDW_D_BYTES: [u8; 32] =
    hex32("851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40");

/// Prefix byte of a serialized [`Commitment`] whose `y` is a quadratic residue.
const COMMITMENT_TAG: u8 = 0x08;
/// Prefix byte of a serialized [`Generator`] whose `y` is a quadratic residue.
const GENERATOR_TAG: u8 = 0x0a;

/// Domain separator for the first Shallue–van de Woestijne input.
const GEN_PREFIX_1: &[u8; 16] = b"1st generation: ";
/// Domain separator for the second Shallue–van de Woestijne input.
const GEN_PREFIX_2: &[u8; 16] = b"2nd generation: ";

// =====================================================================
// Base-field arithmetic (mod p)
// =====================================================================

/// A base-field element, stored as a reduced 256-bit integer.
type Fe = Uint<4>;

/// The secp256k1 base field `GF(p)`.
///
/// A thin wrapper over [`MontModulus`] providing the handful of operations the
/// hash-to-curve map and the point codec need. All of them are constant time.
struct Field {
    m: MontModulus<4>,
}

impl Field {
    /// Builds the field context.
    fn new() -> Field {
        Field {
            m: MontModulus::new(Fe::from_be_bytes(&P_BYTES)),
        }
    }

    /// The modulus `p`.
    fn p(&self) -> &Fe {
        self.m.modulus()
    }

    /// `a + b mod p`.
    fn add(&self, a: &Fe, b: &Fe) -> Fe {
        self.m.add_mod(a, b)
    }

    /// `a − b mod p`.
    fn sub(&self, a: &Fe, b: &Fe) -> Fe {
        self.m.sub_mod(a, b)
    }

    /// `a · b mod p`.
    fn mul(&self, a: &Fe, b: &Fe) -> Fe {
        self.m.mul_mod(a, b)
    }

    /// `a² mod p`.
    fn sqr(&self, a: &Fe) -> Fe {
        self.m.mul_mod(a, a)
    }

    /// `−a mod p`.
    fn neg(&self, a: &Fe) -> Fe {
        self.m.sub_mod(&Fe::ZERO, a)
    }

    /// `a⁻¹ mod p`, or `0` when `a == 0`.
    fn inv(&self, a: &Fe) -> Fe {
        self.m.inv_prime(a)
    }

    /// The principal square root `a^((p+1)/4) mod p`.
    ///
    /// If `a` is a quadratic residue this is a square root of `a`; otherwise
    /// its square is `−a`. Since `p ≡ 7 (mod 8)` the exponent is even, so the
    /// result is always itself a quadratic residue.
    fn sqrt(&self, a: &Fe) -> Fe {
        self.m.pow(a, &Fe::from_be_bytes(&SQRT_EXP_BYTES))
    }

    /// Returns a [`Choice`] that is true iff `a` is a quadratic residue
    /// (counting `0` as one).
    fn is_residue(&self, a: &Fe) -> Choice {
        self.sqrt(&self.sqr(a)).ct_eq(a)
    }

    /// `x³ + 7`, the right-hand side of the curve equation.
    fn curve_rhs(&self, x: &Fe) -> Fe {
        self.add(&self.mul(&self.sqr(x), x), &Fe::from_u64(7))
    }
}

// =====================================================================
// 33-byte point codec
// =====================================================================

/// Builds an [`AffinePoint`] from field coordinates, validating on-curve-ness.
///
/// Goes through the SEC1 decoder because that is the only public constructor;
/// the parity byte selects exactly the `y` supplied here.
fn affine_from_xy(x: &Fe, y: &Fe) -> Result<AffinePoint, Error> {
    let mut y_bytes = [0u8; 32];
    y.write_be_bytes(&mut y_bytes);
    let mut sec1 = [0u8; 33];
    sec1[0] = 0x02 | (y_bytes[31] & 1);
    x.write_be_bytes(&mut sec1[1..]);
    AffinePoint::from_sec1(&sec1)
}

/// Encodes a point in the 33-byte Confidential Transactions form under `tag`
/// (`0x08` for commitments, `0x0a` for generators).
fn serialize_tagged(f: &Field, point: &AffinePoint, tag: u8) -> [u8; 33] {
    let y = Fe::from_be_bytes(&point.y_bytes());
    // Low bit set means "y is a non-residue".
    let bit = f.is_residue(&y).unwrap_u8() ^ 1;
    let mut out = [0u8; 33];
    out[0] = tag | bit;
    out[1..].copy_from_slice(&point.x_bytes());
    out
}

/// Decodes a 33-byte Confidential Transactions point with prefix `tag` or
/// `tag | 1`.
///
/// Rejects any other prefix, an x-coordinate `≥ p`, and an x-coordinate for
/// which `x³ + 7` is not a square. Never panics.
fn parse_tagged(f: &Field, bytes: &[u8; 33], tag: u8) -> Result<AffinePoint, Error> {
    if bytes[0] & !1u8 != tag {
        return Err(Error::Malformed);
    }
    let mut x_bytes = [0u8; 32];
    x_bytes.copy_from_slice(&bytes[1..]);
    let x = Fe::from_be_bytes(&x_bytes);
    if !bool::from(x.ct_lt(f.p())) {
        return Err(Error::InvalidInput);
    }
    let rhs = f.curve_rhs(&x);
    // The principal root is the residue root; negate it when the prefix asks
    // for the non-residue one.
    let root = f.sqrt(&rhs);
    if !bool::from(f.sqr(&root).ct_eq(&rhs)) {
        return Err(Error::InvalidInput);
    }
    if bool::from(root.is_zero()) {
        // y = 0 would be a point of order two; secp256k1's group order is an
        // odd prime, so no such point exists. Defensive.
        return Err(Error::InvalidInput);
    }
    let y = if bytes[0] & 1 == 1 {
        f.neg(&root)
    } else {
        root
    };
    affine_from_xy(&x, &y)
}

// =====================================================================
// Hash to curve
// =====================================================================

/// The Shallue–van de Woestijne map for `y² = x³ + 7`, in the Fouque–Tibouchi
/// formulation.
///
/// With `c = √-3`, `d = (c − 1)/2`, `wd = 1 + b + t² = 8 + t²` and `wn = c·t`:
///
/// ```text
/// x₁ = d − t·wn/wd        x₂ = −1 − x₁        x₃ = 1 + wd²/(−3·t²)
/// ```
///
/// The first `xᵢ` (in that order) for which `xᵢ³ + 7` is a square is taken; `y`
/// is the principal square root, negated iff `t` is odd. The candidate
/// selection is a constant-time select over all three, so nothing about `t`
/// leaks through control flow.
///
/// # Errors
/// [`Error::InvalidInput`] if none of the three candidates is on the curve,
/// which the construction makes impossible for any field element.
fn shallue_van_de_woestijne(f: &Field, t: &Fe) -> Result<(Fe, Fe), Error> {
    let c = Fe::from_be_bytes(&SQRT_MINUS3_BYTES);
    let d = Fe::from_be_bytes(&SVDW_D_BYTES);
    let one = Fe::ONE;

    let t2 = f.sqr(t);
    let wd = f.add(&Fe::from_u64(8), &t2);
    let wn = f.mul(&c, t);

    // x1 = (d·wd − t·wn) / wd
    let x1 = f.mul(&f.sub(&f.mul(&d, &wd), &f.mul(t, &wn)), &f.inv(&wd));
    // x2 = −1 − x1
    let x2 = f.sub(&f.neg(&one), &x1);
    // x3 = 1 + wd² / (−3·t²)
    let x3 = f.add(
        &one,
        &f.mul(&f.sqr(&wd), &f.inv(&f.neg(&f.mul(&Fe::from_u64(3), &t2)))),
    );

    let (r1, ok1) = root_of(f, &x1);
    let (r2, ok2) = root_of(f, &x2);
    let (r3, ok3) = root_of(f, &x3);

    let pick1 = ok1;
    let pick2 = !ok1 & ok2;
    let pick3 = !ok1 & !ok2 & ok3;

    // `conditional_select(a, b, choice)` yields `a` when `choice` is true.
    let mut x = Fe::conditional_select(&x1, &Fe::ZERO, pick1);
    x = Fe::conditional_select(&x2, &x, pick2);
    x = Fe::conditional_select(&x3, &x, pick3);
    let mut y = Fe::conditional_select(&r1, &Fe::ZERO, pick1);
    y = Fe::conditional_select(&r2, &y, pick2);
    y = Fe::conditional_select(&r3, &y, pick3);

    // The sign of y follows the parity of t.
    y = Fe::conditional_select(&f.neg(&y), &y, t.is_odd());

    if bool::from(pick1 | pick2 | pick3) {
        Ok((x, y))
    } else {
        Err(Error::InvalidInput)
    }
}

/// Returns the principal square root of `x³ + 7` and whether it really is a
/// square root (i.e. whether `x` is a valid x-coordinate).
fn root_of(f: &Field, x: &Fe) -> (Fe, Choice) {
    let rhs = f.curve_rhs(x);
    let root = f.sqrt(&rhs);
    let ok = f.sqr(&root).ct_eq(&rhs);
    (root, ok)
}

/// Hashes a 32-byte asset tag to a curve point, per Confidential Assets.
fn hash_to_curve(f: &Field, tag: &[u8; 32]) -> Result<ProjectivePoint, Error> {
    let mut buf = [0u8; 48];
    buf[..16].copy_from_slice(GEN_PREFIX_1);
    buf[16..].copy_from_slice(tag);
    let h1 = sha256(&buf);
    buf[..16].copy_from_slice(GEN_PREFIX_2);
    let h2 = sha256(&buf);
    // The tag is secret in Confidential Assets; do not leave it on the stack.
    buf = [0u8; 48];
    let _ = core::hint::black_box(&buf);

    let t1 = Fe::from_be_bytes(&h1).reduce(f.p());
    let t2 = Fe::from_be_bytes(&h2).reduce(f.p());

    let (x1, y1) = shallue_van_de_woestijne(f, &t1)?;
    let (x2, y2) = shallue_van_de_woestijne(f, &t2)?;
    let p1 = affine_from_xy(&x1, &y1)?.to_projective();
    let p2 = affine_from_xy(&x2, &y2)?.to_projective();
    Ok(p1.add(&p2))
}

// =====================================================================
// Scalars
// =====================================================================

/// Widens a `u64` value into a full group scalar.
///
/// Every `u64` is far below the group order, so this never rejects. The
/// conversion is constant time and the resulting scalar is used with the full
/// 256-bit ladder, so the magnitude of `value` does not affect timing.
pub fn value_scalar(value: u64) -> Scalar {
    let mut bytes = [0u8; 32];
    bytes[24..].copy_from_slice(&value.to_be_bytes());
    Scalar::from_bytes_be_reduce(&bytes)
}

/// Decodes a 32-byte blinding factor, rejecting any value `≥ n`.
fn blind_scalar(blind: &[u8; 32]) -> Result<Scalar, Error> {
    Scalar::from_bytes_be(blind)
}

// =====================================================================
// Generator
// =====================================================================

/// A value generator: a curve point that a [`Commitment`] multiplies its value
/// by.
///
/// Confidential Transactions uses the single fixed generator [`Generator::h`].
/// Confidential Assets uses one generator per asset, derived from the asset tag
/// with [`Generator::from_asset_tag`] and optionally hidden with
/// [`Generator::blinded`].
///
/// A `Generator` is always a valid, non-identity curve point.
#[derive(Clone, Copy)]
pub struct Generator(AffinePoint);

impl Generator {
    /// The fixed second generator `H`, in its 33-byte serialized form.
    ///
    /// `H = lift_x(SHA-256(0x04 ‖ G.x ‖ G.y))` taking the even-`y` root; that
    /// `y` is a quadratic non-residue, hence the `0x0b` prefix. The test
    /// `h_matches_derivation` re-derives this constant from `G`.
    pub const H_BYTES: [u8; 33] =
        hex33("0b50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0");

    /// Returns the fixed second generator `H` used by Confidential
    /// Transactions.
    pub fn h() -> Generator {
        let f = Field::new();
        // Infallible: `H_BYTES` is a checked constant. The fallback keeps this
        // panic-free; `h_matches_derivation` asserts it is never taken, since
        // it would make `h()` return `G` rather than `H`.
        match parse_tagged(&f, &Self::H_BYTES, GENERATOR_TAG) {
            Ok(p) => Generator(p),
            Err(_) => Generator(AffinePoint::generator()),
        }
    }

    /// Derives the Confidential Assets generator `H_a` for a 32-byte asset tag.
    ///
    /// The tag is hashed to the curve as
    ///
    /// ```text
    /// H_a = SW( SHA-256("1st generation: " ‖ tag) )
    ///     + SW( SHA-256("2nd generation: " ‖ tag) )
    /// ```
    ///
    /// where each domain separator is exactly 16 ASCII bytes (note the trailing
    /// space), each digest is read as a big-endian integer and reduced modulo
    /// `p`, and `SW` is the Shallue–van de Woestijne map described on
    /// `shallue_van_de_woestijne`. Summing two independent encodings is what
    /// makes the map indifferentiable from a random oracle, so the result has
    /// no known discrete logarithm with respect to `G` or to any other
    /// generator produced this way.
    ///
    /// The derivation is deterministic and constant time in `tag`.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if the two encodings cancel, giving the point at
    /// infinity — cryptographically unreachable.
    pub fn from_asset_tag(tag: &[u8; 32]) -> Result<Generator, Error> {
        let f = Field::new();
        let point = hash_to_curve(&f, tag)?;
        point.to_affine().map(Generator).ok_or(Error::InvalidInput)
    }

    /// Returns the blinded generator `self + blind·G`.
    ///
    /// Confidential Assets publishes `H_a' = H_a + r'·G` in place of `H_a` so
    /// that the generator does not identify the asset. A commitment against the
    /// blinded generator satisfies
    /// `v·H_a' + r·G = v·H_a + (v·r' + r)·G`, so balancing needs
    /// [`last_blind_with_generator_blinds`].
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if `blind` is not a canonical scalar (`≥ n`), or
    /// if the result is the point at infinity.
    pub fn blinded(&self, blind: &[u8; 32]) -> Result<Generator, Error> {
        let r = blind_scalar(blind)?;
        let point = self
            .0
            .to_projective()
            .add(&ProjectivePoint::mul_generator(&r));
        point.to_affine().map(Generator).ok_or(Error::InvalidInput)
    }

    /// Derives `H_a` from `tag` and blinds it in one step; equivalent to
    /// [`from_asset_tag`](Generator::from_asset_tag) followed by
    /// [`blinded`](Generator::blinded).
    ///
    /// # Errors
    /// As the two steps it composes.
    pub fn from_asset_tag_blinded(tag: &[u8; 32], blind: &[u8; 32]) -> Result<Generator, Error> {
        Generator::from_asset_tag(tag)?.blinded(blind)
    }

    /// Parses a 33-byte serialized generator (`0x0a`/`0x0b` prefix).
    ///
    /// # Errors
    /// [`Error::Malformed`] for a prefix other than `0x0a`/`0x0b`, and
    /// [`Error::InvalidInput`] for an x-coordinate `≥ p` or one that is not on
    /// the curve. Never panics, for any input.
    pub fn parse(bytes: &[u8; 33]) -> Result<Generator, Error> {
        let f = Field::new();
        parse_tagged(&f, bytes, GENERATOR_TAG).map(Generator)
    }

    /// Returns the 33-byte serialized generator (`0x0a`/`0x0b` prefix).
    pub fn serialize(&self) -> [u8; 33] {
        let f = Field::new();
        serialize_tagged(&f, &self.0, GENERATOR_TAG)
    }

    /// Returns this generator as a curve point, for protocols built on top of
    /// commitments (range proofs, surjection proofs).
    pub fn as_point(&self) -> ProjectivePoint {
        self.0.to_projective()
    }

    /// Wraps a curve point as a generator.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if `point` is the identity.
    pub fn from_point(point: &ProjectivePoint) -> Result<Generator, Error> {
        point.to_affine().map(Generator).ok_or(Error::InvalidInput)
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Generator) -> Choice {
        self.as_point().ct_eq(&other.as_point())
    }
}

impl PartialEq for Generator {
    fn eq(&self, other: &Generator) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Generator {}

impl core::fmt::Debug for Generator {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Generator(")?;
        for b in self.serialize() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

// =====================================================================
// Commitment
// =====================================================================

/// A Pedersen commitment `C = v·H + r·G` (or `v·H_a + r·G` against a per-asset
/// [`Generator`]).
///
/// A `Commitment` is always a valid, non-identity curve point: the identity has
/// no 33-byte encoding, so the constructors and the homomorphic operations
/// return an error rather than producing one. Use [`sum`] or
/// [`ProjectivePoint`] arithmetic when an intermediate result may legitimately
/// be the identity.
#[derive(Clone, Copy)]
pub struct Commitment(AffinePoint);

impl Commitment {
    /// Commits to `value` under `blind` with the fixed generator `H`.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if `blind` is not a canonical scalar (`≥ n`) or
    /// if the commitment is the point at infinity (only when `value == 0` and
    /// `blind == 0`).
    pub fn new(value: u64, blind: &[u8; 32]) -> Result<Commitment, Error> {
        Commitment::with_generator(value, blind, &Generator::h())
    }

    /// Commits to `value` under `blind` against an arbitrary generator.
    ///
    /// # Errors
    /// As [`new`](Commitment::new).
    pub fn with_generator(
        value: u64,
        blind: &[u8; 32],
        generator: &Generator,
    ) -> Result<Commitment, Error> {
        let r = blind_scalar(blind)?;
        let v = value_scalar(value);
        let point = generator
            .as_point()
            .mul(&v)
            .add(&ProjectivePoint::mul_generator(&r));
        point.to_affine().map(Commitment).ok_or(Error::InvalidInput)
    }

    /// Parses a 33-byte serialized commitment (`0x08`/`0x09` prefix).
    ///
    /// # Errors
    /// [`Error::Malformed`] for a prefix other than `0x08`/`0x09`, and
    /// [`Error::InvalidInput`] for an x-coordinate `≥ p` or one that is not on
    /// the curve. Never panics, for any input.
    pub fn parse(bytes: &[u8; 33]) -> Result<Commitment, Error> {
        let f = Field::new();
        parse_tagged(&f, bytes, COMMITMENT_TAG).map(Commitment)
    }

    /// Returns the 33-byte serialized commitment (`0x08`/`0x09` prefix).
    pub fn serialize(&self) -> [u8; 33] {
        let f = Field::new();
        serialize_tagged(&f, &self.0, COMMITMENT_TAG)
    }

    /// Returns `self + rhs`, the commitment to the sum of the two values under
    /// the sum of the two blinding factors.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if the sum is the point at infinity.
    pub fn add(&self, rhs: &Commitment) -> Result<Commitment, Error> {
        Commitment::from_point(&self.as_point().add(&rhs.as_point()))
    }

    /// Returns `self − rhs`.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if the difference is the point at infinity
    /// (i.e. `self == rhs`).
    pub fn sub(&self, rhs: &Commitment) -> Result<Commitment, Error> {
        Commitment::from_point(&self.as_point().add(&rhs.as_point().negate()))
    }

    /// Returns `−self`, the commitment to the negated value and blinding
    /// factor.
    pub fn negate(&self) -> Commitment {
        // Negating a non-identity point cannot produce the identity.
        match Commitment::from_point(&self.as_point().negate()) {
            Ok(c) => c,
            Err(_) => *self,
        }
    }

    /// Returns this commitment as a curve point.
    pub fn as_point(&self) -> ProjectivePoint {
        self.0.to_projective()
    }

    /// Wraps a curve point as a commitment.
    ///
    /// # Errors
    /// [`Error::InvalidInput`] if `point` is the identity.
    pub fn from_point(point: &ProjectivePoint) -> Result<Commitment, Error> {
        point.to_affine().map(Commitment).ok_or(Error::InvalidInput)
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Commitment) -> Choice {
        self.as_point().ct_eq(&other.as_point())
    }
}

impl PartialEq for Commitment {
    fn eq(&self, other: &Commitment) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Commitment {}

impl core::fmt::Debug for Commitment {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Commitment(")?;
        for b in self.serialize() {
            write!(f, "{b:02x}")?;
        }
        f.write_str(")")
    }
}

// =====================================================================
// Tallies
// =====================================================================

/// Returns the sum of a set of commitments as a curve point (the identity for
/// an empty slice).
pub fn sum(commitments: &[Commitment]) -> ProjectivePoint {
    let mut acc = ProjectivePoint::identity();
    for c in commitments {
        acc = acc.add(&c.as_point());
    }
    acc
}

/// Checks `Σ positive − Σ negative == 0`, the raw Confidential Transactions
/// tally.
///
/// This is the general form: it holds exactly when both the values and the
/// blinding factors of the two sides sum to the same thing, for every generator
/// involved.
pub fn verify_tally(positive: &[Commitment], negative: &[Commitment]) -> bool {
    let lhs = sum(positive);
    let rhs = sum(negative);
    bool::from(lhs.ct_eq(&rhs))
}

/// Checks that a transaction balances: `Σ inputs == Σ outputs + fee·H`.
///
/// `fee` is the explicit, public fee — Confidential Transactions publishes it in
/// the clear so that the tally can close. Returns `true` only if the values and
/// the blinding factors both balance.
///
/// This says nothing about the *ranges* of the committed values: an output
/// committing to a value near the group order behaves like a negative amount
/// and still balances. A range proof per output is what rules that out.
pub fn verify_sum(inputs: &[Commitment], outputs: &[Commitment], fee: u64) -> bool {
    verify_sum_with_generator(inputs, outputs, fee, &Generator::h())
}

/// [`verify_sum`] against an explicit generator, for Confidential Assets, where
/// the fee is denominated in the asset that `generator` represents.
pub fn verify_sum_with_generator(
    inputs: &[Commitment],
    outputs: &[Commitment],
    fee: u64,
    generator: &Generator,
) -> bool {
    let lhs = sum(inputs);
    let fee_point = generator.as_point().mul(&value_scalar(fee));
    let rhs = sum(outputs).add(&fee_point);
    bool::from(lhs.ct_eq(&rhs))
}

// =====================================================================
// Blinding-factor helpers
// =====================================================================

/// Returns `(Σ positive − Σ negative) mod n`.
///
/// # Errors
/// [`Error::InvalidInput`] if any input is not a canonical scalar (`≥ n`).
pub fn blind_sum(positive: &[[u8; 32]], negative: &[[u8; 32]]) -> Result<[u8; 32], Error> {
    let mut acc = Scalar::ZERO;
    for b in positive {
        acc = acc.add(&blind_scalar(b)?);
    }
    for b in negative {
        acc = acc.sub(&blind_scalar(b)?);
    }
    Ok(acc.to_bytes_be())
}

/// Computes the final blinding factor of a transaction so that it balances.
///
/// Given every input blinding factor and every output blinding factor but the
/// last, returns the value `r` for which
/// `Σ inputs == Σ partial_outputs + r`, i.e. `r = Σ inputs − Σ partial_outputs`
/// modulo `n`. Assigning `r` to the remaining output makes
/// [`verify_sum`] succeed, provided the values also balance.
///
/// # Errors
/// [`Error::InvalidInput`] if any input is not a canonical scalar (`≥ n`).
pub fn last_blind(inputs: &[[u8; 32]], partial_outputs: &[[u8; 32]]) -> Result<[u8; 32], Error> {
    blind_sum(inputs, partial_outputs)
}

/// The Confidential Assets form of [`last_blind`], for transactions whose
/// generators are themselves blinded.
///
/// With a published generator `A' = A + r·G`, a commitment `v·A' + r'·G` is
/// really `v·A + (v·r + r')·G`, so it is the quantities `v·r + r'` that must
/// cancel across the transaction. Given the values `v`, the generator blinding
/// factors `r` and the commitment blinding factors `r'` — the first `n_inputs`
/// entries of each being the inputs, which enter the tally negated — this
/// overwrites the **last** entry of `blinding_factors` with the value that
/// drives the total to zero.
///
/// This mirrors `secp256k1_pedersen_blind_generator_blind_sum`.
///
/// # Errors
/// [`Error::InvalidInput`] if the three slices do not have the same non-zero
/// length, if `n_inputs` exceeds it, or if any blinding factor is not a
/// canonical scalar (`≥ n`).
pub fn last_blind_with_generator_blinds(
    values: &[u64],
    generator_blinds: &[[u8; 32]],
    blinding_factors: &mut [[u8; 32]],
    n_inputs: usize,
) -> Result<(), Error> {
    let n = values.len();
    if n == 0
        || generator_blinds.len() != n
        || blinding_factors.len() != n
        || n_inputs > n
        || n_inputs == n
    {
        return Err(Error::InvalidInput);
    }

    let mut total = Scalar::ZERO;
    for i in 0..n {
        let r = blind_scalar(&generator_blinds[i])?;
        let rp = blind_scalar(&blinding_factors[i])?;
        let term = value_scalar(values[i]).mul(&r).add(&rp);
        total = if i < n_inputs {
            total.sub(&term)
        } else {
            total.add(&term)
        };
    }

    let last = blind_scalar(&blinding_factors[n - 1])?.sub(&total);
    blinding_factors[n - 1] = last.to_bytes_be();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// The oracle-generated interop corpus. See `tools/zkp-interop/README.md`.
    const VECTORS: &str = include_str!("../../tools/zkp-interop/vectors/pedersen.json");

    // --- minimal JSON reading (no alloc) ---

    /// Returns the body of the top-level array `"<name>": [ ... ]`.
    fn section<'a>(src: &'a str, name: &str) -> &'a str {
        let mut key = [0u8; 64];
        let n = name.len();
        key[0] = b'"';
        key[1..1 + n].copy_from_slice(name.as_bytes());
        key[1 + n..4 + n].copy_from_slice(b"\": ");
        key[4 + n] = b'[';
        let key = core::str::from_utf8(&key[..5 + n]).unwrap();
        let start = src.find(key).expect("section") + key.len();
        let rest = &src[start..];
        let end = rest.find("\n  ]").expect("section end");
        &rest[..end]
    }

    /// Splits a section body into its `{ ... }` objects.
    fn objects(section: &str) -> impl Iterator<Item = &str> {
        section
            .split('{')
            .skip(1)
            .map(|o| o.split('}').next().unwrap())
    }

    /// Returns the raw token following `"key":` in `obj`.
    fn raw<'a>(obj: &'a str, key: &str) -> &'a str {
        let mut needle = [0u8; 64];
        let n = key.len();
        needle[0] = b'"';
        needle[1..1 + n].copy_from_slice(key.as_bytes());
        needle[1 + n..3 + n].copy_from_slice(b"\":");
        let needle = core::str::from_utf8(&needle[..3 + n]).unwrap();
        let i = obj.find(needle).expect("key") + needle.len();
        obj[i..].trim_start()
    }

    /// Returns the string value of `"key": "..."`.
    fn text<'a>(obj: &'a str, key: &str) -> &'a str {
        let v = raw(obj, key);
        let v = v.strip_prefix('"').expect("string value");
        &v[..v.find('"').expect("string end")]
    }

    /// Returns the integer value of `"key": 123`.
    fn number(obj: &str, key: &str) -> u64 {
        let v = raw(obj, key);
        let end = v.find(|c: char| !c.is_ascii_digit()).unwrap_or(v.len());
        v[..end].parse().expect("number")
    }

    /// Iterates the quoted strings of `"key": ["..", ".."]`.
    fn text_list<'a>(obj: &'a str, key: &str) -> impl Iterator<Item = &'a str> {
        let v = raw(obj, key);
        let v = v.strip_prefix('[').expect("array value");
        let body = &v[..v.find(']').expect("array end")];
        body.split('"').skip(1).step_by(2)
    }

    /// Iterates the integers of `"key": [1, 2]`.
    fn number_list<'a>(obj: &'a str, key: &str) -> impl Iterator<Item = u64> + 'a {
        let v = raw(obj, key);
        let v = v.strip_prefix('[').expect("array value");
        let body = &v[..v.find(']').expect("array end")];
        body.split(',').map(|s| s.trim().parse().expect("number"))
    }

    /// Iterates the bare quoted strings of a section that is a string array.
    fn string_section<'a>(src: &'a str, name: &str) -> impl Iterator<Item = &'a str> {
        section(src, name).split('"').skip(1).step_by(2)
    }

    fn hex33_rt(s: &str) -> [u8; 33] {
        from_hex::<33>(s)
    }

    // --- the constant H ---

    #[test]
    fn h_matches_derivation() {
        // H = lift_x(SHA-256(uncompressed SEC1 encoding of G)), even-y root.
        let g = AffinePoint::generator();
        let digest = sha256(&g.to_sec1_uncompressed());
        let mut sec1 = [0u8; 33];
        sec1[0] = 0x02; // even y
        sec1[1..].copy_from_slice(&digest);
        let derived = AffinePoint::from_sec1(&sec1).expect("digest is a valid x-coordinate");

        let f = Field::new();
        assert_eq!(
            serialize_tagged(&f, &derived, GENERATOR_TAG),
            Generator::H_BYTES,
            "the hard-coded H does not match its derivation from G"
        );
        assert_eq!(Generator::h().serialize(), Generator::H_BYTES);
        // The x-coordinate is the digest itself: no counter/increment.
        assert_eq!(derived.x_bytes(), digest);
    }

    #[test]
    fn field_constants_are_consistent() {
        let f = Field::new();
        let c = Fe::from_be_bytes(&SQRT_MINUS3_BYTES);
        // c² = −3
        assert!(bool::from(f.sqr(&c).ct_eq(&f.neg(&Fe::from_u64(3)))));
        // d = (c − 1)/2
        let d = Fe::from_be_bytes(&SVDW_D_BYTES);
        assert!(bool::from(
            f.add(&d, &d).ct_eq(&f.sub(&c, &Fe::from_u64(1)))
        ));
        // 4·((p+1)/4) == p + 1
        let e = Fe::from_be_bytes(&SQRT_EXP_BYTES);
        let four_e = e.wrapping_add(&e).wrapping_add(&e).wrapping_add(&e);
        assert_eq!(four_e, f.p().wrapping_add(&Fe::ONE));
    }

    #[test]
    fn h_is_not_the_generator() {
        assert_ne!(Generator::h().serialize(), {
            let f = Field::new();
            serialize_tagged(&f, &AffinePoint::generator(), GENERATOR_TAG)
        });
    }

    // --- homomorphism ---

    #[test]
    fn commitments_are_homomorphic() {
        let r1 = from_hex::<32>("1111111111111111111111111111111111111111111111111111111111111111");
        let r2 = from_hex::<32>("2222222222222222222222222222222222222222222222222222222222222222");
        let c1 = Commitment::new(1000, &r1).unwrap();
        let c2 = Commitment::new(337, &r2).unwrap();
        let sum_c = c1.add(&c2).unwrap();

        let r3 = blind_sum(&[r1, r2], &[]).unwrap();
        let expect = Commitment::new(1337, &r3).unwrap();
        assert_eq!(sum_c, expect);

        // and the inverse direction
        assert_eq!(sum_c.sub(&c2).unwrap(), c1);
        assert_eq!(c1.add(&c1.negate()).unwrap_err(), Error::InvalidInput);
    }

    #[test]
    fn zero_value_zero_blind_is_the_identity() {
        assert!(Commitment::new(0, &[0u8; 32]).is_err());
    }

    #[test]
    fn oversized_blind_is_rejected() {
        // n itself, and 0xff..ff
        let n = from_hex::<32>("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
        assert!(Commitment::new(1, &n).is_err());
        assert!(Commitment::new(1, &[0xff; 32]).is_err());
        assert!(blind_sum(&[[0xff; 32]], &[]).is_err());
    }

    // --- verify_sum ---

    #[test]
    fn verify_sum_balanced_and_unbalanced() {
        let ri = [
            from_hex::<32>("0101010101010101010101010101010101010101010101010101010101010101"),
            from_hex::<32>("0202020202020202020202020202020202020202020202020202020202020202"),
        ];
        let inputs = [
            Commitment::new(700, &ri[0]).unwrap(),
            Commitment::new(300, &ri[1]).unwrap(),
        ];
        // outputs: 600 + 390, fee 10
        let ro0 =
            from_hex::<32>("0303030303030303030303030303030303030303030303030303030303030303");
        let ro1 = last_blind(&ri, &[ro0]).unwrap();
        let outputs = [
            Commitment::new(600, &ro0).unwrap(),
            Commitment::new(390, &ro1).unwrap(),
        ];
        assert!(verify_sum(&inputs, &outputs, 10));
        // wrong fee
        assert!(!verify_sum(&inputs, &outputs, 11));
        // wrong value
        let bad = [
            Commitment::new(601, &ro0).unwrap(),
            Commitment::new(390, &ro1).unwrap(),
        ];
        assert!(!verify_sum(&inputs, &bad, 10));
        // right values, wrong blinding factors
        let other =
            from_hex::<32>("0707070707070707070707070707070707070707070707070707070707070707");
        let bad_blind = [
            Commitment::new(600, &other).unwrap(),
            Commitment::new(390, &ro1).unwrap(),
        ];
        assert!(!verify_sum(&inputs, &bad_blind, 10));
    }

    #[test]
    fn verify_sum_rejects_a_u64_overflow() {
        // The classic inflation attempt: two outputs whose u64 sum wraps to the
        // input value. On the curve the values live mod n, so they do not wrap
        // and the tally fails.
        let ri = from_hex::<32>("0404040404040404040404040404040404040404040404040404040404040404");
        let inputs = [Commitment::new(1, &ri).unwrap()];
        let ro0 =
            from_hex::<32>("0505050505050505050505050505050505050505050505050505050505050505");
        let ro1 = last_blind(&[ri], &[ro0]).unwrap();
        let a = u64::MAX;
        let b = 2u64; // a.wrapping_add(b) == 1
        assert_eq!(a.wrapping_add(b), 1);
        let outputs = [
            Commitment::new(a, &ro0).unwrap(),
            Commitment::new(b, &ro1).unwrap(),
        ];
        assert!(!verify_sum(&inputs, &outputs, 0));
    }

    #[test]
    fn verify_tally_matches_verify_sum() {
        let ri = from_hex::<32>("0606060606060606060606060606060606060606060606060606060606060606");
        let ro = last_blind(&[ri], &[]).unwrap();
        let i = [Commitment::new(5, &ri).unwrap()];
        let o = [Commitment::new(5, &ro).unwrap()];
        assert!(verify_tally(&i, &o));
        assert!(verify_sum(&i, &o, 0));
        let o2 = [Commitment::new(6, &ro).unwrap()];
        assert!(!verify_tally(&i, &o2));
    }

    #[test]
    fn empty_tally_is_balanced() {
        assert!(verify_tally(&[], &[]));
        assert!(verify_sum(&[], &[], 0));
        assert!(!verify_sum(&[], &[], 1));
    }

    // --- last_blind ---

    #[test]
    fn last_blind_balances_a_multi_party_transaction() {
        let ri: [[u8; 32]; 3] = [
            from_hex("0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a"),
            from_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
            from_hex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
        ];
        let ro0 =
            from_hex::<32>("0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d");
        let ro1 = last_blind(&ri, &[ro0]).unwrap();
        // Blinds alone must sum to zero.
        assert_eq!(blind_sum(&ri, &[ro0, ro1]).unwrap(), [0u8; 32]);

        let inputs = [
            Commitment::new(10, &ri[0]).unwrap(),
            Commitment::new(20, &ri[1]).unwrap(),
            Commitment::new(30, &ri[2]).unwrap(),
        ];
        let outputs = [
            Commitment::new(25, &ro0).unwrap(),
            Commitment::new(34, &ro1).unwrap(),
        ];
        assert!(verify_sum(&inputs, &outputs, 1));
    }

    // --- asset generators ---

    #[test]
    fn asset_generators_are_deterministic_and_distinct() {
        let a = Generator::from_asset_tag(&[7u8; 32]).unwrap();
        let b = Generator::from_asset_tag(&[7u8; 32]).unwrap();
        let c = Generator::from_asset_tag(&[8u8; 32]).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, Generator::h());
        // round trip
        assert_eq!(Generator::parse(&a.serialize()).unwrap(), a);
        // 0x0a / 0x0b prefix
        assert!(matches!(a.serialize()[0], 0x0a | 0x0b));
    }

    #[test]
    fn blinded_generators_verify() {
        let tag = [0x5au8; 32];
        let blind =
            from_hex::<32>("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        let base = Generator::from_asset_tag(&tag).unwrap();
        let blinded = base.blinded(&blind).unwrap();
        assert_eq!(
            Generator::from_asset_tag_blinded(&tag, &blind).unwrap(),
            blinded
        );
        assert_ne!(blinded, base);

        // H_a' − r'·G == H_a
        let r = Scalar::from_bytes_be(&blind).unwrap();
        let recovered = blinded
            .as_point()
            .add(&ProjectivePoint::mul_generator(&r).negate());
        assert_eq!(Generator::from_point(&recovered).unwrap(), base);
    }

    #[test]
    fn asset_commitments_balance_per_asset() {
        let gold = Generator::from_asset_tag(&[1u8; 32]).unwrap();
        let ri = from_hex::<32>("1010101010101010101010101010101010101010101010101010101010101010");
        let ro = last_blind(&[ri], &[]).unwrap();
        let i = [Commitment::with_generator(50, &ri, &gold).unwrap()];
        let o = [Commitment::with_generator(50, &ro, &gold).unwrap()];
        assert!(verify_sum_with_generator(&i, &o, 0, &gold));
        // The same amounts under a different asset generator do not balance
        // against gold.
        let silver = Generator::from_asset_tag(&[2u8; 32]).unwrap();
        let o2 = [Commitment::with_generator(50, &ro, &silver).unwrap()];
        assert!(!verify_sum_with_generator(&i, &o2, 0, &gold));
    }

    #[test]
    fn generator_blind_sum_balances_blinded_generators() {
        // Two inputs, two outputs, all on the same blinded generator.
        let values = [40u64, 60, 30, 70];
        let gb: [[u8; 32]; 4] = [
            from_hex("2101010101010101010101010101010101010101010101010101010101010101"),
            from_hex("2202020202020202020202020202020202020202020202020202020202020202"),
            from_hex("2303030303030303030303030303030303030303030303030303030303030303"),
            from_hex("2404040404040404040404040404040404040404040404040404040404040404"),
        ];
        let mut bf: [[u8; 32]; 4] = [
            from_hex("3101010101010101010101010101010101010101010101010101010101010101"),
            from_hex("3202020202020202020202020202020202020202020202020202020202020202"),
            from_hex("3303030303030303030303030303030303030303030303030303030303030303"),
            from_hex("3404040404040404040404040404040404040404040404040404040404040404"),
        ];
        last_blind_with_generator_blinds(&values, &gb, &mut bf, 2).unwrap();

        let tag = [0x99u8; 32];
        let base = Generator::from_asset_tag(&tag).unwrap();
        let mut inputs = [Commitment::new(1, &[1u8; 32]).unwrap(); 2];
        let mut outputs = [Commitment::new(1, &[1u8; 32]).unwrap(); 2];
        for i in 0..4 {
            let g = base.blinded(&gb[i]).unwrap();
            let c = Commitment::with_generator(values[i], &bf[i], &g).unwrap();
            if i < 2 {
                inputs[i] = c;
            } else {
                outputs[i - 2] = c;
            }
        }
        // 40 + 60 == 30 + 70, and the (v·r + r') terms cancel by construction.
        assert!(verify_tally(&inputs, &outputs));
    }

    #[test]
    fn generator_blind_sum_rejects_bad_shapes() {
        let mut bf = [[0u8; 32]; 2];
        assert!(last_blind_with_generator_blinds(&[], &[], &mut [], 0).is_err());
        assert!(last_blind_with_generator_blinds(&[1, 2], &[[0u8; 32]; 2], &mut bf, 3).is_err());
        // every element an input leaves nothing to solve for
        assert!(last_blind_with_generator_blinds(&[1, 2], &[[0u8; 32]; 2], &mut bf, 2).is_err());
    }

    // --- parsing ---

    #[test]
    fn commitment_round_trip() {
        let r = from_hex::<32>("4242424242424242424242424242424242424242424242424242424242424242");
        for v in [0u64, 1, 255, u64::MAX] {
            let c = Commitment::new(v, &r).unwrap();
            let enc = c.serialize();
            assert!(matches!(enc[0], 0x08 | 0x09));
            assert_eq!(Commitment::parse(&enc).unwrap(), c);
            // a generator prefix must not open a commitment and vice versa
            assert!(Generator::parse(&enc).is_err());
        }
    }

    #[test]
    fn parse_rejects_bad_prefixes() {
        let valid = Commitment::new(9, &[3u8; 32]).unwrap().serialize();
        let mut buf = valid;
        for p in 0u16..=255 {
            buf[0] = p as u8;
            if !matches!(p, 0x08 | 0x09) {
                assert!(
                    Commitment::parse(&buf).is_err(),
                    "prefix {p:#04x} accepted as a commitment"
                );
            }
            if !matches!(p, 0x0a | 0x0b) {
                assert!(
                    Generator::parse(&buf).is_err(),
                    "prefix {p:#04x} accepted as a generator"
                );
            }
        }
    }

    #[test]
    fn parse_rejects_out_of_range_x() {
        // x = p, x = p + 1 and x = 2²⁵⁶ − 1
        let mut buf = [0u8; 33];
        buf[0] = 0x08;
        buf[1..].copy_from_slice(&P_BYTES);
        assert!(Commitment::parse(&buf).is_err());
        buf[32] = buf[32].wrapping_add(1);
        assert!(Commitment::parse(&buf).is_err());
        buf[1..].copy_from_slice(&[0xffu8; 32]);
        assert!(Commitment::parse(&buf).is_err());
        buf[0] = 0x0b;
        assert!(Generator::parse(&buf).is_err());
    }

    #[test]
    fn parse_rejects_non_residues() {
        // Find a small x with no curve point and check both object types.
        let f = Field::new();
        let mut found = 0;
        for k in 0u64..64 {
            let x = Fe::from_u64(k);
            let rhs = f.curve_rhs(&x);
            let root = f.sqrt(&rhs);
            if bool::from(f.sqr(&root).ct_eq(&rhs)) {
                continue;
            }
            found += 1;
            let mut buf = [0u8; 33];
            x.write_be_bytes(&mut buf[1..]);
            for tag in [0x08u8, 0x09, 0x0a, 0x0b] {
                buf[0] = tag;
                assert!(Commitment::parse(&buf).is_err());
                assert!(Generator::parse(&buf).is_err());
            }
        }
        assert!(found > 0, "expected at least one non-residue below 64");
    }

    #[test]
    fn parsing_never_panics() {
        // Deterministically walk a wide slice of the 33-byte input space.
        let mut buf = [0u8; 33];
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..4096 {
            for b in buf.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = (state >> 24) as u8;
            }
            let _ = Commitment::parse(&buf);
            let _ = Generator::parse(&buf);
            // and with each of the four legal prefixes over random x
            for tag in [0x08u8, 0x09, 0x0a, 0x0b] {
                buf[0] = tag;
                let _ = Commitment::parse(&buf);
                let _ = Generator::parse(&buf);
            }
        }
    }

    // --- interop vectors ---

    #[test]
    fn interop_generator_h() {
        let start = VECTORS.find("\"generator_h\": \"").unwrap() + 16;
        let hex = &VECTORS[start..start + 66];
        assert_eq!(hex33_rt(hex), Generator::H_BYTES);
    }

    #[test]
    fn interop_commitments() {
        let mut count = 0;
        for obj in objects(section(VECTORS, "commitments")) {
            let value = number(obj, "value");
            let blind = from_hex::<32>(text(obj, "blind"));
            let expect = hex33_rt(text(obj, "commitment"));
            let c = Commitment::new(value, &blind).unwrap();
            assert_eq!(c.serialize(), expect, "value {value}");
            assert_eq!(Commitment::parse(&expect).unwrap(), c);
            count += 1;
        }
        assert_eq!(count, 12);
    }

    #[test]
    fn interop_generators() {
        let mut count = 0;
        for obj in objects(section(VECTORS, "generators")) {
            let tag = from_hex::<32>(text(obj, "tag"));
            let expect = hex33_rt(text(obj, "generator"));
            let g = Generator::from_asset_tag(&tag).unwrap();
            assert_eq!(g.serialize(), expect);
            assert_eq!(Generator::parse(&expect).unwrap(), g);
            count += 1;
        }
        assert_eq!(count, 64);
    }

    #[test]
    fn interop_blinded_generators() {
        let mut count = 0;
        for obj in objects(section(VECTORS, "blinded_generators")) {
            let tag = from_hex::<32>(text(obj, "tag"));
            let blind = from_hex::<32>(text(obj, "blind"));
            let expect = hex33_rt(text(obj, "generator"));
            let g = Generator::from_asset_tag_blinded(&tag, &blind).unwrap();
            assert_eq!(g.serialize(), expect);
            count += 1;
        }
        assert_eq!(count, 16);
    }

    #[test]
    fn interop_asset_commitments() {
        let mut count = 0;
        for obj in objects(section(VECTORS, "asset_commitments")) {
            let tag = from_hex::<32>(text(obj, "tag"));
            let value = number(obj, "value");
            let blind = from_hex::<32>(text(obj, "blind"));
            let expect = hex33_rt(text(obj, "commitment"));
            let g = Generator::from_asset_tag(&tag).unwrap();
            let c = Commitment::with_generator(value, &blind, &g).unwrap();
            assert_eq!(c.serialize(), expect);
            count += 1;
        }
        assert_eq!(count, 8);
    }

    #[test]
    fn interop_blind_sums() {
        let mut count = 0;
        for obj in objects(section(VECTORS, "blind_sums")) {
            let npos = number(obj, "npositive") as usize;
            let mut blinds = [[0u8; 32]; 8];
            let mut n = 0;
            for s in text_list(obj, "blinds") {
                blinds[n] = from_hex::<32>(s);
                n += 1;
            }
            let expect = from_hex::<32>(text(obj, "sum"));
            let got = blind_sum(&blinds[..npos], &blinds[npos..n]).unwrap();
            assert_eq!(got, expect);
            count += 1;
        }
        assert_eq!(count, 5);
    }

    #[test]
    fn interop_generator_blind_sums() {
        let mut count = 0;
        for obj in objects(section(VECTORS, "generator_blind_sums")) {
            let n_inputs = number(obj, "n_inputs") as usize;
            let mut values = [0u64; 8];
            let mut n = 0;
            for v in number_list(obj, "values") {
                values[n] = v;
                n += 1;
            }
            let mut gb = [[0u8; 32]; 8];
            for (i, s) in text_list(obj, "generator_blinds").enumerate() {
                gb[i] = from_hex::<32>(s);
            }
            let mut bf = [[0u8; 32]; 8];
            for (i, s) in text_list(obj, "blinding_factors").enumerate() {
                bf[i] = from_hex::<32>(s);
            }
            let expect = from_hex::<32>(text(obj, "last_blind"));
            last_blind_with_generator_blinds(&values[..n], &gb[..n], &mut bf[..n], n_inputs)
                .unwrap();
            assert_eq!(bf[n - 1], expect);
            count += 1;
        }
        assert_eq!(count, 4);
    }

    #[test]
    fn interop_rejections() {
        let mut count = 0;
        for s in string_section(VECTORS, "invalid_commitments") {
            assert!(
                Commitment::parse(&hex33_rt(s)).is_err(),
                "accepted {s}, which the oracle rejects"
            );
            count += 1;
        }
        assert!(count >= 50);
        count = 0;
        for s in string_section(VECTORS, "invalid_generators") {
            assert!(
                Generator::parse(&hex33_rt(s)).is_err(),
                "accepted {s}, which the oracle rejects"
            );
            count += 1;
        }
        assert!(count >= 50);
    }
}
