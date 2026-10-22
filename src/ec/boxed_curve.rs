//! [`BoxedCurve`]: the curve a runtime-curve key lives on — one of the named
//! [`CurveId`]s, or (with the `ec-custom` feature) a prime-field
//! short-Weierstrass curve built from its explicit parameters.
//!
//! A custom curve runs on the same stack engine as the named ones
//! (`weierstrass::Engine`), built at run time instead of compile time, so
//! its scalar multiplications are the same constant-time fixed-window
//! ladder over the complete Renes–Costello–Batina formulas. Those formulas
//! are complete on any subgroup of odd order, which is all a key ever
//! touches: on a curve with cofactor `h > 1`, every point that enters as a
//! public key is checked to lie in the order-`n` subgroup.

use super::Error;
use super::curves::CurveId;
use super::weierstrass::Curve;
use crate::bignum::BoxedUint;
#[cfg(feature = "der")]
use alloc::vec::Vec;
#[cfg(feature = "ec-custom")]
use {
    super::weierstrass::{Engine, MAX_LIMBS},
    crate::bignum::{BoxedMontModulus, Uint},
    alloc::sync::Arc,
};

/// The curve of a runtime-curve key: a named [`CurveId`], or a custom curve
/// from [`from_params`][from_params] (`ec-custom` feature).
///
/// Every `Boxed*` constructor that takes a curve accepts `impl
/// Into<BoxedCurve>`, so a [`CurveId`] can be passed directly. Cloning is
/// cheap (a custom curve is reference-counted).
#[cfg_attr(
    feature = "ec-custom",
    doc = "",
    doc = "[from_params]: BoxedCurve::from_params"
)]
#[cfg_attr(
    not(feature = "ec-custom"),
    doc = "",
    doc = "[from_params]: BoxedCurve"
)]
#[derive(Clone)]
pub struct BoxedCurve(Repr);

#[derive(Clone)]
enum Repr {
    Named(CurveId),
    #[cfg(feature = "ec-custom")]
    Custom(Arc<Custom>),
}

/// A validated custom curve: its parameters, byte widths and engine.
#[cfg(feature = "ec-custom")]
struct Custom {
    p: BoxedUint,
    a: BoxedUint,
    b: BoxedUint,
    gx: BoxedUint,
    gy: BoxedUint,
    n: BoxedUint,
    h: BoxedUint,
    field_len: usize,
    order_len: usize,
    engine: AnyEngine,
}

/// A runtime engine at the limb width the curve needs (two limbs at least,
/// so the smallest curves share the 128-bit code).
#[cfg(feature = "ec-custom")]
enum AnyEngine {
    L2(Engine<2>),
    L3(Engine<3>),
    L4(Engine<4>),
    L5(Engine<5>),
    L6(Engine<6>),
    L7(Engine<7>),
    L8(Engine<8>),
    L9(Engine<9>),
}

#[cfg(feature = "ec-custom")]
impl AnyEngine {
    fn curve(&self) -> &dyn Curve {
        match self {
            AnyEngine::L2(e) => e,
            AnyEngine::L3(e) => e,
            AnyEngine::L4(e) => e,
            AnyEngine::L5(e) => e,
            AnyEngine::L6(e) => e,
            AnyEngine::L7(e) => e,
            AnyEngine::L8(e) => e,
            AnyEngine::L9(e) => e,
        }
    }
}

impl From<CurveId> for BoxedCurve {
    fn from(id: CurveId) -> Self {
        BoxedCurve(Repr::Named(id))
    }
}

impl From<&BoxedCurve> for BoxedCurve {
    fn from(curve: &BoxedCurve) -> Self {
        curve.clone()
    }
}

impl PartialEq for BoxedCurve {
    /// Named curves compare by name, custom curves by their parameters.
    /// [`from_params`][from_params] maps the parameters of a named
    /// curve to that name, so the two never describe the same curve.
    #[cfg_attr(
        feature = "ec-custom",
        doc = "",
        doc = "[from_params]: BoxedCurve::from_params"
    )]
    #[cfg_attr(
        not(feature = "ec-custom"),
        doc = "",
        doc = "[from_params]: BoxedCurve"
    )]
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (Repr::Named(a), Repr::Named(b)) => a == b,
            #[cfg(feature = "ec-custom")]
            (Repr::Custom(a), Repr::Custom(b)) => {
                Arc::ptr_eq(a, b)
                    || (a.p == b.p
                        && a.a == b.a
                        && a.b == b.b
                        && a.gx == b.gx
                        && a.gy == b.gy
                        && a.n == b.n
                        && a.h == b.h)
            }
            #[cfg(feature = "ec-custom")]
            _ => false,
        }
    }
}

impl Eq for BoxedCurve {}

impl PartialEq<CurveId> for BoxedCurve {
    fn eq(&self, other: &CurveId) -> bool {
        self.id() == Some(*other)
    }
}

impl core::fmt::Debug for BoxedCurve {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.0 {
            Repr::Named(id) => id.fmt(f),
            #[cfg(feature = "ec-custom")]
            Repr::Custom(c) => f
                .debug_struct("Custom")
                .field("field_bits", &c.p.bit_len())
                .field("order_bits", &c.n.bit_len())
                .field("cofactor", &c.h)
                .finish(),
        }
    }
}

impl BoxedCurve {
    /// The named curve, or `None` for a custom one.
    pub fn id(&self) -> Option<CurveId> {
        match &self.0 {
            Repr::Named(id) => Some(*id),
            #[cfg(feature = "ec-custom")]
            Repr::Custom(_) => None,
        }
    }

    /// The field-element byte length (see [`CurveId::field_len`]).
    pub fn field_len(&self) -> usize {
        match &self.0 {
            Repr::Named(id) => id.field_len(),
            #[cfg(feature = "ec-custom")]
            Repr::Custom(c) => c.field_len,
        }
    }

    /// The scalar (group-order) byte length (see [`CurveId::order_len`]).
    pub fn order_len(&self) -> usize {
        match &self.0 {
            Repr::Named(id) => id.order_len(),
            #[cfg(feature = "ec-custom")]
            Repr::Custom(c) => c.order_len,
        }
    }

    /// The field modulus `p`.
    pub fn p(&self) -> BoxedUint {
        self.curve().field_modulus()
    }

    /// The coefficients `(a, b)` of `y² = x³ + a·x + b`.
    pub fn coefficients(&self) -> (BoxedUint, BoxedUint) {
        self.curve().coefficients()
    }

    /// The generator's affine coordinates `(x, y)`.
    pub fn generator(&self) -> (BoxedUint, BoxedUint) {
        self.curve().generator_affine()
    }

    /// The (prime) order `n` of the generator.
    pub fn order(&self) -> BoxedUint {
        self.curve().order()
    }

    /// The cofactor `h = #E(F_p) / n` (1 on every named curve).
    pub fn cofactor(&self) -> BoxedUint {
        match &self.0 {
            Repr::Named(_) => BoxedUint::from_u64(1),
            #[cfg(feature = "ec-custom")]
            Repr::Custom(c) => c.h.clone(),
        }
    }

    /// Whether the cofactor is 1, i.e. every point on the curve is in the
    /// generator's group (no subgroup check needed on import, and an
    /// x-coordinate is below `2n`).
    pub(crate) fn cofactor_is_one(&self) -> bool {
        match &self.0 {
            Repr::Named(_) => true,
            #[cfg(feature = "ec-custom")]
            Repr::Custom(c) => c.h == BoxedUint::from_u64(1),
        }
    }

    /// The arithmetic for this curve.
    pub(crate) fn curve(&self) -> &dyn Curve {
        match &self.0 {
            Repr::Named(id) => id.curve(),
            #[cfg(feature = "ec-custom")]
            Repr::Custom(c) => c.engine.curve(),
        }
    }

    /// Whether the on-curve public point `(x, y)` may be used as a key:
    /// always on a cofactor-1 curve, otherwise iff it lies in the order-`n`
    /// subgroup (a point with a small-order component would leak the
    /// private scalar modulo that order through ECDH, and breaks the
    /// completeness of the point formulas).
    pub(crate) fn accepts_point(&self, x: &BoxedUint, y: &BoxedUint) -> bool {
        #[cfg(feature = "ec-custom")]
        if !self.cofactor_is_one() {
            return self.curve().in_subgroup(x, y);
        }
        let _ = (x, y);
        true
    }

    /// `x mod n` for a field element `x < p` (an affine x-coordinate on its
    /// way to becoming the ECDSA `r`): one masked subtraction when the
    /// cofactor is 1 (`p < 2n`), a long division otherwise, whose schedule
    /// depends only on the (public) widths. Constant time in `x` either way.
    pub(crate) fn x_mod_n(&self, x: &BoxedUint, n: &BoxedUint) -> BoxedUint {
        if self.cofactor_is_one() {
            super::boxed::reduce_once(x, n)
        } else {
            x.reduce(n)
        }
    }
}

impl BoxedCurve {
    /// The named curve with exactly these parameters, if any: `Some(Ok)`
    /// for a match with `h = 1`, `Some(Err)` for a match with any other
    /// cofactor (a named curve's cofactor is 1), `None` otherwise.
    fn match_named(
        p: &BoxedUint,
        a: &BoxedUint,
        b: &BoxedUint,
        gx: &BoxedUint,
        gy: &BoxedUint,
        n: &BoxedUint,
        h: &BoxedUint,
    ) -> Option<Result<Self, Error>> {
        let id = CurveId::ALL.iter().copied().find(|id| {
            let c = id.curve();
            c.field_modulus() == *p
                && c.coefficients() == (a.clone(), b.clone())
                && c.generator_affine() == (gx.clone(), gy.clone())
                && c.order() == *n
        })?;
        Some(if *h == BoxedUint::from_u64(1) {
            Ok(id.into())
        } else {
            Err(Error::InvalidInput)
        })
    }
}

/// `prime-field` (`1.2.840.10045.1.1`), the X9.62 `FieldID` type of a curve
/// over `F_p`.
#[cfg(feature = "der")]
const PRIME_FIELD_OID: &[u64] = &[1, 2, 840, 10045, 1, 1];

/// `ECParameters` (RFC 5480 §2.1.1 / SEC 1 v2 §C.2): the curve field of an
/// EC key's `AlgorithmIdentifier` and of a SEC1 `ECPrivateKey`.
#[cfg(feature = "der")]
impl BoxedCurve {
    /// Encodes the curve as a DER `ECParameters`: the `namedCurve` OID for
    /// a named curve, the `specifiedCurve` (SEC 1 `SpecifiedECDomain`,
    /// version 1, no seed, uncompressed base point, cofactor included) for
    /// a custom one — the form OpenSSL writes with `-param_enc explicit`.
    pub fn to_der(&self) -> Vec<u8> {
        match &self.0 {
            Repr::Named(id) => crate::der::oid_tlv(id.named_curve_oid()),
            #[cfg(feature = "ec-custom")]
            Repr::Custom(c) => {
                use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
                let flen = c.field_len;
                let mut base = alloc::vec![0x04];
                base.extend_from_slice(&c.gx.to_be_bytes(flen));
                base.extend_from_slice(&c.gy.to_be_bytes(flen));
                let uint = |v: &BoxedUint| encode_integer(&v.to_be_bytes(v.bit_len().div_ceil(8)));
                encode_sequence(
                    &[
                        encode_integer(&[1]),
                        encode_sequence(&[oid_tlv(PRIME_FIELD_OID), uint(&c.p)].concat()),
                        encode_sequence(
                            &[
                                encode_octet_string(&c.a.to_be_bytes(flen)),
                                encode_octet_string(&c.b.to_be_bytes(flen)),
                            ]
                            .concat(),
                        ),
                        encode_octet_string(&base),
                        uint(&c.n),
                        uint(&c.h),
                    ]
                    .concat(),
                )
            }
        }
    }

    /// Parses a DER `ECParameters`: a `namedCurve` OID this crate knows, or
    /// a `specifiedCurve` over a prime field (versions 1–3; the optional
    /// seed is ignored; the base point must be uncompressed). Explicit
    /// parameters equal to a named curve's yield that [`CurveId`] in every
    /// build; any other explicit curve needs the `ec-custom` feature and
    /// passes the [`from_params`][from_params] validation. A missing
    /// cofactor is recovered as `round((p + 1) / n)`, which Hasse's bound
    /// makes exact once `n > 4√p`.
    ///
    /// Returns [`Error::Malformed`] for a structural error, an unknown OID
    /// or `implicitCurve`, and [`Error::InvalidInput`] for parameters that
    /// fail validation (or need `ec-custom`).
    #[cfg_attr(
        feature = "ec-custom",
        doc = "",
        doc = "[from_params]: BoxedCurve::from_params"
    )]
    #[cfg_attr(
        not(feature = "ec-custom"),
        doc = "",
        doc = "[from_params]: BoxedCurve"
    )]
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        use crate::der::{Reader, parse_oid, tag};
        let mal = |_| Error::Malformed;
        let mut r = Reader::new(der);
        if r.peek_tag() == Some(tag::OID) {
            let arcs = parse_oid(r.read_oid().map_err(mal)?).map_err(mal)?;
            r.finish().map_err(mal)?;
            return CurveId::from_named_curve_oid(&arcs)
                .map(Self::from)
                .ok_or(Error::Malformed);
        }
        let mut seq = r.read_sequence().map_err(mal)?;
        r.finish().map_err(mal)?;
        let version = seq.read_unsigned_integer_bytes().map_err(mal)?;
        if !matches!(version, [1..=3]) {
            return Err(Error::Malformed);
        }
        let mut field = seq.read_sequence().map_err(mal)?;
        let field_type = parse_oid(field.read_oid().map_err(mal)?).map_err(mal)?;
        if field_type.as_slice() != PRIME_FIELD_OID {
            return Err(Error::Malformed);
        }
        let p = BoxedUint::from_be_bytes(field.read_unsigned_integer_bytes().map_err(mal)?);
        field.finish().map_err(mal)?;
        let mut curve = seq.read_sequence().map_err(mal)?;
        let a = BoxedUint::from_be_bytes(curve.read_octet_string().map_err(mal)?);
        let b = BoxedUint::from_be_bytes(curve.read_octet_string().map_err(mal)?);
        if curve.peek_tag() == Some(tag::BIT_STRING) {
            curve.read_any().map_err(mal)?; // seed
        }
        curve.finish().map_err(mal)?;
        let base = seq.read_octet_string().map_err(mal)?;
        let flen = p.bit_len().div_ceil(8);
        let (gx, gy) = match base {
            [0x04, xy @ ..] if xy.len() == 2 * flen => (
                BoxedUint::from_be_bytes(&xy[..flen]),
                BoxedUint::from_be_bytes(&xy[flen..]),
            ),
            _ => return Err(Error::Malformed),
        };
        let n = BoxedUint::from_be_bytes(seq.read_unsigned_integer_bytes().map_err(mal)?);
        let h = if seq.peek_tag() == Some(tag::INTEGER) {
            BoxedUint::from_be_bytes(seq.read_unsigned_integer_bytes().map_err(mal)?)
        } else {
            if n.is_zero() {
                return Err(Error::InvalidInput);
            }
            p.add(&BoxedUint::from_u64(1))
                .add(&n.shr_bits(1))
                .divrem(&n)
                .0
        };
        seq.finish().map_err(mal)?;
        #[cfg(feature = "ec-custom")]
        {
            Self::from_params(&p, &a, &b, &gx, &gy, &n, &h)
        }
        #[cfg(not(feature = "ec-custom"))]
        {
            Self::match_named(&p, &a, &b, &gx, &gy, &n, &h).unwrap_or(Err(Error::InvalidInput))
        }
    }
}

/// The widest field (and order) a custom curve may have: the engine's
/// widest limb width.
#[cfg(feature = "ec-custom")]
const MAX_BITS: usize = 64 * MAX_LIMBS;

/// The narrowest field a custom curve may have. Anything near this is
/// breakable (secp112r1 was broken in 2009); the floor only keeps out
/// curves too small for the engine's two-limb minimum to be meaningful.
#[cfg(feature = "ec-custom")]
const MIN_FIELD_BITS: usize = 64;

/// The embedding-degree bound of the MOV check (SEC 1 v2 §3.1.1.2.1).
#[cfg(feature = "ec-custom")]
const MOV_BOUND: u64 = 100;

/// Miller–Rabin rounds for `p` and `n` (error ≤ 4⁻⁶⁴ for adversarial
/// input), as `DsaParams::Q_MR_ROUNDS`.
#[cfg(feature = "ec-custom")]
const MR_ROUNDS: usize = 64;

#[cfg(feature = "ec-custom")]
impl BoxedCurve {
    /// Builds a curve `y² = x³ + a·x + b` over `F_p` with generator
    /// `G = (gx, gy)` of prime order `n` and cofactor `h`, validating the
    /// parameters per SEC 1 v2 §3.1.1.2.1:
    ///
    /// * `p` is an odd prime of 64 to 576 bits (`p > 3`);
    /// * `a, b, gx, gy < p`, and `4a³ + 27b² ≢ 0 (mod p)` (non-singular);
    /// * `G` is on the curve;
    /// * `n` is a prime with `n > 4√p` (so `h` and the subgroup are
    ///   determined by `n`), and `[n]G = O`;
    /// * `h·n` is within the Hasse interval `|h·n − (p + 1)| ≤ 2√p`;
    /// * `h·n ≠ p` (anomalous curves fall to Smart's attack) and
    ///   `p^k ≢ 1 (mod n)` for `1 ≤ k < 100` (MOV / Frey–Rück).
    ///
    /// The primality tests are probabilistic (64 Miller–Rabin rounds,
    /// deterministic bases derived from the input). Parameters equal to a
    /// named curve's (with `h = 1`) yield that [`CurveId`], which keeps its
    /// fast paths and its named-curve OID. Validation costs a few scalar
    /// multiplications and exponentiations; build a curve once and clone it.
    ///
    /// Returns [`Error::InvalidInput`] if any check fails.
    pub fn from_params(
        p: &BoxedUint,
        a: &BoxedUint,
        b: &BoxedUint,
        gx: &BoxedUint,
        gy: &BoxedUint,
        n: &BoxedUint,
        h: &BoxedUint,
    ) -> Result<Self, Error> {
        use crate::bignum::prime::is_prime_boxed;
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;

        if let Some(named) = Self::match_named(p, a, b, gx, gy, n, h) {
            return named;
        }
        let one = BoxedUint::from_u64(1);
        let (p_bits, n_bits) = (p.bit_len(), n.bit_len());
        if !(MIN_FIELD_BITS..=MAX_BITS).contains(&p_bits) || n_bits > MAX_BITS {
            return Err(Error::InvalidInput);
        }
        if !p.is_odd() || !n.is_odd() || h.is_zero() {
            return Err(Error::InvalidInput);
        }
        if !a.lt(p) || !b.lt(p) || !gx.lt(p) || !gy.lt(p) {
            return Err(Error::InvalidInput);
        }

        // Every value here is public: the variable-time arithmetic is fine.
        let fp = BoxedMontModulus::new(p);
        let mul = |x: &BoxedUint, y: &BoxedUint| fp.mul_mod(&x.reduce(p), &y.reduce(p));
        let add = |x: &BoxedUint, y: &BoxedUint| x.add(y).reduce(p);
        // 4a³ + 27b² ≢ 0.
        let a3 = mul(&mul(a, a), a);
        let disc = add(
            &mul(&BoxedUint::from_u64(4), &a3),
            &mul(&BoxedUint::from_u64(27), &mul(b, b)),
        );
        if disc.is_zero() {
            return Err(Error::InvalidInput);
        }
        // gy² = gx³ + a·gx + b.
        let rhs = add(&add(&mul(&mul(gx, gx), gx), &mul(a, gx)), b);
        if mul(gy, gy) != rhs {
            return Err(Error::InvalidInput);
        }

        // n > 4√p ⇔ n² > 16p.
        if !p.mul(&BoxedUint::from_u64(16)).lt(&n.mul(n)) || n == p {
            return Err(Error::InvalidInput);
        }
        // Hasse: (h·n − (p + 1))² ≤ 4p, and h·n ≠ p.
        let hn = h.mul(n);
        let p1 = p.add(&one);
        let t = if hn.lt(&p1) { p1.sub(&hn) } else { hn.sub(&p1) };
        if p.mul(&BoxedUint::from_u64(4)).lt(&t.mul(&t)) || hn == *p {
            return Err(Error::InvalidInput);
        }
        // MOV: p^k mod n ≠ 1 for small k.
        let fq = BoxedMontModulus::new(n);
        let p_mod_n = p.reduce(n);
        let mut acc = p_mod_n.clone();
        for _ in 1..MOV_BOUND {
            if acc == one {
                return Err(Error::InvalidInput);
            }
            acc = fq.mul_mod(&acc, &p_mod_n);
        }

        let mut rng = HmacDrbg::<Sha256>::new(
            &p.to_be_bytes(p_bits.div_ceil(8)),
            &n.to_be_bytes(n_bits.div_ceil(8)),
            b"purecrypto-ec-custom-mr-bases",
        );
        if !is_prime_boxed(p, &mut rng, MR_ROUNDS) || !is_prime_boxed(n, &mut rng, MR_ROUNDS) {
            return Err(Error::InvalidInput);
        }

        let limbs = p_bits.max(n_bits).div_ceil(64).max(2);
        let engine = match limbs {
            2 => AnyEngine::L2(engine(p, a, b, gx, gy, n)),
            3 => AnyEngine::L3(engine(p, a, b, gx, gy, n)),
            4 => AnyEngine::L4(engine(p, a, b, gx, gy, n)),
            5 => AnyEngine::L5(engine(p, a, b, gx, gy, n)),
            6 => AnyEngine::L6(engine(p, a, b, gx, gy, n)),
            7 => AnyEngine::L7(engine(p, a, b, gx, gy, n)),
            8 => AnyEngine::L8(engine(p, a, b, gx, gy, n)),
            _ => AnyEngine::L9(engine(p, a, b, gx, gy, n)),
        };
        // [n]G = O, through the same strict test public keys get.
        if !engine.curve().in_subgroup(gx, gy) {
            return Err(Error::InvalidInput);
        }
        Ok(BoxedCurve(Repr::Custom(Arc::new(Custom {
            p: p.clone(),
            a: a.clone(),
            b: b.clone(),
            gx: gx.clone(),
            gy: gy.clone(),
            n: n.clone(),
            h: h.clone(),
            field_len: p_bits.div_ceil(8),
            order_len: n_bits.div_ceil(8),
            engine,
        }))))
    }
}

/// The `L`-limb engine for validated parameters (each fits `L` limbs).
#[cfg(feature = "ec-custom")]
fn engine<const L: usize>(
    p: &BoxedUint,
    a: &BoxedUint,
    b: &BoxedUint,
    gx: &BoxedUint,
    gy: &BoxedUint,
    n: &BoxedUint,
) -> Engine<L> {
    let fixed = |v: &BoxedUint| {
        let mut limbs = [0u64; L];
        for (dst, src) in limbs.iter_mut().zip(v.as_limbs()) {
            *dst = *src;
        }
        Uint::<L>::from_limbs(limbs)
    };
    Engine::from_params(fixed(p), fixed(a), fixed(b), fixed(gx), fixed(gy), fixed(n))
}

#[cfg(all(test, feature = "der"))]
mod tests {
    use super::*;
    use crate::ec::BoxedEcdsaPrivateKey;

    /// OpenSSL 3.5 `ecparam -param_enc explicit` output for curves without
    /// a `CurveId` (and two with one: wtls12 is P-224, prime256v1 P-256).
    macro_rules! params {
        ($($name:literal),* $(,)?) => {
            [$(($name, include_bytes!(concat!("../../testdata/ec-explicit/params-", $name, ".der")) as &[u8])),*]
        };
    }
    const PARAMS: [(&str, &[u8]); 24] = params![
        "secp112r1",
        "secp112r2",
        "secp128r1",
        "secp128r2",
        "prime192v2",
        "prime192v3",
        "prime239v1",
        "prime239v2",
        "prime239v3",
        "wtls6",
        "wtls7",
        "wtls8",
        "wtls9",
        "wtls12",
        "brainpoolP160r1",
        "brainpoolP160t1",
        "brainpoolP192r1",
        "brainpoolP192t1",
        "brainpoolP224t1",
        "brainpoolP256t1",
        "brainpoolP320t1",
        "brainpoolP384t1",
        "brainpoolP512t1",
        "prime256v1",
    ];

    /// Explicit parameters equal to a named curve's map to that curve in
    /// every build, `ec-custom` or not.
    #[test]
    fn explicit_named_parameters_map_to_curve_id() {
        let p256 = BoxedCurve::from_der(PARAMS[23].1).unwrap();
        assert_eq!(p256.id(), Some(CurveId::P256));
        let p224 = BoxedCurve::from_der(PARAMS[13].1).unwrap();
        assert_eq!(p224.id(), Some(CurveId::P224));
        // A key OpenSSL wrote with explicit P-256 parameters loads as a
        // P-256 key, and re-encodes with the named-curve OID.
        let key = BoxedEcdsaPrivateKey::from_sec1_pem(include_str!(
            "../../testdata/ec-explicit/key-prime256v1-explicit.pem"
        ))
        .unwrap();
        assert_eq!(key.curve(), CurveId::P256);
        let der = key.to_sec1_der();
        assert_eq!(
            BoxedEcdsaPrivateKey::from_sec1_der(&der).unwrap().curve(),
            CurveId::P256
        );
        // Without `ec-custom`, any other explicit curve is refused.
        #[cfg(not(feature = "ec-custom"))]
        assert_eq!(
            BoxedCurve::from_der(PARAMS[0].1).err(),
            Some(Error::InvalidInput)
        );
    }

    #[cfg(feature = "ec-custom")]
    mod custom {
        use super::*;
        use crate::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPublicKey, BoxedEcdsaSignature};
        use crate::hash::{Digest, Sha256};
        use crate::rng::HmacDrbg;

        fn curve(name: &str) -> BoxedCurve {
            let der = PARAMS.iter().find(|(n, _)| *n == name).unwrap().1;
            BoxedCurve::from_der(der).unwrap()
        }

        #[test]
        fn explicit_curves_sign_verify_and_agree() {
            let mut rng = HmacDrbg::<Sha256>::new(b"ec-custom", b"n", &[]);
            for (name, der) in PARAMS {
                let c = BoxedCurve::from_der(der).unwrap();
                // wtls12 is P-224 and wtls7 secp160r2 (`legacy-ec`).
                let named = matches!(name, "wtls12" | "prime256v1")
                    || (cfg!(feature = "legacy-ec") && name == "wtls7");
                if named {
                    assert!(c.id().is_some(), "{name}");
                    continue;
                }
                assert_eq!(c.id(), None, "{name}");
                let expect_h = if name.ends_with("r2") && name.starts_with("secp1") {
                    4
                } else {
                    1
                };
                assert_eq!(c.cofactor(), BoxedUint::from_u64(expect_h), "{name}");
                assert_eq!(c.field_len(), c.p().bit_len().div_ceil(8), "{name}");
                assert_eq!(c.order_len(), c.order().bit_len().div_ceil(8), "{name}");

                // Re-encoding is canonical (no seed) and parses back to an
                // equal curve; rebuilding from the accessors agrees too.
                let again = BoxedCurve::from_der(&c.to_der()).unwrap();
                assert_eq!(again, c, "{name}");
                let (a, b) = c.coefficients();
                let (gx, gy) = c.generator();
                let rebuilt =
                    BoxedCurve::from_params(&c.p(), &a, &b, &gx, &gy, &c.order(), &c.cofactor())
                        .unwrap();
                assert_eq!(rebuilt, c, "{name}");

                let sk = BoxedEcdsaPrivateKey::generate(&c, &mut rng);
                assert_eq!(sk.named_curve(), None);
                assert_eq!(sk.boxed_curve(), &c);
                let pk = sk.public_key();
                let sig = sk.sign::<Sha256>(b"msg").unwrap();
                pk.verify::<Sha256>(b"msg", &sig).unwrap();
                assert!(pk.verify::<Sha256>(b"msh", &sig).is_err(), "{name}");
                let der_sig = sig.to_der(&c);
                let back = BoxedEcdsaSignature::from_der_for_curve(&der_sig, &c).unwrap();
                pk.verify::<Sha256>(b"msg", &back).unwrap();
                // SEC1 point round trip, compressed and not.
                let sec1 = pk.to_sec1();
                let pk2 = BoxedEcdsaPublicKey::from_sec1(&c, &sec1).unwrap();
                assert_eq!(pk2.to_sec1(), sec1, "{name}");
                let mut compressed = sec1[..1 + c.field_len()].to_vec();
                compressed[0] = 0x02 | (sec1[sec1.len() - 1] & 1);
                let pk3 = BoxedEcdsaPublicKey::from_sec1(&c, &compressed).unwrap();
                assert_eq!(pk3.to_sec1(), sec1, "{name}");
                // Key files round-trip with explicit parameters.
                let sk2 = BoxedEcdsaPrivateKey::from_sec1_der(&sk.to_sec1_der()).unwrap();
                assert_eq!(sk2.boxed_curve(), &c, "{name}");
                assert_eq!(sk2.public_key().to_sec1(), sec1, "{name}");
                let sk3 = BoxedEcdsaPrivateKey::from_pkcs8_der(&sk.to_pkcs8_der()).unwrap();
                assert_eq!(sk3.public_key().to_sec1(), sec1, "{name}");

                let alice = BoxedEcdhPrivateKey::generate(&c, &mut rng);
                let bob = BoxedEcdhPrivateKey::generate(&c, &mut rng);
                let s1 = alice.diffie_hellman(&bob.public_key()).unwrap();
                let s2 = bob.diffie_hellman(&alice.public_key()).unwrap();
                assert_eq!(s1, s2, "{name}");
                assert_eq!(s1.len(), c.field_len(), "{name}");
                // A key on another curve is refused.
                let other = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut rng);
                assert!(alice.diffie_hellman(&other.public_key()).is_err());
            }
        }

        /// Signatures OpenSSL made with explicit-parameter keys verify, and
        /// the keys load from SEC1 (with the seed OpenSSL includes) and
        /// PKCS#8.
        #[test]
        fn openssl_explicit_keys_and_signatures() {
            let msg = include_bytes!("../../testdata/ec-explicit/msg.txt");
            let cases: [(&str, &str, &[u8]); 5] = [
                (
                    "secp112r2",
                    include_str!("../../testdata/ec-explicit/key-secp112r2.pem"),
                    include_bytes!("../../testdata/ec-explicit/sig-secp112r2.der"),
                ),
                (
                    "secp128r1",
                    include_str!("../../testdata/ec-explicit/key-secp128r1.pem"),
                    include_bytes!("../../testdata/ec-explicit/sig-secp128r1.der"),
                ),
                (
                    "brainpoolP256t1",
                    include_str!("../../testdata/ec-explicit/key-brainpoolP256t1.pem"),
                    include_bytes!("../../testdata/ec-explicit/sig-brainpoolP256t1.der"),
                ),
                (
                    "prime239v1",
                    include_str!("../../testdata/ec-explicit/key-prime239v1.pem"),
                    include_bytes!("../../testdata/ec-explicit/sig-prime239v1.der"),
                ),
                (
                    "wtls8",
                    include_str!("../../testdata/ec-explicit/key-wtls8.pem"),
                    include_bytes!("../../testdata/ec-explicit/sig-wtls8.der"),
                ),
            ];
            for (name, pem, sig) in cases {
                let sk = BoxedEcdsaPrivateKey::from_sec1_pem(pem).unwrap();
                assert_eq!(sk.boxed_curve(), &curve(name), "{name}");
                let pk = sk.public_key();
                let sig = BoxedEcdsaSignature::from_der(sig).unwrap();
                pk.verify::<Sha256>(msg, &sig).unwrap();
                pk.verify_prehash(Sha256::digest(msg).as_ref(), &sig)
                    .unwrap();
                assert!(pk.verify::<Sha256>(b"other", &sig).is_err(), "{name}");
            }
            let p8 = BoxedEcdsaPrivateKey::from_pkcs8_pem(include_str!(
                "../../testdata/ec-explicit/key-brainpoolP256t1.p8.pem"
            ))
            .unwrap();
            let sec1 = BoxedEcdsaPrivateKey::from_sec1_pem(include_str!(
                "../../testdata/ec-explicit/key-brainpoolP256t1.pem"
            ))
            .unwrap();
            assert_eq!(p8.public_key().to_sec1(), sec1.public_key().to_sec1());
        }

        /// ECDH on secp128r2 (cofactor 4) matches OpenSSL `pkeyutl -derive`.
        #[test]
        fn openssl_ecdh_on_cofactor_curve() {
            let a = BoxedEcdhPrivateKey::from(
                BoxedEcdsaPrivateKey::from_sec1_pem(include_str!(
                    "../../testdata/ec-explicit/key-secp128r2-a.pem"
                ))
                .unwrap(),
            );
            let b = BoxedEcdsaPrivateKey::from_sec1_pem(include_str!(
                "../../testdata/ec-explicit/key-secp128r2-b.pem"
            ))
            .unwrap();
            let shared = a.diffie_hellman(&b.public_key()).unwrap();
            assert_eq!(
                shared,
                include_bytes!("../../testdata/ec-explicit/ecdh-secp128r2.bin")
            );
        }

        /// On a cofactor-4 curve, a point on the curve but outside the
        /// generator's subgroup is refused as a public key.
        #[test]
        fn cofactor_curve_rejects_points_outside_subgroup() {
            let c = curve("secp112r2");
            let e = c.curve();
            let flen = c.field_len();
            let (mut inside, mut outside) = (0, 0);
            for x in 1u64..200 {
                let Some((x, y)) = e.decompress(&BoxedUint::from_u64(x), false) else {
                    continue;
                };
                let mut sec1 = alloc::vec![0x04];
                sec1.extend_from_slice(&x.to_be_bytes(flen));
                sec1.extend_from_slice(&y.to_be_bytes(flen));
                let in_group = e.in_subgroup(&x, &y);
                // [h]P is always in the subgroup.
                let hp = e
                    .to_affine(&e.scalar_mul(&c.cofactor(), &e.lift_affine(&x, &y)))
                    .unwrap();
                assert!(e.in_subgroup(&hp.0, &hp.1));
                match BoxedEcdsaPublicKey::from_sec1(&c, &sec1) {
                    Ok(_) => {
                        assert!(in_group);
                        inside += 1;
                    }
                    Err(err) => {
                        assert_eq!(err, Error::InvalidInput);
                        assert!(!in_group);
                        outside += 1;
                    }
                }
            }
            // About a quarter of the curve's points are in the subgroup.
            assert!(inside > 0 && outside > inside, "{inside} / {outside}");
        }

        /// Public-key recovery cannot describe `R.x = r + j·n` for `j > 1`,
        /// so it is refused on a cofactor curve, but still works on a
        /// cofactor-1 custom curve.
        #[test]
        fn recovery_needs_cofactor_one() {
            let mut rng = HmacDrbg::<Sha256>::new(b"ec-custom-recover", b"n", &[]);
            let c4 = curve("secp112r2");
            let sk = BoxedEcdsaPrivateKey::generate(&c4, &mut rng);
            assert_eq!(
                sk.sign_recoverable::<Sha256>(b"m").err(),
                Some(Error::InvalidInput)
            );
            let c1 = curve("brainpoolP192t1");
            let sk = BoxedEcdsaPrivateKey::generate(&c1, &mut rng);
            let (sig, recid) = sk.sign_recoverable::<Sha256>(b"m").unwrap();
            let pk = sig.recover::<Sha256>(&c1, b"m", recid).unwrap();
            assert_eq!(pk.to_sec1(), sk.public_key().to_sec1());
        }

        #[test]
        fn every_named_curve_maps_back_to_its_id() {
            for &id in CurveId::ALL {
                let e = id.curve();
                let (a, b) = e.coefficients();
                let (gx, gy) = e.generator_affine();
                let one = BoxedUint::from_u64(1);
                let c =
                    BoxedCurve::from_params(&e.field_modulus(), &a, &b, &gx, &gy, &e.order(), &one)
                        .unwrap();
                assert_eq!(c.id(), Some(id));
                let two = BoxedUint::from_u64(2);
                assert!(
                    BoxedCurve::from_params(&e.field_modulus(), &a, &b, &gx, &gy, &e.order(), &two)
                        .is_err()
                );
            }
        }

        #[test]
        fn invalid_parameters_are_rejected() {
            let c = curve("secp128r1");
            let (p, n, h) = (c.p(), c.order(), c.cofactor());
            let (a, b) = c.coefficients();
            let (gx, gy) = c.generator();
            let one = BoxedUint::from_u64(1);
            let two = BoxedUint::from_u64(2);
            let build =
                |p: &BoxedUint,
                 a: &BoxedUint,
                 b: &BoxedUint,
                 gx: &BoxedUint,
                 gy: &BoxedUint,
                 n: &BoxedUint,
                 h: &BoxedUint| { BoxedCurve::from_params(p, a, b, gx, gy, n, h) };
            assert!(build(&p, &a, &b, &gx, &gy, &n, &h).is_ok());
            // Generator off the curve (b changed).
            assert!(build(&p, &a, &b.add(&one), &gx, &gy, &n, &h).is_err());
            // Coordinates / coefficients not reduced.
            assert!(build(&p, &a.add(&p), &b, &gx, &gy, &n, &h).is_err());
            assert!(build(&p, &a, &b, &gx.add(&p), &gy, &n, &h).is_err());
            // Wrong order: n ± 2 (still odd), and a composite.
            assert!(build(&p, &a, &b, &gx, &gy, &n.add(&two), &h).is_err());
            assert!(build(&p, &a, &b, &gx, &gy, &n.sub(&two), &h).is_err());
            // Wrong cofactor.
            assert!(build(&p, &a, &b, &gx, &gy, &n, &two).is_err());
            assert!(build(&p, &a, &b, &gx, &gy, &n, &BoxedUint::from_u64(0)).is_err());
            // Even / composite modulus.
            assert!(build(&p.add(&one), &a, &b, &gx, &gy, &n, &h).is_err());
            assert!(build(&p.add(&two), &a, &b, &gx, &gy, &n, &h).is_err());
            // Too small, too large.
            let small = BoxedUint::from_u64(0xffff_ffff_ffff_ffc5); // 2^64 − 59, prime
            assert!(build(&small, &one, &one, &one, &one, &small, &one).is_err());
            let big = BoxedUint::from_be_bytes(&[0xff; 73]);
            assert!(build(&big, &a, &b, &gx, &gy, &n, &h).is_err());
            // The order may not be the field size (an anomalous curve).
            assert!(build(&p, &a, &b, &gx, &gy, &p, &one).is_err());
            // A singular curve: y² = x³ (a = b = 0), with a point on it.
            let zero = BoxedUint::from_u64(0);
            assert!(build(&p, &zero, &zero, &one, &one, &n, &h).is_err());
            // A malformed specifiedCurve is a parse error.
            let mut der = c.to_der();
            der.truncate(der.len() - 1);
            assert_eq!(BoxedCurve::from_der(&der), Err(Error::Malformed));
        }
    }
}
