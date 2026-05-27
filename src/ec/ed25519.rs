//! Ed25519 signatures (EdDSA over edwards25519, RFC 8032).
//!
//! The field is GF(2²⁵⁵−19) — the same prime as X25519 — so the arithmetic
//! reuses the constant-time [`MontModulus`](crate::bignum::MontModulus). Curve
//! points use the twisted Edwards curve `−x² + y² = 1 + d·x²·y²` in extended
//! homogeneous coordinates `(X:Y:Z:T)`, with complete addition formulas
//! (Hisil–Wong–Carter–Dawson 2008), so there are no exceptional cases. Scalar
//! multiplication is a fixed-window-free constant-time double-and-add: every
//! step doubles and conditionally selects the sum, independent of the secret
//! scalar bits. Reduction of scalars modulo the group order `L` rides on the
//! constant-time [`Uint`](crate::bignum::Uint) long division.

use crate::bignum::{MontModulus, Uint};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use crate::ec::Error;
use crate::hash::{Digest, Sha512};
use crate::rng::RngCore;

/// A field element, four 64-bit limbs (256 bits).
type Fe = Uint<4>;

/// `p = 2²⁵⁵ − 19` (big-endian hex).
const P_HEX: &str = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
/// The curve constant `d = −121665/121666 mod p` (big-endian hex).
const D_HEX: &str = "52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3";
/// The group order `L = 2²⁵² + 27742317777372353535851937790883648493`.
const L_HEX: &str = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

/// The standard base point `B`, as its 32-byte RFC 8032 encoding (`y = 4/5`,
/// with an even `x`).
const BASE_ENC: [u8; 32] = {
    let mut b = [0x66u8; 32];
    b[0] = 0x58;
    b
};

/// Parses 64 big-endian hex characters into a field element.
fn fe_from_be_hex(hex: &str) -> Fe {
    let h = hex.as_bytes();
    let mut bytes = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = (h[2 * i] as char).to_digit(16).unwrap() as u8;
        let lo = (h[2 * i + 1] as char).to_digit(16).unwrap() as u8;
        bytes[i] = (hi << 4) | lo;
        i += 1;
    }
    Fe::from_be_bytes(&bytes)
}

/// Modular exponentiation in Montgomery form (`base` and the result are in
/// Montgomery domain). The exponent is public, so the fixed 256-step schedule
/// leaks nothing secret.
fn fe_pow(fp: &MontModulus<4>, one: &Fe, base: Fe, exp: &Fe) -> Fe {
    let mut r = *one;
    let limbs = exp.as_limbs();
    let mut i = 256;
    while i > 0 {
        i -= 1;
        r = fp.mont_mul(&r, &r);
        let bit = ((limbs[i / 64] >> (i % 64)) & 1) as u8;
        let prod = fp.mont_mul(&r, &base);
        // conditional_select(a, b, c) returns a when c is set (this crate's
        // convention): pick `prod` when the exponent bit is 1.
        r = Fe::conditional_select(&prod, &r, Choice::from(bit));
    }
    r
}

/// The edwards25519 field together with the curve constants, all in Montgomery
/// form (except the integer constants `p`, `L`).
struct Field {
    fp: MontModulus<4>,
    /// `1` in Montgomery form.
    one: Fe,
    /// `d` in Montgomery form.
    d: Fe,
    /// `2·d` in Montgomery form (for the addition formula).
    d2: Fe,
    /// `√−1 mod p` in Montgomery form (for point decompression).
    sqrtm1: Fe,
    /// `p − 2` (the Fermat inversion exponent).
    p_minus_2: Fe,
    /// `(p − 5) / 8` (the candidate-root exponent).
    p_minus_5_div_8: Fe,
    /// The prime `p`.
    p: Fe,
    /// The group order `L`.
    l: Fe,
    /// `L` zero-extended to eight limbs, for reducing 512-bit scalars.
    l8: Uint<8>,
}

impl Field {
    fn new() -> Self {
        let p = fe_from_be_hex(P_HEX);
        let fp = MontModulus::new(p);
        let one = fp.to_mont(&Fe::ONE);
        let d = fp.to_mont(&fe_from_be_hex(D_HEX));
        let d2 = fp.add_mod(&d, &d);
        let p_minus_2 = p.wrapping_sub(&Fe::from_u64(2));
        let p_minus_5_div_8 = p.wrapping_sub(&Fe::from_u64(5)).shr1().shr1().shr1();
        let p_minus_1_div_4 = p.wrapping_sub(&Fe::ONE).shr1().shr1();
        // √−1 = 2^((p−1)/4) mod p.
        let two = fp.to_mont(&Fe::from_u64(2));
        let sqrtm1 = fe_pow(&fp, &one, two, &p_minus_1_div_4);
        let l = fe_from_be_hex(L_HEX);
        let ll = l.as_limbs();
        let l8 = Uint::<8>::from_limbs([ll[0], ll[1], ll[2], ll[3], 0, 0, 0, 0]);
        Field {
            fp,
            one,
            d,
            d2,
            sqrtm1,
            p_minus_2,
            p_minus_5_div_8,
            p,
            l,
            l8,
        }
    }

    #[inline]
    fn mul(&self, a: Fe, b: Fe) -> Fe {
        self.fp.mont_mul(&a, &b)
    }
    #[inline]
    fn sq(&self, a: Fe) -> Fe {
        self.fp.mont_mul(&a, &a)
    }
    #[inline]
    fn add(&self, a: Fe, b: Fe) -> Fe {
        self.fp.add_mod(&a, &b)
    }
    #[inline]
    fn sub(&self, a: Fe, b: Fe) -> Fe {
        self.fp.sub_mod(&a, &b)
    }
    #[inline]
    fn neg(&self, a: Fe) -> Fe {
        self.fp.sub_mod(&Fe::ZERO, &a)
    }
    #[inline]
    fn inv(&self, a: Fe) -> Fe {
        fe_pow(&self.fp, &self.one, a, &self.p_minus_2)
    }

    /// The base point `B`, decompressed from its standard encoding.
    fn base(&self) -> Point {
        self.decode(&BASE_ENC).expect("valid base point")
    }

    /// Decompresses a 32-byte point encoding (RFC 8032 §5.1.3), or `None` if the
    /// bytes do not encode a curve point.
    fn decode(&self, enc: &[u8; 32]) -> Option<Point> {
        let sign = (enc[31] >> 7) & 1;
        let mut yb = *enc;
        yb[31] &= 0x7f;
        let yval = Fe::from_le_bytes(&yb);
        if !bool::from(yval.ct_lt(&self.p)) {
            return None;
        }
        let y = self.fp.to_mont(&yval);

        // x² = (y² − 1) / (d·y² + 1) = u / v.
        let yy = self.sq(y);
        let u = self.sub(yy, self.one);
        let v = self.add(self.mul(self.d, yy), self.one);

        // x = u·v³·(u·v⁷)^((p−5)/8), then fix up by √−1 if needed.
        let v3 = self.mul(self.sq(v), v);
        let v7 = self.mul(self.sq(v3), v);
        let pw = fe_pow(&self.fp, &self.one, self.mul(u, v7), &self.p_minus_5_div_8);
        let mut x = self.mul(self.mul(u, v3), pw);

        let vxx = self.mul(v, self.sq(x));
        let ok = bool::from(vxx.ct_eq(&u));
        let alt = bool::from(vxx.ct_eq(&self.neg(u)));
        if !ok && !alt {
            return None;
        }
        if alt {
            x = self.mul(x, self.sqrtm1);
        }

        let xplain = self.fp.from_mont(&x);
        if bool::from(xplain.ct_eq(&Fe::ZERO)) && sign == 1 {
            return None;
        }
        if xplain.is_odd().unwrap_u8() != sign {
            x = self.neg(x);
        }

        let t = self.mul(x, y);
        Some(Point {
            x,
            y,
            z: self.one,
            t,
        })
    }

    /// Compresses a point to its 32-byte encoding.
    fn encode(&self, p: &Point) -> [u8; 32] {
        let zinv = self.inv(p.z);
        let x = self.fp.from_mont(&self.mul(p.x, zinv));
        let y = self.fp.from_mont(&self.mul(p.y, zinv));
        let mut out = [0u8; 32];
        y.write_le_bytes(&mut out);
        out[31] |= x.is_odd().unwrap_u8() << 7;
        out
    }
}

/// A curve point in extended homogeneous coordinates `(X:Y:Z:T)`, all in
/// Montgomery form.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// The neutral element `(0:1:1:0)`.
fn identity(f: &Field) -> Point {
    Point {
        x: Fe::ZERO,
        y: f.one,
        z: f.one,
        t: Fe::ZERO,
    }
}

/// Constant-time point selection: `b` if `c` is set, else `a`. (This crate's
/// `conditional_select(x, y, c)` returns `x` when `c` is set, so the chosen
/// value goes first.)
fn point_select(a: &Point, b: &Point, c: Choice) -> Point {
    Point {
        x: Fe::conditional_select(&b.x, &a.x, c),
        y: Fe::conditional_select(&b.y, &a.y, c),
        z: Fe::conditional_select(&b.z, &a.z, c),
        t: Fe::conditional_select(&b.t, &a.t, c),
    }
}

/// Point addition (add-2008-hwcd-3), complete for `a = −1` since `d` is a
/// non-square on edwards25519.
fn point_add(f: &Field, p: &Point, q: &Point) -> Point {
    let aa = f.mul(f.sub(p.y, p.x), f.sub(q.y, q.x));
    let bb = f.mul(f.add(p.y, p.x), f.add(q.y, q.x));
    let cc = f.mul(f.mul(p.t, f.d2), q.t);
    let dd = f.mul(f.add(p.z, p.z), q.z);
    let e = f.sub(bb, aa);
    let ff = f.sub(dd, cc);
    let g = f.add(dd, cc);
    let h = f.add(bb, aa);
    Point {
        x: f.mul(e, ff),
        y: f.mul(g, h),
        t: f.mul(e, h),
        z: f.mul(ff, g),
    }
}

/// Point doubling (dbl-2008-hwcd) for `a = −1`.
fn point_double(f: &Field, p: &Point) -> Point {
    let a = f.sq(p.x);
    let b = f.sq(p.y);
    let c = f.add(f.sq(p.z), f.sq(p.z));
    let d = f.neg(a);
    let e = f.sub(f.sub(f.sq(f.add(p.x, p.y)), a), b);
    let g = f.add(d, b);
    let ff = f.sub(g, c);
    let h = f.sub(d, b);
    Point {
        x: f.mul(e, ff),
        y: f.mul(g, h),
        t: f.mul(e, h),
        z: f.mul(ff, g),
    }
}

/// Constant-time `[scalar]·p`, scanning the 256-bit little-endian scalar from
/// the most significant bit.
fn scalar_mult(f: &Field, scalar: &[u8; 32], p: &Point) -> Point {
    let mut acc = identity(f);
    let mut i = 256;
    while i > 0 {
        i -= 1;
        acc = point_double(f, &acc);
        let bit = (scalar[i / 8] >> (i % 8)) & 1;
        let sum = point_add(f, &acc, p);
        acc = point_select(&acc, &sum, Choice::from(bit));
    }
    acc
}

/// Joins low/high 256-bit halves into a 512-bit integer.
fn join(lo: &Fe, hi: &Fe) -> Uint<8> {
    let a = lo.as_limbs();
    let b = hi.as_limbs();
    Uint::from_limbs([a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]])
}

/// Zero-extends a 256-bit integer to 512 bits.
fn widen(a: &Fe) -> Uint<8> {
    let l = a.as_limbs();
    Uint::from_limbs([l[0], l[1], l[2], l[3], 0, 0, 0, 0])
}

/// Truncates a 512-bit integer to its low 256 bits.
fn narrow(a: &Uint<8>) -> Fe {
    let l = a.as_limbs();
    Uint::from_limbs([l[0], l[1], l[2], l[3]])
}

/// Reduces a 64-byte little-endian integer modulo `L`.
fn scalar_reduce_wide(bytes: &[u8; 64], l8: &Uint<8>) -> Fe {
    narrow(&Uint::<8>::from_le_bytes(bytes).reduce(l8))
}

/// Computes `(r + k·a) mod L`.
fn scalar_muladd(r: &Fe, k: &Fe, a: &Fe, l8: &Uint<8>) -> Fe {
    let (lo, hi) = k.mul_wide(a);
    let (sum, _) = join(&lo, &hi).adc(&widen(r), 0);
    narrow(&sum.reduce(l8))
}

/// Clamps the lower half of the seed hash into the secret scalar (RFC 8032).
fn clamp(b: &mut [u8; 32]) {
    b[0] &= 248;
    b[31] &= 127;
    b[31] |= 64;
}

/// The `id-Ed25519` OID (1.3.101.112), used for both the key and the signature
/// algorithm (RFC 8410).
#[cfg(feature = "der")]
pub(crate) const ED25519_OID: &[u64] = &[1, 3, 101, 112];

/// An Ed25519 private key — a 32-byte seed.
#[derive(Clone)]
pub struct Ed25519PrivateKey {
    seed: [u8; 32],
}

/// An Ed25519 public key — a 32-byte compressed point.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Ed25519PublicKey([u8; 32]);

/// An Ed25519 signature — 64 bytes (`R ‖ S`).
#[derive(Clone, Copy)]
pub struct Ed25519Signature([u8; 64]);

impl Ed25519PrivateKey {
    /// Generates a new private key from `rng`.
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Ed25519PrivateKey { seed }
    }

    /// Creates a private key from its 32-byte seed.
    pub fn from_bytes(seed: [u8; 32]) -> Self {
        Ed25519PrivateKey { seed }
    }

    /// The 32-byte seed.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    /// Derives the secret scalar `a` (clamped) and the signing prefix from the
    /// seed hash.
    fn expand(&self) -> ([u8; 32], [u8; 32]) {
        let h = Sha512::digest(&self.seed);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        clamp(&mut a);
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);
        (a, prefix)
    }

    /// The corresponding public key `A = [a]B`.
    pub fn public_key(&self) -> Ed25519PublicKey {
        let f = Field::new();
        let (a, _) = self.expand();
        Ed25519PublicKey(f.encode(&scalar_mult(&f, &a, &f.base())))
    }

    /// Signs `message`, returning the 64-byte signature (RFC 8032 §5.1.6).
    pub fn sign(&self, message: &[u8]) -> Ed25519Signature {
        let f = Field::new();
        let (a, prefix) = self.expand();
        let a_enc = f.encode(&scalar_mult(&f, &a, &f.base()));

        // r = SHA-512(prefix ‖ message) mod L; R = [r]B.
        let mut hr = Sha512::new();
        hr.update(&prefix);
        hr.update(message);
        let r = scalar_reduce_wide(&hr.finalize(), &f.l8);
        let mut r_bytes = [0u8; 32];
        r.write_le_bytes(&mut r_bytes);
        let r_enc = f.encode(&scalar_mult(&f, &r_bytes, &f.base()));

        // k = SHA-512(R ‖ A ‖ message) mod L; S = (r + k·a) mod L.
        let mut hk = Sha512::new();
        hk.update(&r_enc);
        hk.update(&a_enc);
        hk.update(message);
        let k = scalar_reduce_wide(&hk.finalize(), &f.l8);
        let a_scalar = Fe::from_le_bytes(&a);
        let s = scalar_muladd(&r, &k, &a_scalar, &f.l8);

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_enc);
        s.write_le_bytes(&mut sig[32..]);
        Ed25519Signature(sig)
    }
}

/// PKCS#8 v1 (RFC 8410) private-key serialization.
#[cfg(feature = "der")]
impl Ed25519PrivateKey {
    /// Encodes the key as a PKCS#8 `OneAsymmetricKey` DER structure.
    pub fn to_pkcs8_der(&self) -> alloc::vec::Vec<u8> {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let version = encode_integer(&[0]);
        let algid = encode_sequence(&oid_tlv(ED25519_OID));
        // privateKey is an OCTET STRING wrapping the CurvePrivateKey OCTET STRING.
        let privkey = encode_octet_string(&encode_octet_string(&self.seed));
        encode_sequence(&[version, algid, privkey].concat())
    }

    /// Encodes the key as a PKCS#8 PEM document (`-----BEGIN PRIVATE KEY-----`).
    pub fn to_pkcs8_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("PRIVATE KEY", &self.to_pkcs8_der())
    }

    /// Parses a PKCS#8 `OneAsymmetricKey` DER structure.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, crate::der::Error> {
        use crate::der::{Error, Reader, parse_oid};
        let mut r = Reader::new(der);
        let mut seq = r.read_sequence()?;
        seq.read_integer_bytes()?; // version (v1 = 0)
        let mut algid = seq.read_sequence()?;
        if parse_oid(algid.read_oid()?)?.as_slice() != ED25519_OID {
            return Err(Error::Malformed);
        }
        let inner = seq.read_octet_string()?;
        let seed_bytes = Reader::new(inner).read_octet_string()?;
        if seed_bytes.len() != 32 {
            return Err(Error::Malformed);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(seed_bytes);
        Ok(Ed25519PrivateKey { seed })
    }

    /// Parses a PKCS#8 PEM private key.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_pkcs8_der(&crate::der::pem_decode(pem, "PRIVATE KEY")?)
    }
}

impl Ed25519PublicKey {
    /// Creates a public key from its 32-byte encoding (not validated until use).
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Ed25519PublicKey(bytes)
    }

    /// The 32-byte encoding.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Verifies `signature` over `message`. Uses the *cofactored* group
    /// equation `[8S]B == [8R] + [8k]A` (ZIP-215 / FIPS-186-5 best practice),
    /// which rejects any small-subgroup `A` or `R`: multiplying by the
    /// cofactor 8 sends every 8-torsion point to the identity, so an
    /// attacker can't smuggle in identity-encoded `A` (which would make
    /// `[k]A == identity` for every `k` and let any `(R, S)` with
    /// `R == [S]B` verify on every message — a universal forgery).
    ///
    /// Returns [`Error::Verification`] on any failure (malformed inputs
    /// included).
    pub fn verify(&self, message: &[u8], signature: &Ed25519Signature) -> Result<(), Error> {
        let f = Field::new();

        // S must be a canonical scalar in [0, L).
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&signature.0[32..]);
        let s = Fe::from_le_bytes(&s_bytes);
        if !bool::from(s.ct_lt(&f.l)) {
            return Err(Error::Verification);
        }

        let mut r_bytes = [0u8; 32];
        r_bytes.copy_from_slice(&signature.0[..32]);
        let r_point = f.decode(&r_bytes).ok_or(Error::Verification)?;
        let a_point = f.decode(&self.0).ok_or(Error::Verification)?;

        // k = SHA-512(R ‖ A ‖ message) mod L.
        let mut hk = Sha512::new();
        hk.update(&r_bytes);
        hk.update(&self.0);
        hk.update(message);
        let k = scalar_reduce_wide(&hk.finalize(), &f.l8);
        let mut k_bytes = [0u8; 32];
        k.write_le_bytes(&mut k_bytes);

        // Cofactored verify: accept iff [8S]B == [8R] + [8k]A. We multiply
        // each side of the cofactor-less equation by 8 = [2][2][2].
        let lhs = scalar_mult(&f, &s_bytes, &f.base());
        let ka = scalar_mult(&f, &k_bytes, &a_point);
        let rhs = point_add(&f, &r_point, &ka);
        let lhs8 = point_double(&f, &point_double(&f, &point_double(&f, &lhs)));
        let rhs8 = point_double(&f, &point_double(&f, &point_double(&f, &rhs)));
        // Operands are public, but the rest of the crate uses constant-time
        // equality for encoded-point comparison; staying consistent here keeps
        // a future refactor from accidentally folding secret bytes through `==`
        // (which has early-exit semantics on `[u8; N]`).
        let lhs_enc = f.encode(&lhs8);
        let rhs_enc = f.encode(&rhs8);
        if bool::from(lhs_enc.ct_eq(&rhs_enc)) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

impl Ed25519Signature {
    /// Creates a signature from its 64-byte encoding.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Ed25519Signature(bytes)
    }

    /// The 64-byte encoding (`R ‖ S`).
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::HmacDrbg;
    use crate::test_util::from_hex;

    /// RFC 8032 §7.1 test vectors: (seed, public key, message, signature).
    struct Vector {
        seed: [u8; 32],
        public: [u8; 32],
        message: &'static [u8],
        signature: [u8; 64],
    }

    fn vectors() -> [Vector; 3] {
        [
            Vector {
                seed: from_hex::<32>(
                    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                ),
                public: from_hex::<32>(
                    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                ),
                message: &[],
                signature: from_hex::<64>(
                    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8\
                     821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
                ),
            },
            Vector {
                seed: from_hex::<32>(
                    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                ),
                public: from_hex::<32>(
                    "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                ),
                message: &[0x72],
                signature: from_hex::<64>(
                    "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085a\
                     c1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
                ),
            },
            Vector {
                seed: from_hex::<32>(
                    "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                ),
                public: from_hex::<32>(
                    "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                ),
                message: &[0xaf, 0x82],
                signature: from_hex::<64>(
                    "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff\
                     9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
                ),
            },
        ]
    }

    #[test]
    fn field_invariants() {
        let f = Field::new();
        // inversion: a * a^(p-2) == 1
        let three = f.fp.to_mont(&Fe::from_u64(3));
        let inv3 = f.inv(three);
        assert!(bool::from(f.mul(three, inv3).ct_eq(&f.one)), "inv broken");
        // sqrt(-1)^2 == -1
        let neg1 = f.neg(f.one);
        assert!(bool::from(f.sq(f.sqrtm1).ct_eq(&neg1)), "sqrtm1 broken");
        // base point decodes
        assert!(f.decode(&BASE_ENC).is_some(), "base decode failed");
    }

    #[test]
    fn rfc8032_public_keys() {
        for v in vectors() {
            let sk = Ed25519PrivateKey::from_bytes(v.seed);
            assert_eq!(sk.public_key().to_bytes(), v.public);
        }
    }

    #[test]
    fn rfc8032_sign() {
        for v in vectors() {
            let sk = Ed25519PrivateKey::from_bytes(v.seed);
            assert_eq!(sk.sign(v.message).to_bytes(), v.signature);
        }
    }

    #[test]
    fn rfc8032_verify() {
        for v in vectors() {
            let pk = Ed25519PublicKey::from_bytes(v.public);
            let sig = Ed25519Signature::from_bytes(v.signature);
            pk.verify(v.message, &sig).unwrap();

            // A flipped message byte must not verify.
            let mut bad = v.message.to_vec();
            bad.push(0x01);
            assert!(pk.verify(&bad, &sig).is_err());

            // A tampered signature must not verify.
            let mut bad_sig = v.signature;
            bad_sig[0] ^= 0x01;
            assert!(
                pk.verify(v.message, &Ed25519Signature::from_bytes(bad_sig))
                    .is_err()
            );
        }
    }

    #[test]
    fn generated_key_roundtrip() {
        let mut rng = HmacDrbg::<crate::hash::Sha256>::new(b"ed25519", b"nonce", &[]);
        let sk = Ed25519PrivateKey::generate(&mut rng);
        let pk = sk.public_key();
        let sig = sk.sign(b"purecrypto ed25519");
        pk.verify(b"purecrypto ed25519", &sig).unwrap();
        assert!(pk.verify(b"different message", &sig).is_err());

        // A non-canonical S (≥ L) is rejected.
        let mut sig_bytes = sig.to_bytes();
        sig_bytes[63] |= 0x80;
        assert!(
            pk.verify(
                b"purecrypto ed25519",
                &Ed25519Signature::from_bytes(sig_bytes)
            )
            .is_err()
        );
    }
}
