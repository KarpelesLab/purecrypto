//! JSON Web Key (RFC 7517) and JWK Set parsing, validation and export.

use super::json::{self, Object, Value};
use super::{Enc, Error, KeyAlg, KeyFamily, SigAlg, base64url, known_alg};
use crate::bignum::BoxedUint;
use crate::der::Reader;
use crate::ec::{
    BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, CurveId, Ed448PrivateKey,
    Ed448PublicKey, Ed25519PrivateKey, Ed25519PublicKey, X448PrivateKey, X448PublicKey,
    X25519PrivateKey, X25519PublicKey,
};
use crate::hash::{Digest, Sha256};
use crate::rsa::{BoxedRsaPrivateKey, BoxedRsaPublicKey};
use crate::zeroize::Zeroizing;
use alloc::string::String;
use alloc::vec::Vec;

/// Minimum RSA modulus size accepted in a JWK (RFC 7518 §3.3 / §4.2 require
/// 2048-bit keys for every RSA algorithm).
pub(crate) const MIN_RSA_BITS: usize = 2048;

/// An `EC` key's curve (RFC 7518 §6.2.1.1, RFC 8812 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EcCurve {
    /// NIST P-256 (`P-256`).
    P256,
    /// NIST P-384 (`P-384`).
    P384,
    /// NIST P-521 (`P-521`).
    P521,
    /// secp256k1 (`secp256k1`).
    Secp256k1,
}

impl EcCurve {
    /// The registered `crv` name.
    pub fn name(self) -> &'static str {
        match self {
            EcCurve::P256 => "P-256",
            EcCurve::P384 => "P-384",
            EcCurve::P521 => "P-521",
            EcCurve::Secp256k1 => "secp256k1",
        }
    }

    /// Parses a registered `crv` name. `P-256K`, the pre-RFC 8812 WebCrypto
    /// spelling of secp256k1, is accepted on input (exports use
    /// `secp256k1`).
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "P-256" => EcCurve::P256,
            "P-384" => EcCurve::P384,
            "P-521" => EcCurve::P521,
            "secp256k1" | "P-256K" => EcCurve::Secp256k1,
            _ => return None,
        })
    }

    /// The JWK curve for one of the crate's curve identifiers, if JOSE
    /// defines a name for it.
    pub fn from_curve_id(id: CurveId) -> Option<Self> {
        Some(match id {
            CurveId::P256 => EcCurve::P256,
            CurveId::P384 => EcCurve::P384,
            CurveId::P521 => EcCurve::P521,
            CurveId::Secp256k1 => EcCurve::Secp256k1,
            _ => return None,
        })
    }
}

/// An `OKP` key's curve (RFC 8037 §3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OkpCurve {
    /// Ed25519 (signing).
    Ed25519,
    /// Ed448 (signing).
    Ed448,
    /// X25519 (key agreement).
    X25519,
    /// X448 (key agreement).
    X448,
}

impl OkpCurve {
    /// The registered `crv` name.
    pub fn name(self) -> &'static str {
        match self {
            OkpCurve::Ed25519 => "Ed25519",
            OkpCurve::Ed448 => "Ed448",
            OkpCurve::X25519 => "X25519",
            OkpCurve::X448 => "X448",
        }
    }

    /// Parses a registered `crv` name.
    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name {
            "Ed25519" => OkpCurve::Ed25519,
            "Ed448" => OkpCurve::Ed448,
            "X25519" => OkpCurve::X25519,
            "X448" => OkpCurve::X448,
            _ => return None,
        })
    }

    /// Whether this is a signing curve (as opposed to key agreement).
    pub fn is_signing(self) -> bool {
        matches!(self, OkpCurve::Ed25519 | OkpCurve::Ed448)
    }

    fn public_len(self) -> usize {
        match self {
            OkpCurve::Ed25519 | OkpCurve::X25519 => 32,
            OkpCurve::Ed448 => 57,
            OkpCurve::X448 => 56,
        }
    }

    fn private_len(self) -> usize {
        self.public_len()
    }
}

/// The private components of an RSA JWK (RFC 7518 §6.3.2).
#[derive(Clone, Debug)]
pub struct RsaPrivateParts {
    d: Zeroizing<Vec<u8>>,
    /// `(p, q, dp, dq, qi)` — present all together or not at all.
    crt: Option<[Zeroizing<Vec<u8>>; 5]>,
}

impl RsaPrivateParts {
    /// The private exponent, big-endian.
    pub fn d(&self) -> &[u8] {
        &self.d
    }

    /// The first prime factor `p`, when the CRT parameters are present.
    pub fn p(&self) -> Option<&[u8]> {
        self.crt.as_ref().map(|c| c[0].as_slice())
    }

    /// The second prime factor `q`, when the CRT parameters are present.
    pub fn q(&self) -> Option<&[u8]> {
        self.crt.as_ref().map(|c| c[1].as_slice())
    }
}

/// The key material of a [`Jwk`], by key type.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum JwkKey {
    /// `kty: oct` — a symmetric key.
    Oct(Zeroizing<Vec<u8>>),
    /// `kty: RSA`.
    Rsa {
        /// Modulus, big-endian.
        n: Vec<u8>,
        /// Public exponent, big-endian.
        e: Vec<u8>,
        /// Private components, when this is a private key.
        private: Option<RsaPrivateParts>,
    },
    /// `kty: EC`.
    Ec {
        /// The curve.
        crv: EcCurve,
        /// Affine x, exactly the field width.
        x: Vec<u8>,
        /// Affine y, exactly the field width.
        y: Vec<u8>,
        /// Private scalar, when this is a private key.
        d: Option<Zeroizing<Vec<u8>>>,
    },
    /// `kty: OKP`.
    Okp {
        /// The curve.
        crv: OkpCurve,
        /// The public key encoding.
        x: Vec<u8>,
        /// The private key, when this is a private key.
        d: Option<Zeroizing<Vec<u8>>>,
    },
}

impl JwkKey {
    /// The `kty` value.
    pub fn kty(&self) -> &'static str {
        match self {
            JwkKey::Oct(_) => "oct",
            JwkKey::Rsa { .. } => "RSA",
            JwkKey::Ec { .. } => "EC",
            JwkKey::Okp { .. } => "OKP",
        }
    }

    /// Whether the key carries private or secret material (`oct` keys
    /// always do).
    pub fn is_private(&self) -> bool {
        match self {
            JwkKey::Oct(_) => true,
            JwkKey::Rsa { private, .. } => private.is_some(),
            JwkKey::Ec { d, .. } | JwkKey::Okp { d, .. } => d.is_some(),
        }
    }

    pub(crate) fn matches(&self, family: KeyFamily) -> bool {
        match (family, self) {
            (KeyFamily::Oct, JwkKey::Oct(_)) => true,
            (KeyFamily::Rsa, JwkKey::Rsa { .. }) => true,
            (KeyFamily::Ec(c), JwkKey::Ec { crv, .. }) => *crv == c,
            (KeyFamily::OkpSign, JwkKey::Okp { crv, .. }) => crv.is_signing(),
            (KeyFamily::Ecdh, JwkKey::Ec { .. }) => true,
            (KeyFamily::Ecdh, JwkKey::Okp { crv, .. }) => !crv.is_signing(),
            _ => false,
        }
    }
}

/// A JSON Web Key: key material plus the `kid`, `alg`, `use` and `key_ops`
/// metadata that governs how the key may be used.
///
/// Parsing validates the key (see the [module docs](super)); the metadata
/// is enforced whenever the key is used for a JWS or JWE.
#[derive(Clone, Debug)]
pub struct Jwk {
    key: JwkKey,
    kid: Option<String>,
    alg: Option<String>,
    key_use: Option<String>,
    key_ops: Option<Vec<String>>,
}

fn b64_member(obj: &Object, name: &str) -> Result<Option<Vec<u8>>, Error> {
    match obj.get_str(name)? {
        None => Ok(None),
        Some(s) => base64url::decode(s)
            .map(Some)
            .map_err(|_| Error::InvalidKey),
    }
}

fn require_b64(obj: &Object, name: &str) -> Result<Vec<u8>, Error> {
    b64_member(obj, name)?.ok_or(Error::Malformed)
}

fn uint(bytes: &[u8]) -> BoxedUint {
    BoxedUint::from_be_bytes(bytes)
}

fn uint_eq(a: &BoxedUint, b: &BoxedUint) -> bool {
    !a.lt(b) && !b.lt(a)
}

/// Whether `n` carries the ROCA (CVE-2017-15361, Infineon RSALib)
/// fingerprint: for every small prime `p` the residue `n mod p` lies in the
/// subgroup generated by 65537. A random modulus matches with probability
/// around 2⁻¹⁵⁴; a vulnerable one always does.
fn roca_fingerprint(n: &[u8]) -> bool {
    const PRIMES: [u32; 38] = [
        3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
        97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
    ];
    PRIMES.iter().all(|&p| {
        let r = n.iter().fold(0u32, |acc, &b| (acc * 256 + b as u32) % p);
        let g = 65537 % p;
        let mut x = 1u32;
        loop {
            if x == r {
                return true;
            }
            x = x * g % p;
            if x == 1 {
                return false;
            }
        }
    })
}

impl Jwk {
    /// Parses a JWK from its JSON text.
    pub fn parse(text: &str) -> Result<Self, Error> {
        Self::from_object(&json::parse_object(text)?)
    }

    /// Builds a JWK from a parsed JSON object, validating the key.
    pub fn from_object(obj: &Object) -> Result<Self, Error> {
        let kty = obj.require_str("kty")?;
        let key = match kty {
            "oct" => {
                let k = require_b64(obj, "k")?;
                if k.is_empty() {
                    return Err(Error::InvalidKey);
                }
                JwkKey::Oct(Zeroizing::new(k))
            }
            "RSA" => Self::parse_rsa(obj)?,
            "EC" => Self::parse_ec(obj)?,
            "OKP" => Self::parse_okp(obj)?,
            _ => return Err(Error::UnsupportedAlgorithm),
        };
        let kid = obj.get_str("kid")?.map(String::from);
        let alg = obj.get_str("alg")?.map(String::from);
        let key_use = obj.get_str("use")?.map(String::from);
        let key_ops = match obj.get_array("key_ops")? {
            None => None,
            Some(items) => {
                let mut ops = Vec::with_capacity(items.len());
                for item in items {
                    let op = item.as_str().ok_or(Error::Malformed)?;
                    if ops.iter().any(|o: &String| o == op) {
                        return Err(Error::Malformed);
                    }
                    ops.push(String::from(op));
                }
                Some(ops)
            }
        };
        let jwk = Jwk {
            key,
            kid,
            alg,
            key_use,
            key_ops,
        };
        jwk.check_metadata()?;
        Ok(jwk)
    }

    fn parse_rsa(obj: &Object) -> Result<JwkKey, Error> {
        let n = require_b64(obj, "n")?;
        let e = require_b64(obj, "e")?;
        let n_int = uint(&n);
        let e_int = uint(&e);
        if n_int.bit_len() < MIN_RSA_BITS {
            return Err(Error::InvalidKey);
        }
        BoxedRsaPublicKey::try_new(n_int.clone(), e_int.clone()).map_err(|_| Error::InvalidKey)?;
        if roca_fingerprint(&n) {
            return Err(Error::InvalidKey);
        }
        if obj.contains("oth") {
            return Err(Error::Unsupported("oth"));
        }
        let d = b64_member(obj, "d")?;
        let crt_names = ["p", "q", "dp", "dq", "qi"];
        let present = crt_names.iter().filter(|m| obj.contains(m)).count();
        let private = match d {
            None => {
                if present != 0 {
                    return Err(Error::Malformed);
                }
                None
            }
            Some(d) => {
                let d_int = uint(&d);
                if d_int.is_zero() || !d_int.lt(&n_int) {
                    return Err(Error::InvalidKey);
                }
                let crt = match present {
                    0 => None,
                    5 => {
                        let mut parts: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(5);
                        for name in crt_names {
                            parts.push(Zeroizing::new(require_b64(obj, name)?));
                        }
                        let p = uint(&parts[0]);
                        let q = uint(&parts[1]);
                        let one = BoxedUint::from_u64(1);
                        if !p.is_odd() || !q.is_odd() || !one.lt(&p) || !one.lt(&q) {
                            return Err(Error::InvalidKey);
                        }
                        if !uint_eq(&p.mul(&q), &n_int) {
                            return Err(Error::InvalidKey);
                        }
                        // e·d ≡ 1 (mod p−1) and (mod q−1), i.e. mod lcm(p−1, q−1).
                        let ed = e_int.mul(&d_int);
                        for prime in [&p, &q] {
                            let (_, r) = ed.divrem(&prime.sub(&one));
                            if !uint_eq(&r, &one) {
                                return Err(Error::InvalidKey);
                            }
                        }
                        let arr: [Zeroizing<Vec<u8>>; 5] =
                            parts.try_into().expect("five CRT parts");
                        Some(arr)
                    }
                    _ => return Err(Error::Malformed),
                };
                Some(RsaPrivateParts {
                    d: Zeroizing::new(d),
                    crt,
                })
            }
        };
        Ok(JwkKey::Rsa { n, e, private })
    }

    fn parse_ec(obj: &Object) -> Result<JwkKey, Error> {
        let crv = EcCurve::from_name(obj.require_str("crv")?).ok_or(Error::UnsupportedAlgorithm)?;
        let x = require_b64(obj, "x")?;
        let y = require_b64(obj, "y")?;
        let flen = crv.field_len();
        if x.len() != flen || y.len() != flen {
            return Err(Error::InvalidKey);
        }
        let mut sec1 = Vec::with_capacity(1 + 2 * flen);
        sec1.push(0x04);
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        BoxedEcdsaPublicKey::from_sec1(crv.curve_id(), &sec1).map_err(|_| Error::InvalidKey)?;
        let d = match b64_member(obj, "d")? {
            None => None,
            Some(d) => {
                if d.len() != crv.order_len() {
                    return Err(Error::InvalidKey);
                }
                let sk = BoxedEcdsaPrivateKey::from_bytes(crv.curve_id(), &d)
                    .map_err(|_| Error::InvalidKey)?;
                if sk.public_key().to_sec1() != sec1 {
                    return Err(Error::InvalidKey);
                }
                Some(Zeroizing::new(d))
            }
        };
        Ok(JwkKey::Ec { crv, x, y, d })
    }

    fn parse_okp(obj: &Object) -> Result<JwkKey, Error> {
        let crv =
            OkpCurve::from_name(obj.require_str("crv")?).ok_or(Error::UnsupportedAlgorithm)?;
        let x = require_b64(obj, "x")?;
        if x.len() != crv.public_len() {
            return Err(Error::InvalidKey);
        }
        let d = match b64_member(obj, "d")? {
            None => None,
            Some(d) => {
                if d.len() != crv.private_len() {
                    return Err(Error::InvalidKey);
                }
                let derived: Vec<u8> = match crv {
                    OkpCurve::Ed25519 => Ed25519PrivateKey::from_bytes(array(&d))
                        .public_key()
                        .to_bytes()
                        .to_vec(),
                    OkpCurve::Ed448 => Ed448PrivateKey::from_bytes(array(&d))
                        .public_key()
                        .to_bytes()
                        .to_vec(),
                    OkpCurve::X25519 => X25519PrivateKey::from_bytes(array(&d))
                        .public_key()
                        .to_vec(),
                    OkpCurve::X448 => X448PrivateKey::from_bytes(array(&d)).public_key().to_vec(),
                };
                if derived != x {
                    return Err(Error::InvalidKey);
                }
                Some(Zeroizing::new(d))
            }
        };
        Ok(JwkKey::Okp { crv, x, d })
    }

    /// Checks `alg` / `use` / `key_ops` against each other and the key.
    fn check_metadata(&self) -> Result<(), Error> {
        if let Some(alg) = self.alg.as_deref() {
            if !known_alg(alg) {
                return Err(Error::UnsupportedAlgorithm);
            }
            let (family, is_sig) = if let Some(a) = SigAlg::from_name(alg) {
                (a.family(), true)
            } else if let Some(a) = KeyAlg::from_name(alg) {
                (a.family(), false)
            } else {
                (KeyFamily::Oct, false)
            };
            if !self.key.matches(family) {
                return Err(Error::KeyMismatch);
            }
            self.check_oct_len_for_alg(alg)?;
            match self.key_use.as_deref() {
                None => {}
                Some("sig") if is_sig => {}
                Some("enc") if !is_sig => {}
                Some(_) => return Err(Error::KeyMismatch),
            }
        }
        match self.key_use.as_deref() {
            None | Some("sig") | Some("enc") => {}
            Some(_) => return Err(Error::Malformed),
        }
        if let (Some(u), Some(ops)) = (self.key_use.as_deref(), self.key_ops.as_deref()) {
            let allowed: &[&str] = if u == "sig" {
                &["sign", "verify"]
            } else {
                &[
                    "encrypt",
                    "decrypt",
                    "wrapKey",
                    "unwrapKey",
                    "deriveKey",
                    "deriveBits",
                ]
            };
            if ops.iter().any(|op| !allowed.contains(&op.as_str())) {
                return Err(Error::KeyMismatch);
            }
        }
        Ok(())
    }

    /// For an `oct` key, checks the length required by algorithm `alg`.
    pub(crate) fn check_oct_len_for_alg(&self, alg: &str) -> Result<(), Error> {
        let JwkKey::Oct(k) = &self.key else {
            return Ok(());
        };
        let ok = match alg {
            "HS256" => k.len() >= 32,
            "HS384" => k.len() >= 48,
            "HS512" => k.len() >= 64,
            "A128KW" | "A128GCMKW" => k.len() == 16,
            "A192KW" | "A192GCMKW" => k.len() == 24,
            "A256KW" | "A256GCMKW" => k.len() == 32,
            other => match Enc::from_name(other) {
                Some(enc) => k.len() == enc.key_len(),
                // dir, PBES2 passwords: any non-empty length.
                None => true,
            },
        };
        if ok { Ok(()) } else { Err(Error::InvalidKey) }
    }

    /// Checks the key may be used with header algorithm `alg` for
    /// operation `op` (`sign`, `verify`, `encrypt`, `decrypt`, ...).
    /// `dir_enc` is the content-encryption name when `alg` is `dir` (the
    /// key's own `alg` then names the content encryption).
    pub(crate) fn check_usable(
        &self,
        alg: &str,
        dir_enc: Option<&str>,
        family: KeyFamily,
        is_sig: bool,
        op: &[&str],
    ) -> Result<(), Error> {
        if !self.key.matches(family) {
            return Err(Error::KeyMismatch);
        }
        if let Some(key_alg) = self.alg.as_deref() {
            let expected = match dir_enc {
                Some(enc) => enc,
                None => alg,
            };
            if key_alg != expected {
                return Err(Error::KeyMismatch);
            }
        } else if alg == KeyAlg::RSA1_5.name() {
            // RSA1_5 is only honoured for a key that opts into it.
            return Err(Error::KeyMismatch);
        }
        match self.key_use.as_deref() {
            None => {}
            Some("sig") if is_sig => {}
            Some("enc") if !is_sig => {}
            Some(_) => return Err(Error::KeyMismatch),
        }
        if let Some(ops) = self.key_ops.as_deref()
            && !ops.iter().any(|o| op.contains(&o.as_str()))
        {
            return Err(Error::KeyMismatch);
        }
        self.check_oct_len_for_alg(dir_enc.unwrap_or(alg))
    }

    // ----- constructors ---------------------------------------------------

    /// A symmetric (`oct`) key.
    pub fn oct(k: &[u8]) -> Self {
        Self::new(JwkKey::Oct(Zeroizing::new(k.to_vec())))
    }

    fn new(key: JwkKey) -> Self {
        Jwk {
            key,
            kid: None,
            alg: None,
            key_use: None,
            key_ops: None,
        }
    }

    fn min_be(v: &BoxedUint) -> Vec<u8> {
        v.to_be_bytes(v.bit_len().div_ceil(8).max(1))
    }

    /// An RSA public key.
    pub fn from_rsa_public(key: &BoxedRsaPublicKey) -> Self {
        Self::new(JwkKey::Rsa {
            n: Self::min_be(key.modulus()),
            e: Self::min_be(key.exponent()),
            private: None,
        })
    }

    /// An RSA private key. The CRT parameters are exported when the key
    /// carries its prime factors.
    pub fn from_rsa_private(key: &BoxedRsaPrivateKey) -> Self {
        let n = Self::min_be(key.modulus());
        let e = Self::min_be(key.public_key().exponent());
        let d = Zeroizing::new(Self::min_be(key.private_exponent()));
        let crt = key.primes().map(|_| {
            // `to_pkcs1_der` computes dp, dq and qInv from the primes; read
            // them back out of the RSAPrivateKey structure.
            let der = Zeroizing::new(key.to_pkcs1_der());
            let mut outer = Reader::new(&der);
            let mut seq = outer.read_sequence().expect("PKCS#1 SEQUENCE");
            let _version = seq.read_integer_bytes().expect("version");
            let mut ints: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(8);
            for _ in 0..8 {
                let v = seq.read_unsigned_integer_bytes().expect("INTEGER");
                // DER keeps a 0x00 sign byte in front of a high-bit value;
                // JWK integers are unsigned and minimal.
                let start = v.iter().position(|&b| b != 0).unwrap_or(v.len() - 1);
                ints.push(Zeroizing::new(v[start..].to_vec()));
            }
            // ints = n, e, d, p, q, dp, dq, qi
            let mut it = ints.drain(3..);
            [
                it.next().expect("p"),
                it.next().expect("q"),
                it.next().expect("dp"),
                it.next().expect("dq"),
                it.next().expect("qi"),
            ]
        });
        Self::new(JwkKey::Rsa {
            n,
            e,
            private: Some(RsaPrivateParts { d, crt }),
        })
    }

    /// An EC public key on one of the JOSE curves.
    pub fn from_ec_public(key: &BoxedEcdsaPublicKey) -> Result<Self, Error> {
        let crv = EcCurve::from_curve_id(key.curve()).ok_or(Error::UnsupportedAlgorithm)?;
        let sec1 = key.to_sec1();
        let flen = crv.field_len();
        Ok(Self::new(JwkKey::Ec {
            crv,
            x: sec1[1..1 + flen].to_vec(),
            y: sec1[1 + flen..].to_vec(),
            d: None,
        }))
    }

    /// An EC private key on one of the JOSE curves.
    pub fn from_ec_private(key: &BoxedEcdsaPrivateKey) -> Result<Self, Error> {
        let mut jwk = Self::from_ec_public(&key.public_key())?;
        // The scalar is the OCTET STRING of the SEC1 ECPrivateKey encoding.
        let der = Zeroizing::new(key.to_sec1_der());
        let mut outer = Reader::new(&der);
        let mut seq = outer.read_sequence().map_err(|_| Error::InvalidKey)?;
        seq.read_integer_bytes().map_err(|_| Error::InvalidKey)?;
        let d = seq.read_octet_string().map_err(|_| Error::InvalidKey)?;
        if let JwkKey::Ec { d: slot, .. } = &mut jwk.key {
            *slot = Some(Zeroizing::new(d.to_vec()));
        }
        Ok(jwk)
    }

    /// An Ed25519 public key.
    pub fn from_ed25519_public(key: &Ed25519PublicKey) -> Self {
        Self::new(JwkKey::Okp {
            crv: OkpCurve::Ed25519,
            x: key.to_bytes().to_vec(),
            d: None,
        })
    }

    /// An Ed25519 private key.
    pub fn from_ed25519_private(key: &Ed25519PrivateKey) -> Self {
        Self::new(JwkKey::Okp {
            crv: OkpCurve::Ed25519,
            x: key.public_key().to_bytes().to_vec(),
            d: Some(Zeroizing::new(key.to_bytes().to_vec())),
        })
    }

    /// An Ed448 public key.
    pub fn from_ed448_public(key: &Ed448PublicKey) -> Self {
        Self::new(JwkKey::Okp {
            crv: OkpCurve::Ed448,
            x: key.to_bytes().to_vec(),
            d: None,
        })
    }

    /// An Ed448 private key.
    pub fn from_ed448_private(key: &Ed448PrivateKey) -> Self {
        Self::new(JwkKey::Okp {
            crv: OkpCurve::Ed448,
            x: key.public_key().to_bytes().to_vec(),
            d: Some(Zeroizing::new(key.to_bytes().to_vec())),
        })
    }

    /// An X25519 public key.
    pub fn from_x25519_public(key: &X25519PublicKey) -> Self {
        Self::new(JwkKey::Okp {
            crv: OkpCurve::X25519,
            x: key.to_bytes().to_vec(),
            d: None,
        })
    }

    /// An X25519 private key.
    pub fn from_x25519_private(key: &X25519PrivateKey) -> Self {
        Self::new(JwkKey::Okp {
            crv: OkpCurve::X25519,
            x: key.public_key().to_vec(),
            d: Some(Zeroizing::new(key.to_bytes().to_vec())),
        })
    }

    /// An X448 public key.
    pub fn from_x448_public(key: &X448PublicKey) -> Self {
        Self::new(JwkKey::Okp {
            crv: OkpCurve::X448,
            x: key.to_bytes().to_vec(),
            d: None,
        })
    }

    /// An X448 private key.
    pub fn from_x448_private(key: &X448PrivateKey) -> Self {
        Self::new(JwkKey::Okp {
            crv: OkpCurve::X448,
            x: key.public_key().to_vec(),
            d: Some(Zeroizing::new(key.to_bytes().to_vec())),
        })
    }

    // ----- metadata -------------------------------------------------------

    /// Sets `kid`.
    pub fn with_kid(mut self, kid: &str) -> Self {
        self.kid = Some(String::from(kid));
        self
    }

    /// Sets `alg`; it must be a registered algorithm the key type can use.
    pub fn with_alg(mut self, alg: &str) -> Result<Self, Error> {
        self.alg = Some(String::from(alg));
        self.check_metadata()?;
        Ok(self)
    }

    /// Sets `use` (`sig` or `enc`).
    pub fn with_use(mut self, key_use: &str) -> Result<Self, Error> {
        self.key_use = Some(String::from(key_use));
        self.check_metadata()?;
        Ok(self)
    }

    /// Sets `key_ops`.
    pub fn with_key_ops(mut self, ops: &[&str]) -> Result<Self, Error> {
        self.key_ops = Some(ops.iter().map(|s| String::from(*s)).collect());
        self.check_metadata()?;
        Ok(self)
    }

    /// The key material.
    pub fn key(&self) -> &JwkKey {
        &self.key
    }

    /// The `kid`, if any.
    pub fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }

    /// The `alg`, if any.
    pub fn alg(&self) -> Option<&str> {
        self.alg.as_deref()
    }

    /// The `use`, if any.
    pub fn key_use(&self) -> Option<&str> {
        self.key_use.as_deref()
    }

    /// The `key_ops`, if any.
    pub fn key_ops(&self) -> Option<&[String]> {
        self.key_ops.as_deref()
    }

    /// Whether the key carries private or secret material.
    pub fn is_private(&self) -> bool {
        self.key.is_private()
    }

    /// The public part of the key (an `oct` key has none: `None`).
    pub fn to_public(&self) -> Option<Self> {
        let key = match &self.key {
            JwkKey::Oct(_) => return None,
            JwkKey::Rsa { n, e, .. } => JwkKey::Rsa {
                n: n.clone(),
                e: e.clone(),
                private: None,
            },
            JwkKey::Ec { crv, x, y, .. } => JwkKey::Ec {
                crv: *crv,
                x: x.clone(),
                y: y.clone(),
                d: None,
            },
            JwkKey::Okp { crv, x, .. } => JwkKey::Okp {
                crv: *crv,
                x: x.clone(),
                d: None,
            },
        };
        Some(Jwk {
            key,
            kid: self.kid.clone(),
            alg: self.alg.clone(),
            key_use: self.key_use.clone(),
            key_ops: self.key_ops.clone(),
        })
    }

    // ----- export ---------------------------------------------------------

    /// The key as a JSON object.
    pub fn to_object(&self) -> Object {
        let mut o = Object::new();
        let b64 = |v: &[u8]| Value::String(base64url::encode(v));
        // `insert` only fails on a duplicate name, which cannot happen here.
        let _ = o.insert_str("kty", self.key.kty());
        match &self.key {
            JwkKey::Oct(k) => {
                let _ = o.insert("k", b64(k));
            }
            JwkKey::Rsa { n, e, private } => {
                let _ = o.insert("n", b64(n));
                let _ = o.insert("e", b64(e));
                if let Some(p) = private {
                    let _ = o.insert("d", b64(&p.d));
                    if let Some(crt) = &p.crt {
                        for (name, v) in ["p", "q", "dp", "dq", "qi"].iter().zip(crt.iter()) {
                            let _ = o.insert(name, b64(v));
                        }
                    }
                }
            }
            JwkKey::Ec { crv, x, y, d } => {
                let _ = o.insert_str("crv", crv.name());
                let _ = o.insert("x", b64(x));
                let _ = o.insert("y", b64(y));
                if let Some(d) = d {
                    let _ = o.insert("d", b64(d));
                }
            }
            JwkKey::Okp { crv, x, d } => {
                let _ = o.insert_str("crv", crv.name());
                let _ = o.insert("x", b64(x));
                if let Some(d) = d {
                    let _ = o.insert("d", b64(d));
                }
            }
        }
        if let Some(kid) = &self.kid {
            let _ = o.insert_str("kid", kid);
        }
        if let Some(alg) = &self.alg {
            let _ = o.insert_str("alg", alg);
        }
        if let Some(u) = &self.key_use {
            let _ = o.insert_str("use", u);
        }
        if let Some(ops) = &self.key_ops {
            let _ = o.insert(
                "key_ops",
                Value::Array(ops.iter().map(|s| Value::String(s.clone())).collect()),
            );
        }
        o
    }

    /// The key as compact JSON.
    pub fn to_json(&self) -> String {
        self.to_object().to_json()
    }

    /// The RFC 7638 SHA-256 thumbprint of the key.
    pub fn thumbprint_sha256(&self) -> [u8; 32] {
        let mut o = Object::new();
        let b64 = |v: &[u8]| Value::String(base64url::encode(v));
        // Required members in lexicographic order, no whitespace.
        match &self.key {
            JwkKey::Oct(k) => {
                let _ = o.insert("k", b64(k));
                let _ = o.insert_str("kty", "oct");
            }
            JwkKey::Rsa { n, e, .. } => {
                let _ = o.insert("e", b64(e));
                let _ = o.insert_str("kty", "RSA");
                let _ = o.insert("n", b64(n));
            }
            JwkKey::Ec { crv, x, y, .. } => {
                let _ = o.insert_str("crv", crv.name());
                let _ = o.insert_str("kty", "EC");
                let _ = o.insert("x", b64(x));
                let _ = o.insert("y", b64(y));
            }
            JwkKey::Okp { crv, x, .. } => {
                let _ = o.insert_str("crv", crv.name());
                let _ = o.insert_str("kty", "OKP");
                let _ = o.insert("x", b64(x));
            }
        }
        Sha256::digest(o.to_json().as_bytes())
    }

    // ----- conversions to crate key types ---------------------------------

    /// The raw bytes of an `oct` key.
    pub fn oct_bytes(&self) -> Result<&[u8], Error> {
        match &self.key {
            JwkKey::Oct(k) => Ok(k),
            _ => Err(Error::KeyMismatch),
        }
    }

    /// The RSA public key.
    pub fn rsa_public_key(&self) -> Result<BoxedRsaPublicKey, Error> {
        match &self.key {
            JwkKey::Rsa { n, e, .. } => {
                BoxedRsaPublicKey::try_new(uint(n), uint(e)).map_err(|_| Error::InvalidKey)
            }
            _ => Err(Error::KeyMismatch),
        }
    }

    /// The RSA private key (with CRT / blinding when the JWK carries `p`
    /// and `q`).
    pub fn rsa_private_key(&self) -> Result<BoxedRsaPrivateKey, Error> {
        match &self.key {
            JwkKey::Rsa {
                n,
                e,
                private: Some(parts),
            } => {
                let (n, e, d) = (uint(n), uint(e), uint(&parts.d));
                Ok(match &parts.crt {
                    Some(crt) => BoxedRsaPrivateKey::from_components_with_primes(
                        n,
                        e,
                        d,
                        uint(&crt[0]),
                        uint(&crt[1]),
                    ),
                    None => BoxedRsaPrivateKey::from_components(n, e, d),
                })
            }
            _ => Err(Error::KeyMismatch),
        }
    }

    /// The EC public key.
    pub fn ec_public_key(&self) -> Result<BoxedEcdsaPublicKey, Error> {
        match &self.key {
            JwkKey::Ec { crv, x, y, .. } => {
                let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
                sec1.push(0x04);
                sec1.extend_from_slice(x);
                sec1.extend_from_slice(y);
                BoxedEcdsaPublicKey::from_sec1(crv.curve_id(), &sec1).map_err(|_| Error::InvalidKey)
            }
            _ => Err(Error::KeyMismatch),
        }
    }

    /// The EC curve of an `EC` key.
    pub fn ec_curve(&self) -> Option<EcCurve> {
        match &self.key {
            JwkKey::Ec { crv, .. } => Some(*crv),
            _ => None,
        }
    }

    /// The OKP curve of an `OKP` key.
    pub fn okp_curve(&self) -> Option<OkpCurve> {
        match &self.key {
            JwkKey::Okp { crv, .. } => Some(*crv),
            _ => None,
        }
    }

    /// The EC private key for signing.
    pub fn ec_private_key(&self) -> Result<BoxedEcdsaPrivateKey, Error> {
        match &self.key {
            JwkKey::Ec {
                crv, d: Some(d), ..
            } => BoxedEcdsaPrivateKey::from_bytes(crv.curve_id(), d).map_err(|_| Error::InvalidKey),
            _ => Err(Error::KeyMismatch),
        }
    }

    /// The EC private key for key agreement.
    pub fn ecdh_private_key(&self) -> Result<BoxedEcdhPrivateKey, Error> {
        match &self.key {
            JwkKey::Ec {
                crv, d: Some(d), ..
            } => BoxedEcdhPrivateKey::from_bytes(crv.curve_id(), d).map_err(|_| Error::InvalidKey),
            _ => Err(Error::KeyMismatch),
        }
    }

    fn okp_public(&self, want: OkpCurve) -> Result<&[u8], Error> {
        match &self.key {
            JwkKey::Okp { crv, x, .. } if *crv == want => Ok(x),
            _ => Err(Error::KeyMismatch),
        }
    }

    fn okp_private(&self, want: OkpCurve) -> Result<&[u8], Error> {
        match &self.key {
            JwkKey::Okp {
                crv, d: Some(d), ..
            } if *crv == want => Ok(d),
            _ => Err(Error::KeyMismatch),
        }
    }

    /// The Ed25519 public key.
    pub fn ed25519_public_key(&self) -> Result<Ed25519PublicKey, Error> {
        Ok(Ed25519PublicKey::from_bytes(array(
            self.okp_public(OkpCurve::Ed25519)?,
        )))
    }

    /// The Ed25519 private key.
    pub fn ed25519_private_key(&self) -> Result<Ed25519PrivateKey, Error> {
        Ok(Ed25519PrivateKey::from_bytes(array(
            self.okp_private(OkpCurve::Ed25519)?,
        )))
    }

    /// The Ed448 public key.
    pub fn ed448_public_key(&self) -> Result<Ed448PublicKey, Error> {
        Ok(Ed448PublicKey::from_bytes(array(
            self.okp_public(OkpCurve::Ed448)?,
        )))
    }

    /// The Ed448 private key.
    pub fn ed448_private_key(&self) -> Result<Ed448PrivateKey, Error> {
        Ok(Ed448PrivateKey::from_bytes(array(
            self.okp_private(OkpCurve::Ed448)?,
        )))
    }

    /// The X25519 public key.
    pub fn x25519_public_key(&self) -> Result<X25519PublicKey, Error> {
        Ok(X25519PublicKey::from_bytes(array(
            self.okp_public(OkpCurve::X25519)?,
        )))
    }

    /// The X25519 private key.
    pub fn x25519_private_key(&self) -> Result<X25519PrivateKey, Error> {
        Ok(X25519PrivateKey::from_bytes(array(
            self.okp_private(OkpCurve::X25519)?,
        )))
    }

    /// The X448 public key.
    pub fn x448_public_key(&self) -> Result<X448PublicKey, Error> {
        Ok(X448PublicKey::from_bytes(array(
            self.okp_public(OkpCurve::X448)?,
        )))
    }

    /// The X448 private key.
    pub fn x448_private_key(&self) -> Result<X448PrivateKey, Error> {
        Ok(X448PrivateKey::from_bytes(array(
            self.okp_private(OkpCurve::X448)?,
        )))
    }
}

/// Copies a slice whose length was already validated into an array.
fn array<const N: usize>(bytes: &[u8]) -> [u8; N] {
    bytes.try_into().expect("length validated at parse time")
}

/// A JWK Set (RFC 7517 §5): a list of keys with unique `kid`s that are
/// either all public or all private/secret.
#[derive(Clone, Debug, Default)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwkSet {
    /// An empty set.
    pub fn new() -> Self {
        JwkSet { keys: Vec::new() }
    }

    /// Parses a JWK Set from its JSON text.
    pub fn parse(text: &str) -> Result<Self, Error> {
        Self::from_object(&json::parse_object(text)?)
    }

    /// Builds a set from a parsed JSON object with a `keys` array.
    pub fn from_object(obj: &Object) -> Result<Self, Error> {
        let items = obj.get_array("keys")?.ok_or(Error::Malformed)?;
        let mut set = JwkSet::new();
        for item in items {
            let o = item.as_object().ok_or(Error::Malformed)?;
            set.push(Jwk::from_object(o)?)?;
        }
        Ok(set)
    }

    /// Adds a key, rejecting a duplicate `kid` and a public/private mix.
    pub fn push(&mut self, key: Jwk) -> Result<(), Error> {
        if let Some(kid) = key.kid()
            && self.keys.iter().any(|k| k.kid() == Some(kid))
        {
            return Err(Error::DuplicateKid);
        }
        if let Some(first) = self.keys.first()
            && first.is_private() != key.is_private()
        {
            return Err(Error::MixedKeySet);
        }
        self.keys.push(key);
        Ok(())
    }

    /// The keys, in order.
    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    /// The key with `kid`, if any.
    pub fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid() == Some(kid))
    }

    /// Selects the key for a header: by `kid` when the header names one
    /// (that key must then pass `fits`), otherwise the unique key that
    /// passes `fits`.
    pub(crate) fn select<F>(&self, kid: Option<&str>, fits: F) -> Result<&Jwk, Error>
    where
        F: Fn(&Jwk) -> bool,
    {
        match kid {
            Some(kid) => {
                let key = self.find_by_kid(kid).ok_or(Error::NoKey)?;
                if fits(key) {
                    Ok(key)
                } else {
                    Err(Error::KeyMismatch)
                }
            }
            None => {
                let mut it = self.keys.iter().filter(|k| fits(k));
                let first = it.next().ok_or(Error::NoKey)?;
                if it.next().is_some() {
                    return Err(Error::Ambiguous);
                }
                Ok(first)
            }
        }
    }

    /// The set as a JSON object.
    pub fn to_object(&self) -> Object {
        let mut o = Object::new();
        let _ = o.insert(
            "keys",
            Value::Array(
                self.keys
                    .iter()
                    .map(|k| Value::Object(k.to_object()))
                    .collect(),
            ),
        );
        o
    }

    /// The set as compact JSON.
    pub fn to_json(&self) -> String {
        self.to_object().to_json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7517 Appendix A.1.
    const RFC7517_A1: &str = r#"{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "use":"enc",
          "kid":"1"},
         {"kty":"RSA",
          "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }"#;

    /// RFC 7517 Appendix A.2.
    pub(crate) const RFC7517_A2: &str = r#"{"keys":
       [
         {"kty":"EC",
          "crv":"P-256",
          "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
          "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
          "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
          "use":"enc",
          "kid":"1"},
         {"kty":"RSA",
          "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
          "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
          "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
          "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
          "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
          "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }"#;

    /// RFC 7517 Appendix A.3.
    const RFC7517_A3: &str = r#"{"keys":
       [
         {"kty":"oct",
          "alg":"A128KW",
          "k":"GawgguFyGrWKav7AX4VKUg"},
         {"kty":"oct",
          "k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
          "kid":"HMAC key used in JWS spec Appendix A.1 example"}
       ]
     }"#;

    #[test]
    fn rfc7517_appendix_a() {
        let pub_set = JwkSet::parse(RFC7517_A1).unwrap();
        assert_eq!(pub_set.keys().len(), 2);
        assert!(!pub_set.keys()[0].is_private());
        assert_eq!(pub_set.keys()[0].key_use(), Some("enc"));
        assert_eq!(pub_set.keys()[0].ec_curve(), Some(EcCurve::P256));
        assert_eq!(pub_set.keys()[1].alg(), Some("RS256"));
        assert_eq!(
            pub_set.find_by_kid("2011-04-29").unwrap().key().kty(),
            "RSA"
        );
        pub_set.keys()[1].rsa_public_key().unwrap();
        assert!(pub_set.keys()[1].rsa_private_key().is_err());

        let priv_set = JwkSet::parse(RFC7517_A2).unwrap();
        assert!(priv_set.keys().iter().all(Jwk::is_private));
        priv_set.keys()[0].ec_private_key().unwrap();
        let rsa = priv_set.keys()[1].rsa_private_key().unwrap();
        assert!(rsa.primes().is_some());
        // Export round-trips.
        let again = JwkSet::parse(&priv_set.to_json()).unwrap();
        assert_eq!(again.to_json(), priv_set.to_json());
        // Public projection matches the public set.
        let projected = priv_set.keys()[1].to_public().unwrap();
        assert_eq!(projected.to_json(), pub_set.keys()[1].to_json());

        let sym = JwkSet::parse(RFC7517_A3).unwrap();
        assert_eq!(sym.keys()[0].oct_bytes().unwrap().len(), 16);
        assert_eq!(sym.keys()[1].oct_bytes().unwrap().len(), 64);
        assert!(
            sym.keys()[0].clone().with_alg("HS256").is_err(),
            "16-byte HMAC key"
        );
    }

    #[test]
    fn rfc8037_examples() {
        let sk = Jwk::parse(
            r#"{"kty":"OKP","crv":"Ed25519",
   "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
   "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
        )
        .unwrap();
        assert_eq!(
            sk.ed25519_private_key().unwrap().to_bytes()[..4],
            [0x9d, 0x61, 0xb1, 0x9d]
        );
        let pk = sk.to_public().unwrap();
        assert_eq!(
            pk.to_json(),
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
        );
        assert_eq!(
            base64url::encode(&pk.thumbprint_sha256()),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
        assert_eq!(sk.thumbprint_sha256(), pk.thumbprint_sha256());
        // A.6 / A.7 key-agreement keys.
        let bob = Jwk::parse(
            r#"{"kty":"OKP","crv":"X25519","kid":"Bob","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#,
        )
        .unwrap();
        assert_eq!(
            bob.x25519_public_key().unwrap().to_bytes()[..2],
            [0xde, 0x9e]
        );
        let dave = Jwk::parse(
            r#"{"kty":"OKP","crv":"X448","kid":"Dave","x":"PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk"}"#,
        )
        .unwrap();
        assert_eq!(
            dave.x448_public_key().unwrap().to_bytes()[..2],
            [0x3e, 0xb7]
        );
        // Mismatched private key is rejected.
        assert_eq!(
            Jwk::parse(
                r#"{"kty":"OKP","crv":"Ed25519","d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2B","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
            )
            .unwrap_err(),
            Error::InvalidKey
        );
    }

    #[test]
    fn set_rules() {
        let mut set = JwkSet::parse(RFC7517_A1).unwrap();
        // Duplicate kid.
        let dup = set.keys()[0].clone();
        assert_eq!(set.push(dup).unwrap_err(), Error::DuplicateKid);
        // Mixing in a secret key.
        assert_eq!(
            set.push(Jwk::oct(&[1u8; 32])).unwrap_err(),
            Error::MixedKeySet
        );
        // Selection.
        assert!(set.select(Some("1"), |k| k.key().kty() == "EC").is_ok());
        assert_eq!(
            set.select(Some("1"), |k| k.key().kty() == "RSA")
                .unwrap_err(),
            Error::KeyMismatch
        );
        assert_eq!(
            set.select(Some("nope"), |_| true).unwrap_err(),
            Error::NoKey
        );
        assert_eq!(set.select(None, |_| true).unwrap_err(), Error::Ambiguous);
        assert!(set.select(None, |k| k.key().kty() == "RSA").is_ok());
    }

    #[test]
    fn rejects_bad_keys() {
        // Off-curve point (last char of y changed).
        assert!(Jwk::parse(r#"{"kty":"EC","crv":"P-256","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyN"}"#).is_err());
        // Wrong coordinate width for the curve.
        assert!(Jwk::parse(r#"{"kty":"EC","crv":"P-384","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#).is_err());
        // alg / curve mismatch.
        assert!(Jwk::parse(r#"{"kty":"EC","crv":"P-256","alg":"ES384","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}"#).is_err());
        // Unknown alg, bad use, sig alg with use enc.
        assert!(Jwk::parse(r#"{"kty":"oct","k":"AAAA","alg":"HS255"}"#).is_err());
        assert!(Jwk::parse(r#"{"kty":"oct","k":"AAAA","use":"mac"}"#).is_err());
        assert!(Jwk::parse(r#"{"kty":"oct","k":"AAAA","alg":"A128KW","use":"sig"}"#).is_err());
        // Empty oct key, padding in k.
        assert!(Jwk::parse(r#"{"kty":"oct","k":""}"#).is_err());
        assert!(Jwk::parse(r#"{"kty":"oct","k":"AAA="}"#).is_err());
        // Unknown kty; missing members.
        assert!(Jwk::parse(r#"{"kty":"DSA"}"#).is_err());
        assert!(Jwk::parse(r#"{"kty":"RSA","n":"AQAB"}"#).is_err());
        // Small RSA key (RFC 7517 has none; build a 1024-bit-looking n).
        let n = base64url::encode(&[0xffu8; 128]);
        assert!(Jwk::parse(&alloc::format!(r#"{{"kty":"RSA","n":"{n}","e":"AQAB"}}"#)).is_err());
    }

    #[test]
    fn roca_detector() {
        // A modulus that is a product of 65537-powers residues everywhere
        // would be flagged; a random-looking one is not. Check the
        // structure with a small synthetic: n = 65537^k mod each prime is
        // hard to build, so just check a real key passes.
        let set = JwkSet::parse(RFC7517_A1).unwrap();
        if let JwkKey::Rsa { n, .. } = set.keys()[1].key() {
            assert!(!roca_fingerprint(n));
        }
        // n = 65537 itself: every residue is 65537 mod p, trivially in the subgroup.
        assert!(roca_fingerprint(&65537u32.to_be_bytes()));
    }

    #[test]
    fn crate_key_round_trips() {
        let set = JwkSet::parse(RFC7517_A2).unwrap();
        let rsa = set.keys()[1].rsa_private_key().unwrap();
        let back = Jwk::from_rsa_private(&rsa).with_kid("2011-04-29");
        let back = back.with_alg("RS256").unwrap();
        assert_eq!(back.to_json(), set.keys()[1].to_json());
        let ec = set.keys()[0].ec_private_key().unwrap();
        let back = Jwk::from_ec_private(&ec).unwrap();
        assert_eq!(
            back.to_object().get_str("d").unwrap(),
            set.keys()[0].to_object().get_str("d").unwrap()
        );
        assert_eq!(
            Jwk::from_ec_public(&ec.public_key()).unwrap().to_json(),
            set.keys()[0]
                .to_public()
                .unwrap()
                .to_json()
                .replace(",\"kid\":\"1\",\"use\":\"enc\"", "")
        );
    }
}
