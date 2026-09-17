//! FIPS 186-4 DSA: signatures in a prime-order subgroup of `Z_p^*`.
//!
//! DSA is the finite-field ancestor of ECDSA. A parameter set
//! ([`DsaParams`]) is a prime `p` of `L` bits, a prime `q` of `N` bits with
//! `q | p − 1`, and a generator `g` of the order-`q` subgroup. A private key is
//! `x ∈ [1, q − 1]`, the public key is `y = g^x mod p`, and a signature is the
//! pair `(r, s)` with `r = (g^k mod p) mod q` and `s = k⁻¹(z + x·r) mod q`
//! for a one-time secret `k` and the truncated message hash `z`.
//!
//! FIPS 186-5 withdrew DSA for new signatures; this module exists for
//! **verification of legacy signatures and interop** (old X.509 / SSH-1
//! `ssh-dss` keys, Java `SHA*withDSA`), and for the Wycheproof `dsa_*`
//! suites. Prefer ECDSA or Ed25519 for anything new.
//!
//! # Sizes
//!
//! Only the FIPS 186-4 §4.2 widths are accepted: `L ∈ {1024, 2048, 3072}`
//! and `N ∈ {160, 224, 256}`, in any combination (older OpenSSL builds paired
//! a 2048-bit `p` with a 160-bit `q`, and such keys are still around).
//! `p` is not primality-tested (that would cost tens of full-width
//! exponentiations per parsed key); `q` is, with 64 Miller-Rabin rounds over
//! bases derived from `q` itself, because the subgroup order is what the
//! verification equation actually relies on. Together with `g^q ≡ 1` and
//! `y^q ≡ 1 (mod p)` this pins `g` and `y` to an order-`q` subgroup whether
//! or not `p` is prime.
//!
//! # Hashing
//!
//! Per FIPS 186-4 §4.6 the digest is truncated to its leftmost `min(N,
//! outlen)` bits, so a SHA-256 digest is used whole on a 256-bit `q` and cut
//! to 224 bits on a 224-bit one. `sign::<D>` derives the nonce with RFC 6979
//! (HMAC-DRBG keyed with `x` and the digest), so every signature is
//! deterministic and the RFC 6979 A.2.1 / A.2.2 vectors are reproduced
//! exactly. Parameter generation (FIPS 186-4 Appendix A) is not implemented:
//! there is no new DSA deployment to generate parameters for, and every
//! caller in practice receives `(p, q, g)` from a key file.
//!
//! # Encodings
//!
//! * Public keys: X.509 `SubjectPublicKeyInfo` with `id-dsa`
//!   (`1.2.840.10040.4.1`), the `Dss-Parms` sequence as the algorithm
//!   parameter and a DER `INTEGER y` inside the `BIT STRING`
//!   ([`DsaPublicKey::to_spki_der`] / [`from_spki_der`]).
//! * Private keys: PKCS#8 `PrivateKeyInfo` with the same algorithm identifier
//!   and a DER `INTEGER x` in the `privateKey` OCTET STRING
//!   ([`DsaPrivateKey::to_pkcs8_der`] / [`from_pkcs8_der`]).
//! * Parameters alone: the `Dss-Parms` sequence ([`DsaParams::to_der`]).
//! * Signatures: strict-DER `Dss-Sig-Value ::= SEQUENCE { r, s INTEGER }`
//!   ([`DsaSignature::to_der`] / [`from_der`]) or the fixed-width IEEE P1363
//!   `r ‖ s` form ([`DsaSignature::to_p1363`] / [`from_p1363`]).
//!
//! [`from_spki_der`]: DsaPublicKey::from_spki_der
//! [`from_pkcs8_der`]: DsaPrivateKey::from_pkcs8_der
//! [`from_der`]: DsaSignature::from_der
//! [`from_p1363`]: DsaSignature::from_p1363
//!
//! # Example
//!
//! ```
//! use purecrypto::dsa::{DsaParams, DsaPrivateKey, DsaSignature};
//! use purecrypto::hash::Sha256;
//! use purecrypto::rng::OsRng;
//!
//! # fn main() -> Result<(), purecrypto::dsa::Error> {
//! # let params = purecrypto::dsa::test_params_2048_256();
//! // `params` is a (p, q, g) triple, typically parsed from a key file.
//! let key = DsaPrivateKey::generate(params, &mut OsRng);
//! let sig = key.sign::<Sha256>(b"message")?;
//! let der = sig.to_der();
//! key.public_key()
//!     .verify::<Sha256>(b"message", &DsaSignature::from_der(&der)?)?;
//! # Ok(())
//! # }
//! ```

use crate::bignum::{BoxedMontModulus, BoxedUint, inv_mod_odd_ct_boxed};
use crate::ct::ConstantTimeEq;
use crate::der::{
    Reader, encode_bit_string, encode_integer, encode_octet_string, encode_sequence, oid_tlv,
    parse_oid, tag,
};
use crate::hash::{Digest, Hmac};
use crate::rng::{CryptoRng, RngCore};
use crate::zeroize::Zeroize;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

/// `id-dsa` (`1.2.840.10040.4.1`): the SPKI / PKCS#8 algorithm OID for DSA
/// keys (RFC 3279 §2.3.2).
const ID_DSA_OID: &[u64] = &[1, 2, 840, 10040, 4, 1];

/// Errors from a DSA operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// `(p, q, g)` failed validation: a width outside the FIPS 186-4 set, an
    /// even `p` or `q`, `q ∤ p − 1`, `g ∉ (1, p)`, `g^q ≢ 1 (mod p)`, or a
    /// composite `q`.
    InvalidParameters,
    /// `y` was outside `(1, p)` or not in the order-`q` subgroup
    /// (`y^q ≢ 1 (mod p)`).
    InvalidPublicKey,
    /// `x` was outside `[1, q − 1]`.
    InvalidPrivateKey,
    /// A value was out of range for the requested encoding (e.g. a signature
    /// component wider than the `q` width it was to be serialized at).
    InvalidInput,
    /// A signature failed verification (including `r` or `s` outside
    /// `[1, q − 1]`).
    Verification,
    /// An encoded key, parameter set, or signature was malformed.
    Malformed,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InvalidParameters => "invalid DSA domain parameters",
            Error::InvalidPublicKey => "invalid DSA public key",
            Error::InvalidPrivateKey => "invalid DSA private key",
            Error::InvalidInput => "DSA value out of range for its encoding",
            Error::Verification => "DSA signature verification failed",
            Error::Malformed => "malformed DSA encoding",
        })
    }
}

impl core::error::Error for Error {}

/// A DSA domain-parameter set `(p, q, g)`: `p` an `L`-bit prime, `q` an
/// `N`-bit prime dividing `p − 1`, and `g` a generator of the order-`q`
/// subgroup of `Z_p^*`. See the [module docs](self) for what
/// [`new`](Self::new) validates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsaParams {
    p: BoxedUint,
    q: BoxedUint,
    g: BoxedUint,
}

/// A DSA public key `y = g^x mod p` on a parameter set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsaPublicKey {
    params: DsaParams,
    y: BoxedUint,
}

/// A DSA private key `x ∈ [1, q − 1]` on a parameter set.
#[derive(Clone)]
pub struct DsaPrivateKey {
    params: DsaParams,
    x: BoxedUint,
}

/// A DSA signature `(r, s)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DsaSignature {
    r: BoxedUint,
    s: BoxedUint,
}

/// `1 ≤ v < n`, evaluated without short-circuiting (`v` may be a secret:
/// a private scalar on import, a nonce candidate in rejection sampling).
fn in_range(v: &BoxedUint, n: &BoxedUint) -> bool {
    (!v.ct_is_zero() & v.reduce(n).ct_eq(v)).into()
}

/// FIPS 186-4 §4.6 / RFC 6979 `bits2int`: the integer formed by the leftmost
/// `qbits` bits of `data` (all of it when the digest is no wider than `q`).
fn bits2int(data: &[u8], qbits: usize) -> BoxedUint {
    let blen = data.len() * 8;
    let v = BoxedUint::from_be_bytes(data);
    if blen > qbits {
        v.shr_bits(blen - qbits)
    } else {
        v
    }
}

/// The RFC 6979 §3.2 HMAC-DRBG that produces DSA nonces.
///
/// One instance per signature; [`next_k`](Self::next_k) yields the first
/// suitable `k` and, if the signer has to retry because `r = 0` or `s = 0`,
/// the following ones by the same `K = HMAC_K(V ‖ 0x00)`, `V = HMAC_K(V)`
/// update the RFC prescribes for an unsuitable candidate (§3.2 step h.3 and
/// the note in §3.3).
struct Rfc6979<D: Digest> {
    k: D::Output,
    v: D::Output,
    q: BoxedUint,
    qlen: usize,
    qbits: usize,
    /// Whether a candidate has already been handed out, i.e. whether the
    /// next call must first run the step-h.3 update.
    started: bool,
}

impl<D: Digest> Rfc6979<D> {
    fn new(x: &BoxedUint, hash: &[u8], q: &BoxedUint, qlen: usize, qbits: usize) -> Self {
        let mut x_oct = x.to_be_bytes(qlen);
        let mut h_oct = bits2int(hash, qbits).reduce(q).to_be_bytes(qlen);

        let mut v = D::zeroed_output();
        for b in v.as_mut() {
            *b = 0x01;
        }
        let mut k = D::zeroed_output();
        for &sep in &[0x00u8, 0x01u8] {
            let mut mac = Hmac::<D>::new(k.as_ref());
            mac.update(v.as_ref());
            mac.update(&[sep]);
            mac.update(&x_oct);
            mac.update(&h_oct);
            k = mac.finalize();
            v = Hmac::<D>::mac(k.as_ref(), v.as_ref());
        }
        // `x_oct` is the private key in the clear.
        x_oct.zeroize();
        h_oct.zeroize();
        Rfc6979 {
            k,
            v,
            q: q.clone(),
            qlen,
            qbits,
            started: false,
        }
    }

    /// Step h.3: the state update after a rejected candidate.
    fn step(&mut self) {
        let mut mac = Hmac::<D>::new(self.k.as_ref());
        mac.update(self.v.as_ref());
        mac.update(&[0x00]);
        self.k = mac.finalize();
        self.v = Hmac::<D>::mac(self.k.as_ref(), self.v.as_ref());
    }

    /// The next `k ∈ [1, q − 1]`.
    fn next_k(&mut self) -> BoxedUint {
        loop {
            if self.started {
                self.step();
            }
            self.started = true;
            let mut t = Vec::with_capacity(self.qlen);
            while t.len() < self.qlen {
                self.v = Hmac::<D>::mac(self.k.as_ref(), self.v.as_ref());
                t.extend_from_slice(self.v.as_ref());
            }
            let candidate = bits2int(&t[..self.qlen], self.qbits);
            t.zeroize();
            if in_range(&candidate, &self.q) {
                return candidate;
            }
        }
    }
}

impl<D: Digest> Drop for Rfc6979<D> {
    fn drop(&mut self) {
        // The DRBG state reproduces every nonce, and a nonce recovers `x`.
        self.k.as_mut().zeroize();
        self.v.as_mut().zeroize();
    }
}

impl DsaParams {
    /// The `p` widths FIPS 186-4 §4.2 allows, in bits.
    pub const P_BITS: &'static [usize] = &[1024, 2048, 3072];
    /// The `q` widths FIPS 186-4 §4.2 allows, in bits.
    pub const Q_BITS: &'static [usize] = &[160, 224, 256];
    /// Miller-Rabin rounds run on `q` by [`new`](Self::new): a `4⁻⁶⁴`
    /// false-accept bound per candidate. The bases come from an HMAC-DRBG
    /// seeded with `q` itself (the verdict must be reproducible and no RNG is
    /// plumbed through key parsing), so this is a soundness check on an
    /// honest-but-wrong parameter set rather than an adversarial bound — the
    /// same trade `dh::DhGroup::from_custom` makes.
    pub const Q_MR_ROUNDS: usize = 64;

    /// Builds and validates a parameter set. Checks, in order:
    /// * `p.bit_len() ∈ {1024, 2048, 3072}` and `q.bit_len() ∈ {160, 224,
    ///   256}` (any pairing);
    /// * `p` and `q` odd;
    /// * `q | p − 1`;
    /// * `1 < g < p` and `g^q ≡ 1 (mod p)`;
    /// * `q` is a probable prime ([`Q_MR_ROUNDS`](Self::Q_MR_ROUNDS)).
    ///
    /// `p` is **not** primality-tested; see the [module docs](self).
    pub fn new(p: BoxedUint, q: BoxedUint, g: BoxedUint) -> Result<Self, Error> {
        use crate::bignum::prime::is_prime_boxed;
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;

        if !Self::P_BITS.contains(&p.bit_len()) || !Self::Q_BITS.contains(&q.bit_len()) {
            return Err(Error::InvalidParameters);
        }
        if !p.is_odd() || !q.is_odd() {
            return Err(Error::InvalidParameters);
        }
        let one = BoxedUint::from_u64(1);
        if !p.sub(&one).reduce(&q).is_zero() {
            return Err(Error::InvalidParameters);
        }
        if g.is_zero() || g == one || !g.lt(&p) {
            return Err(Error::InvalidParameters);
        }
        // Everything here is public, so the variable-time exponentiation is
        // the right tool.
        if BoxedMontModulus::new(&p).pow_public(&g, &q) != one {
            return Err(Error::InvalidParameters);
        }
        let mut rng = HmacDrbg::<Sha256>::new(
            &q.to_be_bytes(q.bit_len().div_ceil(8)),
            b"purecrypto-dsa-q-mr-bases",
            &[],
        );
        if !is_prime_boxed(&q, &mut rng, Self::Q_MR_ROUNDS) {
            return Err(Error::InvalidParameters);
        }
        Ok(DsaParams { p, q, g })
    }

    /// [`new`](Self::new) from big-endian byte strings (leading zeros are
    /// fine, so the DER-style `00`-prefixed forms work as-is).
    pub fn from_be_bytes(p: &[u8], q: &[u8], g: &[u8]) -> Result<Self, Error> {
        Self::new(
            BoxedUint::from_be_bytes(p),
            BoxedUint::from_be_bytes(q),
            BoxedUint::from_be_bytes(g),
        )
    }

    /// The prime modulus `p`.
    pub fn p(&self) -> &BoxedUint {
        &self.p
    }

    /// The subgroup order `q`.
    pub fn q(&self) -> &BoxedUint {
        &self.q
    }

    /// The subgroup generator `g`.
    pub fn g(&self) -> &BoxedUint {
        &self.g
    }

    /// `L`, the bit length of `p`.
    pub fn p_bits(&self) -> usize {
        self.p.bit_len()
    }

    /// `N`, the bit length of `q`.
    pub fn q_bits(&self) -> usize {
        self.q.bit_len()
    }

    /// The byte width of `p` (`L / 8`).
    pub fn p_len(&self) -> usize {
        self.p.bit_len().div_ceil(8)
    }

    /// The byte width of `q` (`N / 8`): the width of each P1363 signature
    /// half and of a serialized private key.
    pub fn q_len(&self) -> usize {
        self.q.bit_len().div_ceil(8)
    }

    /// Encodes the `Dss-Parms ::= SEQUENCE { p, q, g INTEGER }` (RFC 3279
    /// §2.3.2).
    pub fn to_der(&self) -> Vec<u8> {
        encode_sequence(
            &[
                encode_integer(&self.p.to_be_bytes(self.p_len())),
                encode_integer(&self.q.to_be_bytes(self.q_len())),
                encode_integer(&self.g.to_be_bytes(self.p_len())),
            ]
            .concat(),
        )
    }

    /// Parses and validates a `Dss-Parms` sequence.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(der);
        let params = Self::read(&mut r)?;
        r.finish().map_err(|_| Error::Malformed)?;
        Ok(params)
    }

    /// Reads one `Dss-Parms` sequence from `r`.
    fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
        let mut seq = r.read_sequence().map_err(|_| Error::Malformed)?;
        let p = seq
            .read_unsigned_integer_bytes()
            .map_err(|_| Error::Malformed)?;
        let q = seq
            .read_unsigned_integer_bytes()
            .map_err(|_| Error::Malformed)?;
        let g = seq
            .read_unsigned_integer_bytes()
            .map_err(|_| Error::Malformed)?;
        seq.finish().map_err(|_| Error::Malformed)?;
        Self::from_be_bytes(p, q, g)
    }

    /// [`to_der`](Self::to_der) as a `-----BEGIN DSA PARAMETERS-----` PEM
    /// document (the `openssl dsaparam` form).
    pub fn to_pem(&self) -> String {
        crate::der::pem_encode("DSA PARAMETERS", &self.to_der())
    }

    /// Parses a `-----BEGIN DSA PARAMETERS-----` PEM document.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        let der = crate::der::pem_decode(pem, "DSA PARAMETERS").map_err(|_| Error::Malformed)?;
        Self::from_der(&der)
    }

    /// The `AlgorithmIdentifier { id-dsa, Dss-Parms }` used by both SPKI and
    /// PKCS#8.
    fn algorithm_identifier(&self) -> Vec<u8> {
        encode_sequence(&[oid_tlv(ID_DSA_OID), self.to_der()].concat())
    }

    /// Reads an `AlgorithmIdentifier`, requiring `id-dsa` with `Dss-Parms`.
    fn read_algorithm_identifier(r: &mut Reader<'_>) -> Result<Self, Error> {
        let mut algid = r.read_sequence().map_err(|_| Error::Malformed)?;
        let oid = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        if oid.as_slice() != ID_DSA_OID {
            return Err(Error::Malformed);
        }
        // RFC 3279 makes the parameters OPTIONAL (inherited from the CA
        // certificate when absent); a key without them cannot be used, so
        // it is rejected here rather than half-parsed.
        let params = Self::read(&mut algid)?;
        algid.finish().map_err(|_| Error::Malformed)?;
        Ok(params)
    }
}

impl DsaPublicKey {
    /// Builds a public key, checking `1 < y < p` and `y^q ≡ 1 (mod p)`
    /// (FIPS 186-4 Appendix A / SP 800-89 §5.3.1 full public-key
    /// validation).
    pub fn new(params: DsaParams, y: BoxedUint) -> Result<Self, Error> {
        let one = BoxedUint::from_u64(1);
        if y.is_zero() || y == one || !y.lt(&params.p) {
            return Err(Error::InvalidPublicKey);
        }
        if BoxedMontModulus::new(&params.p).pow_public(&y, &params.q) != one {
            return Err(Error::InvalidPublicKey);
        }
        Ok(DsaPublicKey { params, y })
    }

    /// [`new`](Self::new) from a big-endian `y`.
    pub fn from_be_bytes(params: DsaParams, y: &[u8]) -> Result<Self, Error> {
        Self::new(params, BoxedUint::from_be_bytes(y))
    }

    /// The parameter set.
    pub fn params(&self) -> &DsaParams {
        &self.params
    }

    /// The public value `y`.
    pub fn y(&self) -> &BoxedUint {
        &self.y
    }

    /// `y` as big-endian bytes, left-padded to the width of `p`.
    pub fn y_bytes(&self) -> Vec<u8> {
        self.y.to_be_bytes(self.params.p_len())
    }

    /// Verifies `sig` over `msg`, hashing with `D`.
    pub fn verify<D: Digest>(&self, msg: &[u8], sig: &DsaSignature) -> Result<(), Error> {
        self.verify_prehash(D::digest(msg).as_ref(), sig)
    }

    /// Verifies `sig` over an already-computed digest, per FIPS 186-4 §4.7:
    /// `prehash` is truncated to its leftmost `min(N, |prehash|)` bits, `r`
    /// and `s` must both lie in `[1, q − 1]`, and
    /// `(g^(z·s⁻¹) · y^(r·s⁻¹) mod p) mod q` must equal `r`.
    ///
    /// Everything here is public, so the exponentiations are variable-time.
    pub fn verify_prehash(&self, prehash: &[u8], sig: &DsaSignature) -> Result<(), Error> {
        let (p, q, g) = (&self.params.p, &self.params.q, &self.params.g);
        // Plain (variable-time) comparisons: a signature is public.
        if sig.r.is_zero() || sig.s.is_zero() || !sig.r.lt(q) || !sig.s.lt(q) {
            return Err(Error::Verification);
        }
        let fq = BoxedMontModulus::new(q);
        let fp = BoxedMontModulus::new(p);
        let z = bits2int(prehash, q.bit_len()).reduce(q);
        // `q` prime and `1 ≤ s < q` make the inverse exist; `None` can only
        // mean a composite `q` that slipped past Miller-Rabin, and then the
        // signature is not verifiable in any meaningful sense.
        let w = inv_mod_odd_ct_boxed(&sig.s, q)
            .into_option()
            .ok_or(Error::Verification)?;
        let u1 = fq.mul_mod(&z, &w);
        let u2 = fq.mul_mod(&sig.r, &w);
        let v = fp
            .mul_mod(&fp.pow_public(g, &u1), &fp.pow_public(&self.y, &u2))
            .reduce(q);
        if v == sig.r {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }

    /// Encodes the key as an X.509 `SubjectPublicKeyInfo`: `id-dsa` with the
    /// `Dss-Parms` as algorithm parameters, and a DER `INTEGER y` in the
    /// `subjectPublicKey` BIT STRING (RFC 3279 §2.3.2).
    pub fn to_spki_der(&self) -> Vec<u8> {
        let y = encode_integer(&self.y_bytes());
        encode_sequence(&[self.params.algorithm_identifier(), encode_bit_string(&y)].concat())
    }

    /// Parses an X.509 `SubjectPublicKeyInfo` carrying a DSA key, validating
    /// the parameters and the public value as [`new`](Self::new) does.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(der);
        let mut seq = r.read_sequence().map_err(|_| Error::Malformed)?;
        let params = DsaParams::read_algorithm_identifier(&mut seq)?;
        let bits = seq.read_bit_string().map_err(|_| Error::Malformed)?;
        seq.finish().map_err(|_| Error::Malformed)?;
        r.finish().map_err(|_| Error::Malformed)?;
        let mut yr = Reader::new(bits);
        let y = yr
            .read_unsigned_integer_bytes()
            .map_err(|_| Error::Malformed)?;
        yr.finish().map_err(|_| Error::Malformed)?;
        Self::from_be_bytes(params, y)
    }

    /// [`to_spki_der`](Self::to_spki_der) as a `-----BEGIN PUBLIC KEY-----`
    /// PEM document.
    pub fn to_spki_pem(&self) -> String {
        crate::der::pem_encode("PUBLIC KEY", &self.to_spki_der())
    }

    /// Parses a `-----BEGIN PUBLIC KEY-----` PEM document.
    pub fn from_spki_pem(pem: &str) -> Result<Self, Error> {
        let der = crate::der::pem_decode(pem, "PUBLIC KEY").map_err(|_| Error::Malformed)?;
        Self::from_spki_der(&der)
    }
}

impl DsaPrivateKey {
    /// Generates a private key: `x` uniform in `[1, q − 1]` by rejection
    /// sampling (FIPS 186-4 B.1.2), drawn from `rng`, which must be a CSPRNG.
    pub fn generate<R: RngCore + CryptoRng>(params: DsaParams, rng: &mut R) -> Self {
        let q = &params.q;
        let qlen = params.q_len();
        // Mask the top byte to `q.bit_len()` bits so the draw is uniform over
        // `[0, 2^N)` and the rejection rate stays below one half.
        let keep = ((q.bit_len() - 1) % 8) + 1;
        let mask = if keep == 8 { 0xff } else { (1u8 << keep) - 1 };
        let x = loop {
            let mut buf = vec![0u8; qlen];
            rng.fill_bytes(&mut buf);
            buf[0] &= mask;
            let candidate = BoxedUint::from_be_bytes(&buf);
            buf.zeroize();
            if in_range(&candidate, q) {
                break candidate;
            }
        };
        DsaPrivateKey { params, x }
    }

    /// Builds a private key, checking `1 ≤ x ≤ q − 1` without branching on
    /// the value.
    pub fn new(params: DsaParams, x: BoxedUint) -> Result<Self, Error> {
        if !in_range(&x, &params.q) {
            return Err(Error::InvalidPrivateKey);
        }
        Ok(DsaPrivateKey { params, x })
    }

    /// [`new`](Self::new) from a big-endian `x`.
    pub fn from_be_bytes(params: DsaParams, x: &[u8]) -> Result<Self, Error> {
        Self::new(params, BoxedUint::from_be_bytes(x))
    }

    /// The parameter set.
    pub fn params(&self) -> &DsaParams {
        &self.params
    }

    /// `x` as big-endian bytes, left-padded to the width of `q`.
    pub fn x_bytes(&self) -> Vec<u8> {
        self.x.to_be_bytes(self.params.q_len())
    }

    /// The public key `y = g^x mod p` (constant-time in `x`).
    pub fn public_key(&self) -> DsaPublicKey {
        let y = BoxedMontModulus::new(&self.params.p).pow(&self.params.g, &self.x);
        DsaPublicKey {
            params: self.params.clone(),
            y,
        }
    }

    /// Signs `msg`, hashing with `D` and deriving the nonce per RFC 6979.
    pub fn sign<D: Digest>(&self, msg: &[u8]) -> Result<DsaSignature, Error> {
        self.sign_prehash::<D>(D::digest(msg).as_ref())
    }

    /// Signs an already-computed digest. `D` is the hash used for the RFC
    /// 6979 nonce derivation — pass the one that produced `prehash` so the
    /// result matches [`sign::<D>`](Self::sign). `prehash` is truncated to
    /// the leftmost `N` bits when wider than `q` (FIPS 186-4 §4.6).
    ///
    /// # Constant time
    /// `g^k mod p` uses the constant-time [`BoxedMontModulus::pow`] (a
    /// fixed-window ladder padded to the width of `p`), `k⁻¹ mod q` the
    /// constant-time binary extended GCD, and `x·r`, `z + x·r`, `k⁻¹·(…)`
    /// the Montgomery `mul_mod`/`add_mod`. The `r = 0` / `s = 0` retry is
    /// public (it reveals nothing beyond the fact that the DRBG's first
    /// candidate produced a degenerate signature, probability `≈ 2^-N`).
    ///
    /// # Security
    /// The caller owns the guarantee that `prehash` is a strong digest of the
    /// intended message; prefer [`sign`](Self::sign) when the message is at
    /// hand.
    pub fn sign_prehash<D: Digest>(&self, prehash: &[u8]) -> Result<DsaSignature, Error> {
        let (p, q, g) = (&self.params.p, &self.params.q, &self.params.g);
        let fq = BoxedMontModulus::new(q);
        let fp = BoxedMontModulus::new(p);
        let qbits = q.bit_len();
        let z = bits2int(prehash, qbits).reduce(q);
        let mut drbg = Rfc6979::<D>::new(&self.x, prehash, q, self.params.q_len(), qbits);
        loop {
            let mut k = drbg.next_k();
            let r = fp.pow(g, &k).reduce(q);
            if r.is_zero() {
                k.zeroize();
                continue;
            }
            // `1 ≤ k < q` with `q` prime always has an inverse; `None` means
            // `q` is composite after all, and no `k` will do better.
            let Some(mut k_inv) = inv_mod_odd_ct_boxed(&k, q).into_option() else {
                k.zeroize();
                return Err(Error::InvalidParameters);
            };
            let mut xr = fq.mul_mod(&self.x, &r);
            let mut z_xr = fq.add_mod(&z, &xr);
            let s = fq.mul_mod(&k_inv, &z_xr);
            // `k` alone recovers `x = (s·k − z)·r⁻¹ mod q`; wipe every
            // per-signature secret before the buffers go back to the
            // allocator (the `BoxedUint` `Drop` would too — this keeps the
            // window explicit).
            k.zeroize();
            k_inv.zeroize();
            xr.zeroize();
            z_xr.zeroize();
            if s.is_zero() {
                continue;
            }
            return Ok(DsaSignature { r, s });
        }
    }

    /// Encodes the key as an unencrypted PKCS#8 `PrivateKeyInfo` (RFC 5958):
    /// version 0, `id-dsa` with `Dss-Parms`, and a DER `INTEGER x` in the
    /// `privateKey` OCTET STRING — the layout `openssl pkcs8` writes.
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        let x = encode_integer(&self.x_bytes());
        encode_sequence(
            &[
                encode_integer(&[0]),
                self.params.algorithm_identifier(),
                encode_octet_string(&x),
            ]
            .concat(),
        )
    }

    /// Parses an unencrypted PKCS#8 `PrivateKeyInfo` wrapping a DSA key.
    ///
    /// The RFC 5958 OPTIONAL `[0]` attributes are skipped; an OPTIONAL `[1]`
    /// publicKey (`INTEGER y` in a BIT STRING) is checked against `g^x`, so
    /// a file whose two halves disagree is rejected as [`Error::Malformed`]
    /// rather than yielding a key nobody can verify against.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
        let mut r = Reader::new(der);
        let mut seq = r.read_sequence().map_err(|_| Error::Malformed)?;
        let version = seq
            .read_unsigned_integer_bytes()
            .map_err(|_| Error::Malformed)?;
        if version != [0] && version != [1] {
            return Err(Error::Malformed);
        }
        let params = DsaParams::read_algorithm_identifier(&mut seq)?;
        let inner = seq.read_octet_string().map_err(|_| Error::Malformed)?;
        let mut xr = Reader::new(inner);
        let x = xr
            .read_unsigned_integer_bytes()
            .map_err(|_| Error::Malformed)?;
        xr.finish().map_err(|_| Error::Malformed)?;
        let key = Self::from_be_bytes(params, x)?;
        if seq.peek_tag() == Some(tag::context(0)) {
            seq.read_any().map_err(|_| Error::Malformed)?;
        }
        // `[1] IMPLICIT BIT STRING`: the primitive tag `0x81`; accept the
        // constructed spelling too, as the EC parser does.
        if matches!(seq.peek_tag(), Some(t) if t == tag::context(1) || t == 0x81) {
            let (_, body) = seq.read_any().map_err(|_| Error::Malformed)?;
            // The body is the BIT STRING contents: unused-bits octet, then
            // the DER INTEGER y.
            let Some((0, y_der)) = body.split_first() else {
                return Err(Error::Malformed);
            };
            let mut yr = Reader::new(y_der);
            let y = yr
                .read_unsigned_integer_bytes()
                .map_err(|_| Error::Malformed)?;
            yr.finish().map_err(|_| Error::Malformed)?;
            if BoxedUint::from_be_bytes(y) != key.public_key().y {
                return Err(Error::Malformed);
            }
        }
        seq.finish().map_err(|_| Error::Malformed)?;
        r.finish().map_err(|_| Error::Malformed)?;
        Ok(key)
    }

    /// [`to_pkcs8_der`](Self::to_pkcs8_der) as a `-----BEGIN PRIVATE KEY-----`
    /// PEM document.
    pub fn to_pkcs8_pem(&self) -> String {
        crate::der::pem_encode("PRIVATE KEY", &self.to_pkcs8_der())
    }

    /// Parses a `-----BEGIN PRIVATE KEY-----` PEM document.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
        let der = crate::der::pem_decode(pem, "PRIVATE KEY").map_err(|_| Error::Malformed)?;
        Self::from_pkcs8_der(&der)
    }
}

impl core::fmt::Debug for DsaPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DsaPrivateKey")
            .field("params", &self.params)
            .field("x", &"<redacted>")
            .finish()
    }
}

impl Drop for DsaPrivateKey {
    fn drop(&mut self) {
        self.x.zeroize();
    }
}

impl crate::zeroize::ZeroizeOnDrop for DsaPrivateKey {}

impl DsaSignature {
    /// The widest `q` this module accepts, in bytes (256 bits). A DER
    /// component wider than this is rejected at parse time so the fixed-width
    /// re-encoders never see a value that cannot be a valid `r` or `s`.
    pub const MAX_Q_LEN: usize = 32;

    /// Wraps raw `(r, s)`; no range check (the verifier does that).
    pub fn from_components(r: BoxedUint, s: BoxedUint) -> Self {
        DsaSignature { r, s }
    }

    /// `r`.
    pub fn r(&self) -> &BoxedUint {
        &self.r
    }

    /// `s`.
    pub fn s(&self) -> &BoxedUint {
        &self.s
    }

    /// Encodes as DER `Dss-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }`
    /// (RFC 3279 §2.2.2), each integer minimally encoded.
    pub fn to_der(&self) -> Vec<u8> {
        let int = |v: &BoxedUint| encode_integer(&v.to_be_bytes(v.bit_len().div_ceil(8).max(1)));
        encode_sequence(&[int(&self.r), int(&self.s)].concat())
    }

    /// Decodes a DER `Dss-Sig-Value` under strict DER: definite minimal
    /// lengths, no empty INTEGER, no unnecessary leading `0x00` (so a legacy
    /// "missing zero" encoding whose top bit is set is read as negative and
    /// rejected), no `0xff` sign padding, no trailing data, and each
    /// component at most [`MAX_Q_LEN`](Self::MAX_Q_LEN) bytes of magnitude.
    /// Rejecting every non-canonical spelling is what keeps a DSA signature
    /// non-malleable at the byte level.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(der);
        let mut seq = reader.read_sequence().map_err(|_| Error::Malformed)?;
        let r = seq
            .read_unsigned_integer_bytes()
            .map_err(|_| Error::Malformed)?;
        let s = seq
            .read_unsigned_integer_bytes()
            .map_err(|_| Error::Malformed)?;
        seq.finish().map_err(|_| Error::Malformed)?;
        reader.finish().map_err(|_| Error::Malformed)?;
        let magnitude = |body: &[u8]| match body {
            [0x00, rest @ ..] => rest.len(),
            _ => body.len(),
        };
        if magnitude(r) > Self::MAX_Q_LEN || magnitude(s) > Self::MAX_Q_LEN {
            return Err(Error::Malformed);
        }
        Ok(DsaSignature {
            r: BoxedUint::from_be_bytes(r),
            s: BoxedUint::from_be_bytes(s),
        })
    }

    /// Decodes the IEEE P1363 form `r ‖ s`, each half exactly `q_len` bytes
    /// (see [`DsaParams::q_len`]); any other length is [`Error::Malformed`].
    pub fn from_p1363(bytes: &[u8], q_len: usize) -> Result<Self, Error> {
        if q_len == 0 || bytes.len() != 2 * q_len {
            return Err(Error::Malformed);
        }
        let (r, s) = bytes.split_at(q_len);
        Ok(DsaSignature {
            r: BoxedUint::from_be_bytes(r),
            s: BoxedUint::from_be_bytes(s),
        })
    }

    /// Encodes as IEEE P1363 `r ‖ s` with each half left-padded to `q_len`
    /// bytes. [`Error::InvalidInput`] when either component does not fit
    /// (a signature parsed for a wider `q`).
    pub fn to_p1363(&self, q_len: usize) -> Result<Vec<u8>, Error> {
        if self.r.bit_len().div_ceil(8) > q_len || self.s.bit_len().div_ceil(8) > q_len {
            return Err(Error::InvalidInput);
        }
        Ok([self.r.to_be_bytes(q_len), self.s.to_be_bytes(q_len)].concat())
    }
}

/// The 2048/256 parameter set of RFC 6979 A.2.2, for doctests and examples
/// (parameter generation is not implemented, so an example needs a set to
/// start from). Not a hidden test hook: it is a perfectly good parameter
/// set, just a well-known one, so generate keys on it only for examples.
#[doc(hidden)]
pub fn test_params_2048_256() -> DsaParams {
    fn hex(s: &str) -> BoxedUint {
        BoxedUint::from_be_bytes(
            &(0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
                .collect::<Vec<u8>>(),
        )
    }
    DsaParams::new(
        hex(RFC6979_2048_P),
        hex(RFC6979_2048_Q),
        hex(RFC6979_2048_G),
    )
    .expect("RFC 6979 A.2.2 parameters are valid")
}

// RFC 6979 A.2.2.
const RFC6979_2048_P: &str = "9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48\
    C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F\
    FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5\
    B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2\
    35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41\
    F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE\
    92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15\
    3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B";
const RFC6979_2048_Q: &str = "F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F";
const RFC6979_2048_G: &str = "5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613\
    D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4\
    6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472\
    085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5\
    AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA\
    3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71\
    BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0\
    DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha1, Sha224, Sha256, Sha384, Sha512};
    use crate::rng::HmacDrbg;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn uint(s: &str) -> BoxedUint {
        BoxedUint::from_be_bytes(&from_hex(s))
    }

    // RFC 6979 A.2.1: DSA 1024/160.
    const P1024: &str = "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447\
        E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88\
        73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C\
        881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779";
    const Q1024: &str = "996F967F6C8E388D9E28D01E205FBA957A5698B1";
    const G1024: &str = "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D\
        89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD\
        87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4\
        17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD";
    const X1024: &str = "411602CB19A6CCC34494D79D98EF1E7ED5AF25F7";
    const Y1024: &str = "5DF5E01DED31D0297E274E1691C192FE5868FEF9E19A84776454B100CF16F653\
        92195A38B90523E2542EE61871C0440CB87C322FC4B4D2EC5E1E7EC766E1BE8D\
        4CE935437DC11C3C8FD426338933EBFE739CB3465F4D3668C5E473508253B1E6\
        82F65CBDC4FAE93C2EA212390E54905A86E2223170B44EAA7DA5DD9FFCFB7F3B";

    // RFC 6979 A.2.2: DSA 2048/256 (parameters are the module constants).
    const X2048: &str = "69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC";
    const Y2048: &str = "667098C654426C78D7F8201EAC6C203EF030D43605032C2F1FA937E5237DBD94\
        9F34A0A2564FE126DC8B715C5141802CE0979C8246463C40E6B6BDAA2513FA61\
        1728716C2E4FD53BC95B89E69949D96512E873B9C8F8DFD499CC312882561ADE\
        CB31F658E934C0C197F2C4D96B05CBAD67381E7B768891E4DA3843D24D94CDFB\
        5126E9B8BF21E8358EE0E0A30EF13FD6A664C0DCE3731F7FB49A4845A4FD8254\
        687972A2D382599C9BAC4E0ED7998193078913032558134976410B89D2C171D1\
        23AC35FD977219597AA7D15C1A9A428E59194F75C721EBCBCFAE44696A499AFA\
        74E04299F132026601638CB87AB79190D4A0986315DA8EEC6561C938996BEADF";

    fn params_1024() -> DsaParams {
        DsaParams::new(uint(P1024), uint(Q1024), uint(G1024)).unwrap()
    }

    fn key_1024() -> DsaPrivateKey {
        DsaPrivateKey::new(params_1024(), uint(X1024)).unwrap()
    }

    fn key_2048() -> DsaPrivateKey {
        DsaPrivateKey::new(test_params_2048_256(), uint(X2048)).unwrap()
    }

    /// Signs `msg` with `D`, checks the RFC 6979 `(r, s)`, and verifies both
    /// the DER and P1363 round trips.
    fn rfc6979_case<D: Digest>(key: &DsaPrivateKey, msg: &[u8], r: &str, s: &str) {
        let sig = key.sign::<D>(msg).unwrap();
        let qlen = key.params().q_len();
        assert_eq!(sig.r.to_be_bytes(qlen), from_hex(r), "r");
        assert_eq!(sig.s.to_be_bytes(qlen), from_hex(s), "s");
        let pk = key.public_key();
        pk.verify::<D>(msg, &sig).unwrap();
        pk.verify::<D>(msg, &DsaSignature::from_der(&sig.to_der()).unwrap())
            .unwrap();
        pk.verify::<D>(
            msg,
            &DsaSignature::from_p1363(&sig.to_p1363(qlen).unwrap(), qlen).unwrap(),
        )
        .unwrap();
        // The prehash path must agree (same nonce derivation).
        assert_eq!(key.sign_prehash::<D>(D::digest(msg).as_ref()).unwrap(), sig);
        assert!(pk.verify::<D>(b"other", &sig).is_err());
    }

    #[test]
    fn rfc6979_a21_public_key() {
        let pk = key_1024().public_key();
        assert_eq!(pk.y_bytes(), from_hex(Y1024));
        assert_eq!(key_2048().public_key().y_bytes(), from_hex(Y2048));
    }

    #[test]
    fn rfc6979_a21_dsa_1024_sample() {
        let key = key_1024();
        rfc6979_case::<Sha1>(
            &key,
            b"sample",
            "2E1A0C2562B2912CAAF89186FB0F42001585DA55",
            "29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5",
        );
        rfc6979_case::<Sha224>(
            &key,
            b"sample",
            "4BC3B686AEA70145856814A6F1BB53346F02101E",
            "410697B92295D994D21EDD2F4ADA85566F6F94C1",
        );
        rfc6979_case::<Sha256>(
            &key,
            b"sample",
            "81F2F5850BE5BC123C43F71A3033E9384611C545",
            "4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89",
        );
        rfc6979_case::<Sha384>(
            &key,
            b"sample",
            "07F2108557EE0E3921BC1774F1CA9B410B4CE65A",
            "54DF70456C86FAC10FAB47C1949AB83F2C6F7595",
        );
        rfc6979_case::<Sha512>(
            &key,
            b"sample",
            "16C3491F9B8C3FBBDD5E7A7B667057F0D8EE8E1B",
            "02C36A127A7B89EDBB72E4FFBC71DABC7D4FC69C",
        );
    }

    #[test]
    fn rfc6979_a21_dsa_1024_test() {
        let key = key_1024();
        rfc6979_case::<Sha1>(
            &key,
            b"test",
            "42AB2052FD43E123F0607F115052A67DCD9C5C77",
            "183916B0230D45B9931491D4C6B0BD2FB4AAF088",
        );
        rfc6979_case::<Sha224>(
            &key,
            b"test",
            "6868E9964E36C1689F6037F91F28D5F2C30610F2",
            "49CEC3ACDC83018C5BD2674ECAAD35B8CD22940F",
        );
        rfc6979_case::<Sha256>(
            &key,
            b"test",
            "22518C127299B0F6FDC9872B282B9E70D0790812",
            "6837EC18F150D55DE95B5E29BE7AF5D01E4FE160",
        );
        rfc6979_case::<Sha384>(
            &key,
            b"test",
            "854CF929B58D73C3CBFDC421E8D5430CD6DB5E66",
            "91D0E0F53E22F898D158380676A871A157CDA622",
        );
        rfc6979_case::<Sha512>(
            &key,
            b"test",
            "8EA47E475BA8AC6F2D821DA3BD212D11A3DEB9A0",
            "7C670C7AD72B6C050C109E1790008097125433E8",
        );
    }

    #[test]
    fn rfc6979_a22_dsa_2048_sample() {
        let key = key_2048();
        rfc6979_case::<Sha1>(
            &key,
            b"sample",
            "3A1B2DBD7489D6ED7E608FD036C83AF396E290DBD602408E8677DAABD6E7445A",
            "D26FCBA19FA3E3058FFC02CA1596CDBB6E0D20CB37B06054F7E36DED0CDBBCCF",
        );
        rfc6979_case::<Sha224>(
            &key,
            b"sample",
            "DC9F4DEADA8D8FF588E98FED0AB690FFCE858DC8C79376450EB6B76C24537E2C",
            "A65A9C3BC7BABE286B195D5DA68616DA8D47FA0097F36DD19F517327DC848CEC",
        );
        rfc6979_case::<Sha256>(
            &key,
            b"sample",
            "EACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809",
            "7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53",
        );
        rfc6979_case::<Sha384>(
            &key,
            b"sample",
            "B2DA945E91858834FD9BF616EBAC151EDBC4B45D27D0DD4A7F6A22739F45C00B",
            "19048B63D9FD6BCA1D9BAE3664E1BCB97F7276C306130969F63F38FA8319021B",
        );
        rfc6979_case::<Sha512>(
            &key,
            b"sample",
            "2016ED092DC5FB669B8EFB3D1F31A91EECB199879BE0CF78F02BA062CB4C942E",
            "D0C76F84B5F091E141572A639A4FB8C230807EEA7D55C8A154A224400AFF2351",
        );
    }

    #[test]
    fn rfc6979_a22_dsa_2048_test() {
        let key = key_2048();
        rfc6979_case::<Sha1>(
            &key,
            b"test",
            "C18270A93CFC6063F57A4DFA86024F700D980E4CF4E2CB65A504397273D98EA0",
            "414F22E5F31A8B6D33295C7539C1C1BA3A6160D7D68D50AC0D3A5BEAC2884FAA",
        );
        rfc6979_case::<Sha224>(
            &key,
            b"test",
            "272ABA31572F6CC55E30BF616B7A265312018DD325BE031BE0CC82AA17870EA3",
            "E9CC286A52CCE201586722D36D1E917EB96A4EBDB47932F9576AC645B3A60806",
        );
        rfc6979_case::<Sha256>(
            &key,
            b"test",
            "8190012A1969F9957D56FCCAAD223186F423398D58EF5B3CEFD5A4146A4476F0",
            "7452A53F7075D417B4B013B278D1BB8BBD21863F5E7B1CEE679CF2188E1AB19E",
        );
        rfc6979_case::<Sha384>(
            &key,
            b"test",
            "239E66DDBE8F8C230A3D071D601B6FFBDFB5901F94D444C6AF56F732BEB954BE",
            "6BD737513D5E72FE85D1C750E0F73921FE299B945AAD1C802F15C26A43D34961",
        );
        rfc6979_case::<Sha512>(
            &key,
            b"test",
            "89EC4BB1400ECCFF8E7D9AA515CD1DE7803F2DAFF09693EE7FD1353E90A68307",
            "C9F0BDABCC0D880BB137A994CC7F3980CE91CC10FAF529FC46565B15CEA854E1",
        );
    }

    #[test]
    fn params_validation() {
        let (p, q, g) = (uint(P1024), uint(Q1024), uint(G1024));
        let one = BoxedUint::from_u64(1);
        // Wrong widths.
        assert_eq!(
            DsaParams::new(p.shr_bits(1), q.clone(), g.clone()),
            Err(Error::InvalidParameters)
        );
        assert_eq!(
            DsaParams::new(p.clone(), q.shr_bits(1), g.clone()),
            Err(Error::InvalidParameters)
        );
        // q must divide p - 1: swap in the 2048-bit q (right width, wrong
        // value).
        assert_eq!(
            DsaParams::new(p.clone(), uint(RFC6979_2048_Q), g.clone()),
            Err(Error::InvalidParameters)
        );
        // g out of range / outside the subgroup.
        assert_eq!(
            DsaParams::new(p.clone(), q.clone(), one.clone()),
            Err(Error::InvalidParameters)
        );
        assert_eq!(
            DsaParams::new(p.clone(), q.clone(), p.clone()),
            Err(Error::InvalidParameters)
        );
        assert_eq!(
            DsaParams::new(p.clone(), q.clone(), BoxedUint::from_u64(2)),
            Err(Error::InvalidParameters)
        );
        // Even p / q.
        assert_eq!(
            DsaParams::new(p.add(&one), q.clone(), g.clone()),
            Err(Error::InvalidParameters)
        );
        assert!(DsaParams::new(p, q, g).is_ok());
    }

    #[test]
    fn composite_q_rejected_by_miller_rabin() {
        // A parameter set that passes every structural check — 1024-bit
        // prime p, 160-bit q | p − 1, g = 2^((p−1)/q) with g^q ≡ 1 — except
        // that q is the product of two 80-bit primes. Only the Miller-Rabin
        // gate can reject it.
        let p = uint(
            "B25BE6AAED7A8634058D99FF01BD8878B9D56E54868606718A6A219554002B8E\
             77F24A3A14AD5137B66B7310E5AB5650CD8E0F7F7AF3C4FCEDB1443D6B17C1C1\
             F6787026EE046A0EBDDA0D7470D20E770896F6EA52AF68288368793438EC7D29\
             0F5A6B0461637F277EEB731F9539C0334A74B91EBE6EA303D1A8C705AA774A25",
        );
        let q = uint("BCE61076461C84A1DCF749421983FB235711AEBB");
        let g = uint(
            "9E9732C32B7A5E1234CAB03860F29EF6B3DC2BDDC5035F4C98BED816E8E73E98\
             19DDD333B8355D1090126E1FECF88515366D859816DD3FDE3892E51F95B7F73D\
             99C3EED4F46711371134F307219831FF19307BA62FF6A972B109F7D5614561AF\
             E30C5A0644B3087A03A2632CF344134CC1E3D51CAEC1930FF0632F2C1B7BBBB7",
        );
        // Sanity: the structural checks do hold.
        let one = BoxedUint::from_u64(1);
        assert_eq!(p.bit_len(), 1024);
        assert_eq!(q.bit_len(), 160);
        assert!(p.sub(&one).reduce(&q).is_zero());
        assert_eq!(BoxedMontModulus::new(&p).pow_public(&g, &q), one);
        assert_eq!(DsaParams::new(p, q, g), Err(Error::InvalidParameters));
    }

    #[test]
    fn public_key_validation() {
        let params = params_1024();
        let p = params.p().clone();
        let one = BoxedUint::from_u64(1);
        assert_eq!(
            DsaPublicKey::new(params.clone(), BoxedUint::from_u64(0)),
            Err(Error::InvalidPublicKey)
        );
        assert_eq!(
            DsaPublicKey::new(params.clone(), one.clone()),
            Err(Error::InvalidPublicKey)
        );
        assert_eq!(
            DsaPublicKey::new(params.clone(), p.clone()),
            Err(Error::InvalidPublicKey)
        );
        // p − 1 has order 2, not q.
        assert_eq!(
            DsaPublicKey::new(params.clone(), p.sub(&one)),
            Err(Error::InvalidPublicKey)
        );
        // 2 is (almost surely) not in the order-q subgroup.
        assert_eq!(
            DsaPublicKey::new(params.clone(), BoxedUint::from_u64(2)),
            Err(Error::InvalidPublicKey)
        );
        assert!(DsaPublicKey::new(params, uint(Y1024)).is_ok());
    }

    #[test]
    fn private_key_range() {
        let params = params_1024();
        assert_eq!(
            DsaPrivateKey::new(params.clone(), BoxedUint::from_u64(0)).err(),
            Some(Error::InvalidPrivateKey)
        );
        assert_eq!(
            DsaPrivateKey::new(params.clone(), params.q().clone()).err(),
            Some(Error::InvalidPrivateKey)
        );
        let q_minus_1 = params.q().sub(&BoxedUint::from_u64(1));
        assert!(DsaPrivateKey::new(params.clone(), q_minus_1).is_ok());
        assert!(DsaPrivateKey::new(params, BoxedUint::from_u64(1)).is_ok());
    }

    #[test]
    fn generate_sign_verify() {
        let mut rng = HmacDrbg::<Sha256>::new(b"dsa-generate-test", b"", b"");
        let key = DsaPrivateKey::generate(params_1024(), &mut rng);
        assert!(in_range(&key.x, key.params().q()));
        let pk = key.public_key();
        let sig = key.sign::<Sha256>(b"hello").unwrap();
        pk.verify::<Sha256>(b"hello", &sig).unwrap();
        assert!(pk.verify::<Sha256>(b"hellp", &sig).is_err());
        // Another key on the same parameters does not verify it.
        let other = DsaPrivateKey::generate(params_1024(), &mut rng);
        assert!(other.public_key().verify::<Sha256>(b"hello", &sig).is_err());
        // 2048/256 too.
        let key = DsaPrivateKey::generate(test_params_2048_256(), &mut rng);
        let sig = key.sign::<Sha256>(b"hello").unwrap();
        key.public_key().verify::<Sha256>(b"hello", &sig).unwrap();
    }

    #[test]
    fn verify_rejects_out_of_range_components() {
        let key = key_1024();
        let pk = key.public_key();
        let sig = key.sign::<Sha256>(b"sample").unwrap();
        let q = pk.params().q().clone();
        let zero = BoxedUint::from_u64(0);
        for bad in [
            DsaSignature::from_components(zero.clone(), sig.s.clone()),
            DsaSignature::from_components(sig.r.clone(), zero.clone()),
            DsaSignature::from_components(q.clone(), sig.s.clone()),
            DsaSignature::from_components(sig.r.clone(), q.clone()),
            DsaSignature::from_components(sig.r.add(&q), sig.s.clone()),
            DsaSignature::from_components(sig.r.clone(), sig.s.add(&q)),
            // (r = 1, s = 0) and (r = 1, s = q): the "inverse of 0 is 0"
            // forgeries from the Wycheproof notes.
            DsaSignature::from_components(BoxedUint::from_u64(1), zero.clone()),
            DsaSignature::from_components(BoxedUint::from_u64(1), q.clone()),
        ] {
            assert_eq!(
                pk.verify::<Sha256>(b"sample", &bad),
                Err(Error::Verification)
            );
        }
    }

    #[test]
    fn hash_truncation_matches_fips_186_4() {
        // SHA-512 on a 160-bit q: `z` is the leftmost 160 bits of the digest.
        // The RFC 6979 vectors above already pin this; here check that a
        // prehash *narrower* than q is used whole (zero-extended), by
        // signing with a fake 8-byte prehash and verifying with the same.
        let key = key_1024();
        let pk = key.public_key();
        let sig = key
            .sign_prehash::<Sha256>(&[1, 2, 3, 4, 5, 6, 7, 8])
            .unwrap();
        pk.verify_prehash(&[1, 2, 3, 4, 5, 6, 7, 8], &sig).unwrap();
        assert!(pk.verify_prehash(&[1, 2, 3, 4, 5, 6, 7, 9], &sig).is_err());
        // Extra trailing bits beyond N are ignored, so appending a byte to
        // an exactly-N-bit prehash changes nothing: the verifier truncates.
        let h = crate::hash::sha1(b"sample").to_vec();
        let sig = key.sign_prehash::<Sha1>(&h).unwrap();
        let mut wider = h.clone();
        wider.push(0xff);
        pk.verify_prehash(&wider, &sig).unwrap();
    }

    #[test]
    fn signature_der_strictness() {
        let sig = key_1024().sign::<Sha256>(b"sample").unwrap();
        let der = sig.to_der();
        assert_eq!(DsaSignature::from_der(&der).unwrap(), sig);
        // Trailing byte.
        let mut t = der.clone();
        t.push(0);
        assert_eq!(DsaSignature::from_der(&t), Err(Error::Malformed));
        // Unnecessary leading zero inside r (BER, not DER).
        let mut r_der = encode_integer(&sig.r.to_be_bytes(20));
        r_der.insert(2, 0x00);
        r_der[1] += 1;
        let ber = encode_sequence(&[r_der, encode_integer(&sig.s.to_be_bytes(20))].concat());
        assert_eq!(DsaSignature::from_der(&ber), Err(Error::Malformed));
        // Missing zero: a top-bit-set magnitude without the 0x00 pad is a
        // negative INTEGER in DER, hence rejected.
        let neg = encode_sequence(&[vec![0x02, 0x01, 0x80], vec![0x02, 0x01, 0x01]].concat());
        assert_eq!(DsaSignature::from_der(&neg), Err(Error::Malformed));
        // Empty INTEGER.
        let empty = encode_sequence(&[vec![0x02, 0x00], vec![0x02, 0x01, 0x01]].concat());
        assert_eq!(DsaSignature::from_der(&empty), Err(Error::Malformed));
        // Indefinite length.
        assert_eq!(
            DsaSignature::from_der(&[0x30, 0x80, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0, 0]),
            Err(Error::Malformed)
        );
        // Wider than any q.
        let wide = encode_sequence(&[encode_integer(&[0x7f; 33]), encode_integer(&[1])].concat());
        assert_eq!(DsaSignature::from_der(&wide), Err(Error::Malformed));
        // A component that is *exactly* MAX_Q_LEN wide with a sign pad is
        // fine at parse time (the verifier's range check decides).
        let ok = encode_sequence(&[encode_integer(&[0xff; 32]), encode_integer(&[1])].concat());
        assert!(DsaSignature::from_der(&ok).is_ok());
        // Minimal encoding of small components.
        let small =
            DsaSignature::from_components(BoxedUint::from_u64(1), BoxedUint::from_u64(0x80));
        assert_eq!(
            small.to_der(),
            [0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x80]
        );
        let zero = DsaSignature::from_components(BoxedUint::from_u64(0), BoxedUint::from_u64(0));
        assert_eq!(
            zero.to_der(),
            [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]
        );
    }

    #[test]
    fn signature_p1363_widths() {
        let sig = key_1024().sign::<Sha256>(b"sample").unwrap();
        let bytes = sig.to_p1363(20).unwrap();
        assert_eq!(bytes.len(), 40);
        assert_eq!(DsaSignature::from_p1363(&bytes, 20).unwrap(), sig);
        assert_eq!(
            DsaSignature::from_p1363(&bytes[1..], 20),
            Err(Error::Malformed)
        );
        assert_eq!(DsaSignature::from_p1363(&bytes, 0), Err(Error::Malformed));
        // Wider target pads; narrower fails.
        assert_eq!(sig.to_p1363(32).unwrap().len(), 64);
        assert_eq!(sig.to_p1363(19), Err(Error::InvalidInput));
    }

    #[test]
    fn spki_roundtrip_and_validation() {
        let pk = key_2048().public_key();
        let der = pk.to_spki_der();
        assert_eq!(DsaPublicKey::from_spki_der(&der).unwrap(), pk);
        let pem = pk.to_spki_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert_eq!(DsaPublicKey::from_spki_pem(&pem).unwrap(), pk);
        // Structure: SEQUENCE { SEQUENCE { OID id-dsa, SEQUENCE {p,q,g} },
        // BIT STRING { INTEGER y } }.
        let mut r = Reader::new(&der);
        let mut seq = r.read_sequence().unwrap();
        let mut algid = seq.read_sequence().unwrap();
        assert_eq!(parse_oid(algid.read_oid().unwrap()).unwrap(), ID_DSA_OID);
        assert_eq!(
            DsaParams::from_der(algid.read_element().unwrap()).unwrap(),
            *pk.params()
        );
        let bits = seq.read_bit_string().unwrap();
        assert_eq!(bits[0], 0x02);
        // Trailing data and a wrong OID are rejected.
        let mut t = der.clone();
        t.push(0);
        assert_eq!(DsaPublicKey::from_spki_der(&t), Err(Error::Malformed));
        let ec_oid = oid_tlv(&[1, 2, 840, 10045, 2, 1]);
        let algid = encode_sequence(&[ec_oid, pk.params().to_der()].concat());
        let bad =
            encode_sequence(&[algid, encode_bit_string(&encode_integer(&pk.y_bytes()))].concat());
        assert_eq!(DsaPublicKey::from_spki_der(&bad), Err(Error::Malformed));
        // A y outside the subgroup inside an otherwise well-formed SPKI.
        let y_bad = pk.params().p().sub(&BoxedUint::from_u64(1));
        let bad = encode_sequence(
            &[
                pk.params().algorithm_identifier(),
                encode_bit_string(&encode_integer(&y_bad.to_be_bytes(256))),
            ]
            .concat(),
        );
        assert_eq!(
            DsaPublicKey::from_spki_der(&bad),
            Err(Error::InvalidPublicKey)
        );
    }

    #[test]
    fn params_der_roundtrip() {
        let params = params_1024();
        let der = params.to_der();
        assert_eq!(DsaParams::from_der(&der).unwrap(), params);
        let pem = params.to_pem();
        assert!(pem.starts_with("-----BEGIN DSA PARAMETERS-----"));
        assert_eq!(DsaParams::from_pem(&pem).unwrap(), params);
        let mut t = der.clone();
        t.push(0);
        assert_eq!(DsaParams::from_der(&t), Err(Error::Malformed));
    }

    #[test]
    fn pkcs8_roundtrip_and_embedded_public_key() {
        let key = key_1024();
        let der = key.to_pkcs8_der();
        let back = DsaPrivateKey::from_pkcs8_der(&der).unwrap();
        assert_eq!(back.x_bytes(), key.x_bytes());
        assert_eq!(back.params(), key.params());
        let pem = key.to_pkcs8_pem();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert_eq!(
            DsaPrivateKey::from_pkcs8_pem(&pem).unwrap().x_bytes(),
            key.x_bytes()
        );
        // A `[1]` publicKey that matches is accepted; one that does not is
        // rejected.
        let body = |y: &BoxedUint| {
            let mut v = vec![0x00];
            v.extend_from_slice(&encode_integer(&y.to_be_bytes(128)));
            crate::der::encode_tlv(0x81, &v)
        };
        let with = |pub_tlv: Vec<u8>| {
            encode_sequence(
                &[
                    encode_integer(&[0]),
                    key.params().algorithm_identifier(),
                    encode_octet_string(&encode_integer(&key.x_bytes())),
                    pub_tlv,
                ]
                .concat(),
            )
        };
        let good = with(body(key.public_key().y()));
        assert!(DsaPrivateKey::from_pkcs8_der(&good).is_ok());
        let bad = with(body(&key.public_key().y().add(&BoxedUint::from_u64(1))));
        assert_eq!(
            DsaPrivateKey::from_pkcs8_der(&bad).err(),
            Some(Error::Malformed)
        );
        // x = 0 inside PKCS#8.
        let zero = encode_sequence(
            &[
                encode_integer(&[0]),
                key.params().algorithm_identifier(),
                encode_octet_string(&encode_integer(&[0])),
            ]
            .concat(),
        );
        assert_eq!(
            DsaPrivateKey::from_pkcs8_der(&zero).err(),
            Some(Error::InvalidPrivateKey)
        );
        // Debug does not print x.
        let dbg = alloc::format!("{key:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.to_lowercase().contains(&X1024.to_lowercase()));
    }

    #[test]
    fn pkcs8_openssl_interop() {
        // `openssl genpkey -paramfile <RFC 6979 A.2.1 params> ...` style
        // layout, hand-built with the A.2.1 key: version 0, id-dsa +
        // Dss-Parms, OCTET STRING { INTEGER x }. The exact bytes are what
        // `to_pkcs8_der` emits, so this pins the layout against the RFC
        // 3279 / RFC 5958 structure rather than a captured file.
        let key = key_1024();
        let der = key.to_pkcs8_der();
        let mut r = Reader::new(&der);
        let mut seq = r.read_sequence().unwrap();
        assert_eq!(seq.read_unsigned_integer_bytes().unwrap(), [0]);
        let mut algid = seq.read_sequence().unwrap();
        assert_eq!(parse_oid(algid.read_oid().unwrap()).unwrap(), ID_DSA_OID);
        assert_eq!(
            DsaParams::from_der(algid.read_element().unwrap()).unwrap(),
            params_1024()
        );
        algid.finish().unwrap();
        let inner = seq.read_octet_string().unwrap();
        assert_eq!(inner, encode_integer(&from_hex(X1024)));
        seq.finish().unwrap();
        r.finish().unwrap();
    }

    #[test]
    fn rfc6979_retry_advances_the_drbg() {
        // The second candidate must differ from the first and stay in range:
        // this is the path the `r = 0` / `s = 0` retry takes.
        let key = key_1024();
        let q = key.params().q();
        let h = crate::hash::sha256(b"sample");
        let mut drbg = Rfc6979::<Sha256>::new(&key.x, &h, q, 20, 160);
        let k1 = drbg.next_k();
        assert_eq!(
            k1.to_be_bytes(20),
            from_hex("519BA0546D0C39202A7D34D7DFA5E760B318BCFB")
        );
        let k2 = drbg.next_k();
        assert_ne!(k1, k2);
        assert!(in_range(&k2, q));
    }
}
