//! SM2 — the Chinese commercial public-key algorithm (GB/T 32918, RFC 8998).
//!
//! SM2 is an elliptic-curve scheme over the [`sm2p256v1`](super::CurveId::Sm2p256v1)
//! curve, paired with the [`Sm3`] hash. This module implements
//! the two SM2 sub-algorithms purecrypto needs:
//!
//! * **Digital signatures** (GB/T 32918.2 / RFC 8998 §2): `(r, s)` over the
//!   message digest `e = SM3(ZA ‖ M)`, where `ZA` binds the signer's identity
//!   and public key into the hash.
//! * **Public-key encryption** (GB/T 32918.4 / RFC 8998 §3): the SM2 hybrid
//!   PKE producing the `C1 ‖ C3 ‖ C2` ciphertext layout mandated by RFC 8998.
//!
//! The secret scalar is held in a [`BoxedUint`] and wiped on drop; all scalar
//! arithmetic reuses the crate's constant-time field/scalar primitives
//! ([`BoxedMontModulus`], `weierstrass::Curve::scalar_mul`).
//!
//! Keys serialize as standard SEC1 / PKIX structures carrying the SM2 named
//! curve OID (`1.2.156.10197.1.301`), so PKCS#8 / PEM round-trips work through
//! the same DER machinery as the other EC curves.

use super::Error;
use super::curves::CurveId;
use crate::bignum::{BoxedMontModulus, BoxedUint};
use crate::ct::ConstantTimeEq;
use crate::hash::{Digest, Sm3};
use crate::rng::{CryptoRng, RngCore};
use alloc::vec;
use alloc::vec::Vec;

/// The SM2 curve identifier (`sm2p256v1`).
const CURVE: CurveId = CurveId::Sm2p256v1;

/// `id-ecPublicKey` (`1.2.840.10045.2.1`) — the SubjectPublicKeyInfo
/// algorithm OID for EC keys. Defined locally (mirroring the per-curve
/// OID constants in `ed25519`) so the `der`-gated SPKI codecs below stay
/// self-contained and do not pull in the `x509` feature: RFC 8998 reuses
/// the standard PKIX EC SPKI shape, only swapping in the SM2 named curve.
#[cfg(feature = "der")]
const EC_PUBLIC_KEY_OID: &[u64] = &[1, 2, 840, 10045, 2, 1];

/// The default user identity `"1234567812345678"` (GB/T 32918.2 §A,
/// RFC 8998 §2).
pub const DEFAULT_ID: &[u8] = b"1234567812345678";

/// `1 <= v < n`, evaluated without short-circuiting (`v` may be a secret
/// scalar — private-key import, nonce rejection sampling — so the zero test
/// must not leak which limb first differed).
fn in_range(v: &BoxedUint, n: &BoxedUint) -> bool {
    bool::from(!v.ct_is_zero()) & v.lt(n)
}

/// Modular inverse `a^-1 mod m` for prime `m`, via Fermat (`a^(m-2) mod m`).
fn inv_mod(fm: &BoxedMontModulus, a: &BoxedUint, m: &BoxedUint) -> BoxedUint {
    fm.pow(a, &m.sub(&BoxedUint::from_u64(2)))
}

/// A uniformly random scalar in `[1, n-1]` via rejection sampling, masking the
/// high byte to `n.bit_len()` bits to keep the rejection rate low.
fn random_scalar<R: RngCore>(n: &BoxedUint, rng: &mut R) -> BoxedUint {
    let bytes = CURVE.order_len();
    let nbits = n.bit_len();
    let high_keep_bits = ((nbits - 1) % 8) + 1;
    let high_mask = if high_keep_bits == 8 {
        0xff
    } else {
        (1u8 << high_keep_bits) - 1
    };
    loop {
        let mut buf = vec![0u8; bytes];
        rng.fill_bytes(&mut buf);
        buf[0] &= high_mask;
        let candidate = BoxedUint::from_be_bytes(&buf);
        if in_range(&candidate, n) {
            return candidate;
        }
    }
}

/// The 32-byte big-endian encoding of a field element / scalar.
fn enc32(v: &BoxedUint) -> Vec<u8> {
    v.to_be_bytes(32)
}

/// An SM2 public key: an affine point `PA = (xA, yA)` on `sm2p256v1`.
#[derive(Clone, Debug)]
pub struct Sm2PublicKey {
    x: BoxedUint,
    y: BoxedUint,
}

/// An SM2 private key: a scalar `dA ∈ [1, n-1]`. The scalar is wiped on drop.
#[derive(Clone)]
pub struct Sm2PrivateKey {
    d: BoxedUint,
}

/// An SM2 signature `(r, s)`, each in `[1, n-1]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sm2Signature {
    r: BoxedUint,
    s: BoxedUint,
}

/// Computes `ZA = SM3(ENTLA ‖ ID ‖ a ‖ b ‖ Gx ‖ Gy ‖ xA ‖ yA)`.
///
/// `ENTLA` is the two-byte big-endian bit length of `id` (so `id` is limited to
/// `2^16 - 1` bits = 8191 bytes; longer ids are rejected by the callers).
fn za(id: &[u8], x: &BoxedUint, y: &BoxedUint) -> Result<[u8; 32], Error> {
    let bitlen = id
        .len()
        .checked_mul(8)
        .filter(|&b| b <= u16::MAX as usize)
        .ok_or(Error::InvalidInput)?;
    let c = CURVE.curve();
    // a, b in plain (non-Montgomery) form, 32-byte big-endian.
    let (a, b) = c.coefficients();
    let (gx, gy) = c
        .to_affine(&c.generator())
        .expect("generator is not the identity");

    let mut h = Sm3::new();
    h.update(&[(bitlen >> 8) as u8, bitlen as u8]);
    h.update(id);
    h.update(&enc32(&a));
    h.update(&enc32(&b));
    h.update(&enc32(&gx));
    h.update(&enc32(&gy));
    h.update(&enc32(x));
    h.update(&enc32(y));
    Ok(h.finalize())
}

/// Computes the signing/verification digest `e = SM3(ZA ‖ M)` as an integer.
fn message_hash(za: &[u8; 32], msg: &[u8]) -> BoxedUint {
    let mut h = Sm3::new();
    h.update(za);
    h.update(msg);
    BoxedUint::from_be_bytes(h.finalize().as_ref())
}

/// The GB/T 32918 KDF built on SM3: counter-mode `Ha = SM3(Z ‖ ct)` with a
/// 32-bit big-endian counter starting at 1, concatenated to `klen` bytes.
fn kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(klen);
    let mut ct: u32 = 1;
    while out.len() < klen {
        let mut h = Sm3::new();
        h.update(z);
        h.update(&ct.to_be_bytes());
        out.extend_from_slice(h.finalize().as_ref());
        ct = ct.wrapping_add(1);
    }
    out.truncate(klen);
    out
}

impl Sm2PublicKey {
    /// Parses an uncompressed SEC1 point (`0x04 ‖ X ‖ Y`, 65 bytes), rejecting
    /// off-curve points and coordinates out of range.
    pub fn from_sec1(bytes: &[u8]) -> Result<Self, Error> {
        let flen = CURVE.field_len();
        if bytes.len() != 1 + 2 * flen || bytes[0] != 0x04 {
            return Err(Error::Malformed);
        }
        let x = BoxedUint::from_be_bytes(&bytes[1..1 + flen]);
        let y = BoxedUint::from_be_bytes(&bytes[1 + flen..]);
        let c = CURVE.curve();
        if !c.in_field(&x) || !c.in_field(&y) || !c.is_on_curve(&x, &y) {
            return Err(Error::InvalidInput);
        }
        Ok(Sm2PublicKey { x, y })
    }

    /// Encodes the key as an uncompressed SEC1 point (`0x04 ‖ X ‖ Y`).
    pub fn to_sec1(&self) -> Vec<u8> {
        let flen = CURVE.field_len();
        let mut out = vec![0u8; 1 + 2 * flen];
        out[0] = 0x04;
        out[1..1 + flen].copy_from_slice(&self.x.to_be_bytes(flen));
        out[1 + flen..].copy_from_slice(&self.y.to_be_bytes(flen));
        out
    }

    /// The affine `x` coordinate.
    pub fn x(&self) -> &BoxedUint {
        &self.x
    }

    /// The affine `y` coordinate.
    pub fn y(&self) -> &BoxedUint {
        &self.y
    }

    /// Computes `ZA` for this public key and the given identity.
    pub fn za(&self, id: &[u8]) -> Result<[u8; 32], Error> {
        za(id, &self.x, &self.y)
    }

    /// Verifies an SM2 signature `sig` over `msg` under identity `id`
    /// (GB/T 32918.2 §7, RFC 8998 §2).
    pub fn verify(&self, msg: &[u8], sig: &Sm2Signature, id: &[u8]) -> Result<(), Error> {
        let c = CURVE.curve();
        let n = c.order().clone();
        let fq = BoxedMontModulus::new(&n);
        // r, s ∈ [1, n-1].
        if !in_range(&sig.r, &n) || !in_range(&sig.s, &n) {
            return Err(Error::Verification);
        }
        let za = self.za(id)?;
        let e = message_hash(&za, msg).reduce(&n);
        // t = (r + s) mod n; reject t == 0.
        let t = fq.add_mod(&sig.r, &sig.s);
        if t.is_zero() {
            return Err(Error::Verification);
        }
        // (x1, _) = [s]G + [t]PA.
        let point = c.lift_affine(&self.x, &self.y);
        let sum = c.point_add(&c.mul_generator(&sig.s), &c.scalar_mul(&t, &point));
        let (x1, _) = c.to_affine(&sum).ok_or(Error::Verification)?;
        // R = (e + x1) mod n; accept iff R == r.
        let r = fq.add_mod(&e, &x1.reduce(&n));
        if bool::from(r.ct_eq(&sig.r)) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }

    /// Encrypts `msg` to this public key with the SM2 hybrid PKE, returning the
    /// `C1 ‖ C3 ‖ C2` ciphertext (GB/T 32918.4, RFC 8998 §3 ordering). The nonce
    /// `k` is drawn from `rng`, which MUST be a CSPRNG.
    pub fn encrypt<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let c = CURVE.curve();
        let n = c.order().clone();
        let point = c.lift_affine(&self.x, &self.y);
        loop {
            let k = random_scalar(&n, rng);
            // C1 = [k]G (uncompressed point).
            let (x1, y1) = c
                .to_affine(&c.mul_generator(&k))
                .ok_or(Error::InvalidInput)?;
            // [k]PA = (x2, y2). PA has order n (cofactor 1), so this is never
            // the identity for k in [1, n-1].
            let (x2, y2) = c
                .to_affine(&c.scalar_mul(&k, &point))
                .ok_or(Error::InvalidInput)?;

            // t = KDF(x2 ‖ y2, mlen); retry if all-zero.
            let mut z = enc32(&x2);
            z.extend_from_slice(&enc32(&y2));
            let t = kdf(&z, msg.len());
            if t.iter().all(|&b| b == 0) {
                continue;
            }

            // C2 = M ⊕ t.
            let c2: Vec<u8> = msg.iter().zip(&t).map(|(m, k)| m ^ k).collect();
            // C3 = SM3(x2 ‖ M ‖ y2).
            let mut h = Sm3::new();
            h.update(&enc32(&x2));
            h.update(msg);
            h.update(&enc32(&y2));
            let c3 = h.finalize();

            // Output C1 ‖ C3 ‖ C2 (RFC 8998 §3).
            let flen = CURVE.field_len();
            let mut out = Vec::with_capacity(1 + 2 * flen + 32 + c2.len());
            out.push(0x04);
            out.extend_from_slice(&x1.to_be_bytes(flen));
            out.extend_from_slice(&y1.to_be_bytes(flen));
            out.extend_from_slice(c3.as_ref());
            out.extend_from_slice(&c2);
            return Ok(out);
        }
    }
}

impl Sm2PrivateKey {
    /// Creates a private key from a big-endian scalar, checking it is in
    /// `[1, n-1]`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let d = BoxedUint::from_be_bytes(bytes);
        let n = CURVE.curve().order().clone();
        if in_range(&d, &n) {
            Ok(Sm2PrivateKey { d })
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// Generates a new SM2 private key from `rng` (a CSPRNG).
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let n = CURVE.curve().order().clone();
        Sm2PrivateKey {
            d: random_scalar(&n, rng),
        }
    }

    /// The secret scalar as a big-endian 32-byte string.
    pub fn to_bytes(&self) -> Vec<u8> {
        enc32(&self.d)
    }

    /// Derives the public key `PA = [dA]G`.
    pub fn public_key(&self) -> Sm2PublicKey {
        let c = CURVE.curve();
        let (x, y) = c
            .to_affine(&c.mul_generator(&self.d))
            .expect("d in [1,n-1] so d*G is not the identity");
        Sm2PublicKey { x, y }
    }

    /// Signs `msg` under identity `id`, drawing the nonce `k` from `rng`
    /// (a CSPRNG). See [`Self::sign_with_k`] for the pinned-nonce variant used
    /// by Known-Answer-Tests.
    pub fn sign<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        id: &[u8],
        rng: &mut R,
    ) -> Result<Sm2Signature, Error> {
        let n = CURVE.curve().order().clone();
        loop {
            let k = random_scalar(&n, rng);
            match self.sign_with_k(msg, id, &k) {
                Ok(sig) => return Ok(sig),
                // Degenerate nonce (r == 0, r + k == n, or s == 0): resample.
                Err(Error::InvalidInput) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Signs `msg` under identity `id` with an explicit nonce `k`
    /// (GB/T 32918.2 §6). Returns [`Error::InvalidInput`] if the nonce is
    /// degenerate (`r == 0`, `r + k == n`, or `s == 0`), so callers using a
    /// CSPRNG should resample; KAT callers pin a `k` that the vector accepts.
    ///
    /// `k` MUST be a secret, uniformly-random value in `[1, n-1]` — reusing or
    /// leaking it discloses the private key.
    pub fn sign_with_k(&self, msg: &[u8], id: &[u8], k: &BoxedUint) -> Result<Sm2Signature, Error> {
        let c = CURVE.curve();
        let n = c.order().clone();
        let fq = BoxedMontModulus::new(&n);
        if !in_range(k, &n) {
            return Err(Error::InvalidInput);
        }
        let za = self.public_key().za(id)?;
        let e = message_hash(&za, msg).reduce(&n);

        // (x1, _) = [k]G.
        let (x1, _) = c
            .to_affine(&c.mul_generator(k))
            .ok_or(Error::InvalidInput)?;
        // r = (e + x1) mod n; reject r == 0 or r + k == n.
        let r = fq.add_mod(&e, &x1.reduce(&n));
        if r.is_zero() || fq.add_mod(&r, k).is_zero() {
            return Err(Error::InvalidInput);
        }
        // s = ((1 + dA)^-1 · (k − r·dA)) mod n.
        let one = BoxedUint::from_u64(1);
        let d_plus_1_inv = inv_mod(&fq, &fq.add_mod(&one, &self.d), &n);
        let rd = fq.mul_mod(&r, &self.d);
        let k_minus_rd = fq.sub_mod(k, &rd);
        let s = fq.mul_mod(&d_plus_1_inv, &k_minus_rd);
        if s.is_zero() {
            return Err(Error::InvalidInput);
        }
        Ok(Sm2Signature { r, s })
    }

    /// Decrypts an SM2 `C1 ‖ C3 ‖ C2` ciphertext (GB/T 32918.4, RFC 8998 §3).
    /// Validates `C1` is a non-identity on-curve point and checks `C3` in
    /// constant time.
    pub fn decrypt(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
        let c = CURVE.curve();
        let flen = CURVE.field_len();
        let c1_len = 1 + 2 * flen;
        // C1 (65 bytes) ‖ C3 (32 bytes) ‖ C2 (>= 0 bytes).
        if ct.len() < c1_len + 32 {
            return Err(Error::Malformed);
        }
        let (c1_bytes, rest) = ct.split_at(c1_len);
        let (c3, c2) = rest.split_at(32);

        // Parse and validate C1 = (x1, y1): uncompressed, in field, on curve,
        // not the identity.
        if c1_bytes[0] != 0x04 {
            return Err(Error::Malformed);
        }
        let x1 = BoxedUint::from_be_bytes(&c1_bytes[1..1 + flen]);
        let y1 = BoxedUint::from_be_bytes(&c1_bytes[1 + flen..]);
        if !c.in_field(&x1) || !c.in_field(&y1) || !c.is_on_curve(&x1, &y1) {
            return Err(Error::InvalidInput);
        }
        let c1 = c.lift_affine(&x1, &y1);
        // [dB]C1 = (x2, y2). With cofactor 1 and C1 on the curve, the only way
        // this is the identity is C1 = identity (already rejected by the SEC1
        // 0x04 parse) — guard anyway.
        let (x2, y2) = c
            .to_affine(&c.scalar_mul(&self.d, &c1))
            .ok_or(Error::InvalidInput)?;

        // t = KDF(x2 ‖ y2, |C2|); M = C2 ⊕ t.
        let mut z = enc32(&x2);
        z.extend_from_slice(&enc32(&y2));
        let t = kdf(&z, c2.len());
        let msg: Vec<u8> = c2.iter().zip(&t).map(|(c, k)| c ^ k).collect();

        // u = SM3(x2 ‖ M ‖ y2); verify u == C3 in constant time.
        let mut h = Sm3::new();
        h.update(&enc32(&x2));
        h.update(&msg);
        h.update(&enc32(&y2));
        let u = h.finalize();
        if bool::from(u.as_ref().ct_eq(c3)) {
            Ok(msg)
        } else {
            Err(Error::Verification)
        }
    }
}

impl Sm2Signature {
    /// Builds a signature from its `(r, s)` components.
    pub fn from_components(r: BoxedUint, s: BoxedUint) -> Self {
        Sm2Signature { r, s }
    }

    /// The `r` component.
    pub fn r(&self) -> &BoxedUint {
        &self.r
    }

    /// The `s` component.
    pub fn s(&self) -> &BoxedUint {
        &self.s
    }

    /// The fixed `r ‖ s` encoding, each half 32 bytes big-endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = enc32(&self.r);
        out.extend_from_slice(&enc32(&self.s));
        out
    }

    /// Parses a fixed 64-byte `r ‖ s` encoding.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 64 {
            return Err(Error::Malformed);
        }
        Ok(Sm2Signature {
            r: BoxedUint::from_be_bytes(&bytes[..32]),
            s: BoxedUint::from_be_bytes(&bytes[32..]),
        })
    }
}

impl Drop for Sm2PrivateKey {
    fn drop(&mut self) {
        // Best-effort wipe of the secret scalar before its heap-backing `Vec`
        // is freed. Mirrors `BoxedEcdsaPrivateKey`.
        self.d.zeroize();
    }
}

/// DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` — the form X.509
/// uses for the `SM2-with-SM3` signature value (RFC 8998 §2).
#[cfg(feature = "der")]
impl Sm2Signature {
    /// Encodes the signature as a DER `Ecdsa-Sig-Value`.
    pub fn to_der(&self) -> Vec<u8> {
        use crate::der::{encode_integer, encode_sequence};
        encode_sequence(
            &[
                encode_integer(&enc32(&self.r)),
                encode_integer(&enc32(&self.s)),
            ]
            .concat(),
        )
    }

    /// Decodes a DER `Ecdsa-Sig-Value` with strict-DER enforcement.
    pub fn from_der(der: &[u8]) -> Result<Self, Error> {
        use crate::der::Reader;
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
        Ok(Sm2Signature {
            r: BoxedUint::from_be_bytes(r),
            s: BoxedUint::from_be_bytes(s),
        })
    }
}

/// SEC1 `ECPrivateKey` and PKIX `SubjectPublicKeyInfo` encoding, reusing the
/// SM2 named-curve OID so PKCS#8 / PEM round-trips through the shared DER
/// machinery.
#[cfg(feature = "der")]
impl Sm2PrivateKey {
    /// Encodes the key as a SEC1 `ECPrivateKey` DER structure (named curve +
    /// public key included).
    pub fn to_sec1_der(&self) -> Vec<u8> {
        use crate::der::{
            encode_bit_string, encode_context, encode_integer, encode_octet_string,
            encode_sequence, oid_tlv,
        };
        let priv_oct = encode_octet_string(&self.to_bytes());
        let params = encode_context(0, &oid_tlv(CURVE.named_curve_oid()));
        let pubkey = encode_context(1, &encode_bit_string(&self.public_key().to_sec1()));
        encode_sequence(&[encode_integer(&[1]), priv_oct, params, pubkey].concat())
    }

    /// Encodes the key as a SEC1 PEM document (`-----BEGIN EC PRIVATE KEY-----`).
    pub fn to_sec1_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("EC PRIVATE KEY", &self.to_sec1_der())
    }

    /// Parses a SEC1 `ECPrivateKey` DER structure (the named curve must be
    /// `sm2p256v1`).
    pub fn from_sec1_der(der: &[u8]) -> Result<Self, Error> {
        use crate::der::{Reader, parse_oid, tag};
        let mut outer = Reader::new(der);
        let mut seq = outer.read_sequence().map_err(|_| Error::Malformed)?;
        seq.read_integer_bytes().map_err(|_| Error::Malformed)?; // version
        let priv_bytes = seq.read_octet_string().map_err(|_| Error::Malformed)?;
        if seq.peek_tag() != Some(tag::context(0)) {
            return Err(Error::Malformed);
        }
        let params = seq
            .read_tlv(tag::context(0))
            .map_err(|_| Error::Malformed)?;
        let mut pr = Reader::new(params);
        let arcs = parse_oid(pr.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        if CurveId::from_named_curve_oid(&arcs) != Some(CURVE) {
            return Err(Error::Malformed);
        }
        Self::from_bytes(priv_bytes)
    }

    /// Parses a SEC1 PEM EC private key (`sm2p256v1`).
    pub fn from_sec1_pem(pem: &str) -> Result<Self, Error> {
        let der = crate::der::pem_decode(pem, "EC PRIVATE KEY").map_err(|_| Error::Malformed)?;
        Self::from_sec1_der(&der)
    }
}

#[cfg(feature = "der")]
impl Sm2PublicKey {
    /// Encodes the key as a PKIX `SubjectPublicKeyInfo` DER structure
    /// (`id-ecPublicKey` + the SM2 named curve, RFC 8998 §1).
    pub fn to_spki_der(&self) -> Vec<u8> {
        use crate::der::{encode_bit_string, encode_sequence, oid_tlv};
        let algid = encode_sequence(
            &[oid_tlv(EC_PUBLIC_KEY_OID), oid_tlv(CURVE.named_curve_oid())].concat(),
        );
        encode_sequence(&[algid, encode_bit_string(&self.to_sec1())].concat())
    }

    /// Encodes the key as a PKIX PEM document (`-----BEGIN PUBLIC KEY-----`).
    pub fn to_spki_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("PUBLIC KEY", &self.to_spki_der())
    }

    /// Parses a PKIX `SubjectPublicKeyInfo` for an SM2 key.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        use crate::der::{Reader, parse_oid};
        let mut reader = Reader::new(der);
        let mut spki = reader.read_sequence().map_err(|_| Error::Malformed)?;
        let mut algid = spki.read_sequence().map_err(|_| Error::Malformed)?;
        let alg = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        if alg.as_slice() != EC_PUBLIC_KEY_OID {
            return Err(Error::Malformed);
        }
        let arcs = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        if CurveId::from_named_curve_oid(&arcs) != Some(CURVE) {
            return Err(Error::Malformed);
        }
        algid.finish().map_err(|_| Error::Malformed)?;
        let key_bits = spki.read_bit_string().map_err(|_| Error::Malformed)?;
        spki.finish().map_err(|_| Error::Malformed)?;
        Self::from_sec1(key_bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn from_hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(core::str::from_utf8(&s[i..i + 2]).unwrap(), 16).unwrap())
            .collect()
    }

    fn uint(s: &str) -> BoxedUint {
        BoxedUint::from_be_bytes(&from_hex(s))
    }

    // GB/T 32918.2 Annex A.2 / widely-published SM2 signature example.
    //   dA  = 3945208F7B2144B13F36E38AC6D39F958893936928 60B51A42FB81EF4DF7C5B8
    //   ID  = "1234567812345678"
    //   M   = "message digest"
    //   k   = 59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21
    //   r   = F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3
    //   s   = B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA
    #[test]
    fn sign_kat_pinned_k() {
        let d = from_hex("3945208F7B2144B13F36E38AC6D39F9588939369286 0B51A42FB81EF4DF7C5B8");
        let sk = Sm2PrivateKey::from_bytes(&d).unwrap();
        let k = uint("59276E27D506861A16680F3AD9C02DCCEF3CC1FA3CDBE4CE6D54B80DEAC1BC21");
        let sig = sk.sign_with_k(b"message digest", DEFAULT_ID, &k).unwrap();
        assert_eq!(
            sig.r().to_be_bytes(32),
            from_hex("F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3")
        );
        assert_eq!(
            sig.s().to_be_bytes(32),
            from_hex("B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA")
        );
    }

    #[test]
    fn verify_kat() {
        let d = from_hex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8");
        let sk = Sm2PrivateKey::from_bytes(&d).unwrap();
        let pk = sk.public_key();
        let sig = Sm2Signature::from_components(
            uint("F5A03B0648D2C4630EEAC513E1BB81A15944DA3827D5B74143AC7EACEEE720B3"),
            uint("B1B6AA29DF212FD8763182BC0D421CA1BB9038FD1F7F42D4840B69C485BBC1AA"),
        );
        pk.verify(b"message digest", &sig, DEFAULT_ID).unwrap();
        // Tampered message and tampered signature are both rejected.
        assert!(pk.verify(b"tampered digest", &sig, DEFAULT_ID).is_err());
        let bad =
            Sm2Signature::from_components(sig.r().clone(), sig.s().add(&BoxedUint::from_u64(1)));
        assert!(pk.verify(b"message digest", &bad, DEFAULT_ID).is_err());
    }

    #[test]
    fn sign_verify_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"sm2-sign", b"n", &[]);
        let sk = Sm2PrivateKey::generate(&mut rng);
        let pk = sk.public_key();
        let sig = sk.sign(b"hello sm2", DEFAULT_ID, &mut rng).unwrap();
        pk.verify(b"hello sm2", &sig, DEFAULT_ID).unwrap();
        assert!(pk.verify(b"hello sm3", &sig, DEFAULT_ID).is_err());
        // Wrong id is rejected (ZA differs).
        assert!(pk.verify(b"hello sm2", &sig, b"other-id").is_err());
    }

    // GB/T 32918.4 SM2 public-key-encryption example (the canonical worked
    // example, plaintext "encryption standard"). Verified independently against
    // a reference SM2/SM3 implementation; the same SM3 path is pinned by the
    // signature KAT above, so this ciphertext is an end-to-end KAT.
    //   dB  = 1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0
    //   k   = 4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F
    //   M   = "encryption standard"
    #[test]
    fn encrypt_decrypt_kat_pinned_k() {
        let db = from_hex("1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0");
        let sk = Sm2PrivateKey::from_bytes(&db).unwrap();
        let pk = sk.public_key();
        let msg = b"encryption standard";

        // Build the ciphertext using the pinned k from the standard via a
        // deterministic single-shot RNG, then check decryption recovers M and
        // that the ciphertext bytes match the published vector.
        struct OneShot(Vec<u8>);
        impl crate::rng::RngCore for OneShot {
            fn next_u32(&mut self) -> u32 {
                unimplemented!()
            }
            fn next_u64(&mut self) -> u64 {
                unimplemented!()
            }
            fn fill_bytes(&mut self, dst: &mut [u8]) {
                dst.copy_from_slice(&self.0[..dst.len()]);
            }
        }
        impl crate::rng::CryptoRng for OneShot {}

        let k = from_hex("4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F");
        let mut rng = OneShot(k);
        let ct = pk.encrypt(msg, &mut rng).unwrap();

        let expected = from_hex(
            "0411C88AE04CEC1BA554D03D5B5970333A83585826C2A985DE5520D9E934389EFB\
             84B52D344FB21AA8EA38A4940C8332692B8D4DA2393549212EAFDC0F11CA5C9C01\
             37E757931553826A245A0BAEF73E2A693A861C6E93509CDA65C2B97C0AB2EDD76B\
             28B93A4B3765997A3BBC58F998731D0AA2",
        );
        assert_eq!(ct, expected, "SM2 encryption KAT mismatch");

        // Decryption recovers the plaintext.
        let pt = sk.decrypt(&ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_and_tamper() {
        let mut rng = HmacDrbg::<Sha256>::new(b"sm2-enc", b"n", &[]);
        let sk = Sm2PrivateKey::generate(&mut rng);
        let pk = sk.public_key();
        let msg = b"the quick brown fox jumps over the lazy dog";
        let mut ct = pk.encrypt(msg, &mut rng).unwrap();
        assert_eq!(sk.decrypt(&ct).unwrap(), msg);

        // Tampering with C2 (last byte) flips a plaintext bit and breaks C3.
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(sk.decrypt(&ct).is_err());
    }

    #[cfg(feature = "der")]
    #[test]
    fn key_encoding_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"sm2-der", b"n", &[]);
        let sk = Sm2PrivateKey::generate(&mut rng);

        let pem = sk.to_sec1_pem();
        assert!(pem.starts_with("-----BEGIN EC PRIVATE KEY-----"));
        let parsed = Sm2PrivateKey::from_sec1_pem(&pem).unwrap();
        assert_eq!(parsed.public_key().to_sec1(), sk.public_key().to_sec1());

        let spki = sk.public_key().to_spki_der();
        let pk2 = Sm2PublicKey::from_spki_der(&spki).unwrap();
        assert_eq!(pk2.to_sec1(), sk.public_key().to_sec1());

        let sig = sk.sign(b"der", DEFAULT_ID, &mut rng).unwrap();
        let der = sig.to_der();
        assert_eq!(Sm2Signature::from_der(&der).unwrap(), sig);
    }
}
