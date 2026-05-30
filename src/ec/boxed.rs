//! Runtime multi-curve ECDSA and ECDH (heap-backed [`BoxedUint`]).
//!
//! Unlike the const-generic [`ecdsa`](super::ecdsa)/[`ecdh`](super::ecdh) P-256
//! API — which is faster when the curve is fixed at compile time — these types
//! carry their [`CurveId`] at runtime, so one set of types serves every
//! supported curve. This is what the TLS and X.509 layers use, where the peer's
//! curve is known only at parse time.

use super::Error;
use super::curves::CurveId;
use crate::bignum::{BoxedMontModulus, BoxedUint};
use crate::ct::ConstantTimeEq;
use crate::hash::{Digest, Hmac};
use crate::rng::RngCore;
use alloc::vec;
use alloc::vec::Vec;

/// A runtime-curve ECDSA public key (an affine point on its curve).
#[derive(Clone, Debug)]
pub struct BoxedEcdsaPublicKey {
    curve: CurveId,
    x: BoxedUint,
    y: BoxedUint,
}

/// A runtime-curve ECDSA private key (a scalar in `[1, n-1]`).
#[derive(Clone)]
pub struct BoxedEcdsaPrivateKey {
    curve: CurveId,
    d: BoxedUint,
}

/// A runtime-curve ECDSA signature `(r, s)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoxedEcdsaSignature {
    r: BoxedUint,
    s: BoxedUint,
}

/// A runtime-curve ECDH private key.
#[derive(Clone)]
pub struct BoxedEcdhPrivateKey {
    curve: CurveId,
    d: BoxedUint,
}

/// `1 <= v < n`.
fn in_range(v: &BoxedUint, n: &BoxedUint) -> bool {
    !v.is_zero() && v.reduce(n) == *v
}

/// Modular inverse `a^-1 mod m` for prime `m`, via Fermat (`a^(m-2) mod m`).
fn inv_mod(fm: &BoxedMontModulus, a: &BoxedUint, m: &BoxedUint) -> BoxedUint {
    fm.pow(a, &m.sub(&BoxedUint::from_u64(2)))
}

/// RFC 6979 `bits2int`: the integer of the leftmost `qlen` bits of `data`.
fn bits2int(data: &[u8], qlen: usize) -> BoxedUint {
    let blen = data.len() * 8;
    let v = BoxedUint::from_be_bytes(data);
    if blen > qlen {
        v.shr_bits(blen - qlen)
    } else {
        v
    }
}

/// A uniformly random scalar in `[1, n-1]` via rejection sampling.
///
/// Drawing `order_len` bytes and reducing mod `n` is biased when the byte
/// width exceeds `n.bit_len()`. For P-521 in particular, `order_len = 66`
/// (528 bits) while `n` is ~521 bits, so naive reduction is biased by
/// roughly `2^-7` on a band of residues. We instead reject any sample `≥ n`
/// (and zero) and resample — bias collapses to zero.
fn random_scalar<R: RngCore>(curve: CurveId, n: &BoxedUint, rng: &mut R) -> BoxedUint {
    let bytes = curve.order_len();
    // Mask the high byte to `n.bit_len()` bits so the draw is uniform over
    // `[0, 2^n.bit_len())` rather than `[0, 2^(8*order_len))` — without this
    // step P-521's rejection rate would be ~50%.
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
        // Accept iff 1 ≤ candidate < n.
        if !candidate.is_zero() && candidate.lt(n) {
            return candidate;
        }
    }
}

/// RFC 6979 deterministic nonce `k` for order `n` (bit length `qlen`), using
/// HMAC-`D`, with `order_len`-byte octet strings.
fn generate_k<D: Digest>(
    d: &BoxedUint,
    hash: &[u8],
    n: &BoxedUint,
    order_len: usize,
    qlen: usize,
) -> BoxedUint {
    let d_oct = d.to_be_bytes(order_len);
    let h_oct = bits2int(hash, qlen).reduce(n).to_be_bytes(order_len);

    let mut v = D::zeroed_output();
    for b in v.as_mut() {
        *b = 0x01;
    }
    let mut k = D::zeroed_output(); // all zero

    for &sep in &[0x00u8, 0x01u8] {
        let mut mac = Hmac::<D>::new(k.as_ref());
        mac.update(v.as_ref());
        mac.update(&[sep]);
        mac.update(&d_oct);
        mac.update(&h_oct);
        k = mac.finalize();
        v = Hmac::<D>::mac(k.as_ref(), v.as_ref());
    }

    loop {
        let mut t = Vec::with_capacity(order_len);
        while t.len() < order_len {
            v = Hmac::<D>::mac(k.as_ref(), v.as_ref());
            t.extend_from_slice(v.as_ref());
        }
        let candidate = bits2int(&t[..order_len], qlen);
        if in_range(&candidate, n) {
            return candidate;
        }
        let mut mac = Hmac::<D>::new(k.as_ref());
        mac.update(v.as_ref());
        mac.update(&[0x00]);
        k = mac.finalize();
        v = Hmac::<D>::mac(k.as_ref(), v.as_ref());
    }
}

impl BoxedEcdsaPublicKey {
    /// Parses an uncompressed SEC1 point (`0x04 || X || Y`) on `curve`,
    /// rejecting coordinates out of range or off the curve.
    pub fn from_sec1(curve: CurveId, bytes: &[u8]) -> Result<Self, Error> {
        let flen = curve.field_len();
        if bytes.len() != 1 + 2 * flen || bytes[0] != 0x04 {
            return Err(Error::Malformed);
        }
        let x = BoxedUint::from_be_bytes(&bytes[1..1 + flen]);
        let y = BoxedUint::from_be_bytes(&bytes[1 + flen..]);
        let c = curve.curve();
        if !c.in_field(&x) || !c.in_field(&y) || !c.is_on_curve(&x, &y) {
            return Err(Error::InvalidInput);
        }
        Ok(BoxedEcdsaPublicKey { curve, x, y })
    }

    /// Encodes the key as an uncompressed SEC1 point (`0x04 || X || Y`).
    pub fn to_sec1(&self) -> Vec<u8> {
        let flen = self.curve.field_len();
        let mut out = vec![0u8; 1 + 2 * flen];
        out[0] = 0x04;
        out[1..1 + flen].copy_from_slice(&self.x.to_be_bytes(flen));
        out[1 + flen..].copy_from_slice(&self.y.to_be_bytes(flen));
        out
    }

    /// The curve this key belongs to.
    pub fn curve(&self) -> CurveId {
        self.curve
    }

    /// Verifies `sig` over `msg`, hashing with `D`.
    pub fn verify<D: Digest>(&self, msg: &[u8], sig: &BoxedEcdsaSignature) -> Result<(), Error> {
        let c = self.curve.curve();
        let n = c.order().clone();
        let fq = BoxedMontModulus::new(&n);
        if !in_range(&sig.r, &n) || !in_range(&sig.s, &n) {
            return Err(Error::Verification);
        }
        let hash = D::digest(msg);
        let z = bits2int(hash.as_ref(), n.bit_len()).reduce(&n);
        let w = inv_mod(&fq, &sig.s, &n);
        let u1 = fq.mul_mod(&z, &w);
        let u2 = fq.mul_mod(&sig.r, &w);

        let point = c.lift_affine(&self.x, &self.y);
        let sum = c.point_add(&c.mul_generator(&u1), &c.scalar_mul(&u2, &point));
        let (vx, _) = c.to_affine(&sum).ok_or(Error::Verification)?;
        let v = vx.reduce(&n);
        if bool::from(v.ct_eq(&sig.r)) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

impl BoxedEcdsaPrivateKey {
    /// Creates a private key from a big-endian scalar on `curve`, checking it is
    /// in `[1, n-1]`.
    pub fn from_bytes(curve: CurveId, bytes: &[u8]) -> Result<Self, Error> {
        let d = BoxedUint::from_be_bytes(bytes);
        let n = curve.curve().order().clone();
        if in_range(&d, &n) {
            Ok(BoxedEcdsaPrivateKey { curve, d })
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// Generates a new private key on `curve` from `rng`.
    pub fn generate<R: RngCore>(curve: CurveId, rng: &mut R) -> Self {
        let n = curve.curve().order().clone();
        BoxedEcdsaPrivateKey {
            curve,
            d: random_scalar(curve, &n, rng),
        }
    }

    /// The curve this key belongs to.
    pub fn curve(&self) -> CurveId {
        self.curve
    }

    /// Derives the public key `d * G`.
    pub fn public_key(&self) -> BoxedEcdsaPublicKey {
        let c = self.curve.curve();
        let (x, y) = c
            .to_affine(&c.mul_generator(&self.d))
            .expect("d in [1,n-1] so d*G is not the identity");
        BoxedEcdsaPublicKey {
            curve: self.curve,
            x,
            y,
        }
    }

    /// Signs `msg`, hashing with `D` and deriving the nonce per RFC 6979.
    pub fn sign<D: Digest>(&self, msg: &[u8]) -> Result<BoxedEcdsaSignature, Error> {
        let c = self.curve.curve();
        let n = c.order().clone();
        let fq = BoxedMontModulus::new(&n);
        let order_len = self.curve.order_len();

        let hash = D::digest(msg);
        let z = bits2int(hash.as_ref(), n.bit_len()).reduce(&n);
        let k = generate_k::<D>(&self.d, hash.as_ref(), &n, order_len, n.bit_len());

        let r = c
            .to_affine(&c.mul_generator(&k))
            .ok_or(Error::InvalidInput)?
            .0
            .reduce(&n);
        if r.is_zero() {
            return Err(Error::InvalidInput);
        }
        let k_inv = inv_mod(&fq, &k, &n);
        let z_rd = fq.add_mod(&z, &fq.mul_mod(&r, &self.d));
        let s = fq.mul_mod(&k_inv, &z_rd);
        if s.is_zero() {
            return Err(Error::InvalidInput);
        }
        Ok(BoxedEcdsaSignature { r, s })
    }
}

impl BoxedEcdsaSignature {
    /// Builds a signature from its `(r, s)` components.
    pub fn from_components(r: BoxedUint, s: BoxedUint) -> Self {
        BoxedEcdsaSignature { r, s }
    }

    /// The `r` component as a `BoxedUint`. Use [`Self::r_bytes`] for the
    /// fixed-width big-endian byte encoding.
    pub fn r(&self) -> &BoxedUint {
        &self.r
    }

    /// The `s` component as a `BoxedUint`. See [`Self::r`].
    pub fn s(&self) -> &BoxedUint {
        &self.s
    }

    /// The `r` component encoded big-endian, left-padded to
    /// `curve.order_len()` bytes (the SEC1 fixed-width encoding).
    pub fn r_bytes(&self, curve: CurveId) -> Vec<u8> {
        self.r.to_be_bytes(curve.order_len())
    }

    /// The `s` component encoded big-endian, left-padded to
    /// `curve.order_len()` bytes.
    pub fn s_bytes(&self, curve: CurveId) -> Vec<u8> {
        self.s.to_be_bytes(curve.order_len())
    }

    /// The fixed `r ‖ s` encoding, each half `curve.order_len()` bytes.
    pub fn to_bytes(&self, curve: CurveId) -> Vec<u8> {
        let len = curve.order_len();
        let mut out = self.r.to_be_bytes(len);
        out.extend_from_slice(&self.s.to_be_bytes(len));
        out
    }

    /// Whether `s` is in the lower half of `curve`'s group order — the
    /// "low-S" form required by signature-non-malleability conventions
    /// (Bitcoin BIP-62, EVM, anti-replay caches that key on signature
    /// bytes). For any valid ECDSA signature `(r, s)`, the pair
    /// `(r, n − s)` also verifies, so callers needing bytewise unique
    /// signatures must require `is_low_s()`. Mirrors the const-generic
    /// helper in [`super::ecdsa::Signature::is_low_s`].
    pub fn is_low_s(&self, curve: CurveId) -> bool {
        // half_n = (n + 1) / 2 — the smallest "high-S" boundary.
        let n = curve.curve().order().clone();
        let half_n = n.shr_bits(1).add(&BoxedUint::from_u64(1));
        self.s.lt(&half_n)
    }

    /// Returns the canonical low-S representative for this signature on
    /// `curve`: if `s` is already in the lower half, returns a clone;
    /// otherwise returns `(r, n − s)`, which is equally valid and bytewise
    /// unique. Mirrors [`super::ecdsa::Signature::to_low_s`].
    pub fn to_low_s(&self, curve: CurveId) -> Self {
        if self.is_low_s(curve) {
            self.clone()
        } else {
            let n = curve.curve().order().clone();
            BoxedEcdsaSignature {
                r: self.r.clone(),
                s: n.sub(&self.s),
            }
        }
    }
}

impl Drop for BoxedEcdsaPrivateKey {
    fn drop(&mut self) {
        // Best-effort wipe of the scalar `d` before its heap-backing `Vec`
        // is freed. Mirrors the manual-wipe convention used elsewhere in
        // the crate (e.g. `cipher/poly1305.rs`, `cipher/aes/mod.rs`).
        self.d.zeroize();
    }
}

impl Drop for BoxedEcdhPrivateKey {
    fn drop(&mut self) {
        // Best-effort wipe of the ECDH scalar `d`. See `BoxedEcdsaPrivateKey`.
        self.d.zeroize();
    }
}

/// DER `Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }` — the form used
/// by TLS and X.509.
#[cfg(feature = "der")]
impl BoxedEcdsaSignature {
    /// Encodes the signature as a DER `Ecdsa-Sig-Value`.
    pub fn to_der(&self, curve: CurveId) -> Vec<u8> {
        use crate::der::{encode_integer, encode_sequence};
        let len = curve.order_len();
        encode_sequence(
            &[
                encode_integer(&self.r.to_be_bytes(len)),
                encode_integer(&self.s.to_be_bytes(len)),
            ]
            .concat(),
        )
    }

    /// Decodes a DER `Ecdsa-Sig-Value` with strict-DER enforcement (no
    /// unnecessary leading `0x00`/`0xff`, no empty INTEGER body, no trailing
    /// data). Closes the ECDSA signature-malleability gap at the bytes
    /// layer — many byte-distinct encodings of the same `(r, s)` are
    /// otherwise accepted.
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
        Ok(BoxedEcdsaSignature {
            r: BoxedUint::from_be_bytes(r),
            s: BoxedUint::from_be_bytes(s),
        })
    }
}

/// SEC1 `ECPrivateKey` DER/PEM (`EC PRIVATE KEY`), the format OpenSSL emits for
/// EC keys.
#[cfg(feature = "der")]
impl BoxedEcdsaPrivateKey {
    /// Encodes the key as a SEC1 `ECPrivateKey` DER structure (with the named
    /// curve and public key included).
    pub fn to_sec1_der(&self) -> Vec<u8> {
        use crate::der::{
            encode_bit_string, encode_context, encode_integer, encode_octet_string,
            encode_sequence, oid_tlv,
        };
        let order_len = self.curve.order_len();
        let priv_oct = encode_octet_string(&self.d.to_be_bytes(order_len));
        // parameters [0] EXPLICIT namedCurve OID.
        let params = encode_context(0, &oid_tlv(self.curve.named_curve_oid()));
        // publicKey [1] EXPLICIT BIT STRING (uncompressed SEC1 point).
        let pubkey = encode_context(1, &encode_bit_string(&self.public_key().to_sec1()));
        encode_sequence(&[encode_integer(&[1]), priv_oct, params, pubkey].concat())
    }

    /// Encodes the key as a SEC1 PEM document (`-----BEGIN EC PRIVATE KEY-----`).
    pub fn to_sec1_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("EC PRIVATE KEY", &self.to_sec1_der())
    }

    /// Parses a SEC1 `ECPrivateKey` DER structure (the named curve must be one
    /// of the supported curves).
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
        let curve = CurveId::from_named_curve_oid(&arcs).ok_or(Error::Malformed)?;
        Self::from_bytes(curve, priv_bytes)
    }

    /// Parses a SEC1 PEM EC private key.
    pub fn from_sec1_pem(pem: &str) -> Result<Self, Error> {
        let der = crate::der::pem_decode(pem, "EC PRIVATE KEY").map_err(|_| Error::Malformed)?;
        Self::from_sec1_der(&der)
    }
}

impl BoxedEcdhPrivateKey {
    /// Generates a new ECDH private key on `curve` from `rng`.
    pub fn generate<R: RngCore>(curve: CurveId, rng: &mut R) -> Self {
        let n = curve.curve().order().clone();
        BoxedEcdhPrivateKey {
            curve,
            d: random_scalar(curve, &n, rng),
        }
    }

    /// Creates an ECDH private key from a big-endian scalar on `curve`.
    pub fn from_bytes(curve: CurveId, bytes: &[u8]) -> Result<Self, Error> {
        let d = BoxedUint::from_be_bytes(bytes);
        let n = curve.curve().order().clone();
        if in_range(&d, &n) {
            Ok(BoxedEcdhPrivateKey { curve, d })
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// The public key `d * G` to send to the peer.
    pub fn public_key(&self) -> BoxedEcdsaPublicKey {
        let c = self.curve.curve();
        let (x, y) = c
            .to_affine(&c.mul_generator(&self.d))
            .expect("d in [1,n-1] so d*G is not the identity");
        BoxedEcdsaPublicKey {
            curve: self.curve,
            x,
            y,
        }
    }

    /// The ECDH shared secret with `peer`: the affine x-coordinate of
    /// `d * peer`, big-endian, `field_len` bytes.
    pub fn diffie_hellman(&self, peer: &BoxedEcdsaPublicKey) -> Result<Vec<u8>, Error> {
        if peer.curve != self.curve {
            return Err(Error::InvalidInput);
        }
        let c = self.curve.curve();
        let point = c.lift_affine(&peer.x, &peer.y);
        let shared = c.scalar_mul(&self.d, &point);
        let (x, _) = c.to_affine(&shared).ok_or(Error::InvalidInput)?;
        Ok(x.to_be_bytes(self.curve.field_len()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha256, Sha384, Sha512};
    use crate::rng::HmacDrbg;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 6979 A.2.5 — P-256, SHA-256, message "sample".
    #[test]
    fn rfc6979_p256_sample() {
        let d = from_hex("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721");
        let sk = BoxedEcdsaPrivateKey::from_bytes(CurveId::P256, &d).unwrap();
        let sig = sk.sign::<Sha256>(b"sample").unwrap();
        assert_eq!(
            sig.r.to_be_bytes(32),
            from_hex("efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716")
        );
        assert_eq!(
            sig.s.to_be_bytes(32),
            from_hex("f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8")
        );
        sk.public_key().verify::<Sha256>(b"sample", &sig).unwrap();
    }

    // RFC 6979 A.2.6 — P-384, SHA-384, message "sample".
    #[test]
    fn rfc6979_p384_sample() {
        let d = from_hex(
            "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8\
             96d5724e4c70a825f872c9ea60d2edf5",
        );
        let sk = BoxedEcdsaPrivateKey::from_bytes(CurveId::P384, &d).unwrap();
        let sig = sk.sign::<Sha384>(b"sample").unwrap();
        assert_eq!(
            sig.r.to_be_bytes(48),
            from_hex(
                "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c\
                 81a648152e44acf96e36dd1e80fabe46"
            )
        );
        assert_eq!(
            sig.s.to_be_bytes(48),
            from_hex(
                "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f\
                 a329c145786e679e7b82c71a38628ac8"
            )
        );
        sk.public_key().verify::<Sha384>(b"sample", &sig).unwrap();
    }

    // RFC 6979 A.2.7 — P-521, SHA-512, message "sample".
    #[test]
    fn rfc6979_p521_sample() {
        let d = from_hex(
            "00fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75\
             caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b8\
             3538",
        );
        let sk = BoxedEcdsaPrivateKey::from_bytes(CurveId::P521, &d).unwrap();
        let sig = sk.sign::<Sha512>(b"sample").unwrap();
        assert_eq!(
            sig.r.to_be_bytes(66),
            from_hex(
                "00c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f\
                 174e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e3\
                 77fa"
            )
        );
        sk.public_key().verify::<Sha512>(b"sample", &sig).unwrap();
    }

    #[test]
    fn secp256k1_sign_verify_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"secp256k1-key", b"nonce", &[]);
        let sk = BoxedEcdsaPrivateKey::generate(CurveId::Secp256k1, &mut rng);
        let pk = sk.public_key();
        let sig = sk.sign::<Sha256>(b"hello secp256k1").unwrap();
        pk.verify::<Sha256>(b"hello secp256k1", &sig).unwrap();
        assert!(pk.verify::<Sha256>(b"tampered", &sig).is_err());

        // SEC1 round-trip (validates the on-curve check).
        let sec1 = pk.to_sec1();
        assert_eq!(
            BoxedEcdsaPublicKey::from_sec1(CurveId::Secp256k1, &sec1)
                .unwrap()
                .to_sec1(),
            sec1
        );
    }

    #[cfg(feature = "der")]
    #[test]
    fn ec_private_key_sec1_roundtrip() {
        for curve in [
            CurveId::P256,
            CurveId::P384,
            CurveId::P521,
            CurveId::Secp256k1,
        ] {
            let mut rng = HmacDrbg::<Sha256>::new(b"sec1", b"n", &[]);
            let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);

            let pem = sk.to_sec1_pem();
            assert!(pem.starts_with("-----BEGIN EC PRIVATE KEY-----"));
            let parsed = BoxedEcdsaPrivateKey::from_sec1_pem(&pem).unwrap();
            assert_eq!(parsed.curve(), curve);
            // Same key: public points match.
            assert_eq!(parsed.public_key().to_sec1(), sk.public_key().to_sec1());
        }
    }

    #[test]
    fn ecdh_p256_matches_const_generic() {
        // Boxed P-256 ECDH must agree with the const-generic implementation.
        let mut rng = HmacDrbg::<Sha256>::new(b"ecdh", b"n", &[]);
        let a = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut rng);
        let b = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut rng);
        let ab = a.diffie_hellman(&b.public_key()).unwrap();
        let ba = b.diffie_hellman(&a.public_key()).unwrap();
        assert_eq!(ab, ba);
    }

    #[test]
    fn boxed_signature_r_s_accessors_roundtrip() {
        // Generate a real signature, then deconstruct/reconstruct via r/s.
        let mut rng = HmacDrbg::<Sha256>::new(b"sig-rs", b"n", &[]);
        for curve in [
            CurveId::P256,
            CurveId::P384,
            CurveId::P521,
            CurveId::Secp256k1,
        ] {
            let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
            let sig = sk.sign::<Sha256>(b"hello").unwrap();

            // r/s as integers round-trip via from_components.
            let rebuilt = BoxedEcdsaSignature::from_components(sig.r().clone(), sig.s().clone());
            assert_eq!(rebuilt, sig);

            // r_bytes/s_bytes concatenate to to_bytes(curve).
            let mut concat = sig.r_bytes(curve);
            concat.extend_from_slice(&sig.s_bytes(curve));
            assert_eq!(concat, sig.to_bytes(curve));
        }
    }

    #[test]
    fn boxed_signature_low_s_idempotent_and_verifies() {
        // For every supported curve, `to_low_s` must produce a low-S
        // signature that still verifies, and applying it a second time
        // must be a no-op (idempotence).
        let mut rng = HmacDrbg::<Sha256>::new(b"low-s", b"n", &[]);
        for curve in [
            CurveId::P256,
            CurveId::P384,
            CurveId::P521,
            CurveId::Secp256k1,
        ] {
            let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
            let pk = sk.public_key();
            let sig = sk.sign::<Sha256>(b"low-s message").unwrap();

            let low = sig.to_low_s(curve);
            assert!(low.is_low_s(curve), "to_low_s must produce a low-S sig");
            assert_eq!(low.to_low_s(curve), low, "to_low_s must be idempotent");
            // The canonicalised signature must still verify against the
            // public key — flipping `s` to `n − s` is a valid ECDSA
            // signature for the same `(pk, msg)`.
            pk.verify::<Sha256>(b"low-s message", &low).unwrap();
        }
    }

    #[test]
    fn boxed_signature_high_s_flip_round_trip() {
        // Construct a synthetic high-S signature (s' = n − s with original
        // s low) and confirm `to_low_s` recovers the original.
        let mut rng = HmacDrbg::<Sha256>::new(b"high-s", b"n", &[]);
        let curve = CurveId::P256;
        let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
        let sig = sk.sign::<Sha256>(b"flip me").unwrap();
        let low = sig.to_low_s(curve);
        assert!(low.is_low_s(curve));

        // Build the high-S form `(r, n − s)` by hand and verify the
        // helper canonicalises it back.
        let n = curve.curve().order().clone();
        let high = BoxedEcdsaSignature::from_components(low.r().clone(), n.sub(low.s()));
        assert!(!high.is_low_s(curve));
        assert_eq!(high.to_low_s(curve), low);
    }
}
