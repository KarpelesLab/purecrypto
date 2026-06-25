//! X448 Diffie-Hellman over Curve448 (RFC 7748).
//!
//! The field is GF(2⁴⁴⁸−2²²⁴−1); arithmetic reuses the constant-time
//! [`MontModulus`] over seven 64-bit limbs. The
//! scalar multiplication is the Montgomery ladder with constant-time
//! conditional swaps on the Montgomery curve `v² = u³ + A·u² + u` with
//! `A = 156326`.
//!
//! Unlike X25519, RFC 7748 §6.2 does **not** mandate rejecting low-order /
//! contributory-failure peer public keys for X448 (the curve's small subgroup
//! is trivial enough that the cofactor handling differs). For parity with the
//! X25519 surface — and because TLS 1.3 (RFC 8446 §7.4.2) still requires
//! aborting on an all-zero shared secret — [`X448PrivateKey::diffie_hellman`]
//! returns a `Result` and surfaces the all-zero output as an error; the raw
//! [`x448`] primitive performs no such check.

use crate::bignum::{MontModulus, Uint};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::rng::RngCore;

/// An X448 Diffie-Hellman failure mode: the shared secret is the canonical
/// all-zero u-coordinate (the peer supplied a small-order / degenerate public
/// key). RFC 8446 §7.4.2 requires aborting the TLS handshake with
/// `illegal_parameter` in this case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X448Error {
    /// The shared secret is the canonical zero point.
    SmallOrderPeer,
}

impl core::fmt::Display for X448Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            X448Error::SmallOrderPeer => {
                f.write_str("X448 peer public key is a small-order / contributory-failure point")
            }
        }
    }
}

impl core::error::Error for X448Error {}

/// `p = 2⁴⁴⁸ − 2²²⁴ − 1` (big-endian hex).
const P448_HEX: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
ffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
/// `(A − 2) / 4 = 39081` for Curve448 (`A = 156326`).
const A24: u64 = 39081;

type Fe = Uint<7>;

fn fe_from_hex(hex: &str) -> Fe {
    super::uint_from_be_hex(hex)
}

/// Computes the raw X448 function: `scalar * point` on Curve448, returning the
/// resulting u-coordinate (little-endian, 56 bytes).
///
/// **This is the unchecked primitive.** When `point` is a small-order or
/// otherwise degenerate u-coordinate the return value is the all-zero buffer.
/// Callers exposed to network peer input should use
/// [`X448PrivateKey::diffie_hellman`] (which returns `Result`) instead.
pub fn x448(scalar: &[u8; 56], point: &[u8; 56]) -> [u8; 56] {
    let fp = MontModulus::new(fe_from_hex(P448_HEX));

    // Clamp the scalar (RFC 7748 §5): clear the bottom two bits and set the top
    // bit. Curve448's cofactor is 4, hence two low bits; 448 is a multiple of
    // 8, so there is no top-byte mask (unlike X25519's 255-bit field).
    let mut k = *scalar;
    k[0] &= 252;
    k[55] |= 128;
    let k = Fe::from_le_bytes(&k);

    // Decode the u-coordinate: reduce mod p (no top-bit mask — the full 56
    // bytes are significant for the 448-bit field).
    let u = Fe::from_le_bytes(point).reduce(fp.modulus());

    let one = fp.to_mont(&Fe::ONE);
    let x1 = fp.to_mont(&u);
    let mut x2 = one;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = one;
    let a24 = fp.to_mont(&Fe::from_u64(A24));

    let mul = |a: &Fe, b: &Fe| fp.mont_mul(a, b);
    let add = |a: &Fe, b: &Fe| fp.add_mod(a, b);
    let sub = |a: &Fe, b: &Fe| fp.sub_mod(a, b);

    let mut swap = 0u8;
    let limbs = k.as_limbs();
    let mut t = 448;
    while t > 0 {
        t -= 1;
        let kt = ((limbs[t / 64] >> (t % 64)) & 1) as u8;
        swap ^= kt;
        let sw = Choice::from(swap);
        Fe::conditional_swap(&mut x2, &mut x3, sw);
        Fe::conditional_swap(&mut z2, &mut z3, sw);
        swap = kt;

        let a = add(&x2, &z2);
        let aa = mul(&a, &a);
        let b = sub(&x2, &z2);
        let bb = mul(&b, &b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);
        let t0 = add(&da, &cb);
        x3 = mul(&t0, &t0);
        let t1 = sub(&da, &cb);
        let t1sq = mul(&t1, &t1);
        z3 = mul(&x1, &t1sq);
        x2 = mul(&aa, &bb);
        let t2 = add(&aa, &mul(&a24, &e));
        z2 = mul(&e, &t2);
    }
    let sw = Choice::from(swap);
    Fe::conditional_swap(&mut x2, &mut x3, sw);
    Fe::conditional_swap(&mut z2, &mut z3, sw);

    // result = x2 / z2 (or 0 if z2 == 0). The inverse is via Fermat's little
    // theorem (`z^{p-2} mod p`) on the constant-time Montgomery ladder, NOT a
    // variable-time extended-Euclidean inverse — z2 depends on the secret
    // scalar. Fermat naturally returns 0 when z2 == 0, so the small-order case
    // yields the all-zero output without a data-dependent branch.
    let z2_plain = fp.from_mont(&z2);
    let p_minus_2 = fp.modulus().wrapping_sub(&Fe::from_u64(2));
    let z_inv = fp.pow(&z2_plain, &p_minus_2);
    let res = fp.mul_mod(&fp.from_mont(&x2), &z_inv);
    let mut out = [0u8; 56];
    res.write_le_bytes(&mut out);
    out
}

/// The X448 base point (`u = 5`).
pub const BASE_POINT: [u8; 56] = {
    let mut b = [0u8; 56];
    b[0] = 5;
    b
};

/// An X448 private key (a 56-byte scalar).
#[derive(Clone)]
pub struct X448PrivateKey {
    scalar: [u8; 56],
}

// Best-effort zeroize on drop: the scalar is full secret material. Overwrite
// the bytes and route the read through `core::hint::black_box` so LLVM cannot
// eliminate the writes as dead stores (same pattern as X25519).
impl Drop for X448PrivateKey {
    fn drop(&mut self) {
        for b in self.scalar.iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(&self.scalar);
    }
}

impl X448PrivateKey {
    /// Generates a new private key from `rng`.
    ///
    /// `rng` SHOULD be a cryptographically secure CSPRNG (see
    /// [`CryptoRng`](crate::rng::CryptoRng)).
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let mut scalar = [0u8; 56];
        rng.fill_bytes(&mut scalar);
        X448PrivateKey { scalar }
    }

    /// Creates a private key from raw scalar bytes (clamped on use).
    pub fn from_bytes(scalar: [u8; 56]) -> Self {
        X448PrivateKey { scalar }
    }

    /// The raw 56-byte scalar, as supplied to [`from_bytes`](Self::from_bytes)
    /// or generated (clamping is applied on use, not stored). This is secret
    /// key material: the caller owns the returned array and is responsible for
    /// wiping it after use.
    pub fn to_bytes(&self) -> [u8; 56] {
        self.scalar
    }

    /// The public key `X448(scalar, 5)` to send to the peer.
    pub fn public_key(&self) -> [u8; 56] {
        x448(&self.scalar, &BASE_POINT)
    }

    /// The shared secret with `peer`'s public key. Returns
    /// `Err(X448Error::SmallOrderPeer)` when the resulting u-coordinate is the
    /// canonical zero (RFC 8446 §7.4.2 requires this rejection in TLS).
    ///
    /// The zero-check is constant time: the candidate output is materialised
    /// regardless and compared with [`ConstantTimeEq`].
    pub fn diffie_hellman(&self, peer: &[u8; 56]) -> Result<[u8; 56], X448Error> {
        let out = x448(&self.scalar, peer);
        if bool::from(out.ct_eq(&[0u8; 56])) {
            Err(X448Error::SmallOrderPeer)
        } else {
            Ok(out)
        }
    }
}

/// An X448 public key — the 56-byte u-coordinate sent to a peer.
///
/// A thin newtype over the raw bytes so X448 keys can participate in the
/// unified [`key`](crate::key) traits, which pass peer public keys as
/// `&dyn PublicKey`. The low-level [`X448PrivateKey::public_key`] and
/// [`X448PrivateKey::diffie_hellman`] still take and return raw `[u8; 56]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X448PublicKey([u8; 56]);

impl X448PublicKey {
    /// Wraps a 56-byte u-coordinate.
    pub fn from_bytes(bytes: [u8; 56]) -> Self {
        X448PublicKey(bytes)
    }

    /// The 56-byte u-coordinate.
    pub fn to_bytes(&self) -> [u8; 56] {
        self.0
    }

    /// Borrows the 56-byte u-coordinate.
    pub fn as_bytes(&self) -> &[u8; 56] {
        &self.0
    }
}

/// RFC 8410 `id-X448` algorithm OID (1.3.101.111).
#[cfg(feature = "der")]
pub(crate) const X448_OID: &[u64] = &[1, 3, 101, 111];

/// PKCS#8 v1 (RFC 8410) private-key serialization (`id-X448`, raw 56-byte
/// scalar).
#[cfg(feature = "der")]
impl X448PrivateKey {
    /// Encodes the key as a PKCS#8 `OneAsymmetricKey` DER structure.
    pub fn to_pkcs8_der(&self) -> alloc::vec::Vec<u8> {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let version = encode_integer(&[0]);
        let algid = encode_sequence(&oid_tlv(X448_OID));
        let privkey = encode_octet_string(&encode_octet_string(&self.scalar));
        encode_sequence(&[version, algid, privkey].concat())
    }

    /// Encodes the key as a PKCS#8 PEM document (`-----BEGIN PRIVATE KEY-----`).
    pub fn to_pkcs8_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("PRIVATE KEY", &self.to_pkcs8_der())
    }

    /// Parses a PKCS#8 `OneAsymmetricKey` DER structure.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, crate::der::Error> {
        use crate::der::{Error, Reader, parse_oid, tag};
        let mut r = Reader::new(der);
        let mut seq = r.read_sequence()?;
        seq.read_integer_bytes()?; // version (v1 = 0, v2 = 1)
        let mut algid = seq.read_sequence()?;
        if parse_oid(algid.read_oid()?)?.as_slice() != X448_OID {
            return Err(Error::Malformed);
        }
        let inner = seq.read_octet_string()?;
        let scalar_bytes = Reader::new(inner).read_octet_string()?;
        if scalar_bytes.len() != 56 {
            return Err(Error::Malformed);
        }
        let mut scalar = [0u8; 56];
        scalar.copy_from_slice(scalar_bytes);
        // RFC 5958 (PKCS#8 v2): skip the OPTIONAL `[0]` attributes (constructed
        // SET) and `[1]` publicKey (IMPLICIT BIT STRING, primitive tag `0x81`;
        // also accept the constructed `0xA1` spelling) if present, then assert
        // the SEQUENCE and outer reader are fully consumed so genuine trailing
        // garbage is rejected.
        if seq.peek_tag() == Some(tag::context(0)) {
            seq.read_any()?;
        }
        if matches!(seq.peek_tag(), Some(t) if t == tag::context(1) || t == (0x80 | 1)) {
            seq.read_any()?;
        }
        seq.finish()?;
        r.finish()?;
        Ok(X448PrivateKey { scalar })
    }

    /// Parses a PKCS#8 PEM private key.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_pkcs8_der(&crate::der::pem_decode(pem, "PRIVATE KEY")?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::test_util::from_hex;

    fn hex56(s: &str) -> [u8; 56] {
        from_hex::<56>(s)
    }

    #[cfg(feature = "der")]
    #[test]
    fn pkcs8_v1_round_trip() {
        let scalar = hex56(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
             d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        );
        let sk = X448PrivateKey::from_bytes(scalar);
        let der = sk.to_pkcs8_der();
        let sk2 = X448PrivateKey::from_pkcs8_der(&der).expect("v1 parse");
        assert_eq!(sk2.to_bytes(), scalar);
    }

    #[cfg(feature = "der")]
    #[test]
    fn pkcs8_rejects_trailing_garbage() {
        let scalar = hex56(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
             d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        );
        let mut der = X448PrivateKey::from_bytes(scalar).to_pkcs8_der();
        der.push(0xff);
        der.push(0x00);
        assert!(X448PrivateKey::from_pkcs8_der(&der).is_err());
    }

    #[cfg(feature = "der")]
    #[test]
    fn pkcs8_v2_with_public_key_parses() {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let scalar = hex56(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
             d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        );
        let sk = X448PrivateKey::from_bytes(scalar);
        let pub_enc = sk.public_key();

        // PKCS#8 v2 (RFC 5958) with the OPTIONAL `[1]` publicKey present as a
        // primitive IMPLICIT BIT STRING (tag 0x81). The BIT STRING content is
        // 57 bytes (1 unused-bits prefix + 56 key bytes), still short-form.
        let version = encode_integer(&[1]);
        let algid = encode_sequence(&oid_tlv(X448_OID));
        let privkey = encode_octet_string(&encode_octet_string(&scalar));
        let mut pub_bitstring = alloc::vec![0u8]; // 0 unused bits
        pub_bitstring.extend_from_slice(&pub_enc);
        let mut pubkey_field = alloc::vec![0x81u8];
        pubkey_field.push(pub_bitstring.len() as u8); // 57 (< 0x80)
        pubkey_field.extend_from_slice(&pub_bitstring);
        let der = encode_sequence(&[version, algid, privkey, pubkey_field].concat());

        let parsed = X448PrivateKey::from_pkcs8_der(&der).expect("v2 parse");
        assert_eq!(parsed.to_bytes(), scalar);
        assert_eq!(parsed.public_key(), pub_enc);
    }

    #[test]
    fn rfc7748_test_vector() {
        // RFC 7748 §5.2, first X448 vector.
        let scalar = hex56(
            "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121\
             700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3",
        );
        let u = hex56(
            "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9\
             814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086",
        );
        let out = x448(&scalar, &u);
        assert_eq!(
            out,
            hex56(
                "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f\
                 e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"
            )
        );
    }

    #[test]
    fn rfc7748_test_vector_second() {
        // RFC 7748 §5.2, second X448 vector.
        let scalar = hex56(
            "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5\
             38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f",
        );
        let u = hex56(
            "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b\
             165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db",
        );
        let out = x448(&scalar, &u);
        assert_eq!(
            out,
            hex56(
                "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7\
                 ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"
            )
        );
    }

    #[test]
    fn rfc7748_iterated_one() {
        // RFC 7748 §5.2: after 1 iteration of the recurrence (k = u = base
        // point 0500...00), the result is the known value.
        let mut k = [0u8; 56];
        k[0] = 5;
        let u = k;
        k = x448(&k, &u);
        assert_eq!(
            k,
            hex56(
                "3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a\
                 4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113"
            )
        );
    }

    #[test]
    fn rfc7748_iterated_thousand() {
        // RFC 7748 §5.2: 1000 iterations of the recurrence.
        let mut k = [0u8; 56];
        k[0] = 5;
        let mut u = k;
        for _ in 0..1000 {
            let out = x448(&k, &u);
            u = k;
            k = out;
        }
        assert_eq!(
            k,
            hex56(
                "aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4\
                 af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38"
            )
        );
    }

    #[test]
    #[ignore = "1,000,000-iteration RFC 7748 vector is slow; run explicitly"]
    fn rfc7748_iterated_million() {
        let mut k = [0u8; 56];
        k[0] = 5;
        let mut u = k;
        for _ in 0..1_000_000 {
            let out = x448(&k, &u);
            u = k;
            k = out;
        }
        assert_eq!(
            k,
            hex56(
                "077f453681caca3693198420bbe515cae0002472519b3e67661a7e89\
                 cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37"
            )
        );
    }

    #[test]
    fn rfc7748_diffie_hellman() {
        // RFC 7748 §6.2.
        let a = X448PrivateKey::from_bytes(hex56(
            "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
             d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b",
        ));
        let b = X448PrivateKey::from_bytes(hex56(
            "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d\
             6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d",
        ));

        assert_eq!(
            a.public_key(),
            hex56(
                "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
                 22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
            )
        );
        assert_eq!(
            b.public_key(),
            hex56(
                "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
                 27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
            )
        );

        let shared = hex56(
            "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b\
             b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d",
        );
        assert_eq!(a.diffie_hellman(&b.public_key()).unwrap(), shared);
        assert_eq!(b.diffie_hellman(&a.public_key()).unwrap(), shared);
    }

    #[test]
    fn generated_keys_agree() {
        let mut rng = HmacDrbg::<Sha256>::new(b"x448", b"nonce", &[]);
        let a = X448PrivateKey::generate(&mut rng);
        let b = X448PrivateKey::generate(&mut rng);
        assert_eq!(
            a.diffie_hellman(&b.public_key()).unwrap(),
            b.diffie_hellman(&a.public_key()).unwrap()
        );
    }
}
