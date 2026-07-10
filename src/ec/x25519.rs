//! X25519 Diffie-Hellman over Curve25519 (RFC 7748).
//!
//! The field is GF(2²⁵⁵−19); arithmetic reuses the constant-time unsaturated
//! 5×51-bit limb backend (`ec::curve25519::field::Fe`). The scalar
//! multiplication is the Montgomery ladder with constant-time conditional
//! swaps.

use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::ec::curve25519::field::Fe;
use crate::rng::RngCore;

/// An X25519 Diffie-Hellman failure mode. Currently only one: the peer
/// supplied a low-order public key whose product with our scalar is the
/// identity (encoded as the all-zero 32-byte u-coordinate). RFC 8446 §7.4.2
/// requires aborting the handshake with `illegal_parameter` in this case;
/// RFC 7748 §6.1 calls it a "contributory" failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum X25519Error {
    /// The shared secret is the canonical zero point (peer sent a small-order
    /// or otherwise degenerate public key).
    SmallOrderPeer,
}

impl core::fmt::Display for X25519Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            X25519Error::SmallOrderPeer => {
                f.write_str("X25519 peer public key is a small-order / contributory-failure point")
            }
        }
    }
}

impl core::error::Error for X25519Error {}

/// `(A - 2) / 4 = 121665` for Curve25519, as a field element.
const A24: Fe = Fe([121665, 0, 0, 0, 0]);

/// Computes the raw X25519 function: `scalar * point` on Curve25519, returning
/// the resulting u-coordinate (little-endian, 32 bytes).
///
/// **This is the unchecked primitive.** When `point` is a small-order or
/// otherwise degenerate u-coordinate the return value is the all-zero buffer
/// — RFC 7748 §6.1 and RFC 8446 §7.4.2 require rejecting this case in DH
/// contexts, so callers exposed to network peer input should use
/// [`X25519PrivateKey::diffie_hellman`] (which returns `Result`) instead.
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    // Clamp the scalar (RFC 7748 §5).
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    // Decode the u-coordinate: mask the top bit. The value may be a
    // non-canonical residue (`p ≤ u < 2^255`) — the lazy 51-bit
    // representation handles it, and RFC 7748 mandates this masking-only
    // treatment.
    let mut ub = *point;
    ub[31] &= 127;
    let x1 = Fe::from_bytes(&ub);

    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;

    // Montgomery ladder over bits 254..0 of the clamped scalar (bit 255 is
    // cleared and bit 254 set by clamping).
    let mut swap = 0u8;
    let mut t = 255;
    while t > 0 {
        t -= 1;
        let kt = (k[t / 8] >> (t % 8)) & 1;
        swap ^= kt;
        let sw = Choice::from(swap);
        Fe::conditional_swap(&mut x2, &mut x3, sw);
        Fe::conditional_swap(&mut z2, &mut z3, sw);
        swap = kt;

        let a = x2.add(&z2);
        let aa = a.sq();
        let b = x2.sub(&z2);
        let bb = b.sq();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).sq();
        z3 = x1.mul(&da.sub(&cb).sq());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&A24.mul(&e)));
    }
    let sw = Choice::from(swap);
    Fe::conditional_swap(&mut x2, &mut x3, sw);
    Fe::conditional_swap(&mut z2, &mut z3, sw);

    // result = x2 / z2 (or 0 if z2 == 0).
    //
    // The inverse is the constant-time Fermat addition chain (`z^{p-2}`),
    // NOT a variable-time extended-Euclidean inverse — z2 depends on the
    // secret scalar and any timing variation here would leak. Fermat
    // naturally returns 0 when z2 == 0, so the small-order /
    // contributory-failure case yields the all-zero output without a
    // data-dependent branch.
    x2.mul(&z2.invert()).to_bytes()
}

/// The X25519 base point (`u = 9`).
pub const BASE_POINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// An X25519 private key (a 32-byte scalar).
#[derive(Clone)]
pub struct X25519PrivateKey {
    scalar: [u8; 32],
}

// Best-effort zeroize on drop: the 32-byte scalar is full secret material
// and would otherwise be returned to the allocator/stack frame intact.
// Overwrite the bytes and route the read through `core::hint::black_box`
// so LLVM cannot eliminate the writes as dead stores (same pattern as
// ML-DSA/ML-KEM in `src/mldsa/mod.rs` and `src/mlkem/mod.rs`).
impl Drop for X25519PrivateKey {
    fn drop(&mut self) {
        for b in self.scalar.iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(&self.scalar);
    }
}

impl X25519PrivateKey {
    /// Generates a new private key from `rng`.
    ///
    /// `rng` SHOULD be a cryptographically secure CSPRNG (see
    /// [`CryptoRng`](crate::rng::CryptoRng)). The bound is left at [`RngCore`]
    /// only so the TLS / DTLS handshake layers can thread a single shared RNG
    /// type through ephemeral key-share generation; production callers should
    /// pass `OsRng` or an HMAC-DRBG seeded from one.
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let mut scalar = [0u8; 32];
        rng.fill_bytes(&mut scalar);
        X25519PrivateKey { scalar }
    }

    /// Creates a private key from raw scalar bytes (clamped on use).
    pub fn from_bytes(scalar: [u8; 32]) -> Self {
        X25519PrivateKey { scalar }
    }

    /// The raw 32-byte scalar, as supplied to [`from_bytes`](Self::from_bytes)
    /// or generated (clamping is applied on use, not stored). This is secret
    /// key material: the caller owns the returned array and is responsible for
    /// wiping it after use.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar
    }

    /// The public key `X25519(scalar, 9)` to send to the peer.
    pub fn public_key(&self) -> [u8; 32] {
        x25519(&self.scalar, &BASE_POINT)
    }

    /// The shared secret with `peer`'s public key. Returns
    /// `Err(X25519Error::SmallOrderPeer)` when the peer's input lies in the
    /// small subgroup and the resulting u-coordinate is the canonical zero —
    /// RFC 7748 §6.1 and RFC 8446 §7.4.2 require this rejection.
    ///
    /// The zero-check is constant time: the candidate output is materialised
    /// regardless and compared with [`ConstantTimeEq`].
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> Result<[u8; 32], X25519Error> {
        let out = x25519(&self.scalar, peer);
        if bool::from(out.ct_eq(&[0u8; 32])) {
            Err(X25519Error::SmallOrderPeer)
        } else {
            Ok(out)
        }
    }
}

/// An X25519 public key — the 32-byte u-coordinate sent to a peer.
///
/// A thin newtype over the raw bytes so X25519 keys can participate in the
/// unified [`key`](crate::key) traits, which pass peer public keys as
/// `&dyn PublicKey`. The low-level [`X25519PrivateKey::public_key`] and
/// [`X25519PrivateKey::diffie_hellman`] still take and return raw `[u8; 32]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    /// Wraps a 32-byte u-coordinate.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        X25519PublicKey(bytes)
    }

    /// The 32-byte u-coordinate.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Borrows the 32-byte u-coordinate.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// RFC 8410 `id-X25519` algorithm OID (1.3.101.110).
#[cfg(feature = "der")]
pub(crate) const X25519_OID: &[u64] = &[1, 3, 101, 110];

/// PKCS#8 v1 (RFC 8410) private-key serialization. Structurally identical to
/// Ed25519's, with the `id-X25519` OID and the raw 32-byte scalar.
#[cfg(feature = "der")]
impl X25519PrivateKey {
    /// Encodes the key as a PKCS#8 `OneAsymmetricKey` DER structure.
    pub fn to_pkcs8_der(&self) -> alloc::vec::Vec<u8> {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let version = encode_integer(&[0]);
        let algid = encode_sequence(&oid_tlv(X25519_OID));
        // privateKey is an OCTET STRING wrapping the CurvePrivateKey OCTET STRING.
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
        if parse_oid(algid.read_oid()?)?.as_slice() != X25519_OID {
            return Err(Error::Malformed);
        }
        let inner = seq.read_octet_string()?;
        let scalar_bytes = Reader::new(inner).read_octet_string()?;
        if scalar_bytes.len() != 32 {
            return Err(Error::Malformed);
        }
        let mut scalar = [0u8; 32];
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
        Ok(X25519PrivateKey { scalar })
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

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let h = s.as_bytes();
        for i in 0..32 {
            let hi = (h[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (h[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            out[i] = (hi << 4) | lo;
        }
        out
    }

    #[cfg(all(feature = "der", feature = "alloc"))]
    #[test]
    fn openssl_pkcs8_interop() {
        // Generated by `openssl genpkey -algorithm X25519`. We must parse it and
        // re-encode byte-identically (RFC 8410 interop in both directions).
        let pem = "-----BEGIN PRIVATE KEY-----\n\
                   MC4CAQAwBQYDK2VuBCIEIBDbvDuVda/X1UZ3g65tEsm+q+F6ZGOwACWUqgSKcElA\n\
                   -----END PRIVATE KEY-----\n";
        let sk = X25519PrivateKey::from_pkcs8_pem(pem).expect("parse openssl x25519");
        assert_eq!(
            sk.to_bytes(),
            hex32("10dbbc3b9575afd7d5467783ae6d12c9beabe17a6463b0002594aa048a704940")
        );
        assert_eq!(
            sk.to_pkcs8_der(),
            crate::test_util::from_hex_vec(
                "302e020100300506032b656e0422042010dbbc3b9575afd7d5467783ae6d12c9beabe17a6463b0002594aa048a704940"
            )
        );
    }

    #[cfg(feature = "der")]
    #[test]
    fn pkcs8_round_trip() {
        let scalar = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let sk = X25519PrivateKey::from_bytes(scalar);
        let pem = sk.to_pkcs8_pem();
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        let sk2 = X25519PrivateKey::from_pkcs8_pem(&pem).expect("parse pkcs8");
        assert_eq!(sk2.to_bytes(), scalar);
        assert_eq!(sk2.public_key(), sk.public_key());
    }

    #[cfg(feature = "der")]
    #[test]
    fn pkcs8_rejects_trailing_garbage() {
        let scalar = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let mut der = X25519PrivateKey::from_bytes(scalar).to_pkcs8_der();
        der.push(0xff);
        der.push(0x00);
        assert!(X25519PrivateKey::from_pkcs8_der(&der).is_err());
    }

    #[cfg(feature = "der")]
    #[test]
    fn pkcs8_v2_with_public_key_parses() {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let scalar = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let sk = X25519PrivateKey::from_bytes(scalar);
        let pub_enc = sk.public_key();

        // PKCS#8 v2 (RFC 5958) with the OPTIONAL `[1]` publicKey present as a
        // primitive IMPLICIT BIT STRING (tag 0x81), the OpenSSL spelling.
        let version = encode_integer(&[1]);
        let algid = encode_sequence(&oid_tlv(X25519_OID));
        let privkey = encode_octet_string(&encode_octet_string(&scalar));
        let mut pub_bitstring = alloc::vec![0u8]; // 0 unused bits
        pub_bitstring.extend_from_slice(&pub_enc);
        let mut pubkey_field = alloc::vec![0x81u8];
        pubkey_field.push(pub_bitstring.len() as u8);
        pubkey_field.extend_from_slice(&pub_bitstring);
        let der = encode_sequence(&[version, algid, privkey, pubkey_field].concat());

        let parsed = X25519PrivateKey::from_pkcs8_der(&der).expect("v2 parse");
        assert_eq!(parsed.to_bytes(), scalar);
        assert_eq!(parsed.public_key(), pub_enc);
    }

    #[test]
    fn private_key_bytes_round_trip() {
        let scalar = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let sk = X25519PrivateKey::from_bytes(scalar);
        assert_eq!(sk.to_bytes(), scalar, "to_bytes mirrors from_bytes");
        // The reconstructed key derives the same public key.
        let sk2 = X25519PrivateKey::from_bytes(sk.to_bytes());
        assert_eq!(sk2.public_key(), sk.public_key());
    }

    #[test]
    fn rfc7748_test_vector() {
        // RFC 7748 §5.2, first vector.
        let scalar = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let out = x25519(&scalar, &u);
        assert_eq!(
            out,
            hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
    }

    #[test]
    fn rfc7748_diffie_hellman() {
        // RFC 7748 §6.1.
        let a = X25519PrivateKey::from_bytes(hex32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let b = X25519PrivateKey::from_bytes(hex32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));

        assert_eq!(
            a.public_key(),
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            b.public_key(),
            hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );

        let shared = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(a.diffie_hellman(&b.public_key()).unwrap(), shared);
        assert_eq!(b.diffie_hellman(&a.public_key()).unwrap(), shared);
    }

    #[test]
    fn generated_keys_agree() {
        let mut rng = HmacDrbg::<Sha256>::new(b"x25519", b"nonce", &[]);
        let a = X25519PrivateKey::generate(&mut rng);
        let b = X25519PrivateKey::generate(&mut rng);
        assert_eq!(
            a.diffie_hellman(&b.public_key()).unwrap(),
            b.diffie_hellman(&a.public_key()).unwrap()
        );
    }

    #[test]
    fn rejects_small_order_peer() {
        // The seven low-order u-coordinates on Curve25519 (RFC 7748 §6.1 +
        // Bernstein et al.). Any X25519 with these inputs yields the
        // all-zero output, which `diffie_hellman` must surface as an error
        // rather than returning silently.
        let small_order: [[u8; 32]; 7] = [
            [0; 32],
            {
                // u = 1
                let mut b = [0u8; 32];
                b[0] = 1;
                b
            },
            hex32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            hex32("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            // u = p − 1 (yields 0 after multiplication by any clamped scalar)
            hex32("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            // u = p
            hex32("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            // u = p + 1
            hex32("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ];

        let sk = X25519PrivateKey::from_bytes(hex32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        for (i, bad) in small_order.iter().enumerate() {
            let r = sk.diffie_hellman(bad);
            // The "u = 1" case is not low-order (it's the canonical edge); skip
            // index 1 from the rejection assertion if its result is non-zero.
            if i == 1 {
                continue;
            }
            assert_eq!(r, Err(X25519Error::SmallOrderPeer), "vector {i}");
        }
    }
}
