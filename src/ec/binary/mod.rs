//! Binary-field (GF(2^m)) curves sect283k1/r1, sect409k1/r1 and sect571k1/r1
//! (SEC 2 §3; NIST K-283/B-283, K-409/B-409, K-571/B-571) for ECDH.
//!
//! The curves are `y² + xy = x³ + a·x² + b` over the polynomial-basis fields
//! GF(2^283), GF(2^409) and GF(2^571) with the SEC 2 reduction polynomials.
//! Only key agreement and point encoding are provided — no signatures — so
//! everything runs on the constant-time López–Dahab Montgomery ladder over the
//! full scalar width; see [`field`](self) for the field arithmetic
//! (mask-driven carry-less multiplication, Itoh–Tsujii inversion).
//!
//! Public keys ([`BinaryPublicKey`]) are validated on parse: the coordinates
//! must be field elements, the point must satisfy the curve equation, must not
//! be the identity and must lie in the prime-order subgroup (`n·Q = ∞`) — the
//! curves have cofactor 2 or 4, so an unchecked peer point of small order
//! would leak bits of the private scalar through the shared secret. SEC 1
//! compressed points (`02`/`03`, with the binary-field `ỹ = lsb(y/x)` rule)
//! and uncompressed points (`04`) are accepted; hybrid (`06`/`07`) encodings
//! are not.
//!
//! ```
//! use purecrypto::ec::binary::{BinaryCurveId, BinaryPrivateKey};
//! use purecrypto::rng::OsRng;
//!
//! let mut rng = OsRng;
//! let alice = BinaryPrivateKey::generate(BinaryCurveId::Sect283k1, &mut rng);
//! let bob = BinaryPrivateKey::generate(BinaryCurveId::Sect283k1, &mut rng);
//! let z1 = alice.diffie_hellman(&bob.public_key()).unwrap();
//! let z2 = bob.diffie_hellman(&alice.public_key()).unwrap();
//! assert_eq!(z1, z2);
//! ```

mod curve;
mod field;

use super::Error;
use crate::ct::{Choice, ConstantTimeEq};
use crate::rng::{CryptoRng, RngCore};
use crate::zeroize::{Zeroize, ZeroizeOnDrop};
use alloc::vec;
use alloc::vec::Vec;
use curve::{Curve, Point, limbs_is_zero, limbs_lt};
use field::{Limbs, MAX_LIMBS};

/// The `id-ecPublicKey` algorithm OID (RFC 5480 §2.1.1).
#[cfg(feature = "der")]
const EC_PUBLIC_KEY_OID: &[u64] = &[1, 2, 840, 10045, 2, 1];

/// The supported SEC 2 binary curves.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BinaryCurveId {
    /// sect283k1 (NIST K-283): Koblitz, `a = 0`, cofactor 4.
    Sect283k1,
    /// sect283r1 (NIST B-283): `a = 1`, cofactor 2.
    Sect283r1,
    /// sect409k1 (NIST K-409): Koblitz, `a = 0`, cofactor 4.
    Sect409k1,
    /// sect409r1 (NIST B-409): `a = 1`, cofactor 2.
    Sect409r1,
    /// sect571k1 (NIST K-571): Koblitz, `a = 0`, cofactor 4.
    Sect571k1,
    /// sect571r1 (NIST B-571): `a = 1`, cofactor 2.
    Sect571r1,
}

impl BinaryCurveId {
    /// Every supported curve.
    pub const ALL: [BinaryCurveId; 6] = [
        BinaryCurveId::Sect283k1,
        BinaryCurveId::Sect283r1,
        BinaryCurveId::Sect409k1,
        BinaryCurveId::Sect409r1,
        BinaryCurveId::Sect571k1,
        BinaryCurveId::Sect571r1,
    ];

    fn curve(self) -> &'static Curve {
        match self {
            BinaryCurveId::Sect283k1 => &curve::SECT283K1,
            BinaryCurveId::Sect283r1 => &curve::SECT283R1,
            BinaryCurveId::Sect409k1 => &curve::SECT409K1,
            BinaryCurveId::Sect409r1 => &curve::SECT409R1,
            BinaryCurveId::Sect571k1 => &curve::SECT571K1,
            BinaryCurveId::Sect571r1 => &curve::SECT571R1,
        }
    }

    /// The SEC 2 name (`"sect283k1"`, ...).
    pub fn name(self) -> &'static str {
        self.curve().name
    }

    /// Bytes of one field element / coordinate (36, 52 or 72).
    pub fn field_len(self) -> usize {
        self.curve().field.byte_len()
    }

    /// Bytes of a private scalar (`ceil(bit_len(n) / 8)`).
    pub fn scalar_len(self) -> usize {
        self.curve().scalar_len()
    }

    /// The cofactor `h` (2 for the `r1` curves, 4 for the Koblitz curves).
    pub fn cofactor(self) -> u64 {
        self.curve().h
    }

    /// The named-curve OID arcs (`1.3.132.0.{16,17,36,37,38,39}`).
    pub fn named_curve_oid(self) -> &'static [u64] {
        self.curve().oid
    }

    /// Looks a curve up by its named-curve OID.
    pub fn from_named_curve_oid(arcs: &[u64]) -> Option<BinaryCurveId> {
        BinaryCurveId::ALL
            .into_iter()
            .find(|c| c.named_curve_oid() == arcs)
    }
}

impl core::fmt::Display for BinaryCurveId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

/// A validated public point on one of the binary curves.
#[derive(Clone, Copy, Debug)]
pub struct BinaryPublicKey {
    curve: BinaryCurveId,
    point: Point,
}

impl PartialEq for BinaryPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.curve == other.curve
            && bool::from(self.point.x.ct_eq(&other.point.x) & self.point.y.ct_eq(&other.point.y))
    }
}

impl Eq for BinaryPublicKey {}

impl BinaryPublicKey {
    /// Parses a SEC 1 point (`04 || x || y` or `02/03 || x`) and validates it
    /// fully: coordinates in range, on the curve, not the identity, and in
    /// the prime-order subgroup (`n·Q = ∞`).
    ///
    /// Malformed encodings (wrong length or tag, coordinate ≥ 2^m) give
    /// [`Error::Malformed`]; a well-formed point that is off the curve, has
    /// no square root for the compressed form, or lies outside the subgroup
    /// gives [`Error::InvalidInput`].
    pub fn from_sec1(curve: BinaryCurveId, bytes: &[u8]) -> Result<Self, Error> {
        let c = curve.curve();
        let point = c.decode(bytes)?;
        if bool::from(c.in_subgroup(&point)) {
            Ok(BinaryPublicKey { curve, point })
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// The SEC 1 encoding: `04 || x || y`, or `02/03 || x` when `compressed`.
    pub fn to_sec1(&self, compressed: bool) -> Vec<u8> {
        let c = self.curve.curve();
        let mut out = vec![0u8; c.encoded_len(compressed)];
        c.encode(&self.point, compressed, &mut out);
        out
    }

    /// The curve this key lives on.
    pub fn curve(&self) -> BinaryCurveId {
        self.curve
    }

    /// Parses an X.509 `SubjectPublicKeyInfo` (RFC 5480) whose algorithm is
    /// `id-ecPublicKey` with one of the six named-curve OIDs. Explicit
    /// (`ECParameters`) or `implicitlyCA` parameters are rejected, as is any
    /// deviation from strict DER, and the point is validated as by
    /// [`from_sec1`](Self::from_sec1).
    #[cfg(feature = "der")]
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        use crate::der::{Reader, parse_oid};
        let mut outer = Reader::new(der);
        let mut spki = outer.read_sequence().map_err(|_| Error::Malformed)?;
        let mut algid = spki.read_sequence().map_err(|_| Error::Malformed)?;
        let alg = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        if alg.as_slice() != EC_PUBLIC_KEY_OID {
            return Err(Error::Malformed);
        }
        let arcs = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
            .map_err(|_| Error::Malformed)?;
        algid.finish().map_err(|_| Error::Malformed)?;
        let curve = BinaryCurveId::from_named_curve_oid(&arcs).ok_or(Error::Malformed)?;
        let bits = spki.read_bit_string().map_err(|_| Error::Malformed)?;
        spki.finish().map_err(|_| Error::Malformed)?;
        outer.finish().map_err(|_| Error::Malformed)?;
        Self::from_sec1(curve, bits)
    }

    /// Encodes the key as an X.509 `SubjectPublicKeyInfo` with the
    /// named-curve OID and the uncompressed point.
    #[cfg(feature = "der")]
    pub fn to_spki_der(&self) -> Vec<u8> {
        use crate::der::{encode_bit_string, encode_sequence, oid_tlv};
        let algid = encode_sequence(
            &[
                oid_tlv(EC_PUBLIC_KEY_OID),
                oid_tlv(self.curve.named_curve_oid()),
            ]
            .concat(),
        );
        encode_sequence(&[algid, encode_bit_string(&self.to_sec1(false))].concat())
    }
}

/// An ECDH private scalar `d ∈ [1, n − 1]` on one of the binary curves.
///
/// The scalar is wiped on drop.
#[derive(Clone)]
pub struct BinaryPrivateKey {
    curve: BinaryCurveId,
    d: Limbs,
}

impl core::fmt::Debug for BinaryPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BinaryPrivateKey")
            .field("curve", &self.curve)
            .finish_non_exhaustive()
    }
}

impl Drop for BinaryPrivateKey {
    fn drop(&mut self) {
        self.d.zeroize();
    }
}

impl ZeroizeOnDrop for BinaryPrivateKey {}

/// Parses a big-endian scalar of any width into limbs; `None` when a byte
/// beyond the limb capacity is nonzero.
fn limbs_from_be(bytes: &[u8]) -> Option<Limbs> {
    let mut out = [0u64; MAX_LIMBS];
    let mut overflow = 0u8;
    for (i, &b) in bytes.iter().rev().enumerate() {
        if i < 8 * MAX_LIMBS {
            out[i / 8] |= (b as u64) << (8 * (i % 8));
        } else {
            overflow |= b;
        }
    }
    (overflow == 0).then_some(out)
}

impl BinaryPrivateKey {
    /// Generates a uniformly random scalar in `[1, n − 1]` by rejection
    /// sampling `bit_len(n)`-bit candidates.
    pub fn generate<R: RngCore + CryptoRng>(curve: BinaryCurveId, rng: &mut R) -> Self {
        let c = curve.curve();
        let len = c.scalar_len();
        let keep = ((c.n_bits - 1) % 8) + 1;
        let high_mask = if keep == 8 { 0xff } else { (1u8 << keep) - 1 };
        let mut buf = vec![0u8; len];
        loop {
            rng.fill_bytes(&mut buf);
            buf[0] &= high_mask;
            let d = limbs_from_be(&buf).expect("scalar_len bytes fit the limbs");
            // 1 ≤ d < n, evaluated without short-circuiting on the candidate.
            if bool::from(!limbs_is_zero(&d) & limbs_lt(&d, &c.n)) {
                buf.zeroize();
                return BinaryPrivateKey { curve, d };
            }
        }
    }

    /// Creates a key from a big-endian scalar of any width (leading zero
    /// bytes are allowed); the value must satisfy `1 ≤ d ≤ n − 1`, which is
    /// checked in constant time.
    pub fn from_bytes(curve: BinaryCurveId, bytes: &[u8]) -> Result<Self, Error> {
        let c = curve.curve();
        let d = limbs_from_be(bytes).ok_or(Error::InvalidInput)?;
        let ok = !limbs_is_zero(&d) & limbs_lt(&d, &c.n);
        if bool::from(ok) {
            Ok(BinaryPrivateKey { curve, d })
        } else {
            Err(Error::InvalidInput)
        }
    }

    /// The scalar as a fixed-width big-endian byte string
    /// ([`BinaryCurveId::scalar_len`] bytes).
    pub fn to_bytes(&self) -> Vec<u8> {
        let len = self.curve.scalar_len();
        let mut out = vec![0u8; len];
        for (i, b) in out.iter_mut().rev().enumerate() {
            *b = (self.d[i / 8] >> (8 * (i % 8))) as u8;
        }
        out
    }

    /// The curve this key lives on.
    pub fn curve(&self) -> BinaryCurveId {
        self.curve
    }

    /// The public key `d · G`.
    pub fn public_key(&self) -> BinaryPublicKey {
        let c = self.curve.curve();
        let point = c.mul(&self.d, &c.generator());
        debug_assert!(!bool::from(point.inf));
        BinaryPublicKey {
            curve: self.curve,
            point,
        }
    }

    /// ECDH: the x-coordinate of `d · Q` as a fixed-width big-endian field
    /// element ([`BinaryCurveId::field_len`] bytes). Fails when `peer` is on
    /// another curve. (`peer` was validated on parse, so `d · Q` is never the
    /// identity; the flag is still checked.)
    pub fn diffie_hellman(&self, peer: &BinaryPublicKey) -> Result<Vec<u8>, Error> {
        if peer.curve != self.curve {
            return Err(Error::InvalidInput);
        }
        let c = self.curve.curve();
        let mut shared = c.mul(&self.d, &peer.point);
        let mut out = vec![0u8; c.field.byte_len()];
        c.field.encode_be(&shared.x, &mut out);
        let inf: Choice = shared.inf;
        shared.x.zeroize();
        shared.y.zeroize();
        if bool::from(inf) {
            out.zeroize();
            return Err(Error::InvalidInput);
        }
        Ok(out)
    }
}

// `Fe` is only reachable through the key types, which own the wiping.
impl Zeroize for Point {
    fn zeroize(&mut self) {
        self.x.zeroize();
        self.y.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::HmacDrbg;

    fn drbg(seed: u8) -> HmacDrbg<crate::hash::Sha256> {
        HmacDrbg::new(&[seed; 32], &[], &[])
    }

    #[test]
    fn ecdh_is_symmetric_and_round_trips() {
        let mut rng = drbg(1);
        for curve in BinaryCurveId::ALL {
            let a = BinaryPrivateKey::generate(curve, &mut rng);
            let b = BinaryPrivateKey::generate(curve, &mut rng);
            let pa = a.public_key();
            let pb = b.public_key();
            let z1 = a.diffie_hellman(&pb).unwrap();
            let z2 = b.diffie_hellman(&pa).unwrap();
            assert_eq!(z1, z2, "{curve}");
            assert_eq!(z1.len(), curve.field_len());
            // Scalar and point encodings round-trip.
            let a2 = BinaryPrivateKey::from_bytes(curve, &a.to_bytes()).unwrap();
            assert_eq!(a2.to_bytes(), a.to_bytes());
            assert_eq!(a.to_bytes().len(), curve.scalar_len());
            for compressed in [false, true] {
                let enc = pa.to_sec1(compressed);
                let back = BinaryPublicKey::from_sec1(curve, &enc).unwrap();
                assert_eq!(back, pa, "{curve} compressed={compressed}");
            }
            // A zero-padded scalar is the same key.
            let mut padded = vec![0u8; 3];
            padded.extend_from_slice(&a.to_bytes());
            assert_eq!(
                BinaryPrivateKey::from_bytes(curve, &padded)
                    .unwrap()
                    .to_bytes(),
                a.to_bytes()
            );
        }
    }

    #[test]
    fn scalar_range_is_enforced() {
        for curve in BinaryCurveId::ALL {
            let c = curve.curve();
            let len = curve.scalar_len();
            let n = {
                let mut v = vec![0u8; len];
                for (i, b) in v.iter_mut().rev().enumerate() {
                    *b = (c.n[i / 8] >> (8 * (i % 8))) as u8;
                }
                v
            };
            assert!(
                BinaryPrivateKey::from_bytes(curve, &n).is_err(),
                "{curve} n"
            );
            assert!(BinaryPrivateKey::from_bytes(curve, &[0]).is_err());
            assert!(BinaryPrivateKey::from_bytes(curve, &[]).is_err());
            let mut n1 = n.clone();
            n1[len - 1] -= 1;
            let k = BinaryPrivateKey::from_bytes(curve, &n1).unwrap();
            // (n − 1)·G = −G: same x as G.
            let g = BinaryPublicKey {
                curve,
                point: c.generator(),
            };
            assert_eq!(k.public_key().to_sec1(true)[1..], g.to_sec1(true)[1..]);
            assert_ne!(k.public_key(), g);
            assert!(BinaryPrivateKey::from_bytes(curve, &[1]).is_ok());
            // Far too wide with a nonzero high byte.
            let mut wide = vec![0u8; 8 * MAX_LIMBS + 1];
            wide[0] = 1;
            assert!(BinaryPrivateKey::from_bytes(curve, &wide).is_err());
        }
    }

    #[test]
    fn small_order_points_are_rejected() {
        // (0, √b) has order 2 on every curve; (1, y) has order 4 on the
        // Koblitz curves (Wycheproof's LowOrderPublic points).
        for curve in BinaryCurveId::ALL {
            let len = curve.field_len();
            let mut enc = vec![0u8; 1 + len];
            enc[0] = 0x02;
            assert_eq!(
                BinaryPublicKey::from_sec1(curve, &enc),
                Err(Error::InvalidInput),
                "{curve} order-2 point"
            );
        }
        let mut enc = vec![0u8; 73];
        enc[0] = 0x04;
        enc[36] = 1;
        enc[72] = 1;
        assert_eq!(
            BinaryPublicKey::from_sec1(BinaryCurveId::Sect283k1, &enc),
            Err(Error::InvalidInput)
        );
        // Identity and off-curve inputs.
        assert!(BinaryPublicKey::from_sec1(BinaryCurveId::Sect283k1, &[0]).is_err());
        enc[72] = 0;
        assert!(BinaryPublicKey::from_sec1(BinaryCurveId::Sect283k1, &enc).is_err());
    }

    #[test]
    fn wrong_curve_peer_is_refused() {
        let mut rng = drbg(2);
        let a = BinaryPrivateKey::generate(BinaryCurveId::Sect283k1, &mut rng);
        let b = BinaryPrivateKey::generate(BinaryCurveId::Sect283r1, &mut rng);
        assert_eq!(a.diffie_hellman(&b.public_key()), Err(Error::InvalidInput));
    }

    /// NIST CAVP ECC-CDH (KAS) known-answer vectors are not reproduced here;
    /// the Wycheproof `valid` cases pin every curve in
    /// `tests/wycheproof/ec_binary.rs`. This test pins one of them per
    /// curve so `cargo test --lib` covers interoperability too.
    #[test]
    fn wycheproof_pins() {
        // (curve, peer SEC1 point, private scalar, shared x) — tcId 1 of each
        // Wycheproof `ecdh_sect*` file.
        let vectors: [(BinaryCurveId, &str, &str, &str); 6] = [
            (
                BinaryCurveId::Sect283k1,
                "0401eef8bea17e53e591beac95c110187f6d7c27a40d202ac73064b4ca054aa1f51608ddd5042e4525c94f62a1ddae8097c365fc8c9fbeca85feea1c2713f015bd5f584a89b9e13720",
                "013826bf5645617bfbbb162685d0f52f70fcd35e660cb19e70de811999ef28c97a9d4934",
                "05ca68e2b421013f6083d598df151560a45d4ec2ea3fc69ed5383653ea2397a5a627f586",
            ),
            (
                BinaryCurveId::Sect283r1,
                "0406403ff126ec78f67f1a7d0664d49eb386251ec85a22052f29869ffc1eae2c2649bd74f3050e9646db0c9e110e9ec20eeabf20da39e021130604d9ffb4af33cd016c947536cd5b77",
                "02a182530c9d115ba920071df1f9b1077b93df61a39a35188bf58a1c76524639439ac0a8",
                "0195275b6182cb8758bd961d0fc43917b468a8ccbcb2346aac9bcd508f09c969d265b479",
            ),
            (
                BinaryCurveId::Sect409k1,
                "0401de3d9671d7d69f5a749191b02d6bb8bbb9e01d316fb379762ab6ec2c25c0e45c7c94827866cbbac2f4a73ab40553c2ba271b86012e2367b2d80738f18b0b2007e05e98dbd99484fa6beffa04de32a1739b77f3b225fcdcced6d4cc92b45a737588812385f58534",
                "6fc8421b4c7afb918c511673b9b7bea76ecf705ec8d769c92b50c7e80726d5a8f4fe08b8d565f44c0e2b7c155fc9a032a65d86",
                "0162f8dc2419f58ea74efe221e09c9da7534942d86822f2ffa44b9497c08c6d160f11df5746c7ae3471d343703201ccfb1cd9b94",
            ),
            (
                BinaryCurveId::Sect409r1,
                "040044f218735363eaa3aa9db4713b0c20787f6c7b63c5b99640a9c4ee3d46e3211312076b55f126b473aca8318350fabe5338b4cb00e73519e81b20e325ec8ba9cb4035685a3f926cbb02fe0912435c6088f8494447c91a9a959045f9aebc42575d530d6d8b05a473",
                "00df38cadf002bceb4f1883ad281c8bf592a804c4eaded43fb34cd665238012e9a5d5b6e5b71efffc10d92d83a5e7a409465deeb",
                "00dadd7f79efbd812cbd704838f8727573ab9ae915ce1a42f35cfe16df58155710aa468db3aab1cf302c82c6e4fc97fb91a68eeb",
            ),
            (
                BinaryCurveId::Sect571k1,
                "040035203a752378ce50c7694ff64171263ce3392ac263afceb2606a7ac5705ada6ca271bc321d263490d32372f7fb5395d30fc008dc926cd4e33cb1e2fd51fb37f9ba46642af26fa2007ebda653ab1c2ecc112c755c1a10c14751e350c8146b29441386adc47387f46cd0fd63127655eacce57da9b61bf9e5b7b766bb829ada5deb6d44eb8daad389a5507660334d61b0",
                "01a5e90d0e7f369b55ff408abe33d92f8d2a9f7973b02c2e4e1f2b87ef19e240fe996dbde5c08798319e27978f47c4337ab53d9a56b8d47e78ffcf6de9212e3818eacfdb991fad51",
                "06cccb9515a7c6fc4efd697dc1cb6231b841b19bf1046315aa03e31871ff69684380e37e7e47d44ea96289a1089c3669b391610e57a45f890c489d59a47f504916b26b26571ff9c9",
            ),
            (
                BinaryCurveId::Sect571r1,
                "04073d6dac804ab46f8971d5321a26213873cdf4e3571dc64f09c865e9331b85e61ba13a20869d470a975964edb3eb7200b8bb2f27b47c6d2b17b80402fbab1e7ab3be37ccae791f38053e6412cf6af8e1f6687c2f88caf1737a4712de6d47e45c5211f090bb6798a0bd360345003f02a5a31b4636cf34aa6c482d490cce14a9eb7c1b40d731a64e5dc593d5c67fbc6d10",
                "01863004be829983d4e674c1ed4ef912d84a6e3a6cdcc993babe9736be94709985bddb413ad3d2565c2f7fa0d9e0215c5f0149c2d548a00b15f22b30f234ae5f5172c98cef2a3d34",
                "00b442f82bf18ae5de4670087a23d4854855fefc7ace6ccb26e3c2cf6048a1824d31f9c56acc908fda6458fd3df2dd54f3cf6f31742b11c076e4fc90ccdc222cffac7f3c321e3bf5",
            ),
        ];
        for (curve, peer, d, shared) in vectors {
            let peer = BinaryPublicKey::from_sec1(curve, &hex(peer)).unwrap();
            let sk = BinaryPrivateKey::from_bytes(curve, &hex(d)).unwrap();
            assert_eq!(sk.diffie_hellman(&peer).unwrap(), hex(shared), "{curve}");
        }
    }

    #[cfg(feature = "der")]
    #[test]
    fn spki_round_trip_and_rejections() {
        let mut rng = drbg(3);
        for curve in BinaryCurveId::ALL {
            let pk = BinaryPrivateKey::generate(curve, &mut rng).public_key();
            let der = pk.to_spki_der();
            let back = BinaryPublicKey::from_spki_der(&der).unwrap();
            assert_eq!(back, pk, "{curve}");
            assert_eq!(back.curve(), curve);
            // Trailing byte, truncation, and a prime-curve OID all fail.
            let mut trailing = der.clone();
            trailing.push(0);
            assert!(BinaryPublicKey::from_spki_der(&trailing).is_err());
            assert!(BinaryPublicKey::from_spki_der(&der[..der.len() - 1]).is_err());
        }
        // A P-256 SPKI is not a binary-curve key.
        use crate::der::{encode_bit_string, encode_sequence, oid_tlv};
        let algid = encode_sequence(
            &[
                oid_tlv(EC_PUBLIC_KEY_OID),
                oid_tlv(&[1, 2, 840, 10045, 3, 1, 7]),
            ]
            .concat(),
        );
        let spki = encode_sequence(&[algid, encode_bit_string(&[0x04; 65])].concat());
        assert_eq!(BinaryPublicKey::from_spki_der(&spki), Err(Error::Malformed));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
