//! The set of supported elliptic curves and their parameters.

use super::weierstrass::Curve;
use crate::bignum::BoxedUint;

/// A supported prime-order curve.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum CurveId {
    /// NIST P-256 / secp256r1 / prime256v1 (`a = -3`, SHA-256).
    P256,
    /// NIST P-384 / secp384r1 (`a = -3`, SHA-384).
    P384,
    /// NIST P-521 / secp521r1 (`a = -3`, SHA-512).
    P521,
    /// secp256k1 (`a = 0`, SHA-256) — the Bitcoin/Ethereum curve.
    Secp256k1,
    /// sm2p256v1 (`a = -3`, SM3) — the Chinese SM2 curve (GB/T 32918,
    /// RFC 8998). Same field/scalar size as P-256 but distinct parameters.
    Sm2p256v1,
    /// brainpoolP256r1 (RFC 5639, `a` arbitrary). 256-bit ECC Brainpool
    /// "regular" curve; paired with SHA-256.
    BrainpoolP256r1,
    /// brainpoolP384r1 (RFC 5639). 384-bit ECC Brainpool curve; SHA-384.
    BrainpoolP384r1,
    /// brainpoolP512r1 (RFC 5639). 512-bit ECC Brainpool curve; SHA-512.
    BrainpoolP512r1,
    /// secp160k1 (SEC 2 v1 §2.4.1, `a = 0`). Koblitz curve over a 160-bit
    /// field whose group order is **161 bits** — the scalar width exceeds the
    /// coordinate width by a byte.
    Secp160k1,
    /// secp160r1 (SEC 2 v1 §2.4.2, `a = -3`). 160-bit field, 161-bit order.
    Secp160r1,
    /// secp160r2 (SEC 2 v1 §2.4.3, `a = -3`). 160-bit field, 161-bit order.
    Secp160r2,
    /// secp192k1 (SEC 2 v2 §2.2.1, `a = 0`). 192-bit Koblitz curve.
    Secp192k1,
    /// NIST P-192 / secp192r1 / prime192v1 (`a = -3`; FIPS 186-4 D.1.2.1).
    P192,
    /// secp224k1 (SEC 2 v2 §2.3.1, `a = 0`). 224-bit Koblitz curve with a
    /// **225-bit** group order; `p ≡ 5 (mod 8)`, so point decompression goes
    /// through the general Tonelli–Shanks square root.
    Secp224k1,
    /// NIST P-224 / secp224r1 (`a = -3`; FIPS 186-4 D.1.2.2). `p ≡ 1 (mod 4)`,
    /// so point decompression goes through Tonelli–Shanks.
    P224,
    /// brainpoolP224r1 (RFC 5639 §3.3). 224-bit ECC Brainpool curve.
    BrainpoolP224r1,
    /// brainpoolP320r1 (RFC 5639 §3.5). 320-bit ECC Brainpool curve.
    BrainpoolP320r1,
}

/// Big-endian hex parameters for a curve.
struct Params {
    p: &'static str,
    a: &'static str,
    b: &'static str,
    gx: &'static str,
    gy: &'static str,
    n: &'static str,
    field_len: usize,
    order_len: usize,
}

impl CurveId {
    fn params(self) -> Params {
        match self {
            CurveId::P256 => Params {
                p: "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                a: "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                b: "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                gx: "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                gy: "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                n: "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                field_len: 32,
                order_len: 32,
            },
            CurveId::P384 => Params {
                p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
                    ffffffff0000000000000000ffffffff",
                a: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe\
                    ffffffff0000000000000000fffffffc",
                b: "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a\
                    c656398d8a2ed19d2a85c8edd3ec2aef",
                gx: "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38\
                     5502f25dbf55296c3a545e3872760ab7",
                gy: "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0\
                     0a60b1ce1d7e819d7a431d7c90ea0e5f",
                n: "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf\
                    581a0db248b0a77aecec196accc52973",
                field_len: 48,
                order_len: 48,
            },
            CurveId::P521 => Params {
                p: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                    ffff",
                a: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                    ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                    fffc",
                b: "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1\
                    09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b50\
                    3f00",
                gx: "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d\
                     3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5\
                     bd66",
                gy: "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e\
                     662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd1\
                     6650",
                n: "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
                    fffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e9138\
                    6409",
                field_len: 66,
                order_len: 66,
            },
            CurveId::Secp256k1 => Params {
                p: "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",
                a: "00",
                b: "07",
                gx: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                gy: "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
                n: "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
                field_len: 32,
                order_len: 32,
            },
            CurveId::Sm2p256v1 => Params {
                p: "fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffff",
                a: "fffffffeffffffffffffffffffffffffffffffff00000000fffffffffffffffc",
                b: "28e9fa9e9d9f5e344d5a9e4bcf6509a7f39789f515ab8f92ddbcbd414d940e93",
                gx: "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
                gy: "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
                n: "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123",
                field_len: 32,
                order_len: 32,
            },
            // RFC 5639 §3.4 — brainpoolP256r1 (the "r1" regular curve, not the
            // "t1" twisted curve). `a` is neither -3 nor 0; the complete
            // Renes–Costello–Batina point addition handles arbitrary `a`.
            CurveId::BrainpoolP256r1 => Params {
                p: "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
                a: "7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9",
                b: "26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6",
                gx: "8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262",
                gy: "547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997",
                n: "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
                field_len: 32,
                order_len: 32,
            },
            // RFC 5639 §3.6 — brainpoolP384r1.
            CurveId::BrainpoolP384r1 => Params {
                p: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123\
                    acd3a729901d1a71874700133107ec53",
                a: "7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f\
                    8aa5814a503ad4eb04a8c7dd22ce2826",
                b: "04a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d5\
                    7cb4390295dbc9943ab78696fa504c11",
                gx: "1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8\
                     e826e03436d646aaef87b2e247d4af1e",
                gy: "8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff9912928\
                     0e4646217791811142820341263c5315",
                n: "8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7\
                    cf3ab6af6b7fc3103b883202e9046565",
                field_len: 48,
                order_len: 48,
            },
            // RFC 5639 §3.7 — brainpoolP512r1.
            CurveId::BrainpoolP512r1 => Params {
                p: "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330871\
                    7d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3",
                a: "7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc\
                    2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca",
                b: "3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a7\
                    2bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723",
                gx: "81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098e\
                     ff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822",
                gy: "7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111\
                     b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892",
                n: "aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870\
                    553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069",
                field_len: 64,
                order_len: 64,
            },
            // SEC 2 v1 §2.4.1 — secp160k1. The group order is 161 bits, one
            // bit wider than the field: `order_len` is 21 while `field_len`
            // is 20, so scalars, `r`/`s` and RFC 6979 octet strings are one
            // byte longer than coordinates.
            CurveId::Secp160k1 => Params {
                p: "fffffffffffffffffffffffffffffffeffffac73",
                a: "00",
                b: "07",
                gx: "3b4c382ce37aa192a4019e763036f4f5dd4d7ebb",
                gy: "938cf935318fdced6bc28286531733c3f03c4fee",
                n: "0100000000000000000001b8fa16dfab9aca16b6b3",
                field_len: 20,
                order_len: 21,
            },
            // SEC 2 v1 §2.4.2 — secp160r1 (161-bit order).
            CurveId::Secp160r1 => Params {
                p: "ffffffffffffffffffffffffffffffff7fffffff",
                a: "ffffffffffffffffffffffffffffffff7ffffffc",
                b: "1c97befc54bd7a8b65acf89f81d4d4adc565fa45",
                gx: "4a96b5688ef573284664698968c38bb913cbfc82",
                gy: "23a628553168947d59dcc912042351377ac5fb32",
                n: "0100000000000000000001f4c8f927aed3ca752257",
                field_len: 20,
                order_len: 21,
            },
            // SEC 2 v1 §2.4.3 — secp160r2 (same field as secp160k1, 161-bit
            // order).
            CurveId::Secp160r2 => Params {
                p: "fffffffffffffffffffffffffffffffeffffac73",
                a: "fffffffffffffffffffffffffffffffeffffac70",
                b: "b4e134d3fb59eb8bab57274904664d5af50388ba",
                gx: "52dcb034293a117e1f4ff11b30f7199d3144ce6d",
                gy: "feaffef2e331f296e071fa0df9982cfea7d43f2e",
                n: "0100000000000000000000351ee786a818f3a1a16b",
                field_len: 20,
                order_len: 21,
            },
            // SEC 2 v2 §2.2.1 — secp192k1.
            CurveId::Secp192k1 => Params {
                p: "fffffffffffffffffffffffffffffffffffffffeffffee37",
                a: "00",
                b: "03",
                gx: "db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d",
                gy: "9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d",
                n: "fffffffffffffffffffffffe26f2fc170f69466a74defd8d",
                field_len: 24,
                order_len: 24,
            },
            // FIPS 186-4 D.1.2.1 / SEC 2 v2 §2.2.2 — P-192 (secp192r1).
            CurveId::P192 => Params {
                p: "fffffffffffffffffffffffffffffffeffffffffffffffff",
                a: "fffffffffffffffffffffffffffffffefffffffffffffffc",
                b: "64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1",
                gx: "188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012",
                gy: "07192b95ffc8da78631011ed6b24cdd573f977a11e794811",
                n: "ffffffffffffffffffffffff99def836146bc9b1b4d22831",
                field_len: 24,
                order_len: 24,
            },
            // SEC 2 v2 §2.3.1 — secp224k1 (225-bit order).
            CurveId::Secp224k1 => Params {
                p: "fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d",
                a: "00",
                b: "05",
                gx: "a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c",
                gy: "7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5",
                n: "010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7",
                field_len: 28,
                order_len: 29,
            },
            // FIPS 186-4 D.1.2.2 / SEC 2 v2 §2.3.2 — P-224 (secp224r1).
            CurveId::P224 => Params {
                p: "ffffffffffffffffffffffffffffffff000000000000000000000001",
                a: "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
                b: "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
                gx: "b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21",
                gy: "bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
                n: "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
                field_len: 28,
                order_len: 28,
            },
            // RFC 5639 §3.3 — brainpoolP224r1.
            CurveId::BrainpoolP224r1 => Params {
                p: "d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
                a: "68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43",
                b: "2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b",
                gx: "0d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d",
                gy: "58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd",
                n: "d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
                field_len: 28,
                order_len: 28,
            },
            // RFC 5639 §3.5 — brainpoolP320r1.
            CurveId::BrainpoolP320r1 => Params {
                p: "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28\
                    fcd412b1f1b32e27",
                a: "3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f4\
                    92f375a97d860eb4",
                b: "520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd88453981\
                    6f5eb4ac8fb1f1a6",
                gx: "43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c7\
                     10af8d0d39e20611",
                gy: "14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7\
                     d35245d1692e8ee1",
                n: "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e9\
                    8691555b44c59311",
                field_len: 40,
                order_len: 40,
            },
        }
    }

    /// Builds the runtime [`Curve`] for this identifier.
    pub(crate) fn curve(self) -> Curve {
        let p = self.params();
        Curve::new(hex(p.p), hex(p.a), hex(p.b), hex(p.gx), hex(p.gy), hex(p.n))
    }

    /// The field-element byte length: the width of one SEC1 coordinate and
    /// of the ECDH shared secret.
    pub fn field_len(self) -> usize {
        self.params().field_len
    }

    /// The scalar (group-order) byte length: the width of a private key, of
    /// each half of a fixed-width `r ‖ s` signature, and of an RFC 6979
    /// octet string. Equal to [`field_len`](Self::field_len) on most curves,
    /// but one byte larger on secp160k1/r1/r2 and secp224k1, whose order is
    /// a bit longer than the field.
    pub fn order_len(self) -> usize {
        self.params().order_len
    }

    /// Every supported curve, in declaration order.
    pub const ALL: [CurveId; 17] = [
        CurveId::P256,
        CurveId::P384,
        CurveId::P521,
        CurveId::Secp256k1,
        CurveId::Sm2p256v1,
        CurveId::BrainpoolP256r1,
        CurveId::BrainpoolP384r1,
        CurveId::BrainpoolP512r1,
        CurveId::Secp160k1,
        CurveId::Secp160r1,
        CurveId::Secp160r2,
        CurveId::Secp192k1,
        CurveId::P192,
        CurveId::Secp224k1,
        CurveId::P224,
        CurveId::BrainpoolP224r1,
        CurveId::BrainpoolP320r1,
    ];

    /// The X.509 / SEC1 named-curve OID arcs.
    #[cfg(feature = "der")]
    pub(crate) fn named_curve_oid(self) -> &'static [u64] {
        match self {
            CurveId::P256 => &[1, 2, 840, 10045, 3, 1, 7],
            CurveId::P384 => &[1, 3, 132, 0, 34],
            CurveId::P521 => &[1, 3, 132, 0, 35],
            CurveId::Secp256k1 => &[1, 3, 132, 0, 10],
            // id-sm2 / sm2p256v1 (GB/T 32918, RFC 8998).
            CurveId::Sm2p256v1 => &[1, 2, 156, 10197, 1, 301],
            // ecStdCurvesAndGeneration.ellipticCurve.versionOne.* (RFC 5639 §A.1).
            CurveId::BrainpoolP256r1 => &[1, 3, 36, 3, 3, 2, 8, 1, 1, 7],
            CurveId::BrainpoolP384r1 => &[1, 3, 36, 3, 3, 2, 8, 1, 1, 11],
            CurveId::BrainpoolP512r1 => &[1, 3, 36, 3, 3, 2, 8, 1, 1, 13],
            CurveId::BrainpoolP224r1 => &[1, 3, 36, 3, 3, 2, 8, 1, 1, 5],
            CurveId::BrainpoolP320r1 => &[1, 3, 36, 3, 3, 2, 8, 1, 1, 9],
            // certicom-arc / SEC 2 named curves.
            CurveId::Secp160k1 => &[1, 3, 132, 0, 9],
            CurveId::Secp160r1 => &[1, 3, 132, 0, 8],
            CurveId::Secp160r2 => &[1, 3, 132, 0, 30],
            CurveId::Secp192k1 => &[1, 3, 132, 0, 31],
            // prime192v1 (ANSI X9.62), the same curve as secp192r1.
            CurveId::P192 => &[1, 2, 840, 10045, 3, 1, 1],
            CurveId::Secp224k1 => &[1, 3, 132, 0, 32],
            CurveId::P224 => &[1, 3, 132, 0, 33],
        }
    }

    /// Maps a named-curve OID to a [`CurveId`], if supported.
    #[cfg(feature = "der")]
    pub(crate) fn from_named_curve_oid(arcs: &[u64]) -> Option<CurveId> {
        Self::ALL
            .into_iter()
            .find(|id| id.named_curve_oid() == arcs)
    }
}

/// Decodes a big-endian hex string (ASCII whitespace ignored) into a
/// [`BoxedUint`].
fn hex(s: &str) -> BoxedUint {
    let mut bytes = alloc::vec::Vec::with_capacity(s.len() / 2);
    let digits: alloc::vec::Vec<u8> = s
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|c| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        })
        .collect();
    let mut i = 0;
    while i + 1 < digits.len() {
        bytes.push((digits[i] << 4) | digits[i + 1]);
        i += 2;
    }
    BoxedUint::from_be_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(id: CurveId) {
        let curve = id.curve();
        // Generator is on the curve.
        let (gx, gy) = curve.to_affine(&curve.generator()).unwrap();
        assert!(curve.is_on_curve(&gx, &gy), "{id:?} generator off-curve");
        // n * G = identity.
        let n = curve.order().clone();
        assert!(
            curve.to_affine(&curve.mul_generator(&n)).is_none(),
            "{id:?} n*G != identity"
        );
        // (n - 1) * G = -G = (gx, p - gy).
        let flen = id.field_len();
        let (mx, my) = curve
            .to_affine(&curve.mul_generator(&n.sub(&BoxedUint::from_u64(1))))
            .unwrap();
        let p = curve.field_modulus();
        assert_eq!(
            mx.to_be_bytes(flen),
            gx.to_be_bytes(flen),
            "{id:?} (n-1)*G.x"
        );
        assert_eq!(
            my.to_be_bytes(flen),
            p.sub(&gy).to_be_bytes(flen),
            "{id:?} (n-1)*G != -G"
        );
        // The declared byte widths match the parameters.
        assert_eq!(flen, p.bit_len().div_ceil(8), "{id:?} field_len");
        assert_eq!(id.order_len(), n.bit_len().div_ceil(8), "{id:?} order_len");
        // 2G via doubling matches G+G, and is on the curve.
        let g = curve.generator();
        let two_g = curve.point_add(&g, &g);
        let (x2, y2) = curve.to_affine(&two_g).unwrap();
        assert!(curve.is_on_curve(&x2, &y2));
    }

    #[test]
    fn all_curves_consistent() {
        for id in CurveId::ALL {
            check(id);
        }
    }

    // The SEC 2 / FIPS 186-4 / RFC 5639 additions, pinned by name so a
    // regression says which curve. The four curves whose order is a bit
    // wider than the field must declare it through `order_len`.
    #[test]
    fn small_curves_consistent() {
        for id in [
            CurveId::Secp160k1,
            CurveId::Secp160r1,
            CurveId::Secp160r2,
            CurveId::Secp192k1,
            CurveId::P192,
            CurveId::Secp224k1,
            CurveId::P224,
            CurveId::BrainpoolP224r1,
            CurveId::BrainpoolP320r1,
        ] {
            check(id);
        }
        for id in [
            CurveId::Secp160k1,
            CurveId::Secp160r1,
            CurveId::Secp160r2,
            CurveId::Secp224k1,
        ] {
            assert_eq!(id.order_len(), id.field_len() + 1, "{id:?}");
            assert_eq!(
                id.curve().order().bit_len(),
                8 * id.field_len() + 1,
                "{id:?}"
            );
        }
    }

    #[cfg(feature = "der")]
    #[test]
    fn named_curve_oids_round_trip_and_are_distinct() {
        for id in CurveId::ALL {
            assert_eq!(
                CurveId::from_named_curve_oid(id.named_curve_oid()),
                Some(id)
            );
            for other in CurveId::ALL {
                assert!(other == id || other.named_curve_oid() != id.named_curve_oid());
            }
        }
        assert_eq!(
            CurveId::from_named_curve_oid(&[1, 2, 840, 10045, 3, 1, 1]),
            Some(CurveId::P192)
        );
        assert_eq!(
            CurveId::from_named_curve_oid(&[1, 3, 132, 0, 33]),
            Some(CurveId::P224)
        );
        assert_eq!(CurveId::from_named_curve_oid(&[1, 3, 132, 0, 1]), None);
    }

    // RFC 5639 Brainpool curves: generator on-curve and n·G == identity. The
    // `check` helper above also runs these for the standard curves; this test
    // pins the Brainpool additions explicitly so a regression names the curve.
    #[test]
    fn brainpool_curves_consistent() {
        check(CurveId::BrainpoolP256r1);
        check(CurveId::BrainpoolP384r1);
        check(CurveId::BrainpoolP512r1);
    }

    #[test]
    fn p256_known_multiples() {
        // Cross-check small multiples against the established P-256 values.
        let curve = CurveId::P256.curve();
        let two_g = curve
            .to_affine(&curve.mul_generator(&BoxedUint::from_u64(2)))
            .unwrap();
        assert_eq!(
            two_g.0.to_be_bytes(32),
            hex("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978").to_be_bytes(32)
        );
        let three_g = curve
            .to_affine(&curve.mul_generator(&BoxedUint::from_u64(3)))
            .unwrap();
        assert_eq!(
            three_g.0.to_be_bytes(32),
            hex("5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c").to_be_bytes(32)
        );
    }
}
