//! The SEC 2, X9.62 and WTLS binary curves `y² + xy = x³ + a·x² + b` over
//! GF(2^m), with a constant-time López–Dahab Montgomery ladder, a
//! variable-time affine addition for verification, and the SEC 1 §2.3.3 /
//! §2.3.4 point encodings.

use super::field::{Fe, Field, Limbs, MAX_LIMBS, limbs_from_hex};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq};
use crate::zeroize::Zeroize;

/// One curve's public parameters.
#[derive(Clone, Copy, Debug)]
pub(super) struct Curve {
    /// The underlying field.
    pub(super) field: Field,
    /// `a` (0 or 1 for the SEC 2 curves, arbitrary for the X9.62 ones).
    pub(super) a: Fe,
    /// `b` (1 for the Koblitz curves).
    pub(super) b: Fe,
    /// Generator x-coordinate.
    pub(super) gx: Fe,
    /// Generator y-coordinate.
    pub(super) gy: Fe,
    /// Prime order `n` of the generator, little-endian limbs.
    pub(super) n: Limbs,
    /// `bit_len(n)`; scalars encode in `ceil(n_bits / 8)` bytes.
    pub(super) n_bits: usize,
    /// Cofactor `h` (2 to 65392).
    pub(super) h: u64,
    /// The named-curve OID arcs.
    pub(super) oid: &'static [u64],
    /// The OpenSSL short name.
    pub(super) name: &'static str,
}

/// An affine point, with the identity carried as a constant-time flag
/// (`x`/`y` are then unspecified and must not be observed).
#[derive(Clone, Copy, Debug)]
pub(super) struct Point {
    pub(super) x: Fe,
    pub(super) y: Fe,
    pub(super) inf: Choice,
}

impl ConditionallySelectable for Point {
    fn conditional_select(a: &Point, b: &Point, choice: Choice) -> Point {
        Point {
            x: Fe::conditional_select(&a.x, &b.x, choice),
            y: Fe::conditional_select(&a.y, &b.y, choice),
            inf: Choice::conditional_select(&a.inf, &b.inf, choice),
        }
    }
}

// Generated from `openssl ecparam -name <curve> -param_enc explicit
// -outform DER` (OpenSSL 3.5) and cross-checked against SEC 2 v1/v2,
// ANSI X9.62-1998 Annex H and WAP-261-WTLS Annex A: the field polynomial,
// `a`, `b`, `G`, `n` and `h`. The `parameters_are_consistent` and
// `generator_order_and_cofactor` tests check G on the curve and `n·G = ∞`.
// The WTLS curves 3, 4, 5, 10 and 11 reuse the parameters of sect163k1,
// sect113r1, c2pnb163v1, sect233k1 and sect233r1 (as OpenSSL's
// `ec_curve.c` does) under their own OIDs.

/// GF(2^113) with `x^113 + x^9 + 1`.
const F113: Field = Field::new(113, &[9]);

/// GF(2^131) with `x^131 + x^8 + x^3 + x^2 + 1`.
const F131: Field = Field::new(131, &[2, 3, 8]);

/// GF(2^163) with `x^163 + x^7 + x^6 + x^3 + 1`.
const F163: Field = Field::new(163, &[3, 6, 7]);

/// GF(2^193) with `x^193 + x^15 + 1`.
const F193: Field = Field::new(193, &[15]);

/// GF(2^233) with `x^233 + x^74 + 1`.
const F233: Field = Field::new(233, &[74]);

/// GF(2^239) with `x^239 + x^158 + 1`.
const F239: Field = Field::new(239, &[158]);

/// GF(2^283) with `x^283 + x^12 + x^7 + x^5 + 1`.
const F283: Field = Field::new(283, &[5, 7, 12]);

/// GF(2^409) with `x^409 + x^87 + 1`.
const F409: Field = Field::new(409, &[87]);

/// GF(2^571) with `x^571 + x^10 + x^5 + x^2 + 1`.
const F571: Field = Field::new(571, &[2, 5, 10]);

/// GF(2^163) with `x^163 + x^8 + x^2 + x + 1`.
const F163X: Field = Field::new(163, &[1, 2, 8]);

/// GF(2^176) with `x^176 + x^43 + x^2 + x + 1`.
const F176: Field = Field::new(176, &[1, 2, 43]);

/// GF(2^191) with `x^191 + x^9 + 1`.
const F191: Field = Field::new(191, &[9]);

/// GF(2^208) with `x^208 + x^83 + x^2 + x + 1`.
const F208: Field = Field::new(208, &[1, 2, 83]);

/// GF(2^239) with `x^239 + x^36 + 1`.
const F239X: Field = Field::new(239, &[36]);

/// GF(2^272) with `x^272 + x^56 + x^3 + x + 1`.
const F272: Field = Field::new(272, &[1, 3, 56]);

/// GF(2^304) with `x^304 + x^11 + x^2 + x + 1`.
const F304: Field = Field::new(304, &[1, 2, 11]);

/// GF(2^359) with `x^359 + x^68 + 1`.
const F359: Field = Field::new(359, &[68]);

/// GF(2^368) with `x^368 + x^85 + x^2 + x + 1`.
const F368: Field = Field::new(368, &[1, 2, 85]);

/// GF(2^431) with `x^431 + x^120 + 1`.
const F431: Field = Field::new(431, &[120]);

pub(super) const SECT113R1: Curve = Curve {
    field: F113,
    a: Fe::from_hex("03088250ca6e7c7fe649ce85820f7"),
    b: Fe::from_hex("0e8bee4d3e2260744188be0e9c723"),
    gx: Fe::from_hex("09d73616f35f4ab1407d73562c10f"),
    gy: Fe::from_hex("0a52830277958ee84d1315ed31886"),
    n: limbs_from_hex("100000000000000d9ccec8a39e56f"),
    n_bits: 113,
    h: 2,
    oid: &[1, 3, 132, 0, 4],
    name: "sect113r1",
};

pub(super) const SECT113R2: Curve = Curve {
    field: F113,
    a: Fe::from_hex("0689918dbec7e5a0dd6dfc0aa55c7"),
    b: Fe::from_hex("095e9a9ec9b297bd4bf36e059184f"),
    gx: Fe::from_hex("1a57a6a7b26ca5ef52fcdb8164797"),
    gy: Fe::from_hex("0b3adc94ed1fe674c06e695baba1d"),
    n: limbs_from_hex("10000000000000108789b2496af93"),
    n_bits: 113,
    h: 2,
    oid: &[1, 3, 132, 0, 5],
    name: "sect113r2",
};

pub(super) const SECT131R1: Curve = Curve {
    field: F131,
    a: Fe::from_hex("7a11b09a76b562144418ff3ff8c2570b8"),
    b: Fe::from_hex("217c05610884b63b9c6c7291678f9d341"),
    gx: Fe::from_hex("081baf91fdf9833c40f9c181343638399"),
    gy: Fe::from_hex("78c6e7ea38c001f73c8134b1b4ef9e150"),
    n: limbs_from_hex("400000000000000023123953a9464b54d"),
    n_bits: 131,
    h: 2,
    oid: &[1, 3, 132, 0, 22],
    name: "sect131r1",
};

pub(super) const SECT131R2: Curve = Curve {
    field: F131,
    a: Fe::from_hex("3e5a88919d7cafcbf415f07c2176573b2"),
    b: Fe::from_hex("4b8266a46c55657ac734ce38f018f2192"),
    gx: Fe::from_hex("356dcd8f2f95031ad652d23951bb366a8"),
    gy: Fe::from_hex("648f06d867940a5366d9e265de9eb240f"),
    n: limbs_from_hex("400000000000000016954a233049ba98f"),
    n_bits: 131,
    h: 2,
    oid: &[1, 3, 132, 0, 23],
    name: "sect131r2",
};

pub(super) const SECT163K1: Curve = Curve {
    field: F163,
    a: Fe::ONE,
    b: Fe::ONE,
    gx: Fe::from_hex("2fe13c0537bbc11acaa07d793de4e6d5e5c94eee8"),
    gy: Fe::from_hex("289070fb05d38ff58321f2e800536d538ccdaa3d9"),
    n: limbs_from_hex("4000000000000000000020108a2e0cc0d99f8a5ef"),
    n_bits: 163,
    h: 2,
    oid: &[1, 3, 132, 0, 1],
    name: "sect163k1",
};

pub(super) const SECT163R1: Curve = Curve {
    field: F163,
    a: Fe::from_hex("7b6882caaefa84f9554ff8428bd88e246d2782ae2"),
    b: Fe::from_hex("713612dcddcb40aab946bda29ca91f73af958afd9"),
    gx: Fe::from_hex("369979697ab43897789566789567f787a7876a654"),
    gy: Fe::from_hex("0435edb42efafb2989d51fefce3c80988f41ff883"),
    n: limbs_from_hex("3ffffffffffffffffffff48aab689c29ca710279b"),
    n_bits: 162,
    h: 2,
    oid: &[1, 3, 132, 0, 2],
    name: "sect163r1",
};

pub(super) const SECT163R2: Curve = Curve {
    field: F163,
    a: Fe::ONE,
    b: Fe::from_hex("20a601907b8c953ca1481eb10512f78744a3205fd"),
    gx: Fe::from_hex("3f0eba16286a2d57ea0991168d4994637e8343e36"),
    gy: Fe::from_hex("0d51fbc6c71a0094fa2cdd545b11c5c0c797324f1"),
    n: limbs_from_hex("40000000000000000000292fe77e70c12a4234c33"),
    n_bits: 163,
    h: 2,
    oid: &[1, 3, 132, 0, 15],
    name: "sect163r2",
};

pub(super) const SECT193R1: Curve = Curve {
    field: F193,
    a: Fe::from_hex("017858feb7a98975169e171f77b4087de098ac8a911df7b01"),
    b: Fe::from_hex("0fdfb49bfe6c3a89facadaa7a1e5bbc7cc1c2e5d831478814"),
    gx: Fe::from_hex("1f481bc5f0ff84a74ad6cdf6fdef4bf6179625372d8c0c5e1"),
    gy: Fe::from_hex("025e399f2903712ccf3ea9e3a1ad17fb0b3201b6af7ce1b05"),
    n: limbs_from_hex("1000000000000000000000000c7f34a778f443acc920eba49"),
    n_bits: 193,
    h: 2,
    oid: &[1, 3, 132, 0, 24],
    name: "sect193r1",
};

pub(super) const SECT193R2: Curve = Curve {
    field: F193,
    a: Fe::from_hex("163f35a5137c2ce3ea6ed8667190b0bc43ecd69977702709b"),
    b: Fe::from_hex("0c9bb9e8927d4d64c377e2ab2856a5b16e3efb7f61d4316ae"),
    gx: Fe::from_hex("0d9b67d192e0367c803f39e1a7e82ca14a651350aae617e8f"),
    gy: Fe::from_hex("1ce94335607c304ac29e7defbd9ca01f596f927224cdecf6c"),
    n: limbs_from_hex("10000000000000000000000015aab561b005413ccd4ee99d5"),
    n_bits: 193,
    h: 2,
    oid: &[1, 3, 132, 0, 25],
    name: "sect193r2",
};

pub(super) const SECT233K1: Curve = Curve {
    field: F233,
    a: Fe::ZERO,
    b: Fe::ONE,
    gx: Fe::from_hex("17232ba853a7e731af129f22ff4149563a419c26bf50a4c9d6eefad6126"),
    gy: Fe::from_hex("1db537dece819b7f70f555a67c427a8cd9bf18aeb9b56e0c11056fae6a3"),
    n: limbs_from_hex("8000000000000000000000000000069d5bb915bcd46efb1ad5f173abdf"),
    n_bits: 232,
    h: 4,
    oid: &[1, 3, 132, 0, 26],
    name: "sect233k1",
};

pub(super) const SECT233R1: Curve = Curve {
    field: F233,
    a: Fe::ONE,
    b: Fe::from_hex("066647ede6c332c7f8c0923bb58213b333b20e9ce4281fe115f7d8f90ad"),
    gx: Fe::from_hex("0fac9dfcbac8313bb2139f1bb755fef65bc391f8b36f8f8eb7371fd558b"),
    gy: Fe::from_hex("1006a08a41903350678e58528bebf8a0beff867a7ca36716f7e01f81052"),
    n: limbs_from_hex("1000000000000000000000000000013e974e72f8a6922031d2603cfe0d7"),
    n_bits: 233,
    h: 2,
    oid: &[1, 3, 132, 0, 27],
    name: "sect233r1",
};

pub(super) const SECT239K1: Curve = Curve {
    field: F239,
    a: Fe::ZERO,
    b: Fe::ONE,
    gx: Fe::from_hex("29a0b6a887a983e9730988a68727a8b2d126c44cc2cc7b2a6555193035dc"),
    gy: Fe::from_hex("76310804f12e549bdb011c103089e73510acb275fc312a5dc6b76553f0ca"),
    n: limbs_from_hex("2000000000000000000000000000005a79fec67cb6e91f1c1da800e478a5"),
    n_bits: 238,
    h: 4,
    oid: &[1, 3, 132, 0, 3],
    name: "sect239k1",
};

pub(super) const SECT283K1: Curve = Curve {
    field: F283,
    a: Fe::ZERO,
    b: Fe::ONE,
    gx: Fe::from_hex("503213f78ca44883f1a3b8162f188e553cd265f23c1567a16876913b0c2ac2458492836"),
    gy: Fe::from_hex("1ccda380f1c9e318d90f95d07e5426fe87e45c0e8184698e45962364e34116177dd2259"),
    n: limbs_from_hex("1ffffffffffffffffffffffffffffffffffe9ae2ed07577265dff7f94451e061e163c61"),
    n_bits: 281,
    h: 4,
    oid: &[1, 3, 132, 0, 16],
    name: "sect283k1",
};

pub(super) const SECT283R1: Curve = Curve {
    field: F283,
    a: Fe::ONE,
    b: Fe::from_hex("27b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5"),
    gx: Fe::from_hex("5f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053"),
    gy: Fe::from_hex("3676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4"),
    n: limbs_from_hex("3ffffffffffffffffffffffffffffffffffef90399660fc938a90165b042a7cefadb307"),
    n_bits: 282,
    h: 2,
    oid: &[1, 3, 132, 0, 17],
    name: "sect283r1",
};

pub(super) const SECT409K1: Curve = Curve {
    field: F409,
    a: Fe::ZERO,
    b: Fe::ONE,
    gx: Fe::from_hex(
        "060f05f658f49c1ad3ab1890f7184210efd0987e307c84c27accfb8f9f67cc2c460189eb5aaaa62ee222eb1b35540cfe9023746",
    ),
    gy: Fe::from_hex(
        "1e369050b7c4e42acba1dacbf04299c3460782f918ea427e6325165e9ea10e3da5f6c42e9c55215aa9ca27a5863ec48d8e0286b",
    ),
    n: limbs_from_hex(
        "7ffffffffffffffffffffffffffffffffffffffffffffffffffe5f83b2d4ea20400ec4557d5ed3e3e7ca5b4b5c83b8e01e5fcf",
    ),
    n_bits: 407,
    h: 4,
    oid: &[1, 3, 132, 0, 36],
    name: "sect409k1",
};

pub(super) const SECT409R1: Curve = Curve {
    field: F409,
    a: Fe::ONE,
    b: Fe::from_hex(
        "021a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f",
    ),
    gx: Fe::from_hex(
        "15d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7",
    ),
    gy: Fe::from_hex(
        "061b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706",
    ),
    n: limbs_from_hex(
        "10000000000000000000000000000000000000000000000000001e2aad6a612f33307be5fa47c3c9e052f838164cd37d9a21173",
    ),
    n_bits: 409,
    h: 2,
    oid: &[1, 3, 132, 0, 37],
    name: "sect409r1",
};

pub(super) const SECT571K1: Curve = Curve {
    field: F571,
    a: Fe::ZERO,
    b: Fe::ONE,
    gx: Fe::from_hex(
        "26eb7a859923fbc82189631f8103fe4ac9ca2970012d5d46024804801841ca44370958493b205e647da304db4ceb08cbbd1ba39494776fb988b47174dca88c7e2945283a01c8972",
    ),
    gy: Fe::from_hex(
        "349dc807f4fbf374f4aeade3bca95314dd58cec9f307a54ffc61efc006d8a2c9d4979c0ac44aea74fbebbb9f772aedcb620b01a7ba7af1b320430c8591984f601cd4c143ef1c7a3",
    ),
    n: limbs_from_hex(
        "20000000000000000000000000000000000000000000000000000000000000000000000131850e1f19a63e4b391a8db917f4138b630d84be5d639381e91deb45cfe778f637c1001",
    ),
    n_bits: 570,
    h: 4,
    oid: &[1, 3, 132, 0, 38],
    name: "sect571k1",
};

pub(super) const SECT571R1: Curve = Curve {
    field: F571,
    a: Fe::ONE,
    b: Fe::from_hex(
        "2f40e7e2221f295de297117b7f3d62f5c6a97ffcb8ceff1cd6ba8ce4a9a18ad84ffabbd8efa59332be7ad6756a66e294afd185a78ff12aa520e4de739baca0c7ffeff7f2955727a",
    ),
    gx: Fe::from_hex(
        "303001d34b856296c16c0d40d3cd7750a93d1d2955fa80aa5f40fc8db7b2abdbde53950f4c0d293cdd711a35b67fb1499ae60038614f1394abfa3b4c850d927e1e7769c8eec2d19",
    ),
    gy: Fe::from_hex(
        "37bf27342da639b6dccfffeb73d69d78c6c27a6009cbbca1980f8533921e8a684423e43bab08a576291af8f461bb2a8b3531d2f0485c19b16e2f1516e23dd3c1a4827af1b8ac15b",
    ),
    n: limbs_from_hex(
        "3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe661ce18ff55987308059b186823851ec7dd9ca1161de93d5174d66e8382e9bb2fe84e47",
    ),
    n_bits: 570,
    h: 2,
    oid: &[1, 3, 132, 0, 39],
    name: "sect571r1",
};

pub(super) const C2PNB163V1: Curve = Curve {
    field: F163X,
    a: Fe::from_hex("72546b5435234a422e0789675f432c89435de5242"),
    b: Fe::from_hex("0c9517d06d5240d3cff38c74b20b6cd4d6f9dd4d9"),
    gx: Fe::from_hex("7af69989546103d79329fcc3d74880f33bbe803cb"),
    gy: Fe::from_hex("1ec23211b5966adea1d3f87f7ea5848aef0b7ca9f"),
    n: limbs_from_hex("400000000000000000001e60fc8821cc74daeafc1"),
    n_bits: 163,
    h: 2,
    oid: &[1, 2, 840, 10045, 3, 0, 1],
    name: "c2pnb163v1",
};

pub(super) const C2PNB163V2: Curve = Curve {
    field: F163X,
    a: Fe::from_hex("108b39e77c4b108bed981ed0e890e117c511cf072"),
    b: Fe::from_hex("667aceb38af4e488c407433ffae4f1c811638df20"),
    gx: Fe::from_hex("024266e4eb5106d0a964d92c4860e2671db9b6cc5"),
    gy: Fe::from_hex("79f684ddf6684c5cd258b3890021b2386dfd19fc5"),
    n: limbs_from_hex("3fffffffffffffffffffdf64de1151adbb78f10a7"),
    n_bits: 162,
    h: 2,
    oid: &[1, 2, 840, 10045, 3, 0, 2],
    name: "c2pnb163v2",
};

pub(super) const C2PNB163V3: Curve = Curve {
    field: F163X,
    a: Fe::from_hex("7a526c63d3e25a256a007699f5447e32ae456b50e"),
    b: Fe::from_hex("3f7061798eb99e238fd6f1bf95b48feeb4854252b"),
    gx: Fe::from_hex("2f9f87b7c574d0bdecf8a22e6524775f98cdebdcb"),
    gy: Fe::from_hex("5b935590c155e17ea48eb3ff3718b893df59a05d0"),
    n: limbs_from_hex("3fffffffffffffffffffe1aee140f110aff961309"),
    n_bits: 162,
    h: 2,
    oid: &[1, 2, 840, 10045, 3, 0, 3],
    name: "c2pnb163v3",
};

pub(super) const C2PNB176V1: Curve = Curve {
    field: F176,
    a: Fe::from_hex("e4e6db2995065c407d9d39b8d0967b96704ba8e9c90b"),
    b: Fe::from_hex("5dda470abe6414de8ec133ae28e9bbd7fcec0ae0fff2"),
    gx: Fe::from_hex("8d16c2866798b600f9f08bb4a8e860f3298ce04a5798"),
    gy: Fe::from_hex("6fa4539c2dadddd6bab5167d61b436e1d92bb16a562c"),
    n: limbs_from_hex("10092537397eca4f6145799d62b0a19ce06fe26ad"),
    n_bits: 161,
    h: 65390,
    oid: &[1, 2, 840, 10045, 3, 0, 4],
    name: "c2pnb176v1",
};

pub(super) const C2TNB191V1: Curve = Curve {
    field: F191,
    a: Fe::from_hex("2866537b676752636a68f56554e12640276b649ef7526267"),
    b: Fe::from_hex("2e45ef571f00786f67b0081b9495a3d95462f5de0aa185ec"),
    gx: Fe::from_hex("36b3daf8a23206f9c4f299d7b21a9c369137f2c84ae1aa0d"),
    gy: Fe::from_hex("765be73433b3f95e332932e70ea245ca2418ea0ef98018fb"),
    n: limbs_from_hex("40000000000000000000000004a20e90c39067c893bbb9a5"),
    n_bits: 191,
    h: 2,
    oid: &[1, 2, 840, 10045, 3, 0, 5],
    name: "c2tnb191v1",
};

pub(super) const C2TNB191V2: Curve = Curve {
    field: F191,
    a: Fe::from_hex("401028774d7777c7b7666d1366ea432071274f89ff01e718"),
    b: Fe::from_hex("0620048d28bcbd03b6249c99182b7c8cd19700c362c46a01"),
    gx: Fe::from_hex("3809b2b7cc1b28cc5a87926aad83fd28789e81e2c9e3bf10"),
    gy: Fe::from_hex("17434386626d14f3dbf01760d9213a3e1cf37aec437d668a"),
    n: limbs_from_hex("20000000000000000000000050508cb89f652824e06b8173"),
    n_bits: 190,
    h: 4,
    oid: &[1, 2, 840, 10045, 3, 0, 6],
    name: "c2tnb191v2",
};

pub(super) const C2TNB191V3: Curve = Curve {
    field: F191,
    a: Fe::from_hex("6c01074756099122221056911c77d77e77a777e7e7e77fcb"),
    b: Fe::from_hex("71fe1af926cf847989efef8db459f66394d90f32ad3f15e8"),
    gx: Fe::from_hex("375d4ce24fde434489de8746e71786015009e66e38a926dd"),
    gy: Fe::from_hex("545a39176196575d985999366e6ad34ce0a77cd7127b06be"),
    n: limbs_from_hex("155555555555555555555555610c0b196812bfb6288a3ea3"),
    n_bits: 189,
    h: 6,
    oid: &[1, 2, 840, 10045, 3, 0, 7],
    name: "c2tnb191v3",
};

pub(super) const C2PNB208W1: Curve = Curve {
    field: F208,
    a: Fe::ZERO,
    b: Fe::from_hex("c8619ed45a62e6212e1160349e2bfa844439fafc2a3fd1638f9e"),
    gx: Fe::from_hex("89fdfbe4abe193df9559ecf07ac0ce78554e2784eb8c1ed1a57a"),
    gy: Fe::from_hex("0f55b51a06e78e9ac38a035ff520d8b01781beb1a6bb08617de3"),
    n: limbs_from_hex("101baf95c9723c57b6c21da2eff2d5ed588bdd5717e212f9d"),
    n_bits: 193,
    h: 65096,
    oid: &[1, 2, 840, 10045, 3, 0, 10],
    name: "c2pnb208w1",
};

pub(super) const C2TNB239V1: Curve = Curve {
    field: F239X,
    a: Fe::from_hex("32010857077c5431123a46b808906756f543423e8d27877578125778ac76"),
    b: Fe::from_hex("790408f2eedaf392b012edefb3392f30f4327c0ca3f31fc383c422aa8c16"),
    gx: Fe::from_hex("57927098fa932e7c0a96d3fd5b706ef7e5f5c156e16b7e7c86038552e91d"),
    gy: Fe::from_hex("61d8ee5077c33fecf6f1a16b268de469c3c7744ea9a971649fc7a9616305"),
    n: limbs_from_hex("2000000000000000000000000000000f4d42ffe1492a4993f1cad666e447"),
    n_bits: 238,
    h: 4,
    oid: &[1, 2, 840, 10045, 3, 0, 11],
    name: "c2tnb239v1",
};

pub(super) const C2TNB239V2: Curve = Curve {
    field: F239X,
    a: Fe::from_hex("4230017757a767fae42398569b746325d45313af0766266479b75654e65f"),
    b: Fe::from_hex("5037ea654196cff0cd82b2c14a2fcf2e3ff8775285b545722f03eacdb74b"),
    gx: Fe::from_hex("28f9d04e900069c8dc47a08534fe76d2b900b7d7ef31f5709f200c4ca205"),
    gy: Fe::from_hex("5667334c45aff3b5a03bad9dd75e2c71a99362567d5453f7fa6e227ec833"),
    n: limbs_from_hex("1555555555555555555555555555553c6f2885259c31e3fcdf154624522d"),
    n_bits: 237,
    h: 6,
    oid: &[1, 2, 840, 10045, 3, 0, 12],
    name: "c2tnb239v2",
};

pub(super) const C2TNB239V3: Curve = Curve {
    field: F239X,
    a: Fe::from_hex("01238774666a67766d6676f778e676b66999176666e687666d8766c66a9f"),
    b: Fe::from_hex("6a941977ba9f6a435199acfc51067ed587f519c5ecb541b8e44111de1d40"),
    gx: Fe::from_hex("70f6e9d04d289c4e89913ce3530bfde903977d42b146d539bf1bde4e9c92"),
    gy: Fe::from_hex("2e5a0eaf6e5e1305b9004dce5c0ed7fe59a35608f33837c816d80b79f461"),
    n: limbs_from_hex("cccccccccccccccccccccccccccccac4912d2d9df903ef9888b8a0e4cff"),
    n_bits: 236,
    h: 10,
    oid: &[1, 2, 840, 10045, 3, 0, 13],
    name: "c2tnb239v3",
};

pub(super) const C2PNB272W1: Curve = Curve {
    field: F272,
    a: Fe::from_hex("91a091f03b5fba4ab2ccf49c4edd220fb028712d42be752b2c40094dbacdb586fb20"),
    b: Fe::from_hex("7167efc92bb2e3ce7c8aaaff34e12a9c557003d7c73a6faf003f99f6cc8482e540f7"),
    gx: Fe::from_hex("6108babb2ceebcf787058a056cbe0cfe622d7723a289e08a07ae13ef0d10d171dd8d"),
    gy: Fe::from_hex("10c7695716851eef6ba7f6872e6142fbd241b830ff5efcaceccab05e02005dde9d23"),
    n: limbs_from_hex("100faf51354e0e39e4892df6e319c72c8161603fa45aa7b998a167b8f1e629521"),
    n_bits: 257,
    h: 65286,
    oid: &[1, 2, 840, 10045, 3, 0, 16],
    name: "c2pnb272w1",
};

pub(super) const C2PNB304W1: Curve = Curve {
    field: F304,
    a: Fe::from_hex("fd0d693149a118f651e6dce6802085377e5f882d1b510b44160074c1288078365a0396c8e681"),
    b: Fe::from_hex("bddb97e555a50a908e43b01c798ea5daa6788f1ea2794efcf57166b8c14039601e55827340be"),
    gx: Fe::from_hex(
        "197b07845e9be2d96adb0f5f3c7f2cffbd7a3eb8b6fec35c7fd67f26ddf6285a644f740a2614",
    ),
    gy: Fe::from_hex(
        "e19fbeb76e0da171517ecf401b50289bf014103288527a9b416a105e80260b549fdc1b92c03b",
    ),
    n: limbs_from_hex("101d556572aabac800101d556572aabac8001022d5c91dd173f8fb561da6899164443051d"),
    n_bits: 289,
    h: 65070,
    oid: &[1, 2, 840, 10045, 3, 0, 17],
    name: "c2pnb304w1",
};

pub(super) const C2TNB359V1: Curve = Curve {
    field: F359,
    a: Fe::from_hex(
        "5667676a654b20754f356ea92017d946567c46675556f19556a04616b567d223a5e05656fb549016a96656a557",
    ),
    b: Fe::from_hex(
        "2472e2d0197c49363f1fe7f5b6db075d52b6947d135d8ca445805d39bc345626089687742b6329e70680231988",
    ),
    gx: Fe::from_hex(
        "3c258ef3047767e7ede0f1fdaa79daee3841366a132e163aced4ed2401df9c6bdcde98e8e707c07a2239b1b097",
    ),
    gy: Fe::from_hex(
        "53d7e08529547048121e9c95f3791dd804963948f34fae7bf44ea82365dc7868fe57e4ae2de211305a407104bd",
    ),
    n: limbs_from_hex(
        "1af286bca1af286bca1af286bca1af286bca1af286bc9fb8f6b85c556892c20a7eb964fe7719e74f490758d3b",
    ),
    n_bits: 353,
    h: 76,
    oid: &[1, 2, 840, 10045, 3, 0, 18],
    name: "c2tnb359v1",
};

pub(super) const C2PNB368W1: Curve = Curve {
    field: F368,
    a: Fe::from_hex(
        "e0d2ee25095206f5e2a4f9ed229f1f256e79a0e2b455970d8d0d865bd94778c576d62f0ab7519ccd2a1a906ae30d",
    ),
    b: Fe::from_hex(
        "fc1217d4320a90452c760a58edcd30c8dd069b3c34453837a34ed50cb54917e1c2112d84d164f444f8f74786046a",
    ),
    gx: Fe::from_hex(
        "1085e2755381dccce3c1557afa10c2f0c0c2825646c5b34a394cbcfa8bc16b22e7e789e927be216f02e1fb136a5f",
    ),
    gy: Fe::from_hex(
        "7b3eb1bddcba62d5d8b2059b525797fc73822c59059c623a45ff3843cee8f87cd1855adaa81e2a0750b80fda2310",
    ),
    n: limbs_from_hex(
        "10090512da9af72b08349d98a5dd4c7b0532eca51ce03e2d10f3b7ac579bd87e909ae40a6f131e9cfce5bd967",
    ),
    n_bits: 353,
    h: 65392,
    oid: &[1, 2, 840, 10045, 3, 0, 19],
    name: "c2pnb368w1",
};

pub(super) const C2TNB431R1: Curve = Curve {
    field: F431,
    a: Fe::from_hex(
        "1a827ef00dd6fc0e234caf046c6a5d8a85395b236cc4ad2cf32a0cadbdc9ddf620b0eb9906d0957f6c6feacd615468df104de296cd8f",
    ),
    b: Fe::from_hex(
        "10d9b4a3d9047d8b154359abfb1b7f5485b04ceb868237ddc9deda982a679a5a919b626d4e50a8dd731b107a9962381fb5d807bf2618",
    ),
    gx: Fe::from_hex(
        "120fc05d3c67a99de161d2f4092622feca701be4f50f4758714e8a87bbf2a658ef8c21e7c5efe965361f6c2999c0c247b0dbd70ce6b7",
    ),
    gy: Fe::from_hex(
        "20d0af8903a96f8d5fa2c255745d3c451b302c9346d9b7e485e7bce41f6b591f3e8f6addcbb0bc4c2f947a7de1a89b625d6a598b3760",
    ),
    n: limbs_from_hex(
        "340340340340340340340340340340340340340340340340340340323c313fab50589703b5ec68d3587fec60d161cc149c1ad4a91",
    ),
    n_bits: 418,
    h: 10080,
    oid: &[1, 2, 840, 10045, 3, 0, 20],
    name: "c2tnb431r1",
};

pub(super) const WTLS1: Curve = Curve {
    field: F113,
    a: Fe::ONE,
    b: Fe::ONE,
    gx: Fe::from_hex("1667979a40ba497e5d5c270780617"),
    gy: Fe::from_hex("0f44b4af1ecc2630e08785cebcc15"),
    n: limbs_from_hex("fffffffffffffffdbf91af6dea73"),
    n_bits: 112,
    h: 2,
    oid: &[2, 23, 43, 1, 4, 1],
    name: "wap-wsg-idm-ecid-wtls1",
};

pub(super) const WTLS3: Curve = Curve {
    oid: &[2, 23, 43, 1, 4, 3],
    name: "wap-wsg-idm-ecid-wtls3",
    ..SECT163K1
};

pub(super) const WTLS4: Curve = Curve {
    oid: &[2, 23, 43, 1, 4, 4],
    name: "wap-wsg-idm-ecid-wtls4",
    ..SECT113R1
};

pub(super) const WTLS5: Curve = Curve {
    oid: &[2, 23, 43, 1, 4, 5],
    name: "wap-wsg-idm-ecid-wtls5",
    ..C2PNB163V1
};

pub(super) const WTLS10: Curve = Curve {
    oid: &[2, 23, 43, 1, 4, 10],
    name: "wap-wsg-idm-ecid-wtls10",
    ..SECT233K1
};

pub(super) const WTLS11: Curve = Curve {
    oid: &[2, 23, 43, 1, 4, 11],
    name: "wap-wsg-idm-ecid-wtls11",
    ..SECT233R1
};

/// Every curve (for the tests).
#[cfg(test)]
pub(super) const ALL: [&Curve; 40] = [
    &SECT113R1,
    &SECT113R2,
    &SECT131R1,
    &SECT131R2,
    &SECT163K1,
    &SECT163R1,
    &SECT163R2,
    &SECT193R1,
    &SECT193R2,
    &SECT233K1,
    &SECT233R1,
    &SECT239K1,
    &SECT283K1,
    &SECT283R1,
    &SECT409K1,
    &SECT409R1,
    &SECT571K1,
    &SECT571R1,
    &C2PNB163V1,
    &C2PNB163V2,
    &C2PNB163V3,
    &C2PNB176V1,
    &C2TNB191V1,
    &C2TNB191V2,
    &C2TNB191V3,
    &C2PNB208W1,
    &C2TNB239V1,
    &C2TNB239V2,
    &C2TNB239V3,
    &C2PNB272W1,
    &C2PNB304W1,
    &C2TNB359V1,
    &C2PNB368W1,
    &C2TNB431R1,
    &WTLS1,
    &WTLS3,
    &WTLS4,
    &WTLS5,
    &WTLS10,
    &WTLS11,
];

/// `a < b` on little-endian limbs, in constant time (a borrow chain).
pub(super) fn limbs_lt(a: &Limbs, b: &Limbs) -> Choice {
    let mut borrow = 0u128;
    for i in 0..MAX_LIMBS {
        let d = (a[i] as u128)
            .wrapping_sub(b[i] as u128)
            .wrapping_sub(borrow);
        borrow = (d >> 127) & 1;
    }
    Choice::from(borrow as u8)
}

/// Whether every limb is zero, in constant time.
pub(super) fn limbs_is_zero(a: &Limbs) -> Choice {
    a.ct_eq(&[0; MAX_LIMBS])
}

impl Curve {
    /// Bytes of a scalar (`ceil(bit_len(n) / 8)`).
    #[inline]
    pub(super) const fn scalar_len(&self) -> usize {
        self.n_bits.div_ceil(8)
    }

    /// The generator.
    pub(super) fn generator(&self) -> Point {
        Point {
            x: self.gx,
            y: self.gy,
            inf: Choice::from(0),
        }
    }

    /// Whether `(x, y)` satisfies `y² + xy = x³ + a·x² + b`.
    pub(super) fn is_on_curve(&self, x: &Fe, y: &Fe) -> Choice {
        let f = &self.field;
        let x2 = f.sqr(x);
        let lhs = f.sqr(y).add(&f.mul(x, y));
        let rhs = f.mul(&x2, x).add(&f.mul(&self.a, &x2)).add(&self.b);
        lhs.ct_eq(&rhs)
    }

    /// Montgomery doubling in López–Dahab x-only coordinates:
    /// `(X : Z) ↦ (X⁴ + b·Z⁴ : X²·Z²)`.
    #[inline]
    fn mdouble(&self, x: &Fe, z: &Fe) -> (Fe, Fe) {
        let f = &self.field;
        let x2 = f.sqr(x);
        let z2 = f.sqr(z);
        let x4 = f.sqr(&x2);
        let bz4 = f.mul(&self.b, &f.sqr(&z2));
        (x4.add(&bz4), f.mul(&x2, &z2))
    }

    /// Montgomery differential addition: given `x(P₁)`, `x(P₂)` and
    /// `x = x(P₂ − P₁)`, returns `x(P₁ + P₂)` as
    /// `(x·(T₁ + T₂)² + T₁·T₂ : (T₁ + T₂)²)` with `T₁ = X₁Z₂`, `T₂ = X₂Z₁`.
    #[inline]
    fn madd(&self, x1: &Fe, z1: &Fe, x2: &Fe, z2: &Fe, x: &Fe) -> (Fe, Fe) {
        let f = &self.field;
        let t1 = f.mul(x1, z2);
        let t2 = f.mul(x2, z1);
        let z = f.sqr(&t1.add(&t2));
        let xo = f.mul(x, &z).add(&f.mul(&t1, &t2));
        (xo, z)
    }

    /// `k · p` by the López–Dahab Montgomery ladder over the full
    /// `64 · limbs` bit width of `k` (little-endian limbs), with
    /// constant-time swaps driven by consecutive bit differences.
    ///
    /// The ladder starts from `(∞, P)` so every bit — leading zeros included —
    /// runs the same doubling and differential addition. The x-only formulas
    /// carry infinity as `(X : 0)` with `X ≠ 0` and never produce `(0 : 0)`
    /// for a finite `p` on the curve, whatever its order (so the same routine
    /// performs the `n·Q = ∞` subgroup check). The y-coordinate is recovered
    /// from the final pair `(kP, (k+1)P)`; the two cases where that formula
    /// degenerates — `(k+1)P = ∞` (then `kP = −P`) and `x(P) = 0` (an
    /// order-2 point, `kP ∈ {P, ∞}`) — are patched by constant-time selects,
    /// and `kP = ∞` sets the flag.
    pub(super) fn mul(&self, k: &Limbs, p: &Point) -> Point {
        let f = &self.field;
        let x = p.x;
        let y = p.y;
        // R0 = ∞, R1 = P.
        let (mut x1, mut z1) = (Fe::ONE, Fe::ZERO);
        let (mut x2, mut z2) = (x, Fe::ONE);
        let mut prev = Choice::from(0);
        for i in (0..f.bit_width()).rev() {
            let bit = Choice::from(((k[i / 64] >> (i % 64)) & 1) as u8);
            let swap = bit ^ prev;
            Fe::conditional_swap(&mut x1, &mut x2, swap);
            Fe::conditional_swap(&mut z1, &mut z2, swap);
            prev = bit;
            // R1 = R0 + R1, R0 = 2·R0 (in the orientation selected by `bit`).
            let (ax, az) = self.madd(&x1, &z1, &x2, &z2, &x);
            let (dx, dz) = self.mdouble(&x1, &z1);
            x1 = dx;
            z1 = dz;
            x2 = ax;
            z2 = az;
        }
        Fe::conditional_swap(&mut x1, &mut x2, prev);
        Fe::conditional_swap(&mut z1, &mut z2, prev);
        // `prev` is the scalar's lowest bit.
        prev.zeroize();

        // (x1 : z1) = kP, (x2 : z2) = (k+1)P. Recover y (López–Dahab Mxy):
        // y_k = (x + x_k)·[(X₁ + xZ₁)(X₂ + xZ₂) + (x² + y)Z₁Z₂] / (xZ₁Z₂) + y.
        let z1_zero = z1.is_zero();
        let z2_zero = z2.is_zero();
        let x_zero = x.is_zero();
        let mut z1_inv = f.inv(&z1);
        let mut xk = f.mul(&x1, &z1_inv);
        let mut t1 = x1.add(&f.mul(&x, &z1));
        let mut t2 = x2.add(&f.mul(&x, &z2));
        let mut z1z2 = f.mul(&z1, &z2);
        let mut num = f.mul(&t1, &t2).add(&f.mul(&f.sqr(&x).add(&y), &z1z2));
        let mut den = f.inv(&f.mul(&x, &z1z2));
        let mut yk = f.mul(&x.add(&xk), &f.mul(&num, &den)).add(&y);
        // (k+1)P = ∞ ⇒ kP = −P = (x, x + y); x = 0 and kP ≠ ∞ ⇒ kP = P.
        let yk_out = Fe::conditional_select(&x.add(&y), &yk, z2_zero);
        let yk_out = Fe::conditional_select(&y, &yk_out, x_zero);
        let xk_out = Fe::conditional_select(&x, &xk, z2_zero | x_zero);
        // The ladder state and the y-recovery intermediates encode the
        // scalar (e.g. (k+1)P); wipe them before returning.
        for v in [
            &mut x1,
            &mut z1,
            &mut x2,
            &mut z2,
            &mut z1_inv,
            &mut xk,
            &mut t1,
            &mut t2,
            &mut z1z2,
            &mut num,
            &mut den,
            &mut yk,
        ] {
            v.zeroize();
        }
        let (xk, yk) = (xk_out, yk_out);
        Point {
            x: xk,
            y: yk,
            inf: z1_zero | p.inf,
        }
    }

    /// `p + q` by the affine chord-and-tangent formulas, in **variable
    /// time**: for public points only (ECDSA verification).
    pub(super) fn add_vartime(&self, p: &Point, q: &Point) -> Point {
        let f = &self.field;
        if bool::from(p.inf) {
            return *q;
        }
        if bool::from(q.inf) {
            return *p;
        }
        let inf = Point {
            x: Fe::ZERO,
            y: Fe::ZERO,
            inf: Choice::from(1),
        };
        let lam = if bool::from(p.x.ct_eq(&q.x)) {
            // q = −p = (x, x + y), or p = (0, √b) of order 2: the sum is ∞.
            if !bool::from(p.y.ct_eq(&q.y)) || bool::from(p.x.is_zero()) {
                return inf;
            }
            // Doubling: λ = x + y/x.
            p.x.add(&f.mul(&p.y, &f.inv(&p.x)))
        } else {
            f.mul(&p.y.add(&q.y), &f.inv(&p.x.add(&q.x)))
        };
        // x₃ = λ² + λ + x₁ + x₂ + a (x₁ = x₂ for a doubling, so the sum
        // vanishes); y₃ = λ(x₁ + x₃) + x₃ + y₁.
        let x3 = f.sqr(&lam).add(&lam).add(&p.x).add(&q.x).add(&self.a);
        let y3 = f.mul(&lam, &p.x.add(&x3)).add(&x3).add(&p.y);
        Point {
            x: x3,
            y: y3,
            inf: Choice::from(0),
        }
    }

    /// Whether `n · p = ∞` (the prime-order subgroup check).
    pub(super) fn in_subgroup(&self, p: &Point) -> Choice {
        self.mul(&self.n, p).inf
    }

    /// Bytes of the SEC 1 encoding: `1 + len` compressed, `1 + 2·len`
    /// uncompressed.
    pub(super) fn encoded_len(&self, compressed: bool) -> usize {
        let len = self.field.byte_len();
        if compressed { 1 + len } else { 1 + 2 * len }
    }

    /// SEC 1 §2.3.3 encoding of a finite point. The compressed form carries
    /// `ỹ = 0` when `x = 0`, otherwise the constant term of `y · x⁻¹`.
    pub(super) fn encode(&self, p: &Point, compressed: bool, out: &mut [u8]) {
        let f = &self.field;
        let len = f.byte_len();
        debug_assert_eq!(out.len(), self.encoded_len(compressed));
        f.encode_be(&p.x, &mut out[1..1 + len]);
        if compressed {
            // `inv(0) = 0`, so x = 0 yields ỹ = 0 without a branch.
            let ybit = f.mul(&p.y, &f.inv(&p.x)).lsb();
            out[0] = 0x02 | ybit.unwrap_u8();
        } else {
            out[0] = 0x04;
            f.encode_be(&p.y, &mut out[1 + len..]);
        }
    }

    /// SEC 1 §2.3.4 decoding: accepts `04 || x || y` and `02/03 || x`,
    /// verifies the field-element ranges and the curve equation, and refuses
    /// the single-byte identity. The subgroup check is the caller's.
    pub(super) fn decode(&self, bytes: &[u8]) -> Result<Point, super::Error> {
        let f = &self.field;
        let len = f.byte_len();
        let (&tag, rest) = bytes.split_first().ok_or(super::Error::Malformed)?;
        match tag {
            0x04 if rest.len() == 2 * len => {
                let x = f.decode_be(&rest[..len]);
                let y = f.decode_be(&rest[len..]);
                let (Some(x), Some(y)) = (x, y) else {
                    return Err(super::Error::Malformed);
                };
                if bool::from(self.is_on_curve(&x, &y)) {
                    Ok(Point {
                        x,
                        y,
                        inf: Choice::from(0),
                    })
                } else {
                    Err(super::Error::InvalidInput)
                }
            }
            0x02 | 0x03 if rest.len() == len => {
                let x = f.decode_be(rest).ok_or(super::Error::Malformed)?;
                let ybit = Choice::from(tag & 1);
                // x ≠ 0: β = x + a + b·x⁻², z² + z = β, pick the root with
                // the requested constant term, y = x·z.
                let xinv = f.inv(&x);
                let beta = x.add(&self.a).add(&f.mul(&self.b, &f.sqr(&xinv)));
                let (z, ok) = f.solve_quadratic(&beta);
                let flip = z.lsb() ^ ybit;
                let z = Fe::conditional_select(&z.add(&Fe::ONE), &z, flip);
                let y = f.mul(&x, &z);
                // x = 0: y = √b, and only ỹ = 0 is a valid encoding.
                let x_zero = x.is_zero();
                let y = Fe::conditional_select(&f.sqrt(&self.b), &y, x_zero);
                let ok = Choice::conditional_select(&!ybit, &ok, x_zero);
                if bool::from(ok) {
                    Ok(Point {
                        x,
                        y,
                        inf: Choice::from(0),
                    })
                } else {
                    Err(super::Error::InvalidInput)
                }
            }
            _ => Err(super::Error::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    pub(super) const CURVES: [&Curve; 40] = ALL;

    fn scalar(v: u64) -> Limbs {
        let mut k = [0u64; MAX_LIMBS];
        k[0] = v;
        k
    }

    #[test]
    fn parameters_are_consistent() {
        for c in CURVES {
            let g = c.generator();
            assert!(bool::from(c.is_on_curve(&g.x, &g.y)), "{} G", c.name);
            // n has the documented bit length and is odd.
            let top = c.n[(c.n_bits - 1) / 64] >> ((c.n_bits - 1) % 64);
            assert_eq!(top, 1, "{} n_bits", c.name);
            assert_eq!(c.n[0] & 1, 1);
            for &l in &c.n[c.n_bits.div_ceil(64)..] {
                assert_eq!(l, 0);
            }
            assert!(c.n_bits <= c.field.m);
            assert!(
                c.oid[..4] == [1, 3, 132, 0]
                    || c.oid[..6] == [1, 2, 840, 10045, 3, 0]
                    || c.oid[..5] == [2, 23, 43, 1, 4],
                "{}",
                c.name
            );
        }
    }

    #[test]
    fn generator_order_and_cofactor() {
        for c in CURVES {
            let g = c.generator();
            let ng = c.mul(&c.n, &g);
            assert!(bool::from(ng.inf), "{} n·G = ∞", c.name);
            assert!(bool::from(c.in_subgroup(&g)));
            // h·∞ = ∞, and (n − 1)·G = −G = (x, x + y).
            assert!(bool::from(c.mul(&scalar(c.h), &ng).inf));
            let mut n1 = c.n;
            n1[0] -= 1;
            let neg = c.mul(&n1, &g);
            assert!(!bool::from(neg.inf));
            assert_eq!(neg.x.0, g.x.0, "{} (n-1)G.x", c.name);
            assert_eq!(neg.y.0, g.x.add(&g.y).0, "{} (n-1)G.y", c.name);
        }
    }

    #[test]
    fn small_multiples_agree_with_affine_addition() {
        // 2G by the affine doubling formula, 3G = 2G + G by affine addition;
        // both must match the ladder, which also validates y recovery.
        for c in CURVES {
            let f = &c.field;
            let g = c.generator();
            let one = c.mul(&scalar(1), &g);
            assert_eq!((one.x.0, one.y.0), (g.x.0, g.y.0), "{} 1·G", c.name);
            // λ = x + y/x; x₂ = λ² + λ + a; y₂ = x² + (λ + 1)·x₂.
            let lam = g.x.add(&f.mul(&g.y, &f.inv(&g.x)));
            let x2 = f.sqr(&lam).add(&lam).add(&c.a);
            let y2 = f.sqr(&g.x).add(&f.mul(&lam.add(&Fe::ONE), &x2));
            let two = c.mul(&scalar(2), &g);
            assert!(!bool::from(two.inf));
            assert_eq!((two.x.0, two.y.0), (x2.0, y2.0), "{} 2·G", c.name);
            // λ = (y₁ + y₂)/(x₁ + x₂); x₃ = λ² + λ + x₁ + x₂ + a;
            // y₃ = λ(x₁ + x₃) + x₃ + y₁.
            let lam = f.mul(&g.y.add(&y2), &f.inv(&g.x.add(&x2)));
            let x3 = f.sqr(&lam).add(&lam).add(&g.x).add(&x2).add(&c.a);
            let y3 = f.mul(&lam, &g.x.add(&x3)).add(&x3).add(&g.y);
            let three = c.mul(&scalar(3), &g);
            assert_eq!((three.x.0, three.y.0), (x3.0, y3.0), "{} 3·G", c.name);
            assert!(bool::from(c.is_on_curve(&x3, &y3)));
        }
    }

    #[test]
    fn affine_addition_matches_the_ladder() {
        for c in CURVES {
            let g = c.generator();
            let mut acc = Point {
                x: Fe::ZERO,
                y: Fe::ZERO,
                inf: Choice::from(1),
            };
            for k in 1u64..6 {
                acc = c.add_vartime(&acc, &g);
                let want = c.mul(&scalar(k), &g);
                assert_eq!((acc.x.0, acc.y.0), (want.x.0, want.y.0), "{} {k}G", c.name);
            }
            // 2·(3G) by doubling, and P + (−P) = ∞.
            let three = c.mul(&scalar(3), &g);
            let six = c.add_vartime(&three, &three);
            let want = c.mul(&scalar(6), &g);
            assert_eq!((six.x.0, six.y.0), (want.x.0, want.y.0), "{} 6G", c.name);
            let neg = Point {
                x: three.x,
                y: three.x.add(&three.y),
                inf: Choice::from(0),
            };
            assert!(bool::from(c.add_vartime(&three, &neg).inf));
        }
    }

    #[test]
    fn point_encoding_round_trips() {
        for c in CURVES {
            for k in [1u64, 2, 3, 7] {
                let p = c.mul(&scalar(k), &c.generator());
                for compressed in [false, true] {
                    let mut enc = vec![0u8; c.encoded_len(compressed)];
                    c.encode(&p, compressed, &mut enc);
                    let q = c.decode(&enc).unwrap();
                    assert_eq!((q.x.0, q.y.0), (p.x.0, p.y.0), "{} {k}G", c.name);
                    // The other compressed root is a different point: −P.
                    if compressed {
                        enc[0] ^= 1;
                        let neg = c.decode(&enc).unwrap();
                        assert_eq!(neg.y.0, p.x.add(&p.y).0);
                    }
                }
            }
            // The order-2 point (0, √b) compresses with ỹ = 0 only.
            let f = &c.field;
            let mut enc = vec![0u8; c.encoded_len(true)];
            enc[0] = 0x02;
            let p = c.decode(&enc).unwrap();
            assert_eq!(p.y.0, f.sqrt(&c.b).0);
            assert!(bool::from(c.is_on_curve(&p.x, &p.y)));
            assert!(!bool::from(c.in_subgroup(&p)));
            assert!(bool::from(c.mul(&scalar(2), &p).inf));
            enc[0] = 0x03;
            assert!(c.decode(&enc).is_err());
            let mut enc2 = vec![0u8; c.encoded_len(true)];
            c.encode(&p, true, &mut enc2);
            assert_eq!(enc2[0], 0x02);
        }
    }

    #[test]
    fn decode_rejects_bad_input() {
        let c = &SECT283K1;
        let g = c.generator();
        let mut enc = vec![0u8; c.encoded_len(false)];
        c.encode(&g, false, &mut enc);
        assert!(c.decode(&enc[..enc.len() - 1]).is_err());
        assert!(c.decode(&[0x00]).is_err());
        assert!(c.decode(&[]).is_err());
        let mut hybrid = enc.clone();
        hybrid[0] = 0x06;
        assert!(c.decode(&hybrid).is_err());
        let mut off = enc.clone();
        off[enc.len() - 1] ^= 1;
        assert_eq!(
            c.decode(&off).err(),
            Some(super::super::Error::InvalidInput)
        );
        let mut big = enc.clone();
        big[1] |= 0x80; // bit ≥ m in x
        assert_eq!(c.decode(&big).err(), Some(super::super::Error::Malformed));
    }

    #[test]
    fn scalar_comparison() {
        let a = scalar(5);
        let b = scalar(6);
        assert!(bool::from(limbs_lt(&a, &b)));
        assert!(!bool::from(limbs_lt(&b, &a)));
        assert!(!bool::from(limbs_lt(&a, &a)));
        let mut hi = scalar(0);
        hi[3] = 1;
        assert!(bool::from(limbs_lt(&b, &hi)));
        assert!(!bool::from(limbs_lt(&hi, &b)));
        assert!(bool::from(limbs_is_zero(&scalar(0))));
        assert!(!bool::from(limbs_is_zero(&a)));
    }
}
