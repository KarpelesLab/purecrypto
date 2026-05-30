//! Z_q arithmetic (q = 8380417) and the length-256 NTT for ML-DSA (FIPS 204).
//!
//! Field elements are `u32` in `[0, q)`. Multiplication uses Montgomery
//! reduction with `R = 2³²`; the twiddle table [`ZETAS`] is pre-scaled by `R`
//! so the NTT keeps values in the ordinary domain (the `R⁻¹` from each
//! `field_mul` cancels the `R` baked into the zeta), exactly as the reference.

// `Poly` and its inherent methods are `pub` (not `pub(crate)`) so the
// `hazmat-mldsa` surface can re-export them — a re-export cannot widen a
// `pub(crate)` item to `pub`, so the items themselves must be `pub`. When the
// `hazmat-mldsa` feature is off, this private `field` module is not reachable
// through any public path, so those items are (correctly) unreachable from
// outside the crate; suppress the otherwise-spurious lint in that config only.
#![cfg_attr(not(feature = "hazmat-mldsa"), allow(unreachable_pub))]

/// Number of coefficients in a polynomial.
pub(crate) const N: usize = 256;
/// The modulus `q = 2²³ − 2¹³ + 1`.
pub(crate) const Q: u32 = 8380417;
/// Dropped low bits in Power2Round.
pub(crate) const D: u32 = 13;
/// `(q − 1) / 2`, the centering threshold.
pub(crate) const Q_MINUS_1_DIV2: u32 = (Q - 1) / 2;

/// `−q⁻¹ mod 2³²`.
const Q_NEG_INV: u32 = 4236238847;
/// `n⁻¹ · R² mod q`, the inverse-NTT scaling factor.
const INV_N: u32 = 41978;

/// Reduces a value in `[0, 2q)` to `[0, q)`.
#[inline]
pub(crate) fn reduce_once(a: u32) -> u32 {
    let x = a.wrapping_sub(Q);
    x.wrapping_add((x >> 31).wrapping_mul(Q))
}

/// `(a + b) mod q` for `a, b < q`.
#[inline]
pub(crate) fn add(a: u32, b: u32) -> u32 {
    reduce_once(a + b)
}

/// `(a − b) mod q` for `a, b < q`.
#[inline]
pub(crate) fn sub(a: u32, b: u32) -> u32 {
    reduce_once(a + Q - b)
}

/// Montgomery reduction: `a · R⁻¹ mod q` for `a < q · 2³²`.
#[inline]
fn mont_reduce(a: u64) -> u32 {
    let t = (a as u32).wrapping_mul(Q_NEG_INV);
    reduce_once((a.wrapping_add((t as u64).wrapping_mul(Q as u64)) >> 32) as u32)
}

/// Montgomery multiplication; with a Montgomery-domain `zeta` argument this
/// yields the ordinary-domain product.
#[inline]
pub(crate) fn mul(a: u32, b: u32) -> u32 {
    mont_reduce(a as u64 * b as u64)
}

/// A degree-255 polynomial (ring or NTT element; same representation).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Poly {
    /// The 256 coefficients, each a field element in `[0, q)`.
    pub c: [u32; N],
}

impl Poly {
    /// The zero polynomial.
    pub fn zero() -> Self {
        Poly { c: [0; N] }
    }

    /// Coefficient-wise `self + other`.
    pub fn add(&self, other: &Poly) -> Poly {
        let mut r = Poly::zero();
        for i in 0..N {
            r.c[i] = add(self.c[i], other.c[i]);
        }
        r
    }

    /// Coefficient-wise `self − other`.
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut r = Poly::zero();
        for i in 0..N {
            r.c[i] = sub(self.c[i], other.c[i]);
        }
        r
    }

    /// Forward NTT (FIPS 204 Algorithm 41), in place.
    pub fn ntt(&mut self) {
        let f = &mut self.c;
        let mut k = 1;
        let mut len = 128;
        while len >= 1 {
            let mut start = 0;
            while start < N {
                let zeta = ZETAS[k];
                k += 1;
                for j in start..start + len {
                    let t = mul(zeta, f[j + len]);
                    f[j + len] = sub(f[j], t);
                    f[j] = add(f[j], t);
                }
                start += 2 * len;
            }
            len /= 2;
        }
    }

    /// Inverse NTT (FIPS 204 Algorithm 42), in place.
    pub fn inv_ntt(&mut self) {
        let f = &mut self.c;
        let mut k = 255;
        let mut len = 1;
        while len < N {
            let mut start = 0;
            while start < N {
                let zeta = Q - ZETAS[k]; // −zeta
                k -= 1;
                for j in start..start + len {
                    let t = f[j];
                    f[j] = add(t, f[j + len]);
                    f[j + len] = mul(zeta, sub(t, f[j + len]));
                }
                start += 2 * len;
            }
            len *= 2;
        }
        for x in f.iter_mut() {
            *x = mul(*x, INV_N);
        }
    }
}

/// Component-wise product of two NTT-domain polynomials (`a[i]·b[i]·R⁻¹`).
pub(crate) fn ntt_mul(a: &Poly, b: &Poly) -> Poly {
    let mut c = Poly::zero();
    for i in 0..N {
        c.c[i] = mul(a.c[i], b.c[i]);
    }
    c
}

/// Read-only accessor for the `i`-th twiddle factor (Montgomery form), for
/// hazmat callers doing manual NTT-domain work. Panics if `i >= N`.
#[cfg(feature = "hazmat-mldsa")]
pub(crate) fn zeta(i: usize) -> u32 {
    ZETAS[i]
}

/// Twiddle factors `1753^bitrev(k) · R mod q`, in Montgomery form.
static ZETAS: [u32; N] = [
    4193792, 25847, 5771523, 7861508, 237124, 7602457, 7504169, 466468, 1826347, 2353451, 8021166,
    6288512, 3119733, 5495562, 3111497, 2680103, 2725464, 1024112, 7300517, 3585928, 7830929,
    7260833, 2619752, 6271868, 6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, 6718724, 4788269, 5842901, 3915439, 4519302, 5336701,
    3574422, 5512770, 3539968, 8079950, 2348700, 7841118, 6681150, 6736599, 3505694, 4558682,
    3507263, 6239768, 6779997, 3699596, 811944, 531354, 954230, 3881043, 3900724, 5823537, 2071892,
    5582638, 4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196, 7122806,
    1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922, 3412210, 7396998, 2147896,
    2715295, 5412772, 4686924, 7969390, 5903370, 7709315, 7151892, 8357436, 7072248, 7998430,
    1349076, 1852771, 6949987, 5037034, 264944, 508951, 3097992, 44288, 7280319, 904516, 3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969, 7063561, 189548, 4827145,
    3159746, 6529015, 5971092, 8202977, 1315589, 1341330, 1285669, 6795489, 7567685, 6940675,
    5361315, 4499357, 4751448, 3839961, 2091667, 3407706, 2316500, 3817976, 5037939, 2244091,
    5933984, 4817955, 266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
    900702, 1859098, 909542, 819034, 495491, 6767243, 8337157, 7857917, 7725090, 5257975, 2031748,
    3207046, 4823422, 7855319, 7611795, 4784579, 342297, 286988, 5942594, 4108315, 3437287,
    5038140, 1735879, 203044, 2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353,
    1595974, 4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447, 7047359,
    1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775, 7100756, 1917081, 5834105,
    7005614, 1500165, 777191, 2235880, 3406031, 7838005, 5548557, 6709241, 6533464, 5796124,
    4656147, 594136, 4603424, 6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531,
    7173032, 5196991, 162844, 1616392, 3014001, 810149, 1652634, 4686184, 6581310, 5341501,
    3523897, 3866901, 269760, 2213111, 7404533, 1717735, 472078, 7953734, 1723600, 6577327,
    1910376, 6712985, 7276084, 8119771, 4546524, 5441381, 6144432, 7959518, 6094090, 183443,
    7403526, 1612842, 4834730, 7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263,
    1976782,
];
