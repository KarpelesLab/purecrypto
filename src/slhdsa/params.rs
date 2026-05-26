//! SLH-DSA parameter sets (FIPS 205 Table 2).

/// Maximum security parameter (hash output bytes).
pub(crate) const MAX_N: usize = 32;
/// Maximum message-digest size.
pub(crate) const MAX_M: usize = 49;
/// Maximum number of FORS trees.
pub(crate) const MAX_K: usize = 35;
/// Maximum WOTS+ chain count (`2·n + 3`).
pub(crate) const MAX_WOTS_LEN: usize = 67;
/// Maximum signing context length.
pub(crate) const MAX_CONTEXT: usize = 255;

/// An SLH-DSA parameter set.
#[derive(Clone, Copy)]
pub(crate) struct Params {
    /// Use SHAKE256 (true) or SHA-2 (false) for the tweakable hashes.
    pub(crate) is_shake: bool,
    /// Security parameter (hash output bytes): 16, 24, or 32.
    pub(crate) n: u32,
    /// Total hypertree height.
    pub(crate) h: u32,
    /// Number of hypertree layers.
    pub(crate) d: u32,
    /// Height of each XMSS tree (`h = h_prime · d`).
    pub(crate) h_prime: u32,
    /// FORS tree height.
    pub(crate) a: u32,
    /// Number of FORS trees.
    pub(crate) k: u32,
    /// Message-digest size.
    pub(crate) m: u32,
    /// WOTS+ chain count (`2·n + 3`).
    pub(crate) len: u32,
    /// Signature size in bytes.
    pub(crate) sig_size: usize,
    /// Public-key size (`2·n`).
    pub(crate) pk_size: usize,
    /// Private-key size (`4·n`).
    pub(crate) sk_size: usize,
    /// PKIX algorithm OID arcs.
    pub(crate) oid: &'static [u64],
}

impl Params {
    /// FORS message-digest length in bytes.
    pub(crate) fn md_len(&self) -> usize {
        ((self.k * self.a + 7) >> 3) as usize
    }
    /// Byte length of the tree index.
    pub(crate) fn tree_idx_len(&self) -> usize {
        ((self.h - self.h_prime + 7) >> 3) as usize
    }
    /// Bit mask for the tree index.
    pub(crate) fn tree_idx_mask(&self) -> u64 {
        (1u64 << (self.h - self.h_prime)) - 1
    }
    /// Byte length of the leaf index.
    pub(crate) fn leaf_idx_len(&self) -> usize {
        ((self.h_prime + 7) >> 3) as usize
    }
    /// Bit mask for the leaf index.
    pub(crate) fn leaf_idx_mask(&self) -> u64 {
        (1u64 << self.h_prime) - 1
    }
}

/// The twelve standardized parameter sets, exposed via [`ParamSet`].
pub(crate) const SETS: [Params; 12] = [
    // SHA-2.
    p(
        false,
        16,
        63,
        7,
        9,
        12,
        14,
        30,
        35,
        7856,
        32,
        64,
        &[2, 16, 840, 1, 101, 3, 4, 3, 20],
    ),
    p(
        false,
        16,
        66,
        22,
        3,
        6,
        33,
        34,
        35,
        17088,
        32,
        64,
        &[2, 16, 840, 1, 101, 3, 4, 3, 21],
    ),
    p(
        false,
        24,
        63,
        7,
        9,
        14,
        17,
        39,
        51,
        16224,
        48,
        96,
        &[2, 16, 840, 1, 101, 3, 4, 3, 22],
    ),
    p(
        false,
        24,
        66,
        22,
        3,
        8,
        33,
        42,
        51,
        35664,
        48,
        96,
        &[2, 16, 840, 1, 101, 3, 4, 3, 23],
    ),
    p(
        false,
        32,
        64,
        8,
        8,
        14,
        22,
        47,
        67,
        29792,
        64,
        128,
        &[2, 16, 840, 1, 101, 3, 4, 3, 24],
    ),
    p(
        false,
        32,
        68,
        17,
        4,
        9,
        35,
        49,
        67,
        49856,
        64,
        128,
        &[2, 16, 840, 1, 101, 3, 4, 3, 25],
    ),
    // SHAKE.
    p(
        true,
        16,
        63,
        7,
        9,
        12,
        14,
        30,
        35,
        7856,
        32,
        64,
        &[2, 16, 840, 1, 101, 3, 4, 3, 26],
    ),
    p(
        true,
        16,
        66,
        22,
        3,
        6,
        33,
        34,
        35,
        17088,
        32,
        64,
        &[2, 16, 840, 1, 101, 3, 4, 3, 27],
    ),
    p(
        true,
        24,
        63,
        7,
        9,
        14,
        17,
        39,
        51,
        16224,
        48,
        96,
        &[2, 16, 840, 1, 101, 3, 4, 3, 28],
    ),
    p(
        true,
        24,
        66,
        22,
        3,
        8,
        33,
        42,
        51,
        35664,
        48,
        96,
        &[2, 16, 840, 1, 101, 3, 4, 3, 29],
    ),
    p(
        true,
        32,
        64,
        8,
        8,
        14,
        22,
        47,
        67,
        29792,
        64,
        128,
        &[2, 16, 840, 1, 101, 3, 4, 3, 30],
    ),
    p(
        true,
        32,
        68,
        17,
        4,
        9,
        35,
        49,
        67,
        49856,
        64,
        128,
        &[2, 16, 840, 1, 101, 3, 4, 3, 31],
    ),
];

#[allow(clippy::too_many_arguments)]
const fn p(
    is_shake: bool,
    n: u32,
    h: u32,
    d: u32,
    h_prime: u32,
    a: u32,
    k: u32,
    m: u32,
    len: u32,
    sig_size: usize,
    pk_size: usize,
    sk_size: usize,
    oid: &'static [u64],
) -> Params {
    Params {
        is_shake,
        n,
        h,
        d,
        h_prime,
        a,
        k,
        m,
        len,
        sig_size,
        pk_size,
        sk_size,
        oid,
    }
}
