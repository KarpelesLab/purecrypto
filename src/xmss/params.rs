//! XMSS / XMSS^MT parameter sets (RFC 8391 §5, NIST SP 800-208).
//!
//! Only the Winternitz `w = 16` sets are provided (every standardized XMSS set
//! uses `w = 16`). The hash family, output length `n`, total tree height, and —
//! for XMSS^MT — the number of layers `d` derive every other quantity.

/// Largest `n` over the supported sets (SHA2-256 / SHAKE = 32 bytes).
pub(crate) const MAX_N: usize = 32;
/// `w = 16` ⇒ `len_2 = 3`; `len_1 = 8n/4 = 2n` ⇒ at most `2·32 + 3 = 67`.
pub(crate) const MAX_WOTS_LEN: usize = 67;

/// The underlying hash family.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum HashFamily {
    /// SHA-256 (output truncated to `n` for `n < 32`).
    Sha2_256,
    /// SHAKE128, squeezed to `n` bytes.
    Shake128,
    /// SHAKE256, squeezed to `n` bytes.
    Shake256,
}

/// A fully resolved XMSS / XMSS^MT parameter set.
#[derive(Clone, Copy)]
pub(crate) struct Params {
    /// Hash output length in bytes.
    pub n: usize,
    /// Length in bytes of the domain-separation prefix `toByte(X, padding_len)`.
    pub padding_len: usize,
    /// Total (hyper)tree height `h`.
    pub full_height: u32,
    /// Number of layers `d` (1 for XMSS, > 1 for XMSS^MT).
    pub d: u32,
    /// Per-subtree height `h / d`.
    pub tree_height: u32,
    /// `log2(w)`; 4 for `w = 16`.
    pub wots_log_w: u32,
    /// `w - 1`, the maximum chain length step.
    pub wots_w: u32,
    /// `len_1 = 8n / log2(w)`.
    pub wots_len1: usize,
    /// `len_2` (always 3 for `w = 16`).
    pub wots_len2: usize,
    /// `len = len_1 + len_2`, the number of WOTS+ chains.
    pub wots_len: usize,
    /// The hash family.
    pub family: HashFamily,
    /// Index bytes in the signature/secret key (`ceil(h/8)`, min 4 for XMSS).
    pub index_bytes: usize,
}

impl Params {
    /// Bytes in a single WOTS+ signature (`len · n`).
    pub(crate) fn wots_sig_bytes(&self) -> usize {
        self.wots_len * self.n
    }

    /// Bytes in a full XMSS / XMSS^MT signature.
    pub(crate) fn sig_bytes(&self) -> usize {
        self.index_bytes
            + self.n
            + self.d as usize * self.wots_sig_bytes()
            + self.full_height as usize * self.n
    }

    /// Bytes in the raw secret key payload: `idx ‖ SK_SEED ‖ SK_PRF ‖ root ‖ PUB_SEED`.
    pub(crate) fn sk_bytes(&self) -> usize {
        self.index_bytes + 4 * self.n
    }

    /// Bytes in the raw public key payload (`root ‖ PUB_SEED`).
    pub(crate) fn pk_bytes(&self) -> usize {
        2 * self.n
    }

    /// The lowest leaf index that counts as "exhausted" (the first index at
    /// which [`sign`](crate::xmss::XmssMtPrivateKey::sign) must refuse).
    ///
    /// Normally this is `2^full_height`: every leaf `0..2^h` is signable and the
    /// post-increment sentinel `2^h` is stored to mark the key spent. But when
    /// `index_bytes * 8 == full_height` (the XMSS^MT h=40 sets, where the index
    /// field is exactly `h` bits wide) the sentinel `2^h` is unrepresentable and
    /// would wrap to `0`, silently re-enabling leaf 0 and reusing its WOTS+
    /// one-time key. In that case the last leaf is sacrificed: the highest
    /// signable index is `2^h - 2`, leaving `2^h - 1` (all-ones) as the
    /// representable exhausted sentinel. Matches the xmss reference behaviour.
    ///
    /// Returns `None` when `full_height >= 64` (the index can never overflow a
    /// `u64`, so the key never exhausts within representable state).
    pub(crate) fn exhausted_index(&self) -> Option<u64> {
        if self.full_height >= 64 {
            return None;
        }
        let total = 1u64 << self.full_height;
        if self.index_bytes * 8 == self.full_height as usize {
            // Sentinel `2^h` does not fit in `index_bytes`; stop one leaf early.
            Some(total - 1)
        } else {
            Some(total)
        }
    }
}

/// Builds the derived fields from the core inputs.
const fn make(n: usize, full_height: u32, d: u32, family: HashFamily) -> Params {
    // padding_len follows the reference: 4 for n=24, otherwise n.
    let padding_len = if n == 24 { 4 } else { n };
    let wots_log_w = 4; // w = 16
    let wots_len1 = (8 * n) / wots_log_w as usize;
    let wots_len2 = 3;
    let index_bytes = if d == 1 {
        4
    } else {
        (full_height as usize).div_ceil(8)
    };
    Params {
        n,
        padding_len,
        full_height,
        d,
        tree_height: full_height / d,
        wots_log_w,
        wots_w: 16,
        wots_len1,
        wots_len2,
        wots_len: wots_len1 + wots_len2,
        family,
        index_bytes,
    }
}

/// The XMSS parameter sets this crate supports (RFC 8391 §5.3, SP 800-208).
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum XmssParamSet {
    /// XMSS-SHA2_10_256 (OID 0x00000001).
    Sha2_10_256 = 0x0000_0001,
    /// XMSS-SHA2_16_256 (OID 0x00000002).
    Sha2_16_256 = 0x0000_0002,
    /// XMSS-SHA2_20_256 (OID 0x00000003).
    Sha2_20_256 = 0x0000_0003,
    /// XMSS-SHAKE_10_256 (SHAKE128, OID 0x00000007).
    Shake_10_256 = 0x0000_0007,
    /// XMSS-SHAKE_16_256 (SHAKE128, OID 0x00000008).
    Shake_16_256 = 0x0000_0008,
    /// XMSS-SHAKE_20_256 (SHAKE128, OID 0x00000009).
    Shake_20_256 = 0x0000_0009,
    /// XMSS-SHA2_10_192 (OID 0x0000000d).
    Sha2_10_192 = 0x0000_000d,
    /// XMSS-SHA2_16_192 (OID 0x0000000e).
    Sha2_16_192 = 0x0000_000e,
    /// XMSS-SHA2_20_192 (OID 0x0000000f).
    Sha2_20_192 = 0x0000_000f,
    /// XMSS-SHAKE256_10_256 (SHAKE256, OID 0x00000010).
    Shake256_10_256 = 0x0000_0010,
    /// XMSS-SHAKE256_16_256 (SHAKE256, OID 0x00000011).
    Shake256_16_256 = 0x0000_0011,
    /// XMSS-SHAKE256_20_256 (SHAKE256, OID 0x00000012).
    Shake256_20_256 = 0x0000_0012,
}

impl XmssParamSet {
    /// The 32-bit XMSS algorithm OID (RFC 8391 / IANA registry).
    pub fn oid(self) -> u32 {
        self as u32
    }

    /// Looks up a parameter set by its 32-bit OID.
    pub fn from_oid(oid: u32) -> Option<Self> {
        use XmssParamSet::*;
        Some(match oid {
            0x0000_0001 => Sha2_10_256,
            0x0000_0002 => Sha2_16_256,
            0x0000_0003 => Sha2_20_256,
            0x0000_0007 => Shake_10_256,
            0x0000_0008 => Shake_16_256,
            0x0000_0009 => Shake_20_256,
            0x0000_000d => Sha2_10_192,
            0x0000_000e => Sha2_16_192,
            0x0000_000f => Sha2_20_192,
            0x0000_0010 => Shake256_10_256,
            0x0000_0011 => Shake256_16_256,
            0x0000_0012 => Shake256_20_256,
            _ => return None,
        })
    }

    pub(crate) fn params(self) -> Params {
        use HashFamily::*;
        use XmssParamSet::*;
        match self {
            Sha2_10_256 => make(32, 10, 1, Sha2_256),
            Sha2_16_256 => make(32, 16, 1, Sha2_256),
            Sha2_20_256 => make(32, 20, 1, Sha2_256),
            Shake_10_256 => make(32, 10, 1, Shake128),
            Shake_16_256 => make(32, 16, 1, Shake128),
            Shake_20_256 => make(32, 20, 1, Shake128),
            Sha2_10_192 => make(24, 10, 1, Sha2_256),
            Sha2_16_192 => make(24, 16, 1, Sha2_256),
            Sha2_20_192 => make(24, 20, 1, Sha2_256),
            Shake256_10_256 => make(32, 10, 1, Shake256),
            Shake256_16_256 => make(32, 16, 1, Shake256),
            Shake256_20_256 => make(32, 20, 1, Shake256),
        }
    }
}

/// The XMSS^MT parameter sets this crate supports (RFC 8391 §5.4).
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum XmssMtParamSet {
    /// XMSSMT-SHA2_20/2_256 (OID 0x00000001).
    Sha2_20_2_256 = 0x0000_0001,
    /// XMSSMT-SHA2_20/4_256 (OID 0x00000002).
    Sha2_20_4_256 = 0x0000_0002,
    /// XMSSMT-SHA2_40/2_256 (OID 0x00000003).
    Sha2_40_2_256 = 0x0000_0003,
    /// XMSSMT-SHA2_40/4_256 (OID 0x00000004).
    Sha2_40_4_256 = 0x0000_0004,
    /// XMSSMT-SHA2_40/8_256 (OID 0x00000005).
    Sha2_40_8_256 = 0x0000_0005,
    /// XMSSMT-SHA2_60/3_256 (OID 0x00000006).
    Sha2_60_3_256 = 0x0000_0006,
    /// XMSSMT-SHA2_60/6_256 (OID 0x00000007).
    Sha2_60_6_256 = 0x0000_0007,
    /// XMSSMT-SHA2_60/12_256 (OID 0x00000008).
    Sha2_60_12_256 = 0x0000_0008,
    /// XMSSMT-SHAKE_20/2_256 (SHAKE128, OID 0x00000011).
    Shake_20_2_256 = 0x0000_0011,
    /// XMSSMT-SHAKE_20/4_256 (SHAKE128, OID 0x00000012).
    Shake_20_4_256 = 0x0000_0012,
}

impl XmssMtParamSet {
    /// The 32-bit XMSS^MT algorithm OID (RFC 8391 / IANA registry).
    pub fn oid(self) -> u32 {
        self as u32
    }

    /// Looks up a parameter set by its 32-bit OID.
    pub fn from_oid(oid: u32) -> Option<Self> {
        use XmssMtParamSet::*;
        Some(match oid {
            0x0000_0001 => Sha2_20_2_256,
            0x0000_0002 => Sha2_20_4_256,
            0x0000_0003 => Sha2_40_2_256,
            0x0000_0004 => Sha2_40_4_256,
            0x0000_0005 => Sha2_40_8_256,
            0x0000_0006 => Sha2_60_3_256,
            0x0000_0007 => Sha2_60_6_256,
            0x0000_0008 => Sha2_60_12_256,
            0x0000_0011 => Shake_20_2_256,
            0x0000_0012 => Shake_20_4_256,
            _ => return None,
        })
    }

    pub(crate) fn params(self) -> Params {
        use HashFamily::*;
        use XmssMtParamSet::*;
        match self {
            Sha2_20_2_256 => make(32, 20, 2, Sha2_256),
            Sha2_20_4_256 => make(32, 20, 4, Sha2_256),
            Sha2_40_2_256 => make(32, 40, 2, Sha2_256),
            Sha2_40_4_256 => make(32, 40, 4, Sha2_256),
            Sha2_40_8_256 => make(32, 40, 8, Sha2_256),
            Sha2_60_3_256 => make(32, 60, 3, Sha2_256),
            Sha2_60_6_256 => make(32, 60, 6, Sha2_256),
            Sha2_60_12_256 => make(32, 60, 12, Sha2_256),
            Shake_20_2_256 => make(32, 20, 2, Shake128),
            Shake_20_4_256 => make(32, 20, 4, Shake128),
        }
    }
}
