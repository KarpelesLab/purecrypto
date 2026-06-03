//! LM-OTS and LMS parameter sets (RFC 8554 §4.1, §5.1, Tables 1 and 2).

/// Domain-separation constant for the LM-OTS public-key hash (RFC 8554 §4.3).
pub(crate) const D_PBLC: u16 = 0x8080;
/// Domain-separation constant for the LM-OTS message hash (RFC 8554 §4.5).
pub(crate) const D_MESG: u16 = 0x8181;
/// Domain-separation constant for an LMS leaf hash (RFC 8554 §5.3).
pub(crate) const D_LEAF: u16 = 0x8282;
/// Domain-separation constant for an LMS interior-node hash (RFC 8554 §5.3).
pub(crate) const D_INTR: u16 = 0x8383;

/// The hash output length, in bytes. Every parameter set in this module uses
/// SHA-256 with `n = m = 32`.
pub(crate) const N: usize = 32;

/// The maximum number of Winternitz chains across the supported LM-OTS sets
/// (`p = 265` for `w = 1`). Used to size fixed buffers.
pub(crate) const MAX_P: usize = 265;

/// An LM-OTS parameter set: SHA-256, `n = 32`, Winternitz width `w`.
///
/// The numeric typecodes are the LM-OTS registry values from RFC 8554 §4.1.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum LmotsType {
    /// LMOTS_SHA256_N32_W1 (`w = 1`, `p = 265`).
    Sha256N32W1 = 1,
    /// LMOTS_SHA256_N32_W2 (`w = 2`, `p = 133`).
    Sha256N32W2 = 2,
    /// LMOTS_SHA256_N32_W4 (`w = 4`, `p = 67`).
    Sha256N32W4 = 3,
    /// LMOTS_SHA256_N32_W8 (`w = 8`, `p = 34`).
    Sha256N32W8 = 4,
}

impl LmotsType {
    /// Maps a wire typecode to a known LM-OTS parameter set.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1 => LmotsType::Sha256N32W1,
            2 => LmotsType::Sha256N32W2,
            3 => LmotsType::Sha256N32W4,
            4 => LmotsType::Sha256N32W8,
            _ => return None,
        })
    }

    /// The wire typecode.
    pub(crate) fn typecode(self) -> u32 {
        self as u32
    }

    /// The Winternitz width `w` in bits (one of 1, 2, 4, 8).
    pub(crate) fn w(self) -> u32 {
        match self {
            LmotsType::Sha256N32W1 => 1,
            LmotsType::Sha256N32W2 => 2,
            LmotsType::Sha256N32W4 => 4,
            LmotsType::Sha256N32W8 => 8,
        }
    }

    /// The number of Winternitz chains `p` (RFC 8554 Table 1 / Appendix B).
    pub(crate) fn p(self) -> usize {
        match self {
            LmotsType::Sha256N32W1 => 265,
            LmotsType::Sha256N32W2 => 133,
            LmotsType::Sha256N32W4 => 67,
            LmotsType::Sha256N32W8 => 34,
        }
    }

    /// The checksum left-shift `ls` (RFC 8554 Table 1 / Appendix B).
    pub(crate) fn ls(self) -> u32 {
        match self {
            LmotsType::Sha256N32W1 => 7,
            LmotsType::Sha256N32W2 => 6,
            LmotsType::Sha256N32W4 => 4,
            LmotsType::Sha256N32W8 => 0,
        }
    }

    /// `2^w - 1`, the maximum Winternitz coefficient / chain length.
    pub(crate) fn max_digit(self) -> u32 {
        (1u32 << self.w()) - 1
    }

    /// The serialized LM-OTS signature length: `4 + n*(p+1)` bytes.
    pub(crate) fn sig_len(self) -> usize {
        4 + N * (self.p() + 1)
    }
}

/// An LMS parameter set: SHA-256, `m = 32`, Merkle tree of height `h`.
///
/// The numeric typecodes are the LMS registry values from RFC 8554 §5.1.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum LmsType {
    /// LMS_SHA256_M32_H5 (`h = 5`, 32 leaves).
    Sha256M32H5 = 5,
    /// LMS_SHA256_M32_H10 (`h = 10`, 1024 leaves).
    Sha256M32H10 = 6,
    /// LMS_SHA256_M32_H15 (`h = 15`, 32768 leaves).
    Sha256M32H15 = 7,
    /// LMS_SHA256_M32_H20 (`h = 20`, ~1M leaves).
    Sha256M32H20 = 8,
    /// LMS_SHA256_M32_H25 (`h = 25`, ~33M leaves).
    Sha256M32H25 = 9,
}

impl LmsType {
    /// Maps a wire typecode to a known LMS parameter set.
    pub(crate) fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            5 => LmsType::Sha256M32H5,
            6 => LmsType::Sha256M32H10,
            7 => LmsType::Sha256M32H15,
            8 => LmsType::Sha256M32H20,
            9 => LmsType::Sha256M32H25,
            _ => return None,
        })
    }

    /// The wire typecode.
    pub(crate) fn typecode(self) -> u32 {
        self as u32
    }

    /// The Merkle tree height `h`.
    pub(crate) fn h(self) -> u32 {
        match self {
            LmsType::Sha256M32H5 => 5,
            LmsType::Sha256M32H10 => 10,
            LmsType::Sha256M32H15 => 15,
            LmsType::Sha256M32H20 => 20,
            LmsType::Sha256M32H25 => 25,
        }
    }

    /// The number of leaves `2^h`.
    pub(crate) fn leaves(self) -> u64 {
        1u64 << self.h()
    }
}
