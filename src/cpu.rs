//! Run-time CPU feature detection that does not need `std`.
//!
//! Every hardware backend in the crate (SHA-NI, AES-NI, PCLMULQDQ, AVX2,
//! AVX-512, the aarch64 crypto extensions) asks this module whether its
//! instructions may run, so the answer is the same everywhere and a `no_std`
//! build gets the same hardware paths as a `std` one.
//!
//! - **x86_64**: `CPUID` (leaves 1 and 7) read through `core::arch`, cached in
//!   an atomic after the first query. AVX/AVX2/AVX-512 additionally require
//!   the OS to have enabled the wider register state: `CPUID.1:ECX.OSXSAVE`
//!   and the matching `XCR0` bits (YMM for AVX2; opmask/ZMM for AVX-512),
//!   read with `XGETBV`. The SSE-class extensions (SHA-NI, AES-NI, PCLMULQDQ,
//!   SSSE3, SSE4.1) use only the XMM registers. A target whose ABI does not
//!   itself use SSE (`target_feature = "sse2"` off, e.g. a soft-float kernel
//!   target, which may run with the FPU disabled) reports nothing at all.
//!   This matches what `std::is_x86_feature_detected!` answers.
//! - **aarch64**: with `std`, `std::arch::is_aarch64_feature_detected!` (it
//!   asks the OS, e.g. `getauxval(AT_HWCAP)` on Linux). Without `std` there is
//!   no portable way to ask — `ID_AA64ISAR0_EL1` is not readable from EL0 on
//!   every OS — so the answer is the compile-time
//!   `cfg!(target_feature = "...")`: build with e.g.
//!   `-C target-feature=+sha2,+aes` (or a `-C target-cpu` that has them) to
//!   get the hardware paths in a `no_std` aarch64 build.
//!
//! Callers still check [`crate::ct::force_portable`] themselves; this module
//! only reports what the hardware can do.
// Each backend uses only some of these probes, and which backends are compiled
// depends on the feature set and target.
#![allow(dead_code)]

#[cfg(target_arch = "x86_64")]
mod x86 {
    use core::sync::atomic::{AtomicU32, Ordering};

    pub(super) const SSE2: u32 = 1 << 0;
    pub(super) const SSSE3: u32 = 1 << 1;
    pub(super) const SSE41: u32 = 1 << 2;
    pub(super) const AES: u32 = 1 << 3;
    pub(super) const PCLMULQDQ: u32 = 1 << 4;
    pub(super) const SHA: u32 = 1 << 5;
    pub(super) const AVX2: u32 = 1 << 6;
    pub(super) const AVX512F: u32 = 1 << 7;
    pub(super) const AVX512BW: u32 = 1 << 8;
    pub(super) const BMI1: u32 = 1 << 9;
    pub(super) const BMI2: u32 = 1 << 10;
    pub(super) const AVX512VL: u32 = 1 << 11;
    pub(super) const AVX512IFMA: u32 = 1 << 12;
    /// Set once the cache holds a detection result.
    const READY: u32 = 1 << 31;

    static CACHE: AtomicU32 = AtomicU32::new(0);

    /// The detected feature bits. Racing first calls each run the (idempotent)
    /// detection and store the same value.
    #[inline]
    pub(super) fn features() -> u32 {
        let cached = CACHE.load(Ordering::Relaxed);
        if cached & READY != 0 {
            return cached;
        }
        let detected = detect() | READY;
        CACHE.store(detected, Ordering::Relaxed);
        detected
    }

    /// `XGETBV` with `ECX = 0`: the OS-enabled state components (`XCR0`).
    ///
    /// # Safety
    /// The CPU must report `OSXSAVE` (`CPUID.1:ECX` bit 27); otherwise the
    /// instruction raises #UD.
    #[target_feature(enable = "xsave")]
    #[allow(unsafe_code)]
    unsafe fn xcr0() -> u64 {
        // SAFETY: the caller has checked `OSXSAVE`.
        unsafe { core::arch::x86_64::_xgetbv(0) }
    }

    #[cold]
    #[allow(unsafe_code, unused_unsafe)]
    fn detect() -> u32 {
        use core::arch::x86_64::{__cpuid, __cpuid_count};

        if !cfg!(target_feature = "sse2") {
            return 0;
        }
        // SAFETY: `CPUID` exists on every x86_64 CPU (newer toolchains make
        // these intrinsics safe, hence `unused_unsafe`).
        let max_leaf = unsafe { __cpuid(0) }.eax;
        let l1 = unsafe { __cpuid(1) };
        let (ebx7, max7) = if max_leaf >= 7 {
            // SAFETY: as above; leaf 7 is in range.
            let l7 = unsafe { __cpuid_count(7, 0) };
            (l7.ebx, true)
        } else {
            (0, false)
        };
        let bit = |reg: u32, n: u32| reg & (1 << n) != 0;

        let mut f = 0;
        if bit(l1.edx, 26) {
            f |= SSE2;
        }
        if bit(l1.ecx, 9) {
            f |= SSSE3;
        }
        if bit(l1.ecx, 19) {
            f |= SSE41;
        }
        if bit(l1.ecx, 25) {
            f |= AES;
        }
        if bit(l1.ecx, 1) {
            f |= PCLMULQDQ;
        }
        if max7 && bit(ebx7, 29) {
            f |= SHA;
        }
        if max7 && bit(ebx7, 3) {
            f |= BMI1;
        }
        if max7 && bit(ebx7, 8) {
            f |= BMI2;
        }

        // The wide-register extensions also need the OS to save that state.
        let osxsave = bit(l1.ecx, 27);
        let avx = bit(l1.ecx, 28);
        if osxsave && avx && max7 {
            // SAFETY: `OSXSAVE` was just checked.
            let xcr0 = unsafe { xcr0() };
            let ymm = xcr0 & 0b110 == 0b110; // SSE + AVX state
            let zmm = xcr0 & 0b1110_0000 == 0b1110_0000; // opmask + ZMM_Hi256 + Hi16_ZMM
            if ymm && bit(ebx7, 5) {
                f |= AVX2;
            }
            if ymm && zmm && bit(ebx7, 16) {
                f |= AVX512F;
                if bit(ebx7, 30) {
                    f |= AVX512BW;
                }
                if bit(ebx7, 31) {
                    f |= AVX512VL;
                }
                if bit(ebx7, 21) {
                    f |= AVX512IFMA;
                }
            }
        }
        f
    }

    #[inline]
    pub(super) fn has(mask: u32) -> bool {
        features() & mask == mask
    }
}

#[cfg(target_arch = "x86_64")]
mod x86_api {
    use super::x86::*;

    /// SSE2 (always present on x86_64 targets that use SSE at all).
    #[inline]
    pub(crate) fn sse2() -> bool {
        has(SSE2)
    }
    /// SSSE3.
    #[inline]
    pub(crate) fn ssse3() -> bool {
        has(SSSE3)
    }
    /// SSE4.1.
    #[inline]
    pub(crate) fn sse41() -> bool {
        has(SSE41)
    }
    /// AES-NI.
    #[inline]
    pub(crate) fn aes() -> bool {
        has(AES)
    }
    /// PCLMULQDQ (carry-less multiply).
    #[inline]
    pub(crate) fn pclmulqdq() -> bool {
        has(PCLMULQDQ)
    }
    /// The SHA extensions (SHA-1 and SHA-256, "SHA-NI").
    #[inline]
    pub(crate) fn sha() -> bool {
        has(SHA)
    }
    /// SHA-NI together with the SSE levels its kernels also use (SSE2, SSSE3,
    /// SSE4.1).
    #[inline]
    pub(crate) fn sha_ni() -> bool {
        has(SHA | SSE2 | SSSE3 | SSE41)
    }
    /// AVX2, with the OS saving YMM state.
    #[inline]
    pub(crate) fn avx2() -> bool {
        has(AVX2)
    }
    /// AVX-512 Foundation, with the OS saving opmask and ZMM state.
    #[inline]
    pub(crate) fn avx512f() -> bool {
        has(AVX512F)
    }
    /// AVX-512 Byte/Word (implies [`avx512f`]).
    #[inline]
    pub(crate) fn avx512bw() -> bool {
        has(AVX512BW | AVX512F)
    }
    /// AVX-512 Vector Length extensions (the AVX-512 instructions on 128-
    /// and 256-bit vectors; implies [`avx512f`]).
    #[inline]
    pub(crate) fn avx512vl() -> bool {
        has(AVX512VL | AVX512F)
    }
    /// AVX-512 IFMA (52-bit integer multiply-add; implies [`avx512f`]).
    #[inline]
    pub(crate) fn avx512ifma() -> bool {
        has(AVX512IFMA | AVX512F)
    }
    /// BMI1 (`ANDN` and friends).
    #[inline]
    pub(crate) fn bmi1() -> bool {
        has(BMI1)
    }
    /// BMI2 (`RORX`, `MULX`, `SHLX` and friends).
    #[inline]
    pub(crate) fn bmi2() -> bool {
        has(BMI2)
    }
}
#[cfg(target_arch = "x86_64")]
#[allow(unused_imports)]
pub(crate) use x86_api::*;

/// aarch64 feature probe: the OS's answer with `std`, the compile-time target
/// features without it (see the module docs).
#[cfg(all(target_arch = "aarch64", feature = "std"))]
macro_rules! arm_has {
    ($f:tt) => {
        std::arch::is_aarch64_feature_detected!($f)
    };
}
#[cfg(all(target_arch = "aarch64", not(feature = "std")))]
macro_rules! arm_has {
    ($f:tt) => {
        cfg!(target_feature = $f)
    };
}

/// Advanced SIMD (NEON).
#[cfg(target_arch = "aarch64")]
#[inline]
pub(crate) fn neon() -> bool {
    arm_has!("neon")
}
/// FEAT_AES (with FEAT_PMULL, which Rust bundles under `aes`).
#[cfg(target_arch = "aarch64")]
#[inline]
pub(crate) fn aes() -> bool {
    arm_has!("aes")
}
/// FEAT_SHA1 + FEAT_SHA256 (Rust's `sha2`).
#[cfg(target_arch = "aarch64")]
#[inline]
pub(crate) fn sha2() -> bool {
    arm_has!("sha2")
}
/// FEAT_SHA512 + FEAT_SHA3 (Rust's `sha3`).
#[cfg(target_arch = "aarch64")]
#[inline]
pub(crate) fn sha3() -> bool {
    arm_has!("sha3")
}

#[cfg(all(test, feature = "std", target_arch = "x86_64"))]
mod tests {
    /// The `core`-only detection must agree with the standard library's.
    #[test]
    fn matches_std_detection() {
        assert_eq!(super::sse2(), std::is_x86_feature_detected!("sse2"));
        assert_eq!(super::ssse3(), std::is_x86_feature_detected!("ssse3"));
        assert_eq!(super::sse41(), std::is_x86_feature_detected!("sse4.1"));
        assert_eq!(super::aes(), std::is_x86_feature_detected!("aes"));
        assert_eq!(
            super::pclmulqdq(),
            std::is_x86_feature_detected!("pclmulqdq")
        );
        assert_eq!(super::sha(), std::is_x86_feature_detected!("sha"));
        assert_eq!(super::avx2(), std::is_x86_feature_detected!("avx2"));
        assert_eq!(super::avx512f(), std::is_x86_feature_detected!("avx512f"));
        assert_eq!(super::avx512bw(), std::is_x86_feature_detected!("avx512bw"));
        assert_eq!(super::bmi1(), std::is_x86_feature_detected!("bmi1"));
        assert_eq!(super::bmi2(), std::is_x86_feature_detected!("bmi2"));
        assert_eq!(super::avx512vl(), std::is_x86_feature_detected!("avx512vl"));
        assert_eq!(
            super::avx512ifma(),
            std::is_x86_feature_detected!("avx512ifma") && super::avx512f()
        );
    }
}
