//! Random number generation.
//!
//! [`RngCore`] is the byte-source interface; [`CryptoRng`] marks generators
//! that are cryptographically secure. [`HmacDrbg`] is a deterministic
//! SP 800-90A generator built on our HMAC, and (with `std`) [`OsRng`] draws
//! directly from the operating system's entropy pool. The OS-side source
//! varies by target:
//!
//! * **Apple** (macOS, iOS, tvOS, watchOS, visionOS): `arc4random_buf(3)`
//!   from `libSystem`. Always seeded by the kernel before userspace runs;
//!   no early-boot caveat.
//! * **Windows**: `ProcessPrng` from `bcryptprimitives.dll`.
//! * **Linux** (default): `/dev/urandom` (per-thread cached fd).
//! * **Linux with `linux-getrandom` feature**: `getrandom(2)` via raw
//!   syscalls (no `libc` dep). Blocks until the kernel CSPRNG is seeded —
//!   recommended for processes that may start very early in boot.
//!   Supported arches: x86_64, aarch64, armv7, riscv64; other Linux arches
//!   transparently fall through to `/dev/urandom`.
//! * **Other Unix** (FreeBSD, OpenBSD, NetBSD, etc.): `/dev/urandom`.

mod hmac_drbg;
#[cfg(all(feature = "linux-getrandom", target_os = "linux"))]
mod linux_getrandom;

pub use hmac_drbg::HmacDrbg;

/// A source of random bytes.
pub trait RngCore {
    /// Fills `dest` entirely with random bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]);

    /// Returns the next random `u32` (little-endian from [`Self::fill_bytes`]).
    #[inline]
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    /// Returns the next random `u64` (little-endian from [`Self::fill_bytes`]).
    #[inline]
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
}

/// Marker for generators that are cryptographically secure — suitable for keys,
/// nonces, and other secret material.
///
/// This is a promise about the implementation, not something the type system
/// can verify; do not implement it for non-CSPRNGs.
pub trait CryptoRng {}

/// Operating-system entropy source.
///
/// Reads from `/dev/urandom`. Available on Unix targets with the `std` feature.
#[cfg(all(feature = "std", unix))]
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

// Per-thread cached `/dev/urandom` file handle. Keep one open file per
// thread to avoid the open/close overhead that dominates the cost of a
// small entropy draw. `/dev/urandom` survives indefinitely under POSIX,
// so a cached handle stays valid for the thread's lifetime. RefCell is
// fine here: the borrow is uncontended (one thread); a panic between
// `borrow_mut` and unborrow would poison the cell, but the only
// operation inside the borrow is `read_exact`, whose panic path would
// terminate the thread anyway via the `expect` below.
//
// Skipped on Apple targets: arc4random_buf is always used there.
#[cfg(all(feature = "std", unix, not(target_vendor = "apple")))]
std::thread_local! {
    static URANDOM: core::cell::RefCell<Option<std::fs::File>> =
        const { core::cell::RefCell::new(None) };
}

// Apple platforms (macOS, iOS, tvOS, watchOS, visionOS) expose
// `arc4random_buf(3)` from libSystem, which is always linked. The
// function is documented to always succeed (failure aborts the
// process); the kernel seeds the underlying CSPRNG before any user
// process runs, so there's no early-boot caveat to worry about.
#[cfg(all(feature = "std", unix, target_vendor = "apple"))]
unsafe extern "C" {
    fn arc4random_buf(buf: *mut core::ffi::c_void, len: usize);
}

#[cfg(all(feature = "std", unix))]
impl RngCore for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if dest.is_empty() {
            return;
        }

        // Apple platforms — always use arc4random_buf. The two
        // mutually-exclusive cfg blocks below ensure each target sees
        // exactly one branch, so there's no `unreachable_code` lint.
        #[cfg(target_vendor = "apple")]
        {
            // SAFETY: arc4random_buf writes exactly `len` bytes into a
            // caller-supplied buffer and has no failure mode (it
            // aborts the process on internal CSPRNG failure).
            #[allow(unsafe_code)]
            unsafe {
                arc4random_buf(dest.as_mut_ptr() as *mut core::ffi::c_void, dest.len());
            }
        }

        #[cfg(not(target_vendor = "apple"))]
        {
            // Linux with the `linux-getrandom` feature: try the syscall
            // first; fall back to /dev/urandom on ENOSYS or unsupported
            // arch, panic on any other errno.
            #[cfg(all(feature = "linux-getrandom", target_os = "linux"))]
            match linux_getrandom::try_getrandom(dest) {
                Ok(()) => return,
                Err(linux_getrandom::Error::NotImplemented) => {} // fall through
                Err(linux_getrandom::Error::Other(e)) => {
                    panic!("getrandom(2) failed with errno {e}");
                }
            }

            urandom_fill(dest);
        }
    }
}

#[cfg(all(feature = "std", unix, not(target_vendor = "apple")))]
fn urandom_fill(dest: &mut [u8]) {
    use std::io::Read;

    URANDOM.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(std::fs::File::open("/dev/urandom").expect("failed to open /dev/urandom"));
        }
        slot.as_mut()
            .unwrap()
            .read_exact(dest)
            .expect("failed to read entropy from /dev/urandom");
    });
}

#[cfg(all(feature = "std", unix))]
impl CryptoRng for OsRng {}

/// Operating-system entropy source for Windows, via the Win32 system CSPRNG.
///
/// Unlike Unix's `/dev/urandom`, Windows has no file-based entropy, so this
/// calls `ProcessPrng` (bcryptprimitives.dll) directly — the crate's only use
/// of `unsafe` outside the `ffi` module, confined here behind
/// `#![allow(unsafe_code)]`.
#[cfg(all(feature = "std", windows))]
mod os_windows {
    #![allow(unsafe_code)]
    use super::{CryptoRng, RngCore};

    // `BOOL ProcessPrng(PBYTE pbData, SIZE_T cbData)` — documented to always
    // succeed (it returns TRUE), drawing from the same CSPRNG as BCryptGenRandom.
    // `kind = "raw-dylib"` synthesizes the import from the DLL directly: the
    // Windows SDK ships bcryptprimitives.dll but no import `.lib` for it (this is
    // the approach the `getrandom` crate uses for the same function).
    #[link(name = "bcryptprimitives", kind = "raw-dylib")]
    unsafe extern "system" {
        fn ProcessPrng(data: *mut u8, len: usize) -> i32;
    }

    /// Operating-system entropy source.
    #[derive(Debug, Clone, Copy, Default)]
    pub struct OsRng;

    impl RngCore for OsRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            if dest.is_empty() {
                return;
            }
            let ok = unsafe { ProcessPrng(dest.as_mut_ptr(), dest.len()) };
            assert!(ok != 0, "ProcessPrng failed to produce entropy");
        }
    }

    impl CryptoRng for OsRng {}
}

#[cfg(all(feature = "std", windows))]
pub use os_windows::OsRng;

#[cfg(all(test, feature = "std", any(unix, windows)))]
mod tests {
    use super::*;

    #[test]
    fn os_rng_fills_and_varies() {
        let mut rng = OsRng;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        // Astronomically unlikely to be all-zero or identical.
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }
}
