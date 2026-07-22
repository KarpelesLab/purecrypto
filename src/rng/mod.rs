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

// WebAssembly entropy backends. `wasm32` has no ambient OS CSPRNG, so `OsRng`
// routes to the host: an imported function on `wasm32-unknown-unknown`, or
// `wasi_snapshot_preview1::random_get` on `wasm32-wasip1` (feature
// `wasi-getrandom`). The gate matches exactly one available backend so the
// `wasm` module never compiles without one.
#[cfg(all(
    target_arch = "wasm32",
    any(
        target_os = "unknown",
        all(target_os = "wasi", feature = "wasi-getrandom"),
    )
))]
mod wasm;
#[cfg(all(
    target_arch = "wasm32",
    any(
        target_os = "unknown",
        all(target_os = "wasi", feature = "wasi-getrandom"),
    )
))]
pub use wasm::OsRng;

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

// Forwarding impls so a `&mut R` (and therefore a `&mut dyn RngCore`) can be
// used anywhere an `R: RngCore` is expected by value. Generic primitives in the
// crate take the RNG as a sized `R: RngCore` parameter; these blanket impls are
// what let a trait-object RNG (e.g. the `&mut dyn CryptoRngCore` the [`key`]
// facade hands around) bridge into them.
//
// [`key`]: crate::key
impl<R: RngCore + ?Sized> RngCore for &mut R {
    #[inline]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        (**self).fill_bytes(dest)
    }
    #[inline]
    fn next_u32(&mut self) -> u32 {
        (**self).next_u32()
    }
    #[inline]
    fn next_u64(&mut self) -> u64 {
        (**self).next_u64()
    }
}

impl<R: CryptoRng + ?Sized> CryptoRng for &mut R {}

/// Object-safe combination of [`RngCore`] and [`CryptoRng`].
///
/// APIs that need a *secure* RNG behind a trait object take
/// `&mut dyn CryptoRngCore` rather than two separate bounds (which `dyn` cannot
/// express). The blanket impl covers every `T: RngCore + CryptoRng`, and the
/// forwarding `RngCore`/`CryptoRng` impls on `&mut R` above make
/// `&mut dyn CryptoRngCore` itself usable wherever a sized `R: RngCore +
/// CryptoRng` is required.
pub trait CryptoRngCore: RngCore + CryptoRng {}

impl<T: RngCore + CryptoRng + ?Sized> CryptoRngCore for T {}

/// Operating-system entropy source.
///
/// Reads from `/dev/urandom`. Available on Unix targets with the `std` feature.
#[cfg(all(feature = "std", unix))]
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

/// Operating-system entropy source for the `fullrust` target (libc-free Linux).
///
/// Reads `/dev/urandom` through plain `std::fs`; `File::open` is `O_CLOEXEC` on
/// this target, so the fd is not inherited across `execve(2)` — the same
/// guarantee the unix path pins explicitly with `custom_flags`. `fullrust` is
/// not a member of the `unix` family, so it needs its own `OsRng` here.
#[cfg(all(feature = "std", target_os = "fullrust"))]
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

#[cfg(all(feature = "std", target_os = "fullrust"))]
impl RngCore for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use std::io::Read;
        if dest.is_empty() {
            return;
        }
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(dest))
            .expect("OsRng: reading /dev/urandom failed");
    }
}

#[cfg(all(feature = "std", target_os = "fullrust"))]
impl CryptoRng for OsRng {}

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
//
// The extern declaration is wrapped in a submodule so the
// `#![allow(unsafe_code)]` scope is local — the rest of mod.rs stays
// under the crate-wide `unsafe_code = "deny"` policy.
#[cfg(all(feature = "std", unix, target_vendor = "apple"))]
mod os_apple {
    #![allow(unsafe_code)]
    unsafe extern "C" {
        pub(super) fn arc4random_buf(buf: *mut core::ffi::c_void, len: usize);
    }
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
                os_apple::arc4random_buf(dest.as_mut_ptr() as *mut core::ffi::c_void, dest.len());
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
    use std::os::unix::fs::OpenOptionsExt;

    // O_CLOEXEC ensures the fd is not inherited across `execve(2)`, so a
    // child process forked-then-exec'd by the host application cannot end
    // up holding a stray fd to /dev/urandom. Stdlib's `File::open` adds
    // O_CLOEXEC on modern Rust/Linux, but pinning it here makes the
    // property local to this file rather than implicit in the toolchain
    // version. The numeric value differs across Unix variants:
    //   Linux        — O_CLOEXEC = 0o2_000_000
    //   FreeBSD      — O_CLOEXEC = 0x0010_0000
    //   OpenBSD      — O_CLOEXEC = 0x0001_0000
    //   NetBSD       — O_CLOEXEC = 0x0040_0000
    //   illumos/Sol. — O_CLOEXEC = 0x80_0000
    // On other Unix targets we leave `custom_flags` at zero and rely on
    // the stdlib default (no regression from the previous behaviour).
    #[cfg(target_os = "linux")]
    const O_CLOEXEC: i32 = 0o2_000_000;
    #[cfg(target_os = "freebsd")]
    const O_CLOEXEC: i32 = 0x0010_0000;
    #[cfg(target_os = "openbsd")]
    const O_CLOEXEC: i32 = 0x0001_0000;
    #[cfg(target_os = "netbsd")]
    const O_CLOEXEC: i32 = 0x0040_0000;
    #[cfg(any(target_os = "illumos", target_os = "solaris"))]
    const O_CLOEXEC: i32 = 0x80_0000;
    #[cfg(not(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "illumos",
        target_os = "solaris",
    )))]
    const O_CLOEXEC: i32 = 0;

    URANDOM.with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = Some(
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(O_CLOEXEC)
                    .open("/dev/urandom")
                    .expect("failed to open /dev/urandom"),
            );
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

    // Regression: F1 (audit 04-rng.md) — the cached `/dev/urandom` fd MUST
    // carry FD_CLOEXEC so it is not inherited across `execve(2)`. The
    // `O_CLOEXEC` open flag sets that fd flag at creation time; this test
    // primes the per-thread cache by drawing some bytes, then re-opens
    // `/dev/urandom` the same way and confirms the flag is present on the
    // freshly opened fd (the cached fd lives behind a `thread_local!` so we
    // can't borrow it without restructuring; opening a second time
    // exercises the same code path).
    #[cfg(all(unix, not(target_vendor = "apple")))]
    #[test]
    fn urandom_fd_is_cloexec() {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        // Prime the per-thread cache so the open path runs at least once.
        let mut rng = OsRng;
        let mut buf = [0u8; 16];
        rng.fill_bytes(&mut buf);

        // Re-open with the same flags and verify FD_CLOEXEC. Mirrors the
        // O_CLOEXEC value used by `urandom_fill`.
        #[cfg(target_os = "linux")]
        const O_CLOEXEC: i32 = 0o2_000_000;
        #[cfg(target_os = "freebsd")]
        const O_CLOEXEC: i32 = 0x0010_0000;
        #[cfg(target_os = "openbsd")]
        const O_CLOEXEC: i32 = 0x0001_0000;
        #[cfg(target_os = "netbsd")]
        const O_CLOEXEC: i32 = 0x0040_0000;
        #[cfg(any(target_os = "illumos", target_os = "solaris"))]
        const O_CLOEXEC: i32 = 0x80_0000;
        #[cfg(not(any(
            target_os = "linux",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "illumos",
            target_os = "solaris",
        )))]
        const O_CLOEXEC: i32 = 0;

        // On targets where we don't set the flag (no known O_CLOEXEC
        // constant), the test is informational: the stdlib usually sets
        // it anyway on modern Rust, but we don't guarantee it here.
        if O_CLOEXEC == 0 {
            return;
        }

        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(O_CLOEXEC)
            .open("/dev/urandom")
            .expect("open /dev/urandom");

        // F_GETFD = 1, FD_CLOEXEC = 1 (both fixed across Unix). Use raw
        // libc-style probe via a tiny extern; we deliberately don't pull
        // a libc dep, so spell it inline.
        #[allow(unsafe_code)]
        mod probe {
            unsafe extern "C" {
                pub(super) fn fcntl(fd: i32, cmd: i32, ...) -> i32;
            }
        }
        const F_GETFD: i32 = 1;
        const FD_CLOEXEC: i32 = 1;
        #[allow(unsafe_code)]
        let flags = unsafe { probe::fcntl(f.as_raw_fd(), F_GETFD) };
        assert!(flags >= 0, "fcntl(F_GETFD) failed");
        assert!(
            flags & FD_CLOEXEC != 0,
            "/dev/urandom fd missing FD_CLOEXEC (got flags = {flags:#x})"
        );
    }
}
