//! Linux `getrandom(2)` via raw syscall — no `libc` dependency.
//!
//! When the `linux-getrandom` feature is enabled and we are on a supported
//! Linux architecture, [`OsRng::fill_bytes`](super::OsRng) prefers
//! `getrandom(2)` over reading `/dev/urandom`. The two relevant differences
//! versus `/dev/urandom`:
//!
//! * **Early-boot blocking.** `getrandom(2)` with `flags = 0` blocks until
//!   the kernel CSPRNG is initialised (RDRAND-seeded or sufficient entropy
//!   harvested). `/dev/urandom` historically returned bytes from a
//!   not-yet-seeded pool — fine on a long-running process, occasionally
//!   weak on a freshly-booted ephemeral container.
//! * **No file descriptor.** Saves one open fd per thread and one
//!   read-from-`/dev/urandom` VFS traversal per call.
//!
//! Architectures supported: x86_64, aarch64, armv7 (EABI), riscv64. On any
//! other Linux arch [`try_getrandom`] returns `Err(NotImplemented)` and the
//! caller falls back to `/dev/urandom`. On kernels older than 3.17 the
//! syscall returns `ENOSYS`; the caller falls back transparently.
//!
//! The syscall is interrupted by signals (`EINTR`) and may return fewer
//! bytes than requested for `len > 256`; [`try_getrandom`] handles both by
//! looping.

#![allow(unsafe_code)] // syscall asm — `rng/` is one of the two unsafe carve-outs

/// Reasons [`try_getrandom`] can fail. The caller (in `super::OsRng`)
/// distinguishes between `NotImplemented` (definitely fall back to
/// `/dev/urandom`) and `IoError` (the syscall failed for a reason that
/// should panic, because falling back to `/dev/urandom` would hide a
/// kernel-level entropy failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Error {
    /// The kernel doesn't have `getrandom(2)` (Linux < 3.17 → ENOSYS) or we
    /// were built for an unsupported architecture.
    NotImplemented,
    /// Any other error (EFAULT, EAGAIN with GRND_NONBLOCK — we don't pass
    /// that flag — etc.). Treated as fatal by the caller.
    #[allow(dead_code)] // currently unreachable; kept for the explicit branch
    Other(i32),
}

/// Fills `buf` with kernel CSPRNG bytes via `getrandom(2)`. Loops on short
/// reads (rare; only for `buf.len() > 256`) and on `EINTR`. Returns
/// `Err(NotImplemented)` on `ENOSYS` so the caller can fall back.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
    )
))]
pub(super) fn try_getrandom(buf: &mut [u8]) -> Result<(), Error> {
    const ENOSYS: i32 = 38;
    const EINTR: i32 = 4;

    let mut filled = 0usize;
    while filled < buf.len() {
        // SAFETY: We pass a valid pointer + length into the buffer; the
        // kernel writes at most `remaining` bytes into the supplied range.
        let ret = unsafe {
            getrandom_syscall(
                buf[filled..].as_mut_ptr(),
                buf.len() - filled,
                0, // flags = 0 — block until seeded, read from urandom pool.
            )
        };
        if ret < 0 {
            let errno = -ret as i32;
            if errno == EINTR {
                continue;
            }
            if errno == ENOSYS {
                return Err(Error::NotImplemented);
            }
            return Err(Error::Other(errno));
        }
        // ret > 0 here (ret == 0 would only happen on len == 0, but we
        // entered the loop with filled < buf.len()).
        filled += ret as usize;
    }
    Ok(())
}

/// Catch-all stub for Linux on unsupported architectures (e.g. mips64,
/// powerpc64, s390x). Reports unimplemented so the caller falls back to
/// `/dev/urandom`.
#[cfg(all(
    target_os = "linux",
    not(any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
    ))
))]
pub(super) fn try_getrandom(_buf: &mut [u8]) -> Result<(), Error> {
    Err(Error::NotImplemented)
}

/// x86_64: `syscall` instruction, syscall number 318, args in rdi/rsi/rdx,
/// return in rax. `syscall` clobbers rcx (return address) and r11 (rflags).
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn getrandom_syscall(buf: *mut u8, len: usize, flags: u32) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") 318isize => ret,
            in("rdi") buf,
            in("rsi") len,
            in("rdx") flags as usize,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// aarch64: `svc #0` instruction, syscall number 278 (asm-generic), args in
/// x0/x1/x2, syscall number in x8, return in x0.
#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
unsafe fn getrandom_syscall(buf: *mut u8, len: usize, flags: u32) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") 278isize,
            inlateout("x0") buf as isize => ret,
            in("x1") len,
            in("x2") flags as usize,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// armv7 (32-bit EABI): `svc #0`, syscall number 384, args in r0/r1/r2,
/// syscall number in r7, return in r0.
#[cfg(all(target_os = "linux", target_arch = "arm"))]
unsafe fn getrandom_syscall(buf: *mut u8, len: usize, flags: u32) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("r7") 384isize,
            inlateout("r0") buf as isize => ret,
            in("r1") len,
            in("r2") flags as usize,
            options(nostack, preserves_flags),
        );
    }
    ret
}

/// riscv64: `ecall` instruction, syscall number 278 (asm-generic), args in
/// a0/a1/a2, syscall number in a7, return in a0.
#[cfg(all(target_os = "linux", target_arch = "riscv64"))]
unsafe fn getrandom_syscall(buf: *mut u8, len: usize, flags: u32) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "ecall",
            in("a7") 278isize,
            inlateout("a0") buf as isize => ret,
            in("a1") len,
            in("a2") flags as usize,
            options(nostack, preserves_flags),
        );
    }
    ret
}

#[cfg(test)]
mod tests {
    use super::*;

    /// On the test runner (any supported Linux arch), `getrandom(2)` should
    /// succeed and fill the buffer with apparently-random bytes. On an
    /// unsupported arch the function returns `NotImplemented` and the test
    /// is a no-op.
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "riscv64",
        )
    ))]
    #[test]
    fn fills_a_small_buffer() {
        let mut buf = [0u8; 32];
        try_getrandom(&mut buf).expect("getrandom should succeed on a supported Linux arch");
        // Vanishingly unlikely to be all-zero from a 256-bit kernel read.
        assert!(buf.iter().any(|&b| b != 0));
    }

    /// Exercise the short-read loop with a length over the kernel's
    /// no-short-read bound (256 bytes per current Linux). The function
    /// should still return a fully-filled buffer.
    #[cfg(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "riscv64",
        )
    ))]
    #[test]
    fn fills_a_large_buffer() {
        // Box the buffer to avoid a 4 KiB stack frame.
        let mut buf: alloc::boxed::Box<[u8; 4096]> = alloc::boxed::Box::new([0u8; 4096]);
        try_getrandom(&mut buf[..]).expect("getrandom should succeed");
        // At least 90% of bytes should be non-zero on a healthy kernel.
        let nonzero = buf.iter().filter(|&&b| b != 0).count();
        assert!(
            nonzero > 4096 * 9 / 10,
            "suspiciously many zeros: {nonzero}/4096"
        );
    }
}
