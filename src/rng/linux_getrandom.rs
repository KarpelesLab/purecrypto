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
//! Architectures supported: x86_64, aarch64, armv7 (EABI, both ARM and Thumb
//! instruction sets) and riscv64. On any other Linux arch [`try_getrandom`]
//! returns `Err(NotImplemented)` and the caller falls back to `/dev/urandom`.
//! On kernels older than 3.17 the syscall returns `ENOSYS`; the caller falls
//! back transparently.
//!
//! On armv7 the syscall number lives in `r7`, which is also the Thumb frame
//! pointer and therefore reserved by LLVM — naming it as an `asm!` operand is a
//! hard compile error on any Thumb-mode target (`thumbv7neon-unknown-linux-*`).
//! [`getrandom_syscall`] saves and restores it around the trap instead. CI
//! `cargo check`s both `arm-unknown-linux-gnueabihf` (ARM mode) and
//! `thumbv7neon-unknown-linux-gnueabihf` (Thumb mode) so this cannot regress
//! into a feature that is in the DEFAULT set yet silently unbuildable.
//!
//! The syscall is interrupted by signals (`EINTR`) and may return fewer
//! bytes than requested for `len > 256`; [`try_getrandom`] handles both by
//! looping.

#![allow(unsafe_code)]
// syscall asm — `rng/` is one of the two unsafe carve-outs
// Under Miri the syscall `asm!` is never invoked (try_getrandom takes the
// `/dev/urandom` fallback), leaving the per-arch `getrandom_syscall` helpers
// uncalled.
#![cfg_attr(miri, allow(dead_code))]

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
    // Constructed only by the real syscall path (supported arches); the
    // unsupported-arch `try_getrandom` stub below returns `NotImplemented`
    // exclusively, so the variant is never built on those targets — hence the
    // allow, which keeps cross-target `-D warnings` builds green.
    #[allow(dead_code)]
    Other(i32),
    /// The syscall reported success but returned an impossible byte count:
    /// 0 for a non-empty request, or more than was asked for. `getrandom(2)`
    /// never does either (it blocks, writes 1..=len bytes, or fails), so it
    /// is treated as a kernel-level failure rather than retried — retrying
    /// a 0 would spin forever on a broken kernel/sandbox shim. Treated as
    /// fatal by the caller.
    #[allow(dead_code)]
    BadCount,
}

/// Fills `buf` with kernel CSPRNG bytes via `getrandom(2)`. Loops on short
/// reads (rare; only for `buf.len() > 256`) and on `EINTR`. Returns
/// `Err(NotImplemented)` on `ENOSYS` so the caller can fall back.
#[cfg(all(
    target_os = "linux",
    not(miri),
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
    )
))]
pub(super) fn try_getrandom(buf: &mut [u8]) -> Result<(), Error> {
    fill_with(buf, |ptr, len| {
        // SAFETY: `ptr`/`len` describe the unfilled tail of `buf`, a valid,
        // uniquely-borrowed range; the kernel writes at most `len` bytes
        // into it.
        unsafe {
            getrandom_syscall(
                ptr, len, 0, // flags = 0 — block until seeded, read from urandom pool.
            )
        }
    })
}

/// The retry loop behind [`try_getrandom`], parameterised over the raw
/// syscall so the error handling can be unit-tested without a kernel.
/// `syscall(ptr, len)` must follow the `getrandom(2)` ABI: the number of
/// bytes written, or `-errno`.
#[cfg(all(
    target_os = "linux",
    not(miri),
    any(
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "riscv64",
    )
))]
fn fill_with(
    buf: &mut [u8],
    mut syscall: impl FnMut(*mut u8, usize) -> isize,
) -> Result<(), Error> {
    const ENOSYS: i32 = 38;
    const EINTR: i32 = 4;

    let mut filled = 0usize;
    while filled < buf.len() {
        let remaining = buf.len() - filled;
        let ret = syscall(buf[filled..].as_mut_ptr(), remaining);
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
        // `getrandom(2)` returns 0 only for a zero-length request, and we
        // entered the loop with `remaining > 0`. A 0 here means the kernel
        // (or a seccomp/ptrace shim standing in for it) is misbehaving;
        // fail closed instead of spinning on it forever. A count beyond the
        // request is equally impossible and equally untrustworthy.
        if ret == 0 || ret as usize > remaining {
            return Err(Error::BadCount);
        }
        filled += ret as usize;
    }
    Ok(())
}

/// Catch-all stub for Linux on unsupported architectures (e.g. mips64,
/// powerpc64, s390x), and for **Miri**, which cannot execute the raw syscall
/// `asm!`. Reports unimplemented so the caller falls back to `/dev/urandom`
/// (which Miri supports under `-Zmiri-disable-isolation`).
#[cfg(all(
    target_os = "linux",
    any(
        miri,
        not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "riscv64",
        ))
    )
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
///
/// `r7` is the ARM/Thumb frame pointer and LLVM reserves it, so it cannot be
/// named as an `asm!` operand — `in("r7")` is rejected outright with *"the
/// frame pointer (r7) cannot be used as an operand for inline asm"*. The
/// portable workaround (the same one `rustix`/`linux-raw-sys` use for this
/// exact register) is to let the register allocator pick a scratch register,
/// save `r7` into it, load the syscall number, trap, and restore `r7` — all
/// within one `asm!` block so nothing observes the clobbered frame pointer.
#[cfg(all(target_os = "linux", target_arch = "arm"))]
unsafe fn getrandom_syscall(buf: *mut u8, len: usize, flags: u32) -> isize {
    let ret: isize;
    unsafe {
        core::arch::asm!(
            "mov {tmp}, r7",
            "mov r7, {nr}",
            "svc #0",
            "mov r7, {tmp}",
            tmp = out(reg) _,
            nr = in(reg) 384isize,
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
        not(miri), // exercises the raw syscall asm, which Miri cannot execute
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
        not(miri), // exercises the raw syscall asm, which Miri cannot execute
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

    /// Regression for the retry loop: a syscall that returns 0 for a
    /// non-empty request used to be added to `filled` (no progress) and
    /// retried forever. It must fail closed instead.
    #[cfg(all(
        target_os = "linux",
        not(miri),
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "riscv64",
        )
    ))]
    #[test]
    fn zero_return_fails_closed_instead_of_spinning() {
        let mut buf = [0u8; 32];
        let mut calls = 0;
        let r = fill_with(&mut buf, |_, _| {
            calls += 1;
            0
        });
        assert_eq!(r, Err(Error::BadCount));
        assert_eq!(calls, 1);

        // A count beyond the request is rejected the same way.
        let mut buf = [0u8; 32];
        let r = fill_with(&mut buf, |_, len| len as isize + 1);
        assert_eq!(r, Err(Error::BadCount));
    }

    /// The loop still handles the documented cases: EINTR is retried, short
    /// reads are resumed at the right offset, ENOSYS maps to
    /// `NotImplemented`, and any other errno is `Other`.
    #[cfg(all(
        target_os = "linux",
        not(miri),
        any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "riscv64",
        )
    ))]
    #[test]
    fn eintr_and_short_reads_are_resumed() {
        let mut buf = [0u8; 10];
        let mut step = 0;
        let r = fill_with(&mut buf, |ptr, len| {
            step += 1;
            match step {
                1 => -4, // EINTR: retry
                2 => {
                    // Short read of 4 bytes.
                    assert_eq!(len, 10);
                    // SAFETY: test-only mock honouring the callee contract.
                    unsafe { core::ptr::write_bytes(ptr, 0xAA, 4) };
                    4
                }
                _ => {
                    assert_eq!(len, 6);
                    // SAFETY: as above.
                    unsafe { core::ptr::write_bytes(ptr, 0xBB, 6) };
                    6
                }
            }
        });
        assert_eq!(r, Ok(()));
        assert_eq!(&buf[..4], &[0xAA; 4]);
        assert_eq!(&buf[4..], &[0xBB; 6]);

        let mut buf = [0u8; 8];
        assert_eq!(fill_with(&mut buf, |_, _| -38), Err(Error::NotImplemented));
        assert_eq!(fill_with(&mut buf, |_, _| -14), Err(Error::Other(14)));
        // Zero-length requests never call the syscall.
        assert_eq!(fill_with(&mut [], |_, _| panic!("called")), Ok(()));
    }
}
