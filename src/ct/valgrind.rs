//! Valgrind memcheck client requests for the constant-time harness.
//!
//! INTERNAL. The public entry points are re-exported from [`crate::ct`] only
//! under the hidden `__ct-check` cargo feature, which exists for the
//! `tests/ct_valgrind.rs` harness and nothing else; nothing here is part of
//! the public API and it may change or vanish without notice.
//!
//! # The technique
//!
//! This is the ctgrind / TIMECOP method used by libsodium, BoringSSL and
//! PQClean. The harness marks secret inputs *undefined* with memcheck's
//! `MAKE_MEM_UNDEFINED` client request. memcheck then tracks that taint
//! bit-precisely through every instruction of the real, optimized binary and
//! reports any conditional branch ("Conditional jump or move depends on
//! uninitialised value(s)") or memory address ("Use of uninitialised value of
//! size N") computed from it — exactly the two things constant-time code must
//! never do with a secret. Public results are marked *defined* again with
//! `MAKE_MEM_DEFINED` before anything branches on them.
//!
//! Inside the library, [`declassify_value`] marks the few values that are
//! public by specification even though memcheck sees them as derived from a
//! secret (a rejection-sampling accept/reject bit, a verification verdict, a
//! value that is about to be published as part of a signature or public
//! key). Every such call site cites its justification; the list is mirrored
//! in `docs/validation.md`.
//!
//! # The client-request ABI
//!
//! A client request is a "special instruction preamble" — a sequence of
//! register rotations that sums to a full turn and is therefore an
//! architectural no-op — followed by a marker instruction that is itself a
//! no-op (`xchg rbx, rbx` / `orr x10, x10, x10`). Valgrind's JIT recognizes the
//! sequence and services the request whose arguments are in a six-word array
//! `[request, a1, a2, a3, a4, a5]`; on real hardware the instructions simply
//! execute and change nothing, so the default result is returned. The
//! sequences and register assignments below are transcribed from
//! `VALGRIND_DO_CLIENT_REQUEST_EXPR` in Valgrind's `include/valgrind.h` for
//! `PLAT_amd64_linux` and `PLAT_arm64_linux`; the request numbers from the
//! `VG_USERREQ__*` enum in `memcheck/memcheck.h`. That keeps the crate free of
//! foreign code: no C header, no build script, no dependency.
//!
//! Without `__ct-check`, or on any other architecture, every function here is
//! an empty `#[inline(always)]` body, so the library's declassification
//! points compile to nothing.

#[cfg(all(
    feature = "__ct-check",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod imp {
    //! The only `unsafe` in this module: the client-request instruction
    //! sequence. It reads the six-word argument array through the pointer it
    //! is given and nothing else; it never dereferences the addresses it
    //! forwards to Valgrind (Valgrind only updates its shadow memory for
    //! them). Outside Valgrind it is a sequence of no-op instructions. The
    //! `#[allow(unsafe_code)]` is scoped to the two `asm!` blocks, matching
    //! the crate's `unsafe_code = "deny"` policy of local opt-ins.

    /// `VG_USERREQ_TOOL_BASE('M', 'C')`: `('M' << 24) | ('C' << 16)`.
    const MC_BASE: u64 = ((b'M' as u64) << 24) | ((b'C' as u64) << 16);
    /// `VG_USERREQ__MAKE_MEM_UNDEFINED` (memcheck.h: base + 1).
    pub(super) const MAKE_MEM_UNDEFINED: u64 = MC_BASE + 1;
    /// `VG_USERREQ__MAKE_MEM_DEFINED` (memcheck.h: base + 2).
    pub(super) const MAKE_MEM_DEFINED: u64 = MC_BASE + 2;
    /// `VG_USERREQ__RUNNING_ON_VALGRIND` (valgrind.h core request).
    pub(super) const RUNNING_ON_VALGRIND: u64 = 0x1001;

    /// Issues one client request; returns `default` when not under Valgrind.
    #[inline(never)]
    pub(super) fn client_request(default: u64, request: u64, a1: u64, a2: u64) -> u64 {
        let args: [u64; 6] = [request, a1, a2, 0, 0, 0];
        let result: u64;
        #[cfg(target_arch = "x86_64")]
        // SAFETY: the rotations of `rdi` by 3+13+61+51 = 128 bits leave it
        // unchanged and `xchg rbx, rbx` is a no-op, so on hardware the block
        // only moves `default` through `rdx`. Under Valgrind, the tool reads
        // `args` (a live, initialized local) through `rax` and writes the
        // result to `rdx`. `rdi` is declared clobbered anyway, in case a
        // future Valgrind leaves it modified.
        #[allow(unsafe_code)]
        unsafe {
            core::arch::asm!(
                "rol rdi, 3",
                "rol rdi, 13",
                "rol rdi, 61",
                "rol rdi, 51",
                "xchg rbx, rbx",
                in("rax") args.as_ptr(),
                inout("rdx") default => result,
                out("rdi") _,
                options(nostack),
            );
        }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: the rotations of `x12` by 3+13+51+61 = 128 bits leave it
        // unchanged and `orr x10, x10, x10` is a no-op, so on hardware the
        // block only moves `default` through `x3`. Under Valgrind, the tool
        // reads `args` through `x4` and writes the result to `x3`. `x12` is
        // declared clobbered anyway.
        #[allow(unsafe_code)]
        unsafe {
            core::arch::asm!(
                "ror x12, x12, #3",
                "ror x12, x12, #13",
                "ror x12, x12, #51",
                "ror x12, x12, #61",
                "orr x10, x10, x10",
                in("x4") args.as_ptr(),
                inout("x3") default => result,
                out("x12") _,
                options(nostack),
            );
        }
        // Keep `args` alive (and in memory) across the asm block.
        core::hint::black_box(&args);
        result
    }
}

/// Marks `len` bytes at `ptr` as secret (memcheck "undefined").
#[inline(always)]
fn mark_undefined(ptr: *const u8, len: usize) {
    #[cfg(all(
        feature = "__ct-check",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        imp::client_request(0, imp::MAKE_MEM_UNDEFINED, ptr as u64, len as u64);
    }
    #[cfg(not(all(
        feature = "__ct-check",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        let _ = (ptr, len);
    }
}

/// Marks `len` bytes at `ptr` as public (memcheck "defined").
#[inline(always)]
fn mark_defined(ptr: *const u8, len: usize) {
    #[cfg(all(
        feature = "__ct-check",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        imp::client_request(0, imp::MAKE_MEM_DEFINED, ptr as u64, len as u64);
    }
    #[cfg(not(all(
        feature = "__ct-check",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        let _ = (ptr, len);
    }
}

/// Marks the bytes of `secret` as secret: under Valgrind memcheck, any branch
/// or memory index later computed from them is reported as an error.
///
/// A no-op outside Valgrind, without the `__ct-check` feature, and on
/// architectures other than x86_64 and aarch64. Only the address is passed
/// to Valgrind; the bytes themselves are never read or written.
#[inline(always)]
pub fn classify(secret: &[u8]) {
    mark_undefined(secret.as_ptr(), secret.len());
}

/// Marks the bytes of `public` as public again (see [`classify`]).
#[inline(always)]
pub fn declassify(public: &[u8]) {
    mark_defined(public.as_ptr(), public.len());
}

/// [`classify`] for the in-memory representation of any value (a key struct,
/// a limb array, ...).
///
/// Only meaningful for plain data: classifying a pointer (a `Vec`'s buffer
/// pointer, a reference field) makes memcheck report the dereference, which
/// is a harness bug rather than a finding.
#[inline(always)]
pub fn classify_val<T: ?Sized>(value: &T) {
    mark_undefined(
        (value as *const T).cast::<u8>(),
        core::mem::size_of_val(value),
    );
}

/// [`declassify`] for the in-memory representation of any value.
#[inline(always)]
pub fn declassify_val<T: ?Sized>(value: &T) {
    mark_defined(
        (value as *const T).cast::<u8>(),
        core::mem::size_of_val(value),
    );
}

/// Returns `value`, marked public.
///
/// This is the library-side declassification point: wrap a value that is
/// public *by specification* although it is computed from a secret (a
/// rejection-sampling accept/reject bit, a verification verdict), so the
/// Valgrind harness does not report the branch taken on it. Compiles to the
/// identity without `__ct-check`. Every call site must say why the value is
/// public; never use it to silence a real finding.
#[inline(always)]
pub fn declassify_value<T: Copy>(value: T) -> T {
    #[cfg(all(
        feature = "__ct-check",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        // Spill to memory so the request covers it, then reload: the asm
        // block may (as far as the compiler knows) have written the slot, so
        // the reload reads the now-defined bytes rather than a stale register.
        let slot = value;
        declassify_val(&slot);
        core::hint::black_box(slot)
    }
    #[cfg(not(all(
        feature = "__ct-check",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        value
    }
}

/// Whether the process runs under Valgrind (`RUNNING_ON_VALGRIND`): `0`
/// natively, the Valgrind nesting depth otherwise. Always `0` without
/// `__ct-check` or on unsupported architectures.
#[inline(always)]
pub fn running_on_valgrind() -> u64 {
    #[cfg(all(
        feature = "__ct-check",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    {
        imp::client_request(0, imp::RUNNING_ON_VALGRIND, 0, 0)
    }
    #[cfg(not(all(
        feature = "__ct-check",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )))]
    {
        0
    }
}
