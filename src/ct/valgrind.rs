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
//! `PLAT_amd64_linux`, `PLAT_x86_linux`, `PLAT_arm64_linux` and
//! `PLAT_arm_linux`; the request numbers from the `VG_USERREQ__*` enum in
//! `memcheck/memcheck.h`. That keeps the crate free of foreign code: no C
//! header, no build script, no dependency.
//!
//! Without `__ct-check`, or on any other architecture, every function here is
//! an empty `#[inline(always)]` body, so the library's declassification
//! points compile to nothing.
//!
//! [`force_portable`] is the harness's other hook: a switch, read once from
//! the environment, that makes every runtime CPU-dispatch site take its
//! portable backend so those kernels are checked too. It is the constant
//! `false` without the feature.

/// Whether the client requests are live: the feature is on and the target is
/// one whose client-request ABI is transcribed below.
const ACTIVE: bool = cfg!(all(
    feature = "__ct-check",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm"
    )
));

/// `VG_USERREQ_TOOL_BASE('M', 'C')`: `('M' << 24) | ('C' << 16)`.
const MC_BASE: usize = ((b'M' as usize) << 24) | ((b'C' as usize) << 16);
/// `VG_USERREQ__MAKE_MEM_UNDEFINED` (memcheck.h: base + 1).
const MAKE_MEM_UNDEFINED: usize = MC_BASE + 1;
/// `VG_USERREQ__MAKE_MEM_DEFINED` (memcheck.h: base + 2).
const MAKE_MEM_DEFINED: usize = MC_BASE + 2;
/// `VG_USERREQ__CHECK_MEM_IS_DEFINED` (memcheck.h: base + 5).
const CHECK_MEM_IS_DEFINED: usize = MC_BASE + 5;
/// `VG_USERREQ__RUNNING_ON_VALGRIND` (valgrind.h core request).
const RUNNING_ON_VALGRIND: usize = 0x1001;

#[cfg(all(
    feature = "__ct-check",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm"
    )
))]
mod imp {
    //! The only `unsafe` in this module: the client-request instruction
    //! sequence. It reads the six-word argument array through the pointer it
    //! is given and nothing else; it never dereferences the addresses it
    //! forwards to Valgrind (Valgrind only updates its shadow memory for
    //! them). Outside Valgrind it is a sequence of no-op instructions. The
    //! `#[allow(unsafe_code)]` is scoped to the `asm!` blocks, matching the
    //! crate's `unsafe_code = "deny"` policy of local opt-ins.
    //!
    //! The argument words are machine words: valgrind.h declares them
    //! `unsigned long` on the 64-bit platforms and `unsigned int` on
    //! `PLAT_x86_linux` / `PLAT_arm_linux`, i.e. `usize` on each.

    /// Issues one client request; returns `default` when not under Valgrind.
    #[inline(never)]
    pub(super) fn client_request(default: usize, request: usize, a1: usize, a2: usize) -> usize {
        let args: [usize; 6] = [request, a1, a2, 0, 0, 0];
        let result: usize;
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
        #[cfg(target_arch = "x86")]
        // SAFETY: `PLAT_x86_linux`: the rotations of `edi` by 3+13+29+19 = 64
        // bits leave it unchanged and `xchg ebx, ebx` is a no-op, so on
        // hardware the block only moves `default` through `edx`. Under
        // Valgrind, the tool reads `args` through `eax` and writes the result
        // to `edx`. `edi` is declared clobbered anyway.
        #[allow(unsafe_code)]
        unsafe {
            core::arch::asm!(
                "rol edi, 3",
                "rol edi, 13",
                "rol edi, 29",
                "rol edi, 19",
                "xchg ebx, ebx",
                in("eax") args.as_ptr(),
                inout("edx") default => result,
                out("edi") _,
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
        #[cfg(target_arch = "arm")]
        // SAFETY: `PLAT_arm_linux`: the rotations of `r12` by 3+13+29+19 = 64
        // bits leave it unchanged and `orr r10, r10, r10` is a no-op, so on
        // hardware the block only moves `default` through `r3`. Under
        // Valgrind, the tool reads `args` through `r4` and writes the result
        // to `r3`. `r12` is declared clobbered anyway.
        #[allow(unsafe_code)]
        unsafe {
            core::arch::asm!(
                "mov r12, r12, ror #3",
                "mov r12, r12, ror #13",
                "mov r12, r12, ror #29",
                "mov r12, r12, ror #19",
                "orr r10, r10, r10",
                in("r4") args.as_ptr(),
                inout("r3") default => result,
                out("r12") _,
                options(nostack),
            );
        }
        // Keep `args` alive (and in memory) across the asm block.
        core::hint::black_box(&args);
        result
    }
}

#[cfg(not(all(
    feature = "__ct-check",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "aarch64",
        target_arch = "arm"
    )
)))]
mod imp {
    /// No client-request ABI (or the feature is off): every request returns
    /// its default, exactly as it does natively.
    #[inline(always)]
    pub(super) fn client_request(default: usize, _req: usize, _a1: usize, _a2: usize) -> usize {
        default
    }
}

/// Marks `len` bytes at `ptr` as secret (memcheck "undefined").
#[inline(always)]
fn mark_undefined(ptr: *const u8, len: usize) {
    if ACTIVE {
        imp::client_request(0, MAKE_MEM_UNDEFINED, ptr as usize, len);
    }
}

/// Marks `len` bytes at `ptr` as public (memcheck "defined").
#[inline(always)]
fn mark_defined(ptr: *const u8, len: usize) {
    if ACTIVE {
        imp::client_request(0, MAKE_MEM_DEFINED, ptr as usize, len);
    }
}

/// Marks the bytes of `secret` as secret: under Valgrind memcheck, any branch
/// or memory index later computed from them is reported as an error.
///
/// A no-op outside Valgrind, without the `__ct-check` feature, and on
/// architectures other than x86_64, x86, aarch64 and arm. Only the address
/// is passed to Valgrind; the bytes themselves are never read or written.
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

/// Asks memcheck to report (as an error, with the origin of the taint) any
/// secret byte in the in-memory representation of `value`. A debugging aid
/// for the harness: it pins *where* a value became tainted without waiting
/// for the branch that consumes it. No-op outside Valgrind.
#[inline(always)]
pub fn check_defined_val<T: ?Sized>(value: &T) {
    if ACTIVE {
        imp::client_request(
            0,
            CHECK_MEM_IS_DEFINED,
            (value as *const T).cast::<u8>() as usize,
            core::mem::size_of_val(value),
        );
    }
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
    if ACTIVE {
        // Spill to memory so the request covers it, then reload: the asm
        // block may (as far as the compiler knows) have written the slot, so
        // the reload reads the now-defined bytes rather than a stale register.
        let slot = value;
        declassify_val(&slot);
        core::hint::black_box(slot)
    } else {
        value
    }
}

/// Whether the process runs under Valgrind (`RUNNING_ON_VALGRIND`): `0`
/// natively, the Valgrind nesting depth otherwise. Always `0` without
/// `__ct-check` or on unsupported architectures.
#[inline(always)]
pub fn running_on_valgrind() -> usize {
    if ACTIVE {
        imp::client_request(0, RUNNING_ON_VALGRIND, 0, 0)
    } else {
        0
    }
}

/// The environment variable that, set to `1`, makes [`force_portable`]
/// return `true`.
pub const FORCE_PORTABLE_ENV: &str = "PURECRYPTO_CT_FORCE_PORTABLE";

/// Whether runtime CPU dispatch must ignore the detected CPU features and
/// run the portable (scalar, table-free) backend.
///
/// Only the constant-time harness uses this. The CI runners have AES-NI /
/// PMULL / AVX2 / the SHA extensions, so without it the portable AES, GHASH,
/// ChaCha20, Poly1305, SHA-1/2, BLAKE3 and Keccak kernels would never run
/// under memcheck there. It reads [`FORCE_PORTABLE_ENV`] once and caches the
/// answer. Without `__ct-check` (or without `std`) it is the constant
/// `false`, so every dispatch site compiles exactly as before.
#[inline]
pub fn force_portable() -> bool {
    #[cfg(all(feature = "__ct-check", feature = "std"))]
    {
        use core::sync::atomic::{AtomicU8, Ordering};
        // 0 = not read yet, 1 = detected dispatch, 2 = forced portable.
        static STATE: AtomicU8 = AtomicU8::new(0);
        match STATE.load(Ordering::Relaxed) {
            1 => false,
            2 => true,
            _ => {
                let on = std::env::var_os(FORCE_PORTABLE_ENV).is_some_and(|v| v == "1");
                STATE.store(if on { 2 } else { 1 }, Ordering::Relaxed);
                on
            }
        }
    }
    #[cfg(not(all(feature = "__ct-check", feature = "std")))]
    {
        false
    }
}
