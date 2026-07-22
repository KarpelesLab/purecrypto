//! C ABI for `purecrypto` (the `ffi` feature).
//!
//! This is the only module permitted to use `unsafe` (the crate sets
//! `unsafe_code = "deny"`, not `forbid`, for exactly this purpose). It exposes
//! `extern "C"` entry points — hashing, HMAC, randomness, RSA/ECDSA keys and
//! signatures, and X.509 parsing/verification — declared in
//! `include/purecrypto.h`.
//!
//! ## Conventions
//! - Functions return [`PcStatus`] (`0` = success, negative = error). Fallible
//!   constructors instead return an opaque pointer that is NULL on failure.
//! - Variable-length output uses the in/out length convention: pass a buffer and
//!   a `*out_len` holding its capacity; on return `*out_len` is the actual (or,
//!   on [`PcStatus::BufferTooSmall`], the required) length. Call with a zero
//!   capacity to query the length first.
//! - Opaque handles (`PcHash`, `PcRsaKey`, `PcEcKey`, `PcCert`) are created and
//!   freed by the library; every `*_new`/`*_generate`/`*_from_*` is paired with
//!   a `*_free`.
//! - Every entry point catches panics, so a Rust panic surfaces as
//!   [`PcStatus::Internal`] rather than unwinding across the boundary.
//!
//! Build a C library with, e.g.:
//! `cargo rustc --release --features ffi --crate-type staticlib`
//! (or `--crate-type cdylib`).
#![allow(unsafe_code)]
#![allow(unreachable_pub)]

mod cipher;
mod common;
mod crl;
mod csr;
mod ec;
mod hash;
mod kdf;
mod lms;
mod mldsa;
mod mlkem;
mod quic;
mod rng;
mod rsa;
mod slhdsa;
mod sm2;
mod tls;
mod x25519;
mod x509;
mod xmss;

pub use common::PcStatus;

/// Allocates `size` uninitialized bytes in the module's heap and returns a
/// pointer to them (NULL if `size` is 0 or the allocation fails).
///
/// Exposed chiefly for **WebAssembly** hosts: JavaScript cannot allocate inside
/// the wasm linear memory on its own, so it calls `pc_malloc` to reserve space
/// for the input/output buffers the `pc_*` entry points read and write, then
/// releases it with [`pc_free`]. Native C callers can use their own `malloc`.
///
/// The allocation is untracked (aligned for any byte buffer), so the caller
/// must remember `size` and pass the SAME value to [`pc_free`].
#[unsafe(no_mangle)]
pub extern "C" fn pc_malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    let Ok(layout) = alloc::alloc::Layout::from_size_align(size, 1) else {
        return core::ptr::null_mut();
    };
    // SAFETY: `layout` has a non-zero size (checked above).
    unsafe { alloc::alloc::alloc(layout) }
}

/// Frees a buffer returned by [`pc_malloc`]. `ptr` must have come from
/// `pc_malloc(size)` with the identical `size`; a NULL `ptr` or zero `size` is
/// a no-op. The buffer must not be used after this call.
///
/// # Safety
/// `ptr` must be a live allocation produced by `pc_malloc(size)` and `size`
/// must match that call exactly.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_free(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    let Ok(layout) = alloc::alloc::Layout::from_size_align(size, 1) else {
        return;
    };
    // SAFETY: the caller guarantees `ptr` came from `pc_malloc(size)`.
    unsafe { alloc::alloc::dealloc(ptr, layout) };
}

#[cfg(test)]
mod tests;
