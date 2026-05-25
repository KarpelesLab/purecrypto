//! Shared C-ABI plumbing: status codes, the panic guard, and pointer/buffer
//! helpers.

/// Result code returned by `purecrypto` C functions. `0` is success; negative
/// values are errors. Mirrors `PcStatus` in `include/purecrypto.h`.
#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PcStatus {
    /// Success.
    Ok = 0,
    /// A required pointer argument was NULL.
    NullPointer = -1,
    /// The output buffer was too small; `*out_len` holds the required length.
    BufferTooSmall = -2,
    /// An input (key, certificate, …) failed to decode.
    BadEncoding = -3,
    /// A signature or MAC failed verification.
    Verification = -4,
    /// The requested algorithm, curve, or parameter is not supported.
    Unsupported = -5,
    /// An unexpected internal error (e.g. a caught panic).
    Internal = -6,
}

/// Runs `f`, converting any panic into [`PcStatus::Internal`] so unwinding never
/// crosses the C boundary.
pub(super) fn guard(f: impl FnOnce() -> PcStatus) -> PcStatus {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(PcStatus::Internal)
}

/// Borrows `len` bytes at `ptr` as a slice. A zero length yields an empty slice
/// (even if `ptr` is NULL); a NULL pointer with non-zero length yields `None`.
///
/// # Safety
/// `ptr` must point to `len` valid, initialized bytes that outlive the call.
pub(super) unsafe fn slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { core::slice::from_raw_parts(ptr, len) })
}

/// Copies `data` into the caller's `out` buffer using the in/out length
/// convention: `*out_len` holds the buffer capacity on entry and is always set
/// to the required length on return. Returns [`PcStatus::BufferTooSmall`] (with
/// the required length written) if the buffer is too small.
///
/// # Safety
/// `out_len` must be a valid pointer; `out` must point to at least `*out_len`
/// writable bytes (or be NULL only when querying the length).
pub(super) unsafe fn out_write(data: &[u8], out: *mut u8, out_len: *mut usize) -> PcStatus {
    if out_len.is_null() {
        return PcStatus::NullPointer;
    }
    let cap = unsafe { *out_len };
    unsafe { *out_len = data.len() };
    if data.len() > cap {
        return PcStatus::BufferTooSmall;
    }
    if !data.is_empty() {
        if out.is_null() {
            return PcStatus::NullPointer;
        }
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), out, data.len()) };
    }
    PcStatus::Ok
}
