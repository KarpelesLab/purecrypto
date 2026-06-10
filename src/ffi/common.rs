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
    /// TLS / DTLS engine has nothing to emit and needs more wire bytes.
    WantRead = -7,
    /// TLS / DTLS engine has bytes to send; drain via `pc_tls_pop`.
    WantWrite = -8,
    /// Application I/O attempted before the handshake completed.
    WantHandshake = -9,
    /// Connection closed (peer or local sent close_notify).
    Closed = -10,
    /// Fatal TLS alert received from the peer.
    TlsAlert = -11,
}

/// Runs `f`, converting any panic into [`PcStatus::Internal`] so unwinding never
/// crosses the C boundary.
pub(super) fn guard(f: impl FnOnce() -> PcStatus) -> PcStatus {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(PcStatus::Internal)
}

/// Wraps an `extern "C" fn` body that returns a `*mut T` so that any panic is
/// caught and converted to a NULL return. Required because unwinding across
/// the C ABI is undefined behaviour.
pub(super) fn guard_ptr<T>(f: impl FnOnce() -> *mut T) -> *mut T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(core::ptr::null_mut())
}

/// Wraps an `extern "C" fn` body that returns an `i32` so that any panic is
/// caught and converted to `sentinel` (typically `0` for a boolean query or
/// `-1` for a query-with-error).
pub(super) fn guard_i32(sentinel: i32, f: impl FnOnce() -> i32) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(sentinel)
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

/// Overwrites `buf` with zeros and routes the read through
/// `core::hint::black_box` so LLVM cannot eliminate the writes as dead stores.
/// Used to scrub recovered plaintext / shared secrets before their backing
/// storage is returned to the allocator (mirrors the in-house pattern in
/// `src/ffi/rsa.rs` and `src/mlkem/mod.rs`).
pub(super) fn wipe_vec(buf: &mut alloc::vec::Vec<u8>) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(&buf);
}

/// [`wipe_vec`] for stack-allocated buffers: zeros `buf` behind a
/// `black_box` barrier so a shared secret copied out to the caller does
/// not linger in the local array after the frame is popped.
pub(super) fn wipe_array(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(&buf);
}

#[cfg(test)]
mod tests {
    #[test]
    fn guard_catches_panic_returns_internal() {
        let s = super::guard(|| panic!("test panic"));
        assert_eq!(s, super::PcStatus::Internal);
    }

    #[test]
    fn guard_ptr_catches_panic_and_returns_null() {
        let p: *mut u8 = super::guard_ptr(|| panic!("test panic"));
        assert!(p.is_null());
    }

    #[test]
    fn guard_ptr_passes_value_through() {
        let mut x = 7u8;
        let p: *mut u8 = super::guard_ptr(|| &mut x as *mut u8);
        assert!(!p.is_null());
    }

    #[test]
    fn guard_i32_catches_panic_and_returns_sentinel() {
        let v = super::guard_i32(-42, || panic!("test panic"));
        assert_eq!(v, -42);
    }

    #[test]
    fn guard_i32_passes_value_through() {
        let v = super::guard_i32(-1, || 5);
        assert_eq!(v, 5);
    }
}
