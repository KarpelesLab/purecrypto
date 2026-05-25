//! Best-effort secret wiping, without `unsafe` or external dependencies.
//!
//! The values are overwritten with zeros and then passed through
//! [`core::hint::black_box`], the same optimization barrier the
//! [`ct`](crate::ct) module relies on, to discourage the compiler from
//! eliminating the writes as a dead store. This is best-effort: a true
//! guarantee would require volatile writes, but those need `unsafe`, which this
//! crate forbids.

/// Overwrites `bytes` with zeros.
#[inline]
pub(super) fn zero_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(bytes);
}
