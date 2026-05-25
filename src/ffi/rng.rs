//! C ABI for cryptographically secure randomness (the OS CSPRNG).

use super::common::{PcStatus, guard};
use crate::rng::{OsRng, RngCore};

/// Fills `len` bytes at `out` with cryptographically secure random data.
///
/// # Safety
/// `out` must point to at least `len` writable bytes (or `len` may be 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rand_bytes(out: *mut u8, len: usize) -> PcStatus {
    guard(|| {
        if len == 0 {
            return PcStatus::Ok;
        }
        if out.is_null() {
            return PcStatus::NullPointer;
        }
        let buf = unsafe { core::slice::from_raw_parts_mut(out, len) };
        OsRng.fill_bytes(buf);
        PcStatus::Ok
    })
}
