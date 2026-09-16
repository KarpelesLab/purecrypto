//! C ABI for cryptographically secure randomness (the OS CSPRNG).

use super::common::{PcStatus, guard, slice_mut};
use crate::rng::{OsRng, RngCore};

/// Fills `len` bytes at `out` with cryptographically secure random data.
///
/// # Safety
/// `out` must point to at least `len` writable bytes (or `len` may be 0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_rand_bytes(out: *mut u8, len: usize) -> PcStatus {
    guard(|| {
        let Some(buf) = (unsafe { slice_mut(out, len) }) else {
            return PcStatus::NullPointer;
        };
        OsRng.fill_bytes(buf);
        PcStatus::Ok
    })
}
