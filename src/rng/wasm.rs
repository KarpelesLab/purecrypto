//! WebAssembly entropy backends for [`OsRng`](super::OsRng).
//!
//! `wasm32` has no ambient operating-system CSPRNG the way Unix (`/dev/urandom`)
//! or Windows (`ProcessPrng`) do, so entropy must be routed in from the host.
//! Two interchangeable backends are provided here, selected purely by the build
//! target (and, for WASI, one opt-in feature) — mirroring how `linux-getrandom`
//! selects between `getrandom(2)` and `/dev/urandom` on Linux:
//!
//! * **Browser / generic host** — `wasm32-unknown-unknown`. Calls an imported
//!   host function `purecrypto.random_get(ptr, len)` that the embedder must
//!   supply, typically wired to `crypto.getRandomValues` in the browser or
//!   `crypto.randomFillSync` under Node. There is no error return (matching the
//!   other platforms' [`OsRng`]): the host glue MUST fill the whole buffer or
//!   trap. If the import is absent the module fails to instantiate.
//!
//!   Because that import cannot signal failure, the buffer is pre-poisoned with
//!   a sentinel pattern and checked afterwards, so glue that silently no-ops
//!   panics instead of yielding keys derived from stale linear memory. Do not
//!   rely on this as a randomness check — it only rejects "the host wrote
//!   nothing".
//!
//! * **WASI preview 1** — `wasm32-wasip1` with the `wasi-getrandom` feature.
//!   Calls `random_get` from the `wasi_snapshot_preview1` module; no host glue
//!   is needed because the WASI runtime provides it.
//!
//! Example browser wiring (JS), given the instance's linear `memory`:
//!
//! ```js
//! const imports = {
//!   purecrypto: {
//!     random_get(ptr, len) {
//!       const buf = new Uint8Array(memory.buffer, ptr, len);
//!       // crypto.getRandomValues caps at 65536 bytes per call — chunk it.
//!       for (let off = 0; off < len; off += 65536) {
//!         crypto.getRandomValues(buf.subarray(off, Math.min(off + 65536, len)));
//!       }
//!     },
//!   },
//! };
//! ```

#![allow(unsafe_code)]
// `rng/` is one of the two crate-wide `unsafe_code = "deny"` carve-outs; the
// only `unsafe` here is the FFI declaration of the host entropy import.

use super::{CryptoRng, RngCore};

/// Operating-system entropy source (WebAssembly).
///
/// Draws from the host: the imported `purecrypto.random_get` on
/// `wasm32-unknown-unknown`, or `wasi_snapshot_preview1::random_get` on
/// `wasm32-wasip1` (feature `wasi-getrandom`).
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

// --- Browser / generic host import backend --------------------------------
#[cfg(target_os = "unknown")]
mod backend {
    #[link(wasm_import_module = "purecrypto")]
    unsafe extern "C" {
        /// Fills `len` bytes starting at `ptr` with CSPRNG output. Supplied by
        /// the embedder; the contract is to write exactly `len` bytes or trap.
        pub(super) fn random_get(ptr: *mut u8, len: usize);
    }

    /// Byte written at index `i` before calling the host, so that "the host
    /// wrote nothing" is distinguishable from a legitimate result. Position-
    /// dependent so a host that memsets a constant is caught too.
    #[inline]
    fn sentinel(i: usize) -> u8 {
        0xA5 ^ (i as u8)
    }

    pub(super) fn fill(dest: &mut [u8]) {
        // The host import has no return value, so a glue implementation that
        // silently does nothing — a `try`/`catch` swallowing the `SecurityError`
        // `crypto.getRandomValues` raises on a non-secure origin, an early
        // return at the 65536-byte chunk boundary, a Node shim that forgets to
        // write back — would hand us whatever was already in linear memory
        // (zeros, for a fresh allocation) and `OsRng` would report success.
        // Every sibling backend fails closed (Unix panics, WASI asserts on
        // errno, Windows asserts, Apple's `arc4random_buf` aborts internally),
        // so this one must too.
        //
        // Pre-poison the buffer with a known pattern and verify it changed.
        // This is NOT a randomness test — it cannot detect a weak or repeated
        // stream — but it catches the entire "host wrote nothing" class for the
        // cost of one extra pass over the buffer.
        for (i, b) in dest.iter_mut().enumerate() {
            *b = sentinel(i);
        }
        // SAFETY: `dest` is a valid, uniquely-borrowed slice of `dest.len()`
        // bytes living in linear memory; the host contract is to write exactly
        // that many bytes into it and nothing beyond.
        unsafe { random_get(dest.as_mut_ptr(), dest.len()) };

        assert!(
            dest.iter().enumerate().any(|(i, &b)| b != sentinel(i)),
            "purecrypto.random_get host import wrote nothing: the entropy \
             buffer still holds the pre-call sentinel pattern"
        );
        // A host that zeroes the buffer instead of filling it is the other
        // common failure. Only check where a genuine all-zero draw is
        // impossible in practice (2^-128 at 16 bytes); shorter draws would
        // false-positive.
        assert!(
            dest.len() < 16 || dest.iter().any(|&b| b != 0),
            "purecrypto.random_get host import returned all-zero bytes"
        );
    }
}

// --- WASI preview 1 backend -----------------------------------------------
#[cfg(all(target_os = "wasi", feature = "wasi-getrandom"))]
mod backend {
    #[link(wasm_import_module = "wasi_snapshot_preview1")]
    unsafe extern "C" {
        /// `random_get(buf, buf_len) -> errno`. Fills the buffer with
        /// cryptographically secure random bytes; returns `0` (`__WASI_ERRNO_SUCCESS`)
        /// on success. The `errno` is the 16-bit WASI error type.
        pub(super) fn random_get(buf: *mut u8, buf_len: usize) -> u16;
    }

    pub(super) fn fill(dest: &mut [u8]) {
        // SAFETY: `dest` is a valid, uniquely-borrowed slice of `dest.len()`
        // bytes; on success the runtime writes exactly that many bytes.
        let errno = unsafe { random_get(dest.as_mut_ptr(), dest.len()) };
        assert!(
            errno == 0,
            "wasi_snapshot_preview1::random_get failed (errno {errno})"
        );
    }
}

impl RngCore for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if dest.is_empty() {
            return;
        }
        backend::fill(dest);
    }
}

impl CryptoRng for OsRng {}
