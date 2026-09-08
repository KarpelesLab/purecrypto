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
//!   Because that import cannot signal failure, the buffer is requested in
//!   chunks of at most 65536 bytes (the `crypto.getRandomValues` per-call
//!   cap), each pre-poisoned with a sentinel pattern and checked afterwards —
//!   including its final bytes — so glue that silently no-ops, or fills only
//!   the first `getRandomValues`-sized chunk, panics instead of yielding keys
//!   derived from stale linear memory. See [`host_fill`](super::host_fill).
//!   Do not rely on this as a randomness check — it only rejects "the host
//!   did not write (all of) the bytes".
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
//!       // `len` never exceeds 65536 (the crypto.getRandomValues per-call
//!       // cap): the library chunks larger requests on its side.
//!       crypto.getRandomValues(new Uint8Array(memory.buffer, ptr, len));
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
        /// `len` is at most `host_fill::MAX_CHUNK` (65536) bytes per call.
        pub(super) fn random_get(ptr: *mut u8, len: usize);
    }

    pub(super) fn fill(dest: &mut [u8]) {
        // The host import has no return value, so it cannot report failure;
        // `host_fill` chunks the request, pre-poisons each chunk with a
        // sentinel pattern and panics (fails closed, like every sibling
        // backend) if the host did not overwrite all of it. See that
        // module's docs for the failure modes this guards against.
        crate::rng::host_fill::fill_chunked(dest, |chunk| {
            // SAFETY: `chunk` is a valid, uniquely-borrowed slice of
            // `chunk.len()` bytes living in linear memory; the host contract
            // is to write exactly that many bytes into it and nothing beyond.
            unsafe { random_get(chunk.as_mut_ptr(), chunk.len()) };
        });
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
