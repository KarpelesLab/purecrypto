//! Chunked, fail-closed filling from a host entropy import that cannot signal
//! failure — the browser / generic-host `purecrypto.random_get` backend in
//! [`wasm`](super::wasm).
//!
//! The import has no return value, so a glue implementation that silently
//! does nothing — a `try`/`catch` swallowing the `SecurityError`
//! `crypto.getRandomValues` raises on a non-secure origin, an early return at
//! the 65536-byte chunk boundary, a Node shim that forgets to write back —
//! would hand back whatever was already in linear memory (zeros, for a fresh
//! allocation) and `OsRng` would report success. Every sibling backend fails
//! closed (Unix panics, WASI asserts on errno, Windows asserts, Apple's
//! `arc4random_buf` aborts internally), so this one must too.
//!
//! The defence is to never ask the host for more than [`MAX_CHUNK`] bytes at
//! once, pre-poison each chunk with a position-dependent sentinel pattern,
//! and verify after the call that the pattern is gone — including from the
//! final bytes of the chunk, so "wrote only a prefix" is caught as well as
//! "wrote nothing". Chunking on this side matters: `crypto.getRandomValues`
//! rejects requests above 65536 bytes, so host glue typically loops over
//! chunks of that size, and glue whose loop stops after the first chunk
//! would otherwise pass a single whole-buffer "did anything change?" check
//! while leaving the tail as the deterministic sentinel.
//!
//! None of this is a randomness test: it cannot detect a weak or repeated
//! stream, only a host that did not write (all of) the bytes it was asked for.
//!
//! The logic is pure so it can be unit-tested natively with mock hosts; the
//! module is compiled on the wasm target that uses it and under `test`.

/// Largest request handed to the host in one call. Equals the per-call cap
/// of `crypto.getRandomValues`, so glue need not chunk on its side.
pub(super) const MAX_CHUNK: usize = 65536;

/// Number of trailing bytes of each chunk that must no longer hold the
/// sentinel. A genuine random draw matches the sentinel there with
/// probability 2^-128, so the check cannot false-positive in practice;
/// chunks shorter than this get only the whole-chunk check.
const TAIL_WINDOW: usize = 16;

/// Byte written at index `i` before calling the host, so that "the host
/// wrote nothing" is distinguishable from a legitimate result. Position-
/// dependent so a host that memsets a constant is caught too.
#[inline]
fn sentinel(i: usize) -> u8 {
    0xA5 ^ (i as u8)
}

/// Overwrites `chunk` with the sentinel pattern ahead of the host call.
pub(super) fn poison(chunk: &mut [u8]) {
    for (i, b) in chunk.iter_mut().enumerate() {
        *b = sentinel(i);
    }
}

/// Verifies, after the host call, that `chunk` (previously [`poison`]ed) was
/// actually written. Returns a description of the failure for the panic
/// message. Not a randomness test.
pub(super) fn check(chunk: &[u8]) -> Result<(), &'static str> {
    if chunk.iter().enumerate().all(|(i, &b)| b == sentinel(i)) {
        return Err("wrote nothing: the entropy buffer still holds the pre-call sentinel pattern");
    }
    if chunk.len() >= TAIL_WINDOW {
        let start = chunk.len() - TAIL_WINDOW;
        if chunk[start..]
            .iter()
            .enumerate()
            .all(|(i, &b)| b == sentinel(start + i))
        {
            return Err(
                "wrote only a prefix of the request: its final bytes still hold the pre-call \
                 sentinel pattern",
            );
        }
        // A host that zeroes the buffer instead of filling it is the other
        // common failure. Only check where a genuine all-zero draw is
        // impossible in practice (2^-128 at 16 bytes); shorter draws would
        // false-positive.
        if chunk.iter().all(|&b| b == 0) {
            return Err("returned all-zero bytes");
        }
    }
    Ok(())
}

/// Fills `dest` through `host`, handing it at most [`MAX_CHUNK`] bytes per
/// call and failing closed (panicking) on any chunk the host did not fill.
pub(super) fn fill_chunked(dest: &mut [u8], mut host: impl FnMut(&mut [u8])) {
    for chunk in dest.chunks_mut(MAX_CHUNK) {
        poison(chunk);
        host(chunk);
        if let Err(what) = check(chunk) {
            panic!("purecrypto.random_get host import {what}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deterministic stand-in for a working host CSPRNG (xorshift32).
    struct MockHost {
        state: u32,
        /// Sizes of every request received, in order.
        requests: alloc::vec::Vec<usize>,
    }

    impl MockHost {
        fn new() -> Self {
            MockHost {
                state: 0x1234_5678,
                requests: alloc::vec::Vec::new(),
            }
        }
        fn next(&mut self) -> u8 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.state = x;
            x as u8
        }
        /// Writes the first `n` bytes of `buf` (the rest is left as-is).
        fn write_prefix(&mut self, buf: &mut [u8], n: usize) {
            for b in buf[..n].iter_mut() {
                *b = self.next();
            }
        }
    }

    fn holds_sentinel(chunk: &[u8]) -> bool {
        chunk.iter().enumerate().all(|(i, &b)| b == sentinel(i))
    }

    #[test]
    fn honest_host_fills_every_chunk() {
        // Three chunks: two full ones and a short tail, so both the chunk
        // boundaries and the final partial request are exercised.
        let len = 2 * MAX_CHUNK + 100;
        let mut dest = alloc::vec![0u8; len];
        let mut host = MockHost::new();
        fill_chunked(&mut dest, |chunk| {
            host.requests.push(chunk.len());
            let n = chunk.len();
            host.write_prefix(chunk, n);
        });
        assert_eq!(host.requests, [MAX_CHUNK, MAX_CHUNK, 100]);
        // No chunk still carries the sentinel; in particular the tail of
        // every chunk was written.
        for chunk in dest.chunks(MAX_CHUNK) {
            assert!(!holds_sentinel(chunk));
            assert!(!holds_sentinel(&chunk[chunk.len() - TAIL_WINDOW..]));
        }
    }

    #[test]
    fn short_requests_are_a_single_chunk() {
        let mut dest = [0u8; 8];
        let mut calls = 0;
        let mut host = MockHost::new();
        fill_chunked(&mut dest, |chunk| {
            calls += 1;
            assert_eq!(chunk.len(), 8);
            host.write_prefix(chunk, 8);
        });
        assert_eq!(calls, 1);
        assert!(!holds_sentinel(&dest));
    }

    /// The regression this module exists for: glue that fills the first
    /// 65536-byte request and then stops used to pass a whole-buffer
    /// "did anything change?" check, leaving the tail as the sentinel.
    #[test]
    #[should_panic(expected = "wrote nothing")]
    fn host_that_stops_after_first_chunk_is_rejected() {
        let mut dest = alloc::vec![0u8; MAX_CHUNK + 100];
        let mut host = MockHost::new();
        let mut served = 0usize;
        fill_chunked(&mut dest, |chunk| {
            if served == 0 {
                let n = chunk.len();
                host.write_prefix(chunk, n);
            }
            served += chunk.len();
        });
    }

    /// A host that writes only part of each request (an off-by-one in the
    /// glue's chunk loop, say) is caught by the tail-window check.
    #[test]
    #[should_panic(expected = "wrote only a prefix")]
    fn host_that_writes_a_partial_chunk_is_rejected() {
        let mut dest = alloc::vec![0u8; 4096];
        let mut host = MockHost::new();
        fill_chunked(&mut dest, |chunk| {
            let n = chunk.len() / 2;
            host.write_prefix(chunk, n);
        });
    }

    #[test]
    #[should_panic(expected = "wrote nothing")]
    fn host_that_writes_nothing_is_rejected() {
        let mut dest = [0u8; 32];
        fill_chunked(&mut dest, |_| {});
    }

    #[test]
    #[should_panic(expected = "returned all-zero bytes")]
    fn host_that_zeroes_is_rejected() {
        let mut dest = [0u8; 32];
        fill_chunked(&mut dest, |chunk| chunk.fill(0));
    }

    /// Below the 16-byte window a genuine all-zero draw is plausible, so
    /// the all-zero check must not fire there (matching the pre-existing
    /// behaviour).
    #[test]
    fn short_all_zero_draw_is_accepted() {
        let mut dest = [0u8; 8];
        fill_chunked(&mut dest, |chunk| chunk.fill(0));
        assert_eq!(dest, [0u8; 8]);
    }

    #[test]
    fn check_reports_each_failure_class() {
        let mut buf = [0u8; 64];
        poison(&mut buf);
        assert!(check(&buf).unwrap_err().starts_with("wrote nothing"));

        let mut host = MockHost::new();
        host.write_prefix(&mut buf, 40);
        assert!(check(&buf).unwrap_err().starts_with("wrote only a prefix"));

        host.write_prefix(&mut buf, 64);
        assert_eq!(check(&buf), Ok(()));

        buf.fill(0);
        assert_eq!(check(&buf), Err("returned all-zero bytes"));
    }
}
