//! Wycheproof (https://github.com/C2SP/wycheproof) test-vector harness.
//!
//! Each module exercises one family of primitives through the public API
//! only, against the converted vectors in `testdata/wycheproof/` (regenerate
//! with `tools/wycheproof/convert.py`). See `common.rs` for the loader and the
//! pass/fail policy: every `valid` case must be accepted with the expected
//! output, every `invalid` case must be rejected, `acceptable` cases may go
//! either way unless a module tightens them.

// The harness is one crate; `pub` items in `common` are only reachable from
// the sibling modules, which the lint counts as unreachable.
#![allow(unreachable_pub)]

mod common;

#[cfg(feature = "cipher")]
mod aead;
