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
#[cfg(feature = "bls")]
mod bls;
#[cfg(feature = "chunked")]
mod chunked;
#[cfg(feature = "cipher")]
mod cipher_modes;
#[cfg(feature = "dsa")]
mod dsa;
#[cfg(feature = "ec")]
mod ec_agree;
#[cfg(feature = "legacy-ec")]
mod ec_binary;
#[cfg(feature = "ec")]
mod ec_formats;
#[cfg(feature = "ec")]
mod ecdsa;
#[cfg(feature = "fpe")]
mod fpe;
#[cfg(feature = "jose")]
mod jose;
#[cfg(feature = "kdf")]
mod mac_kdf;
#[cfg(any(feature = "mlkem", feature = "mldsa"))]
mod pq;
#[cfg(feature = "rsa")]
mod rsa;
