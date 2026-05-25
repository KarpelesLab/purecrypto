# purecrypto

A cryptography toolkit written **entirely in Rust**, depending on no foreign
code. `purecrypto` is built from the ground up — starting at constant-time
primitives and working up through hashing, ciphers, bignum arithmetic,
asymmetric keys, ASN.1, X.509 and TLS — and is usable three ways:

- as a **Rust library**,
- as a **C library** (`cdylib` with a C ABI), and
- as a **standalone command-line tool** (key generation, file encryption,
  building a CA, signing certificates, …).

> Status: **early foundation.** Only the constant-time primitive layer exists
> so far. APIs are unstable and nothing here has been audited — do not use it
> for anything real yet.

## Design principles

- **No foreign code.** No C, no assembly pulled from other libraries, and no
  third-party crypto crates. Everything is implemented here, in Rust.
- **Constant time by default.** Secret-dependent values flow through the
  [`ct`](src/ct) layer (branchless equality, selection, ordering) so higher
  layers avoid timing side channels.
- **`no_std` core.** The crate is `#![no_std]`; `alloc` and `std` are opt-in
  features (`std` is the default and implies `alloc`).

## Layout

Single crate, modules gated by Cargo features:

| Layer            | Module      | Status |
| ---------------- | ----------- | ------ |
| Constant-time    | `ct`        | ✅ implemented |
| Hashing          | `hash`      | 🟡 SHA-2 (224/256/384/512, 512/224, 512/256), HMAC |
| Key derivation   | `kdf`       | 🟡 PBKDF2 |
| Symmetric cipher | `cipher`    | 🟡 AES-128/192/256 (constant-time, table-free); CBC/CFB/OFB/CTR; GCM (AEAD) |
| Bignum (CT)      | `bignum`    | 🟡 Uint<LIMBS>: add/sub, CT compare, conditional select, byte I/O |
| Asymmetric keys  | `keys`      | ⬜ planned (RSA, ECDSA, Ed25519, ML-KEM) |
| ASN.1            | `asn1`      | ⬜ planned |
| X.509            | `x509`      | ⬜ planned |
| TLS / DTLS       | `tls`       | ⬜ planned |
| C ABI            | `ffi`       | ⬜ planned |
| CLI              | (binary)    | ⬜ planned |

## Building

```sh
cargo build              # default: std (implies alloc)
cargo build --no-default-features            # bare no_std
cargo build --no-default-features --features alloc   # no_std + alloc
cargo test
```

Requires Rust 1.95+ (edition 2024).

## License

Licensed under the [MIT License](LICENSE).
