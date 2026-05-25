# purecrypto

[![CI](https://github.com/KarpelesLab/purecrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/purecrypto/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/purecrypto.svg)](https://crates.io/crates/purecrypto)
[![docs.rs](https://img.shields.io/docsrs/purecrypto)](https://docs.rs/purecrypto)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A cryptography toolkit written **entirely in Rust**, depending on no foreign
code. `purecrypto` is built from the ground up — starting at constant-time
primitives and working up through hashing, ciphers, bignum arithmetic,
asymmetric keys, ASN.1, X.509 and TLS — and is usable three ways:

- as a **Rust library**,
- as a **C library** (`cdylib` with a C ABI), and
- as a **standalone command-line tool** (key generation, file encryption,
  building a CA, signing certificates, …).

> Status: **work in progress.** The crypto stack up through a TLS 1.3
> client and server (sans-I/O, with a blocking TCP adapter) is implemented and
> validated against published test vectors, but APIs are unstable and nothing
> here has been audited — do not use it for anything real yet.

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
| Hashing          | `hash`      | ✅ SHA-2, SHA-3 + Keccak-256, SHAKE/cSHAKE/KMAC/TupleHash/ParallelHash, TurboSHAKE/KangarooTwelve, BLAKE2b/2s (+keyed/X), BLAKE3, SM3, MD4/MD5/SHA-1/RIPEMD-160; HMAC + `Mac` trait (constant-time verify, drop-zeroizing) |
| Randomness       | `rng`       | 🟡 RngCore/CryptoRng, HMAC-DRBG, OsRng (Unix) |
| Symmetric cipher | `cipher`    | 🟡 AES-128/192/256 (constant-time, table-free); CBC/CFB/OFB/CTR; GCM (AEAD) |
| Bignum (CT)      | `bignum`    | 🟡 Uint<LIMBS>, widening mul, Montgomery modular arith, modexp + Fermat inverse |
| Asymmetric keys  | `rsa`       | 🟡 RSA keygen, raw, PKCS#1 v1.5 enc/sign, PSS sign/verify, PKCS#1 DER/PEM |
| Key derivation   | `kdf`       | 🟡 PBKDF2, HKDF |
| Elliptic curve   | `ec`        | 🟡 ECDSA/ECDH on P-256/P-384/P-521/secp256k1 (runtime multi-curve) + fast const-generic P-256, X25519; Ed25519/ML-KEM planned |
| ASN.1 / DER      | `der`       | 🟡 DER reader/writer, base64, PEM; RSA PKCS#1 key (de)serialization |
| X.509            | `x509`      | 🟡 self-signed + CA issuance, parse, verify (RSA + P-256/ECDSA); PKIX SPKI; OpenSSL-interop |
| TLS / DTLS       | `tls`       | 🟡 TLS 1.3 client + server (sans-I/O core + blocking TCP `Stream`); x25519/secp256r1, AES-GCM; RFC 8448 KATs |
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
