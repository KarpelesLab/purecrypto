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
| Symmetric cipher | `cipher`    | 🟡 AES-128/192/256 (constant-time, table-free); CBC/CFB/OFB/CTR; GCM and ChaCha20-Poly1305 (AEAD) |
| Bignum (CT)      | `bignum`    | 🟡 Uint<LIMBS>, widening mul, Montgomery modular arith, modexp + Fermat inverse |
| Asymmetric keys  | `rsa`       | 🟡 RSA keygen, raw, PKCS#1 v1.5 enc/sign, PSS sign/verify, PKCS#1 DER/PEM |
| Key derivation   | `kdf`       | 🟡 PBKDF2, HKDF |
| Elliptic curve   | `ec`        | 🟡 ECDSA/ECDH on P-256/P-384/P-521/secp256k1 (runtime multi-curve) + fast const-generic P-256, X25519, Ed25519 (EdDSA, RFC 8032) |
| Post-quantum KEM | `mlkem`     | 🟡 ML-KEM-768 (FIPS 203), `no_std`/no-alloc; OpenSSL-interop |
| ASN.1 / DER      | `der`       | 🟡 DER reader/writer, base64, PEM; RSA PKCS#1 key (de)serialization |
| X.509            | `x509`      | 🟡 self-signed + CA issuance (RSA, ECDSA & Ed25519), PKCS#10 CSRs, parse, verify; PKIX SPKI; OpenSSL-interop |
| TLS / DTLS       | `tls`       | 🟡 TLS 1.3 client + server (sans-I/O core + blocking TCP `Stream`); x25519/secp256r1 + X25519MLKEM768 hybrid; AES-GCM & ChaCha20-Poly1305; Ed25519/ECDSA/RSA auth; RFC 8448 KATs |
| C ABI            | `ffi`       | ✅ hashing/HMAC, RNG, RSA, ECDSA & Ed25519 keys/signatures, X.509; opaque handles + caller buffers; `include/purecrypto.h` |
| CLI              | (binary)    | ✅ `hash`, `rand`, `genpkey`, `pkey`, `req`, `x509` (CA), `s_client` |

## Building

```sh
cargo build              # default: std + the CLI binary
cargo build --no-default-features            # bare no_std
cargo build --no-default-features --features alloc   # no_std + alloc
cargo test
```

Requires Rust 1.95+ (edition 2024).

## C library

Prebuilt archives — the `purecrypto` CLI, the static (`.a`/`.lib`) and shared
(`.so`/`.dylib`/`.dll`) C libraries, and the header — are attached to each
[GitHub release](https://github.com/KarpelesLab/purecrypto/releases) for Linux,
macOS, and Windows.

The same code is callable from C via the `ffi` feature. Because the crate stays
`rlib` by default (so the `no_std` build is unaffected), produce the C library
with `cargo rustc`:

```sh
cargo rustc --lib --release --features ffi --crate-type cdylib    # -> target/release/libpurecrypto.so
cargo rustc --lib --release --features ffi --crate-type staticlib # -> target/release/libpurecrypto.a

# Static link (self-contained):
cc app.c -I include target/release/libpurecrypto.a -lpthread -ldl -lm -o app
```

The API is declared in [`include/purecrypto.h`](include/purecrypto.h): one-shot
and streaming hashing, HMAC, OS randomness, RSA/ECDSA key generation, signing,
verification and PEM I/O, and X.509 parsing/verification. Functions return a
`pc_status` code; variable-length output uses an in/out length buffer; stateful
objects are opaque handles freed by the library; panics never cross the boundary.

## Command-line tool

The `purecrypto` binary (built by default; or `cargo build --features cli`):

```sh
purecrypto hash sha256 file.txt            # or pipe via stdin
purecrypto rand 32                          # hex (or --binary)
purecrypto genpkey -algorithm EC -curve P-256 -out key.pem
purecrypto genpkey -algorithm RSA -bits 2048 -out rsa.pem
purecrypto genpkey -algorithm ED25519 -out ed.pem
purecrypto pkey -in key.pem -pubout         # emit the public key
purecrypto req  -key key.pem -subj "/CN=example.com" \
                -addext "subjectAltName=DNS:example.com" -out req.csr
purecrypto x509 -req -in req.csr -CA ca.pem -CAkey ca.key -out cert.pem
purecrypto s_client -connect example.com:443   # TLS 1.3 test client
```

## License

Licensed under the [MIT License](LICENSE).
