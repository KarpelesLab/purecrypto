# purecrypto

[![CI](https://github.com/KarpelesLab/purecrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/purecrypto/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/purecrypto.svg)](https://crates.io/crates/purecrypto)
[![docs.rs](https://img.shields.io/docsrs/purecrypto)](https://docs.rs/purecrypto)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A cryptography toolkit written **entirely in Rust**, depending on no foreign
code. `purecrypto` is built from the ground up — starting at constant-time
primitives and working up through hashing, ciphers, bignum arithmetic, the
classical and post-quantum asymmetric stacks, ASN.1, X.509 and TLS — and is
usable three ways:

- as a **Rust library**,
- as a **C library** (`cdylib` with a C ABI), and
- as a **standalone command-line tool** (`purecrypto`: hashing, randomness, key
  generation including PQ, CSRs, a small CA, a TLS 1.3 test client, …).

> Status: **work in progress.** Everything below is implemented and validated
> against published test vectors (RFCs, NIST FIPS ACVP, OpenSSL interop), but
> APIs are unstable and nothing here has been audited — do not use it for
> anything real yet.

## Design principles

- **No foreign code.** No C, no assembly pulled from other libraries, and no
  third-party crypto crates. Everything is implemented here, in Rust.
- **Constant time by default.** Secret-dependent values flow through the
  [`ct`](src/ct) layer (branchless equality, selection, ordering) so higher
  layers avoid timing side channels. Where an algorithm is intrinsically
  non-constant-time (RSA keygen, modular inverse), it's used only on
  one-time/key-generation paths and documented as such.
- **`no_std` core.** The crate is `#![no_std]`; `alloc` and `std` are opt-in
  features (`std` is the default and implies `alloc`).
- **Validated.** Where a standard publishes test vectors we run them — RFC
  8439, RFC 8032, RFC 8448, FIPS 203/204/205 ACVP — and cross-check the X.509
  / TLS / PQC stacks against OpenSSL 3.5.

## Layout

Single crate, modules gated by Cargo features:

| Layer            | Module      | Status |
| ---------------- | ----------- | ------ |
| Constant-time    | `ct`        | ✅ implemented |
| Hashing          | `hash`      | ✅ SHA-2, SHA-3 + Keccak-256, SHAKE/cSHAKE/KMAC/TupleHash/ParallelHash, TurboSHAKE/KangarooTwelve, BLAKE2b/2s (+keyed/X), BLAKE3, SM3, MD4/MD5/SHA-1/RIPEMD-160; HMAC + `Mac` trait (constant-time verify, drop-zeroizing) |
| Randomness       | `rng`       | ✅ RngCore/CryptoRng, HMAC-DRBG (NIST SP 800-90A), OsRng (Unix + Windows) |
| Symmetric cipher | `cipher`    | 🟡 AES-128/192/256 (constant-time, table-free); CBC/CFB/OFB/CTR; GCM and ChaCha20-Poly1305 (AEAD). _Missing: CCM, XTS, AES-key-wrap._ |
| Bignum (CT)      | `bignum`    | ✅ `Uint<LIMBS>` and runtime-sized `BoxedUint`, widening mul, Montgomery modular arith, modexp, Fermat & extended-Euclid inverse |
| Asymmetric keys  | `rsa`       | 🟡 RSA keygen (compile-time + runtime, 512–65536 bits), raw, PKCS#1 v1.5 enc/sign, PSS sign/verify, PKCS#1 DER/PEM. _Missing: OAEP encryption._ |
| Key derivation   | `kdf`       | 🟡 PBKDF2, HKDF. _Missing: password hashing (Argon2, scrypt, bcrypt)._ |
| Elliptic curve   | `ec`        | ✅ ECDSA/ECDH on P-256/P-384/P-521/secp256k1 (runtime multi-curve) + fast const-generic P-256, X25519, Ed25519 (EdDSA, RFC 8032) |
| Post-quantum KEM | `mlkem`     | 🟡 ML-KEM-768 (FIPS 203), `no_std`/no-alloc; OpenSSL-interop. _Missing: ML-KEM-512 and ML-KEM-1024._ |
| Post-quantum sig | `mldsa`     | ✅ ML-DSA-44/65/87 (FIPS 204); hedged + deterministic; FIPS 204 ACVP + OpenSSL-interop |
| Post-quantum sig | `slhdsa`    | ✅ SLH-DSA, all 12 sets (FIPS 205, SHA-2/SHAKE × 128/192/256 × s/f); FIPS 205 ACVP + OpenSSL-interop |
| ASN.1 / DER      | `der`       | ✅ DER reader/writer, base64, PEM |
| X.509            | `x509`      | ✅ self-signed + CA issuance (RSA, ECDSA & Ed25519), PKCS#10 CSRs, parse, verify; PKIX SPKI; OpenSSL-interop |
| TLS              | `tls`       | 🟡 TLS 1.3 client + server (sans-I/O core + blocking TCP `Stream`); x25519/secp256r1 + X25519MLKEM768 hybrid; AES-GCM & ChaCha20-Poly1305; Ed25519/ECDSA/RSA auth; RFC 8448 KATs. _Missing: TLS 1.2, DTLS, session resumption / PSK / 0-RTT, client auth._ |
| C ABI            | `ffi`       | ✅ hashing/HMAC, RNG, RSA, ECDSA & Ed25519 keys/signatures, X.509; opaque handles + caller buffers; `include/purecrypto.h` |
| CLI              | (binary)    | ✅ `hash`, `rand`, `genpkey` (classical + PQ), `pkey`, `req`, `x509` (CA), `s_client` |

## Cargo features

Default is `std + cli` with every module on. Disable defaults for a `no_std`
build and re-enable only what you need:

```toml
# Bare no_std, no allocator: just `ct` and primitives that fit.
purecrypto = { version = "0.0.3", default-features = false }

# no_std core + ML-KEM-768 (no alloc):
purecrypto = { version = "0.0.3", default-features = false, features = ["mlkem"] }

# Library with PQ signing only:
purecrypto = { version = "0.0.3", default-features = false, features = ["mldsa", "slhdsa"] }
```

Module gates: `hash`, `cipher`, `kdf`, `bignum`, `rng`, `rsa`, `der`, `ec`,
`x509`, `tls`, `mlkem`, `mldsa`, `slhdsa`, `ffi`, `cli`. Each pulls in only its
own dependencies. `alloc` is required by anything that needs heap (most things
except `ct`, `hash`, `cipher`, and the no-alloc `mlkem` core).

## Building

```sh
cargo build                                          # default: std + CLI binary
cargo build --no-default-features                    # bare no_std
cargo build --no-default-features --features alloc   # no_std + alloc
cargo test                                           # full suite
cargo test --release -- --ignored                    # heavy KATs (SLH-DSA 's' sets, RSA keygen)
```

Requires Rust 1.95+ (edition 2024).

## Command-line tool

The `purecrypto` binary (built by default; or `cargo build --features cli`).
Every subcommand reads `stdin` when no `-in` is given and writes to `stdout`
when no `-out` is given, so commands compose with pipes.

### `hash` — message digests

```sh
purecrypto hash sha256 file.txt              # one-shot digest
echo -n abc | purecrypto hash sha3-256       # any algorithm from the `hash` module
```

Algorithms: `sha224`, `sha256`, `sha384`, `sha512`, `sha512-224`, `sha512-256`,
`sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`, `keccak256`, `blake2b256`,
`blake2b384`, `blake2b512`, `blake2s256`, `blake3`, `sm3`, `sha1`, `md5`,
`ripemd160`. (The XOFs `shake128`/`shake256` and the BLAKE2X/cSHAKE/KMAC
variants are exposed through the Rust library, not the CLI.)

### `rand` — randomness

```sh
purecrypto rand 32              # 32 random bytes as hex
purecrypto rand 16 --binary     # raw bytes to stdout
```

### `genpkey` — key generation (classical and post-quantum)

```sh
# Classical
purecrypto genpkey -algorithm RSA -bits 2048   -out rsa.pem    # also 3072, 4096
purecrypto genpkey -algorithm RSA -bits 8192   -out rsa8k.pem  # any even size, 512..=65536
purecrypto genpkey -algorithm EC  -curve P-256 -out ec.pem     # or P-384, P-521, secp256k1
purecrypto genpkey -algorithm ED25519          -out ed.pem

# Post-quantum signatures (FIPS 204 / FIPS 205)
purecrypto genpkey -algorithm ML-DSA-44               -out mldsa44.pem
purecrypto genpkey -algorithm ML-DSA-65               -out mldsa65.pem
purecrypto genpkey -algorithm ML-DSA-87               -out mldsa87.pem
purecrypto genpkey -algorithm SLH-DSA-SHA2-128f       -out slh128f.pem
purecrypto genpkey -algorithm SLH-DSA-SHAKE-256s      -out slh256s.pem

# Post-quantum KEM (FIPS 203)
purecrypto genpkey -algorithm ML-KEM-768              -out mlkem.pem
```

The full SLH-DSA matrix is supported:
`SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}` (12 parameter sets).

Output format:
- RSA → `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1)
- EC → `-----BEGIN EC PRIVATE KEY-----` (SEC1)
- Ed25519 / ML-DSA / ML-KEM / SLH-DSA → `-----BEGIN PRIVATE KEY-----` (PKCS#8,
  algorithm identified by the embedded OID)

> **PKCS#8 interop note.** purecrypto uses the simple PKCS#8 form — `OCTET
> STRING` containing the raw expanded key bytes — for every PQ scheme. This
> matches OpenSSL 3.5 byte-for-byte for SLH-DSA, and OpenSSL parses the
> resulting private keys directly. For ML-DSA and ML-KEM, OpenSSL writes a
> richer `SEQUENCE { seed, expanded }` form; purecrypto's PEM round-trips
> through itself but may not load into OpenSSL as a private key. Public-key
> SPKI is fully interoperable for every scheme.

### `pkey` — inspect or convert a key

```sh
purecrypto pkey -in key.pem -text     # describe the key
purecrypto pkey -in key.pem -pubout   # emit the SPKI public-key PEM
purecrypto pkey < key.pem             # re-emit the private key (round-trip)
```

`pkey` auto-detects every supported flavor (RSA PKCS#1, EC SEC1, and the PKCS#8
types above) and routes by the embedded OID for PKCS#8 inputs.

### `req` — PKCS#10 certificate signing requests

```sh
purecrypto req -key leaf.pem -subj "/CN=leaf.example/O=Acme" \
               -addext "subjectAltName=DNS:leaf.example,DNS:www.leaf.example" \
               -out leaf.csr
purecrypto req -in leaf.csr -verify       # check the CSR self-signature
```

### `x509` — self-signed certificates and a small CA

```sh
# Build a self-signed CA cert
purecrypto x509 -new --ca -key ca.pem -subj "/CN=Internal CA" -out ca.crt

# Issue a leaf certificate from a CSR
purecrypto x509 -req -in leaf.csr -CA ca.crt -CAkey ca.pem -out leaf.crt

# Inspect a certificate
purecrypto x509 -in leaf.crt -text
```

### `s_client` — TLS 1.3 test client

```sh
purecrypto s_client -connect example.com:443
purecrypto s_client -connect 127.0.0.1:8443 -CAfile ca.crt -servername leaf.example
purecrypto s_client -connect 127.0.0.1:8443 -insecure -quiet      # skip cert verify, stdin → server
```

The client offers `X25519MLKEM768` (post-quantum hybrid) first, then `x25519`
and `secp256r1`; all three TLS 1.3 cipher suites
(`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
`TLS_CHACHA20_POLY1305_SHA256`); and Ed25519, ECDSA, and RSA peer signatures.

### Cookbook

End-to-end CA + leaf with EC keys:

```sh
purecrypto genpkey -algorithm EC -curve P-256 -out ca.pem
purecrypto x509 -new --ca -key ca.pem -subj "/CN=My CA" -out ca.crt

purecrypto genpkey -algorithm EC -curve P-256 -out leaf.pem
purecrypto req -key leaf.pem -subj "/CN=leaf.example" \
               -addext "subjectAltName=DNS:leaf.example" -out leaf.csr
purecrypto x509 -req -in leaf.csr -CA ca.crt -CAkey ca.pem -out leaf.crt
```

A post-quantum signature key and its public counterpart:

```sh
purecrypto genpkey -algorithm ML-DSA-65 -out mldsa.pem
purecrypto pkey -in mldsa.pem -text                       # ML-DSA-65 private key
purecrypto pkey -in mldsa.pem -pubout > mldsa.pub.pem     # PKIX SPKI
```

## Library usage

Idiomatic Rust API — see [docs.rs/purecrypto](https://docs.rs/purecrypto) for
the full reference. A few common patterns:

```rust
use purecrypto::hash::{Digest, Sha256};
let d = Sha256::digest(b"abc");

use purecrypto::ec::Ed25519PrivateKey;
use purecrypto::rng::OsRng;
let sk = Ed25519PrivateKey::generate(&mut OsRng);
let sig = sk.sign(b"hello");
sk.public_key().verify(b"hello", &sig).unwrap();

use purecrypto::mldsa::MlDsa65PrivateKey;
let (sk, pk) = MlDsa65PrivateKey::generate(&mut OsRng);
let sig = sk.sign(&mut OsRng, b"hello", b"").unwrap();
assert!(pk.verify(&sig, b"hello", b""));

use purecrypto::mlkem::MlKem768DecapsKey;
let (dk, ek) = MlKem768DecapsKey::generate(&mut OsRng);
let (ct, ss_a) = ek.encapsulate(&mut OsRng);
let ss_b = dk.decapsulate(&ct);
assert_eq!(ss_a, ss_b);
```

## C library

Prebuilt archives — the `purecrypto` CLI, the static (`.a`/`.lib`) and shared
(`.so`/`.dylib`/`.dll`) C libraries, and the header — are attached to each
[GitHub release](https://github.com/KarpelesLab/purecrypto/releases) for Linux,
macOS, and Windows.

The same code is callable from C via the `ffi` feature. Because the crate stays
`rlib` by default (so the `no_std` build is unaffected), produce the C library
with `cargo rustc`:

```sh
cargo rustc --lib --release --features ffi --crate-type cdylib    # → target/release/libpurecrypto.so
cargo rustc --lib --release --features ffi --crate-type staticlib # → target/release/libpurecrypto.a

# Static link (self-contained):
cc app.c -I include target/release/libpurecrypto.a -lpthread -ldl -lm -o app
```

The API is declared in [`include/purecrypto.h`](include/purecrypto.h): one-shot
and streaming hashing, HMAC, OS randomness, RSA/ECDSA/Ed25519 key generation,
signing, verification and PEM I/O, and X.509 parsing/verification. Functions
return a `pc_status` code; variable-length output uses an in/out length buffer;
stateful objects are opaque handles freed by the library; panics never cross
the boundary. The C ABI currently covers the classical asymmetric stack;
post-quantum keys are reached via the Rust library or the CLI.

## License

Licensed under the [MIT License](LICENSE).
