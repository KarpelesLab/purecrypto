# purecrypto

[![CI](https://github.com/KarpelesLab/purecrypto/actions/workflows/ci.yml/badge.svg)](https://github.com/KarpelesLab/purecrypto/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/purecrypto.svg)](https://crates.io/crates/purecrypto)
[![docs.rs](https://img.shields.io/docsrs/purecrypto)](https://docs.rs/purecrypto)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A cryptography toolkit written **entirely in Rust**, with no foreign code.
It is built from the ground up, from constant-time primitives through
hashing, ciphers, bignum arithmetic, the classical and post-quantum
asymmetric stacks, ASN.1, X.509, TLS, DTLS and QUIC, and it is usable three
ways:

- as a **Rust library** (`no_std` core, every layer feature-gated),
- as a **C library** (`cdylib` / `staticlib` with a C ABI, also compiled to
  WebAssembly), and
- as a **command-line tool** (`purecrypto`: hashing, key generation
  including post-quantum, CSRs, a small CA, TLS / DTLS / QUIC test clients
  and servers).

It has OpenSSL-like breadth, but unlike a monolithic binary dependency an
application compiles in only the parts it needs.

## Quick start

Rust:

```rust
use purecrypto::hash::{Digest, Sha256};
use purecrypto::ec::Ed25519PrivateKey;
use purecrypto::mlkem::MlKem768DecapsKey;
use purecrypto::rng::OsRng;

let digest = Sha256::digest(b"abc");

let sk = Ed25519PrivateKey::generate(&mut OsRng);
let sig = sk.sign(b"hello");
sk.public_key().verify(b"hello", &sig).unwrap();

let (dk, ek) = MlKem768DecapsKey::generate(&mut OsRng);
let (ct, ss_a) = ek.encapsulate(&mut OsRng);
assert_eq!(dk.decapsulate(&ct), ss_a);
```

A TLS client that verifies against the embedded root store:

```rust,no_run
use purecrypto::rng::OsRng;
use purecrypto::tls::{Config, Connection, RootCertStore};
use std::sync::Arc;

let cfg = Config::builder()
    .tls_only()
    .rng(Arc::new(OsRng))                 // no default: the entropy source is explicit
    .roots(RootCertStore::with_embedded_roots())
    .server_name("example.com")
    .alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    .build();
let mut conn = Connection::client(&cfg).unwrap();
// Sans-I/O: pop wire bytes from `conn` and send them, feed received bytes
// back. `tls::Stream` wraps this for blocking TCP; `tokio` / `mio` adapters
// are behind features of the same name.
```

Command line:

```sh
cargo install purecrypto
purecrypto hash sha256 file.txt
purecrypto genpkey -algorithm ML-DSA-65 -out mldsa.pem
purecrypto s_client -connect example.com:443 -alpn h2
```

C:

```sh
cargo rustc --lib --release --features ffi --crate-type staticlib
cc app.c -I include target/release/libpurecrypto.a -lpthread -ldl -lm -o app
```

## Documentation

- **[Command-line reference](docs/cli.md)**: every subcommand, with a
  cookbook (CA setup, mTLS, PQC keys, password-based encryption).
- **[Signature registry and policy](docs/signature-registry.md)**: which
  signature algorithms X.509 and TLS verifiers accept, and how to change it.
- **[Recommended usage](docs/recommended-usage.md)**: the opinionated safe
  path, blessed defaults versus compatibility-only versus hazmat.
- **[Validation and assurance matrix](docs/validation.md)**: per module,
  test vectors, interop targets, fuzzing, negative-input coverage,
  constant-time posture, known limitations.
- **[Threat model](docs/threat-model.md)**: what is and is not defended
  against.
- **[Benchmarks](docs/benchmarks.md)**: per-algorithm numbers and the
  constant-time trade-offs behind them.
- **[Security policy](SECURITY.md)**: how to report a vulnerability, and the
  audit status.
- **[Demo site](https://karpeleslab.github.io/purecrypto/)**: the real
  library running in the browser through the C ABI compiled to WebAssembly
  (source in [`web/`](web/)).
- **[API reference](https://docs.rs/purecrypto)** on docs.rs.

## Design principles

- **No foreign code.** No C, no assembly borrowed from other libraries, no
  third-party crypto crates. Everything is implemented here, in Rust. The
  only dependencies are two sibling pure-Rust `no_std` crates under the
  same maintainership, `compcol` (the zlib codec for RFC 8879 certificate
  compression) and `cacrt` (the embedded root bundle), plus the optional
  `tokio` / `mio` I/O adapters.
- **Constant time by default.** Secret-dependent values flow through the
  [`ct`](src/ct) layer (branchless equality, selection, ordering). Where an
  algorithm is intrinsically variable-time (RSA key generation, the
  extended-Euclid inverse), it is used only on one-time or key-generation
  paths and documented as such.
- **`no_std` core.** The crate is `#![no_std]`; `alloc` and `std` are
  opt-in features (`std` is the default and implies `alloc`). Most
  primitives, and the fixed-curve half of `ec`, need no allocator at all.
- **Validated.** Where a standard publishes test vectors they run in CI
  (RFC 8439, RFC 8032, RFC 8448, FIPS 203/204/205 ACVP, BIP340, and more),
  and the X.509, TLS and PQC stacks are cross-checked against OpenSSL 3.5.
  See [docs/validation.md](docs/validation.md).

## What is inside

Single crate, one Cargo feature per module. Details, test-vector sources and
known limitations for each row live in [docs/validation.md](docs/validation.md).

| Feature | What it provides |
| --- | --- |
| `ct` (always on) | Branchless equality, selection, ordering, and `Choice` |
| `hash` | SHA-2, SHA-3 / Keccak, SHAKE, cSHAKE, KMAC, TupleHash, ParallelHash, TurboSHAKE, KangarooTwelve, BLAKE2b/2s/2X, BLAKE3, SM3, Whirlpool, Streebog, MD2/4/5, SHA-1, RIPEMD-160; HMAC and the `Mac` trait |
| `cipher` | AES (constant-time, table-free), SM4, Camellia, ARIA; CBC/CFB/OFB/CTR; AES-GCM, CCM, ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM-SIV, AES-SIV, AEGIS-128L/256; XTS; AES-KW/KWP; DES/3DES for legacy interop |
| `mac` | AES-CMAC, GMAC, UMAC-64/128 |
| `kdf` | HKDF, PBKDF2, scrypt, Argon2id/2d/2i, SP 800-108 KBKDF, PBES2 |
| `rng` | `RngCore`/`CryptoRng`, HMAC-DRBG, `OsRng` (Unix, Linux `getrandom(2)`, Windows, Apple, WASI, browser wasm) |
| `bignum` | Const-generic `Uint` and runtime `BoxedUint`, Montgomery arithmetic, constant-time modexp |
| `rsa` | Key generation (512 to 65536 bits), PKCS#1 v1.5, OAEP, PSS, blinded CRT with fault check, PKCS#1 DER/PEM |
| `dh` | Finite-field DH over RFC 3526 groups 14 to 18 plus RFC 4419 group exchange |
| `ec` | ECDSA/ECDH on P-256, P-384, P-521, secp256k1, Brainpool; X25519, X448, Ed25519, Ed448; SM2 signature and encryption |
| `bip340` | BIP340 Schnorr signatures over secp256k1 |
| `zkp-*` | Experimental secp256k1 extensions mirroring `secp256k1-zkp`: sign-to-contract, ECDSA adaptor signatures, Pedersen commitments, Borromean range proofs, asset surjection proofs, half-aggregation, ring-signature whitelisting (`zkp` enables all; no semver guarantee) |
| `ristretto255` | The RFC 9496 prime-order group (stable API) |
| `hazmat-*` | Low-level secp256k1, edwards25519 and ML-DSA arithmetic for threshold / FROST work (no semver guarantee) |
| `mlkem` | ML-KEM-512/768/1024 (FIPS 203), no allocator needed |
| `mldsa` | ML-DSA-44/65/87 (FIPS 204), hedged and deterministic |
| `slhdsa` | SLH-DSA, all 12 parameter sets (FIPS 205) |
| `falcon` | Falcon-512/1024 (FN-DSA, FIPS 206 draft) with a constant-time emulated-float sampler |
| `lms`, `xmss` | LMS/HSS and XMSS/XMSS^MT stateful hash-based signatures (SP 800-208) |
| `ascon` | Ascon-AEAD128, Ascon-Hash256, XOF128, CXOF128 (SP 800-232) |
| `aez` | AEZ v5 robust authenticated encryption |
| `hpke` | RFC 9180: 4 KEMs, 3 KDFs, 3 AEADs, all four modes |
| `key` | An `EVP_PKEY`-style `PrivateKey`/`PublicKey` facade over every asymmetric key, with generic PKCS#8/SPKI decoding |
| `der` | DER reader/writer, base64, PEM |
| `x509` | Certificates, CSRs, CRLs, OCSP, SCTs, chain building with name constraints and policy processing, CA issuance |
| `pkcs12` | PKCS#12 / PFX archives, both directions |
| `tls` | TLS 1.2 and 1.3, client and server, sans-I/O; mTLS, ALPN, resumption, 0-RTT, KeyUpdate, exporters, raw public keys, X25519MLKEM768 |
| `dtls` | DTLS 1.2 and 1.3 (RFC 6347 / RFC 9147): cookies, fragmentation, replay windows, ACK-driven retransmission, KeyUpdate |
| `quic` | QUIC v1 (RFC 9000/9001/9002) plus DATAGRAM (RFC 9221), sans-I/O |
| `ech` | Encrypted Client Hello (draft-ietf-tls-esni-22), client and server |
| `cert-compression` | RFC 8879 certificate compression |
| `embedded-roots` | A curated root-certificate bundle (`RootCertStore::with_embedded_roots()`) |
| `tls-legacy` | SSL 3.0 / TLS 1.0 / TLS 1.1 with CBC suites. **Deprecated and insecure**, off by default, for talking to legacy devices only |
| `tokio`, `mio` | Async and non-blocking I/O adapters for `tls` |
| `ffi` | The C ABI (`include/purecrypto.h`) |
| `cli` | The `purecrypto` binary |

## Cargo features

The default feature set is `std` plus most modules and the CLI. Opt-in
features are `quic`, `hpke`, `ech`, `falcon`, `ristretto255`, `bip340`, the
`zkp-*` set, the `hazmat-*` set, `tls-legacy`, `wasi-getrandom`, `ffi`,
`tokio` and `mio`. Disable the defaults for a `no_std` build and re-enable
only what you need:

```toml
# Bare no_std, no allocator: `ct` plus whatever primitives you turn on.
purecrypto = { version = "0.8", default-features = false, features = ["hash", "cipher"] }

# no_std ML-KEM-768, no allocator:
purecrypto = { version = "0.8", default-features = false, features = ["mlkem"] }

# no_std elliptic curves without an allocator: P-256 ECDSA/ECDH, X25519,
# X448, Ed25519, Ed448. Add `alloc` for the runtime multi-curve path
# (P-384/P-521/secp256k1/Brainpool), SM2, and the DER/PEM codecs.
purecrypto = { version = "0.8", default-features = false, features = ["ec"] }

# Post-quantum signing only:
purecrypto = { version = "0.8", default-features = false, features = ["mldsa", "slhdsa"] }

# TLS engine for a no_std target with an allocator:
purecrypto = { version = "0.8", default-features = false, features = ["tls", "dtls"] }
```

Each feature pulls in only what it needs. `alloc` is required by anything
that must size buffers at runtime (DH, X.509, TLS, the boxed RSA/EC paths);
`ct`, `hash`, `cipher`, `kdf`, `mlkem`, `mldsa`, `slhdsa`, `lms`, `xmss`,
`aez`, `rsa` and the fixed-curve half of `ec` build without it.

## Building

```sh
cargo build                                          # default: std + CLI binary
cargo build --no-default-features                    # bare no_std
cargo build --no-default-features --features alloc   # no_std + alloc
cargo test                                           # full suite
cargo test --release -- --ignored                    # heavy KATs (SLH-DSA 's' sets, RSA keygen)
```

Requires Rust 1.89 or newer (edition 2024); the MSRV is declared in
`Cargo.toml` and enforced in CI, which also builds bare-metal
(`thumbv7em-none-eabi`), 32-bit ARM, RISC-V, wasm32 and WASI targets.

For WebAssembly, build the `ffi` feature as a `cdylib` for
`wasm32-unknown-unknown`; the module imports one host function,
`purecrypto.random_get`, for entropy. [`web/`](web/) is a complete example.

## Command-line tool

One binary, OpenSSL-style subcommands. Every subcommand reads `stdin` when
no `-in` is given and writes to `stdout` when no `-out` is given. Private
material is written mode 0600 and never overwrites an existing file. The
full reference with every flag is in [docs/cli.md](docs/cli.md).

| Subcommand | Purpose | Example |
| --- | --- | --- |
| `hash` / `dgst` | Message digests | `purecrypto hash sha3-256 file` |
| `mac` | HMAC, AES-CMAC, GMAC | `purecrypto mac -alg hmac-sha256 -keyfile k -in msg` |
| `kdf` | HKDF, PBKDF2, scrypt, Argon2, KBKDF | `purecrypto kdf argon2 -variant 2id -password-file - -salt HEX -t-cost 3 -m-cost 65536 -len 32` |
| `enc` | AEAD encrypt/decrypt, AES key wrap | `purecrypto enc -alg AES-256-GCM -keyfile k -nonce HEX -in plain -out ct` |
| `rand` | OS randomness | `purecrypto rand 32` |
| `genpkey` | Keys: RSA, EC, SM2, Ed25519/448, ML-DSA, ML-KEM, SLH-DSA, LMS/HSS, XMSS | `purecrypto genpkey -algorithm EC -curve P-256 -out ec.pem` |
| `pkey` | Inspect or convert a key | `purecrypto pkey -in key.pem -pubout` |
| `pkeyutl` | Sign, verify, encrypt, decrypt with any key | `purecrypto pkeyutl sign -inkey k.pem -in msg -out msg.sig` |
| `kem` | ML-KEM keygen / encaps / decaps | `purecrypto kem encaps -peer ek.bin -out-ct ct -out-ss ss` |
| `kex` | X25519, X448, ECDH shared secrets | `purecrypto kex -alg X25519 -key my.pem -peer their.pub.pem` |
| `req` | PKCS#10 CSRs | `purecrypto req -key leaf.pem -subj /CN=leaf -out leaf.csr` |
| `x509` | Self-signed certs, issue from CSR, inspect | `purecrypto x509 -req -in leaf.csr -CA ca.crt -CAkey ca.pem -san leaf.example -out leaf.crt` |
| `ca` | A directory-backed development CA with revocation and CRLs | `purecrypto ca init -dir ./myca -cn "My CA"` |
| `crl` | Parse, verify, query CRLs | `purecrypto crl -in x.crl -verify -CAfile ca.crt` |
| `s_client`, `s_server` | TLS 1.3 / 1.2 test client and server (also DTLS and QUIC via flags) | `purecrypto s_client -connect example.com:443 -alpn h2` |
| `s_dtls_client`, `s_dtls_server` | DTLS 1.2 / 1.3 | `purecrypto s_dtls_server -dtls1_3 -accept 0.0.0.0:5685 -cert c.pem -key k.pem` |
| `q_client`, `q_server` | QUIC v1 | `purecrypto q_client -connect localhost:4434 -alpn h3` |

Two behaviours worth knowing: `s_client` verifies the server certificate by
default (against the embedded roots or `-CAfile`) and prints a loud warning
under `-insecure`, and a TCP close without a TLS `close_notify` is reported
as a possible truncation with a non-zero exit.

## Library usage

The idiomatic Rust API is documented on
[docs.rs/purecrypto](https://docs.rs/purecrypto). Runtime algorithm
selection is available where it helps:

```rust
use purecrypto::hash::HashAlgorithm;

// `HashAlgorithm` names every digest in the crate; `Hasher` holds the state
// inline (no allocation) and implements `hash::DynDigest`.
let alg: HashAlgorithm = "sha256".parse().unwrap();
let mut h = alg.hasher();                 // also an io::Write / fmt::Write sink
h.update(b"a");
h.update(b"bc");
assert_eq!(format!("{}", h.finalize()).len(), 64);   // hex via Display
```

### TLS, DTLS and QUIC configuration

All four handshake versions (TLS 1.2, TLS 1.3, DTLS 1.2, DTLS 1.3) and both
roles share one API: `tls::Config` plus `tls::Connection`. The version range
is chosen with `versions(min, max)` (or the `tls_only()` / `dtls()`
shorthands); the role is chosen when the connection is built with
`Connection::client(&cfg)` or `Connection::server(&cfg)`. QUIC reuses the
same `Config` for its TLS layer.

```text
// Client (TLS or DTLS, any version):
Config::builder()
    .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3)
    .rng(Arc::new(OsRng))                     // required; or a TPM/HSM EntropySource
    .roots(roots)
    .server_name("example.com")
    .alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    .record_size_limit(4096)                  // RFC 8449
    .try_identity(client_chain, client_key)?  // mTLS; checks the key matches the leaf
    .build();

// Server:
Config::builder()
    .tls_only()
    .rng(Arc::new(OsRng))
    .try_identity(chain, SigningKey::Ecdsa(key))?   // Rsa, Ecdsa, Ed25519, Ed448, MlDsa*, External
    .alpn(...)
    .ticket_key([0u8; 32])                    // enables NewSessionTicket (rotate; see docs)
    .max_early_data(16384)                    // accept up to N bytes of 0-RTT
    .client_auth(ClientAuth { roots, required: true })   // mTLS
    .build();

// DTLS server (one Connection per peer address):
Config::builder()
    .dtls()
    .rng(Arc::new(OsRng))
    .try_identity(chain, key)?
    .cookie_secret(current)                   // amplification defence
    .previous_cookie_secret(old)              // optional: honour cookies across a rotation
    .peer_socket_addr(peer)                   // required whenever cookies are on
    .max_record_size(1200)                    // MTU ceiling
    .build();
```

There is no implicit RNG: `Connection::client` / `Connection::server` return
`MissingEntropySource` unless `rng(...)` was set, which is what lets a TPM or
HSM supply entropy instead of the OS. `try_identity` and `try_private_key` fail at configuration time when the
private key does not belong to the leaf certificate; the older `identity` /
`private_key` builders skip that check. A cookie-requiring DTLS server needs
`peer_socket_addr` (or `peer_address`), because the cookie binds the
client's address; without it, `Connection::server` refuses to start rather
than silently becoming a UDP reflection amplifier.

After a handshake completes, both sides expose:

- `alpn_selected()`: the negotiated ALPN name, if any.
- `tls_exporter(label, context, out)`: RFC 8446 §7.5 / RFC 5705 keying
  material.
- `peer_certificates()`: the validated chain, leaf first (also restored on a
  resumed mTLS session).
- `received_close_notify()`: whether the peer closed cleanly. A transport
  EOF without it is a truncation.
- Client only: `take_session()` returns a `ResumptionSession` derived from
  the server's NewSessionTicket; pass it to `resumption_session(...)` next
  time (TLS 1.3 PSK or TLS 1.2 RFC 5077 ticket). `write_early_data(&[u8])`
  sends 0-RTT on such a resumed connection.

**0-RTT replay caveat.** RFC 8446 §8: an active attacker can replay 0-RTT
data. The built-in `ReplayWindow` blocks repeated binders within one
process; cross-process defences are the application's job. Only send
idempotent requests through `write_early_data`.

### Signature algorithms

X.509 and TLS verification dispatch through a registry of signature
algorithms gated by a strict whitelist, `SignaturePolicy`. The default
(`modern()`) is the IANA-blessed set plus ML-DSA, with RSA keys of 2048 bits
or more. To accept SHA-1 RSA for a legacy peer, or to go PQC-only:

```rust
use purecrypto::signature_registry::SignaturePolicy;
use purecrypto::tls::{Config, RootCertStore};

let legacy = Config::builder()
    .roots(RootCertStore::new())
    .signature_policy(SignaturePolicy::modern().permit("rsa-pkcs1-sha1").with_min_rsa_bits(1024))
    .build();

let pqc_only = Config::builder()
    .roots(RootCertStore::new())
    .signature_policy(SignaturePolicy::empty().permit("ml-dsa-65").permit("ed25519"))
    .build();
```

The full registry table and `try_permit` (for ids that come from
configuration) are in [docs/signature-registry.md](docs/signature-registry.md).

## C library

Prebuilt archives (the CLI, the static and shared C libraries, and the
header) are attached to each
[GitHub release](https://github.com/KarpelesLab/purecrypto/releases) for
Linux, macOS and Windows. To build them yourself:

```sh
cargo rustc --lib --release --features ffi --crate-type cdylib    # target/release/libpurecrypto.so
cargo rustc --lib --release --features ffi --crate-type staticlib # target/release/libpurecrypto.a
cc app.c -I include target/release/libpurecrypto.a -lpthread -ldl -lm -o app
```

The API is declared in [`include/purecrypto.h`](include/purecrypto.h):
hashing, HMAC/CMAC/GMAC, KDFs, randomness, AEADs and key wrap, RSA, ECDSA,
Ed25519/Ed448, X25519/X448, SM2, ML-KEM, ML-DSA, SLH-DSA, LMS/HSS, XMSS,
CSRs, X.509 and CRLs, and sans-I/O TLS, DTLS and QUIC. Every function returns
a `PcStatus` (`PC_OK` or a negative code, for example `PC_CLOSED` once the
peer's `close_notify` has been processed, or `PC_KEY_MISMATCH` when a
certificate is configured with the wrong key). Variable-length output uses
an in/out length buffer; stateful objects are opaque handles freed by the
library; panics never cross the boundary.

The TLS surface mirrors OpenSSL's memory BIO: the caller pumps wire bytes
through `pc_tls_feed` / `pc_tls_pop` and application bytes through
`pc_tls_send` / `pc_tls_recv`. A DTLS server with cookies enabled needs
`pc_dtls_cfg_set_peer_addr` for each peer. The smoke tests in
[`tests/`](tests/) (`ffi_smoke.c`, `ffi_tls_smoke.c`, `ffi_dtls_smoke.c`,
`ffi_quic_smoke.c`) are complete, runnable examples.

## Security status

This crate has not had a third-party human audit and is not FIPS
validated. Whole-codebase automated audits are run regularly and their
fixes land on `master`; see [SECURITY.md](SECURITY.md) and
[docs/validation.md](docs/validation.md) for what that does and does not
cover, and report vulnerabilities privately through GitHub's security
advisories.

## License

Licensed under the [MIT License](LICENSE).
