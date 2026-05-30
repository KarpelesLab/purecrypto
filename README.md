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
| Symmetric cipher | `cipher`    | ✅ AES-128/192/256 (constant-time, table-free); CBC/CFB/OFB/CTR; GCM, CCM and ChaCha20-Poly1305 (AEAD); XTS (disk encryption); AES-KW + AES-KWP (RFC 3394 / 5649); DES + 3-DES (EDE3 / EDE2) with `Cbc64` for legacy interop |
| MAC              | `mac`       | ✅ UMAC-64 / UMAC-128 (RFC 4418); HMAC lives in `hash` |
| Bignum (CT)      | `bignum`    | ✅ `Uint<LIMBS>` and runtime-sized `BoxedUint`, widening mul, Montgomery modular arith, modexp, Fermat & extended-Euclid inverse |
| Asymmetric keys  | `rsa`       | ✅ RSA keygen (compile-time + runtime, 512–65536 bits), raw, PKCS#1 v1.5 enc/sign, OAEP enc, PSS sign/verify, PKCS#1 DER/PEM |
| Key derivation   | `kdf`       | ✅ PBKDF2, HKDF, scrypt (RFC 7914), Argon2id/2d/2i (RFC 9106) |
| Elliptic curve   | `ec`        | ✅ ECDSA/ECDH on P-256/P-384/P-521/secp256k1 (runtime multi-curve) + fast const-generic P-256, X25519, Ed25519 (EdDSA, RFC 8032) |
| Post-quantum KEM | `mlkem`     | ✅ ML-KEM-512 / 768 / 1024 (FIPS 203), `no_std`/no-alloc; OpenSSL-interop on -768 |
| Post-quantum sig | `mldsa`     | ✅ ML-DSA-44/65/87 (FIPS 204); hedged + deterministic; FIPS 204 ACVP + OpenSSL-interop |
| Post-quantum sig | `slhdsa`    | ✅ SLH-DSA, all 12 sets (FIPS 205, SHA-2/SHAKE × 128/192/256 × s/f); FIPS 205 ACVP + OpenSSL-interop |
| Diffie-Hellman   | `dh`        | ✅ Finite-field DH over RFC 3526 MODP groups (group14..group18) + RFC 4419 group-exchange, for SSH / legacy TLS / IKE interop (new code: ECDH in `ec`) |
| ASN.1 / DER      | `der`       | ✅ DER reader/writer, base64, PEM |
| X.509            | `x509`      | ✅ self-signed + CA issuance (RSA, ECDSA & Ed25519), PKCS#10 CSRs, parse, verify; PKIX SPKI; RFC 5280 nameConstraints enforcement across the chain; OpenSSL-interop |
| TLS              | `tls`       | ✅ TLS 1.2 and 1.3, DTLS 1.2 and 1.3 client + server (sans-I/O core + blocking `Stream`); x25519/secp256r1 + X25519MLKEM768 hybrid (1.3); AES-GCM & ChaCha20-Poly1305; Ed25519/ECDSA/RSA auth; ALPN, record_size_limit (RFC 8449), TLS-Exporter (RFC 5705); PSK session resumption + 0-RTT (early_data) with an anti-replay window (1.3); RFC 5077 session tickets (1.2); mTLS / client certificate authentication; HelloRetryRequest (client + server); bidirectional KeyUpdate; RFC 8448 KATs; DTLS HelloVerifyRequest / cookie DoS guard, handshake fragmentation + reassembly, 64-bit sliding-window anti-replay; DTLS 1.3 encrypted sequence numbers + ACK-driven retransmission. |
| HPKE             | `hpke`     | ✅ RFC 9180 hybrid public-key encryption — 4 KEMs × 3 KDFs × 3 AEADs + ExportOnly, all four modes (Base/PSK/Auth/AuthPSK) |
| ECH              | `ech`      | ✅ draft-ietf-tls-esni-22 Encrypted Client Hello — client + server, retry_configs, HRR confirmation signal, bit-shape GREASE |
| QUIC             | `quic`     | ✅ QUIC v1 (RFC 9000) + QUIC-TLS (RFC 9001) + recovery / congestion (RFC 9002) + DATAGRAM extension (RFC 9221), sans-I/O |
| Cert compression | `cert-compression` | ✅ RFC 8879 TLS 1.3 certificate compression (zlib via the `compcol` sibling crate) |
| C ABI            | `ffi`       | ✅ hashing/HMAC, RNG, AEAD + AES-KW, RSA, ECDSA, Ed25519, ML-KEM, ML-DSA, SLH-DSA, X.509, TLS / DTLS (sans-I/O); opaque handles + caller buffers; `include/purecrypto.h` |
| CLI              | (binary)    | ✅ `hash`, `rand`, `genpkey` (classical + PQ), `pkey`, `req`, `x509` (CA), `s_client`, `s_server`, `s_dtls_client`, `s_dtls_server` |

## CLI + C-API coverage matrix

Each functional area below is callable from the Rust library, the
`purecrypto` CLI, and the C ABI (`include/purecrypto.h`).

| Area                                  | CLI                                  | C API                                                              |
| ------------------------------------- | ------------------------------------ | ------------------------------------------------------------------ |
| Hashing (SHA-2/3, BLAKE2/3, SM3, …)   | `hash`                               | `pc_digest`, `pc_hash_*`                                           |
| HMAC (SHA-1, SHA-2, SHA-3, SM3, …)    | `mac`                                | `pc_hmac`                                                          |
| KDFs (HKDF, PBKDF2, scrypt, Argon2)   | `kdf hkdf\|pbkdf2\|scrypt\|argon2`   | `pc_hkdf`, `pc_pbkdf2`, `pc_scrypt`, `pc_argon2`                   |
| AEAD (AES-GCM/CCM, ChaCha20-Poly1305) | `enc`                                | `pc_aead_encrypt`, `pc_aead_decrypt`                               |
| AES key wrap (RFC 3394/5649)          | `enc -alg AES-KW\|AES-KWP`           | `pc_aes_kw_wrap/unwrap`, `pc_aes_kwp_wrap/unwrap`                  |
| Randomness                            | `rand`                               | `pc_rand_bytes`                                                    |
| RSA keygen + PKCS#1 sign/verify       | `genpkey`, `req`, `x509`, `pkeyutl`  | `pc_rsa_generate`, `pc_rsa_sign_pkcs1`, `pc_rsa_verify_pkcs1`      |
| RSA-PSS sign/verify                   | `pkeyutl sign/verify -pkeyopt pss`   | `pc_rsa_sign_pss`, `pc_rsa_verify_pss`                             |
| RSA-OAEP encrypt/decrypt              | `pkeyutl encrypt/decrypt -pkeyopt oaep` | `pc_rsa_encrypt_oaep`, `pc_rsa_decrypt_oaep`                    |
| ECDSA keygen + sign/verify            | `genpkey -alg EC`, `pkeyutl`         | `pc_ec_generate`, `pc_ec_sign`, `pc_ec_verify`                     |
| Ed25519 sign/verify                   | `genpkey -alg ED25519`, `pkeyutl`    | `pc_ed25519_*`                                                     |
| ECDH on NIST curves                   | `kex -alg ECDH-P{256,384,521}`       | `pc_ecdh`                                                          |
| X25519                                | `kex -alg X25519`                    | `pc_x25519`, `pc_x25519_public`                                    |
| ML-KEM (FIPS 203)                     | `kem keygen\|encaps\|decaps`         | `pc_mlkem_*`                                                       |
| ML-DSA (FIPS 204)                     | `pkeyutl sign/verify` (ML-DSA keys)  | `pc_mldsa_*`                                                       |
| SLH-DSA (FIPS 205)                    | `pkeyutl sign/verify` (SLH-DSA keys) | `pc_slhdsa_*`                                                      |
| CSR (PKCS#10)                         | `req`                                | `pc_csr_create_rsa`, `pc_csr_from_pem`, `pc_csr_verify_self_signed`|
| X.509 certificate parse + verify      | `x509`, `ca`                         | `pc_cert_*`, `pc_ec_self_signed_pem`                               |
| CRL parse + verify                    | `crl`                                | `pc_crl_*`                                                         |
| TLS 1.2 / 1.3 client + server         | `s_client`, `s_server`               | `pc_tls_cfg_*`, `pc_tls_*` (memory-BIO style)                      |
| DTLS 1.2 / 1.3 client + server        | `s_dtls_client`, `s_dtls_server`     | `pc_tls_cfg_*` (`PC_DTLS_1_*` selector), `pc_dtls_next_timeout/on_timeout` |

The C ABI is sans-I/O for TLS/DTLS: the caller pumps wire bytes through
`pc_tls_feed` / `pc_tls_pop` and application bytes through `pc_tls_send` /
`pc_tls_recv` (mirrors OpenSSL's `BIO_s_mem`).

## Cargo features

Default is `std + cli` with every module on. Disable defaults for a `no_std`
build and re-enable only what you need:

```toml
# Bare no_std, no allocator: just `ct` and primitives that fit.
purecrypto = { version = "0.3", default-features = false }

# no_std core + ML-KEM-768 (no alloc):
purecrypto = { version = "0.3", default-features = false, features = ["mlkem"] }

# Library with PQ signing only:
purecrypto = { version = "0.3", default-features = false, features = ["mldsa", "slhdsa"] }
```

Module gates: `hash`, `cipher`, `mac`, `kdf`, `bignum`, `rng`,
`linux-getrandom`, `rsa`, `dh`, `der`, `ec`, `x509`, `tls`, `dtls`, `quic`,
`mlkem`, `mldsa`, `slhdsa`, `hpke`, `ech`, `cert-compression`, `ffi`, `cli`.
Each pulls in only its own dependencies. `alloc` is required by anything that
needs heap (most things except `ct`, `hash`, `cipher`, and the no-alloc
`mlkem` core).

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

# Post-quantum KEM (FIPS 203) — all three security levels
purecrypto genpkey -algorithm ML-KEM-512              -out mlkem512.pem
purecrypto genpkey -algorithm ML-KEM-768              -out mlkem768.pem
purecrypto genpkey -algorithm ML-KEM-1024             -out mlkem1024.pem
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

# Negotiate HTTP/2 (or fall back to http/1.1) via ALPN
purecrypto s_client -connect example.com:443 -alpn h2,http/1.1

# Dump the negotiated secrets in NSS SSLKEYLOGFILE format — Wireshark can
# then decrypt the captured pcap.
purecrypto s_client -connect example.com:443 -keylogfile sslkeys.log

# Present a client certificate (mTLS). The key may be Ed25519 (PKCS#8) or
# ECDSA (SEC1).
purecrypto s_client -connect server:443 -cert client.pem -key client.key
```

The client offers `X25519MLKEM768` (post-quantum hybrid) first, then `x25519`
and `secp256r1`; all three TLS 1.3 cipher suites
(`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`,
`TLS_CHACHA20_POLY1305_SHA256`); and Ed25519, ECDSA, and RSA peer signatures.

### `s_server` — TLS 1.3 echo / `-www` server

A one-shot test server: it binds, accepts one connection, performs the
handshake, exchanges data, and exits.

```sh
# Plain TLS echo:
purecrypto s_server -cert server.pem -key server.key -accept 4433

# Serve a fixed HTTP response (text/plain) for one request:
purecrypto s_server -cert server.pem -key server.key -accept 4433 -www

# Negotiate ALPN, listen on 8443:
purecrypto s_server -cert server.pem -key server.key -accept 8443 -alpn h2,http/1.1

# mTLS: require + verify a client cert against the bundle in `client-ca.pem`.
purecrypto s_server -cert server.pem -key server.key -accept 8443 \
                    -Verify client-ca.pem
```

### TLS 1.2

`s_client` / `s_server` default to TLS 1.3. Pass `-tls1_2` on either side
to force TLS 1.2. The TLS 1.2 path is ECDHE-AEAD only (AES-GCM and
ChaCha20-Poly1305) and supports mTLS plus RFC 5077 session tickets.

```sh
# Server (TLS 1.2)
purecrypto s_server -tls1_2 -accept 0.0.0.0:4443 -cert cert.pem -key key.pem

# Client (TLS 1.2)
purecrypto s_client -tls1_2 -connect example.com:443 -CAfile roots.pem
```

### DTLS — `s_dtls_client` / `s_dtls_server`

DTLS runs the TLS handshake over UDP. Either use the dedicated
`s_dtls_client` / `s_dtls_server` binaries, or pass `-dtls1_2` / `-dtls1_3`
to `s_client` / `s_server`. The two forms are equivalent.

```sh
# DTLS 1.2 echo
purecrypto s_dtls_server -dtls1_2 -accept 0.0.0.0:5684 -cert cert.pem -key key.pem
purecrypto s_dtls_client -dtls1_2 -connect localhost:5684

# DTLS 1.3 echo
purecrypto s_dtls_server -dtls1_3 -accept 0.0.0.0:5685 -cert cert.pem -key key.pem
purecrypto s_dtls_client -dtls1_3 -connect localhost:5685

# Equivalent via s_client / s_server with version flags
purecrypto s_server -dtls1_3 -accept 0.0.0.0:5685 -cert cert.pem -key key.pem
purecrypto s_client -dtls1_3 -connect localhost:5685
```

The DTLS server stands up a HelloVerifyRequest cookie exchange (1.2) or
HelloRetryRequest cookie (1.3) before allocating any per-connection
state, and both directions install a 64-bit sliding-window replay
filter once the handshake-protected keys are in place. The default
record size is 1200 bytes to stay below common path MTUs; override with
`-mtu`.

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

A two-process mTLS handshake on a single host (client cert presented to the
server, both keys Ed25519):

```sh
# CA + server cert + client cert
purecrypto genpkey -algorithm ED25519 -out ca.pem
purecrypto x509 -new --ca -key ca.pem -subj "/CN=Local CA" -out ca.crt
purecrypto genpkey -algorithm ED25519 -out server.pem
purecrypto req -key server.pem -subj "/CN=127.0.0.1" \
               -addext "subjectAltName=DNS:127.0.0.1" -out server.csr
purecrypto x509 -req -in server.csr -CA ca.crt -CAkey ca.pem -out server.crt
purecrypto genpkey -algorithm ED25519 -out client.pem
purecrypto req -key client.pem -subj "/CN=alice" -out client.csr
purecrypto x509 -req -in client.csr -CA ca.crt -CAkey ca.pem -out client.crt

# In one terminal — server requires + verifies client certs against ca.crt:
purecrypto s_server -cert server.crt -key server.pem -accept 8443 -Verify ca.crt -www

# In another terminal — client presents its cert + key:
purecrypto s_client -connect 127.0.0.1:8443 -CAfile ca.crt \
                    -cert client.crt -key client.pem -alpn http/1.1 \
                    -keylogfile keys.log
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

### Versions and transports

`purecrypto` ships both TLS (TCP) and DTLS (UDP) at two protocol
versions each:

All four versions (TLS 1.2, TLS 1.3, DTLS 1.2, DTLS 1.3) and both roles
(client, server) share **one** public API: [`tls::Config`] +
[`tls::Connection`]. The version is selected by
`Config::builder().versions(min, max).build()`; the role is selected at
connection-construction time via `Connection::client(&cfg)` or
`Connection::server(&cfg)`.

- **TLS 1.2** is ECDHE-AEAD only (AES-128/256-GCM, ChaCha20-Poly1305) —
  no static RSA, no static DH, no CBC. Forward secrecy by construction.
  Includes mTLS and RFC 5077 stateless session tickets.
- **TLS 1.3** is the full RFC 8446 with PSK resumption, 0-RTT,
  exporter, ALPN, mTLS, and downgrade-detection.
- **DTLS 1.2** (RFC 6347) carries the TLS 1.2 handshake over UDP with
  HelloVerifyRequest cookies, handshake fragmentation/reassembly,
  replay protection, and retransmission. Negotiates the same
  ECDHE-AEAD suites × groups × signature schemes the TLS 1.2 path
  supports.
- **DTLS 1.3** (RFC 9147) carries the TLS 1.3 handshake over UDP with
  selective ACK reliability, encrypted sequence numbers, and a
  HelloRetryRequest cookie. Negotiates the same TLS 1.3 suites,
  groups (including `X25519MLKEM768`), and signature schemes as the
  TLS 1.3 path.

### TLS 1.3

The `tls` module is a sans-I/O TLS 1.3 implementation with a thin
`std::io::Read + Write` adapter for blocking TCP. The full feature surface,
configured per side:

```text
// Client (TLS or DTLS, any version):
Config::builder()
    .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_3)
    .roots(roots)
    .server_name("example.com")
    .alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    .record_size_limit(4096)             // RFC 8449
    .identity(client_chain, client_key)  // mTLS (any SigningKey)
    .build();

// Server (TLS or DTLS, any version):
Config::builder()
    .tls_only()                          // shorthand for versions(TLSv1_2, TLSv1_3)
    .identity(chain, SigningKey::Rsa(rsa) | SigningKey::Ecdsa(ec) | ...)
    .alpn(...)
    .ticket_key([0u8; 32])               // enables NewSessionTicket emission
    .max_early_data(16384)               // accept up to N bytes of 0-RTT
    .client_auth(ClientAuth { roots, required: true }) // mTLS
    .build();

// DTLS variant:
Config::builder()
    .dtls()                              // shorthand for versions(DTLSv1_2, DTLSv1_3)
    .identity(chain, key)
    .cookie_secret([0u8; 32])            // amplification defense
    .max_record_size(1200)               // MTU ceiling
    .build();

let mut conn = Connection::client(&cfg)?;   // or Connection::server(&cfg)
```

After a handshake completes, both sides expose:

- `connection.alpn_protocol()` — the negotiated ALPN name, if any.
- `connection.tls_exporter(label, context, out)` — RFC 8446 §7.5 / RFC 5705
  application-layer keying material.
- `connection.peer_certificates()` — the validated chain (leaf first).
- (client) `connection.take_session()` — moves out a `StoredSession`
  derived from the server's NewSessionTicket; pass it to
  `ClientConfig::with_session` next time you connect to the same server.
- (client) `connection.write_early_data(&[u8])` — sends application data
  under the early-traffic key before `ServerHello` arrives, valid only on a
  resumed connection whose session enabled 0-RTT.

**0-RTT replay caveat.** RFC 8446 §8: 0-RTT data is replayable by an active
attacker, since the server cannot bind the early bytes to a unique
client-server handshake instance. The provided `ReplayWindow` blocks repeated
binders within a process, but cross-process / cross-server replay defenses
are application-level. Mark any data sent via `write_early_data` as
idempotent (a HEAD/GET, an idempotent RPC, …) and never as a state-changing
write.

```rust,no_run
use purecrypto::tls::{Config, Connection, HandshakeStatus, RootCertStore};

let roots = RootCertStore::new();        // populate from a PEM bundle …
let cfg = Config::builder()
    .tls_only()
    .roots(roots)
    .server_name("example.com")
    .alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()])
    .build();
let mut conn = Connection::client(&cfg).unwrap();

// Drive the handshake: pop wire bytes from `conn`, send them, recv from
// the peer, feed them back. The sans-I/O surface is the same for TLS and
// DTLS — the only difference is "stream" vs "datagram" framing.
# fn _h(_: Connection) -> std::io::Result<()> { Ok(()) }
```


### Signature algorithms

X.509 chain validation and TLS 1.3 `CertificateVerify` both dispatch through
the [`signature_registry`](src/signature_registry.rs) module. Every signature
primitive purecrypto can do appears as a registry entry; a strict whitelist
[`SignaturePolicy`] controls which ones a verifier will accept.

#### Registry

| `id` (whitelist key)        | X.509 OID                       | TLS 1.3 scheme | Default `modern()` |
| --------------------------- | ------------------------------- | -------------- | ------------------ |
| `rsa-pkcs1-sha1`            | `1.2.840.113549.1.1.5`          | (none)         | opt-in |
| `rsa-pkcs1-sha256`          | `1.2.840.113549.1.1.11`         | `0x0401`       | ✅ |
| `rsa-pkcs1-sha384`          | `1.2.840.113549.1.1.12`         | `0x0501`       | ✅ |
| `rsa-pkcs1-sha512`          | `1.2.840.113549.1.1.13`         | (none)         | opt-in |
| `rsa-pss-rsae-sha256`       | `1.2.840.113549.1.1.11` (RSAE)  | `0x0804`       | ✅ |
| `rsa-pss-rsae-sha384`       | `1.2.840.113549.1.1.12` (RSAE)  | `0x0805`       | ✅ |
| `rsa-pss-rsae-sha512`       | `1.2.840.113549.1.1.13` (RSAE)  | `0x0806`       | ✅ |
| `rsa-pss-pss-sha256`        | `1.2.840.113549.1.1.10` (PSS-keys) | (none)      | opt-in |
| `ecdsa-with-sha256`         | `1.2.840.10045.4.3.2` (any curve) | (none)       | ✅ |
| `ecdsa-with-sha384`         | `1.2.840.10045.4.3.3` (any curve) | (none)       | ✅ |
| `ecdsa-with-sha512`         | `1.2.840.10045.4.3.4` (any curve) | (none)       | ✅ |
| `ecdsa-secp256r1-sha256`    | (TLS-only — strict curve)       | `0x0403`       | ✅ |
| `ecdsa-secp384r1-sha384`    | (TLS-only — strict curve)       | `0x0503`       | ✅ |
| `ecdsa-secp521r1-sha512`    | (TLS-only — strict curve)       | `0x0603`       | ✅ |
| `ecdsa-secp256r1-sha384/512`, `ecdsa-secp384r1-sha256/512`, `ecdsa-secp521r1-sha256/384` | cross-hash, policy-only | (none) | opt-in |
| `ecdsa-secp256k1-sha256/384/512` | secp256k1, policy-only      | (none)         | opt-in |
| `ed25519`                   | `1.3.101.112`                   | `0x0807`       | ✅ |
| `ml-dsa-44` / `-65` / `-87` | `2.16.840.1.101.3.4.3.17/18/19` | `0x0904/05/06` | ✅ (NIST FIPS 204) |
| `slh-dsa-sha2-128s/128f/192s/192f/256s/256f`, `slh-dsa-shake-128s/128f/192s/192f/256s/256f` | `2.16.840.1.101.3.4.3.20..31` | (none) | opt-in (FIPS 205) |

The matched-curve / matched-hash ECDSA pairs (e.g. P-256 + SHA-256) have IANA
TLS scheme codes; cross-hash pairs and all secp256k1 entries are reachable for
chain dispatch via the OID-keyed `ecdsa-with-shaN` entries — which accept any
supported curve — and as fine-grained policy-keyed entries for TLS opt-in.

ML-DSA is on the default whitelist (the modern PQC future). SLH-DSA's twelve
parameter sets are registered but never on the default whitelist: signatures
are 7–50 KB and rarely the right default for X.509 leaves.

#### Configuring the policy

```rust
use purecrypto::signature_registry::SignaturePolicy;
use purecrypto::tls::{Config, RootCertStore};

let roots = RootCertStore::new();

// Default — modern IANA-blessed set, RSA ≥ 2048 bits.
let cfg = Config::builder().roots(roots).build();

// Legacy interop: accept SHA-1 RSA and lower the RSA-bit floor to 1024.
let roots = RootCertStore::new();
let cfg = Config::builder()
    .roots(roots)
    .signature_policy(
        SignaturePolicy::modern()
            .permit("rsa-pkcs1-sha1")
            .with_min_rsa_bits(1024),
    )
    .build();

// PQC-strict: only ML-DSA + Ed25519, refuse everything classical.
let roots = RootCertStore::new();
let cfg = Config::builder()
    .roots(roots)
    .signature_policy(
        SignaturePolicy::empty()
            .permit("ml-dsa-65")
            .permit("ml-dsa-87")
            .permit("ed25519"),
    )
    .build();

// SLH-DSA chains: opt in to a single set the application expects.
let roots = RootCertStore::new();
let cfg = Config::builder()
    .roots(roots)
    .signature_policy(SignaturePolicy::modern().permit("slh-dsa-sha2-128f"))
    .build();
```

`signature_policy` on the unified [`Config`] applies to both client and
server roles — for the server it gates client-certificate validation under
mTLS. The policy is a strict whitelist:
adding an entry to the registry does NOT auto-permit it — the caller has to
add the id explicitly.

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
signing, verification and PEM I/O, ML-KEM (FIPS 203) / ML-DSA (FIPS 204) /
SLH-DSA (FIPS 205) keys, X.509 parsing/verification, and a sans-I/O TLS /
DTLS surface (`pc_tls_cfg_*`, `pc_tls_*`) including post-handshake
accessors for the negotiated cipher suite and peer SNI. Functions return a
`pc_status` code; variable-length output uses an in/out length buffer;
stateful objects are opaque handles freed by the library; panics never
cross the boundary.

## License

Licensed under the [MIT License](LICENSE).
