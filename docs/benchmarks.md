# Benchmarks

Real numbers from the in-repo harness, with notes on the constant-time
tradeoffs behind them. These are **microbenchmarks on one machine** — use them
for rough relative comparison, not as an SLA. Reproduce with:

```sh
cargo run --release --example bench --features std,cipher,hash,ec,rsa,mlkem,aez
```

## Measurement setup

- **CPU**: Intel Core i9-14900K (crypto ISA present: `aes`, `pclmulqdq`,
  `sha_ni`, `avx2`).
- **Build**: `--release` (thin-LTO), single thread, warm cache.
- **rustc**: 1.96.0 (MSRV is 1.95; newer compilers may differ slightly).
- Throughput is measured at a 64 KiB message; asymmetric ops are reported as
  latency (µs/op) and ops/s.

Because the relevant hardware instructions are present, the symmetric/hash
numbers reflect the **hardware-accelerated** backends (AES-NI, PCLMULQDQ for
GHASH, SHA-NI, AVX2 for ChaCha20/BLAKE3; see below for AVX-512). On a
machine **without** them, the crate falls back to its constant-time,
table-free software paths, which are correct and constant-time but slower
(see [tradeoffs](#constant-time-tradeoffs)).

## Symmetric (throughput, 64 KiB)

| Algorithm | MiB/s | ops/s |
|---|--:|--:|
| AES-128-GCM (encrypt) | 2532 | 40 508 |
| AES-256-GCM (encrypt) | 2392 | 38 276 |
| ChaCha20-Poly1305 (encrypt) | 1582 | 25 309 |
| AES-256 raw block (16 B) | 1782 | 116 765 967 |
| AEZ (τ=16, robust AE) | 481 | 7 695 |

### ChaCha20 and Poly1305 on AVX-512 (Zen 5)

The table above is the AVX2 picture. On a CPU with AVX-512 and IFMA the
crate runs a 16-way ChaCha20 kernel, a 4×8-lane IFMA Poly1305 kernel, and
for ChaCha20-Poly1305 a stitched loop that runs the Poly1305 multiplies
between the ChaCha20 rounds. Medians of five runs, each on a random core
in 100–180 of a shared AMD Zen 5 server (`taskset`), GB/s = 10⁹ bytes/s;
OpenSSL 3.5 (`openssl speed -evp …`; Poly1305 through `EVP_MAC`) and
libsodium measured the same way, interleaved with ours:

| Algorithm | 16 KiB | 1 MiB | OpenSSL 16 KiB | OpenSSL 1 MiB |
|---|--:|--:|--:|--:|
| ChaCha20 | 8.9 | 8.9 | 8.8 | 8.6 |
| Poly1305 | 33.4 | 40.2 | 16.0 | 17.7 |
| ChaCha20-Poly1305 (seal) | 7.4 | 8.2 | 5.8 | 5.8 |

Before these kernels the same machine gave 4.9 / 5.1 / 2.4 GB/s at 16 KiB
(ChaCha20 / Poly1305 / AEAD). libsodium: Poly1305 5.5, ChaCha20-Poly1305
1.7 GB/s at 16 KiB. ChaCha20 is at parity with OpenSSL: both are bound by
the vector ALU (about 0.52 cycles/byte), not by memory or dispatch.

## Hashes (throughput, 64 KiB)

| Algorithm | MiB/s |
|---|--:|
| SHA-256 | 2582 |
| SHA-512 | 718 |
| BLAKE3 | 2674 |

(SHA-256 reflects SHA-NI; BLAKE3 uses the AVX2 8-way backend. x86 has no
SHA-512 instruction, and the SHA-512 figure above predates the vectorised
x86_64 kernel — see below.)

### SHA-512 on AMD Zen 5

SHA-512 (and SHA-384, SHA-512/224, SHA-512/256, HMAC over them) runs an x86_64
kernel that computes the message schedule of two blocks at a time in 256-bit
vectors (AVX-512VL rotations where available, else AVX2) while BMI2 `rorx`
rounds run on the scalar side; the portable fallback is fully unrolled. Median
µs per message on a Threadripper PRO 9995WX (Zen 5, pinned to one core, five
runs; libsodium 1.0.18 and OpenSSL 3.5.8 `speed -evp sha512` / `-hmac sha512`
on the same core):

| Message | purecrypto (before) | purecrypto | libsodium | OpenSSL |
|---|--:|--:|--:|--:|
| SHA-512, 64 B | 0.226 | 0.129 | 0.177 | 0.160 |
| SHA-512, 1 KiB | 1.83 | 0.90 | 1.46 | 1.13 |
| SHA-512, 16 KiB | 25.7 | 12.3 | 20.3 | 12.4 |
| SHA-512, 1 MiB | 1628 | 780 | 1292 | 798 |
| HMAC-SHA512, 64 B | 0.855 | 0.482 | 0.745 | 0.268 |
| HMAC-SHA512, 1 KiB | 2.51 | 1.30 | 2.03 | 1.07 |
| HMAC-SHA512, 1 MiB | 1633 | 782 | 1285 | 830 |

The HMAC rows include keying (`Hmac::mac`); OpenSSL's `speed -hmac` reuses one
keyed context, so its short-message figures leave out the two key-block
compressions. The AVX2 build of the kernel (CPUs without AVX-512VL) is about
18% slower than the AVX-512VL one here, the portable path about 50% slower.

## Asymmetric (latency)

| Operation | ops/s | µs/op |
|---|--:|--:|
| RSA-2048 sign (PKCS#1 v1.5) | 117 | 8517 |
| RSA-2048 verify | 25 269 | 39.6 |
| ECDSA P-256 sign | 94 200 | 10.6 ¹ |
| ECDSA P-256 verify | 23 900 | 41.9 ¹ |
| Ed25519 sign | 4 973 | 201.1 |
| Ed25519 verify | 4 850 | 206.2 |
| X25519 (Diffie–Hellman) | 18 843 | 53.1 |
| ML-KEM-768 keygen | 43 287 | 23.1 |
| ML-KEM-768 encapsulate | 42 846 | 23.3 |
| ML-KEM-768 decapsulate | 35 157 | 28.4 |

¹ The P-256 rows were remeasured after the P-256 performance pass on a
different machine (AMD Ryzen Threadripper PRO 9995WX, rustc 1.97, pinned
with `taskset` to one core, median of five runs on random cores), next to
`openssl speed -seconds 3 ecdsap256 ecdhp256` (OpenSSL 3, assembly
`ecp_nistz256`) pinned the same way:

| P-256 operation | purecrypto µs/op | OpenSSL µs/op |
|---|--:|--:|
| ECDSA sign (SHA-256, RFC 6979) | 10.6 | 11.3 |
| ECDSA verify | 41.9 | 34.8 |
| ECDH (shared secret) | 40.6 | 26.4 |
| Key generation (`d·G`) | 8.6 | — |

Signing and key generation run the constant-time 5-bit comb over
Jacobian mixed additions; ECDH the constant-time 4-bit window ladder in
Jacobian coordinates; verification a variable-time interleaved wNAF
(width 6 for `G`, 5 for `Q`). The remaining verify / ECDH gap is the field
multiplication: OpenSSL's hand-written `mulx`/`adx` kernel against
portable `u128` Rust.

## Constant-time tradeoffs

The crate is **pure Rust with no hand-written assembly** and prioritises
constant-time, no-foreign-code implementations. That shapes the numbers:

- **Symmetric/hash are competitive** because the hot paths dispatch to CPU
  crypto instructions at run time (AES-NI, PCLMULQDQ, SHA-NI, AVX2) — these are
  themselves data-independent, so the fast path *is* the constant-time path. The
  table-free software fallback (GF(2⁸)-inversion AES S-box, bit-by-bit GHASH)
  pays a real penalty on hardware without those instructions, by design — it
  avoids the cache-timing leak that lookup tables would introduce.
- **The elliptic curves are the deliberate cost.** ECDSA/Ed25519/X25519 use
  constant-time scalar multiplication (complete Renes–Costello–Batina addition
  for the Weierstrass curves, the Montgomery ladder for X25519/X448, fixed
  double-and-add for Ed25519) with no secret-dependent table lookups or
  branches. That is slower than the variable-time windowed/precomputed-table
  methods fast libraries use (P-256 signing is the exception, at parity with
  OpenSSL — see the note under the table). We trade raw speed for the constant-time property and
  the no-assembly portability.
- **RSA private-key ops are blinded** (per-call base blinding), which adds a
  modular multiply but removes the timing dependence on the private exponent.
- **ML-KEM is fast and constant-time** (the lattice arithmetic is naturally
  data-independent; decapsulation runs both the FO check and the
  implicit-rejection branch unconditionally).

So: where the bottleneck is a hardware-accelerated primitive, you pay little for
constant time; where it is software big-integer / curve arithmetic, constant
time costs throughput, and that is an intentional choice for this crate.

## Cross-target

These numbers are **x86_64 only**. On aarch64 the crate uses the ARM AES/PMULL
and SHA extensions where present; some accelerations (e.g. an ARM PCLMULQDQ-style
GHASH and ARM SHA-512) are not yet wired, so the symmetric/hash profile differs.
Per-target numbers would need a dedicated CI benchmark job — not yet run.
