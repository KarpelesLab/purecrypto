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
- **rustc**: 1.96.0 (MSRV is 1.88; newer compilers may differ slightly).
- Throughput is measured at a 64 KiB message; asymmetric ops are reported as
  latency (µs/op) and ops/s.

Because the relevant hardware instructions are present, the symmetric/hash
numbers reflect the **hardware-accelerated** backends (AES-NI, PCLMULQDQ for
GHASH, SHA-NI, AVX2 for ChaCha20/BLAKE3). On a machine **without** them, the
crate falls back to its constant-time, table-free software paths, which are
correct and constant-time but slower (see [tradeoffs](#constant-time-tradeoffs)).

## Symmetric (throughput, 64 KiB)

| Algorithm | MiB/s | ops/s |
|---|--:|--:|
| AES-128-GCM (encrypt) | 2532 | 40 508 |
| AES-256-GCM (encrypt) | 2392 | 38 276 |
| ChaCha20-Poly1305 (encrypt) | 1582 | 25 309 |
| AES-256 raw block (16 B) | 1782 | 116 765 967 |
| AEZ (τ=16, robust AE) | 481 | 7 695 |

## Hashes (throughput, 64 KiB)

| Algorithm | MiB/s |
|---|--:|
| SHA-256 | 2582 |
| SHA-512 | 718 |
| BLAKE3 | 2674 |

(SHA-256 reflects SHA-NI; SHA-512 has no SHA-NI on this CPU, so it runs the
scalar path — hence the gap. BLAKE3 uses the AVX2 8-way backend.)

## Asymmetric (latency)

| Operation | ops/s | µs/op |
|---|--:|--:|
| RSA-2048 sign (PKCS#1 v1.5) | 117 | 8517 |
| RSA-2048 verify | 25 269 | 39.6 |
| ECDSA P-256 sign | 6 378 | 156.8 |
| ECDSA P-256 verify | 3 489 | 286.6 |
| Ed25519 sign | 4 973 | 201.1 |
| Ed25519 verify | 4 850 | 206.2 |
| X25519 (Diffie–Hellman) | 18 843 | 53.1 |
| ML-KEM-768 keygen | 43 287 | 23.1 |
| ML-KEM-768 encapsulate | 42 846 | 23.3 |
| ML-KEM-768 decapsulate | 35 157 | 28.4 |

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
  methods fast libraries use, and the P-256 field arithmetic in particular is
  not yet fully optimised. We trade raw speed for the constant-time property and
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
