# Fuzz tests

Coverage-guided fuzz targets for the network and file-format parsers in
the `purecrypto` crate. Built with [`cargo-fuzz`] + [libFuzzer].

The parent crate's stable-Rust PR CI does **not** run this directory.
Fuzzing requires nightly Rust; see `.github/workflows/fuzz.yml` for the
weekly-cron + manual-dispatch CI job that does run the targets.

[`cargo-fuzz`]: https://github.com/rust-fuzz/cargo-fuzz
[libFuzzer]: https://llvm.org/docs/LibFuzzer.html

## Running a single target

```bash
# One-time install:
cargo +nightly install cargo-fuzz

# 60-second run:
cd /path/to/purecrypto
cargo +nightly fuzz run x509_certificate -- -max_total_time=60
```

When libFuzzer finds an interesting input, it saves it in
`fuzz/corpus/x509_certificate/<hash>` for future re-seeding. A crash
input goes to `fuzz/artifacts/x509_certificate/crash-<hash>`.

## Running every target (smoke)

```bash
for t in $(cargo +nightly fuzz list); do
    echo "=== $t ==="
    cargo +nightly fuzz run "$t" -- -max_total_time=30 || break
done
```

## Reproducing a crash

```bash
cargo +nightly fuzz run x509_certificate fuzz/artifacts/x509_certificate/crash-XXXX
```

## Adding a new target

1. Add `[[bin]]` entry to `fuzz/Cargo.toml`.
2. Create `fuzz_targets/<name>.rs` following the skeleton:
   ```rust
   #![no_main]
   use libfuzzer_sys::fuzz_target;
   fuzz_target!(|data: &[u8]| {
       let _ = purecrypto::module::ParseTarget::from_bytes(data);
   });
   ```
3. Add the target name to the matrix in `.github/workflows/fuzz.yml`.
4. (Optional) Drop a few hand-picked seed inputs in
   `fuzz/corpus/<name>/`. libFuzzer will seed itself with random bytes
   otherwise, but a real seed corpus speeds up coverage convergence
   significantly.

## What's intentionally not fuzzed

- **AEAD decrypt** — the math is shape-oblivious; framing is covered by
  the TLS/DTLS/QUIC record targets.
- **Raw-bytes key constructors** (`X25519StaticSecret::from_bytes`,
  `Ed25519PublicKey::from_bytes`, …) — length-checked at the boundary.
- **Signature verification math** — differential testing against known
  vectors is the right tool. The *parsing* layer (DER ECDSA via
  `ecdsa_sig_der`) is covered.
- **Pure crypto primitives** (cipher cores, hash cores, bignum ops) —
  handle any input by design.

## Triage convention

A new crash is a real bug until proven otherwise. Workflow:

1. Reproduce locally — `cargo +nightly fuzz run <target> <crash-input>`.
2. If the parser should have rejected the input gracefully, fix it in
   `src/` (separate `fix(...)` commit) and add the input as a named
   regression seed under `fuzz/corpus/<target>/regression-<short-desc>`.
3. If the crash is a `debug_assert!` over an invariant the parser
   *does* guarantee, mark the assert with a comment and leave the seed
   in the corpus.
