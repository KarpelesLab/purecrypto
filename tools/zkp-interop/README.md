# secp256k1-zkp interop oracle

Establishes byte-exact interoperability for the `zkp-*` modules **without
consulting the reference implementation's source**.

## Policy

The `zkp-*` modules are written clean-room from papers and specifications
(each module names its source of truth in its rustdoc). To check that our
outputs match the ecosystem, `secp256k1-zkp` is used as a **black-box oracle**:

* It is cloned and built here, **outside the crate**. It is never vendored,
  never added as a dependency, and never linked into `libpurecrypto`.
* It is driven only through its **public C API** (`include/*.h`). Those headers
  are the interface contract and are required in order to call the library at
  all.
* **No `src/*.c` implementation file is read.** That is the line this harness
  exists to preserve.
* Generated vectors are written to `vectors/` as JSON and committed. The crate's
  tests consume those vectors; they never link against the oracle.

`secp256k1-zkp` is MIT-licensed, so derivation would be permitted with
attribution. The clean-room route is a deliberate choice to keep this crate's
"no foreign code" charter intact and its provenance easy to audit.

## Usage

    ./build-oracle.sh          # clone + build the oracle (network required)

Then compile and run the per-module generator you need, e.g.

    cc gen-rangeproof-vectors.c -I oracle/include oracle/.libs/libsecp256k1.a \
       -o gen-rangeproof && ./gen-rangeproof > vectors/rangeproof.json

There is one `gen-*.c` per module that has vectors; each is self-contained
and rewrites its own JSON file deterministically.

Neither script runs in CI: CI consumes the committed JSON only, so the test
suite stays hermetic and offline.

## Interop status

Recorded per module in `vectors/STATUS.md`. Modules whose wire format has no
normative specification (range proofs, surjection proofs, whitelisting) state
explicitly whether byte-exact compatibility has been established or not, rather
than implying it.
