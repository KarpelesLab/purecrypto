# Wycheproof vectors

[Wycheproof](https://github.com/C2SP/wycheproof) is a corpus of test vectors
that probes the edge cases real implementations get wrong: malformed DER,
non-canonical encodings, points off the curve, low-order keys, tag
truncation, padding variants, and so on. `tests/wycheproof/` runs the
applicable files through purecrypto's **public API only**.

## Layout

| Path | What |
| --- | --- |
| `tools/wycheproof/convert.py` | Re-encodes upstream `testvectors_v1/*.json` into the flat format below. Pins the upstream commit in each output header. |
| `testdata/wycheproof/<name>.txt` | Converted vectors, one file per upstream JSON file, checked in so `cargo test` is hermetic. |
| `tests/wycheproof/common.rs` | Loader and runner: enforces the valid / invalid / acceptable policy and lists every mismatching `tcId`. |
| `tests/wycheproof/<family>.rs` | One module per primitive family (AEAD, cipher modes, MAC/KDF, ECDSA, ECDH/EdDSA, RSA, ML-KEM/ML-DSA). |

## Format

The crate has no JSON dependency, not even for tests, and the raw JSON for
the applicable subset is ~65 MB. The converter flattens each file into
`key=value` lines:

```
# wycheproof aes_gcm_test.json commit=<sha> algorithm=AES-GCM schema=... numberOfTests=316
G ivSize=96 keySize=128 tagSize=128 type=AeadTest ...
T tcId=1 flags=Ktv key=... iv=... aad= msg=... ct=... tag=... result=valid comment=...
```

- `G` starts a test group; its fields are the group's JSON fields (nested
  objects flattened with `.`, e.g. `publicKey.curve`).
- `T` is one test case belonging to the preceding group.
- Values are verbatim; `%` and whitespace inside a value are percent-encoded.
  `comment` is always last and runs to end of line. Empty `flags` and
  `comment` are omitted. PEM / JWK fields are dropped.

## Policy

- `valid`: must be accepted **and** produce the expected output.
- `invalid`: must be rejected (at parse or verify time).
- `acceptable`: either outcome, unless a module tightens it for a specific
  flag. Each module's report of what the crate does per flag lives in a
  comment next to the test.
- `Outcome::Skipped` is reserved for parameters the API genuinely cannot
  express (for example a truncated GCM tag length the type has no variant
  for). Every skip has a code comment. A file where every case is skipped
  fails, so a silently unexercised file cannot pass.

## Updating

```sh
git clone --depth 1 https://github.com/C2SP/wycheproof /tmp/wycheproof
python3 tools/wycheproof/convert.py /tmp/wycheproof testdata/wycheproof
cargo test --test wycheproof
```

Add new files to the `INCLUDE` list in `convert.py` when a new primitive
lands, then cover them in the matching harness module.
