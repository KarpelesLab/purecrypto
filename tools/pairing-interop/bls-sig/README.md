# BLS signature vectors for BN254 and BLS12-377

`vectors/gnark.jsonl` is the corpus embedded (via `include_str!`, so the tests
stay hermetic) by the shared test suite in `src/pairing_common/bls_sig.rs`. It
runs once for each of `bn254::{min_pk, min_sig}` and
`bls12_377::{min_pk, min_sig}`. The file holds 120 records, one JSON object per line:
6 keys × 5 messages × 2 variants × 2 curves. Each record carries:

| field | what |
|---|---|
| `curve`, `variant` | `bn254` / `bls12-377`, `min_pk` / `min_sig` |
| `ikm`, `key_info`, `sk` | `KeyGen(IKM, key_info)` (draft-05 §2.3), big-endian scalar |
| `pk` | `SkToPk`: `sk·G` in the curve's compressed (gnark) encoding |
| `pop` | `PopProve`: `sk·H(pk, DST_POP_PROOF)` |
| `msg` | the message (empty, `abc`, `abcdef0123456789`, a sentence, 300 zero bytes) |
| `basic`, `aug`, `pop_sig` | `Sign` under the Basic, Message Augmentation (`H(pk ‖ msg)`) and Proof of Possession ciphersuites |

## Ciphersuites

No standard BLS ciphersuite exists for either curve: the draft defines only
BLS12-381. The IDs follow the draft's rule, `BLS_SIG_` ‖ hash-to-curve suite ‖
`NUL_` / `AUG_` / `POP_`, plus `BLS_POP_` ‖ suite ‖ `POP_` for proofs of
possession. The hash-to-curve suites are the ones purecrypto shares with
gnark-crypto (see `../bn254/` and `../bls12-377/`):

| module | keys | signatures | hash-to-curve suite |
|---|---|---|---|
| `bn254::min_pk` | G1 (32 B) | G2 (64 B) | `BN254G2_XMD:SHA-256_SVDW_RO_` |
| `bn254::min_sig` | G2 (64 B) | G1 (32 B) | `BN254G1_XMD:SHA-256_SVDW_RO_` |
| `bls12_377::min_pk` | G1 (48 B) | G2 (96 B) | `BLS12377G2_XMD:SHA-256_SSWU_RO_` |
| `bls12_377::min_sig` | G2 (96 B) | G1 (48 B) | `BLS12377G1_XMD:SHA-256_SSWU_RO_` |

## Method

The two halves are independent of purecrypto's Rust code:

* `keygen.py` implements KeyGen from the draft's pseudocode using only Python's
  `hmac` and `hashlib` (`L = 48` for both the 254- and 253-bit group orders).
* `gnark/main.go` drives gnark-crypto v0.21 as a **black box**, through its
  public API only, as for the other pairing vectors. gnark-crypto has no BLS
  signature package, so the driver composes the scheme from
  `ScalarMultiplicationBase`, `HashToG1` / `HashToG2` and `Bytes()`. No
  implementation source was read.

## Regenerating

Requires Go ≥ 1.26 (the module pins gnark-crypto v0.21.0):

```sh
cd tools/pairing-interop/bls-sig
python3 keygen.py > vectors/keygen.jsonl
(cd gnark && go run . < ../vectors/keygen.jsonl > ../vectors/gnark.jsonl)
```
