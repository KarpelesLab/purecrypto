# BN254 interop vectors

`vectors/gnark.json` is the corpus `src/bn254/vectors.rs` embeds (via
`include_str!`, so the tests stay hermetic). It holds 114 records, one flat JSON
object per line:

| kind | what | count |
|---|---|---|
| `g1`, `g2` | `k·G` for edge and pseudo-random `k`: compressed (gnark) and uncompressed (EIP-196/197) encodings | 25 + 25 |
| `g1add`, `g2add` | `a + b` on arbitrary multiples | 4 + 4 |
| `pairing` | `e(a·G1, b·G2)` in gnark's 384-byte GT layout | 9 |
| `pairing_check` | raw EIP-197 `ecPairing` inputs (1–12 pairs) and their verdicts | 6 true + 6 false |
| `h2c` | `HashToG1` / `EncodeToG1` / `HashToG2` / `EncodeToG2` on the RFC 9380 message set | 20 |
| `map_g1`, `map_g2` | `MapToG1` / `MapToG2` on field elements (zero included) | 6 + 6 |
| `g2_not_in_subgroup` | twist points outside `G2` (gnark's `MapToCurve2`, no cofactor clearing) that gnark's decoder rejects | 3 |

## Method

Clean-room, as for `tools/zkp-interop/`: purecrypto's implementation follows
the papers and RFCs cited in `src/bn254/`, and the reference libraries were
only ever driven through their **public APIs** as black-box oracles. No
implementation source of either library was read. The format facts below were
recovered by probing outputs, not by reading code:

* Uncompressed points are `x ‖ y` big-endian (`G2` coordinates as `c1 ‖ c0`),
  all zeros for the identity — EIP-196/197, and also gnark's `RawBytes`.
* gnark's compressed points carry `10` (smaller `y`), `11` (larger `y`) or `01`
  (identity) in the top two bits; "larger" compares `c1` first for `Fp2`.
* `GT` bytes are the twelve `Fp` coefficients big-endian in reverse tower order
  (`c1.c2.c1` first, `c0.c0.c0` last).
* The pairing value is `e(P, Q)^(2x(6x² + 3x + 1))` of the exact
  `f^((p¹² − 1)/r)` — the Fuentes-Castañeda hard part. gnark and arkworks
  agree on it.
* Hash-to-curve is RFC 9380 SVDW with `Z = 1` on both groups (the Appendix H.1
  search), `L = 48`; `G2` cofactor clearing is the Fuentes-Castañeda–Knapp–
  Rodríguez-Henríquez `ψ` formula, not multiplication by `2p − r`.

## Regenerating

Requires Go ≥ 1.26 (the module pins gnark-crypto v0.21.0) and, for the
cross-check, a Rust toolchain with network access for arkworks 0.5:

```sh
cd tools/pairing-interop/bn254/gnark
go run ./gen > ../vectors/gnark.json      # deterministic: SHA-256 counter inputs
cd ../ark
cargo run --release -- ../vectors/gnark.json   # "arkworks agrees on 82 records"
```

`gnark/probe/` is the throwaway probe used to recover the formats above.
arkworks has no BN254 hash-to-curve, so the `h2c` and `map_*` records are
gnark-only.
