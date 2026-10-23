# BLS12-377 interop vectors

Known-answer vectors for `purecrypto::bls12_377`, produced **black-box** from
two reference libraries. Only their public APIs were driven. No implementation
source of either library was read. The tests in `src/bls12_377/vectors.rs`
embed the flattened form `testdata/bls12_377/kat.txt`, so they are hermetic.

| File | Producer |
|---|---|
| `gnark/main.go` | driver for gnark-crypto v0.21.0 (`ecc/bls12-377`) |
| `ark/main.rs` | driver for arkworks 0.5 (`ark-bls12-377`, `ark-ec`, `ark-serialize`) |
| `vectors/gnark.json`, `vectors/ark.json` | their output |
| `to_kat.py` | JSON → `testdata/bls12_377/kat.txt` |

## Regenerating

The oracle build directory `tools/pairing-interop/oracle/` is gitignored.

```sh
# gnark-crypto (Go ≥ 1.25; v0.22 needs Go 1.26.8)
mkdir -p tools/pairing-interop/oracle/go/gen377 && cd tools/pairing-interop/oracle/go
go mod init oracle && go get github.com/consensys/gnark-crypto@v0.21.0
cp ../../bls12-377/gnark/main.go gen377/ && go mod tidy
go run ./gen377 > ../../bls12-377/vectors/gnark.json

# arkworks: a scratch crate with ark-bls12-377/ark-bn254/ark-ec/ark-ff/
# ark-serialize 0.5 and sha2 0.10, src/main.rs = ark/main.rs
cargo run --release > ../../bls12-377/vectors/ark.json

python3 tools/pairing-interop/bls12-377/to_kat.py \
    tools/pairing-interop/bls12-377/vectors/{gnark,ark}.json > testdata/bls12_377/kat.txt
```

The constants come from `tools/bls12_377/consts.py`. It reads `gnark.json`
and `tools/bls12_377/iso2.json`, and every value it emits is checked. See its
docstring.

## What the vectors pin

- **Point encodings.** `G1`/`G2` scalar multiples of the generators (edge
  scalars 1, 2, 3, r−1, and SHA-256-chained random ones), in gnark's
  compressed and uncompressed forms and arkworks' `CanonicalSerialize`
  compressed and uncompressed forms, plus the identity in all four.
- **Pairing values.** `e(a·G1, b·G2)` as gnark `GT.Bytes()` and as the
  arkworks serialization.
- **Hash-to-curve.** gnark `HashToG1/G2` and `EncodeToG1/G2` on the RFC 9380
  test messages (`""`, `"abc"`, `"abcdef0123456789"`, `q128_…`, `a512_…`).
  The DSTs are `QUUX-V01-CS02-with-BLS12377G{1,2}_XMD:SHA-256_SSWU_{RO,NU}_`.
- **Raw maps.** gnark `MapToG1/MapToG2` at chosen field elements, `u = 0`
  included.

## Facts recovered by probing (do not "fix" them)

- **Point encoding.** gnark uses the ZCash flag layout: `0x80` compressed,
  `0x40` infinity, `0x20` "y is lexicographically largest", big-endian, and
  `Fp2` written `c1 ‖ c0`. The `Fp2` order is c1 first, then c0. arkworks is
  little-endian with `Fp2` as `c0 ‖ c1`. Its flags are in the top two bits of
  the **last** byte: `0x80` "y largest" (same ordering as gnark), `0x40`
  infinity. arkworks sets the sign bit in the *uncompressed* form too. Our
  decoder requires that bit to match `y`.
- **GT bytes.** gnark writes the twelve `Fp` coefficients big-endian in
  reverse tower order (`c1.b2.a1` first). arkworks writes them little-endian
  in tower order.
- **The pairing is cubed.** Both libraries return `e(P, Q)³`, i.e. the
  final-exponentiation hard part is `3·Φ₁₂(p)/r`. A pure-Python
  `f^((p¹²−1)/r)` matched gnark only after cubing. We compute the same.
- **G1 SSWU.** The target curve is `E'1: y² = x³ + A'x + 22`, with `A'`
  recovered from `MapToCurve1` outputs and j-invariant 54000. `Z = 5` was
  found by reproducing `MapToCurve1`; RFC 9380's `find_z_sswu` would give
  `−11`. `Z = 5` fails RFC criteria 3 and 4. Consequently `u = 0` has no
  image, and gnark returns `(0, 0)`, i.e. the identity. The isogeny is the
  2-isogeny with rational kernel `(x0, 0)`. Of the six isomorphisms onto
  `y² = x³ + 1`, exactly one reproduces `MapToG1`, with `h_eff = 1 − x`.
- **G2 SSWU.** `E'2` was recovered from `MapToCurve2` outputs. `Z = 12 + u`
  is RFC 9380's `find_z_sswu` choice (it iterates `u, −u, u+1, …`).
- **G2 isogeny.** Its degree is not 2, 3, 5, 7, 9, 11 or 13 (all searched
  first). The Frobenius conductor of `E'2` has 23 as its only small prime
  factor, so the isogeny that ascends to the `j = 0` curve has degree 23.
  Frobenius has the double eigenvalue 12 (mod 23), of order 11 modulo ±1.
  `derive_iso2.py` takes `gcd(ψ₂₃, x^(q¹¹) − x)`. That gcd has degree
  exactly 11, giving one kernel polynomial whose Kohel codomain has `j = 0`.
  The run takes about 13 minutes in pure Python. Exactly one of the six
  isomorphisms, combined with Budroni–Pintore cofactor clearing (not plain
  multiplication by `h₂`), reproduces `MapToG2`.
- **arkworks hash-to-G1 differs.** arkworks' G2 hash agrees with gnark's;
  its G1 hash does not. It is not a scalar multiple via `h/h_eff`. We follow
  gnark. The test `arkworks_hash_agreement` records both facts.
