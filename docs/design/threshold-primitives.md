# Design: low-level / threshold-crypto primitives for purecrypto

Status: **proposal — for review before implementation**
Author: security/eng (Claude-assisted)
Date: 2026-05-30

Downstream threshold-crypto libraries (`frost-ristretto255-tss`, `frost-tss`,
`dkls-tss`, `mldsa-tss`) need access to arithmetic that purecrypto currently
keeps private behind its high-level, misuse-resistant APIs. This document
specifies how we expose that arithmetic without compromising the audited
high-level paths or the crate's conventions.

## Decisions (locked with maintainer)

1. **Packaging:** dedicated `hazmat` namespaces, feature-gated, documented as
   *no semver-stability guarantee, caller owns correctness + constant-time
   discipline*. Mirrors `dalek`/`RustCrypto` `hazmat`. Keeps the footgun and
   the semver burden quarantined away from the audited surface.
   - **`ristretto255` is the exception: a STABLE public module** (RFC 9496 is a
     stable spec and the natural FROST dependency). Everything else is hazmat.
2. **Oblivious transfer:** **NOT** implemented in purecrypto. purecrypto
   exposes only the group operations (#2/#3) and the random-oracle hashing OT
   is built from; base-OT and OT-extension live in `tsslib`.
3. **secp256k1:** new **dedicated, native-fast const-generic backend**
   (stack-allocated, like `p256.rs`), not the heap-backed runtime
   `Boxed`/`Weierstrass` path. Maintainer wants **native specialized field
   arithmetic** for secp256k1's prime `p = 2²⁵⁶ − 2³² − 977` (fast reduction,
   not the generic 4-limb Montgomery CIOS), and the **same per-curve native
   treatment eventually for P-256 and others**. So the architecture must admit a
   *native field backend per curve*, not just a generic one. See the revised
   Item 3 for the field-backend abstraction + the correctness-first → native-fast
   phasing.
4. **Shared scalar:** one `Scalar` type for the order-`L` field, re-exported in
   both `edwards25519::hazmat` and `ristretto255` (FROST-friendly).
5. **`mldsa::hazmat`:** expose the internal `Params` struct **directly** (its
   shape becomes semver-load-bearing *within the hazmat no-guarantee contract*).
6. Design doc first (this file); implementation staged after sign-off.

## Cross-cutting conventions (apply to every item)

- **Feature gate:** one opt-in feature per exposure. `hazmat` arithmetic is
  *off by default* (not in the `default` set). Naming: `hazmat-*`.
- **`hazmat` module placement:** a `pub mod hazmat` inside the owning module
  (`ec::edwards25519::hazmat`, `ec::secp256k1::hazmat`, `mldsa::hazmat`), each
  gated. A crate-level doc note flags all `hazmat` as unstable.
- **Lints:** crate enforces `missing_docs=warn`, `unreachable_pub=warn`,
  `unsafe_code=deny`. Every new `pub` item gets a `///` doc; each `hazmat` item
  additionally carries a `# Hazmat` / `# Warning` doc section.
- **Constant-time:** scalar/point ops stay constant-time (reuse `ct::*`,
  `ConditionallySelectable`, Montgomery ladder already used internally).
  Variable-time helpers, where offered, are suffixed `_vartime` and documented.
- **Zeroize:** secret-bearing newtypes (scalars) impl `Drop` with the existing
  `black_box`-guarded wipe pattern (no `zeroize` crate — no-foreign-code).
- **No foreign code:** everything implemented in-house from existing
  primitives. ristretto255 + the secp256k1 backend are new in-house code.
- **KATs:** RFC/FIPS vectors in `testdata/`, loaded via `include_str!` +
  `test_util::from_hex`, asserted in `#[test]`. Each item lists its vector
  source below. A `hazmat` exposure is not "done" without KAT coverage.

---

## Item 5 — ML-DSA-44 low-level primitives  *(lowest risk; do first)*

**Goal:** expose NTT, `Poly`/vector types, sampling, and bit-packing so partial
ML-DSA-44 signatures can be combined.

**Current state:** `src/mldsa/{field,sample,encode,reduce}.rs` already contain a
clean, parameter-set-independent `pub(crate)` layer. ML-DSA-44's path is
identical to 65/87 (`P44` const, `K=L=4`). **No refactor — visibility only.**

**Plan:** add `#[cfg(feature = "hazmat-mldsa")] pub mod hazmat;` under
`src/mldsa/` that *re-exports* (does not move) the curated set:

- Ring: `Poly` (`field.rs:27`) + `c: [u32; N]` accessor, `N`, `Q`, `zero`,
  `add`, `sub`, `ntt`, `inv_ntt`, `ntt_mul`.
- Reduction/rounding (verified in `reduce.rs`): `power2_round` (22), `decompose`
  (56), `high_bits` (43), `make_hint` (64), `use_hint` (70), `inf_norm` (97),
  consts `GAMMA2_32`/`GAMMA2_88`; plus `field.rs` helpers `reduce_once`/`add`/
  `sub`/`mul` and consts `N`/`Q`/`D`/`Q_MINUS_1_DIV2`.
- Sampling (verified symbol names in `sample.rs`): `sample_ntt_poly` (RejNTTPoly
  / ExpandA, line 13), `sample_bounded_poly` (RejBoundedPoly / ExpandS, line 35),
  `sample_challenge` (SampleInBall, line 72), `expand_mask` (ExpandMask, line 100).
- Encoding (verified in `encode.rs`): `pack_t1`/`unpack_t1`, `pack_t0`/`unpack_t0`,
  `pack_eta2`/`unpack_eta2`, `pack_eta4`/`unpack_eta4`, `pack_z17`/`pack_z19`/
  `unpack_z17`/`unpack_z19`, `pack_w1_4`/`pack_w1_6`, `pack_hint`/`unpack_hint`.
  The `Params`-dispatched `pack_eta`/`unpack_eta`/`pack_z`/`unpack_z`/`pack_w1`
  are private `fn` in `mod.rs` (130–167) — re-expose as hazmat wrappers.
- Params: `Params` struct + `P44` (and `P65`/`P87` for completeness). **Its
  fields are all private today** (`eta`/`tau`/`gamma1`/`gamma2`/`omega`/`beta`/
  `ctilde`/`pubkey`/`privkey`/`sig`, mod.rs:54–67) → exposing it "directly" per
  decision means making the fields `pub` (or adding `pub const fn` accessors).
  **Note `K`/`L` are NOT in `Params`** — they're const generics on
  `keygen`/`sign_internal`/`verify_internal` (mod.rs:260/331/493). Threshold
  callers need them, so the hazmat surface must also surface the (K,L) per level,
  e.g. a `pub const ML_DSA_44: (Params, usize, usize)` or a small
  `pub struct Level { params: Params, k: usize, l: usize }`.
- `ZETAS` (`field.rs:140`, currently a private `static`) exposed read-only via a
  `pub fn zeta(i: usize) -> u32` accessor for callers doing manual NTT-domain
  work.

**Risk:** low. Flipping `pub(crate)`→`pub`-via-reexport on math with no secret
branching. Main cost is the doc + the explicit "unstable" contract.

**KATs:** existing `testdata/mldsa44_*.kat` already exercise these paths
end-to-end; add a focused round-trip test that drives `ntt`/`inv_ntt`/pack/unpack
directly through the `hazmat` re-exports so the public surface is pinned.

---

## Item 3 — secp256k1 scalar + point + compressed SEC1  *(native-fast const-generic backend)*

**Goal:** public secp256k1 scalar field ops, point add / scalar-mul /
mul-generator, and **compressed** SEC1 codec (currently only uncompressed 0x04
exists, via the boxed path) — backed by a **native-fast field implementation**.

**Current state:** secp256k1 params exist (`curves.rs:82`) but only through the
heap-backed runtime path. The const-generic infra is the `Curve` trait
(`p256.rs:59`): associated consts `FIELD_MODULUS`, `ORDER`, `GENERATOR_X/Y`,
`OID`, `FIELD_LEN`, `ORDER_LEN`, with `Point<C>` in projective coords
(`p256.rs:70`). Today every const-generic curve shares the generic 4-limb
`MontModulus<4>` CIOS field arithmetic.

### Field-backend abstraction (enables per-curve native arithmetic)

To get native-fast secp256k1 *and* keep P-256 working *and* allow P-256/others
to go native later, introduce a `FieldBackend` trait the curve arithmetic is
generic over:

```text
trait FieldBackend {            // one impl per curve's base field
    type Elem: Copy + ConditionallySelectable + ConstantTimeEq;
    const ZERO/ONE: Elem;
    fn add/sub/mul/square/negate(..) -> Elem;
    fn invert(Elem) -> Elem;    // constant-time (Fermat or addition chain)
    fn sqrt(Elem) -> CtOption<Elem>;
    fn from_bytes_be / to_bytes_be(..);   // canonical, range-checked
}
```

- **`GenericMont<C>`**: a blanket backend wrapping today's `MontModulus<4>` — so
  P-256 keeps its exact current arithmetic with zero behavior change.
- **`Secp256k1Field`**: a *native* backend for `p = 2²⁵⁶ − 2³² − 977`. The
  pseudo-Mersenne shape gives a fast reduction (multiply the top half by
  `2³² + 977` and fold, two passes) instead of generic CIOS. Constant-time, no
  secret branches. This is the new numeric core and the bulk of the risk.

The point formulas (`Point<C>` add/double/ladder) become generic over
`FieldBackend` rather than calling `MontModulus` directly. They must be written
**`a`-generic**: P-256 uses `a = −3`, secp256k1 uses `a = 0`. Add an `A`
associated const (or an `a·X·Z²` term the backend can special-case to skip when
`a = 0`) so both curves share one complete-addition implementation.

### Phasing (de-risks the native arithmetic)

- **Phase A — correctness oracle:** stand up `Secp256k1` on the *generic*
  backend (`GenericMont`) so the whole public API + SEC1 codec + KATs land and
  go green first. This is the reference.
- **Phase B — native field:** implement `Secp256k1Field` (native reduction,
  invert, sqrt) and switch secp256k1 to it. Gate correctness by
  **differential-testing Phase B against Phase A** over randomized inputs
  (same RNG seed via fixtures, since `Math.random` is unavailable) *and* the
  fixed KATs. Phase B does not change the public API.
- **(Future) P-256 native:** a `P256Field` backend can be added the same way,
  validated against the existing P-256 KATs — out of scope for this batch, but
  the abstraction is what makes it a drop-in later.

### Public surface — feature `hazmat-secp256k1`

- `Scalar` (mod n): `from_bytes_be`/`to_bytes_be` (canonical-checked +
  unchecked `_reduce` variant for hash-to-scalar), `add`, `sub`, `mul`,
  `negate`, `invert` (Fermat, constant-time), `is_zero`, `ZERO`/`ONE`.
  `Drop`-wiped.
- `ProjectivePoint` / `AffinePoint`: `GENERATOR`, `IDENTITY`, `add`,
  `double`, `mul` (scalar·point, constant-time ladder), `mul_generator`,
  `negate`, `ct_eq`, `is_identity`, `to_affine`.
- SEC1: `to_sec1_compressed` (0x02/0x03 + X), `to_sec1_uncompressed`,
  `from_sec1` accepting **both** compressed and uncompressed. Compressed
  decode needs **y-recovery via modular sqrt** for `p ≡ 3 (mod 4)`
  (secp256k1 qualifies → `y = (x³+7)^((p+1)/4)`); provided by the field
  backend's `sqrt`.
- Wire `from_sec1`/`to_sec1` so the existing high-level boxed secp256k1 ECDSA
  can optionally share the compressed codec (nice-to-have, not required).

**Risk:** medium→high (the native field is the high part). On-curve /
not-identity checks on `from_sec1`; cofactor 1 for secp256k1 so no
small-subgroup check needed. Constant-time scalar mul + field ops required.

**KATs:** point add/double/mul against known secp256k1 vectors; compressed↔
uncompressed round-trips; reject off-curve, reject x≥p, reject identity encoding;
scalar arithmetic vs reference; **Phase-B-vs-Phase-A differential tests**. Store
vectors under `testdata/secp256k1_*.kat`.

---

## Items 1 + 2 — ristretto255 + exposed Edwards25519/Curve25519  *(shared backend)*

These share the scalar field (order L) and the Edwards point ops, so they are
designed together around **one `curve25519` backend** that both the existing,
audited Ed25519 signing path and the new public API consume.

**Current state:** `ed25519.rs` has it all but **private**: `Field` (GF(2^255-19)
with mul/inv/sqrt-in-`decode`), extended-coord `Point` (add/double/scalar_mult/
encode/decode), and scalar helpers (`scalar_reduce_wide` 64→mod-L,
`scalar_muladd`, `clamp`). ristretto255 additionally needs a *named*
`sqrt_ratio_i` (currently only implicit inside `decode`) and the elligator /
encode / decode / equality layer of RFC 9496.

### Stage 2a — factor out `curve25519` backend (refactor, no behavior change)

Extract the private field/point/scalar internals from `ed25519.rs` into
`src/ec/curve25519/` (`field.rs`, `point.rs`, `scalar.rs`) as `pub(crate)`.
**Ed25519 signing/verification must keep byte-for-byte identical behavior** —
re-run the full Ed25519 + RFC 8032 KAT suite as the regression gate. This is the
single highest-risk step because it touches audited code; it is a pure move +
re-wire, no algorithm change.

### Stage 2b — `ec::edwards25519::hazmat`  (feature `hazmat-edwards25519`) — Item 2

Public newtypes over the backend:
- `Scalar` (mod L): `add`/`sub`/`mul`/`negate`/`invert`, `from_bytes_canonical`,
  `from_bytes_mod_order` (wide 64→L reduce = exposed `scalar_reduce_wide`),
  `to_bytes`, `ZERO`/`ONE`. `Drop`-wiped. (Shared by ristretto255 + FROST
  hash-to-scalar.)
- `EdwardsPoint`: `GENERATOR`(basepoint), `IDENTITY`, `add`/`sub`/`double`,
  `mul`(scalar·point), `mul_base`(scalar·basepoint), `negate`, `ct_eq`,
  `compress`/`decompress` (RFC 8032 32-byte), `mul_by_cofactor`,
  `is_small_order`/`is_torsion_free`.

### Stage 2c — `ec::ristretto255` (RFC 9496)  (feature `ristretto255`) — Item 1

Built on the backend; **this one is a stable public module, not hazmat** — RFC
9496 is a stable spec and the natural FROST dependency:
- `RistrettoPoint`: `IDENTITY`, `BASEPOINT`, `add`/`sub`, `mul`(scalar·point),
  `mul_base`, `ct_eq`/`==` (ristretto equality, *not* raw coord compare),
  `compress`→`CompressedRistretto([u8;32])`, `decompress` (canonical-checked),
  `from_uniform_bytes(&[u8;64])` (one-way map / hash-to-group via the
  RFC 9496 elligator + `sqrt_ratio_i`).
- Reuses `Scalar` from 2b.
- Internally needs the named `sqrt_ratio_i` extracted/added in 2a.

**Risk:** 2a is the risk; 2b/2c are additive. The 2a refactor must not perturb
the signing hot path or the constant-time properties the audit relied on.

**KATs:** RFC 9496 has explicit vectors (encode/decode of multiples of the
basepoint, the `from_uniform_bytes` map vectors, invalid-encoding rejection
list) → `testdata/ristretto255_*.kat`. Edwards hazmat: cross-check
`mul_base(s)` against Ed25519's internal `[s]B`, add/double against known
points. Regression: full pre-existing Ed25519/RFC 8032 suite must stay green.

---

## Item 4 — Oblivious transfer  →  *out of scope for purecrypto*

Per decision: base-OT and OT-extension live in **tsslib**, not here. purecrypto's
contribution is the group ops (Items 2/3) plus the random-oracle hashing OT needs
(already public: `hash` / `kdf` / SHAKE / HKDF). **Action:** document in the
tsslib integration notes which purecrypto APIs the OT layer should consume
(`ristretto255` / `secp256k1::hazmat` group ops + `hash` RO); no purecrypto code
for OT. If a base-OT *primitive* is later wanted in-crate, it can be revisited as
a separate `ot` feature, but it is excluded from this plan.

---

## Feature wiring (Cargo.toml)

```toml
# hazmat: low-level arithmetic, NO stability guarantee, off by default.
hazmat-mldsa        = ["mldsa"]
hazmat-secp256k1    = ["ec"]
hazmat-edwards25519 = ["ec"]
ristretto255        = ["ec", "hash", "rng"]   # stable public module
```

`default` is unchanged (none of the above join it). `lib.rs` gains a doc note:
“`hazmat-*` features expose unstable low-level arithmetic with no semver
guarantee; callers own correctness and constant-time discipline.”

## Staging / sequencing

| Stage | Item | Risk | Gate before merge |
|------|------|------|-------------------|
| 1 | #5 ML-DSA-44 hazmat re-exports | low | mldsa KATs + new round-trip test |
| 2 | #3 secp256k1 backend + scalar/point | med | secp256k1 KATs, on-curve/reject tests |
| 3 | #3 compressed SEC1 + sqrt | med | codec round-trip + reject vectors |
| 4 | #2a curve25519 backend extract | **high** | full Ed25519/RFC 8032 regression green |
| 5 | #2b edwards25519 hazmat | low | edwards KATs vs internal [s]B |
| 6 | #1 ristretto255 module | med | RFC 9496 KATs |
| 7 | #4 tsslib integration notes | n/a | doc only |

Each stage = its own PR/commit set, CI gates (`fmt`, `clippy --all-targets
--all-features -D warnings`, `cargo test --all-features`, no_std build) per the
crate's existing bar.

## Open questions for review — RESOLVED 2026-05-30

1. **Stability of `ristretto255` vs hazmat:** → **STABLE public module.**
2. **secp256k1 backend:** → **native-fast** field arithmetic (not generic
   Montgomery), via the `FieldBackend` abstraction above; `a`-generic point
   formulas; native treatment for P-256/others to follow later. Phased
   correctness-first → native (Phase A/B) to de-risk.
3. **Shared scalar:** → **one shared `Scalar` (order L)** across
   `edwards25519::hazmat` and `ristretto255`.
4. **`mldsa::hazmat` `Params`:** → **expose the `Params` struct directly.**
