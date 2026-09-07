# Interop status

One row per module. "Byte-exact" means our output was compared against the
oracle over generated vectors and matched exactly. Vector JSON in this
directory is consumed by the crate's tests, which never link the oracle.

| Module | Wire format specified? | Interop status |
|---|---|---|
| bip340 | Yes (BIP340) | **official vectors** — all 19 of BIP340's `test-vectors.csv` (no oracle needed) |
| sign_to_contract | Yes | **byte-exact** — `sign_to_contract.json`, 14 vectors; regenerate with `gen-sign-to-contract.c` |
| adaptor | Yes (documented) | **byte-exact** — `ecdsa_adaptor.json`, 32 valid + 8 negative |
| pedersen | Yes | **byte-exact** — `pedersen.json`: H, 12 commitments, 64 generators, 16 blinded generators, 8 asset commitments, 9 blind sums, 102 rejections |
| rangeproof | **No** | pending |
| surjection | **No** | pending |
| halfagg | Draft only | pending |
| whitelist | **No** | **byte-exact, bidirectional** — `whitelist.json`, 22 vectors; oracle proofs verify under us and ours verify under the oracle |
