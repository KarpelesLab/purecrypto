# Interop status

One row per module. "Byte-exact" means our output was compared
against the oracle over generated vectors and matched exactly.

| Module | Wire format specified? | Interop status |
|---|---|---|
| bip340 | Yes (BIP340) | pending |
| sign_to_contract | Yes | pending |
| adaptor | Yes (documented) | **byte-exact** — `ecdsa_adaptor.json` (32 valid + 8 negative) |
| pedersen | Yes | pending |
| rangeproof | **No** | pending |
| surjection | **No** | pending |
| halfagg | Draft only | pending |
| whitelist | **No** | pending |
