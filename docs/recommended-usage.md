# Recommended usage (the safe path)

> **DRAFT — maintainer to bless the opinions below.** The crate is broad and
> ships compatibility/legacy algorithms on purpose. This page is the opinionated
> "use exactly this" guide. The factual coverage is in
> [`validation.md`](validation.md); the boundaries are in
> [`threat-model.md`](threat-model.md).

The crate exposes a lot. Most of it you should not reach for. Three tiers:

1. **Blessed** — modern, safe defaults. Use these.
2. **Compatibility-only** — present for interop with existing systems. Do not
   use for new designs unless you must talk to something that requires them.
3. **Hazmat** — low-level, no semver, no constant-time guarantee. Avoid unless
   you specifically know why.

## TL;DR — blessed defaults

| Task | Use | Notes |
|---|---|---|
| Hash | SHA-256 / SHA-512, or SHA3-256; BLAKE3 for speed | `crate::hash` |
| AEAD | **AES-256-GCM** (with AES-NI) or **ChaCha20-Poly1305** | `crate::cipher`; XChaCha20-Poly1305 for random/long-lived nonces |
| Nonce-misuse safety | AES-GCM-SIV or AES-SIV | when you can't guarantee unique nonces |
| MAC | HMAC-SHA-256 (verify via the constant-time `Mac::verify`) | `crate::hash` |
| Randomness | `OsRng` | `crate::rng`; or an HMAC-DRBG seeded from it |
| Signature (classical) | **Ed25519** | `crate::ec`; ECDSA P-256 only if the ecosystem requires ECDSA |
| Signature (post-quantum) | **ML-DSA-65** | `crate::mldsa`; or SLH-DSA for a conservative hash-based choice |
| Key agreement | **X25519** | `crate::ec`; in TLS, keep the X25519MLKEM768 hybrid group |
| Public-key encryption | **ML-KEM** + AEAD, or **RSA-OAEP** (SHA-256) | never PKCS#1 v1.5 encryption |
| Key derivation (from a strong secret) | **HKDF-SHA-256** | `crate::kdf` |
| Password hashing / KDF | **Argon2id** | `crate::kdf`; scrypt acceptable |
| Transport | **TLS 1.3** | set `min_version` to 1.3 |
| Load a key of unknown type | `key::AnyKey::from_pkcs8` → operate via the `key` facade | type-honest, covers KEM keys too |

## Per-domain

- **Symmetric encryption.** Default to `Aes256Gcm` where AES-NI is available,
  `ChaCha20Poly1305` otherwise. If nonce uniqueness is hard to guarantee, use the
  misuse-resistant `AesGcmSiv`/`AesSiv`. For random 192-bit nonces use
  `XChaCha20Poly1305`. Always treat a decryption error as "reject the message,"
  never branch on *why*.
- **Signatures.** Ed25519 is the default. Use ECDSA P-256 only for X.509 / WebPKI
  ecosystems. For post-quantum, ML-DSA-65 (balanced) or SLH-DSA (slow, large,
  but only hash assumptions). Prefer RSA-**PSS** over PKCS#1 v1.5 if you must use
  RSA. For uniform handling across algorithms, the `key::PrivateKey` /
  `key::PublicKey` facade is the recommended entry point.
- **Key agreement.** X25519 for new protocols. In TLS, the default already
  negotiates the **X25519MLKEM768 hybrid** — keep it for forward security against
  "harvest now, decrypt later."
- **Public-key encryption / key transport.** Prefer a KEM: ML-KEM-768 →
  derive a key with HKDF → AEAD. If you must use RSA, use **OAEP** (SHA-256).
  **Do not** use RSA PKCS#1 v1.5 encryption (Bleichenbacher oracle).
- **Key derivation & passwords.** HKDF for deriving keys from a high-entropy
  secret. **Argon2id** for passwords. PBKDF2 only for compatibility.
- **TLS / DTLS / QUIC.** Set `Config` `min_version` to TLS 1.3 for new
  deployments; the default suites (AES-GCM / ChaCha20-Poly1305) and groups are
  the right set. Enable mTLS via client certificates where appropriate. Note:
  DTLS/QUIC are loopback-validated only (see validation matrix) — pilot
  accordingly.
- **X.509 / signature policy.** Use the default modern signature policy
  (whitelist). Do **not** enable SHA-1 signature algorithms except for explicit,
  scoped legacy verification.

## Recommended parameters

- **RSA**: ≥ 3072-bit for new keys (2048 is the floor, for legacy interop). PSS
  with salt length = digest length, SHA-256.
- **RSA-OAEP**: SHA-256 label/MGF1.
- **Argon2id**: tune to your latency budget; a reasonable server baseline is
  m = 64 MiB, t = 3, p = 1 (raise memory/time toward ~250 ms+).
- **scrypt**: N = 2¹⁵ (32768), r = 8, p = 1 as a minimum.
- **PBKDF2** (compat only): ≥ 600 000 iterations with SHA-256.
- **TLS**: `min_version = TLS 1.3` for anything not pinned to a legacy peer.

## Compatibility-only — do not use in new designs

Present for talking to existing systems; each has a documented weakness:

- `tls-legacy` feature: SSL 3.0 / TLS 1.0 / 1.1 — BEAST, POODLE, Lucky13 residue,
  MD5/SHA-1 PRF, static-RSA key transport. Off by default; requires lowering
  `min_version` at runtime.
- **RSA PKCS#1 v1.5 *encryption*** — Bleichenbacher padding oracle.
- **SHA-1 / MD5 / MD4 / RIPEMD-160** for signing — not collision-resistant.
  (Verification of legacy signatures is fine.)
- **DES / 3DES**, RC2 — broken / disallowed; interop only.
- **Finite-field `dh`** (RFC 3526 MODP) — prefer ECDH (`ec`) for new code.
- **SM2** — use only for GB/T 32918 / RFC 8998 regional compliance.
- **Keccak-256** (the Ethereum pre-standard variant) — use SHA3-256 unless you
  need the Ethereum variant specifically.
- **RSA < 2048-bit** — do not generate.

## Hazmat — do not use unless you know why

The `hazmat-secp256k1`, `hazmat-edwards25519`, and `hazmat-mldsa` features expose
low-level scalar/point/polynomial arithmetic for threshold/FROST-style callers.
They carry **no semver stability and no constant-time guarantee** — you own
correctness and timing discipline. The stable `ristretto255` module is the safe
prime-order-group choice for FROST-like protocols.
