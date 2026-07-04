# Validation & assurance matrix

This page summarises, per module, how `purecrypto` is validated: which test
vectors and interop targets it is checked against, its fuzzing coverage, its
negative/malformed-input handling, its constant-time posture, and its known
limitations / non-goals.

It is a factual map of what the test suite and code actually do. For the
recommended *safe* subset of the API, see
[`recommended-usage.md`](recommended-usage.md); for performance, see
[`benchmarks.md`](benchmarks.md).

## Assurance & audit status

- **No third-party human security audit** has been performed. Treat the crate
  accordingly.
- **Automated whole-codebase security audits were performed by Claude Fable 5.**
  This is *not* a substitute for a human/third-party audit, but it is meaningful:
  Fable 5 has surfaced real, confirmed vulnerabilities in major open-source
  projects. Several findings from those passes are reflected in the code (e.g.
  fail-closed parsing, padding-oracle hardening, bounds tightening).
- **Constant-time posture is "by construction,"** resting on the [`ct`](../src/ct)
  primitives and the unconditional [`bignum`](../src/bignum) layer (see the
  [Constant-time posture](#constant-time-posture) section). It has **not** been
  validated with a timing-analysis tool (dudect/ctgrind/etc.) or a formal CT
  audit; the `ct` module documents this explicitly as best-effort at the source
  level.

## At-a-glance matrix

KAT source legend: **ACVP** = NIST ACVP test vectors · **RFC** = the RFC's own
vectors · **CAVP** = NIST CAVP · **OpenSSL** = vectors produced by OpenSSL ·
**ref** = upstream reference-implementation vectors · **unit** = inline /
hand-derived correctness tests.

| Module | Standards | KAT source | Cross-impl interop | Fuzzed | Const-time |
|---|---|---|---|---|---|
| `ct` | — (foundation) | unit (exhaustive u8/i8) | — | — | foundation |
| `bignum` | — (foundation) | unit | — | — | yes (unconditional) |
| `hash` | FIPS 180-4, FIPS 202, SP 800-185, RFC 7693, BLAKE3, GOST R 34.11-2012 / RFC 6986 (Streebog), ISO/IEC 10118-3 (Whirlpool), K12/M14 paper, RFC 1319 (MD2) | RFC / NIST samples; M14 oracle-derived (K12-validated), cross-checked vs noble-hashes | OpenSSL (Whirlpool, SM3, SHAKE, BLAKE2), PyCryptodome (MD2), gostcrypto (Streebog), noble-hashes (M14, 14-round) | — | MAC verify CT |
| `mac` | RFC 4418 (UMAC) | RFC | — | — | built on CT AES |
| `rng` | SP 800-90A (HMAC-DRBG) | CAVP | — | — | n/a (public output) |
| `cipher` | FIPS 197, SP 800-38A/C/D, RFC 8439/8452, RFC 3713 | RFC / NIST | — | — | AES table-free; ARX |
| `kdf` | RFC 8018/5869/7914, SP 800-108 | RFC / CAVP | — | `pbes2_decrypt` | built on CT HMAC |
| `ascon` | NIST SP 800-232 (final) | ref KAT | — | — | permutation (no tables) |
| `der` | ITU-T X.690 | unit | — | `der_reader`, `pem_decode` | n/a (public) |
| `rsa` | RFC 8017 (PKCS#1 v1.5, PSS, OAEP) | unit | X.509 SPKI path | `pkcs8_rsa` | base-blinded |
| `ec` | FIPS 186, RFC 8032 (EdDSA), RFC 7748 (X25519/X448) | RFC / unit | OpenSSL (X25519 PKCS#8, ECDSA via dgst) | `ecdsa_sig_der`, `pkcs8_ed25519`, `spki_pubkey` | complete formulas / ladder |
| `dh` | RFC 3526, RFC 4419, SP 800-56A checks | unit | — (SSH/legacy-TLS groups) | `dh_share` | modexp on CT bignum |
| `key` | — (facade over the above) | unit (incl. OpenSSL X25519 PKCS#8) | inherits | `spki_pubkey`, `pkcs8_*` | inherits |
| `mlkem` | FIPS 203 | unit + OpenSSL 3.5 | OpenSSL (SPKI, ct/ss) | `mlkem_pkcs8` | CT decaps + implicit rejection |
| `mldsa` | FIPS 204 | **ACVP** (keygen/siggen/sigver, all levels) | OpenSSL (SPKI) | `pkcs8_mldsa` | hedged; CT compare + wipe |
| `slhdsa` | FIPS 205 | **ACVP** (keygen/siggen/sigver) | — | `pkcs8_slhdsa` | hedged; wipe-on-drop |
| `falcon` | FN-DSA / FIPS 206 draft | ref (samplerz KAT) + unit | — | — | signing CT (FPEMU); keygen best-effort |
| `lms` | RFC 8554, SP 800-208 | **RFC 8554 App. F** | ref vectors | `lms_parse` | n/a (hash-based, **stateful**) |
| `xmss` | RFC 8391, SP 800-208 | ref-impl KAT | ref vectors | `xmss_parse` | n/a (hash-based, **stateful**) |
| `x509` | RFC 5280 | unit | OpenSSL (SPKI pin) | `x509_certificate`, `x509_crl`, `x509_csr`, `spki_pubkey`, `ocsp_response`, `cert_decompress` | delegates to primitives |
| `pkcs12` | RFC 7292, RFC 9579 (PBMAC1) | OpenSSL fixtures | OpenSSL 3 + 1.1.1 legacy | `pbes2_decrypt` | MAC CT, wrong-pw gate, wipe |
| `tls` | RFC 8446 (1.3), RFC 5246 (1.2) | **RFC 8448** traces | loopback; legacy vs OpenSSL 1.1.1; PSS interop | `tls_client_feed`, `tls_server_feed`, `tls_legacy_feed`, `ech_*` | CT record protection; legacy CBC caveats |
| `dtls` | RFC 6347 (1.2), RFC 9147 (1.3) | loopback | loopback; **DTLS 1.2 server vs OpenSSL 3.5** (`s_client`) | `dtls_client_feed`, `dtls_server_feed` | inherits TLS |
| `quic` | RFC 9000/9001/9002/9221 | loopback | loopback; **QUIC v1 server vs OpenSSL 3.5** (`s_client -quic`) | `quic_client_feed`, `quic_server_feed`, `quic_transport_params` | inherits TLS 1.3 |
| `hpke` | RFC 9180 | **RFC 9180 App. A** (full 12-suite matrix) | RFC vectors | — | delegates to EC/KDF/AEAD |
| `signature_registry` | — (X.509/TLS dispatch) | via primitives | via X.509/TLS | — | delegates |
| `ffi` | — (C ABI) | unit (C-boundary) | — | — | delegates; panic-catching |

## Test vectors & KAT sources (detail)

- **Post-quantum signatures** — ML-DSA and SLH-DSA run the **NIST ACVP** keygen
  / siggen / sigver vectors (`testdata/mldsa{44,65,87}_{keygen,siggen,sigver}.kat`,
  `testdata/slhdsa_{keygen,siggen,sigver}.kat`). Falcon runs the reference
  discrete-Gaussian sampler KAT (`testdata/falcon_samplerz.kat`) plus
  sign→verify round-trips.
- **ML-KEM** — **NIST ACVP** keyGen / encapDecap vectors at all three parameter
  sets (`testdata/mlkem{512,768,1024}_{keygen,encap,decap}.kat`, a trimmed slice
  of the multi-MB ACVP-Server corpus), plus round-trips and **OpenSSL 3.5
  byte-compatibility** with deterministic keygen (`d = z = 0x32`), checked
  against `testdata/mlkem768_openssl_{spki,ct}.hex`.
- **Stateful HBS** — LMS runs the **RFC 8554 Appendix F** vectors
  (`testdata/lms_rfc8554.kat`); XMSS runs reference-implementation vectors
  (`testdata/xmss_kat.kat`).
- **TLS** — the **RFC 8448** "simple 1-RTT" key-schedule and CertificateVerify
  traces (`testdata/rfc8448_*.hex`).
- **HPKE** — **RFC 9180 Appendix A**, the full KEM × KDF × AEAD suite matrix,
  reproduced deterministically via a scripted RNG.
- **Classical primitives** — hashes (FIPS/RFC sample vectors), HMAC (RFC 2104),
  KMAC/cSHAKE/TupleHash/ParallelHash (NIST SP 800-185 samples), AEAD/ciphers
  (NIST SP 800-38C/D, RFC 8439/8452, RFC 3713), HMAC-DRBG and KBKDF (NIST
  **CAVP**), PBKDF2/HKDF (RFC 8018 / RFC 5869), UMAC (RFC 4418), Ascon (NIST SP
  800-232 reference KATs).

## Cross-implementation interop

- **OpenSSL, byte-exact**: X25519 PKCS#8 (RFC 8410), ML-KEM-768 SPKI + ct/ss,
  ML-DSA-65 SPKI, X.509 SPKI pin (SHA-256 over the SPKI), PKCS#12 archives
  (OpenSSL 3 default *and* OpenSSL legacy 3DES), RSA-PSS (`examples/pss_interop`).
- **OpenSSL, behavioural**: ECDSA sign↔verify via `openssl dgst`, TLS 1.0/1.1
  legacy interop against OpenSSL 1.1.1 (`examples/tls_legacy_interop`, the
  `tls-legacy` feature).
- **OpenSSL 3.5, DTLS/QUIC handshake**: the **DTLS 1.2 server** completes a
  handshake (and exchanges app data) with `openssl s_client -dtls1_2`, and the
  **QUIC v1 server** with `openssl s_client -quic` (TLS 1.3, ALPN, app data).
  The client directions and DTLS 1.3 remain loopback-only: OpenSSL is
  QUIC-client-only and its `s_client` here lacks `-dtls1_3`.
- **Loopback** (own client ↔ own server, all platforms): TLS 1.2/1.3, DTLS
  1.2/1.3, QUIC v1.

## Fuzzing

29 `cargo-fuzz` (libFuzzer) targets under `fuzz/fuzz_targets/`, run in CI
(`.github/workflows/fuzz.yml`). They concentrate on the untrusted-input
attack surface — parsers and protocol feeders:

- **Encoding/parsers**: `der_reader`, `pem_decode`, `spki_pubkey`,
  `pkcs8_{rsa,ed25519,mldsa,slhdsa}`, `mlkem_pkcs8`, `ecdsa_sig_der`,
  `lms_parse`, `xmss_parse`, `dh_share`, `pbes2_decrypt`.
- **X.509 / PKI**: `x509_certificate`, `x509_crl`, `x509_csr`,
  `ocsp_response`, `cert_decompress`.
- **Protocol feeders** (arbitrary bytes → state machine, must reject
  gracefully): `tls_client_feed`, `tls_server_feed`, `tls_legacy_feed`,
  `dtls_client_feed`, `dtls_server_feed`, `quic_client_feed`,
  `quic_server_feed`, `quic_transport_params`, `ech_config_list`,
  `ech_extension`, `ech_retry_configs`.

## Negative / malformed-input coverage

The suite contains explicit rejection tests throughout; representative classes:

- **AEAD / MAC tamper rejection**: GCM-SIV, CCM, Ascon, ChaCha20-Poly1305 reject
  modified tags and (where applicable) leave the output buffer unwiped-safe;
  HMAC/BLAKE2-MAC reject truncated/empty tags and over-long keys.
- **Key-agreement contributory failure**: X25519/X448 reject small-order peers
  (`SmallOrderPeer`); finite-field DH enforces subgroup confinement and rejects
  `0`/`1`.
- **PQC structural validation**: ML-KEM validates encapsulation-key coefficient
  ranges and the decapsulation-key hash field (`from_bytes_validated`), and uses
  FO + **implicit rejection** on tampered ciphertext (returns a pseudo-random
  secret, never an error); ML-DSA rejects out-of-range coefficients on decode.
- **Stateful-key safety**: LMS/XMSS reject reuse/rollback of the one-time index,
  enforce exhaustion (`Exhausted` / `KeyExhausted`), are not `Clone`, and LMS
  caps legacy root-less key height to bound a load-time Merkle-recompute DoS.
- **ASN.1 / DER**: non-minimal lengths, wrong tags, truncation, and trailing
  data are rejected (X.690 minimality).
- **PKI / protocol**: tampered certificates fail verification; CSR trailing
  bytes, malformed RDNs, and bad string tags are rejected; PKCS#12 returns a
  single `MacMismatch` for a wrong password (no plaintext leak); TLS/DTLS/QUIC
  feeders surface alerts / errors rather than misbehaving. The fuzz targets
  above exercise these paths continuously.

## Constant-time posture

Reported as **what the code is built to do** — not as an audited guarantee.

- **Foundation**: `ct` provides branchless equality/ordering/selection with a
  `black_box` barrier; `bignum` processes all limbs unconditionally so timing
  depends only on the (public) operand size. `ct` documents that genuine CT also
  depends on the target CPU and emitted code and should be tool-validated.
- **Symmetric**: AES uses GF(2⁸)-inversion S-boxes (no table lookups);
  ChaCha20/Poly1305 are ARX/limb arithmetic; GHASH is a branchless table-free
  field multiply.
- **RSA**: private-key operations are **base-blinded** (Coron) with a per-call
  blinder; prime generation is variable-time (one-time keygen, documented).
- **EC**: complete (Renes–Costello–Batina) addition for the Weierstrass curves,
  Montgomery ladder with constant-time swaps for X25519/X448, constant-time
  selection for Ed25519/Ed448.
- **ML-KEM**: decapsulation, the FO re-encryption check, and the
  implicit-rejection fallback are data-oblivious (both branches always run).
- **ML-DSA / SLH-DSA**: hedged-by-default signing, constant-time signature
  comparison and `black_box` wiping of secret intermediates; the lattice
  rejection-sampling loop is iteration-count-variable (driven by public data).
- **Falcon**: signing is data-oblivious via emulated IEEE-754 (FPEMU), so it
  needs no hardware float and is bit-reproducible; key generation is best-effort.
- **PKCS#12 / TLS**: PKCS#12 verifies the MAC in constant time and gates
  decryption on it; TLS 1.2/1.3 record protection is constant-time. **Legacy
  CBC** (`tls-legacy`) is constant-time + uniform-error but does **not** fully
  equalise the MAC block count (residual Lucky13), and SSL 3.0 POODLE padding is
  unauthenticated and unfixable — hence legacy is off by default.
- **Not timing-sensitive / public**: `der`, `rng` output, hashing of public
  data, the hash-based stateful signers (LMS/XMSS, whose chain lengths depend on
  the public message hash).

## Known limitations & non-goals

- **Compat-only / legacy** (off by default or to be avoided in new code): the
  `tls-legacy` feature (SSL 3.0 / TLS 1.0/1.1 — BEAST/POODLE/Lucky13 residue,
  MD5/SHA-1 PRF, static-RSA); RSA PKCS#1 v1.5 *encryption* (Bleichenbacher
  oracle); MD2/MD4/MD5/SHA-1/RIPEMD-160 (not collision-resistant); DES/3DES;
  finite-field `dh` (prefer ECDH); SM2 (regional). See
  [`recommended-usage.md`](recommended-usage.md).
- **Stateful keys**: LMS and XMSS advance a one-time-key index on every
  signature; **reuse is catastrophic** and the caller must persist state after
  every `sign`.
- **Phased interop**: the DTLS 1.2 and QUIC v1 **server** directions are
  validated against OpenSSL 3.5, but the client directions and DTLS 1.3 are
  still loopback-only (OpenSSL is QUIC-client-only and exposes no `-dtls1_3`
  client here). QUIC ships v1 with streams / full RFC 9002 recovery / Retry /
  key update / DATAGRAM partially deferred (see module docs).
- **Hazmat**: the `hazmat-*` features expose low-level arithmetic with **no
  semver and no constant-time guarantee** — the caller owns correctness and CT.
- **Scope**: the crate is primitives + TLS/PKI plumbing (OpenSSL-like). Threshold
  / multi-party / message-envelope layers are out of scope.
- **Coverage gaps**: ML-KEM ACVP is a trimmed slice (not the full corpus);
  external DTLS/QUIC interop covers the server directions only (client
  directions + DTLS 1.3 pending a suitable reference peer); no NIST FIPS
  validation (CMVP) and no third-party audit.

---

*This document describes the state of the test suite and code as of the current
revision; verify against the source where it matters.*
