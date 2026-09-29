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
  [Constant-time posture](#constant-time-posture) section). A source-level
  constant-time review of every module was performed by Claude Fable 5.1 on
  2026-09-17 (secret inputs enumerated per operation, then every branch,
  memory index and variable-latency instruction on their data paths
  checked); its findings are fixed or listed under
  [Known residuals](#known-constant-time-residuals). The compiled code of
  the main secret-handling paths is additionally checked in CI with
  **Valgrind memcheck used as a taint tracker** (the ctgrind / TIMECOP
  technique) on x86_64, aarch64, i686 and armv7 Linux, with detected and
  forced-portable CPU dispatch and with and without the precomputed curve
  tables — see
  [Machine-code validation](#machine-code-validation-valgrind-memcheck) for
  exactly what that covers and what it cannot. There has been no formal
  third-party CT audit and no statistical timing measurement (dudect-style).

## At-a-glance matrix

KAT source legend: **ACVP** = NIST ACVP test vectors · **RFC** = the RFC's own
vectors · **CAVP** = NIST CAVP · **OpenSSL** = vectors produced by OpenSSL ·
**ref** = upstream reference-implementation vectors · **Wycheproof** = the
[C2SP/Wycheproof](https://github.com/C2SP/wycheproof) edge-case corpus (see
[below](#wycheproof)) · **unit** = inline / hand-derived correctness tests.

| Module | Standards | KAT source | Cross-impl interop | Fuzzed | Const-time |
|---|---|---|---|---|---|
| `ct` | — (foundation) | unit (exhaustive u8/i8) | — | — | foundation |
| `bignum` | — (foundation) | unit | — | — | yes (unconditional) |
| `hash` | FIPS 180-4, FIPS 202, SP 800-185, RFC 7693, BLAKE3, GOST R 34.11-2012 / RFC 6986 (Streebog), ISO/IEC 10118-3 (Whirlpool), K12/M14 paper, RFC 1319 (MD2) | RFC / NIST samples; **Wycheproof** (HMAC ×12, KMAC); M14 oracle-derived (K12-validated), cross-checked vs noble-hashes | OpenSSL (Whirlpool, SM3, SHAKE, BLAKE2), PyCryptodome (MD2), gostcrypto (Streebog), noble-hashes (M14, 14-round) | — | MAC verify CT |
| `mac` | RFC 4418 (UMAC), SipHash (Aumasson–Bernstein), draft-krovetz-vmac-01 (VMAC, behind the opt-in `vmac` feature) | RFC / paper vectors; **Wycheproof** (SipHash ×5, VMAC ×2) | — | — | built on CT AES; SipHash ARX; VMAC mask-based arithmetic |
| `rng` | SP 800-90A (HMAC-DRBG) | CAVP | — | — | n/a (public output) |
| `cipher` | FIPS 197, SP 800-38A/C/D, RFC 8439/8452, RFC 3713, EAX, AEGIS, RFC 7518 §5.2; RFC 4269 (SEED), MORUS v2 and AEGIS-128 behind the opt-in `legacy-ciphers` feature | RFC / NIST; **Wycheproof** (GCM, GCM-SIV, CCM, EAX, ChaCha20/XChaCha20-Poly1305, AEGIS, MORUS, GMAC, CBC, CMAC, SIV, KW/KWP, XTS, CBC-HS; ARIA/Camellia/SEED/SM4 modes) | — | — | AES table-free; ARX |
| `kdf` | RFC 8018/5869/7914, SP 800-108 | RFC / CAVP; **Wycheproof** (HKDF, PBKDF2, PBES2) | — | `pbes2_decrypt` | built on CT HMAC |
| `ascon` | NIST SP 800-232 (final); the v1.2 Ascon-128/128a/80pq AEADs behind the opt-in `legacy-ciphers` feature | ref KAT; **Wycheproof** | — | — | permutation (no tables) |
| `fpe` | NIST SP 800-38G FF1 (Rev. 1 `radix^n >= 10^6` floor; 2016 floor via `new_legacy`) | NIST FF1 samples (AES-128/192/256, radix 10 and 36); **Wycheproof** (22 files: 13 radices as digit lists, 9 as alphabets) | — | — | AES CT; the digit arithmetic is data-dependent by the nature of FPE |
| `dsa` | FIPS 186-4 (2048/224, 2048/256, 3072/256), RFC 6979 nonces | RFC 6979 A.2.1/A.2.2; **Wycheproof** (8 files) | — | — | CT ladder + CT inverse of `k`; legacy interop only |
| `bls` | BLS12-381, RFC 9380 (`BLS12381G2_XMD:SHA-256_SSWU_RO_`, G1 too), draft-irtf-cfrg-bls-signature (min-pubkey-size; Basic / Aug / PoP) | RFC 9380 J.9.1 / J.10.1 / K; Ethereum bls12-381-tests; **Wycheproof** (4 files) | — | — | fixed-limb Montgomery fields; masked-window scalar mult; complete addition |
| `chunked` | c2sp.org/chunked-encryption (Cobblestone-128/256) | **Wycheproof** (2 files) | — | — | delegates to AES-GCM / HKDF; commitment checked in CT before any chunk |
| `jose` | RFC 7515/7516/7517/7518/7638/8037 (JWS, JWE, JWK, thumbprints, OKP) | RFC appendix examples (bit-exact); **Wycheproof** (4 JOSE files + 6 JWK key-agreement files) | — | — | single collapsed error for every verification/decryption failure; RSA1_5 via implicit rejection |
| `der` | ITU-T X.690 | unit | — | `der_reader`, `pem_decode` | n/a (public) |
| `rsa` | RFC 8017 (PKCS#1 v1.5, PSS, OAEP) | unit; **Wycheproof** (v1.5 verify/sign/decrypt, PSS, OAEP, primality) | X.509 SPKI path | `pkcs8_rsa` | base-blinded; CT-shaped keygen |
| `ec` | FIPS 186, SEC 2 (incl. the binary curves), RFC 5639, RFC 8032 (EdDSA), RFC 7748 (X25519/X448) | RFC / unit; **Wycheproof** (ECDSA DER + P1363 on 16 curves × SHA-2/SHA-3/SHAKE, ECDH SPKI + raw + PEM + JWK on 16 curves, X25519/X448 + SPKI/PEM/JWK, Ed25519/Ed448, curve parameters; the secp160/192/224k1, P-192 and binary-curve files need `legacy-ec`) | OpenSSL (X25519 PKCS#8, ECDSA via dgst) | `ecdsa_sig_der`, `pkcs8_ed25519`, `spki_pubkey` | complete formulas / ladder |
| `dh` | RFC 3526, RFC 4419, SP 800-56A checks | unit | — (SSH/legacy-TLS groups) | `dh_share` | modexp on CT bignum |
| `key` | — (facade over the above) | unit (incl. OpenSSL X25519 PKCS#8) | inherits | `spki_pubkey`, `pkcs8_*` | inherits |
| `mlkem` | FIPS 203 | **ACVP** + OpenSSL 3.5; **Wycheproof** (keygen, encaps, decaps, malformed keys) | OpenSSL (SPKI, ct/ss) | `mlkem_pkcs8` | CT decaps + implicit rejection |
| `mldsa` | FIPS 204 | **ACVP** (keygen/siggen/sigver, all levels); **Wycheproof** (verify, sign from seed / expanded key, contexts) | OpenSSL (SPKI) | `pkcs8_mldsa`, `mldsa_verify` | hedged; CT compare + wipe |
| `slhdsa` | FIPS 205 | **ACVP** (keygen/siggen/sigver) | — | `pkcs8_slhdsa`, `slhdsa_verify` | hedged; wipe-on-drop |
| `falcon` | FN-DSA / FIPS 206 draft | ref (samplerz KAT) + unit | — | `falcon_verify` | signing CT (FPEMU); keygen best-effort |
| `lms` | RFC 8554, SP 800-208 | **RFC 8554 App. F** | ref vectors | `lms_parse` | n/a (hash-based, **stateful**) |
| `xmss` | RFC 8391, SP 800-208 | ref-impl KAT | ref vectors | `xmss_parse` | n/a (hash-based, **stateful**) |
| `x509` | RFC 5280 | unit | OpenSSL (SPKI pin) | `x509_certificate`, `x509_crl`, `x509_csr`, `spki_pubkey`, `ocsp_response`, `cert_decompress` | delegates to primitives |
| `pkcs12` | RFC 7292, RFC 9579 (PBMAC1) | OpenSSL fixtures | OpenSSL 3 + 1.1.1 legacy | `pkcs12_parse` (outer PFX / MacData / KDF params; the bags behind the MAC need a seeded corpus) | MAC CT, wrong-pw gate, wipe |
| `tls` | RFC 8446 (1.3), RFC 5246 (1.2) | **RFC 8448** traces; OpenSSL ChaCha20-Poly1305 record capture (RFC 7905) | loopback; **TLS 1.3 vs OpenSSL 3.0, OpenSSL 3.6, BoringSSL, GnuTLS 3.8, Apple's Network.framework and wolfSSL 5.9, both roles** (CI: certs × groups × suites, resumption (incl. PSK-only), external PSK, 0-RTT, HRR, mTLS, KeyUpdate, compression, RPK, OCSP, ALPN, record_size_limit, TLS 1.2 fallback); **TLS 1.2 vs OpenSSL 3.x, both roles, all AEAD suites** (CI); legacy vs OpenSSL 1.1.1; ECH vs BoringSSL; PSS interop | `tls_client_feed`, `tls_server_feed`, `tls_legacy_feed`, `ech_*` | CT record protection; legacy CBC caveats |
| `dtls` | RFC 6347 (1.2), RFC 9147 (1.3), RFC 9146 (connection IDs) | loopback; **wolfSSL 5.9 DTLS 1.3 record capture** (RFC 9147 §5.9 label prefix) | loopback; **DTLS 1.2 vs OpenSSL 3.x, both roles, all AEAD suites, fragmented ClientHello, client certificates** (CI); **DTLS 1.2 and DTLS 1.3 vs wolfSSL 5.9, both roles** (CI: certs × groups × suites, HRR, KeyUpdate, ALPN, mTLS, fragmentation at two MTUs, a lossy path, connection IDs); **DTLS 1.2 vs Mbed TLS 4.2, both roles** (CI: certs × groups × suites, ALPN, a lossy path, connection IDs) | `dtls_client_feed`, `dtls_server_feed` | inherits TLS |
| `quic` | RFC 9000/9001/9002/9221/9368/9369 | loopback | loopback; **QUIC v1 + v2 vs quic-go, both roles** and **vs OpenSSL 3.6 `s_client -quic`** (CI) | `quic_client_feed`, `quic_server_feed`, `quic_transport_params` | inherits TLS 1.3 |

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

### Wycheproof

The applicable part of the Wycheproof corpus (upstream `testvectors_v1`,
commit `3fa63dd`) is checked in as `testdata/wycheproof/*.txt` — a flat
`key=value` re-encoding produced by `tools/wycheproof/convert.py`, so the
vectors need no JSON parser — and runs in `tests/wycheproof/` through the
**public API only**. Policy (`tests/wycheproof/common.rs`): every `valid`
case must be accepted with the expected output, every `invalid` case must
be rejected, `acceptable` cases are pinned per flag by each module, and a
file whose cases were all skipped fails. Coverage at the time of writing:

| Family | Files | Cases (valid / invalid / acceptable) | Notes |
|---|---|---|---|
| AEADs (AES/ARIA/SM4/SEED-GCM, GCM-SIV, AES/ARIA/Camellia/SM4/SEED-CCM, AES-EAX, ChaCha20-/XChaCha20-Poly1305, AEGIS-128/128L/256, MORUS-640/1280, Ascon-128/128a/80pq and Ascon-AEAD128, GMAC, A128/192/256CBC-HS) | 26 | 5700 / 2565 / 0 | all tag lengths CCM defines; wrong-length nonces/keys rejected via the `try_*` APIs |
| Block-cipher modes (CBC/PKCS#7, CMAC, AES-SIV incl. AES-192, KW/KWP, XTS over AES/ARIA/Camellia/SEED) | 15 | 1150 / 2910 / 10 | `Cbc` is unpadded by design; the harness pads |
| HMAC (SHA-1/2/3, SHA-512/t, SM3), KMAC, SipHash-1-3/2-4/4-8, SipHashX, VMAC-64/128 | 21 | 2089 / 2154 / 0 | truncated tags prefix-compared; `verify` is length-strict; VMAC nonces with the top bit set rejected |
| HKDF, PBKDF2, PBES2 | 24 | 1884 / 12 / 0 | one PBKDF2 case skipped (16M iterations); PBES2 vectors are the bare RFC 8018 primitive, checked through PBKDF2 + CBC and — where in the wrapper's algorithm set — asserted to hit the 10 000-iteration floor |
| ECDSA (P-192/224/256/384/521, secp160k1/r1/r2, secp192k1, secp224k1, secp256k1, brainpoolP224/256/320/384/512r1 × SHA-2, SHA-3, SHAKE; DER and P1363; Bitcoin low-s) | 73 | 13736 / 16167 / 0 | SPKI keys cross-checked against SEC1; P-256 and secp256k1 also through the fixed-size types; P1363 halves are order-width (21 / 29 bytes on the 161- / 225-bit-order curves) |
| ECDH (SPKI and raw points, 10 prime curves), curve parameters | 15 | 7820 / 647 / 2301 | all wrong-curve / twist / explicit-parameter keys rejected; compressed peers (Tonelli–Shanks on P-224) must agree; 10 curves absent from the crate (twisted Brainpool, FRP256v1, brainpoolP160/192) skipped in `ec_prime_order_curves` |
| ECDH on the binary curves sect283/409/571 k1/r1 | 6 | 93 / 126 / 1355 | López–Dahab ladder; low-order peers rejected by the `n·Q = ∞` check |
| ECDH PEM (SPKI + PKCS#8 PEM on P-224/256/384/521), X25519 / X448 PEM | 6 | 2689 / 211 / 1417 | `InvalidPem` (mangled DER behind the armour) rejected like `InvalidAsn` |
| ECDH / XDH through JWK (`_webcrypto`, `x25519_jwk`, `x448_jwk`) | 6 | 2723 / 130 / 499 | JWK coordinates exact-width and on-curve; `P-256K` accepted as an input alias |
| X25519, X448 (raw and SPKI/PKCS#8), Ed25519, Ed448 | 6 | 1140 / 195 / 997 | zero-shared-secret peers are an error (`SmallOrderPeer`) |
| DSA 2048/224, 2048/256, 3072/256 (DER and P1363) | 8 | 588 / 1364 / 4 | key parsed from components and SPKI and required to agree; `MissingZero` legacy encodings rejected |
| RSA PKCS#1 v1.5 verify (SHA-2, SHA-512/t, SHA-3), deterministic signing, decryption | 32 | 377 / 6082 / 102 | `MissingNull` DigestInfo rejected; implicit-rejection decrypt cross-checked |
| RSA-PSS (MGF1 and the RFC 8702 SHAKE128/SHAKE256 forms), RSA-OAEP (incl. an MGF1 hash distinct from the message hash, via the `_mgf` APIs; two-prime and three-prime keys), primality | 52 | 3234 / 1777 / 11 | three-prime OAEP decrypted both from the multi-prime PKCS#8 and from a key built from the components incl. `otherPrimeInfos` |
| BLS12-381: hash-to-G2, Basic / PoP signature verify, aggregate verify | 4 | 82 / 85 / 0 | `NotInSubgroup`, `InvalidFlags`, `NotOnCurve`, `IdentityPoint`, `EmptyAggregate`, `MismatchedCount` must fail with the matching error variant |
| ML-KEM (keygen, encaps, decaps, malformed keys), ML-DSA (verify, sign from seed and expanded key, contexts) | 21 | 1829 / 965 / 0 | 69 ML-DSA "external mu" cases skipped (no `Sign_internal(mu)` entry point) |
| FF1 (radix 10/16/26/32/36/45/62/64/85/255/256/65535/65536 as digit lists, and the nine text alphabets through `Alphabet`) | 22 | 49240 / 8006 / 0 | messages up to 260 digits; `SmallMessageSize` cases (valid under the 2016 floor only) are refused by `Ff1::new` and then checked through `Ff1::new_legacy` |
| C2SP chunked encryption (Cobblestone-128/256) | 2 | 20 / 50 / 0 | one-shot, streaming (partial-prefix + sticky error) and raw-mode paths, plus byte-exact re-encryption with the vectors' salt |
| JOSE: JWS, JWK sets, JWE, mixed | 4 | 116 / 525 / 0 | 8 `json_web_signature` cases skipped as upstream defects (byte-identical to valid cases or keys whose `alg` contradicts the header); JSON-serialization cases verified through the JSON API |

**Every one of the 343 upstream files runs: 145 265 cases, 88 skipped**
(the ML-DSA external-mu cases, the ten curves the parameter file lists that
the crate does not implement, the eight upstream-defective JWS cases and the
16M-iteration PBKDF2 case). The corpus found two crate bugs (the SPKI parser
accepted trailing bytes after a well-formed key; the `key` facade split raw
`r ‖ s` signatures at the field width, wrong on the curves whose order is a
bit longer than the field), both fixed. The following were implemented so
the corpus could be covered in full: AES-192-SIV, SHA-3 / SHA-512/t PKCS#1
DigestInfo prefixes, separate-MGF-hash PSS/OAEP, multi-prime RSA, SHAKE-PSS
(RFC 8702), AES-EAX, SEED, MORUS, AEGIS-128, Ascon v1.2,
AES-CBC-HMAC-SHA2, SipHash/SipHashX, VMAC, FF1, DSA, secp160/192/224 and
brainpoolP224/320r1, the sect283/409/571 binary curves, BLS12-381 with BLS
signatures, C2SP chunked encryption and JOSE. Regenerate after an upstream
update with the commands in `tools/wycheproof/README.md`.

## Cross-implementation interop

- **OpenSSL, byte-exact**: X25519 PKCS#8 (RFC 8410), ML-KEM-768 SPKI + ct/ss,
  ML-DSA-65 SPKI, X.509 SPKI pin (SHA-256 over the SPKI), PKCS#12 archives
  (OpenSSL 3 default *and* OpenSSL legacy 3DES), RSA-PSS (`examples/pss_interop`).
- **OpenSSL, behavioural**: ECDSA sign↔verify via `openssl dgst`, TLS 1.0/1.1
  legacy interop against OpenSSL 1.1.1 (`examples/tls_legacy_interop`, the
  `tls-legacy` feature).
- **OpenSSL 3.x, TLS 1.2 and DTLS 1.2 cipher-suite matrix** (CI job
  `interop-openssl-tls12.yml`, script `tools/tls12-interop/run.sh`): the
  purecrypto CLI against the runner's `openssl s_client` / `s_server`, in
  **both roles**, over TCP (TLS 1.2) and UDP (DTLS 1.2), with an ECDSA and
  an RSA certificate, for every AEAD suite the 1.2 engines offer — the
  OpenSSL side pins the suite and each handshake exchanges application
  data:

  | Suite | TLS 1.2 client / server | DTLS 1.2 client / server | DTLS 1.2 server, fragmented ClientHello | DTLS 1.2 mTLS client / server (+ fragmented) |
  |---|---|---|---|---|
  | `ECDHE-{ECDSA,RSA}-AES128-GCM-SHA256` | ✅ / ✅ | ✅ / ✅ | ✅ | ✅ / ✅ (✅) |
  | `ECDHE-{ECDSA,RSA}-AES256-GCM-SHA384` | ✅ / ✅ | ✅ / ✅ | ✅ | ✅ / ✅ (✅) |
  | `ECDHE-{ECDSA,RSA}-CHACHA20-POLY1305` (RFC 7905) | ✅ / ✅ | ✅ / ✅ | ✅ | ✅ / ✅ (✅) |

  Every DTLS 1.2 case also runs with a client certificate: the server
  demands one (`openssl s_server -Verify 1` / `purecrypto s_server
  -Verify`) and the client presents the case's leaf, so the client's
  Certificate and CertificateVerify — signed over the DTLS-shaped
  transcript (RFC 6347 §4.2.6), after the ClientKeyExchange (RFC 5246
  §7.4.8) — are verified by the other implementation; in the fragmented
  variant the OpenSSL client's 256-byte MTU splits its Certificate across
  datagrams too.

  The OpenSSL → purecrypto DTLS 1.2 cases run twice: as OpenSSL sends by
  default, and with `s_client` at its minimum link MTU (256) and an ALPN
  offer sized so that both the first and the cookie-bearing ClientHello
  arrive in two datagrams. The server's stateless cookie path (RFC 6347
  §4.2.1) used to refuse any ClientHello that was not one whole fragment,
  so a client on a small path MTU could never complete the
  HelloVerifyRequest round trip; the harness had hidden that behind
  `-mtu 1500`. Such ClientHellos are now reassembled in the same bounded
  pre-cookie buffer the DTLS 1.3 server uses (8 KiB claimed length, four
  candidates, flushed after 32 fragments without a completion, `message_seq`
  0 or 1 only) before the cookie is checked.

  Three symmetric bugs that loopback had hidden fell to this matrix: the
  ChaCha20-Poly1305 suites used the AES-GCM explicit-nonce framing instead
  of the RFC 7905 XOR construction, the DTLS 1.2 transcript hashed
  TLS-shaped handshake headers instead of the 12-byte DTLS ones (RFC 6347
  §4.2.6), and the fragmented pre-cookie ClientHello above (the purecrypto
  client never fragments its own). A record capture from that OpenSSL
  exchange is pinned as a unit test of the RFC 7905 nonce and key-block
  layout.
- **TLS 1.3 matrix, both roles, against OpenSSL 3.0, OpenSSL 3.6 and
  BoringSSL** (CI workflow `interop.yml`, one job per peer; runner
  `tools/interop/run.sh`, adapters under `tools/interop/peers/`, contract in
  `tools/interop/README.md`): the purecrypto CLI against the runner's
  `openssl` 3.0.x, an `openssl` 3.6 built from source (ML-KEM hybrid,
  ML-DSA, raw public keys, zlib compression) and `bssl` at a pinned commit,
  over TCP, purecrypto as client (`C`) and as server (`S`). Every case
  exchanges application data and is checked on **both** sides for the
  negotiated version, suite and group (a handshake that completed with the
  wrong group is a failure) and, where the tool sends one, for the peer's
  `close_notify`. 264 cases per peer; `⏭` is a SKIP with the reason (a peer
  or tool limitation, never a relaxed check):

  | Case | OpenSSL 3.0 (C / S) | OpenSSL 3.6 (C / S) | BoringSSL (C / S) |
  |---|---|---|---|
  | Plain: `{RSA-2048, P-256, P-384, Ed25519}` × `{x25519, P-256, P-384, P-521}` × `{AES-128-GCM, AES-256-GCM, ChaCha20}` | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ (S: AES-128-GCM only — `bssl client` cannot pin a TLS 1.3 suite) |
  | Plain, `X25519MLKEM768` | ⏭ 3.0 has none | ✅ / ✅ | ✅ / ✅ |
  | Plain, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` (RFC 10024) | ⏭ 3.0 has none | ✅ / ✅ | ⏭ BoringSSL has no NIST-curve hybrids |
  | Plain, ML-DSA-65 certificate | ⏭ 3.0 has none | ✅ / ✅ | ⏭ no ML-DSA |
  | Resumption (PSK + DHE) | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
  | Resumption, PSK-only (`psk_ke`) | ✅ / ✅ (`-allow_no_dhe_kex`) | ✅ / ✅ | ⏭ BoringSSL has no `psk_ke` |
  | External PSK (RFC 8446 §4.2.11) | ✅ / ✅ (`-psk` / `-psk_identity`) | ✅ / ✅ | ✅ / ✅ (RFC 9258 importer, `-psk-hex`) |
  | 0-RTT accepted | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
  | 0-RTT rejected across a HelloRetryRequest, PSK still accepted | ✅ / ✅ | ✅ / ✅ | ✅ / ⏭ `bssl client` treats `EARLY_DATA_REJECTED` as fatal |
  | HelloRetryRequest to `x25519`, `P-256`, `P-384`, `P-521` | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
  | HelloRetryRequest to `X25519MLKEM768` | ⏭ | ✅ / ✅ | ✅ / ⏭ `bssl client` always shares it |
  | HelloRetryRequest to `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` | ⏭ | ✅ / ✅ | ⏭ |
  | mTLS, client certificate `{RSA-2048, P-256, P-384, Ed25519}` | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ (C with Ed25519: ⏭ `bssl server` cannot be told to accept it) |
  | mTLS, ML-DSA-65 client certificate | ⏭ | ✅ / ✅ | ⏭ |
  | KeyUpdate (`update_requested`) from purecrypto, peer replies | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
  | KeyUpdate (`update_requested`) from the peer, purecrypto replies | ✅ / ✅ | ✅ / ✅ | ⏭ `bssl` has no trigger |
  | RFC 8879 zlib certificate compression (server certificate) | ⏭ 3.2+ | ✅ / ✅ | ⏭ the tool registers no algorithm |
  | RFC 7250 raw public key, server identity | ⏭ 3.2+ | ✅ / ✅ | ✅ / ✅ |
  | RFC 7250 raw public key, client identity | ⏭ 3.2+ | ✅ / ✅ | ✅ / ✅ |
  | OCSP stapling (`openssl ocsp` response, validated) | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
  | ALPN | ✅ / ✅ | ✅ / ✅ | ⏭ `bssl server` has no ALPN option / ✅ |
  | RFC 8449 `record_size_limit` | ⏭ not implemented by OpenSSL | ⏭ | ⏭ not implemented by BoringSSL |
  | Chain > 16 KiB (Certificate spans records) | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
  | TLS 1.2 fallback (peer is 1.2-only) | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
  | `close_notify` from the peer | ✅ / ✅ | ✅ / ✅ | ⏭ neither `bssl` role sends one |

  What this matrix caught that loopback could not: the client only sent
  `psk_key_exchange_modes` when it already held a session, so a BoringSSL
  server — which issues no ticket to a client that advertised no mode (RFC
  8446 §4.2.9) — could never be resumed; loopback resumed happily, since
  the purecrypto server issues tickets regardless. Two OpenSSL behaviours
  are worked around on the *peer* side, documented in the adapter: with
  anti-replay on, OpenSSL's stateful 0-RTT tickets are single-use, so the
  ticket a HelloRetryRequest makes the client re-present is already gone
  (`-no_anti_replay`); and OpenSSL only sends compressed certificates it
  pre-compressed (`-cert_comp`). Compression of the *client* certificate
  (RFC 8879 in the mTLS direction) is not implemented by purecrypto and is
  not in the matrix.
- **TLS 1.3 matrix, both roles, against Mbed TLS 4.2.0** (the same
  workflow, peer `mbedtls`, adapter `tools/interop/peers/mbedtls.sh`): the
  purecrypto CLI against `ssl_client2` / `ssl_server2` from a source build
  of the pinned release tag (`MBEDTLS_TAG` in the workflow; the default
  configuration plus `MBEDTLS_SSL_EARLY_DATA` and
  `MBEDTLS_SSL_RECORD_SIZE_LIMIT`, which are off by default), cached by tag.
  The two programs are HTTP-shaped rather than stdin-driven, so the payload
  travels as the request page; neither prints the negotiated group or the
  PSK / early-data outcome, so the adapter reads the library's debug log
  (`write selected_group:`, `key exchange mode: psk_ephemeral`, `DHE group
  name:`, `ServerHello: pre_shared_key(41) extension exists.`,
  `EncryptedExtensions: early_data(42) extension exists.`). 81 of the 228
  cases run, 148 SKIP; the peer pins group and suite in both roles
  (`groups=`, `force_ciphersuite=`), so every run is checked on both sides:

  | Case | Mbed TLS 4.2.0 (C / S) |
  |---|---|
  | Plain: `{RSA-2048, P-256, P-384}` × `{x25519, P-256, P-384, P-521}` × `{AES-128-GCM, AES-256-GCM, ChaCha20}` | ✅ / ✅ |
  | Plain, `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` | ⏭ no ML-KEM hybrids |
  | Plain, Ed25519 certificate | ⏭ no EdDSA |
  | Plain, ML-DSA-65 certificate | ⏭ no ML-DSA |
  | Resumption (PSK + DHE) | ✅ / ✅ |
  | Resumption, PSK-only (`psk_ke`) | ⏭ the Mbed TLS server prefers (psk_)ephemeral while a key_share is offered / ✅ |
  | External PSK (RFC 8446 §4.2.11) | ✅ / ✅ (`psk=` / `psk_identity=`) |
  | 0-RTT accepted | ✅ / ✅ |
  | 0-RTT rejected across a HelloRetryRequest, PSK still accepted | ✅ / ✅ |
  | HelloRetryRequest to `x25519`, `P-256`, `P-384`, `P-521` | ✅ / ✅ |
  | HelloRetryRequest to the ML-KEM hybrids | ⏭ |
  | mTLS, client certificate `{RSA-2048, P-256, P-384}` | ✅ / ✅ |
  | mTLS, Ed25519 / ML-DSA-65 client certificate | ⏭ / ⏭ |
  | KeyUpdate from either side | ⏭ Mbed TLS does not implement TLS 1.3 KeyUpdate at all: a received one is a fatal `unexpected_message` |
  | RFC 8879 zlib certificate compression | ⏭ not implemented |
  | RFC 7250 raw public key, either identity | ⏭ not implemented |
  | OCSP stapling | ⏭ no `status_request` in Mbed TLS's TLS 1.3 |
  | ALPN | ✅ / ✅ |
  | RFC 8449 `record_size_limit` | ✅ / ✅ — the Mbed TLS server splits its 3000-byte response into six 511-byte records for the purecrypto client's limit of 512; the Mbed TLS client advertises 16384 on every TLS 1.3 connection, which the purecrypto server accepts |
  | Chain > 16 KiB (Certificate spans records) | ⏭ a handshake message must fit Mbed TLS's fixed 16 KiB I/O buffer (`MBEDTLS_SSL_{IN,OUT}_CONTENT_LEN` cannot be larger): its server cannot write the Certificate, its client cannot reassemble it |
  | TLS 1.2 fallback (peer is 1.2-only) | ✅ / ✅ |
  | `close_notify` from the peer | ✅ / ✅ |

  Mbed TLS also speaks DTLS 1.2 (no DTLS 1.3), and the adapter lists it
  (`protos`), so the DTLS 1.2 matrix runs against it too — the second
  external peer for purecrypto's DTLS 1.2 after OpenSSL and wolfSSL, and
  the second for RFC 9146 connection IDs (`dtls=1 force_version=dtls12`,
  `cid=1 cid_val=HEX` on both programs; the summary's `Peer CID (length N
  Bytes): …` is the purecrypto side's CID). 44 of the 152 DTLS 1.2 cases
  run:

  | Case | Mbed TLS 4.2.0, DTLS 1.2 (C / S) |
  |---|---|
  | Plain: `{P-256, P-384}` × `{x25519, P-256, P-384}` × `{AES-128-GCM, AES-256-GCM, ChaCha20}` | ✅ / ✅ |
  | Plain, RSA-2048 certificate | ✅ / ⏭ the Mbed TLS (D)TLS 1.2 server signs ServerKeyExchange with PKCS#1 v1.5 only, and purecrypto's 1.2 client offers RSA-PSS only ("got ciphersuites in common, but none of them usable"); the Mbed TLS client verifies the purecrypto server's `rsa_pss_rsae_sha256` signature |
  | Plain, Ed25519 / ML-DSA-65 certificate; `X25519MLKEM768` | ⏭ purecrypto's 1.2 engines |
  | ALPN | ✅ / ✅ |
  | Handshake over a path dropping 20 % of datagrams; the last flight lost (`loss-final`) | ✅ / ✅ |
  | RFC 9146 connection IDs | ✅ / ✅ |
  | Chain > 16 KiB, at the default and at a 512-byte MTU | ⏭ the 16 KiB I/O buffer |
  | HelloRetryRequest, KeyUpdate | — (none in DTLS 1.2) |
  | Resumption, 0-RTT, mTLS | ⏭ purecrypto's DTLS engines |

  No purecrypto defect surfaced against Mbed TLS. One tool behaviour is
  worked around on the peer side: `ssl_server2` answers one request per
  connection, and a client whose 0-RTT was rejected sends the early data
  again as ordinary data before the payload, so that case runs the server
  with `exchanges=2`.
- **Windows SChannel, TLS 1.3 matrix, both roles** (the `schannel` job of
  `interop.yml`, on GitHub's `windows-latest` image — Windows Server 2025,
  build 10.0.26100 — through .NET's `System.Net.Security.SslStream`, which
  is SChannel on Windows; adapter `tools/interop/peers/schannel.sh`, peer
  program `tools/interop/peers/schannel/` in C#, built on the runner with
  the image's .NET SDK and run on its newest runtime, .NET 10). Same
  runner and cases as the table above; the peer reports what `SslStream`
  exposes (`SslProtocol`, `NegotiatedCipherSuite`, `KeyExchangeStrength` —
  the curve size, which tells x25519 (255), P-256 and P-384 apart, since
  the group itself is not named on TLS 1.3 — ALPN, the peer certificate
  and mutual authentication), and the purecrypto side is pinned and
  verified as before. Two things about the peer's environment: the image
  pins SChannel's TLS policy (the group-policy cipher-suite and ECC-curve
  lists under `HKLM\SOFTWARE\Policies\Microsoft\Cryptography\Configuration\SSL\00010002`)
  to a list without curve25519 and ChaCha20, both of which the OS supports
  and has in its local defaults, and without NistP521, which it supports
  but leaves out of its default curve order — so the job appends the
  three to the policy lists before the matrix (SChannel picks that up at
  once); and
  `SslStream` has no knob for cipher suites or groups on Windows
  (`CipherSuitesPolicy` is Linux/macOS only), so the SChannel *client*
  offers everything the policy enables, and the purecrypto server's own
  preference (AES-128-GCM) is the only suite that can be checked in that
  direction. 52 cases pass, 174 are SKIPs:

  | Case | SChannel (C / S) |
  |---|---|
  | Plain: `{RSA-2048, P-256, P-384}` × `{x25519, P-256, P-384, P-521}` × `{AES-128-GCM, AES-256-GCM, ChaCha20}` | ✅ / ✅ (S: AES-128-GCM only — the client cannot restrict suites) |
  | Plain, Ed25519 certificate | ⏭ SChannel has no Ed25519 (and .NET cannot load the key) |
  | Plain, ML-DSA-65 certificate | ⏭ SChannel has no ML-DSA |
  | Plain, `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` | ⏭ no ML-KEM hybrid group in Server 2025's SChannel |
  | Resumption (PSK + DHE) | ✅ / ✅ (`SslStream` does not report resumption; the purecrypto side's `resumed: yes` on the second connection of one peer process does) |
  | Resumption, PSK-only (`psk_ke`) | ⏭ `SslStream` exposes no PSK-only resumption |
  | External PSK (RFC 8446 §4.2.11) | ⏭ `SslStream` has no external-PSK API |
  | 0-RTT (accepted, and rejected across an HRR) | ⏭ `SslStream` has no 0-RTT API and SChannel accepts no early data |
  | HelloRetryRequest | ⏭ the SChannel client sends a key share for every group it offers, and the server's group preference follows system policy: neither side can be steered into one |
  | mTLS, client certificate `{RSA-2048, P-256, P-384}` | ✅ / ✅ (client certificates verified by the .NET chain engine, rooted in the run's CA) |
  | mTLS, Ed25519 / ML-DSA-65 client certificate | ⏭ as above |
  | KeyUpdate (`update_requested`) from purecrypto, peer replies | ✅ / ✅ (SChannel replies with the next application-data record it sends, not on its own — RFC 8446 §4.6.3 asks for no more — so the peer is made to send after the update: the server answers after the client's first record, the client sends a second round) |
  | KeyUpdate from the peer, purecrypto replies | ⏭ `SslStream` has no KeyUpdate API |
  | RFC 8879 certificate compression | ⏭ not implemented by SChannel |
  | RFC 7250 raw public keys (either direction) | ⏭ not implemented by SChannel |
  | OCSP stapling | ✅ (the client runs with revocation checking on: the leaf has no AIA URL, so the platform chain engine can only pass on the stapled response — and rejects the certificate with `RevocationStatusUnknown` when purecrypto does not staple) / ⏭ the SChannel server staples only a response it fetched itself (AIA); no API to supply one |
  | ALPN | ✅ / ✅ |
  | RFC 8449 `record_size_limit` | ⏭ not implemented by SChannel |
  | Chain > 16 KiB (Certificate spans records) | ✅ / ⏭ SChannel cannot send a Certificate message over 16 KiB: the server credential is refused up front (`AcquireCredentialsHandle`: `SEC_E_INVALID_PARAMETER`; the same 9 KiB leaf under a small issuer, or the same 9 KiB intermediate under a small leaf, is fine). Receiving such a chain works (C) |
  | TLS 1.2 fallback (peer is 1.2-only) | ✅ / ✅ |
  | `close_notify` from the peer | ✅ / ✅ (`SslStream.ShutdownAsync`) |

  Nothing on the purecrypto side needed changing. Two Windows behaviours
  shape the adapter: a socket closed with unread data resets the
  connection, and Windows discards the receive queue on a reset, so the
  peer server only answers after the client's first record (the
  purecrypto `-reconnect` ticket-only connection says goodbye at once; an
  answer written into its closing socket cost the server that
  connection's `close_notify`); and SChannel answers a
  `KeyUpdate(update_requested)` only with the next application-data
  record it sends.
- **Apple's TLS stack (Network.framework), TLS 1.3 matrix, both roles** (the
  `apple` job of `interop.yml` on `macos-latest`; adapter
  `tools/interop/peers/apple.sh` driving the Swift tool in
  `tools/interop/peers/apple/`, an `NWConnection` client and an `NWListener`
  server configured through `sec_protocol_options_*`): the same 228-case
  matrix against the OS's TLS stack — the peer version is the runner's
  macOS (`macos-latest` was 26.6.2 / 25G83 when this landed; the job
  prints `sw_vers`). Identities are PKCS#12 archives the purecrypto CLI exports
  (`pkcs12 -export`) imported into a throwaway keychain; groups, 0-RTT,
  resumption and compression facts, and raw public keys go through SPI
  from Apple's open-source `SecProtocolPriv.h`, resolved at run time and
  SKIPped with a reason when absent. The tool reads the negotiated
  parameters when the exchange is over, not when the connection becomes
  ready: the stack keeps rewriting its metadata object, unlocked, while it
  processes the NewSessionTickets that follow the handshake, and a read in
  that window came back without the group (or the peer's chain) on a
  loaded runner. The group is compared as a whole value for every session;
  `group: unavailable` (the SPI answered nothing) fails the case, and only
  `group: unknown (no SPI)` — a macOS without the symbol — leaves the
  group to the purecrypto side's `key exchange:` line, which the runner
  checks in every case. `C` / `S` as above:

  | Case | Apple (C / S) |
  |---|---|
  | Plain: `{RSA-2048, P-256, P-384}` × `{x25519, P-256, P-384, P-521, X25519MLKEM768}` × `{AES-128-GCM, AES-256-GCM, ChaCha20}` | ✅ / ✅ (the client offers both AES-GCM suites whichever is asked for; the purecrypto server's `-ciphersuites` pins the case's) |
  | Plain, Ed25519 certificate | ⏭ the stack offers no `ed25519` signature scheme (with or without the eddsa SPI) and its keychain has no Ed25519 keys |
  | Plain, ML-DSA-65 certificate | ⏭ no ML-DSA |
  | Plain, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` | ⏭ the stack has no NIST-curve ML-KEM hybrids |
  | Resumption (PSK + DHE) | ✅ / ✅ |
  | Resumption, PSK-only (`psk_ke`) | ⏭ Network.framework exposes no PSK-only resumption |
  | External PSK (RFC 8446 §4.2.11) | ⏭ Network.framework has no external-PSK API |
  | 0-RTT accepted | ✅ / ⏭ a listener that accepts 0-RTT never completes the connection (`errSSLClosedNoNotify`; OpenSSL's client sees the same) |
  | 0-RTT rejected across a HelloRetryRequest, PSK still accepted | ✅ / ✅ |
  | HelloRetryRequest to `x25519`, `P-256`, `P-384`, `P-521` | ✅ / ✅ |
  | HelloRetryRequest to `X25519MLKEM768` | ⏭ the client always shares it / ✅ |
  | HelloRetryRequest to the NIST-curve hybrids | ⏭ |
  | mTLS, client certificate `{RSA-2048, P-256, P-384}` | ✅ / ✅ |
  | mTLS, Ed25519 / ML-DSA-65 client certificate | ⏭ as above |
  | KeyUpdate (`update_requested`) from purecrypto, peer replies | ✅ / ✅ |
  | KeyUpdate (`update_requested`) from the peer, purecrypto replies | ⏭ no API to send one |
  | RFC 8879 zlib certificate compression (server certificate) | ✅ / ✅ (the stack compresses its own and accepts ours) |
  | RFC 7250 raw public key, server identity | ✅ / ⏭ presenting one through the SPI fails with `errSSLInternal` |
  | RFC 7250 raw public key, client identity | ⏭ same / ✅ (the allowlist is enforced: a key not on it draws `bad_certificate`) |
  | OCSP stapling | ✅ / ⏭ no API to staple on a server |
  | ALPN | ✅ / ✅ |
  | RFC 8449 `record_size_limit` | ⏭ not implemented by Apple's stack |
  | Chain > 16 KiB (Certificate spans records) | ✅ / ✅ |
  | TLS 1.2 fallback (peer is 1.2-only) | ✅ / ✅ |
  | `close_notify` from the peer | ✅ / ✅ (checked on the purecrypto side; Network.framework reports a `close_notify` and a bare FIN alike) |

  What this peer caught: a server may issue its NewSessionTickets with its
  first write rather than right after the handshake (Apple's does), so a
  client that sends nothing and waits for a ticket waits forever —
  `s_client -reconnect` now closes after its wait and takes the tickets
  that come back with the server's goodbye. And `Config::cipher_suites`
  was inert on the server: a client that cannot narrow its offer (Apple's
  sends both AES-GCM suites for either) could never be steered to
  AES-256-GCM; the TLS 1.3 server now honours it as its accept-set in
  server preference order (`s_server -ciphersuites`). The Apple client
  resumes only with early data enabled through the SPI; the tool enables
  it for the resumption cases without queuing any 0-RTT.
- **The same matrix against LibreSSL** (`interop.yml`, adapter
  `tools/interop/peers/libressl.sh`; two jobs): LibreSSL 4.3.2 built from
  the release tarball on Linux, and the LibreSSL 3.3.6 every Mac ships as
  `/usr/bin/openssl` on the macOS runner. LibreSSL's `s_client` /
  `s_server` are OpenSSL-1.0-shaped and its TLS 1.3 stack is its own, so
  the adapter is separate from the OpenSSL one. Both roles, 228 cases each;
  4.3.2 passes 94 and skips 132, 3.3.6 passes 73 and skips 153, none fail:

  | Case | LibreSSL 4.3 (C / S) | LibreSSL 3.3, macOS (C / S) |
  |---|---|---|
  | Plain: `{RSA-2048, P-256, P-384}` × `{x25519, P-256, P-384, P-521}` × `{AES-128-GCM, AES-256-GCM, ChaCha20}` | ✅ / ✅ | ✅ / ✅ |
  | Plain, `X25519MLKEM768` | ✅ / ✅ | ⏭ 4.3+ |
  | Plain, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` | ⏭ LibreSSL has no NIST-curve hybrids | ⏭ |
  | Plain, Ed25519 certificate | ⏭ no Ed25519 in TLS: the apps cannot load the key, `signature_algorithms` omits it | ⏭ |
  | Plain, ML-DSA-65 certificate | ⏭ no ML-DSA | ⏭ |
  | Resumption (PSK + DHE), 0-RTT accepted, 0-RTT rejected across HRR | ⏭ LibreSSL's TLS 1.3 has no resumption: no `psk_key_exchange_modes`, no NewSessionTicket | ⏭ |
  | Resumption, PSK-only (`psk_ke`) | ⏭ LibreSSL's TLS 1.3 has no resumption | ⏭ |
  | External PSK (RFC 8446 §4.2.11) | ⏭ LibreSSL's TLS 1.3 has no external PSK | ⏭ |
  | HelloRetryRequest to `x25519`, `P-256`, `P-384`, `P-521` | ✅ / ✅ | ✅ / ✅ |
  | HelloRetryRequest to `X25519MLKEM768` | ✅ / ✅ | ⏭ |
  | HelloRetryRequest to the NIST-curve hybrids | ⏭ | ⏭ |
  | mTLS, client certificate `{RSA-2048, P-256, P-384}` | ✅ / ✅ | ✅ / ✅ |
  | mTLS, Ed25519 / ML-DSA-65 client certificate | ⏭ | ⏭ |
  | KeyUpdate (`update_requested`) from purecrypto, peer replies | ✅ / ✅ | ⏭ 3.3's `s_server` answers with records neither side can decrypt (also against OpenSSL 3.6) / ✅ |
  | KeyUpdate (`update_requested`) from the peer, purecrypto replies | ⏭ the apps have no trigger | ⏭ |
  | RFC 8879 zlib certificate compression (server certificate) | ⏭ not implemented by LibreSSL | ⏭ |
  | RFC 7250 raw public key, server or client identity | ⏭ not implemented by LibreSSL | ⏭ |
  | OCSP stapling | ✅ / ✅ (`s_server -status` fetches from an `openssl ocsp` responder the adapter runs) | ✅ / ✅ |
  | ALPN | ✅ / ✅ | ✅ / ✅ |
  | RFC 8449 `record_size_limit` | ⏭ not implemented by LibreSSL | ⏭ |
  | Chain > 16 KiB (Certificate spans records) | ✅ / ✅ | ✅ / ✅ |
  | TLS 1.2 fallback (peer is 1.2-only) | ⏭ LibreSSL has no RFC 7627 `extended_master_secret`; purecrypto requires it on TLS 1.2 (both roles abort with `handshake_failure`, as RFC 7627 §5.3 describes) | ⏭ |
  | `close_notify` from the peer | ✅ / ⏭ `s_server` sets the shutdown flags without sending the alert | ✅ / ⏭ |

  LibreSSL peculiarities the adapter accommodates rather than skips: its
  client sends key shares for the first *two* groups it lists (one, before
  4.x), so the HRR cases list the pinned group third; `s_server` builds the
  chain it sends from `-CAfile` alone (the oversized chain's intermediate
  goes there — with the root too, it sends all three); 3.3's `s_server` has
  no `-naccept`, block-buffers its summary and never exits on its own, so it
  runs on a pty and is stopped after `CONNECTION CLOSED`. Two purecrypto
  security checks surfaced as LibreSSL limitations and were kept: the TLS
  1.2 extended-master-secret requirement above, and the signature policy
  on stapled OCSP responses — LibreSSL's own `openssl ocsp` responder
  signs with SHA-1 (no `-rmd`), which purecrypto's client refuses with
  `bad_certificate`, so the responder the OCSP case runs is the runner's
  OpenSSL 3, signing with SHA-256.
- **TLS 1.3 matrix, both roles, against GnuTLS 3.8.3 and 3.8.13** (the
  same workflow, peers `gnutls` and `gnutls-src`, adapter
  `tools/interop/peers/gnutls.sh`): the purecrypto CLI against `gnutls-cli`
  / `gnutls-serv` from the runner's `gnutls-bin` (GnuTLS 3.8.3 on
  ubuntu-24.04, a build without zlib; the job prints the exact version)
  and from GnuTLS 3.8.13 built from the release tarball with leancrypto
  1.9.1 (cached by version: ML-KEM hybrids and ML-DSA are only in a
  3.8.10+ build with leancrypto, which no distribution package has).
  Everything is pinned through a priority string
  (`-VERS-ALL:+VERS-TLS1.3:-GROUP-ALL:+GROUP-…:-CIPHER-ALL:+…`,
  `CTYPE-*-RAWPK` for raw public keys) and verified from the tools'
  `- Description:` line, verbose ECDH block and `-d 5` debug log
  (handshake messages, extensions, alerts). `gnutls-serv` never exits on
  its own, so the adapter runs it under a small supervisor that stops it
  once its log shows the case's `close_notify` from the client. 111 of
  the 228 cases run against 3.8.3 and 164 against 3.8.13:

  | Case | GnuTLS 3.8.3 (C / S) | GnuTLS 3.8.13 + leancrypto (C / S) |
  |---|---|---|
  | Plain: `{RSA-2048, P-256, P-384, Ed25519}` × `{x25519, P-256, P-384, P-521}` × `{AES-128-GCM, AES-256-GCM, ChaCha20}` | ✅ / ✅ | ✅ / ✅ |
  | Plain, `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` | ⏭ no ML-KEM in this build | ✅ / ✅ |
  | Plain, ML-DSA-65 certificate | ⏭ no ML-DSA in this build | ✅ / ✅ |
  | Resumption (PSK + DHE) | ✅ / ✅ | ✅ / ✅ |
  | Resumption, PSK-only (`psk_ke`) | ✅ / ✅ (server priority `+PSK`) | ✅ / ✅ |
  | External PSK (RFC 8446 §4.2.11) | ✅ / ✅ (`--pskusername` / `--pskpasswd`) | ✅ / ✅ |
  | 0-RTT accepted | ✅ / ✅ (C: `gnutls-serv` < 3.8.10 drops the early data it read, so the record-layer log stands in for the echo) | ✅ / ✅ |
  | 0-RTT rejected across a HelloRetryRequest, PSK still accepted | ⏭ GnuTLS issue #1429, both roles (below) | ⏭ |
  | HelloRetryRequest to `x25519`, `P-256`, `P-384`, `P-521` | ✅ / ✅ | ✅ / ✅ |
  | HelloRetryRequest to the ML-KEM hybrids | ⏭ | ✅ / ⏭ `gnutls-cli` always lists and shares the hybrids first |
  | mTLS, client certificate `{RSA-2048, P-256, P-384, Ed25519}` | ✅ / ✅ | ✅ / ✅ |
  | mTLS, ML-DSA-65 client certificate | ⏭ | ✅ / ✅ |
  | KeyUpdate (`update_requested`) from purecrypto, peer replies | ✅ / ✅ | ✅ / ✅ |
  | KeyUpdate (`update_requested`) from the peer, purecrypto replies | ✅ (`gnutls-cli` `^rekey^`) / ⏭ `gnutls-serv` has no trigger | same |
  | RFC 8879 zlib certificate compression (server certificate) | ⏭ the Ubuntu package is built without zlib | ✅ / ✅ |
  | RFC 7250 raw public key, server identity | ✅ / ✅ | ✅ / ✅ |
  | RFC 7250 raw public key, client identity | ✅ / ✅ (`gnutls-serv` requires but cannot pin a raw client key) | same |
  | OCSP stapling (`openssl ocsp` response, validated) | ✅ / ✅ | ✅ / ✅ |
  | ALPN | ✅ / ✅ | ✅ / ✅ |
  | RFC 8449 `record_size_limit` (512; both sides' records checked) | ✅ / ✅ | ✅ / ✅ |
  | Chain > 16 KiB (Certificate spans records) | ✅ / ✅ | ✅ / ✅ |
  | TLS 1.2 fallback (peer is 1.2-only) | ✅ / ✅ | ✅ / ✅ |
  | `close_notify` from the peer | ✅ / ✅ | ✅ / ✅ |

  The one GnuTLS limitation that is a protocol bug rather than a missing
  knob: 0-RTT across a HelloRetryRequest (GnuTLS issue #1429, open since
  2022 and still in 3.8.13). Its client, retried after offering early data,
  sends the second ClientHello *encrypted under the early traffic keys* with
  the `early_data` extension still present — RFC 8446 §4.1.2 requires a
  plaintext second ClientHello without it — so the purecrypto server skips
  it as rejected early data (§4.2.10) and the client waits forever. Its
  server decides to accept early data while parsing the first ClientHello,
  before it chooses to retry, and then treats the purecrypto client's
  plaintext second ClientHello as an early-data record it cannot decrypt
  (`bad_record_mac`). Both directions are SKIPped with that reason; the
  purecrypto side of the same case passes against OpenSSL. Two GnuTLS
  conventions are worth knowing when reading its logs: `record_size_limit`
  is advertised and enforced counting the inner content-type byte
  (`--recordsize 512` sends 513, and a received 512 caps records at 511
  bytes of data — both consistent with RFC 8449 §4 and with purecrypto's
  512 + 1), and a resumed session's description line names no group
  (`(TLS1.3-X.509)--(AES-128-GCM)`), so the adapter reads the verbose
  `Using curve:` line for it. One tool bug is worked around by version:
  `gnutls-serv` before 3.8.10 reads accepted early data and then discards
  it (`if (r == 0)` where the read returned the length; `>= 0` since
  3.8.10), so on 3.8.3 the 0-RTT case is verified from the record layer's
  log of the decrypted early-data record rather than from the echo.
- **wolfSSL 5.9.4, TLS 1.3, DTLS 1.2 and DTLS 1.3, both roles** (the same
  `interop.yml` job family; adapter `tools/interop/peers/wolfssl.sh`,
  driving wolfSSL's example `client` / `server` built from the pinned
  release tag with `--enable-dtls13` and the rest). The TLS 1.3 matrix is
  the one above; wolfSSL is also the **first peer purecrypto's DTLS 1.3
  has ever spoken to** — it had been loopback-only — and gets the DTLS
  matrix (`proto=dtls13` / `dtls12` in `tools/interop/run.sh`, over
  loopback UDP, `s_client -dtls1_3` / `s_server -dtls1_3`): the plain
  product, HelloRetryRequest per group, RFC 9147 §8 KeyUpdate with the
  epoch change from either side, ALPN, the > 16 KiB chain at the default
  and at a 512-byte MTU (dozens of fragments each way), a client
  certificate of every kind (on DTLS 1.3 the client's Certificate +
  CertificateVerify + Finished flight is multi-message and, with the
  ML-DSA-65 identity, several KiB across many records; on DTLS 1.2 the
  Certificate / CertificateVerify wrap the ClientKeyExchange), and a
  handshake through a relay dropping 20 % of the datagrams in each
  direction (ACK-driven retransmission on 1.3, whole flights on 1.2). 772
  cases; `C` / `S` as above, `⏭` a SKIP with the reason:

  | Case | TLS 1.3 (C / S) | DTLS 1.3 (C / S) | DTLS 1.2 (C / S) |
  |---|---|---|---|
  | Plain: `{RSA-2048, P-256, P-384, Ed25519, ML-DSA-65}` × `{x25519, P-256}` × three suites | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ (RSA, P-256 and P-384 certificates: the 1.2 engines sign with RSA or ECDSA only) |
  | Plain, `P-384` / `P-521` key exchange | ✅ / ⏭ the example client can share X25519, P-256 or a hybrid first, not P-384 or P-521 (the `hrr` case steers there) | ✅ / ⏭ same | ✅ (P-384 certificate; with another certificate ⏭ RFC 8422 §5.1.1: the wolfSSL 1.2 server uses its certificate's curve and requires it in `supported_groups`) / ✅ |
  | Plain, `X25519MLKEM768`, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` | ✅ / ✅ | ⏭ the stateless server validates the cookie on the first fragment, and a first ClientHello with a hybrid share (1216 to 1665 bytes) does not fit in one datagram (the `hrr` case carries it in CH2) / ✅ | ⏭ the 1.2 engines have no hybrid |
  | Resumption (PSK + DHE); 0-RTT accepted | ✅ / ✅ | ⏭ purecrypto's DTLS engines have no resumption | ⏭ |
  | Resumption, PSK-only (`psk_ke`) | ✅ / ✅ (`-K`) | — | — |
  | External PSK (RFC 8446 §4.2.11) | ✅ / ✅ (`-s`) | — | — |
  | 0-RTT rejected across a HelloRetryRequest | ⏭ the wolfSSL server deprotects the 0-RTT records it must skip under the early keys it derived, then refuses the plaintext second ClientHello / ⏭ the example client shares the resumed session's group, so no HRR can be forced | — | — |
  | HelloRetryRequest to every group (`x25519`, `P-256`, `P-384`, `P-521`, the three hybrids) | ✅ / ✅ | ✅ / ✅ (a hybrid arrives in a fragmented CH2 with the cookie first) | — (no HRR in 1.2) |
  | mTLS, client certificate of every kind | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ (RSA, P-256, P-384: the 1.2 engines sign with RSA or ECDSA only; C with P-384 ⏭ RFC 8422 §5.1.1 as in the plain case) |
  | KeyUpdate from purecrypto, peer replies | ✅ / ✅ | ✅ / ✅ | — |
  | KeyUpdate from the peer, purecrypto replies | ✅ / ✅ | ✅ / ✅ (the example client's `-I` writes a message it never reads back, and `wolfSSL_shutdown` sends no close_notify while that echo is pending, so the peer's close_notify is not demanded in that one case) | — |
  | RFC 8879 certificate compression; RFC 8449 `record_size_limit` | ⏭ not implemented by wolfSSL | — | — |
  | RFC 7250 raw public key, server identity | ⏭ the example server has no RPK option / ✅ | — | — |
  | RFC 7250 raw public key, client identity | ⏭ the client's `--rpk` offers raw keys for both directions with no X.509 fallback | — | — |
  | OCSP stapling | ⏭ the example server staples only what it fetched from a responder; the client insists on the nonce it requested, which a pre-generated staple lacks | — | — |
  | ALPN | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
  | Chain > 16 KiB | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |
  | Chain > 16 KiB at a 512-byte MTU | — | ✅ / ✅ | ✅ / ✅ |
  | Handshake over a path dropping 20 % of datagrams | — | ✅ / ✅ (large chain) | ✅ / ✅ |
  | The last flight of the handshake lost (`loss-final`) | — | ✅ / ✅ (large chain) | ✅ / ✅ |
  | RFC 9146 connection IDs (`--cid` on the example tools; each side receives under its own CID, both report the other's) | — | ✅ / ✅ (RFC 9147 §9 unified-header C bit) | ✅ / ✅ (`tls12_cid` records, the §5.3 additional data) |
  | TLS 1.2 fallback (peer is 1.2-only) | ✅ / ✅ | — | — |
  | `close_notify` from the peer | ✅ / ✅ | ✅ / ✅ | ✅ / ✅ |

  Four bugs fell to this peer, all invisible to loopback because both
  purecrypto ends made the same mistake: **every HKDF-Expand-Label in
  DTLS 1.3 used the `"tls13 "` prefix where RFC 9147 §5.9 requires
  `"dtls13"`** — the handshake keys of the two implementations never
  matched (pinned by wolfSSL's records and exported secrets as a unit
  test); the DTLS 1.2 HelloVerifyRequest cookie was 38 bytes, which
  wolfSSL's client (still at the 32-byte bound of RFC 4347) silently
  drops, so the exchange looped — it is now 32 bytes; the DTLS 1.3
  client put the `cookie` extension last in its second ClientHello,
  behind the multi-KB hybrid `key_share`, and wolfSSL's stateless server
  only looks for it in the first fragment — it goes first now; and the
  (D)TLS 1.2 engines verified ECDSA signatures through the TLS 1.3
  curve-pinned schemes, refusing wolfSSL's `(sha256, ecdsa)` under a
  P-384 key, which RFC 5246 §7.4.1.4.1 allows. On the way the DTLS
  engines gained what the matrix needs to be verifiable at all:
  `close_notify` in both directions, KeyUpdate and the negotiated group /
  HelloRetryRequest / KeyUpdate accessors through `Connection`, and
  `key_exchange_groups` / `key_shares` (the DTLS 1.3 client used to share
  every group, the servers to select from a fixed order).

  A fifth showed up as a flake of the lossy case (5 of 30 relay seeds against
  the wolfSSL server: `SSL_accept error 6, peer sent close notify
  alert`), and was the driver's, not the engines': **the side that
  finishes the handshake first stopped caring whether the other side
  finished at all**. The relay's packet trace (`LOSSY_TRACE=1`; times in
  ms, `e2` the handshake epoch, `e3` the application one):

  ```text
   9328 drop c->s #25 (66 bytes) enc/e2/61     the client's Finished: lost
   9328 pass c->s #27 (39 bytes) enc/e3/34     its application data (discarded: the server is in its handshake)
  11344 pass c->s #28 (24 bytes) enc/e3/19     close_notify, 2 s of silence later -> SSL_accept fails
  12352 pass c->s #29 (66 bytes) enc/e2/61     the Finished again: 3 s late, and too late
  ```

  The DTLS 1.3 client engine did keep its Finished in the retransmission
  set until the server's ACK (RFC 9147 §5.8.1, §7), but `s_client`
  restarted the clock it drives the engine with at the end of the
  handshake, so a timer armed at "3 s" on the handshake's clock fired 3 s
  into the data phase instead of 1 s after the Finished; and nothing told
  it that a flight was still unacknowledged, so after `-read_timeout` of
  silence it sent its close_notify. The mirror image failed the wolfSSL
  client (`wolfSSL_connect error 6, peer sent close notify alert`):
  `s_server`'s ACK for the client's Finished was lost, and its idle
  close_notify went out between two retransmissions of that Finished.
  `Connection::handshake_flight_pending` now says that the peer may still
  be in its handshake and `Connection::set_now` gives the engine the time
  its timers are armed from; a DTLS 1.3 client holds a close_notify back
  until its Finished is acknowledged, the servers send their final flight
  (DTLS 1.2) or final ACK (DTLS 1.3) once more ahead of an early
  close_notify, and the two commands drive the connection until the
  handshake is over on both sides. The `loss-final` cases lose exactly
  those datagrams, deterministically.
- **quic-go and OpenSSL, QUIC v1 + v2** (CI job `interop-quic.yml`, script
  `tools/quic-interop/run.sh`): the purecrypto CLI (`q_client` /
  `q_server`) against a small quic-go client and server
  (`tools/quic-interop/quicgo`, quic-go pinned in its `go.mod`) in **both
  roles**, and against `openssl s_client -quic` (OpenSSL built from source
  at a pinned tag). Every case checks the outcome from both sides' logs —
  negotiated ALPN and suite, resumption / 0-RTT / Retry flags, key phase,
  byte counts and SHA-256 of the data each side received, close reason —
  and, for what the quic-go application cannot see, its qlog trace.

  | Case | purecrypto client → quic-go server | quic-go client → purecrypto server | OpenSSL client → purecrypto server |
  |---|---|---|---|
  | Handshake + bidirectional stream echo (ALPN, suite checked both sides) | ✅ | ✅ | ✅ |
  | Unidirectional streams (client uni → server uni reply) | ✅ | ✅ | — (no s_client mode) |
  | 8 MiB echo (flow control; quic-go's own key update and CID rotation followed) | ✅ | ✅ | ✅ (8 MiB upload) |
  | 8 MiB echo with 1-in-50 datagram loss each way (RFC 9002 recovery) | ✅ | ✅ | — |
  | Retry / address validation (RFC 9000 §8.1.2) | ✅ (`retry=yes`, quic-go `addr_verified=true`) | ✅ (quic-go qlog shows the Retry) | ✅ |
  | Session resumption (PSK) | ✅ | ✅ | ✅ (`-sess_in`, `Reused`) |
  | 0-RTT accepted (RFC 9001 §4.6) | ✅ (`early_data=accepted`, quic-go `used0rtt=true`) | ✅ | — (OpenSSL's QUIC client has no 0-RTT) |
  | purecrypto-initiated key update (RFC 9001 §6) | ✅ (quic-go qlog `remote_update`, phase 1) | ✅ | ✅ |
  | TLS_CHACHA20_POLY1305_SHA256 / TLS_AES_256_GCM_SHA384 | ✅ / ✅ | skipped: neither side can pin the suite (Go's crypto/tls does not restrict TLS 1.3 suites; `cipher_suites` is a client knob) | ✅ / ✅ |
  | CONNECTION_CLOSE with application error code + reason | ✅ | ✅ | — |
  | Idle timeout (RFC 9000 §10.1), both sides report it | ✅ | ✅ | — |
  | DATAGRAM frames (RFC 9221), four each way | ✅ | ✅ | — |
  | Client migration to a new socket (§9; path validation both ways) | ✅ | ✅ | — |
  | Connection-ID switch + RETIRE_CONNECTION_ID (§5.1.2) | ✅ | ✅ | — |
  | Plain QUIC v2 (RFC 9369; both sides settle on v2) | ✅ (`version=v2`, quic-go `version=6b3343cf`) | ✅ | — (OpenSSL's QUIC client is v1-only) |
  | Incompatible version negotiation (peer v1-only → VN → restart on v1, RFC 9000 §6 / RFC 9368 §2.1) | ✅ (client offers v2 first, restarts on v1) | ✅ (`version negotiation sent`, quic-go opens a second trace) | — |
  | Retry (RFC 9000 §8.1.2) under v2 (v2 Retry integrity tag, RFC 9369 §3.3.3; version-bound token) | ✅ (`retry=yes version=v2`) | — | — |
  | Resumption + 0-RTT under v2 (RFC 9369 §5 version-bound ticket) | ✅ (`version=v2 resumed=yes`, 0-RTT accepted) | — | — |
  | Key update under v2 (RFC 9369 §3.3.2 `quicv2 ku`) | skipped vs quic-go: quic-go v0.63 derives the update secret with the v1 `quic ku` label regardless of version (`internal/handshake/updatable_aead.go`), so it cannot decrypt a conformant v2 update; covered pc↔pc (loopback test + RFC 9369 §A.5 `quicv2 ku` vector + the ct_valgrind v2 arm) | — | — |
  | Stateless reset (§10.3; server restarted with the same reset key) | ✅ | ✅ | — |
  | ECN validation (§13.4; both sides report the path capable) | ✅ (Linux) | ✅ (Linux) | — |
  | X25519MLKEM768 key exchange | ✅ | ✅ | ✅ |
  | `SecP256r1MLKEM768`, `SecP384r1MLKEM1024` (RFC 10024), `P-521`: pinned on both sides (`-groups` / quic-go `-curves`), the 1665-byte shares in two Initials each way | ✅ | ✅ | ✅ |
  | HelloRetryRequest over QUIC: the purecrypto server pinned to a group the client only advertised (each of the three above; OpenSSL: `SecP384r1MLKEM1024`) | — | ✅ (`hrr=yes`) | ✅ |

  Two engine bugs that loopback had hidden fell to this matrix on its first
  run, both in the server: a PATH_CHALLENGE arriving from an address the
  peer was only *probing* (RFC 9000 §9.1 — what quic-go always does before
  migrating) was dropped as unanswerable instead of being answered on that
  path (§8.2.2), so the client never migrated; and a key update initiated
  in the same flight as HANDSHAKE_DONE reached the client before it had
  confirmed the handshake, which OpenSSL treats as KEY_UPDATE_ERROR — the
  server now waits for the HANDSHAKE_DONE packet to be acknowledged. The
  first master run then caught a third with the lossy upload: a packet
  carrying MAX_STREAM_DATA was dropped and nothing ever sent the credit
  again (loss recovery only knew about CRYPTO, STREAM and HANDSHAKE_DONE),
  so the quic-go client — which had already reported STREAM_DATA_BLOCKED
  once, as RFC 9000 §13.3 allows — waited forever. Every stream-layer
  control frame a lost packet carried (MAX_DATA, MAX_STREAM_DATA,
  MAX_STREAMS, the `*_BLOCKED` frames, RESET_STREAM, STOP_SENDING) is now
  sent again as §13.3 requires. All three have unit tests. OpenSSL covers
  the client direction only: `s_server`
  has no QUIC mode and the server-side API has no command-line front end.
  (DTLS 1.3 has its own peer above: wolfSSL.)
- **BoringSSL, TLS 1.3 Encrypted Client Hello** (RFC 9849, CI job
  `interop-boringssl.yml`, script `tools/ech-interop/run.sh`): the purecrypto
  CLI against `bssl` at a pinned commit, over TCP, in **both roles**, each
  side running on keys the other tool generated:

  | Case | purecrypto client → bssl server | bssl client → purecrypto server |
  |---|---|---|
  | ECH accepted, inner SNI at the server, data both ways | ✅ | ✅ |
  | HelloRetryRequest (key-share mismatch) + ECH HRR confirmation | ✅ | ✅ |
  | Stale config → rejected, outer `public_name` authenticated, `retry_configs` | ✅ (configs byte-equal the server's; a retry with them is accepted) | ✅ (bssl reports `ECH_REJECTED`) |
  | Rejection across a HelloRetryRequest | ✅ | ✅ |
  | GREASE ECH (server with and without ECH keys) | ✅ | ✅ |

  A one-off check against Cloudflare's production deployment
  (`crypto.cloudflare.com`, config from its DNS HTTPS record) is accepted
  (`sni=encrypted`), and a corrupted config is rejected with `retry_configs`
  equal to the published list. That check needs the network and is not in CI.
- **Loopback** (own client ↔ own server, all platforms): TLS 1.2/1.3, DTLS
  1.2/1.3, QUIC v1 and v2 (including RFC 9368 compatible and incompatible
  version negotiation).

## Fuzzing

33 `cargo-fuzz` (libFuzzer) targets under `fuzz/fuzz_targets/`, run in CI
(`.github/workflows/fuzz.yml`). They concentrate on the untrusted-input
attack surface — parsers and protocol feeders:

- **Encoding/parsers**: `der_reader`, `pem_decode`, `spki_pubkey`,
  `pkcs8_{rsa,ed25519,mldsa,slhdsa}`, `mlkem_pkcs8`, `ecdsa_sig_der`,
  `lms_parse`, `xmss_parse`, `dh_share`, `pbes2_decrypt`, `pkcs12_parse`.
- **Signature decoders (through verify)**: `falcon_verify` (key + Golomb-Rice
  `s2` decoders), `mldsa_verify` (`z` / hint unpacking), `slhdsa_verify`.
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
  blinder; PKCS#1 v1.5 / OAEP decoding fuses every padding check into one
  verdict and moves the recovered message with a barrel shifter rather than a
  secret-offset slice. Key generation is shaped independently of the primes
  it produces: `d = e⁻¹ mod φ(n)` comes from a fixed-trip-count binary
  extended GCD (`bignum::inv_mod_ct`), trial division uses a
  multiply-by-reciprocal instead of a division instruction, and each
  Miller-Rabin round runs a fixed number of squarings. Only the *number* of
  rejected candidates is observable.
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

### Machine-code validation (Valgrind memcheck)

Source-level discipline is necessary but not sufficient: LLVM is free to turn
a mask into a branch, unswitch a loop on a secret-derived invariant, or lower
a `||` into a jump on the second operand. `tests/ct_valgrind.rs`, run by
`.github/workflows/ct-valgrind.yml` on every push to `master` and every pull
request, checks the **optimized release binary** (opt-level 3, thin LTO, the
profile users ship) across the code-generation variants where different
machine code hides:

| Matrix entry | Target | What differs |
|---|---|---|
| `x86_64` | `x86_64-unknown-linux-gnu` on `ubuntu-latest` | the CPU dispatch memcheck's emulated CPU allows: AES-NI, PCLMULQDQ, AVX2 (Valgrind hides AVX-512 and SHA-NI) |
| `x86_64, portable` | same | every dispatch site forced onto its portable kernel (`PURECRYPTO_CT_FORCE_PORTABLE=1`): table-free AES, the branchless GHASH multiply, scalar ChaCha20 / Poly1305 / BLAKE3 / Keccak / SHA |
| `x86_64, table-free` | same, `--no-default-features` minus `ed25519-table` / `p256-table` | the constant-time windowed ladders for `[k]B` / `[k]G` and interleaved double-scalar verification instead of the precomputed comb tables |
| `aarch64`, `aarch64, portable`, `aarch64, table-free` | `aarch64-unknown-linux-gnu` on `ubuntu-24.04-arm` | as above with the Arm extensions (AES, PMULL, SHA-2, SHA-512) |
| `i686` | `i686-unknown-linux-gnu` under the amd64 Valgrind's x86 tool | 32-bit `usize` and limbs: 64-bit multiplies and shifts become multi-instruction sequences, 64-bit divisions library calls; no hardware backends are compiled for it, so this is the portable code throughout |
| `armv7` | `armv7-unknown-linux-gnueabihf` under `valgrind:armhf`, in AArch32 mode on the Neoverse-N2 runner | the 32-bit Arm lowering of the same |

Every entry runs the positive control, then the full case list.

- Every secret input is marked *undefined* through a Valgrind client
  request — an inline-asm magic sequence behind the hidden `__ct-check`
  feature (`src/ct/valgrind.rs`, transcribed from `valgrind.h` for the four
  platforms; no C header, no dependency) — and memcheck then reports any
  **conditional branch** or **memory address** computed from it,
  bit-precisely, anywhere in the call tree. Secrets enter as classified
  key/seed/plaintext/traffic-secret bytes, through a `TaintRng` whose every
  output byte is secret (so key generation, nonces, blinding and hedging
  are checked as they run on `OsRng`), or as the classified secret parts of
  an imported key (RSA limbs, a JWK's private fields, a Falcon key's
  expanded buffers). Public results (ciphertexts, tags, signatures, public
  keys, shared secrets) are marked *defined* again before the harness
  compares them; the library-side counterparts are the
  [declassification points](#declassification-points) below.
- The protocol record layers and key schedules are reached through
  `ct::hooks`, `__ct-check`-only entry points into the crate-private code
  (`src/ct/hooks.rs`): a full handshake would drag public values (randoms,
  transcript, certificates) through the same paths as the secrets. The
  hooks call the same functions the engines call; the receive-side glue
  they add (sequence-number / header-protection removal, AAD
  reconstruction, packet-number decoding) mirrors the engines' receive
  paths step for step.
- A **positive control** (a deliberate secret branch and a secret table
  index) must be flagged in the same run, so a green result cannot come
  from broken instrumentation; the harness also refuses to run outside
  Valgrind when `CT_REQUIRE_VALGRIND=1`, and CI checks that each variant
  really is the one under test (`cpu dispatch: forced portable`, `tables:
  none`). Under `cargo test --all-features` the client requests are no-ops
  and the same binary is a plain smoke test.
- **Covered** (one fixed-seed instance each, 103 cases): the `ct`
  primitives; AES-128/192/256, Camellia, ARIA, SM4 and SEED block
  encryption; AES-GCM, AES-GCM-SIV, AES-CCM, AES-EAX, ChaCha20-Poly1305,
  XChaCha20-Poly1305, AEGIS-128L, AEGIS-128, MORUS-640/1280, Ascon-AEAD128,
  Ascon-128/128a, SEED-GCM (seal, open, and open with a forged tag);
  AES-CBC/CTR/CFB/OFB, AES-XTS (with ciphertext stealing), AES-KW and KWP
  (wrap, unwrap, corrupted unwrap), AES-SIV, AEZ, C2SP chunked encryption;
  AES-CMAC, GMAC, UMAC-64/128, VMAC-64/128, Poly1305, KMAC128, SipHash-2-4,
  HMAC-SHA-256/512 (`mac` and `verify`, good and bad); HKDF, PBKDF2,
  KBKDF, Argon2i, HMAC-DRBG (generate, reseed), PBES2 AES-256-GCM
  `decrypt_authenticated` (right and wrong password); SHA-2, SHA-3, SHAKE,
  BLAKE2b, BLAKE3, SM3 over secret input; **TLS 1.3** key schedule (with
  and without PSK, exporter, resumption), Finished MAC + verify (good and
  bad), record protection for all three suites (seal, open, open of a
  padded record, forged record), `KeyUpdate` derivation; **TLS 1.2** PRF
  (master secret, extended master secret, key block), Finished verify and
  AEAD records; **DTLS 1.2** records, and records carrying a connection ID
  (RFC 9146 §5.3 additional data, `DTLSInnerPlaintext` type and padding
  stripped by the constant-time scan; all three suites, forged record,
  wrong CID); **DTLS 1.3** records with sequence-number encryption (all
  three suites, forged record), and with a connection ID in the unified
  header (parsed with the receiver's CID length; the C bit refused when
  none is negotiated); **QUIC**
  1-RTT packet protection with header protection (all three suites, forged
  packet) and the key-update derivation; X25519, X448, Ed25519, Ed448,
  P-256 ECDSA sign / ECDH / keygen, P-384, P-521 and brainpoolP256r1 ECDSA
  sign / ECDH (boxed path), secp256k1 ECDSA sign and ECDH, BIP340 Schnorr
  sign, ristretto255 scalar multiplication, SM2 sign and encrypt / decrypt
  (tampered ciphertext), DSA-2048 sign, FFDH group14, HPKE (X25519 and
  P-256 KEMs, seal + open + forged ciphertext), BLS12-381 signing; the
  `zkp` modules — sign-to-contract, adaptor encrypt / decrypt / recover,
  Pedersen commit + an 8-bit range proof, a 3-input surjection proof and a
  3-key whitelist proof, the ring position classified as secret in the last
  two; RSA-2048 key generation, PSS and SHAKE-PSS sign, OAEP decrypt,
  PKCS#1 v1.5 decrypt in its explicit-error, fixed-length (`_session`) and
  implicit-rejection forms — each with a valid and a tampered ciphertext —
  and a three-prime key (PSS sign, OAEP decrypt); JOSE JWE decrypt
  (`dir`, `A256KW`, `ECDH-ES+A256KW`, `RSA-OAEP-256`) and JWS sign
  (`HS256`, `ES256`, `EdDSA`); ML-KEM-512/768/1024 keygen and
  decapsulation (768 also encapsulation and a tampered ciphertext);
  ML-DSA-44/65/87 keygen and deterministic signing (65 also hedged);
  SLH-DSA-SHA2-128f, SHAKE-128f and SHA2-128s keygen + sign; Falcon-512
  signing (the key generated on public randomness, then its expanded
  buffers classified); LMS (H5) keygen + sign, HSS (two H5 levels), XMSS
  (SHA2_10_256) and XMSS^MT (SHA2_20/2_256) keygen + sign.
- **Not covered**: everything not in that list (notably the TLS/DTLS/QUIC
  handshake state machines above the record layer, the `halfagg` module,
  which has no secret input, and the hazmat surfaces); code paths a single
  fixed input does not reach; **variable-latency instructions** (memcheck
  flags branches and addresses, not a division or multiply whose timing
  depends on its operands); other compilers, LLVM versions, targets and
  optimization levels than the CI's; and every microarchitectural channel
  (cache, port contention, speculation, power) — the harness shows the
  *machine code* is data-oblivious, not that the *CPU* is.
- The documented variable-time residuals below are deliberately not in the
  harness (they would be flagged, correctly); nothing is suppressed.
  Beyond the list below that also excludes FF1 (its radix arithmetic on the
  digits is data-dependent by construction), the table-driven hashes
  (Streebog, Whirlpool, MD2 — documented at the code site) and PKCS#12
  (its archives are PBES2 CBC-PAD envelopes).

The first run found and fixed four cases where LLVM had undone
source-level constant-time code: the barrel shifter that moves a decrypted
RSA message to the front of its block (`ct_shift_left`) was loop-unswitched
into a branch on each secret shift bit; the masked merge of the synthetic
plaintext in `decrypt_pkcs1v15_implicit` was unswitched into a branch on the
padding verdict — the Bleichenbacher oracle it exists to remove; the
`pos < len || byte == 0` width assertion in `BoxedUint::to_be_bytes` was
lowered to a branch on every byte of a private-operation result; and the
masked conditional subtraction in the BLS12-381 field arithmetic
(`bls::mont::reduce_once` / `neg`) was lowered to a branch on the secret
carry. Each is now pinned by an optimization barrier and by this harness.
Two source-level issues went with them: the early-exit range check of a
decoded ML-DSA secret vector, and RSA key generation branching (and
selecting a pointer) on which prime is larger. The second pass (protocol
record layers, the remaining signature schemes and symmetric modes, the
code-generation variants) found one more: the DTLS 1.3 record layer
stripped the inner-plaintext padding with a backward `rposition` scan —
time proportional to the padding, the very leak the TLS 1.3 record layer's
constant-time scan exists to prevent — and now shares that scan.

#### Declassification points

memcheck cannot know that a value computed from a secret is public by
specification, so the library marks such values *defined* at the point they
become public (`ct::declassify`; a no-op outside the harness). Every site
says why, and this is the complete list — anything outside it that branches
on a secret is a bug:

- **Verification verdicts**: an AEAD / MAC / key-wrap / AEZ / UMAC / VMAC
  tag comparison, the C2SP chunked-encryption commitment, an RSA OAEP or
  PKCS#1 v1.5 padding verdict (the explicit-error API, whose
  Bleichenbacher caveat is documented), the RSA fault-check result, the
  X25519 / X448 all-zero output check, ECDSA's degenerate `r = 0` /
  `s = 0`, the DH contributory-failure check, the ML-DSA secret-vector
  range check, the SM2 `C3` hash and all-zero key-stream checks, the
  AES-XTS `k1 == k2` check, the JOSE HS-family MAC verdict, a
  secp256k1 scalar's range and zero checks (`Scalar::from_bytes_be`, the
  BIP340 / sign-to-contract / adaptor / whitelist key checks), the DSA
  `x` / `k` range check, the `zkp` consistency checks (an opening matches
  its commitment, a ring key matches its secret, an index is in range) —
  all returned to the caller as `Ok`/`Err`. The TLS 1.3 / DTLS 1.3
  "inner plaintext is all zero" verdict (a protocol violation answered with
  an alert) belongs here too.
- **Rejection-sampling and retry decisions**: RFC 6979 / FIPS 186-5 scalar
  and nonce candidates (ECDSA, DSA, sign-to-contract), SM2 nonce retries,
  the ML-DSA signing loop, ML-DSA `RejBoundedPoly` (ExpandS), every RSA
  key-generation decision (a composite candidate, `p = q`, `|p − q|` too
  small, `e` not invertible, the rare `2^64 | p − 1` Miller-Rabin tail),
  the Falcon signature norm bound, the Falcon sampler's loop controls (see
  the residual below), the VMAC L3 key-derivation window (a candidate is
  rejected with probability 2⁻⁵⁶, whatever the key), and the range-proof
  exponent search (the accepted parameters are the proof header). Only the
  count is observable.
- **Public outputs the library itself branches on before returning them**:
  the ML-KEM and ML-DSA matrix seed `ρ`; the ML-DSA challenge `c̃`
  (SampleInBall) and, once accepted, `z` and the hint; every SLH-DSA
  signature component as it is written (the tree, leaf, FORS and WOTS+
  indices are functions of the signature and public key); the XMSS
  randomizer `R`, the message digest it seeds and each subtree root (the
  base-w digits of these set the public WOTS+ chain lengths); the HSS child
  public key and deterministic LM-OTS randomizer `C` (both published in the
  signature); an accepted Falcon `s₂` before compression; the DSA `r` and
  `s`; the BIP340 public key and signature before the signer's own
  fault-check verification; the sign-to-contract low-S flag (published in
  the opening); the RSA plaintext *length*; the AES-KWP plaintext length
  once the wrap has authenticated; the boxed-curve public keys and
  signatures (their encoders size them by bit length); the modulus of a
  generated RSA key; a JWS signature or MAC before base64url encoding; the
  TLS 1.3 / DTLS 1.3 true content type and content length recovered from a
  record (the engine dispatches on the type and every later step is shaped
  by the length — what the constant-time scan protects is the time taken to
  *find* them under the padding); the DTLS 1.3 ciphertext before its
  sequence-number mask is computed from it, and the unmasked sequence
  number; the QUIC first byte and packet number after header-protection
  removal (RFC 9001 hides them from on-path observers only; the receiver
  needs them to parse the packet and pick its keys and nonce).
- **Structural facts about a secret modulus**: whether it is zero or even
  (a panic), its limb width (`significant_limbs`, as in BoringSSL: an RSA
  prime's size is fixed by the modulus size), whether an imported key's
  primes are present, distinct and usable (it selects the CRT or
  full-width path), the identity check of an affine conversion on a
  prime-order curve (`[k]P` is the identity iff `k ≡ 0 mod n` or `P` is),
  and whether a DSA `k` has an inverse mod the (prime) `q`.

### Known constant-time residuals

What the 2026-09 review left in place, each deliberate and documented at the
code site:

- **Legacy CBC (`tls-legacy`)**: the Lucky13 mitigation equalises the
  compression-block count but not the per-call overhead of the padding
  hashes, and SSL 3.0 skips the equaliser entirely (POODLE makes SSL 3.0
  unfixable regardless). Off by default.
- **DES/3DES and Blowfish (bcrypt)** use S-box tables indexed by key-derived
  data — inherent to those designs, kept for legacy interop and
  `bcrypt_pbkdf` compatibility (the AES/ARIA/Camellia/SM4 cores are
  table-free).
- **Falcon key generation and secret-key import** run the NTRU solver on
  variable-time big integers, as the module documents; signing and
  verification are data-oblivious. Signing's Gaussian sampler follows the
  reference: the number of SamplerZ iterations is independent of the
  centre and standard deviation (the isochronous design of Howe, Prest,
  Ricosset and Rossi, which is what the `σ_min / σ'` scaling is for) and
  BerExp reads one more random byte exactly when a fresh uniform byte
  equals the threshold byte (probability 1/256 whatever the threshold), so
  the harness declassifies those two loop controls; the sampled values
  themselves stay secret.
- **Key serialization formats** (PKCS#8 / PKCS#1 DER, JWK) encode private
  integers minimally, so an encoding's length is the component's bit
  length; the harness classifies a JWK's private fields after
  construction and checks the operations run on them.
- **Argon2d/id data-dependent addressing and scrypt's `Integerify`** are the
  algorithms' design.
- **PBES2 CBC-PAD envelopes** carry no integrity tag, so "padding valid"
  is observable by construction; `decrypt_authenticated` refuses them.
- **Rejection-sampling loop counts** (ML-DSA signing, ECDSA nonce, ML-DSA
  challenge, surjection-proof subset draws) are public per specification;
  the work inside each attempt is constant-shaped. The ML-DSA challenge
  `c̃` of a *rejected* attempt drives SampleInBall's data-dependent loop and
  is therefore exposed (declassified) too; `y` and `z` of that attempt are
  not.
- **RSA key generation** reveals the rejected-candidate count and, with
  probability 2⁻⁶⁴ per candidate, that `2⁶⁴` divides `p − 1` (the
  Miller-Rabin tail past the fixed 64 squarings).
- **Public-exponent RSA / secp256k1 field exponentiation** select on a
  public exponent bit; the secret base never drives a branch.
- **`debug_assert!`s on secret-derived bits** (e.g. in `Choice::from`) exist
  only in debug builds.

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
- **Phased interop**: TLS 1.2 and DTLS 1.2 are validated against OpenSSL,
  wolfSSL and Mbed TLS in both roles, DTLS 1.3 against wolfSSL in both
  roles (one peer so far — OpenSSL exposes no `-dtls1_3` client), RFC 9146
  connection IDs against wolfSSL (DTLS 1.2 and 1.3) and Mbed TLS (DTLS
  1.2), and QUIC v1 + v2 (RFC 9369) with RFC 9368 version negotiation
  against quic-go in both roles, plus QUIC v1 against OpenSSL's (v1-only)
  QUIC client. QUIC ships without HTTP/3.
- **Hazmat**: the `hazmat-*` features expose low-level arithmetic with **no
  semver and no constant-time guarantee** — the caller owns correctness and CT.
- **Scope**: the crate is primitives + TLS/PKI plumbing (OpenSSL-like). Threshold
  / multi-party / message-envelope layers are out of scope.
- **Coverage gaps**: ML-KEM ACVP is a trimmed slice (not the full corpus);
  DTLS 1.3 has a single external peer (wolfSSL), and its resumption and
  0-RTT are not implemented at all; the
  RFC 9146 §6 peer-address update is exercised end to end by the CLI's own
  client and server only (no peer tool moves its socket mid-connection),
  and the return-routability check of draft-ietf-tls-dtls-rrc is not
  implemented (no peer in the matrix speaks it; the application's
  obligation is documented on `Connection::datagram_allows_peer_address_update`);
  RFC 9368 compatible version negotiation (the v1 → v2 upgrade without a
  round trip) is exercised by purecrypto against itself only, since
  quic-go v0.63 does not send `version_information`;
  no NIST FIPS validation (CMVP) and no third-party audit.

---

*This document describes the state of the test suite and code as of the current
revision; verify against the source where it matters.*
