# Threat model

The boundaries below — especially what is *out of scope* — are security
commitments of the project. See [`validation.md`](validation.md) for the
concrete coverage map and [`recommended-usage.md`](recommended-usage.md) for the
safe subset of the API.

## What this crate protects

`purecrypto` provides cryptographic primitives and the TLS/PKI plumbing built on
them. The assets it is designed to protect are the usual ones:

- **Confidentiality** of plaintext under AEAD / public-key encryption / KEM.
- **Integrity & authenticity** of messages (MAC/AEAD), signatures, and
  certificate chains.
- **Secrecy of private keys and derived shared secrets**, including against
  *timing* observation of secret-dependent computation.

## Adversary model — in scope

The implementations are built to withstand:

- **Adaptive chosen-ciphertext / chosen-message** attackers at the algorithm
  level (e.g. AEAD forgery resistance, signature unforgeability, KEM IND-CCA via
  Fujisaki–Okamoto + implicit rejection).
- **Malformed / hostile input** to parsers and protocol state machines
  (DER/PEM/PKCS#8/SPKI/X.509/TLS/DTLS/QUIC): the goal is graceful rejection, no
  panics, no memory unsafety — exercised by the `cargo-fuzz` targets listed
  in `docs/validation.md`.
- **Timing side channels from secret-dependent code paths**, to the extent
  achievable at the Rust source level: branchless `ct` primitives,
  all-limbs-unconditional `bignum`, blinded RSA, constant-time curve scalar
  multiplication, constant-time MAC/tag comparison, uniform decryption errors
  (PKCS#12, TLS), and implicit-rejection KEM decapsulation.
- **Padding-oracle classes** on the supported modern paths (OAEP, AEAD); the
  known oracle-prone legacy paths are flagged and off by default.

## Out of scope / explicitly NOT defended against

- **Physical / microarchitectural side channels beyond data-independence**:
  power analysis, EM, fault injection, Spectre/Meltdown-class speculation,
  cache/port contention from a co-resident attacker. Constant-time here means
  "no secret-dependent branches or memory addresses". That property is
  checked on the *compiled* release binary with Valgrind memcheck as a taint
  tracker, on x86_64 and aarch64 Linux, for the primitives listed in
  [`validation.md`](validation.md#machine-code-validation-valgrind-memcheck)
  — not for every path, not on other compilers or targets, and not for
  variable-latency instructions (division, some multipliers) or anything the
  CPU does with data-oblivious code. No statistical timing measurement has
  been made.
- **A compromised or weak RNG.** Security assumes `OsRng` (or a properly seeded
  CSPRNG) actually provides unpredictable bytes. Bad entropy breaks key
  generation, signing nonces, and KEM/ECDH.
- **Misuse of stateful keys.** Reusing an LMS/XMSS one-time index is
  catastrophic; the crate guards against in-process reuse but cannot prevent a
  caller from restoring an old key-state file.
- **Caller-side key management**: secure storage, zeroization of bytes the caller
  copies out (`to_bytes`, `Secret::into_bytes`), access control, and key
  lifecycle are the caller's responsibility.
- **The `hazmat-*` features**: no semver and no constant-time guarantee — the
  caller owns correctness and CT discipline.
- **Legacy / compatibility paths** (`tls-legacy`, PKCS#1 v1.5 encryption, SHA-1
  signing, DES/3DES, …): provided for interop, with documented residual
  weaknesses (Lucky13/POODLE/Bleichenbacher/collisions). Not part of the safe
  model.
- **Supply-chain / build integrity**, FIPS/CMVP validation, and protocol-level
  concerns outside the implemented RFCs.

## Trust assumptions

- The operating system's entropy source (`/dev/urandom` / `getrandom(2)` /
  `arc4random` / `ProcessPrng`) is sound.
- The Rust toolchain and `core`/`alloc` are trusted; the only non-first-party
  runtime dependency is `compcol` (RFC 8879 cert compression, sibling project,
  outside the crypto trust boundary).
- Callers persist stateful-signer key state correctly and do not reuse it.
- Certificate validity is only as good as the clock the verifier is given.
  The chain verifier takes the validation time as an `Option`: `None` skips
  every validity check — certificate `notBefore` / `notAfter` and CRL
  `thisUpdate` / `nextUpdate` — so an expired or not-yet-valid certificate
  verifies. That form is only for callers that have already checked time
  themselves or knowingly accept the risk. Under `std` the TLS engines supply
  the system clock; without `std` there is no clock, and expiry can only be
  enforced if the caller sets `Config::verification_time`.

## Residual risk

No third-party human audit and no CMVP. Constant-time behaviour of the main
secret-handling paths is machine-checked (Valgrind taint tracking on two
architectures) but not measured on hardware. The DTLS 1.2 and
QUIC v1 **server** directions interop with OpenSSL 3.5, but the client directions
and DTLS 1.3 are loopback-validated only. TLS 1.3 Encrypted Client Hello
(RFC 9849) interops with BoringSSL in both roles, including HelloRetryRequest,
rejection with `retry_configs`, and GREASE (CI); ECH over QUIC has no external
peer yet. See [`validation.md`](validation.md)
for the concrete coverage map and [`recommended-usage.md`](recommended-usage.md)
for the safe subset.
