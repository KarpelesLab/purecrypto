# Security policy

## Reporting a vulnerability

Please report security issues **privately**, not via public issues or pull
requests.

- Preferred: GitHub **private vulnerability reporting** — open the repository's
  **Security** tab → **Report a vulnerability**. This opens a private advisory
  visible only to the maintainers.

Please include enough to reproduce (affected version/commit, feature flags, and
a minimal test case or input). We aim to acknowledge reports promptly and will
coordinate disclosure with you.

## Supported versions

`purecrypto` is pre-1.0 (`0.x`). Security fixes are released against the
**latest published version** only; please upgrade to the latest `0.x` release
to receive them.

## Status & assurance

This crate has **not** had a third-party human security audit, and is **not**
FIPS/CMVP validated. Whole-codebase **automated** security audits have been run
with Claude Fable 5 — meaningful (Fable 5 has found real vulnerabilities in
major projects) but not a substitute for a human audit.

For the full picture — per-module test vectors, interop targets, fuzzing,
negative-input coverage, constant-time posture, and known limitations — see
[`docs/validation.md`](docs/validation.md). For the recommended *safe* subset of
the API (and which legacy/compat paths to avoid), see
[`docs/recommended-usage.md`](docs/recommended-usage.md).
