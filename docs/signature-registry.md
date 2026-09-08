# Signature algorithms: the registry and the policy whitelist

X.509 chain validation and the TLS 1.3 `CertificateVerify` message both
dispatch through the [`signature_registry`](../src/signature_registry.rs)
module. Every signature primitive purecrypto can do appears as one registry
entry. A strict whitelist, `SignaturePolicy`, controls which entries a
verifier will accept. Adding an entry to the registry never auto-permits it;
the caller has to name the id explicitly.

## Registry

| `id` (whitelist key)        | X.509 OID                       | TLS 1.3 scheme | In `modern()` |
| --------------------------- | ------------------------------- | -------------- | ------------- |
| `rsa-pkcs1-sha1`            | `1.2.840.113549.1.1.5`          | (none)         | opt-in |
| `rsa-pkcs1-sha256`          | `1.2.840.113549.1.1.11`         | `0x0401`       | yes |
| `rsa-pkcs1-sha384`          | `1.2.840.113549.1.1.12`         | `0x0501`       | yes |
| `rsa-pkcs1-sha512`          | `1.2.840.113549.1.1.13`         | (none)         | opt-in |
| `rsa-pss-rsae-sha256`       | `1.2.840.113549.1.1.11` (RSAE)  | `0x0804`       | yes |
| `rsa-pss-rsae-sha384`       | `1.2.840.113549.1.1.12` (RSAE)  | `0x0805`       | yes |
| `rsa-pss-rsae-sha512`       | `1.2.840.113549.1.1.13` (RSAE)  | `0x0806`       | yes |
| `rsa-pss-pss-sha256`        | `1.2.840.113549.1.1.10` (PSS keys) | (none)      | opt-in |
| `ecdsa-with-sha256`         | `1.2.840.10045.4.3.2` (any curve) | (none)       | yes |
| `ecdsa-with-sha384`         | `1.2.840.10045.4.3.3` (any curve) | (none)       | yes |
| `ecdsa-with-sha512`         | `1.2.840.10045.4.3.4` (any curve) | (none)       | yes |
| `ecdsa-secp256r1-sha256`    | (TLS only, strict curve)        | `0x0403`       | yes |
| `ecdsa-secp384r1-sha384`    | (TLS only, strict curve)        | `0x0503`       | yes |
| `ecdsa-secp521r1-sha512`    | (TLS only, strict curve)        | `0x0603`       | yes |
| `ecdsa-secp256r1-sha384/512`, `ecdsa-secp384r1-sha256/512`, `ecdsa-secp521r1-sha256/384` | cross-hash, policy only | (none) | opt-in |
| `ecdsa-secp256k1-sha256/384/512` | secp256k1, policy only      | (none)         | opt-in |
| `ed25519`                   | `1.3.101.112`                   | `0x0807`       | yes |
| `ed448`                     | `1.3.101.113`                   | `0x0808`       | yes |
| `ml-dsa-44` / `-65` / `-87` | `2.16.840.1.101.3.4.3.17/18/19` | `0x0904/05/06` | yes (FIPS 204) |
| `slh-dsa-sha2-128s/128f/192s/192f/256s/256f`, `slh-dsa-shake-128s/128f/192s/192f/256s/256f` | `2.16.840.1.101.3.4.3.20..31` | (none) | opt-in (FIPS 205) |

The matched-curve, matched-hash ECDSA pairs (P-256 with SHA-256, and so on)
have IANA TLS scheme codes. Cross-hash pairs and every secp256k1 entry are
reachable for chain dispatch through the OID-keyed `ecdsa-with-shaN` entries,
which accept any supported curve, and as fine-grained policy-keyed entries
for TLS opt-in.

ML-DSA is on the default whitelist. SLH-DSA's twelve parameter sets are
registered but never on the default whitelist: signatures are 7 to 50 KB and
rarely the right default for X.509 leaves.

## Configuring the policy

```rust
use purecrypto::signature_registry::SignaturePolicy;
use purecrypto::tls::{Config, RootCertStore};

// Default: the modern IANA-blessed set above, RSA >= 2048 bits.
let cfg = Config::builder().roots(RootCertStore::new()).build();

// Legacy interop: accept SHA-1 RSA and lower the RSA-bit floor to 1024.
let cfg = Config::builder()
    .roots(RootCertStore::new())
    .signature_policy(
        SignaturePolicy::modern()
            .permit("rsa-pkcs1-sha1")
            .with_min_rsa_bits(1024),
    )
    .build();

// PQC-strict: only ML-DSA and Ed25519, refuse everything classical.
let cfg = Config::builder()
    .roots(RootCertStore::new())
    .signature_policy(
        SignaturePolicy::empty()
            .permit("ml-dsa-65")
            .permit("ml-dsa-87")
            .permit("ed25519"),
    )
    .build();

// SLH-DSA chains: opt in to the single set the application expects.
let cfg = Config::builder()
    .roots(RootCertStore::new())
    .signature_policy(SignaturePolicy::modern().permit("slh-dsa-sha2-128f"))
    .build();
```

`permit` silently ignores an id that is not in the registry, which keeps
literal-chaining ergonomic but hides typos. When the id comes from
configuration or user input, use `try_permit`, which returns an error for an
unknown id:

```rust
use purecrypto::signature_registry::SignaturePolicy;

let policy = SignaturePolicy::empty()
    .try_permit("ed25519")
    .expect("known id");
assert!(SignaturePolicy::empty().try_permit("ed25519-typo").is_err());
```

`signature_policy` on the unified `Config` applies to both roles. For a
server it gates client-certificate validation under mTLS.
