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
| `rsa-pss-rsae-sha256`       | (TLS only, `rsaEncryption` key) | `0x0804`       | yes |
| `rsa-pss-rsae-sha384`       | (TLS only, `rsaEncryption` key) | `0x0805`       | yes |
| `rsa-pss-rsae-sha512`       | (TLS only, `rsaEncryption` key) | `0x0806`       | yes |
| `rsa-pss-pss-sha256`        | `1.2.840.113549.1.1.10` (`id-RSASSA-PSS`) when its `RSASSA-PSS-params` name SHA-256 / MGF1-SHA-256 | `0x0809` (`id-RSASSA-PSS` key) | yes |
| `rsa-pss-pss-sha384`        | `id-RSASSA-PSS` when its params name SHA-384 / MGF1-SHA-384 | `0x080A` (`id-RSASSA-PSS` key) | yes |
| `rsa-pss-pss-sha512`        | `id-RSASSA-PSS` when its params name SHA-512 / MGF1-SHA-512 | `0x080B` (`id-RSASSA-PSS` key) | yes |
| `ecdsa-with-sha256`         | `1.2.840.10045.4.3.2` (any curve) | (none)       | yes |
| `ecdsa-with-sha384`         | `1.2.840.10045.4.3.3` (any curve) | (none)       | yes |
| `ecdsa-with-sha512`         | `1.2.840.10045.4.3.4` (any curve) | (none)       | yes |
| `ecdsa-secp256r1-sha256`    | (TLS only, strict curve)        | `0x0403`       | yes |
| `ecdsa-secp384r1-sha384`    | (TLS only, strict curve)        | `0x0503`       | yes |
| `ecdsa-secp521r1-sha512`    | (TLS only, strict curve)        | `0x0603`       | yes |
| `ecdsa-secp256r1-sha384/512`, `ecdsa-secp384r1-sha256/512`, `ecdsa-secp521r1-sha256/384` | cross-hash, policy only | (none) | opt-in |
| `ecdsa-secp256k1-sha256/384/512` | secp256k1, policy only      | (none)         | opt-in |
| `ecdsa-brainpoolP256r1-sha256`, `ecdsa-brainpoolP384r1-sha384`, `ecdsa-brainpoolP512r1-sha512` | (TLS only, strict curve; Brainpool, RFC 5639) | `0x081A/1B/1C` (RFC 8734, TLS 1.3 only) | yes |
| `sm2-with-sm3`              | `1.2.156.10197.1.501`           | (none)         | opt-in |
| `ed25519`                   | `1.3.101.112`                   | `0x0807`       | yes |
| `ed448`                     | `1.3.101.113`                   | `0x0808`       | yes |
| `ml-dsa-44` / `-65` / `-87` | `2.16.840.1.101.3.4.3.17/18/19` | `0x0904/05/06` | yes (FIPS 204) |
| `slh-dsa-sha2-128s/128f/192s/192f/256s/256f`, `slh-dsa-shake-128s/128f/192s/192f/256s/256f` | `2.16.840.1.101.3.4.3.20..31` | (none) | opt-in (FIPS 205) |

The matched-curve, matched-hash ECDSA pairs (P-256 with SHA-256, and so on)
have IANA TLS scheme codes: RFC 8446 for the NIST curves, RFC 8734 for the
Brainpool curves (TLS 1.3 only — the TLS 1.2 / DTLS 1.2 engines refuse a
Brainpool identity with `Error::UnsupportedKeyType`, and the 1.2 clients do
not offer those code points). secp256k1 and SM2 have no TLS signature scheme
at all, so `ConfigBuilder::try_identity` refuses such a key up front. Every
ECDSA entry is reachable for chain dispatch through the OID-keyed
`ecdsa-with-shaN` entries, which accept any supported curve; the cross-hash
pairs and the secp256k1 entries exist as fine-grained policy-keyed entries
for opt-in.

The three `rsa-pss-rsae-*` entries carry **no** X.509 OID: in X.509 the
`sha*WithRSAEncryption` OIDs mean PKCS#1 v1.5 and belong to the
`rsa-pkcs1-*` entries, while an RSA-PSS certificate signature is
`id-RSASSA-PSS`.

## RSA-PSS in TLS: two scheme families, one per SPKI form

RFC 8446 §4.2.3 defines two RSASSA-PSS scheme families that differ only in
the key the certificate carries: `rsa_pss_rsae_*` (`0x0804..06`) for a key
certified as `rsaEncryption`, `rsa_pss_pss_*` (`0x0809..0B`) for one
certified as `id-RSASSA-PSS`. The signatures themselves are identical PSS
signatures (MGF1 over the scheme's digest, salt as long as the digest), so
the crate ties the families to the key form rather than to the math:

* Verifying: `tls::crypto::sign::verify_signature` accepts an
  `rsa_pss_rsae_*` `CertificateVerify` (or TLS 1.2 `ServerKeyExchange` /
  `CertificateVerify`) only under an `AnyPublicKey::Rsa` peer key and an
  `rsa_pss_pss_*` one only under an `AnyPublicKey::RsaPss` key — whose RFC
  4055 restriction, if any, must name the scheme's digest — and reports
  anything else as `PeerMisbehaved`. The `rsa-pss-rsae-*` registry entries
  refuse an `id-RSASSA-PSS` SPKI outright; the `rsa-pss-pss-*` entries accept
  both forms because the X.509 path needs the `rsaEncryption` one.
* Signing: the engines bind an RSA identity to its leaf's SPKI form when the
  identity is installed (`ServerKey::bound_to_leaf` /
  `ClientKey::bound_to_leaf`). An in-process `SigningKey::Rsa` whose leaf is
  `id-RSASSA-PSS` signs `rsa_pss_pss_<digest>` — the digest the SPKI's
  restriction pins, SHA-256 when unrestricted — and otherwise
  `rsa_pss_rsae_sha256`. An external signer's advertised list is narrowed to
  the family the leaf permits; `LocalSigner` around an RSA key advertises
  `0x0804, 0x0809, 0x080A, 0x080B` and signs whichever the engine
  negotiates. The client engines, which thread no RNG through the handshake,
  derive the PSS salt from the key and the signed content (public, so the
  signature is no weaker; two signatures of the same content are identical).
* Offering: the client's `signature_algorithms` and the server's
  `CertificateRequest` list all three `rsa_pss_pss_*` code points after the
  RSAE ones — the crate offers every scheme the registry verifies and
  `modern()` permits, and a PSS-restricted peer leaf can only be
  authenticated under its own digest. The TLS 1.2 / DTLS 1.2 engines also
  sign and verify both families (RFC 8446 defines them for TLS 1.2 as well).

## RSA-PSS in X.509: the parameters select the entry

`id-RSASSA-PSS` names no digest by itself. RFC 4055 §3.1 puts the digest,
the MGF1 digest, the salt length and the trailer field in the
`RSASSA-PSS-params` of the *signature's* `AlgorithmIdentifier`, so
`find_by_oid` deliberately does not resolve that OID (none of the
`rsa-pss-pss-*` entries lists it). Instead the X.509 parsers expose the whole
identifier — `Certificate::signature_algorithm`,
`CertificateRevocationList::signature_algorithm`,
`OcspResponse::signature_algorithm`,
`CertificationRequest::signature_algorithm` — as an
`x509::SignatureAlgorithmIdentifier` (OID plus `x509::SignatureParams`), and
`AnyPublicKey::signature_algorithm` resolves it:

* `id-RSASSA-PSS` maps to the `rsa-pss-pss-<digest>` entry for the digest the
  parameters name, provided MGF1 uses the same digest and the trailer field
  is 1 (the only profile the registry implements). The entry then verifies
  through `SignatureAlgorithm::verify_with_params` with the signature's own
  salt length — it is not assumed to equal the digest length.
* An `id-RSASSA-PSS` identifier without parameters (or with an empty
  SEQUENCE) means the DER defaults — SHA-1 / MGF1-SHA-1 / salt 20 — and is
  `UnsupportedAlgorithm`, never a silent SHA-256 assumption.
* The issuer key may be certified as `rsaEncryption` or as `id-RSASSA-PSS`.
  A PSS-restricted key parses to `x509::AnyPublicKey::RsaPss` with its RFC
  4055 `PssRestriction` preserved, and the signature's parameters must be
  compatible with it per RFC 4055 §3.3 (`PssRestriction::permits_params`):
  same digest, same MGF1 digest, same trailer field, and a salt at least as
  long as the key's. Anything else resolves to no entry. Such a key also
  refuses every PKCS#1 v1.5 OID, and the `rsa-pkcs1-*` entries refuse a
  PSS-restricted SPKI outright (RFC 4055 §1.2).
* Certificates and CRLs compare the inner (`TBSCertificate.signature` /
  `TBSCertList.signature`) and outer `signatureAlgorithm` byte for byte
  (RFC 5280 §4.1.1.2 / §5.1.1.2), parameters included, so an outer
  identifier that names a different PSS parameter set than the signed one
  is `Malformed`.

The chain verifier, the CRL and OCSP gates whitelist the entry this dispatch
returns, not a bare OID lookup. On the issuing side `CertSigner::RsaPss(key,
PssHash)` and `SignatureAlgId::RsaPssSha256 / Sha384 / Sha512` write the
matching `RSASSA-PSS-params` (MGF1 with the same digest, salt = digest
length) into both identifiers.

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
