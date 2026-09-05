//! Shared X.509 / key helpers for the CLI tools.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::util::die;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId, Ed25519PrivateKey};
use purecrypto::rng::{OsRng, RngCore};
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::x509::extension::{
    Extension, GeneralName, KeyUsageBits, basic_constraints, extended_key_usage, key_usage,
    subject_alt_name,
};
use purecrypto::x509::{
    AnyPublicKey, CertSigner, Certificate, CertificationRequest, DistinguishedName, Time, Validity,
    oid,
};

/// A loaded private key (the owner; borrow a [`CertSigner`] from it). One
/// instance per CLI invocation, so variant-size disparity is irrelevant.
#[allow(clippy::large_enum_variant)]
pub(crate) enum PrivateKey {
    Rsa(BoxedRsaPrivateKey),
    Ec(BoxedEcdsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
}

impl PrivateKey {
    /// Loads an RSA PKCS#1, EC SEC1, or Ed25519 PKCS#8 private-key PEM.
    pub(crate) fn from_pem(pem: &str) -> Option<Self> {
        if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(pem) {
            return Some(PrivateKey::Rsa(k));
        }
        if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(pem) {
            return Some(PrivateKey::Ec(k));
        }
        Ed25519PrivateKey::from_pkcs8_pem(pem)
            .ok()
            .map(PrivateKey::Ed25519)
    }

    /// Borrows a certificate/CSR signer.
    pub(crate) fn signer(&self) -> CertSigner<'_> {
        match self {
            PrivateKey::Rsa(k) => CertSigner::Rsa(k),
            PrivateKey::Ec(k) => CertSigner::Ecdsa(k),
            PrivateKey::Ed25519(k) => CertSigner::Ed25519(k),
        }
    }
}

/// Loads a private key from `path`, dying on any error.
pub(crate) fn load_key(path: &str) -> PrivateKey {
    crate::util::warn_if_world_readable_key(path);
    let raw = std::fs::read(path).unwrap_or_else(|e| die(format!("cannot read {path}: {e}")));
    let pem = core::str::from_utf8(&raw).unwrap_or_else(|_| die(format!("{path} is not PEM")));
    PrivateKey::from_pem(pem).unwrap_or_else(|| die(format!("cannot parse key in {path}")))
}

/// Parses an OpenSSL-style subject string such as `/CN=example.com/O=Acme`.
///
/// Each attribute value is screened for ASCII control characters (`< 0x20`)
/// and rejected if any are present. The CA records issued/revoked rows as
/// one JSON object per line in `issued.jsonl` / `revoked.jsonl`; a stray
/// `\n` in a CN would corrupt subsequent records, and `parse_revoked_jsonl`
/// can be tricked into reading the wrong field if `\\"` appears unescaped.
pub(crate) fn parse_subject(subj: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    for part in subj.split('/').filter(|s| !s.is_empty()) {
        let Some((k, v)) = part.split_once('=') else {
            die(format!("malformed subject component: {part}"));
        };
        if v.bytes().any(|b| b < 0x20) {
            die(format!(
                "subject attribute {} contains a control character",
                k.trim()
            ));
        }
        match k.trim().to_ascii_uppercase().as_str() {
            "CN" => dn.common_name = Some(v.into()),
            "O" => dn.organization = Some(v.into()),
            "OU" => dn.organizational_unit = Some(v.into()),
            "C" => dn.country = Some(v.into()),
            other => die(format!("unsupported subject attribute: {other}")),
        }
    }
    dn
}

/// Escapes `s` for safe embedding inside a JSON string literal (used by the
/// `issued.jsonl` / `revoked.jsonl` ledgers). Handles the six control-character
/// escapes called out in RFC 8259 §7 plus the generic `\u{XXXX}` form for the
/// remaining `0x00..0x1F` range; non-control bytes pass through verbatim
/// (we already rejected `\` paths in [`parse_subject`], but explicit `\\` and
/// `\"` escapes are emitted for defense in depth).
pub(crate) fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                use core::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

/// Renders a distinguished name like `CN=example.com, O=Acme`.
pub(crate) fn format_dn(dn: &DistinguishedName) -> String {
    let mut parts = Vec::new();
    if let Some(c) = &dn.country {
        parts.push(format!("C={c}"));
    }
    if let Some(o) = &dn.organization {
        parts.push(format!("O={o}"));
    }
    if let Some(ou) = &dn.organizational_unit {
        parts.push(format!("OU={ou}"));
    }
    if let Some(cn) = &dn.common_name {
        parts.push(format!("CN={cn}"));
    }
    parts.join(", ")
}

/// A human label for a public key's algorithm and size/curve.
pub(crate) fn describe_key(key: &AnyPublicKey) -> String {
    match key {
        AnyPublicKey::Rsa(k) => format!("RSA, {} bits", k.modulus().bit_len()),
        AnyPublicKey::Ecdsa(k) => format!(
            "ECDSA, {}",
            match k.curve() {
                CurveId::P256 => "P-256",
                CurveId::P384 => "P-384",
                CurveId::P521 => "P-521",
                CurveId::Secp256k1 => "secp256k1",
                CurveId::Sm2p256v1 => "sm2p256v1",
                _ => "unknown",
            }
        ),
        AnyPublicKey::Ed25519(_) => "Ed25519".to_string(),
        AnyPublicKey::Ed448(_) => "Ed448".to_string(),
        AnyPublicKey::MlDsa44(_) => "ML-DSA-44".to_string(),
        AnyPublicKey::MlDsa65(_) => "ML-DSA-65".to_string(),
        AnyPublicKey::MlDsa87(_) => "ML-DSA-87".to_string(),
        AnyPublicKey::SlhDsa(k) => format!("SLH-DSA ({:?})", k.parameter_set()),
        _ => "unknown".to_string(),
    }
}

/// The last instant an X.509 `Time` can represent without wrapping:
/// 9999-12-31T23:59:59Z. `Time::utc` reduces the year modulo 10000, so a
/// notAfter (or a CRL nextUpdate) past this point silently comes back as a
/// *different* — and much earlier — date. We reject instead.
pub(crate) const MAX_X509_UNIX_TIME: u64 = 253_402_300_799;

/// The notAfter timestamp `now + days * 86_400`, or `None` if the
/// user-supplied `-days` value would wrap the u64 (same guard as the
/// `ca crl` next-update arithmetic) or would land past the last year an
/// X.509 time can encode ([`MAX_X509_UNIX_TIME`]).
fn validity_end(now: u64, days: u64) -> Option<u64> {
    let end = days.checked_mul(86_400).and_then(|d| now.checked_add(d))?;
    (end <= MAX_X509_UNIX_TIME).then_some(end)
}

/// A validity window of `days` starting now. `days` is user-supplied
/// (`-days N` on `x509 -new`/`-req` and `ca issue`/`sign-csr`); dies with a
/// clear message instead of silently wrapping on a pathologically large value
/// or emitting a year that has wrapped modulo 10000.
pub(crate) fn validity_days(days: u64) -> Validity {
    if days == 0 {
        die("-days must be at least 1 (notBefore == notAfter is not a usable validity window)");
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let end = validity_end(now, days).unwrap_or_else(|| {
        die(format!(
            "-days {days} puts notAfter past the last representable X.509 date \
             (9999-12-31T23:59:59Z); pick a smaller value"
        ))
    });
    Validity::new(Time::from_unix(now), Time::from_unix(end))
}

/// A serial number carrying a full 64 bits of CSPRNG output, as CA/Browser
/// Forum Baseline Requirements §7.1 demands (">= 64 bits of output from a
/// CSPRNG", and greater than zero).
///
/// All 64 bits come from [`OsRng`]; none are masked off. DER positivity is
/// *not* our problem here: `der::encode_integer` prepends the `0x00` sign pad
/// whenever the top bit is set, so a high-bit-set draw encodes as a positive
/// 9-byte INTEGER rather than a negative one. The only value excluded is
/// zero (BR: the serial must be greater than zero), which costs no meaningful
/// entropy at a 2^-64 rejection rate.
pub(crate) fn random_serial() -> u64 {
    loop {
        let mut b = [0u8; 8];
        OsRng.fill_bytes(&mut b);
        let n = u64::from_be_bytes(b);
        if n != 0 {
            return n;
        }
    }
}

/// Minimum RSA modulus size accepted on a submitted CSR. NIST SP 800-57 and
/// the CA/B Forum Baseline Requirements both put 1024-bit RSA below the
/// acceptable floor.
pub(crate) const MIN_RSA_BITS: usize = 2048;

/// Signature algorithms we refuse to certify: every OID whose message digest
/// is SHA-1, MD5, MD4, or MD2. All four are collision-broken, and a CSR is a
/// signed statement we are about to countersign.
const WEAK_CSR_SIGNATURE_ALGS: &[(&[u64], &str)] = &[
    (&[1, 2, 840, 113549, 1, 1, 2], "md2WithRSAEncryption"),
    (&[1, 2, 840, 113549, 1, 1, 3], "md4WithRSAEncryption"),
    (&[1, 2, 840, 113549, 1, 1, 4], "md5WithRSAEncryption"),
    (&[1, 2, 840, 113549, 1, 1, 5], "sha1WithRSAEncryption"),
    (&[1, 2, 840, 10040, 4, 3], "dsa-with-sha1"),
    (&[1, 2, 840, 10045, 4, 1], "ecdsa-with-SHA1"),
    (&[1, 3, 14, 3, 2, 3], "md5WithRSA (OIW)"),
    (&[1, 3, 14, 3, 2, 26], "id-sha1 (OIW)"),
    (&[1, 3, 14, 3, 2, 27], "dsaWithSHA1 (OIW)"),
    (&[1, 3, 14, 3, 2, 29], "sha1WithRSA (OIW)"),
];

/// The arcs of the CSR's `signatureAlgorithm` field, or `None` if the DER
/// cannot be walked (the caller treats that as a policy failure).
///
/// `CertificationRequest` exposes no accessor for this field, so we re-walk
/// the outer `CertificationRequest ::= SEQUENCE { certificationRequestInfo,
/// signatureAlgorithm, signature }` ourselves.
fn csr_signature_algorithm(csr: &CertificationRequest) -> Option<Vec<u64>> {
    use purecrypto::der::{Reader, parse_oid};
    let mut r = Reader::new(csr.to_der());
    let mut seq = r.read_sequence().ok()?;
    seq.read_element().ok()?; // certificationRequestInfo
    let mut algid = seq.read_sequence().ok()?; // signatureAlgorithm
    parse_oid(algid.read_oid().ok()?).ok()
}

/// Verifies a submitted CSR's self-signature **and** screens it against the
/// issuance policy every CA path shares:
///
///   * the self-signature must verify (nothing else may be trusted first);
///   * the signature algorithm must not use a broken digest (SHA-1 / MD*) —
///     `verify_self_signed` deliberately applies no strength policy of its
///     own, so this is the only place that check happens;
///   * an RSA subject key must be at least [`MIN_RSA_BITS`] bits.
///
/// Dies with a clear diagnostic on any failure.
pub(crate) fn verify_and_screen_csr(csr: &CertificationRequest) {
    csr.verify_self_signed()
        .unwrap_or_else(|e| die(format!("CSR signature invalid: {e}")));

    match csr_signature_algorithm(csr) {
        None => die("cannot read the CSR's signatureAlgorithm"),
        Some(arcs) => {
            if let Some((_, name)) = WEAK_CSR_SIGNATURE_ALGS
                .iter()
                .find(|(oid, _)| *oid == arcs.as_slice())
            {
                die(format!(
                    "refusing to certify a CSR signed with {name}: SHA-1/MD5-class \
                     digests are collision-broken; re-issue the request with SHA-256 or better"
                ));
            }
        }
    }

    match csr.public_key() {
        Err(e) => die(format!("bad CSR key: {e}")),
        Ok(AnyPublicKey::Rsa(k)) => {
            let bits = k.modulus().bit_len();
            if bits < MIN_RSA_BITS {
                die(format!(
                    "refusing to certify a {bits}-bit RSA key: the minimum is {MIN_RSA_BITS} bits"
                ));
            }
        }
        Ok(_) => {}
    }
}

/// Which profile [`default_extensions`] should build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    /// An end-entity certificate.
    Leaf,
    /// A CA certificate signed by another CA (`-ca` on `ca issue` /
    /// `ca sign-csr` / `x509 -req`). Bounded to `pathLen:0`.
    SubCa,
    /// A self-signed root (`x509 -new -ca`). No `pathLenConstraint` — a root
    /// is the top of its own hierarchy and may sign intermediates.
    RootCa,
}

/// The v3 extension set for an issuance that names no template.
///
/// RFC 5280 §4.2.1.3: an absent `keyUsage` places **no** restriction on what
/// the key may be used for, so a bare `x509 -req` / `x509 -new` / `ca issue`
/// used to mint certificates good for any purpose, and a `-ca` one used to
/// mint an *unconstrained* CA — `basicConstraints{CA:true}` and nothing else,
/// free to sign further CAs for any name. These defaults pin the common cases:
///
///   * [`Profile::Leaf`]: `basicConstraints{CA:false}` +
///     `keyUsage{digitalSignature, keyEncipherment}` +
///     `extendedKeyUsage{serverAuth, clientAuth}`;
///   * [`Profile::SubCa`]: `basicConstraints{CA:true, pathLen:0}` (may sign
///     leaves, not further CAs) + `keyUsage{keyCertSign, cRLSign}`;
///   * [`Profile::RootCa`]: the same without the `pathLen` bound.
///
/// Operators wanting a different profile use `-template NAME` /
/// `-template-file PATH`.
pub(crate) fn default_extensions(profile: Profile, sans: &[GeneralName]) -> Vec<Extension> {
    let mut out = Vec::new();
    match profile {
        Profile::Leaf => {
            out.push(basic_constraints(false, None));
            out.push(key_usage(
                KeyUsageBits::DIGITAL_SIGNATURE | KeyUsageBits::KEY_ENCIPHERMENT,
            ));
            out.push(extended_key_usage(&[
                oid::ID_KP_SERVER_AUTH,
                oid::ID_KP_CLIENT_AUTH,
            ]));
        }
        Profile::SubCa | Profile::RootCa => {
            let path_len = (profile == Profile::SubCa).then_some(0);
            out.push(basic_constraints(true, path_len));
            out.push(key_usage(
                KeyUsageBits::KEY_CERT_SIGN | KeyUsageBits::CRL_SIGN,
            ));
        }
    }
    if !sans.is_empty() {
        out.push(subject_alt_name(sans));
    }
    out
}

/// Wraps plain dNSName strings as [`GeneralName`]s for [`default_extensions`].
pub(crate) fn dns_general_names(names: &[String]) -> Vec<GeneralName> {
    names.iter().map(|s| GeneralName::Dns(s.clone())).collect()
}

/// Extracts the `BIT STRING` *contents* of an `AnyPublicKey`'s SPKI — the
/// raw key-bits payload, without the outer `SubjectPublicKeyInfo` SEQUENCE
/// or the BIT STRING's unused-bits prefix byte. This is the input to method
/// 1 of RFC 5280 §4.2.1.2 for computing a subjectKeyIdentifier.
pub(crate) fn spki_bit_string_contents(key: &AnyPublicKey) -> Vec<u8> {
    let der = key.to_spki_der();
    // SPKI ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }.
    // Walk the outer SEQUENCE → AlgorithmIdentifier → BIT STRING.
    use purecrypto::der::Reader;
    let mut r = Reader::new(&der);
    let mut spki = r.read_sequence().expect("SPKI: outer SEQUENCE");
    spki.read_sequence().expect("SPKI: AlgorithmIdentifier");
    spki.read_bit_string().expect("SPKI: BIT STRING").to_vec()
}

/// Returns the issuer's subjectKeyIdentifier bytes (the keyIdentifier
/// OCTET STRING inside the SKI extension), or an empty vec if the
/// certificate has no SKI extension. Used by templates that emit an
/// authorityKeyIdentifier on the issued leaf.
pub(crate) fn issuer_ski_bytes(cert: &Certificate) -> Vec<u8> {
    let exts = cert.extensions().unwrap_or_default();
    for e in exts {
        if e.oid == oid::SUBJECT_KEY_IDENTIFIER {
            // Value is OCTET STRING { keyIdentifier }.
            use purecrypto::der::Reader;
            let mut r = Reader::new(&e.value);
            if let Ok(ki) = r.read_octet_string() {
                return ki.to_vec();
            }
        }
    }
    Vec::new()
}

/// Parses dNSName entries from `-addext "subjectAltName=DNS:a,DNS:b"` or a plain
/// comma list (`a,b`).
pub(crate) fn parse_sans(spec: &str) -> Vec<String> {
    let list = spec.strip_prefix("subjectAltName=").unwrap_or(spec);
    list.split(',')
        .map(|e| e.trim())
        .filter(|e| !e.is_empty())
        .map(|e| e.strip_prefix("DNS:").unwrap_or(e).to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `validity_days` notAfter arithmetic (`now + days * 86_400`) must
    /// not silently wrap u64 on a user-controlled `-days` value (reached
    /// from `x509 -new`/`-req` and `ca issue`/`sign-csr`). Mirrors the
    /// `ca crl` next-update regression test.
    #[test]
    fn validity_end_uses_checked_arithmetic() {
        // Normal cases work.
        assert_eq!(validity_end(1_000, 30), Some(1_000 + 30 * 86_400));
        assert_eq!(validity_end(0, 1), Some(86_400));
        assert_eq!(validity_end(0, 365), Some(365 * 86_400));
        // Multiplication overflow: 2^64/86400 ≈ 2.135e14 days. A u64-max
        // days value must NOT silently wrap to a small notAfter timestamp.
        assert_eq!(validity_end(0, u64::MAX), None);
        // Addition overflow on a near-MAX `now`.
        assert_eq!(validity_end(u64::MAX - 1, 1), None);
        // `now = u64::MAX` no longer wraps, but it is far past the last date
        // an X.509 time can encode, so the range check rejects it anyway.
        assert_eq!(validity_end(u64::MAX, 0), None);
        // Boundary just past the safe zone: almost * 86_400 fits, but one
        // more day overflows.
        let almost = u64::MAX / 86_400;
        assert!(validity_end(0, almost).is_none());
        assert_eq!(validity_end(0, almost + 1), None);
    }

    /// C-8.2: a `-days` value that pushes notAfter past year 9999 must be
    /// refused, not silently reduced modulo 10000 by `Time::utc` (which would
    /// hand back a certificate expiring in, say, 2024 while the operator
    /// believes it runs to 12024).
    #[test]
    fn validity_end_rejects_years_past_9999() {
        // The last representable instant is accepted...
        assert_eq!(
            validity_end(MAX_X509_UNIX_TIME - 86_400, 1),
            Some(MAX_X509_UNIX_TIME)
        );
        // ...one second past it (one more day) is not.
        assert_eq!(validity_end(MAX_X509_UNIX_TIME - 86_400 + 1, 1), None);
        // A ~10000-year request from a present-day `now` must be refused...
        let now = 1_750_000_000; // mid-2025
        let days = 3_650_000; // ≈ 9993 years
        assert_eq!(validity_end(now, days), None);
        // ...because `Time::utc` reduces the year modulo 10000: without the
        // guard the notAfter of a certificate valid to year 12018 encodes as
        // 2018 — seven years in the PAST.
        let encoded = Time::from_unix(now + days * 86_400);
        assert_eq!(
            &encoded.as_str()[..4],
            "2018",
            "expected the year-12018 wrap this guard exists to prevent"
        );
    }

    /// C-1: certificate serials must carry a full 64 bits of CSPRNG output
    /// (CA/Browser Forum BR §7.1). The old implementation masked off the top
    /// bit and forced the low bit, leaving 62 usable bits.
    #[test]
    fn random_serial_has_full_64_bits_of_entropy() {
        const DRAWS: usize = 512;
        let mut seen = std::collections::HashSet::new();
        // `or_all` accumulates every bit that was ever 1, `and_all` every bit
        // that was always 1. After 512 independent draws both must show that
        // all 64 bit positions are free-running: any bit forced to 0 leaves a
        // hole in `or_all`, any bit forced to 1 shows up in `and_all`. The
        // odds of a false failure are 64 * 2^-512.
        let mut or_all: u64 = 0;
        let mut and_all: u64 = u64::MAX;
        for _ in 0..DRAWS {
            let s = random_serial();
            assert_ne!(s, 0, "serial must be greater than zero");
            or_all |= s;
            and_all &= s;
            seen.insert(s);
        }
        assert_eq!(or_all, u64::MAX, "some serial bit is always zero");
        assert_eq!(and_all, 0, "some serial bit is always one");
        // Two consecutive issuances must not collide.
        assert_eq!(seen.len(), DRAWS, "duplicate serial in {DRAWS} draws");
        // The DER encoding must be >= 8 significant bytes (>= 64 bits) for the
        // overwhelming majority of draws — only a zero top byte shortens it,
        // at a rate of 1/256.
        let short = seen.iter().filter(|s| **s < 1 << 56).count();
        assert!(
            short < DRAWS / 16,
            "{short}/{DRAWS} serials encode in under 8 bytes — entropy is being masked"
        );
    }

    /// C-8.3: the no-template issuance profile must constrain what the key can
    /// be used for. An absent keyUsage means "any purpose" (RFC 5280 §4.2.1.3).
    #[test]
    fn default_extensions_constrain_key_usage() {
        let leaf = default_extensions(Profile::Leaf, &[]);
        let ku = leaf
            .iter()
            .find(|e| e.oid == oid::KEY_USAGE)
            .expect("leaf keyUsage");
        assert!(ku.critical);
        assert!(leaf.iter().any(|e| e.oid == oid::EXT_KEY_USAGE));
        assert!(leaf.iter().any(|e| e.oid == oid::BASIC_CONSTRAINTS));

        let ca = default_extensions(Profile::SubCa, &[]);
        assert!(ca.iter().any(|e| e.oid == oid::KEY_USAGE));
        // A sub-CA gets no EKU (it is not a leaf) but must be pathLen-bounded.
        assert!(ca.iter().all(|e| e.oid != oid::EXT_KEY_USAGE));
        let bc = ca
            .iter()
            .find(|e| e.oid == oid::BASIC_CONSTRAINTS)
            .expect("CA basicConstraints");
        // SEQUENCE { BOOLEAN TRUE, INTEGER 0 } — the pathLen must be present.
        assert!(
            bc.value.windows(3).any(|w| w == [0x02, 0x01, 0x00]),
            "sub-CA basicConstraints is missing pathLenConstraint: {:02x?}",
            bc.value
        );

        // A self-signed root is the top of its own hierarchy: CA bit and
        // keyUsage, but no pathLen bound.
        let root = default_extensions(Profile::RootCa, &[]);
        let bc = root
            .iter()
            .find(|e| e.oid == oid::BASIC_CONSTRAINTS)
            .expect("root basicConstraints");
        assert!(!bc.value.windows(3).any(|w| w == [0x02, 0x01, 0x00]));
        assert!(root.iter().any(|e| e.oid == oid::KEY_USAGE));
    }

    /// SANs handed to the default profile land in a subjectAltName extension.
    #[test]
    fn default_extensions_carry_sans() {
        let names = dns_general_names(&["a.example".to_string(), "b.example".to_string()]);
        let exts = default_extensions(Profile::Leaf, &names);
        assert!(exts.iter().any(|e| e.oid == oid::SUBJECT_ALT_NAME));
    }
}
