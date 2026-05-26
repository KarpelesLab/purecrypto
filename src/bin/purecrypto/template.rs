//! Certificate templates: TOML-driven extension profiles used by
//! `purecrypto req`, `purecrypto ca issue`, and `purecrypto ca sign-csr`.
//!
//! Templates carry the *policy* of a certificate — which extensions to emit
//! and with which bits/OIDs/critical flags. The actual subject DN, public
//! key, and validity come from the CLI / CSR. A template is **a hint, not a
//! directive**: when signing a CSR the template wins on key usage / EKU /
//! basic constraints; only `subject_alt_name.from_csr = true` lets the CSR
//! supply its requested SANs.

#![allow(dead_code)]

use std::fmt;

use crate::toml::{self, TomlError, TomlTable, TomlValue};
use purecrypto::x509::extension::{
    Extension, GeneralName, KeyUsageBits, authority_key_identifier, basic_constraints,
    certificate_policies, crl_distribution_points, extended_key_usage, key_usage, name_constraints,
    subject_alt_name, subject_key_identifier,
};
use purecrypto::x509::oid;

/// One certificate profile: extension policy + a default validity in days.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct CertTemplate {
    pub name: String,
    pub default_days: Option<u32>,
    pub basic_constraints: Option<BasicConstraintsT>,
    pub key_usage: Option<KeyUsageBits>,
    pub key_usage_critical: bool,
    pub extended_key_usage: Vec<Vec<u64>>,
    pub san_from_csr: bool,
    pub san_explicit: Vec<GeneralName>,
    pub include_ski: bool,
    pub include_aki: bool,
    pub name_constraints_permitted: Vec<GeneralName>,
    pub name_constraints_excluded: Vec<GeneralName>,
    pub policy_oids: Vec<Vec<u64>>,
    pub crldp_urls: Vec<String>,
}

/// `[basic_constraints]` block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BasicConstraintsT {
    pub ca: bool,
    pub path_len: Option<u32>,
}

/// Template loading / resolution errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TemplateError {
    /// The TOML itself was malformed (with a line number).
    Toml(TomlError),
    /// A value in the TOML had the wrong type or shape (no line number;
    /// `field` names the offending path, e.g. `basic_constraints.path_len`).
    BadValue { field: String, reason: String },
    /// Caller asked for a built-in name that doesn't exist.
    UnknownBuiltin(String),
    /// File I/O failed when loading a `-template-file PATH` override.
    Io(String),
}

impl fmt::Display for TemplateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TemplateError::Toml(e) => write!(f, "{e}"),
            TemplateError::BadValue { field, reason } => {
                write!(f, "template error in `{field}`: {reason}")
            }
            TemplateError::UnknownBuiltin(name) => {
                write!(f, "unknown built-in template `{name}`")
            }
            TemplateError::Io(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for TemplateError {}

// --- the built-in catalog --------------------------------------------------

/// Built-in template name → TOML source. Used by `builtin()`,
/// `BUILTIN_NAMES`, and `ca list-templates`.
const BUILTINS: &[(&str, &str)] = &[
    (
        "tls-server",
        include_str!("templates_builtin/tls-server.toml"),
    ),
    (
        "tls-client",
        include_str!("templates_builtin/tls-client.toml"),
    ),
    (
        "mtls-client",
        include_str!("templates_builtin/mtls-client.toml"),
    ),
    ("ca-root", include_str!("templates_builtin/ca-root.toml")),
    (
        "ca-intermediate",
        include_str!("templates_builtin/ca-intermediate.toml"),
    ),
    (
        "code-signing",
        include_str!("templates_builtin/code-signing.toml"),
    ),
    (
        "email-protection",
        include_str!("templates_builtin/email-protection.toml"),
    ),
    (
        "time-stamping",
        include_str!("templates_builtin/time-stamping.toml"),
    ),
];

/// The list of built-in template names, in catalog order. Drives
/// `ca list-templates`.
pub(crate) fn builtin_names() -> Vec<&'static str> {
    BUILTINS.iter().map(|(n, _)| *n).collect()
}

impl CertTemplate {
    /// Loads a template from a TOML string.
    pub(crate) fn from_toml(s: &str) -> Result<Self, TemplateError> {
        let root = toml::parse(s).map_err(TemplateError::Toml)?;
        // Default: AKI/SKI on, key_usage_critical = true.
        let mut t = CertTemplate {
            key_usage_critical: true,
            include_ski: true,
            include_aki: true,
            ..CertTemplate::default()
        };

        for (key, value) in &root {
            match key.as_str() {
                "name" => {
                    t.name = require_string(value, "name")?.into();
                }
                "default_days" => {
                    let n = require_int(value, "default_days")?;
                    if !(0..=u32::MAX as i64).contains(&n) {
                        return bad("default_days", "must fit in u32");
                    }
                    t.default_days = Some(n as u32);
                }
                "basic_constraints" => {
                    let tbl = require_table(value, "basic_constraints")?;
                    t.basic_constraints = Some(parse_basic_constraints(tbl)?);
                }
                "key_usage" => {
                    let tbl = require_table(value, "key_usage")?;
                    let (bits, critical) = parse_key_usage(tbl)?;
                    t.key_usage = Some(bits);
                    t.key_usage_critical = critical;
                }
                "extended_key_usage" => {
                    let tbl = require_table(value, "extended_key_usage")?;
                    t.extended_key_usage = parse_eku(tbl)?;
                }
                "subject_alt_name" => {
                    let tbl = require_table(value, "subject_alt_name")?;
                    let (from_csr, explicit) = parse_san(tbl)?;
                    t.san_from_csr = from_csr;
                    t.san_explicit = explicit;
                }
                "subject_key_identifier" => {
                    let tbl = require_table(value, "subject_key_identifier")?;
                    t.include_ski = bool_field(tbl, "include", true)?;
                }
                "authority_key_identifier" => {
                    let tbl = require_table(value, "authority_key_identifier")?;
                    t.include_aki = bool_field(tbl, "include", true)?;
                }
                "name_constraints" => {
                    let tbl = require_table(value, "name_constraints")?;
                    let (p, e) = parse_name_constraints(tbl)?;
                    t.name_constraints_permitted = p;
                    t.name_constraints_excluded = e;
                }
                "certificate_policies" => {
                    let tbl = require_table(value, "certificate_policies")?;
                    t.policy_oids = parse_policies(tbl)?;
                }
                "crl_distribution_points" => {
                    let tbl = require_table(value, "crl_distribution_points")?;
                    t.crldp_urls = parse_crldp(tbl)?;
                }
                other => {
                    return bad("<root>", &format!("unknown top-level key `{other}`"));
                }
            }
        }
        Ok(t)
    }

    /// Returns one of the built-in profiles, or `None` if the name is unknown.
    pub(crate) fn builtin(name: &str) -> Option<Self> {
        for (n, src) in BUILTINS {
            if *n == name {
                // The built-ins parse cleanly at build time; an Err here would
                // be a programmer error — propagate it as a panic in tests but
                // bubble it to the caller in release.
                return Some(
                    Self::from_toml(src)
                        .unwrap_or_else(|e| panic!("built-in template `{name}` is broken: {e}")),
                );
            }
        }
        None
    }

    /// Resolves a `-template NAME` / `-template-file PATH` pair. When both
    /// are given the file overrides the built-in (its TOML is loaded fresh,
    /// so the file is the *whole* template — not a diff). When neither is
    /// given returns `None`.
    pub(crate) fn resolve(
        name: Option<&str>,
        path: Option<&str>,
    ) -> Result<Option<Self>, TemplateError> {
        if let Some(p) = path {
            let body = std::fs::read_to_string(p)
                .map_err(|e| TemplateError::Io(format!("cannot read {p}: {e}")))?;
            return Ok(Some(Self::from_toml(&body)?));
        }
        if let Some(n) = name {
            return Self::builtin(n)
                .map(Some)
                .ok_or_else(|| TemplateError::UnknownBuiltin(n.into()));
        }
        Ok(None)
    }

    /// Builds the v3 extension list this template emits, given an optional
    /// CSR-supplied SAN list (for `subject_alt_name.from_csr = true`) and
    /// the issuer's SKI bytes / subject's SPKI BIT STRING contents (for
    /// AKI / SKI derivation). `issuer_ski` may be empty (root cert with
    /// `include_aki = false`); the resolver will then skip AKI.
    pub(crate) fn extensions(
        &self,
        csr_sans: Option<&[GeneralName]>,
        issuer_ski: &[u8],
        subject_spki_bit_string_contents: &[u8],
    ) -> Vec<Extension> {
        let mut out: Vec<Extension> = Vec::new();

        if let Some(bc) = &self.basic_constraints {
            out.push(basic_constraints(bc.ca, bc.path_len));
        }
        if let Some(bits) = self.key_usage {
            let mut ext = key_usage(bits);
            ext.critical = self.key_usage_critical;
            out.push(ext);
        }
        if !self.extended_key_usage.is_empty() {
            let oid_slices: Vec<&[u64]> = self
                .extended_key_usage
                .iter()
                .map(|v| v.as_slice())
                .collect();
            out.push(extended_key_usage(&oid_slices));
        }

        // SAN: from-CSR list (if requested) ⊎ explicit list.
        let mut all_sans: Vec<GeneralName> = Vec::new();
        if self.san_from_csr
            && let Some(extra) = csr_sans
        {
            all_sans.extend(extra.iter().cloned());
        }
        for n in &self.san_explicit {
            if !all_sans.contains(n) {
                all_sans.push(n.clone());
            }
        }
        if !all_sans.is_empty() {
            out.push(subject_alt_name(&all_sans));
        }

        if self.include_ski && !subject_spki_bit_string_contents.is_empty() {
            out.push(subject_key_identifier(subject_spki_bit_string_contents));
        }
        if self.include_aki && !issuer_ski.is_empty() {
            out.push(authority_key_identifier(issuer_ski));
        }
        if !self.name_constraints_permitted.is_empty() || !self.name_constraints_excluded.is_empty()
        {
            out.push(name_constraints(
                &self.name_constraints_permitted,
                &self.name_constraints_excluded,
            ));
        }
        if !self.policy_oids.is_empty() {
            let oid_slices: Vec<&[u64]> = self.policy_oids.iter().map(|v| v.as_slice()).collect();
            out.push(certificate_policies(&oid_slices));
        }
        if !self.crldp_urls.is_empty() {
            let urls: Vec<&str> = self.crldp_urls.iter().map(String::as_str).collect();
            out.push(crl_distribution_points(&urls));
        }
        out
    }
}

// --- TOML field plumbing ---------------------------------------------------

fn require_string<'a>(v: &'a TomlValue, field: &str) -> Result<&'a str, TemplateError> {
    v.as_str().ok_or_else(|| TemplateError::BadValue {
        field: field.into(),
        reason: "expected a string".into(),
    })
}

fn require_int(v: &TomlValue, field: &str) -> Result<i64, TemplateError> {
    v.as_int().ok_or_else(|| TemplateError::BadValue {
        field: field.into(),
        reason: "expected an integer".into(),
    })
}

fn require_table<'a>(v: &'a TomlValue, field: &str) -> Result<&'a TomlTable, TemplateError> {
    v.as_table().ok_or_else(|| TemplateError::BadValue {
        field: field.into(),
        reason: "expected a table".into(),
    })
}

fn require_array<'a>(v: &'a TomlValue, field: &str) -> Result<&'a [TomlValue], TemplateError> {
    v.as_array().ok_or_else(|| TemplateError::BadValue {
        field: field.into(),
        reason: "expected an array".into(),
    })
}

fn bool_field(tbl: &TomlTable, key: &str, default: bool) -> Result<bool, TemplateError> {
    match tbl.get(key) {
        Some(TomlValue::Bool(b)) => Ok(*b),
        Some(other) => Err(TemplateError::BadValue {
            field: key.into(),
            reason: format!("expected a boolean, got {other:?}"),
        }),
        None => Ok(default),
    }
}

fn string_array_field(tbl: &TomlTable, key: &str) -> Result<Vec<String>, TemplateError> {
    match tbl.get(key) {
        None => Ok(Vec::new()),
        Some(v) => {
            let arr = require_array(v, key)?;
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let s = require_string(item, key)?;
                out.push(s.to_string());
            }
            Ok(out)
        }
    }
}

fn bad<T>(field: &str, reason: &str) -> Result<T, TemplateError> {
    Err(TemplateError::BadValue {
        field: field.into(),
        reason: reason.into(),
    })
}

fn parse_oid_arcs(s: &str, field: &str) -> Result<Vec<u64>, TemplateError> {
    let mut out = Vec::new();
    for part in s.split('.') {
        let n: u64 = part.parse().map_err(|_| TemplateError::BadValue {
            field: field.into(),
            reason: format!("`{s}` is not a dotted OID"),
        })?;
        out.push(n);
    }
    if out.len() < 2 {
        return bad(field, &format!("OID `{s}` must have at least two arcs"));
    }
    Ok(out)
}

fn parse_basic_constraints(tbl: &TomlTable) -> Result<BasicConstraintsT, TemplateError> {
    let ca = bool_field(tbl, "ca", false)?;
    let path_len = match tbl.get("path_len") {
        None => None,
        Some(v) => {
            let n = require_int(v, "basic_constraints.path_len")?;
            if n < 0 || n > u32::MAX as i64 {
                return bad("basic_constraints.path_len", "must be a non-negative u32");
            }
            if !ca {
                return bad(
                    "basic_constraints.path_len",
                    "only meaningful when ca = true",
                );
            }
            Some(n as u32)
        }
    };
    Ok(BasicConstraintsT { ca, path_len })
}

fn parse_key_usage(tbl: &TomlTable) -> Result<(KeyUsageBits, bool), TemplateError> {
    let critical = bool_field(tbl, "critical", true)?;
    let mut bits = KeyUsageBits::empty();
    let pairs: &[(&str, KeyUsageBits)] = &[
        ("digital_signature", KeyUsageBits::DIGITAL_SIGNATURE),
        ("non_repudiation", KeyUsageBits::NON_REPUDIATION),
        ("key_encipherment", KeyUsageBits::KEY_ENCIPHERMENT),
        ("data_encipherment", KeyUsageBits::DATA_ENCIPHERMENT),
        ("key_agreement", KeyUsageBits::KEY_AGREEMENT),
        ("key_cert_sign", KeyUsageBits::KEY_CERT_SIGN),
        ("crl_sign", KeyUsageBits::CRL_SIGN),
        ("encipher_only", KeyUsageBits::ENCIPHER_ONLY),
        ("decipher_only", KeyUsageBits::DECIPHER_ONLY),
    ];
    for (k, b) in pairs {
        if bool_field(tbl, k, false)? {
            bits |= *b;
        }
    }
    for k in tbl.keys() {
        if k == "critical" {
            continue;
        }
        if !pairs.iter().any(|(known, _)| known == k) {
            return bad(&format!("key_usage.{k}"), "unknown key_usage flag");
        }
    }
    Ok((bits, critical))
}

fn parse_eku(tbl: &TomlTable) -> Result<Vec<Vec<u64>>, TemplateError> {
    let mut out: Vec<Vec<u64>> = Vec::new();
    let named: &[(&str, &[u64])] = &[
        ("server_auth", oid::ID_KP_SERVER_AUTH),
        ("client_auth", oid::ID_KP_CLIENT_AUTH),
        ("code_signing", oid::ID_KP_CODE_SIGNING),
        ("email_protection", oid::ID_KP_EMAIL_PROTECTION),
        ("time_stamping", oid::ID_KP_TIME_STAMPING),
        ("ocsp_signing", oid::ID_KP_OCSP_SIGNING),
    ];
    for (k, o) in named {
        if bool_field(tbl, k, false)? {
            out.push(o.to_vec());
        }
    }
    for raw in string_array_field(tbl, "additional")? {
        out.push(parse_oid_arcs(&raw, "extended_key_usage.additional")?);
    }
    for k in tbl.keys() {
        if k == "additional" {
            continue;
        }
        if !named.iter().any(|(known, _)| known == k) {
            return bad(&format!("extended_key_usage.{k}"), "unknown EKU flag");
        }
    }
    Ok(out)
}

fn parse_san(tbl: &TomlTable) -> Result<(bool, Vec<GeneralName>), TemplateError> {
    let from_csr = bool_field(tbl, "from_csr", false)?;
    let mut out: Vec<GeneralName> = Vec::new();
    for s in string_array_field(tbl, "dns")? {
        out.push(GeneralName::Dns(s));
    }
    for s in string_array_field(tbl, "email")? {
        out.push(GeneralName::Email(s));
    }
    for s in string_array_field(tbl, "uri")? {
        out.push(GeneralName::Uri(s));
    }
    for s in string_array_field(tbl, "ip")? {
        out.push(parse_ip(&s)?);
    }
    Ok((from_csr, out))
}

fn parse_ip(s: &str) -> Result<GeneralName, TemplateError> {
    if let Some(v4) = parse_ipv4(s) {
        return Ok(GeneralName::IpV4(v4));
    }
    if let Some(v6) = parse_ipv6(s) {
        return Ok(GeneralName::IpV6(v6));
    }
    bad("subject_alt_name.ip", &format!("invalid IP literal `{s}`"))
}

fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse().ok()?;
    }
    Some(out)
}

fn parse_ipv6(s: &str) -> Option<[u8; 16]> {
    // Minimal IPv6 parser: supports `::` and hex groups, no embedded IPv4.
    let (head, tail) = match s.find("::") {
        Some(i) => (&s[..i], &s[i + 2..]),
        None => (s, ""),
    };
    let head_groups: Vec<&str> = if head.is_empty() {
        Vec::new()
    } else {
        head.split(':').collect()
    };
    let tail_groups: Vec<&str> = if tail.is_empty() {
        Vec::new()
    } else {
        tail.split(':').collect()
    };
    if s.contains("::") {
        if head_groups.len() + tail_groups.len() > 8 {
            return None;
        }
    } else if head_groups.len() != 8 {
        return None;
    }
    let mut full: Vec<u16> = Vec::with_capacity(8);
    for g in &head_groups {
        full.push(u16::from_str_radix(g, 16).ok()?);
    }
    let zeros = 8 - head_groups.len() - tail_groups.len();
    full.resize(full.len() + zeros, 0);
    for g in &tail_groups {
        full.push(u16::from_str_radix(g, 16).ok()?);
    }
    if full.len() != 8 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, w) in full.iter().enumerate() {
        out[2 * i] = (w >> 8) as u8;
        out[2 * i + 1] = (w & 0xff) as u8;
    }
    Some(out)
}

fn parse_name_constraints(
    tbl: &TomlTable,
) -> Result<(Vec<GeneralName>, Vec<GeneralName>), TemplateError> {
    let permitted = string_array_field(tbl, "permitted_dns")?
        .into_iter()
        .map(GeneralName::Dns)
        .collect();
    let excluded = string_array_field(tbl, "excluded_dns")?
        .into_iter()
        .map(GeneralName::Dns)
        .collect();
    Ok((permitted, excluded))
}

fn parse_policies(tbl: &TomlTable) -> Result<Vec<Vec<u64>>, TemplateError> {
    let mut out = Vec::new();
    for s in string_array_field(tbl, "policies")? {
        out.push(parse_oid_arcs(&s, "certificate_policies.policies")?);
    }
    Ok(out)
}

fn parse_crldp(tbl: &TomlTable) -> Result<Vec<String>, TemplateError> {
    string_array_field(tbl, "urls")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_builtin_parses() {
        for n in builtin_names() {
            let t = CertTemplate::builtin(n).unwrap_or_else(|| panic!("missing `{n}`"));
            assert_eq!(t.name, n, "name field mismatch in built-in {n}");
        }
    }

    #[test]
    fn tls_server_emits_expected_extensions() {
        let t = CertTemplate::builtin("tls-server").unwrap();
        let csr_sans = [GeneralName::Dns("host.example".into())];
        let ski_subject = [0u8; 65]; // pretend SPKI BIT STRING contents
        let exts = t.extensions(Some(&csr_sans), &[0xCC; 20], &ski_subject);
        // basicConstraints + keyUsage + EKU + SAN + SKI + AKI = 6 entries.
        assert_eq!(exts.len(), 6);
        assert_eq!(exts[0].oid, oid::BASIC_CONSTRAINTS);
        assert_eq!(exts[1].oid, oid::KEY_USAGE);
        assert!(exts[1].critical);
        assert_eq!(exts[2].oid, oid::EXT_KEY_USAGE);
        assert_eq!(exts[3].oid, oid::SUBJECT_ALT_NAME);
        assert_eq!(exts[4].oid, oid::SUBJECT_KEY_IDENTIFIER);
        assert_eq!(exts[5].oid, oid::AUTHORITY_KEY_IDENTIFIER);
    }

    #[test]
    fn ca_root_omits_aki_and_san() {
        let t = CertTemplate::builtin("ca-root").unwrap();
        // No issuer SKI provided → AKI must be skipped per template policy.
        let exts = t.extensions(None, &[], &[0x33; 65]);
        assert!(exts.iter().all(|e| e.oid != oid::AUTHORITY_KEY_IDENTIFIER));
        assert!(exts.iter().any(|e| e.oid == oid::SUBJECT_KEY_IDENTIFIER));
        assert!(exts.iter().any(|e| e.oid == oid::BASIC_CONSTRAINTS));
    }

    #[test]
    fn ca_intermediate_carries_path_len_zero() {
        let t = CertTemplate::builtin("ca-intermediate").unwrap();
        let bc = t.basic_constraints.unwrap();
        assert!(bc.ca);
        assert_eq!(bc.path_len, Some(0));
    }

    #[test]
    fn key_usage_critical_override_via_user_file() {
        let src = r#"name = "custom"

[basic_constraints]
ca = false

[key_usage]
critical = false
digital_signature = true
"#;
        let t = CertTemplate::from_toml(src).unwrap();
        assert!(!t.key_usage_critical);
        let exts = t.extensions(None, &[], &[]);
        let ku = exts.iter().find(|e| e.oid == oid::KEY_USAGE).unwrap();
        assert!(!ku.critical);
    }

    #[test]
    fn resolve_prefers_file_over_builtin() {
        // Write a custom override that flips critical to false.
        let tmp = std::env::temp_dir().join(format!("pc_tmpl_{}.toml", std::process::id()));
        std::fs::write(
            &tmp,
            r#"name = "tls-server"
default_days = 90

[basic_constraints]
ca = false

[key_usage]
critical = false
digital_signature = true
"#,
        )
        .unwrap();
        let t = CertTemplate::resolve(Some("tls-server"), Some(tmp.to_str().unwrap()))
            .unwrap()
            .unwrap();
        assert_eq!(t.default_days, Some(90));
        assert!(!t.key_usage_critical);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn resolve_unknown_builtin_errors() {
        let err = CertTemplate::resolve(Some("does-not-exist"), None).unwrap_err();
        assert!(matches!(err, TemplateError::UnknownBuiltin(_)));
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let src = r#"name = "x"
bogus = 1
"#;
        let err = CertTemplate::from_toml(src).unwrap_err();
        assert!(matches!(err, TemplateError::BadValue { .. }));
    }

    #[test]
    fn rejects_unknown_key_usage_flag() {
        let src = r#"name = "x"

[key_usage]
totally_real_bit = true
"#;
        let err = CertTemplate::from_toml(src).unwrap_err();
        assert!(matches!(err, TemplateError::BadValue { .. }));
    }

    #[test]
    fn rejects_path_len_without_ca() {
        let src = r#"name = "x"

[basic_constraints]
ca = false
path_len = 0
"#;
        let err = CertTemplate::from_toml(src).unwrap_err();
        assert!(matches!(err, TemplateError::BadValue { .. }));
    }

    #[test]
    fn parses_san_ip_and_eku_additional() {
        let src = r#"name = "x"

[subject_alt_name]
dns = ["example.com"]
ip = ["10.0.0.1", "::1"]
email = ["a@b"]
uri = ["https://x"]

[extended_key_usage]
server_auth = true
additional = ["1.3.6.1.4.1.99999.1"]
"#;
        let t = CertTemplate::from_toml(src).unwrap();
        assert_eq!(t.san_explicit.len(), 5);
        assert_eq!(t.extended_key_usage.len(), 2);
    }

    #[test]
    fn parses_policies_and_crldp() {
        let src = r#"name = "x"

[certificate_policies]
policies = ["2.23.140.1.2.1"]

[crl_distribution_points]
urls = ["http://crl.example/r.crl"]
"#;
        let t = CertTemplate::from_toml(src).unwrap();
        assert_eq!(t.policy_oids[0], vec![2, 23, 140, 1, 2, 1]);
        assert_eq!(t.crldp_urls, ["http://crl.example/r.crl"]);
    }
}
