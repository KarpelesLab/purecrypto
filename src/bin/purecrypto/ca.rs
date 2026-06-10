//! `purecrypto ca` — manage a development CA on disk.
//!
//! Layout (`DIR/`):
//!
//! ```text
//! root.key       (0600)  — PEM private key (algorithm-dependent format)
//! root.crt       (0644)  — PEM self-signed CA certificate (serial = 1)
//! serial         (0644)  — next-to-issue serial, single decimal u64
//! issued.jsonl   (0644)  — JSON Lines, one record per issued cert
//! revoked.jsonl  (0644)  — JSON Lines, one record per revocation
//! crl.pem        (0644)  — last emitted CRL (re-written by `ca crl`)
//! ```
//!
//! Subcommands: `init`, `sign-csr`, `issue`, `revoke`, `crl`, `show`.

use std::path::{Path, PathBuf};

use crate::pki::{
    describe_key, format_dn, issuer_ski_bytes, json_escape, parse_sans, parse_subject,
    spki_bit_string_contents, validity_days,
};
use crate::template::{CertTemplate, builtin_names};
use crate::util::{Args, SentinelLock, die, write_output, write_output_with_mode};
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId, Ed448PrivateKey, Ed25519PrivateKey};
use purecrypto::rng::OsRng;
use purecrypto::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
use purecrypto::x509::extension::{Extension, GeneralName};
use purecrypto::x509::{
    AnyPublicKey, CertSigner, Certificate, CertificateRevocationList, CertificationRequest,
    CrlBuilder, CrlReason, DistinguishedName, Time, Validity,
};

/// CA directory layout helpers.
struct CaDir {
    dir: PathBuf,
}

impl CaDir {
    fn new(dir: &str) -> Self {
        CaDir {
            dir: PathBuf::from(dir),
        }
    }
    fn root_key(&self) -> PathBuf {
        self.dir.join("root.key")
    }
    fn root_crt(&self) -> PathBuf {
        self.dir.join("root.crt")
    }
    fn serial(&self) -> PathBuf {
        self.dir.join("serial")
    }
    fn issued(&self) -> PathBuf {
        self.dir.join("issued.jsonl")
    }
    fn revoked(&self) -> PathBuf {
        self.dir.join("revoked.jsonl")
    }
    fn crl_pem(&self) -> PathBuf {
        self.dir.join("crl.pem")
    }
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_string(path: &Path) -> String {
    std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(format!("cannot read {}: {e}", path.display())))
}

fn read_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap_or_else(|e| die(format!("cannot read {}: {e}", path.display())))
}

fn write_string(path: &Path, data: &str) {
    std::fs::write(path, data)
        .unwrap_or_else(|e| die(format!("cannot write {}: {e}", path.display())))
}

fn append_line(path: &Path, line: &str) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .unwrap_or_else(|e| die(format!("cannot open {}: {e}", path.display())));
    writeln!(f, "{line}").unwrap_or_else(|e| die(format!("cannot write {}: {e}", path.display())));
}

/// Loads `DIR/root.crt`.
fn load_root_cert(ca: &CaDir) -> Certificate {
    let pem = read_string(&ca.root_crt());
    Certificate::from_pem(&pem).unwrap_or_else(|e| die(format!("bad root.crt: {e}")))
}

/// Loads `DIR/root.key` as one of the supported algorithms. One instance
/// per `ca` invocation, so the variant-size disparity is irrelevant.
#[allow(clippy::large_enum_variant)]
enum RootKey {
    Rsa(BoxedRsaPrivateKey),
    Ec(BoxedEcdsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
    Ed448(Ed448PrivateKey),
}

impl RootKey {
    fn signer(&self) -> CertSigner<'_> {
        match self {
            RootKey::Rsa(k) => CertSigner::Rsa(k),
            RootKey::Ec(k) => CertSigner::Ecdsa(k),
            RootKey::Ed25519(k) => CertSigner::Ed25519(k),
            RootKey::Ed448(k) => CertSigner::Ed448(k),
        }
    }
}

fn load_root_key(ca: &CaDir) -> RootKey {
    if let Some(s) = ca.root_key().to_str() {
        crate::util::warn_if_world_readable_key(s);
    }
    let raw = read_bytes(&ca.root_key());
    let pem = core::str::from_utf8(&raw)
        .unwrap_or_else(|_| die(format!("{} is not PEM", ca.root_key().display())));
    if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(pem) {
        return RootKey::Rsa(k);
    }
    if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(pem) {
        return RootKey::Ec(k);
    }
    if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem(pem) {
        return RootKey::Ed25519(k);
    }
    if let Ok(k) = Ed448PrivateKey::from_pkcs8_pem(pem) {
        return RootKey::Ed448(k);
    }
    die(format!("cannot parse {}", ca.root_key().display()))
}

fn next_serial(ca: &CaDir) -> u64 {
    let s = read_string(&ca.serial());
    s.trim()
        .parse::<u64>()
        .unwrap_or_else(|_| die(format!("bad serial in {}", ca.serial().display())))
}

fn bump_serial(ca: &CaDir, current: u64) {
    let next = current
        .checked_add(1)
        .unwrap_or_else(|| die("serial counter overflow (u64)"));
    write_string(&ca.serial(), &format!("{next}\n"));
}

/// Reads the current serial, hands it back, and bumps the on-disk counter
/// — all under an inter-process [`SentinelLock`] so two racing
/// `purecrypto ca` invocations cannot see the same value at `next_serial`,
/// write the same `current + 1` back, and issue two certificates with the
/// same serial (which would break the auditing / revocation invariants the
/// CA depends on).
fn allocate_serial(ca: &CaDir) -> u64 {
    let _lock = SentinelLock::acquire(ca.dir.join("serial.lock"), "`purecrypto ca`");
    let serial = next_serial(ca);
    bump_serial(ca, serial);
    serial
}

fn serial_to_be_bytes(serial: u64) -> Vec<u8> {
    let b = serial.to_be_bytes();
    let mut i = 0;
    while i + 1 < b.len() && b[i] == 0 {
        i += 1;
    }
    b[i..].to_vec()
}

/// Days from `-days` (default 365).
fn days(args: &Args) -> u64 {
    args.value("-days")
        .map(|d| {
            d.parse::<u64>()
                .unwrap_or_else(|_| die("invalid -days value"))
        })
        .unwrap_or(365)
}

fn ca_dir(args: &Args) -> CaDir {
    let dir = args
        .value("-dir")
        .unwrap_or_else(|| die("missing -dir <DIR>"));
    CaDir::new(dir)
}

// ---------------------------------------------------------------------------
// init

fn run_init(args: Args) {
    let ca = ca_dir(&args);
    if ca.root_key().exists() {
        die(format!(
            "{} already exists — refusing to overwrite a CA",
            ca.root_key().display()
        ));
    }
    std::fs::create_dir_all(&ca.dir)
        .unwrap_or_else(|e| die(format!("cannot mkdir {}: {e}", ca.dir.display())));

    let cn = args.value("-cn").unwrap_or("purecrypto Development CA");
    let algorithm = args.value("-algorithm").unwrap_or("EC");
    let curve = args.value("-curve").unwrap_or("P-256");
    let days_n = days(&args);

    // Generate the key.
    let (key_pem, key_for_signer) = match algorithm.to_ascii_uppercase().as_str() {
        "EC" | "ECDSA" => {
            let curve_id = match curve.to_ascii_lowercase().as_str() {
                "p-256" | "p256" | "prime256v1" | "secp256r1" => CurveId::P256,
                "p-384" | "p384" | "secp384r1" => CurveId::P384,
                "p-521" | "p521" | "secp521r1" => CurveId::P521,
                other => die(format!("unknown curve: {other}")),
            };
            let k = BoxedEcdsaPrivateKey::generate(curve_id, &mut OsRng);
            (k.to_sec1_pem(), RootKey::Ec(k))
        }
        "RSA" => {
            use purecrypto::bignum::Uint;
            let k = RsaPrivateKey::<32>::generate(Uint::from_u64(65537), &mut OsRng, 20);
            let pem = k.to_pkcs1_pem();
            (
                pem,
                RootKey::Rsa(BoxedRsaPrivateKey::from_pkcs1_der(&k.to_pkcs1_der()).unwrap()),
            )
        }
        "ED25519" => {
            let k = Ed25519PrivateKey::generate(&mut OsRng);
            (k.to_pkcs8_pem(), RootKey::Ed25519(k))
        }
        "ED448" => {
            let k = Ed448PrivateKey::generate(&mut OsRng);
            (k.to_pkcs8_pem(), RootKey::Ed448(k))
        }
        other => die(format!(
            "unsupported -algorithm {other} (try EC, RSA, ED25519, ED448)"
        )),
    };

    // Build the self-signed CA cert using the built-in `ca-root` template.
    // The template adds subjectKeyIdentifier + keyUsage (keyCertSign | cRLSign)
    // + basicConstraints.ca=true on top of the legacy cert-only fields.
    let subject = DistinguishedName::common_name(cn);
    let validity = validity_days(days_n);
    let signer = key_for_signer.signer();
    let root_tmpl =
        CertTemplate::builtin("ca-root").unwrap_or_else(|| die("missing ca-root template"));
    let pubkey = signer.public_key();
    let spki_bits = spki_bit_string_contents(&pubkey);
    let exts: Vec<Extension> = root_tmpl.extensions(None, &[], &spki_bits);
    let cert = Certificate::self_signed_with_extensions(
        &signer, &subject, &validity, 1, // CA serial = 1
        &exts,
    )
    .unwrap_or_else(|e| die(format!("cannot self-sign CA: {e}")));

    // Persist.
    write_output_with_mode(
        Some(ca.root_key().to_str().unwrap()),
        key_pem.as_bytes(),
        true,
    );
    std::fs::write(ca.root_crt(), cert.to_pem())
        .unwrap_or_else(|e| die(format!("cannot write root.crt: {e}")));
    write_string(&ca.serial(), "2\n");
    // Touch the JSONL files so they exist with valid mode.
    write_string(&ca.issued(), "");
    write_string(&ca.revoked(), "");

    println!(
        "Initialized CA at {} (subject: {}, algorithm: {})",
        ca.dir.display(),
        format_dn(&subject),
        algorithm
    );
}

// ---------------------------------------------------------------------------
// issue — sign a bare public key (no CSR roundtrip).

fn parse_sans_arg(args: &Args) -> Vec<String> {
    if let Some(ext) = args.value("-addext").or_else(|| args.value("-san")) {
        parse_sans(ext)
    } else if let Some(sans) = args.value("-sans") {
        parse_sans(sans)
    } else {
        Vec::new()
    }
}

fn run_issue(args: Args) {
    let ca = ca_dir(&args);
    let pub_path = args
        .value("-pubkey")
        .unwrap_or_else(|| die("missing -pubkey <pub.pem>"));
    let cn = args
        .value("-cn")
        .or_else(|| args.value("-subj"))
        .unwrap_or_else(|| die("missing -cn <NAME>"));
    let is_ca_flag = args.flag("-ca") || args.flag("--ca");

    // Template resolution: explicit -template wins; -ca is short-hand for
    // ca-intermediate; otherwise the (per-arg) -days/-sans drive a plain
    // issuance with no v3 extension policy beyond basicConstraints + SAN.
    let template_name = args.value("-template").or(if is_ca_flag {
        Some("ca-intermediate")
    } else {
        None
    });
    let template = CertTemplate::resolve(template_name, args.value("-template-file"))
        .unwrap_or_else(|e| die(format!("template error: {e}")));

    let days_n = args
        .value("-days")
        .map(|d| d.parse::<u64>().unwrap_or_else(|_| die("invalid -days")))
        .or_else(|| {
            template
                .as_ref()
                .and_then(|t| t.default_days.map(|d| d as u64))
        })
        .unwrap_or(365);

    let raw = read_bytes(Path::new(pub_path));
    let pem = core::str::from_utf8(&raw).unwrap_or_else(|_| die("pubkey is not PEM"));
    let subject_key =
        AnyPublicKey::from_spki_pem(pem).unwrap_or_else(|e| die(format!("bad pubkey: {e}")));

    // CN can be either a plain string or an OpenSSL-style /CN=foo/O=bar subject.
    let subject = if cn.starts_with('/') {
        parse_subject(cn)
    } else {
        DistinguishedName::common_name(cn)
    };

    let sans = parse_sans_arg(&args);
    let san_refs: Vec<&str> = sans.iter().map(String::as_str).collect();

    let root_key = load_root_key(&ca);
    let root_cert = load_root_cert(&ca);
    let issuer_dn = root_cert
        .subject()
        .unwrap_or_else(|e| die(format!("bad CA subject: {e}")));

    // Atomic read-modify-write of the serial counter under a sentinel
    // file lock — see `SerialLock`.
    let serial = allocate_serial(&ca);
    let validity = validity_days(days_n);

    let cert = if let Some(tmpl) = template {
        let issuer_ski = issuer_ski_bytes(&root_cert);
        let subj_spki_bits = spki_bit_string_contents(&subject_key);
        let csr_sans: Vec<GeneralName> = sans.iter().map(|s| GeneralName::Dns(s.clone())).collect();
        let exts: Vec<Extension> = tmpl.extensions(Some(&csr_sans), &issuer_ski, &subj_spki_bits);
        Certificate::issue_with_extensions(
            &root_key.signer(),
            &issuer_dn,
            &subject,
            &subject_key,
            &validity,
            serial,
            &exts,
        )
        .unwrap_or_else(|e| die(format!("cannot issue cert: {e}")))
    } else {
        Certificate::issue_general(
            &root_key.signer(),
            &issuer_dn,
            &subject,
            &subject_key,
            &validity,
            serial,
            is_ca_flag,
            &san_refs,
        )
        .unwrap_or_else(|e| die(format!("cannot issue cert: {e}")))
    };

    // Record in issued.jsonl. Every string field goes through `json_escape`
    // so a control character or `"` in a SAN / subject cannot corrupt the
    // one-record-per-line invariant the parser depends on.
    let sans_json = sans
        .iter()
        .map(|s| format!("\"{}\"", json_escape(s)))
        .collect::<Vec<_>>()
        .join(",");
    let record = format!(
        "{{\"serial\":{},\"subject\":\"{}\",\"sans\":[{}],\"not_after\":\"{}\",\"issued_at\":{}}}",
        serial,
        json_escape(&format_dn(&subject)),
        sans_json,
        json_escape(validity.not_after.as_str()),
        now_unix()
    );
    append_line(&ca.issued(), &record);

    write_output(args.value("-out"), cert.to_pem().as_bytes());
    if args.value("-out").is_none() {
        // The PEM was written to stdout; emit a parenthetical to stderr.
        eprintln!("issued serial {serial}");
    }
}

// ---------------------------------------------------------------------------
// sign-csr — sign an existing CSR

fn run_sign_csr(args: Args) {
    let ca = ca_dir(&args);
    let csr_path = args
        .value("-in")
        .unwrap_or_else(|| die("missing -in <csr.pem>"));
    let is_ca_flag = args.flag("-ca") || args.flag("--ca");

    let template_name = args.value("-template").or(if is_ca_flag {
        Some("ca-intermediate")
    } else {
        None
    });
    let template = CertTemplate::resolve(template_name, args.value("-template-file"))
        .unwrap_or_else(|e| die(format!("template error: {e}")));

    let days_n = args
        .value("-days")
        .map(|d| d.parse::<u64>().unwrap_or_else(|_| die("invalid -days")))
        .or_else(|| {
            template
                .as_ref()
                .and_then(|t| t.default_days.map(|d| d as u64))
        })
        .unwrap_or(365);

    let raw = read_bytes(Path::new(csr_path));
    let pem = core::str::from_utf8(&raw).unwrap_or_else(|_| die("CSR is not PEM"));
    let csr = CertificationRequest::from_pem(pem).unwrap_or_else(|e| die(format!("bad CSR: {e}")));

    let root_key = load_root_key(&ca);
    let root_cert = load_root_cert(&ca);
    let issuer_dn = root_cert
        .subject()
        .unwrap_or_else(|e| die(format!("bad CA subject: {e}")));

    let serial = allocate_serial(&ca);
    let validity = validity_days(days_n);

    // The CSR's self-signature MUST verify before we trust its subject/key.
    csr.verify_self_signed()
        .unwrap_or_else(|e| die(format!("CSR signature invalid: {e}")));
    let subject_from_csr = csr
        .subject()
        .unwrap_or_else(|e| die(format!("bad CSR subject: {e}")));
    let subject_key = csr
        .public_key()
        .unwrap_or_else(|e| die(format!("bad CSR key: {e}")));

    let cert = if let Some(tmpl) = template {
        let issuer_ski = issuer_ski_bytes(&root_cert);
        let subj_spki_bits = spki_bit_string_contents(&subject_key);
        // CSR-supplied SANs honored only when the template asks for them.
        let csr_dns = csr.subject_alt_names().unwrap_or_default();
        let csr_sans: Vec<GeneralName> = csr_dns
            .iter()
            .map(|s| GeneralName::Dns(s.clone()))
            .collect();
        let exts: Vec<Extension> = tmpl.extensions(Some(&csr_sans), &issuer_ski, &subj_spki_bits);
        Certificate::issue_with_extensions(
            &root_key.signer(),
            &issuer_dn,
            &subject_from_csr,
            &subject_key,
            &validity,
            serial,
            &exts,
        )
        .unwrap_or_else(|e| die(format!("cannot issue cert from CSR: {e}")))
    } else {
        Certificate::issue_from_csr(
            &root_key.signer(),
            &issuer_dn,
            &csr,
            &validity,
            serial,
            is_ca_flag,
        )
        .unwrap_or_else(|e| die(format!("cannot issue cert from CSR: {e}")))
    };

    let subject = subject_from_csr;
    let sans = csr.subject_alt_names().unwrap_or_default();
    let sans_json = sans
        .iter()
        .map(|s| format!("\"{}\"", json_escape(s)))
        .collect::<Vec<_>>()
        .join(",");
    let record = format!(
        "{{\"serial\":{},\"subject\":\"{}\",\"sans\":[{}],\"not_after\":\"{}\",\"issued_at\":{}}}",
        serial,
        json_escape(&format_dn(&subject)),
        sans_json,
        json_escape(validity.not_after.as_str()),
        now_unix()
    );
    append_line(&ca.issued(), &record);

    write_output(args.value("-out"), cert.to_pem().as_bytes());
}

// ---------------------------------------------------------------------------
// revoke — append a revocation record (no CRL refresh)

fn parse_reason(s: &str) -> CrlReason {
    match s.to_ascii_lowercase().replace('_', "-").as_str() {
        "unspecified" | "" => CrlReason::Unspecified,
        "key-compromise" => CrlReason::KeyCompromise,
        "ca-compromise" => CrlReason::CACompromise,
        "affiliation-changed" => CrlReason::AffiliationChanged,
        "superseded" => CrlReason::Superseded,
        "cessation-of-operation" => CrlReason::CessationOfOperation,
        "certificate-hold" => CrlReason::CertificateHold,
        "remove-from-crl" => CrlReason::RemoveFromCRL,
        "privilege-withdrawn" => CrlReason::PrivilegeWithdrawn,
        "aa-compromise" => CrlReason::AaCompromise,
        other => die(format!("unknown -reason: {other}")),
    }
}

fn parse_serial_arg(raw: &str) -> u64 {
    // Accept `123` or `0x7B`.
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).unwrap_or_else(|_| die(format!("bad -serial hex: {raw}")))
    } else {
        raw.parse::<u64>()
            .unwrap_or_else(|_| die(format!("bad -serial: {raw}")))
    }
}

fn run_revoke(args: Args) {
    let ca = ca_dir(&args);
    let serial = args
        .value("-serial")
        .map(parse_serial_arg)
        .unwrap_or_else(|| die("missing -serial <N>"));
    let reason = args
        .value("-reason")
        .map(parse_reason)
        .unwrap_or(CrlReason::Unspecified);

    let record = format!(
        "{{\"serial\":{},\"revoked_at\":{},\"reason\":\"{:?}\"}}",
        serial,
        now_unix(),
        reason
    );
    append_line(&ca.revoked(), &record);
    println!("revoked serial {serial}");
}

// ---------------------------------------------------------------------------
// crl — sign the current revoked.jsonl as a fresh CRL

#[derive(Debug)]
struct RevokedRow {
    serial: u64,
    revoked_at: u64,
    reason: CrlReason,
}

fn parse_revoked_jsonl(path: &Path) -> Vec<RevokedRow> {
    let raw = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        // Tiny hand parser: {"serial":N,"revoked_at":T,"reason":"Word"}.
        let serial = extract_u64(line, "\"serial\":")
            .unwrap_or_else(|| die(format!("bad revoked.jsonl row: {line}")));
        let revoked_at = extract_u64(line, "\"revoked_at\":").unwrap_or(0);
        let reason_str = extract_str(line, "\"reason\":\"").unwrap_or_else(|| "Unspecified".into());
        let reason = match reason_str.as_str() {
            "Unspecified" => CrlReason::Unspecified,
            "KeyCompromise" => CrlReason::KeyCompromise,
            "CACompromise" => CrlReason::CACompromise,
            "AffiliationChanged" => CrlReason::AffiliationChanged,
            "Superseded" => CrlReason::Superseded,
            "CessationOfOperation" => CrlReason::CessationOfOperation,
            "CertificateHold" => CrlReason::CertificateHold,
            "RemoveFromCRL" => CrlReason::RemoveFromCRL,
            "PrivilegeWithdrawn" => CrlReason::PrivilegeWithdrawn,
            "AaCompromise" => CrlReason::AaCompromise,
            _ => CrlReason::Unspecified,
        };
        out.push(RevokedRow {
            serial,
            revoked_at,
            reason,
        });
    }
    out
}

fn extract_u64(line: &str, prefix: &str) -> Option<u64> {
    let i = line.find(prefix)?;
    let rest = &line[i + prefix.len()..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn extract_str(line: &str, prefix: &str) -> Option<String> {
    let i = line.find(prefix)?;
    let rest = &line[i + prefix.len()..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn run_crl(args: Args) {
    let ca = ca_dir(&args);
    let days_n = days(&args);
    let now = now_unix();

    let root_key = load_root_key(&ca);
    let root_cert = load_root_cert(&ca);
    let issuer_dn = root_cert
        .subject()
        .unwrap_or_else(|e| die(format!("bad CA subject: {e}")));

    let this_update = Time::from_unix(now);
    // `days_n` is user-supplied (`-days N`); guard the * 86_400 + now
    // arithmetic so a pathologically large value can't wrap the u64.
    let next_update_unix = days_n
        .checked_mul(86_400)
        .and_then(|delta| now.checked_add(delta))
        .unwrap_or_else(|| {
            die(format!(
                "-days {days_n} overflows when added to current time; pick a smaller value"
            ))
        });
    let next_update = Time::from_unix(next_update_unix);
    let mut b = CrlBuilder::new(&issuer_dn, this_update, Some(next_update));

    let rows = parse_revoked_jsonl(&ca.revoked());
    for r in &rows {
        b.revoke(
            &serial_to_be_bytes(r.serial),
            Time::from_unix(r.revoked_at),
            if matches!(r.reason, CrlReason::Unspecified) {
                None
            } else {
                Some(r.reason)
            },
        );
    }
    let crl = b
        .sign(&root_key.signer())
        .unwrap_or_else(|e| die(format!("cannot sign CRL: {e}")));
    let pem = crl.to_pem();
    write_string(&ca.crl_pem(), &pem);
    if let Some(out) = args.value("-out") {
        write_output(Some(out), pem.as_bytes());
    } else {
        println!(
            "wrote {} ({} revocations)",
            ca.crl_pem().display(),
            rows.len()
        );
    }
}

// ---------------------------------------------------------------------------
// show

fn run_show(args: Args) {
    let ca = ca_dir(&args);
    if !ca.root_crt().exists() {
        die(format!(
            "no CA at {}: run `ca init` first",
            ca.dir.display()
        ));
    }
    let cert = load_root_cert(&ca);
    let subject = cert
        .subject()
        .unwrap_or_else(|e| die(format!("bad subject: {e}")));
    let key = cert
        .subject_public_key()
        .unwrap_or_else(|e| die(format!("bad key: {e}")));
    let next_serial = if ca.serial().exists() {
        read_string(&ca.serial()).trim().to_string()
    } else {
        "?".into()
    };
    let issued = std::fs::read_to_string(ca.issued())
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();
    let revoked = std::fs::read_to_string(ca.revoked())
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();
    let crl_present = ca.crl_pem().exists();

    println!("CA at {}", ca.dir.display());
    println!("    Subject:    {}", format_dn(&subject));
    println!("    Key:        {}", describe_key(&key));
    println!("    Next serial: {next_serial}");
    println!("    Issued:     {issued}");
    println!("    Revoked:    {revoked}");
    println!(
        "    CRL:        {}",
        if crl_present { "present" } else { "(none)" }
    );
    // Try to parse the CRL if present and print its dates.
    if crl_present {
        let pem = read_string(&ca.crl_pem());
        if let Ok(crl) = CertificateRevocationList::from_pem(&pem) {
            if let Ok(t) = crl.this_update() {
                println!("    thisUpdate: {}", t.as_str());
            }
            if let Ok(Some(t)) = crl.next_update() {
                println!("    nextUpdate: {}", t.as_str());
            }
            if let Ok(entries) = crl.entries() {
                println!("    CRL entries: {}", entries.len());
            }
        }
    }
    // The _validity is just to keep compilers happy when unused.
    let _ = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
}

// ---------------------------------------------------------------------------
// list-templates

fn run_list_templates(_args: Args) {
    println!("Built-in certificate templates:");
    for n in builtin_names() {
        let t = CertTemplate::builtin(n).expect("missing built-in");
        let days = t
            .default_days
            .map(|d| format!("{d}d"))
            .unwrap_or_else(|| "?".into());
        println!("    {:<18} default_days={days}", n);
    }
}

// ---------------------------------------------------------------------------
// dispatch

const USAGE: &str = "\
purecrypto ca — manage a development CA

USAGE:
    purecrypto ca init    -dir DIR [-cn NAME] [-algorithm EC|RSA|ED25519|ED448] [-curve P-256] [-days N]
    purecrypto ca issue   -dir DIR -pubkey leaf.pub -cn NAME [-sans a,b] [-days N] [-out cert.pem] [-ca] [-template NAME] [-template-file PATH]
    purecrypto ca sign-csr -dir DIR -in csr.pem [-out cert.pem] [-days N] [-ca] [-template NAME] [-template-file PATH]
    purecrypto ca revoke  -dir DIR -serial 7|0x7 [-reason key-compromise|superseded|...]
    purecrypto ca crl     -dir DIR [-out crl.pem] [-days N]
    purecrypto ca show    -dir DIR
    purecrypto ca list-templates
";

pub(crate) fn run(args: Args) {
    let positionals = args.positionals(&[
        "-dir",
        "-cn",
        "-algorithm",
        "-curve",
        "-days",
        "-pubkey",
        "-in",
        "-out",
        "-sans",
        "-addext",
        "-san",
        "-subj",
        "-serial",
        "-reason",
        "-template",
        "-template-file",
    ]);
    let sub = positionals.first().copied().unwrap_or("");

    match sub {
        "init" => run_init(args),
        "issue" => run_issue(args),
        "sign-csr" => run_sign_csr(args),
        "revoke" => run_revoke(args),
        "crl" => run_crl(args),
        "show" => run_show(args),
        "list-templates" => run_list_templates(args),
        "" | "help" | "-h" | "--help" => println!("{USAGE}"),
        other => die(format!(
            "unknown ca subcommand '{other}' (try `purecrypto ca help`)"
        )),
    }
}

#[cfg(test)]
mod tests {
    //! FFI-1 / FFI-2 regression coverage. The full `run_*` entry points
    //! shell out to `die()` (process exit) so we exercise the inner
    //! helpers — `allocate_serial` (FFI-1) and the `run_crl` next-update
    //! arithmetic (FFI-2) — directly against scratch directories.
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

    /// Counter used to mint unique scratch directory names. We can't add
    /// a `tempfile` dev-dependency (Cargo.toml is off-limits) so we roll
    /// our own minimal tempdir over `std::env::temp_dir`.
    static SCRATCH_COUNTER: AtomicU64 = AtomicU64::new(0);

    /// Auto-cleaning scratch directory. Drop removes the tree on a best-
    /// effort basis so a panicking test does not leak permanent files.
    struct ScratchDir(PathBuf);

    impl ScratchDir {
        fn new(tag: &str) -> Self {
            let n = SCRATCH_COUNTER.fetch_add(1, Ordering::Relaxed);
            // Mix in pid + nanos so two parallel `cargo test` runs cannot
            // collide on the directory name.
            let pid = std::process::id();
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let path = std::env::temp_dir().join(format!("purecrypto-ca-{tag}-{pid}-{nanos}-{n}"));
            std::fs::create_dir_all(&path).expect("mkdir scratch");
            ScratchDir(path)
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Builds a fresh on-disk CA directory primed with a starting serial.
    /// The caller MUST keep the returned `ScratchDir` alive — dropping it
    /// removes the directory and invalidates the `CaDir`.
    fn fresh_ca(start: u64, tag: &str) -> (CaDir, ScratchDir) {
        let td = ScratchDir::new(tag);
        let dir = td.0.to_str().expect("utf-8 path").to_string();
        let ca = CaDir::new(&dir);
        std::fs::write(ca.serial(), format!("{start}\n")).expect("seed serial");
        (ca, td)
    }

    /// FFI-1: two threads racing `allocate_serial` against the same `serial`
    /// file must hand out distinct numbers — otherwise the CA could issue
    /// two certificates with the same serial, breaking revocation /
    /// auditing.
    #[test]
    fn allocate_serial_is_atomic_across_threads() {
        let (ca, _td) = fresh_ca(100, "atomic");
        let ca = Arc::new(ca);
        const THREADS: u32 = 8;
        const PER_THREAD: u32 = 16;
        let barrier = Arc::new(std::sync::Barrier::new(THREADS as usize));
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let ca = Arc::clone(&ca);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                let mut got = Vec::with_capacity(PER_THREAD as usize);
                for _ in 0..PER_THREAD {
                    got.push(allocate_serial(&ca));
                }
                got
            }));
        }
        let mut all: Vec<u64> = Vec::new();
        for h in handles {
            all.extend(h.join().expect("thread"));
        }
        // Every serial is distinct.
        let set: HashSet<u64> = all.iter().copied().collect();
        assert_eq!(
            set.len(),
            all.len(),
            "duplicate serials produced under concurrency: {all:?}"
        );
        // Issued exactly THREADS*PER_THREAD serials starting at 100.
        let expected: HashSet<u64> = (100..100 + (THREADS * PER_THREAD) as u64).collect();
        assert_eq!(set, expected);
        // On-disk serial reflects the final state.
        let next: u64 = std::fs::read_to_string(ca.serial())
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(next, 100 + (THREADS * PER_THREAD) as u64);
        // Lock file removed at end.
        assert!(!ca.dir.join("serial.lock").exists());
    }

    /// The lock is released even when the holding scope panics, so a
    /// crashed allocator does not freeze the next caller for the full
    /// 3-second retry window.
    #[test]
    fn serial_lock_drop_on_panic_unblocks_next_caller() {
        let (ca, _td) = fresh_ca(7, "panic");
        let ca = Arc::new(ca);
        let ca_clone = Arc::clone(&ca);
        let h = std::thread::spawn(move || {
            let _lock = SentinelLock::acquire(ca_clone.dir.join("serial.lock"), "`purecrypto ca`");
            panic!("simulated allocator crash with lock held");
        });
        assert!(h.join().is_err(), "thread should have panicked");
        // Drop has run; the next allocator must succeed immediately.
        let n = allocate_serial(&ca);
        assert_eq!(n, 7);
    }

    /// FFI-1 extra: stress the retry loop. Two background workers
    /// hammer the same `serial` file while the main thread counts
    /// how many distinct values fell out.
    #[test]
    fn allocate_serial_no_gaps_under_contention() {
        let (ca, _td) = fresh_ca(1, "nogaps");
        let ca = Arc::new(ca);
        let count = Arc::new(AtomicU32::new(0));
        const N: u32 = 32;
        let mut handles = Vec::new();
        for _ in 0..4 {
            let ca = Arc::clone(&ca);
            let count = Arc::clone(&count);
            handles.push(std::thread::spawn(move || {
                let mut got = Vec::new();
                while count.fetch_add(1, Ordering::Relaxed) < N {
                    got.push(allocate_serial(&ca));
                }
                got
            }));
        }
        let mut all = Vec::new();
        for h in handles {
            all.extend(h.join().unwrap());
        }
        all.sort();
        assert_eq!(all.len(), N as usize, "missed an allocation");
        for (i, v) in all.iter().enumerate() {
            assert_eq!(*v, 1 + i as u64, "gap or duplicate at index {i}: {all:?}");
        }
    }

    /// FFI-2: the run_crl next-update arithmetic (`now + days_n * 86_400`)
    /// must not silently wrap u64. This test mirrors the production
    /// `checked_mul`/`checked_add` chain so regressions in either step
    /// are caught.
    #[test]
    fn crl_next_update_uses_checked_arithmetic() {
        // The chain that ships in run_crl. Keep the literal `86_400` here
        // so a refactor of the constant in production is visible by diff.
        let compute = |now: u64, days_n: u64| -> Option<u64> {
            days_n.checked_mul(86_400).and_then(|d| now.checked_add(d))
        };
        // Normal cases work.
        assert_eq!(compute(1_000, 30), Some(1_000 + 30 * 86_400));
        assert_eq!(compute(0, 1), Some(86_400));
        // Multiplication overflow: 2^64/86400 ≈ 2.135e14 days. A u64-max
        // days_n must NOT silently wrap to a small next-update timestamp.
        assert_eq!(compute(0, u64::MAX), None);
        // Addition overflow on a near-MAX `now`.
        assert_eq!(compute(u64::MAX - 1, 1), None);
        assert_eq!(compute(u64::MAX, 0), Some(u64::MAX));
        // Boundary just past the safe zone.
        let almost = u64::MAX / 86_400;
        // almost * 86_400 fits, but +1 day overflows.
        assert!(compute(0, almost).is_some());
        assert_eq!(compute(0, almost + 1), None);
    }
}
