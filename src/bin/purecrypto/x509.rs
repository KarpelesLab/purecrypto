//! `purecrypto x509` — inspect, self-sign, or CA-sign certificates.

use crate::pki::{
    Profile, default_extensions, describe_key, dns_general_names, format_dn, load_key, parse_sans,
    parse_subject, random_serial, validity_days, verify_and_screen_csr,
};
use crate::util::{Args, die, read_input, write_output};
use purecrypto::x509::extension::Extension;
use purecrypto::x509::{Certificate, CertificationRequest, oid};

fn days(args: &Args) -> u64 {
    args.value("-days")
        .or_else(|| args.value("--days"))
        .map(|d| d.parse().unwrap_or_else(|_| die("invalid -days")))
        .unwrap_or(365)
}

fn serial(args: &Args) -> u64 {
    args.value("-set_serial")
        .map(|s| s.parse().unwrap_or_else(|_| die("invalid -set_serial")))
        .unwrap_or_else(random_serial)
}

fn sans_from_args(args: &Args) -> Vec<String> {
    args.value("-addext")
        .or_else(|| args.value("--addext"))
        .or_else(|| args.value("-san"))
        .map(parse_sans)
        .unwrap_or_default()
}

/// The subjectAltName list `x509 -req` will certify.
///
/// A CSR's requested `subjectAltName` is the requester's claim, not a
/// verified fact: copying it verbatim (which is what
/// `Certificate::issue_from_csr` does) turns a request for
/// `DNS:www.google.com` into a chain-valid certificate for that name. So the
/// operator's own `-san`/`-addext` wins, the request's list is used only
/// behind `-copy-csr-san`, and a loud warning names every copied entry.
fn resolve_req_sans(args: &Args, csr: &CertificationRequest) -> Vec<String> {
    let explicit = sans_from_args(args);
    if !explicit.is_empty() {
        return explicit;
    }
    let requested = csr.subject_alt_names().unwrap_or_default();
    if requested.is_empty() {
        return Vec::new();
    }
    if args.flag("-copy-csr-san") || args.flag("--copy-csr-san") || args.flag("-allow-csr-san") {
        eprintln!(
            "purecrypto: WARNING: -copy-csr-san given — certifying {} subjectAltName(s) \
             claimed by the request without any verification: {}",
            requested.len(),
            requested.join(", ")
        );
        return requested;
    }
    eprintln!(
        "purecrypto: note: ignoring {} subjectAltName(s) requested by the CSR ({}); \
         pass -san NAME[,NAME] to certify names you have verified, or -copy-csr-san \
         to take the request's list as-is",
        requested.len(),
        requested.join(", ")
    );
    Vec::new()
}

/// Prints a human-readable certificate summary. When `with_ext` is true,
/// every v3 extension is dumped (oid + critical bit + a short decoded
/// summary for the well-known kinds, raw hex for unknown ones).
fn dump(cert: &Certificate, with_ext: bool) {
    let subject = cert
        .subject()
        .unwrap_or_else(|e| die(format!("bad subject: {e}")));
    let issuer = cert
        .issuer()
        .unwrap_or_else(|e| die(format!("bad issuer: {e}")));
    let validity = cert
        .validity()
        .unwrap_or_else(|e| die(format!("bad validity: {e}")));
    let key = cert
        .subject_public_key()
        .unwrap_or_else(|e| die(format!("bad key: {e}")));
    let sans = cert.subject_alt_names().unwrap_or_default();
    println!("Certificate:");
    println!("    Subject:   {}", format_dn(&subject));
    println!("    Issuer:    {}", format_dn(&issuer));
    println!("    Not Before: {}", validity.not_before.as_str());
    println!("    Not After:  {}", validity.not_after.as_str());
    println!("    Public Key: {}", describe_key(&key));
    if !sans.is_empty() {
        println!("    Subject Alternative Names: {}", sans.join(", "));
    }
    if with_ext {
        match cert.extensions() {
            Ok(exts) => print_extensions(&exts),
            Err(e) => println!("    (could not read extensions: {e})"),
        }
    }
}

fn print_extensions(exts: &[Extension]) {
    if exts.is_empty() {
        return;
    }
    println!("    X509v3 extensions:");
    for e in exts {
        let oid_str = e
            .oid
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join(".");
        let label = friendly_oid(&e.oid);
        let crit = if e.critical { ", critical" } else { "" };
        match decode_known_extension(e) {
            Some(body) => {
                println!("        {label} ({oid_str}{crit}):");
                for line in body.lines() {
                    println!("            {line}");
                }
            }
            None => {
                println!("        {label} ({oid_str}{crit}):");
                println!("            {}", hex(&e.value));
            }
        }
    }
}

fn friendly_oid(arcs: &[u64]) -> String {
    match arcs {
        a if a == oid::BASIC_CONSTRAINTS => "basicConstraints".into(),
        a if a == oid::KEY_USAGE => "keyUsage".into(),
        a if a == oid::EXT_KEY_USAGE => "extendedKeyUsage".into(),
        a if a == oid::SUBJECT_ALT_NAME => "subjectAltName".into(),
        a if a == oid::SUBJECT_KEY_IDENTIFIER => "subjectKeyIdentifier".into(),
        a if a == oid::AUTHORITY_KEY_IDENTIFIER => "authorityKeyIdentifier".into(),
        a if a == oid::NAME_CONSTRAINTS => "nameConstraints".into(),
        a if a == oid::CERTIFICATE_POLICIES => "certificatePolicies".into(),
        a if a == oid::CRL_DISTRIBUTION_POINTS => "cRLDistributionPoints".into(),
        _ => "extension".into(),
    }
}

fn decode_known_extension(e: &Extension) -> Option<String> {
    use purecrypto::der::{Reader, parse_oid, tag};
    if e.oid == oid::BASIC_CONSTRAINTS {
        let mut r = Reader::new(&e.value);
        let mut seq = r.read_sequence().ok()?;
        let is_ca = if seq.peek_tag() == Some(tag::BOOLEAN) {
            seq.read_boolean().ok()?
        } else {
            false
        };
        let mut s = format!("CA: {is_ca}");
        if !seq.is_empty() {
            let _ = seq.read_unsigned_integer_bytes(); // pathLen — best effort
            s.push_str(" (pathLen present)");
        }
        return Some(s);
    }
    if e.oid == oid::KEY_USAGE {
        let mut r = Reader::new(&e.value);
        let raw = r.read_tlv(tag::BIT_STRING).ok()?;
        if raw.is_empty() {
            return None;
        }
        let bytes = &raw[1..];
        let mut mask: u16 = 0;
        if let Some(b) = bytes.first() {
            mask |= *b as u16;
        }
        if let Some(b) = bytes.get(1) {
            mask |= (*b as u16) << 8;
        }
        let pairs: &[(u16, &str)] = &[
            (0x80, "digitalSignature"),
            (0x40, "nonRepudiation"),
            (0x20, "keyEncipherment"),
            (0x10, "dataEncipherment"),
            (0x08, "keyAgreement"),
            (0x04, "keyCertSign"),
            (0x02, "cRLSign"),
            (0x01, "encipherOnly"),
            (0x80_00, "decipherOnly"),
        ];
        let names: Vec<&str> = pairs
            .iter()
            .filter_map(|(b, n)| if mask & b != 0 { Some(*n) } else { None })
            .collect();
        return Some(names.join(", "));
    }
    if e.oid == oid::EXT_KEY_USAGE {
        let mut r = Reader::new(&e.value);
        let mut seq = r.read_sequence().ok()?;
        let mut names: Vec<String> = Vec::new();
        while !seq.is_empty() {
            let raw = seq.read_oid().ok()?;
            let arcs = parse_oid(raw).ok()?;
            names.push(match arcs.as_slice() {
                a if a == oid::ID_KP_SERVER_AUTH => "serverAuth".into(),
                a if a == oid::ID_KP_CLIENT_AUTH => "clientAuth".into(),
                a if a == oid::ID_KP_CODE_SIGNING => "codeSigning".into(),
                a if a == oid::ID_KP_EMAIL_PROTECTION => "emailProtection".into(),
                a if a == oid::ID_KP_TIME_STAMPING => "timeStamping".into(),
                a if a == oid::ID_KP_OCSP_SIGNING => "ocspSigning".into(),
                _ => arcs
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join("."),
            });
        }
        return Some(names.join(", "));
    }
    if e.oid == oid::SUBJECT_ALT_NAME {
        let mut r = Reader::new(&e.value);
        let mut seq = r.read_sequence().ok()?;
        let mut parts = Vec::new();
        while !seq.is_empty() {
            let (t, v) = seq.read_any().ok()?;
            match t {
                0x82 => parts.push(format!("DNS:{}", String::from_utf8_lossy(v))),
                0x81 => parts.push(format!("email:{}", String::from_utf8_lossy(v))),
                0x86 => parts.push(format!("URI:{}", String::from_utf8_lossy(v))),
                0x87 => parts.push(format!("IP:{}", hex(v))),
                _ => parts.push(format!("tag-{t:#x}")),
            }
        }
        return Some(parts.join(", "));
    }
    if e.oid == oid::SUBJECT_KEY_IDENTIFIER {
        let mut r = Reader::new(&e.value);
        let ki = r.read_octet_string().ok()?;
        return Some(hex(ki));
    }
    if e.oid == oid::AUTHORITY_KEY_IDENTIFIER {
        let mut r = Reader::new(&e.value);
        let mut seq = r.read_sequence().ok()?;
        // First entry, if present, is [0] IMPLICIT OCTET STRING.
        if seq.peek_tag() == Some(0x80) {
            let ki = seq.read_tlv(0x80).ok()?;
            return Some(format!("keyid: {}", hex(ki)));
        }
        return Some("(empty)".into());
    }
    None
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 3);
    for (i, b) in bytes.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        let hi = b >> 4;
        let lo = b & 0xf;
        s.push(hex_digit(hi));
        s.push(hex_digit(lo));
    }
    s
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => '?',
    }
}

pub(crate) fn run(args: Args) {
    let is_ca = args.flag("--ca") || args.flag("-ca");

    // CA-sign a CSR: -req -in csr -CA cert -CAkey key.
    if args.flag("-req") || args.flag("--req") {
        let csr_path = args
            .value("-in")
            .unwrap_or_else(|| die("missing -in <csr.pem>"));
        let ca_path = args
            .value("-CA")
            .unwrap_or_else(|| die("missing -CA <ca.pem>"));
        let cakey_path = args
            .value("-CAkey")
            .unwrap_or_else(|| die("missing -CAkey <cakey.pem>"));

        let raw = read_input(Some(csr_path));
        let csr = CertificationRequest::from_pem(
            core::str::from_utf8(&raw).unwrap_or_else(|_| die("CSR is not PEM")),
        )
        .unwrap_or_else(|e| die(format!("cannot parse CSR: {e}")));

        let ca_raw = std::fs::read(ca_path).unwrap_or_else(|e| die(format!("read {ca_path}: {e}")));
        let ca = Certificate::from_pem(
            core::str::from_utf8(&ca_raw).unwrap_or_else(|_| die("CA is not PEM")),
        )
        .unwrap_or_else(|e| die(format!("cannot parse CA cert: {e}")));
        let issuer = ca
            .subject()
            .unwrap_or_else(|e| die(format!("bad CA subject: {e}")));

        // Verify the request's self-signature and screen it against the same
        // policy `ca sign-csr` applies (no SHA-1/MD5 signature, RSA >= 2048).
        verify_and_screen_csr(&csr);
        let subject = csr
            .subject()
            .unwrap_or_else(|e| die(format!("bad CSR subject: {e}")));
        let subject_key = csr
            .public_key()
            .unwrap_or_else(|e| die(format!("bad CSR key: {e}")));

        // `Certificate::issue_from_csr` would certify the request's own
        // subjectAltName list verbatim and, under `-ca`, emit nothing but
        // `basicConstraints{CA:true}` — an unconstrained sub-CA with no
        // pathLen and no keyUsage. Build the extensions here instead:
        //   * SANs come from the operator's `-san`/`-addext`, or from the
        //     request only behind `-copy-csr-san` (with a stderr warning);
        //   * `default_extensions` pins pathLen 0 + keyCertSign/cRLSign for
        //     `-ca`, and keyUsage + EKU for a leaf.
        let sans = resolve_req_sans(&args, &csr);
        let profile = if is_ca { Profile::SubCa } else { Profile::Leaf };
        let exts = default_extensions(profile, &dns_general_names(&sans));
        let cakey = load_key(cakey_path);
        let cert = Certificate::issue_with_extensions(
            &cakey.signer(),
            &issuer,
            &subject,
            &subject_key,
            &validity_days(days(&args)),
            serial(&args),
            &exts,
        )
        .unwrap_or_else(|e| die(format!("cannot issue certificate: {e}")));
        write_output(args.value("-out"), cert.to_pem().as_bytes());
        return;
    }

    // Self-sign a new certificate: -new -key key -subj "/CN=...".
    if args.flag("-new") || args.flag("--new") {
        let key_path = args
            .value("-key")
            .unwrap_or_else(|| die("missing -key <key.pem>"));
        let subj = args.value("-subj").unwrap_or_else(|| die("missing -subj"));
        let key = load_key(key_path);
        let subject = parse_subject(subj);
        let sans = sans_from_args(&args);
        // Same constrained default profile as the CA paths: an absent
        // keyUsage means "any purpose" under RFC 5280 §4.2.1.3. A self-signed
        // `-ca` is a root, so it keeps keyCertSign/cRLSign but takes no
        // pathLen bound (it must be able to sign intermediates).
        let profile = if is_ca {
            Profile::RootCa
        } else {
            Profile::Leaf
        };
        let exts = default_extensions(profile, &dns_general_names(&sans));
        let cert = Certificate::self_signed_with_extensions(
            &key.signer(),
            &subject,
            &validity_days(days(&args)),
            serial(&args),
            &exts,
        )
        .unwrap_or_else(|e| die(format!("cannot self-sign: {e}")));
        write_output(args.value("-out"), cert.to_pem().as_bytes());
        return;
    }

    // Inspect: -in cert.
    let path = args.value("-in").unwrap_or_else(|| {
        die(
            "usage:\n  \
             purecrypto x509 -in <cert.pem> -text [-ext]\n  \
             purecrypto x509 -new -key <key.pem> -subj /CN=... [-san a,b] [-days N] [-ca] [-out f]\n  \
             purecrypto x509 -req -in <csr.pem> -CA <ca.pem> -CAkey <cakey.pem> [-san a,b] \
             [-copy-csr-san] [-days N] [-ca] [-out f]\n\n\
             A CSR's requested subjectAltName is NOT certified unless -copy-csr-san is given; \
             name the SANs with -san instead. -ca emits a pathLen:0 sub-CA with \
             keyUsage=keyCertSign,cRLSign.",
        )
    });
    let raw = read_input(Some(path));
    let cert = Certificate::from_pem(
        core::str::from_utf8(&raw).unwrap_or_else(|_| die("cert is not PEM")),
    )
    .unwrap_or_else(|e| die(format!("cannot parse certificate: {e}")));
    let with_ext = args.flag("-ext") || args.flag("--ext");
    dump(&cert, with_ext);
}
