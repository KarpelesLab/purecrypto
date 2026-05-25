//! `purecrypto x509` — inspect, self-sign, or CA-sign certificates.

use crate::pki::{
    describe_key, format_dn, load_key, parse_sans, parse_subject, random_serial, validity_days,
};
use crate::util::{Args, die, read_input, write_output};
use purecrypto::x509::{Certificate, CertificationRequest};

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

/// Prints a human-readable certificate summary.
fn dump(cert: &Certificate) {
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

        let cakey = load_key(cakey_path);
        let cert = Certificate::issue_from_csr(
            &cakey.signer(),
            &issuer,
            &csr,
            &validity_days(days(&args)),
            serial(&args),
            is_ca,
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
        let san_refs: Vec<&str> = sans.iter().map(String::as_str).collect();
        let cert = Certificate::self_signed_general(
            &key.signer(),
            &subject,
            &validity_days(days(&args)),
            serial(&args),
            is_ca,
            &san_refs,
        )
        .unwrap_or_else(|e| die(format!("cannot self-sign: {e}")));
        write_output(args.value("-out"), cert.to_pem().as_bytes());
        return;
    }

    // Inspect: -in cert.
    let path = args.value("-in").unwrap_or_else(|| {
        die("usage: purecrypto x509 -in <cert.pem> -text | -new ... | -req ...")
    });
    let raw = read_input(Some(path));
    let cert = Certificate::from_pem(
        core::str::from_utf8(&raw).unwrap_or_else(|_| die("cert is not PEM")),
    )
    .unwrap_or_else(|e| die(format!("cannot parse certificate: {e}")));
    dump(&cert);
}
