//! `purecrypto req` — create or inspect a PKCS#10 certificate request.

use crate::pki::{describe_key, format_dn, load_key, parse_sans, parse_subject};
use crate::template::CertTemplate;
use crate::util::{Args, die, read_input, write_output};
use purecrypto::x509::CertificationRequest;
use purecrypto::x509::extension::{Extension, GeneralName};

fn sans_from_args(args: &Args) -> Vec<String> {
    if let Some(ext) = args.value("-addext").or_else(|| args.value("--addext")) {
        parse_sans(ext)
    } else if let Some(list) = args.value("-san").or_else(|| args.value("--san")) {
        parse_sans(list)
    } else {
        Vec::new()
    }
}

pub(crate) fn run(args: Args) {
    // Inspect mode: -in <csr>.
    if let Some(path) = args.value("-in").or_else(|| args.value("--in")) {
        let raw = read_input(Some(path));
        let pem = core::str::from_utf8(&raw).unwrap_or_else(|_| die("CSR is not PEM"));
        let csr = CertificationRequest::from_pem(pem)
            .unwrap_or_else(|e| die(format!("cannot parse CSR: {e}")));

        if args.flag("-verify") || args.flag("--verify") {
            match csr.verify_self_signed() {
                Ok(()) => println!("certificate request self-signature verify OK"),
                Err(_) => die("certificate request signature is INVALID"),
            }
            return;
        }

        let subject = csr
            .subject()
            .unwrap_or_else(|e| die(format!("bad subject: {e}")));
        let key = csr
            .public_key()
            .unwrap_or_else(|e| die(format!("bad key: {e}")));
        let sans = csr.subject_alt_names().unwrap_or_default();
        println!("Certificate Request:");
        println!("    Subject: {}", format_dn(&subject));
        println!("    Public Key: {}", describe_key(&key));
        if !sans.is_empty() {
            println!("    Subject Alternative Names: {}", sans.join(", "));
        }
        return;
    }

    // Create mode: -key + -subj.
    let key_path = args
        .value("-key")
        .or_else(|| args.value("--key"))
        .unwrap_or_else(|| die("usage: purecrypto req -key <key.pem> -subj \"/CN=...\" [-addext subjectAltName=DNS:...] [-template tls-server] [-template-file path.toml] [-out csr.pem]"));
    let subj = args
        .value("-subj")
        .or_else(|| args.value("--subj"))
        .unwrap_or_else(|| die("missing -subj"));

    let key = load_key(key_path);
    let subject = parse_subject(subj);
    let sans = sans_from_args(&args);

    let template = CertTemplate::resolve(args.value("-template"), args.value("-template-file"))
        .unwrap_or_else(|e| die(format!("template error: {e}")));

    let csr = if let Some(tmpl) = template {
        // The template owns the extension policy; argv SANs are merged in.
        let csr_sans: Vec<GeneralName> = sans.iter().map(|s| GeneralName::Dns(s.clone())).collect();
        // For a CSR there's no issuer SKI / subject SPKI binding needed yet:
        // the template's extensions() builder will skip SKI/AKI when those
        // inputs are empty.
        let exts: Vec<Extension> = tmpl.extensions(Some(&csr_sans), &[], &[]);
        CertificationRequest::create_with_extensions(&key.signer(), &subject, &exts)
            .unwrap_or_else(|e| die(format!("cannot create CSR: {e}")))
    } else {
        let san_refs: Vec<&str> = sans.iter().map(String::as_str).collect();
        CertificationRequest::create(&key.signer(), &subject, &san_refs)
            .unwrap_or_else(|e| die(format!("cannot create CSR: {e}")))
    };
    write_output(args.value("-out"), csr.to_pem().as_bytes());
}

#[cfg(target_vendor = "fullrust")]
#[allow(unused_imports)]
use crate::__prelude::*;
