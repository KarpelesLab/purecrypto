//! `purecrypto crl -in FILE [-text | -CAfile CA -verify | -serial SERIAL -is-revoked]`

use crate::pki::format_dn;
use crate::util::{Args, die, from_hex, read_input};
use purecrypto::x509::{Certificate, CertificateRevocationList};

fn load_crl(path: Option<&str>) -> CertificateRevocationList {
    let raw = read_input(path);
    let s = core::str::from_utf8(&raw).unwrap_or("");
    if s.contains("-----BEGIN") {
        CertificateRevocationList::from_pem(s)
            .unwrap_or_else(|e| die(format!("could not parse CRL PEM: {e}")))
    } else {
        CertificateRevocationList::from_der(raw)
            .unwrap_or_else(|e| die(format!("could not parse CRL DER: {e}")))
    }
}

fn text(crl: &CertificateRevocationList) {
    let issuer = crl
        .issuer()
        .unwrap_or_else(|e| die(format!("bad issuer: {e}")));
    let this = crl
        .this_update()
        .unwrap_or_else(|e| die(format!("bad thisUpdate: {e}")));
    let next = crl
        .next_update()
        .unwrap_or_else(|e| die(format!("bad nextUpdate: {e}")));
    println!("Certificate Revocation List:");
    println!("    Issuer:      {}", format_dn(&issuer));
    println!("    This Update: {}", this.as_str());
    if let Some(n) = next {
        println!("    Next Update: {}", n.as_str());
    }
    let entries = crl
        .entries()
        .unwrap_or_else(|e| die(format!("bad entries: {e}")));
    println!("    Revoked entries: {}", entries.len());
    for e in &entries {
        let serial_hex = e.serial.iter().fold(String::new(), |mut s, b| {
            s.push_str(&format!("{b:02x}"));
            s
        });
        match e.reason {
            Some(r) => println!(
                "        serial={serial_hex} date={} reason={:?}",
                e.revocation_date.as_str(),
                r
            ),
            None => println!(
                "        serial={serial_hex} date={}",
                e.revocation_date.as_str()
            ),
        }
    }
}

fn verify(crl: &CertificateRevocationList, ca_path: &str) {
    let ca_pem =
        std::fs::read(ca_path).unwrap_or_else(|e| die(format!("cannot read {ca_path}: {e}")));
    let ca_pem = core::str::from_utf8(&ca_pem).unwrap_or_else(|_| die("CA file is not UTF-8 PEM"));
    let ca =
        Certificate::from_pem(ca_pem).unwrap_or_else(|e| die(format!("cannot parse CA cert: {e}")));
    let key = ca
        .subject_public_key()
        .unwrap_or_else(|e| die(format!("CA has no public key: {e}")));
    match crl.verify_signature_with(&key) {
        Ok(()) => println!("verify OK"),
        Err(_) => {
            eprintln!("verify FAIL");
            std::process::exit(1);
        }
    }
}

fn is_revoked(crl: &CertificateRevocationList, serial_arg: &str) {
    // Accept decimal, hex (with `:` / no separators), or `0x...` prefix.
    let serial_bytes = if let Some(rest) = serial_arg.strip_prefix("0x") {
        from_hex(rest).unwrap_or_else(|| die(format!("invalid serial hex: {serial_arg}")))
    } else if serial_arg.bytes().all(|b| b.is_ascii_digit()) {
        let n: u128 = serial_arg
            .parse()
            .unwrap_or_else(|_| die(format!("invalid serial: {serial_arg}")));
        let mut out = n.to_be_bytes().to_vec();
        while out.len() > 1 && out[0] == 0 {
            out.remove(0);
        }
        out
    } else {
        let cleaned: String = serial_arg.chars().filter(|c| *c != ':').collect();
        from_hex(&cleaned).unwrap_or_else(|| die(format!("invalid serial hex: {serial_arg}")))
    };
    let revoked = crl
        .is_revoked(&serial_bytes)
        .unwrap_or_else(|e| die(format!("CRL parse error: {e}")));
    if revoked {
        println!("revoked");
    } else {
        println!("not revoked");
        std::process::exit(1);
    }
}

pub(crate) fn run(args: Args) {
    let in_path = args.value("-in").or_else(|| args.value("--in"));
    let crl = load_crl(in_path);
    if args.flag("-text") || args.flag("--text") {
        text(&crl);
        return;
    }
    if args.flag("-verify") || args.flag("--verify") {
        let ca = args
            .value("-CAfile")
            .or_else(|| args.value("--CAfile"))
            .or_else(|| args.value("-cafile"))
            .unwrap_or_else(|| die("-verify requires -CAfile CA.pem"));
        verify(&crl, ca);
        return;
    }
    if args.flag("-is-revoked") || args.flag("--is-revoked") {
        let serial = args
            .value("-serial")
            .or_else(|| args.value("--serial"))
            .unwrap_or_else(|| die("-is-revoked requires -serial SERIAL"));
        is_revoked(&crl, serial);
        return;
    }
    die("usage: purecrypto crl -in FILE [-text | -CAfile FILE -verify | -serial S -is-revoked]");
}

#[cfg(target_vendor = "fullrust")]
#[allow(unused_imports)]
use crate::__prelude::*;
