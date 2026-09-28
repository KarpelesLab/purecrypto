//! `purecrypto pkcs12` — build or unpack a PKCS#12 / PFX archive (RFC 7292),
//! the `.p12` bundle of a private key and its certificate chain that the
//! platform TLS stacks (Apple's Security framework, Windows SChannel) import
//! identities from.
//!
//! ```text
//! purecrypto pkcs12 -export -inkey key.pem -in cert.pem [-certfile chain.pem]
//!                   [-name LABEL] -passout pass:PW -out id.p12
//! purecrypto pkcs12 -in id.p12 -passin pass:PW [-nokeys] [-nocerts] [-info] [-out out.pem]
//! ```

use crate::util::{
    Args, die, read_secret_file, warn_if_world_readable_key, write_output, write_output_with_mode,
    zero_buf,
};
use purecrypto::der::{pem_decode, pem_encode};
use purecrypto::ec::BoxedEcdsaPrivateKey;
use purecrypto::pkcs12::Pfx;
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::x509::{AnyPrivateKey, Certificate, Pkcs8ReadOptions};

const USAGE: &str = "\
usage: purecrypto pkcs12 -export -inkey key.pem -in cert.pem [-certfile chain.pem]
                         [-name LABEL] -passout pass:PW -out id.p12
       purecrypto pkcs12 -in id.p12 -passin pass:PW [-nokeys] [-nocerts] [-info] [-out out.pem]

  -export      build an archive from a private key (PKCS#8, PKCS#1 or SEC1 PEM)
               and one or more CERTIFICATE blocks (-in first, then -certfile)
  -passout /   the password, as pass:STRING, env:VARIABLE or file:PATH
  -passin      (the first line of the file)
  -info        print what the archive holds instead of PEM";

/// Resolves an `openssl`-style password source: `pass:STR`, `env:VAR` or
/// `file:PATH` (first line).
fn password(spec: Option<&str>, flag: &str) -> String {
    let spec = spec.unwrap_or_else(|| die(format!("{flag} is required\n{USAGE}")));
    if let Some(p) = spec.strip_prefix("pass:") {
        p.to_string()
    } else if let Some(v) = spec.strip_prefix("env:") {
        std::env::var(v)
            .unwrap_or_else(|_| die(format!("{flag}: environment variable {v} is not set")))
    } else if let Some(path) = spec.strip_prefix("file:") {
        let mut raw = read_secret_file(path);
        let s = String::from_utf8_lossy(&raw)
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        zero_buf(&mut raw);
        s
    } else {
        die(format!(
            "{flag}: expected pass:STRING, env:VARIABLE or file:PATH"
        ))
    }
}

/// The PKCS#8 `PrivateKeyInfo` DER for a private-key PEM in any of the forms
/// the other subcommands accept: PKCS#8 (`PRIVATE KEY`, any algorithm the
/// crate knows), PKCS#1 (`RSA PRIVATE KEY`) or SEC1 (`EC PRIVATE KEY`).
fn pkcs8_from_pem(pem: &str, path: &str) -> Vec<u8> {
    if let Ok(der) = pem_decode(pem, "PRIVATE KEY") {
        AnyPrivateKey::from_pkcs8_der(&der, Pkcs8ReadOptions::new())
            .unwrap_or_else(|e| die(format!("{path}: unsupported PKCS#8 key: {e:?}")));
        return der;
    }
    if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(pem) {
        return k.to_pkcs8_der();
    }
    if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(pem) {
        return k.to_pkcs8_der();
    }
    die(format!(
        "{path}: could not parse the private key (expected a PKCS#8, PKCS#1 or SEC1 PEM)"
    ))
}

/// Every CERTIFICATE block of a PEM file, as DER, in file order.
fn certs_from_pem(path: &str) -> Vec<Vec<u8>> {
    let data =
        std::fs::read_to_string(path).unwrap_or_else(|e| die(format!("cannot read {path}: {e}")));
    let mut out = Vec::new();
    let mut block = String::new();
    let mut in_cert = false;
    for line in data.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            block.clear();
        }
        if in_cert {
            block.push_str(line);
            block.push('\n');
        }
        if line.starts_with("-----END CERTIFICATE-----") {
            in_cert = false;
            let cert = Certificate::from_pem(&block)
                .unwrap_or_else(|_| die(format!("could not parse a certificate in {path}")));
            out.push(cert.to_der().to_vec());
        }
    }
    out
}

fn export(args: &Args) {
    let key_path = args
        .value("-inkey")
        .unwrap_or_else(|| die(format!("-export needs -inkey key.pem\n{USAGE}")));
    let cert_path = args
        .value("-in")
        .unwrap_or_else(|| die(format!("-export needs -in cert.pem\n{USAGE}")));
    let out = args.value("-out");
    let pw = password(args.value("-passout"), "-passout");

    warn_if_world_readable_key(key_path);
    let mut key_pem =
        std::fs::read(key_path).unwrap_or_else(|e| die(format!("cannot read {key_path}: {e}")));
    let pem = String::from_utf8_lossy(&key_pem).into_owned();
    let mut pkcs8 = pkcs8_from_pem(&pem, key_path);
    zero_buf(&mut key_pem);

    let mut chain = certs_from_pem(cert_path);
    if chain.is_empty() {
        die(format!("{cert_path} contained no CERTIFICATE blocks"));
    }
    if let Some(extra) = args.value("-certfile") {
        chain.extend(certs_from_pem(extra));
    }
    // The leaf must belong to the key: a mismatched bundle imports fine and
    // then fails every handshake, far from the cause.
    let leaf = Certificate::from_der(chain[0].clone()).unwrap_or_else(|_| {
        die(format!(
            "{cert_path}: the first certificate is not parseable"
        ))
    });
    let key = AnyPrivateKey::from_pkcs8_der(&pkcs8, Pkcs8ReadOptions::new())
        .unwrap_or_else(|e| die(format!("{key_path}: unsupported key: {e:?}")));
    let signer = key
        .cert_signer()
        .unwrap_or_else(|e| die(format!("{key_path}: not a signing key: {e:?}")));
    match leaf.subject_public_key_matches(&signer.public_key()) {
        Ok(true) => {}
        Ok(false) => die(format!(
            "private key {key_path} does not match the first certificate in {cert_path}"
        )),
        Err(e) => die(format!("{cert_path}: unreadable subject public key: {e}")),
    }

    let chain_refs: Vec<&[u8]> = chain.iter().map(Vec::as_slice).collect();
    let p12 = Pfx::build(
        &pkcs8,
        &chain_refs,
        &pw,
        args.value("-name"),
        &mut purecrypto::rng::OsRng,
    );
    zero_buf(&mut pkcs8);
    write_output_with_mode(out, &p12, /* private = */ true);
}

fn unpack(args: &Args) {
    let in_path = args
        .value("-in")
        .unwrap_or_else(|| die(format!("-in id.p12 is required\n{USAGE}")));
    let pw = password(args.value("-passin"), "-passin");
    let raw = read_secret_file(in_path);
    let parsed = Pfx::parse(&raw, &pw).unwrap_or_else(|e| match e {
        purecrypto::pkcs12::Error::MacMismatch => die(format!(
            "{in_path}: MAC check failed (wrong password or tampered file)"
        )),
        other => die(format!("{in_path}: cannot parse PKCS#12: {other:?}")),
    });

    if args.flag("-info") {
        let mut text = format!(
            "{in_path}: {} private key(s), {} certificate(s)\n",
            parsed.keys.len(),
            parsed.certs.len()
        );
        for (i, der) in parsed.certs.iter().enumerate() {
            match Certificate::from_der(der.clone()).and_then(|c| c.subject()) {
                Ok(subject) => text.push_str(&format!(
                    "certificate {i}: subject {}\n",
                    crate::pki::format_dn(&subject)
                )),
                Err(_) => text.push_str(&format!("certificate {i}: (unparseable)\n")),
            }
        }
        for name in &parsed.friendly_names {
            text.push_str(&format!("friendly name: {name}\n"));
        }
        write_output(args.value("-out"), text.as_bytes());
        return;
    }

    let mut pem: Vec<u8> = Vec::new();
    let with_keys = !args.flag("-nokeys");
    if with_keys {
        for k in &parsed.keys {
            pem.extend_from_slice(pem_encode("PRIVATE KEY", k).as_bytes());
        }
    }
    if !args.flag("-nocerts") {
        for c in &parsed.certs {
            pem.extend_from_slice(pem_encode("CERTIFICATE", c).as_bytes());
        }
    }
    write_output_with_mode(
        args.value("-out"),
        &pem,
        /* private = */ with_keys && !parsed.keys.is_empty(),
    );
    zero_buf(&mut pem);
}

pub(crate) fn run(args: Args) {
    if args.flag("-h") || args.flag("--help") {
        println!("{USAGE}");
        return;
    }
    if args.flag("-export") {
        export(&args);
    } else {
        unpack(&args);
    }
}
