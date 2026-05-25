//! Integration tests that drive the built `purecrypto` binary.
#![cfg(feature = "cli")]

use std::io::Write;
use std::process::{Command, Stdio};

/// Runs the CLI with `args`, feeding `stdin`, returning `(stdout, success)`.
fn run(args: &[&str], stdin: &[u8]) -> (String, bool) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_purecrypto"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn purecrypto");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        out.status.success(),
    )
}

#[test]
fn hash_sha256_stdin() {
    let (out, ok) = run(&["hash", "sha256"], b"abc");
    assert!(ok);
    assert_eq!(
        out.trim(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn hash_unknown_algorithm_fails() {
    let (_, ok) = run(&["hash", "nope"], b"x");
    assert!(!ok);
}

#[test]
fn rand_emits_hex() {
    let (out, ok) = run(&["rand", "16"], b"");
    assert!(ok);
    assert_eq!(out.trim().len(), 32); // 16 bytes -> 32 hex chars
    assert!(out.trim().bytes().all(|b| b.is_ascii_hexdigit()));
}

#[test]
fn ca_workflow_genpkey_req_sign() {
    // Unique scratch dir for this test process.
    let dir = std::env::temp_dir().join(format!("pc_cli_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = |name: &str| dir.join(name).to_str().unwrap().to_string();

    // CA key + self-signed CA cert.
    assert!(
        run(
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-curve",
                "P-256",
                "-out",
                &p("ca_key.pem")
            ],
            b""
        )
        .1
    );
    assert!(
        run(
            &[
                "x509",
                "-new",
                "--ca",
                "-key",
                &p("ca_key.pem"),
                "-subj",
                "/CN=Test CA",
                "-out",
                &p("ca.pem")
            ],
            b"",
        )
        .1
    );

    // Leaf key + CSR.
    assert!(
        run(
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-curve",
                "P-256",
                "-out",
                &p("leaf_key.pem")
            ],
            b""
        )
        .1
    );
    assert!(
        run(
            &[
                "req",
                "-key",
                &p("leaf_key.pem"),
                "-subj",
                "/CN=leaf.test",
                "-addext",
                "subjectAltName=DNS:leaf.test",
                "-out",
                &p("leaf.csr"),
            ],
            b"",
        )
        .1
    );

    // CSR self-signature verifies.
    let (vout, ok) = run(&["req", "-in", &p("leaf.csr"), "-verify"], b"");
    assert!(ok && vout.contains("verify OK"));

    // CA signs the CSR.
    assert!(
        run(
            &[
                "x509",
                "-req",
                "-in",
                &p("leaf.csr"),
                "-CA",
                &p("ca.pem"),
                "-CAkey",
                &p("ca_key.pem"),
                "-out",
                &p("leaf.pem")
            ],
            b"",
        )
        .1
    );

    // The issued cert carries the requested subject, the CA issuer, and the SAN.
    let (text, ok) = run(&["x509", "-in", &p("leaf.pem"), "-text"], b"");
    assert!(ok, "x509 -text failed: {text}");
    assert!(text.contains("CN=leaf.test"), "{text}");
    assert!(
        text.contains("Issuer:") && text.contains("CN=Test CA"),
        "{text}"
    );
    assert!(text.contains("leaf.test"), "{text}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn genpkey_ec_then_inspect() {
    let (key_pem, ok) = run(&["genpkey", "-algorithm", "EC", "-curve", "P-256"], b"");
    assert!(ok);
    assert!(key_pem.contains("BEGIN EC PRIVATE KEY"));

    // Public key extraction.
    let (pub_pem, ok) = run(&["pkey", "-pubout"], key_pem.as_bytes());
    assert!(ok);
    assert!(pub_pem.contains("BEGIN PUBLIC KEY"));

    // Text inspection names the curve.
    let (text, ok) = run(&["pkey", "-text"], key_pem.as_bytes());
    assert!(ok);
    assert!(text.contains("P-256"));
}
