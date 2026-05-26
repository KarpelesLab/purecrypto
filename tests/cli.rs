//! Integration tests that drive the built `purecrypto` binary.
#![cfg(feature = "cli")]

use std::io::{Read, Write};
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
fn s_client_loopback() {
    use purecrypto::rng::OsRng;
    use purecrypto::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
    use purecrypto::tls::{ServerConfig, ServerConnection, Stream};
    use purecrypto::x509::{Certificate, DistinguishedName, Time, Validity};
    use std::net::TcpListener;

    const KEY: &str = include_str!("../testdata/rsa2048_test_a.pem");

    // A local TLS server that completes one handshake, echoes a reply, and exits.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().expect("accept");
        let signing = RsaPrivateKey::<32>::from_pkcs1_pem(KEY).unwrap();
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed(
            &signing,
            &DistinguishedName::common_name("127.0.0.1"),
            &validity,
            1,
            false,
        )
        .unwrap();
        let key = BoxedRsaPrivateKey::from_pkcs1_pem(KEY).unwrap();
        let config = ServerConfig::with_rsa(vec![cert.to_der().to_vec()], key);
        let mut conn = ServerConnection::new(config, OsRng);
        let mut tls = Stream::new(&mut conn, &mut sock);
        tls.complete_handshake().expect("server handshake");
        let mut buf = [0u8; 64];
        let _ = tls.read(&mut buf); // the client's "PING"
        tls.write_all(b"PONG").unwrap();
        tls.flush().unwrap();
    });

    // The CLI connects (insecure: self-signed), sends PING, prints the reply.
    let (out, ok) = run(
        &[
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-insecure",
            "-quiet",
        ],
        b"PING",
    );
    server.join().unwrap();
    assert!(ok, "s_client exited with failure");
    assert!(
        out.contains("PONG"),
        "expected PONG in stdout, got: {out:?}"
    );
}

/// s_client and s_server round-trip over a local TCP port, exercising
/// ALPN negotiation and -keylogfile capture.
#[test]
fn s_client_s_server_roundtrip_alpn_keylog() {
    use purecrypto::ec::Ed25519PrivateKey;
    use purecrypto::rng::OsRng;
    use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    // Pick a free port up front.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let dir = std::env::temp_dir().join(format!("pc_s_server_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");
    let log_path = dir.join("keylog.txt");

    // Self-signed Ed25519 cert for 127.0.0.1.
    let key = Ed25519PrivateKey::generate(&mut OsRng);
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let cert = Certificate::self_signed_general(
        &CertSigner::Ed25519(&key),
        &DistinguishedName::common_name("127.0.0.1"),
        &validity,
        1,
        false,
        &["127.0.0.1"],
    )
    .unwrap();
    std::fs::write(&cert_path, cert.to_pem()).unwrap();
    std::fs::write(&key_path, key.to_pkcs8_pem()).unwrap();

    // Spawn s_server in a background process (single-shot, `-www`).
    let server_proc = std::process::Command::new(env!("CARGO_BIN_EXE_purecrypto"))
        .args([
            "s_server",
            "-cert",
            cert_path.to_str().unwrap(),
            "-key",
            key_path.to_str().unwrap(),
            "-accept",
            &port.to_string(),
            "-alpn",
            "h2,http/1.1",
            "-www",
            "-quiet",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn s_server");

    // Give the server time to bind.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // s_client connects, negotiates ALPN, dumps secrets to keylogfile.
    let (out, ok) = run(
        &[
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-insecure",
            "-alpn",
            "http/1.1",
            "-keylogfile",
            log_path.to_str().unwrap(),
            "-quiet",
        ],
        b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n",
    );

    let _ = server_proc.wait_with_output();

    assert!(ok, "s_client failed");
    assert!(
        out.contains("hello from purecrypto s_server"),
        "expected -www body in client stdout, got: {out:?}"
    );

    // The keylogfile must contain the expected secret labels.
    let log = std::fs::read_to_string(&log_path).expect("read keylog");
    for label in [
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
        "EXPORTER_SECRET",
    ] {
        assert!(log.contains(label), "missing {label} in keylog:\n{log}");
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "requires network access"]
fn s_client_live_cloudflare() {
    let (_out, ok) = run(
        &["s_client", "-connect", "cloudflare.com:443"],
        b"GET / HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n",
    );
    assert!(ok);
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

#[test]
fn genpkey_ed25519_then_inspect() {
    let (key_pem, ok) = run(&["genpkey", "-algorithm", "ED25519"], b"");
    assert!(ok);
    assert!(key_pem.contains("BEGIN PRIVATE KEY"));

    // Public key extraction (PKIX SPKI).
    let (pub_pem, ok) = run(&["pkey", "-pubout"], key_pem.as_bytes());
    assert!(ok);
    assert!(pub_pem.contains("BEGIN PUBLIC KEY"));

    // Text inspection names the algorithm.
    let (text, ok) = run(&["pkey", "-text"], key_pem.as_bytes());
    assert!(ok);
    assert!(text.contains("Ed25519"));
}

#[test]
fn genpkey_ml_dsa_65_roundtrip() {
    let (pem, ok) = run(&["genpkey", "-algorithm", "ML-DSA-65"], b"");
    assert!(ok);
    assert!(pem.contains("BEGIN PRIVATE KEY"));
    let (text, ok) = run(&["pkey", "-text"], pem.as_bytes());
    assert!(ok);
    assert!(text.contains("ML-DSA-65"));
    let (pub_pem, ok) = run(&["pkey", "-pubout"], pem.as_bytes());
    assert!(ok);
    assert!(pub_pem.contains("BEGIN PUBLIC KEY"));
}

#[test]
fn genpkey_ml_kem_768_roundtrip() {
    let (pem, ok) = run(&["genpkey", "-algorithm", "ML-KEM-768"], b"");
    assert!(ok);
    let (text, ok) = run(&["pkey", "-text"], pem.as_bytes());
    assert!(ok);
    assert!(text.contains("ML-KEM-768"));
}

#[test]
fn genpkey_ml_kem_512_roundtrip() {
    let (pem, ok) = run(&["genpkey", "-algorithm", "ML-KEM-512"], b"");
    assert!(ok);
    let (text, ok) = run(&["pkey", "-text"], pem.as_bytes());
    assert!(ok && text.contains("ML-KEM-512"));
    let (pub_pem, ok) = run(&["pkey", "-pubout"], pem.as_bytes());
    assert!(ok && pub_pem.contains("BEGIN PUBLIC KEY"));
}

#[test]
fn genpkey_ml_kem_1024_roundtrip() {
    let (pem, ok) = run(&["genpkey", "-algorithm", "ML-KEM-1024"], b"");
    assert!(ok);
    let (text, ok) = run(&["pkey", "-text"], pem.as_bytes());
    assert!(ok && text.contains("ML-KEM-1024"));
    let (pub_pem, ok) = run(&["pkey", "-pubout"], pem.as_bytes());
    assert!(ok && pub_pem.contains("BEGIN PUBLIC KEY"));
}

#[test]
fn genpkey_slh_dsa_sha2_128f_roundtrip() {
    let (pem, ok) = run(&["genpkey", "-algorithm", "SLH-DSA-SHA2-128f"], b"");
    assert!(ok);
    let (text, ok) = run(&["pkey", "-text"], pem.as_bytes());
    assert!(ok);
    assert!(text.contains("SLH-DSA"));
    let (pub_pem, ok) = run(&["pkey", "-pubout"], pem.as_bytes());
    assert!(ok);
    assert!(pub_pem.contains("BEGIN PUBLIC KEY"));
}
