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

/// End-to-end exercise of `purecrypto ca`: init → genpkey leaf → ca issue →
/// x509 inspect → ca revoke → ca crl → verify the CRL revokes the leaf.
#[test]
fn ca_subcommand_full_flow() {
    use purecrypto::x509::{Certificate, CertificateRevocationList};

    let dir = std::env::temp_dir().join(format!("pc_cli_ca_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let p = |name: &str| dir.join(name).to_str().unwrap().to_string();

    // CA init.
    assert!(
        run(
            &[
                "ca",
                "init",
                "-dir",
                dir.to_str().unwrap(),
                "-cn",
                "Test CLI CA"
            ],
            b""
        )
        .1,
        "ca init failed"
    );

    // Leaf key + extracted public key.
    assert!(
        run(
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-curve",
                "P-256",
                "-out",
                &p("leaf.key"),
            ],
            b""
        )
        .1,
        "genpkey failed"
    );
    let (pubkey_pem, ok) = run(&["pkey", "-in", &p("leaf.key"), "-pubout"], b"");
    assert!(ok, "pkey -pubout failed");
    std::fs::write(dir.join("leaf.pub"), pubkey_pem).unwrap();

    // CA issues a leaf.
    assert!(
        run(
            &[
                "ca",
                "issue",
                "-dir",
                dir.to_str().unwrap(),
                "-pubkey",
                &p("leaf.pub"),
                "-cn",
                "host.example",
                "-sans",
                "host.example",
                "-out",
                &p("leaf.crt"),
            ],
            b""
        )
        .1,
        "ca issue failed"
    );

    // x509 inspect: the issued cert has the right subject + issuer.
    let (text, ok) = run(&["x509", "-in", &p("leaf.crt"), "-text"], b"");
    assert!(ok, "x509 inspect failed: {text}");
    assert!(text.contains("CN=host.example"), "subject missing: {text}");
    assert!(text.contains("CN=Test CLI CA"), "issuer missing: {text}");

    // The leaf is signed by the CA: verify via the library.
    let root_pem = std::fs::read_to_string(dir.join("root.crt")).unwrap();
    let leaf_pem = std::fs::read_to_string(dir.join("leaf.crt")).unwrap();
    let root = Certificate::from_pem(&root_pem).unwrap();
    let leaf = Certificate::from_pem(&leaf_pem).unwrap();
    let root_key = root.subject_public_key().unwrap();
    leaf.verify_signature_with(&root_key)
        .expect("leaf should verify under the CA key");

    // Revoke the leaf (CA serial starts at 2).
    assert!(
        run(
            &[
                "ca",
                "revoke",
                "-dir",
                dir.to_str().unwrap(),
                "-serial",
                "2",
                "-reason",
                "key-compromise",
            ],
            b""
        )
        .1,
        "ca revoke failed"
    );

    // Refresh the CRL.
    assert!(
        run(
            &[
                "ca",
                "crl",
                "-dir",
                dir.to_str().unwrap(),
                "-out",
                &p("crl.pem"),
            ],
            b""
        )
        .1,
        "ca crl failed"
    );

    // Load the CRL and verify it revokes the leaf serial, and that its
    // signature is valid under the CA key.
    let crl_pem = std::fs::read_to_string(dir.join("crl.pem")).unwrap();
    let crl = CertificateRevocationList::from_pem(&crl_pem).unwrap();
    assert!(
        crl.is_revoked(&[2]).unwrap(),
        "CRL should list serial 2 as revoked"
    );
    crl.verify_signature_with(&root_key)
        .expect("CRL signature should verify under the CA key");
    crl.check_signature_algid_consistent()
        .expect("CRL inner/outer algid should agree");

    // `ca show` produces a usable summary.
    let (show, ok) = run(&["ca", "show", "-dir", dir.to_str().unwrap()], b"");
    assert!(ok, "ca show failed");
    assert!(show.contains("CN=Test CLI CA"), "show output: {show}");
    assert!(show.contains("Revoked:    1"), "show output: {show}");
    assert!(show.contains("CRL:        present"), "show output: {show}");

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

/// s_client and s_server round-trip over a local TCP port speaking TLS 1.2,
/// exercising the `-tls1_2` flag on both sides plus the TLS 1.2 keylog
/// format (`CLIENT_RANDOM ...`).
#[test]
fn s_client_s_server_tls12_roundtrip() {
    use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
    use purecrypto::rng::OsRng;
    use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    // Pick a free port up front.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind probe");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let dir = std::env::temp_dir().join(format!("pc_s_server_tls12_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");
    let log_path = dir.join("keylog.txt");

    // Self-signed P-256 ECDSA cert for 127.0.0.1 (TLS 1.2 server requires
    // an RSA or ECDSA key for the ECDHE-* suite signature).
    let mut rng = OsRng;
    let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let cert = Certificate::self_signed_general(
        &CertSigner::Ecdsa(&key),
        &DistinguishedName::common_name("127.0.0.1"),
        &validity,
        1,
        false,
        &["127.0.0.1"],
    )
    .unwrap();
    std::fs::write(&cert_path, cert.to_pem()).unwrap();
    std::fs::write(&key_path, key.to_sec1_pem()).unwrap();

    // Spawn s_server -tls1_2 in a background process (single-shot, `-www`).
    let server_proc = std::process::Command::new(env!("CARGO_BIN_EXE_purecrypto"))
        .args([
            "s_server",
            "-tls1_2",
            "-cert",
            cert_path.to_str().unwrap(),
            "-key",
            key_path.to_str().unwrap(),
            "-accept",
            &port.to_string(),
            "-www",
            "-quiet",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn s_server");

    // Give the server time to bind.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // s_client -tls1_2 connects, dumps CLIENT_RANDOM line to keylogfile.
    let (out, ok) = run(
        &[
            "s_client",
            "-tls1_2",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-insecure",
            "-keylogfile",
            log_path.to_str().unwrap(),
            "-quiet",
        ],
        b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n",
    );

    let _ = server_proc.wait_with_output();

    assert!(ok, "s_client -tls1_2 failed");
    assert!(
        out.contains("hello from purecrypto s_server"),
        "expected -www body in client stdout, got: {out:?}"
    );

    // The keylogfile must contain the TLS 1.2 CLIENT_RANDOM line.
    let log = std::fs::read_to_string(&log_path).expect("read keylog");
    assert!(
        log.starts_with("CLIENT_RANDOM "),
        "expected CLIENT_RANDOM keylog line, got:\n{log}"
    );
    // CLIENT_RANDOM <64 hex> <96 hex>\n  (64 = 32 bytes cr, 96 = 48 bytes master)
    let parts: Vec<&str> = log.trim().split_ascii_whitespace().collect();
    assert_eq!(parts.len(), 3, "malformed CLIENT_RANDOM line: {log}");
    assert_eq!(parts[0], "CLIENT_RANDOM");
    assert_eq!(parts[1].len(), 64, "client_random hex len wrong: {log}");
    assert_eq!(parts[2].len(), 96, "master_secret hex len wrong: {log}");
    assert!(parts[1].bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(parts[2].bytes().all(|b| b.is_ascii_hexdigit()));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
#[ignore = "requires network access"]
fn s_client_live_cloudflare_tls12() {
    let (_out, ok) = run(
        &["s_client", "-tls1_2", "-connect", "cloudflare.com:443"],
        b"GET / HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n",
    );
    assert!(ok);
}

/// `s_dtls_client` and `s_dtls_server` round-trip over a local UDP port,
/// exercising the DTLS 1.2 handshake (with HelloVerifyRequest cookie)
/// and an app-data echo.
#[test]
fn s_dtls_client_s_dtls_server_roundtrip() {
    use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
    use purecrypto::rng::OsRng;
    use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    // Pick a free UDP port up front by binding then dropping.
    let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind probe");
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let dir = std::env::temp_dir().join(format!("pc_s_dtls_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");

    // Self-signed P-256 ECDSA cert for 127.0.0.1. The DTLS 1.2 server we
    // wrap is ECDSA-only.
    let mut rng = OsRng;
    let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let cert = Certificate::self_signed_general(
        &CertSigner::Ecdsa(&key),
        &DistinguishedName::common_name("127.0.0.1"),
        &validity,
        1,
        false,
        &["127.0.0.1"],
    )
    .unwrap();
    std::fs::write(&cert_path, cert.to_pem()).unwrap();
    std::fs::write(&key_path, key.to_sec1_pem()).unwrap();

    // Spawn s_dtls_server in a background process. Disable the cookie
    // exchange to keep the round-trip path short — the cookie path is
    // exercised by the DTLS unit tests.
    let server_proc = std::process::Command::new(env!("CARGO_BIN_EXE_purecrypto"))
        .args([
            "s_dtls_server",
            "-cert",
            cert_path.to_str().unwrap(),
            "-key",
            key_path.to_str().unwrap(),
            "-accept",
            &format!("127.0.0.1:{port}"),
            "-no_cookie",
            "-quiet",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn s_dtls_server");

    // Give the server time to bind.
    std::thread::sleep(std::time::Duration::from_millis(200));

    // s_dtls_client connects, sends one line, and expects the echo back.
    // `-insecure` skips peer-cert validation (the test fixture's cert isn't
    // anchored to a trusted root); since the audit fix the DTLS client
    // refuses to start without either `-CAfile` or this explicit opt-in.
    let (out, _ok) = run(
        &[
            "s_dtls_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-insecure",
            "-quiet",
        ],
        b"hello\n",
    );

    let _ = server_proc.wait_with_output();

    // The CLI exits when the data-phase idle deadline fires; we don't
    // assert on the exit code (which is non-deterministic across CI
    // schedulers) — only that the echo round-tripped.
    assert!(
        out.contains("hello"),
        "expected 'hello' in client stdout, got: {out:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Same DTLS 1.2 roundtrip as above, but exercising the unified binaries
/// `s_client -dtls1_2` ↔ `s_server -dtls1_2`. This proves that the
/// version-flag dispatch in `s_client` / `s_server` reaches the same
/// UDP code path as the `s_dtls_*` convenience aliases.
#[test]
fn s_client_s_server_dtls12_roundtrip() {
    use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
    use purecrypto::rng::OsRng;
    use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind probe");
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let dir = std::env::temp_dir().join(format!("pc_dtls12_unified_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");

    let mut rng = OsRng;
    let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let cert = Certificate::self_signed_general(
        &CertSigner::Ecdsa(&key),
        &DistinguishedName::common_name("127.0.0.1"),
        &validity,
        1,
        false,
        &["127.0.0.1"],
    )
    .unwrap();
    std::fs::write(&cert_path, cert.to_pem()).unwrap();
    std::fs::write(&key_path, key.to_sec1_pem()).unwrap();

    // `s_server -dtls1_2` instead of `s_dtls_server`.
    let server_proc = std::process::Command::new(env!("CARGO_BIN_EXE_purecrypto"))
        .args([
            "s_server",
            "-dtls1_2",
            "-cert",
            cert_path.to_str().unwrap(),
            "-key",
            key_path.to_str().unwrap(),
            "-accept",
            &format!("127.0.0.1:{port}"),
            "-no_cookie",
            "-quiet",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn s_server -dtls1_2");

    std::thread::sleep(std::time::Duration::from_millis(200));

    // `s_client -dtls1_2` instead of `s_dtls_client`.
    let (out, _ok) = run(
        &[
            "s_client",
            "-dtls1_2",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-insecure",
            "-quiet",
        ],
        b"hello\n",
    );

    let _ = server_proc.wait_with_output();

    assert!(
        out.contains("hello"),
        "expected 'hello' in client stdout, got: {out:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// DTLS 1.3 roundtrip using the unified `s_client -dtls1_3` ↔
/// `s_server -dtls1_3` flags from commit 14.
#[test]
fn s_client_s_server_dtls13_roundtrip() {
    use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
    use purecrypto::rng::OsRng;
    use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    let probe = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind probe");
    let port = probe.local_addr().unwrap().port();
    drop(probe);

    let dir = std::env::temp_dir().join(format!("pc_dtls13_unified_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server.key");

    let mut rng = OsRng;
    let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let cert = Certificate::self_signed_general(
        &CertSigner::Ecdsa(&key),
        &DistinguishedName::common_name("127.0.0.1"),
        &validity,
        1,
        false,
        &["127.0.0.1"],
    )
    .unwrap();
    std::fs::write(&cert_path, cert.to_pem()).unwrap();
    std::fs::write(&key_path, key.to_sec1_pem()).unwrap();

    let server_proc = std::process::Command::new(env!("CARGO_BIN_EXE_purecrypto"))
        .args([
            "s_server",
            "-dtls1_3",
            "-cert",
            cert_path.to_str().unwrap(),
            "-key",
            key_path.to_str().unwrap(),
            "-accept",
            &format!("127.0.0.1:{port}"),
            "-no_cookie",
            "-quiet",
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn s_server -dtls1_3");

    std::thread::sleep(std::time::Duration::from_millis(200));

    let (out, _ok) = run(
        &[
            "s_client",
            "-dtls1_3",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-insecure",
            "-quiet",
        ],
        b"hello\n",
    );

    let _ = server_proc.wait_with_output();

    assert!(
        out.contains("hello"),
        "expected 'hello' in client stdout, got: {out:?}"
    );

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

// ---------------------------------------------------------------------------
// Template + extension tests

#[test]
fn ca_template_tls_server() {
    let dir = std::env::temp_dir().join(format!("pc_tmpl_srv_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let p = |name: &str| dir.join(name).to_str().unwrap().to_string();

    // Root CA.
    assert!(
        run(
            &[
                "ca",
                "init",
                "-dir",
                dir.to_str().unwrap(),
                "-cn",
                "Root CA"
            ],
            b"",
        )
        .1,
        "ca init failed"
    );
    // Leaf key + pub.
    assert!(
        run(
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-curve",
                "P-256",
                "-out",
                &p("leaf.key")
            ],
            b""
        )
        .1
    );
    let (pubkey_pem, ok) = run(&["pkey", "-in", &p("leaf.key"), "-pubout"], b"");
    assert!(ok);
    std::fs::write(dir.join("leaf.pub"), pubkey_pem).unwrap();

    // Issue with -template tls-server.
    assert!(
        run(
            &[
                "ca",
                "issue",
                "-dir",
                dir.to_str().unwrap(),
                "-template",
                "tls-server",
                "-pubkey",
                &p("leaf.pub"),
                "-cn",
                "host.example",
                "-sans",
                "host.example,*.host.example",
                "-out",
                &p("leaf.crt"),
            ],
            b""
        )
        .1,
        "ca issue with template failed"
    );

    let (text, ok) = run(&["x509", "-in", &p("leaf.crt"), "-text", "-ext"], b"");
    assert!(ok, "x509 -text -ext failed: {text}");
    assert!(text.contains("CA: false"), "basicConstraints: {text}");
    assert!(
        text.contains("digitalSignature") && text.contains("keyEncipherment"),
        "keyUsage: {text}"
    );
    assert!(text.contains("serverAuth"), "EKU: {text}");
    assert!(
        text.contains("DNS:host.example") && text.contains("DNS:*.host.example"),
        "SAN: {text}"
    );
    assert!(text.contains("subjectKeyIdentifier"), "SKI: {text}");
    assert!(text.contains("authorityKeyIdentifier"), "AKI: {text}");

    // The leaf verifies against the (now-extended) root CA.
    let root_pem = std::fs::read_to_string(dir.join("root.crt")).unwrap();
    let leaf_pem = std::fs::read_to_string(dir.join("leaf.crt")).unwrap();
    let root = purecrypto::x509::Certificate::from_pem(&root_pem).unwrap();
    let leaf = purecrypto::x509::Certificate::from_pem(&leaf_pem).unwrap();
    let root_key = root.subject_public_key().unwrap();
    leaf.verify_signature_with(&root_key).unwrap();

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ca_template_intermediate_chain() {
    let dir = std::env::temp_dir().join(format!("pc_tmpl_chain_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let p = |name: &str| dir.join(name).to_str().unwrap().to_string();

    // Root CA.
    assert!(
        run(
            &[
                "ca",
                "init",
                "-dir",
                dir.to_str().unwrap(),
                "-cn",
                "Chain Root"
            ],
            b"",
        )
        .1
    );

    // Intermediate keypair + pubkey extracted via pkey -pubout.
    assert!(
        run(
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-curve",
                "P-256",
                "-out",
                &p("int.key")
            ],
            b""
        )
        .1
    );
    let (int_pub, ok) = run(&["pkey", "-in", &p("int.key"), "-pubout"], b"");
    assert!(ok);
    std::fs::write(dir.join("int.pub"), int_pub).unwrap();

    // Root issues the intermediate with -template ca-intermediate.
    assert!(
        run(
            &[
                "ca",
                "issue",
                "-dir",
                dir.to_str().unwrap(),
                "-template",
                "ca-intermediate",
                "-pubkey",
                &p("int.pub"),
                "-cn",
                "Chain Intermediate",
                "-out",
                &p("int.crt"),
            ],
            b""
        )
        .1,
        "intermediate issue failed"
    );

    // The intermediate cert verifies under the root.
    let root_pem = std::fs::read_to_string(dir.join("root.crt")).unwrap();
    let int_pem = std::fs::read_to_string(dir.join("int.crt")).unwrap();
    let root = purecrypto::x509::Certificate::from_pem(&root_pem).unwrap();
    let int_cert = purecrypto::x509::Certificate::from_pem(&int_pem).unwrap();
    int_cert
        .verify_signature_with(&root.subject_public_key().unwrap())
        .expect("intermediate must verify under root");
    // basicConstraints.ca = true, pathLen = 0 on the intermediate.
    let bc = int_cert.basic_constraints().unwrap().unwrap();
    assert_eq!(bc, (true, Some(0)), "ca-intermediate path_len");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn req_template_csr() {
    let dir = std::env::temp_dir().join(format!("pc_tmpl_req_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let p = |name: &str| dir.join(name).to_str().unwrap().to_string();

    assert!(
        run(
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-curve",
                "P-256",
                "-out",
                &p("leaf.key")
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
                &p("leaf.key"),
                "-subj",
                "/CN=tmpl.example",
                "-template",
                "tls-server",
                "-san",
                "tmpl.example,alt.example",
                "-out",
                &p("leaf.csr"),
            ],
            b"",
        )
        .1,
        "req -template failed"
    );
    let (vout, ok) = run(&["req", "-in", &p("leaf.csr"), "-verify"], b"");
    assert!(ok && vout.contains("verify OK"));

    // Parse the CSR via the library to inspect its extensionRequest.
    let csr_pem = std::fs::read_to_string(dir.join("leaf.csr")).unwrap();
    let csr = purecrypto::x509::CertificationRequest::from_pem(&csr_pem).unwrap();
    let exts = csr.extension_requests().unwrap();
    assert!(
        exts.iter()
            .any(|e| e.oid == purecrypto::x509::oid::EXT_KEY_USAGE),
        "CSR should request EKU"
    );
    assert!(
        exts.iter()
            .any(|e| e.oid == purecrypto::x509::oid::KEY_USAGE),
        "CSR should request keyUsage"
    );
    let sans = csr.subject_alt_names().unwrap();
    assert!(sans.contains(&"tmpl.example".to_string()));
    assert!(sans.contains(&"alt.example".to_string()));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn template_user_file_overrides_critical() {
    let dir = std::env::temp_dir().join(format!("pc_tmpl_user_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let p = |name: &str| dir.join(name).to_str().unwrap().to_string();

    assert!(
        run(
            &[
                "ca",
                "init",
                "-dir",
                dir.to_str().unwrap(),
                "-cn",
                "UF Root"
            ],
            b"",
        )
        .1
    );
    assert!(
        run(
            &[
                "genpkey",
                "-algorithm",
                "EC",
                "-curve",
                "P-256",
                "-out",
                &p("leaf.key")
            ],
            b""
        )
        .1
    );
    let (pubkey_pem, ok) = run(&["pkey", "-in", &p("leaf.key"), "-pubout"], b"");
    assert!(ok);
    std::fs::write(dir.join("leaf.pub"), pubkey_pem).unwrap();

    // Custom template: key_usage non-critical, just digitalSignature.
    let tmpl = r#"name = "custom"

[basic_constraints]
ca = false

[key_usage]
critical = false
digital_signature = true

[subject_key_identifier]
include = true

[authority_key_identifier]
include = true
"#;
    let tmpl_path = dir.join("custom.toml");
    std::fs::write(&tmpl_path, tmpl).unwrap();

    assert!(
        run(
            &[
                "ca",
                "issue",
                "-dir",
                dir.to_str().unwrap(),
                "-template-file",
                tmpl_path.to_str().unwrap(),
                "-pubkey",
                &p("leaf.pub"),
                "-cn",
                "user.example",
                "-out",
                &p("leaf.crt"),
            ],
            b"",
        )
        .1,
        "user-file override failed"
    );

    let leaf_pem = std::fs::read_to_string(dir.join("leaf.crt")).unwrap();
    let leaf = purecrypto::x509::Certificate::from_pem(&leaf_pem).unwrap();
    // keyUsage extension exists but is NOT marked critical.
    let exts = leaf.extensions().unwrap();
    let ku = exts
        .iter()
        .find(|e| e.oid == purecrypto::x509::oid::KEY_USAGE)
        .expect("keyUsage emitted");
    assert!(!ku.critical, "user override should flip critical bit");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ca_list_templates_lists_builtins() {
    let (out, ok) = run(&["ca", "list-templates"], b"");
    assert!(ok, "ca list-templates failed");
    for name in [
        "tls-server",
        "tls-client",
        "mtls-client",
        "ca-root",
        "ca-intermediate",
        "code-signing",
        "email-protection",
        "time-stamping",
    ] {
        assert!(out.contains(name), "missing {name} in {out}");
    }
}

// ---- MAC / KDF / ENC subcommand tests (Phase 1) ----

#[test]
fn mac_hmac_sha256_known_answer() {
    // RFC 4231 §4.2 test case 1: key = 20 × 0x0b, data = "Hi There".
    let (out, ok) = run(
        &[
            "mac",
            "-alg",
            "hmac-sha256",
            "-key",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        ],
        b"Hi There",
    );
    assert!(ok);
    assert_eq!(
        out.trim(),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    );
}

#[test]
fn kdf_hkdf_known_answer() {
    // RFC 5869 §A.1 (test case 1).
    let (out, ok) = run(
        &[
            "kdf",
            "hkdf",
            "-hash",
            "sha256",
            "-ikm",
            "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
            "-salt",
            "000102030405060708090a0b0c",
            "-info",
            "f0f1f2f3f4f5f6f7f8f9",
            "-len",
            "42",
        ],
        b"",
    );
    assert!(ok);
    assert_eq!(
        out.trim(),
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    );
}

#[test]
fn kdf_pbkdf2_known_answer() {
    // RFC 6070 test case 2: password="password", salt="salt", c=2, dkLen=20.
    // But that's HMAC-SHA1; we use HMAC-SHA256 RFC 7914 §11 vector instead.
    // password="passwd", salt="salt", c=1, dkLen=64.
    // Output from libgcrypt / openssl: 55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783
    let (out, ok) = run(
        &[
            "kdf",
            "pbkdf2",
            "-hash",
            "sha256",
            "-password",
            "passwd",
            "-salt",
            "73616c74",
            "-iter",
            "1",
            "-len",
            "64",
        ],
        b"",
    );
    assert!(ok);
    assert_eq!(
        out.trim(),
        "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc\
49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783"
    );
}

#[test]
fn enc_aes_gcm_roundtrip() {
    let dir = std::env::temp_dir().join(format!("pc_enc_gcm_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n).to_str().unwrap().to_string();
    std::fs::write(dir.join("pt.bin"), b"hello purecrypto").unwrap();

    // Encrypt.
    let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    let nonce = "010203040506070809101112";
    assert!(
        run(
            &[
                "enc",
                "-alg",
                "AES-256-GCM",
                "-key",
                key,
                "-nonce",
                nonce,
                "-in",
                &p("pt.bin"),
                "-out",
                &p("ct.bin"),
            ],
            b"",
        )
        .1
    );

    // Decrypt.
    assert!(
        run(
            &[
                "enc",
                "-alg",
                "AES-256-GCM",
                "-d",
                "-key",
                key,
                "-nonce",
                nonce,
                "-in",
                &p("ct.bin"),
                "-out",
                &p("rt.bin"),
            ],
            b"",
        )
        .1
    );
    let rt = std::fs::read(dir.join("rt.bin")).unwrap();
    assert_eq!(rt, b"hello purecrypto");

    // Tamper with the tag; decrypt must fail.
    let mut ct = std::fs::read(dir.join("ct.bin")).unwrap();
    *ct.last_mut().unwrap() ^= 1;
    std::fs::write(dir.join("ct_bad.bin"), &ct).unwrap();
    let (_o, ok) = run(
        &[
            "enc",
            "-alg",
            "AES-256-GCM",
            "-d",
            "-key",
            key,
            "-nonce",
            nonce,
            "-in",
            &p("ct_bad.bin"),
            "-out",
            &p("rt_bad.bin"),
        ],
        b"",
    );
    assert!(!ok, "tampered AES-GCM ciphertext must be rejected");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn enc_chacha20_poly1305_roundtrip() {
    let dir = std::env::temp_dir().join(format!("pc_enc_cc20_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = |n: &str| dir.join(n).to_str().unwrap().to_string();
    std::fs::write(dir.join("pt.bin"), b"chacha20 + poly1305").unwrap();

    let key = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    let nonce = "010203040506070809101112";
    assert!(
        run(
            &[
                "enc",
                "-alg",
                "CHACHA20-POLY1305",
                "-key",
                key,
                "-nonce",
                nonce,
                "-aad",
                "deadbeef",
                "-in",
                &p("pt.bin"),
                "-out",
                &p("ct.bin"),
            ],
            b"",
        )
        .1
    );
    assert!(
        run(
            &[
                "enc",
                "-alg",
                "CHACHA20-POLY1305",
                "-d",
                "-key",
                key,
                "-nonce",
                nonce,
                "-aad",
                "deadbeef",
                "-in",
                &p("ct.bin"),
                "-out",
                &p("rt.bin"),
            ],
            b"",
        )
        .1
    );
    let rt = std::fs::read(dir.join("rt.bin")).unwrap();
    assert_eq!(rt, b"chacha20 + poly1305");
    let _ = std::fs::remove_dir_all(&dir);
}
