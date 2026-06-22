//! Legacy TLS interop against OpenSSL (the de-facto reference) — run with:
//!
//! ```sh
//! cargo run --example tls_legacy_interop --features tls-legacy
//! ```
//!
//! Drives the **public** `Config` / `Connection` API with a lowered
//! `min_version`, in both roles, against `openssl s_server` / `s_client`, over
//! real TCP sockets. Covers TLS 1.0 and TLS 1.1 × {static-RSA AES-256-CBC-SHA,
//! ECDHE-RSA AES-128-CBC-SHA}, plus SSL 3.0 × static-RSA when the OpenSSL build
//! supports it.
//!
//! Point `OPENSSL_BIN` at a legacy OpenSSL (1.1.1 built with `enable-ssl3
//! enable-ssl3-method enable-weak-ssl-ciphers`) to exercise SSL 3.0 — the
//! system OpenSSL 3.x removed it, so SSL 3.0 is auto-skipped there. The CI
//! `legacy-tls-interop` workflow builds such an OpenSSL and runs this.
//!
//! Exits non-zero if any case fails.

use purecrypto::bignum::Uint;
use purecrypto::rng::OsRng;
use purecrypto::rsa::{BoxedRsaPrivateKey, RsaPrivateKey};
use purecrypto::tls::{
    Config, Connection, HandshakeStatus, ProtocolVersion, RootCertStore, SigningKey,
};
use purecrypto::x509::{Certificate, DistinguishedName, Time, Validity};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const STATIC_RSA_AES256_SHA: u16 = 0x0035; // TLS_RSA_WITH_AES_256_CBC_SHA
const ECDHE_RSA_AES128_SHA: u16 = 0xC013; // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA

/// The OpenSSL binary to drive. CI points this at a legacy build (1.1.1 with
/// `enable-ssl3`) so SSL 3.0 can be tested; defaults to the system `openssl`.
fn openssl_bin() -> String {
    std::env::var("OPENSSL_BIN").unwrap_or_else(|_| "openssl".to_string())
}

fn openssl_cipher(suite: u16) -> &'static str {
    match suite {
        STATIC_RSA_AES256_SHA => "AES256-SHA",
        ECDHE_RSA_AES128_SHA => "ECDHE-RSA-AES128-SHA",
        _ => unreachable!(),
    }
}

fn version_flag(v: ProtocolVersion) -> &'static str {
    match v {
        ProtocolVersion::SSLv3 => "-ssl3",
        ProtocolVersion::TLSv1_0 => "-tls1",
        ProtocolVersion::TLSv1_1 => "-tls1_1",
        _ => unreachable!(),
    }
}

fn version_name(v: ProtocolVersion) -> &'static str {
    match v {
        ProtocolVersion::SSLv3 => "SSL3.0",
        ProtocolVersion::TLSv1_0 => "TLS1.0",
        ProtocolVersion::TLSv1_1 => "TLS1.1",
        _ => "?",
    }
}

/// Whether this OpenSSL understands a given `s_client` protocol flag (e.g.
/// `-ssl3`). System OpenSSL 3.x lacks `-ssl3`, so SSL 3.0 is skipped there.
fn openssl_supports(flag: &str) -> bool {
    Command::new(openssl_bin())
        .args(["s_client", "-help"])
        .output()
        .map(|o| {
            let mut txt = String::from_utf8_lossy(&o.stdout).into_owned();
            txt.push_str(&String::from_utf8_lossy(&o.stderr));
            txt.contains(flag)
        })
        .unwrap_or(false)
}

/// Writes the throwaway private key with mode 0600 and `create_new` (Unix) so
/// the PEM is never group/world-readable and the write never follows a
/// pre-existing file or symlink planted at the path.
fn write_private_key(path: &std::path::Path, data: &[u8]) {
    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).expect("create key file");
    f.write_all(data).expect("write key file");
}

/// Pick a likely-free localhost port by binding to :0 and releasing it.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Pump the handshake to completion over `sock`.
fn drive_handshake(conn: &mut Connection, sock: &mut TcpStream) -> Result<(), String> {
    let mut buf = [0u8; 8192];
    loop {
        let out = conn.pop().map_err(|e| format!("pop: {e:?}"))?;
        if !out.is_empty() {
            if std::env::var("DBG").is_ok() {
                let hex: String = out[..out.len().min(96)]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                eprintln!("DBG us->peer {} bytes: {hex}", out.len());
            }
            sock.write_all(&out).map_err(|e| format!("write: {e}"))?;
        }
        match conn.handshake().map_err(|e| format!("handshake: {e:?}"))? {
            HandshakeStatus::Complete => return Ok(()),
            HandshakeStatus::WantWrite => continue,
            HandshakeStatus::WantRead => {
                let n = sock.read(&mut buf).map_err(|e| format!("read: {e}"))?;
                if n == 0 {
                    return Err("peer closed during handshake".into());
                }
                if std::env::var("DBG").is_ok() {
                    let hex: String = buf[..n.min(96)]
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    eprintln!("DBG peer->us {n} bytes: {hex}");
                }
                conn.feed(&buf[..n]).map_err(|e| format!("feed: {e:?}"))?;
            }
        }
    }
}

/// purecrypto **client** ↔ `openssl s_server -www`.
fn pc_client_vs_openssl_server(
    version: ProtocolVersion,
    suite: u16,
    cert_path: &str,
    key_path: &str,
) -> Result<String, String> {
    let port = free_port();
    let mut server: Child = Command::new(openssl_bin())
        .args([
            "s_server",
            "-accept",
            &port.to_string(),
            "-cert",
            cert_path,
            "-key",
            key_path,
            version_flag(version),
            "-cipher",
            &format!("{}@SECLEVEL=0", openssl_cipher(suite)),
            "-www",
            "-naccept",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn s_server: {e}"))?;

    // Wait for the listener.
    let mut sock = connect_retry(port).inspect_err(|_| {
        let _ = server.kill();
    })?;
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let cfg = Config::builder()
        .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
        .tls_only()
        .min_version(version)
        .max_version(version)
        .cipher_suites(&[suite])
        .roots(RootCertStore::new())
        .server_name("interop.example")
        .verify_certificates(false)
        .build();
    let mut conn = Connection::client(&cfg).map_err(|e| format!("client cfg: {e:?}"))?;

    let result = (|| {
        drive_handshake(&mut conn, &mut sock)?;
        let neg = conn.negotiated_version();
        if neg != Some(version) {
            return Err(format!("negotiated {neg:?}, expected {version:?}"));
        }
        if conn.negotiated_cipher_suite() != Some(suite) {
            return Err(format!(
                "cipher {:?}, expected {suite:#06x}",
                conn.negotiated_cipher_suite()
            ));
        }
        // Exchange application data: an HTTP request, read the s_server page.
        conn.send(b"GET / HTTP/1.0\r\n\r\n")
            .map_err(|e| format!("send: {e:?}"))?;
        let out = conn.pop().map_err(|e| format!("pop: {e:?}"))?;
        sock.write_all(&out).map_err(|e| format!("write: {e}"))?;
        let mut resp = Vec::new();
        let mut buf = [0u8; 8192];
        loop {
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if conn.feed(&buf[..n]).is_err() {
                        break;
                    }
                    resp.extend_from_slice(&conn.recv().unwrap_or_default());
                    if resp.len() > 8192 {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if !resp.windows(8).any(|w| w == b"s_server") && !resp.starts_with(b"HTTP/") {
            return Err(format!(
                "unexpected app-data response ({} bytes): {:?}",
                resp.len(),
                String::from_utf8_lossy(&resp[..resp.len().min(60)])
            ));
        }
        Ok(format!(
            "{} app-data bytes; cipher {}",
            resp.len(),
            conn.negotiated_cipher_suite_name().unwrap_or("?")
        ))
    })();

    let _ = server.kill();
    let _ = server.wait();
    result
}

/// purecrypto **server** ↔ `openssl s_client`.
fn pc_server_vs_openssl_client(
    version: ProtocolVersion,
    suite: u16,
    cert_der: &[u8],
    key: &BoxedRsaPrivateKey,
) -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    let port = listener.local_addr().unwrap().port();

    let mut client: Child = Command::new(openssl_bin())
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            version_flag(version),
            "-cipher",
            &format!("{}@SECLEVEL=0", openssl_cipher(suite)),
            "-quiet",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn s_client: {e}"))?;

    let (mut sock, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let cfg = Config::builder()
        .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
        .tls_only()
        .min_version(version)
        .max_version(version)
        .cipher_suites(&[suite])
        .identity(vec![cert_der.to_vec()], SigningKey::Rsa(key.clone()))
        .build();
    let mut conn = Connection::server(&cfg).map_err(|e| format!("server cfg: {e:?}"))?;

    let result = (|| {
        drive_handshake(&mut conn, &mut sock)?;
        if conn.negotiated_version() != Some(version) {
            return Err(format!("negotiated {:?}", conn.negotiated_version()));
        }
        // openssl s_client forwards its stdin as TLS app data.
        client
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"ping-from-openssl\n")
            .map_err(|e| format!("openssl stdin: {e}"))?;
        // Read that app data on the purecrypto server, echo a reply.
        let mut buf = [0u8; 8192];
        let got = loop {
            let plain = conn.recv().unwrap_or_default();
            if plain.windows(9).any(|w| w == b"ping-from") {
                break plain;
            }
            let n = sock.read(&mut buf).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("client closed before sending data".into());
            }
            conn.feed(&buf[..n]).map_err(|e| format!("feed: {e:?}"))?;
        };
        conn.send(b"pong-from-purecrypto\n")
            .map_err(|e| format!("send: {e:?}"))?;
        let out = conn.pop().map_err(|e| format!("pop: {e:?}"))?;
        sock.write_all(&out).map_err(|e| format!("write: {e}"))?;
        Ok(format!(
            "echoed {} bytes; cipher {}",
            got.len(),
            conn.negotiated_cipher_suite_name().unwrap_or("?")
        ))
    })();

    let _ = client.kill();
    let _ = client.wait();
    result
}

fn connect_retry(port: u16) -> Result<TcpStream, String> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => return Ok(s),
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(format!("connect: {e}")),
        }
    }
}

fn main() {
    // openssl must support the legacy versions.
    let have = Command::new(openssl_bin())
        .arg("version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    println!("reference: {}", have.trim());

    // Generate the RSA leaf + self-signed cert with purecrypto itself (no
    // dependency on an `openssl.cnf`, which the legacy OpenSSL build lacks).
    // The cert/key PEMs are written to disk for `openssl s_server -cert/-key`.
    let mut rng = OsRng;
    let rsa = RsaPrivateKey::<32>::generate(Uint::from_u64(65537), &mut rng, 20); // 2048-bit
    let name = DistinguishedName::common_name("interop.example");
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let cert = Certificate::self_signed(&rsa, &name, &validity, 1, false).expect("self-sign");
    let cert_der = cert.to_der().to_vec();
    let key = BoxedRsaPrivateKey::from_pkcs1_der(&rsa.to_pkcs1_der()).unwrap();

    // Per-run unique scratch dir: a fixed name under the shared /tmp would let
    // another local user pre-create it (symlink games) and would leave the
    // private key lying around between runs.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir =
        std::env::temp_dir().join(format!("pc_legacy_interop-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.to_pem()).unwrap();
    write_private_key(&key_path, rsa.to_pkcs1_pem().as_bytes());

    // (version, cipher-suite) cases. SSL 3.0 is included only when this OpenSSL
    // build supports `-ssl3` (a legacy build); the system OpenSSL 3.x skips it.
    // SSL 3.0 is tested with static-RSA only — its canonical key exchange.
    let mut cases: Vec<(ProtocolVersion, u16)> = Vec::new();
    if openssl_supports("-ssl3") {
        cases.push((ProtocolVersion::SSLv3, STATIC_RSA_AES256_SHA));
    } else {
        println!(
            "note: {} has no -ssl3; skipping SSL 3.0 interop",
            openssl_bin()
        );
    }
    for v in [ProtocolVersion::TLSv1_0, ProtocolVersion::TLSv1_1] {
        cases.push((v, STATIC_RSA_AES256_SHA));
        cases.push((v, ECDHE_RSA_AES128_SHA));
    }

    let mut failures = 0;
    let mut ran = 0;
    for (version, suite) in cases {
        let label = format!("{} {}", version_name(version), openssl_cipher(suite));
        ran += 1;

        match pc_client_vs_openssl_server(
            version,
            suite,
            cert_path.to_str().unwrap(),
            key_path.to_str().unwrap(),
        ) {
            Ok(info) => println!("PASS  pc-client  <-> openssl-server  {label}  ({info})"),
            Err(e) => {
                println!("FAIL  pc-client  <-> openssl-server  {label}  ({e})");
                failures += 1;
            }
        }

        match pc_server_vs_openssl_client(version, suite, &cert_der, &key) {
            Ok(info) => println!("PASS  openssl-client <-> pc-server   {label}  ({info})"),
            Err(e) => {
                println!("FAIL  openssl-client <-> pc-server   {label}  ({e})");
                failures += 1;
            }
        }
    }

    // Best-effort: don't leave the throwaway key/cert behind in /tmp.
    let _ = std::fs::remove_dir_all(&dir);

    if failures == 0 {
        println!(
            "\nAll {} legacy interop case(s) passed against OpenSSL.",
            ran * 2
        );
    } else {
        eprintln!("\n{failures} interop case(s) FAILED.");
        std::process::exit(1);
    }
}
