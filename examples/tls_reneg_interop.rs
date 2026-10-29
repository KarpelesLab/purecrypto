//! TLS 1.2 secure renegotiation (RFC 5746) interop against OpenSSL — run
//! with:
//!
//! ```sh
//! cargo run --example tls_reneg_interop
//! ```
//!
//! Drives the public `Config` / `Connection` API over real TCP sockets
//! against `openssl s_server -tls1_2` / `openssl s_client -tls1_2`, whose
//! interactive `R` command renegotiates (a new ClientHello from `s_client`,
//! a HelloRequest from `s_server`):
//!
//! 1. purecrypto server ← `s_client` `R` (client-initiated), data after;
//! 2. purecrypto server, renegotiation off ← `s_client` `R`: declined;
//! 3. purecrypto client ← `s_server` `R` (server-initiated HelloRequest);
//! 4. purecrypto client → `Connection::renegotiate` against `s_server`.
//!
//! Point `OPENSSL_BIN` at another OpenSSL to test it. Not run in CI (it
//! needs an `openssl` binary); exits non-zero if any case fails.

use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::rng::OsRng;
use purecrypto::tls::{Config, Connection, ProtocolVersion, RootCertStore, SigningKey};
use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

const HOST: &str = "reneg.example";

fn openssl_bin() -> String {
    std::env::var("OPENSSL_BIN").unwrap_or_else(|_| "openssl".to_string())
}

/// Writes the throwaway private key with mode 0600 and `create_new`.
fn write_private_key(path: &std::path::Path, data: &[u8]) {
    let mut opts = std::fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
        .and_then(|mut f| f.write_all(data))
        .expect("write key file");
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
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

/// Shuttles bytes between `conn` and `sock` until `done` holds (collecting
/// received plaintext into `got`) or `timeout` passes.
fn pump_until(
    conn: &mut Connection,
    sock: &mut TcpStream,
    got: &mut Vec<u8>,
    timeout: Duration,
    mut done: impl FnMut(&Connection, &[u8]) -> bool,
) -> Result<(), String> {
    sock.set_read_timeout(Some(Duration::from_millis(50))).ok();
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; 16 * 1024];
    loop {
        let out = conn.pop().map_err(|e| format!("pop: {e:?}"))?;
        if !out.is_empty() {
            sock.write_all(&out).map_err(|e| format!("write: {e}"))?;
        }
        got.extend_from_slice(&conn.recv().map_err(|e| format!("recv: {e:?}"))?);
        if done(conn, got) {
            // Flush whatever the last feed produced.
            let out = conn.pop().map_err(|e| format!("pop: {e:?}"))?;
            if !out.is_empty() {
                sock.write_all(&out).map_err(|e| format!("write: {e}"))?;
            }
            return Ok(());
        }
        if Instant::now() > deadline {
            return Err(format!(
                "timed out (renegotiations {}, received {:?})",
                conn.renegotiation_count(),
                String::from_utf8_lossy(got)
            ));
        }
        match sock.read(&mut buf) {
            Ok(0) => return Err("peer closed".into()),
            Ok(n) => {
                conn.feed(&buf[..n]).map_err(|e| format!("feed: {e:?}"))?;
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e) => return Err(format!("read: {e}")),
        }
    }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn send_line(stdin: &mut ChildStdin, line: &str) -> Result<(), String> {
    stdin
        .write_all(line.as_bytes())
        .and_then(|_| stdin.flush())
        .map_err(|e| format!("openssl stdin: {e}"))
}

struct Fixture {
    cert_der: Vec<u8>,
    key: BoxedEcdsaPrivateKey,
    cert_path: String,
    key_path: String,
}

fn server_config(f: &Fixture, renegotiate: bool) -> Config {
    Config::builder()
        .rng(Arc::new(OsRng))
        .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_2)
        .identity(vec![f.cert_der.clone()], SigningKey::Ecdsa(f.key.clone()))
        .allow_renegotiation(renegotiate)
        .build()
}

fn client_config(f: &Fixture) -> Config {
    let mut roots = RootCertStore::new();
    roots.add_der(f.cert_der.clone()).unwrap();
    Config::builder()
        .rng(Arc::new(OsRng))
        .versions(ProtocolVersion::TLSv1_2, ProtocolVersion::TLSv1_2)
        .roots(roots)
        .server_name(HOST)
        .allow_renegotiation(true)
        .build()
}

fn spawn_s_client(port: u16) -> Result<Child, String> {
    Command::new(openssl_bin())
        .args([
            "s_client",
            "-connect",
            &format!("127.0.0.1:{port}"),
            "-tls1_2",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn s_client: {e}"))
}

fn spawn_s_server(f: &Fixture, port: u16, client_reneg: bool) -> Result<Child, String> {
    let mut cmd = Command::new(openssl_bin());
    cmd.arg("s_server");
    if client_reneg {
        // OpenSSL 3 servers refuse client-initiated renegotiation unless
        // told otherwise (SSL_OP_ALLOW_CLIENT_RENEGOTIATION).
        cmd.arg("-client_renegotiation");
    }
    cmd.args([
        "-accept",
        &port.to_string(),
        "-cert",
        &f.cert_path,
        "-key",
        &f.key_path,
        "-tls1_2",
        "-naccept",
        "1",
    ])
    .stdin(Stdio::piped())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .spawn()
    .map_err(|e| format!("spawn s_server: {e}"))
}

/// Our server, `s_client` sends `R` then a line of data.
fn server_vs_s_client(f: &Fixture, renegotiate: bool) -> Result<String, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    let port = listener.local_addr().unwrap().port();
    let mut child = spawn_s_client(port)?;
    let (mut sock, _) = listener.accept().map_err(|e| format!("accept: {e}"))?;
    let mut conn =
        Connection::server(&server_config(f, renegotiate)).map_err(|e| format!("{e:?}"))?;
    let mut stdin = child.stdin.take().unwrap();
    let result = (|| {
        let mut got = Vec::new();
        pump_until(
            &mut conn,
            &mut sock,
            &mut got,
            Duration::from_secs(5),
            |c, _| c.is_handshake_complete(),
        )?;
        send_line(&mut stdin, "before\n")?;
        pump_until(
            &mut conn,
            &mut sock,
            &mut got,
            Duration::from_secs(5),
            |_, g| contains(g, b"before\n"),
        )?;
        send_line(&mut stdin, "R\n")?;
        if renegotiate {
            pump_until(
                &mut conn,
                &mut sock,
                &mut got,
                Duration::from_secs(5),
                |c, _| c.renegotiation_count() == 1 && !c.is_renegotiating(),
            )?;
            send_line(&mut stdin, "after\n")?;
            pump_until(
                &mut conn,
                &mut sock,
                &mut got,
                Duration::from_secs(5),
                |_, g| contains(g, b"after\n"),
            )?;
            conn.send(b"pong\n").map_err(|e| format!("send: {e:?}"))?;
            pump_until(
                &mut conn,
                &mut sock,
                &mut got,
                Duration::from_millis(300),
                |_, _| false,
            )
            .ok();
            Ok(format!(
                "renegotiated ({} so far), data before and after; suite {}",
                conn.renegotiation_count(),
                conn.negotiated_cipher_suite_name().unwrap_or("?")
            ))
        } else {
            // Declined with a warning; OpenSSL then aborts its own
            // renegotiation attempt. Give it a moment and report.
            let r = pump_until(
                &mut conn,
                &mut sock,
                &mut got,
                Duration::from_secs(2),
                |c, _| c.peer_renegotiation_requests() == 1,
            );
            r?;
            pump_until(
                &mut conn,
                &mut sock,
                &mut got,
                Duration::from_millis(500),
                |_, _| false,
            )
            .ok();
            if conn.renegotiation_count() != 0 {
                return Err("renegotiated although disabled".into());
            }
            Ok("declined with no_renegotiation (OpenSSL then aborts its handshake)".into())
        }
    })();
    drop(stdin);
    let _ = child.kill();
    let out = child.wait_with_output().ok();
    if (result.is_err() || std::env::var_os("RENEG_INTEROP_VERBOSE").is_some())
        && let Some(o) = out
    {
        eprintln!("s_client stdout: {}", String::from_utf8_lossy(&o.stdout));
        eprintln!("s_client stderr: {}", String::from_utf8_lossy(&o.stderr));
    }
    result
}

/// Who renegotiates in [`client_vs_s_server`].
#[derive(Clone, Copy, PartialEq)]
enum ClientCase {
    /// `R` typed into `s_server`: a HelloRequest.
    ServerInitiated,
    /// `Connection::renegotiate` against `s_server -client_renegotiation`.
    ClientInitiated,
    /// `Connection::renegotiate` against a default OpenSSL 3 server, which
    /// declines client-initiated renegotiation.
    ClientInitiatedDeclined,
}

/// Our client against `s_server`.
fn client_vs_s_server(f: &Fixture, case: ClientCase) -> Result<String, String> {
    let port = free_port();
    let mut child = spawn_s_server(f, port, case == ClientCase::ClientInitiated)?;
    let mut sock = connect_retry(port).inspect_err(|_| {
        let _ = child.kill();
    })?;
    let mut conn = Connection::client(&client_config(f)).map_err(|e| format!("{e:?}"))?;
    let mut stdin = child.stdin.take().unwrap();
    let result = (|| {
        let mut got = Vec::new();
        pump_until(
            &mut conn,
            &mut sock,
            &mut got,
            Duration::from_secs(5),
            |c, _| c.is_handshake_complete(),
        )?;
        // s_server echoes its stdin to us as application data.
        send_line(&mut stdin, "before\n")?;
        pump_until(
            &mut conn,
            &mut sock,
            &mut got,
            Duration::from_secs(5),
            |_, g| contains(g, b"before\n"),
        )?;
        if case == ClientCase::ServerInitiated {
            send_line(&mut stdin, "R\n")?;
        } else {
            conn.renegotiate()
                .map_err(|e| format!("renegotiate: {e:?}"))?;
        }
        let want = u32::from(case != ClientCase::ClientInitiatedDeclined);
        pump_until(
            &mut conn,
            &mut sock,
            &mut got,
            Duration::from_secs(5),
            |c, _| c.renegotiation_count() == want && !c.is_renegotiating(),
        )?;
        send_line(&mut stdin, "after\n")?;
        pump_until(
            &mut conn,
            &mut sock,
            &mut got,
            Duration::from_secs(5),
            |_, g| contains(g, b"after\n"),
        )?;
        conn.send(b"hello-from-purecrypto\n")
            .map_err(|e| format!("send: {e:?}"))?;
        pump_until(
            &mut conn,
            &mut sock,
            &mut got,
            Duration::from_millis(300),
            |_, _| false,
        )
        .ok();
        Ok(format!(
            "{}, data before and after; suite {}",
            if want == 1 {
                "renegotiated"
            } else {
                "declined with no_renegotiation, session kept"
            },
            conn.negotiated_cipher_suite_name().unwrap_or("?")
        ))
    })();
    drop(stdin);
    let _ = child.kill();
    let out = child.wait_with_output().ok();
    match (&result, out) {
        (Ok(_), Some(o)) => {
            if !contains(&o.stdout, b"hello-from-purecrypto") {
                return Err("s_server did not print our post-renegotiation data".into());
            }
        }
        (Err(_), Some(o)) => {
            eprintln!("s_server stdout: {}", String::from_utf8_lossy(&o.stdout));
            eprintln!("s_server stderr: {}", String::from_utf8_lossy(&o.stderr));
        }
        _ => {}
    }
    result
}

fn main() {
    let have = Command::new(openssl_bin())
        .arg("version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    println!("reference: {}", have.trim());

    let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut OsRng);
    let cert = Certificate::self_signed_general(
        &CertSigner::Ecdsa(&key),
        &DistinguishedName::common_name(HOST),
        &Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        ),
        1,
        false,
        &[HOST],
    )
    .expect("self-sign");
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("pc_reneg_interop-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.to_pem()).unwrap();
    write_private_key(&key_path, key.to_pkcs8_pem().as_bytes());
    let f = Fixture {
        cert_der: cert.to_der().to_vec(),
        key,
        cert_path: cert_path.display().to_string(),
        key_path: key_path.display().to_string(),
    };

    type Case = (&'static str, fn(&Fixture) -> Result<String, String>);
    let cases: [Case; 5] = [
        ("server <- s_client R (client-initiated)", |f| {
            server_vs_s_client(f, true)
        }),
        ("server (reneg off) <- s_client R", |f| {
            server_vs_s_client(f, false)
        }),
        ("client <- s_server R (HelloRequest)", |f| {
            client_vs_s_server(f, ClientCase::ServerInitiated)
        }),
        (
            "client renegotiate() -> s_server -client_renegotiation",
            |f| client_vs_s_server(f, ClientCase::ClientInitiated),
        ),
        ("client renegotiate() -> s_server (declines)", |f| {
            client_vs_s_server(f, ClientCase::ClientInitiatedDeclined)
        }),
    ];
    let mut failed = 0;
    for (name, case) in cases {
        match case(&f) {
            Ok(msg) => println!("PASS  {name}: {msg}"),
            Err(e) => {
                failed += 1;
                println!("FAIL  {name}: {e}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
    if failed > 0 {
        std::process::exit(1);
    }
}
