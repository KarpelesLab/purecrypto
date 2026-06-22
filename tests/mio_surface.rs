//! Integration tests for the `mio` TLS surface (`purecrypto::tls::mio`).
//!
//! Built only when the `mio` feature is on; `cargo test --all-features`
//! exercises them on every CI OS.
#![cfg(feature = "mio")]

use std::io::{self, Read, Write};
use std::sync::Arc;

use mio::event::Source;
use mio::net::TcpStream;
use mio::{Events, Interest, Poll, Token};
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::hash::Sha256;
use purecrypto::rng::{HmacDrbg, OsRng};
use purecrypto::tls::mio::drive_handshake;
use purecrypto::tls::{Config, Connection, RootCertStore, SigningKey};
use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

const SOCK: Token = Token(0);
const SIGNER: Token = Token(1);

fn server_identity(seed: &[u8], cn: &str) -> (BoxedEcdsaPrivateKey, Vec<u8>) {
    let mut kg = HmacDrbg::<Sha256>::new(seed, b"nonce", &[]);
    let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut kg);
    let name = DistinguishedName::common_name(cn);
    let validity = Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2034, 1, 1, 0, 0, 0),
    );
    let cert = Certificate::self_signed_general(
        &CertSigner::Ecdsa(&key),
        &name,
        &validity,
        1,
        false,
        &[cn],
    )
    .unwrap();
    (key, cert.to_der().to_vec())
}

fn client_config(leaf: Vec<u8>, sni: &str) -> Config {
    let mut roots = RootCertStore::new();
    roots.add_der(leaf).unwrap();
    Config::builder()
        .tls_only()
        .rng(Arc::new(OsRng))
        .roots(roots)
        .server_name(sni)
        .build()
}

/// Encrypt+send one application message over a non-blocking mio socket.
fn pump_write<S: Source + Write>(
    conn: &mut Connection,
    sock: &mut S,
    poll: &mut Poll,
    events: &mut Events,
    data: &[u8],
) -> io::Result<()> {
    conn.send(data).unwrap();
    let out = conn.pop().unwrap();
    let mut off = 0;
    while off < out.len() {
        match sock.write(&out[off..]) {
            Ok(n) => off += n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => poll.poll(events, None)?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Receive+decrypt one application message over a non-blocking mio socket.
fn pump_read<S: Source + Read>(
    conn: &mut Connection,
    sock: &mut S,
    poll: &mut Poll,
    events: &mut Events,
) -> io::Result<Vec<u8>> {
    loop {
        let pt = conn.recv().unwrap();
        if !pt.is_empty() {
            return Ok(pt);
        }
        let mut buf = [0u8; 4096];
        match sock.read(&mut buf) {
            Ok(0) => return Ok(Vec::new()),
            Ok(n) => {
                let mut fed = 0;
                while fed < n {
                    fed += conn.feed(&buf[fed..n]).unwrap();
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => poll.poll(events, None)?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// A full handshake driven by `drive_handshake` on both ends over a mio
/// `Poll`, then one app message each way.
#[test]
fn mio_drive_round_trip() {
    let (key, leaf) = server_identity(b"mio-rt", "mio.example");
    let server_cfg = Config::builder()
        .tls_only()
        .rng(Arc::new(OsRng))
        .identity(vec![leaf.clone()], SigningKey::Ecdsa(key))
        .build();

    // Blocking std accept on a background thread → hand the stream to mio.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (std_sock, _) = listener.accept().unwrap();
        std_sock.set_nonblocking(true).unwrap();
        let mut sock = TcpStream::from_std(std_sock);
        let mut conn = Connection::server(&server_cfg).unwrap();
        let mut poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(8);
        drive_handshake(&mut conn, &mut sock, &mut poll, SOCK, SIGNER).unwrap();
        assert!(conn.is_handshake_complete());
        poll.registry()
            .register(&mut sock, SOCK, Interest::READABLE | Interest::WRITABLE)
            .unwrap();
        let msg = pump_read(&mut conn, &mut sock, &mut poll, &mut events).unwrap();
        assert_eq!(msg, b"ping");
        pump_write(&mut conn, &mut sock, &mut poll, &mut events, b"pong").unwrap();
    });

    let client_cfg = client_config(leaf, "mio.example");
    let mut sock = TcpStream::connect(addr).unwrap();
    let mut conn = Connection::client(&client_cfg).unwrap();
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(8);
    drive_handshake(&mut conn, &mut sock, &mut poll, SOCK, SIGNER).unwrap();
    assert!(conn.is_handshake_complete());
    poll.registry()
        .register(&mut sock, SOCK, Interest::READABLE | Interest::WRITABLE)
        .unwrap();
    pump_write(&mut conn, &mut sock, &mut poll, &mut events, b"ping").unwrap();
    let msg = pump_read(&mut conn, &mut sock, &mut poll, &mut events).unwrap();
    assert_eq!(msg, b"pong");

    server.join().unwrap();
}

/// The device-signer path under mio: the server identity is an external
/// `PrivateKey` whose `SignOp` pends on a fd, so `drive_handshake` registers a
/// `SignerSource` and waits on it via the `Poll`.
#[cfg(unix)]
#[test]
fn mio_drive_device_signer() {
    use purecrypto::tls::{PrivateKey, Readiness, SignOp, SignProgress};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    const ECDSA_SECP256R1_SHA256: u16 = 0x0403;

    struct DeviceKey {
        key: BoxedEcdsaPrivateKey,
    }
    impl PrivateKey for DeviceKey {
        fn schemes(&self) -> Vec<u16> {
            vec![ECDSA_SECP256R1_SHA256]
        }
        fn start_sign(
            &self,
            _scheme: u16,
            message: &[u8],
        ) -> Result<Box<dyn SignOp>, purecrypto::tls::Error> {
            let (near, far) = UnixStream::pair().unwrap();
            near.set_nonblocking(true).unwrap();
            let key = self.key.clone();
            let msg = message.to_vec();
            std::thread::spawn(move || {
                let mut far = far;
                std::thread::sleep(std::time::Duration::from_millis(5));
                let sig = key.sign::<Sha256>(&msg).unwrap().to_der(CurveId::P256);
                let len = u16::try_from(sig.len()).unwrap();
                let _ = far.write_all(&len.to_be_bytes());
                let _ = far.write_all(&sig);
            });
            Ok(Box::new(DeviceOp {
                near,
                buf: Vec::new(),
            }))
        }
    }
    struct DeviceOp {
        near: UnixStream,
        buf: Vec<u8>,
    }
    impl SignOp for DeviceOp {
        fn resume(&mut self) -> Result<SignProgress, purecrypto::tls::Error> {
            let mut chunk = [0u8; 256];
            loop {
                match self.near.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(purecrypto::tls::Error::HandshakeFailure),
                }
            }
            if self.buf.len() < 2 {
                return Ok(SignProgress::Pending);
            }
            let len = u16::from_be_bytes([self.buf[0], self.buf[1]]) as usize;
            if self.buf.len() < 2 + len {
                return Ok(SignProgress::Pending);
            }
            Ok(SignProgress::Done(self.buf[2..2 + len].to_vec()))
        }
        fn readiness(&self) -> Option<Readiness> {
            Some(Readiness::from_raw_fd(self.near.as_raw_fd()))
        }
    }

    let (key, leaf) = server_identity(b"mio-device", "device.example");
    let server_cfg = Config::builder()
        .tls_only()
        .rng(Arc::new(OsRng))
        .private_key(vec![leaf.clone()], Arc::new(DeviceKey { key }))
        .build();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (std_sock, _) = listener.accept().unwrap();
        std_sock.set_nonblocking(true).unwrap();
        let mut sock = TcpStream::from_std(std_sock);
        let mut conn = Connection::server(&server_cfg).unwrap();
        let mut poll = Poll::new().unwrap();
        drive_handshake(&mut conn, &mut sock, &mut poll, SOCK, SIGNER).unwrap();
        assert!(conn.is_handshake_complete());
    });

    let client_cfg = client_config(leaf, "device.example");
    let mut sock = TcpStream::connect(addr).unwrap();
    let mut conn = Connection::client(&client_cfg).unwrap();
    let mut poll = Poll::new().unwrap();
    drive_handshake(&mut conn, &mut sock, &mut poll, SOCK, SIGNER).unwrap();
    assert!(conn.is_handshake_complete());

    server.join().unwrap();
}
