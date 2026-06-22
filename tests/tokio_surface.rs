//! Integration tests for the `tokio` TLS surface (`purecrypto::tls::tokio`).
//!
//! Built only when the `tokio` feature is on; `cargo test --all-features`
//! exercises them on every CI OS.
#![cfg(feature = "tokio")]

use std::sync::Arc;

use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::hash::Sha256;
use purecrypto::rng::{HmacDrbg, OsRng};
use purecrypto::tls::tokio::TlsStream;
use purecrypto::tls::{Config, Connection, RootCertStore, SigningKey};
use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// A seeded self-signed ECDSA P-256 leaf + its key; the leaf doubles as the
/// client's trust anchor (directly trusted, like `examples/tls_loopback.rs`).
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

/// A full TLS 1.3 handshake + app-data round-trip, both ends wrapped in the
/// async `TlsStream`, over a real loopback `TcpStream`.
#[tokio::test]
async fn tls_stream_round_trip() {
    let (key, leaf) = server_identity(b"tokio-rt", "tokio.example");
    let server_cfg = Config::builder()
        .tls_only()
        .rng(Arc::new(OsRng))
        .identity(vec![leaf.clone()], SigningKey::Ecdsa(key))
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let conn = Connection::server(&server_cfg).unwrap();
        let mut tls = TlsStream::handshake(conn, sock).await.unwrap();
        let mut buf = [0u8; 16];
        let n = tls.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        tls.write_all(b"pong").await.unwrap();
        tls.flush().await.unwrap();
    });

    let client_cfg = client_config(leaf, "tokio.example");
    let sock = TcpStream::connect(addr).await.unwrap();
    let conn = Connection::client(&client_cfg).unwrap();
    let mut tls = TlsStream::handshake(conn, sock).await.unwrap();
    tls.write_all(b"ping").await.unwrap();
    tls.flush().await.unwrap();
    let mut buf = [0u8; 16];
    let n = tls.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"pong");

    server.await.unwrap();
}

/// The device-signer path: the server identity is an external `PrivateKey`
/// whose `SignOp` pends on a fd, so the async handshake must await it through
/// `AsyncFd`. The "device" is a thread on the far end of a `UnixStream`.
#[cfg(unix)]
#[tokio::test]
async fn tls_stream_device_signer() {
    use purecrypto::tls::{PrivateKey, Readiness, SignOp, SignProgress};
    use std::io::{Read, Write};
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
            // The "HSM": sign after a beat, write u16-len-prefixed DER back.
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
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
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

    let (key, leaf) = server_identity(b"tokio-device", "device.example");
    let server_cfg = Config::builder()
        .tls_only()
        .rng(Arc::new(OsRng))
        .private_key(vec![leaf.clone()], Arc::new(DeviceKey { key }))
        .build();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let conn = Connection::server(&server_cfg).unwrap();
        let mut tls = TlsStream::handshake(conn, sock).await.unwrap();
        let mut buf = [0u8; 16];
        let n = tls.read(&mut buf).await.unwrap();
        tls.write_all(&buf[..n]).await.unwrap();
        tls.flush().await.unwrap();
    });

    let client_cfg = client_config(leaf, "device.example");
    let sock = TcpStream::connect(addr).await.unwrap();
    let conn = Connection::client(&client_cfg).unwrap();
    let mut tls = TlsStream::handshake(conn, sock).await.unwrap();
    tls.write_all(b"echo").await.unwrap();
    tls.flush().await.unwrap();
    let mut buf = [0u8; 16];
    let n = tls.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"echo");

    server.await.unwrap();
}
