//! Transparent pluggable private keys: one `drive()` loop for any key.
//!
//! The server's identity key is installed as a [`PrivateKey`] trait object and
//! the handshake is driven with [`Connection::drive`]. The caller's loop is the
//! same it would write for an in-process key — it services peer I/O and, when
//! the engine needs the identity signature, simply waits on an *opaque*
//! readiness token. It never sees the message, the signature, or the device
//! transport.
//!
//! Here the "device" is a background thread reachable over a `UnixStream`: the
//! signing key lives in the thread (as an HSM would), and the [`SignOp`] on the
//! engine side waits for the reply on the socket fd. Swap the thread for a real
//! TPM/HSM driver and the server code below does not change.
//!
//! Run with: `cargo run --example tls_private_key_driven`

#[cfg(unix)]
fn main() {
    unix::run();
}

#[cfg(not(unix))]
fn main() {
    eprintln!("this example uses unix sockets to model the device; unix only");
}

#[cfg(unix)]
mod unix {
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    use std::sync::Arc;

    use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
    use purecrypto::hash::Sha256;
    use purecrypto::rng::HmacDrbg;
    use purecrypto::tls::{Config, Connection, PrivateKey, Readiness, SignOp, SignProgress, Step};
    use purecrypto::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    // ecdsa_secp256r1_sha256 (RFC 8446 §4.2.3).
    const ECDSA_SECP256R1_SHA256: u16 = 0x0403;

    /// A private key whose signing happens on a separate "device" thread,
    /// reached over a `UnixStream`. Models a TPM/HSM: the key never has to be in
    /// the engine's address space (we keep a clone here only to feed the mock
    /// device thread).
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
            let (near, far) = UnixStream::pair().expect("socketpair");
            near.set_nonblocking(true).expect("nonblocking");

            // Hand the request to the device thread: it owns the key, signs
            // after a little "hardware latency", and writes back a u16-length-
            // prefixed DER signature.
            let key = self.key.clone();
            let msg = message.to_vec();
            std::thread::spawn(move || {
                let mut far = far;
                std::thread::sleep(std::time::Duration::from_millis(5));
                let sig = key
                    .sign::<Sha256>(&msg)
                    .expect("device sign")
                    .to_der(CurveId::P256);
                let len = u16::try_from(sig.len()).expect("sig fits u16");
                let _ = far.write_all(&len.to_be_bytes());
                let _ = far.write_all(&sig);
            });

            Ok(Box::new(DeviceOp {
                near,
                buf: Vec::new(),
            }))
        }
    }

    /// The engine-side half of one signature: reads the device's reply off the
    /// socket, non-blocking, framed as `u16 len || der_sig`.
    struct DeviceOp {
        near: UnixStream,
        buf: Vec<u8>,
    }

    impl SignOp for DeviceOp {
        fn resume(&mut self) -> Result<SignProgress, purecrypto::tls::Error> {
            // Pull whatever is available without blocking.
            let mut chunk = [0u8; 256];
            loop {
                match self.near.read(&mut chunk) {
                    Ok(0) => break, // peer finished writing
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
                return Ok(SignProgress::Pending); // more bytes still in flight
            }
            Ok(SignProgress::Done(self.buf[2..2 + len].to_vec()))
        }

        fn readiness(&self) -> Option<Readiness> {
            // Tell the caller which fd to wait on while we're Pending.
            Some(Readiness::from_raw_fd(self.near.as_raw_fd()))
        }
    }

    pub(crate) fn run() {
        // The key the "device" will use, plus a self-signed cert over it.
        let mut kg = HmacDrbg::<Sha256>::new(b"driven-example", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut kg);
        let name = DistinguishedName::common_name("device.example");
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
            &["device.example"],
        )
        .unwrap();
        let cert_der = cert.to_der().to_vec();

        // Install the key as a trait object — no key bytes, no transport, in
        // the server config. The caller is now key-agnostic.
        let server_cfg = Config::builder()
            .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
            .tls_only()
            .private_key(vec![cert_der], Arc::new(DeviceKey { key }))
            .build();
        let mut server = Connection::server(&server_cfg).expect("server config");

        let client_cfg = Config::builder()
            .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
            .tls_only()
            .verify_certificates(false)
            .server_name("device.example")
            .build();
        let mut client = Connection::client(&client_cfg).expect("client config");

        // Drive: the server loop never branches on the key kind. The only
        // signing-specific arm just waits on an opaque fd.
        for _ in 0..32 {
            loop {
                let out = client.pop().unwrap();
                if out.is_empty() {
                    break;
                }
                server.feed(&out).unwrap();
            }
            loop {
                match server.drive().expect("drive") {
                    Step::WantWrite => {
                        let out = server.pop().unwrap();
                        if out.is_empty() {
                            break;
                        }
                        client.feed(&out).unwrap();
                    }
                    // Sync: block on the device fd. Async would instead register
                    // `r.as_raw_fd()` with the reactor (`tokio::io::unix::AsyncFd`)
                    // and `.await` its readability — same loop, same `drive()`.
                    Step::WantSigner(Some(r)) => {
                        println!("server waiting on signing device (fd {})", r.as_raw_fd());
                        r.wait().expect("wait on device");
                    }
                    Step::WantSigner(None) => {}
                    Step::WantRead | Step::Complete => break,
                    // `Step` is #[non_exhaustive]; nothing to do for future
                    // reasons in this example — yield back to the outer loop.
                    _ => break,
                }
            }
            if client.is_handshake_complete() && server.is_handshake_complete() {
                break;
            }
        }

        assert!(client.is_handshake_complete() && server.is_handshake_complete());
        println!("handshake complete — identity signed by the (mock) device");

        // Prove the channel works.
        client.send(b"ping").unwrap();
        let req = client.pop().unwrap();
        server.feed(&req).unwrap();
        println!(
            "server received: {:?}",
            String::from_utf8_lossy(&server.recv().unwrap_or_default())
        );
    }
}
