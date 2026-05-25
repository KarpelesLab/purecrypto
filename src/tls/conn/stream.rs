//! A blocking [`std::io`] adapter over the sans-I/O connection core.
//!
//! [`Stream`] wraps a TLS [`Connection`] together with any
//! `Read + Write` transport (e.g. a `TcpStream`) and drives the handshake and
//! record I/O so the caller can treat an established connection as an ordinary
//! byte stream.

use super::{ClientConnection, ServerConnection};
use crate::rng::RngCore;
use crate::tls::Error as TlsError;
use alloc::vec::Vec;
use std::io::{self, Read, Write};

/// The connection behaviours [`Stream`] drives, implemented by both
/// [`ClientConnection`] and [`ServerConnection`].
pub trait Connection {
    /// Feeds received TLS bytes.
    fn read_tls(&mut self, bytes: &[u8]);
    /// Removes and returns bytes queued for transmission.
    fn write_tls(&mut self) -> Vec<u8>;
    /// Advances the state machine over buffered records.
    fn process_new_packets(&mut self) -> Result<(), TlsError>;
    /// Whether the handshake is still in progress.
    fn is_handshaking(&self) -> bool;
    /// Queues application data for sending.
    fn send_application_data(&mut self, data: &[u8]) -> Result<(), TlsError>;
    /// Removes and returns any received application plaintext.
    fn take_received_plaintext(&mut self) -> Vec<u8>;
}

impl Connection for ClientConnection {
    fn read_tls(&mut self, bytes: &[u8]) {
        ClientConnection::read_tls(self, bytes)
    }
    fn write_tls(&mut self) -> Vec<u8> {
        ClientConnection::write_tls(self)
    }
    fn process_new_packets(&mut self) -> Result<(), TlsError> {
        ClientConnection::process_new_packets(self)
    }
    fn is_handshaking(&self) -> bool {
        ClientConnection::is_handshaking(self)
    }
    fn send_application_data(&mut self, data: &[u8]) -> Result<(), TlsError> {
        ClientConnection::send_application_data(self, data)
    }
    fn take_received_plaintext(&mut self) -> Vec<u8> {
        ClientConnection::take_received_plaintext(self)
    }
}

impl<R: RngCore> Connection for ServerConnection<R> {
    fn read_tls(&mut self, bytes: &[u8]) {
        ServerConnection::read_tls(self, bytes)
    }
    fn write_tls(&mut self) -> Vec<u8> {
        ServerConnection::write_tls(self)
    }
    fn process_new_packets(&mut self) -> Result<(), TlsError> {
        ServerConnection::process_new_packets(self)
    }
    fn is_handshaking(&self) -> bool {
        ServerConnection::is_handshaking(self)
    }
    fn send_application_data(&mut self, data: &[u8]) -> Result<(), TlsError> {
        ServerConnection::send_application_data(self, data)
    }
    fn take_received_plaintext(&mut self) -> Vec<u8> {
        ServerConnection::take_received_plaintext(self)
    }
}

/// A blocking TLS stream: a [`Connection`] driven over a `Read + Write`
/// transport.
pub struct Stream<'a, C: Connection, T: Read + Write> {
    conn: &'a mut C,
    sock: &'a mut T,
    /// Received plaintext not yet handed to the reader.
    pending: Vec<u8>,
}

impl<'a, C: Connection, T: Read + Write> Stream<'a, C, T> {
    /// Wraps `conn` and `sock`.
    pub fn new(conn: &'a mut C, sock: &'a mut T) -> Self {
        Stream {
            conn,
            sock,
            pending: Vec::new(),
        }
    }

    /// Writes any queued TLS records to the transport.
    fn flush_tls(&mut self) -> io::Result<()> {
        let out = self.conn.write_tls();
        if !out.is_empty() {
            self.sock.write_all(&out)?;
            self.sock.flush()?;
        }
        Ok(())
    }

    /// Reads one chunk from the transport and processes it. Returns the number
    /// of transport bytes consumed (0 on EOF).
    fn read_and_process(&mut self) -> io::Result<usize> {
        let mut buf = [0u8; 4096];
        let n = self.sock.read(&mut buf)?;
        if n == 0 {
            return Ok(0);
        }
        self.conn.read_tls(&buf[..n]);
        self.conn
            .process_new_packets()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        self.pending
            .extend_from_slice(&self.conn.take_received_plaintext());
        Ok(n)
    }

    /// Drives the handshake to completion.
    pub fn complete_handshake(&mut self) -> io::Result<()> {
        while self.conn.is_handshaking() {
            self.flush_tls()?;
            if self.conn.is_handshaking() && self.read_and_process()? == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "peer closed during handshake",
                ));
            }
        }
        self.flush_tls()
    }
}

impl<C: Connection, T: Read + Write> Read for Stream<'_, C, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.conn.is_handshaking() {
            self.complete_handshake()?;
        }
        while self.pending.is_empty() {
            if self.read_and_process()? == 0 {
                return Ok(0); // clean EOF
            }
        }
        let n = self.pending.len().min(buf.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

impl<C: Connection, T: Read + Write> Write for Stream<'_, C, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.conn.is_handshaking() {
            self.complete_handshake()?;
        }
        self.conn
            .send_application_data(buf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_tls()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bignum::BoxedUint;
    use crate::rng::OsRng;
    use crate::rsa::BoxedRsaPrivateKey;
    use crate::test_util::rsa_test_key_a;
    use crate::tls::{ClientConfig, RootCertStore, ServerConfig};
    use crate::x509::{Certificate, DistinguishedName, Time, Validity};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    fn rsa_server() -> (ServerConfig, Vec<u8>) {
        let key = rsa_test_key_a();
        let name = DistinguishedName::common_name("localhost");
        let validity = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        let cert = Certificate::self_signed(&key, &name, &validity, 1, false).unwrap();
        let der = cert.to_der().to_vec();
        let mut buf = [0u8; 256];
        key.modulus().write_be_bytes(&mut buf);
        let n = BoxedUint::from_be_bytes(&buf);
        key.exponent().write_be_bytes(&mut buf);
        let e = BoxedUint::from_be_bytes(&buf);
        key.private_exponent().write_be_bytes(&mut buf);
        let d = BoxedUint::from_be_bytes(&buf);
        let boxed = BoxedRsaPrivateKey::from_components(n, e, d);
        (ServerConfig::with_rsa(alloc::vec![der.clone()], boxed), der)
    }

    // A real loopback over 127.0.0.1: the Stream adapter drives both sides'
    // handshakes and carries an application request/response.
    #[test]
    fn tcp_round_trip() {
        let (server_config, cert_der) = rsa_server();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut conn = ServerConnection::new(server_config, OsRng);
            let mut tls = Stream::new(&mut conn, &mut sock);
            tls.complete_handshake().unwrap();
            let mut buf = [0u8; 32];
            let n = tls.read(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"GET /");
            tls.write_all(b"200 OK").unwrap();
            tls.flush().unwrap();
        });

        let mut roots = RootCertStore::new();
        roots.add_der(cert_der).unwrap();
        let mut sock = TcpStream::connect(addr).unwrap();
        let mut conn = ClientConnection::new(ClientConfig::new(roots), "localhost", &mut OsRng);
        let mut tls = Stream::new(&mut conn, &mut sock);
        tls.complete_handshake().unwrap();
        tls.write_all(b"GET /").unwrap();
        tls.flush().unwrap();
        let mut buf = [0u8; 32];
        let n = tls.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"200 OK");

        server.join().unwrap();
    }
}
