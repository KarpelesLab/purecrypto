//! mio reactor I/O surface for the sans-I/O TLS engine (`mio` feature).
//!
//! Two pieces let a synchronous, single-threaded [`mio`] event loop drive the
//! engine, including a device-backed signer:
//!
//! - [`SignerSource`] (unix) wraps the signer's [`Readiness`](super::Readiness)
//!   as a [`mio::event::Source`], so its fd registers with a [`mio::Poll`]
//!   alongside your socket.
//! - [`drive_handshake`] runs a [`Connection`] handshake to
//!   completion against a non-blocking, mio-registered socket, registering the
//!   signer fd on demand when the engine asks for it.
//!
//! TLS only (stream transport); drive DTLS manually.

use std::io::{self, Read, Write};

use super::{Connection, Error, Step};

fn ioerr(e: Error) -> io::Error {
    io::Error::other(e)
}

/// The signer's [`Readiness`](super::Readiness) as a registerable
/// [`mio::event::Source`] (unix; a thin [`mio::unix::SourceFd`] over the fd).
///
/// Register it with your [`mio::Poll`] when [`drive`](super::Connection::drive)
/// yields [`Step::WantSigner`]; the fd is owned by the
/// signing operation and stays valid until the next
/// [`drive`](super::Connection::drive).
#[cfg(unix)]
pub struct SignerSource {
    fd: std::os::fd::RawFd,
}

#[cfg(unix)]
impl SignerSource {
    /// Wrap the readiness token's descriptor.
    pub fn new(readiness: &super::Readiness) -> Self {
        use std::os::fd::AsRawFd;
        SignerSource {
            fd: readiness.as_raw_fd(),
        }
    }
}

#[cfg(unix)]
impl ::mio::event::Source for SignerSource {
    fn register(
        &mut self,
        registry: &::mio::Registry,
        token: ::mio::Token,
        interests: ::mio::Interest,
    ) -> io::Result<()> {
        ::mio::unix::SourceFd(&self.fd).register(registry, token, interests)
    }
    fn reregister(
        &mut self,
        registry: &::mio::Registry,
        token: ::mio::Token,
        interests: ::mio::Interest,
    ) -> io::Result<()> {
        ::mio::unix::SourceFd(&self.fd).reregister(registry, token, interests)
    }
    fn deregister(&mut self, registry: &::mio::Registry) -> io::Result<()> {
        ::mio::unix::SourceFd(&self.fd).deregister(registry)
    }
}

/// Drive `conn`'s handshake to completion over a non-blocking, mio-compatible
/// `sock`, using `poll` as the reactor. `sock_token` / `signer_token` identify
/// the socket and (when the engine needs it) the signing device in the
/// `poll`'s event set; pass two distinct tokens.
///
/// The socket must already be non-blocking (e.g. `mio::net::TcpStream`). On
/// return, the socket has been deregistered from `poll`; the caller may
/// re-register it for application I/O.
pub fn drive_handshake<S>(
    conn: &mut Connection,
    sock: &mut S,
    poll: &mut ::mio::Poll,
    sock_token: ::mio::Token,
    signer_token: ::mio::Token,
) -> io::Result<()>
where
    S: ::mio::event::Source + Read + Write,
{
    use ::mio::{Events, Interest};

    poll.registry()
        .register(sock, sock_token, Interest::READABLE | Interest::WRITABLE)?;
    let mut events = Events::with_capacity(8);

    let result = drive_loop(conn, sock, poll, &mut events, sock_token, signer_token);

    // Always leave the socket deregistered, regardless of outcome.
    let _ = poll.registry().deregister(sock);
    result
}

fn drive_loop<S>(
    conn: &mut Connection,
    sock: &mut S,
    poll: &mut ::mio::Poll,
    events: &mut ::mio::Events,
    sock_token: ::mio::Token,
    signer_token: ::mio::Token,
) -> io::Result<()>
where
    S: ::mio::event::Source + Read + Write,
{
    let _ = (sock_token, signer_token);
    loop {
        match conn.drive().map_err(ioerr)? {
            Step::Complete => return Ok(()),
            Step::WantWrite => {
                let out = conn.pop().map_err(ioerr)?;
                let mut off = 0;
                while off < out.len() {
                    match sock.write(&out[off..]) {
                        Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                        Ok(n) => off += n,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            poll.poll(events, None)?;
                        }
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                }
            }
            Step::WantRead => {
                // Drain the socket to EWOULDBLOCK before blocking: mio is
                // edge-triggered, so the readiness edge is only re-armed once a
                // read returns WouldBlock. Reading just once and then polling
                // would lose the next edge and hang.
                let mut buf = [0u8; 16 * 1024];
                let mut progressed = false;
                loop {
                    match sock.read(&mut buf) {
                        Ok(0) => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "peer closed during handshake",
                            ));
                        }
                        Ok(n) => {
                            let mut fed = 0;
                            while fed < n {
                                fed += conn.feed(&buf[fed..n]).map_err(ioerr)?;
                            }
                            progressed = true;
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(e),
                    }
                }
                // Nothing was available: the edge is now armed, so block until
                // the peer sends more, then re-drive. If we did read, fall
                // straight back to drive() to consume it.
                if !progressed {
                    poll.poll(events, None)?;
                }
            }
            Step::WantSigner(readiness) => {
                #[cfg(unix)]
                if let Some(r) = readiness {
                    // Register the signer fd on a DEDICATED poll and block on it,
                    // so we never disturb (and lose, under edge-triggering) the
                    // socket's readiness on the caller's `poll`.
                    let mut src = SignerSource::new(&r);
                    let mut spoll = ::mio::Poll::new()?;
                    spoll
                        .registry()
                        .register(&mut src, signer_token, ::mio::Interest::READABLE)?;
                    let mut sev = ::mio::Events::with_capacity(4);
                    loop {
                        spoll.poll(&mut sev, None)?;
                        if sev.iter().any(|ev| ev.token() == signer_token) {
                            break;
                        }
                    }
                    continue;
                }
                // No waitable fd (or non-unix): just re-drive. In-process keys
                // never reach here.
                let _ = &readiness;
            }
        }
    }
}
