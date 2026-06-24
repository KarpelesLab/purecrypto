//! Tokio async I/O surface for the sans-I/O TLS engine (`tokio` feature).
//!
//! [`TlsStream`] wraps a [`Connection`] plus any tokio
//! [`AsyncRead`] + [`AsyncWrite`] transport (typically a `tokio::net::TcpStream`)
//! and turns the sans-I/O [`drive`](super::Connection::drive) loop into an
//! ordinary async stream: [`handshake`](TlsStream::handshake) runs the
//! handshake to completion, then the value itself implements [`AsyncRead`] +
//! [`AsyncWrite`] over the TLS record layer.
//!
//! When the server identity is a device-backed [`HandshakeSigner`](super::HandshakeSigner)
//! (TPM/HSM), the handshake transparently awaits the signer's
//! [`Readiness`](super::Readiness) through [`tokio::io::unix::AsyncFd`] — the
//! caller writes no signing glue and never sees the device.
//!
//! TLS only: an async byte stream maps onto TLS, not DTLS datagrams. Drive DTLS
//! connections manually with [`Connection::drive`](super::Connection::drive).

use alloc::vec::Vec;
use core::pin::Pin;
use core::task::{Context, Poll, ready};
use std::io;

use ::tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::{Connection, Error, Step};

fn ioerr(e: Error) -> io::Error {
    io::Error::other(e)
}

/// Yield to the executor exactly once, then resume. Dependency-free equivalent
/// of `tokio::task::yield_now` (avoids pulling tokio's `rt` feature); used only
/// on the degenerate no-fd-yet-pending signer path.
async fn yield_once() {
    struct YieldOnce(bool);
    impl core::future::Future for YieldOnce {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.0 {
                Poll::Ready(())
            } else {
                self.0 = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
    YieldOnce(false).await;
}

/// A buffer of decrypted application plaintext that scrubs itself on drop
/// (defense-in-depth: decrypted bytes should not linger in freed heap).
/// Wraps a `Vec<u8>` and wipes its live contents in `Drop`.
#[derive(Default)]
struct Plaintext(Vec<u8>);

impl core::ops::Deref for Plaintext {
    type Target = Vec<u8>;
    fn deref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl core::ops::DerefMut for Plaintext {
    fn deref_mut(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }
}

impl Drop for Plaintext {
    fn drop(&mut self) {
        super::conn::wipe(&mut self.0);
    }
}

/// An async TLS stream: a [`Connection`] bridged onto a tokio
/// [`AsyncRead`] + [`AsyncWrite`] transport. Construct via
/// [`handshake`](Self::handshake).
pub struct TlsStream<S> {
    conn: Connection,
    sock: S,
    /// Decrypted plaintext awaiting the reader (`rbuf[rpos..]`).
    rbuf: Plaintext,
    rpos: usize,
    /// Ciphertext awaiting the socket (`wbuf[wpos..]`).
    wbuf: Vec<u8>,
    wpos: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream<S> {
    /// Drive `conn`'s handshake to completion over `sock`, returning the ready
    /// stream. Build `conn` yourself with
    /// [`Connection::client`](super::Connection::client) /
    /// [`server`](super::Connection::server); the cert chain, RNG
    /// ([`ConfigBuilder::rng`](super::ConfigBuilder::rng)), and any device
    /// [`HandshakeSigner`](super::HandshakeSigner) come from its `Config`.
    pub async fn handshake(mut conn: Connection, mut sock: S) -> io::Result<Self> {
        let mut rd = [0u8; 16 * 1024];
        loop {
            match conn.drive().map_err(ioerr)? {
                Step::WantWrite => {
                    let out = conn.pop().map_err(ioerr)?;
                    if !out.is_empty() {
                        sock.write_all(&out).await?;
                        sock.flush().await?;
                    }
                }
                Step::WantRead => {
                    let n = sock.read(&mut rd).await?;
                    if n == 0 {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "peer closed during handshake",
                        ));
                    }
                    let mut fed = 0;
                    while fed < n {
                        fed += conn.feed(&rd[fed..n]).map_err(ioerr)?;
                    }
                }
                Step::WantSigner(readiness) => {
                    // The signing device needs servicing. Await its fd through
                    // the reactor, then re-drive so the SignOp can make progress.
                    #[cfg(unix)]
                    if let Some(r) = readiness {
                        use ::tokio::io::Interest;
                        use ::tokio::io::unix::AsyncFd;
                        // AsyncFd registers the (borrowed) fd; dropping it only
                        // deregisters — `Readiness` does not own/close the fd, so
                        // the SignOp retains it.
                        let afd = AsyncFd::with_interest(r, Interest::READABLE)?;
                        let mut guard = afd.readable().await?;
                        guard.clear_ready();
                        continue;
                    }
                    // No waitable fd (or non-unix): cooperatively yield, then
                    // re-drive. In-process keys never reach here.
                    let _ = &readiness;
                    yield_once().await;
                }
                Step::Complete => break,
            }
        }
        Ok(TlsStream {
            conn,
            sock,
            rbuf: Plaintext::default(),
            rpos: 0,
            wbuf: Vec::new(),
            wpos: 0,
        })
    }

    /// The negotiated protocol version, once known.
    pub fn negotiated_version(&self) -> Option<super::ProtocolVersion> {
        self.conn.negotiated_version()
    }

    /// Consume the stream, returning the inner [`Connection`] and transport.
    pub fn into_inner(self) -> (Connection, S) {
        // `self.rbuf` (a `Plaintext`) is dropped here, scrubbing any residual
        // decrypted application data; `conn`/`sock` move out to the caller.
        (self.conn, self.sock)
    }

    /// Flush `wbuf` to the socket without blocking; `Ready(Ok(()))` once empty.
    fn flush_wbuf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while self.wpos < self.wbuf.len() {
            match Pin::new(&mut self.sock).poll_write(cx, &self.wbuf[self.wpos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => self.wpos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.wbuf.clear();
        self.wpos = 0;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // 1. Serve already-decrypted plaintext.
            if this.rpos < this.rbuf.len() {
                let n = (this.rbuf.len() - this.rpos).min(buf.remaining());
                buf.put_slice(&this.rbuf[this.rpos..this.rpos + n]);
                this.rpos += n;
                if this.rpos == this.rbuf.len() {
                    // Plaintext fully delivered to the reader: scrub it before
                    // releasing the buffer (defense-in-depth — decrypted
                    // application data should not linger in freed capacity).
                    super::conn::wipe(&mut this.rbuf);
                    this.rbuf.clear();
                    this.rpos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            // 2. Pull plaintext the engine already has buffered.
            let pt = this.conn.recv().map_err(ioerr)?;
            if !pt.is_empty() {
                // Replacing `rbuf` drops the previous `Plaintext`, which scrubs
                // its residual decrypted bytes.
                this.rbuf = Plaintext(pt);
                this.rpos = 0;
                continue;
            }
            // 3. Need more ciphertext from the socket.
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.sock).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => {
                    let filled = rb.filled();
                    if filled.is_empty() {
                        // Transport EOF. RFC 8446 §6.1: a TLS peer signals
                        // end-of-data with a `close_notify` alert. If the
                        // transport closed WITHOUT one, the stream was
                        // truncated — possibly by an attacker stripping the
                        // tail — so we must surface an error rather than a
                        // clean EOF. Only a received close_notify makes EOF
                        // clean.
                        if this.conn.received_close_notify() {
                            // Orderly close: leave `buf` untouched (0 bytes).
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "peer closed connection without close_notify (possible truncation attack)",
                        )));
                    }
                    let mut fed = 0;
                    while fed < filled.len() {
                        fed += this.conn.feed(&filled[fed..]).map_err(ioerr)?;
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Push any backlog first so we don't grow `wbuf` unboundedly.
        ready!(this.flush_wbuf(cx))?;
        this.conn.send(buf).map_err(ioerr)?;
        let out = this.conn.pop().map_err(ioerr)?;
        this.wbuf.extend_from_slice(&out);
        // Best-effort flush; any remainder is drained by poll_flush.
        if let Poll::Ready(Err(e)) = this.flush_wbuf(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.flush_wbuf(cx))?;
        Pin::new(&mut this.sock).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.flush_wbuf(cx))?;
        // Emit close_notify, then flush it before shutting the transport.
        this.conn.close().map_err(ioerr)?;
        let out = this.conn.pop().map_err(ioerr)?;
        this.wbuf.extend_from_slice(&out);
        ready!(this.flush_wbuf(cx))?;
        Pin::new(&mut this.sock).poll_shutdown(cx)
    }
}
