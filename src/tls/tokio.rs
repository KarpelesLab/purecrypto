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
        match Self::handshake_loop(&mut conn, &mut sock).await {
            Ok(()) => Ok(TlsStream {
                conn,
                sock,
                rbuf: Plaintext::default(),
                rpos: 0,
                wbuf: Vec::new(),
                wpos: 0,
            }),
            Err(e) => {
                // A protocol failure leaves the fatal alert describing it
                // queued in the engine (`feed`/`drive` return before the
                // loop's next `WantWrite`). Make one non-blocking attempt to
                // put it on the wire so the peer learns *why* the handshake
                // died instead of seeing a bare FIN; never delay or mask the
                // primary error for it.
                if let Ok(out) = conn.pop()
                    && !out.is_empty()
                {
                    let mut sock = Pin::new(&mut sock);
                    core::future::poll_fn(|cx| {
                        let _ = sock.as_mut().poll_write(cx, &out);
                        Poll::Ready(())
                    })
                    .await;
                }
                Err(e)
            }
        }
    }

    /// The handshake driver proper; `Ok(())` once the engine reports
    /// completion and its final flight has been flushed.
    async fn handshake_loop(conn: &mut Connection, sock: &mut S) -> io::Result<()> {
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
                Step::Complete => return Ok(()),
            }
        }
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
            // 3. Retry any backlog the engine owes the peer (a `KeyUpdate`
            // reply or alert queued by an earlier feed whose flush came
            // back `Pending`). That flush registered write interest, so
            // the wake-up that brought us here may be *writability*, not
            // readable data: a read-only application never calls
            // `poll_write`, so this is the only place the backlog can
            // drain. Best effort — a socket error here is the writer's to
            // surface, and `Pending` keeps the interest armed.
            let _ = this.flush_wbuf(cx);
            // 4. Need more ciphertext from the socket.
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
                    let mut feed_err = None;
                    while fed < filled.len() {
                        match this.conn.feed(&filled[fed..]) {
                            Ok(n) => fed += n,
                            Err(e) => {
                                feed_err = Some(e);
                                break;
                            }
                        }
                    }
                    // Feeding can queue records the engine owes the peer:
                    // a `KeyUpdate` reply (RFC 8446 §4.6.3), an alert, a
                    // post-handshake flight — and a *failed* feed queues
                    // the fatal alert describing the failure. Drain the
                    // engine on both outcomes. A read-only application
                    // never calls `poll_write`, so without draining here
                    // that queue grows for every inbound byte with no
                    // ceiling and no backpressure — a peer streaming
                    // `KeyUpdate(update_requested)` could grow it until
                    // the process runs out of memory.
                    this.wbuf
                        .extend_from_slice(&this.conn.pop().map_err(ioerr)?);
                    // Best-effort flush: if the socket is not writable right
                    // now the bytes stay in `wbuf` and go out on the next
                    // poll (step 3) or write. `poll_read` must not return
                    // `Pending` on the write side's behalf, so the result is
                    // discarded. On a fatal feed error this is the last-ditch
                    // attempt to deliver the alert before the error surfaces
                    // — the error itself is never delayed or masked by it.
                    let _ = this.flush_wbuf(cx);
                    if let Some(e) = feed_err {
                        return Poll::Ready(Err(ioerr(e)));
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

#[cfg(test)]
mod tests {
    //! Liveness of the read path: replies the engine generates while the
    //! application only *reads* (a `KeyUpdate` answer, the fatal alert of a
    //! failed `feed`) must still reach the peer.

    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::pin::Pin;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use core::task::{Context, Poll};
    use core::time::Duration;
    use std::io;

    use ::tokio::io::{
        AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, duplex,
    };

    use super::TlsStream;
    use crate::ec::{BoxedEcdsaPrivateKey, CurveId};
    use crate::hash::Sha256;
    use crate::rng::{HmacDrbg, OsRng};
    use crate::tls::conn::{ClientConfig, ClientConnection};
    use crate::tls::{AlertDescription, Config, Connection, Error, RootCertStore, SigningKey};
    use crate::x509::{CertSigner, Certificate, DistinguishedName, Time, Validity};

    const TIMEOUT: Duration = Duration::from_secs(10);

    /// A transport that answers the next `stalls` `poll_write`s with
    /// `Pending` (waking itself so the task is re-polled), then passes
    /// through. Models a socket whose send buffer is momentarily full — the
    /// case where a read-side flush cannot complete immediately.
    struct StallWrites<S> {
        inner: S,
        stalls: Arc<AtomicUsize>,
    }

    impl<S: AsyncRead + Unpin> AsyncRead for StallWrites<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for StallWrites<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.stalls.load(Ordering::SeqCst) > 0 {
                self.stalls.fetch_sub(1, Ordering::SeqCst);
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Pin::new(&mut self.inner).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    fn server_config() -> (Config, Vec<u8>) {
        let mut kg = HmacDrbg::<Sha256>::new(b"tokio-unit", b"nonce", &[]);
        let key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut kg);
        let name = DistinguishedName::common_name("tokio.example");
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
            &["tokio.example"],
        )
        .unwrap();
        let leaf = cert.to_der().to_vec();
        let cfg = Config::builder()
            .tls_only()
            .rng(Arc::new(OsRng))
            .identity(alloc::vec![leaf.clone()], SigningKey::Ecdsa(key))
            .build();
        (cfg, leaf)
    }

    /// A raw (sans-I/O) client engine: the peer we drive by hand so the test
    /// controls exactly which records it sends and observes.
    fn raw_client(leaf: Vec<u8>) -> ClientConnection {
        let mut roots = RootCertStore::new();
        roots.add_der(leaf).unwrap();
        ClientConnection::new(ClientConfig::new(roots), "tokio.example", &mut OsRng).unwrap()
    }

    /// Pumps the raw client through its handshake over `pipe`, then drains
    /// whatever the server already wrote (its NewSessionTicket flight) so
    /// the pipe is empty when the test starts poking at it.
    async fn pump_raw_client(client: &mut ClientConnection, pipe: &mut DuplexStream) {
        let mut buf = [0u8; 16 * 1024];
        loop {
            let out = client.write_tls();
            if !out.is_empty() {
                pipe.write_all(&out).await.unwrap();
            }
            if !client.is_handshaking() {
                break;
            }
            let n = pipe.read(&mut buf).await.unwrap();
            assert!(n > 0, "server closed during handshake");
            client.read_tls(&buf[..n]);
            client.process_new_packets().unwrap();
        }
        // Non-blocking drain: the server's `handshake` future has already
        // completed by the time this matters, so everything it wrote is
        // sitting in the duplex buffer.
        loop {
            let mut rb = ReadBuf::new(&mut buf);
            let got =
                core::future::poll_fn(|cx| match Pin::new(&mut *pipe).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => Poll::Ready(rb.filled().len()),
                    Poll::Ready(Err(e)) => panic!("pipe read: {e}"),
                    Poll::Pending => Poll::Ready(0),
                })
                .await;
            if got == 0 {
                break;
            }
            client.read_tls(&buf[..got]);
            client.process_new_packets().unwrap();
        }
    }

    /// Server `TlsStream` (over a stalling transport) handshaken against a
    /// raw client engine on the other end of a duplex pipe.
    async fn handshaken_pair() -> (
        TlsStream<StallWrites<DuplexStream>>,
        Arc<AtomicUsize>,
        ClientConnection,
        DuplexStream,
    ) {
        let (cfg, leaf) = server_config();
        let (a, mut b) = duplex(64 * 1024);
        let stalls = Arc::new(AtomicUsize::new(0));
        let sock = StallWrites {
            inner: a,
            stalls: stalls.clone(),
        };
        let conn = Connection::server(&cfg).unwrap();
        let mut client = raw_client(leaf);
        let (tls, ()) = ::tokio::join!(
            TlsStream::handshake(conn, sock),
            pump_raw_client(&mut client, &mut b)
        );
        (tls.unwrap(), stalls, client, b)
    }

    /// RFC 8446 §4.6.3: a peer's `KeyUpdate(update_requested)` must be
    /// answered even though the application never writes — and even when
    /// the first flush attempt finds the socket unwritable. The server side
    /// only ever calls `read`; the raw client waits for the reply with a
    /// timeout (the pre-fix code left it in `wbuf` forever once the flush
    /// returned `Pending`, so the client's wait would expire).
    #[::tokio::test]
    async fn read_only_application_answers_key_update_request() {
        let (mut tls, stalls, mut client, mut pipe) = handshaken_pair().await;

        // The next server-side write attempt stalls: this is the read-path
        // flush of the KeyUpdate reply.
        stalls.store(1, Ordering::SeqCst);
        client.request_key_update().unwrap();
        client.send_application_data(b"hello").unwrap();
        pipe.write_all(&client.write_tls()).await.unwrap();

        let server_side = async {
            let mut buf = [0u8; 64];
            let n = tls.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"hello");
            // Still read-only: the next read is what retries the stalled
            // flush and, later, receives the client's follow-up.
            let n = tls.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"again");
            // Only now does the application write; the client decrypting
            // this proves it processed our KeyUpdate reply (our write key
            // rolled forward when the reply was generated).
            tls.write_all(b"pong").await.unwrap();
            tls.flush().await.unwrap();
        };
        let client_side = async {
            let mut buf = [0u8; 4096];
            let n = pipe.read(&mut buf).await.unwrap();
            assert!(n > 0, "server hung up instead of answering the KeyUpdate");
            client.read_tls(&buf[..n]);
            client.process_new_packets().unwrap();
            assert!(
                client.take_received_plaintext().is_empty(),
                "the reply must be a KeyUpdate, not application data"
            );
            client.send_application_data(b"again").unwrap();
            pipe.write_all(&client.write_tls()).await.unwrap();
            let n = pipe.read(&mut buf).await.unwrap();
            client.read_tls(&buf[..n]);
            client.process_new_packets().unwrap();
            assert_eq!(client.take_received_plaintext(), b"pong");
        };
        ::tokio::time::timeout(TIMEOUT, async {
            ::tokio::join!(server_side, client_side);
        })
        .await
        .expect("KeyUpdate reply never reached the peer");
        assert_eq!(
            stalls.load(Ordering::SeqCst),
            0,
            "the stall must have been consumed"
        );
    }

    /// A record that fails deprotection is a fatal `bad_record_mac`. The
    /// alert the engine queues for it must be delivered before the read
    /// error surfaces to the application; the peer sees `AlertReceived`
    /// rather than a silent hang (the pre-fix `poll_read` returned on the
    /// `feed` error before ever popping the engine's output).
    #[::tokio::test]
    async fn fatal_alert_is_delivered_before_read_error_surfaces() {
        let (mut tls, _stalls, mut client, mut pipe) = handshaken_pair().await;

        // A well-formed application_data record whose payload is junk (long
        // enough to carry an AEAD tag, so the failure is the MAC check).
        let mut junk = alloc::vec![0x17, 0x03, 0x03, 0x00, 0x20];
        junk.extend((1..=32u8).collect::<Vec<u8>>());
        pipe.write_all(&junk).await.unwrap();

        let server_side = async {
            let mut buf = [0u8; 64];
            let err = tls.read(&mut buf).await.unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::Other);
        };
        let client_side = async {
            let mut buf = [0u8; 4096];
            let n = pipe.read(&mut buf).await.unwrap();
            assert!(n > 0, "server hung up without sending an alert");
            client.read_tls(&buf[..n]);
            let res = client.process_new_packets();
            assert!(
                matches!(
                    res,
                    Err(Error::AlertReceived(AlertDescription::BadRecordMac))
                ),
                "peer must receive the fatal bad_record_mac alert, got {res:?}"
            );
        };
        ::tokio::time::timeout(TIMEOUT, async {
            ::tokio::join!(server_side, client_side);
        })
        .await
        .expect("fatal alert never reached the peer");
    }
}
