//! Shared UDP I/O scaffolding used by `s_client -dtls1_*` and
//! `s_server -dtls1_*`.
//!
//! The DTLS 1.2 and DTLS 1.3 client / server connection types in
//! [`purecrypto::dtls`] expose the same sans-I/O surface
//! (`feed_datagram`, `pop_outbound_datagrams`, `take_received`, `send`,
//! `next_timeout`, `on_timeout`, `is_handshake_complete`). This module
//! abstracts that surface into two traits and provides the blocking
//! handshake / data-pump loops both binaries share, so the four
//! version combinations don't each carry their own UDP plumbing.
//!
//! The traits are intentionally minimal — anything version-specific
//! (printing the protocol version, dumping per-connection key material,
//! ALPN reporting) is handled by the caller around the loops.
//!
//! Both traits use a generic `Datagrams` shape (one `Vec<u8>` per
//! datagram); the caller is responsible for socket I/O. We keep blocking
//! socket reads with short timeouts so the retransmit timers stay
//! responsive — exactly the pattern the `s_dtls_*` binaries used before
//! the unification.

use std::io::{Read, Write};
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use crate::util::die;

/// Sans-I/O surface shared by [`DtlsClientConnection12`] and
/// [`DtlsClientConnection13`] (and the server counterparts after their
/// peer is bound). Implemented for whichever connection type the CLI
/// instantiates per `-dtls1_*` flag.
pub(crate) trait DtlsCore {
    /// Have we transitioned out of the handshake into application data?
    fn is_handshake_complete(&self) -> bool;
    /// Drain any UDP datagrams queued by the state machine for the wire.
    fn pop_outbound(&mut self) -> Vec<Vec<u8>>;
    /// Feed one wire datagram into the state machine.
    fn feed(&mut self, datagram: &[u8]) -> Result<(), String>;
    /// Drain decrypted application bytes from the state machine.
    fn take_received(&mut self) -> Vec<u8>;
    /// Encrypt application plaintext for transmission.
    fn send_app(&mut self, plaintext: &[u8]) -> Result<(), String>;
    /// Absolute monotonic deadline at which `on_timeout` should fire next.
    fn next_timeout(&self) -> Option<Duration>;
    /// Advance the retransmit / ACK machinery to `now`.
    fn on_timeout(&mut self, now: Duration);
}

/// Drives a DTLS handshake to completion on a UDP socket that has been
/// `connect()`-ed to the peer (so `send` / `recv` work without explicit
/// addresses). Exits via [`die`] on any error.
pub(crate) fn drive_handshake<C: DtlsCore + ?Sized>(
    conn: &mut C,
    socket: &UdpSocket,
    mtu: usize,
    deadline: Duration,
) {
    let start = Instant::now();
    let handshake_deadline = start + deadline;
    let mut buf = vec![0u8; mtu.max(1500) + 256];

    while !conn.is_handshake_complete() {
        if Instant::now() > handshake_deadline {
            die("DTLS handshake timed out");
        }

        for dg in conn.pop_outbound() {
            socket
                .send(&dg)
                .unwrap_or_else(|e| die(format!("UDP send failed: {e}")));
        }

        let to = match conn.next_timeout() {
            Some(t) => {
                let now = start.elapsed();
                if t > now {
                    (t - now).min(Duration::from_millis(200))
                } else {
                    Duration::from_millis(1)
                }
            }
            None => Duration::from_millis(200),
        };
        socket.set_read_timeout(Some(to)).ok();

        match socket.recv(&mut buf) {
            Ok(n) => {
                if let Err(e) = conn.feed(&buf[..n]) {
                    die(format!("DTLS error: {e}"));
                }
            }
            Err(e) if is_timeout(&e) => { /* fall through to timer pump */ }
            Err(e) => die(format!("UDP recv failed: {e}")),
        }

        // Drain any datagrams produced by the just-fed record (server
        // flights often arrive then need an immediate ACK back).
        for dg in conn.pop_outbound() {
            socket
                .send(&dg)
                .unwrap_or_else(|e| die(format!("UDP send failed: {e}")));
        }

        if let Some(t) = conn.next_timeout()
            && start.elapsed() >= t
        {
            conn.on_timeout(start.elapsed());
        }
    }
}

/// Client-side data-phase pump: forwards stdin to the peer line by line,
/// prints peer plaintext to stdout, exits on stdin-EOF + post-stdin idle
/// or on `app_timeout`.
pub(crate) fn drive_client_data<C: DtlsCore + ?Sized>(
    conn: &mut C,
    socket: &UdpSocket,
    mtu: usize,
    app_timeout: Duration,
) {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin();
        let mut line = Vec::new();
        let mut chunk = [0u8; 1];
        loop {
            match stdin.read(&mut chunk) {
                Ok(0) => break,
                Ok(_) => {
                    line.push(chunk[0]);
                    if chunk[0] == b'\n' && tx.send(core::mem::take(&mut line)).is_err() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
        if !line.is_empty() {
            let _ = tx.send(line);
        }
        // Drop tx implicitly so the main loop sees disconnect.
    });

    let mut buf = vec![0u8; mtu.max(1500) + 256];
    let mut stdout = std::io::stdout();
    let app_deadline = Instant::now() + app_timeout;
    let post_stdin_idle = Duration::from_secs(2);
    let mut stdin_done = false;
    let mut last_inbound = Instant::now();

    loop {
        if Instant::now() > app_deadline {
            break;
        }
        loop {
            match rx.try_recv() {
                Ok(line) => {
                    last_inbound = Instant::now();
                    if let Err(e) = conn.send_app(&line) {
                        die(format!("DTLS send failed: {e}"));
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    stdin_done = true;
                    break;
                }
            }
        }
        for dg in conn.pop_outbound() {
            socket
                .send(&dg)
                .unwrap_or_else(|e| die(format!("UDP send failed: {e}")));
        }
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();
        match socket.recv(&mut buf) {
            Ok(n) => {
                last_inbound = Instant::now();
                if let Err(e) = conn.feed(&buf[..n]) {
                    die(format!("DTLS error: {e}"));
                }
                let plain = conn.take_received();
                if !plain.is_empty() {
                    let _ = stdout.write_all(&plain);
                    let _ = stdout.flush();
                }
            }
            Err(e) if is_timeout(&e) => { /* loop */ }
            Err(e) => die(format!("UDP recv failed: {e}")),
        }
        if stdin_done && last_inbound.elapsed() > post_stdin_idle {
            break;
        }
    }
}

/// Server-side data-phase pump: echoes any plaintext from the peer back
/// to the peer, exits on a contiguous `idle_limit` of inactivity.
pub(crate) fn drive_server_echo<C: DtlsCore + ?Sized>(
    conn: &mut C,
    socket: &UdpSocket,
    mtu: usize,
    idle_limit: Duration,
) {
    let mut buf = vec![0u8; mtu.max(1500) + 256];
    let mut last_activity = Instant::now();
    loop {
        if last_activity.elapsed() > idle_limit {
            break;
        }
        socket
            .set_read_timeout(Some(Duration::from_millis(250)))
            .ok();
        match socket.recv(&mut buf) {
            Ok(n) => {
                last_activity = Instant::now();
                if let Err(e) = conn.feed(&buf[..n]) {
                    die(format!("DTLS error: {e}"));
                }
                let plain = conn.take_received();
                if !plain.is_empty()
                    && let Err(e) = conn.send_app(&plain)
                {
                    die(format!("DTLS send failed: {e}"));
                }
            }
            Err(e) if is_timeout(&e) => { /* idle tick */ }
            Err(e) => die(format!("UDP recv failed: {e}")),
        }
        for dg in conn.pop_outbound() {
            socket
                .send(&dg)
                .unwrap_or_else(|e| die(format!("UDP send failed: {e}")));
        }
    }
}

/// Whether `e` is a socket-read timeout (which the platform reports as
/// either WouldBlock or TimedOut depending on the OS / mode).
pub(crate) fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

// --- Concrete `DtlsCore` impls for the four connection types ---

use purecrypto::dtls::{
    DtlsClientConnection12, DtlsClientConnection13, DtlsServerConnection12, DtlsServerConnection13,
};
use purecrypto::rng::RngCore;

impl DtlsCore for DtlsClientConnection12 {
    fn is_handshake_complete(&self) -> bool {
        DtlsClientConnection12::is_handshake_complete(self)
    }
    fn pop_outbound(&mut self) -> Vec<Vec<u8>> {
        self.pop_outbound_datagrams()
    }
    fn feed(&mut self, datagram: &[u8]) -> Result<(), String> {
        self.feed_datagram(datagram).map_err(|e| format!("{e:?}"))
    }
    fn take_received(&mut self) -> Vec<u8> {
        DtlsClientConnection12::take_received(self)
    }
    fn send_app(&mut self, plaintext: &[u8]) -> Result<(), String> {
        self.send(plaintext).map_err(|e| format!("{e:?}"))
    }
    fn next_timeout(&self) -> Option<Duration> {
        DtlsClientConnection12::next_timeout(self)
    }
    fn on_timeout(&mut self, now: Duration) {
        DtlsClientConnection12::on_timeout(self, now)
    }
}

impl DtlsCore for DtlsClientConnection13 {
    fn is_handshake_complete(&self) -> bool {
        DtlsClientConnection13::is_handshake_complete(self)
    }
    fn pop_outbound(&mut self) -> Vec<Vec<u8>> {
        self.pop_outbound_datagrams()
    }
    fn feed(&mut self, datagram: &[u8]) -> Result<(), String> {
        self.feed_datagram(datagram).map_err(|e| format!("{e:?}"))
    }
    fn take_received(&mut self) -> Vec<u8> {
        DtlsClientConnection13::take_received(self)
    }
    fn send_app(&mut self, plaintext: &[u8]) -> Result<(), String> {
        self.send(plaintext).map_err(|e| format!("{e:?}"))
    }
    fn next_timeout(&self) -> Option<Duration> {
        DtlsClientConnection13::next_timeout(self)
    }
    fn on_timeout(&mut self, now: Duration) {
        DtlsClientConnection13::on_timeout(self, now)
    }
}

impl<R: RngCore> DtlsCore for DtlsServerConnection12<R> {
    fn is_handshake_complete(&self) -> bool {
        DtlsServerConnection12::is_handshake_complete(self)
    }
    fn pop_outbound(&mut self) -> Vec<Vec<u8>> {
        self.pop_outbound_datagrams()
    }
    fn feed(&mut self, datagram: &[u8]) -> Result<(), String> {
        self.feed_datagram(datagram).map_err(|e| format!("{e:?}"))
    }
    fn take_received(&mut self) -> Vec<u8> {
        DtlsServerConnection12::take_received(self)
    }
    fn send_app(&mut self, plaintext: &[u8]) -> Result<(), String> {
        self.send(plaintext).map_err(|e| format!("{e:?}"))
    }
    fn next_timeout(&self) -> Option<Duration> {
        DtlsServerConnection12::next_timeout(self)
    }
    fn on_timeout(&mut self, now: Duration) {
        DtlsServerConnection12::on_timeout(self, now)
    }
}

impl<R: RngCore> DtlsCore for DtlsServerConnection13<R> {
    fn is_handshake_complete(&self) -> bool {
        DtlsServerConnection13::is_handshake_complete(self)
    }
    fn pop_outbound(&mut self) -> Vec<Vec<u8>> {
        self.pop_outbound_datagrams()
    }
    fn feed(&mut self, datagram: &[u8]) -> Result<(), String> {
        self.feed_datagram(datagram).map_err(|e| format!("{e:?}"))
    }
    fn take_received(&mut self) -> Vec<u8> {
        DtlsServerConnection13::take_received(self)
    }
    fn send_app(&mut self, plaintext: &[u8]) -> Result<(), String> {
        self.send(plaintext).map_err(|e| format!("{e:?}"))
    }
    fn next_timeout(&self) -> Option<Duration> {
        DtlsServerConnection13::next_timeout(self)
    }
    fn on_timeout(&mut self, now: Duration) {
        DtlsServerConnection13::on_timeout(self, now)
    }
}
