//! The UDP side of `s_client` / `s_server` in DTLS mode: one clock and one
//! receive step for the whole life of a connection.
//!
//! The DTLS engines are sans-I/O: they never read a clock, and a flight
//! queued while a datagram is processed arms its retransmission timer from
//! the last time the engine was *told* ([`Connection::set_now`],
//! [`Connection::on_timeout`]). So the driver
//!
//! - keeps a single [`Clock`] per connection, handshake and data phase
//!   alike — restarting it at the end of the handshake sent every timer
//!   armed during the handshake (the DTLS 1.3 client's Finished above all)
//!   seconds into the future;
//! - tells the engine the time before every datagram it feeds;
//! - wakes up at the engine's deadline rather than at the next tick of a
//!   fixed poll interval.
//!
//! It also knows when a connection may be left alone:
//! [`Connection::handshake_flight_pending`] says that the peer may still
//! be inside its handshake — our Finished or our ACK for its Finished was
//! lost — and the socket must keep being read, and the timers fired, until
//! it is not (RFC 9147 §5.8.1, RFC 6347 §4.2.4).

use std::io::ErrorKind;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use purecrypto::tls::{Connection, Error};

/// How long a DTLS handshake may take. A flight lost `n` times in a row
/// costs 2ⁿ − 1 seconds of backoff (1 s doubling, RFC 9147 §5.8.2 / RFC
/// 6347 §4.2.4.1): this admits five consecutive losses of one flight.
pub(crate) const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(45);

/// How long a finished session is kept alive for the sake of a peer that
/// may not have completed its handshake
/// ([`Connection::handshake_flight_pending`]) before it is closed anyway:
/// four retransmissions of a final flight (1 + 2 + 4 + 8 s) and some slack.
pub(crate) const FINAL_FLIGHT_WAIT: Duration = Duration::from_secs(20);

/// Longest sleep in [`step`]: the callers' own deadlines are checked at
/// least this often.
const POLL: Duration = Duration::from_millis(250);

/// The connection's monotonic clock: the time since it was created, which
/// is what the engine's timers are expressed in.
pub(crate) struct Clock(Instant);

impl Clock {
    pub(crate) fn start() -> Self {
        Self(Instant::now())
    }

    pub(crate) fn now(&self) -> Duration {
        self.0.elapsed()
    }
}

/// What one [`step`] saw.
pub(crate) enum Step {
    /// A datagram arrived and was processed.
    Datagram,
    /// Nothing arrived within the poll interval (a timer may have fired).
    Quiet,
    /// The socket failed — for a connected UDP socket typically an ICMP
    /// port-unreachable: the peer is gone.
    Gone,
}

/// Sends every datagram the engine has queued (flights and their
/// retransmissions, ACKs, application data, alerts).
pub(crate) fn flush(conn: &mut Connection, socket: &UdpSocket) {
    loop {
        let dg = conn.pop().unwrap_or_default();
        if dg.is_empty() {
            break;
        }
        let _ = socket.send(&dg);
    }
}

/// Tells the engine the time and fires its retransmission timer if due.
pub(crate) fn tick(conn: &mut Connection, clock: &Clock) {
    let now = clock.now();
    conn.set_now(now);
    if let Some(t) = conn.next_timeout()
        && now >= t
    {
        conn.on_timeout(now);
    }
}

/// One turn of the driver: flushes what is queued, waits for a datagram
/// until the engine's next deadline (at most [`POLL`]), feeds it, fires
/// the timer if due, and flushes again. An error from the engine — an
/// authenticated protocol violation or a fatal alert; whatever is
/// spoofable is dropped silently inside it — is returned.
pub(crate) fn step(
    conn: &mut Connection,
    socket: &UdpSocket,
    clock: &Clock,
    buf: &mut [u8],
) -> Result<Step, Error> {
    tick(conn, clock);
    flush(conn, socket);
    let wait = match conn.next_timeout() {
        Some(t) => t.saturating_sub(clock.now()).min(POLL),
        None => POLL,
    };
    // A zero timeout means "block forever" to the socket API.
    let _ = socket.set_read_timeout(Some(wait.max(Duration::from_millis(1))));
    let seen = match socket.recv(buf) {
        Ok(n) => {
            conn.set_now(clock.now());
            let fed = conn.feed(&buf[..n]);
            // An alert the engine queued on its way out still goes out.
            flush(conn, socket);
            fed?;
            Step::Datagram
        }
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => Step::Quiet,
        Err(e) if e.kind() == ErrorKind::Interrupted => Step::Quiet,
        Err(_) => Step::Gone,
    };
    tick(conn, clock);
    flush(conn, socket);
    Ok(seen)
}

/// Keeps a finished session alive while the peer may still be inside its
/// handshake: reads and answers datagrams and fires the retransmission
/// timer until [`Connection::handshake_flight_pending`] turns `false`, the
/// peer closes, or [`FINAL_FLIGHT_WAIT`] passes. `on_data` receives the
/// application data that arrives meanwhile.
pub(crate) fn settle(
    conn: &mut Connection,
    socket: &UdpSocket,
    clock: &Clock,
    buf: &mut [u8],
    mut on_data: impl FnMut(&mut Connection, Vec<u8>),
) {
    let until = clock.now() + FINAL_FLIGHT_WAIT;
    while conn.handshake_flight_pending() && !conn.received_close_notify() && clock.now() < until {
        match step(conn, socket, clock, buf) {
            Ok(Step::Datagram) => {
                let plain = conn.recv().unwrap_or_default();
                if !plain.is_empty() {
                    on_data(conn, plain);
                    flush(conn, socket);
                }
            }
            Ok(Step::Quiet) => {}
            Ok(Step::Gone) | Err(_) => break,
        }
    }
}
