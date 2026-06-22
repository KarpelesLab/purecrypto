//! `SSLKEYLOGFILE`-format key-material sink for TLS / DTLS.
//!
//! Wireshark, NSS, curl and friends use a de-facto file format known as
//! `SSLKEYLOGFILE` to dump the per-handshake secrets needed to decrypt a
//! captured TLS / DTLS trace offline. The format is one line per secret:
//!
//! ```text
//! <LABEL> <client_random_hex> <secret_hex>
//! ```
//!
//! [`KeyLog`] is the trait every TLS / DTLS engine in this crate calls into
//! when it derives a logged secret. The sink is registered once, on the
//! [`super::Config`], and the engine invokes
//! [`KeyLog::log`] right after each derivation. When no sink is registered
//! (the default), nothing is logged and the engine fast-paths the
//! [`Option::is_some`] check.
//!
//! Labels emitted by this crate are the NSS / Wireshark / curl canon:
//!
//! | label | scope |
//! |---|---|
//! | `CLIENT_RANDOM` | TLS 1.2 / DTLS 1.2: the 48-byte master secret |
//! | `CLIENT_HANDSHAKE_TRAFFIC_SECRET` | TLS 1.3 / DTLS 1.3 |
//! | `SERVER_HANDSHAKE_TRAFFIC_SECRET` | TLS 1.3 / DTLS 1.3 |
//! | `CLIENT_TRAFFIC_SECRET_0` | TLS 1.3 / DTLS 1.3 application secret |
//! | `SERVER_TRAFFIC_SECRET_0` | TLS 1.3 / DTLS 1.3 application secret |
//! | `EXPORTER_SECRET` | TLS 1.3 / DTLS 1.3 exporter master secret |
//! | `CLIENT_EARLY_TRAFFIC_SECRET` | TLS 1.3 0-RTT |
//!
//! The convenience implementation [`WriterKeyLog`] wraps any
//! `std::io::Write` (file, stderr, `Vec<u8>` for tests, ...) behind a
//! `Mutex` so it can be shared across connections from one configuration.
//!
//! ```ignore
//! use std::sync::Arc;
//! use purecrypto::tls::{Config, WriterKeyLog};
//!
//! let f = std::fs::OpenOptions::new()
//!     .create(true).append(true).open("/tmp/keys.log").unwrap();
//! let cfg = Config::builder()
//!     .key_log(Arc::new(WriterKeyLog::new(f)))
//!     .build();
//! ```

#[cfg(feature = "std")]
use alloc::sync::Arc;

/// Sink for handshake secrets in NSS `SSLKEYLOGFILE` format.
///
/// Implementations are called from the handshake state machine and must be
/// cheap: don't block on the network, don't take a slow lock. A
/// `Mutex<impl Write>` is fine.
///
/// `Send + Sync` because the same [`super::Config`] (and therefore the same
/// `Arc<dyn KeyLog>`) can back multiple concurrent connections.
pub trait KeyLog: Send + Sync {
    /// Record a secret. `label` is the NSS canonical label (e.g.
    /// `"CLIENT_HANDSHAKE_TRAFFIC_SECRET"`), `client_random` is the
    /// `ClientHello.random` keying the line, `secret` is the raw bytes.
    fn log(&self, label: &str, client_random: &[u8; 32], secret: &[u8]);
}

/// A [`KeyLog`] that writes one `SSLKEYLOGFILE` line per call to any
/// `std::io::Write`. The writer is held behind a `Mutex` so the sink is
/// `Send + Sync`.
#[cfg(feature = "std")]
pub struct WriterKeyLog<W: std::io::Write + Send> {
    writer: std::sync::Mutex<W>,
}

#[cfg(feature = "std")]
impl<W: std::io::Write + Send> WriterKeyLog<W> {
    /// Wraps `w` in a `Mutex` and returns a [`KeyLog`] that writes one line
    /// per call.
    pub fn new(w: W) -> Self {
        Self {
            writer: std::sync::Mutex::new(w),
        }
    }

    /// Test-only access to the inner writer. Used by loopback tests to
    /// inspect captured key material.
    #[cfg(test)]
    pub(crate) fn writer_lock_for_test(&self) -> std::sync::MutexGuard<'_, W> {
        self.writer.lock().expect("keylog mutex")
    }
}

#[cfg(feature = "std")]
impl<W: std::io::Write + Send> KeyLog for WriterKeyLog<W> {
    fn log(&self, label: &str, client_random: &[u8; 32], secret: &[u8]) {
        let mut line =
            alloc::string::String::with_capacity(label.len() + 1 + 64 + 1 + secret.len() * 2 + 1);
        line.push_str(label);
        line.push(' ');
        append_hex(&mut line, client_random);
        line.push(' ');
        append_hex(&mut line, secret);
        line.push('\n');
        // Errors here are intentionally swallowed: the handshake must not
        // fail because the keylog file went away.
        if let Ok(mut w) = self.writer.lock() {
            let _ = w.write_all(line.as_bytes());
            let _ = w.flush();
        }
    }
}

/// Opens `path` with `O_CREATE | O_APPEND` and (on Unix) mode `0o600`,
/// returning a [`WriterKeyLog`] ready to register on a
/// [`super::ConfigBuilder`]. The 0o600 mode keeps the file readable only
/// by its owner — these secrets are sensitive.
#[cfg(feature = "std")]
pub fn file_keylog(path: &std::path::Path) -> std::io::Result<Arc<WriterKeyLog<std::fs::File>>> {
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let f = opts.open(path)?;
    Ok(Arc::new(WriterKeyLog::new(f)))
}

/// Appends `bytes` as lowercase hex to `out`. Only the `std` `WriterKeyLog`
/// uses it; `no_std` builds have no built-in keylog sink.
#[cfg(feature = "std")]
fn append_hex(out: &mut alloc::string::String, bytes: &[u8]) {
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    /// `WriterKeyLog` produces an NSS-compliant line: `<label> <hex cr> <hex
    /// secret>\n`, with lowercase hex throughout.
    #[test]
    fn writer_keylog_format() {
        let buf: Vec<u8> = Vec::new();
        let sink: Arc<WriterKeyLog<Vec<u8>>> = Arc::new(WriterKeyLog::new(buf));
        let cr: [u8; 32] = [0xab; 32];
        let secret: [u8; 48] = [0xcd; 48];
        sink.log("CLIENT_RANDOM", &cr, &secret);
        // We cannot recover the `Vec<u8>` from the Mutex-wrapped sink
        // without consuming it; instead lock and inspect.
        let got = sink.writer_lock_for_test();
        let line = core::str::from_utf8(&got).unwrap();
        let expected_cr = "ab".repeat(32);
        let expected_secret = "cd".repeat(48);
        let expected = alloc::format!("CLIENT_RANDOM {expected_cr} {expected_secret}\n");
        assert_eq!(line, expected.as_str());
    }
}
