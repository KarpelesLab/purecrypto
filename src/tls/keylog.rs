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
        let line = keylog_line(label, client_random, secret);
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
///
/// The path is opened without following a symbolic link at `path` itself
/// (`O_NOFOLLOW` where the platform's flag is known, plus an explicit
/// symlink check), must be a regular file once open, and on Unix its
/// permissions are reset to `0o600` even when it already existed: the
/// creation mode never applies to a pre-existing file, and a world-readable
/// file (or a link into someone else's directory) planted ahead of time
/// would otherwise collect the session secrets.
#[cfg(feature = "std")]
pub fn file_keylog(path: &std::path::Path) -> std::io::Result<Arc<WriterKeyLog<std::fs::File>>> {
    // A link at `path` is refused rather than opened through: `O_NOFOLLOW`
    // makes the kernel do it (`ELOOP`); this pre-check covers the platforms
    // whose flag value is not spelled out below. It is not a race-free
    // guard on those, only a best effort on top of the mode reset.
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        return Err(std::io::Error::other(
            "keylog path is a symbolic link; refusing to write secrets through it",
        ));
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        if let Some(flag) = o_nofollow() {
            opts.custom_flags(flag);
        }
    }
    let f = opts.open(path)?;
    if !f.metadata()?.file_type().is_file() {
        return Err(std::io::Error::other(
            "keylog path is not a regular file; refusing to write secrets to it",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        f.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(Arc::new(WriterKeyLog::new(f)))
}

/// The platform's `O_NOFOLLOW` open flag, or `None` where its value is not
/// known here (the caller then relies on the symlink pre-check alone). Kept
/// as literals so the crate stays free of a `libc` dependency; the values are
/// the kernels' ABI constants, which do not change (cross-checked against
/// the `libc` crate's per-target definitions). Getting one wrong is not
/// harmless: on Linux the bit means something else on other architectures
/// (`O_LARGEFILE` on arm / aarch64), so the open would quietly follow links.
#[cfg(all(feature = "std", unix))]
fn o_nofollow() -> Option<i32> {
    // Linux / Android: the value is per architecture. arm, aarch64,
    // powerpc(64) and m68k use 0o100000 (there 0o400000 is `O_LARGEFILE`
    // or `O_DIRECT`, which would silently follow links); the asm-generic
    // value 0o400000 holds for the rest Rust targets (sparc and mips spell
    // it 0x20000 in their own headers — the same number). An architecture
    // not listed gets `None` and the symlink pre-check alone.
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "m68k"
        )
    ))]
    {
        Some(0o100000)
    }
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "loongarch64",
            target_arch = "s390x",
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "mips32r6",
            target_arch = "mips64r6",
            target_arch = "sparc",
            target_arch = "sparc64",
            target_arch = "csky",
            target_arch = "hexagon"
        )
    ))]
    {
        Some(0o400000)
    }
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        not(any(
            target_arch = "arm",
            target_arch = "aarch64",
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "m68k",
            target_arch = "x86",
            target_arch = "x86_64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "loongarch64",
            target_arch = "s390x",
            target_arch = "mips",
            target_arch = "mips64",
            target_arch = "mips32r6",
            target_arch = "mips64r6",
            target_arch = "sparc",
            target_arch = "sparc64",
            target_arch = "csky",
            target_arch = "hexagon"
        ))
    ))]
    {
        None
    }
    #[cfg(any(target_os = "solaris", target_os = "illumos"))]
    {
        Some(0o400000)
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    {
        Some(0x0100)
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "netbsd",
        target_os = "openbsd"
    )))]
    {
        None
    }
}

/// Formats one `SSLKEYLOGFILE` line: `<label> <hex client_random> <hex
/// secret>\n`. The line carries the secret in hex, so it is built in a
/// [`Zeroizing`](crate::zeroize::Zeroizing) buffer reserved at its exact
/// final length up front — no reallocation leaves an unwiped partial copy
/// behind — and wiped once the writer has it.
#[cfg(feature = "std")]
fn keylog_line(
    label: &str,
    client_random: &[u8; 32],
    secret: &[u8],
) -> crate::zeroize::Zeroizing<alloc::string::String> {
    let mut line = crate::zeroize::Zeroizing::new(alloc::string::String::with_capacity(
        label.len() + 1 + 64 + 1 + secret.len() * 2 + 1,
    ));
    line.push_str(label);
    line.push(' ');
    append_hex(&mut line, client_random);
    line.push(' ');
    append_hex(&mut line, secret);
    line.push('\n');
    line
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

    /// Finding: the hex secret line was built in a plain `String` and freed
    /// unwiped. It is now a wipe-on-drop buffer whose up-front reservation
    /// is exact, so no reallocation copied the secret elsewhere first.
    #[test]
    fn keylog_line_is_wiped_and_never_reallocated() {
        fn wipes_on_drop<T: crate::zeroize::ZeroizeOnDrop>(_: &T) {}
        let line = keylog_line("CLIENT_TRAFFIC_SECRET_0", &[0x01; 32], &[0xfe; 48]);
        wipes_on_drop(&line);
        assert_eq!(line.len(), line.capacity(), "reservation must be exact");
        assert!(line.ends_with(&alloc::format!(" {}\n", "fe".repeat(48))));

        let mut line = line;
        crate::zeroize::Zeroize::zeroize(&mut line);
        assert!(line.is_empty());
    }

    /// CFG-F4: `file_keylog` followed a symbolic link at the path and left a
    /// pre-existing file's permissions alone (`mode(0o600)` only governs
    /// creation). A link is now refused and an existing file is reset to
    /// owner-only.
    #[cfg(unix)]
    #[test]
    fn file_keylog_refuses_symlinks_and_tightens_existing_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(alloc::format!(
            "purecrypto-keylog-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // A pre-existing, group/world-readable file: opened and tightened.
        let existing = dir.join("existing.log");
        std::fs::write(&existing, b"").unwrap();
        std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o644)).unwrap();
        let sink = file_keylog(&existing).unwrap();
        sink.log("CLIENT_RANDOM", &[0x01; 32], &[0x02; 48]);
        drop(sink);
        let mode = std::fs::metadata(&existing).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "existing keylog file must be owner-only");

        // A symlink to it: refused, and nothing written through it.
        let before = std::fs::read(&existing).unwrap();
        let link = dir.join("link.log");
        std::os::unix::fs::symlink(&existing, &link).unwrap();
        assert!(file_keylog(&link).is_err(), "symlink must be refused");
        assert_eq!(std::fs::read(&existing).unwrap(), before);

        // A dangling symlink is refused too (it must not be created through).
        let dangling = dir.join("dangling.log");
        std::os::unix::fs::symlink(dir.join("nowhere.log"), &dangling).unwrap();
        assert!(file_keylog(&dangling).is_err());
        assert!(!dir.join("nowhere.log").exists());

        // A directory is not a regular file.
        assert!(file_keylog(&dir).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `O_NOFOLLOW` value is the kernel's for this target: on its own
    /// (without the symlink pre-check) it makes opening a link fail. A wrong
    /// value — the arm / aarch64 / powerpc builds once used the x86 one,
    /// which is `O_LARGEFILE` there — opens straight through the link.
    #[cfg(unix)]
    #[test]
    fn o_nofollow_flag_refuses_links_by_itself() {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(any(target_os = "linux", target_os = "android", target_os = "macos"))]
        assert!(o_nofollow().is_some());
        let Some(flag) = o_nofollow() else {
            return;
        };
        let dir = std::env::temp_dir().join(alloc::format!(
            "purecrypto-nofollow-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("target.log");
        std::fs::write(&target, b"").unwrap();
        let link = dir.join("link.log");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let open = |p: &std::path::Path| {
            std::fs::OpenOptions::new()
                .append(true)
                .custom_flags(flag)
                .open(p)
        };
        assert!(open(&target).is_ok(), "a regular file opens");
        assert!(open(&link).is_err(), "O_NOFOLLOW must refuse the link");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
