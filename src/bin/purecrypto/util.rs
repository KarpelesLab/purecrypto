//! Shared CLI helpers: argument parsing and file/stdin I/O.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::exit;

/// Prints `purecrypto: <msg>` to stderr and exits with status 1.
pub(crate) fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("purecrypto: {}", msg.as_ref());
    exit(1);
}

/// A trivial argument view over the tokens following the subcommand.
pub(crate) struct Args {
    tokens: Vec<String>,
}

impl Args {
    pub(crate) fn new(tokens: Vec<String>) -> Self {
        Args { tokens }
    }

    /// Builds a fresh [`Args`] by prepending `prefix` tokens. The shim
    /// binaries `s_dtls_client` / `s_dtls_server` use this to inject
    /// `-dtls1_2` ahead of the user's argv before handing off to the
    /// shared `s_client` / `s_server` logic.
    pub(crate) fn with_prefix(self, prefix: &[&str]) -> Self {
        let mut out: Vec<String> = prefix.iter().map(|s| s.to_string()).collect();
        out.extend(self.tokens);
        Args { tokens: out }
    }

    /// Iterator over the raw argv tokens (post-subcommand). Used by callers
    /// that need to collect every occurrence of a repeated flag (e.g.
    /// `pkeyutl -pkeyopt a:b -pkeyopt c:d` — `value` only returns the first).
    pub(crate) fn tokens_iter(&self) -> std::slice::Iter<'_, String> {
        self.tokens.iter()
    }

    /// The value following flag `name` (e.g. `-in file` → `Some("file")`).
    pub(crate) fn value(&self, name: &str) -> Option<&str> {
        let i = self.tokens.iter().position(|t| t == name)?;
        self.tokens.get(i + 1).map(String::as_str)
    }

    /// Whether the boolean flag `name` is present.
    pub(crate) fn flag(&self, name: &str) -> bool {
        self.tokens.iter().any(|t| t == name)
    }

    /// Returns the position (argv index, post-subcommand) of the last
    /// occurrence of `name`, if any. Useful for last-wins flag semantics
    /// (e.g. choosing between `-tls1_2` and `-dtls1_3`).
    pub(crate) fn last_pos(&self, name: &str) -> Option<usize> {
        self.tokens.iter().rposition(|t| t == name)
    }

    /// Positional arguments — tokens that are neither a flag nor the value of a
    /// value-taking flag in `value_flags`.
    pub(crate) fn positionals(&self, value_flags: &[&str]) -> Vec<&str> {
        let mut out = Vec::new();
        let mut skip = false;
        for t in &self.tokens {
            if skip {
                skip = false;
                continue;
            }
            if value_flags.contains(&t.as_str()) {
                skip = true; // consume this flag's value
                continue;
            }
            if t.starts_with('-') && t.as_str() != "-" {
                continue; // a boolean flag
            }
            out.push(t.as_str());
        }
        out
    }
}

/// Inter-process lock around a multi-step read-modify-write of an on-disk
/// resource (the CA `serial` counter, a stateful LMS/HSS/XMSS signing key, …).
///
/// We can't reach for `flock(2)` directly (the crate denies `unsafe_code`
/// outside `src/ffi/`), so we use a pure-`std` sentinel file opened with
/// `create_new(true)`. The kernel guarantees that at most one caller wins
/// the create; everyone else gets `AlreadyExists` and retries with a small
/// sleep. Bounded retry (~3 s) so a stale lock from a crashed peer eventually
/// surfaces a clear error rather than hanging forever. The lock file is
/// removed on `Drop` (including unwind), so a panicking holder unblocks the
/// next caller immediately.
pub(crate) struct SentinelLock {
    path: PathBuf,
}

impl SentinelLock {
    /// Acquires the lock at `path`. `holder` names the command that would be
    /// holding a stale lock (e.g. "`purecrypto ca`") in the timeout message.
    pub(crate) fn acquire(path: PathBuf, holder: &str) -> Self {
        // 1500 * 20ms = 30s timeout. This bounds recovery from a *stale* lock
        // left by a crashed peer; live contention must never hit it. The budget
        // therefore has to comfortably exceed the wallclock of many serialized
        // peer invocations, each of which holds the lock for a full stateful
        // sign + fsync'd key rewrite — which for a large tree, a slow disk, or a
        // debug build is far from instant. (The earlier 3s budget was already
        // ~85% consumed by a routine 12-signature concurrency test on fast
        // hardware, and tipped over on loaded CI runners.) A crashed peer's lock
        // taking 30s to break is an acceptable price for never spuriously
        // failing a legitimate signature.
        const MAX_RETRIES: u32 = 1500;
        const SLEEP_MS: u64 = 20;
        for attempt in 0..MAX_RETRIES {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(_f) => return SentinelLock { path },
                // `AlreadyExists`: another caller currently holds the lock.
                // `PermissionDenied`: on Windows, a lock file that a peer is
                // concurrently unlinking enters a "delete-pending" state in
                // which `create_new` fails with ERROR_ACCESS_DENIED (os error
                // 5) until the last handle closes — a transient race, not a
                // hard error. Treat both as "retry", so a contended lock never
                // spuriously aborts the process.
                Err(e)
                    if e.kind() == std::io::ErrorKind::AlreadyExists
                        || e.kind() == std::io::ErrorKind::PermissionDenied =>
                {
                    if attempt + 1 == MAX_RETRIES {
                        die(format!(
                            "timed out waiting for lock {} \
                             (stale lock from a crashed {holder}? \
                             delete it manually if so)",
                            path.display()
                        ));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(SLEEP_MS));
                }
                Err(e) => die(format!("cannot create lock {}: {e}", path.display())),
            }
        }
        unreachable!()
    }
}

impl Drop for SentinelLock {
    fn drop(&mut self) {
        // Best-effort: if the unlink fails (e.g. another process already
        // raced to remove it), there's nothing useful to recover.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Symmetric read-side counterpart to [`write_output_with_mode(.., private=true)`].
///
/// On Unix, checks that the file at `path` is not group- or world-accessible
/// (any of the lower 6 mode bits set is suspicious for a private key). If so,
/// emits a warning to stderr and proceeds — the warn-only default keeps
/// existing setups working; a future `--strict-key-perms` knob can promote
/// this to a hard refusal. On non-Unix targets the function is a no-op.
///
/// Call this before `std::fs::read` / `read_to_string` on any path that
/// contains private-key bytes (RSA PKCS#1, EC SEC1, Ed25519/ML-DSA/ML-KEM
/// PKCS#8, CA `root.key`, etc.).
pub(crate) fn warn_if_world_readable_key(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(md) = std::fs::metadata(path) {
            let mode = md.mode() & 0o777;
            if mode & 0o077 != 0 {
                eprintln!(
                    "purecrypto: warning: {path} is group/other-readable (mode {mode:o}); \
                     run `chmod 600 {path}` to restrict to owner-only"
                );
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Loads `-----BEGIN CERTIFICATE-----` blocks from `path` and adds each one to
/// `store` via `add_pem`. Dies on file-read failure, on a parse failure inside
/// any one block (no silent truncation of the trust store), and if `path`
/// yields zero blocks. Returns the number of certificates loaded.
///
/// `path` is included in error messages so the user sees which bundle was bad.
pub(crate) fn load_pem_certs_into<F, E>(path: &str, mut add_pem: F) -> usize
where
    F: FnMut(&str) -> Result<(), E>,
    E: core::fmt::Display,
{
    let data =
        std::fs::read_to_string(path).unwrap_or_else(|e| die(format!("cannot read {path}: {e}")));
    let mut block = String::new();
    let mut in_cert = false;
    let mut loaded = 0usize;
    for line in data.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            block.clear();
        }
        if in_cert {
            block.push_str(line);
            block.push('\n');
        }
        if line.starts_with("-----END CERTIFICATE-----") {
            in_cert = false;
            if let Err(e) = add_pem(&block) {
                die(format!(
                    "{path}: certificate #{} failed to parse: {e}",
                    loaded + 1
                ));
            }
            loaded += 1;
        }
    }
    if loaded == 0 {
        die(format!("{path}: no certificates found"));
    }
    loaded
}

/// Reads all input: from `path` if `Some` and not `"-"`, otherwise from stdin.
pub(crate) fn read_input(path: Option<&str>) -> Vec<u8> {
    match path {
        Some(p) if p != "-" => {
            std::fs::read(p).unwrap_or_else(|e| die(format!("cannot read {p}: {e}")))
        }
        _ => {
            let mut buf = Vec::new();
            std::io::stdin()
                .read_to_end(&mut buf)
                .unwrap_or_else(|e| die(format!("cannot read stdin: {e}")));
            buf
        }
    }
}

/// Writes `data` to `path` if `Some` and not `"-"`, otherwise to stdout.
pub(crate) fn write_output(path: Option<&str>, data: &[u8]) {
    write_output_with_mode(path, data, /* private = */ false)
}

/// Like [`write_output`] but with explicit secrecy hinting:
///   * `private = true` → on Unix, opens with mode `0o600` and `create_new`
///     so an existing file at `path` is NOT silently overwritten (a typo
///     would otherwise destroy a CA key). Pass `--force` upstream to allow
///     overwrite (the caller deletes the file first).
///   * `private = false` → behaves like `std::fs::write` (mode 0o644 with
///     the usual umask, truncate-on-overwrite).
pub(crate) fn write_output_with_mode(path: Option<&str>, data: &[u8], private: bool) {
    match path {
        Some(p) if p != "-" => {
            if private {
                write_private_file(p, data);
            } else {
                std::fs::write(p, data).unwrap_or_else(|e| die(format!("cannot write {p}: {e}")));
            }
        }
        _ => {
            if private && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
                die(
                    "refusing to write private key bytes to a terminal — pass `-out PATH` \
                     to a file or `-out -` to confirm",
                );
            }
            std::io::stdout()
                .write_all(data)
                .unwrap_or_else(|e| die(format!("cannot write stdout: {e}")));
        }
    }
}

/// Opens `path` with `create_new` (refuses to overwrite) and Unix mode 0o600,
/// then writes `data`. Used for any file that holds a private key.
fn write_private_file(path: &str, data: &[u8]) {
    use std::fs::OpenOptions;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let mut f = opts.open(path).unwrap_or_else(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            die(format!(
                "refusing to overwrite existing file {path} (delete it first to issue a new private key)"
            ));
        }
        die(format!("cannot create {path}: {e}"));
    });
    f.write_all(data)
        .unwrap_or_else(|e| die(format!("cannot write {path}: {e}")));
}

/// Creates `path` fresh with the explicit Unix `mode` and writes `data`.
///
/// The open uses `create_new` (`O_CREAT | O_EXCL`), which the kernel refuses
/// when *anything* already exists at the path — including a symbolic link,
/// even a dangling one. That is what stops an attacker who can pre-plant
/// `DIR/serial` (or any other CA state file) as a symlink from redirecting
/// our write into an arbitrary file. Use this for every first-creation of a
/// CA state file; use [`atomic_overwrite`] when a legitimate rewrite of an
/// existing file is needed.
pub(crate) fn write_new_file(path: &std::path::Path, data: &[u8], mode: u32) {
    use std::fs::OpenOptions;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(not(unix))]
    let _ = mode;

    let mut opts = OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    opts.mode(mode);
    let mut f = opts.open(path).unwrap_or_else(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            die(format!(
                "refusing to overwrite existing file {} (delete it first)",
                path.display()
            ));
        }
        die(format!("cannot create {}: {e}", path.display()));
    });
    f.write_all(data)
        .unwrap_or_else(|e| die(format!("cannot write {}: {e}", path.display())));
}

/// Dies when `path` exists and is a symbolic link.
///
/// `create_new` (see [`write_new_file`]) and the rename in
/// [`atomic_overwrite`] already refuse to *follow* a link, but an append-mode
/// open has no such protection — `OpenOptions::append` follows a symlink and
/// would extend whatever it points at. The append-style ledgers therefore
/// screen the path first.
pub(crate) fn reject_symlink(path: &std::path::Path) {
    match std::fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => die(format!(
            "refusing to write through the symbolic link {} — remove it first",
            path.display()
        )),
        _ => {}
    }
}

/// Atomically replaces `path`'s contents with `data` (write a sibling temp
/// file, fsync, rename over the original, then fsync the containing
/// directory). The temp file is created with the explicit Unix `mode`.
///
/// The rename replaces the *directory entry*, so a symbolic link sitting at
/// `path` is overwritten rather than written through, and a reader never
/// observes a half-written file. Dies on any I/O failure — callers use this
/// where a torn or lost write would break a security invariant (an advanced
/// one-time-signature key, a CA serial counter, a regenerated CRL).
pub(crate) fn atomic_overwrite(path: &std::path::Path, data: &[u8], mode: u32) {
    let display = path.display().to_string();
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(format!(".tmp.{}", std::process::id()));
    let tmp = PathBuf::from(tmp);
    {
        use std::fs::OpenOptions;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(not(unix))]
        let _ = mode;
        let mut opts = OpenOptions::new();
        // `create_new` refuses to clobber a pre-existing file or symlink at the
        // temp path (defense in depth). If a stale temp survives a previous
        // crashed run we remove it once and retry, then fail hard.
        opts.create_new(true).write(true);
        #[cfg(unix)]
        opts.mode(mode);
        let mut f = match opts.open(&tmp) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                std::fs::remove_file(&tmp).unwrap_or_else(|e| {
                    die(format!(
                        "cannot remove stale temp file {}: {e}",
                        tmp.display()
                    ))
                });
                opts.open(&tmp)
                    .unwrap_or_else(|e| die(format!("cannot create {}: {e}", tmp.display())))
            }
            Err(e) => die(format!("cannot create temp file {}: {e}", tmp.display())),
        };
        f.write_all(data)
            .unwrap_or_else(|e| die(format!("cannot write {}: {e}", tmp.display())));
        f.sync_all()
            .unwrap_or_else(|e| die(format!("cannot fsync {}: {e}", tmp.display())));
    }
    std::fs::rename(&tmp, path).unwrap_or_else(|e| {
        let _ = std::fs::remove_file(&tmp);
        die(format!("cannot atomically replace {display}: {e}"))
    });
    // rename(2) only becomes durable once the containing directory's entry
    // reaches disk. Without an fsync of the directory, a power loss after the
    // caller has acted on the write (emitted a signature, handed out a serial)
    // can roll the file back to its previous contents.
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    #[cfg(unix)]
    {
        // On Unix a directory can be opened read-only and fsync'd. This must
        // succeed: dying here keeps the "no signature unless the advanced key
        // is durable" contract the stateful-signature path depends on.
        let d = std::fs::File::open(dir).unwrap_or_else(|e| {
            die(format!(
                "cannot open directory {} to fsync rename: {e}",
                dir.display()
            ))
        });
        d.sync_all().unwrap_or_else(|e| {
            die(format!(
                "cannot fsync directory {} after rename: {e}",
                dir.display()
            ))
        });
    }
    #[cfg(not(unix))]
    {
        // Windows cannot fsync a directory through std (opening a directory
        // requires FILE_FLAG_BACKUP_SEMANTICS, and FlushFileBuffers on a
        // directory handle is not supported). Best-effort only; NTFS metadata
        // journaling gives the rename reasonable ordering guarantees.
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

/// Lowercase hex encoding.
pub(crate) fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Lowercase hex encoding (`to_hex`) terminated by a newline. Convenience
/// wrapper used by the hashing/MAC/KDF subcommands.
pub(crate) fn to_hex_line(bytes: &[u8]) -> String {
    let mut s = to_hex(bytes);
    s.push('\n');
    s
}

/// Decodes a hex string (any case, ASCII whitespace ignored). Returns `None`
/// on a non-hex character or odd length.
pub(crate) fn from_hex(s: &str) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !cleaned.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let mut i = 0;
    while i < cleaned.len() {
        let hi = (cleaned[i] as char).to_digit(16)?;
        let lo = (cleaned[i + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Some(out)
}

/// Parses a CLI flag value as hex bytes, exiting with an error message
/// referencing the flag if invalid.
pub(crate) fn parse_hex_flag(value: &str, flag: &str) -> Vec<u8> {
    from_hex(value).unwrap_or_else(|| die(format!("invalid hex value for {flag}: {value}")))
}

/// Best-effort overwrite of `buf` with zeros, mirroring
/// `src/hash/zeroize.rs::zero_bytes`. Used after parsing a hex-encoded secret
/// off argv (or out of a file) into a `Vec<u8>` we no longer need — the
/// `Vec`'s heap allocation is dropped immediately after, but at least the
/// bytes are wiped before the allocator can hand the chunk back out.
pub(crate) fn zero_buf(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(buf);
}

/// Reads raw bytes from `path` (no hex decoding). Use this for `-*file`
/// flags that carry secret material — the caller is responsible for
/// [`zero_buf`]-ing the result once it's no longer needed.
///
/// Also runs the same group/world-readable warning that
/// [`warn_if_world_readable_key`] does, since key/AAD files are exactly the
/// kind of thing that should not be `0o644`.
pub(crate) fn read_secret_file(path: &str) -> Vec<u8> {
    warn_if_world_readable_key(path);
    std::fs::read(path).unwrap_or_else(|e| die(format!("cannot read {path}: {e}")))
}

/// Parses a positive integer from a CLI flag.
pub(crate) fn parse_u32_flag(value: &str, flag: &str) -> u32 {
    value
        .parse::<u32>()
        .unwrap_or_else(|_| die(format!("invalid integer for {flag}: {value}")))
}

/// Parses a positive `usize` from a CLI flag.
pub(crate) fn parse_usize_flag(value: &str, flag: &str) -> usize {
    value
        .parse::<usize>()
        .unwrap_or_else(|_| die(format!("invalid integer for {flag}: {value}")))
}

/// Parses a comma-separated `-alpn` value into a list of protocol identifiers.
/// Shared by the TLS and QUIC client/server drivers.
pub(crate) fn parse_alpn(s: &str) -> Vec<Vec<u8>> {
    s.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| p.as_bytes().to_vec())
        .collect()
}

/// Loads a single PEM certificate chain (one or more CERTIFICATE blocks) into
/// a list of DER-encoded certificates. Shared by the TLS and QUIC drivers.
pub(crate) fn load_cert_chain(path: &str) -> Vec<Vec<u8>> {
    let data = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(format!("cannot read cert file {path}: {e}")));
    let mut out = Vec::new();
    let mut block = String::new();
    let mut in_cert = false;
    for line in data.lines() {
        if line.starts_with("-----BEGIN CERTIFICATE-----") {
            in_cert = true;
            block.clear();
        }
        if in_cert {
            block.push_str(line);
            block.push('\n');
        }
        if line.starts_with("-----END CERTIFICATE-----") {
            in_cert = false;
            let cert = purecrypto::x509::Certificate::from_pem(&block)
                .unwrap_or_else(|_| die(format!("could not parse cert in {path}")));
            out.push(cert.to_der().to_vec());
        }
    }
    if out.is_empty() {
        die(format!("{path} contained no CERTIFICATE blocks"));
    }
    out
}

/// Opens `path` as the destination for an NSS `SSLKEYLOGFILE` dump. Unix mode
/// `0o600`, append-only — multiple connections in the same process append to
/// the same file. Shared by the TLS and QUIC drivers.
pub(crate) fn open_keylog(path: &str) -> std::sync::Arc<dyn purecrypto::tls::KeyLog> {
    use std::fs::OpenOptions;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(unix)]
    opts.mode(0o600);
    let f = opts
        .open(path)
        .unwrap_or_else(|e| die(format!("cannot open keylog {path}: {e}")));
    std::sync::Arc::new(purecrypto::tls::WriterKeyLog::new(f))
}
