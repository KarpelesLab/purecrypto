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
        // 150 * 20ms = 3s timeout. Long enough to overlap a normal peer
        // invocation's wallclock; short enough that a crashed peer surfaces
        // quickly.
        const MAX_RETRIES: u32 = 150;
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
