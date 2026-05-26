//! Shared CLI helpers: argument parsing and file/stdin I/O.

use std::io::{Read, Write};
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
    match path {
        Some(p) if p != "-" => {
            std::fs::write(p, data).unwrap_or_else(|e| die(format!("cannot write {p}: {e}")))
        }
        _ => std::io::stdout()
            .write_all(data)
            .unwrap_or_else(|e| die(format!("cannot write stdout: {e}"))),
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
