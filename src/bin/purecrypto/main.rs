//! The `purecrypto` command-line tool: hashing, key generation, CA management,
//! and a TLS test client (`s_client`), built entirely on the `purecrypto`
//! library.

mod ca;
mod dtls_io;
mod genpkey;
mod hash;
mod pkey;
mod pki;
mod rand;
mod req;
mod s_client;
mod s_dtls_client;
mod s_dtls_server;
mod s_server;
mod toml;
mod util;
mod x509;

use util::{Args, die};

const USAGE: &str = "\
purecrypto — pure-Rust cryptography toolkit

USAGE:
    purecrypto <command> [options]

COMMANDS:
    hash <alg> [file]    Hash a file or stdin (sha256, sha3-256, blake3, …)
    rand <nbytes>        Emit cryptographically secure random bytes
    genpkey              Generate an RSA or EC private key
    pkey                 Inspect or convert a private key
    req                  Create or inspect a PKCS#10 certificate request
    x509                 Inspect, self-sign, or CA-sign a certificate
    ca                   Manage a development CA on disk (init, issue, crl, ...)
    s_client             Open a TLS 1.3 connection and report the result
    s_server             Run a one-shot TLS 1.3 echo/-www server
    s_dtls_client        Open a DTLS 1.2 connection over UDP
    s_dtls_server        Run a one-shot DTLS 1.2 echo server over UDP
    help                 Show this help

Run a command with no/invalid arguments to see its usage.";

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let cmd = argv.get(1).map(String::as_str);
    let rest = Args::new(argv.get(2..).unwrap_or(&[]).to_vec());

    match cmd {
        Some("hash") | Some("dgst") => hash::run(rest),
        Some("rand") => rand::run(rest),
        Some("genpkey") => genpkey::run(rest),
        Some("pkey") => pkey::run(rest),
        Some("req") => req::run(rest),
        Some("x509") => x509::run(rest),
        Some("ca") => ca::run(rest),
        Some("s_client") => s_client::run(rest),
        Some("s_server") => s_server::run(rest),
        Some("s_dtls_client") => s_dtls_client::run(rest),
        Some("s_dtls_server") => s_dtls_server::run(rest),
        Some("help") | Some("-h") | Some("--help") | None => println!("{USAGE}"),
        Some(other) => die(format!("unknown command '{other}' (try 'purecrypto help')")),
    }
}
