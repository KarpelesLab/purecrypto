//! The `purecrypto` command-line tool: hashing, key generation, CA management,
//! and a TLS test client (`s_client`), built entirely on the `purecrypto`
//! library.

mod genpkey;
mod hash;
mod pkey;
mod rand;
mod util;

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
        Some("help") | Some("-h") | Some("--help") | None => println!("{USAGE}"),
        Some(other) => die(format!("unknown command '{other}' (try 'purecrypto help')")),
    }
}
