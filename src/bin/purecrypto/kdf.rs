//! `purecrypto kdf <subcommand>` — HKDF, PBKDF2, scrypt, and Argon2.

use crate::util::{
    Args, die, parse_hex_flag, parse_u32_flag, parse_usize_flag, to_hex_line, write_output,
};
use purecrypto::hash::{Sha256, Sha384, Sha512};
use purecrypto::kdf::argon2::{Argon2Params, Argon2Type, argon2};
use purecrypto::kdf::scrypt::scrypt;
use purecrypto::kdf::{hkdf, pbkdf2};

/// Resolves a password from either `-password STR` or `-password-file FILE`.
/// `-password-file -` reads stdin's first line.
fn read_password(args: &Args) -> Vec<u8> {
    if let Some(p) = args.value("-password").or_else(|| args.value("--password")) {
        eprintln!(
            "purecrypto: warning: -password STR exposes the passphrase via /proc/<pid>/cmdline; \
             prefer -password-file FILE (or -password-file - to read stdin)"
        );
        return p.as_bytes().to_vec();
    }
    if let Some(p) = args
        .value("-password-file")
        .or_else(|| args.value("--password-file"))
    {
        let bytes = if p == "-" {
            use std::io::BufRead;
            let mut line = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut line)
                .unwrap_or_else(|e| die(format!("cannot read stdin: {e}")));
            line.into_bytes()
        } else {
            std::fs::read(p).unwrap_or_else(|e| die(format!("cannot read {p}: {e}")))
        };
        // Strip a trailing newline (CR/LF), mirroring how shells write passphrase files.
        let mut out = bytes;
        while matches!(out.last(), Some(b'\n' | b'\r')) {
            out.pop();
        }
        return out;
    }
    die("missing -password STR or -password-file FILE");
}

fn emit(args: &Args, out: &[u8]) {
    let dest = args.value("-out").or_else(|| args.value("--out"));
    if args.flag("-binary") || args.flag("--binary") {
        write_output(dest, out);
    } else {
        write_output(dest, to_hex_line(out).as_bytes());
    }
}

fn run_hkdf(args: Args) {
    let hash = args
        .value("-hash")
        .or_else(|| args.value("--hash"))
        .unwrap_or("sha256");
    let salt = args
        .value("-salt")
        .map(|h| parse_hex_flag(h, "-salt"))
        .unwrap_or_default();
    let ikm = args
        .value("-ikm")
        .map(|h| parse_hex_flag(h, "-ikm"))
        .unwrap_or_else(|| die("missing -ikm HEX"));
    let info = args
        .value("-info")
        .map(|h| parse_hex_flag(h, "-info"))
        .unwrap_or_default();
    let len = args
        .value("-len")
        .map(|s| parse_usize_flag(s, "-len"))
        .unwrap_or_else(|| die("missing -len N"));

    let mut out = vec![0u8; len];
    match hash.to_ascii_lowercase().as_str() {
        "sha256" => hkdf::<Sha256>(&salt, &ikm, &info, &mut out),
        "sha384" => hkdf::<Sha384>(&salt, &ikm, &info, &mut out),
        "sha512" => hkdf::<Sha512>(&salt, &ikm, &info, &mut out),
        _ => die(format!("unsupported -hash for hkdf: {hash}")),
    }
    emit(&args, &out);
}

fn run_pbkdf2(args: Args) {
    let hash = args
        .value("-hash")
        .or_else(|| args.value("--hash"))
        .unwrap_or("sha256");
    let pw = read_password(&args);
    let salt = args
        .value("-salt")
        .map(|h| parse_hex_flag(h, "-salt"))
        .unwrap_or_else(|| die("missing -salt HEX"));
    let iter = args
        .value("-iter")
        .map(|s| parse_u32_flag(s, "-iter"))
        .unwrap_or_else(|| die("missing -iter N"));
    let len = args
        .value("-len")
        .map(|s| parse_usize_flag(s, "-len"))
        .unwrap_or_else(|| die("missing -len N"));

    let mut out = vec![0u8; len];
    match hash.to_ascii_lowercase().as_str() {
        "sha256" => pbkdf2::<Sha256>(&pw, &salt, iter, &mut out),
        "sha384" => pbkdf2::<Sha384>(&pw, &salt, iter, &mut out),
        "sha512" => pbkdf2::<Sha512>(&pw, &salt, iter, &mut out),
        _ => die(format!("unsupported -hash for pbkdf2: {hash}")),
    }
    emit(&args, &out);
}

fn run_scrypt(args: Args) {
    let pw = read_password(&args);
    let salt = args
        .value("-salt")
        .map(|h| parse_hex_flag(h, "-salt"))
        .unwrap_or_else(|| die("missing -salt HEX"));
    let n = args
        .value("-n")
        .map(|s| parse_u32_flag(s, "-n"))
        .unwrap_or_else(|| die("missing -n N"));
    let r = args
        .value("-r")
        .map(|s| parse_u32_flag(s, "-r"))
        .unwrap_or_else(|| die("missing -r N"));
    let p = args
        .value("-p")
        .map(|s| parse_u32_flag(s, "-p"))
        .unwrap_or_else(|| die("missing -p N"));
    let len = args
        .value("-len")
        .map(|s| parse_usize_flag(s, "-len"))
        .unwrap_or_else(|| die("missing -len N"));

    // -n is N, but the library takes log2(N). Validate that N is a power of two.
    if n == 0 || (n & (n - 1)) != 0 {
        die(format!("-n must be a power of two (got {n})"));
    }
    let log_n = n.trailing_zeros() as u8;

    let mut out = vec![0u8; len];
    scrypt(&pw, &salt, log_n, r, p, &mut out)
        .unwrap_or_else(|e| die(format!("scrypt failed: {e}")));
    emit(&args, &out);
}

fn run_argon2(args: Args) {
    let variant = args
        .value("-variant")
        .or_else(|| args.value("--variant"))
        .unwrap_or("2id");
    let variant = match variant.to_ascii_lowercase().as_str() {
        "2i" | "argon2i" | "i" => Argon2Type::Argon2i,
        "2d" | "argon2d" | "d" => Argon2Type::Argon2d,
        "2id" | "argon2id" | "id" => Argon2Type::Argon2id,
        other => die(format!("unknown -variant: {other}")),
    };
    let pw = read_password(&args);
    let salt = args
        .value("-salt")
        .map(|h| parse_hex_flag(h, "-salt"))
        .unwrap_or_else(|| die("missing -salt HEX"));
    let t_cost = args
        .value("-t-cost")
        .or_else(|| args.value("--t-cost"))
        .map(|s| parse_u32_flag(s, "-t-cost"))
        .unwrap_or_else(|| die("missing -t-cost N"));
    let m_cost = args
        .value("-m-cost")
        .or_else(|| args.value("--m-cost"))
        .map(|s| parse_u32_flag(s, "-m-cost"))
        .unwrap_or_else(|| die("missing -m-cost N (KiB)"));
    let par = args
        .value("-p")
        .or_else(|| args.value("--p"))
        .map(|s| parse_u32_flag(s, "-p"))
        .unwrap_or(1);
    let len = args
        .value("-len")
        .map(|s| parse_usize_flag(s, "-len"))
        .unwrap_or_else(|| die("missing -len N"));

    let params = Argon2Params {
        t_cost,
        m_cost_kib: m_cost,
        parallelism: par,
        variant,
        version: 0x13,
    };
    let mut out = vec![0u8; len];
    argon2(&params, &pw, &salt, &[], &[], &mut out)
        .unwrap_or_else(|e| die(format!("argon2 failed: {e}")));
    emit(&args, &out);
}

const USAGE: &str = "\
purecrypto kdf <subcommand> [options]

SUBCOMMANDS:
    hkdf    -hash sha256|sha384|sha512 -ikm HEX [-salt HEX] [-info HEX] -len N
    pbkdf2  -hash sha256|sha384|sha512 -password STR -salt HEX -iter N -len N
    scrypt  -password STR -salt HEX -n N -r R -p P -len N
    argon2  -variant 2i|2d|2id -password STR -salt HEX -t-cost N -m-cost N [-p P] -len N

Output is hex unless `-binary` is set, written to `-out` (default stdout).";

pub(crate) fn run(args: Args) {
    // First positional after `kdf` selects the algorithm subcommand.
    let pos = args.positionals(&[
        "-hash",
        "--hash",
        "-salt",
        "--salt",
        "-ikm",
        "--ikm",
        "-info",
        "--info",
        "-password",
        "--password",
        "-password-file",
        "--password-file",
        "-iter",
        "--iter",
        "-n",
        "--n",
        "-r",
        "--r",
        "-p",
        "--p",
        "-len",
        "--len",
        "-variant",
        "--variant",
        "-t-cost",
        "--t-cost",
        "-m-cost",
        "--m-cost",
        "-out",
        "--out",
    ]);
    let sub = pos.first().copied().unwrap_or("");
    match sub {
        "hkdf" => run_hkdf(args),
        "pbkdf2" => run_pbkdf2(args),
        "scrypt" => run_scrypt(args),
        "argon2" => run_argon2(args),
        "" => die(USAGE),
        other => die(format!("unknown kdf subcommand '{other}'\n\n{USAGE}")),
    }
}
