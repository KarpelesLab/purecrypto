//! `purecrypto hash <algorithm> [file]` — hash a file or stdin.

use crate::util::{Args, die, read_input, to_hex, write_output};
use purecrypto::hash;

/// Computes the digest of `data` under the named algorithm.
fn digest(alg: &str, data: &[u8]) -> Option<Vec<u8>> {
    let d = match alg.to_ascii_lowercase().as_str() {
        "sha224" => hash::sha224(data).to_vec(),
        "sha256" => hash::sha256(data).to_vec(),
        "sha384" => hash::sha384(data).to_vec(),
        "sha512" => hash::sha512(data).to_vec(),
        "sha512-224" => hash::sha512_224(data).to_vec(),
        "sha512-256" => hash::sha512_256(data).to_vec(),
        "sha3-224" => hash::sha3_224(data).to_vec(),
        "sha3-256" => hash::sha3_256(data).to_vec(),
        "sha3-384" => hash::sha3_384(data).to_vec(),
        "sha3-512" => hash::sha3_512(data).to_vec(),
        "keccak256" => hash::keccak256(data).to_vec(),
        "blake2b256" => hash::blake2b256(data).to_vec(),
        "blake2b384" => hash::blake2b384(data).to_vec(),
        "blake2b512" => hash::blake2b512(data).to_vec(),
        "blake2s256" => hash::blake2s256(data).to_vec(),
        "blake3" => hash::blake3(data).to_vec(),
        "sm3" => hash::sm3(data).to_vec(),
        "sha1" => hash::sha1(data).to_vec(),
        "md5" => hash::md5(data).to_vec(),
        "ripemd160" => hash::ripemd160(data).to_vec(),
        _ => return None,
    };
    Some(d)
}

pub(crate) fn run(args: Args) {
    let pos = args.positionals(&["-out"]);
    let Some(&alg) = pos.first() else {
        die("usage: purecrypto hash <algorithm> [file]  (file defaults to stdin)");
    };
    let data = read_input(pos.get(1).copied());
    let Some(out) = digest(alg, &data) else {
        die(format!("unknown hash algorithm: {alg}"));
    };

    let dest = args.value("-out");
    if args.flag("--binary") || args.flag("-binary") {
        write_output(dest, &out);
    } else {
        let mut line = to_hex(&out);
        line.push('\n');
        write_output(dest, line.as_bytes());
    }
}
