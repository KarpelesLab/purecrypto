//! `purecrypto mac -alg ALG -key HEX|-keyfile FILE [in FILE] [-out FILE]`
//! — emit an HMAC tag (mirrors `openssl dgst -mac hmac`).

use crate::util::{Args, die, parse_hex_flag, read_input, to_hex_line, write_output};
use purecrypto::hash::{Hmac, HmacSha256, HmacSha384, HmacSha512, Sha1};

type HmacSha1 = Hmac<Sha1>;

/// Returns the HMAC tag (raw bytes) of `msg` under `key` for the named
/// algorithm. Supported: `hmac-sha1`, `hmac-sha256`, `hmac-sha384`,
/// `hmac-sha512`.
fn mac_tag(alg: &str, key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let tag = match alg.to_ascii_lowercase().as_str() {
        "hmac-sha1" | "sha1" => HmacSha1::mac(key, msg).as_ref().to_vec(),
        "hmac-sha256" | "sha256" => HmacSha256::mac(key, msg).as_ref().to_vec(),
        "hmac-sha384" | "sha384" => HmacSha384::mac(key, msg).as_ref().to_vec(),
        "hmac-sha512" | "sha512" => HmacSha512::mac(key, msg).as_ref().to_vec(),
        _ => return None,
    };
    Some(tag)
}

pub(crate) fn run(args: Args) {
    let alg = args
        .value("-alg")
        .or_else(|| args.value("--alg"))
        .unwrap_or_else(|| die("missing -alg (try -alg hmac-sha256)"));

    let key = if let Some(hex) = args.value("-key").or_else(|| args.value("--key")) {
        parse_hex_flag(hex, "-key")
    } else if let Some(path) = args.value("-keyfile").or_else(|| args.value("--keyfile")) {
        std::fs::read(path).unwrap_or_else(|e| die(format!("cannot read {path}: {e}")))
    } else {
        die("missing -key HEX or -keyfile FILE");
    };

    let pos = args.positionals(&[
        "-alg",
        "--alg",
        "-key",
        "--key",
        "-keyfile",
        "--keyfile",
        "-in",
        "--in",
        "-out",
        "--out",
    ]);
    let in_path = args
        .value("-in")
        .or_else(|| args.value("--in"))
        .or_else(|| pos.first().copied());
    let msg = read_input(in_path);

    let tag = mac_tag(alg, &key, &msg).unwrap_or_else(|| die(format!("unknown -alg: {alg}")));
    let dest = args.value("-out").or_else(|| args.value("--out"));
    if args.flag("-binary") || args.flag("--binary") {
        write_output(dest, &tag);
    } else {
        write_output(dest, to_hex_line(&tag).as_bytes());
    }
}
