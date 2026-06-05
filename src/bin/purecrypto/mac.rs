//! `purecrypto mac -alg ALG -key HEX|-keyfile FILE [in FILE] [-out FILE]`
//! — emit an HMAC tag (mirrors `openssl dgst -mac hmac`).

use crate::util::{Args, die, parse_hex_flag, read_input, to_hex_line, write_output};
use purecrypto::cipher::{Aes128, Aes256, AesCmac128, AesCmac256, AesGmac128, AesGmac256};
use purecrypto::hash::{Hmac, HmacSha256, HmacSha384, HmacSha512, Sha1};

type HmacSha1 = Hmac<Sha1>;

/// Computes the AES-CMAC tag (RFC 4493), selecting AES-128 or AES-256 by key
/// length. Exits with an error if the key is not 16 or 32 bytes.
fn cmac_tag(key: &[u8], msg: &[u8]) -> Vec<u8> {
    match key.len() {
        16 => {
            let k: [u8; 16] = key.try_into().unwrap();
            let mut c = AesCmac128::new(Aes128::new(&k));
            c.update(msg);
            c.finalize().to_vec()
        }
        32 => {
            let k: [u8; 32] = key.try_into().unwrap();
            let mut c = AesCmac256::new(Aes256::new(&k));
            c.update(msg);
            c.finalize().to_vec()
        }
        _ => die("AES-CMAC key must be 16 bytes (AES-128) or 32 bytes (AES-256)"),
    }
}

/// Computes the GMAC tag (NIST SP 800-38D), selecting AES-128 or AES-256 by
/// key length. The 12-byte `nonce` is required and MUST be unique per
/// (key, message). Exits with an error if the key is not 16/32 bytes or the
/// nonce is not 12 bytes.
fn gmac_tag(key: &[u8], nonce: &[u8], msg: &[u8]) -> Vec<u8> {
    let n: [u8; 12] = nonce
        .try_into()
        .unwrap_or_else(|_| die("GMAC nonce must be 12 bytes"));
    match key.len() {
        16 => {
            let k: [u8; 16] = key.try_into().unwrap();
            let mut g = AesGmac128::new(Aes128::new(&k), &n);
            g.update(msg);
            g.finalize().to_vec()
        }
        32 => {
            let k: [u8; 32] = key.try_into().unwrap();
            let mut g = AesGmac256::new(Aes256::new(&k), &n);
            g.update(msg);
            g.finalize().to_vec()
        }
        _ => die("GMAC key must be 16 bytes (AES-128) or 32 bytes (AES-256)"),
    }
}

/// Returns the MAC tag (raw bytes) of `msg` under `key` for the named
/// algorithm. Supported: `hmac-sha1`, `hmac-sha256`, `hmac-sha384`,
/// `hmac-sha512`, and `cmac` / `aes-cmac` (AES-CMAC, RFC 4493). GMAC is
/// handled separately in `run` since it also requires a nonce.
fn mac_tag(alg: &str, key: &[u8], msg: &[u8]) -> Option<Vec<u8>> {
    let tag = match alg.to_ascii_lowercase().as_str() {
        "hmac-sha1" | "sha1" => HmacSha1::mac(key, msg).as_ref().to_vec(),
        "hmac-sha256" | "sha256" => HmacSha256::mac(key, msg).as_ref().to_vec(),
        "hmac-sha384" | "sha384" => HmacSha384::mac(key, msg).as_ref().to_vec(),
        "hmac-sha512" | "sha512" => HmacSha512::mac(key, msg).as_ref().to_vec(),
        "cmac" | "aes-cmac" => cmac_tag(key, msg),
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
        "-nonce",
        "--nonce",
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

    let tag = match alg.to_ascii_lowercase().as_str() {
        "gmac" | "aes-gmac" => {
            let nonce = args
                .value("-nonce")
                .or_else(|| args.value("--nonce"))
                .map(|h| parse_hex_flag(h, "-nonce"))
                .unwrap_or_else(|| die("GMAC requires -nonce HEX (12 bytes)"));
            gmac_tag(&key, &nonce, &msg)
        }
        _ => mac_tag(alg, &key, &msg).unwrap_or_else(|| die(format!("unknown -alg: {alg}"))),
    };
    let dest = args.value("-out").or_else(|| args.value("--out"));
    if args.flag("-binary") || args.flag("--binary") {
        write_output(dest, &tag);
    } else {
        write_output(dest, to_hex_line(&tag).as_bytes());
    }
}
