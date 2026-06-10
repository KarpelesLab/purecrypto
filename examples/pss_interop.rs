//! Verifies an OpenSSL-generated RSA-PSS signature with purecrypto.
//!
//! Takes three file paths: an RSA public key (PKCS#1 PEM), the message, and
//! the signature. Prints OK on success. Example invocation:
//!
//! ```sh
//! cargo run --example pss_interop -- pss_pub.pem pss_msg.txt pss_sig.bin
//! ```

use purecrypto::der;
use purecrypto::rsa::BoxedRsaPublicKey;
use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let [_, pub_path, msg_path, sig_path] = args.as_slice() else {
        eprintln!("usage: pss_interop <pub.pem (PKCS#1)> <msg-file> <sig-file>");
        std::process::exit(2);
    };
    let pem = fs::read_to_string(pub_path).expect("read pub");
    let msg = fs::read(msg_path).expect("read msg");
    let sig = fs::read(sig_path).expect("read sig");

    // Runtime-sized key: parse the PKCS#1 PEM body into a BoxedRsaPublicKey,
    // so the modulus size need not be known at compile time.
    let der = der::pem_decode(&pem, "RSA PUBLIC KEY").expect("pem");
    let pk = BoxedRsaPublicKey::from_pkcs1_der(&der).expect("parse pubkey");
    match pk.verify_pss::<purecrypto::hash::Sha256>(&msg, &sig) {
        Ok(()) => println!("OK: OpenSSL PSS signature verified by purecrypto"),
        Err(e) => {
            println!("FAIL: {e}");
            std::process::exit(1);
        }
    }
}
