//! Verifies an OpenSSL-generated RSA-PSS signature with purecrypto.
//!
//! Expects three files in /tmp: an RSA public key (PKCS#1 PEM) at
//! `/tmp/pss_pub.pem`, the message at `/tmp/pss_msg.txt`, and the signature at
//! `/tmp/pss_sig.bin`. Prints OK on success.

use purecrypto::rsa::RsaPublicKey;
use std::fs;

fn main() {
    let pem = fs::read_to_string("/tmp/pss_pub.pem").expect("read pub");
    let msg = fs::read("/tmp/pss_msg.txt").expect("read msg");
    let sig = fs::read("/tmp/pss_sig.bin").expect("read sig");

    // 2048-bit modulus => 32 limbs.
    let pk = RsaPublicKey::<32>::from_pkcs1_pem(&pem).expect("parse pubkey");
    match pk.verify_pss::<purecrypto::hash::Sha256>(&msg, &sig) {
        Ok(()) => println!("OK: OpenSSL PSS signature verified by purecrypto"),
        Err(e) => {
            println!("FAIL: {e}");
            std::process::exit(1);
        }
    }
}
