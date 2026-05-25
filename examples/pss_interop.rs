//! Verifies an OpenSSL-generated RSA-PSS signature with purecrypto.
//!
//! Expects three files in /tmp: an RSA public key (PKCS#1 PEM) at
//! `/tmp/pss_pub.pem`, the message at `/tmp/pss_msg.txt`, and the signature at
//! `/tmp/pss_sig.bin`. Prints OK on success.

use purecrypto::der;
use purecrypto::rsa::BoxedRsaPublicKey;
use std::fs;

fn main() {
    let pem = fs::read_to_string("/tmp/pss_pub.pem").expect("read pub");
    let msg = fs::read("/tmp/pss_msg.txt").expect("read msg");
    let sig = fs::read("/tmp/pss_sig.bin").expect("read sig");

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
