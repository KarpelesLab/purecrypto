//! Generates a self-signed RSA certificate and prints it as PEM.
//!
//! Run: `cargo run --example selfsigned_cert | openssl x509 -text -noout`

use purecrypto::bignum::Uint;
use purecrypto::rng::OsRng;
use purecrypto::rsa::RsaPrivateKey;
use purecrypto::x509::{Certificate, DistinguishedName, Time, Validity};

fn main() {
    let mut rng = OsRng;
    // 512-bit modulus keeps the example fast; bump LIMBS for stronger keys.
    let key = RsaPrivateKey::<8>::generate(Uint::from_u64(65537), &mut rng, 20);

    let name =
        DistinguishedName::common_name("purecrypto.example").with_organization("Karpelès Lab Inc.");
    let validity = Validity::new(
        Time::utc(2025, 1, 1, 0, 0, 0),
        Time::utc(2035, 1, 1, 0, 0, 0),
    );

    let cert = Certificate::self_signed(&key, &name, &validity, 1, true).expect("issue cert");
    print!("{}", cert.to_pem());
}
