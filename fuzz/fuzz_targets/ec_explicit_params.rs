//! Fuzz explicit-parameter ("custom") elliptic curves — the `ec-custom`
//! feature: `BoxedCurve::from_params`, its DER front end
//! `BoxedCurve::from_der` (the X9.62 `specifiedCurve` form of
//! `ECParameters`), the SEC1 / PKCS#8 private-key parsers that reach it,
//! and the point / scalar / signature decoders running on a curve built at
//! run time.
//!
//! A `specifiedCurve` is the one place where the *curve itself* is
//! attacker-chosen: the modulus, both coefficients, the base point, the
//! order and the cofactor all come from the key file. Validation (SEC 1
//! §3.1.1.2.1: primality, non-singularity, base point on the curve, Hasse
//! interval, MOV, `[n]G = O`) then builds a Montgomery engine at whatever
//! limb width the numbers need — none of it may panic, divide by zero or
//! index out of bounds for any seven integers.
//!
//! The first byte selects one of four shapes:
//!
//! 0. raw DER — the input goes to `from_der` and to the SEC1 / PKCS#8
//!    private-key parsers;
//! 1. seven length-prefixed integers `p, a, b, Gx, Gy, n, h` straight into
//!    `from_params`. Each field is capped at 72 bytes (576 bits, the
//!    widest field the engine accepts) so the bignum work stays bounded;
//! 2. a pinned, valid curve with exactly one of its seven parameters
//!    replaced by fuzz bytes. Random integers almost never get past the
//!    "base point on the curve" check, so this is what reaches the later
//!    stages (order bound, Hasse interval, MOV, primality, `[n]G = O`)
//!    with one inconsistent value at a time;
//! 3. a pinned, valid curve, used as-is.
//!
//! Whenever a curve comes out, the rest of the input is decoded on it: a
//! SEC1 public key (with the subgroup check the cofactor-4 curves need), a
//! private scalar, a DER signature, one verification and one ECDH — the
//! "cheap operation" that proves the freshly built engine is usable.
//!
//! The pinned curves are OpenSSL `ecparam -param_enc explicit` outputs
//! from `testdata/ec-explicit/`, chosen to span the limb widths (2 to 8)
//! and to include cofactor 4.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::bignum::BoxedUint;
use purecrypto::ec::{
    BoxedCurve, BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey, BoxedEcdsaPublicKey, BoxedEcdsaSignature,
};
use std::sync::OnceLock;

/// A PKCS#8 key on a 576-bit explicit curve is under 1 KiB.
const MAX_INPUT: usize = 2048;

/// 576 bits: `from_params` rejects anything wider on its bit-length check,
/// before doing arithmetic on it.
const MAX_FIELD: usize = 72;

macro_rules! params {
    ($($name:literal),* $(,)?) => {
        [$(include_bytes!(concat!("../../testdata/ec-explicit/params-", $name, ".der")) as &[u8]),*]
    };
}

/// secp112r2 and secp128r2 have cofactor 4; the rest are prime-order.
const PINNED_DER: [&[u8]; 6] = params![
    "secp112r2",
    "secp128r2",
    "wtls9",
    "prime239v1",
    "brainpoolP256t1",
    "brainpoolP512t1",
];

static PINNED: OnceLock<Vec<BoxedCurve>> = OnceLock::new();

fn pinned() -> &'static [BoxedCurve] {
    PINNED.get_or_init(|| {
        PINNED_DER
            .iter()
            .map(|der| BoxedCurve::from_der(der).expect("pinned explicit curve"))
            .collect()
    })
}

/// Splits `n` bytes (or as many as remain) off the front of `data`.
fn take<'a>(data: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, tail) = data.split_at(n.min(data.len()));
    *data = tail;
    head
}

fn take_u8(data: &mut &[u8]) -> u8 {
    take(data, 1).first().copied().unwrap_or(0)
}

/// A length-prefixed big-endian integer of at most `MAX_FIELD` bytes.
fn take_uint(data: &mut &[u8]) -> BoxedUint {
    let n = usize::from(take_u8(data)) % (MAX_FIELD + 1);
    BoxedUint::from_be_bytes(take(data, n))
}

/// The seven parameters of `curve`, in `from_params` order.
fn params_of(curve: &BoxedCurve) -> [BoxedUint; 7] {
    let (a, b) = curve.coefficients();
    let (gx, gy) = curve.generator();
    [curve.p(), a, b, gx, gy, curve.order(), curve.cofactor()]
}

fn from_params(v: &[BoxedUint; 7]) -> Option<BoxedCurve> {
    BoxedCurve::from_params(&v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &v[6]).ok()
}

/// A curve that validated must survive its own DER form and report the
/// parameters it was built from.
fn check_curve(curve: &BoxedCurve) {
    let der = curve.to_der();
    let again = BoxedCurve::from_der(&der).expect("own ECParameters re-parse");
    assert_eq!(&again, curve, "ECParameters round trip changed the curve");
    assert_eq!(again.to_der(), der);
    let v = params_of(curve);
    assert_eq!(
        from_params(&v).as_ref(),
        Some(curve),
        "a curve's own parameters must rebuild it"
    );
    assert_eq!(curve.field_len(), v[0].bit_len().div_ceil(8));
    assert_eq!(curve.order_len(), v[5].bit_len().div_ceil(8));
}

/// Decodes the rest of the input on `curve`: public key, scalar,
/// signature, then one verification and one key agreement.
fn use_curve(curve: &BoxedCurve, mut data: &[u8]) {
    let n_point = usize::from(take_u8(&mut data));
    let point = take(&mut data, n_point);
    let n_scalar = usize::from(take_u8(&mut data)) % (MAX_FIELD + 2);
    let scalar = take(&mut data, n_scalar);
    let sig_der = data;

    let public = BoxedEcdsaPublicKey::from_sec1(curve, point).ok();
    if let Some(pk) = &public {
        // The uncompressed form is canonical and decodes to the same key.
        let sec1 = pk.to_sec1();
        let again = BoxedEcdsaPublicKey::from_sec1(curve, &sec1).expect("own SEC1 point re-parse");
        assert_eq!(again.to_sec1(), sec1);
        assert_eq!(pk.boxed_curve(), curve);
    }

    // Both scalar importers apply the same `1 <= d < n` range check.
    let ecdsa = BoxedEcdsaPrivateKey::from_bytes(curve, scalar).ok();
    let ecdh = BoxedEcdhPrivateKey::from_bytes(curve, scalar).ok();
    assert_eq!(ecdsa.is_some(), ecdh.is_some());

    let unbounded = BoxedEcdsaSignature::from_der(sig_der);
    if let Ok(sig) = BoxedEcdsaSignature::from_der_for_curve(sig_der, curve) {
        assert!(unbounded.is_ok());
        // Bounded by this curve's order width, so the fixed-width
        // re-encoders must not panic.
        let _ = sig.to_bytes(curve);
        let _ = sig.to_der(curve);
        let _ = sig.is_low_s(curve);
        if let Some(pk) = &public {
            let _ = pk.verify_prehash(&[0x5a; 32], &sig);
        }
    }

    if let (Some(sk), Some(pk)) = (&ecdh, &public) {
        // An accepted public key is in the order-`n` subgroup, so the
        // agreement only fails if the result is the identity — which a
        // nonzero scalar below `n` cannot produce.
        let shared = sk.diffie_hellman(pk).expect("ECDH with a validated key");
        assert_eq!(shared.len(), curve.field_len());
    }
}

/// A private key that parsed must re-serialize and re-parse to itself.
fn check_private_key(key: &BoxedEcdsaPrivateKey) {
    let der = key.to_pkcs8_der();
    let again = BoxedEcdsaPrivateKey::from_pkcs8_der(&der).expect("own PKCS#8 re-parse");
    assert_eq!(again.boxed_curve(), key.boxed_curve());
    assert_eq!(*again.to_bytes(), *key.to_bytes());
    let sec1 = BoxedEcdsaPrivateKey::from_sec1_der(&key.to_sec1_der()).expect("own SEC1 re-parse");
    assert_eq!(*sec1.to_bytes(), *key.to_bytes());
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let Some((&shape, mut body)) = data.split_first() else {
        return;
    };
    match shape % 4 {
        0 => {
            if let Ok(curve) = BoxedCurve::from_der(body) {
                check_curve(&curve);
            }
            if let Ok(key) = BoxedEcdsaPrivateKey::from_sec1_der(body) {
                check_private_key(&key);
            }
            if let Ok(key) = BoxedEcdsaPrivateKey::from_pkcs8_der(body) {
                check_private_key(&key);
            }
            let _ = BoxedEcdhPrivateKey::from_pkcs8_der(body);
        }
        1 => {
            let v: [BoxedUint; 7] = core::array::from_fn(|_| take_uint(&mut body));
            if let Some(curve) = from_params(&v) {
                check_curve(&curve);
                use_curve(&curve, body);
            }
        }
        2 => {
            let curves = pinned();
            let base = &curves[usize::from(take_u8(&mut body)) % curves.len()];
            let mut v = params_of(base);
            let field = usize::from(take_u8(&mut body)) % v.len();
            v[field] = take_uint(&mut body);
            if let Some(curve) = from_params(&v) {
                check_curve(&curve);
                use_curve(&curve, body);
            }
        }
        _ => {
            let curves = pinned();
            let curve = &curves[usize::from(take_u8(&mut body)) % curves.len()];
            use_curve(curve, body);
        }
    }
});
