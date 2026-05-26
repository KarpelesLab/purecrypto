//! `purecrypto kex -alg X25519|ECDH-P256|ECDH-P384|ECDH-P521 -key FILE -peer FILE -out FILE`
//! — derive a Diffie-Hellman shared secret.

use crate::util::{Args, die, write_output_with_mode};
use purecrypto::der::{Reader, pem_decode, tag};
use purecrypto::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPublicKey, CurveId, x25519::X25519PrivateKey};
use purecrypto::x509::AnyPublicKey;

/// Parses the private scalar `d` (big-endian) out of a SEC1 `EC PRIVATE KEY`
/// PEM document, returning `(curve, scalar_bytes)`.
fn parse_sec1_scalar(pem: &str) -> Option<(CurveId, Vec<u8>)> {
    let der = pem_decode(pem, "EC PRIVATE KEY").ok()?;
    let mut outer = Reader::new(&der);
    let mut seq = outer.read_sequence().ok()?;
    seq.read_integer_bytes().ok()?; // version
    let priv_bytes = seq.read_octet_string().ok()?.to_vec();
    if seq.peek_tag() != Some(tag::context(0)) {
        return None;
    }
    let params = seq.read_tlv(tag::context(0)).ok()?;
    let mut pr = Reader::new(params);
    let arcs = purecrypto::der::parse_oid(pr.read_oid().ok()?).ok()?;
    let curve = curve_from_arcs(arcs.as_slice())?;
    Some((curve, priv_bytes))
}

fn curve_from_arcs(arcs: &[u64]) -> Option<CurveId> {
    // OIDs from RFC 5480 §2.1.1.1 / SEC 2.
    const P256: &[u64] = &[1, 2, 840, 10045, 3, 1, 7];
    const P384: &[u64] = &[1, 3, 132, 0, 34];
    const P521: &[u64] = &[1, 3, 132, 0, 35];
    const SECP256K1: &[u64] = &[1, 3, 132, 0, 10];
    if arcs == P256 {
        Some(CurveId::P256)
    } else if arcs == P384 {
        Some(CurveId::P384)
    } else if arcs == P521 {
        Some(CurveId::P521)
    } else if arcs == SECP256K1 {
        Some(CurveId::Secp256k1)
    } else {
        None
    }
}

pub(crate) fn run(args: Args) {
    let alg = args
        .value("-alg")
        .or_else(|| args.value("--alg"))
        .unwrap_or_else(|| die("missing -alg X25519|ECDH-P256|ECDH-P384|ECDH-P521"));
    let key_path = args
        .value("-key")
        .or_else(|| args.value("--key"))
        .unwrap_or_else(|| die("missing -key FILE"));
    let peer_path = args
        .value("-peer")
        .or_else(|| args.value("--peer"))
        .unwrap_or_else(|| die("missing -peer FILE"));
    let out_path = args
        .value("-out")
        .or_else(|| args.value("--out"))
        .unwrap_or_else(|| die("missing -out FILE"));

    let key_bytes =
        std::fs::read(key_path).unwrap_or_else(|e| die(format!("cannot read {key_path}: {e}")));
    let peer_bytes =
        std::fs::read(peer_path).unwrap_or_else(|e| die(format!("cannot read {peer_path}: {e}")));

    let alg = alg.to_ascii_uppercase();
    let secret = match alg.as_str() {
        "X25519" => {
            // X25519 has no PKCS#8 plumbing in the library yet — accept either
            // a 32-byte binary scalar or a 64-character hex scalar for both
            // `-key` and `-peer`.
            let scalar = parse_raw_or_hex_32(&key_bytes)
                .unwrap_or_else(|| die("-key must be a 32-byte X25519 scalar (raw or hex)"));
            let peer = parse_raw_or_hex_32(&peer_bytes)
                .unwrap_or_else(|| die("-peer must be a 32-byte X25519 public key (raw or hex)"));
            let sk = X25519PrivateKey::from_bytes(scalar);
            sk.diffie_hellman(&peer)
                .unwrap_or_else(|e| die(format!("X25519: {e}")))
                .to_vec()
        }
        a if a.starts_with("ECDH-") => {
            let want_curve = match a {
                "ECDH-P256" => CurveId::P256,
                "ECDH-P384" => CurveId::P384,
                "ECDH-P521" => CurveId::P521,
                "ECDH-SECP256K1" => CurveId::Secp256k1,
                _ => die(format!("unknown -alg: {a}")),
            };
            let key_pem = core::str::from_utf8(&key_bytes)
                .unwrap_or_else(|_| die("-key is not a UTF-8 PEM document"));
            let peer_pem = core::str::from_utf8(&peer_bytes)
                .unwrap_or_else(|_| die("-peer is not a UTF-8 PEM document"));
            let (curve, scalar) = parse_sec1_scalar(key_pem)
                .unwrap_or_else(|| die("-key must be a SEC1 EC PRIVATE KEY PEM"));
            if curve != want_curve {
                die(format!(
                    "-key is on the wrong curve for {a}: got {:?}, want {:?}",
                    curve, want_curve
                ));
            }
            let sk = BoxedEcdhPrivateKey::from_bytes(curve, &scalar)
                .unwrap_or_else(|e| die(format!("invalid scalar: {e}")));
            let peer_any = AnyPublicKey::from_spki_pem(peer_pem)
                .unwrap_or_else(|e| die(format!("-peer must be SPKI PEM: {e}")));
            let peer_pk: BoxedEcdsaPublicKey = match peer_any {
                AnyPublicKey::Ecdsa(k) if k.curve() == want_curve => k,
                AnyPublicKey::Ecdsa(k) => die(format!(
                    "-peer is on curve {:?}, expected {:?}",
                    k.curve(),
                    want_curve
                )),
                _ => die("-peer must be an ECDSA SPKI on the matching curve"),
            };
            sk.diffie_hellman(&peer_pk)
                .unwrap_or_else(|e| die(format!("ECDH derivation failed: {e}")))
        }
        other => die(format!("unknown -alg: {other}")),
    };

    write_output_with_mode(Some(out_path), &secret, /* private = */ true);
}

fn parse_raw_or_hex_32(bytes: &[u8]) -> Option<[u8; 32]> {
    if bytes.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        return Some(out);
    }
    // Treat as hex (ignoring whitespace).
    let s = core::str::from_utf8(bytes).ok()?;
    let dec = crate::util::from_hex(s)?;
    if dec.len() == 32 {
        let mut out = [0u8; 32];
        out.copy_from_slice(&dec);
        Some(out)
    } else {
        None
    }
}
