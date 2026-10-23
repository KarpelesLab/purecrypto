//! Interop vectors produced by gnark-crypto v0.21 driven as a black-box
//! oracle (`tools/pairing-interop/bn254/`): scalar multiples and their
//! encodings, additions, pairing values, EIP-197 pairing checks, the four
//! hash-to-curve suites, the raw maps, and twist points outside `G2` that
//! both implementations must reject. Allocator-free so it runs in the
//! leanest feature set.

use super::*;
use crate::test_util::from_hex;

const VECTORS: &str = include_str!("../../tools/pairing-interop/bn254/vectors/gnark.json");

/// The string value of `"key": "…"` in a one-line flat JSON object.
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let mut pat = [0u8; 32];
    let pat = {
        let n = key.len() + 5;
        pat[0] = b'"';
        pat[1..=key.len()].copy_from_slice(key.as_bytes());
        pat[key.len() + 1..n].copy_from_slice(b"\": \"");
        core::str::from_utf8(&pat[..n]).unwrap()
    };
    let start = line
        .find(pat)
        .unwrap_or_else(|| panic!("no {key} in {line}"))
        + pat.len();
    let len = line[start..].find('"').unwrap();
    &line[start..start + len]
}

/// Decodes hex into the front of `buf`, returning the decoded length.
fn hex_into(s: &str, buf: &mut [u8]) -> usize {
    let b = s.as_bytes();
    assert_eq!(b.len() % 2, 0);
    for (i, pair) in b.chunks_exact(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
        let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
        buf[i] = (hi << 4) | lo;
    }
    b.len() / 2
}

fn records(kind: &'static str) -> impl Iterator<Item = &'static str> {
    VECTORS
        .lines()
        .filter(move |l| l.starts_with('{') && field(l, "kind") == kind)
}

fn count(kind: &'static str) -> usize {
    records(kind).count()
}

#[test]
fn scalar_multiples_and_encodings() {
    for kind in ["g1", "g2"] {
        assert_eq!(count(kind), 25, "{kind}");
    }
    for l in records("g1") {
        let k = Fr::from_bytes(&from_hex(field(l, "k"))).unwrap();
        let p = G1::generator().mul(&k);
        let c: [u8; 32] = from_hex(field(l, "compressed"));
        let u: [u8; 64] = from_hex(field(l, "uncompressed"));
        assert_eq!(p.to_compressed(), c, "{l}");
        assert_eq!(p.to_uncompressed(), u, "{l}");
        assert_eq!(G1::from_compressed(&c).unwrap(), p);
        assert_eq!(G1::from_uncompressed(&u).unwrap(), p);
    }
    for l in records("g2") {
        let k = Fr::from_bytes(&from_hex(field(l, "k"))).unwrap();
        let q = G2::generator().mul(&k);
        let c: [u8; 64] = from_hex(field(l, "compressed"));
        let u: [u8; 128] = from_hex(field(l, "uncompressed"));
        assert_eq!(q.to_compressed(), c, "{l}");
        assert_eq!(q.to_uncompressed(), u, "{l}");
        assert_eq!(G2::from_compressed(&c).unwrap(), q);
        assert_eq!(G2::from_uncompressed(&u).unwrap(), q);
    }
}

#[test]
fn additions() {
    assert_eq!(count("g1add"), 4);
    for l in records("g1add") {
        let a = G1::from_uncompressed(&from_hex::<64>(field(l, "a"))).unwrap();
        let b = G1::from_uncompressed(&from_hex::<64>(field(l, "b"))).unwrap();
        assert_eq!((a + b).to_uncompressed(), from_hex::<64>(field(l, "sum")));
    }
    assert_eq!(count("g2add"), 4);
    for l in records("g2add") {
        let a = G2::from_uncompressed(&from_hex::<128>(field(l, "a"))).unwrap();
        let b = G2::from_uncompressed(&from_hex::<128>(field(l, "b"))).unwrap();
        assert_eq!((a + b).to_uncompressed(), from_hex::<128>(field(l, "sum")));
    }
}

#[test]
fn pairing_values() {
    assert_eq!(count("pairing"), 9);
    for l in records("pairing") {
        let a = Fr::from_bytes(&from_hex(field(l, "a"))).unwrap();
        let b = Fr::from_bytes(&from_hex(field(l, "b"))).unwrap();
        let gt: [u8; 384] = from_hex(field(l, "gt"));
        let e = pairing(&G1::generator().mul(&a), &G2::generator().mul(&b));
        assert_eq!(e.to_bytes(), gt, "{l}");
        assert_eq!(Gt::from_bytes(&gt).unwrap(), e);
    }
}

#[test]
fn eip197_pairing_checks() {
    assert_eq!(count("pairing_check"), 12);
    let mut buf = [0u8; 192 * 12];
    let (mut ok, mut bad) = (0, 0);
    for l in records("pairing_check") {
        let n = hex_into(field(l, "input"), &mut buf);
        let want = l.contains("\"result\": true");
        assert_eq!(pairing_check_eip197(&buf[..n]), Ok(want), "{n} bytes");
        if want { ok += 1 } else { bad += 1 }
    }
    assert_eq!((ok, bad), (6, 6));
}

#[test]
fn hash_to_curve_suites() {
    assert_eq!(count("h2c"), 20);
    let mut msg = [0u8; 600];
    for l in records("h2c") {
        let n = hex_into(field(l, "msg"), &mut msg);
        let msg = &msg[..n];
        let dst = field(l, "dst").as_bytes();
        match field(l, "suite") {
            "BN254G1_XMD:SHA-256_SVDW_RO_" => {
                let want: [u8; 64] = from_hex(field(l, "point"));
                assert_eq!(hash_to_g1(msg, dst).to_uncompressed(), want, "{l}");
                assert_eq!(G1::hash_to_curve(msg, dst).to_uncompressed(), want);
            }
            "BN254G1_XMD:SHA-256_SVDW_NU_" => {
                let want: [u8; 64] = from_hex(field(l, "point"));
                assert_eq!(encode_to_g1(msg, dst).to_uncompressed(), want, "{l}");
            }
            "BN254G2_XMD:SHA-256_SVDW_RO_" => {
                let want: [u8; 128] = from_hex(field(l, "point"));
                assert_eq!(hash_to_g2(msg, dst).to_uncompressed(), want, "{l}");
                assert_eq!(G2::hash_to_curve(msg, dst).to_uncompressed(), want);
            }
            "BN254G2_XMD:SHA-256_SVDW_NU_" => {
                let want: [u8; 128] = from_hex(field(l, "point"));
                assert_eq!(encode_to_g2(msg, dst).to_uncompressed(), want, "{l}");
            }
            s => panic!("unknown suite {s}"),
        }
    }
}

#[test]
fn raw_maps() {
    assert_eq!(count("map_g1"), 6);
    for l in records("map_g1") {
        let u = Fp::from_bytes(&from_hex(field(l, "u"))).unwrap();
        let want: [u8; 64] = from_hex(field(l, "point"));
        assert_eq!(G1::map_to_curve(&u).to_uncompressed(), want, "{l}");
    }
    assert_eq!(count("map_g2"), 6);
    for l in records("map_g2") {
        let u0 = Fp::from_bytes(&from_hex(field(l, "u0"))).unwrap();
        let u1 = Fp::from_bytes(&from_hex(field(l, "u1"))).unwrap();
        let want: [u8; 128] = from_hex(field(l, "point"));
        assert_eq!(
            G2::map_to_curve(&Fp2::new(u0, u1)).to_uncompressed(),
            want,
            "{l}"
        );
    }
}

#[test]
fn twist_points_outside_g2_are_rejected() {
    assert_eq!(count("g2_not_in_subgroup"), 3);
    for l in records("g2_not_in_subgroup") {
        let c: [u8; 64] = from_hex(field(l, "compressed"));
        let u: [u8; 128] = from_hex(field(l, "uncompressed"));
        assert_eq!(G2::from_compressed(&c), Err(Error::NotInSubgroup));
        assert_eq!(G2::from_uncompressed(&u), Err(Error::NotInSubgroup));
        let mut rec = [0u8; 192];
        rec[..64].copy_from_slice(&G1::generator().to_uncompressed());
        rec[64..].copy_from_slice(&u);
        assert_eq!(pairing_check_eip197(&rec), Err(Error::NotInSubgroup));
    }
}
