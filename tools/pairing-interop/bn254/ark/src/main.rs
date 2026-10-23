//! Cross-checks the gnark-generated BN254 vectors against arkworks 0.5
//! (a second, independent black-box oracle, public API only): scalar
//! multiples, additions, pairing values (in gnark's GT byte layout) and the
//! pairing-check verdicts.
//!
//!     cd tools/pairing-interop/bn254/ark && cargo run --release -- ../vectors/gnark.json

use ark_bn254::{Bn254, Fq, Fq12, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, Zero};

fn field<'a>(line: &'a str, key: &str) -> &'a str {
    let pat = format!("\"{key}\": \"");
    let start = line.find(&pat).unwrap_or_else(|| panic!("no {key}")) + pat.len();
    let len = line[start..].find('"').unwrap();
    &line[start..start + len]
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn fq_be(x: &Fq) -> Vec<u8> {
    x.into_bigint().to_bytes_be()
}

fn fq(b: &[u8]) -> Fq {
    Fq::from_be_bytes_mod_order(b)
}

fn g1_raw(p: &G1Affine) -> Vec<u8> {
    if p.is_zero() {
        return vec![0; 64];
    }
    [fq_be(&p.x), fq_be(&p.y)].concat()
}

fn g2_raw(q: &G2Affine) -> Vec<u8> {
    if q.is_zero() {
        return vec![0; 128];
    }
    [fq_be(&q.x.c1), fq_be(&q.x.c0), fq_be(&q.y.c1), fq_be(&q.y.c0)].concat()
}

fn g1_from(b: &[u8]) -> G1Affine {
    if b.iter().all(|&x| x == 0) {
        return G1Affine::zero();
    }
    let p = G1Affine::new_unchecked(fq(&b[..32]), fq(&b[32..]));
    assert!(p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve());
    p
}

fn g2_from(b: &[u8]) -> G2Affine {
    if b.iter().all(|&x| x == 0) {
        return G2Affine::zero();
    }
    let x = Fq2::new(fq(&b[32..64]), fq(&b[..32]));
    let y = Fq2::new(fq(&b[96..]), fq(&b[64..96]));
    let q = G2Affine::new_unchecked(x, y);
    assert!(q.is_on_curve() && q.is_in_correct_subgroup_assuming_on_curve());
    q
}

/// gnark's GT layout: the twelve Fp coefficients big-endian, last first.
fn gt_bytes(f: &Fq12) -> Vec<u8> {
    let mut c = Vec::new();
    for c6 in [&f.c0, &f.c1] {
        for c2 in [&c6.c0, &c6.c1, &c6.c2] {
            c.push(fq_be(&c2.c0));
            c.push(fq_be(&c2.c1));
        }
    }
    c.reverse();
    c.concat()
}

fn main() {
    let path = std::env::args().nth(1).expect("path to gnark.json");
    let text = std::fs::read_to_string(path).unwrap();
    let mut n = 0;
    for l in text.lines().filter(|l| l.starts_with('{')) {
        match field(l, "kind") {
            "g1" => {
                let k = Fr::from_be_bytes_mod_order(&unhex(field(l, "k")));
                let p = (G1Projective::generator() * k).into_affine();
                assert_eq!(g1_raw(&p), unhex(field(l, "uncompressed")), "{l}");
            }
            "g2" => {
                let k = Fr::from_be_bytes_mod_order(&unhex(field(l, "k")));
                let q = (G2Projective::generator() * k).into_affine();
                assert_eq!(g2_raw(&q), unhex(field(l, "uncompressed")), "{l}");
            }
            "g1add" => {
                let s = g1_from(&unhex(field(l, "a"))) + g1_from(&unhex(field(l, "b")));
                assert_eq!(g1_raw(&s.into_affine()), unhex(field(l, "sum")));
            }
            "g2add" => {
                let s = g2_from(&unhex(field(l, "a"))) + g2_from(&unhex(field(l, "b")));
                assert_eq!(g2_raw(&s.into_affine()), unhex(field(l, "sum")));
            }
            "pairing" => {
                let a = Fr::from_be_bytes_mod_order(&unhex(field(l, "a")));
                let b = Fr::from_be_bytes_mod_order(&unhex(field(l, "b")));
                let e = Bn254::pairing(G1Projective::generator() * a, G2Projective::generator() * b);
                assert_eq!(gt_bytes(&e.0), unhex(field(l, "gt")), "{l}");
            }
            "pairing_check" => {
                let input = unhex(field(l, "input"));
                let (ps, qs): (Vec<_>, Vec<_>) = input
                    .chunks(192)
                    .map(|r| (g1_from(&r[..64]), g2_from(&r[64..])))
                    .unzip();
                let ok = Bn254::multi_pairing(ps, qs).is_zero();
                assert_eq!(ok, l.contains("\"result\": true"), "{l}");
            }
            "g2_not_in_subgroup" => {
                let b = unhex(field(l, "uncompressed"));
                let x = Fq2::new(fq(&b[32..64]), fq(&b[..32]));
                let y = Fq2::new(fq(&b[96..]), fq(&b[64..96]));
                let q = G2Affine::new_unchecked(x, y);
                assert!(q.is_on_curve() && !q.is_in_correct_subgroup_assuming_on_curve());
            }
            _ => continue,
        }
        n += 1;
    }
    println!("arkworks agrees on {n} records");
}
