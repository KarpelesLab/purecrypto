//! Known-answer tests against gnark-crypto v0.21 and arkworks 0.5, from
//! `testdata/bls12_377/kat.txt` (generated black-box by the drivers in
//! `tools/pairing-interop/bls12-377/`).

use super::hash_to_curve::{map_to_curve_g1, map_to_curve_g2};
use super::*;

const KAT: &str = include_str!("../../testdata/bls12_377/kat.txt");

const DST_G1_RO: &[u8] = b"QUUX-V01-CS02-with-BLS12377G1_XMD:SHA-256_SSWU_RO_";
const DST_G1_NU: &[u8] = b"QUUX-V01-CS02-with-BLS12377G1_XMD:SHA-256_SSWU_NU_";
const DST_G2_RO: &[u8] = b"QUUX-V01-CS02-with-BLS12377G2_XMD:SHA-256_SSWU_RO_";
const DST_G2_NU: &[u8] = b"QUUX-V01-CS02-with-BLS12377G2_XMD:SHA-256_SSWU_NU_";

/// Decodes hex into a fixed buffer, returning the used prefix length.
fn unhex<'a>(s: &str, buf: &'a mut [u8; 1024]) -> &'a [u8] {
    if s == "-" {
        return &buf[..0];
    }
    let n = s.len() / 2;
    for i in 0..n {
        buf[i] = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    &buf[..n]
}

fn arr<const N: usize>(s: &str) -> [u8; N] {
    let mut buf = [0u8; 1024];
    let b = unhex(s, &mut buf);
    let mut out = [0u8; N];
    out.copy_from_slice(b);
    out
}

fn scalar(s: &str) -> Fr {
    Fr::from_bytes(&arr::<32>(s)).unwrap()
}

fn lines(kind: &'static str) -> impl Iterator<Item = alloc_free::Fields> {
    KAT.lines().filter_map(move |l| {
        let mut it = l.split(' ');
        (it.next() == Some(kind)).then(|| alloc_free::Fields::new(l))
    })
}

mod alloc_free {
    /// The space-separated fields of one KAT line (no allocation).
    pub(super) struct Fields(&'static str);
    impl Fields {
        pub(super) fn new(l: &'static str) -> Self {
            Fields(l)
        }
        pub(super) fn get(&self, i: usize) -> &'static str {
            self.0.split(' ').nth(i + 1).unwrap()
        }
    }
}

#[test]
fn g1_scalar_mul_and_encodings() {
    let mut n = 0;
    for f in lines("g1") {
        let k = scalar(f.get(0));
        let p = G1::generator() * k;
        assert_eq!(p.to_compressed(), arr::<48>(f.get(1)));
        assert_eq!(p.to_uncompressed(), arr::<96>(f.get(2)));
        assert_eq!(p.to_compressed_ark(), arr::<48>(f.get(3)));
        assert_eq!(p.to_uncompressed_ark(), arr::<96>(f.get(4)));
        assert_eq!(G1::from_compressed(&arr::<48>(f.get(1))).unwrap(), p);
        assert_eq!(G1::from_uncompressed(&arr::<96>(f.get(2))).unwrap(), p);
        assert_eq!(G1::from_compressed_ark(&arr::<48>(f.get(3))).unwrap(), p);
        assert_eq!(G1::from_uncompressed_ark(&arr::<96>(f.get(4))).unwrap(), p);
        n += 1;
    }
    assert_eq!(n, 14);
}

#[test]
fn g2_scalar_mul_and_encodings() {
    let mut n = 0;
    for f in lines("g2") {
        let k = scalar(f.get(0));
        let p = G2::generator() * k;
        assert_eq!(p.to_compressed(), arr::<96>(f.get(1)));
        assert_eq!(p.to_uncompressed(), arr::<192>(f.get(2)));
        assert_eq!(p.to_compressed_ark(), arr::<96>(f.get(3)));
        assert_eq!(p.to_uncompressed_ark(), arr::<192>(f.get(4)));
        assert_eq!(G2::from_compressed(&arr::<96>(f.get(1))).unwrap(), p);
        assert_eq!(G2::from_uncompressed(&arr::<192>(f.get(2))).unwrap(), p);
        assert_eq!(G2::from_compressed_ark(&arr::<96>(f.get(3))).unwrap(), p);
        assert_eq!(G2::from_uncompressed_ark(&arr::<192>(f.get(4))).unwrap(), p);
        n += 1;
    }
    assert_eq!(n, 14);
}

#[test]
fn pairings_match_gnark_and_arkworks() {
    let mut n = 0;
    for f in lines("pair") {
        let p = G1::generator() * scalar(f.get(0));
        let q = G2::generator() * scalar(f.get(1));
        let e = pairing(&p, &q);
        assert_eq!(e.to_bytes(), arr::<576>(f.get(2)));
        assert_eq!(e.to_bytes_ark(), arr::<576>(f.get(3)));
        assert_eq!(Gt::from_bytes(&arr::<576>(f.get(2))).unwrap(), e);
        assert_eq!(Gt::from_bytes_ark(&arr::<576>(f.get(3))).unwrap(), e);
        n += 1;
    }
    assert_eq!(n, 6);
}

#[test]
fn hash_and_encode_match_gnark() {
    let mut n = 0;
    for f in lines("hash") {
        let mut buf = [0u8; 1024];
        let msg = unhex(f.get(0), &mut buf);
        assert_eq!(
            hash_to_g1(msg, DST_G1_RO).to_compressed(),
            arr::<48>(f.get(1))
        );
        assert_eq!(
            encode_to_g1(msg, DST_G1_NU).to_compressed(),
            arr::<48>(f.get(2))
        );
        assert_eq!(
            hash_to_g2(msg, DST_G2_RO).to_compressed(),
            arr::<96>(f.get(3))
        );
        assert_eq!(
            encode_to_g2(msg, DST_G2_NU).to_compressed(),
            arr::<96>(f.get(4))
        );
        n += 1;
    }
    assert_eq!(n, 5);
}

/// arkworks' G2 hash agrees with gnark's (and so with ours); its G1 hash
/// does not — recorded here so a change on either side is noticed.
#[test]
fn arkworks_hash_agreement() {
    let mut n = 0;
    for f in lines("arkhash") {
        let mut buf = [0u8; 1024];
        let msg = unhex(f.get(0), &mut buf);
        let h2 = hash_to_g2(msg, DST_G2_RO);
        assert_eq!(h2.to_compressed_ark(), arr::<96>(f.get(2)));
        let h1 = hash_to_g1(msg, DST_G1_RO);
        let ark1 = G1::from_compressed_ark(&arr::<48>(f.get(1))).unwrap();
        assert_ne!(h1, ark1);
        n += 1;
    }
    assert_eq!(n, 3);
}

#[test]
fn raw_maps_match_gnark() {
    for f in lines("map1") {
        let u = Fp::from_bytes(&arr::<48>(f.get(0))).unwrap();
        let p = G1::clear_cofactor(&map_to_curve_g1(&u));
        assert_eq!(p.to_compressed(), arr::<48>(f.get(1)));
    }
    for f in lines("map2") {
        let u = Fp2::new(
            Fp::from_bytes(&arr::<48>(f.get(0))).unwrap(),
            Fp::from_bytes(&arr::<48>(f.get(1))).unwrap(),
        );
        let p = G2::clear_cofactor(&map_to_curve_g2(&u));
        assert_eq!(p.to_compressed(), arr::<96>(f.get(2)));
    }
}
