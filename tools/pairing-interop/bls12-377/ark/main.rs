//! Black-box vector generator for purecrypto's BLS12-377 module, driving
//! only the public API of arkworks 0.5 (`ark-bls12-377`, `ark-ec`,
//! `ark-serialize`). Prints JSON on stdout. See ../README.md.

use ark_bls12_377::{Bls12_377, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, PrimeGroup};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn ser<T: CanonicalSerialize>(t: &T) -> (String, String) {
    let mut c = Vec::new();
    t.serialize_compressed(&mut c).unwrap();
    let mut u = Vec::new();
    t.serialize_uncompressed(&mut u).unwrap();
    (hex(&c), hex(&u))
}

fn main() {
    // The same scalar list as the gnark driver.
    let mut ks: Vec<Fr> = vec![
        Fr::from(1u64),
        Fr::from(2u64),
        Fr::from(3u64),
        Fr::from(0x1234567u64),
        -Fr::from(1u64),
    ];
    let mut seed: [u8; 32] = Sha256::digest(b"purecrypto bls12-377 scalars").into();
    for _ in 0..8 {
        ks.push(Fr::from_be_bytes_mod_order(&seed));
        seed = Sha256::digest(seed).into();
    }
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    let mut out = String::from("{\n");
    let mut g1s = Vec::new();
    let mut g2s = Vec::new();
    for k in &ks {
        let p: G1Affine = (g1 * k).into_affine();
        let q: G2Affine = (g2 * k).into_affine();
        let (pc, pu) = ser(&p);
        let (qc, qu) = ser(&q);
        g1s.push(format!("  {{\"Comp\": \"{pc}\", \"Raw\": \"{pu}\"}}"));
        g2s.push(format!("  {{\"Comp\": \"{qc}\", \"Raw\": \"{qu}\"}}"));
    }
    let (ic, iu) = ser(&G1Affine::zero());
    let (jc, ju) = ser(&G2Affine::zero());
    out += &format!(" \"G1Inf\": {{\"Comp\": \"{ic}\", \"Raw\": \"{iu}\"}},\n");
    out += &format!(" \"G2Inf\": {{\"Comp\": \"{jc}\", \"Raw\": \"{ju}\"}},\n");
    out += &format!(" \"G1Mul\": [\n{}\n ],\n", g1s.join(",\n"));
    out += &format!(" \"G2Mul\": [\n{}\n ],\n", g2s.join(",\n"));
    let mut prs = Vec::new();
    let mut i = 0;
    while i + 1 < ks.len() {
        let e = Bls12_377::pairing(g1 * ks[i], g2 * ks[i + 1]);
        let (c, u) = ser(&e);
        prs.push(format!("  {{\"Comp\": \"{c}\", \"Raw\": \"{u}\"}}"));
        i += 2;
    }
    out += &format!(" \"Pairings\": [\n{}\n ],\n", prs.join(",\n"));
    type H1 = MapToCurveBasedHasher<
        G1Projective,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<ark_bls12_377::g1::Config>,
    >;
    type H2 = MapToCurveBasedHasher<
        G2Projective,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<ark_bls12_377::g2::Config>,
    >;
    let h1 = H1::new(b"QUUX-V01-CS02-with-BLS12377G1_XMD:SHA-256_SSWU_RO_").unwrap();
    let h2 = H2::new(b"QUUX-V01-CS02-with-BLS12377G2_XMD:SHA-256_SSWU_RO_").unwrap();
    let mut hs = Vec::new();
    for m in ["", "abc", "abcdef0123456789"] {
        let (a, _) = ser(&h1.hash(m.as_bytes()).unwrap());
        let (b, _) = ser(&h2.hash(m.as_bytes()).unwrap());
        hs.push(format!("  {{\"Msg\": \"{m}\", \"G1\": \"{a}\", \"G2\": \"{b}\"}}"));
    }
    out += &format!(" \"Hashes\": [\n{}\n ]\n}}\n", hs.join(",\n"));
    print!("{out}");
}
