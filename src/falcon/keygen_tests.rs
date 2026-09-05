//! Key-generation correctness: the exact NTRU equation `f·G − g·F = q` over
//! `ℤ[x]/(xⁿ+1)`, and `h·f ≡ g (mod q)`. These are complete correctness proofs
//! independent of any KAT — a wrong solver cannot satisfy them.

use super::super::sampler::SamplerRng;
use super::super::zint::Zint;
use super::{Q, karamul, ntru_gen};
use alloc::vec::Vec;

/// Deterministic byte source (keygen consumes a lot of randomness).
struct DetRng(u64);
impl SamplerRng for DetRng {
    fn next_bytes(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(0x5851_F42D_4C95_7F2D)
                .wrapping_add(0x1405_7B7E_F767_814F);
            *b = (self.0 >> 56) as u8;
        }
    }
}

fn to_zint(p: &[i64]) -> Vec<Zint> {
    p.iter().map(|&c| Zint::from_i64(c)).collect()
}

/// Schoolbook negacyclic multiply mod q.
fn polymul_modq(a: &[i64], b: &[i64], n: usize) -> Vec<i64> {
    let mut acc = alloc::vec![0i64; n];
    for i in 0..n {
        for j in 0..n {
            let p = a[i] * b[j];
            let k = i + j;
            if k < n {
                acc[k] += p;
            } else {
                acc[k - n] -= p;
            }
        }
    }
    acc.iter().map(|v| v.rem_euclid(Q)).collect()
}

fn check_keygen(n: usize, seed: u64) {
    let mut rng = DetRng(seed);
    let (f, g, cap_f, cap_g, h) = ntru_gen(n, &mut rng);
    assert_eq!(f.len(), n);

    // 1) NTRU equation: f·G − g·F == q (constant polynomial).
    let fg = karamul(&to_zint(&f), &to_zint(&cap_g));
    let gf = karamul(&to_zint(&g), &to_zint(&cap_f));
    let q = Zint::from_i64(Q);
    for i in 0..n {
        let d = fg[i].sub(&gf[i]);
        if i == 0 {
            assert_eq!(d, q, "n={n}: (f·G − g·F)[0] must be q");
        } else {
            assert!(d.is_zero(), "n={n}: (f·G − g·F)[{i}] must be 0");
        }
    }

    // 2) Public key: h·f ≡ g (mod q).
    let h_i: Vec<i64> = h.iter().map(|&x| x as i64).collect();
    let hf = polymul_modq(&h_i, &f, n);
    for i in 0..n {
        assert_eq!(hf[i], g[i].rem_euclid(Q), "n={n}: (h·f − g)[{i}] ≠ 0 mod q");
    }
}

#[test]
fn keygen_ntru_equation_n256() {
    check_keygen(256, 0x1111_2222_3333_4444);
}

#[test]
fn keygen_ntru_equation_n512() {
    check_keygen(512, 0xACE1_0F1E_2D3C_4B5A);
}

/// `ntru_gen` used to check the Gram-Schmidt bound, invertibility, NTRUSolve
/// success and that `F, G` fit an `i64` — but not that the coefficients fit the
/// *compact encoding*: `f`/`g` in `fg_bits(n)`-bit fields, `F` in 8-bit ones.
/// A key over that range signed fine in memory, but `to_bytes` emitted a
/// wrapped encoding that `check_ntru` rejected on reload: silent, unrecoverable
/// key loss for anyone who generated, saved and restarted. Every generated key
/// must now round-trip.
#[test]
fn keygen_coefficients_fit_the_compact_encoding() {
    use super::super::encode::{fg_bits, fits_reference_signed, fits_signed};

    for (n, seed) in [
        (256usize, 0xDEAD_BEEF_0000_0001u64),
        (512, 0x0BAD_C0DE_1234_5678),
    ] {
        let mut rng = DetRng(seed);
        let (f, g, cap_f, _cap_g, _h) = ntru_gen(n, &mut rng);
        let w = fg_bits(n);
        assert!(fits_signed(&f, w), "n={n}: f outside its {w}-bit field");
        assert!(fits_signed(&g, w), "n={n}: g outside its {w}-bit field");
        assert!(fits_signed(&cap_f, 8), "n={n}: F outside its 8-bit field");
        // And the stricter symmetric range the reference encoder requires, so
        // the encoding stays byte-compatible with it.
        assert!(
            fits_reference_signed(&f, w),
            "n={n}: f outside the reference range"
        );
        assert!(
            fits_reference_signed(&g, w),
            "n={n}: g outside the reference range"
        );
        assert!(
            fits_reference_signed(&cap_f, 8),
            "n={n}: |F_i| > 127 -- the case with non-negligible probability"
        );
    }
}

/// End-to-end: a generated key survives `to_bytes` -> `from_bytes`. Before the
/// range check this could fail for a key that had just signed correctly.
#[test]
fn generated_keys_round_trip_through_the_compact_encoding() {
    use super::super::{Degree, FalconPrivateKey};

    struct R(u64);
    impl crate::rng::RngCore for R {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for b in dest.iter_mut() {
                self.0 = self
                    .0
                    .wrapping_mul(0x5851_F42D_4C95_7F2D)
                    .wrapping_add(0x1405_7B7E_F767_814F);
                *b = (self.0 >> 56) as u8;
            }
        }
    }
    impl crate::rng::CryptoRng for R {}

    for seed in [0x1u64, 0x5EED_1234_ABCD_0001, 0xFFFF_0000_1111_2222] {
        let mut rng = R(seed);
        let sk = FalconPrivateKey::generate(Degree::Falcon512, &mut rng);
        let bytes = sk.to_bytes();
        let back = FalconPrivateKey::from_bytes(&bytes).expect("generated key must reload");
        assert_eq!(back.to_bytes(), bytes, "reload is byte-identical");
        // And it still signs.
        let sig = back.sign(b"round trip", &mut rng);
        assert!(super::super::verify(
            &sk.public_key_bytes(),
            b"round trip",
            &sig
        ));
    }
}
