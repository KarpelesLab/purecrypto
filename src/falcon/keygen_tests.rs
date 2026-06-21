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
