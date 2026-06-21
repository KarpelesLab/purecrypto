//! `SamplerZ` known-answer tests against the `tprest/falcon.py` reference
//! vectors (`scripts/samplerz_KAT512.py` + `samplerz_KAT1024.py`, 3072 cases).
//!
//! Each vector pins `(mu, sigma, sigmin, octets) → z`: the exact center,
//! deviations, consumed random bytes, and expected output. Passing them proves
//! both the output distribution *and* the exact random-byte consumption order,
//! which is the real correctness gate for the constant-time sampler — far
//! stronger than any round-trip check.

use super::super::fpr::Fpr;
use super::{SamplerRng, sampler_z};
use crate::test_util::from_hex_vec;
use alloc::vec::Vec;

/// Replicates the reference `KAT_randbytes`: each `randombytes(k)` call returns
/// the next `k` bytes of the fixed string, **byte-reversed** (`fromhex(..)[::-1]`).
struct KatRng {
    data: Vec<u8>,
    pos: usize,
}

impl SamplerRng for KatRng {
    fn next_bytes(&mut self, buf: &mut [u8]) {
        let k = buf.len();
        for (i, slot) in buf.iter_mut().enumerate() {
            *slot = self.data[self.pos + (k - 1 - i)];
        }
        self.pos += k;
    }
}

#[test]
fn samplerz_reference_kats() {
    let mut count = 0usize;
    for (lineno, line) in include_str!("../../testdata/falcon_samplerz.kat")
        .lines()
        .enumerate()
    {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.split_whitespace();
        let mu: f64 = it.next().unwrap().parse().unwrap();
        let sigma: f64 = it.next().unwrap().parse().unwrap();
        let sigmin: f64 = it.next().unwrap().parse().unwrap();
        let octets = from_hex_vec(it.next().unwrap());
        let z_exp: i64 = it.next().unwrap().parse().unwrap();

        let mut rng = KatRng {
            data: octets,
            pos: 0,
        };
        let z = sampler_z(
            Fpr::from_f64(mu),
            Fpr::from_f64(sigma),
            Fpr::from_f64(sigmin),
            &mut rng,
        );
        assert_eq!(
            z,
            z_exp,
            "line {}: mu={mu} sigma={sigma} sigmin={sigmin} got {z} want {z_exp}",
            lineno + 1
        );
        count += 1;
    }
    assert_eq!(count, 3072, "expected all reference vectors to run");
}
