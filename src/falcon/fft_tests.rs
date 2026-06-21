//! FFT correctness: round-trip identity and agreement with schoolbook
//! negacyclic multiplication. Values are compared in host `f64` with a
//! tolerance (the table-free roots carry a few ulps of error by design).

use super::super::fpr::Fpr;
use super::{Cplx, Fft, mul_fft};
use alloc::vec::Vec;

struct Sm64(u64);
impl Sm64 {
    fn new(s: u64) -> Sm64 {
        Sm64(s)
    }
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Small signed value in [-128, 127], as an `Fpr`.
    fn small(&mut self) -> Fpr {
        let v = (self.next() & 0xFF) as i64 - 128;
        Fpr::of_i64(v)
    }
}

fn rand_poly(rng: &mut Sm64, n: usize) -> Vec<Fpr> {
    (0..n).map(|_| rng.small()).collect()
}

/// Schoolbook negacyclic product mod (xⁿ+1) in host `f64`.
fn schoolbook(a: &[Fpr], b: &[Fpr]) -> Vec<f64> {
    let n = a.len();
    let mut out = alloc::vec![0.0f64; n];
    for i in 0..n {
        for j in 0..n {
            let p = a[i].to_f64() * b[j].to_f64();
            let k = i + j;
            if k < n {
                out[k] += p;
            } else {
                out[k - n] -= p;
            }
        }
    }
    out
}

#[test]
fn fft_ifft_round_trip() {
    let mut rng = Sm64::new(0x5151_2323_8989_ABAB);
    for &n in &[2usize, 4, 8, 16, 256, 512, 1024] {
        let fft = Fft::new(n);
        for _ in 0..8 {
            let f = rand_poly(&mut rng, n);
            let back = fft.ifft(&fft.fft(&f));
            let mut maxerr = 0.0f64;
            for i in 0..n {
                maxerr = maxerr.max((f[i].to_f64() - back[i].to_f64()).abs());
            }
            assert!(maxerr < 1e-6, "n={n} round-trip maxerr={maxerr}");
        }
    }
}

#[test]
fn fft_mul_matches_schoolbook() {
    let mut rng = Sm64::new(0xC0DE_F00D_1234_9999);
    for &n in &[2usize, 4, 8, 16, 256, 512, 1024] {
        let fft = Fft::new(n);
        for _ in 0..6 {
            let a = rand_poly(&mut rng, n);
            let b = rand_poly(&mut rng, n);
            let c = fft.ifft(&mul_fft(&fft.fft(&a), &fft.fft(&b)));
            let want = schoolbook(&a, &b);
            let mut maxerr = 0.0f64;
            for i in 0..n {
                maxerr = maxerr.max((c[i].to_f64() - want[i]).abs());
            }
            // Products of values up to ~128 over n terms; a few ulps scaled up.
            assert!(maxerr < 1e-3, "n={n} mul maxerr={maxerr}");
        }
    }
}

#[test]
fn split_merge_round_trip() {
    let mut rng = Sm64::new(0x7777_3333_BBBB_1111);
    for &n in &[4usize, 8, 16, 512, 1024] {
        let fft = Fft::new(n);
        let f = rand_poly(&mut rng, n);
        let fh = fft.fft(&f);
        let (f0, f1) = fft.split_fft(&fh);
        let merged = fft.merge_fft_pub(&f0, &f1);
        let mut maxerr = 0.0f64;
        for i in 0..n {
            let e = (fh[i].re.to_f64() - merged[i].re.to_f64()).abs();
            let g = (fh[i].im.to_f64() - merged[i].im.to_f64()).abs();
            maxerr = maxerr.max(e).max(g);
        }
        assert!(maxerr < 1e-6, "n={n} split/merge maxerr={maxerr}");
    }
}

#[test]
fn conj_is_involution() {
    let z = Cplx::new(Fpr::of_i64(3), Fpr::of_i64(-7));
    let zz = z.conj().conj();
    assert_eq!(zz.re.to_f64(), 3.0);
    assert_eq!(zz.im.to_f64(), -7.0);
}
