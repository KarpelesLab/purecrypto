//! End-to-end sign→verify round-trip. The verifier here is the existing,
//! KAT-validated `falcon::verify`, so a passing round-trip proves keygen, key
//! expansion, the LDL tree, fast-Fourier sampling, and signing all agree on a
//! genuine Falcon signature (norm bound + the `s₀ + s₁·h = c` relation).

use super::super::keygen::ntru_gen;
use super::super::sampler::SamplerRng;
use super::super::{Degree, encode::encode_pubkey, verify};
use super::{expand_key, sign_internal};

struct DetRng(u64);
impl DetRng {
    fn fill(&mut self, buf: &mut [u8]) {
        for b in buf.iter_mut() {
            self.0 = self
                .0
                .wrapping_mul(0x5851_F42D_4C95_7F2D)
                .wrapping_add(0x1405_7B7E_F767_814F);
            *b = (self.0 >> 56) as u8;
        }
    }
}
impl SamplerRng for DetRng {
    fn next_bytes(&mut self, buf: &mut [u8]) {
        self.fill(buf);
    }
}

fn round_trip(n: usize, degree: Degree, logn: u8, seed: u64) {
    let mut rng = DetRng(seed);
    let (f, g, cap_f, cap_g, h) = ntru_gen(n, &mut rng);
    let key = expand_key(&f, &g, &cap_f, &cap_g, degree);
    let pk = encode_pubkey(&h, logn);

    for m in 0..3u8 {
        let msg = [m, m ^ 0xAA, 0x5C, m.wrapping_add(7)];
        let mut salt = [0u8; 40];
        rng.fill(&mut salt);
        let sig = sign_internal(&key, &msg, &salt, &mut rng).expect("sampler must converge");
        assert_eq!(sig.len(), degree.sig_len(), "signature length");
        assert!(
            verify(&pk, &msg, &sig),
            "valid signature must verify (m={m})"
        );

        // A flipped message must not verify.
        let bad_msg = [m, m ^ 0xAA, 0x5D, m.wrapping_add(7)];
        assert!(!verify(&pk, &bad_msg, &sig), "tampered message must fail");

        // A flipped signature byte must not verify.
        let mut bad_sig = sig.clone();
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 0x01;
        assert!(!verify(&pk, &msg, &bad_sig), "tampered signature must fail");
    }
}

#[test]
fn sign_verify_round_trip_512() {
    round_trip(512, Degree::Falcon512, 9, 0xF00D_BEEF_2468_1357);
}

/// Pins the exact signature bytes for a deterministic key and sampler stream.
///
/// Falcon signing has no byte-exact external vectors here (the table-free FFT
/// roots differ from the C reference's by a few ulps), so this guards the
/// emulated-FP pipeline — FFT layout, LDL tree, ffSampling — against any
/// refactor that changes a single rounding.
#[test]
fn signatures_are_pinned_512() {
    let mut rng = DetRng(0x0DDB_A11C_AFE0_5EED);
    let (f, g, cap_f, cap_g, _h) = ntru_gen(512, &mut rng);
    let key = expand_key(&f, &g, &cap_f, &cap_g, Degree::Falcon512);
    let mut all = alloc::vec::Vec::new();
    for m in 0..4u8 {
        let mut salt = [0u8; 40];
        rng.fill(&mut salt);
        let sig = sign_internal(&key, &[m; 5], &salt, &mut rng).expect("converges");
        all.extend_from_slice(&sig);
    }
    let digest = crate::hash::sha256(&all);
    let want: [u8; 32] = crate::test_util::from_hex(
        "ec2181bdf3f1cfcb52c5622267def45f58c7a1cacd599bc966c08daf580eb4cc",
    );
    assert_eq!(digest, want);
}
