//! AES mode throughput probe:
//! `cargo run --release --example aes_modes --features std,cipher -- [secs] [filter]`.
//! Prints decimal GB/s (the unit `openssl speed` uses) for each mode at
//! 16 KiB and 1 MiB.

use std::hint::black_box;
use std::time::Instant;

use purecrypto::cipher::{Aes128, Aes256, BlockCipher, Cbc, Ctr, Gcm};

fn gbps(secs: f64, bytes: usize, mut f: impl FnMut()) -> f64 {
    f();
    let mut iters = 1u64;
    loop {
        let t = Instant::now();
        for _ in 0..iters {
            f();
        }
        let el = t.elapsed().as_secs_f64();
        if el >= secs {
            return iters as f64 * bytes as f64 / el / 1e9;
        }
        iters = (iters as f64 * (secs / el.max(1e-6)).clamp(1.5, 16.0)) as u64 + 1;
    }
}

fn main() {
    let secs: f64 = std::env::args().nth(1).map_or(1.0, |s| s.parse().unwrap());
    let filter = std::env::args().nth(2).unwrap_or_default();
    for &n in &[16 * 1024usize, 1 << 20] {
        let mut buf = vec![0u8; n];
        let nonce = [7u8; 12];
        let g128 = Gcm::new(Aes128::new(&[1u8; 16]));
        let g256 = Gcm::new(Aes256::new(&[1u8; 32]));
        let a128 = Aes128::new(&[1u8; 16]);
        let a256 = Aes256::new(&[1u8; 32]);
        let mut run = |name: &str, f: &mut dyn FnMut(&mut [u8])| {
            if !name.contains(filter.as_str()) {
                return;
            }
            let r = gbps(secs, n, || f(black_box(&mut buf)));
            println!("{name:<20} {n:>8} B  {r:>7.2} GB/s");
        };
        run("aes128-gcm-enc", &mut |b| {
            black_box(g128.encrypt(&nonce, b"", b));
        });
        // CTR is an involution, so with C = E(0) the zero buffer is itself the
        // ciphertext of C: alternating the two tags keeps every decrypt valid.
        let mut c = vec![0u8; n];
        let tag_c = g128.encrypt(&nonce, b"", &mut c);
        let tag_z = g128.encrypt(&nonce, b"", &mut c.clone());
        let mut flip = false;
        let mut first = true;
        run("aes128-gcm-dec", &mut |b| {
            if first {
                b.copy_from_slice(&c);
                first = false;
            }
            let t = if flip { &tag_z } else { &tag_c };
            flip = !flip;
            g128.decrypt(&nonce, b"", b, t).expect("valid tag");
        });
        run("aes256-gcm-enc", &mut |b| {
            black_box(g256.encrypt(&nonce, b"", b));
        });
        run("aes128-ctr", &mut |b| {
            Ctr::new(a128.clone(), &[0u8; 16]).apply_keystream(b);
        });
        run("aes256-ctr", &mut |b| {
            Ctr::new(a256.clone(), &[0u8; 16]).apply_keystream(b);
        });
        run("aes128-cbc-enc", &mut |b| {
            Cbc::new(a128.clone(), &[0u8; 16]).encrypt(b).unwrap();
        });
        run("aes128-cbc-dec", &mut |b| {
            Cbc::new(a128.clone(), &[0u8; 16]).decrypt(b).unwrap();
        });
        run("aes256-cbc-enc", &mut |b| {
            Cbc::new(a256.clone(), &[0u8; 16]).encrypt(b).unwrap();
        });
        run("aes128-ecb-enc", &mut |b| {
            a128.encrypt_blocks(b);
        });
    }
}
