//! Ad-hoc profiling harness for identifying optimization choke points.
//!
//! Run with: `cargo run --release --example bench`
//! Not a correctness test; intentionally minimal (no external deps).

use std::hint::black_box;
use std::time::{Duration, Instant};

use purecrypto::bignum::BoxedUint;
use purecrypto::cipher::{Aes128, Aes256, BlockCipher, ChaCha20Poly1305, Gcm};
use purecrypto::ec::ecdsa::EcdsaPrivateKey;
use purecrypto::ec::ed25519::Ed25519PrivateKey;
use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::hash::{Blake3, Digest, Sha256, Sha512};
use purecrypto::mlkem::MlKem768DecapsKey;
use purecrypto::rng::OsRng;
use purecrypto::rsa::BoxedRsaPrivateKey;

/// Times `f` repeatedly until ~`target` elapsed; returns ops/sec.
fn ops_per_sec(target: Duration, mut f: impl FnMut()) -> f64 {
    // Warmup + calibrate.
    f();
    let mut iters: u64 = 1;
    loop {
        let start = Instant::now();
        for _ in 0..iters {
            f();
        }
        let el = start.elapsed();
        if el >= target {
            return iters as f64 / el.as_secs_f64();
        }
        // Scale up toward the target.
        let factor = (target.as_secs_f64() / el.as_secs_f64().max(1e-9)).clamp(2.0, 16.0);
        iters = ((iters as f64) * factor) as u64 + 1;
    }
}

fn bench_throughput(name: &str, bytes: usize, target: Duration, mut f: impl FnMut()) {
    let ops = ops_per_sec(target, &mut f);
    let mib = (ops * bytes as f64) / (1024.0 * 1024.0);
    println!("  {name:<28} {mib:>10.1} MiB/s   ({ops:>12.0} op/s, {bytes} B)");
}

fn bench_latency(name: &str, target: Duration, mut f: impl FnMut()) {
    let ops = ops_per_sec(target, &mut f);
    let us = 1_000_000.0 / ops;
    println!("  {name:<28} {ops:>12.0} op/s   ({us:>10.2} µs/op)");
}

fn main() {
    let t = Duration::from_millis(400);
    let mut rng = OsRng;

    println!("\n=== Symmetric (throughput) ===");
    {
        const N: usize = 64 * 1024;
        let mut buf = vec![0u8; N + 16];
        let nonce12 = [0u8; 12];

        let gcm128 = Gcm::new(Aes128::new(&[0u8; 16]));
        bench_throughput("AES-128-GCM enc", N, t, || {
            let _ = black_box(gcm128.encrypt(&nonce12, b"", black_box(&mut buf[..N])));
        });

        let gcm256 = Gcm::new(Aes256::new(&[0u8; 32]));
        bench_throughput("AES-256-GCM enc", N, t, || {
            let _ = black_box(gcm256.encrypt(&nonce12, b"", black_box(&mut buf[..N])));
        });

        let cc = ChaCha20Poly1305::new(&[0u8; 32]);
        bench_throughput("ChaCha20-Poly1305 enc", N, t, || {
            let _ = black_box(cc.encrypt(&nonce12, b"", black_box(&mut buf[..N])));
        });

        let aes = Aes256::new(&[0u8; 32]);
        let mut blk = [0u8; 16];
        bench_throughput("AES-256 raw block enc", 16, t, || {
            aes.encrypt_block(black_box(&mut blk));
        });
    }

    println!("\n=== Hashes (throughput) ===");
    {
        const N: usize = 64 * 1024;
        let data = vec![0u8; N];
        bench_throughput("SHA-256", N, t, || {
            black_box(Sha256::digest(black_box(&data)));
        });
        bench_throughput("SHA-512", N, t, || {
            black_box(Sha512::digest(black_box(&data)));
        });
        bench_throughput("BLAKE3", N, t, || {
            black_box(Blake3::digest(black_box(&data)));
        });
    }

    println!("\n=== Asymmetric (latency) ===");
    {
        let msg = b"benchmark message";

        // RSA-2048
        let e = BoxedUint::from_u64(65537);
        let rsa = BoxedRsaPrivateKey::generate(2048, e, &mut rng, 5);
        let rsa_pub = rsa.public_key();
        let rsa_sig = rsa.sign_pkcs1v15::<Sha256>(msg).unwrap();
        bench_latency("RSA-2048 sign (pkcs1)", t, || {
            black_box(rsa.sign_pkcs1v15::<Sha256>(black_box(msg)).unwrap());
        });
        bench_latency("RSA-2048 verify (pkcs1)", t, || {
            rsa_pub
                .verify_pkcs1v15::<Sha256>(black_box(msg), black_box(&rsa_sig))
                .unwrap();
        });

        // ECDSA P-256
        let ec = EcdsaPrivateKey::generate(&mut rng);
        let ec_pub = ec.public_key();
        let ec_sig = ec.sign::<Sha256>(msg).unwrap();
        bench_latency("ECDSA P-256 sign", t, || {
            black_box(ec.sign::<Sha256>(black_box(msg)).unwrap());
        });
        bench_latency("ECDSA P-256 verify", t, || {
            ec_pub
                .verify::<Sha256>(black_box(msg), black_box(&ec_sig))
                .unwrap();
        });

        // Ed25519
        let ed = Ed25519PrivateKey::generate(&mut rng);
        let ed_pub = ed.public_key();
        let ed_sig = ed.sign(msg);
        bench_latency("Ed25519 sign", t, || {
            black_box(ed.sign(black_box(msg)));
        });
        bench_latency("Ed25519 verify", t, || {
            black_box(ed_pub.verify(black_box(msg), black_box(&ed_sig)).is_ok());
        });

        // X25519
        let a = X25519PrivateKey::generate(&mut rng);
        let b = X25519PrivateKey::generate(&mut rng);
        let bp = b.public_key();
        bench_latency("X25519 DH", t, || {
            black_box(a.diffie_hellman(black_box(&bp)).unwrap());
        });

        // ML-KEM-768
        let (dk, ek) = MlKem768DecapsKey::generate(&mut rng);
        let (ct, _ss) = ek.encapsulate(&mut rng);
        bench_latency("ML-KEM-768 keygen", t, || {
            black_box(MlKem768DecapsKey::generate(&mut rng));
        });
        bench_latency("ML-KEM-768 encaps", t, || {
            black_box(ek.encapsulate(&mut rng));
        });
        bench_latency("ML-KEM-768 decaps", t, || {
            black_box(dk.decapsulate(black_box(&ct)));
        });
    }
    println!();
}
