//! Ad-hoc profiling harness for identifying optimization choke points.
//!
//! Run with: `cargo run --release --example bench`
//! Not a correctness test; intentionally minimal (no external deps).

use std::hint::black_box;
use std::time::{Duration, Instant};

use purecrypto::bignum::BoxedUint;
use purecrypto::cipher::{Aes128, Aes256, Aez, BlockCipher, ChaCha20Poly1305, Gcm, Poly1305};
use purecrypto::ec::ecdsa::EcdsaPrivateKey;
use purecrypto::ec::ed25519::Ed25519PrivateKey;
use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::hash::{Blake3, Digest, Sha3_256, Sha256, Sha512, shake128};
use purecrypto::mldsa::MlDsa65PrivateKey;
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

        // Decrypt: restore the same ciphertext each iteration so the tag check
        // passes (the memcpy is noise next to the AEAD work).
        let tag = gcm128.encrypt(&nonce12, b"", &mut buf[..N]);
        let ct = buf[..N].to_vec();
        bench_throughput("AES-128-GCM dec", N, t, || {
            buf[..N].copy_from_slice(&ct);
            gcm128
                .decrypt(&nonce12, b"", black_box(&mut buf[..N]), &tag)
                .expect("tag must verify");
        });

        let cc = ChaCha20Poly1305::new(&[0u8; 32]);
        bench_throughput("ChaCha20-Poly1305 enc", N, t, || {
            let _ = black_box(cc.encrypt(&nonce12, b"", black_box(&mut buf[..N])));
        });

        let poly_key = [7u8; 32];
        bench_throughput("Poly1305 MAC", N, t, || {
            let mut p = Poly1305::new(black_box(&poly_key));
            p.update(black_box(&buf[..N]));
            black_box(p.finish());
        });

        let aes = Aes256::new(&[0u8; 32]);
        let mut blk = [0u8; 16];
        bench_throughput("AES-256 raw block enc", 16, t, || {
            aes.encrypt_block(black_box(&mut blk));
        });

        // AEZ on the software AES round (baseline for a future HW-round speedup).
        let aez = Aez::new(&[0u8; 48]);
        let ad: [&[u8]; 0] = [];
        bench_throughput("AEZ enc (tau=16)", N, t, || {
            black_box(aez.encrypt(black_box(b"nonce0"), &ad, 16, black_box(&buf[..N])));
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
        bench_throughput("SHA3-256", N, t, || {
            black_box(Sha3_256::digest(black_box(&data)));
        });
        let mut xof_out = [0u8; 64];
        bench_throughput("SHAKE-128", N, t, || {
            shake128(black_box(&data), black_box(&mut xof_out));
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

        // ML-DSA-65. Fixed seed: deterministic signing's rejection-loop
        // count depends on the key, so a pinned key keeps runs comparable.
        let (mldsa_sk, mldsa_pk) = MlDsa65PrivateKey::from_seed(&[0x42u8; 32]);
        let mldsa_sig = mldsa_sk.sign_deterministic(msg, b"").unwrap();
        bench_latency("ML-DSA-65 keygen", t, || {
            black_box(MlDsa65PrivateKey::generate(&mut rng));
        });
        bench_latency("ML-DSA-65 sign (det)", t, || {
            black_box(mldsa_sk.sign_deterministic(black_box(msg), b"").unwrap());
        });
        bench_latency("ML-DSA-65 verify", t, || {
            black_box(mldsa_pk.verify(black_box(&mldsa_sig), black_box(msg), b""));
        });

        // SLH-DSA (hash-based; dominated by WOTS+/FORS hashing).
        {
            use purecrypto::slhdsa::{ParamSet, PrivateKey};
            let (sk, _pk) = PrivateKey::generate(ParamSet::Sha2_192s, &mut rng);
            bench_latency("SLH-DSA-SHA2-192s keygen", t, || {
                black_box(PrivateKey::generate(ParamSet::Sha2_192s, &mut rng));
            });
            bench_latency("SLH-DSA-SHA2-192s sign", t, || {
                black_box(sk.sign_deterministic(b"bench message", &[]).unwrap());
            });
            let (sk, _pk) = PrivateKey::generate(ParamSet::Shake_192s, &mut rng);
            bench_latency("SLH-DSA-SHAKE-192s keygen", t, || {
                black_box(PrivateKey::generate(ParamSet::Shake_192s, &mut rng));
            });
            bench_latency("SLH-DSA-SHAKE-192s sign", t, || {
                black_box(sk.sign_deterministic(b"bench message", &[]).unwrap());
            });
        }
    }
    println!();
}
