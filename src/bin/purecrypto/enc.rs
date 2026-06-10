//! `purecrypto enc` — AEAD encryption / decryption and AES-KW/KWP key wrapping.
//!
//! Key/AAD material can be supplied either as hex on argv (`-key HEX`,
//! `-aad HEX`) or as the raw contents of a file (`-keyfile FILE`,
//! `-aadfile FILE`). The argv forms still work for backwards compatibility
//! but emit a warning to stderr, since they leak to `/proc/<pid>/cmdline`.

use crate::util::{
    Args, die, parse_hex_flag, read_input, read_secret_file, write_output, write_output_with_mode,
    zero_buf,
};
use purecrypto::ascon::AsconAead128;
use purecrypto::cipher::{
    Aegis128L, Aegis256, Aes128, Aes128Ccm, Aes128Ccm8, Aes128Gcm, Aes128Kw, Aes128Kwp, Aes256,
    Aes256Ccm, Aes256Ccm8, Aes256Gcm, Aes256Kw, Aes256Kwp, AesGcmSiv, AesSiv, ChaCha20Poly1305,
    XChaCha20Poly1305,
};

#[derive(Clone, Copy)]
enum Algo {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20P1305,
    Aes128Ccm,
    Aes256Ccm,
    Aes128Ccm8,
    Aes256Ccm8,
    Aes128GcmSiv,
    Aes256GcmSiv,
    XChaCha20P1305,
    Aes128Siv,
    Aes256Siv,
    Aegis128L,
    Aegis256,
    AsconAead128,
    Aes128Kw,
    Aes256Kw,
    Aes128Kwp,
    Aes256Kwp,
}

fn parse_alg(name: &str) -> Option<Algo> {
    let up = name.to_ascii_uppercase();
    let n = up.replace('_', "-");
    Some(match n.as_str() {
        "AES-128-GCM" => Algo::Aes128Gcm,
        "AES-256-GCM" => Algo::Aes256Gcm,
        "CHACHA20-POLY1305" => Algo::ChaCha20P1305,
        "AES-128-CCM" => Algo::Aes128Ccm,
        "AES-256-CCM" => Algo::Aes256Ccm,
        "AES-128-CCM8" => Algo::Aes128Ccm8,
        "AES-256-CCM8" => Algo::Aes256Ccm8,
        "AES-128-GCM-SIV" => Algo::Aes128GcmSiv,
        "AES-256-GCM-SIV" => Algo::Aes256GcmSiv,
        "XCHACHA20-POLY1305" => Algo::XChaCha20P1305,
        "AES-128-SIV" => Algo::Aes128Siv,
        "AES-256-SIV" => Algo::Aes256Siv,
        "AEGIS-128L" => Algo::Aegis128L,
        "AEGIS-256" => Algo::Aegis256,
        "ASCON-AEAD128" => Algo::AsconAead128,
        "AES-128-KW" | "AES-KW-128" => Algo::Aes128Kw,
        "AES-256-KW" | "AES-KW-256" => Algo::Aes256Kw,
        "AES-128-KWP" | "AES-KWP-128" => Algo::Aes128Kwp,
        "AES-256-KWP" | "AES-KWP-256" => Algo::Aes256Kwp,
        _ => return None,
    })
}

fn key_size(alg: Algo) -> usize {
    match alg {
        Algo::Aes128Gcm
        | Algo::Aes128Ccm
        | Algo::Aes128Ccm8
        | Algo::Aes128GcmSiv
        | Algo::Aegis128L
        | Algo::AsconAead128
        | Algo::Aes128Kw
        | Algo::Aes128Kwp => 16,
        Algo::ChaCha20P1305
        | Algo::XChaCha20P1305
        | Algo::Aes256Gcm
        | Algo::Aes256Ccm
        | Algo::Aes256Ccm8
        | Algo::Aes256GcmSiv
        | Algo::Aes128Siv
        | Algo::Aegis256
        | Algo::Aes256Kw
        | Algo::Aes256Kwp => 32,
        // AES-SIV uses a double-length key: 64 bytes selects AES-256-SIV.
        Algo::Aes256Siv => 64,
    }
}

fn aead_encrypt(alg: Algo, key: &[u8], nonce: &[u8], aad: &[u8], buf: &mut Vec<u8>) {
    let tag = match alg {
        Algo::Aes128Gcm => {
            let k: [u8; 16] = key.try_into().expect("aes-128 key length");
            Aes128Gcm::new(Aes128::new(&k)).encrypt(nonce, aad, buf.as_mut_slice())
        }
        Algo::Aes256Gcm => {
            let k: [u8; 32] = key.try_into().expect("aes-256 key length");
            Aes256Gcm::new(Aes256::new(&k)).encrypt(nonce, aad, buf.as_mut_slice())
        }
        Algo::ChaCha20P1305 => {
            let k: [u8; 32] = key.try_into().expect("chacha20-poly1305 key length");
            let n: [u8; 12] = nonce
                .try_into()
                .unwrap_or_else(|_| die("nonce must be 12 bytes"));
            ChaCha20Poly1305::new(&k).encrypt(&n, aad, buf.as_mut_slice())
        }
        Algo::Aes128Ccm => {
            let k: [u8; 16] = key.try_into().expect("aes-128 key length");
            Aes128Ccm::new(Aes128::new(&k)).encrypt(nonce, aad, buf.as_mut_slice())
        }
        Algo::Aes256Ccm => {
            let k: [u8; 32] = key.try_into().expect("aes-256 key length");
            Aes256Ccm::new(Aes256::new(&k)).encrypt(nonce, aad, buf.as_mut_slice())
        }
        Algo::Aes128Ccm8 => {
            let k: [u8; 16] = key.try_into().expect("aes-128 key length");
            let t = Aes128Ccm8::new(Aes128::new(&k)).encrypt(nonce, aad, buf.as_mut_slice());
            // CCM8 has an 8-byte tag; pad to 16 to keep the output framing uniform.
            let mut padded = [0u8; 16];
            padded[..8].copy_from_slice(&t);
            buf.extend_from_slice(&padded[..8]);
            return;
        }
        Algo::Aes256Ccm8 => {
            let k: [u8; 32] = key.try_into().expect("aes-256 key length");
            let t = Aes256Ccm8::new(Aes256::new(&k)).encrypt(nonce, aad, buf.as_mut_slice());
            buf.extend_from_slice(&t);
            return;
        }
        Algo::Aes128GcmSiv | Algo::Aes256GcmSiv => {
            let n: [u8; 12] = nonce
                .try_into()
                .unwrap_or_else(|_| die("nonce must be 12 bytes for AES-GCM-SIV"));
            AesGcmSiv::new(key).encrypt(&n, aad, buf.as_mut_slice())
        }
        Algo::XChaCha20P1305 => {
            let k: [u8; 32] = key.try_into().expect("xchacha20-poly1305 key length");
            let n: [u8; 24] = nonce
                .try_into()
                .unwrap_or_else(|_| die("nonce must be 24 bytes for XChaCha20-Poly1305"));
            XChaCha20Poly1305::new(&k).encrypt(&n, aad, buf.as_mut_slice())
        }
        Algo::Aes128Siv | Algo::Aes256Siv => {
            // AES-SIV is deterministic: the nonce is supplied as the single
            // associated-data header and the output is `V ‖ ciphertext`.
            let out = AesSiv::new(key).seal(&[nonce], buf.as_slice());
            *buf = out;
            return;
        }
        Algo::Aegis128L => {
            let k: [u8; 16] = key.try_into().expect("aegis-128l key length");
            let n: [u8; 16] = nonce
                .try_into()
                .unwrap_or_else(|_| die("nonce must be 16 bytes for AEGIS-128L"));
            Aegis128L::new(&k).encrypt(&n, aad, buf.as_mut_slice())
        }
        Algo::Aegis256 => {
            let k: [u8; 32] = key.try_into().expect("aegis-256 key length");
            let n: [u8; 32] = nonce
                .try_into()
                .unwrap_or_else(|_| die("nonce must be 32 bytes for AEGIS-256"));
            Aegis256::new(&k).encrypt(&n, aad, buf.as_mut_slice())
        }
        Algo::AsconAead128 => {
            let k: [u8; 16] = key.try_into().expect("ascon-aead128 key length");
            let n: [u8; 16] = nonce
                .try_into()
                .unwrap_or_else(|_| die("nonce must be 16 bytes for ASCON-AEAD128"));
            AsconAead128::new(&k).encrypt(&n, aad, buf.as_mut_slice())
        }
        _ => unreachable!("aead_encrypt only called for AEAD algs"),
    };
    buf.extend_from_slice(&tag);
}

fn aead_decrypt(alg: Algo, key: &[u8], nonce: &[u8], aad: &[u8], ct_and_tag: &[u8]) -> Vec<u8> {
    // AES-SIV's output is `V ‖ ciphertext` (V prepended), with the nonce passed
    // as the single associated-data header; handle it before the append-tag path.
    if let Algo::Aes128Siv | Algo::Aes256Siv = alg {
        return AesSiv::new(key)
            .open(&[nonce], ct_and_tag)
            .unwrap_or_else(|_| die("authentication tag verification failed"));
    }
    let tag_len = match alg {
        Algo::Aes128Ccm8 | Algo::Aes256Ccm8 => 8,
        _ => 16,
    };
    if ct_and_tag.len() < tag_len {
        die("ciphertext shorter than the authentication tag");
    }
    let (ct, tag) = ct_and_tag.split_at(ct_and_tag.len() - tag_len);
    let mut buf = ct.to_vec();
    let ok = match alg {
        Algo::Aes128Gcm => {
            let k: [u8; 16] = key.try_into().expect("aes-128 key length");
            let t: [u8; 16] = tag.try_into().unwrap();
            Aes128Gcm::new(Aes128::new(&k))
                .decrypt(nonce, aad, &mut buf, &t)
                .is_ok()
        }
        Algo::Aes256Gcm => {
            let k: [u8; 32] = key.try_into().expect("aes-256 key length");
            let t: [u8; 16] = tag.try_into().unwrap();
            Aes256Gcm::new(Aes256::new(&k))
                .decrypt(nonce, aad, &mut buf, &t)
                .is_ok()
        }
        Algo::ChaCha20P1305 => {
            let k: [u8; 32] = key.try_into().expect("chacha20 key length");
            let n: [u8; 12] = nonce
                .try_into()
                .unwrap_or_else(|_| die("nonce must be 12 bytes"));
            let t: [u8; 16] = tag.try_into().unwrap();
            ChaCha20Poly1305::new(&k)
                .decrypt(&n, aad, &mut buf, &t)
                .is_ok()
        }
        Algo::Aes128Ccm => {
            let k: [u8; 16] = key.try_into().expect("aes-128 key length");
            let t: [u8; 16] = tag.try_into().unwrap();
            Aes128Ccm::new(Aes128::new(&k))
                .decrypt(nonce, aad, &mut buf, &t)
                .is_ok()
        }
        Algo::Aes256Ccm => {
            let k: [u8; 32] = key.try_into().expect("aes-256 key length");
            let t: [u8; 16] = tag.try_into().unwrap();
            Aes256Ccm::new(Aes256::new(&k))
                .decrypt(nonce, aad, &mut buf, &t)
                .is_ok()
        }
        Algo::Aes128Ccm8 => {
            let k: [u8; 16] = key.try_into().expect("aes-128 key length");
            let t: [u8; 8] = tag.try_into().unwrap();
            Aes128Ccm8::new(Aes128::new(&k))
                .decrypt(nonce, aad, &mut buf, &t)
                .is_ok()
        }
        Algo::Aes256Ccm8 => {
            let k: [u8; 32] = key.try_into().expect("aes-256 key length");
            let t: [u8; 8] = tag.try_into().unwrap();
            Aes256Ccm8::new(Aes256::new(&k))
                .decrypt(nonce, aad, &mut buf, &t)
                .is_ok()
        }
        Algo::Aes128GcmSiv | Algo::Aes256GcmSiv => {
            let n: [u8; 12] = nonce
                .try_into()
                .unwrap_or_else(|_| die("nonce must be 12 bytes for AES-GCM-SIV"));
            let t: [u8; 16] = tag.try_into().unwrap();
            AesGcmSiv::new(key).decrypt(&n, aad, &mut buf, &t).is_ok()
        }
        Algo::XChaCha20P1305 => {
            let k: [u8; 32] = key.try_into().expect("xchacha20 key length");
            let n: [u8; 24] = nonce
                .try_into()
                .unwrap_or_else(|_| die("nonce must be 24 bytes for XChaCha20-Poly1305"));
            let t: [u8; 16] = tag.try_into().unwrap();
            XChaCha20Poly1305::new(&k)
                .decrypt(&n, aad, &mut buf, &t)
                .is_ok()
        }
        Algo::Aegis128L => {
            let k: [u8; 16] = key.try_into().expect("aegis-128l key length");
            let n: [u8; 16] = nonce
                .try_into()
                .unwrap_or_else(|_| die("nonce must be 16 bytes for AEGIS-128L"));
            let t: [u8; 16] = tag.try_into().unwrap();
            Aegis128L::new(&k).decrypt(&n, aad, &mut buf, &t).is_ok()
        }
        Algo::Aegis256 => {
            let k: [u8; 32] = key.try_into().expect("aegis-256 key length");
            let n: [u8; 32] = nonce
                .try_into()
                .unwrap_or_else(|_| die("nonce must be 32 bytes for AEGIS-256"));
            let t: [u8; 16] = tag.try_into().unwrap();
            Aegis256::new(&k).decrypt(&n, aad, &mut buf, &t).is_ok()
        }
        Algo::AsconAead128 => {
            let k: [u8; 16] = key.try_into().expect("ascon-aead128 key length");
            let n: [u8; 16] = nonce
                .try_into()
                .unwrap_or_else(|_| die("nonce must be 16 bytes for ASCON-AEAD128"));
            let t: [u8; 16] = tag.try_into().unwrap();
            AsconAead128::new(&k).decrypt(&n, aad, &mut buf, &t).is_ok()
        }
        _ => unreachable!("aead_decrypt only called for AEAD algs"),
    };
    if !ok {
        die("authentication tag verification failed");
    }
    buf
}

fn kw_wrap(alg: Algo, kek: &[u8], plaintext: &[u8]) -> Vec<u8> {
    match alg {
        Algo::Aes128Kw => {
            let k: [u8; 16] = kek.try_into().expect("aes-128 kek length");
            let mut out = vec![0u8; plaintext.len() + 8];
            Aes128Kw::new(Aes128::new(&k))
                .wrap(plaintext, &mut out)
                .unwrap_or_else(|e| die(format!("AES-KW wrap failed: {e}")));
            out
        }
        Algo::Aes256Kw => {
            let k: [u8; 32] = kek.try_into().expect("aes-256 kek length");
            let mut out = vec![0u8; plaintext.len() + 8];
            Aes256Kw::new(Aes256::new(&k))
                .wrap(plaintext, &mut out)
                .unwrap_or_else(|e| die(format!("AES-KW wrap failed: {e}")));
            out
        }
        Algo::Aes128Kwp => {
            let k: [u8; 16] = kek.try_into().expect("aes-128 kek length");
            let padded = plaintext.len().div_ceil(8) * 8;
            let mut out = vec![0u8; padded + 8];
            Aes128Kwp::new(Aes128::new(&k))
                .wrap(plaintext, &mut out)
                .unwrap_or_else(|e| die(format!("AES-KWP wrap failed: {e}")));
            out
        }
        Algo::Aes256Kwp => {
            let k: [u8; 32] = kek.try_into().expect("aes-256 kek length");
            let padded = plaintext.len().div_ceil(8) * 8;
            let mut out = vec![0u8; padded + 8];
            Aes256Kwp::new(Aes256::new(&k))
                .wrap(plaintext, &mut out)
                .unwrap_or_else(|e| die(format!("AES-KWP wrap failed: {e}")));
            out
        }
        _ => unreachable!("kw_wrap only for KW/KWP algs"),
    }
}

fn kw_unwrap(alg: Algo, kek: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    match alg {
        Algo::Aes128Kw => {
            if ciphertext.len() < 24 {
                die("AES-KW ciphertext too short");
            }
            let k: [u8; 16] = kek.try_into().expect("aes-128 kek length");
            let mut out = vec![0u8; ciphertext.len() - 8];
            Aes128Kw::new(Aes128::new(&k))
                .unwrap(ciphertext, &mut out)
                .unwrap_or_else(|e| die(format!("AES-KW unwrap failed: {e}")));
            out
        }
        Algo::Aes256Kw => {
            if ciphertext.len() < 24 {
                die("AES-KW ciphertext too short");
            }
            let k: [u8; 32] = kek.try_into().expect("aes-256 kek length");
            let mut out = vec![0u8; ciphertext.len() - 8];
            Aes256Kw::new(Aes256::new(&k))
                .unwrap(ciphertext, &mut out)
                .unwrap_or_else(|e| die(format!("AES-KW unwrap failed: {e}")));
            out
        }
        Algo::Aes128Kwp => {
            if ciphertext.len() < 16 {
                die("AES-KWP ciphertext too short");
            }
            let k: [u8; 16] = kek.try_into().expect("aes-128 kek length");
            let mut out = vec![0u8; ciphertext.len() - 8];
            let n = Aes128Kwp::new(Aes128::new(&k))
                .unwrap(ciphertext, &mut out)
                .unwrap_or_else(|e| die(format!("AES-KWP unwrap failed: {e}")));
            out.truncate(n);
            out
        }
        Algo::Aes256Kwp => {
            if ciphertext.len() < 16 {
                die("AES-KWP ciphertext too short");
            }
            let k: [u8; 32] = kek.try_into().expect("aes-256 kek length");
            let mut out = vec![0u8; ciphertext.len() - 8];
            let n = Aes256Kwp::new(Aes256::new(&k))
                .unwrap(ciphertext, &mut out)
                .unwrap_or_else(|e| die(format!("AES-KWP unwrap failed: {e}")));
            out.truncate(n);
            out
        }
        _ => unreachable!("kw_unwrap only for KW/KWP algs"),
    }
}

pub(crate) fn run(args: Args) {
    let alg_name = args
        .value("-alg")
        .or_else(|| args.value("--alg"))
        .unwrap_or_else(|| die("missing -alg (e.g. AES-256-GCM, CHACHA20-POLY1305, AES-256-KW)"));
    let alg = parse_alg(alg_name).unwrap_or_else(|| die(format!("unknown -alg: {alg_name}")));

    // Key: prefer `-keyfile FILE` (raw bytes), fall back to `-key HEX` with a
    // deprecation warning since argv is world-readable via /proc/<pid>/cmdline.
    let mut key = if let Some(hex) = args.value("-key").or_else(|| args.value("--key")) {
        eprintln!(
            "purecrypto: warning: -key HEX exposes the key via /proc/<pid>/cmdline; \
             prefer -keyfile FILE (raw bytes)"
        );
        parse_hex_flag(hex, "-key")
    } else if let Some(path) = args.value("-keyfile").or_else(|| args.value("--keyfile")) {
        read_secret_file(path)
    } else {
        die("missing -key HEX or -keyfile FILE (raw bytes)");
    };
    if key.len() != key_size(alg) {
        zero_buf(&mut key);
        die(format!(
            "wrong key length for {alg_name}: expected {} bytes, got {}",
            key_size(alg),
            key.len()
        ));
    }

    let in_path = args.value("-in").or_else(|| args.value("--in"));
    let input = read_input(in_path);
    let dest = args.value("-out").or_else(|| args.value("--out"));
    let decrypt = args.flag("-d") || args.flag("--decrypt");
    // AAD: same convention as the key — `-aadfile FILE` is preferred over the
    // argv `-aad HEX` form.
    let aad = if let Some(hex) = args.value("-aad").or_else(|| args.value("--aad")) {
        eprintln!(
            "purecrypto: warning: -aad HEX exposes the AAD via /proc/<pid>/cmdline; \
             prefer -aadfile FILE (raw bytes)"
        );
        parse_hex_flag(hex, "-aad")
    } else if let Some(path) = args.value("-aadfile").or_else(|| args.value("--aadfile")) {
        read_secret_file(path)
    } else {
        Vec::new()
    };

    let result = match alg {
        Algo::Aes128Kw | Algo::Aes256Kw | Algo::Aes128Kwp | Algo::Aes256Kwp => {
            if decrypt {
                // An AES-KW/KWP unwrap recovers KEY MATERIAL: write it like
                // the kem/kex secrets (0600, create_new, refuse a TTY) rather
                // than a world-readable 0644 file.
                let unwrapped = kw_unwrap(alg, &key, &input);
                zero_buf(&mut key);
                write_output_with_mode(dest, &unwrapped, /* private = */ true);
                return;
            }
            kw_wrap(alg, &key, &input)
        }
        _ => {
            let nonce = args
                .value("-nonce")
                .or_else(|| args.value("--iv"))
                .map(|h| parse_hex_flag(h, "-nonce"))
                .unwrap_or_else(|| {
                    zero_buf(&mut key);
                    die("missing -nonce HEX (12 bytes for GCM/ChaCha20-Poly1305)")
                });
            if decrypt {
                aead_decrypt(alg, &key, &nonce, &aad, &input)
            } else {
                let mut buf = input;
                aead_encrypt(alg, &key, &nonce, &aad, &mut buf);
                buf
            }
        }
    };

    zero_buf(&mut key);
    write_output(dest, &result);
}
