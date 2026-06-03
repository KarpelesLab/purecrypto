//! `purecrypto pkeyutl` — generic asymmetric encrypt/decrypt/sign/verify.

use crate::util::{Args, die, read_input, write_output};
use purecrypto::ec::sm2::DEFAULT_ID;
use purecrypto::ec::{
    BoxedEcdsaPrivateKey, BoxedEcdsaSignature, CurveId, Ed448PrivateKey, Ed25519PrivateKey,
    Sm2PrivateKey, Sm2PublicKey, Sm2Signature,
};
use purecrypto::hash::{Sha1, Sha256, Sha384, Sha512};
use purecrypto::lms::{HssPrivateKey, LmsPrivateKey};
use purecrypto::mldsa::{MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey};
use purecrypto::rng::OsRng;
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::slhdsa;
use purecrypto::x509::AnyPublicKey;
use purecrypto::xmss::{XmssMtPrivateKey, XmssPrivateKey};

const USAGE: &str = "\
purecrypto pkeyutl <subcommand>

  encrypt -inkey FILE [-pubin] -pkeyopt OPT [-in FILE] [-out FILE]
  decrypt -inkey FILE          -pkeyopt OPT [-in FILE] [-out FILE]
  sign    -inkey FILE          [-pkeyopt OPT] -in FILE -out FILE
  verify  -inkey FILE [-pubin] [-pkeyopt OPT] -sigfile FILE -in FILE

-pkeyopt options:
  rsa_padding_mode:oaep        OAEP encrypt/decrypt
  rsa_padding_mode:pkcs1       PKCS#1 v1.5 encrypt/decrypt / signature
  rsa_padding_mode:pss         RSA-PSS signature
  rsa_oaep_md:sha256|sha384|sha512   OAEP hash (default sha256)
  rsa_oaep_label:HEX           OAEP label (default empty)
  digest:sha256|sha384|sha512|sha1   hash for sign/verify (default sha256)

SM2 (GB/T 32918 / RFC 8998): an SM2 key auto-routes to SM2-DSA (sign/verify,
DER Ecdsa-Sig-Value) and SM2-PKE (encrypt/decrypt). Use -id STR to override the
default signer identity (1234567812345678).";

/// Returns all `-pkeyopt key:value` entries.
fn pkeyopts(args: &Args) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // Args treats every occurrence of `-pkeyopt`'s value: walk argv ourselves.
    let mut iter = args.tokens_iter();
    while let Some(t) = iter.next() {
        if (t == "-pkeyopt" || t == "--pkeyopt")
            && let Some(v) = iter.next()
        {
            let (k, val) = v.split_once(':').unwrap_or((v.as_str(), ""));
            out.push((k.to_string(), val.to_string()));
        }
    }
    out
}

#[derive(Default)]
struct Opts {
    padding: Option<String>,
    oaep_md: Option<String>,
    oaep_label: Vec<u8>,
    digest: Option<String>,
}

fn parse_opts(args: &Args) -> Opts {
    let mut opts = Opts::default();
    for (k, v) in pkeyopts(args) {
        match k.as_str() {
            "rsa_padding_mode" => opts.padding = Some(v),
            "rsa_oaep_md" => opts.oaep_md = Some(v),
            "rsa_oaep_label" => {
                opts.oaep_label =
                    crate::util::from_hex(&v).unwrap_or_else(|| die("rsa_oaep_label must be hex"));
            }
            "digest" => opts.digest = Some(v),
            other => die(format!("unknown -pkeyopt key: {other}")),
        }
    }
    opts
}

// The RSA-2048 / -3072 / -4096 variant dominates the enum size, but the value
// is short-lived inside `pkeyutl` — boxing every arm would be ceremony for no
// real benefit. (See the matching pattern in `pkey.rs`.)
#[allow(clippy::large_enum_variant)]
enum PrivKey {
    Rsa(BoxedRsaPrivateKey),
    Ec(BoxedEcdsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
    Ed448(Ed448PrivateKey),
    MlDsa44(MlDsa44PrivateKey),
    MlDsa65(MlDsa65PrivateKey),
    MlDsa87(MlDsa87PrivateKey),
    SlhDsa(slhdsa::PrivateKey),
    Sm2(Sm2PrivateKey),
}

fn load_priv(path: &str) -> PrivKey {
    crate::util::warn_if_world_readable_key(path);
    let raw = std::fs::read(path).unwrap_or_else(|e| die(format!("cannot read {path}: {e}")));
    let pem = core::str::from_utf8(&raw).unwrap_or_else(|_| die("key file is not UTF-8 PEM"));
    if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(pem) {
        return PrivKey::Rsa(k);
    }
    // SM2 keys share the SEC1 `EC PRIVATE KEY` PEM label with ECDSA keys, and the
    // generic ECDSA parser would accept the SM2 named-curve OID — so try the SM2
    // parser FIRST (it rejects every non-SM2 curve) to route SM2 to SM2-DSA /
    // SM2-PKE rather than the ECDSA path.
    if let Ok(k) = Sm2PrivateKey::from_sec1_pem(pem) {
        return PrivKey::Sm2(k);
    }
    if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(pem) {
        return PrivKey::Ec(k);
    }
    if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem(pem) {
        return PrivKey::Ed25519(k);
    }
    if let Ok(k) = Ed448PrivateKey::from_pkcs8_pem(pem) {
        return PrivKey::Ed448(k);
    }
    if let Ok(k) = MlDsa65PrivateKey::from_pkcs8_pem(pem) {
        return PrivKey::MlDsa65(k);
    }
    if let Ok(k) = MlDsa44PrivateKey::from_pkcs8_pem(pem) {
        return PrivKey::MlDsa44(k);
    }
    if let Ok(k) = MlDsa87PrivateKey::from_pkcs8_pem(pem) {
        return PrivKey::MlDsa87(k);
    }
    if let Ok(k) = slhdsa::PrivateKey::from_pkcs8_pem(pem) {
        return PrivKey::SlhDsa(k);
    }
    die("unrecognized private key (expected RSA PKCS#1, EC SEC1, or PKCS#8 PEM)");
}

// ---------------------------------------------------------------------------
// Stateful hash-based signatures (LMS / HSS / XMSS / XMSS^MT)
//
// These keys carry a one-time-key index that advances on every signature. The
// CLI stores the raw `to_bytes()` serialization (NOT PEM). On `sign` we:
//   1. load the private key from the FILE (stdin is rejected — we must write
//      the advanced state back to a real path),
//   2. produce the signature (which advances the in-memory index),
//   3. ATOMICALLY rewrite the key file (temp + rename) with the advanced
//      `to_bytes()` BEFORE emitting the signature, and
//   4. warn loudly on stderr that the key has advanced and the old copy must
//      never be reused.
// `verify` derives the public key from the same raw key file (deriving the
// public key does NOT advance state) and checks the signature.
// ---------------------------------------------------------------------------

/// A loaded stateful signing key, tagged by scheme.
enum StatefulKey {
    Lms(LmsPrivateKey),
    Hss(HssPrivateKey),
    Xmss(XmssPrivateKey),
    XmssMt(XmssMtPrivateKey),
}

/// Attempts to parse `raw` as one of the stateful private-key serializations.
/// The four `from_bytes` parsers are mutually exclusive (distinct magic /
/// length / typecode framing), so order is immaterial.
fn parse_stateful(raw: &[u8]) -> Option<StatefulKey> {
    if let Ok(k) = LmsPrivateKey::from_bytes(raw) {
        return Some(StatefulKey::Lms(k));
    }
    if let Ok(k) = HssPrivateKey::from_bytes(raw) {
        return Some(StatefulKey::Hss(k));
    }
    if let Ok(k) = XmssPrivateKey::from_bytes(raw) {
        return Some(StatefulKey::Xmss(k));
    }
    if let Ok(k) = XmssMtPrivateKey::from_bytes(raw) {
        return Some(StatefulKey::XmssMt(k));
    }
    None
}

/// Atomically replaces `path`'s contents with `data` (write a sibling temp
/// file, fsync, then rename over the original). On Unix the temp file is
/// created mode 0o600. Dies on any I/O failure — we must NOT emit a signature
/// if persisting the advanced key failed.
fn atomic_overwrite(path: &str, data: &[u8]) {
    use std::io::Write;
    let tmp = format!("{path}.tmp.{}", std::process::id());
    {
        use std::fs::OpenOptions;
        #[cfg(unix)]
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = OpenOptions::new();
        opts.create(true).truncate(true).write(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut f = opts
            .open(&tmp)
            .unwrap_or_else(|e| die(format!("cannot create temp key file {tmp}: {e}")));
        f.write_all(data)
            .unwrap_or_else(|e| die(format!("cannot write temp key file {tmp}: {e}")));
        f.sync_all()
            .unwrap_or_else(|e| die(format!("cannot fsync temp key file {tmp}: {e}")));
    }
    std::fs::rename(&tmp, path).unwrap_or_else(|e| {
        let _ = std::fs::remove_file(&tmp);
        die(format!("cannot atomically replace key file {path}: {e}"))
    });
}

/// Stateful `sign`: load, sign (advancing the index), persist the advanced key
/// back to `key_path` atomically, warn, then return the signature.
fn stateful_sign(key_path: &str, msg: &[u8]) -> Vec<u8> {
    crate::util::warn_if_world_readable_key(key_path);
    let raw =
        std::fs::read(key_path).unwrap_or_else(|e| die(format!("cannot read {key_path}: {e}")));
    let key = parse_stateful(&raw)
        .unwrap_or_else(|| die("not a recognized LMS/HSS/XMSS/XMSS^MT private key"));

    // Sign, then capture the ADVANCED serialization to persist before we hand
    // the signature back to the caller.
    let (sig, advanced) = match key {
        StatefulKey::Lms(mut k) => {
            let s = k
                .sign(&mut OsRng, msg)
                .unwrap_or_else(|e| die(format!("LMS sign failed: {e:?}")));
            (s, k.to_bytes())
        }
        StatefulKey::Hss(mut k) => {
            let s = k
                .sign(&mut OsRng, msg)
                .unwrap_or_else(|e| die(format!("HSS sign failed: {e:?}")));
            (s, k.to_bytes())
        }
        StatefulKey::Xmss(mut k) => {
            let s = k
                .sign(msg)
                .unwrap_or_else(|e| die(format!("XMSS sign failed: {e:?}")));
            (s, k.to_bytes())
        }
        StatefulKey::XmssMt(mut k) => {
            let s = k
                .sign(msg)
                .unwrap_or_else(|e| die(format!("XMSS^MT sign failed: {e:?}")));
            (s, k.to_bytes())
        }
    };

    // Persist the advanced state BEFORE the signature is emitted. If this fails,
    // `atomic_overwrite` exits non-zero and the signature is never written.
    atomic_overwrite(key_path, &advanced);
    eprintln!(
        "purecrypto: warning: stateful key {key_path} has ADVANCED to its next \
         one-time index and been rewritten in place. The previous key state is \
         GONE — never restore or reuse an older copy of this file, or signatures \
         will reuse a one-time key (catastrophic)."
    );
    sig
}

/// Stateful `verify`: derive the public key from the raw private-key file and
/// check `sig` over `msg`. Returns `true` if the file is a stateful key (and
/// sets `*ok`); `false` if it is not a stateful key at all.
fn stateful_verify(raw: &[u8], msg: &[u8], sig: &[u8]) -> Option<bool> {
    let key = parse_stateful(raw)?;
    let ok = match key {
        StatefulKey::Lms(k) => k.public_key().verify(msg, sig),
        StatefulKey::Hss(k) => k.public_key().verify(msg, sig),
        StatefulKey::Xmss(k) => k.public_key().verify(msg, sig),
        StatefulKey::XmssMt(k) => k.public_key().verify(msg, sig),
    };
    Some(ok)
}

/// The SM2 signer identity `Z_A` (GB/T 32918.2). Defaults to the standard
/// `1234567812345678`; `-id STR` overrides it with raw UTF-8 bytes.
fn sm2_id(args: &Args) -> Vec<u8> {
    match args.value("-id").or_else(|| args.value("--id")) {
        Some(s) => s.as_bytes().to_vec(),
        None => DEFAULT_ID.to_vec(),
    }
}

fn load_spki(path: &str) -> AnyPublicKey {
    let raw = std::fs::read(path).unwrap_or_else(|e| die(format!("cannot read {path}: {e}")));
    let pem = core::str::from_utf8(&raw).unwrap_or_else(|_| die("pubkey is not UTF-8 PEM"));
    AnyPublicKey::from_spki_pem(pem).unwrap_or_else(|e| die(format!("cannot parse SPKI PEM: {e}")))
}

/// Attempts to load an SM2 public key from `path`: a `PUBLIC KEY` SPKI PEM
/// (preferred for `-pubin`), or the public half of an SM2 SEC1 private key.
/// Returns `None` if the file is not an SM2 key.
fn try_load_sm2_public(path: &str) -> Option<Sm2PublicKey> {
    let raw = std::fs::read(path).ok()?;
    let pem = core::str::from_utf8(&raw).ok()?;
    if let Ok(der) = purecrypto::der::pem_decode(pem, "PUBLIC KEY")
        && let Ok(pk) = Sm2PublicKey::from_spki_der(&der)
    {
        return Some(pk);
    }
    Sm2PrivateKey::from_sec1_pem(pem)
        .ok()
        .map(|sk| sk.public_key())
}

fn run_encrypt(args: Args) {
    let in_path = args.value("-in").or_else(|| args.value("--in"));
    let pt = read_input(in_path);
    let opts = parse_opts(&args);
    let padding = opts.padding.as_deref().unwrap_or("pkcs1");
    let inkey = args
        .value("-inkey")
        .or_else(|| args.value("--inkey"))
        .unwrap_or_else(|| die("missing -inkey"));

    // SM2 hybrid PKE (GB/T 32918.4 / RFC 8998): detect an SM2 key and route
    // before the RSA-only padding logic.
    if let Some(pk) = try_load_sm2_public(inkey) {
        let ct = pk
            .encrypt(&pt, &mut OsRng)
            .unwrap_or_else(|e| die(format!("SM2 encrypt failed: {e:?}")));
        let out_path = args.value("-out").or_else(|| args.value("--out"));
        write_output(out_path, &ct);
        return;
    }

    let ct = if args.flag("-pubin") || args.flag("--pubin") {
        let any = load_spki(inkey);
        let rsa = match any {
            AnyPublicKey::Rsa(k) => k,
            _ => die("RSA encrypt requires an RSA SPKI"),
        };
        match padding {
            "oaep" => {
                let md = opts.oaep_md.as_deref().unwrap_or("sha256");
                match md.to_ascii_lowercase().as_str() {
                    "sha256" => rsa
                        .encrypt_oaep::<Sha256, _>(&pt, &opts.oaep_label, &mut OsRng)
                        .unwrap_or_else(|e| die(format!("OAEP encrypt failed: {e}"))),
                    "sha384" => rsa
                        .encrypt_oaep::<Sha384, _>(&pt, &opts.oaep_label, &mut OsRng)
                        .unwrap_or_else(|e| die(format!("OAEP encrypt failed: {e}"))),
                    "sha512" => rsa
                        .encrypt_oaep::<Sha512, _>(&pt, &opts.oaep_label, &mut OsRng)
                        .unwrap_or_else(|e| die(format!("OAEP encrypt failed: {e}"))),
                    _ => die(format!("unsupported rsa_oaep_md: {md}")),
                }
            }
            "pkcs1" => rsa
                .encrypt_pkcs1v15(&pt, &mut OsRng)
                .unwrap_or_else(|e| die(format!("PKCS1 encrypt failed: {e}"))),
            other => die(format!("unsupported rsa_padding_mode for encrypt: {other}")),
        }
    } else {
        let key = load_priv(inkey);
        let rsa = match key {
            PrivKey::Rsa(k) => k,
            _ => die("RSA encrypt requires an RSA key"),
        };
        let pub_k = rsa.public_key();
        match padding {
            "oaep" => {
                let md = opts.oaep_md.as_deref().unwrap_or("sha256");
                match md.to_ascii_lowercase().as_str() {
                    "sha256" => pub_k
                        .encrypt_oaep::<Sha256, _>(&pt, &opts.oaep_label, &mut OsRng)
                        .unwrap_or_else(|e| die(format!("OAEP encrypt failed: {e}"))),
                    "sha384" => pub_k
                        .encrypt_oaep::<Sha384, _>(&pt, &opts.oaep_label, &mut OsRng)
                        .unwrap_or_else(|e| die(format!("OAEP encrypt failed: {e}"))),
                    "sha512" => pub_k
                        .encrypt_oaep::<Sha512, _>(&pt, &opts.oaep_label, &mut OsRng)
                        .unwrap_or_else(|e| die(format!("OAEP encrypt failed: {e}"))),
                    _ => die(format!("unsupported rsa_oaep_md: {md}")),
                }
            }
            "pkcs1" => pub_k
                .encrypt_pkcs1v15(&pt, &mut OsRng)
                .unwrap_or_else(|e| die(format!("PKCS1 encrypt failed: {e}"))),
            other => die(format!("unsupported rsa_padding_mode: {other}")),
        }
    };
    let out_path = args.value("-out").or_else(|| args.value("--out"));
    write_output(out_path, &ct);
}

fn run_decrypt(args: Args) {
    let in_path = args.value("-in").or_else(|| args.value("--in"));
    let ct = read_input(in_path);
    let opts = parse_opts(&args);
    let padding = opts.padding.as_deref().unwrap_or("pkcs1");
    let inkey = args
        .value("-inkey")
        .or_else(|| args.value("--inkey"))
        .unwrap_or_else(|| die("missing -inkey"));
    let key = load_priv(inkey);
    // SM2 hybrid PKE decrypt routes to the SM2 private key.
    if let PrivKey::Sm2(sk) = &key {
        let pt = sk
            .decrypt(&ct)
            .unwrap_or_else(|e| die(format!("SM2 decrypt failed: {e:?}")));
        let out_path = args.value("-out").or_else(|| args.value("--out"));
        write_output(out_path, &pt);
        return;
    }
    let rsa = match key {
        PrivKey::Rsa(k) => k,
        _ => die("RSA decrypt requires an RSA key"),
    };
    let pt = match padding {
        "oaep" => {
            let md = opts.oaep_md.as_deref().unwrap_or("sha256");
            match md.to_ascii_lowercase().as_str() {
                "sha256" => rsa
                    .decrypt_oaep::<Sha256>(&ct, &opts.oaep_label)
                    .unwrap_or_else(|e| die(format!("OAEP decrypt failed: {e}"))),
                "sha384" => rsa
                    .decrypt_oaep::<Sha384>(&ct, &opts.oaep_label)
                    .unwrap_or_else(|e| die(format!("OAEP decrypt failed: {e}"))),
                "sha512" => rsa
                    .decrypt_oaep::<Sha512>(&ct, &opts.oaep_label)
                    .unwrap_or_else(|e| die(format!("OAEP decrypt failed: {e}"))),
                _ => die(format!("unsupported rsa_oaep_md: {md}")),
            }
        }
        "pkcs1" => rsa
            .decrypt_pkcs1v15(&ct)
            .unwrap_or_else(|e| die(format!("PKCS1 decrypt failed: {e}"))),
        other => die(format!("unsupported rsa_padding_mode: {other}")),
    };
    let out_path = args.value("-out").or_else(|| args.value("--out"));
    write_output(out_path, &pt);
}

fn run_sign(args: Args) {
    let in_path = args
        .value("-in")
        .or_else(|| args.value("--in"))
        .unwrap_or_else(|| die("missing -in FILE"));
    let msg = std::fs::read(in_path).unwrap_or_else(|e| die(format!("cannot read {in_path}: {e}")));
    let opts = parse_opts(&args);
    let inkey = args
        .value("-inkey")
        .or_else(|| args.value("--inkey"))
        .unwrap_or_else(|| die("missing -inkey"));
    if inkey == "-" {
        die("stateful keys (LMS/XMSS) and signing require -inkey FILE, not stdin");
    }

    // Stateful hash-based signature? Detect from the raw key bytes and route to
    // the special path that rewrites the advanced key file before emitting the
    // signature. (Reading the file twice is fine; the authoritative parse is in
    // `stateful_sign`.)
    if let Ok(raw) = std::fs::read(inkey)
        && parse_stateful(&raw).is_some()
    {
        let sig = stateful_sign(inkey, &msg);
        let out_path = args
            .value("-out")
            .or_else(|| args.value("--out"))
            .unwrap_or_else(|| die("missing -out FILE"));
        write_output(Some(out_path), &sig);
        return;
    }

    let key = load_priv(inkey);
    let pss = matches!(opts.padding.as_deref(), Some("pss"));
    let digest = opts.digest.as_deref().unwrap_or("sha256");

    let sig = match key {
        PrivKey::Rsa(k) => {
            if pss {
                match digest.to_ascii_lowercase().as_str() {
                    "sha256" => k.sign_pss::<Sha256, _>(&msg, &mut OsRng),
                    "sha384" => k.sign_pss::<Sha384, _>(&msg, &mut OsRng),
                    "sha512" => k.sign_pss::<Sha512, _>(&msg, &mut OsRng),
                    _ => die(format!("unsupported RSA-PSS digest: {digest}")),
                }
                .unwrap_or_else(|e| die(format!("RSA-PSS sign failed: {e}")))
            } else {
                match digest.to_ascii_lowercase().as_str() {
                    "sha256" => k.sign_pkcs1v15::<Sha256>(&msg),
                    "sha384" => k.sign_pkcs1v15::<Sha384>(&msg),
                    "sha512" => k.sign_pkcs1v15::<Sha512>(&msg),
                    "sha1" => k.sign_pkcs1v15::<Sha1>(&msg),
                    _ => die(format!("unsupported RSA digest: {digest}")),
                }
                .unwrap_or_else(|e| die(format!("RSA sign failed: {e}")))
            }
        }
        PrivKey::Ec(k) => {
            let curve = k.curve();
            let sig = match curve {
                CurveId::P256 | CurveId::Secp256k1 | CurveId::Sm2p256v1 => k.sign::<Sha256>(&msg),
                CurveId::P384 => k.sign::<Sha384>(&msg),
                CurveId::P521 => k.sign::<Sha512>(&msg),
            }
            .unwrap_or_else(|e| die(format!("ECDSA sign failed: {e}")));
            sig.to_der(curve)
        }
        PrivKey::Ed25519(k) => k.sign(&msg).to_bytes().to_vec(),
        PrivKey::Ed448(k) => k.sign(&msg).to_bytes().to_vec(),
        PrivKey::MlDsa44(k) => k
            .sign(&mut OsRng, &msg, b"")
            .unwrap_or_else(|e| die(format!("ML-DSA-44 sign failed: {e:?}"))),
        PrivKey::MlDsa65(k) => k
            .sign(&mut OsRng, &msg, b"")
            .unwrap_or_else(|e| die(format!("ML-DSA-65 sign failed: {e:?}"))),
        PrivKey::MlDsa87(k) => k
            .sign(&mut OsRng, &msg, b"")
            .unwrap_or_else(|e| die(format!("ML-DSA-87 sign failed: {e:?}"))),
        PrivKey::SlhDsa(k) => k
            .sign(&mut OsRng, &msg, b"")
            .unwrap_or_else(|e| die(format!("SLH-DSA sign failed: {e:?}"))),
        PrivKey::Sm2(k) => {
            let id = sm2_id(&args);
            k.sign(&msg, &id, &mut OsRng)
                .unwrap_or_else(|e| die(format!("SM2 sign failed: {e:?}")))
                .to_der()
        }
    };
    let out_path = args
        .value("-out")
        .or_else(|| args.value("--out"))
        .unwrap_or_else(|| die("missing -out FILE"));
    write_output(Some(out_path), &sig);
}

fn run_verify(args: Args) {
    let in_path = args
        .value("-in")
        .or_else(|| args.value("--in"))
        .unwrap_or_else(|| die("missing -in FILE"));
    let msg = std::fs::read(in_path).unwrap_or_else(|e| die(format!("cannot read {in_path}: {e}")));
    let sig_path = args
        .value("-sigfile")
        .or_else(|| args.value("--sigfile"))
        .unwrap_or_else(|| die("missing -sigfile FILE"));
    let sig =
        std::fs::read(sig_path).unwrap_or_else(|e| die(format!("cannot read {sig_path}: {e}")));
    let inkey = args
        .value("-inkey")
        .or_else(|| args.value("--inkey"))
        .unwrap_or_else(|| die("missing -inkey"));
    let opts = parse_opts(&args);
    let pss = matches!(opts.padding.as_deref(), Some("pss"));
    let digest = opts.digest.as_deref().unwrap_or("sha256");

    let raw_key = std::fs::read(inkey).unwrap_or_else(|e| die(format!("cannot read {inkey}: {e}")));

    // Stateful hash-based signatures: the public key is derived from the raw
    // private-key file (deriving the public key does NOT advance state).
    if let Some(ok) = stateful_verify(&raw_key, &msg, &sig) {
        report_verify(ok);
        return;
    }

    // SM2 verification: accept either a `PUBLIC KEY` SPKI PEM (the SM2 named
    // curve) or an SM2 SEC1 private key (deriving its public key — which does
    // not expose the secret). The generic `AnyPublicKey` parser does not handle
    // SM2, so detect it here and route to SM2-DSA (`Ecdsa-Sig-Value` signature).
    if let Ok(pem) = core::str::from_utf8(&raw_key) {
        let pk = purecrypto::der::pem_decode(pem, "PUBLIC KEY")
            .ok()
            .and_then(|der| Sm2PublicKey::from_spki_der(&der).ok())
            .or_else(|| {
                Sm2PrivateKey::from_sec1_pem(pem)
                    .ok()
                    .map(|sk| sk.public_key())
            });
        if let Some(pk) = pk {
            let id = sm2_id(&args);
            let ok = Sm2Signature::from_der(&sig)
                .map(|parsed| pk.verify(&msg, &parsed, &id).is_ok())
                .unwrap_or(false);
            report_verify(ok);
            return;
        }
    }

    let any = load_spki(inkey);
    let ok = match any {
        AnyPublicKey::Rsa(k) => {
            if pss {
                match digest.to_ascii_lowercase().as_str() {
                    "sha256" => k.verify_pss::<Sha256>(&msg, &sig),
                    "sha384" => k.verify_pss::<Sha384>(&msg, &sig),
                    "sha512" => k.verify_pss::<Sha512>(&msg, &sig),
                    _ => die(format!("unsupported RSA-PSS digest: {digest}")),
                }
                .is_ok()
            } else {
                match digest.to_ascii_lowercase().as_str() {
                    "sha256" => k.verify_pkcs1v15::<Sha256>(&msg, &sig),
                    "sha384" => k.verify_pkcs1v15::<Sha384>(&msg, &sig),
                    "sha512" => k.verify_pkcs1v15::<Sha512>(&msg, &sig),
                    "sha1" => k.verify_pkcs1v15::<Sha1>(&msg, &sig),
                    _ => die(format!("unsupported RSA digest: {digest}")),
                }
                .is_ok()
            }
        }
        AnyPublicKey::Ecdsa(k) => {
            let parsed = match BoxedEcdsaSignature::from_der(&sig) {
                Ok(s) => s,
                Err(_) => {
                    println!("verify FAIL");
                    std::process::exit(1);
                }
            };
            match k.curve() {
                CurveId::P256 | CurveId::Secp256k1 | CurveId::Sm2p256v1 => {
                    k.verify::<Sha256>(&msg, &parsed)
                }
                CurveId::P384 => k.verify::<Sha384>(&msg, &parsed),
                CurveId::P521 => k.verify::<Sha512>(&msg, &parsed),
            }
            .is_ok()
        }
        AnyPublicKey::Ed25519(k) => {
            use purecrypto::ec::Ed25519Signature;
            match <[u8; 64]>::try_from(sig.as_slice()) {
                Ok(b) => k.verify(&msg, &Ed25519Signature::from_bytes(b)).is_ok(),
                Err(_) => false,
            }
        }
        AnyPublicKey::Ed448(k) => {
            use purecrypto::ec::Ed448Signature;
            match <[u8; 114]>::try_from(sig.as_slice()) {
                Ok(b) => k.verify(&msg, &Ed448Signature::from_bytes(b)).is_ok(),
                Err(_) => false,
            }
        }
        AnyPublicKey::MlDsa44(k) => k.verify(&sig, &msg, b""),
        AnyPublicKey::MlDsa65(k) => k.verify(&sig, &msg, b""),
        AnyPublicKey::MlDsa87(k) => k.verify(&sig, &msg, b""),
        AnyPublicKey::SlhDsa(k) => k.verify(&sig, &msg, b""),
    };
    report_verify(ok);
}

/// Prints the OpenSSL-style verification result and exits non-zero on failure.
fn report_verify(ok: bool) {
    if ok {
        println!("Signature verified");
    } else {
        println!("Signature verification failure");
        std::process::exit(1);
    }
}

pub(crate) fn run(args: Args) {
    let pos = args.positionals(&[
        "-inkey",
        "--inkey",
        "-in",
        "--in",
        "-out",
        "--out",
        "-sigfile",
        "--sigfile",
        "-pkeyopt",
        "--pkeyopt",
        "-id",
        "--id",
    ]);
    let sub = pos.first().copied().unwrap_or("");
    match sub {
        "encrypt" => run_encrypt(args),
        "decrypt" => run_decrypt(args),
        "sign" => run_sign(args),
        "verify" => run_verify(args),
        "" => die(USAGE),
        other => die(format!("unknown pkeyutl subcommand '{other}'\n\n{USAGE}")),
    }
}
