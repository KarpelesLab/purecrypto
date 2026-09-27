//! Constant-time verification under Valgrind memcheck (the ctgrind / TIMECOP
//! technique used by libsodium, BoringSSL and PQClean).
//!
//! Every case below derives its inputs from a fixed seed, marks the secret
//! ones *undefined* with `purecrypto::ct::classify` (a Valgrind client
//! request, compiled in by the hidden `__ct-check` feature), runs the
//! operation, and marks the public results *defined* again with
//! `ct::declassify` before comparing or printing them. Under
//! `valgrind --tool=memcheck` any conditional branch or memory address
//! computed from a secret — in the real optimized binary, after LLVM has done
//! whatever it likes with the source — is reported as "Conditional jump or
//! move depends on uninitialised value(s)" or "Use of uninitialised value of
//! size N", and `--error-exitcode=1` fails the run.
//!
//! Run natively (`cargo test --all-features --test ct_valgrind`) the client
//! requests are no-ops and this is a plain smoke test of the same code paths.
//! CI (`.github/workflows/ct-valgrind.yml`) builds it in release mode and
//! runs it under memcheck on x86_64 and aarch64 Linux.
//!
//! Usage: `ct_valgrind [--positive-control] [--list] [FILTER...]`. With
//! filters, only cases whose name contains one of them run. With
//! `--positive-control`, runs a deliberately variable-time function instead,
//! which memcheck MUST flag — CI asserts that it does, which is what makes a
//! clean run of the real cases meaningful. With `CT_REQUIRE_VALGRIND=1` in
//! the environment the harness refuses to run outside Valgrind, so a broken
//! CI invocation cannot pass vacuously.
//!
//! Secrets enter a case in one of three ways: as classified byte arrays
//! (keys, seeds, plaintexts), through [`TaintRng`] — an HMAC-DRBG whose every
//! output byte is classified, so key generation and hedged signing see
//! secret randomness exactly as they would from `OsRng` — or by classifying
//! the secret limbs of an imported RSA key. Public halves of a key (an
//! ML-DSA `rho`/`tr`, an SLH-DSA `PK.root`) are declassified by the harness,
//! because they *are* the public key, and randomness that is published (a
//! PSS salt, an LM-OTS randomizer) comes from a public RNG. The
//! declassification points inside the library are listed in
//! `docs/validation.md` ("Declassification points").
//!
//! Deliberately NOT covered — accepted variable-time residuals documented in
//! `docs/validation.md`, which this harness would (correctly) flag:
//!
//! * legacy CBC / MAC-then-encrypt record protection (`tls-legacy`, Lucky13
//!   residue) and PBES2 CBC-PAD;
//! * DES/3DES and Blowfish / `bcrypt_pbkdf` (key-dependent S-box tables);
//! * Falcon key generation and secret-key import (variable-time NTRU solve);
//! * Argon2d/Argon2id data-dependent addressing and scrypt's `Integerify`.
//!
//! Also not covered: the portable fallbacks of runtime-dispatched SIMD code
//! (AES, GHASH, ChaCha20, SHA-2, Keccak). Each runner tests whichever backend
//! its (Valgrind-emulated) CPU selects; the crate has no switch to force the
//! portable path.

use std::hint::black_box;
use std::time::Instant;

use purecrypto::ct::{
    self, Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq,
    ConstantTimeGreater, ConstantTimeLess, classify, declassify,
};
use purecrypto::rng::{CryptoRng, HmacDrbg, RngCore};

use purecrypto::ascon::AsconAead128;
use purecrypto::bignum::BoxedUint;
use purecrypto::bls;
use purecrypto::cipher::{
    Aegis128L, Aes128, Aes128Ccm, Aes128Eax, Aes192, Aes256, Aes256GcmSiv, AesCmac128, Aria128,
    BlockCipher, Camellia128, ChaCha20Poly1305, Gcm, Poly1305, Sm4, XChaCha20Poly1305,
};
use purecrypto::dh::{DhPrivateKey, group14};
use purecrypto::ec::CurveId;
use purecrypto::ec::boxed::{BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey};
use purecrypto::ec::ecdh::EcdhPrivateKey;
use purecrypto::ec::ecdsa::EcdsaPrivateKey;
use purecrypto::ec::ed448::Ed448PrivateKey;
use purecrypto::ec::ed25519::Ed25519PrivateKey;
use purecrypto::ec::secp256k1_ecdsa::Secp256k1EcdsaPrivateKey;
use purecrypto::ec::sm2::Sm2PrivateKey;
use purecrypto::ec::x448::X448PrivateKey;
use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::hash::{
    Blake2b512, Blake3, Digest, HmacSha256, HmacSha512, Kmac128, Sha3_256, Sha256, Sha384, Sha512,
    Sm3, shake256,
};
use purecrypto::hpke::{self, CipherSuite, HpkeAead, HpkeKdf, HpkeKem};
use purecrypto::kdf::argon2::{Argon2Params, Argon2Type, argon2};
use purecrypto::kdf::{hkdf, pbkdf2};
use purecrypto::lms::{LmotsType, LmsPrivateKey, LmsType};
use purecrypto::mac::SipHash24;
use purecrypto::mldsa::{MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey};
use purecrypto::mlkem::{
    MlKem512DecapsKey, MlKem768Ciphertext, MlKem768DecapsKey, MlKem1024DecapsKey,
};
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::slhdsa::{self, ParamSet};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic, non-constant bytes from `tag` (a tiny xorshift; the values
/// only need to be fixed and irregular, not random).
fn fixed_bytes<const N: usize>(tag: u64) -> [u8; N] {
    let mut s = 0x9E37_79B9_7F4A_7C15u64 ^ tag.wrapping_mul(0xD1B5_4A32_D192_ED03);
    let mut out = [0u8; N];
    for b in out.iter_mut() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        *b = (s >> 24) as u8;
    }
    black_box(out)
}

/// [`fixed_bytes`], classified as secret.
fn secret_bytes<const N: usize>(tag: u64) -> [u8; N] {
    let out = fixed_bytes::<N>(tag);
    classify(&out);
    out
}

/// Marks a whole value as public and returns it (for results the harness is
/// about to inspect).
fn public<T: ?Sized>(v: &T) -> &T {
    ct::declassify_val(v);
    v
}

/// A deterministic CSPRNG whose every output byte is classified secret, so
/// the code consuming it (key generation, nonces, blinding, hedging) is
/// checked exactly as it runs on `OsRng` output.
struct TaintRng(HmacDrbg<Sha256>);

impl TaintRng {
    fn new(tag: u64) -> Self {
        TaintRng(HmacDrbg::new(&tag.to_le_bytes(), b"ct_valgrind", b"taint"))
    }
}

impl RngCore for TaintRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest);
        classify(dest);
    }
}

impl CryptoRng for TaintRng {}

/// A deterministic CSPRNG with *public* output, for the public side of a
/// test (encrypting to a key, making a peer).
fn public_rng(tag: u64) -> HmacDrbg<Sha256> {
    HmacDrbg::new(&tag.to_le_bytes(), b"ct_valgrind", b"public")
}

/// Short hex prefix of a public result, for the log.
fn hex8(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// A [`BoxedUint`] whose limbs are classified secret.
fn secret_uint(v: &BoxedUint) -> BoxedUint {
    let out = BoxedUint::from_be_bytes(&v.to_be_bytes(v.bit_len().div_ceil(8)));
    ct::classify_val(out.as_limbs());
    out
}

// ---------------------------------------------------------------------------
// ct:: primitives
// ---------------------------------------------------------------------------

fn ct_primitives() -> String {
    let a = secret_bytes::<32>(1);
    let mut b = a;
    b[31] ^= 1;
    classify(&b);

    let eq_self = a.ct_eq(&a);
    let eq_other = a.ct_eq(&b);
    let x = u64::from_le_bytes(a[..8].try_into().unwrap());
    let y = u64::from_le_bytes(b[8..16].try_into().unwrap());
    let lt = x.ct_lt(&y);
    let gt = x.ct_gt(&y);
    let sel = u64::conditional_select(&x, &y, lt);
    let mut sa = x;
    let mut sb = y;
    u64::conditional_swap(&mut sa, &mut sb, gt);
    let mut neg = (x as i64) >> 3;
    neg.conditional_negate(eq_other);
    let combo: Choice = (eq_self & !eq_other) | (lt ^ gt);
    let byte_eq = a[0].ct_eq(&b[0]);
    let arr_sel = <[u8; 32]>::conditional_select(&a, &b, combo);

    let r = [
        ct::declassify_value(eq_self).unwrap_u8(),
        ct::declassify_value(eq_other).unwrap_u8(),
        ct::declassify_value(combo).unwrap_u8(),
        ct::declassify_value(byte_eq).unwrap_u8(),
    ];
    let words = [
        ct::declassify_value(sel),
        ct::declassify_value(sa ^ sb),
        ct::declassify_value(neg as u64),
    ];
    assert_eq!(r[0], 1);
    assert_eq!(r[1], 0);
    assert_eq!(r[2], 1);
    format!(
        "eq={}{} combo={} sel={:016x} swap={:016x} neg={:016x} arr={}",
        r[0],
        r[1],
        r[2],
        words[0],
        words[1],
        words[2],
        hex8(public(&arr_sel))
    )
}

// ---------------------------------------------------------------------------
// Symmetric
// ---------------------------------------------------------------------------

fn aes_block<C: BlockCipher>(cipher: &C) -> String {
    let mut block = secret_bytes::<16>(3);
    let orig = block;
    cipher.encrypt_block(&mut block);
    let ct_hex = hex8(public(&block));
    cipher.decrypt_block(&mut block);
    let back = ct::declassify_value(block.ct_eq(&orig));
    assert!(bool::from(back));
    ct_hex
}

fn aes128_block() -> String {
    aes_block(&Aes128::new(&secret_bytes::<16>(2)))
}

fn aes256_block() -> String {
    aes_block(&Aes256::new(&secret_bytes::<32>(4)))
}

fn aes192_block() -> String {
    aes_block(&Aes192::new(&secret_bytes::<24>(120)))
}

fn camellia128_block() -> String {
    aes_block(&Camellia128::new(&secret_bytes::<16>(121)))
}

fn aria128_block() -> String {
    aes_block(&Aria128::new(&secret_bytes::<16>(122)))
}

fn sm4_block() -> String {
    aes_block(&Sm4::new(&secret_bytes::<16>(123)))
}

/// Seal, open with the right tag, open with a wrong tag.
fn aead_roundtrip(
    seal: impl Fn(&mut [u8]) -> [u8; 16],
    open: impl Fn(&mut [u8], &[u8; 16]) -> bool,
) -> String {
    let pt = secret_bytes::<100>(5);
    let mut buf = pt;
    let tag = seal(&mut buf);
    // Ciphertext and tag are public outputs.
    declassify(&buf);
    declassify(&tag);
    let out = format!("ct={} tag={}", hex8(&buf), hex8(&tag));
    let sealed = buf;

    let mut good = sealed;
    assert!(open(&mut good, &tag), "authentic ciphertext must open");
    assert!(bool::from(ct::declassify_value(good.ct_eq(&pt))));

    let mut bad_tag = tag;
    bad_tag[15] ^= 0x80;
    let mut forged = sealed;
    assert!(!open(&mut forged, &bad_tag), "forged tag must be rejected");
    // On rejection the buffer holds the (public) ciphertext again, or has
    // been wiped (AES-GCM-SIV decrypts before it can verify); memcheck
    // cannot see that re-applying the keystream cancelled it.
    declassify(&forged);
    assert!(
        forged == sealed || forged.iter().all(|&b| b == 0),
        "buffer must hold the ciphertext or be wiped"
    );
    out
}

fn aes128_gcm() -> String {
    let gcm = Gcm::new(Aes128::new(&secret_bytes::<16>(6)));
    let nonce = fixed_bytes::<12>(7);
    aead_roundtrip(
        |b| gcm.encrypt(&nonce, b"aad", b),
        |b, t| gcm.decrypt(&nonce, b"aad", b, t).is_ok(),
    )
}

fn aes256_gcm() -> String {
    let gcm = Gcm::new(Aes256::new(&secret_bytes::<32>(8)));
    let nonce = fixed_bytes::<12>(9);
    aead_roundtrip(
        |b| gcm.encrypt(&nonce, b"aad", b),
        |b, t| gcm.decrypt(&nonce, b"aad", b, t).is_ok(),
    )
}

fn chacha20_poly1305() -> String {
    let aead = ChaCha20Poly1305::new(&secret_bytes::<32>(10));
    let nonce = fixed_bytes::<12>(11);
    aead_roundtrip(
        |b| aead.encrypt(&nonce, b"aad", b),
        |b, t| aead.decrypt(&nonce, b"aad", b, t).is_ok(),
    )
}

fn xchacha20_poly1305() -> String {
    let aead = XChaCha20Poly1305::new(&secret_bytes::<32>(12));
    let nonce = fixed_bytes::<24>(13);
    aead_roundtrip(
        |b| aead.encrypt(&nonce, b"aad", b),
        |b, t| aead.decrypt(&nonce, b"aad", b, t).is_ok(),
    )
}

fn aes256_gcm_siv() -> String {
    let aead = Aes256GcmSiv::new(&secret_bytes::<32>(100));
    let nonce = fixed_bytes::<12>(101);
    aead_roundtrip(
        |b| aead.encrypt(&nonce, b"aad", b),
        |b, t| aead.decrypt(&nonce, b"aad", b, t).is_ok(),
    )
}

fn aes128_ccm() -> String {
    let aead = Aes128Ccm::new(Aes128::new(&secret_bytes::<16>(102)));
    let nonce = fixed_bytes::<12>(103);
    aead_roundtrip(
        |b| aead.encrypt(&nonce, b"aad", b),
        |b, t| aead.decrypt(&nonce, b"aad", b, t).is_ok(),
    )
}

fn aes128_eax() -> String {
    let aead = Aes128Eax::new(Aes128::new(&secret_bytes::<16>(104)));
    let nonce = fixed_bytes::<16>(105);
    aead_roundtrip(
        |b| aead.encrypt(&nonce, b"aad", b),
        |b, t| aead.decrypt(&nonce, b"aad", b, t).is_ok(),
    )
}

fn aegis128l() -> String {
    let aead = Aegis128L::new(&secret_bytes::<16>(106));
    let nonce = fixed_bytes::<16>(107);
    aead_roundtrip(
        |b| aead.encrypt(&nonce, b"aad", b),
        |b, t| aead.decrypt(&nonce, b"aad", b, t).is_ok(),
    )
}

fn ascon_aead128() -> String {
    let aead = AsconAead128::new(&secret_bytes::<16>(108));
    let nonce = fixed_bytes::<16>(109);
    aead_roundtrip(
        |b| aead.encrypt(&nonce, b"aad", b),
        |b, t| aead.decrypt(&nonce, b"aad", b, t).is_ok(),
    )
}

fn aes_cmac() -> String {
    let mut mac = AesCmac128::new(Aes128::new(&secret_bytes::<16>(110)));
    mac.update(&secret_bytes::<77>(111));
    hex8(public(&mac.finalize()))
}

fn kmac128() -> String {
    let key = secret_bytes::<32>(124);
    let msg = secret_bytes::<150>(125);
    let mut out = [0u8; 32];
    let mut m = Kmac128::new(&key, b"ct");
    m.update(&msg);
    m.finalize_into(&mut out);
    let mut expected = out;
    declassify(&expected);
    let mut m = Kmac128::new(&key, b"ct");
    m.update(&msg);
    let ok = m.verify(&expected);
    expected[0] ^= 1;
    let mut m = Kmac128::new(&key, b"ct");
    m.update(&msg);
    let bad = m.verify(&expected);
    assert!(bool::from(ct::declassify_value(ok)));
    assert!(!bool::from(ct::declassify_value(bad)));
    hex8(public(&out))
}

fn siphash24() -> String {
    let key = secret_bytes::<16>(126);
    let msg = secret_bytes::<45>(127);
    let mut h = SipHash24::new(&key);
    h.update(&msg);
    hex8(public(&h.finalize()))
}

fn poly1305() -> String {
    let key = secret_bytes::<32>(14);
    let msg = secret_bytes::<333>(15);
    let mut p = Poly1305::new(&key);
    p.update(&msg[..17]);
    p.update(&msg[17..]);
    hex8(public(&p.finish()))
}

fn hmac_sha256() -> String {
    let key = secret_bytes::<40>(16);
    let msg = secret_bytes::<200>(17);
    let tag = HmacSha256::mac(&key, &msg);
    let mut expected = tag;
    declassify(&expected);
    let ok = HmacSha256::new(&key).chain(&msg).verify(&expected);
    expected[0] ^= 1;
    let bad = HmacSha256::new(&key).chain(&msg).verify(&expected);
    // The verdicts are the public outputs of `verify`.
    assert!(bool::from(ct::declassify_value(ok)));
    assert!(!bool::from(ct::declassify_value(bad)));
    hex8(public(&tag))
}

fn hmac_sha512() -> String {
    let key = secret_bytes::<200>(18);
    let msg = secret_bytes::<300>(19);
    let tag = HmacSha512::mac(&key, &msg);
    let mut expected = tag;
    declassify(&expected);
    let ok = HmacSha512::new(&key).chain(&msg).verify(&expected);
    expected[63] ^= 1;
    let bad = HmacSha512::new(&key).chain(&msg).verify(&expected);
    assert!(bool::from(ct::declassify_value(ok)));
    assert!(!bool::from(ct::declassify_value(bad)));
    hex8(public(&tag))
}

fn hkdf_sha256() -> String {
    let ikm = secret_bytes::<32>(20);
    let mut okm = [0u8; 80];
    hkdf::<Sha256>(b"salt", &ikm, b"info", &mut okm);
    hex8(public(&okm))
}

fn pbkdf2_sha256() -> String {
    let password = secret_bytes::<20>(112);
    let mut out = [0u8; 48];
    pbkdf2::<Sha256>(&password, b"salt", 3, &mut out);
    hex8(public(&out))
}

/// Argon2i only: its addressing is data-independent by design (Argon2d/id
/// are the documented exclusion).
fn argon2i() -> String {
    let params = Argon2Params {
        t_cost: 2,
        m_cost_kib: 64,
        parallelism: 1,
        variant: Argon2Type::Argon2i,
        version: 0x13,
    };
    let password = secret_bytes::<16>(113);
    let mut out = [0u8; 32];
    argon2(&params, &password, b"saltsalt", b"", b"", &mut out).expect("valid params");
    hex8(public(&out))
}

fn sha2() -> String {
    let data = secret_bytes::<1000>(21);
    let a = Sha256::digest(&data);
    let b = Sha384::digest(&data[..129]);
    let c = Sha512::digest(&data);
    format!(
        "sha256={} sha384={} sha512={}",
        hex8(public(&a)),
        hex8(public(&b)),
        hex8(public(&c))
    )
}

fn sha3_shake() -> String {
    let data = secret_bytes::<1000>(22);
    let a = Sha3_256::digest(&data);
    let mut x = [0u8; 200];
    shake256(&data[..137], &mut x);
    format!(
        "sha3-256={} shake256={}",
        hex8(public(&a)),
        hex8(public(&x))
    )
}

fn blake2b_sm3() -> String {
    let data = secret_bytes::<300>(128);
    let a = Blake2b512::digest(&data);
    let b = Sm3::digest(&data);
    format!("blake2b={} sm3={}", hex8(public(&a)), hex8(public(&b)))
}

fn blake3() -> String {
    // Several chunks, so the multi-chunk (SIMD) path runs.
    let data = secret_bytes::<5000>(23);
    hex8(public(&Blake3::digest(&data)))
}

// ---------------------------------------------------------------------------
// Elliptic curves
// ---------------------------------------------------------------------------

fn x25519() -> String {
    let sk = X25519PrivateKey::from_bytes(secret_bytes::<32>(30));
    let peer = X25519PrivateKey::from_bytes(fixed_bytes::<32>(31)).public_key();
    let pk = sk.public_key();
    let shared = sk.diffie_hellman(&peer).expect("non-degenerate peer");
    format!("pk={} ss={}", hex8(public(&pk)), hex8(public(&shared)))
}

fn x448() -> String {
    let sk = X448PrivateKey::from_bytes(secret_bytes::<56>(32));
    let peer = X448PrivateKey::from_bytes(fixed_bytes::<56>(33)).public_key();
    let pk = sk.public_key();
    let shared = sk.diffie_hellman(&peer).expect("non-degenerate peer");
    format!("pk={} ss={}", hex8(public(&pk)), hex8(public(&shared)))
}

fn hpke_case(kem: HpkeKem, aead: HpkeAead, tag: u64) -> String {
    let suite = CipherSuite::new(kem, HpkeKdf::HkdfSha256, aead);
    // Recipient key from secret randomness; the encoded public key is public.
    let (sk_r, pk_r) = kem
        .generate_key_pair(&mut TaintRng::new(tag))
        .expect("keygen");
    declassify(&pk_r);
    let pt = secret_bytes::<40>(tag + 1);
    // The ephemeral KEM key is secret randomness too.
    let (enc, ct) = hpke::seal(
        &mut TaintRng::new(tag + 2),
        suite,
        &pk_r,
        b"info",
        b"aad",
        &pt,
    )
    .expect("seal");
    declassify(&enc);
    declassify(&ct);
    let got = hpke::open(suite, &enc, &sk_r, b"info", b"aad", &ct).expect("open");
    declassify(&got);
    declassify(&pt);
    assert_eq!(got, pt);
    let mut bad = ct.clone();
    bad[3] ^= 1;
    assert!(hpke::open(suite, &enc, &sk_r, b"info", b"aad", &bad).is_err());
    format!("enc={} ct={}", hex8(&enc), hex8(&ct))
}

fn hpke_x25519_chacha() -> String {
    hpke_case(
        HpkeKem::DhkemX25519HkdfSha256,
        HpkeAead::ChaCha20Poly1305,
        130,
    )
}

fn hpke_p256_aes128gcm() -> String {
    hpke_case(HpkeKem::DhkemP256HkdfSha256, HpkeAead::Aes128Gcm, 133)
}

fn bls12381_sign() -> String {
    let mut raw = secret_bytes::<32>(136);
    // Keep the scalar below the 255-bit group order.
    raw[0] &= 0x0f;
    raw[31] &= 0x0f;
    let sk = bls::SecretKey::from_bytes(&raw).expect("scalar in range");
    let pk = sk.public_key().to_bytes();
    let sig = sk
        .sign(bls::Scheme::Basic, b"ct_valgrind message")
        .to_bytes();
    format!("pk={} sig={}", hex8(public(&pk)), hex8(public(&sig)))
}

fn lms_h5_sign() -> String {
    let seed = secret_bytes::<32>(137);
    let mut sk = LmsPrivateKey::from_seed(
        LmsType::Sha256M32H5,
        LmotsType::Sha256N32W4,
        &fixed_bytes::<16>(138),
        &seed,
    );
    let pk = sk.public_key();
    declassify(pk.to_bytes());
    // The LM-OTS randomizer `C` is published in the signature (RFC 8554
    // §4.5) and drives the public chain lengths, so it is public randomness.
    let sig = sk
        .sign(&mut public_rng(139), b"ct_valgrind message")
        .expect("fresh key");
    declassify(&sig);
    assert!(pk.verify(b"ct_valgrind message", &sig));
    format!("pk={} sig={}", hex8(pk.to_bytes()), hex8(&sig))
}

fn ed25519_sign() -> String {
    let sk = Ed25519PrivateKey::from_bytes(secret_bytes::<32>(34));
    let pk = sk.public_key().to_bytes();
    let sig = sk.sign(b"ct_valgrind message").to_bytes();
    format!("pk={} sig={}", hex8(public(&pk)), hex8(public(&sig)))
}

fn ed448_sign() -> String {
    let sk = Ed448PrivateKey::from_bytes(secret_bytes::<57>(35));
    let pk = sk.public_key().to_bytes();
    let sig = sk.sign(b"ct_valgrind message").to_bytes();
    format!("pk={} sig={}", hex8(public(&pk)), hex8(public(&sig)))
}

fn p256_ecdsa_sign() -> String {
    let sk = EcdsaPrivateKey::from_bytes(&secret_bytes::<32>(36)).expect("scalar in range");
    let pk = sk.public_key().to_sec1();
    let sig = sk
        .sign::<Sha256>(b"ct_valgrind message")
        .unwrap()
        .to_bytes();
    format!("pk={} sig={}", hex8(public(&pk)), hex8(public(&sig)))
}

fn p256_ecdh() -> String {
    let sk = EcdhPrivateKey::from_bytes(&secret_bytes::<32>(37)).expect("scalar in range");
    let peer = EcdhPrivateKey::from_bytes(&fixed_bytes::<32>(38))
        .unwrap()
        .public_key();
    let pk = sk.public_key().to_sec1();
    let shared = sk.diffie_hellman(&peer).expect("valid peer");
    format!("pk={} ss={}", hex8(public(&pk)), hex8(public(&shared)))
}

fn p256_keygen() -> String {
    let mut rng = TaintRng::new(39);
    let sk = EcdsaPrivateKey::generate(&mut rng);
    hex8(public(&sk.public_key().to_sec1()))
}

fn p384_ecdsa_sign() -> String {
    let sk = BoxedEcdsaPrivateKey::from_bytes(CurveId::P384, &secret_bytes::<48>(114))
        .expect("scalar in range");
    let sig = sk.sign::<Sha384>(b"ct_valgrind message").unwrap();
    let sig = sig.to_bytes(CurveId::P384);
    format!("sig={}", hex8(public(&sig[..])))
}

fn p384_ecdh() -> String {
    let sk = BoxedEcdhPrivateKey::from_bytes(CurveId::P384, &secret_bytes::<48>(115))
        .expect("scalar in range");
    let peer = BoxedEcdhPrivateKey::from_bytes(CurveId::P384, &fixed_bytes::<48>(116))
        .unwrap()
        .public_key();
    let shared = sk.diffie_hellman(&peer).expect("valid peer");
    format!("ss={}", hex8(public(&shared[..])))
}

fn sm2_sign() -> String {
    let sk = Sm2PrivateKey::from_bytes(&secret_bytes::<32>(117)).expect("scalar in range");
    let sig = sk
        .sign(
            b"ct_valgrind message",
            b"1234567812345678",
            &mut TaintRng::new(118),
        )
        .unwrap();
    let sig = sig.to_bytes();
    format!("sig={}", hex8(public(&sig[..])))
}

fn ffdh_group14() -> String {
    let sk = DhPrivateKey::from_bytes(group14(), &secret_bytes::<32>(119)).expect("in range");
    let peer = DhPrivateKey::from_bytes(group14(), &fixed_bytes::<32>(120))
        .unwrap()
        .public_key();
    let shared = sk.shared_secret(&peer).expect("valid peer");
    format!("ss={}", hex8(public(shared.as_bytes())))
}

fn secp256k1_ecdsa_sign() -> String {
    let sk =
        Secp256k1EcdsaPrivateKey::from_bytes(&secret_bytes::<32>(40)).expect("scalar in range");
    let pk = sk.public_key().to_sec1();
    let sig = sk
        .sign::<Sha256>(b"ct_valgrind message")
        .unwrap()
        .to_bytes();
    format!("pk={} sig={}", hex8(public(&pk)), hex8(public(&sig)))
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

const RSA_PEM: &str = include_str!("../testdata/rsa2048_test_a.pem");

/// The fixed 2048-bit test key, rebuilt with its private components (`d`,
/// `p`, `q`) classified secret. `n` and `e` stay public.
fn rsa_key() -> BoxedRsaPrivateKey {
    let parsed = BoxedRsaPrivateKey::from_pkcs1_pem(RSA_PEM).expect("test key parses");
    let (p, q) = parsed.primes().expect("test key has primes");
    BoxedRsaPrivateKey::from_components_with_primes(
        parsed.modulus().clone(),
        parsed.public_key().exponent().clone(),
        secret_uint(parsed.private_exponent()),
        secret_uint(p),
        secret_uint(q),
    )
}

fn rsa2048_pss_sign() -> String {
    let key = rsa_key();
    // The PSS salt is public: anyone holding the signature and the public
    // key recovers it (RFC 8017 §9.1.2), so it is drawn from the public RNG.
    let sig = key
        .sign_pss::<Sha256, _>(b"ct_valgrind message", &mut public_rng(50))
        .expect("sign");
    declassify(&sig);
    key.public_key()
        .verify_pss::<Sha256>(b"ct_valgrind message", &sig)
        .expect("signature verifies");
    hex8(&sig)
}

fn rsa2048_oaep_decrypt() -> String {
    let key = rsa_key();
    let msg = fixed_bytes::<48>(51);
    let ct = key
        .public_key()
        .encrypt_oaep::<Sha256, _>(&msg, b"label", &mut public_rng(52))
        .expect("encrypt");
    let pt = key.decrypt_oaep::<Sha256>(&ct, b"label").expect("decrypt");
    declassify(&pt);
    assert_eq!(pt, msg);
    let mut bad = ct.clone();
    bad[100] ^= 0x01;
    let rejected = key.decrypt_oaep::<Sha256>(&bad, b"label").is_err();
    assert!(rejected);
    format!("pt={} tampered-rejected={rejected}", hex8(&pt))
}

fn rsa2048_pkcs1v15_implicit() -> String {
    let key = rsa_key();
    let msg = fixed_bytes::<48>(53);
    let ct = key
        .public_key()
        .encrypt_pkcs1v15(&msg, &mut public_rng(54))
        .expect("encrypt");
    let pt = key.decrypt_pkcs1v15_implicit(&ct).expect("decrypt");
    declassify(&pt);
    assert_eq!(pt, msg);
    // A ciphertext that does not decrypt to valid padding: the implicit
    // rejection path returns a synthetic message instead of an error.
    let mut bad = ct.clone();
    bad[0] ^= 0x01;
    let synthetic = key.decrypt_pkcs1v15_implicit(&bad).expect("no error");
    declassify(&synthetic);
    assert_ne!(synthetic, msg);
    format!("pt={} synthetic={}", hex8(&pt), hex8(&synthetic))
}

fn rsa2048_pkcs1v15_explicit() -> String {
    let key = rsa_key();
    let msg = fixed_bytes::<48>(56);
    let ct = key
        .public_key()
        .encrypt_pkcs1v15(&msg, &mut public_rng(57))
        .expect("encrypt");
    let pt = key.decrypt_pkcs1v15(&ct).expect("decrypt");
    declassify(&pt);
    assert_eq!(pt, msg);
    // The explicit-error API: the verdict is its (public) result.
    let mut bad = ct.clone();
    bad[0] ^= 0x01;
    let rejected = key.decrypt_pkcs1v15(&bad).is_err();
    format!("pt={} tampered-rejected={rejected}", hex8(&pt))
}

fn rsa2048_pkcs1v15_session() -> String {
    let key = rsa_key();
    let msg = fixed_bytes::<48>(58);
    let ct = key
        .public_key()
        .encrypt_pkcs1v15(&msg, &mut public_rng(59))
        .expect("encrypt");
    // TLS 1.2 RSA key transport: fixed expected length, synthetic output on
    // any padding failure.
    let pt = key.decrypt_pkcs1v15_session(&ct, 48).expect("decrypt");
    declassify(&pt);
    assert_eq!(pt, msg);
    let mut bad = ct.clone();
    bad[0] ^= 0x01;
    let synthetic = key.decrypt_pkcs1v15_session(&bad, 48).expect("no error");
    declassify(&synthetic);
    assert_ne!(synthetic, msg);
    format!("pt={} synthetic={}", hex8(&pt), hex8(&synthetic))
}

fn rsa2048_keygen() -> String {
    let mut rng = TaintRng::new(55);
    let key = BoxedRsaPrivateKey::generate(2048, BoxedUint::from_u64(65537), &mut rng, 0);
    let n = key.modulus().to_be_bytes(256);
    hex8(public(&n[..]))
}

// ---------------------------------------------------------------------------
// Post-quantum
// ---------------------------------------------------------------------------

fn mlkem768_keygen() -> String {
    let d = secret_bytes::<32>(60);
    let z = secret_bytes::<32>(61);
    let (_dk, ek) = MlKem768DecapsKey::from_seeds(&d, &z);
    hex8(public(&ek.to_bytes()[..]))
}

/// ML-KEM-768 decapsulation key from public seeds, re-imported with its
/// secret parts (`dk_PKE` and the implicit-rejection seed `z`) classified;
/// the embedded `ek` and `H(ek)` are public.
fn mlkem768_dk() -> (MlKem768DecapsKey, purecrypto::mlkem::MlKem768EncapsKey) {
    let (dk, ek) = MlKem768DecapsKey::from_seeds(&fixed_bytes::<32>(62), &fixed_bytes::<32>(63));
    let bytes = dk.to_bytes();
    let dk = MlKem768DecapsKey::from_bytes(bytes);
    let raw = dk.to_bytes();
    // `to_bytes` copies, so classify the copy we re-import.
    classify(&raw[..1152]);
    classify(&raw[raw.len() - 32..]);
    (MlKem768DecapsKey::from_bytes(raw), ek)
}

fn mlkem768_encaps() -> String {
    let (_dk, ek) = MlKem768DecapsKey::from_seeds(&fixed_bytes::<32>(66), &fixed_bytes::<32>(67));
    let (ct, ss) = ek.encapsulate(&mut TaintRng::new(68));
    let ct = ct.to_bytes();
    format!("ct={} ss={}", hex8(public(&ct[..])), hex8(public(&ss)))
}

fn mlkem768_decaps() -> String {
    let (dk, ek) = mlkem768_dk();
    let (ct, ss) = ek.encapsulate_deterministic(&fixed_bytes::<32>(64));
    let got = dk.decapsulate(&ct);
    declassify(&got);
    assert_eq!(got, ss);
    hex8(&got)
}

fn mlkem768_decaps_implicit_reject() -> String {
    let (dk, ek) = mlkem768_dk();
    let (ct, ss) = ek.encapsulate_deterministic(&fixed_bytes::<32>(65));
    let mut raw = ct.to_bytes();
    raw[7] ^= 0x10;
    let got = dk.decapsulate(&MlKem768Ciphertext::from_bytes(raw));
    declassify(&got);
    assert_ne!(got, ss);
    hex8(&got)
}

fn mlkem512_1024() -> String {
    let (dk, ek) =
        MlKem512DecapsKey::from_seeds(&secret_bytes::<32>(140), &secret_bytes::<32>(141));
    let (ct, ss) = ek.encapsulate_deterministic(&fixed_bytes::<32>(142));
    let got = dk.decapsulate(&ct);
    // `ek` derives from the secret seed here, so `ss` is tainted too.
    declassify(&got);
    declassify(&ss);
    assert_eq!(got, ss);
    let (dk, ek) =
        MlKem1024DecapsKey::from_seeds(&secret_bytes::<32>(143), &secret_bytes::<32>(144));
    let (ct, ss) = ek.encapsulate_deterministic(&fixed_bytes::<32>(145));
    let got2 = dk.decapsulate(&ct);
    declassify(&got2);
    declassify(&ss);
    assert_eq!(got2, ss);
    format!("ss512={} ss1024={}", hex8(&got), hex8(&got2))
}

fn mldsa44_87_sign() -> String {
    let (sk, pk) = MlDsa44PrivateKey::from_seed(&secret_bytes::<32>(146));
    let sig = sk.sign_deterministic(b"ct_valgrind message", b"").unwrap();
    declassify(&sig);
    declassify(pk.to_bytes());
    assert!(pk.verify(&sig, b"ct_valgrind message", b""));
    let (sk, pk) = MlDsa87PrivateKey::from_seed(&secret_bytes::<32>(147));
    let sig2 = sk.sign_deterministic(b"ct_valgrind message", b"").unwrap();
    declassify(&sig2);
    declassify(pk.to_bytes());
    assert!(pk.verify(&sig2, b"ct_valgrind message", b""));
    format!("sig44={} sig87={}", hex8(&sig), hex8(&sig2))
}

fn mldsa65_keygen() -> String {
    let (_sk, pk) = MlDsa65PrivateKey::from_seed(&secret_bytes::<32>(70));
    hex8(public(pk.to_bytes()))
}

/// ML-DSA-65 key with its secret parts classified. The encoded private key is
/// `rho ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0`; `rho` (the matrix seed) and `tr = H(pk)`
/// are public — they are, or are derived only from, the public key.
fn mldsa65_sk() -> (MlDsa65PrivateKey, purecrypto::mldsa::MlDsa65PublicKey) {
    let (sk, pk) = MlDsa65PrivateKey::from_seed(&fixed_bytes::<32>(71));
    let bytes = sk.to_bytes();
    classify(&bytes[32..64]);
    classify(&bytes[128..]);
    (sk, pk)
}

fn mldsa65_sign_deterministic() -> String {
    let (sk, pk) = mldsa65_sk();
    let sig = sk.sign_deterministic(b"ct_valgrind message", b"").unwrap();
    declassify(&sig);
    assert!(pk.verify(&sig, b"ct_valgrind message", b""));
    hex8(&sig)
}

fn mldsa65_sign_hedged() -> String {
    let (sk, pk) = mldsa65_sk();
    let sig = sk
        .sign(&mut TaintRng::new(72), b"ct_valgrind message", b"ctx")
        .unwrap();
    declassify(&sig);
    assert!(pk.verify(&sig, b"ct_valgrind message", b"ctx"));
    hex8(&sig)
}

fn slhdsa_case(set: ParamSet, tag: u64) -> String {
    let sk_seed = secret_bytes::<16>(tag);
    let sk_prf = secret_bytes::<16>(tag + 1);
    let pk_seed = fixed_bytes::<16>(tag + 2);
    let (sk, pk) = slhdsa::PrivateKey::from_seeds(set, &sk_seed, &sk_prf, &pk_seed);
    // `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`: the root is the public key.
    declassify(&sk.to_bytes()[48..64]);
    declassify(pk.to_bytes());
    let sig = sk.sign_deterministic(b"ct_valgrind message", b"").unwrap();
    declassify(&sig);
    assert!(pk.verify(&sig, b"ct_valgrind message", b""));
    format!("pk={} sig={}", hex8(pk.to_bytes()), hex8(&sig))
}

fn slhdsa_sha2_128f() -> String {
    slhdsa_case(ParamSet::Sha2_128f, 80)
}

fn slhdsa_shake_128f() -> String {
    slhdsa_case(ParamSet::Shake_128f, 90)
}

// ---------------------------------------------------------------------------
// Positive control
// ---------------------------------------------------------------------------

/// Deliberately variable-time: a branch and a table index on a secret byte.
/// memcheck must report both; CI fails if it does not.
#[inline(never)]
fn positive_control() -> u32 {
    let secret = secret_bytes::<16>(99);
    let table: [u32; 256] = core::array::from_fn(|i| (i as u32).wrapping_mul(2654435761));
    let mut acc = 0u32;
    // An opaque call on one arm, so LLVM cannot turn the branch into a
    // conditional select (which memcheck, correctly, would not flag).
    if black_box(secret[0]) == 0x42 {
        acc ^= black_box(control_side_effect)(acc);
    }
    acc ^= black_box(table)[black_box(secret[1]) as usize];
    ct::declassify_value(acc)
}

#[inline(never)]
fn control_side_effect(x: u32) -> u32 {
    println!("positive control: secret branch taken");
    x.wrapping_add(1)
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

type Case = (&'static str, fn() -> String);

const CASES: &[Case] = &[
    ("ct_primitives", ct_primitives),
    ("aes128_block", aes128_block),
    ("aes256_block", aes256_block),
    ("aes192_block", aes192_block),
    ("camellia128_block", camellia128_block),
    ("aria128_block", aria128_block),
    ("sm4_block", sm4_block),
    ("aes128_gcm", aes128_gcm),
    ("aes256_gcm", aes256_gcm),
    ("chacha20_poly1305", chacha20_poly1305),
    ("xchacha20_poly1305", xchacha20_poly1305),
    ("aes256_gcm_siv", aes256_gcm_siv),
    ("aes128_ccm", aes128_ccm),
    ("aes128_eax", aes128_eax),
    ("aegis128l", aegis128l),
    ("ascon_aead128", ascon_aead128),
    ("aes_cmac", aes_cmac),
    ("kmac128", kmac128),
    ("siphash24", siphash24),
    ("poly1305", poly1305),
    ("hmac_sha256", hmac_sha256),
    ("hmac_sha512", hmac_sha512),
    ("hkdf_sha256", hkdf_sha256),
    ("pbkdf2_sha256", pbkdf2_sha256),
    ("argon2i", argon2i),
    ("sha2", sha2),
    ("sha3_shake", sha3_shake),
    ("blake2b_sm3", blake2b_sm3),
    ("blake3", blake3),
    ("hpke_x25519_chacha", hpke_x25519_chacha),
    ("hpke_p256_aes128gcm", hpke_p256_aes128gcm),
    ("bls12381_sign", bls12381_sign),
    ("lms_h5_sign", lms_h5_sign),
    ("x25519", x25519),
    ("x448", x448),
    ("ed25519_sign", ed25519_sign),
    ("ed448_sign", ed448_sign),
    ("p256_ecdsa_sign", p256_ecdsa_sign),
    ("p256_ecdh", p256_ecdh),
    ("p256_keygen", p256_keygen),
    ("secp256k1_ecdsa_sign", secp256k1_ecdsa_sign),
    ("p384_ecdsa_sign", p384_ecdsa_sign),
    ("p384_ecdh", p384_ecdh),
    ("sm2_sign", sm2_sign),
    ("ffdh_group14", ffdh_group14),
    ("rsa2048_pss_sign", rsa2048_pss_sign),
    ("rsa2048_oaep_decrypt", rsa2048_oaep_decrypt),
    ("rsa2048_pkcs1v15_implicit", rsa2048_pkcs1v15_implicit),
    ("rsa2048_pkcs1v15_explicit", rsa2048_pkcs1v15_explicit),
    ("rsa2048_pkcs1v15_session", rsa2048_pkcs1v15_session),
    ("rsa2048_keygen", rsa2048_keygen),
    ("mlkem768_keygen", mlkem768_keygen),
    ("mlkem768_encaps", mlkem768_encaps),
    ("mlkem768_decaps", mlkem768_decaps),
    (
        "mlkem768_decaps_implicit_reject",
        mlkem768_decaps_implicit_reject,
    ),
    ("mlkem512_1024", mlkem512_1024),
    ("mldsa44_87_sign", mldsa44_87_sign),
    ("mldsa65_keygen", mldsa65_keygen),
    ("mldsa65_sign_deterministic", mldsa65_sign_deterministic),
    ("mldsa65_sign_hedged", mldsa65_sign_hedged),
    ("slhdsa_sha2_128f", slhdsa_sha2_128f),
    ("slhdsa_shake_128f", slhdsa_shake_128f),
];

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let on_valgrind = ct::running_on_valgrind();
    println!(
        "ct_valgrind: {} ({})",
        if on_valgrind != 0 {
            "running under Valgrind"
        } else {
            "running natively (client requests are no-ops)"
        },
        std::env::consts::ARCH
    );
    if std::env::var_os("CT_REQUIRE_VALGRIND").is_some_and(|v| v == "1") && on_valgrind == 0 {
        eprintln!("ct_valgrind: CT_REQUIRE_VALGRIND=1 but not running under Valgrind");
        std::process::exit(2);
    }

    if args.iter().any(|a| a == "--list") {
        for (name, _) in CASES {
            println!("{name}");
        }
        return;
    }
    if args.iter().any(|a| a == "--positive-control") {
        let v = positive_control();
        println!("positive control ran (acc={v:08x}); memcheck must have reported it");
        return;
    }

    // `cargo test` passes libtest flags such as `--nocapture`; ignore them.
    let filters: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    let total = Instant::now();
    let mut ran = 0;
    for (name, case) in CASES {
        if !filters.is_empty() && !filters.iter().any(|f| name.contains(f.as_str())) {
            continue;
        }
        // Marks where each case starts in the interleaved memcheck log.
        println!("-- {name}");
        let t = Instant::now();
        let out = case();
        println!(
            "ok {name:<34} {:>9.1} ms  {out}",
            t.elapsed().as_secs_f64() * 1e3
        );
        ran += 1;
    }
    println!(
        "ct_valgrind: {ran} case(s) in {:.1} s",
        total.elapsed().as_secs_f64()
    );
    assert!(ran > 0, "no case matched the filter");
}
