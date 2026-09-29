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
//! runs it under memcheck on x86_64, aarch64, i686 and armv7 Linux — the
//! 64-bit targets both with the CPU dispatch they detect (AES-NI / PMULL /
//! AVX2 / SHA extensions) and with every dispatch site forced onto its
//! portable kernel (`PURECRYPTO_CT_FORCE_PORTABLE=1`, see
//! `ct::force_portable`), and once more built without the precomputed
//! Ed25519 / P-256 base-point tables.
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
//! (keys, seeds, plaintexts, traffic secrets), through [`TaintRng`] — an
//! HMAC-DRBG whose every output byte is classified, so key generation and
//! hedged signing see secret randomness exactly as they would from `OsRng` —
//! or by classifying the secret parts of an imported key (RSA limbs, a JWK's
//! private fields, a Falcon key's expanded buffers through
//! `ct::hooks::falcon_classify_private_key`). Public halves of a key (an
//! ML-DSA `rho`/`tr`, an SLH-DSA `PK.root`, an XMSS `PUB_SEED`) are
//! declassified by the harness, because they *are* the public key, and
//! randomness that is published (a PSS salt, an LM-OTS randomizer, a Falcon
//! salt) comes from a public RNG. The declassification points inside the
//! library are listed in `docs/validation.md` ("Declassification points").
//!
//! The protocol record layers and key schedules (TLS 1.2/1.3, DTLS 1.2/1.3,
//! QUIC) are reached through `purecrypto::ct::hooks`, thin `__ct-check`-only
//! entry points into the crate-private code (a handshake would drag public
//! values through the same paths).
//!
//! Deliberately NOT covered — accepted variable-time residuals documented in
//! `docs/validation.md`, which this harness would (correctly) flag:
//!
//! * legacy CBC / MAC-then-encrypt record protection (`tls-legacy`, Lucky13
//!   residue), PBES2 CBC-PAD and the PKCS#12 archives built on it;
//! * DES/3DES and Blowfish / `bcrypt_pbkdf` (key-dependent S-box tables), and
//!   the table-driven hashes (Streebog, Whirlpool, MD2, ...);
//! * Falcon key generation and secret-key import (variable-time NTRU solve);
//! * Argon2d/Argon2id data-dependent addressing and scrypt's `Integerify`;
//! * FF1's radix arithmetic on the digits (data-dependent by construction).
//!
//! Also not covered: the `halfagg` module (no secret inputs).

use std::hint::black_box;
use std::time::Instant;

use purecrypto::ct::{
    self, Choice, ConditionallyNegatable, ConditionallySelectable, ConstantTimeEq,
    ConstantTimeGreater, ConstantTimeLess, classify, declassify,
};
use purecrypto::rng::{CryptoRng, HmacDrbg, RngCore};

use purecrypto::ct::hooks::{self, Suite};

use purecrypto::ascon::{Ascon128, Ascon128a, AsconAead128};
use purecrypto::bignum::BoxedUint;
use purecrypto::bls;
use purecrypto::chunked::{self, Cobblestone128};
use purecrypto::cipher::{
    Aegis128, Aegis128L, Aes128, Aes128Ccm, Aes128Eax, Aes128Kw, Aes128Kwp, Aes128Xts, Aes192,
    Aes256, Aes256GcmSiv, AesCmac128, AesSiv, Aez, Aria128, BlockCipher, Camellia128, Cbc, Cfb,
    ChaCha20Poly1305, Ctr, Gcm, Gmac, Morus640, Morus1280, Ofb, Poly1305, Seed, Sm4,
    XChaCha20Poly1305, kwp_ciphertext_len,
};
use purecrypto::dh::{DhPrivateKey, group14};
use purecrypto::dsa::{self, DsaPrivateKey};
use purecrypto::ec::CurveId;
use purecrypto::ec::boxed::{BoxedEcdhPrivateKey, BoxedEcdsaPrivateKey};
use purecrypto::ec::ecdh::EcdhPrivateKey;
use purecrypto::ec::ecdsa::EcdsaPrivateKey;
use purecrypto::ec::ed448::Ed448PrivateKey;
use purecrypto::ec::ed25519::Ed25519PrivateKey;
use purecrypto::ec::ristretto255::{RistrettoPoint, Scalar as RistrettoScalar};
use purecrypto::ec::secp256k1::Scalar as Secp256k1Scalar;
use purecrypto::ec::secp256k1::schnorr;
use purecrypto::ec::secp256k1_ecdsa::Secp256k1EcdsaPrivateKey;
use purecrypto::ec::sm2::Sm2PrivateKey;
use purecrypto::ec::x448::X448PrivateKey;
use purecrypto::ec::x25519::X25519PrivateKey;
use purecrypto::falcon::{Degree as FalconDegree, FalconPrivateKey};
use purecrypto::hash::{
    Blake2b512, Blake3, Digest, HmacSha256, HmacSha512, Kmac128, Sha3_256, Sha256, Sha384, Sha512,
    Shake128, Sm3, shake256,
};
use purecrypto::hpke::{self, CipherSuite, HpkeAead, HpkeKdf, HpkeKem};
use purecrypto::jose::{Enc, Jwe, Jwk, JwkKey, Jws, KeyAlg, SigAlg};
use purecrypto::kdf::argon2::{Argon2Params, Argon2Type, argon2};
use purecrypto::kdf::pbes2::{self, CipherChoice, KdfChoice, Pbes2Params};
use purecrypto::kdf::{HmacSha256Prf, hkdf, kbkdf_counter, pbkdf2};
use purecrypto::lms::{HssPrivateKey, LmotsType, LmsPrivateKey, LmsType};
use purecrypto::mac::{SipHash24, Umac64, Umac128, Vmac64, Vmac128};
use purecrypto::mldsa::{MlDsa44PrivateKey, MlDsa65PrivateKey, MlDsa87PrivateKey};
use purecrypto::mlkem::{
    MlKem512DecapsKey, MlKem768Ciphertext, MlKem768DecapsKey, MlKem1024DecapsKey,
};
use purecrypto::rsa::BoxedRsaPrivateKey;
use purecrypto::slhdsa::{self, ParamSet};
use purecrypto::xmss::{XmssMtParamSet, XmssMtPrivateKey, XmssParamSet, XmssPrivateKey};
use purecrypto::zkp::pedersen::{Commitment, Generator};
use purecrypto::zkp::sign_to_contract as s2c;
use purecrypto::zkp::surjection::SurjectionProof;
use purecrypto::zkp::{adaptor, rangeproof, whitelist};

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

fn slhdsa_sha2_128s() -> String {
    slhdsa_case(ParamSet::Sha2_128s, 150)
}

/// Falcon-512 signing with the expanded key's buffers classified.
/// Key generation (the variable-time NTRU solve) runs on public randomness
/// first: it is the documented residual, not what this case checks.
fn falcon512_sign() -> String {
    let sk = FalconPrivateKey::generate(FalconDegree::Falcon512, &mut public_rng(160));
    let pk = sk.public_key();
    hooks::falcon_classify_private_key(&sk);
    let sig = sk.sign(b"ct_valgrind message", &mut SaltPublicRng::new(161));
    declassify(&sig);
    assert!(
        pk.verify(b"ct_valgrind message", &sig)
            .expect("well-formed")
    );
    format!("sig={}", hex8(&sig))
}

/// An RNG whose first `fill_bytes` call (Falcon's 40-byte salt `r`, which
/// is published in the signature and hashed with the message into the public
/// target point) is public and every later byte (the Gaussian sampler's
/// randomness) secret.
struct SaltPublicRng {
    rng: TaintRng,
    salt_drawn: bool,
}

impl SaltPublicRng {
    fn new(tag: u64) -> Self {
        SaltPublicRng {
            rng: TaintRng::new(tag),
            salt_drawn: false,
        }
    }
}

impl RngCore for SaltPublicRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
        if !self.salt_drawn {
            self.salt_drawn = true;
            declassify(dest);
        }
    }
}

impl CryptoRng for SaltPublicRng {}

fn xmss_sign() -> String {
    // SK_SEED ‖ SK_PRF ‖ PUB_SEED: the last third is public-key material.
    let seed = secret_bytes::<96>(170);
    declassify(&seed[64..]);
    let mut sk = XmssPrivateKey::from_seed(XmssParamSet::Sha2_10_256, &seed);
    let pk = sk.public_key();
    declassify(pk.to_bytes());
    let sig = sk.sign(b"ct_valgrind message").expect("fresh key");
    declassify(&sig);
    assert!(pk.verify(b"ct_valgrind message", &sig));
    format!("pk={} sig={}", hex8(pk.to_bytes()), hex8(&sig))
}

fn xmssmt_sign() -> String {
    let seed = secret_bytes::<96>(171);
    declassify(&seed[64..]);
    let mut sk = XmssMtPrivateKey::from_seed(XmssMtParamSet::Sha2_20_2_256, &seed);
    let pk = sk.public_key();
    declassify(pk.to_bytes());
    let sig = sk.sign(b"ct_valgrind message").expect("fresh key");
    declassify(&sig);
    assert!(pk.verify(b"ct_valgrind message", &sig));
    format!("pk={} sig={}", hex8(pk.to_bytes()), hex8(&sig))
}

fn hss_l2_sign() -> String {
    let levels = [
        (
            LmsType::Sha256M32H5,
            LmotsType::Sha256N32W4,
            fixed_bytes::<16>(172),
            secret_bytes::<32>(173),
        ),
        (
            LmsType::Sha256M32H5,
            LmotsType::Sha256N32W4,
            fixed_bytes::<16>(174),
            secret_bytes::<32>(175),
        ),
    ];
    let mut sk = HssPrivateKey::from_levels(&levels).expect("valid levels");
    let pk = sk.public_key();
    declassify(pk.to_bytes());
    // The LM-OTS randomizers are published in the signature (see lms_h5).
    let sig = sk
        .sign(&mut public_rng(176), b"ct_valgrind message")
        .expect("fresh key");
    declassify(&sig);
    assert!(pk.verify(b"ct_valgrind message", &sig));
    format!("pk={} sig={}", hex8(pk.to_bytes()), hex8(&sig))
}

// ---------------------------------------------------------------------------
// Protocol record layers and key schedules (through `ct::hooks`)
// ---------------------------------------------------------------------------

const SUITES: [Suite; 3] = [
    Suite::Aes128GcmSha256,
    Suite::Aes256GcmSha384,
    Suite::ChaCha20Poly1305Sha256,
];

/// The suite's hash length: the length of its traffic secrets.
fn hash_len(suite: Suite) -> usize {
    if suite == Suite::Aes256GcmSha384 {
        48
    } else {
        32
    }
}

/// The suite's AEAD key length.
fn key_len(suite: Suite) -> usize {
    if suite == Suite::Aes128GcmSha256 {
        16
    } else {
        32
    }
}

/// A copy of `v`, marked public, for comparing a secret against a result.
fn public_copy<const N: usize>(v: &[u8; N]) -> [u8; N] {
    let out = *v;
    declassify(&out);
    out
}

fn tls13_key_schedule() -> String {
    let mut out = Vec::new();
    for (i, suite) in SUITES.into_iter().enumerate() {
        let n = hash_len(suite);
        let tag = 200 + 10 * i as u64;
        let ecdhe = secret_bytes::<32>(tag);
        let psk = secret_bytes::<48>(tag + 1);
        // Transcript hashes are public.
        let th = fixed_bytes::<144>(tag + 2);
        let ks = hooks::tls::tls13_key_schedule(
            suite,
            (i != 0).then_some(&psk[..n]),
            false,
            Some(&ecdhe),
            &th[..n],
            &th[48..48 + n],
            &th[96..96 + n],
        );
        out.push(hex8(public(&ks[..])));
        let next = hooks::tls::tls13_next_traffic_secret(suite, &ks[..n]);
        out.push(hex8(public(&next[..])));
        // RFC 8446 §4.2.9 `psk_ke` (no (EC)DHE input, §7.1 zero string)
        // with an external PSK (§4.2.11, `"ext binder"`): the PSK is then
        // the only secret in the schedule.
        let ks = hooks::tls::tls13_key_schedule(
            suite,
            Some(&psk[..n]),
            true,
            None,
            &th[..n],
            &th[48..48 + n],
            &th[96..96 + n],
        );
        out.push(hex8(public(&ks[..])));
    }
    out.join(" ")
}

fn tls13_finished() -> String {
    let mut out = Vec::new();
    for (i, suite) in SUITES.into_iter().enumerate() {
        let n = hash_len(suite);
        let key = secret_bytes::<48>(230 + i as u64);
        let th = fixed_bytes::<48>(235 + i as u64);
        let (vd, _) = hooks::tls::tls13_finished(suite, &key[..n], &th[..n], &[]);
        declassify(&vd);
        let (_, ok) = hooks::tls::tls13_finished(suite, &key[..n], &th[..n], &vd);
        let mut bad = vd.clone();
        bad[n - 1] ^= 1;
        let (_, rejected) = hooks::tls::tls13_finished(suite, &key[..n], &th[..n], &bad);
        // The verdicts are the public outcome the engines branch on.
        assert!(bool::from(ct::declassify_value(ok)));
        assert!(!bool::from(ct::declassify_value(rejected)));
        out.push(hex8(&vd));
    }
    out.join(" ")
}

fn tls13_record_case(suite: Suite, tag: u64) -> String {
    let secret = secret_bytes::<48>(tag);
    let secret = &secret[..hash_len(suite)];
    let content = secret_bytes::<300>(tag + 1);
    let expected = public_copy(&content);

    let rec = hooks::tls::tls13_seal(suite, secret, 23, &content, 0).expect("seal");
    declassify(&rec);
    let (ty, got) = hooks::tls::tls13_open(suite, secret, &rec).expect("authentic record");
    declassify(&got);
    assert_eq!((ty, &got[..]), (23, &expected[..]));

    // RFC 8446 §5.4 padding: the receiver must find the type byte under it
    // without its position showing in the timing.
    let padded = hooks::tls::tls13_seal(suite, secret, 22, &content[..100], 157).expect("seal");
    declassify(&padded);
    let (ty2, got2) = hooks::tls::tls13_open(suite, secret, &padded).expect("authentic record");
    declassify(&got2);
    assert_eq!((ty2, &got2[..]), (22, &expected[..100]));

    let mut bad = rec.clone();
    bad[40] ^= 0x04;
    assert!(hooks::tls::tls13_open(suite, secret, &bad).is_err());
    format!("rec={} padded={}", hex8(&rec[5..]), hex8(&padded[5..]))
}

fn tls13_record_aes128() -> String {
    tls13_record_case(Suite::Aes128GcmSha256, 240)
}

fn tls13_record_aes256() -> String {
    tls13_record_case(Suite::Aes256GcmSha384, 243)
}

fn tls13_record_chacha() -> String {
    tls13_record_case(Suite::ChaCha20Poly1305Sha256, 246)
}

fn tls12_prf_finished() -> String {
    let mut out = Vec::new();
    for (i, suite) in [Suite::Aes128GcmSha256, Suite::Aes256GcmSha384]
        .into_iter()
        .enumerate()
    {
        let tag = 250 + 10 * i as u64;
        let premaster = secret_bytes::<48>(tag);
        let cr = fixed_bytes::<32>(tag + 1);
        let sr = fixed_bytes::<32>(tag + 2);
        let session_hash = fixed_bytes::<48>(tag + 3);
        let n = hash_len(suite);
        let classic = hooks::tls::tls12_key_block(suite, &premaster, &cr, &sr, None);
        let ems =
            hooks::tls::tls12_key_block(suite, &premaster, &cr, &sr, Some(&session_hash[..n]));
        let mut master = [0u8; 48];
        master.copy_from_slice(&ems[..48]);
        let (vd, _) =
            hooks::tls::tls12_finished(suite, &master, b"client finished", &session_hash[..n], &[]);
        declassify(&vd);
        let (_, ok) =
            hooks::tls::tls12_finished(suite, &master, b"client finished", &session_hash[..n], &vd);
        let mut bad = vd;
        bad[0] ^= 0x20;
        let (_, rejected) = hooks::tls::tls12_finished(
            suite,
            &master,
            b"client finished",
            &session_hash[..n],
            &bad,
        );
        assert!(bool::from(ct::declassify_value(ok)));
        assert!(!bool::from(ct::declassify_value(rejected)));
        out.push(format!(
            "kb={} ems-kb={} fin={}",
            hex8(public(&classic[48..])),
            hex8(public(&ems[48..])),
            hex8(&vd)
        ));
    }
    out.join(" ")
}

fn tls12_records() -> String {
    let mut out = Vec::new();
    for (i, suite) in SUITES.into_iter().enumerate() {
        let tag = 270 + 10 * i as u64;
        let key = secret_bytes::<32>(tag);
        let key = &key[..key_len(suite)];
        // The write IV comes from the key block: secret. A 4-byte GCM salt
        // or the 12-byte ChaCha20-Poly1305 IV (RFC 7905 §2).
        let iv = secret_bytes::<12>(tag + 1);
        let iv = &iv[..hooks::tls::tls12_fixed_iv_len(suite)];
        let payload = secret_bytes::<200>(tag + 2);
        let expected = public_copy(&payload);
        let frag = hooks::tls::tls12_seal(suite, key, iv, 23, &payload).expect("seal");
        declassify(&frag);
        // GCM fragments carry the 8-byte explicit nonce; ChaCha20's do not.
        let explicit = hooks::tls::tls12_record_iv_len(suite);
        assert_eq!(frag.len(), explicit + payload.len() + 16);
        let len = (frag.len() as u16).to_be_bytes();
        let header = [23, 3, 3, len[0], len[1]];
        let got = hooks::tls::tls12_open(suite, key, iv, &header, &frag).expect("authentic");
        declassify(&got);
        assert_eq!(got, expected);
        let mut bad = frag.clone();
        bad[30] ^= 1;
        assert!(hooks::tls::tls12_open(suite, key, iv, &header, &bad).is_err());
        out.push(hex8(&frag[explicit..]));
    }
    out.join(" ")
}

fn dtls12_records() -> String {
    let mut out = Vec::new();
    for (i, suite) in SUITES.into_iter().enumerate() {
        let tag = 300 + 10 * i as u64;
        let key = secret_bytes::<32>(tag);
        let key = &key[..key_len(suite)];
        let iv = secret_bytes::<12>(tag + 1);
        let iv = &iv[..hooks::tls::tls12_fixed_iv_len(suite)];
        let payload = secret_bytes::<150>(tag + 2);
        let expected = public_copy(&payload);
        let epoch_seq = (1u64 << 48) | 0x2a;
        let frag = hooks::dtls::dtls12_seal(suite, key, iv, epoch_seq, 23, &payload).expect("seal");
        declassify(&frag);
        let explicit = hooks::tls::tls12_record_iv_len(suite);
        assert_eq!(frag.len(), explicit + payload.len() + 16);
        let got =
            hooks::dtls::dtls12_open(suite, key, iv, epoch_seq, 23, &frag).expect("authentic");
        declassify(&got);
        assert_eq!(got, expected);
        let mut bad = frag.clone();
        bad[frag.len() - 1] ^= 1;
        assert!(hooks::dtls::dtls12_open(suite, key, iv, epoch_seq, 23, &bad).is_err());
        out.push(hex8(&frag[explicit..]));
    }
    out.join(" ")
}

fn dtls13_records() -> String {
    let mut out = Vec::new();
    for (i, suite) in SUITES.into_iter().enumerate() {
        let tag = 330 + 10 * i as u64;
        let secret = secret_bytes::<48>(tag);
        let secret = &secret[..hash_len(suite)];
        let payload = secret_bytes::<150>(tag + 1);
        let expected = public_copy(&payload);
        let (epoch, seq) = (3u16, 0x1234u64);
        let wire =
            hooks::dtls::dtls13_seal(suite, secret, epoch, seq, &[], 23, &payload).expect("seal");
        declassify(&wire);
        let (got_seq, ty, got) =
            hooks::dtls::dtls13_open(suite, secret, epoch, seq - 1, 0, &wire).expect("authentic");
        declassify(&got);
        assert_eq!((got_seq, ty, &got[..]), (seq, 23, &expected[..]));
        let mut bad = wire.clone();
        bad[20] ^= 1;
        assert!(hooks::dtls::dtls13_open(suite, secret, epoch, seq - 1, 0, &bad).is_err());
        out.push(hex8(&wire));
    }
    out.join(" ")
}

/// DTLS 1.2 records carrying a connection ID (RFC 9146 §4, §5.3): the
/// `DTLSInnerPlaintext` wrapping, the CID additional data, and the
/// constant-time strip of the inner content type and padding on the way
/// back. The CID is public (it travels in the clear in every record
/// header), the key, IV and content are secret.
fn dtls12_cid_records() -> String {
    let mut out = Vec::new();
    let cid = [0xc1, 0xd2, 0xe3, 0xf4, 0x05];
    for (i, suite) in SUITES.into_iter().enumerate() {
        let tag = 360 + 10 * i as u64;
        let key = secret_bytes::<32>(tag);
        let key = &key[..key_len(suite)];
        let iv = secret_bytes::<12>(tag + 1);
        let iv = &iv[..hooks::tls::tls12_fixed_iv_len(suite)];
        let payload = secret_bytes::<150>(tag + 2);
        let expected = public_copy(&payload);
        let epoch_seq = (1u64 << 48) | 0x2a;
        let frag = hooks::dtls::dtls12_cid_seal(suite, key, iv, epoch_seq, &cid, 23, &payload)
            .expect("seal");
        declassify(&frag);
        let explicit = hooks::tls::tls12_record_iv_len(suite);
        assert_eq!(frag.len(), explicit + payload.len() + 1 + 16);
        let (ty, got) = hooks::dtls::dtls12_cid_open(suite, key, iv, epoch_seq, &cid, &frag)
            .expect("authentic");
        declassify(&got);
        assert_eq!((ty, &got[..]), (23, &expected[..]));
        let mut bad = frag.clone();
        bad[frag.len() - 1] ^= 1;
        assert!(hooks::dtls::dtls12_cid_open(suite, key, iv, epoch_seq, &cid, &bad).is_err());
        // Another CID: the additional data no longer matches.
        let other = [0xc1, 0xd2, 0xe3, 0xf4, 0x06];
        assert!(hooks::dtls::dtls12_cid_open(suite, key, iv, epoch_seq, &other, &frag).is_err());
        out.push(hex8(&frag[explicit..]));
    }
    out.join(" ")
}

/// DTLS 1.3 records with a connection ID in the unified header (RFC 9147
/// §4, §9): the header parsed with the receiver's CID length, the CID in
/// the AEAD additional data, sequence-number encryption unaffected.
fn dtls13_cid_records() -> String {
    let mut out = Vec::new();
    let cid = [0xa1, 0xb2, 0xc3];
    for (i, suite) in SUITES.into_iter().enumerate() {
        let tag = 390 + 10 * i as u64;
        let secret = secret_bytes::<48>(tag);
        let secret = &secret[..hash_len(suite)];
        let payload = secret_bytes::<150>(tag + 1);
        let expected = public_copy(&payload);
        let (epoch, seq) = (3u16, 0x1234u64);
        let wire =
            hooks::dtls::dtls13_seal(suite, secret, epoch, seq, &cid, 23, &payload).expect("seal");
        declassify(&wire);
        // C bit set, the CID right after the first byte.
        assert_eq!(wire[0] & 0b0001_0000, 0b0001_0000);
        assert_eq!(&wire[1..4], &cid);
        let (got_seq, ty, got) =
            hooks::dtls::dtls13_open(suite, secret, epoch, seq - 1, 3, &wire).expect("authentic");
        declassify(&got);
        assert_eq!((got_seq, ty, &got[..]), (seq, 23, &expected[..]));
        let mut bad = wire.clone();
        bad[20] ^= 1;
        assert!(hooks::dtls::dtls13_open(suite, secret, epoch, seq - 1, 3, &bad).is_err());
        // A receiver with no CID negotiated refuses the C bit outright.
        assert!(hooks::dtls::dtls13_open(suite, secret, epoch, seq - 1, 0, &wire).is_err());
        out.push(hex8(&wire));
    }
    out.join(" ")
}

fn quic_packets() -> String {
    use purecrypto::quic::QuicVersion;
    let mut out = Vec::new();
    // Cover both QUIC versions: v2 (RFC 9369) uses the same primitives with
    // different HKDF labels, so the constant-time property must hold there too.
    for (i, suite) in SUITES.into_iter().enumerate() {
        for version in [QuicVersion::V1, QuicVersion::V2] {
            let tag = 360 + 10 * i as u64;
            let secret = secret_bytes::<48>(tag);
            let secret = &secret[..hash_len(suite)];
            let payload = secret_bytes::<120>(tag + 1);
            let expected = public_copy(&payload);
            let dcid = fixed_bytes::<8>(tag + 2);
            let pn = 0x1a_2b3c;
            let pkt = hooks::quic::protect(version, suite, secret, &dcid, pn, 3, true, &payload)
                .expect("seal");
            declassify(&pkt);
            let (got_pn, first, got) =
                hooks::quic::unprotect(version, suite, secret, dcid.len(), pn - 5, &pkt)
                    .expect("authentic");
            declassify(&got);
            assert_eq!((got_pn, first & 0x04, &got[..]), (pn, 0x04, &expected[..]));
            let mut bad = pkt.clone();
            bad[40] ^= 1;
            assert!(
                hooks::quic::unprotect(version, suite, secret, dcid.len(), pn - 5, &bad).is_err()
            );
            let next = hooks::quic::key_update(version, suite, secret);
            out.push(format!(
                "{version} pkt={} ku={}",
                hex8(&pkt),
                hex8(public(&next[..]))
            ));
        }
    }
    out.join(" ")
}

/// ML-KEM-1024 decapsulation key with its secret parts classified, as
/// [`mlkem768_dk`] does for ML-KEM-768 (`dk_PKE` is 1536 bytes here).
fn mlkem1024_dk() -> MlKem1024DecapsKey {
    let (dk, _) = MlKem1024DecapsKey::from_seeds(&fixed_bytes::<32>(380), &fixed_bytes::<32>(381));
    let raw = dk.to_bytes();
    classify(&raw[..1536]);
    let n = raw.len();
    classify(&raw[n - 32..]);
    MlKem1024DecapsKey::from_bytes(raw)
}

/// The RFC 10024 hybrids and secp521r1 as the TLS 1.3 / DTLS 1.3 / QUIC
/// engines run them (`tls::crypto::kex`): the client's scalar and
/// decapsulation key are secret, so is the server's randomness (its
/// ephemeral scalar and the ML-KEM encapsulation coins); the shares are
/// public, the shared secrets are compared after declassification.
fn tls13_kex_hybrids() -> String {
    let mut out = Vec::new();

    // SecP256r1MLKEM768.
    let mut d = secret_bytes::<32>(382);
    d[0] &= 0x7f;
    let ec = BoxedEcdhPrivateKey::from_bytes(CurveId::P256, &d).expect("scalar in range");
    let (dk, _) = mlkem768_dk();
    let cshare = hooks::kex::p256_mlkem768_client_share(&ec, &dk);
    declassify(&cshare);
    let (sshare, ss_server) =
        hooks::kex::p256_mlkem768_server(&mut TaintRng::new(383), &cshare).expect("valid share");
    declassify(&sshare);
    let ss_client = hooks::kex::p256_mlkem768_client(&ec, &dk, &sshare).expect("valid share");
    declassify(&ss_client);
    declassify(&ss_server);
    assert_eq!(ss_client, ss_server);
    out.push(format!("p256mlkem768={}", hex8(&ss_client)));

    // SecP384r1MLKEM1024.
    let mut d = secret_bytes::<48>(384);
    d[0] &= 0x7f;
    let ec = BoxedEcdhPrivateKey::from_bytes(CurveId::P384, &d).expect("scalar in range");
    let dk = mlkem1024_dk();
    let cshare = hooks::kex::p384_mlkem1024_client_share(&ec, &dk);
    declassify(&cshare);
    let (sshare, ss_server) =
        hooks::kex::p384_mlkem1024_server(&mut TaintRng::new(385), &cshare).expect("valid share");
    declassify(&sshare);
    let ss_client = hooks::kex::p384_mlkem1024_client(&ec, &dk, &sshare).expect("valid share");
    declassify(&ss_client);
    declassify(&ss_server);
    assert_eq!(ss_client, ss_server);
    out.push(format!("p384mlkem1024={}", hex8(&ss_client)));

    // secp521r1.
    let mut d = secret_bytes::<66>(386);
    d[0] &= 0x01;
    let ec = BoxedEcdhPrivateKey::from_bytes(CurveId::P521, &d).expect("scalar in range");
    let cshare = ec.public_key().to_sec1();
    declassify(&cshare);
    let (sshare, ss_server) =
        hooks::kex::secp521r1_server(&mut TaintRng::new(387), &cshare).expect("valid share");
    declassify(&sshare);
    let ss_client = hooks::kex::secp521r1_client(&ec, &sshare).expect("valid share");
    declassify(&ss_client);
    declassify(&ss_server);
    assert_eq!(ss_client, ss_server);
    out.push(format!("secp521r1={}", hex8(&ss_client)));

    out.join(" ")
}

// ---------------------------------------------------------------------------
// secp256k1 extensions, ristretto255, more curves, DSA, RSA variants
// ---------------------------------------------------------------------------

/// A secp256k1 secret key (below the group order: top byte cleared).
fn secp256k1_secret(tag: u64) -> [u8; 32] {
    let mut sk = secret_bytes::<32>(tag);
    sk[0] &= 0x7f;
    sk[31] |= 1;
    sk
}

/// The compressed public key of a public secp256k1 scalar.
fn secp256k1_pub(sk: &[u8; 32]) -> [u8; 33] {
    let pk = s2c::public_key(sk).expect("valid scalar");
    *public(&pk)
}

fn bip340_sign() -> String {
    let sk = secp256k1_secret(400);
    let aux = secret_bytes::<32>(401);
    let pk = schnorr::public_key(&sk).expect("valid scalar");
    declassify(&pk);
    let sig = schnorr::sign(&sk, b"ct_valgrind message", &aux).expect("sign");
    declassify(&sig);
    schnorr::verify(&pk, b"ct_valgrind message", &sig).expect("verifies");
    format!("pk={} sig={}", hex8(&pk), hex8(&sig))
}

fn zkp_sign_to_contract() -> String {
    let sk = secp256k1_secret(402);
    let msg = fixed_bytes::<32>(403);
    let data = fixed_bytes::<32>(404);
    let (sig, opening) = s2c::sign_with_commitment(&sk, &msg, &data).expect("sign");
    declassify(&sig);
    let opening = opening.to_bytes();
    declassify(&opening);
    let opening = s2c::Opening::from_bytes(&opening).expect("valid opening");
    s2c::verify_commitment(&sig, &data, &opening).expect("commitment opens");
    format!("sig={}", hex8(&sig))
}

fn zkp_adaptor() -> String {
    let sk = secp256k1_secret(405);
    let y = secp256k1_secret(406);
    let pk = s2c::public_key(&sk).expect("valid scalar");
    declassify(&pk);
    let enckey = s2c::public_key(&y).expect("valid scalar");
    declassify(&enckey);
    let msg = fixed_bytes::<32>(407);
    let asig = adaptor::encrypt(&sk, &enckey, &msg).expect("encrypt");
    declassify(&asig);
    adaptor::verify(&asig, &pk, &enckey, &msg).expect("adaptor verifies");
    let sig = adaptor::decrypt(&asig, &y).expect("decrypt");
    declassify(&sig);
    let recovered = adaptor::recover(&enckey, &asig, &sig).expect("recover");
    declassify(&recovered);
    assert_eq!(recovered, public_copy(&y));
    format!("asig={} sig={}", hex8(&asig), hex8(&sig))
}

fn zkp_pedersen_rangeproof() -> String {
    let blind = secp256k1_secret(408);
    let nonce = secret_bytes::<32>(409);
    let value = u64::from_le_bytes(secret_bytes::<8>(410)) & 0xff;
    let commit = Commitment::new(value, &blind).expect("commit");
    let c = commit.serialize();
    declassify(&c);
    let commit = Commitment::parse(&c).expect("valid commitment");
    // An 8-bit range proof hides `value` in [0, 256).
    let proof = rangeproof::sign(
        &commit,
        &blind,
        &nonce,
        value,
        0,
        0,
        8,
        &[],
        &[],
        &Generator::h(),
    )
    .expect("prove");
    declassify(&proof);
    let (min, max) = rangeproof::verify(&commit, &proof, &[], &Generator::h()).expect("verifies");
    format!(
        "commit={} proof={} range=[{min},{max}]",
        hex8(&c),
        hex8(&proof)
    )
}

fn zkp_surjection() -> String {
    let tags: Vec<[u8; 32]> = (0..3).map(|i| fixed_bytes::<32>(411 + i)).collect();
    let blinds: Vec<[u8; 32]> = (0..3).map(|i| secp256k1_secret(420 + i)).collect();
    let out_blind = secp256k1_secret(425);
    // The generators are published; the blinds that made them are secret.
    let gens: Vec<Generator> = (0..3)
        .map(|i| {
            let g = Generator::from_asset_tag_blinded(&tags[i], &blinds[i]).expect("gen");
            Generator::parse(public(&g.serialize())).expect("valid generator")
        })
        .collect();
    let out = Generator::from_asset_tag_blinded(&tags[1], &out_blind).expect("gen");
    let out = Generator::parse(public(&out.serialize())).expect("valid generator");
    let seed = fixed_bytes::<32>(426);
    let (mut proof, idx) =
        SurjectionProof::initialize(&tags, 2, &tags[1], 100, &seed).expect("initialize");
    // Which input the output spends is what the proof hides: the ring
    // position must not drive a branch or an address.
    let secret_idx = idx;
    ct::classify_val(&secret_idx);
    proof
        .generate(&gens, &out, secret_idx, &blinds[idx], &out_blind)
        .expect("generate");
    let bytes = proof.serialize();
    declassify(&bytes);
    let proof = SurjectionProof::parse(&bytes).expect("parse");
    proof.verify(&gens, &out).expect("verifies");
    format!("proof={}", hex8(&bytes))
}

fn zkp_whitelist() -> String {
    let n = 3;
    let index = 1;
    let online: Vec<[u8; 32]> = (0..n).map(|i| fixed_bytes::<32>(430 + i)).collect();
    let offline: Vec<[u8; 32]> = (0..n).map(|i| fixed_bytes::<32>(440 + i)).collect();
    let sub = fixed_bytes::<32>(450);
    let scalar = |b: &[u8; 32]| Secp256k1Scalar::from_bytes_be_reduce(b);
    let on_pk: Vec<[u8; 33]> = online
        .iter()
        .map(|k| secp256k1_pub(&scalar(k).to_bytes_be()))
        .collect();
    let off_pk: Vec<[u8; 33]> = offline
        .iter()
        .map(|k| secp256k1_pub(&scalar(k).to_bytes_be()))
        .collect();
    let sub_pk = secp256k1_pub(&scalar(&sub).to_bytes_be());
    let online_sk = scalar(&online[index]).to_bytes_be();
    let summed_sk = scalar(&offline[index]).add(&scalar(&sub)).to_bytes_be();
    classify(&online_sk);
    classify(&summed_sk);
    // The signer's ring position is what the proof hides.
    let secret_index = index;
    ct::classify_val(&secret_index);
    let proof = whitelist::sign(
        &online_sk,
        &summed_sk,
        &on_pk,
        &off_pk,
        &sub_pk,
        secret_index,
        &mut TaintRng::new(451),
    )
    .expect("sign");
    let bytes = proof.to_bytes();
    declassify(&bytes);
    let proof = whitelist::Whitelist::from_bytes(&bytes).expect("parse");
    whitelist::verify(&proof, &on_pk, &off_pk, &sub_pk).expect("verifies");
    format!("proof={}", hex8(&bytes))
}

fn ristretto255_mul() -> String {
    let wide = secret_bytes::<64>(460);
    let s = RistrettoScalar::from_bytes_mod_order(&wide);
    let p = RistrettoPoint::mul_base(&s).compress().to_bytes();
    declassify(&p);
    let q = RistrettoPoint::from_uniform_bytes(&fixed_bytes::<64>(461));
    let shared = q.mul(&s).compress().to_bytes();
    format!("pk={} ss={}", hex8(&p), hex8(public(&shared)))
}

fn boxed_curve_case(curve: CurveId, tag: u64) -> String {
    let n = curve.order_len();
    let mut d = vec![0u8; n];
    d.copy_from_slice(&secret_bytes::<66>(tag)[..n]);
    // Keep the scalar below the group order.
    d[0] &= if curve == CurveId::P521 { 0x01 } else { 0x7f };
    let sk = BoxedEcdsaPrivateKey::from_bytes(curve, &d).expect("scalar in range");
    let sig = sk.sign::<Sha512>(b"ct_valgrind message").expect("sign");
    let sig = sig.to_bytes(curve);
    let dh = BoxedEcdhPrivateKey::from_bytes(curve, &d).expect("scalar in range");
    let mut peer = fixed_bytes::<66>(tag + 1)[..n].to_vec();
    peer[0] &= 0x01;
    let peer = BoxedEcdhPrivateKey::from_bytes(curve, &peer)
        .expect("scalar in range")
        .public_key();
    let shared = dh.diffie_hellman(&peer).expect("valid peer");
    format!(
        "sig={} ss={}",
        hex8(public(&sig[..])),
        hex8(public(&shared[..]))
    )
}

fn p521_ecdsa_ecdh() -> String {
    boxed_curve_case(CurveId::P521, 470)
}

fn brainpoolp256r1_ecdsa_ecdh() -> String {
    boxed_curve_case(CurveId::BrainpoolP256r1, 472)
}

fn secp256k1_ecdh() -> String {
    let d = secp256k1_secret(474);
    let sk = BoxedEcdhPrivateKey::from_bytes(CurveId::Secp256k1, &d).expect("scalar in range");
    let mut peer = fixed_bytes::<32>(475);
    peer[0] &= 0x7f;
    let peer = BoxedEcdhPrivateKey::from_bytes(CurveId::Secp256k1, &peer)
        .expect("scalar in range")
        .public_key();
    let shared = sk.diffie_hellman(&peer).expect("valid peer");
    format!("ss={}", hex8(public(&shared[..])))
}

fn dsa2048_sign() -> String {
    let mut x = secret_bytes::<32>(480);
    x[0] &= 0x3f;
    x[31] |= 1;
    let sk = DsaPrivateKey::from_be_bytes(dsa::test_params_2048_256(), &x).expect("x in range");
    let sig = sk.sign::<Sha256>(b"ct_valgrind message").expect("sign");
    let der = sig.to_der();
    declassify(&der);
    format!("sig={}", hex8(&der))
}

fn sm2_encrypt_decrypt() -> String {
    let sk = Sm2PrivateKey::from_bytes(&secret_bytes::<32>(481)).expect("scalar in range");
    let pk = sk.public_key();
    let msg = secret_bytes::<48>(482);
    let expected = public_copy(&msg);
    // The ephemeral key is secret randomness.
    let ct = pk.encrypt(&msg, &mut TaintRng::new(483)).expect("encrypt");
    declassify(&ct);
    let pt = sk.decrypt(&ct).expect("decrypt");
    declassify(&pt);
    assert_eq!(pt, expected);
    let mut bad = ct.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(sk.decrypt(&bad).is_err());
    format!("ct={}", hex8(&ct))
}

const RSA3_TXT: &str =
    include_str!("../testdata/wycheproof/rsa_three_primes_oaep_2048_sha1_mgf1sha1.txt");

/// The hex string following `key` in the Wycheproof three-prime key JSON.
fn json_hex(key: &str) -> BoxedUint {
    let start = RSA3_TXT.find(key).expect("key present") + key.len();
    let end = start + RSA3_TXT[start..].find('"').expect("closing quote");
    let hex = &RSA3_TXT[start..end];
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect();
    BoxedUint::from_be_bytes(&bytes)
}

fn rsa2048_three_prime() -> String {
    let key = BoxedRsaPrivateKey::from_components_with_other_primes(
        json_hex("\"modulus\":\""),
        json_hex("\"publicExponent\":\""),
        secret_uint(&json_hex("\"privateExponent\":\"")),
        secret_uint(&json_hex("\"prime1\":\"")),
        secret_uint(&json_hex("\"prime2\":\"")),
        vec![secret_uint(&json_hex("\"otherPrimeInfos\":[[\""))],
    );
    assert_eq!(key.num_primes(), 3);
    let sig = key
        .sign_pss::<Sha256, _>(b"ct_valgrind message", &mut public_rng(484))
        .expect("sign");
    declassify(&sig);
    key.public_key()
        .verify_pss::<Sha256>(b"ct_valgrind message", &sig)
        .expect("signature verifies");
    let msg = fixed_bytes::<32>(485);
    let ct = key
        .public_key()
        .encrypt_oaep::<Sha256, _>(&msg, b"", &mut public_rng(486))
        .expect("encrypt");
    let pt = key.decrypt_oaep::<Sha256>(&ct, b"").expect("decrypt");
    declassify(&pt);
    assert_eq!(pt, msg);
    format!("sig={} pt={}", hex8(&sig), hex8(&pt))
}

fn rsa2048_pss_shake() -> String {
    let key = rsa_key();
    let sig = key
        .sign_pss_shake::<Shake128, _>(b"ct_valgrind message", &mut public_rng(487))
        .expect("sign");
    declassify(&sig);
    key.public_key()
        .verify_pss_shake::<Shake128>(b"ct_valgrind message", &sig)
        .expect("signature verifies");
    hex8(&sig)
}

// ---------------------------------------------------------------------------
// More symmetric modes, MACs, KDFs and envelopes
// ---------------------------------------------------------------------------

fn aes_stream_modes() -> String {
    let key = secret_bytes::<16>(500);
    let iv = fixed_bytes::<16>(501);
    let pt = secret_bytes::<96>(502);
    let expected = public_copy(&pt);
    let mut out = Vec::new();

    let mut buf = pt;
    Cbc::new(Aes128::new(&key), &iv)
        .encrypt(&mut buf)
        .expect("block multiple");
    declassify(&buf);
    out.push(hex8(&buf));
    Cbc::new(Aes128::new(&key), &iv)
        .decrypt(&mut buf)
        .expect("block multiple");
    assert!(bool::from(ct::declassify_value(buf.ct_eq(&pt))));

    let mut buf = pt;
    Ctr::new(Aes128::new(&key), &iv).apply_keystream(&mut buf);
    declassify(&buf);
    out.push(hex8(&buf));
    Ctr::new(Aes128::new(&key), &iv).apply_keystream(&mut buf);
    declassify(&buf);
    assert_eq!(buf, expected);

    let mut buf = pt;
    Cfb::new(Aes128::new(&key), &iv).encrypt(&mut buf);
    declassify(&buf);
    out.push(hex8(&buf));
    Cfb::new(Aes128::new(&key), &iv).decrypt(&mut buf);
    declassify(&buf);
    assert_eq!(buf, expected);

    let mut buf = pt;
    Ofb::new(Aes128::new(&key), &iv).apply_keystream(&mut buf);
    declassify(&buf);
    out.push(hex8(&buf));
    Ofb::new(Aes128::new(&key), &iv).apply_keystream(&mut buf);
    declassify(&buf);
    assert_eq!(buf, expected);
    out.join(" ")
}

fn aes128_xts() -> String {
    let xts = Aes128Xts::new_from_key_bytes(&secret_bytes::<32>(503)).expect("distinct halves");
    let pt = secret_bytes::<100>(504);
    let expected = public_copy(&pt);
    let mut buf = pt;
    // A partial final block, so ciphertext stealing runs.
    xts.encrypt_sector(7, &mut buf).expect("valid length");
    declassify(&buf);
    let out = hex8(&buf);
    xts.decrypt_sector(7, &mut buf).expect("valid length");
    declassify(&buf);
    assert_eq!(buf, expected);
    out
}

fn aes_key_wrap() -> String {
    let kek = secret_bytes::<16>(505);
    let cek = secret_bytes::<32>(506);
    let expected = public_copy(&cek);
    let kw = Aes128Kw::new(Aes128::new(&kek));
    let mut wrapped = [0u8; 40];
    kw.wrap(&cek, &mut wrapped).expect("wrap");
    declassify(&wrapped);
    let mut unwrapped = [0u8; 32];
    kw.unwrap(&wrapped, &mut unwrapped).expect("authentic");
    declassify(&unwrapped);
    assert_eq!(unwrapped, expected);
    let mut bad = wrapped;
    bad[20] ^= 1;
    assert!(kw.unwrap(&bad, &mut unwrapped).is_err());

    let kwp = Aes128Kwp::new(Aes128::new(&kek));
    let mut wrapped_p = [0u8; 40];
    kwp.wrap(&cek[..27], &mut wrapped_p[..kwp_ciphertext_len(27)])
        .expect("wrap");
    let wrapped_p = &wrapped_p[..kwp_ciphertext_len(27)];
    declassify(wrapped_p);
    let mut out = [0u8; 40];
    let n = kwp.unwrap(wrapped_p, &mut out).expect("authentic");
    declassify(&out);
    assert_eq!(&out[..n], &expected[..27]);
    let mut bad = wrapped_p.to_vec();
    bad[3] ^= 1;
    assert!(kwp.unwrap(&bad, &mut out).is_err());
    format!("kw={} kwp={}", hex8(&wrapped), hex8(wrapped_p))
}

fn aes_siv() -> String {
    let siv = AesSiv::new(&secret_bytes::<32>(507));
    let pt = secret_bytes::<70>(508);
    let expected = public_copy(&pt);
    let ct = siv.seal(&[b"ad1", b"ad2"], &pt);
    declassify(&ct);
    let got = siv.open(&[b"ad1", b"ad2"], &ct).expect("authentic");
    declassify(&got);
    assert_eq!(got, expected);
    let mut bad = ct.clone();
    bad[2] ^= 1;
    assert!(siv.open(&[b"ad1", b"ad2"], &bad).is_err());
    hex8(&ct)
}

fn gmac_umac_vmac() -> String {
    let key = secret_bytes::<16>(509);
    let msg = secret_bytes::<300>(510);
    let mut g = Gmac::new(Aes128::new(&key), &fixed_bytes::<12>(511));
    g.update(&msg);
    let gtag = g.finalize();
    let nonce = fixed_bytes::<8>(512);
    let utag = Umac64::compute(&key, &msg, &nonce);
    let mut u = Umac128::new(&key);
    u.update(&msg);
    let utag2 = public_copy(&u.finalize(&nonce));
    let mut u = Umac128::new(&key);
    u.update(&msg);
    assert!(u.verify(&nonce, &utag2));
    let vtag = Vmac64::compute(&key, &msg, &nonce).expect("valid nonce");
    let vtag2 = public_copy(
        &Vmac128::new(&key)
            .chain(&msg)
            .finalize(&nonce)
            .expect("valid nonce"),
    );
    assert!(Vmac128::new(&key).chain(&msg).verify(&nonce, &vtag2));
    format!(
        "gmac={} umac={} vmac={}",
        hex8(public(&gtag)),
        hex8(public(&utag)),
        hex8(public(&vtag))
    )
}

fn aez() -> String {
    let aez = Aez::new(&secret_bytes::<48>(513));
    let pt = secret_bytes::<60>(514);
    let expected = public_copy(&pt);
    let nonce = fixed_bytes::<12>(515);
    let ct = aez.encrypt(&nonce, &[b"ad"], 16, &pt);
    declassify(&ct);
    let got = aez.decrypt(&nonce, &[b"ad"], 16, &ct).expect("authentic");
    declassify(&got);
    assert_eq!(got, expected);
    let mut bad = ct.clone();
    bad[5] ^= 1;
    assert!(aez.decrypt(&nonce, &[b"ad"], 16, &bad).is_err());
    hex8(&ct)
}

fn c2sp_chunked() -> String {
    let key = secret_bytes::<16>(518);
    let msg = secret_bytes::<200>(519);
    let expected = public_copy(&msg);
    // The salt is published at the front of the ciphertext.
    let ct = chunked::encrypt::<Cobblestone128>(&key, b"ctx", &msg, &mut public_rng(520))
        .expect("encrypt");
    declassify(&ct);
    let pt = chunked::decrypt::<Cobblestone128>(&key, b"ctx", &ct).expect("authentic");
    declassify(&pt);
    assert_eq!(pt, expected);
    let mut bad = ct.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(chunked::decrypt::<Cobblestone128>(&key, b"ctx", &bad).is_err());
    hex8(&ct[24..])
}

fn legacy_aeads() -> String {
    let mut out = Vec::new();
    let key = secret_bytes::<32>(521);
    let k16: [u8; 16] = key[..16].try_into().unwrap();
    let nonce = fixed_bytes::<16>(522);
    let run = |seal: &dyn Fn(&mut [u8]) -> [u8; 16],
               open: &dyn Fn(&mut [u8], &[u8; 16]) -> bool| {
        aead_roundtrip(seal, open)
    };
    out.push(run(
        &|b| Morus640::new(&k16).encrypt(&nonce, b"aad", b),
        &|b, t| Morus640::new(&k16).decrypt(&nonce, b"aad", b, t).is_ok(),
    ));
    out.push(run(
        &|b| Morus1280::new(&key).encrypt(&nonce, b"aad", b),
        &|b, t| Morus1280::new(&key).decrypt(&nonce, b"aad", b, t).is_ok(),
    ));
    out.push(run(
        &|b| Aegis128::new(&k16).encrypt(&nonce, b"aad", b),
        &|b, t| Aegis128::new(&k16).decrypt(&nonce, b"aad", b, t).is_ok(),
    ));
    out.push(run(
        &|b| Ascon128::new(&k16).encrypt(&nonce, b"aad", b),
        &|b, t| Ascon128::new(&k16).decrypt(&nonce, b"aad", b, t).is_ok(),
    ));
    out.push(run(
        &|b| Ascon128a::new(&k16).encrypt(&nonce, b"aad", b),
        &|b, t| Ascon128a::new(&k16).decrypt(&nonce, b"aad", b, t).is_ok(),
    ));
    let n12 = fixed_bytes::<12>(523);
    out.push(run(
        &|b| Gcm::new(Seed::new(&k16)).encrypt(&n12, b"aad", b),
        &|b, t| {
            Gcm::new(Seed::new(&k16))
                .decrypt(&n12, b"aad", b, t)
                .is_ok()
        },
    ));
    out.push(aes_block(&Seed::new(&k16)));
    out.join(" ")
}

fn kbkdf_hmac_drbg() -> String {
    let ki = secret_bytes::<32>(524);
    let mut okm = [0u8; 48];
    kbkdf_counter::<HmacSha256Prf>(&ki, b"label", b"context", &mut okm).expect("kbkdf");
    // HMAC-DRBG seeded with secret entropy: its state and output are secret.
    let mut drbg = HmacDrbg::<Sha256>::new(&secret_bytes::<32>(525), b"nonce", b"pers");
    let mut a = [0u8; 64];
    drbg.generate(&mut a, b"");
    drbg.reseed(&secret_bytes::<32>(526), b"more");
    let mut b = [0u8; 40];
    drbg.generate(&mut b, b"additional");
    format!(
        "kbkdf={} drbg={}{}",
        hex8(public(&okm)),
        hex8(public(&a)),
        hex8(public(&b))
    )
}

fn pbes2_gcm() -> String {
    let inner = secret_bytes::<64>(527);
    let expected = public_copy(&inner);
    let params = Pbes2Params {
        kdf: KdfChoice::Pbkdf2HmacSha256 { iterations: 10_000 },
        cipher: CipherChoice::Aes256Gcm,
        salt_len: 16,
    };
    let password = secret_bytes::<16>(528);
    // Salt and nonce are published in the envelope.
    let blob = pbes2::encrypt(&inner, &password, &params, &mut public_rng(529));
    declassify(&blob);
    let got = pbes2::decrypt_authenticated(&blob, &password).expect("authentic");
    declassify(&got);
    assert_eq!(got, expected);
    let mut wrong = password;
    wrong[0] ^= 1;
    assert!(pbes2::decrypt_authenticated(&blob, &wrong).is_err());
    hex8(&blob[blob.len() - 16..])
}

/// Marks a JWK's private material secret. A JWK is a serialization format:
/// it holds its key in the minimal big-endian encoding the format
/// prescribes, so a key is built here from public bytes and its private
/// fields are classified afterwards (the encoding's length — the bit
/// length of `d`, `p`, `q` — is public in JWK by construction).
fn classify_jwk(jwk: &Jwk) {
    match jwk.key() {
        JwkKey::Oct(k) => classify(k),
        JwkKey::Rsa {
            private: Some(parts),
            ..
        } => {
            classify(parts.d());
            classify(parts.p().expect("CRT key"));
            classify(parts.q().expect("CRT key"));
        }
        JwkKey::Ec { d: Some(d), .. } | JwkKey::Okp { d: Some(d), .. } => classify(d),
        _ => panic!("not a private JWK"),
    }
}

fn jose_jwe_decrypt() -> String {
    let mut out = Vec::new();
    let pt = b"ct_valgrind JWE payload";
    // Symmetric keys: the token is made with a public copy of the key (the
    // encryption side is not what this case checks) and opened with the
    // secret one.
    let raw = fixed_bytes::<32>(530);
    for (alg, key_alg) in [(KeyAlg::Dir, "A256GCM"), (KeyAlg::A256KW, "A256KW")] {
        let enc_key = Jwk::oct(&raw).with_alg(key_alg).expect("alg");
        let token = Jwe::encrypt_compact(&enc_key, alg, Enc::A256Gcm, pt, &mut public_rng(531))
            .expect("encrypt");
        let dec_key = Jwk::oct(&raw).with_alg(key_alg).expect("alg");
        classify_jwk(&dec_key);
        let got = Jwe::parse(&token)
            .expect("parse")
            .decrypt(&dec_key)
            .expect("decrypt");
        declassify(&got);
        assert_eq!(got, pt);
        out.push(token[token.len() - 12..].to_string());
    }
    // ECDH-ES+A256KW to a P-256 key, RSA-OAEP-256 to the RSA test key.
    let mut d = fixed_bytes::<32>(532);
    d[0] &= 0x7f;
    let ec = BoxedEcdsaPrivateKey::from_bytes(CurveId::P256, &d).expect("scalar in range");
    let rsa = BoxedRsaPrivateKey::from_pkcs1_pem(RSA_PEM).expect("test key parses");
    for (jwk, alg, tag) in [
        (
            Jwk::from_ec_private(&ec).expect("jwk"),
            KeyAlg::EcdhEsA256KW,
            533,
        ),
        (Jwk::from_rsa_private(&rsa), KeyAlg::RsaOaep256, 534),
    ] {
        let token = Jwe::encrypt_compact(
            &jwk.to_public().expect("public half"),
            alg,
            Enc::A256Gcm,
            pt,
            &mut public_rng(tag),
        )
        .expect("encrypt");
        classify_jwk(&jwk);
        let got = Jwe::parse(&token)
            .expect("parse")
            .decrypt(&jwk)
            .expect("decrypt");
        declassify(&got);
        assert_eq!(got, pt);
        out.push(token[token.len() - 12..].to_string());
    }
    out.join(" ")
}

fn jose_jws_sign() -> String {
    let mut out = Vec::new();
    let hs = Jwk::oct(&fixed_bytes::<32>(535));
    let mut d = fixed_bytes::<32>(536);
    d[0] &= 0x7f;
    let es = Jwk::from_ec_private(
        &BoxedEcdsaPrivateKey::from_bytes(CurveId::P256, &d).expect("scalar in range"),
    )
    .expect("jwk");
    let ed = Jwk::from_ed25519_private(&Ed25519PrivateKey::from_bytes(fixed_bytes::<32>(537)));
    for (key, alg) in [
        (&hs, SigAlg::HS256),
        (&es, SigAlg::ES256),
        (&ed, SigAlg::EdDSA),
    ] {
        let verify_key = if alg == SigAlg::HS256 {
            key.clone()
        } else {
            key.to_public().expect("public half")
        };
        classify_jwk(key);
        let token = Jws::sign_compact(key, alg, b"ct_valgrind payload", &mut public_rng(538))
            .expect("sign");
        let parsed = Jws::parse(&token).expect("parse");
        // HS256 verification recomputes the MAC under the secret key; the
        // verdict is its public result.
        let ok = parsed.verify(&verify_key).is_ok();
        assert!(ok);
        out.push(token[token.len() - 12..].to_string());
    }
    out.join(" ")
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
    ("slhdsa_sha2_128s", slhdsa_sha2_128s),
    ("falcon512_sign", falcon512_sign),
    ("xmss_sign", xmss_sign),
    ("xmssmt_sign", xmssmt_sign),
    ("hss_l2_sign", hss_l2_sign),
    // Protocols
    ("tls13_key_schedule", tls13_key_schedule),
    ("tls13_finished", tls13_finished),
    ("tls13_record_aes128", tls13_record_aes128),
    ("tls13_record_aes256", tls13_record_aes256),
    ("tls13_record_chacha", tls13_record_chacha),
    ("tls12_prf_finished", tls12_prf_finished),
    ("tls12_records", tls12_records),
    ("dtls12_records", dtls12_records),
    ("dtls13_records", dtls13_records),
    ("dtls12_cid_records", dtls12_cid_records),
    ("dtls13_cid_records", dtls13_cid_records),
    ("quic_packets", quic_packets),
    ("tls13_kex_hybrids", tls13_kex_hybrids),
    // secp256k1 extensions, more curves and RSA variants
    ("bip340_sign", bip340_sign),
    ("zkp_sign_to_contract", zkp_sign_to_contract),
    ("zkp_adaptor", zkp_adaptor),
    ("zkp_pedersen_rangeproof", zkp_pedersen_rangeproof),
    ("zkp_surjection", zkp_surjection),
    ("zkp_whitelist", zkp_whitelist),
    ("ristretto255_mul", ristretto255_mul),
    ("p521_ecdsa_ecdh", p521_ecdsa_ecdh),
    ("brainpoolp256r1_ecdsa_ecdh", brainpoolp256r1_ecdsa_ecdh),
    ("secp256k1_ecdh", secp256k1_ecdh),
    ("dsa2048_sign", dsa2048_sign),
    ("sm2_encrypt_decrypt", sm2_encrypt_decrypt),
    ("rsa2048_three_prime", rsa2048_three_prime),
    ("rsa2048_pss_shake", rsa2048_pss_shake),
    // More symmetric
    ("aes_stream_modes", aes_stream_modes),
    ("aes128_xts", aes128_xts),
    ("aes_key_wrap", aes_key_wrap),
    ("aes_siv", aes_siv),
    ("gmac_umac_vmac", gmac_umac_vmac),
    ("aez", aez),
    ("c2sp_chunked", c2sp_chunked),
    ("legacy_aeads", legacy_aeads),
    ("kbkdf_hmac_drbg", kbkdf_hmac_drbg),
    ("pbes2_gcm", pbes2_gcm),
    ("jose_jwe_decrypt", jose_jwe_decrypt),
    ("jose_jws_sign", jose_jws_sign),
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
    // The code-generation variant under test; CI checks these lines.
    println!(
        "ct_valgrind: cpu dispatch: {}",
        if ct::force_portable() {
            "forced portable"
        } else {
            "detected"
        }
    );
    let tables: Vec<&str> = [
        ("ed25519", cfg!(feature = "ed25519-table")),
        ("p256", cfg!(feature = "p256-table")),
    ]
    .iter()
    .filter(|(_, on)| *on)
    .map(|(name, _)| *name)
    .collect();
    println!(
        "ct_valgrind: tables: {}",
        if tables.is_empty() {
            "none".to_string()
        } else {
            tables.join(",")
        }
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
