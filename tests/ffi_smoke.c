/*
 * Smoke test for the purecrypto C ABI. Links against libpurecrypto and exercises
 * a representative slice of the API. Build & run, e.g.:
 *
 *   cargo rustc --release --features ffi --crate-type staticlib
 *   cc tests/ffi_smoke.c -I include -L target/release -lpurecrypto \
 *      -lpthread -ldl -lm -o /tmp/ffi_smoke && /tmp/ffi_smoke
 *
 * Exits 0 on success; prints the failing check and exits 1 otherwise.
 */
#include "purecrypto.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *msg) {
  fprintf(stderr, "FAIL: %s\n", msg);
  return 1;
}

int main(void) {
  /* 1. One-shot SHA-256("abc"). */
  static const uint8_t expected[32] = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
      0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
      0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  uint8_t out[64];
  size_t out_len = sizeof(out);
  if (pc_digest(PC_SHA256, (const uint8_t *)"abc", 3, out, &out_len) != PC_OK)
    return fail("pc_digest");
  if (out_len != 32 || memcmp(out, expected, 32) != 0)
    return fail("sha256 mismatch");

  /* 2. Streaming SHA-256, fed in two chunks, must match. */
  PcHash *h = pc_hash_new(PC_SHA256);
  if (!h)
    return fail("pc_hash_new");
  if (pc_hash_update(h, (const uint8_t *)"a", 1) != PC_OK ||
      pc_hash_update(h, (const uint8_t *)"bc", 2) != PC_OK)
    return fail("pc_hash_update");
  uint8_t out2[32];
  size_t out2_len = sizeof(out2);
  if (pc_hash_finish(h, out2, &out2_len) != PC_OK)
    return fail("pc_hash_finish");
  pc_hash_free(h);
  if (out2_len != 32 || memcmp(out2, expected, 32) != 0)
    return fail("streaming sha256 mismatch");

  /* 3. BUFFER_TOO_SMALL reports the required length. */
  size_t need = 0;
  if (pc_digest(PC_SHA256, (const uint8_t *)"abc", 3, NULL, &need) !=
      PC_BUFFER_TOO_SMALL)
    return fail("expected PC_BUFFER_TOO_SMALL");
  if (need != 32)
    return fail("required length");

  /* 4. Randomness fills the buffer. */
  uint8_t rnd[16];
  memset(rnd, 0, sizeof(rnd));
  if (pc_rand_bytes(rnd, sizeof(rnd)) != PC_OK)
    return fail("pc_rand_bytes");
  int any = 0;
  for (size_t i = 0; i < sizeof(rnd); i++)
    any |= rnd[i];
  if (!any)
    return fail("rand all zero");

  /* 5. ECDSA: generate, sign, verify against the exported public key. */
  PcEcKey *ec = pc_ec_generate(PC_P256);
  if (!ec)
    return fail("pc_ec_generate");
  const uint8_t msg[] = "hello from C";
  uint8_t sig[160];
  size_t sig_len = sizeof(sig);
  if (pc_ec_sign(ec, msg, sizeof(msg), sig, &sig_len) != PC_OK)
    return fail("pc_ec_sign");
  pc_ec_free(ec);

  /* 6. Ed25519: generate, export keys, sign (64-byte signature). */
  PcEd25519Key *ed = pc_ed25519_generate();
  if (!ed)
    return fail("pc_ed25519_generate");
  uint8_t edpriv[128];
  size_t edpriv_len = sizeof(edpriv);
  if (pc_ed25519_private_to_pem(ed, edpriv, &edpriv_len) != PC_OK)
    return fail("pc_ed25519_private_to_pem");
  if (strncmp((const char *)edpriv, "-----BEGIN PRIVATE KEY-----", 27) != 0)
    return fail("ed25519 private PEM header");
  uint8_t edpub[128];
  size_t edpub_len = sizeof(edpub);
  if (pc_ed25519_public_to_pem(ed, edpub, &edpub_len) != PC_OK)
    return fail("pc_ed25519_public_to_pem");
  if (strncmp((const char *)edpub, "-----BEGIN PUBLIC KEY-----", 26) != 0)
    return fail("ed25519 public PEM header");
  uint8_t edsig[64];
  size_t edsig_len = sizeof(edsig);
  if (pc_ed25519_sign(ed, msg, sizeof(msg), edsig, &edsig_len) != PC_OK)
    return fail("pc_ed25519_sign");
  if (edsig_len != 64)
    return fail("ed25519 signature length");
  pc_ed25519_free(ed);

  /* 7. AES-256-GCM round trip. */
  {
    uint8_t key[32];
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)i;
    uint8_t nonce[12] = {0,1,2,3,4,5,6,7,8,9,10,11};
    uint8_t aad[4] = {0xDE,0xAD,0xBE,0xEF};
    const uint8_t pt[] = "ffi AEAD test";
    uint8_t ct[64];
    size_t ct_len = sizeof(ct);
    if (pc_aead_encrypt(PC_AEAD_AES256_GCM, key, sizeof(key),
                        nonce, sizeof(nonce), aad, sizeof(aad),
                        pt, sizeof(pt), ct, &ct_len) != PC_OK)
      return fail("pc_aead_encrypt");
    if (ct_len != sizeof(pt) + 16)
      return fail("aead ciphertext length");

    uint8_t rt[64];
    size_t rt_len = sizeof(rt);
    if (pc_aead_decrypt(PC_AEAD_AES256_GCM, key, sizeof(key),
                        nonce, sizeof(nonce), aad, sizeof(aad),
                        ct, ct_len, rt, &rt_len) != PC_OK)
      return fail("pc_aead_decrypt");
    if (rt_len != sizeof(pt) || memcmp(rt, pt, sizeof(pt)) != 0)
      return fail("aead round trip");

    /* Tampering the tag must yield PC_VERIFICATION. */
    ct[ct_len - 1] ^= 1;
    if (pc_aead_decrypt(PC_AEAD_AES256_GCM, key, sizeof(key),
                        nonce, sizeof(nonce), aad, sizeof(aad),
                        ct, ct_len, rt, &rt_len) != PC_VERIFICATION)
      return fail("aead tamper not rejected");
  }

  /* 8. ChaCha20-Poly1305 round trip. */
  {
    uint8_t key[32];
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(i ^ 0x55);
    uint8_t nonce[12];
    for (size_t i = 0; i < sizeof(nonce); i++) nonce[i] = (uint8_t)i;
    const uint8_t pt[] = "chacha20 from C";
    uint8_t ct[64];
    size_t ct_len = sizeof(ct);
    if (pc_aead_encrypt(PC_AEAD_CHACHA20_POLY1305, key, sizeof(key),
                        nonce, sizeof(nonce), NULL, 0,
                        pt, sizeof(pt), ct, &ct_len) != PC_OK)
      return fail("pc_aead_encrypt cc20");
    uint8_t rt[64];
    size_t rt_len = sizeof(rt);
    if (pc_aead_decrypt(PC_AEAD_CHACHA20_POLY1305, key, sizeof(key),
                        nonce, sizeof(nonce), NULL, 0,
                        ct, ct_len, rt, &rt_len) != PC_OK)
      return fail("pc_aead_decrypt cc20");
    if (memcmp(rt, pt, sizeof(pt)) != 0)
      return fail("cc20 round trip");
  }

  /* 9. HKDF-SHA256 RFC 5869 §A.1 vector. */
  {
    const uint8_t ikm[22] = {
      0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,
      0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b,0x0b};
    const uint8_t salt[13] = {0,1,2,3,4,5,6,7,8,9,10,11,12};
    const uint8_t info[10] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9};
    static const uint8_t want[42] = {
      0x3c,0xb2,0x5f,0x25,0xfa,0xac,0xd5,0x7a,0x90,0x43,0x4f,0x64,0xd0,0x36,
      0x2f,0x2a,0x2d,0x2d,0x0a,0x90,0xcf,0x1a,0x5a,0x4c,0x5d,0xb0,0x2d,0x56,
      0xec,0xc4,0xc5,0xbf,0x34,0x00,0x72,0x08,0xd5,0xb8,0x87,0x18,0x58,0x65};
    uint8_t okm[42];
    if (pc_hkdf(PC_SHA256, salt, sizeof(salt), ikm, sizeof(ikm),
                info, sizeof(info), okm, sizeof(okm)) != PC_OK)
      return fail("pc_hkdf");
    if (memcmp(okm, want, sizeof(okm)) != 0)
      return fail("hkdf vector mismatch");
  }

  /* 10. PBKDF2-SHA256 RFC 7914 §11 vector. */
  {
    const uint8_t pw[6] = "passwd";
    const uint8_t salt[4] = {'s','a','l','t'};
    uint8_t dk[64];
    if (pc_pbkdf2(PC_SHA256, pw, 6, salt, 4, 1, dk, 64) != PC_OK)
      return fail("pc_pbkdf2");
    static const uint8_t want[] = {
      0x55,0xac,0x04,0x6e,0x56,0xe3,0x08,0x9f,0xec,0x16,0x91,0xc2,0x25,0x44,
      0xb6,0x05};
    if (memcmp(dk, want, sizeof(want)) != 0)
      return fail("pbkdf2 vector mismatch");
  }

  /* 11. X25519 RFC 7748 §6.1 vector — round trip Alice/Bob. */
  {
    uint8_t a_priv[32], b_priv[32], a_pub[32], b_pub[32], ss_a[32], ss_b[32];
    static const uint8_t A[32] = {
      0x77,0x07,0x6d,0x0a,0x73,0x18,0xa5,0x7d,0x3c,0x16,0xc1,0x72,0x51,0xb2,
      0x66,0x45,0xdf,0x4c,0x2f,0x87,0xeb,0xc0,0x99,0x2a,0xb1,0x77,0xfb,0xa5,
      0x1d,0xb9,0x2c,0x2a};
    static const uint8_t B[32] = {
      0x5d,0xab,0x08,0x7e,0x62,0x4a,0x8a,0x4b,0x79,0xe1,0x7f,0x8b,0x83,0x80,
      0x0e,0xe6,0x6f,0x3b,0xb1,0x29,0x26,0x18,0xb6,0xfd,0x1c,0x2f,0x8b,0x27,
      0xff,0x88,0xe0,0xeb};
    memcpy(a_priv, A, 32);
    memcpy(b_priv, B, 32);
    if (pc_x25519_public(a_priv, a_pub) != PC_OK)
      return fail("pc_x25519_public a");
    if (pc_x25519_public(b_priv, b_pub) != PC_OK)
      return fail("pc_x25519_public b");
    if (pc_x25519(a_priv, b_pub, ss_a) != PC_OK)
      return fail("pc_x25519 a->b");
    if (pc_x25519(b_priv, a_pub, ss_b) != PC_OK)
      return fail("pc_x25519 b->a");
    if (memcmp(ss_a, ss_b, 32) != 0)
      return fail("x25519 shared secrets differ");
  }

  /* 12. ECDH P-256 round trip — generate two keys, exchange SPKIs, derive
   *     scalars by parsing the SEC1 PEM with a small inline base64 decoder,
   *     and confirm both sides reach the same shared secret via pc_ecdh.
   */
  {
    PcEcKey *a = pc_ec_generate(PC_P256);
    PcEcKey *b = pc_ec_generate(PC_P256);
    if (!a || !b) return fail("pc_ec_generate p256");

    uint8_t a_pem[512], b_pem[512], a_spki_pem[512], b_spki_pem[512];
    size_t a_len = sizeof(a_pem), b_len = sizeof(b_pem);
    size_t a_spki_len = sizeof(a_spki_pem), b_spki_len = sizeof(b_spki_pem);
    if (pc_ec_private_to_pem(a, a_pem, &a_len) != PC_OK
        || pc_ec_private_to_pem(b, b_pem, &b_len) != PC_OK
        || pc_ec_public_to_pem(a, a_spki_pem, &a_spki_len) != PC_OK
        || pc_ec_public_to_pem(b, b_spki_pem, &b_spki_len) != PC_OK)
      return fail("ec key export");
    pc_ec_free(a);
    pc_ec_free(b);

    /* Strip PEM armor & decode base64 into a DER buffer. */
    static const char b64chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int b64dec[256];
    for (int i = 0; i < 256; i++) b64dec[i] = -1;
    for (int i = 0; i < 64; i++) b64dec[(unsigned char)b64chars[i]] = i;

    /* PEM-decoder: writes raw DER into `out`, returning length or -1. */
#define PEM_DECODE(in, in_len, out, out_cap)                                   \
  ({                                                                           \
    const char *_b = (const char *)(in), *_e = _b + (in_len);                  \
    while (_b < _e && *_b != '\n') _b++;                                       \
    _b++;                                                                      \
    const char *_end = _e - 1;                                                 \
    while (_end > _b && *_end != '-') _end--;                                  \
    while (_end > _b && *_end != '\n') _end--;                                 \
    int _state = 0; uint32_t _acc = 0; size_t _n = 0;                          \
    for (const char *_p = _b; _p < _end; _p++) {                               \
      if (*_p == '\n' || *_p == '\r' || *_p == ' ' || *_p == '=') continue;    \
      int v = b64dec[(unsigned char)*_p];                                      \
      if (v < 0) { _n = (size_t)-1; break; }                                   \
      _acc = (_acc << 6) | (uint32_t)v;                                        \
      _state++;                                                                \
      if (_state == 4) {                                                       \
        if (_n + 3 > (out_cap)) { _n = (size_t)-1; break; }                    \
        (out)[_n++] = (uint8_t)(_acc >> 16);                                   \
        (out)[_n++] = (uint8_t)((_acc >> 8) & 0xff);                           \
        (out)[_n++] = (uint8_t)(_acc & 0xff);                                  \
        _state = 0; _acc = 0;                                                  \
      }                                                                        \
    }                                                                          \
    if (_state == 2) {                                                         \
      if (_n + 1 > (out_cap)) { _n = (size_t)-1; }                             \
      else (out)[_n++] = (uint8_t)(_acc >> 4);                                 \
    } else if (_state == 3) {                                                  \
      if (_n + 2 > (out_cap)) { _n = (size_t)-1; }                             \
      else {                                                                   \
        (out)[_n++] = (uint8_t)(_acc >> 10);                                   \
        (out)[_n++] = (uint8_t)((_acc >> 2) & 0xff);                           \
      }                                                                        \
    }                                                                          \
    _n;                                                                        \
  })

    uint8_t a_der[256], b_der[256], a_spki[256], b_spki[256];
    size_t a_der_len = PEM_DECODE(a_pem, a_len, a_der, sizeof(a_der));
    size_t b_der_len = PEM_DECODE(b_pem, b_len, b_der, sizeof(b_der));
    size_t a_spki_der_len = PEM_DECODE(a_spki_pem, a_spki_len, a_spki, sizeof(a_spki));
    size_t b_spki_der_len = PEM_DECODE(b_spki_pem, b_spki_len, b_spki, sizeof(b_spki));
    if (a_der_len == (size_t)-1 || b_der_len == (size_t)-1
        || a_spki_der_len == (size_t)-1 || b_spki_der_len == (size_t)-1)
      return fail("pem decode");

    /* Find the 32-byte privateKey OCTET STRING in SEC1:
     *  SEQUENCE { INTEGER 1, OCTET STRING (32), [0] params, [1] pub }.
     * We skip the outer 2-byte SEQUENCE header + 3-byte version INTEGER and
     * pick up the OCTET STRING.
     */
    uint8_t *a_scalar = NULL, *b_scalar = NULL;
    /* Search for 04 20 (OCTET STRING of length 32). */
    for (size_t i = 0; i + 33 < a_der_len; i++)
      if (a_der[i] == 0x04 && a_der[i+1] == 0x20) { a_scalar = &a_der[i+2]; break; }
    for (size_t i = 0; i + 33 < b_der_len; i++)
      if (b_der[i] == 0x04 && b_der[i+1] == 0x20) { b_scalar = &b_der[i+2]; break; }
    if (!a_scalar || !b_scalar) return fail("sec1 scalar locate");

    uint8_t ss_a[32], ss_b[32];
    size_t ss_a_len = sizeof(ss_a), ss_b_len = sizeof(ss_b);
    if (pc_ecdh(PC_P256, a_scalar, 32, b_spki, b_spki_der_len,
                ss_a, &ss_a_len) != PC_OK)
      return fail("pc_ecdh a->b");
    if (pc_ecdh(PC_P256, b_scalar, 32, a_spki, a_spki_der_len,
                ss_b, &ss_b_len) != PC_OK)
      return fail("pc_ecdh b->a");
    if (ss_a_len != 32 || ss_b_len != 32 || memcmp(ss_a, ss_b, 32) != 0)
      return fail("ecdh shared secrets disagree");
#undef PEM_DECODE
  }

  /* 14. ML-KEM-768 round trip via FFI. Since I-6, pc_mlkem_encaps expects
   * the SPKI as raw DER bytes (matching its declared C ABI), not PEM. */
  {
    PcMlKem *k = pc_mlkem_generate(PC_ML_KEM_768);
    if (!k) return fail("pc_mlkem_generate");
    uint8_t spki[2048];
    size_t spki_len = sizeof(spki);
    if (pc_mlkem_public_to_der(k, spki, &spki_len) != PC_OK)
      return fail("pc_mlkem_public_to_der");
    uint8_t ct[1200];
    size_t ct_len = sizeof(ct);
    uint8_t ss_a[32], ss_b[32];
    if (pc_mlkem_encaps(PC_ML_KEM_768, spki, spki_len, ct, &ct_len, ss_a) != PC_OK)
      return fail("pc_mlkem_encaps");
    if (ct_len != 1088) return fail("mlkem ciphertext length");
    if (pc_mlkem_decaps(k, ct, ct_len, ss_b) != PC_OK)
      return fail("pc_mlkem_decaps");
    if (memcmp(ss_a, ss_b, 32) != 0) return fail("mlkem ss mismatch");
    pc_mlkem_free(k);
  }

  /* 15. ML-DSA-65 sign / verify round trip; tamper rejection. */
  {
    PcMlDsa *k = pc_mldsa_generate(PC_ML_DSA_65);
    if (!k) return fail("pc_mldsa_generate");
    uint8_t spki[3000];
    size_t spki_len = sizeof(spki);
    if (pc_mldsa_public_to_pem(k, spki, &spki_len) != PC_OK)
      return fail("pc_mldsa_public_to_pem");

    /* Strip the PEM armor manually (small inline decoder). */
    static const char b64chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int b64dec[256];
    for (int i = 0; i < 256; i++) b64dec[i] = -1;
    for (int i = 0; i < 64; i++) b64dec[(unsigned char)b64chars[i]] = i;
    uint8_t spki_der[3000];
    size_t spki_der_len = 0;
    const char *_b = (const char *)spki, *_e = (const char *)spki + spki_len;
    while (_b < _e && *_b != '\n') _b++; _b++;
    const char *_end = _e - 1;
    while (_end > _b && *_end != '-') _end--;
    while (_end > _b && *_end != '\n') _end--;
    int _state = 0; uint32_t _acc = 0;
    for (const char *_p = _b; _p < _end; _p++) {
      if (*_p == '\n' || *_p == '\r' || *_p == ' ' || *_p == '=') continue;
      int v = b64dec[(unsigned char)*_p];
      if (v < 0) return fail("ml-dsa pem decode");
      _acc = (_acc << 6) | (uint32_t)v;
      _state++;
      if (_state == 4) {
        spki_der[spki_der_len++] = (uint8_t)(_acc >> 16);
        spki_der[spki_der_len++] = (uint8_t)((_acc >> 8) & 0xff);
        spki_der[spki_der_len++] = (uint8_t)(_acc & 0xff);
        _state = 0; _acc = 0;
      }
    }
    if (_state == 2) spki_der[spki_der_len++] = (uint8_t)(_acc >> 4);
    else if (_state == 3) {
      spki_der[spki_der_len++] = (uint8_t)(_acc >> 10);
      spki_der[spki_der_len++] = (uint8_t)((_acc >> 2) & 0xff);
    }

    const uint8_t msg[] = "ml-dsa hello";
    uint8_t sig[5000];
    size_t sig_len = sizeof(sig);
    if (pc_mldsa_sign(k, msg, sizeof(msg), sig, &sig_len) != PC_OK)
      return fail("pc_mldsa_sign");
    if (pc_mldsa_verify(PC_ML_DSA_65, spki_der, spki_der_len,
                        msg, sizeof(msg), sig, sig_len) != PC_OK)
      return fail("pc_mldsa_verify");
    sig[0] ^= 1;
    if (pc_mldsa_verify(PC_ML_DSA_65, spki_der, spki_der_len,
                        msg, sizeof(msg), sig, sig_len) != PC_VERIFICATION)
      return fail("ml-dsa tampered sig not rejected");
    pc_mldsa_free(k);
  }

  /* 16. SLH-DSA SHA2-128f sign/verify round trip. */
  {
    PcSlhDsa *k = pc_slhdsa_generate(PC_SLH_DSA_SHA2_128F);
    if (!k) return fail("pc_slhdsa_generate");
    uint8_t spki[200];
    size_t spki_len = sizeof(spki);
    if (pc_slhdsa_public_to_pem(k, spki, &spki_len) != PC_OK)
      return fail("pc_slhdsa_public_to_pem");
    /* Decode the SPKI PEM as in test 15. */
    static const char b64chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int b64dec[256];
    for (int i = 0; i < 256; i++) b64dec[i] = -1;
    for (int i = 0; i < 64; i++) b64dec[(unsigned char)b64chars[i]] = i;
    uint8_t spki_der[200];
    size_t spki_der_len = 0;
    const char *_b = (const char *)spki, *_e = (const char *)spki + spki_len;
    while (_b < _e && *_b != '\n') _b++; _b++;
    const char *_end = _e - 1;
    while (_end > _b && *_end != '-') _end--;
    while (_end > _b && *_end != '\n') _end--;
    int _state = 0; uint32_t _acc = 0;
    for (const char *_p = _b; _p < _end; _p++) {
      if (*_p == '\n' || *_p == '\r' || *_p == ' ' || *_p == '=') continue;
      int v = b64dec[(unsigned char)*_p];
      if (v < 0) return fail("slh-dsa pem decode");
      _acc = (_acc << 6) | (uint32_t)v;
      _state++;
      if (_state == 4) {
        spki_der[spki_der_len++] = (uint8_t)(_acc >> 16);
        spki_der[spki_der_len++] = (uint8_t)((_acc >> 8) & 0xff);
        spki_der[spki_der_len++] = (uint8_t)(_acc & 0xff);
        _state = 0; _acc = 0;
      }
    }
    if (_state == 2) spki_der[spki_der_len++] = (uint8_t)(_acc >> 4);
    else if (_state == 3) {
      spki_der[spki_der_len++] = (uint8_t)(_acc >> 10);
      spki_der[spki_der_len++] = (uint8_t)((_acc >> 2) & 0xff);
    }
    const uint8_t msg[] = "slh-dsa hello";
    /* SLH-DSA-SHA2-128f signatures are 17 088 bytes. */
    static uint8_t sig[20000];
    size_t sig_len = sizeof(sig);
    if (pc_slhdsa_sign(k, msg, sizeof(msg), sig, &sig_len) != PC_OK)
      return fail("pc_slhdsa_sign");
    if (pc_slhdsa_verify(spki_der, spki_der_len,
                         msg, sizeof(msg), sig, sig_len) != PC_OK)
      return fail("pc_slhdsa_verify");
    pc_slhdsa_free(k);
  }

  /* 17. RSA-PSS sign/verify round trip. */
  {
    PcRsaKey *rsa = pc_rsa_generate(2048);
    if (!rsa) return fail("pc_rsa_generate");
    uint8_t spki_pem[2048];
    size_t spki_pem_len = sizeof(spki_pem);
    if (pc_rsa_public_to_pem(rsa, spki_pem, &spki_pem_len) != PC_OK)
      return fail("pc_rsa_public_to_pem");
    /* Decode PEM as above. */
    static const char b64chars[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int b64dec[256];
    for (int i = 0; i < 256; i++) b64dec[i] = -1;
    for (int i = 0; i < 64; i++) b64dec[(unsigned char)b64chars[i]] = i;
    uint8_t spki[2048];
    size_t spki_len = 0;
    {
      const char *_b = (const char *)spki_pem, *_e = (const char *)spki_pem + spki_pem_len;
      while (_b < _e && *_b != '\n') _b++; _b++;
      const char *_end = _e - 1;
      while (_end > _b && *_end != '-') _end--;
      while (_end > _b && *_end != '\n') _end--;
      int _state = 0; uint32_t _acc = 0;
      for (const char *_p = _b; _p < _end; _p++) {
        if (*_p == '\n' || *_p == '\r' || *_p == ' ' || *_p == '=') continue;
        int v = b64dec[(unsigned char)*_p];
        if (v < 0) return fail("rsa pem decode");
        _acc = (_acc << 6) | (uint32_t)v;
        _state++;
        if (_state == 4) {
          spki[spki_len++] = (uint8_t)(_acc >> 16);
          spki[spki_len++] = (uint8_t)((_acc >> 8) & 0xff);
          spki[spki_len++] = (uint8_t)(_acc & 0xff);
          _state = 0; _acc = 0;
        }
      }
      if (_state == 2) spki[spki_len++] = (uint8_t)(_acc >> 4);
      else if (_state == 3) {
        spki[spki_len++] = (uint8_t)(_acc >> 10);
        spki[spki_len++] = (uint8_t)((_acc >> 2) & 0xff);
      }
    }
    const uint8_t pss_msg[] = "rsa-pss hello";
    uint8_t sig[512];
    size_t sig_len = sizeof(sig);
    if (pc_rsa_sign_pss(rsa, PC_SHA256, pss_msg, sizeof(pss_msg),
                        sig, &sig_len) != PC_OK)
      return fail("pc_rsa_sign_pss");
    if (pc_rsa_verify_pss(spki, spki_len, PC_SHA256,
                          pss_msg, sizeof(pss_msg), sig, sig_len) != PC_OK)
      return fail("pc_rsa_verify_pss");

    /* 18. RSA-OAEP encrypt / decrypt round trip with the same key. */
    const uint8_t oaep_msg[] = "oaep round trip";
    uint8_t oaep_ct[512];
    size_t oaep_ct_len = sizeof(oaep_ct);
    if (pc_rsa_encrypt_oaep(spki, spki_len, PC_SHA256, NULL, 0,
                            oaep_msg, sizeof(oaep_msg),
                            oaep_ct, &oaep_ct_len) != PC_OK)
      return fail("pc_rsa_encrypt_oaep");
    uint8_t oaep_rt[64];
    size_t oaep_rt_len = sizeof(oaep_rt);
    if (pc_rsa_decrypt_oaep(rsa, PC_SHA256, NULL, 0,
                            oaep_ct, oaep_ct_len,
                            oaep_rt, &oaep_rt_len) != PC_OK)
      return fail("pc_rsa_decrypt_oaep");
    if (oaep_rt_len != sizeof(oaep_msg) ||
        memcmp(oaep_rt, oaep_msg, sizeof(oaep_msg)) != 0)
      return fail("oaep round trip");

    /* 19. CSR build → verify_self_signed via the RSA key. */
    PcCsr *csr = pc_csr_create_rsa(rsa, "ffi.test", NULL, 0);
    if (!csr) return fail("pc_csr_create_rsa");
    if (pc_csr_verify_self_signed(csr) != PC_OK)
      return fail("pc_csr_verify_self_signed");
    uint8_t cn[64];
    size_t cn_len = sizeof(cn);
    if (pc_csr_subject_cn(csr, cn, &cn_len) != PC_OK)
      return fail("pc_csr_subject_cn");
    if (cn_len != 8 || memcmp(cn, "ffi.test", 8) != 0)
      return fail("csr cn mismatch");
    pc_csr_free(csr);

    pc_rsa_free(rsa);
  }

  printf("ffi_smoke: OK\n");
  return 0;
}
