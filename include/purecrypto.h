/*
 * purecrypto C ABI.
 *
 * Build the library with, e.g.:
 *   cargo rustc --release --features ffi --crate-type staticlib   (-> libpurecrypto.a)
 *   cargo rustc --release --features ffi --crate-type cdylib      (-> libpurecrypto.so)
 *
 * Functional areas exposed by this header:
 *   - Hashing      — SHA-2/3, BLAKE2/3, Keccak, SM3, SHA-1, MD5, RIPEMD-160
 *                    (pc_digest, pc_hash_*, pc_hmac)
 *   - KDFs         — HKDF, PBKDF2, scrypt, Argon2, SP 800-108 KBKDF
 *                    (pc_hkdf/pc_pbkdf2/pc_scrypt/pc_argon2/pc_kbkdf_*)
 *   - AEAD         — AES-GCM/CCM, ChaCha20-Poly1305, AEGIS-128L/256,
 *                    Ascon-AEAD128 (pc_aead_*)
 *   - MACs         — AES-CMAC (pc_cmac), GMAC (pc_gmac)
 *   - AES key wrap — RFC 3394 / 5649 (pc_aes_kw_*, pc_aes_kwp_*)
 *   - Ascon XOFs   — Ascon-XOF128 / -CXOF128 (pc_ascon_xof / pc_ascon_cxof)
 *   - Randomness   — pc_rand_bytes
 *   - RSA          — keygen, PKCS#1 v1.5 + PSS sign/verify, OAEP enc/dec
 *   - ECDSA / Ed25519 / Ed448 — keygen + sign/verify
 *   - ECDH / X25519 / X448 — pc_ecdh, pc_x25519, pc_x448
 *   - SM2          — GB/T 32918 / RFC 8998 keygen, sign, verify, enc/dec (pc_sm2_*)
 *   - ML-KEM       — FIPS 203 keygen, encaps, decaps (pc_mlkem_*)
 *   - ML-DSA       — FIPS 204 keygen, sign, verify (pc_mldsa_*)
 *   - SLH-DSA      — FIPS 205 keygen, sign, verify (pc_slhdsa_*)
 *   - LMS / HSS    — RFC 8554 STATEFUL hash-based signatures (pc_lms_* / pc_hss_*)
 *   - XMSS / XMSS^MT — RFC 8391 STATEFUL hash-based signatures (pc_xmss_* / pc_xmssmt_*)
 *   - CSR          — PKCS#10 build / parse / self-sig verify (pc_csr_*)
 *   - X.509        — pc_cert_*
 *   - CRL          — pc_crl_*
 *   - TLS/DTLS     — 1.2/1.3 client + server, memory-BIO style (pc_tls_*)
 *
 * Conventions:
 *  - Functions return pc_status (0 = PC_OK, negative = error). Constructors
 *    instead return an opaque pointer that is NULL on failure.
 *  - Variable-length output uses the in/out length convention: pass a buffer and
 *    set *out_len to its capacity; on return *out_len is the actual length, or
 *    (on PC_BUFFER_TOO_SMALL) the required length. Call with out_len capacity 0
 *    to query the size first.
 *  - Opaque handles are created and freed by the library; pair every
 *    new/generate/from_* with the matching *_free.
 *  - Every entry point catches panics (returned as PC_INTERNAL).
 *
 * Threading:
 *   The opaque handles minted by this library (pc_hash, pc_hmac_ctx,
 *   pc_aead_ctx, pc_rsa, pc_ec, pc_mlkem, pc_mldsa, pc_slhdsa, pc_csr,
 *   pc_cert, pc_crl, pc_tls_cfg, pc_tls, pc_quic_cfg, pc_quic, ...) are
 *   NOT safe for concurrent use from multiple threads. The underlying
 *   Rust types are !Sync. Callers using the library from a threaded
 *   program MUST serialize every call that touches the same handle
 *   (e.g. with pthread_mutex_t). Different handles are independent and
 *   may be used concurrently on separate threads. The pc_rand_bytes
 *   entry point is the only stateless exception — it draws from the
 *   OS CSPRNG directly and is safe to call from any thread.
 */
#ifndef PURECRYPTO_H
#define PURECRYPTO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Result codes. */
typedef enum {
  PC_OK = 0,
  PC_NULL_POINTER = -1,
  PC_BUFFER_TOO_SMALL = -2,
  PC_BAD_ENCODING = -3,
  PC_VERIFICATION = -4,
  PC_UNSUPPORTED = -5,
  PC_INTERNAL = -6,
  /* TLS/DTLS engine status codes. */
  PC_WANT_READ = -7,       /* engine has nothing to emit; feed more bytes */
  PC_WANT_WRITE = -8,      /* engine has bytes to send; drain via pc_tls_pop */
  PC_WANT_HANDSHAKE = -9,  /* application I/O attempted before handshake done */
  PC_CLOSED = -10,         /* peer or local sent close_notify */
  PC_TLS_ALERT = -11       /* a fatal TLS alert was received */
} pc_status;

/* AEAD algorithm identifiers (for pc_aead_encrypt / pc_aead_decrypt). */
typedef enum {
  PC_AEAD_AES128_GCM = 1,
  PC_AEAD_AES256_GCM = 2,
  PC_AEAD_CHACHA20_POLY1305 = 3,
  PC_AEAD_AES128_CCM = 4,
  PC_AEAD_AES256_CCM = 5,
  PC_AEAD_AES128_CCM8 = 6,
  PC_AEAD_AES256_CCM8 = 7,
  PC_AEAD_AES128_GCM_SIV = 8,
  PC_AEAD_AES256_GCM_SIV = 9,
  PC_AEAD_XCHACHA20_POLY1305 = 10,
  PC_AEAD_AES128_SIV = 11,  /* nonce arg is the single AD; output is V||ct */
  PC_AEAD_AES256_SIV = 12,  /* 64-byte key */
  PC_AEAD_AEGIS128L = 13,   /* 16-byte key, 16-byte nonce */
  PC_AEAD_AEGIS256 = 14,    /* 32-byte key, 32-byte nonce */
  PC_AEAD_ASCON_AEAD128 = 15 /* 16-byte key, 16-byte nonce */
} pc_aead_id;

/* Argon2 variant (for pc_argon2). */
typedef enum {
  PC_ARGON2D = 4,
  PC_ARGON2I = 5,
  PC_ARGON2ID = 6
} pc_argon2_variant;

/* Hash algorithm identifiers (for pc_digest, pc_hash_new, pc_hmac, RSA sign). */
typedef enum {
  PC_SHA224 = 1,
  PC_SHA256 = 2,
  PC_SHA384 = 3,
  PC_SHA512 = 4,
  PC_SHA512_224 = 5,
  PC_SHA512_256 = 6,
  PC_SHA3_224 = 7,
  PC_SHA3_256 = 8,
  PC_SHA3_384 = 9,
  PC_SHA3_512 = 10,
  PC_KECCAK256 = 11,
  PC_BLAKE2B256 = 12,
  PC_BLAKE2B512 = 13,
  PC_BLAKE2S256 = 14,
  PC_BLAKE3 = 15,
  PC_SM3 = 16,
  PC_SHA1 = 17,
  PC_MD5 = 18,
  PC_RIPEMD160 = 19,
  PC_ASCON_HASH256 = 20
} pc_hash_id;

/* PRF selectors for the SP 800-108 KBKDF (pc_kbkdf_counter / _feedback). */
typedef enum {
  PC_KBKDF_HMAC_SHA256 = 1,
  PC_KBKDF_HMAC_SHA384 = 2,
  PC_KBKDF_HMAC_SHA512 = 3,
  PC_KBKDF_CMAC_AES128 = 4,  /* requires a 16-byte KI */
  PC_KBKDF_CMAC_AES256 = 5   /* requires a 32-byte KI */
} pc_kbkdf_prf;

/* Elliptic curve identifiers. */
typedef enum {
  PC_P256 = 1,
  PC_P384 = 2,
  PC_P521 = 3,
  PC_SECP256K1 = 4
} pc_curve;

/* ML-KEM parameter sets. */
typedef enum {
  PC_ML_KEM_512 = 1,
  PC_ML_KEM_768 = 2,
  PC_ML_KEM_1024 = 3
} pc_mlkem_set;

/* ML-DSA parameter sets. */
typedef enum {
  PC_ML_DSA_44 = 1,
  PC_ML_DSA_65 = 2,
  PC_ML_DSA_87 = 3
} pc_mldsa_set;

/* SLH-DSA parameter sets (FIPS 205 — 12 sets). */
typedef enum {
  PC_SLH_DSA_SHA2_128S = 1,
  PC_SLH_DSA_SHA2_128F = 2,
  PC_SLH_DSA_SHA2_192S = 3,
  PC_SLH_DSA_SHA2_192F = 4,
  PC_SLH_DSA_SHA2_256S = 5,
  PC_SLH_DSA_SHA2_256F = 6,
  PC_SLH_DSA_SHAKE_128S = 7,
  PC_SLH_DSA_SHAKE_128F = 8,
  PC_SLH_DSA_SHAKE_192S = 9,
  PC_SLH_DSA_SHAKE_192F = 10,
  PC_SLH_DSA_SHAKE_256S = 11,
  PC_SLH_DSA_SHAKE_256F = 12
} pc_slhdsa_set;

/* LMS parameter sets (RFC 8554 §5.1 typecodes; tree height h). */
typedef enum {
  PC_LMS_SHA256_M32_H5 = 5,
  PC_LMS_SHA256_M32_H10 = 6,
  PC_LMS_SHA256_M32_H15 = 7,
  PC_LMS_SHA256_M32_H20 = 8,
  PC_LMS_SHA256_M32_H25 = 9
} pc_lms_type;

/* LM-OTS parameter sets (RFC 8554 §4.1 typecodes; Winternitz width w). */
typedef enum {
  PC_LMOTS_SHA256_N32_W1 = 1,
  PC_LMOTS_SHA256_N32_W2 = 2,
  PC_LMOTS_SHA256_N32_W4 = 3,
  PC_LMOTS_SHA256_N32_W8 = 4
} pc_lmots_type;

/* Opaque handles. */
typedef struct PcHash PcHash;
typedef struct PcRsaKey PcRsaKey;
typedef struct PcEcKey PcEcKey;
typedef struct PcEd25519Key PcEd25519Key;
typedef struct PcEd448Key PcEd448Key;
typedef struct PcCert PcCert;
typedef struct PcMlKem PcMlKem;
typedef struct PcMlDsa PcMlDsa;
typedef struct PcSlhDsa PcSlhDsa;
typedef struct PcSm2 PcSm2;
typedef struct PcLms PcLms;     /* STATEFUL — see pc_lms_* contract below */
typedef struct PcHss PcHss;     /* STATEFUL — see pc_hss_* contract below */
typedef struct PcXmss PcXmss;   /* STATEFUL — see pc_xmss_* contract below */
typedef struct PcXmssMt PcXmssMt; /* STATEFUL — see pc_xmssmt_* contract below */
typedef struct PcCsr PcCsr;
typedef struct PcCrl PcCrl;
typedef struct PcTlsCfg PcTlsCfg;
typedef struct PcTls PcTls;
typedef struct PcQuicCfg PcQuicCfg;
typedef struct PcQuic PcQuic;

/* TLS / DTLS role + version selectors. */
typedef enum { PC_TLS_CLIENT = 0, PC_TLS_SERVER = 1 } pc_tls_role;
typedef enum {
  PC_TLS_1_2 = 0x0303,
  PC_TLS_1_3 = 0x0304,
  PC_DTLS_1_2 = (int)0xFEFD,
  PC_DTLS_1_3 = (int)0xFEFC
} pc_tls_version;

/* ---- Hashing ---- */
pc_status pc_digest(int32_t alg, const uint8_t *data, size_t data_len,
                    uint8_t *out, size_t *out_len);
PcHash *pc_hash_new(int32_t alg);
pc_status pc_hash_update(PcHash *h, const uint8_t *data, size_t len);
pc_status pc_hash_finish(PcHash *h, uint8_t *out, size_t *out_len);
void pc_hash_free(PcHash *h);

/* ---- HMAC (SHA-1, SHA-2, SHA-3, SM3, RIPEMD-160) ---- */
pc_status pc_hmac(int32_t alg, const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len, uint8_t *out,
                  size_t *out_len);

/* ---- AEAD ciphers (AES-GCM/CCM, ChaCha20-Poly1305) ----
 *
 * pc_aead_encrypt writes ciphertext+tag in one buffer (tag appended). On
 * success *ct_and_tag_len = pt_len + tag_len (16 by default, 8 for CCM8).
 * pc_aead_decrypt verifies the tag before any plaintext is written and returns
 * PC_VERIFICATION on mismatch (CCM additionally wipes the working buffer).
 */
pc_status pc_aead_encrypt(int32_t alg, const uint8_t *key, size_t key_len,
                          const uint8_t *nonce, size_t nonce_len,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *pt, size_t pt_len,
                          uint8_t *ct_and_tag, size_t *ct_and_tag_len);
pc_status pc_aead_decrypt(int32_t alg, const uint8_t *key, size_t key_len,
                          const uint8_t *nonce, size_t nonce_len,
                          const uint8_t *aad, size_t aad_len,
                          const uint8_t *ct_and_tag, size_t ct_and_tag_len,
                          uint8_t *pt, size_t *pt_len);

/* ---- AES key wrap (RFC 3394) and key wrap with padding (RFC 5649) ----
 * kek_len = 16 or 32 selects AES-128 or AES-256.
 */
pc_status pc_aes_kw_wrap(const uint8_t *kek, size_t kek_len,
                         const uint8_t *key, size_t key_len,
                         uint8_t *out, size_t *out_len);
pc_status pc_aes_kw_unwrap(const uint8_t *kek, size_t kek_len,
                           const uint8_t *ct, size_t ct_len,
                           uint8_t *out, size_t *out_len);
pc_status pc_aes_kwp_wrap(const uint8_t *kek, size_t kek_len,
                          const uint8_t *key, size_t key_len,
                          uint8_t *out, size_t *out_len);
pc_status pc_aes_kwp_unwrap(const uint8_t *kek, size_t kek_len,
                            const uint8_t *ct, size_t ct_len,
                            uint8_t *out, size_t *out_len);

/* ---- Block-cipher MACs ----
 * pc_cmac: AES-CMAC (RFC 4493). key_len 16/32 selects AES-128/256; 16-byte tag.
 * pc_gmac: GMAC (NIST SP 800-38D). key_len 16/32 selects AES-128/256; the nonce
 *          MUST be 12 bytes and unique per (key, message); 16-byte tag.
 */
pc_status pc_cmac(const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len,
                  uint8_t *out, size_t *out_len);
pc_status pc_gmac(const uint8_t *key, size_t key_len,
                  const uint8_t *nonce, size_t nonce_len,
                  const uint8_t *data, size_t data_len,
                  uint8_t *out, size_t *out_len);

/* ---- Ascon XOFs (NIST SP 800-232) ----
 * Squeeze exactly out_len bytes (out_len is the requested length, not an in/out
 * capacity). pc_ascon_cxof takes a customization string (at most 256 bytes).
 */
pc_status pc_ascon_xof(const uint8_t *data, size_t data_len,
                       uint8_t *out, size_t out_len);
pc_status pc_ascon_cxof(const uint8_t *custom, size_t custom_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t *out, size_t out_len);

/* ---- KDFs ---- */
pc_status pc_hkdf(int32_t hash,
                  const uint8_t *salt, size_t salt_len,
                  const uint8_t *ikm, size_t ikm_len,
                  const uint8_t *info, size_t info_len,
                  uint8_t *out, size_t out_len);
pc_status pc_pbkdf2(int32_t hash,
                    const uint8_t *pw, size_t pw_len,
                    const uint8_t *salt, size_t salt_len,
                    uint32_t iterations,
                    uint8_t *out, size_t out_len);
pc_status pc_scrypt(const uint8_t *pw, size_t pw_len,
                    const uint8_t *salt, size_t salt_len,
                    uint32_t n, uint32_t r, uint32_t p,
                    uint8_t *out, size_t out_len);
pc_status pc_argon2(int32_t variant,
                    const uint8_t *pw, size_t pw_len,
                    const uint8_t *salt, size_t salt_len,
                    uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                    uint8_t *out, size_t out_len);
/* SP 800-108 KBKDF. prf is a pc_kbkdf_prf. Counter-mode fixed input is
 * [i]_32 || Label || 0x00 || Context || [L]_32; feedback-mode prepends K(i-1)
 * with K(0) = iv (which may be empty). out_len is the requested output length. */
pc_status pc_kbkdf_counter(int32_t prf,
                           const uint8_t *ki, size_t ki_len,
                           const uint8_t *label, size_t label_len,
                           const uint8_t *context, size_t context_len,
                           uint8_t *out, size_t out_len);
pc_status pc_kbkdf_feedback(int32_t prf,
                            const uint8_t *ki, size_t ki_len,
                            const uint8_t *iv, size_t iv_len,
                            const uint8_t *label, size_t label_len,
                            const uint8_t *context, size_t context_len,
                            uint8_t *out, size_t out_len);

/* ---- Randomness ---- */
pc_status pc_rand_bytes(uint8_t *out, size_t len);

/* ---- RSA ---- */
PcRsaKey *pc_rsa_generate(uint32_t bits); /* 2048 | 3072 | 4096 */
PcRsaKey *pc_rsa_from_pem(const uint8_t *pem, size_t len);
pc_status pc_rsa_private_to_pem(const PcRsaKey *key, uint8_t *out,
                               size_t *out_len);
pc_status pc_rsa_public_to_pem(const PcRsaKey *key, uint8_t *out,
                              size_t *out_len);
pc_status pc_rsa_sign_pkcs1(const PcRsaKey *key, int32_t alg,
                            const uint8_t *msg, size_t msg_len, uint8_t *out,
                            size_t *out_len);
pc_status pc_rsa_verify_pkcs1(const uint8_t *spki, size_t spki_len, int32_t alg,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *sig, size_t sig_len);
void pc_rsa_free(PcRsaKey *key);

/* ---- ECDSA ---- */
PcEcKey *pc_ec_generate(int32_t curve);
PcEcKey *pc_ec_from_pem(const uint8_t *pem, size_t len);
pc_status pc_ec_private_to_pem(const PcEcKey *key, uint8_t *out,
                              size_t *out_len);
pc_status pc_ec_public_to_pem(const PcEcKey *key, uint8_t *out, size_t *out_len);
pc_status pc_ec_sign(const PcEcKey *key, const uint8_t *msg, size_t msg_len,
                     uint8_t *out, size_t *out_len);
pc_status pc_ec_verify(const uint8_t *spki, size_t spki_len, const uint8_t *msg,
                       size_t msg_len, const uint8_t *sig, size_t sig_len);
void pc_ec_free(PcEcKey *key);

/* ---- ECDH (NIST P-256/P-384/P-521/secp256k1) ----
 * `priv_be` is the big-endian private scalar (field_len bytes for the curve).
 * `peer_spki` is the peer's SPKI DER.
 * Output is the affine x-coordinate of the shared point, big-endian.
 */
pc_status pc_ecdh(int32_t curve, const uint8_t *priv_be, size_t priv_len,
                  const uint8_t *peer_spki, size_t peer_spki_len,
                  uint8_t *out, size_t *out_len);

/* ---- X25519 (RFC 7748) ----
 * Returns PC_VERIFICATION when `peer` is a small-order point.
 */
pc_status pc_x25519(const uint8_t *scalar, const uint8_t *peer, uint8_t *out);
pc_status pc_x25519_public(const uint8_t *scalar, uint8_t *out);

/* ---- X448 (RFC 7748) ----
 * 56-byte scalar / peer / output. Returns PC_VERIFICATION when `peer` is a
 * small-order point.
 */
pc_status pc_x448(const uint8_t *scalar, const uint8_t *peer, uint8_t *out);
pc_status pc_x448_public(const uint8_t *scalar, uint8_t *out);

/* ---- Ed25519 ---- */
PcEd25519Key *pc_ed25519_generate(void);
PcEd25519Key *pc_ed25519_from_pem(const uint8_t *pem, size_t len);
pc_status pc_ed25519_private_to_pem(const PcEd25519Key *key, uint8_t *out,
                                    size_t *out_len);
pc_status pc_ed25519_public_to_pem(const PcEd25519Key *key, uint8_t *out,
                                   size_t *out_len);
pc_status pc_ed25519_sign(const PcEd25519Key *key, const uint8_t *msg,
                          size_t msg_len, uint8_t *out, size_t *out_len);
pc_status pc_ed25519_verify(const uint8_t *spki, size_t spki_len,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len);
void pc_ed25519_free(PcEd25519Key *key);

/* ---- Ed448 ----
 * Signatures are the raw 114-byte R||S; the empty context is used (pure
 * Ed448, RFC 8032 section 5.2).
 */
PcEd448Key *pc_ed448_generate(void);
PcEd448Key *pc_ed448_from_pem(const uint8_t *pem, size_t len);
pc_status pc_ed448_private_to_pem(const PcEd448Key *key, uint8_t *out,
                                  size_t *out_len);
pc_status pc_ed448_public_to_pem(const PcEd448Key *key, uint8_t *out,
                                 size_t *out_len);
pc_status pc_ed448_sign(const PcEd448Key *key, const uint8_t *msg,
                        size_t msg_len, uint8_t *out, size_t *out_len);
pc_status pc_ed448_verify(const uint8_t *spki, size_t spki_len,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len);
void pc_ed448_free(PcEd448Key *key);

/* ---- X.509 ---- */
PcCert *pc_cert_from_pem(const uint8_t *pem, size_t len);
PcCert *pc_cert_from_der(const uint8_t *der, size_t len);
pc_status pc_cert_to_der(const PcCert *cert, uint8_t *out, size_t *out_len);
pc_status pc_cert_public_key_spki(const PcCert *cert, uint8_t *out,
                                  size_t *out_len);
pc_status pc_cert_verify(const PcCert *cert, const PcCert *issuer);
void pc_cert_free(PcCert *cert);

/* Convenience: issue a self-signed ECDSA certificate (DNS SAN = `cn`,
 * basicConstraints CA = false, validity = `days` days from now). The PEM
 * is suitable both for pc_tls_cfg_set_certificate's chain and (when reused
 * by the other endpoint) for pc_tls_cfg_add_root_pem's trust anchor. */
pc_status pc_ec_self_signed_pem(const PcEcKey *key, const char *cn,
                                uint32_t days, uint8_t *out, size_t *out_len);

/* ---- RSA-PSS sign / verify ---- */
pc_status pc_rsa_sign_pss(const PcRsaKey *key, int32_t alg,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t *out, size_t *out_len);
pc_status pc_rsa_verify_pss(const uint8_t *spki, size_t spki_len, int32_t alg,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len);

/* ---- RSA-OAEP encrypt / decrypt ----
 * hash selects both EME and MGF1 (SHA-256/384/512).
 * label may be empty (NULL with label_len == 0). */
pc_status pc_rsa_encrypt_oaep(const uint8_t *spki, size_t spki_len, int32_t hash,
                              const uint8_t *label, size_t label_len,
                              const uint8_t *pt, size_t pt_len,
                              uint8_t *out, size_t *out_len);
pc_status pc_rsa_decrypt_oaep(const PcRsaKey *key, int32_t hash,
                              const uint8_t *label, size_t label_len,
                              const uint8_t *ct, size_t ct_len,
                              uint8_t *out, size_t *out_len);

/* ---- ML-KEM (FIPS 203) ---- */
PcMlKem *pc_mlkem_generate(int32_t set);
PcMlKem *pc_mlkem_from_pkcs8_pem(const uint8_t *pem, size_t len);
pc_status pc_mlkem_private_to_pem(const PcMlKem *k, uint8_t *out, size_t *out_len);
pc_status pc_mlkem_public_to_pem(const PcMlKem *k, uint8_t *out, size_t *out_len);
pc_status pc_mlkem_public_to_der(const PcMlKem *k, uint8_t *out, size_t *out_len);
/* pc_mlkem_encaps expects ek_spki to be a raw SPKI DER blob (not PEM). */
pc_status pc_mlkem_encaps(int32_t set, const uint8_t *ek_spki, size_t ek_spki_len,
                          uint8_t *ct, size_t *ct_len, uint8_t ss[32]);
pc_status pc_mlkem_decaps(const PcMlKem *k, const uint8_t *ct, size_t ct_len, uint8_t ss[32]);
void pc_mlkem_free(PcMlKem *k);

/* ---- ML-DSA (FIPS 204) ---- */
PcMlDsa *pc_mldsa_generate(int32_t set);
PcMlDsa *pc_mldsa_from_pkcs8_pem(const uint8_t *pem, size_t len);
pc_status pc_mldsa_private_to_pem(const PcMlDsa *k, uint8_t *out, size_t *out_len);
pc_status pc_mldsa_public_to_pem(const PcMlDsa *k, uint8_t *out, size_t *out_len);
pc_status pc_mldsa_sign(const PcMlDsa *k, const uint8_t *msg, size_t msg_len,
                        uint8_t *out, size_t *out_len);
pc_status pc_mldsa_verify(int32_t set, const uint8_t *spki, size_t spki_len,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len);
void pc_mldsa_free(PcMlDsa *k);

/* ---- SLH-DSA (FIPS 205) ---- */
PcSlhDsa *pc_slhdsa_generate(int32_t set);
PcSlhDsa *pc_slhdsa_from_pkcs8_pem(const uint8_t *pem, size_t len);
pc_status pc_slhdsa_private_to_pem(const PcSlhDsa *k, uint8_t *out, size_t *out_len);
pc_status pc_slhdsa_public_to_pem(const PcSlhDsa *k, uint8_t *out, size_t *out_len);
pc_status pc_slhdsa_sign(const PcSlhDsa *k, const uint8_t *msg, size_t msg_len,
                         uint8_t *out, size_t *out_len);
pc_status pc_slhdsa_verify(const uint8_t *spki, size_t spki_len,
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len);
void pc_slhdsa_free(PcSlhDsa *k);

/* ---- SM2 (GB/T 32918 / RFC 8998) ----
 * SM2 is NOT routed through pc_ec_* (which rejects the SM2 curve). These use
 * SM2-DSA (with the Z_A signer identity; id NULL/0 selects the default
 * 1234567812345678) and SM2 hybrid PKE. Private keys are SEC1 'EC PRIVATE KEY'
 * PEM; public keys are 'PUBLIC KEY' SPKI DER. Signatures are DER Ecdsa-Sig-Value.
 */
PcSm2 *pc_sm2_generate(void);
PcSm2 *pc_sm2_from_pem(const uint8_t *pem, size_t len);
pc_status pc_sm2_private_to_pem(const PcSm2 *k, uint8_t *out, size_t *out_len);
pc_status pc_sm2_public_to_pem(const PcSm2 *k, uint8_t *out, size_t *out_len);
pc_status pc_sm2_sign(const PcSm2 *k, const uint8_t *id, size_t id_len,
                      const uint8_t *msg, size_t msg_len,
                      uint8_t *out, size_t *out_len);
pc_status pc_sm2_verify(const uint8_t *spki, size_t spki_len,
                        const uint8_t *id, size_t id_len,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *sig, size_t sig_len);
pc_status pc_sm2_encrypt(const uint8_t *spki, size_t spki_len,
                         const uint8_t *pt, size_t pt_len,
                         uint8_t *out, size_t *out_len);
pc_status pc_sm2_decrypt(const PcSm2 *k, const uint8_t *ct, size_t ct_len,
                         uint8_t *out, size_t *out_len);
void pc_sm2_free(PcSm2 *k);

/* ============================================================================
 * STATEFUL hash-based signatures: LMS / HSS (RFC 8554) and XMSS / XMSS^MT
 * (RFC 8391). These keys carry a one-time-key index that ADVANCES on every
 * signature. The signing handle's state lives in memory only; there is no
 * in-library persistence.
 *
 * CONTRACT — after EVERY successful *_sign:
 *   1. re-serialize the handle with the matching *_private_to_bytes, and
 *   2. durably persist those bytes (overwriting the prior copy)
 * BEFORE the produced signature is released or used. Signing two different
 * messages from the same persisted state reuses a one-time key and can leak
 * the signing key — catastrophic. The private-key serialization embeds the
 * live index; the public-key blob from *_public_to_bytes is self-describing
 * (it carries the parameter set) so *_verify needs no extra parameter.
 * ==========================================================================*/

/* ---- LMS (single tree) ---- */
PcLms *pc_lms_generate(int32_t lms_param, int32_t lmots_param); /* pc_lms_type, pc_lmots_type */
PcLms *pc_lms_from_bytes(const uint8_t *bytes, size_t len);
pc_status pc_lms_private_to_bytes(const PcLms *k, uint8_t *out, size_t *out_len);
pc_status pc_lms_public_to_bytes(const PcLms *k, uint8_t *out, size_t *out_len);
/* Advances the handle's index; persist via pc_lms_private_to_bytes before use.
 * The output capacity is checked BEFORE signing: a size query (*out_len == 0)
 * or too-small buffer returns PC_BUFFER_TOO_SMALL with the required length in
 * *out_len and does NOT consume a one-time key. */
pc_status pc_lms_sign(PcLms *k, const uint8_t *msg, size_t msg_len,
                      uint8_t *out, size_t *out_len);
pc_status pc_lms_verify(const uint8_t *pubkey, size_t pubkey_len,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *sig, size_t sig_len);
void pc_lms_free(PcLms *k);

/* ---- HSS (multi-level LMS) ---- */
PcHss *pc_hss_generate(size_t levels, int32_t lms_param, int32_t lmots_param); /* levels 1..8 */
PcHss *pc_hss_from_bytes(const uint8_t *bytes, size_t len);
pc_status pc_hss_private_to_bytes(const PcHss *k, uint8_t *out, size_t *out_len);
pc_status pc_hss_public_to_bytes(const PcHss *k, uint8_t *out, size_t *out_len);
/* Advances the handle's state; persist via pc_hss_private_to_bytes before use.
 * Capacity is checked BEFORE signing (see pc_lms_sign): a size query never
 * consumes a one-time key. */
pc_status pc_hss_sign(PcHss *k, const uint8_t *msg, size_t msg_len,
                      uint8_t *out, size_t *out_len);
pc_status pc_hss_verify(const uint8_t *pubkey, size_t pubkey_len,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *sig, size_t sig_len);
void pc_hss_free(PcHss *k);

/* ---- XMSS (single tree) ----
 * oid is the RFC 8391 numeric parameter-set OID (e.g. 1 = XMSS-SHA2_10_256).
 */
PcXmss *pc_xmss_generate(uint32_t oid);
PcXmss *pc_xmss_from_bytes(const uint8_t *bytes, size_t len);
pc_status pc_xmss_private_to_bytes(const PcXmss *k, uint8_t *out, size_t *out_len);
pc_status pc_xmss_public_to_bytes(const PcXmss *k, uint8_t *out, size_t *out_len);
/* Advances the handle's index; persist via pc_xmss_private_to_bytes before use.
 * Capacity is checked BEFORE signing (see pc_lms_sign): a size query never
 * consumes a one-time key. */
pc_status pc_xmss_sign(PcXmss *k, const uint8_t *msg, size_t msg_len,
                       uint8_t *out, size_t *out_len);
pc_status pc_xmss_verify(const uint8_t *pubkey, size_t pubkey_len,
                         const uint8_t *msg, size_t msg_len,
                         const uint8_t *sig, size_t sig_len);
void pc_xmss_free(PcXmss *k);

/* ---- XMSS^MT (multi-tree) ---- */
PcXmssMt *pc_xmssmt_generate(uint32_t oid);
PcXmssMt *pc_xmssmt_from_bytes(const uint8_t *bytes, size_t len);
pc_status pc_xmssmt_private_to_bytes(const PcXmssMt *k, uint8_t *out, size_t *out_len);
pc_status pc_xmssmt_public_to_bytes(const PcXmssMt *k, uint8_t *out, size_t *out_len);
/* Advances the handle's state; persist via pc_xmssmt_private_to_bytes before use.
 * Capacity is checked BEFORE signing (see pc_lms_sign): a size query never
 * consumes a one-time key. */
pc_status pc_xmssmt_sign(PcXmssMt *k, const uint8_t *msg, size_t msg_len,
                         uint8_t *out, size_t *out_len);
pc_status pc_xmssmt_verify(const uint8_t *pubkey, size_t pubkey_len,
                           const uint8_t *msg, size_t msg_len,
                           const uint8_t *sig, size_t sig_len);
void pc_xmssmt_free(PcXmssMt *k);

/* ---- CSR (PKCS#10) ---- */
PcCsr *pc_csr_create_rsa(const PcRsaKey *rsa_key, const char *subject_cn,
                         const char *const *dns_names, size_t dns_count);
PcCsr *pc_csr_from_pem(const uint8_t *pem, size_t len);
pc_status pc_csr_to_pem(const PcCsr *csr, uint8_t *out, size_t *out_len);
pc_status pc_csr_verify_self_signed(const PcCsr *csr);
pc_status pc_csr_subject_cn(const PcCsr *csr, uint8_t *out, size_t *out_len);
void pc_csr_free(PcCsr *csr);

/* ---- CRL ---- */
PcCrl *pc_crl_from_pem(const uint8_t *pem, size_t len);
PcCrl *pc_crl_from_der(const uint8_t *der, size_t len);
pc_status pc_crl_verify_with(const PcCrl *crl, const PcCert *issuer);
/* Returns 1 (revoked), 0 (not revoked), or -1 on a CRL parse error. */
int pc_crl_is_revoked(const PcCrl *crl, const uint8_t *serial_be, size_t len);
void pc_crl_free(PcCrl *crl);

/* ============================================================================
 * TLS / DTLS (memory-BIO style — the underlying engine is sans-I/O).
 *
 * Usage pattern:
 *   1. PcTlsCfg *cfg = pc_tls_cfg_new(role, version);
 *      configure (roots, cert, SNI, ALPN, …);
 *   2. PcTls *ssl = pc_tls_new(cfg);            // may be called repeatedly
 *   3. loop:
 *        pc_tls_handshake(ssl);
 *        // if WANT_WRITE: pc_tls_pop(ssl, buf, &n); send(buf, n) to peer
 *        // if WANT_READ:  recv(buf, &n); pc_tls_feed(ssl, buf, n, NULL)
 *        // if OK:         handshake done
 *   4. pc_tls_send(ssl, app_in, n);             // post-handshake
 *      pc_tls_pop(ssl, wire_out, &m);           // drain & transmit
 *      pc_tls_feed(ssl, wire_in, k, NULL);      // peer's reply
 *      pc_tls_recv(ssl, app_out, &j);           // decrypted bytes
 *   5. pc_tls_close(ssl);
 *      pc_tls_free(ssl);
 *      pc_tls_cfg_free(cfg);
 * ========================================================================== */

PcTlsCfg *pc_tls_cfg_new(int32_t role, int32_t version);
void pc_tls_cfg_free(PcTlsCfg *cfg);

pc_status pc_tls_cfg_add_root_pem(PcTlsCfg *cfg, const uint8_t *pem, size_t len);
pc_status pc_tls_cfg_set_server_name(PcTlsCfg *cfg, const char *sni);
pc_status pc_tls_cfg_set_certificate(PcTlsCfg *cfg,
                                     const uint8_t *chain_pem, size_t chain_len,
                                     const uint8_t *key_pem, size_t key_pem_len);
pc_status pc_tls_cfg_set_alpn(PcTlsCfg *cfg, const char *const *protocols, size_t n);
pc_status pc_tls_cfg_set_verify_certificates(PcTlsCfg *cfg, int32_t verify);
pc_status pc_tls_cfg_set_client_auth(PcTlsCfg *cfg, int32_t required,
                                     const uint8_t *roots_pem, size_t roots_pem_len);
pc_status pc_tls_cfg_add_crl_pem(PcTlsCfg *cfg, const uint8_t *pem, size_t len);

/* DTLS server only: cookie-exchange secret. `secret_len` MUST be 32; any
 * other length is rejected with PC_UNSUPPORTED. The explicit-length form
 * replaces an earlier null-terminator-less 32-byte fixed signature so the
 * size mismatch is visible at the C ABI rather than silently reading past
 * the end of a short caller buffer. */
pc_status pc_dtls_cfg_set_cookie_secret(PcTlsCfg *cfg,
                                        const uint8_t *secret, size_t secret_len);
/* DTLS server only: disable the cookie round-trip (HelloVerifyRequest / HRR
 * cookie). Recommended only for tests. */
pc_status pc_dtls_cfg_set_no_cookie(PcTlsCfg *cfg);

PcTls *pc_tls_new(const PcTlsCfg *cfg);
void pc_tls_free(PcTls *tls);

/* Feed wire bytes from the peer into the engine. If `consumed` is non-NULL,
 * the count of bytes accepted into the engine's input buffer is written
 * before this call returns — including on the error path (today the engines
 * buffer eagerly, so on error `*consumed == in_len`). Callers MUST consult
 * `*consumed` after a non-`Ok` return so they neither re-feed already-
 * buffered bytes nor lose the still-unbuffered tail. */
pc_status pc_tls_feed(PcTls *tls, const uint8_t *wire_in, size_t in_len, size_t *consumed);
/* pc_tls_pop / pc_tls_recv: a PC_BUFFER_TOO_SMALL return (including the
 * size-query call with *out_len == 0) is non-destructive — the pending
 * chunk is retained and re-served by the next call, with *out_len set to
 * the required length. */
pc_status pc_tls_pop(PcTls *tls, uint8_t *wire_out, size_t *out_len);
pc_status pc_tls_send(PcTls *tls, const uint8_t *app_in, size_t in_len);
pc_status pc_tls_recv(PcTls *tls, uint8_t *app_out, size_t *out_len);
pc_status pc_tls_handshake(PcTls *tls);
pc_status pc_tls_close(PcTls *tls);

int pc_tls_is_handshake_complete(const PcTls *tls);
pc_status pc_tls_negotiated_version(const PcTls *tls, uint16_t *out);
pc_status pc_tls_negotiated_cipher_suite(const PcTls *tls, uint16_t *out);
pc_status pc_tls_negotiated_cipher_suite_name(const PcTls *tls,
                                              uint8_t *out, size_t *out_len);
pc_status pc_tls_alpn_selected(const PcTls *tls, uint8_t *out, size_t *out_len);
pc_status pc_tls_peer_server_name(const PcTls *tls, uint8_t *out, size_t *out_len);
pc_status pc_tls_peer_certificate(const PcTls *tls, uint8_t *out, size_t *out_len);

/* DTLS-only: timeout machinery. */
pc_status pc_dtls_next_timeout(const PcTls *tls,
                               uint64_t *seconds_out, uint32_t *nanos_out,
                               int32_t *has_timeout);
pc_status pc_dtls_on_timeout(PcTls *tls, uint64_t now_seconds, uint32_t now_nanos);

/* ============================================================================
 * QUIC v1 (RFC 9000 / 9001 / 9002 / 9221) — memory-BIO style. The underlying
 * engine is sans-I/O; the host wires it to a `UdpSocket`.
 *
 * Usage pattern:
 *   1. PcQuicCfg *cfg = pc_quic_cfg_new(role);
 *      configure (roots, cert, server_name, ALPN, transport params, ...);
 *   2. PcQuic *q = pc_quic_new(cfg);
 *      pc_quic_set_peer_addr(q, peer_ipv6_16, 16, peer_port);  // server: from recvfrom
 *   3. loop:
 *        pc_quic_handshake(q);
 *        // drain outbound:
 *        while (pc_quic_pop_datagram(q, buf, &n), n > 0) sendto(peer, buf, n);
 *        // recv:  recvfrom(...);  pc_quic_feed_datagram(q, buf, n);
 *        // tick:  pc_quic_on_timeout(q, secs, nanos);
 *   4. pc_quic_open_bidi(q, &id);
 *      pc_quic_stream_write(q, id, data, len, &written);
 *      pc_quic_stream_finish(q, id);
 *      pc_quic_stream_read(q, id, app, &m, &fin);
 *   5. pc_quic_free(q); pc_quic_cfg_free(cfg);
 *
 * Only QUIC v1 (RFC 9000) is supported; PC_QUIC_V1 is provided for
 * future-proofing.
 * ========================================================================== */

/* QUIC wire version. */
#define PC_QUIC_V1 0x00000001

PcQuicCfg *pc_quic_cfg_new(int32_t role);     /* PC_TLS_CLIENT | PC_TLS_SERVER */
void       pc_quic_cfg_free(PcQuicCfg *cfg);

pc_status pc_quic_cfg_add_root_pem(PcQuicCfg *cfg, const uint8_t *pem, size_t len);
pc_status pc_quic_cfg_set_server_name(PcQuicCfg *cfg, const char *sni);
pc_status pc_quic_cfg_set_certificate(PcQuicCfg *cfg,
                                      const uint8_t *chain_pem, size_t chain_len,
                                      const uint8_t *key_pem,  size_t key_len);
pc_status pc_quic_cfg_set_alpn(PcQuicCfg *cfg, const char *const *protocols, size_t n);
pc_status pc_quic_cfg_set_verify_certificates(PcQuicCfg *cfg, int32_t verify);

pc_status pc_quic_cfg_set_max_idle_timeout_ms(PcQuicCfg *cfg, uint64_t ms);
pc_status pc_quic_cfg_set_initial_max_data(PcQuicCfg *cfg, uint64_t bytes);
pc_status pc_quic_cfg_set_initial_max_streams_bidi(PcQuicCfg *cfg, uint64_t streams);
pc_status pc_quic_cfg_set_max_datagram_frame_size(PcQuicCfg *cfg, uint64_t bytes);
pc_status pc_quic_cfg_set_require_retry(PcQuicCfg *cfg, int32_t require);   /* server-only */

PcQuic *pc_quic_new(const PcQuicCfg *cfg);
void    pc_quic_free(PcQuic *q);

pc_status pc_quic_feed_datagram(PcQuic *q, const uint8_t *dg, size_t len);
/* pc_quic_pop_datagram / pc_quic_recv_datagram: a PC_BUFFER_TOO_SMALL return
 * (including the size-query call with *out_len == 0) is non-destructive —
 * the pending datagram/payload is retained and re-served by the next call,
 * with *out_len set to the required length. */
pc_status pc_quic_pop_datagram(PcQuic *q, uint8_t *out, size_t *out_len);
pc_status pc_quic_handshake(PcQuic *q);
pc_status pc_quic_is_handshake_complete(const PcQuic *q, int32_t *out);

pc_status pc_quic_next_timeout(const PcQuic *q,
                               uint64_t *seconds_out, uint32_t *nanos_out,
                               int32_t  *has_timeout);
pc_status pc_quic_on_timeout(PcQuic *q,
                             uint64_t since_start_secs, uint32_t since_start_nanos);

pc_status pc_quic_open_bidi(PcQuic *q, uint64_t *id_out);
pc_status pc_quic_open_uni(PcQuic *q, uint64_t *id_out);
pc_status pc_quic_stream_write(PcQuic *q, uint64_t id,
                               const uint8_t *data, size_t len,
                               size_t *written_out);
pc_status pc_quic_stream_finish(PcQuic *q, uint64_t id);
pc_status pc_quic_stream_read(PcQuic *q, uint64_t id,
                              uint8_t *out, size_t *out_len,
                              int32_t *fin_seen);
pc_status pc_quic_stream_reset(PcQuic *q, uint64_t id, uint64_t app_error);
pc_status pc_quic_stream_stop_sending(PcQuic *q, uint64_t id, uint64_t app_error);

pc_status pc_quic_send_datagram(PcQuic *q, const uint8_t *data, size_t len);
pc_status pc_quic_recv_datagram(PcQuic *q, uint8_t *out, size_t *out_len);

pc_status pc_quic_initiate_key_update(PcQuic *q);

/* `ipv6_bytes_len` MUST be 16 (an IPv6 representation; IPv4-mapped
 * `::ffff:a.b.c.d` is fine). Any other length is rejected with
 * PC_UNSUPPORTED. The explicit-length form replaces the earlier 16-byte
 * fixed signature for the same reason as pc_dtls_cfg_set_cookie_secret. */
pc_status pc_quic_set_peer_addr(PcQuic *q,
                                const uint8_t *ipv6_bytes, size_t ipv6_bytes_len,
                                uint16_t port);

pc_status pc_quic_negotiated_alpn(const PcQuic *q, uint8_t *out, size_t *out_len);
pc_status pc_quic_peer_certificate(const PcQuic *q, uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* PURECRYPTO_H */
