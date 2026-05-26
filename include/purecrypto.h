/*
 * purecrypto C ABI.
 *
 * Build the library with, e.g.:
 *   cargo rustc --release --features ffi --crate-type staticlib   (-> libpurecrypto.a)
 *   cargo rustc --release --features ffi --crate-type cdylib      (-> libpurecrypto.so)
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
  PC_AEAD_AES256_CCM8 = 7
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
  PC_RIPEMD160 = 19
} pc_hash_id;

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

/* Opaque handles. */
typedef struct PcHash PcHash;
typedef struct PcRsaKey PcRsaKey;
typedef struct PcEcKey PcEcKey;
typedef struct PcEd25519Key PcEd25519Key;
typedef struct PcCert PcCert;
typedef struct PcMlKem PcMlKem;
typedef struct PcMlDsa PcMlDsa;
typedef struct PcSlhDsa PcSlhDsa;
typedef struct PcCsr PcCsr;
typedef struct PcCrl PcCrl;
typedef struct PcTlsCfg PcTlsCfg;
typedef struct PcTls PcTls;

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

/* DTLS server only: cookie-exchange secret (32 bytes). */
pc_status pc_dtls_cfg_set_cookie_secret(PcTlsCfg *cfg, const uint8_t *secret_32);
/* DTLS server only: disable the cookie round-trip (HelloVerifyRequest / HRR
 * cookie). Recommended only for tests. */
pc_status pc_dtls_cfg_set_no_cookie(PcTlsCfg *cfg);

PcTls *pc_tls_new(const PcTlsCfg *cfg);
void pc_tls_free(PcTls *tls);

pc_status pc_tls_feed(PcTls *tls, const uint8_t *wire_in, size_t in_len, size_t *consumed);
pc_status pc_tls_pop(PcTls *tls, uint8_t *wire_out, size_t *out_len);
pc_status pc_tls_send(PcTls *tls, const uint8_t *app_in, size_t in_len);
pc_status pc_tls_recv(PcTls *tls, uint8_t *app_out, size_t *out_len);
pc_status pc_tls_handshake(PcTls *tls);
pc_status pc_tls_close(PcTls *tls);

int pc_tls_is_handshake_complete(const PcTls *tls);
pc_status pc_tls_negotiated_version(const PcTls *tls, uint16_t *out);
pc_status pc_tls_alpn_selected(const PcTls *tls, uint8_t *out, size_t *out_len);
pc_status pc_tls_peer_certificate(const PcTls *tls, uint8_t *out, size_t *out_len);

/* DTLS-only: timeout machinery. */
pc_status pc_dtls_next_timeout(const PcTls *tls,
                               uint64_t *seconds_out, uint32_t *nanos_out,
                               int32_t *has_timeout);
pc_status pc_dtls_on_timeout(PcTls *tls, uint64_t now_seconds, uint32_t now_nanos);

#ifdef __cplusplus
}
#endif

#endif /* PURECRYPTO_H */
