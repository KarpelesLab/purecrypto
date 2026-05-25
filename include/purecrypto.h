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
  PC_INTERNAL = -6
} pc_status;

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

/* Opaque handles. */
typedef struct PcHash PcHash;
typedef struct PcRsaKey PcRsaKey;
typedef struct PcEcKey PcEcKey;
typedef struct PcCert PcCert;

/* ---- Hashing ---- */
pc_status pc_digest(int32_t alg, const uint8_t *data, size_t data_len,
                    uint8_t *out, size_t *out_len);
PcHash *pc_hash_new(int32_t alg);
pc_status pc_hash_update(PcHash *h, const uint8_t *data, size_t len);
pc_status pc_hash_finish(PcHash *h, uint8_t *out, size_t *out_len);
void pc_hash_free(PcHash *h);

/* ---- HMAC (SHA-224/256/384/512) ---- */
pc_status pc_hmac(int32_t alg, const uint8_t *key, size_t key_len,
                  const uint8_t *msg, size_t msg_len, uint8_t *out,
                  size_t *out_len);

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

/* ---- X.509 ---- */
PcCert *pc_cert_from_pem(const uint8_t *pem, size_t len);
PcCert *pc_cert_from_der(const uint8_t *der, size_t len);
pc_status pc_cert_to_der(const PcCert *cert, uint8_t *out, size_t *out_len);
pc_status pc_cert_public_key_spki(const PcCert *cert, uint8_t *out,
                                  size_t *out_len);
pc_status pc_cert_verify(const PcCert *cert, const PcCert *issuer);
void pc_cert_free(PcCert *cert);

#ifdef __cplusplus
}
#endif

#endif /* PURECRYPTO_H */
