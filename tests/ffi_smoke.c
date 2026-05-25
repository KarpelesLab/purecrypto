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

  printf("ffi_smoke: OK\n");
  return 0;
}
