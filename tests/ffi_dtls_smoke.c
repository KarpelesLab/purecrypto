/*
 * In-process DTLS 1.3 loopback driven through the purecrypto C ABI. The
 * cookie round-trip is disabled (in-memory test, no amplification surface)
 * to keep the test deterministic and short.
 */
#include "purecrypto.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *msg) {
  fprintf(stderr, "FAIL: %s\n", msg);
  return 1;
}

/* Drain one datagram from `src` and inject it into `dst`. */
static size_t pump(PcTls *src, PcTls *dst) {
  uint8_t buf[16384];
  size_t n = sizeof(buf);
  if (pc_tls_pop(src, buf, &n) != PC_OK) return (size_t)-1;
  if (n == 0) return 0;
  if (pc_tls_feed(dst, buf, n, NULL) != PC_OK) return (size_t)-1;
  return n;
}

int main(void) {
  /* ECDSA P-256 server key + self-signed cert. */
  PcEcKey *sk = pc_ec_generate(PC_P256);
  if (!sk) return fail("pc_ec_generate");
  uint8_t key_pem[1024]; size_t key_pem_len = sizeof(key_pem);
  if (pc_ec_private_to_pem(sk, key_pem, &key_pem_len) != PC_OK)
    return fail("ec_private_to_pem");
  uint8_t cert_pem[2048]; size_t cert_pem_len = sizeof(cert_pem);
  if (pc_ec_self_signed_pem(sk, "ffi-dtls.test", 30, cert_pem, &cert_pem_len) != PC_OK)
    return fail("self_signed_pem");
  pc_ec_free(sk);

  /* Server config: DTLS 1.3, no cookie (test only). */
  PcTlsCfg *scfg = pc_tls_cfg_new(PC_TLS_SERVER, PC_DTLS_1_3);
  if (!scfg) return fail("scfg");
  if (pc_tls_cfg_set_certificate(scfg, cert_pem, cert_pem_len,
                                 key_pem, key_pem_len) != PC_OK)
    return fail("cfg_set_certificate");
  if (pc_dtls_cfg_set_no_cookie(scfg) != PC_OK)
    return fail("set_no_cookie");

  /* Client config. */
  PcTlsCfg *ccfg = pc_tls_cfg_new(PC_TLS_CLIENT, PC_DTLS_1_3);
  if (!ccfg) return fail("ccfg");
  if (pc_tls_cfg_add_root_pem(ccfg, cert_pem, cert_pem_len) != PC_OK)
    return fail("add_root_pem");
  if (pc_tls_cfg_set_server_name(ccfg, "ffi-dtls.test") != PC_OK)
    return fail("set_server_name");

  PcTls *server = pc_tls_new(scfg);
  PcTls *client = pc_tls_new(ccfg);
  if (!server || !client) return fail("pc_tls_new");

  /* Drive the handshake (DTLS emits datagrams one at a time). */
  for (int iter = 0; iter < 64; iter++) {
    pc_tls_handshake(client);
    pc_tls_handshake(server);
    /* Pump everything pending on each side until both are quiet. */
    size_t moved = 0;
    for (int j = 0; j < 16; j++) {
      size_t a = pump(client, server);
      size_t b = pump(server, client);
      if (a == (size_t)-1 || b == (size_t)-1) return fail("pump");
      moved += a + b;
      if (a == 0 && b == 0) break;
    }
    if (pc_tls_is_handshake_complete(client) && pc_tls_is_handshake_complete(server))
      break;
    if (moved == 0) {
      /* Some implementations require a tick of "time" between flights;
       * exercise the timeout machinery so we exit the stall when the engine
       * is waiting for a retransmit. */
      uint64_t s; uint32_t ns; int32_t has;
      if (pc_dtls_next_timeout(client, &s, &ns, &has) == PC_OK && has) {
        pc_dtls_on_timeout(client, s, ns);
      }
      if (pc_dtls_next_timeout(server, &s, &ns, &has) == PC_OK && has) {
        pc_dtls_on_timeout(server, s, ns);
      }
    }
  }
  if (!pc_tls_is_handshake_complete(client)) return fail("client handshake");
  if (!pc_tls_is_handshake_complete(server)) return fail("server handshake");

  uint16_t ver = 0;
  if (pc_tls_negotiated_version(client, &ver) != PC_OK || ver != 0xFEFC)
    return fail("dtls version");

  /* Application data both directions. Drain all queued datagrams. */
  uint8_t buf[16384];
  uint8_t app[1024]; size_t app_len;
  const uint8_t hello[] = "hello dtls";
  if (pc_tls_send(client, hello, sizeof(hello) - 1) != PC_OK)
    return fail("send c->s");
  for (int j = 0; j < 16; j++) {
    size_t n = sizeof(buf);
    if (pc_tls_pop(client, buf, &n) != PC_OK) return fail("pop c->s");
    if (n == 0) break;
    if (pc_tls_feed(server, buf, n, NULL) != PC_OK) return fail("feed c->s");
  }
  app_len = sizeof(app);
  if (pc_tls_recv(server, app, &app_len) != PC_OK)
    return fail("recv server");
  if (app_len != sizeof(hello) - 1 || memcmp(app, hello, app_len) != 0)
    return fail("server received");

  const uint8_t back[] = "hi back";
  if (pc_tls_send(server, back, sizeof(back) - 1) != PC_OK)
    return fail("send s->c");
  for (int j = 0; j < 16; j++) {
    size_t n = sizeof(buf);
    if (pc_tls_pop(server, buf, &n) != PC_OK) return fail("pop s->c");
    if (n == 0) break;
    if (pc_tls_feed(client, buf, n, NULL) != PC_OK) return fail("feed s->c");
  }
  app_len = sizeof(app);
  if (pc_tls_recv(client, app, &app_len) != PC_OK)
    return fail("recv client");
  if (app_len != sizeof(back) - 1 || memcmp(app, back, app_len) != 0)
    return fail("client received");

  pc_tls_free(client);
  pc_tls_free(server);
  pc_tls_cfg_free(ccfg);
  pc_tls_cfg_free(scfg);

  printf("ffi_dtls_smoke: OK\n");
  return 0;
}
