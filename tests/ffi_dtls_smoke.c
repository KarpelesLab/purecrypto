/*
 * In-process DTLS loopbacks driven through the purecrypto C ABI.
 *
 * Three handshakes are run: DTLS 1.3 with the cookie exchange disabled
 * (in-memory test, no amplification surface), and DTLS 1.2 + DTLS 1.3 with
 * the cookie exchange ON — the production configuration, which needs both
 * pc_dtls_cfg_set_cookie_secret and pc_dtls_cfg_set_peer_addr. A fourth
 * case checks that a cookie server missing its peer address is refused up
 * front (PC_BAD_CONFIG / NULL) rather than failing on the first ClientHello.
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

/* Runs one loopback: `version` is PC_DTLS_1_2 / PC_DTLS_1_3; `cookie` picks
 * the cookie exchange (secret + peer address) over pc_dtls_cfg_set_no_cookie.
 * Returns 0 on success. */
static int run_loopback(int32_t version, int cookie, uint16_t expect_ver) {
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

  /* Server config. */
  PcTlsCfg *scfg = pc_tls_cfg_new(PC_TLS_SERVER, version);
  if (!scfg) return fail("scfg");
  if (pc_tls_cfg_set_certificate(scfg, cert_pem, cert_pem_len,
                                 key_pem, key_pem_len) != PC_OK)
    return fail("cfg_set_certificate");
  if (cookie) {
    /* Production shape: a long-lived secret plus the datagram source
     * address (what recvfrom reported), bound into every cookie. */
    static const uint8_t secret[32] = {
      0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
      0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    static const uint8_t peer_v4[4] = { 127, 0, 0, 1 };
    if (pc_dtls_cfg_set_cookie_secret(scfg, secret, sizeof(secret)) != PC_OK)
      return fail("set_cookie_secret");
    /* Secret but no address is exactly the config the audit found failing
     * silently on the first ClientHello; it is now refused by name. */
    if (pc_tls_cfg_validate(scfg) != PC_BAD_CONFIG)
      return fail("validate should report PC_BAD_CONFIG without peer addr");
    if (pc_tls_new(scfg) != NULL)
      return fail("pc_tls_new should be NULL without peer addr");
    if (pc_dtls_cfg_set_peer_addr(scfg, peer_v4, 3, 4433) != PC_UNSUPPORTED)
      return fail("3-byte peer addr should be PC_UNSUPPORTED");
    if (pc_dtls_cfg_set_peer_addr(scfg, peer_v4, sizeof(peer_v4), 4433) != PC_OK)
      return fail("set_peer_addr");
    if (pc_tls_cfg_validate(scfg) != PC_OK)
      return fail("validate after peer addr");
  } else {
    if (pc_dtls_cfg_set_no_cookie(scfg) != PC_OK)
      return fail("set_no_cookie");
  }

  /* Client config. */
  PcTlsCfg *ccfg = pc_tls_cfg_new(PC_TLS_CLIENT, version);
  if (!ccfg) return fail("ccfg");
  if (pc_tls_cfg_add_root_pem(ccfg, cert_pem, cert_pem_len) != PC_OK)
    return fail("add_root_pem");
  if (pc_tls_cfg_set_server_name(ccfg, "ffi-dtls.test") != PC_OK)
    return fail("set_server_name");

  PcTls *server = pc_tls_new(scfg);
  PcTls *client = pc_tls_new(ccfg);
  if (!server || !client) return fail("pc_tls_new");

  /* Drive the handshake (DTLS emits datagrams one at a time). With the
   * cookie exchange on there is one extra round trip (HelloVerifyRequest /
   * HelloRetryRequest, then the ClientHello is re-sent with the cookie). */
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
  if (pc_tls_negotiated_version(client, &ver) != PC_OK || ver != expect_ver)
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

  /* DTLS has no close_notify exchange: never reported as closed. */
  if (pc_tls_received_close_notify(client) != 0)
    return fail("dtls must not report close_notify");

  pc_tls_free(client);
  pc_tls_free(server);
  pc_tls_cfg_free(ccfg);
  pc_tls_cfg_free(scfg);
  return 0;
}

int main(void) {
  if (run_loopback(PC_DTLS_1_3, 0, 0xFEFC)) return fail("DTLS 1.3, no cookie");
  if (run_loopback(PC_DTLS_1_2, 1, 0xFEFD)) return fail("DTLS 1.2, cookie");
  if (run_loopback(PC_DTLS_1_3, 1, 0xFEFC)) return fail("DTLS 1.3, cookie");

  printf("ffi_dtls_smoke: OK\n");
  return 0;
}
