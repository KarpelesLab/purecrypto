/*
 * In-process TLS 1.3 loopback test, driven entirely through the purecrypto
 * C ABI. Builds an ECDSA P-256 self-signed server cert, configures a
 * server + client, pumps the handshake to completion, exchanges application
 * data both directions, and closes.
 *
 * Build:
 *   cargo rustc --release --features ffi --crate-type staticlib
 *   cc tests/ffi_tls_smoke.c -I include target/release/libpurecrypto.a \
 *      -lpthread -ldl -lm -o /tmp/ffi_tls_smoke && /tmp/ffi_tls_smoke
 */
#include "purecrypto.h"
#include <stdio.h>
#include <string.h>

static int fail(const char *msg) {
  fprintf(stderr, "FAIL: %s\n", msg);
  return 1;
}

/* Pump one side: drain whatever bytes the engine wants to send, feed them
 * to the peer. Returns the number of bytes pushed (so the caller knows
 * when both sides are idle).
 */
static size_t pump(PcTls *src, PcTls *dst) {
  uint8_t buf[16384];
  size_t n = sizeof(buf);
  if (pc_tls_pop(src, buf, &n) != PC_OK) return (size_t)-1;
  if (n == 0) return 0;
  if (pc_tls_feed(dst, buf, n, NULL) != PC_OK) return (size_t)-1;
  return n;
}

int main(void) {
  int rc;

  /* 1. Generate an ECDSA P-256 server key. */
  PcEcKey *server_key = pc_ec_generate(PC_P256);
  if (!server_key) return fail("pc_ec_generate");

  uint8_t key_pem[1024];
  size_t key_pem_len = sizeof(key_pem);
  if (pc_ec_private_to_pem(server_key, key_pem, &key_pem_len) != PC_OK)
    return fail("pc_ec_private_to_pem");

  /* 2. Self-sign a P-256 leaf certificate (CN = "ffi-tls.test"). */
  uint8_t cert_pem[2048];
  size_t cert_pem_len = sizeof(cert_pem);
  if (pc_ec_self_signed_pem(server_key, "ffi-tls.test", 30,
                            cert_pem, &cert_pem_len) != PC_OK)
    return fail("pc_ec_self_signed_pem");
  pc_ec_free(server_key);

  /* 3. Server config: TLS 1.3, present (cert, key). */
  PcTlsCfg *scfg = pc_tls_cfg_new(PC_TLS_SERVER, PC_TLS_1_3);
  if (!scfg) return fail("pc_tls_cfg_new server");
  if (pc_tls_cfg_set_certificate(scfg, cert_pem, cert_pem_len,
                                 key_pem, key_pem_len) != PC_OK)
    return fail("pc_tls_cfg_set_certificate");

  /* 4. Client config: TLS 1.3, trust the server cert as a root + SNI. */
  PcTlsCfg *ccfg = pc_tls_cfg_new(PC_TLS_CLIENT, PC_TLS_1_3);
  if (!ccfg) return fail("pc_tls_cfg_new client");
  if (pc_tls_cfg_add_root_pem(ccfg, cert_pem, cert_pem_len) != PC_OK)
    return fail("pc_tls_cfg_add_root_pem");
  if (pc_tls_cfg_set_server_name(ccfg, "ffi-tls.test") != PC_OK)
    return fail("pc_tls_cfg_set_server_name");

  /* 5. Materialise both connections. */
  PcTls *server = pc_tls_new(scfg);
  PcTls *client = pc_tls_new(ccfg);
  if (!server || !client) return fail("pc_tls_new");

  /* 6. Drive the handshake by pumping until both sides report complete. */
  for (int iter = 0; iter < 32; iter++) {
    /* Advance each side. */
    pc_tls_handshake(client);
    pc_tls_handshake(server);

    size_t c_to_s = pump(client, server);
    if (c_to_s == (size_t)-1) return fail("pump c->s");
    size_t s_to_c = pump(server, client);
    if (s_to_c == (size_t)-1) return fail("pump s->c");

    if (pc_tls_is_handshake_complete(client)
        && pc_tls_is_handshake_complete(server)
        && c_to_s == 0 && s_to_c == 0)
      break;

    if (c_to_s == 0 && s_to_c == 0
        && (!pc_tls_is_handshake_complete(client)
            || !pc_tls_is_handshake_complete(server))) {
      fprintf(stderr, "stalled iter=%d ch=%d sh=%d\n",
              iter,
              pc_tls_is_handshake_complete(client),
              pc_tls_is_handshake_complete(server));
      return fail("handshake stalled");
    }
  }
  if (!pc_tls_is_handshake_complete(client)) return fail("client handshake");
  if (!pc_tls_is_handshake_complete(server)) return fail("server handshake");

  /* 7. Negotiated version should be 0x0304. */
  uint16_t ver = 0;
  if (pc_tls_negotiated_version(client, &ver) != PC_OK || ver != 0x0304)
    return fail("negotiated version");

  /* 8. Application data: client -> server. */
  const uint8_t hello[] = "hello from ffi-tls C";
  if (pc_tls_send(client, hello, sizeof(hello) - 1) != PC_OK)
    return fail("pc_tls_send client");

  /* Drain the client's wire bytes and feed them to the server. */
  uint8_t buf[16384];
  size_t n = sizeof(buf);
  if (pc_tls_pop(client, buf, &n) != PC_OK) return fail("pop client");
  if (n == 0) return fail("client emitted nothing");
  if (pc_tls_feed(server, buf, n, NULL) != PC_OK) return fail("feed server");

  uint8_t app[1024];
  size_t app_len = sizeof(app);
  rc = pc_tls_recv(server, app, &app_len);
  if (rc != PC_OK) return fail("pc_tls_recv server");
  if (app_len != sizeof(hello) - 1 || memcmp(app, hello, app_len) != 0)
    return fail("server received wrong app data");

  /* 9. Reverse direction: server -> client. */
  const uint8_t hi[] = "hi from server";
  if (pc_tls_send(server, hi, sizeof(hi) - 1) != PC_OK)
    return fail("pc_tls_send server");
  n = sizeof(buf);
  if (pc_tls_pop(server, buf, &n) != PC_OK) return fail("pop server");
  if (n == 0) return fail("server emitted nothing");
  if (pc_tls_feed(client, buf, n, NULL) != PC_OK) return fail("feed client");

  app_len = sizeof(app);
  rc = pc_tls_recv(client, app, &app_len);
  if (rc != PC_OK) return fail("pc_tls_recv client");
  if (app_len != sizeof(hi) - 1 || memcmp(app, hi, app_len) != 0)
    return fail("client received wrong app data");

  /* 10. ALPN was not configured; expect an empty selected protocol. */
  uint8_t alpn[64];
  size_t alpn_len = sizeof(alpn);
  if (pc_tls_alpn_selected(client, alpn, &alpn_len) != PC_OK)
    return fail("pc_tls_alpn_selected");
  if (alpn_len != 0) return fail("alpn should be empty");

  /* 11. Peer leaf certificate is available to the client. */
  uint8_t peer_der[2048];
  size_t peer_der_len = sizeof(peer_der);
  if (pc_tls_peer_certificate(client, peer_der, &peer_der_len) != PC_OK)
    return fail("pc_tls_peer_certificate");
  if (peer_der_len == 0) return fail("peer cert empty");

  /* 12. Clean shutdown. */
  pc_tls_close(client);
  pc_tls_close(server);

  pc_tls_free(client);
  pc_tls_free(server);
  pc_tls_cfg_free(ccfg);
  pc_tls_cfg_free(scfg);

  printf("ffi_tls_smoke: OK\n");
  return 0;
}
