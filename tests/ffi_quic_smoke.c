/*
 * In-process QUIC v1 loopback test, driven entirely through the
 * purecrypto C ABI. Builds an Ed25519 self-signed server cert,
 * configures a server + client, drives the handshake to completion
 * by pumping `pc_quic_pop_datagram` / `pc_quic_feed_datagram` between
 * them, opens a bidi stream, exchanges "ping" / "pong" with FIN,
 * and tears down.
 *
 * Build:
 *   cargo rustc --release --features ffi --crate-type staticlib
 *   cc tests/ffi_quic_smoke.c -I include target/release/libpurecrypto.a \
 *      -lpthread -ldl -lm -o /tmp/ffi_quic_smoke && /tmp/ffi_quic_smoke
 */
#include "purecrypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *msg) {
  fprintf(stderr, "FAIL: %s\n", msg);
  return 1;
}

/* Drain at most one datagram from `src` and inject it into `dst`.
 * Returns the number of bytes moved (0 when nothing pending). */
static size_t pump_one(PcQuic *src, PcQuic *dst) {
  uint8_t buf[2048];
  size_t n = sizeof(buf);
  if (pc_quic_pop_datagram(src, buf, &n) != PC_OK) return (size_t)-1;
  if (n == 0) return 0;
  if (pc_quic_feed_datagram(dst, buf, n) != PC_OK) return (size_t)-1;
  return n;
}

/* Drain everything pending on `src` into `dst`. */
static size_t pump_all(PcQuic *src, PcQuic *dst) {
  size_t total = 0;
  for (int i = 0; i < 32; i++) {
    size_t n = pump_one(src, dst);
    if (n == (size_t)-1) return (size_t)-1;
    if (n == 0) break;
    total += n;
  }
  return total;
}

int main(void) {
  /* 1. Generate an Ed25519 server key + self-sign a certificate
   *    (CN = "ffi-quic.test", DNS SAN). Ed25519 matches the
   *    QuicConnection loopback tests in src/quic/connection.rs.    */
  PcEd25519Key *ed = pc_ed25519_generate();
  if (!ed) return fail("pc_ed25519_generate");

  uint8_t key_pem[1024];
  size_t key_pem_len = sizeof(key_pem);
  if (pc_ed25519_private_to_pem(ed, key_pem, &key_pem_len) != PC_OK)
    return fail("pc_ed25519_private_to_pem");
  pc_ed25519_free(ed);

  /* Use an ECDSA P-256 cert instead — `pc_ec_self_signed_pem` is
   * the canonical helper exposed by the C ABI and `pc_tls_*` /
   * `pc_dtls_*` smoke tests both use it. The QUIC engine accepts
   * any TLS-1.3-eligible signing key. */
  PcEcKey *server_key = pc_ec_generate(PC_P256);
  if (!server_key) return fail("pc_ec_generate");

  uint8_t ec_key_pem[1024];
  size_t ec_key_pem_len = sizeof(ec_key_pem);
  if (pc_ec_private_to_pem(server_key, ec_key_pem, &ec_key_pem_len) != PC_OK)
    return fail("pc_ec_private_to_pem");

  uint8_t cert_pem[2048];
  size_t cert_pem_len = sizeof(cert_pem);
  if (pc_ec_self_signed_pem(server_key, "ffi-quic.test", 30,
                            cert_pem, &cert_pem_len) != PC_OK)
    return fail("pc_ec_self_signed_pem");
  pc_ec_free(server_key);

  /* 2. Server config: present (cert, key). */
  PcQuicCfg *scfg = pc_quic_cfg_new(PC_TLS_SERVER);
  if (!scfg) return fail("pc_quic_cfg_new server");
  if (pc_quic_cfg_set_certificate(scfg, cert_pem, cert_pem_len,
                                  ec_key_pem, ec_key_pem_len) != PC_OK)
    return fail("pc_quic_cfg_set_certificate");

  /* 3. Client config: trust the server cert as a root + SNI. */
  PcQuicCfg *ccfg = pc_quic_cfg_new(PC_TLS_CLIENT);
  if (!ccfg) return fail("pc_quic_cfg_new client");
  if (pc_quic_cfg_add_root_pem(ccfg, cert_pem, cert_pem_len) != PC_OK)
    return fail("pc_quic_cfg_add_root_pem");
  if (pc_quic_cfg_set_server_name(ccfg, "ffi-quic.test") != PC_OK)
    return fail("pc_quic_cfg_set_server_name");

  /* 4. Materialise both connections. */
  PcQuic *server = pc_quic_new(scfg);
  PcQuic *client = pc_quic_new(ccfg);
  if (!server || !client) return fail("pc_quic_new");

  /* 5. Bind loopback addresses on both sides. Not strictly needed for
   *    a non-retry handshake, but exercises the ABI. The 16-byte buffer
   *    is the IPv4-mapped form of 127.0.0.1 (::ffff:7f00:0001). */
  static const uint8_t v4mapped_loopback[16] = {
      0,0,0,0, 0,0,0,0, 0,0,0xff,0xff, 127,0,0,1
  };
  if (pc_quic_set_peer_addr(server, v4mapped_loopback, 4433) != PC_OK)
    return fail("set_peer_addr server");
  if (pc_quic_set_peer_addr(client, v4mapped_loopback, 4433) != PC_OK)
    return fail("set_peer_addr client");

  /* 6. Drive the handshake: pump datagrams in both directions until
   *    `pc_quic_is_handshake_complete` reports 1 for both sides.    */
  for (int iter = 0; iter < 32; iter++) {
    int c_done = 0, s_done = 0;
    pc_quic_is_handshake_complete(client, &c_done);
    pc_quic_is_handshake_complete(server, &s_done);
    if (c_done && s_done) break;

    size_t c_to_s = pump_all(client, server);
    if (c_to_s == (size_t)-1) return fail("pump c->s");
    size_t s_to_c = pump_all(server, client);
    if (s_to_c == (size_t)-1) return fail("pump s->c");

    if (c_to_s == 0 && s_to_c == 0) {
      /* Nothing moved — tick the PTO timer on both sides to break
       * any stall. (No-op when no timer is armed.) */
      uint64_t s_ = 0; uint32_t ns = 0; int32_t has = 0;
      pc_quic_next_timeout(client, &s_, &ns, &has);
      pc_quic_on_timeout(client, s_ + 1, ns);
      pc_quic_next_timeout(server, &s_, &ns, &has);
      pc_quic_on_timeout(server, s_ + 1, ns);
    }
  }
  int c_done = 0, s_done = 0;
  pc_quic_is_handshake_complete(client, &c_done);
  pc_quic_is_handshake_complete(server, &s_done);
  if (!c_done) return fail("client handshake did not complete");
  if (!s_done) return fail("server handshake did not complete");

  /* 7. pc_quic_handshake returns Ok now (post-completion). */
  if (pc_quic_handshake(client) != PC_OK)
    return fail("pc_quic_handshake post-complete");
  if (pc_quic_handshake(server) != PC_OK)
    return fail("pc_quic_handshake server post-complete");

  /* 8. Drain post-handshake control flights (NEW_CID / HANDSHAKE_DONE). */
  for (int i = 0; i < 8; i++) {
    size_t a = pump_all(client, server);
    size_t b = pump_all(server, client);
    if (a == (size_t)-1 || b == (size_t)-1) return fail("post-handshake pump");
    if (a == 0 && b == 0) break;
  }

  /* 9. Client opens a bidi stream, writes "ping", finishes. */
  uint64_t cid = 0;
  if (pc_quic_open_bidi(client, &cid) != PC_OK)
    return fail("pc_quic_open_bidi");

  const uint8_t ping[] = "ping";
  size_t written = 0;
  if (pc_quic_stream_write(client, cid, ping, sizeof(ping) - 1, &written) != PC_OK)
    return fail("pc_quic_stream_write ping");
  if (written != sizeof(ping) - 1)
    return fail("ping not fully accepted");
  if (pc_quic_stream_finish(client, cid) != PC_OK)
    return fail("pc_quic_stream_finish client");

  /* 10. Pump client → server until the server reads the full "ping" + FIN. */
  uint8_t buf[256];
  size_t read_total = 0;
  int fin_seen = 0;
  for (int i = 0; i < 64 && (read_total < sizeof(ping) - 1 || !fin_seen); i++) {
    if (pump_all(client, server) == (size_t)-1) return fail("pump c->s ping");
    if (pump_all(server, client) == (size_t)-1) return fail("pump s->c ping");
    /* Try the same stream id on the server side — bidi streams use the
     * exact id from the initiating side. */
    size_t n = sizeof(buf) - read_total;
    int f = 0;
    pc_status r = pc_quic_stream_read(server, cid, buf + read_total, &n, &f);
    if (r != PC_OK) return fail("pc_quic_stream_read server ping");
    read_total += n;
    if (f) fin_seen = 1;
  }
  if (read_total != sizeof(ping) - 1)
    return fail("server didn't receive 'ping'");
  if (memcmp(buf, ping, sizeof(ping) - 1) != 0)
    return fail("server received wrong bytes");
  if (!fin_seen) return fail("server didn't see client FIN");

  /* 11. Server echoes "pong" + FIN. */
  const uint8_t pong[] = "pong";
  size_t s_written = 0;
  if (pc_quic_stream_write(server, cid, pong, sizeof(pong) - 1, &s_written) != PC_OK)
    return fail("pc_quic_stream_write pong");
  if (s_written != sizeof(pong) - 1)
    return fail("pong not fully accepted");
  if (pc_quic_stream_finish(server, cid) != PC_OK)
    return fail("pc_quic_stream_finish server");

  /* 12. Pump server → client until the client reads "pong" + FIN. */
  uint8_t buf2[256];
  size_t c_read_total = 0;
  int c_fin_seen = 0;
  for (int i = 0; i < 64 && (c_read_total < sizeof(pong) - 1 || !c_fin_seen); i++) {
    if (pump_all(server, client) == (size_t)-1) return fail("pump s->c pong");
    if (pump_all(client, server) == (size_t)-1) return fail("pump c->s pong");
    size_t n = sizeof(buf2) - c_read_total;
    int f = 0;
    pc_status r = pc_quic_stream_read(client, cid, buf2 + c_read_total, &n, &f);
    if (r != PC_OK) return fail("pc_quic_stream_read client pong");
    c_read_total += n;
    if (f) c_fin_seen = 1;
  }
  if (c_read_total != sizeof(pong) - 1)
    return fail("client didn't receive 'pong'");
  if (memcmp(buf2, pong, sizeof(pong) - 1) != 0)
    return fail("client received wrong bytes");
  if (!c_fin_seen) return fail("client didn't see server FIN");

  /* 13. Free everything in reverse order. */
  pc_quic_free(client);
  pc_quic_free(server);
  pc_quic_cfg_free(ccfg);
  pc_quic_cfg_free(scfg);

  printf("ffi_quic_smoke: OK\n");
  return 0;
}
