# apple-interop

The peer tool behind `tools/interop/peers/apple.sh`: a TLS client and a TLS
server on Apple's Network.framework (`NWConnection` / `NWListener` with
`NWProtocolTLS.Options`, configured through `sec_protocol_options_*`), so
the interop matrix can drive the macOS TLS stack in both roles. The stack
under test is the OS's, so `apple-interop version` reports the macOS
version and there is nothing to pin.

```sh
tools/interop/peers/apple/build.sh          # swift build -c release; prints the binary
apple-interop server --p12 id.p12 --pass PW --ca ca.crt --send reply.txt \
                     --log server.out --port-file port [--accept 2] [--client-auth] ...
apple-interop client --port N --sni localhost --ca ca.crt --send ping.txt \
                     --log client.out [--resume --log2 client2.out] [--early-data FILE] ...
apple-interop probe sec_protocol_metadata_get_session_resumed ...   # which SPI this macOS has
```

Every negotiated parameter is logged as `key: value` lines (`protocol
version`, `cipher suite`, `group`, `alpn`, `resumed`, `early data accepted`,
`certificate compression`, `peer certificates`, `peer public key`, `ocsp
response`, `verify`, `challenge`, the application data as `data:` lines,
`close_notify: sent`), which the adapter's `verify` greps.

The parameters are read once per session, **when the exchange is over**
(the client has heard nothing for `--read-timeout`, the server has the
client's close) and before our `close_notify` — not when the connection
becomes ready; see [Reading the metadata](#reading-the-metadata).

## What is public API and what is SPI

Public `sec_protocol_options_*` covers the TLS version range, the cipher
suites (with a caveat below), ALPN, SNI, the local identity, client
authentication (`set_peer_authentication_required` + a verify block that
anchors `SecTrust` to the case's CA), the challenge block that presents a
client certificate, OCSP requests, tickets and resumption. The identity is
a PKCS#12 the purecrypto CLI exports (`purecrypto pkcs12 -export`), imported
with `SecPKCS12Import` into a throwaway file keychain that is deleted on
exit — the only public way to obtain a `SecIdentity` on macOS.

The rest goes through SPI declared in the open-source Security project's
`SecProtocolPriv.h` (apple-oss-distributions/Security), resolved with
`dlsym` and used only when present (`probe` tells the adapter, which SKIPs
with the reason otherwise):

| SPI | used for |
|---|---|
| `sec_protocol_options_append_tls_key_exchange_group` | pinning the offered / accepted groups (takes `0x11EC` for X25519MLKEM768) |
| `sec_protocol_options_set_tls_early_data_enabled` | 0-RTT, and resumption at all (see below) |
| `sec_protocol_metadata_get_session_resumed` | the `resumed:` line |
| `sec_protocol_metadata_copy_tls_negotiated_group` (or the older `get_`) | the `group:` line |
| `sec_protocol_metadata_get_tls_certificate_compression_used` / `_algorithm` | the `certificate compression:` line |
| `sec_protocol_options_set_server_raw_public_key_certificates` / `..._client_...` | accepting RFC 7250 raw public keys from the peer |

A fact that comes from SPI has three possible values, and `verify` keeps
them apart:

| logged | meaning | `verify` |
|---|---|---|
| `group: P-384`, `resumed: yes`, `certificate compression: zlib`, ... | what the stack reports | compared with the case; the group as a whole value, for every session in the log |
| `group: unknown (no SPI)` (likewise `resumed:`, `certificate compression:`) | this macOS does not have the symbol | the Apple side cannot tell: the group is then checked on the purecrypto side alone (`key exchange:`, which the runner verifies for every case); cases that are *about* the fact (`resume`, `0rtt`, `certcomp`) are SKIPped by `supports` |
| `group: unavailable` | the SPI is there and returned nothing, after up to 100 reads 10 ms apart (a `metadata:` line says how many it took) | a failure, never a pass |

## Reading the metadata

`sec_protocol_metadata_t` is only safe to read while the stack is idle.
Its accessors take no lock, and the stack goes on writing to the object on
its own thread (`com.apple.network.connections`) after the handshake: for
every NewSessionTicket a client receives,
`boringssl_context_new_session_handler` rebuilds the session's state
(`boringssl_session_set_peer_verification_state_from_session`), and a
server's tickets arrive right behind the handshake — just when `.ready`
is delivered to the application's queue. A read from the `.ready` handler
races with that. Observed under CPU load (about one handshake in a
hundred on a busy 16-core machine; a case now and then on the 3-vCPU CI
runner), such a read returned the scalars (version, suite, resumed,
compression) but no group, or no peer chain, or no peer public key. Each
was there a few hundred microseconds later and could be gone again while
the next ticket was processed; one read crashed in `objc_retain` on an
object the stack had just released. This is what made the matrix flaky
while the tool logged from the `.ready` handler (and reported the missing
group as `unknown (no SPI)`, which it was not).

Hence the read at the end of the exchange. It is the stack's behaviour,
not the peer's: nothing about the handshake differs (no HelloRetryRequest
is involved, and the purecrypto side reported the right group every time).

## Observed on macOS 26 (what the SKIPs and workarounds are for)

- A client caches its session — and so resumes on the next connection —
  only with early data enabled through the SPI; `--resume` therefore turns
  it on (nothing is sent early unless `--early-data` queues it).
- A server sends its NewSessionTickets with its first write, not right
  after the handshake; a client that sends nothing gets them bundled with
  the server's `close_notify`. `purecrypto s_client -reconnect` handles
  that (it closes after its ticket wait and reads what comes back).
- A listener with early data enabled accepts the client's 0-RTT (the
  EncryptedExtensions say so) but the accepted `NWConnection` never becomes
  ready and ends with `errSSLClosedNoNotify` — with OpenSSL's client too.
  Rejected early data (across a HelloRetryRequest) completes normally.
- `sec_protocol_options_append_tls_ciphersuite` cannot separate the two
  AES-GCM suites: either one makes the client offer both (AES-256 first),
  ChaCha20 alone is honoured. The purecrypto server pins its own accept-set
  (`-ciphersuites`), so the matrix still covers every suite.
- The client always sends a key share for X25519MLKEM768 when it offers
  it, so no HelloRetryRequest to that group can be forced.
- `signature_algorithms` carries ECDSA and RSA only (no ed25519, with or
  without the eddsa SPI), and the keychain has no Ed25519 or ML-DSA key
  type.
- Presenting our own raw public key through the SPI fails inside the stack
  with `errSSLInternal`; accepting the peer's works and the allowlist is
  enforced (a key not on it draws `bad_certificate`).
- Network.framework reports a peer's `close_notify` and a bare FIN the same
  way (and synthesises an end-of-stream on cancel), so the tool does not
  claim to have seen a `close_notify`; the purecrypto side's report is what
  the runner checks for that.
- No API sends a KeyUpdate, staples an OCSP response on a server, or
  advertises RFC 8449 `record_size_limit`.
