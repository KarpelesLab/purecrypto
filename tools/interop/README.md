# TLS interop matrix

`run.sh` drives the `purecrypto` CLI (`s_client` / `s_server`) against one
peer implementation over real loopback TCP sockets, in **both roles**, and
checks the negotiated parameters on **both sides** from their logs: a
handshake that completed with the wrong group, suite or version is a FAIL,
as is a session the peer ended without `close_notify`.

```sh
cargo build --release --features ech --bin purecrypto
PURECRYPTO=target/release/purecrypto tools/interop/run.sh --peer openssl-system
PURECRYPTO=target/release/purecrypto tools/interop/run.sh --peer boringssl --filter 'ps_(resume|0rtt)'
tools/interop/run.sh --peer openssl-src --list
```

Output is one `PASS|FAIL|SKIP <case> [reason]` line per case and a summary;
the exit status is non-zero on any FAIL, and a failed case dumps every log
from its work directory. Every process runs under `timeout`
(`INTEROP_TIMEOUT` seconds per client step, default 30), so a hang fails
its case rather than the CI job. `--keep` preserves the scratch directory.

The peers in CI: `.github/workflows/interop.yml` runs one job per adapter.

## Cases

A case is a set of `key=value` words:

| key     | values |
|---------|--------|
| `proto` | `tls13`, `tls12` (the TLS 1.2 fallback case) |
| `role`  | `peer-server` (purecrypto is the client), `peer-client` (purecrypto is the server) |
| `cert`  | `rsa2048`, `p256`, `p384`, `ed25519`, `mldsa65`, `large` (a > 16 KiB chain) |
| `group` | `x25519`, `p256`, `p384`, `p521`, `x25519mlkem768`, `secp256r1mlkem768` |
| `suite` | `aes128gcm`, `aes256gcm`, `chacha20` |
| `feat`  | see below |

and is named `<proto>_<ps|pc>_<feat>_<cert>_<group>_<suite>`. The matrix is
the full `cert × group × suite` product for `feat=plain`, then one case per
feature (with `p256` / `x25519` / `aes128gcm` unless the feature says
otherwise), `hrr` once per group, and `mtls` once per certificate kind (as
the *client* identity):

| `feat` | what is exercised | how the purecrypto side is driven |
|---|---|---|
| `plain` | handshake + application data both ways, pinned group and suite | `-groups` / `-ciphersuites` |
| `resume` | PSK (`psk_dhe_ke`) resumption on a second connection | `-reconnect` / `-naccept 2` |
| `resume-psk` | PSK-only (no DHE) resumption | *SKIP: purecrypto implements `psk_dhe_ke` only* |
| `0rtt` | 0-RTT accepted on the resumed connection | `-reconnect -early_data FILE` / `-naccept 2 -early_data` |
| `0rtt-hrr` | 0-RTT offered but the resumed handshake takes a HelloRetryRequest: early data rejected and re-sent, PSK still accepted | client shares only P-256 against a server pinned to X25519 |
| `hrr` | HelloRetryRequest to the pinned group (one case per group) | `-key-shares` on the client, `-groups` on the server |
| `mtls` | client certificate of each kind, verified by the server | `-cert`/`-key` and `-Verify` |
| `keyupdate` | purecrypto sends `KeyUpdate(update_requested)`, the peer replies | `-key_update` |
| `keyupdate-peer` | the peer sends `KeyUpdate(update_requested)`, purecrypto replies | (peer-driven) |
| `certcomp` | RFC 8879 zlib-compressed server certificate | default (advertised) |
| `rpk` | RFC 7250 raw public key as the *server* identity | `-enable_server_rpk` (+ `-rpk_peer_key` pin on the client) |
| `rpk-client` | raw public key as the *client* identity | `-enable_client_rpk` (+ `-rpk_peer_key` allowlist on the server) |
| `ocsp` | stapled OCSP response (RFC 6066 / 8446 §4.4.2.1) | `-status_file` |
| `alpn` | ALPN selects `h2` | `-alpn h2,http/1.1` |
| `rsl` | RFC 8449 `record_size_limit` (with a payload over the limit) | `-record_size_limit 512` |
| `large-chain` | a certificate chain over 16 KiB (must span records) | `cert=large` |
| `tls12` | the peer speaks TLS 1.2 only; purecrypto negotiates down | `-min_protocol TLSv1.2` |

The purecrypto side's expectations come from the case (`pc_verify` in
`run.sh`, reading the `key: value` report `s_client` / `s_server` print —
`cipher suite:`, `key exchange:`, `HelloRetryRequest:`, `resumed:`,
`early data:`, `peer certificate:`, `own certificate:`, `… compression:`,
`OCSP staple:`, `record_size_limit:`, `KeyUpdate: sent N, received M`,
`close_notify:`). The peer side's expectations are the adapter's job.

Certificates are generated at run time with the purecrypto CLI (one CA, one
leaf per key kind, the oversized chain, the raw public keys) and the OCSP
response with `openssl ocsp` (`OPENSSL`, default `openssl` from PATH; the
`ocsp` cases SKIP without one).

## Adding a peer

Drop an adapter under `peers/`: either an executable `peers/<name>` (any
language — a PowerShell or Swift program for the platform stacks is fine) or
a `peers/<name>.sh` run with bash. The runner invokes it as
`peers/<name> <subcommand>` with the case in the environment; nothing else
in the runner needs to change.

### Environment

| variable | meaning |
|---|---|
| `CASE` | the case spec (`proto=tls13 role=peer-server …`) |
| `CASE_PROTO`, `CASE_ROLE`, `CASE_CERT`, `CASE_GROUP`, `CASE_SUITE`, `CASE_FEAT` | the case, one key per variable |
| `WORK` | the case's directory: put every log here (dumped on failure) |
| `PKI` | certificates: `ca.crt`, `<cert>.crt` / `<cert>.key` / `<cert>.pub` (SPKI PEM) for `rsa2048 p256 p384 ed25519 mldsa65`, `large.crt` (leaf + intermediate) / `large-leaf.crt` / `large-int.crt` / `large.key`, `early.txt` (the 0-RTT payload) |
| `OCSP` | the DER OCSP response for `p256.crt`, or empty |
| `PORT` | (`client` only) the purecrypto server's port |
| `PURECRYPTO`, `TO` (the `timeout` binary), `STEP_TIMEOUT`, `SERVER_TIMEOUT` | tooling |
| `$WORK/client.in` | what the client of the case sends (whoever it is) |
| `$WORK/server.in` | a payload for a peer server to send back, if its tool forwards stdin |

### Subcommands

| subcommand | contract |
|---|---|
| `info` | print the peer's version on stdout |
| `quirks` | (optional) print space-separated tokens for documented tool limitations the runner should allow for: `no-close-notify` (the tool never sends `close_notify`, so its absence is not a failure) |
| `supports` | exit 0 to run the case; exit 3 with the reason on stdout to SKIP it; anything else is an error |
| `server` | start the peer server in the background, wait until it is listening, write the port to `$WORK/server.port` and the pid to `$WORK/server.pid`, then exit 0. Logs go to `$WORK/server.out` / `server.err`. The runner kills the pid (and `$WORK/feeder.pid`, if any) when the case is over. Shell adapters get this from `lib.sh`'s `start_bg_server`, which also picks a free port and retries collisions |
| `client` | run the peer client against `127.0.0.1:$PORT` to completion, sending `$WORK/client.in`, twice when the feature resumes; exit with the client's status; logs in `$WORK/client.out` / `client.err` (`client2.*` for a second connection) |
| `verify` | check the peer's own logs for the negotiated parameters the case demands (version, suite, group, resumption, early data, ALPN, client certificate, …) and the application data; exit 0, or print what is missing and exit 1 |

`lib.sh` (sourced by the shell adapters) provides `skip`, `expect`,
`refute`, `expect_re`, `start_bg_server`, `version_ge` and the naming
helpers. `peers/openssl.sh` and `peers/boringssl.sh` are the reference
adapters; `peers/openssl-system.sh` / `peers/openssl-src.sh` only set
`OPENSSL` and source the shared one, so one adapter covers OpenSSL 3.0
through 3.6 by version detection. `peers/schannel.sh` is the shape for a
platform stack without a command-line tool: a wrapper that builds and
drives a small program of its own (`peers/schannel/`, C# on .NET's
`SslStream`, which is SChannel on Windows). The runner itself works under
Git Bash on Windows (MSYS path conversion is switched off and every path
it hands out is in Windows form).

Skip rather than weaken: when a peer's tool cannot express a case, `supports`
says so with the reason, and the reason lands in the run output and in
`docs/validation.md`. Never relax a security check on the purecrypto side to
make a peer happy — report it instead.
