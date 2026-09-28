# `purecrypto` command-line reference

The `purecrypto` binary is built by default (`cargo build`, or
`cargo build --features cli`). Its subcommands follow OpenSSL's naming where
one exists. Every subcommand reads `stdin` when no `-in` is given and writes
to `stdout` when no `-out` is given, so commands compose with pipes. Flags
accept one or two leading dashes (`-out` and `--out` are the same).

Every subcommand prints its usage when run with missing arguments.

Two conventions apply across the tool:

- **Private material is written mode 0600 and never overwrites** an existing
  file. Raw key bytes are refused on a terminal unless you pass `-out -`.
- **Secrets on the command line leak** through `/proc/<pid>/cmdline`. Flags
  such as `-key HEX`, `-password STR`, and `-ikm HEX` warn on use; prefer the
  `-keyfile` / `-password-file` forms (`-password-file -` reads stdin).
- **`-` means stdin for every input flag** — `-in`, `-keyfile`, `-aadfile`,
  `-sigfile`, `-inkey`, `-peer`, `-ct`, `-CAfile`, `-CA`, `-CAkey`,
  `-password-file`, and the positional file of `hash` / `mac`. There is only
  one stdin, so at most one input per invocation may be `-` (a second is
  refused, including the implicit stdin default when `-in` is omitted).
  Files holding private keys are checked for group/other-readable permissions
  and warned about; public inputs (AAD, peer public keys, certificates) are
  not.
- **Positional arguments beyond what a subcommand takes are refused** with
  `unexpected argument(s): ...` rather than silently ignored.

## Contents

- [`hash` / `dgst`](#hash--dgst)
- [`mac`](#mac)
- [`kdf`](#kdf)
- [`enc`](#enc)
- [`rand`](#rand)
- [`genpkey`](#genpkey)
- [`pkey`](#pkey)
- [`pkcs12`](#pkcs12)
- [`pkeyutl`](#pkeyutl)
- [`kem`](#kem)
- [`kex`](#kex)
- [`req`](#req)
- [`x509`](#x509)
- [`ca`](#ca)
- [`crl`](#crl)
- [`s_client` / `s_server`](#s_client--s_server)
- [Encrypted Client Hello: `generate-ech`, `-ech-*`](#encrypted-client-hello-generate-ech--ech-)
- [DTLS: `s_dtls_client` / `s_dtls_server`](#dtls-s_dtls_client--s_dtls_server)
- [QUIC: `q_client` / `q_server`](#quic-q_client--q_server)
- [Cookbook](#cookbook)

## `hash` / `dgst`

```sh
purecrypto hash sha256 file.txt              # one-shot digest
echo -n abc | purecrypto hash sha3-256       # any algorithm from the `hash` module
```

Algorithms: `sha224`, `sha256`, `sha384`, `sha512`, `sha512-224`,
`sha512-256`, `sha3-224`, `sha3-256`, `sha3-384`, `sha3-512`, `keccak256`,
`blake2b256`, `blake2b384`, `blake2b512`, `blake2s256`, `blake3`, `m14`,
`sm3`, `whirlpool`, `streebog256`, `streebog512`, `ascon-hash256`, `sha1`,
`md2`, `md4`, `md5`, `ripemd160`. Common spellings such as `sha-256` or
`sha512/256` are accepted. Of the XOFs only `ascon-xof128` and
`ascon-cxof128` (`-len N [-custom HEX]`) are exposed by the CLI; `shake128`,
`shake256`, BLAKE2X, cSHAKE and KMAC are available through the Rust library.

## `mac`

```sh
purecrypto mac -alg hmac-sha256 -keyfile k.bin -in msg.txt
purecrypto mac -alg cmac        -keyfile aes.key -in msg.txt          # AES-CMAC, RFC 4493
purecrypto mac -alg gmac        -keyfile aes.key -nonce HEX -in msg.txt   # GMAC, SP 800-38D
```

`hmac-<hash>` (or a bare hash name) works for every digest `hash` knows.
`-key HEX` is accepted but warns; `-binary` emits raw bytes.

## `kdf`

```text
purecrypto kdf hkdf    -hash sha256|sha384|sha512 -ikm HEX|-ikmfile FILE [-salt HEX] [-info HEX] -len N
purecrypto kdf pbkdf2  -hash sha256|sha384|sha512 -password STR|-password-file FILE -salt HEX -iter N -len N
purecrypto kdf scrypt  -password STR|-password-file FILE -salt HEX -n N -r R -p P -len N
purecrypto kdf argon2  -variant 2i|2d|2id -password STR|-password-file FILE -salt HEX -t-cost N -m-cost N [-p P] -len N
purecrypto kdf kbkdf   -mode counter|feedback -prf hmac-sha256|hmac-sha384|hmac-sha512|cmac-aes128|cmac-aes256
                       -ki HEX|-kifile FILE [-label HEX] [-context HEX] [-iv HEX] -len N
```

Output is hex unless `-binary` is set.

## `enc`

AEAD encryption and AES key wrap.

```sh
purecrypto enc -alg AES-256-GCM -keyfile k.bin -nonce HEX [-aad HEX|-aadfile F] -in plain -out ct
purecrypto enc -alg AES-256-GCM -keyfile k.bin -nonce HEX -d -in ct -out plain
purecrypto enc -alg AES-256-KW  -keyfile kek.bin -in key.bin -out wrapped
```

Algorithms: `AES-128-GCM`, `AES-256-GCM`, `CHACHA20-POLY1305`,
`XCHACHA20-POLY1305`, `AES-128-CCM`, `AES-256-CCM`, `AES-128-CCM8`,
`AES-256-CCM8`, `AES-128-GCM-SIV`, `AES-256-GCM-SIV`, `AES-128-SIV`,
`AES-256-SIV`, `AEGIS-128L`, `AEGIS-256`, `ASCON-AEAD128`, `AES-128-KW`,
`AES-256-KW`, `AES-128-KWP`, `AES-256-KWP`. On a tag failure nothing is
written.

## `rand`

```sh
purecrypto rand 32              # 32 random bytes as hex
purecrypto rand 16 --binary     # raw bytes to stdout
purecrypto rand 32 -out seed.bin
```

`-out` files are created mode 0600.

## `genpkey`

```sh
# Classical
purecrypto genpkey -algorithm RSA -bits 2048   -out rsa.pem    # any even size, 512..=65536
purecrypto genpkey -algorithm EC  -curve P-256 -out ec.pem     # or P-384, P-521, secp256k1
purecrypto genpkey -algorithm SM2              -out sm2.pem
purecrypto genpkey -algorithm ED25519          -out ed.pem     # or ED448

# Post-quantum signatures (FIPS 204 / FIPS 205)
purecrypto genpkey -algorithm ML-DSA-65               -out mldsa65.pem   # 44, 65, 87
purecrypto genpkey -algorithm SLH-DSA-SHA2-128f       -out slh128f.pem   # all 12 sets

# Post-quantum KEM (FIPS 203)
purecrypto genpkey -algorithm ML-KEM-768              -out mlkem768.pem  # 512, 768, 1024

# Stateful hash-based signatures (SP 800-208)
purecrypto genpkey -algorithm LMS-SHA256-H10-W4       -out lms.key
purecrypto genpkey -algorithm HSS-L2-SHA256-H10-W4    -out hss.key
purecrypto genpkey -algorithm XMSS-SHA2_10_256        -out xmss.key
purecrypto genpkey -algorithm XMSSMT-SHA2_20/2_256    -out xmssmt.key
```

The full SLH-DSA matrix is `SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}`.

Output format:

- RSA: `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1)
- EC / SM2: `-----BEGIN EC PRIVATE KEY-----` (SEC1)
- LMS / HSS / XMSS / XMSS^MT: the raw binary state serialization (not
  PEM — it carries the live one-time-key index and is rewritten by
  `pkeyutl sign`; `pkey -in` does not read it). LMS/HSS files use the
  library's *cached* form (`to_bytes_with_cache`), which also carries the
  signer's Merkle node cache: every `pkeyutl sign` is a fresh process, and
  without it each one would first re-derive the whole tree — a full key
  generation per signature (about 2 s for `H15`, 40 s for `H20`, hours for
  `H25`). The price is the file size: roughly 2 KiB for `H5`, 64 KiB for
  `H10` and 2 MiB for `H15` and above, per HSS level, rewritten on every
  signature. The plain form written by older releases still loads (the
  first signature after it pays the rebuild once, and rewrites the file in
  the cached form).
- Everything else: `-----BEGIN PRIVATE KEY-----` (PKCS#8, algorithm
  identified by the embedded OID)

> **PKCS#8 interop.** Private keys use the LAMPS PQC encodings and are
> interoperable with OpenSSL 3.5 in both directions. ML-DSA and ML-KEM emit
> the `SEQUENCE { seed, expandedKey }` CHOICE form, byte-for-byte identical to
> OpenSSL 3.5's default `seed-priv` output; the parser also accepts the
> `seed`, `expandedKey`, and legacy raw-expanded forms. SLH-DSA uses the bare
> `OCTET STRING` form. Public-key SPKI is interoperable for every scheme.

> **Stateful keys.** LMS/HSS and XMSS keys advance an index on every
> signature. `pkeyutl sign` rewrites the key file in place after signing and
> refuses to sign if it cannot; never copy a stateful key file. LMS/HSS key
> files written by this release are not readable by releases that predate
> the cached form.

## `pkey`

```sh
purecrypto pkey -in key.pem -text     # describe the key
purecrypto pkey -in key.pem -pubout   # emit the SPKI public-key PEM
purecrypto pkey < key.pem             # re-emit the private key (round-trip)
```

`pkey` auto-detects RSA PKCS#1, EC SEC1, and every PKCS#8 type above.
`req`, `x509`, `ca`, `s_server` and `s_client -key` load ML-DSA-44/65/87
PKCS#8 keys as well as RSA, EC, Ed25519 and Ed448 ones.

## `pkcs12`

```sh
# Bundle a key with its certificate chain (PKCS#12 / PFX, RFC 7292): what the
# platform TLS stacks import an identity from.
purecrypto pkcs12 -export -inkey server.key -in server.crt -certfile ca.crt \
                  -name "my server" -passout pass:secret -out server.p12
purecrypto pkcs12 -in server.p12 -passin pass:secret -info     # what is inside
purecrypto pkcs12 -in server.p12 -passin pass:secret -nokeys   # the certificates, PEM
purecrypto pkcs12 -in server.p12 -passin pass:secret -out id.pem   # key + certs, PEM
```

`-export` takes the key in any form the other subcommands read (PKCS#8,
PKCS#1 or SEC1 PEM) and every `CERTIFICATE` block of `-in` (the leaf first)
and `-certfile`; it refuses a key that does not match the leaf. The archive
is the same shape `openssl pkcs12 -export` writes by default — PBES2 with
PBKDF2-SHA256 and AES-256-CBC around the key, a SHA-256 MAC over the whole —
and imports into macOS's Security framework and OpenSSL 3. Passwords come
from `pass:STRING`, `env:VARIABLE` or `file:PATH` (first line); the
`-passin` side also reads the legacy 3DES/SHA-1 archives `openssl pkcs12
-legacy` writes. Output holding a private key is written `0600`, never over
an existing file.

## `pkeyutl`

```text
purecrypto pkeyutl encrypt -inkey FILE [-pubin] -pkeyopt OPT [-in FILE] [-out FILE]
purecrypto pkeyutl decrypt -inkey FILE          -pkeyopt OPT [-in FILE] [-out FILE]
purecrypto pkeyutl sign    -inkey FILE          [-pkeyopt OPT] -in FILE -out FILE
purecrypto pkeyutl verify  -inkey FILE [-pubin] [-pkeyopt OPT] -sigfile FILE -in FILE
```

`-pkeyopt` values: `rsa_padding_mode:oaep|pkcs1|pss`, `rsa_oaep_md:NAME`,
`rsa_oaep_label:HEX`, `digest:sha224|sha256|sha384|sha512|sha1`. ECDSA,
Ed25519/Ed448, ML-DSA, SLH-DSA, LMS/HSS and XMSS keys are routed by key type.

`-pubin` declares `-inkey` to be a `PUBLIC KEY` (SPKI) PEM: it is read as
public material (no permission warning) and anything else — a private key
included — is refused. Without it, `verify` accepts an SPKI PEM or a private
key (LMS/HSS/XMSS raw, SM2 SEC1, ...) whose public half is derived, with the
private-key permission warning.
An SM2 key routes to SM2-DSA for sign/verify and SM2-PKE for
encrypt/decrypt; `-id STR` overrides the default signer identity.

RSA encryption defaults to `rsa_padding_mode:pkcs1`, which prints a warning;
prefer `oaep`. PKCS#1 v1.5 decryption uses implicit rejection (RFC 8017
§7.2.2): a corrupt ciphertext, or one encrypted to a different key, does
**not** produce an error — it produces a deterministic pseudo-random
plaintext, so no padding oracle is exposed. The command therefore cannot tell
you a PKCS#1 decrypt went wrong; validate the recovered plaintext yourself.
Every other decrypt failure prints the single fixed string `decrypt failed`.

## `kem`

```sh
purecrypto kem keygen -alg ML-KEM-768 -out-secret dk.bin -out-public ek.bin
purecrypto kem encaps -peer ek.bin -out-ct ct.bin -out-ss ss_a.bin
purecrypto kem decaps -key dk.bin -ct ct.bin -out-ss ss_b.bin
cmp ss_a.bin ss_b.bin
```

## `kex`

```sh
purecrypto kex -alg X25519      -key my.x25519 -peer their.x25519.pub -out ss.bin   # or X448
purecrypto kex -alg ECDH-P256   -key my.pem -peer their.pub.pem -out ss.bin       # or P384, P521
```

`ECDH-*` takes a SEC1 private-key PEM and the peer's SPKI PEM. `X25519` /
`X448` have no PEM plumbing in the CLI: `-key` is the raw 32- / 56-byte
scalar (or its hex), `-peer` the raw public key (or hex) — e.g. `purecrypto
rand 32 -binary -out my.x25519`.

## `req`

```sh
purecrypto req -key leaf.pem -subj "/CN=leaf.example/O=Acme" \
               -addext "subjectAltName=DNS:leaf.example,DNS:www.leaf.example" \
               -out leaf.csr
purecrypto req -in leaf.csr -verify       # check the CSR self-signature
```

`-template tls-server` (or `-template-file x.toml`) applies a built-in or
custom extension template; see `ca list-templates`.

## `x509`

```sh
# Build a self-signed CA cert
purecrypto x509 -new -ca -key ca.pem -subj "/CN=Internal CA" -out ca.crt

# Issue a leaf certificate from a CSR. A CSR's requested subjectAltName is
# NOT certified by default (it is the requester's claim); name the SANs with
# -san, or pass -copy-csr-san to take the request's list as-is.
purecrypto x509 -req -in leaf.csr -CA ca.crt -CAkey ca.pem \
                -san leaf.example,www.leaf.example -out leaf.crt

# Replace the request's whole subject with one you chose, rather than
# certifying the name the requester asked for.
purecrypto x509 -req -in leaf.csr -CA ca.crt -CAkey ca.pem \
                -subj "/CN=Leaf, Inc." -san leaf.example -out leaf.crt

# Inspect a certificate
purecrypto x509 -in leaf.crt -text [-ext]
```

`-CA` must be a CA certificate (basicConstraints CA:TRUE and, when keyUsage
is present, keyCertSign) and `-CAkey` must be its key; a mismatched key is
always an error, and `-force` signs under a non-CA certificate anyway. `-ca`
on `-req` emits a pathLen:0 sub-CA. Serial numbers are drawn from the OS
CSPRNG for every certificate.

### Subject and SAN vetting on `-req`

| Flag | Effect |
| --- | --- |
| `-san a,b` | Certify exactly these SANs — the operator's list, not the request's. |
| `-copy-csr-san` | Take the CSR's requested SAN list as-is (each copied entry is named in a stderr warning). |
| `-subj "/CN=..."` | Replace the request's **whole** subject with this one. |
| `-allow-cn-hostname` | Escape hatch: certify a host-like CSR commonName with no vetted SAN anyway. |

A leaf with **no** vetted subjectAltName whose CSR commonName looks like a
DNS name, a wildcard, or an IP literal is **refused**. Hostname verification
falls back to the commonName exactly when a certificate carries no SAN, so
issuing such a certificate would silently certify a host name the requester
picked. Supply your own names with `-san`, accept the request's with
`-copy-csr-san`, replace the subject with `-subj /CN=...`, or override the
check with `-allow-cn-hostname`.

## `ca`

A small development CA that keeps its state in a directory.

```text
purecrypto ca init     -dir DIR [-cn NAME] [-algorithm EC|RSA|ED25519|ED448] [-curve P-256] [-days N]
purecrypto ca issue    -dir DIR -pubkey leaf.pub -cn NAME [-sans a,b] [-days N] [-out cert.pem] [-ca] [-template NAME] [-template-file PATH] [-force]
purecrypto ca sign-csr -dir DIR -in csr.pem [-out cert.pem] [-days N] [-ca] [-san a,b] [-copy-csr-san] [-subj /CN=...] [-allow-cn-hostname] [-template NAME] [-template-file PATH] [-force]
purecrypto ca revoke   -dir DIR -serial N|0xN [-reason key-compromise|superseded|...] [-force]
purecrypto ca crl      -dir DIR [-out crl.pem] [-days N]
purecrypto ca show     -dir DIR
purecrypto ca list-templates
```

A template file (`-template-file x.toml`, same TOML shape as the built-ins
`ca list-templates` prints) may scope a sub-CA with a `[name_constraints]`
section. Each key is a string array of subtrees, one `permitted_*` /
`excluded_*` pair per name form (RFC 5280 §4.2.1.10):

```toml
[name_constraints]
permitted_dns   = [".corp.example"]                 # dNSName
permitted_email = [".corp.example", "ops@corp.example"]  # rfc822Name
permitted_uri   = [".corp.example"]                 # URI host
permitted_dn    = ["/O=Example Corp/C=US"]          # directoryName, -subj syntax
excluded_dns    = ["internal.corp.example"]
```

`-subj` (and the `*_dn` entries) accept `CN`, `O`, `OU`, `C` and
`emailAddress` (also `E`). Unknown keys in any template section are errors.

Issued and revoked certificates are appended to JSON-lines ledgers in `DIR`
(opened without following symlinks). `ca crl` emits a CRL carrying a
monotonic `cRLNumber` from `DIR/crlnumber`. The same CA-certificate and key
checks as `x509 -req` apply.

`ca sign-csr` applies the same subject and SAN vetting as
[`x509 -req`](#subject-and-san-vetting-on--req): the request's
subjectAltName is not certified unless `-copy-csr-san` is given, and a leaf
with no vetted SAN whose CSR commonName looks like a DNS name, wildcard, or
IP literal is refused. `-subj "/CN=..."` replaces the request's whole subject
with an operator-supplied one; `-allow-cn-hostname` is the escape hatch that
certifies the host-like commonName anyway.

Submitted CSRs must also carry a >= 2048-bit RSA key and a signature that is
not SHA-1/MD5-based.

## `crl`

```sh
purecrypto crl -in crl.pem -text
purecrypto crl -in crl.pem -verify -CAfile ca.crt
purecrypto crl -in crl.pem -is-revoked -serial 0x1A2B
```

## `s_client` / `s_server`

TLS 1.3 by default; `-tls1_2` forces TLS 1.2 (ECDHE-AEAD only, mTLS and
RFC 5077 tickets supported). The same two commands drive DTLS and QUIC
through version flags, described below.

```text
purecrypto s_client -connect host:port [-tls1_2 | -dtls1_2 | -dtls1_3] [-min_protocol TLSv1.2]
                    [-servername name] [-CAfile bundle.pem] [-insecure] [-showcerts]
                    [-alpn h2,http/1.1] [-cert client.pem -key client.key] [-mtu N]
                    [-groups x25519:secp256r1] [-key-shares x25519,...]
                    [-ciphersuites TLS_AES_128_GCM_SHA256:...] [-reconnect [-early_data FILE]]
                    [-key_update] [-enable_server_rpk -rpk_peer_key pub.pem] [-enable_client_rpk]
                    [-record_size_limit N] [-no_cert_comp] [-read_timeout SECS]
                    [-keylogfile keys.log] [-quiet]
                    [-ech-config-list list [-ech-retry-configs-out FILE] | -ech-grease]
purecrypto s_server -cert cert.pem -key key.pem -accept PORT [-tls1_2 | -dtls1_2 | -dtls1_3]
                    [-min_protocol TLSv1.2] [-Verify ca.pem] [-alpn h2,http/1.1] [-www]
                    [-naccept N] [-mtu N] [-no_cookie] [-groups x25519:secp256r1]
                    [-prefer-group NAME] [-ciphersuites TLS_AES_128_GCM_SHA256:...]
                    [-no_ticket] [-early_data [-max_early_data N]]
                    [-key_update] [-status_file resp.der] [-enable_server_rpk]
                    [-enable_client_rpk -rpk_peer_key pub.pem] [-record_size_limit N]
                    [-no_cert_comp] [-keylogfile keys.log] [-quiet]
                    [-ech-key key.bin -ech-config config.bin]
```

```sh
purecrypto s_client -connect example.com:443                       # verifies against the embedded roots
purecrypto s_client -connect 127.0.0.1:8443 -CAfile ca.crt -servername leaf.example
purecrypto s_client -connect 127.0.0.1:8443 -insecure -quiet       # skip cert verify (prints a WARNING)
purecrypto s_client -connect example.com:443 -alpn h2,http/1.1     # ALPN
purecrypto s_client -connect example.com:443 -keylogfile keys.log  # NSS SSLKEYLOGFILE for Wireshark
purecrypto s_client -connect server:443 -cert client.pem -key client.key   # mTLS

purecrypto s_server -cert server.pem -key server.key -accept 4433        # echo
purecrypto s_server -cert server.pem -key server.key -accept 4433 -www   # one fixed HTTP response
purecrypto s_server -cert server.pem -key server.key -accept 8443 -Verify client-ca.pem   # require + verify client certs

# Resume: two connections, the second offering the first one's ticket and
# 0-RTT data; the server accepts two connections and 0-RTT.
purecrypto s_server -cert server.pem -key server.key -accept 4433 -naccept 2 -early_data
purecrypto s_client -connect 127.0.0.1:4433 -CAfile ca.crt -reconnect -early_data first.txt
```

After the handshake both commands print the negotiated parameters to
stderr, one `key: value` line per fact, so a harness can grep each one
(this is what `tools/interop/run.sh` checks against the peer's own log):

```text
cipher suite: TLS_AES_128_GCM_SHA256
key exchange: X25519MLKEM768
HelloRetryRequest: no
resumed: no
early data: none                     # accepted | rejected | none
peer certificate: X.509 (2)          # raw public key | none
peer certificate compression: none   # client: zlib when the server compressed
own certificate: X.509               # server (and an RPK client): raw public key
own certificate compression: zlib    # server
OCSP staple: no                      # client
record_size_limit: not negotiated
…
KeyUpdate: sent 1, received 1        # once the data phase is over
close_notify: received               # the peer ended the session properly
```

Behaviour worth knowing:

- The client offers `X25519MLKEM768` first, then `x25519`, `secp256r1` and
  `secp384r1`, with a key share for each; all three TLS 1.3 suites; and
  Ed25519, Ed448, ECDSA and RSA peer signatures. `-key-shares x25519` (a
  comma-separated list) pre-shares keys for those groups only: every group is
  still offered, and a server preferring another answers with a
  HelloRetryRequest.
- `-groups x25519:secp256r1` (colon- or comma-separated, `openssl -groups`
  spelling; `p256` / `P-256` are accepted too) restricts and orders the
  groups. On the client it is the `supported_groups` offer, with a share
  for each (narrow those further with `-key-shares`). On the server it is
  the accept-set in *server* preference: the first listed group the client
  shared wins, and a client that shared none of them but offered one is
  sent a HelloRetryRequest for it. `-ciphersuites TLS_AES_128_GCM_SHA256:…`
  restricts and orders the TLS 1.3 suites the same way: the client's offer,
  or the server's accept-set in *server* preference (the first listed suite
  the client offered wins; a client offering none of them is refused).
- `s_server -prefer-group NAME` (`x25519`, `secp256r1`, `secp384r1`,
  `X25519MLKEM768`) makes the server ask, by HelloRetryRequest, for that group
  whenever the client offers it without a key share. After the handshake the
  server prints the SNI it was sent (`SNI: …`).
- `-min_protocol TLSv1.2` widens the pinned TLS 1.3 client or server into a
  version-spanning one (1.2..=1.3), the fallback `openssl` performs by
  default; the `connected:` / `handshake complete:` line says which was
  negotiated.
- `s_server` issues a session ticket after every TLS 1.3 handshake (under a
  per-process random key; `-no_ticket` turns it off) and, with `-naccept N`,
  serves N connections in a row, so a client can come back and resume.
  `-early_data` accepts 0-RTT on a resumed connection (`-max_early_data`
  caps it, default 16384) and echoes it like any other input: early data is
  replayable (RFC 8446 §8), this is a test server. `s_client -reconnect`
  connects twice — the first time only to be issued a ticket — and offers
  it on the second connection; `-early_data FILE` sends the file as 0-RTT
  with that offer, and re-sends it as ordinary data if the server rejected
  it (as one does after a HelloRetryRequest). The first connection sends
  nothing and waits 2 s for a ticket; a server that bundles its
  NewSessionTickets with its first write instead (Apple's
  Network.framework does) gets a `close_notify` then, and the tickets that
  come back with its own goodbye are used.
- `-key_update` (either side, TLS 1.3 and DTLS 1.3) sends
  `KeyUpdate(update_requested)` right after the handshake, before any
  application data; the tally line at the end shows the peer's reply. A
  peer's own `KeyUpdate(update_requested)` is answered in kind.
- RFC 7250 raw public keys: `s_server -enable_server_rpk` sends the bare
  public key of `-key` (no chain) to a client that offers
  `server_certificate_type = RawPublicKey`; `s_client -enable_server_rpk`
  offers it (X.509 still accepted) and must pin the server's key with
  `-rpk_peer_key FILE` (a `PUBLIC KEY` PEM, as `pkey -pubout` writes; several
  blocks form an allowlist), since there is no chain to validate. The other
  direction is `s_client -cert … -key … -enable_client_rpk` (present the
  identity as a raw key when the server asks for a certificate) against
  `s_server -Verify ca.pem -enable_client_rpk -rpk_peer_key FILE` (accept
  raw client keys from that allowlist; `-Verify` still makes the request).
- `s_server -status_file resp.der` staples a DER OCSP response (RFC 6066 §8;
  on TLS 1.3 in the leaf's `status_request` entry); the client always asks,
  validates a staple against the chain, and reports `OCSP staple: yes`.
- `-record_size_limit N` (64..=16385) advertises RFC 8449; `-no_cert_comp`
  turns off the RFC 8879 `compress_certificate` advertisement (zlib is
  advertised by default in a build with `cert-compression`).
- `s_client -read_timeout SECS` (default 5) is how long the client waits for
  more data after the last byte before ending the session with
  `close_notify`; it then waits, bounded by the same timeout, for the
  peer's `close_notify` and reports whether it came.
- `s_server` is a one-shot test server: it accepts one connection, exchanges
  data, and exits (over TCP it also gives up after 60 s without a client).
  `-accept` takes a bare port, which binds `127.0.0.1`; the DTLS and QUIC
  servers accept `host:port` as well.
- `-accept 0` (or `host:0`) lets the kernel pick a free port. All three
  servers print the address they actually bound in their `listening on …`
  stderr banner, so a harness can start the server first and read the port
  back from that line, rather than probing for a free port and hoping nobody
  takes it before the server binds. `-quiet` suppresses the banner.
- A TCP close without a TLS `close_notify` is reported as a possible
  truncation on stderr and the client exits non-zero.
- `-key` must match `-cert`; a mismatch is refused before listening.
- `-Verify` (client certificate authentication) is TLS-only: combined with
  `-dtls1_2` / `-dtls1_3` it is refused up front, because the DTLS server
  does not support client authentication.
- `-keylogfile` is opened without following symlinks and refused if the
  file is readable by others.

## Encrypted Client Hello: `generate-ech`, `-ech-*`

Encrypted Client Hello (ECH, [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849))
hides the real server name, ALPN and the rest of the ClientHello from the
network: the client encrypts that *inner* hello to a public key the server
publishes (an `ECHConfigList`, normally in a DNS HTTPS record) and sends an
*outer* hello naming only the configuration's `public_name`. It needs a
binary built with the `ech` feature (`cargo build --features ech`, or
`cargo install purecrypto --features ech`); without it the ECH flags are
refused rather than ignored. TLS 1.3 over TCP only.

```text
purecrypto generate-ech -public-name NAME -out-ech-config-list list.bin
                        -out-ech-config config.bin -out-private-key key.bin
                        [-config-id N] [-max-name-length N]
purecrypto s_client … -ech-config-list list.bin [-ech-retry-configs-out retry.bin]
purecrypto s_client … -ech-grease
purecrypto s_server … -ech-key key.bin -ech-config config.bin
```

The files use BoringSSL's formats, so keys move between `purecrypto` and
`bssl generate-ech` / `bssl server -ech-key … -ech-config …` /
`bssl client -ech-config-list …` unchanged:

- **`ECHConfigList`** (`-out-ech-config-list`, `-ech-config-list`) — the wire
  list a DNS HTTPS record's `ech=` parameter carries. `s_client` also takes it
  base64-encoded, as DNS tooling prints it.
- **`ECHConfig`** (`-out-ech-config`, `-ech-config`) — one wire config.
- **private key** (`-out-private-key`, `-ech-key`) — the raw HPKE private key
  (32 bytes: `generate-ech` makes DHKEM(X25519, HKDF-SHA256) keys offering
  AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305). Written mode 0600 and never
  over an existing file.

`s_client -ech-config-list` seals the `-servername` hello and prints
`ECH: accepted` once the server confirms it. If the server cannot decrypt it
(a stale configuration), it completes the handshake as `public_name` instead;
the client verifies the certificate for that name, prints `ECH: rejected` and
the server's `retry_configs` (base64; `-ech-retry-configs-out` also saves them
as an `ECHConfigList` to retry with), sends `ech_required` and exits non-zero
— such a connection is never used for data. `-ech-grease` sends a
look-alike extension without a configuration (and prints
`ECH: GREASE (not negotiated)`). `s_server` reports `ECH: accepted` or
`ECH: not accepted` next to the SNI it handshook on, and sends its own
configuration as `retry_configs` whenever it rejects.

```sh
# A server with an ECH key, and a client that hides secret.example behind
# public.example (the certificate should cover both names).
purecrypto generate-ech -public-name public.example -out-ech-config-list ech.list \
                        -out-ech-config ech.cfg -out-private-key ech.key
purecrypto s_server -cert server.crt -key server.pem -accept 8443 -www \
                    -ech-key ech.key -ech-config ech.cfg
purecrypto s_client -connect 127.0.0.1:8443 -CAfile ca.crt -servername secret.example \
                    -ech-config-list ech.list

# A public ECH deployment: fetch the ECHConfigList from DNS (the `ech=` value
# of the HTTPS record, base64) and look for `sni=encrypted`.
purecrypto s_client -connect crypto.cloudflare.com:443 -ech-config-list cf-ech.b64 \
                    < request.txt     # GET /cdn-cgi/trace
```

## DTLS: `s_dtls_client` / `s_dtls_server`

DTLS runs the TLS handshake over UDP. Use the dedicated commands or pass
`-dtls1_2` / `-dtls1_3` to `s_client` / `s_server`; the two forms are
equivalent.

```sh
purecrypto s_dtls_server -dtls1_2 -accept 0.0.0.0:5684 -cert cert.pem -key key.pem
purecrypto s_dtls_client -dtls1_2 -connect localhost:5684

purecrypto s_dtls_server -dtls1_3 -accept 0.0.0.0:5685 -cert cert.pem -key key.pem
purecrypto s_dtls_client -dtls1_3 -connect localhost:5685
```

The server performs a HelloVerifyRequest (1.2) or HelloRetryRequest cookie
(1.3) exchange before allocating per-connection state; `-no_cookie` disables
it for tests only, since a cookie-less DTLS server is a UDP reflection
amplifier. Both directions run a 64-bit sliding-window replay filter. The
default record size is 1200 bytes; override with `-mtu`.

Both commands print the same `key: value` negotiated-parameter report as
their TCP counterparts (`connected: DTLSv1.3` / `handshake complete:
DTLSv1.3`, `cipher suite:`, `key exchange:`, `HelloRetryRequest:` — `yes`
whenever the server's cookie exchange ran — and, at the end, `KeyUpdate:
sent N, received M` and `close_notify:`), so `tools/interop/run.sh` checks
DTLS cases the way it checks TLS ones. `-groups`, `-key-shares` and
`-ciphersuites` pin the client's offer and `-groups` the server's accept
set as over TCP; `-key_update` (DTLS 1.3 only, RFC 9147 §8) rekeys right
after the handshake and asks the peer to. The session ends with a
`close_notify` in a protected record, answered in kind, and the client
waits `-read_timeout` seconds for the peer's before reporting. Not
implemented over DTLS, and refused up front: client certificates
(`-Verify`, `-cert`), resumption and 0-RTT (`-reconnect`, `-early_data`,
`-naccept`), raw public keys, `-record_size_limit`, ECH.

## QUIC: `q_client` / `q_server`

QUIC v1 (RFC 9000) over UDP, secured by TLS 1.3 keys. Use the dedicated
commands or pass `-quic` to `s_client` / `s_server`. The two commands speak
a small echo protocol that the interop matrix in `tools/quic-interop/` also
implements on the quic-go side: the server echoes every client-initiated
bidirectional stream, answers every client-initiated unidirectional stream
on a unidirectional stream of its own, and echoes every DATAGRAM frame (RFC
9221); the client sends stdin on one stream (or as DATAGRAMs) and writes the
reply to stdout. ALPN is mandatory (RFC 9001 §8.1).

```text
purecrypto q_client -connect host:port -alpn proto [-insecure] [-servername name] [-CAfile bundle.pem]
                    [-uni | -datagram] [-exchanges N] [-pause ms] [-migrate] [-switch-cid]
                    [-reconnect [-early-data]] [-key-update] [-ciphersuites list] [-key-shares groups]
                    [-close-code N] [-close-reason text] [-idle-timeout ms] [-linger ms]
                    [-timeout secs] [-keylogfile keys.log] [-quiet]
purecrypto q_server -cert cert.pem -key key.pem -accept host:port -alpn proto [-www] [-retry]
                    [-early-data] [-key-update] [-switch-cid] [-ciphersuites list] [-idle-timeout ms]
                    [-reset-key hex32] [-naccept N] [-timeout secs] [-keylogfile keys.log] [-quiet]
```

```sh
purecrypto q_server -accept 0.0.0.0:4434 -cert cert.pem -key key.pem -alpn h3
purecrypto q_client -connect localhost:4434 -alpn h3
```

Both print what the handshake negotiated on stderr (`negotiated: alpn=…
suite=… resumed=… early_data=… retry=… ecn=…`), one line per stream with
the byte count and SHA-256 of what arrived, and how the connection ended
(`closed: application error 0x0 () by peer`, `closed: idle timeout`,
`closed: stateless reset`).

Client options:

- `-uni` sends stdin on a unidirectional stream and prints the server's
  unidirectional reply; `-datagram` sends each line of stdin as one DATAGRAM
  frame and prints the echoes (unreliable: it stops waiting after 2 s).
- `-exchanges N` repeats the exchange on fresh streams, `-pause ms` apart.
  `-migrate` rebinds to a new UDP socket between exchanges (a client
  migration, RFC 9000 §9, probed with a PATH_CHALLENGE); `-switch-cid`
  moves to a spare server-issued connection ID and retires the old one
  (§5.1.2).
- `-reconnect` connects a second time with the first connection's session
  ticket; with `-early-data` the second connection's data goes out as 0-RTT
  when the ticket permits it. The log reports `resumed=yes` and
  `early_data=accepted|rejected|offered|none`.
- `-key-update` initiates a 1-RTT key update once the handshake is
  confirmed and reports when the peer's reply in the new phase confirms it.
- `-ciphersuites` restricts the offered TLS 1.3 suites (OpenSSL names,
  `:`-separated); `-key-shares` restricts the groups a `key_share` is sent
  for (`x25519`, `secp256r1`, `secp384r1`, `X25519MLKEM768`).
- `-close-code N` / `-close-reason text` set the application error the
  final CONNECTION_CLOSE carries (default `0`). `-idle-timeout ms` sets the
  advertised `max_idle_timeout` (default 60 000). `-linger ms` keeps the
  connection open and idle after the exchanges until the peer closes it or
  the time elapses, so an idle timeout or a stateless reset can be observed.

Server options:

- `-retry` validates client addresses with a Retry packet before committing
  state (§8.1.2). `-early-data` accepts 0-RTT on resumed connections (the
  echo has nothing to lose to a replay; do not copy this into a server whose
  early requests are not idempotent). Session tickets are always issued
  (a fresh ticket key per process).
- `-key-update` initiates a key update on every connection once the client
  has acknowledged HANDSHAKE_DONE; `-switch-cid` switches to a spare
  client-issued connection ID.
- `-reset-key hex32` fixes the stateless-reset key (§10.3.1) so a restarted
  server still resets the connections its predecessor held; random
  otherwise.
- `-naccept N` exits after N connections have ended (default 1; `0` keeps
  serving until `-timeout secs`, default 30, elapses). `-www` answers the
  first bidirectional stream with a canned body instead of echoing.

Only the `s_client -quic` direction is available from OpenSSL; both roles
are exercised against quic-go by `tools/quic-interop/run.sh` (see
[`validation.md`](validation.md)).

## Cookbook

### CA plus leaf with EC keys

```sh
purecrypto genpkey -algorithm EC -curve P-256 -out ca.pem
purecrypto x509 -new -ca -key ca.pem -subj "/CN=My CA" -out ca.crt

purecrypto genpkey -algorithm EC -curve P-256 -out leaf.pem
purecrypto req -key leaf.pem -subj "/CN=leaf.example" \
               -addext "subjectAltName=DNS:leaf.example" -out leaf.csr
purecrypto x509 -req -in leaf.csr -CA ca.crt -CAkey ca.pem \
                -san leaf.example -out leaf.crt
```

The `-san` here is what makes the issuance valid: without a vetted SAN the
CSR's `/CN=leaf.example` looks like a host name and the command refuses. Add
`-copy-csr-san` to certify the request's own list, `-subj` to substitute your
own subject, or `-allow-cn-hostname` to override.

### The same with the `ca` subcommand, plus revocation

```sh
purecrypto ca init -dir ./myca -cn "My CA" -algorithm EC
purecrypto ca sign-csr -dir ./myca -in leaf.csr -san leaf.example -out leaf.crt
purecrypto ca revoke -dir ./myca -serial 0x<serial printed by sign-csr> -reason superseded
purecrypto ca crl -dir ./myca -out myca.crl
purecrypto crl -in myca.crl -verify -CAfile ./myca/root.crt
```

### A post-quantum signature key and its public counterpart

```sh
purecrypto genpkey -algorithm ML-DSA-65 -out mldsa.pem
purecrypto pkey -in mldsa.pem -text                       # ML-DSA-65 private key
purecrypto pkey -in mldsa.pem -pubout > mldsa.pub.pem     # PKIX SPKI
echo -n hello > msg
purecrypto pkeyutl sign   -inkey mldsa.pem -in msg -out msg.sig
purecrypto pkeyutl verify -inkey mldsa.pub.pem -pubin -sigfile msg.sig -in msg
```

### A two-process mTLS handshake on one host

```sh
# CA + server cert + client cert, all Ed25519
purecrypto genpkey -algorithm ED25519 -out ca.pem
purecrypto x509 -new -ca -key ca.pem -subj "/CN=Local CA" -out ca.crt
purecrypto genpkey -algorithm ED25519 -out server.pem
purecrypto req -key server.pem -subj "/CN=127.0.0.1" \
               -addext "subjectAltName=IP:127.0.0.1" -out server.csr
purecrypto x509 -req -in server.csr -CA ca.crt -CAkey ca.pem \
                -san 127.0.0.1 -out server.crt
purecrypto genpkey -algorithm ED25519 -out client.pem
purecrypto req -key client.pem -subj "/CN=alice" -out client.csr
purecrypto x509 -req -in client.csr -CA ca.crt -CAkey ca.pem -out client.crt

# Terminal 1: server requires + verifies client certs against ca.crt
purecrypto s_server -cert server.crt -key server.pem -accept 8443 -Verify ca.crt -www

# Terminal 2: client presents its cert + key
purecrypto s_client -connect 127.0.0.1:8443 -CAfile ca.crt \
                    -cert client.crt -key client.pem -alpn http/1.1 \
                    -keylogfile keys.log
```

### Encrypt a file with a password-derived key

```sh
purecrypto rand 16 -out salt.bin
purecrypto kdf argon2 -variant 2id -password-file - -salt "$(xxd -p salt.bin)" \
                      -t-cost 3 -m-cost 65536 -len 32 -binary -out k.bin
purecrypto rand 12 -out nonce.bin
purecrypto enc -alg AES-256-GCM -keyfile k.bin -nonce "$(xxd -p nonce.bin)" -in secret.txt -out secret.enc
purecrypto enc -alg AES-256-GCM -keyfile k.bin -nonce "$(xxd -p nonce.bin)" -d -in secret.enc
```
