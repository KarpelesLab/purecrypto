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

## Contents

- [`hash` / `dgst`](#hash--dgst)
- [`mac`](#mac)
- [`kdf`](#kdf)
- [`enc`](#enc)
- [`rand`](#rand)
- [`genpkey`](#genpkey)
- [`pkey`](#pkey)
- [`pkeyutl`](#pkeyutl)
- [`kem`](#kem)
- [`kex`](#kex)
- [`req`](#req)
- [`x509`](#x509)
- [`ca`](#ca)
- [`crl`](#crl)
- [`s_client` / `s_server`](#s_client--s_server)
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
`sha512/256` are accepted. The XOFs (`shake128`, `shake256`, BLAKE2X,
cSHAKE, KMAC) are exposed through the Rust library, not the CLI.

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
purecrypto genpkey -algorithm LMS-SHA256-H10-W4       -out lms.pem
purecrypto genpkey -algorithm HSS-L2-SHA256-H10-W4    -out hss.pem
purecrypto genpkey -algorithm XMSS-SHA2_10_256        -out xmss.pem
purecrypto genpkey -algorithm XMSSMT-SHA2_20/2_256    -out xmssmt.pem
```

The full SLH-DSA matrix is `SLH-DSA-{SHA2,SHAKE}-{128,192,256}{s,f}`.

Output format:

- RSA: `-----BEGIN RSA PRIVATE KEY-----` (PKCS#1)
- EC / SM2: `-----BEGIN EC PRIVATE KEY-----` (SEC1)
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
> refuses to sign if it cannot; never copy a stateful key file.

## `pkey`

```sh
purecrypto pkey -in key.pem -text     # describe the key
purecrypto pkey -in key.pem -pubout   # emit the SPKI public-key PEM
purecrypto pkey < key.pem             # re-emit the private key (round-trip)
```

`pkey` auto-detects RSA PKCS#1, EC SEC1, and every PKCS#8 type above.

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
An SM2 key routes to SM2-DSA for sign/verify and SM2-PKE for
encrypt/decrypt; `-id STR` overrides the default signer identity.

## `kem`

```sh
purecrypto kem keygen -alg ML-KEM-768 -out-secret dk.bin -out-public ek.bin
purecrypto kem encaps -peer ek.bin -out-ct ct.bin -out-ss ss_a.bin
purecrypto kem decaps -key dk.bin -ct ct.bin -out-ss ss_b.bin
cmp ss_a.bin ss_b.bin
```

## `kex`

```sh
purecrypto kex -alg X25519      -key my.pem -peer their.pub.pem -out ss.bin
purecrypto kex -alg ECDH-P256   -key my.pem -peer their.pub.pem -out ss.bin   # or P384, P521, X448
```

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

# Inspect a certificate
purecrypto x509 -in leaf.crt -text [-ext]
```

`-CA` must be a CA certificate (basicConstraints CA:TRUE and, when keyUsage
is present, keyCertSign) and `-CAkey` must be its key; a mismatched key is
always an error, and `-force` signs under a non-CA certificate anyway. `-ca`
on `-req` emits a pathLen:0 sub-CA. Serial numbers are drawn from the OS
CSPRNG for every certificate.

## `ca`

A small development CA that keeps its state in a directory.

```text
purecrypto ca init     -dir DIR [-cn NAME] [-algorithm EC|RSA|ED25519|ED448] [-curve P-256] [-days N]
purecrypto ca issue    -dir DIR -pubkey leaf.pub -cn NAME [-sans a,b] [-days N] [-out cert.pem] [-ca] [-template NAME] [-template-file PATH] [-force]
purecrypto ca sign-csr -dir DIR -in csr.pem [-out cert.pem] [-days N] [-ca] [-san a,b] [-copy-csr-san] [-template NAME] [-template-file PATH] [-force]
purecrypto ca revoke   -dir DIR -serial N|0xN [-reason key-compromise|superseded|...] [-force]
purecrypto ca crl      -dir DIR [-out crl.pem] [-days N]
purecrypto ca show     -dir DIR
purecrypto ca list-templates
```

Issued and revoked certificates are appended to JSON-lines ledgers in `DIR`
(opened without following symlinks). `ca crl` emits a CRL carrying a
monotonic `cRLNumber` from `DIR/crlnumber`. The same CA-certificate and key
checks as `x509 -req` apply.

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
purecrypto s_client -connect host:port [-tls1_2 | -dtls1_2 | -dtls1_3] [-servername name]
                    [-CAfile bundle.pem] [-insecure] [-showcerts] [-alpn h2,http/1.1]
                    [-cert client.pem -key client.key] [-mtu N] [-keylogfile keys.log] [-quiet]
purecrypto s_server -cert cert.pem -key key.pem -accept PORT [-tls1_2 | -dtls1_2 | -dtls1_3]
                    [-Verify ca.pem] [-alpn h2,http/1.1] [-www] [-mtu N] [-no_cookie]
                    [-keylogfile keys.log] [-quiet]
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
```

Behaviour worth knowing:

- The client offers `X25519MLKEM768` first, then `x25519` and `secp256r1`;
  all three TLS 1.3 suites; and Ed25519, Ed448, ECDSA and RSA peer
  signatures.
- `s_server` is a one-shot test server: it accepts one connection, exchanges
  data, and exits. It binds `127.0.0.1` unless you give an explicit address.
- A TCP close without a TLS `close_notify` is reported as a possible
  truncation on stderr and the client exits non-zero.
- `-key` must match `-cert`; a mismatch is refused before listening.
- `-keylogfile` is opened without following symlinks and refused if the
  file is readable by others.

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

## QUIC: `q_client` / `q_server`

QUIC v1 (RFC 9000) over UDP, secured by TLS 1.3 keys. Use the dedicated
commands or pass `-quic` to `s_client` / `s_server`. The client drives one
bidirectional stream (stdin to server, reply to stdout).

```text
purecrypto q_client -connect host:port [-alpn h3] [-insecure] [-servername name] [-CAfile bundle.pem] [-keylogfile keys.log] [-quiet]
purecrypto q_server -cert cert.pem -key key.pem -accept host:port [-alpn h3] [-www] [-retry] [-keylogfile keys.log] [-quiet]
```

```sh
purecrypto q_server -accept 0.0.0.0:4434 -cert cert.pem -key key.pem -alpn h3
purecrypto q_client -connect localhost:4434 -alpn h3
```

`-retry` makes the server validate client addresses with a Retry packet
before committing state.

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
               -addext "subjectAltName=DNS:127.0.0.1" -out server.csr
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
