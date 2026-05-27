# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0](https://github.com/KarpelesLab/purecrypto/compare/v0.1.1...v0.2.0) - 2026-05-27

### Added

- *(kdf)* encrypted PKCS#8 (RFC 5958 §3 / RFC 8018 PBES2)

### Fixed

- *(tls,dtls)* TLS / DTLS robustness hardening
- *(x509,der)* X.509 / DER strictness hardening

### Other

- BoxedRsaPublicKey::exponent + kdf::bcrypt_pbkdf path cleanup
- strict SAN parsing + iPAddress accessor + IP-aware host matcher

## [0.1.1](https://github.com/KarpelesLab/purecrypto/compare/v0.1.0...v0.1.1) - 2026-05-27

### Added

- *(dh)* finite-field Diffie-Hellman (RFC 3526 MODP groups)
- *(kdf)* bcrypt_pbkdf — OpenSSH-style PBKDF over Blowfish
- *(rsa)* SPKI + PKCS#8 + PEM round-trip helpers
- *(ec)* r/s component accessors on ECDSA + Ed25519 signatures

### Other

- ignore Cargo.lock (regression of 4a39a57)

## [0.1.0](https://github.com/KarpelesLab/purecrypto/compare/v0.0.7...v0.1.0) - 2026-05-27

### Added

- *(tls)* RFC 7627 Extended Master Secret for TLS 1.2 + DTLS 1.2
- *(quic,ffi)* C ABI surface (PcQuicCfg / PcQuic) + smoke test
- *(quic,cli)* q_client / q_server subcommands over UDP loopback
- *(quic)* key update + DATAGRAM frames + stateless reset recognition
- *(quic)* Retry + address validation + path challenge + CID rotation
- *(quic)* streams + flow control (RFC 9000 §2-§4)
- *(quic)* RFC 9002 loss recovery + NewReno + ACK frame builder
- *(quic)* QuicConnection — handshake-only client + server (RFC 9000 §17, §12)
- *(tls)* QuicHooks seam — engine_mode + per-level hooks for QUIC
- *(quic)* RFC 9001 §5 packet protection — crypto + pkt
- *(quic)* RFC 9000 foundations — varint, PN, frames, transport params
- *(tls)* SSLKEYLOGFILE support via Config::key_log
- *(ffi)* memory-BIO TLS 1.2/1.3 + DTLS 1.2/1.3 (sans-I/O C ABI)
- *(ffi)* ML-KEM, ML-DSA, SLH-DSA, RSA-PSS, RSA-OAEP, CSR, CRL
- *(ffi)* AEAD, KW, KDF, HMAC widening, ECDH, X25519
- *(cli)* kem, kex, pkeyutl, crl subcommands
- *(cli)* mac, kdf, enc subcommands for HMAC + HKDF/PBKDF2/scrypt/Argon2 + AEAD encryption

### Fixed

- *(tests)* gate run_capture with #[cfg(unix)]
- *(crypto,pqc,ffi,cli)* 10 MEDIUM hardening items
- *(tls,x509)* 7 MEDIUM hardening items
- *(quic)* 5 MEDIUM hardening items (Retry state, final_size, reset token,
- *(tls)* enforce 0-RTT byte budget + TLS 1.3 ticket expiry
- *(quic)* wire RFC 9002 loss recovery + NewReno into connection
- *(quic)* cap CRYPTO reassembly + propagate active_connection_id_limit
- *(ffi)* catch panics in pointer/i32-returning extern "C" functions
- *(quic)* verify peer's TP CID echoes (RFC 9000 §7.3) — CRITICAL
- *(cli)* s_client must drain pre-buffered plaintext before sock.read
- *(cli)* drain pre-buffered plaintext after handshake; non-blocking -www
- *(cli)* s_server -www must feed received bytes into TLS engine

### Other

- *(tls)* unified `tls::Config` for TLS+DTLS, client+server
- full CLI + C-API coverage table; tests/ffi_smoke ties to public surface

## [0.0.7](https://github.com/KarpelesLab/purecrypto/compare/v0.0.6...v0.0.7) - 2026-05-26

### Added

- *(cli)* -template / -template-file plumbing + ca list-templates + x509 -ext
- *(cli)* CertTemplate + 8 built-in profile catalog
- *(cli)* hand-rolled minimal TOML parser
- *(x509)* extension types + encoders + issue_with_extensions
- *(cli)* `purecrypto ca` — manage a development CA on disk
- *(tls)* CRL stapling on the TLS 1.3 Certificate message
- *(tls)* CrlStore + verify_chain_with_crls
- *(x509)* CRL types — CertificateRevocationList + CrlBuilder

### Other

- rustfmt sweep + clippy-clean across all targets
- *(cli)* pass -insecure to DTLS round-trip tests after audit fix

### Security

- residual LOW findings — DER strict tail, IA5 SAN, ct hygiene, drop wipes
- *(cli)* private-key file modes + DTLS verify required + rand cap + serial cleanup

## [0.0.6](https://github.com/KarpelesLab/purecrypto/compare/v0.0.5...v0.0.6) - 2026-05-26

### Added

- *(cli)* unified -tls / -dtls version flags
- *(dtls)* DTLS 1.3 client + server + cookie
- *(dtls)* DTLS 1.3 ACK + reliability
- *(dtls)* DTLS 1.3 record framing
- *(cli)* s_dtls_client / s_dtls_server binaries
- *(dtls)* DTLS 1.2 client + server
- *(dtls)* DTLS 1.2 retransmission
- *(dtls)* record layer + replay window + reassembly + cookie
- *(cli,tls)* -tls1_2 flag + live interop
- *(tls)* TLS 1.2 hostile-peer hardening
- *(tls)* TLS 1.2 mTLS + RFC 5077 session tickets
- *(tls)* TLS 1.2 server (ECDHE-AEAD)
- *(tls)* TLS 1.2 client (ECDHE-AEAD, server-cert-only)
- *(tls)* TLS 1.2 handshake-message codec
- *(tls)* TLS 1.2 cipher-suite codes, PRF, explicit-nonce AEAD
- *(signature_registry)* optional SHA-1-RSA + RSA-PSS-PSS keys
- *(tls)* ML-DSA in TLS 1.3 CertificateVerify
- *(x509)* SLH-DSA chain + secp256k1 + cross-hash ECDSA
- *(x509,signature_registry)* ML-DSA chain + issuance support
- *(x509,tls)* policy whitelist — SignaturePolicy
- SignatureAlgorithm registry — refactor verify dispatch
- *(cli)* keylogfile, ALPN, mTLS flags; new s_server binary
- *(tls)* mTLS / client certificate authentication
- *(tls)* 0-RTT (early_data)
- *(tls)* PSK session resumption (server + client)

### Other

- README — TLS 1.2, DTLS 1.2, DTLS 1.3
- README — signature registry, policy, supported algorithms
- README — TLS row to ✅, document the new features

### Security

- *(pqc)* ML-KEM EK input validation + ML-DSA ct_eq
- *(cipher,ec,rng)* ChaCha20/GCM length caps + P-521 rejection + DRBG reseed
- *(dtls)* replay window + cookie expiry + reassembly cap
- *(tls)* downgrade defenses + RSA-PKCS1 ban + plaintext-after-keys + mTLS purpose
- *(ec,der)* Ed25519 cofactored verify + OID canonicalization + PEM strictness
- *(x509,der)* DN raw-DER + strict-INTEGER + pathLen overflow + ECDSA strict DER + low-S
- *(x509)* inner/outer algid + critical-ext rejection + keyCertSign + EC coord reduction + chain cap
- *(ec,tls)* Fermat inverse on secret z + X25519 zero rejection
- *(rsa)* base blinding + constant-time PKCS#1 v1.5 + PSS ct_eq

## [0.0.5](https://github.com/KarpelesLab/purecrypto/compare/v0.0.4...v0.0.5) - 2026-05-26

### Added

- *(tls)* PSK key-schedule plumbing
- *(tls)* TLS-Exporter (RFC 5705 / RFC 8446 §7.5)
- *(tls)* record_size_limit (RFC 8449)
- *(tls)* ALPN (RFC 7301)
- *(x509,tls)* chain-validation completeness — basicConstraints, keyUsage, EKU
- *(tls)* hostile-peer record-layer hardening
- *(tls)* HelloRetryRequest — transcript rewrite + ClientHello retry
- *(tls)* KeyUpdate — full bidirectional rekey
- *(tls)* NewSessionTicket — parse and store post-handshake
- *(kdf,hash)* Argon2id / Argon2d / Argon2i (RFC 9106)
- *(cipher,kdf)* Salsa20/8 core + scrypt (RFC 7914)
- *(mlkem)* add ML-KEM-512 and ML-KEM-1024 (FIPS 203)
- *(rsa)* OAEP encryption / decryption (RFC 8017 §7.1)
- *(cipher)* AES-XTS — IEEE 1619-2007 / NIST SP 800-38E
- *(cipher)* AES-CCM AEAD (RFC 3610 / NIST SP 800-38C)
- *(cipher)* AES key wrap — RFC 3394 (KW) and RFC 5649 (KWP)

### Other

- cargo fmt --all
- flip cipher / rsa / kdf / mlkem rows to ✅

## [0.0.4](https://github.com/KarpelesLab/purecrypto/compare/v0.0.3...v0.0.4) - 2026-05-26

### Added

- *(cli,pq)* PKCS#8 + CLI for ML-DSA, ML-KEM-768, and SLH-DSA
- *(rsa)* runtime key generation for arbitrary modulus sizes
- *(slhdsa)* add SLH-DSA (FIPS 205) hash-based signatures — all 12 sets
- *(mldsa)* add ML-DSA (FIPS 204) signatures — 44/65/87
- *(tls,mlkem)* add hybrid X25519MLKEM768 key exchange + ML-KEM SPKI
- *(mlkem)* add ML-KEM-768 (FIPS 203), no_std and no-alloc
- *(ec)* add Ed25519 (EdDSA, RFC 8032) across the full stack
- *(cipher)* add ChaCha20-Poly1305 AEAD + TLS 1.3 suite
- *(rng)* add Windows OsRng via ProcessPrng (fixes Windows release builds)

### Fixed

- *(rng)* link bcryptprimitives via raw-dylib for Windows OsRng

### Other

- honest status table — flip completed rows to ✅, name the gaps
- comprehensive README — current state and CLI usage
- document ML-DSA and SLH-DSA
- document ChaCha20-Poly1305, Ed25519, ML-KEM-768 and hybrid TLS
- run tests and clippy on Windows and macOS

### Added

- *(rsa)* runtime RSA key generation (`BoxedRsaPrivateKey::generate`) for arbitrary moduli; `genpkey` now accepts any even size up to 65536 bits (e.g. 8192), falling back from the const-generic path
- *(slhdsa)* SLH-DSA (FIPS 205), all 12 parameter sets; ACVP + OpenSSL-interop validated
- *(mldsa)* ML-DSA-44/65/87 (FIPS 204); ACVP + OpenSSL-interop validated
- *(tls,mlkem)* hybrid X25519MLKEM768 (0x11ec) TLS 1.3 key exchange; ML-KEM-768 PKIX SPKI
- *(mlkem)* ML-KEM-768 (FIPS 203), `no_std`/no-alloc; OpenSSL 3.5 interop-validated
- *(ec)* Ed25519 (EdDSA, RFC 8032) — library, X.509, TLS 1.3, CLI, and C FFI
- *(cipher)* ChaCha20-Poly1305 AEAD (RFC 8439) + TLS_CHACHA20_POLY1305_SHA256

## [0.0.3](https://github.com/KarpelesLab/purecrypto/compare/v0.0.2...v0.0.3) - 2026-05-25

### Added

- *(cli)* add s_client TLS 1.3 test client
- *(cli)* add req and x509 tools (CSR + RSA/ECDSA CA management)
- *(cli)* add purecrypto binary with hash, rand, genpkey, pkey
- *(ffi)* add C ABI (hashing, HMAC, RNG, RSA/ECDSA, X.509)
- *(x509,ec,tls)* general (RSA+ECDSA) issuance, PKCS#10 CSR, EC key PEM, TLS accessors
- *(hash)* add TurboSHAKE and KangarooTwelve (12-round Keccak XOFs)
- *(hash)* add TupleHash and ParallelHash (SP 800-185)
- *(hash)* zeroize key/state material on drop for keyed types
- *(hash)* add unified Mac trait + constant-time verify for KMAC and BLAKE2 MACs
- *(hash)* add BLAKE3 (hash, keyed, derive-key; Digest + XOF)
- *(hash)* add keyed BLAKE2 (MAC) and BLAKE2X (XOF)
- *(hash)* add cSHAKE, KMAC128/256 and KMAC-XOF (SP 800-185)
- *(hash)* add SM3 (GB/T 32905)
- *(hash)* add XOF trait, SHAKE128/256, and Keccak-256

### Other

- attach release binaries — CLI, C library (.a/.so), and header
- document the C ABI + CLI, add a C-ABI smoke-test CI job
- *(hash)* document the completed hash module and mark it done

## [0.0.2](https://github.com/KarpelesLab/purecrypto/compare/v0.0.1...v0.0.2) - 2026-05-25

### Added

- *(hash)* add MD4, MD5, SHA-1, RIPEMD-160, SHA-3, and BLAKE2
- *(ec,tls)* verify real-world P-384 ECDSA chains; HTTPS GET example
- *(x509,tls)* wire multi-curve ECDSA into AnyPublicKey and TLS
- *(ec)* add runtime multi-curve ECDSA/ECDH (BoxedUint), keep fast P-256
- *(tls)* tolerate post-handshake messages on the client
- *(tls)* verify certificate validity period and host name
- *(rsa)* add BoxedRsaPrivateKey PKCS#1 DER/PEM loaders + TLS example
- *(tls)* add in-process loopback and blocking TCP Stream adapter
- *(tls)* add the TLS 1.3 server handshake state machine
- *(tls)* add sans-I/O connection core and TLS 1.3 client handshake
- *(tls)* add TLS 1.3 handshake signatures and certificate-chain verification
- *(tls)* add TLS 1.3 record protection (AEAD)
- *(tls)* add TLS 1.3 transcript hash and key schedule
- *(tls)* add TLS 1.3 wire codec, version and error scaffolding
- *(x509,ec)* DER ECDSA sigs, PKIX SPKI, EC certificate support
- *(rsa)* runtime-sized RSA keys (BoxedRsaPublicKey/PrivateKey)
- *(bignum)* runtime-sized BoxedUint + Montgomery modexp
- *(rsa)* RSA-PSS sign/verify; use RSA-2048 throughout
- *(ec)* X25519 Diffie-Hellman (RFC 7748)
- *(ec)* P-256 ECDH key agreement
- *(kdf)* HKDF (RFC 5869)

### Other

- *(tls)* remove the temporary dead_code allow and wire up loose ends

## [0.0.1](https://github.com/KarpelesLab/purecrypto/compare/v0.0.0...v0.0.1) - 2026-05-25

### Added

- *(x509)* self-signed/CA certificate issuance, parsing, verification
- *(der)* OID, BOOLEAN, string and time types for X.509
- *(rsa)* PKCS#1 DER and PEM key serialization
- *(der)* base64 and PEM encoding
- *(der)* minimal ASN.1 DER reader and writer
- *(rsa)* PKCS#1 v1.5 encryption and signatures
- *(rsa)* key types and key generation
- *(rsa)* Miller-Rabin primality and random prime generation
- *(bignum)* general modular inverse via binary extended GCD
- *(rng)* add RNG layer — RngCore, OsRng, HMAC-DRBG
- *(bignum)* constant-time modexp and Fermat modular inverse

### Fixed

- *(bignum)* general modular inverse (extended Euclid) + Uint::divrem

### Other

- Create FUNDING.yml
- use actions/checkout@v6
- add README badges; ci: bump checkout to v5
