# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

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
