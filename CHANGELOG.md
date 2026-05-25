# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
