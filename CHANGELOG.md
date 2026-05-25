# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
