# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.26](https://github.com/KarpelesLab/purecrypto/compare/v0.6.25...v0.6.26) - 2026-06-27

### Other

- add Streebog, Whirlpool, MarsupilamiFourteen and MD2
- peek_initial_sni — handle coalesced Initial packets

## [0.6.25](https://github.com/KarpelesLab/purecrypto/compare/v0.6.24...v0.6.25) - 2026-06-25

### Other

- *(cli)* de-flake q_client_q_server_roundtrip on slow CI hosts
- add peek_initial_sni — pre-handshake SNI/ALPN for HTTP/3 cert selection
- client-side TLS 1.2/1.3 version negotiation (hybrid ClientHello + downgrade)

## [0.6.24](https://github.com/KarpelesLab/purecrypto/compare/v0.6.23...v0.6.24) - 2026-06-25

### Other

- lazy single-engine server front-end (build one engine, not both)
- negotiate TLS 1.2 or 1.3 from the ClientHello on a spanning server
- group hex literal to satisfy clippy::unusual_byte_groupings
- reject duplicate CertificateRequest in TLS 1.3 client
- *(tls)* flag verify_certificates(false) as MITM-open in docs
- zeroize XOF reader buffers on drop
- *(kdf/argon2)* note m_cost/t_cost are unbounded for untrusted input
- *(kdf/scrypt)* correct enforced-bound description, note p is unbounded
- reject empty salt and password
- correct overstated constant-time docs for the FPEMU
- validate imported secret keys against the NTRU equation
- reject trailing whole zero bytes in unpadded signatures
- add defense-in-depth debug_asserts
- reject trailing junk in EdDSA/X25519/X448 PKCS#8 parsers
- enforce cRLSign keyUsage on CRL signers (RFC 5280 §6.3.3)
- *(readme)* PQC PKCS#8 now fully interoperable with OpenSSL 3.5
- emit LAMPS CHOICE PKCS#8 private keys (OpenSSL 3.5 interop)
- *(readme)* drop ✅ badges from the capability table

## [0.6.23](https://github.com/KarpelesLab/purecrypto/compare/v0.6.22...v0.6.23) - 2026-06-25

### Other

- *(readme)* drop dated "Status: mostly stable" blockquote
- add non-consuming peek_client_hello for per-connection cert selection

## [0.6.22](https://github.com/KarpelesLab/purecrypto/compare/v0.6.21...v0.6.22) - 2026-06-25

### Other

- fix a broken intra-doc link in next_timeout's docs
- self_signed_with_sans accepts any signing key, not just RSA
- read & set IP ECN on the QUIC sockets (Linux)
- implement ECN — counting, ACK echo, CE reaction, validation
- wire ech_outer_extensions compression into the handshake
- drive q_server through the QuicServer router
- add a QuicServer connection router with stateless-reset emission
- derive stateless-reset tokens from a static key (RFC 9000 §10.3.1)
- send a RawPublicKey client certificate for mTLS (RFC 7250 §4.4)
- implement the RFC 9000 §10.1 idle timeout
- expose exporter, 0-RTT send, and resumption on the public Connection
- fix stale claims found in the documentation audit
- *(quic)* correct stale "Phase 4" capability claims in connection.rs
- let Miri run the getrandom path via the /dev/urandom fallback

## [0.6.21](https://github.com/KarpelesLab/purecrypto/compare/v0.6.20...v0.6.21) - 2026-06-24

### Other

- record OpenSSL DTLS/QUIC server interop and shipped ML-KEM ACVP corpus
- fix ServerHello interop with OpenSSL (legacy_version + renegotiation_info)
- *(mlkem)* add genuine NIST ACVP ML-KEM known-answer tests
- lead with the modular / feature-gated positioning in the README
- drop DRAFT notes from threat-model and recommended-usage
- add validation matrix, recommended-usage, threat model, benchmarks + SECURITY.md
- fix stated MSRV in README (1.88, not 1.95)

## [0.6.20](https://github.com/KarpelesLab/purecrypto/compare/v0.6.19...v0.6.20) - 2026-06-24

### Added

- *(key)* parse ML-KEM from PKCS#8/SPKI + unified outer AnyKey enum
- *(key)* parse X25519/X448 from PKCS#8 + SPKI (AnyPrivateKey/AnyPublicKey)

### Fixed

- *(x509)* gate the anykey module on `key`, not just `mlkem`

### Other

- list the `key` module in the README + fix its feature comment

## [0.6.19](https://github.com/KarpelesLab/purecrypto/compare/v0.6.18...v0.6.19) - 2026-06-24

### Added

- *(ec)* add X25519PrivateKey/X448PrivateKey::to_bytes
- *(key)* impl PrivateKey/PublicKey for AnyPrivateKey/AnyPublicKey
- *(key)* surface AnyPrivateKey/AnyPublicKey from key + into_dyn() bridges
- *(cli)* route pkeyutl sign/verify through the unified key traits
- *(key)* generic from_pkcs8/from_spki decoders + ECDSA/SM2 DER encoding option
- *(key)* unified asymmetric-key traits (PrivateKey/PublicKey + capabilities)

### Other

- *(tls)* deprecate the PrivateKey alias since 0.6.19, not 0.7.0
- *(key)* tighten the facade — drop capability traits, de-scope KEM/stateful, self-validating params

## [0.6.18](https://github.com/KarpelesLab/purecrypto/compare/v0.6.17...v0.6.18) - 2026-06-22

### Other

- export the fallible try_hkdf_expand / HkdfError publicly
- wipe interactive passphrase buffer; warn on weak work factors
- document non-thread-safety of stateful OTS signers
- clamp peer active_connection_id_limit to a sane ceiling
- clamp ack_delay to peer max_ack_delay in update_rtt
- reject send-half frames on peer-initiated uni streams before lazy creation
- make unpack_signed total with internal bounds check (audit Low #1)
- assert wots_msg_csum accumulator bound (audit Low #3)
- remove expand panic-on-mismatch; document X25519 validation gap (audit Low #2)
- add fallible try_hkdf_expand variant (audit Low #4)
- guard scalar_mul against over-wide scalars (Low, latent)
- fail loud on non-coprime qInv in to_pkcs1_der (Low)
- parse INTEGER length via DER reader, not a fixed offset
- decode DN attribute values per their ASN.1 string tag
- bound PBMAC1 keyLength before pre-auth PBKDF2/allocation
- fail closed on critical crlExtensions and entry extensions
- close hostname-skip, HRR-group, and session_id parity gaps
- reject SKE group not in offered supported_groups
- tls 1.2 server: enforce validated client cert when mTLS is required
- tls 1.2/1.3: scrub transient premaster, key_block and shared secrets
- key 0-RTT anti-replay window on the selected PSK binder
- larger default GREASE payload; bounds-safe outer-ext decode
- remap surviving parent indices in inhibited-mapping prune
- exclude self-issued from pathLen, chain EKU to intermediates
- surface truncation on EOF without close_notify; zeroize plaintext

## [0.6.17](https://github.com/KarpelesLab/purecrypto/compare/v0.6.16...v0.6.17) - 2026-06-22

### Other

- optional tokio + mio I/O surfaces over the sans-I/O engine
- require caller-provided entropy; the sans-I/O engine no longer defaults to OsRng
- expose Readiness via std AsFd/AsRawFd for clean async integration
- transparent pluggable private keys (PrivateKey trait + Connection::drive)
- tls_external_signing — TPM/HSM suspend/resume driver loop
- two-phase prepare/finish signing for offline (TPM/HSM) CA keys
- external ServerKeyExchange signing (suspend/resume)
- external CertificateVerify signing — DTLS 1.3 server
- external CertificateVerify signing — TLS 1.3 client mTLS
- external (suspend/resume) CertificateVerify signing — TLS 1.3 server

## [0.6.16](https://github.com/KarpelesLab/purecrypto/compare/v0.6.15...v0.6.16) - 2026-06-22

### Other

- injectable entropy source (Config::rng / EntropySource)
- narrow the state-machine modules' blanket allow to unreachable_pub
- narrow the server modules' blanket allow to unreachable_pub
- share the CT PKCS#1 v1.5 padding check and the rsaEncryption OID
- add SuiteParams::crypter to collapse RecordCrypter::new sites
- share limb helpers between boxed and boxed_montgomery
- share the windowed-CTR keystream loop between GCM and GCM-SIV
- dedup shared helpers (wipe, ALPN/cert/keylog loaders)
- share one big-endian hex decoder across the curve field modules
- funnel ServerConfig constructors through one from_key
- share the AVX2 8x8 transpose between SHA-256-MB and BLAKE3
- use public-exponent ladder for the public operation
- reuse keyed HMAC across iterations; reuse scrypt BlockMix scratch
- clear stale dead-code allows; scope the staged ones
- consolidate dead-code allows; drop vestigial helpers
- drop blanket dead-code allows; gate test-only helpers
- remove stale dead-code suppressions and dead bookkeeping

## [0.6.15](https://github.com/KarpelesLab/purecrypto/compare/v0.6.14...v0.6.15) - 2026-06-22

### Other

- fail closed on 0-RTT with no active anti-replay defense
- assert tree/leaf index lengths fit u64 in split_digest
- constant-time PKCS#7 padding strip; clarify MIN_ITERATIONS
- don't fatally close on STOP_SENDING/MAX_STREAM_DATA for an
- zeroize const-generic ECDSA/ECDH private keys on drop
- guard >=128 shifts in rint/floor/trunc (panic-DoS hardening)
- public keygen/sign API + compact key serialization (Phase 5)
- signing — ffSampling preimage + compression (Phase 4)
- key generation — NTRUGen/NTRUSolve/Reduce + public key (Phase 3)
- LDL tree (ffLDL) + fast-Fourier sampling (ffSampling) (Phase 2)
- FFT over emulated double + constant-time Gaussian sampler (Phase 1)
- emulated constant-time IEEE-754 double (Phase 0 of keygen+sign)
- wire Brainpool curves into pc_ec_sign/verify (integration fixup)
- add RFC 7292 PFX parse + build with OpenSSL interop
- add FN-DSA (FIPS 206) signature verification (verify-only)
- add RFC 5280 §6.1 policy-tree processing and RFC 6962 SCT/CT verification
- add Brainpool curves (RFC 5639) with ECDSA support
- add constant-time Camellia (RFC 3713) and ARIA (RFC 5794)

## [0.6.14](https://github.com/KarpelesLab/purecrypto/compare/v0.6.13...v0.6.14) - 2026-06-19

### Other

- lower to Rust 1.88 and add a CI job that enforces it

## [0.6.13](https://github.com/KarpelesLab/purecrypto/compare/v0.6.12...v0.6.13) - 2026-06-16

### Other

- fix Duration-overflow panic in out_of_order loss test (CI flake)
- strict-DER finish() on RSA SPKI + ct PATH_RESPONSE compare
- server SHOULD try all configs sharing a config_id before reject
- reject out-of-range AES-CCM nonce with clean die() instead of panic
- add differential test guarding aggregated-reduction GHASH
- scrub secret modexp Vec<Limb> scratch on drop

## [0.6.12](https://github.com/KarpelesLab/purecrypto/compare/v0.6.11...v0.6.12) - 2026-06-15

### Other

- widen stateful-sign lock budget 3s -> 30s (fix CI flake)
- fix aarch64 aggregated-GHASH block byte order
- 4-bit windowed constant-time modexp (~1.55x RSA-2048 sign)
- aggregated-reduction GHASH (~2.8x on AES-GCM)
- AVX2 8-way keystream (~2.2x on ChaCha20-Poly1305)
- 8-way multi-buffer PRF_keygen for expand_seed
- batch WOTS+ F-chains through 8-way SHA-256 kernel (SHA-2 n=16)
- batch LM-OTS public_key Winternitz chains through AVX2 multi-buffer SHA-256
- multi-buffer AVX2 SHA-256, batched into XMSS WOTS+
- AVX2 8-way SIMD chunk backend (~2.5x on bulk)
- register-resident multi-block SHA-NI / sha2 compression
- reject PSK binders that are not 32 or 48 bytes at parse
- add configurable salt-length sign/verify (strict default)
- enforce canonical DER INTEGER encoding on key import
- reject STOP_SENDING on receive-only stream as STREAM_STATE_ERROR
- park connection in Closed state on received fatal alert

## [0.6.11](https://github.com/KarpelesLab/purecrypto/compare/v0.6.10...v0.6.11) - 2026-06-11

### Fixed

- *(ct)* normalize Choice::from with branchless != 0 instead of & 1
- *(cmac)* make inherent Cmac::verify length-strict (reject truncated/empty tags)

### Other

- scrub per-call AEAD/key-wrap/MAC key copies on drop
- collapse nested if-let to satisfy clippy collapsible_if
- normalize rustfmt formatting on CLI -len cap paths
- enforce strict no-trailing-bytes finish() on ResponseData and SingleResponse
- route typed verify_signature through algid-consistency check
- reject trailing bytes after the iPAddress SAN SEQUENCE
- cap caller-controlled output lengths and reject empty AEAD nonce
- warn on world-readable private-key reads in pkey and pkeyutl
- scrub leftover secret-key and cookie/retry-secret stack copies
- reject NULL output before burning a stateful LMS/XMSS one-time key
- cap caller counts before reserving and validate ALPN entries
- wipe decrypted QUIC stream plaintext in pc_quic_stream_read
- zeroize seed copies in LmsPrivateKey/HssPrivateKey generate
- zeroize the random message m in encapsulate
- fix XMSS^MT h=40 leaf-index wrap to 0 at exhaustion (OTS reuse)
- reject app data after EndOfEarlyData but before client Finished
- cap EncryptedExtensions extension count to keep dup scan linear
- cap TLS 1.2 / legacy handshake reassembly buffer
- drop conflicting overlapping fragments, not genuine bytes
- silently drop spoofable plaintext handshake records mid-handshake
- fix L-3 conn flow-control leak for bytes discarded after STOP_SENDING
- fix L-2 retire_prior_to retiring the in-use outbound DCID
- fix L-1 unbounded ACK-range tracking (quadratic insert DoS)
- fix H-1 self-initiated key update desync + replay-window reset
- declare the API mostly stable and sync drifted sections

## [0.6.10](https://github.com/KarpelesLab/purecrypto/compare/v0.6.9...v0.6.10) - 2026-06-10

### Other

- wipe the minted QUIC retry secret stack copy
- zeroize TLS 1.3 key-schedule secrets on drop
- never leak the inner SNI on a non-confirming HelloRetryRequest
- real cookie max-age when the caller never drives the clock
- surface authenticated DTLS 1.3 alerts instead of discarding them
- release handshake flights on peer response so connections outlive GiveUp
- only acknowledge handshake records, never ACK-of-ACK (RFC 9147 §7)
- accept PKCS#8 RSA keys in pc_quic_cfg_set_certificate
- wire real negotiated ALPN and peer certificate through pc_quic
- restrict application CONNECTION_CLOSE (0x1d) to 0-RTT/1-RTT levels
- reject zero-length NEW_CONNECTION_ID CIDs and stream counts above 2^60
- warn when kdf reads a passphrase from an interactive terminal
- wipe private-key serialization temporaries and retained secrets
- fsync the parent directory after the stateful-key rename
- document the no-validation contract of the infallible constructors
- validate RSASSA-PSS params and stop OID-sharing on PSS-RSAE entries
- harden DN, time, nameConstraints, and OCSP responder parsing
- wipe transient secrets in sign, keygen, pk-derivation and seed gen
- wipe transient secrets in encaps, keygen, noise PRF and seed gen
- cap from_bytes root recompute to deny untrusted-blob CPU-DoS
- make GCM nonce cap compile on 16/32-bit targets; CI builds thumbv7em

## [0.6.9](https://github.com/KarpelesLab/purecrypto/compare/v0.6.8...v0.6.9) - 2026-06-10

### Other

- store root(s) in private-key serialization to avoid O(2^h) load
- harden pkeyutl pkcs1 decrypt oracle hygiene and warn on legacy modes
- zeroize the TLS 1.2 master secret in every long-lived holder
- fail closed when a cipher_suites restriction matches no supported suite
- fail closed on retry tokens when no clock is configured
- cover OCSP, QUIC-client, LMS/XMSS, and legacy-TLS attacker surfaces
- enforce nameConstraints declared on trust anchors
- make SM4 constant-time via an algebraic table-free S-box
- move PskTooShort to the enum tail to keep variant discriminants stable
- document BEAST exposure of TLS 1.0 CBC chained IVs
- cap extensions per handshake message to bound duplicate scan
- derive SH accept_confirmation per RFC 9849 §7.2 (extract from inner CH random)
- stop silently ignoring Config::require_extended_master_secret
- validate HelloRetryRequest legacy_session_id_echo
- enforce the RFC 8446 §8.2 ticket-age freshness window on 0-RTT
- reject 0-RTT when the negotiated ALPN differs from the ticket's session
- prune acked CRYPTO ranges from the crypto_buf sent-history
- reject CRYPTO frames whose offset + length exceeds 2^62-1
- stop rewriting peer_addr from arbitrary inbound datagrams
- enforce mandatory ALPN (RFC 9001 §8.1) at connection construction
- discard retained previous-phase rx keys after 3xPTO
- old-phase packets opened with retained keys no longer drive key-update commits
- document the amplification risk of disabling the cookie exchange
- cap pre-cookie reassembly at 32 KiB and one in-flight message
- silently drop spoofable epoch-0 handshake faults instead of erroring
- bind OCSP times to GeneralizedTime form; finish() extension readers
- fix temp-dir/key-perm hygiene and fixed-seed/fixed-path patterns
- write kdf hex output and pkeyutl-decrypt plaintext as private files
- stop short-circuiting zero/equality tests on secret EC scalars
- range-check levels in the free verify_hss function
- zeroize the implicit-rejection secret k_bar in decapsulation
- wipe ECDH/X25519/X448 shared secrets before they leave scope
- scrypt enforces its documented 32-bit block-counter bounds
- enforce RFC 9180 §9.5 32-byte PSK minimum in PSK / AuthPSK modes
- argon2 rejects salts shorter than RFC 9106's 8-byte minimum
- enforce SP 800-90A HMAC-DRBG bounds (per-request cap, entropy input)
- kdf, hpke: wipe secret intermediates left in freed memory
- cap attacker-controlled PBES2 iteration count at 10M on decrypt
- pbes2 accepts DER INTEGERs whose minimal form carries a 0x00 pad

## [0.6.8](https://github.com/KarpelesLab/purecrypto/compare/v0.6.7...v0.6.8) - 2026-06-10

### Other

- expose peer_certificates(), alpn_protocol(), negotiated_cipher_suite()
- expose received_close_notify() so callers can detect truncation
- wipe recovered plaintext / unwrapped keys in cipher decrypt paths
- pc_mldsa_verify enforces the caller-pinned parameter set
- check sign-buffer capacity before consuming a stateful one-time key
- make pc_tls_pop/recv and pc_quic_pop/recv_datagram non-destructive on BufferTooSmall
- converge argv/file secret hygiene on the enc conventions
- write unwrapped/derived key material with private file mode
- checked validity_days arithmetic (-days overflow)
- lock stateful pkeyutl sign against concurrent OTS index reuse
- RESET_STREAM charges connection flow control for final size
- anchor flow-control credit on consumption, not receipt
- enforce zero reserved header bits post-AEAD (RFC 9000 §17)
- reject duplicate transport parameters (RFC 9000 §7.4.1)
- cap ACK range-count preallocation by wire-length bound
- silently discard invalid records instead of failing the connection
- stop overclaiming a matched-pair ECDSA whitelist for X.509 chains
- bind Time body format to its ASN.1 tag when reading (RFC 5280 §4.1.2.5)
- evaluate subject CN against name constraints when leaf has no dNSName SAN
- enforce RFC 5246 7.4.7.1 premaster client_version rollback check
- fix Lucky13 equalizer off-by-one compression count
- pin the HelloRetryRequest cipher suite across to the ServerHello
- authenticate the server before surfacing retry_configs
- quarantine accepted 0-RTT early data away from 1-RTT plaintext
- wipe transient secrets before return in keygen/sign/decaps
- guard argon2 memory-matrix size with checked_mul
- validate keys parsed from SPKI/PKCS#8; fix FIPS 203 §7.2 modulus check
- Miller-Rabin safe-prime validation in DhGroup::from_custom
- reject non-canonical ristretto255 encodings (s >= p)
- remove secret-dependent memory access in implicit-rejection decrypt
- CMAC/GMAC — set Mac::OUTPUT_LEN so trait verify rejects truncated tags
- Mac::verify — reject empty expected tag for variable-output MACs
- fix HSS upper-level LM-OTS randomizer reuse (one-time-key reuse)
- recoverable ECDSA — sign_recoverable + public-key recovery (ecrecover)

## [0.6.7](https://github.com/KarpelesLab/purecrypto/compare/v0.6.6...v0.6.7) - 2026-06-08

### Other

- secp256k1 group arithmetic — compressed lift_x, point add, x-only tweak
- ECDSA sign_prehash / verify_prehash (sign an external digest)
- bump actions/cache v4 -> v5 (Node 24; clears deprecation warning)
- SSL 3.0 OpenSSL interop fixes + CI workflow

## [0.6.6](https://github.com/KarpelesLab/purecrypto/compare/v0.6.5...v0.6.6) - 2026-06-08

### Other

- fix TLS 1.0/1.1 interop bugs found against OpenSSL

## [0.6.5](https://github.com/KarpelesLab/purecrypto/compare/v0.6.4...v0.6.5) - 2026-06-08

### Other

- client-certificate mutual auth on the TLS 1.0/1.1 path

## [0.6.4](https://github.com/KarpelesLab/purecrypto/compare/v0.6.3...v0.6.4) - 2026-06-08

### Other

- generic PKCS#8 loader AnyPrivateKey (self-describing key type)
- client cipher-suite selection via Config::cipher_suites ([#23](https://github.com/KarpelesLab/purecrypto/pull/23))
- Certificate::spki_der() exposes the raw SubjectPublicKeyInfo ([#25](https://github.com/KarpelesLab/purecrypto/pull/25))
- PKCS#8 (incl. encrypted) loaders for BoxedEcdsaPrivateKey ([#24](https://github.com/KarpelesLab/purecrypto/pull/24))
- Lucky13 block-count equaliser for the CBC decrypt MAC
- document the tls-legacy feature (SSLv3/TLS1.0/1.1 interop)
- SSL 3.0 crypto profile + handshake (POODLE-caveated)
- BEAST 1/n-1 record split on the TLS 1.0 send path
- stop tracking .claude/ session state (committed in error)
- wire the TLS 1.0/1.1 handshake (client + server)
- static-RSA ClientKeyExchange codec
- version-branched ServerKeyExchange codec (no SigAndHashAlg)
- RecordProtection dispatch enum + negotiated_version threading
- CBC record crypter owns its explicit-IV CSPRNG
- legacy CBC cipher suites + key_block layout (phase 3)
- CBC MAC-then-encrypt record layer (phase 2 of legacy SSLv3/TLS1.0/1.1)
- require client server_name only when verifying certificates
- legacy PRF + raw PKCS#1v1.5 RSA sign (phase 1 of SSLv3/TLS1.0/1.1 interop)
- aarch64 SHA-256 (sha2) and SHA-512 (sha512) hardware
- aarch64 PMULL GHASH
- batch standalone CTR and GCM-SIV keystreams via encrypt_blocks
- hardware backend for the bare AES round (AEGIS/AEZ)
- add AEZ v5 (robust authenticated-encryption by enciphering)
- fix ARMv8 AES decryption (equivalent inverse cipher keys)
- size the public-exponent modexp to e, not the modulus (verify ~108x)
- hardware SHA-256 via x86_64 SHA-NI
- hardware-accelerated AES-GCM (AES-NI + ARMv8-AES + PCLMULQDQ GHASH)

## [0.6.3](https://github.com/KarpelesLab/purecrypto/compare/v0.6.2...v0.6.3) - 2026-06-06

### Other

- drop Copy from OcspCheckOptions to keep it growable
- pass OCSP check knobs via an OcspCheckOptions object
- fix rustdoc private-intra-doc-link warning in from_pkcs1_der
- use create_new for atomic key-overwrite temp file (LOW, defense in depth)
- cap per-epoch send records to prevent AEAD nonce reuse
- validate ServerHello session_id echo + pin post-HRR key_share group [LOW]
- harden expand_label PRK copy against length mismatch [LOW]
- reject keyUsage BIT STRING with non-zero unused trailing bits [LOW]
- reject non-minimal long-form length encoding [LOW]
- gate OCSP staple signatures by SignaturePolicy [MEDIUM]
- zeroize context key material and secret PRK (audit LOW)
- zeroize SharedSecret on drop (audit LOW)
- zeroize password-derived working buffers [LOW]
- make default verify length-strict for fixed-output MACs [LOW]
- validate keyed-MAC key length [MEDIUM]
- validate persisted signing keys in from_bytes (audit MEDIUM)
- bound inbound DATAGRAM queue, enforce DATAGRAM/Initial/TP rules
- admit stream before charging conn flow control [LOW]
- reject even/zero modulus and undersized const-generic keys on import [HIGH/LOW]
- enforce FIPS 186-5 |p-q| minimum distance in keygen [LOW]
- Remove the fullrust freestanding-target build path
- Depend on published fullrust crates instead of relative paths
- anchor at the first trusted CA in the chain, not only the top
- Build the CLI as a libc-free static binary on the fullrust target

## [0.6.2](https://github.com/KarpelesLab/purecrypto/compare/v0.6.1...v0.6.2) - 2026-06-05

### Other

- add EcdhPrivateKey::from_bytes for static ECDH scalars
- document the nonce/payload-length panics on encrypt/decrypt
- embedded root-CA trust store via the cacrt crate

## [0.6.1](https://github.com/KarpelesLab/purecrypto/compare/v0.6.0...v0.6.1) - 2026-06-03

### Other

- define EC public-key OID locally so SPKI builds without x509

## [0.6.0](https://github.com/KarpelesLab/purecrypto/compare/v0.5.1...v0.6.0) - 2026-06-03

### Added

- enable ascon/lms/xmss by default

### Fixed

- fix CI: rustfmt build_subtree signature + sm2 rustdoc link errors

### Other

- retry serial lock on Windows delete-pending PermissionDenied
- fix rustdoc intra-doc links broken by security-audit fixes
- document no-policy verify on AnyPublicKey/CSR entry points (Finding 4)
- hash full Name TLV + reject CA delegated responder (Findings 2, 3)
- enforce inner/outer signatureAlgorithm consistency in verify (Finding 1)
- validate GCM/CCM nonce length for AEAD parity
- zeroize recovered plaintext in pc_sm2_decrypt
- enforce RFC 8452 §6 input-length caps
- guard AES-KWP unwrap against <16-byte ciphertext
- silently drop per-packet AEAD failures (RFC 9000 §12.2)
- stash digest of over-long HMAC key instead of asserting
- zeroize secret k and v on drop
- reject over-long Export + poison context after message limit
- checked_mul the V-buffer size to avoid 32-bit overflow DoS
- verify leaf hostname against server_name (auth bypass)
- fail closed on multi-level HSS to stop LM-OTS key reuse
- manual rotate to avoid non-inlined intrinsic in debug
- cache built subtrees + PRF midstate so signing is O(h)
- mark AnyPublicKey/CertSigner/CurveId/SigningKey non_exhaustive
- document AEGIS/GMAC/SM4/Ascon/KBKDF/SM2/LMS/XMSS
- declare new pc_* + CLI round-trip tests
- wire SM2 and stateful LMS/XMSS signatures
- wire SP 800-108 KBKDF + Ascon hashes/XOFs
- wire AEGIS-128L/256, Ascon-AEAD128, and GMAC
- reject SM2 curve keys in generic ECDSA sign/verify
- add XMSS/XMSS^MT stateful hash-based signatures (RFC 8391)
- add LMS/HSS stateful hash-based signatures (RFC 8554)
- add Ascon-AEAD128 + Ascon-Hash256/XOF128/CXOF128 (NIST SP 800-232)
- add SM2 curve + signature + encryption (GB/T 32918, RFC 8998)
- add SP 800-108 KBKDF (counter + feedback, HMAC/CMAC PRF)
- add SM4 (GB/T 32907 / RFC 8998)
- add GMAC (NIST SP 800-38D)
- add AEGIS-128L/256 (draft-irtf-cfrg-aegis-aead)
- add ascon/lms/xmss feature gates + placeholder modules
- gate AES-SIV behind alloc and CMAC Mac impl behind hash
- document AES-CMAC/SIV/GCM-SIV/XChaCha20-Poly1305 and X448/Ed448
- add Ed448 (SignatureScheme 0x0808) certificate auth
- expose Ed448/X448
- register Ed448/X448 (OID, SPKI, signature registry)
- add curve448 backend + Ed448 (RFC 8032)
- add X448 Diffie-Hellman (RFC 7748)
- wire new AEADs into C ABI and enc verb
- add XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03)
- add AES-GCM-SIV (RFC 8452)
- add AES-SIV (RFC 5297)
- add AES-CMAC (RFC 4493)

### Added

- *(cipher)* AES-CMAC (RFC 4493) — generic over the block cipher, also exposed as a `Mac`
- *(cipher)* AES-SIV (RFC 5297) and AES-GCM-SIV (RFC 8452) nonce-misuse-resistant AEADs
- *(cipher)* XChaCha20-Poly1305 (extended 24-byte nonce, draft-irtf-cfrg-xchacha-03)
- *(ec)* X448 key agreement (RFC 7748) and Ed448 signatures (RFC 8032), with PKCS#8 DER/PEM
- *(x509,ec)* Ed448 SPKI parsing, signature-registry + cert-chain verify, self-signed/CA issuance (id-Ed448 1.3.101.113)
- *(tls)* Ed448 certificate authentication (TLS 1.3 SignatureScheme ed448 = 0x0808)
- *(ffi,cli)* expose the new AEADs (`enc`, `pc_aead_*`), AES-CMAC (`mac -alg cmac`, `pc_cmac`), Ed448 (`genpkey -alg ED448`, `pkeyutl`, `pc_ed448_*`) and X448 (`kex -alg X448`, `pc_x448`)
- *(cipher)* AEGIS-128L / AEGIS-256 (draft-irtf-cfrg-aegis-aead) and SM4 block cipher (GB/T 32907 / RFC 8998)
- *(cipher)* GMAC (NIST SP 800-38D)
- *(ascon)* Ascon (NIST SP 800-232): Ascon-AEAD128 + Ascon-Hash256 / Ascon-XOF128 / Ascon-CXOF128 — on by default
- *(kdf)* SP 800-108 KBKDF in counter and feedback modes, with HMAC and AES-CMAC PRFs
- *(ec)* SM2 signature (SM2DSA over SM3) + public-key encryption (GB/T 32918 / RFC 8998); sm2p256v1 curve, SPKI/cert-chain verify (id-sm2 1.2.156.10197.1.301, sm2sign-with-sm3 1.2.156.10197.1.501)
- *(lms)* LMS / HSS stateful hash-based signatures (RFC 8554, NIST SP 800-208) — on by default
- *(xmss)* XMSS / XMSS^MT stateful hash-based signatures (RFC 8391, NIST SP 800-208) — on by default
- *(ffi,cli)* expose AEGIS / Ascon-AEAD / SM4 (`enc`), GMAC (`mac -alg gmac`, `pc_gmac`), KBKDF (`kdf kbkdf`, `pc_kbkdf_*`), Ascon hashes (`hash`, `pc_ascon_xof/cxof`), SM2 (`genpkey -alg SM2`, `pkeyutl`, `pc_sm2_*`), and LMS/XMSS (`genpkey`, `pkeyutl` with persist-after-sign, `pc_lms_*`/`pc_xmss_*`)

## [0.5.1](https://github.com/KarpelesLab/purecrypto/compare/v0.5.0...v0.5.1) - 2026-06-01

### Other

- expose affine coordinates on EdwardsPoint
- guard from_seeds against short seeds with a clear panic
- forward Config.verification_time to server engines
- enable linux-getrandom by default
- warn when kdf passphrase is passed on argv (F7)
- reject ECH whose HPKE suite isn't in the published ECHConfig (F6)
- enforce delegated OCSP responder certificate validity period (F5)
- reject signature representative s>=n and strict PSS leading-octet check (F4)
- bound handshake message_seq to prevent pre-cookie DoS (F3)
- bound pending_retire and validate retire_prior_to (F2)
- enforce client certificate validity period in mTLS (F1)
- fix private-intra-doc-link errors in ec/mldsa module docs
- *(test)* update recv_pending_fragments_are_bounded for drop-on-overflow
- fix two bugs behind the flaky out-of-order stream test
- switch base field to the native Secp256k1Field backend
- add native pseudo-Mersenne field backend + differential tests
- *(release-plz)* use RELEASE_PLZ_TOKEN; restore workflow clobbered in 77e4b4a
- *(release-plz)* authenticate with RELEASE_PLZ_TOKEN PAT
- silence feature-gated lints exposed by hazmat-mldsa build combo
- *(curve25519)* fix feature-gated dead_code warnings on default build
- resolve merge conflict markers in mod.rs module declarations
- add ristretto255 (RFC 9496) stable prime-order group (Stage 6, Items 1+2)
- add edwards25519::hazmat low-level group/scalar API (Stage 5, Items 1+2)
- extract shared curve25519 backend from ed25519 (Stage 4, Items 1+2)
- *(secp256k1)* public scalar/point arithmetic + compressed SEC1 (Stage 2/3, Item 3)
- expose low-level primitives via mldsa::hazmat (Stage 1 / Item 5)
- *(design)* threshold/low-level primitives plan (hazmat, secp256k1 native, ristretto255)
- propagate nameConstraints to intermediates (RFC 5280 §6.1.4)
- explicit Drop wiping DhPrivateKey secret exponent
- wipe residual key-stream/subkey in cipher mode wrappers on drop
- *(client)* reject un-offered cipher suite / key-share group in ServerHello
- reject NUL/control chars in DistinguishedName attribute values
- reject NUL/control chars in nameConstraints dNSName subtrees
- harden ASN.1 time parsing and fail OCSP freshness closed on bad time
- regression tests for cookie fail-closed without secret
- fail closed when cookie exchange is required but no secret is set
- apply the emsa separator-index truncation fix to the scanners
- fix PKCS#1 v1.5 / OAEP separator-index truncation for keys > 2048-bit
- add regression test for ACK-range CPU-exhaustion DoS
- bound ACK-range processing — reject PNs never sent, iterate sparsely

## [0.5.0](https://github.com/KarpelesLab/purecrypto/compare/v0.4.0...v0.5.0) - 2026-05-30

### Other

- mark Config/Identity/ClientAuth/QuicConfig non_exhaustive
- *(mlkem)* qualify CryptoRng intra-doc link inside ml_kem_set! macro
- O_CLOEXEC on /dev/urandom + tighten CryptoRng bound on keygen
- zeroize BoxedEc/Ed25519 private keys; P-256 random_scalar rejection; BoxedEcdsa low-S
- wipe KMAC XOF / UMAC / BoxedRsa secrets on drop
- zeroize key handles on free; explicit length params for DTLS cookie + QUIC peer-addr
- reject zero divisor + guard truncating ops
- fix tree_idx_mask shift overflow + add KAT roundtrips
- validate from_bytes coefficients; branch-free inf_norm/vec_inf_norm/count_ones
- add -keyfile / -aadfile to avoid argv secret leak
- error on missing SNI; checked u16 length casts
- enforce role on HANDSHAKE_DONE and NEW_TOKEN (RFC 9000 §19.20/§19.7)
- *(kw)* constant-time KWP unwrap validation

### Security

- fix issues from parallel audit (DTLS/QUIC/TLS/RSA/X.509/FFI)

## [0.4.0](https://github.com/KarpelesLab/purecrypto/compare/v0.3.0...v0.4.0) - 2026-05-30

### Added

- *(cipher)* add DES, 3-DES (EDE3/EDE2) + Cbc64 for legacy interop
- *(tls,ech)* server-emitted HelloRetryRequest with ECH HRR confirmation

### Other

- *(readme)* bump example version pins to 0.3
- *(readme)* refresh module/feature table + Cargo.toml version pins

## [0.3.0](https://github.com/KarpelesLab/purecrypto/compare/v0.2.0...v0.3.0) - 2026-05-29

### Added

- *(tls,ech)* end-to-end ECH loopback example (wave 3b.5)
- *(tls,ech)* server EE retry_configs + client Error::EchRejected (wave 3b.4)
- *(tls,ech)* client SH accept-signal verification + transcript swap (wave 3b.3)
- *(tls,ech)* client real-ECH emission via seal_with (wave 3b.2)
- *(tls,ech)* server-side decap + accept-signal patching (wave 3b.1)
- *(tls)* RFC 8879 certificate compression (zlib via compcol)
- *(tls,ech)* HPKE seal pipeline for outer/inner ClientHello
- *(tls,ech)* ech_outer_extensions compressor and decompressor
- *(tls,ech)* ECH codec foundations + GREASE producer
- *(hpke)* RFC 9180 hybrid public key encryption
- *(tls)* RFC 7250 raw public keys for TLS 1.3
- *(tls,x509)* OCSP stapling (RFC 6066 + 6960)
- *(tls)* add P-384 ECDHE key exchange
- *(tls,dtls)* add RFC 5705 exporter for TLS 1.2 / DTLS 1.2 + DTLS 1.3
- *(mac)* add UMAC-64 and UMAC-128 (RFC 4418)
- *(dtls)* multi-sig signing for DTLS 1.2
- *(dtls)* multi-group ECDHE for DTLS 1.2
- *(dtls)* multi-suite negotiation for DTLS 1.2
- *(dtls)* clean up DTLS 1.3 signing path + add multi-sig coverage
- *(dtls)* multi-group key agreement for DTLS 1.3
- *(dtls)* multi-suite negotiation for DTLS 1.3
- *(x509)* enforce RFC 5280 nameConstraints across the chain
- *(tls,ffi)* expose peer SNI + cipher-suite accessors over the C ABI
- *(tls)* Connection::negotiated_cipher_suite[_name]
- *(rng)* use arc4random_buf on Apple targets
- *(rng)* linux-getrandom feature — getrandom(2) via raw syscall asm

### Fixed

- *(tls)* bound the handshake-message reassembly buffer
- *(x509,pki)* tighten nameConstraints IP mask + close SAN-less leaf bypass
- *(rsa)* validate p·q == n on PKCS#1 / PKCS#8 private-key import
- *(ffi)* accept PKCS#8-wrapped RSA private keys in pc_tls_cfg_set_certificate
- *(dh)* enforce MIN_CUSTOM_GROUP_BITS = 2048 in from_custom
- *(ffi,cli)* propagate PEM-trust-store parse failures
- *(rsa)* validate public exponent + harden PKCS#1 export
- *(rng)* scope arc4random_buf extern in a submodule
- *(crypto,pqc)* hygiene hardening — PBKDF2, BLAKE2 MAC, FIPS 203/204/205
- *(ffi,rng,cli)* FFI / RNG / CLI hygiene
- *(quic)* RFC 9000 §12.4 per-level frame restrictions + §13.2.5 ack_delay

### Other

- *(fuzz)* add ECH + cert-compression wire-parser targets
- *(tls,ech)* end-to-end Phase 5 cryptographic round-trip
- *(fuzz)* add cargo-fuzz workspace with 20 targets
- mark all public error enums #[non_exhaustive]
- *(docs)* add rustdoc-warnings-denied job + fix pre-existing links
- *(tls)* update module docs to reflect TLS 1.2/1.3 + DTLS + QUIC scope

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
