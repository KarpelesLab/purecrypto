//! Fuzz `decode_compressed_certificate` — the body parser for an
//! RFC 8879 `CompressedCertificate` handshake message. Drives the
//! framing decoder (algorithm + uncompressed_length + compressed
//! body), the algorithm allowlist, the zlib bomb cap
//! (`MAX_UNCOMPRESSED_BYTES`), and the in-house zlib decoder via the
//! `compcol` dependency. Decompressed bytes are discarded — this
//! target's job is to keep the decoder from panicking, looping
//! forever, or over-allocating.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::tls::cert_compression::decode_compressed_certificate;

fuzz_target!(|data: &[u8]| {
    let _ = decode_compressed_certificate(data);
});
