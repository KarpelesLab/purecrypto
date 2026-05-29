//! RFC 8879 — TLS Certificate Compression (TLS 1.3).
//!
//! Wire surface:
//!
//! - **`compress_certificate` extension** (IANA code point 27, `0x001b`):
//!   appears in the `ClientHello` (covering the server's `Certificate`) or
//!   in the server's `CertificateRequest` (covering the client's mTLS
//!   `Certificate`). Body: a `u8`-length list of `u16` algorithm IDs the
//!   sender can DECOMPRESS, in preference order. Unidirectional — the
//!   peer either picks one or does nothing, with no response extension.
//! - **`CompressedCertificate` handshake message** (type 25): replaces a
//!   regular `Certificate` on the wire when the sender chose to compress.
//!   Body: `algorithm u16 ‖ uncompressed_length u24 ‖
//!   compressed_certificate_message<u24>`. The decompressed bytes are
//!   processed exactly as a `Certificate` message body would be; the
//!   transcript hash is fed the COMPRESSED wire bytes (matching how
//!   BoringSSL / rustls drive it — RFC 8879 leaves the choice unstated
//!   but only this interpretation is reproducible by both peers).
//!
//! Algorithm IDs (`CertificateCompressionAlgorithm` registry, RFC 8879 §7):
//!
//! | id | name   | container |
//! |----|--------|-----------|
//! |  1 | zlib   | RFC 1950 zlib over RFC 1951 DEFLATE |
//! |  2 | brotli | RFC 7932                            |
//! |  3 | zstd   | RFC 8478                            |
//!
//! Only **zlib (1)** is implemented here; brotli/zstd remain unwired. The
//! zlib codec is the `compcol` crate, the sole vendored dependency of this
//! crate ([[compcol-allowed-for-deflate]] memory documents the carve-out).
//!
//! Size policy (RFC 8879 §5):
//!
//! > Implementations SHOULD bound the memory usage when decompressing and
//! > MUST limit the size of the resulting decompressed chain to the
//! > specified uncompressed length.
//!
//! We enforce both: a hard module-level cap [`MAX_UNCOMPRESSED_BYTES`] on
//! the `uncompressed_length` field itself (so a malicious header cannot
//! coerce a huge allocation up front), and a streaming-decode budget equal
//! to that declared length (so the actual decompression cannot exceed it
//! mid-stream). After decoding, the produced byte count is checked for an
//! exact match — RFC 8879 §4 ("if the result is not the same as the
//! declared uncompressed_length, abort with `bad_certificate`").

use crate::tls::Error;
use crate::tls::codec::hs_type;
use crate::tls::codec::{ReadCursor, put_u16, with_len_u8, with_len_u24};
use alloc::vec::Vec;

/// Hard cap on the `uncompressed_length` field of any received
/// `CompressedCertificate`. Real-world TLS certificate chains never come
/// close to this; rejecting earlier saves an allocation and is the
/// classic decompression-bomb defence per RFC 8879 §5. The TLS framing
/// itself caps `Certificate` at `2^24 - 1` bytes, so this is purely a
/// per-deployment policy knob we have chosen.
pub(crate) const MAX_UNCOMPRESSED_BYTES: u32 = 256 * 1024;

/// IANA `CertificateCompressionAlgorithm` codepoints (RFC 8879 §7).
pub(crate) mod algorithm {
    /// `zlib(1)` — RFC 1950 zlib container around RFC 1951 DEFLATE. The
    /// only algorithm wired in this crate.
    pub(crate) const ZLIB: u16 = 1;
    /// `brotli(2)` — RFC 7932. Not wired.
    #[allow(dead_code)]
    pub(crate) const BROTLI: u16 = 2;
    /// `zstd(3)` — RFC 8478. Not wired.
    #[allow(dead_code)]
    pub(crate) const ZSTD: u16 = 3;
}

/// Default `cert_compression_algorithms` advertisement: zlib only.
pub(crate) fn default_algorithms() -> Vec<u16> {
    alloc::vec![algorithm::ZLIB]
}

/// True when this build can encode/decode `algorithm`. Today: zlib only.
pub(crate) fn supports(algorithm: u16) -> bool {
    algorithm == algorithm::ZLIB
}

/// Pick the first algorithm that is in BOTH `offered` (the peer's
/// advertisement) and `local` (our own preference list), ordering by
/// the OFFERER's preference (RFC 8879 §3: "the value the sender lists
/// first is the preferred one"). Returns `None` when there is no
/// overlap. Used to negotiate `compress_certificate` once both sides
/// have announced their lists.
pub(crate) fn pick_from_lists(offered: &[u16], local: &[u16]) -> Option<u16> {
    offered
        .iter()
        .copied()
        .find(|a| supports(*a) && local.contains(a))
}

// -------- extension codec --------

/// Encode the `compress_certificate` extension body for advertising
/// `algorithms`. Wire shape: `u8` length, then that many `u16` IDs.
/// `algorithms` must be 1..=127 entries (so the list bytes fit a `u8`
/// length); we cap at 127 — anything beyond the supported set today is
/// dropped by the caller anyway.
pub(crate) fn encode_extension(algorithms: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + algorithms.len() * 2);
    let take = algorithms.len().min(127);
    with_len_u8(&mut out, |b| {
        for alg in &algorithms[..take] {
            put_u16(b, *alg);
        }
    });
    out
}

/// Decode the `compress_certificate` extension body. Returns the list of
/// algorithm IDs the peer can DECOMPRESS, in their preference order. Per
/// RFC 8879 §3 the inner list length is 2..=254 bytes (1..=127 IDs); we
/// reject a zero-length list and any odd byte count.
pub(crate) fn decode_extension(body: &[u8]) -> Result<Vec<u16>, Error> {
    let mut c = ReadCursor::new(body);
    let list = c.vec_u8()?;
    c.expect_empty()?;
    if list.is_empty() || list.len() % 2 != 0 {
        return Err(Error::Decode);
    }
    let mut algs = Vec::with_capacity(list.len() / 2);
    let mut lc = ReadCursor::new(list);
    while !lc.is_empty() {
        algs.push(lc.u16()?);
    }
    Ok(algs)
}

// -------- handshake-message codec --------

/// Build a complete `CompressedCertificate` handshake message (header
/// included) compressing `certificate_message_body` (the BODY of the
/// `Certificate` handshake message — what would have followed the
/// 4-byte handshake header). The caller supplies the algorithm; today
/// only [`algorithm::ZLIB`] is accepted.
pub(crate) fn encode_compressed_certificate(
    algorithm: u16,
    certificate_message_body: &[u8],
) -> Result<Vec<u8>, Error> {
    if !supports(algorithm) {
        return Err(Error::IllegalParameter);
    }
    let uncompressed_length: u32 = certificate_message_body
        .len()
        .try_into()
        .map_err(|_| Error::IllegalParameter)?;
    // u24 ceiling — RFC 8446 §4.4.2 already implies this; redundant but
    // makes the precondition explicit.
    if uncompressed_length > 0x00FF_FFFF {
        return Err(Error::IllegalParameter);
    }
    let compressed = zlib_compress(certificate_message_body)?;
    // Build the full handshake message: type (u8) || length (u24) || body.
    let mut msg = Vec::with_capacity(4 + 5 + compressed.len());
    msg.push(hs_type::COMPRESSED_CERTIFICATE);
    with_len_u24(&mut msg, |b| {
        put_u16(b, algorithm);
        // uncompressed_length is a u24.
        b.extend_from_slice(&uncompressed_length.to_be_bytes()[1..]);
        with_len_u24(b, |c| c.extend_from_slice(&compressed));
    });
    Ok(msg)
}

/// Decode a received `CompressedCertificate` handshake-message body
/// (i.e. the bytes that follow the 4-byte handshake header).
///
/// Returns the decompressed `Certificate` message body — the caller
/// then dispatches it through the regular `Certificate` parser. On any
/// failure (unsupported algorithm, malformed framing, decompression
/// rejected, length mismatch, declared length over cap), this returns
/// [`Error::CertDecompressionFailed`].
pub(crate) fn decode_compressed_certificate(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut c = ReadCursor::new(body);
    let algorithm = c.u16().map_err(|_| Error::CertDecompressionFailed)?;
    let uncompressed_length_u32 = c.u24().map_err(|_| Error::CertDecompressionFailed)? as u32;
    let compressed = c.vec_u24().map_err(|_| Error::CertDecompressionFailed)?;
    c.expect_empty()
        .map_err(|_| Error::CertDecompressionFailed)?;
    if !supports(algorithm) {
        return Err(Error::CertDecompressionFailed);
    }
    if uncompressed_length_u32 > MAX_UNCOMPRESSED_BYTES {
        return Err(Error::CertDecompressionFailed);
    }
    let out = zlib_decompress_capped(compressed, uncompressed_length_u32 as usize)?;
    // RFC 8879 §4: "If the received CompressedCertificate message cannot
    // be decompressed, the connection MUST be terminated with the
    // bad_certificate alert." We treat a length mismatch as part of "cannot
    // be decompressed" — the produced bytes were not the original.
    if out.len() != uncompressed_length_u32 as usize {
        return Err(Error::CertDecompressionFailed);
    }
    Ok(out)
}

// -------- compcol zlib glue --------

/// One-shot zlib compression — no size cap on the input (encoder is the
/// trusted side: we are encoding our own `Certificate` message).
fn zlib_compress(input: &[u8]) -> Result<Vec<u8>, Error> {
    compcol::vec::compress_to_vec::<compcol::zlib::Zlib>(input)
        // We control the input on this path, so a compress failure means a
        // bug in compcol or memory exhaustion — neither is a peer-driven
        // condition. Map to `InternalError`-equivalent: keep the public
        // signature symmetric and surface as IllegalParameter (we never
        // reach this in tests).
        .map_err(|_| Error::IllegalParameter)
}

/// Streaming zlib decompression with an explicit output budget. The
/// decoder is `LimitedDecoder<zlib::Decoder>` with the budget set to
/// `cap` bytes — the decoder aborts mid-stream with
/// `Error::OutputLimitExceeded` if the payload would emit beyond `cap`,
/// which we convert to [`Error::CertDecompressionFailed`].
///
/// Allocates one output buffer of size `cap`; the caller has already
/// bounded `cap` against [`MAX_UNCOMPRESSED_BYTES`].
fn zlib_decompress_capped(input: &[u8], cap: usize) -> Result<Vec<u8>, Error> {
    use compcol::limit::LimitedDecoder;
    use compcol::{Decoder, Status};

    let inner = compcol::zlib::Decoder::new();
    let mut dec = LimitedDecoder::new(inner, cap as u64);
    let mut out = alloc::vec![0u8; cap];
    let mut input_pos = 0usize;
    let mut output_pos = 0usize;
    let mut input_drained = false;

    loop {
        if !input_drained {
            let (progress, status) = dec
                .decode(&input[input_pos..], &mut out[output_pos..])
                .map_err(|_| Error::CertDecompressionFailed)?;
            input_pos += progress.consumed;
            output_pos += progress.written;
            match status {
                Status::StreamEnd => break,
                Status::OutputFull => {
                    // Either the buffer truly filled (next byte would
                    // exceed `cap`) or the decoder cannot make progress
                    // without more output room. Either way, the payload
                    // exceeds the declared length — reject.
                    return Err(Error::CertDecompressionFailed);
                }
                Status::InputEmpty => {
                    // No more input bytes to feed; ask the decoder to
                    // flush any remaining state via `finish` below.
                    input_drained = true;
                }
            }
        } else {
            let (progress, status) = dec
                .finish(&mut out[output_pos..])
                .map_err(|_| Error::CertDecompressionFailed)?;
            output_pos += progress.written;
            match status {
                Status::StreamEnd => break,
                Status::OutputFull => {
                    return Err(Error::CertDecompressionFailed);
                }
                Status::InputEmpty => {
                    // Decoder still wants input but the wire stream is
                    // exhausted — truncated payload.
                    return Err(Error::CertDecompressionFailed);
                }
            }
        }
    }

    out.truncate(output_pos);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_codec_round_trip() {
        let advert = alloc::vec![algorithm::ZLIB];
        let body = encode_extension(&advert);
        // Wire shape: 1 byte list length (2) || u16 algorithm (0x0001).
        assert_eq!(body, alloc::vec![0x02, 0x00, 0x01]);
        let decoded = decode_extension(&body).expect("decode");
        assert_eq!(decoded, advert);
    }

    #[test]
    fn extension_codec_multiple_algorithms() {
        let advert = alloc::vec![algorithm::ZLIB, algorithm::BROTLI, algorithm::ZSTD];
        let body = encode_extension(&advert);
        let decoded = decode_extension(&body).expect("decode");
        assert_eq!(decoded, advert);
    }

    #[test]
    fn extension_decode_rejects_empty_list() {
        // u8 length = 0
        let body = alloc::vec![0x00];
        assert!(matches!(decode_extension(&body), Err(Error::Decode)));
    }

    #[test]
    fn extension_decode_rejects_odd_length() {
        // u8 length = 3 (not divisible by 2)
        let body = alloc::vec![0x03, 0x00, 0x01, 0x00];
        assert!(matches!(decode_extension(&body), Err(Error::Decode)));
    }

    #[test]
    fn extension_decode_rejects_trailing_garbage() {
        // u8 length = 2, then two more bytes outside the inner list.
        let body = alloc::vec![0x02, 0x00, 0x01, 0xAA];
        assert!(matches!(decode_extension(&body), Err(Error::Decode)));
    }

    #[test]
    fn pick_returns_zlib_when_offered() {
        let local = default_algorithms();
        assert_eq!(
            pick_from_lists(&[algorithm::ZLIB], &local),
            Some(algorithm::ZLIB)
        );
        // Even when brotli is preferred, we pick zlib because that's all
        // we can decode and it's in our local list.
        assert_eq!(
            pick_from_lists(&[algorithm::BROTLI, algorithm::ZLIB], &local),
            Some(algorithm::ZLIB)
        );
    }

    #[test]
    fn pick_returns_none_with_no_overlap() {
        let local = default_algorithms();
        assert_eq!(
            pick_from_lists(&[algorithm::BROTLI, algorithm::ZSTD], &local),
            None
        );
        assert_eq!(pick_from_lists(&[], &local), None);
        assert_eq!(pick_from_lists(&[42, 9000], &local), None);
    }

    #[test]
    fn pick_returns_none_when_local_lacks_algorithm() {
        // Peer offers zlib but our local config opted it out.
        assert_eq!(pick_from_lists(&[algorithm::ZLIB], &[]), None);
        // Peer offers zlib but our local config only lists brotli (which
        // we cannot support anyway) — still no pick.
        assert_eq!(
            pick_from_lists(&[algorithm::ZLIB], &[algorithm::BROTLI]),
            None
        );
    }

    #[test]
    fn compressed_certificate_round_trip() {
        // A realistic-looking Certificate message body: empty context
        // byte, then a single 1024-byte "cert" stuffed with a repeating
        // pattern so zlib gets real compression to work with.
        let mut cert_body = Vec::new();
        cert_body.push(0); // certificate_request_context empty
        with_len_u24(&mut cert_body, |list| {
            with_len_u24(list, |c| {
                for i in 0..1024 {
                    c.push((i % 251) as u8);
                }
            });
            // empty per-entry extensions
            list.extend_from_slice(&[0, 0]);
        });

        let msg = encode_compressed_certificate(algorithm::ZLIB, &cert_body).expect("encode");
        // The message must begin with type 25 and a u24 length.
        assert_eq!(msg[0], 25);
        let declared_msg_len =
            ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
        assert_eq!(declared_msg_len, msg.len() - 4);

        // Round-trip back through the decoder.
        let recovered = decode_compressed_certificate(&msg[4..]).expect("decode");
        assert_eq!(recovered, cert_body);
        // And — for a sufficiently repetitive payload — the compressed
        // wire is genuinely smaller.
        assert!(
            msg.len() < cert_body.len(),
            "compressed wire ({}) should be smaller than cert body ({}) for repeating data",
            msg.len(),
            cert_body.len()
        );
    }

    #[test]
    fn decode_rejects_unsupported_algorithm() {
        // Build a CompressedCertificate body declaring algorithm 2
        // (brotli), with a dummy 4-byte payload claiming uncompressed
        // length 8. The decoder must reject before touching the payload.
        let mut body = Vec::new();
        put_u16(&mut body, algorithm::BROTLI);
        body.extend_from_slice(&[0x00, 0x00, 0x08]); // u24 uncompressed_length
        with_len_u24(&mut body, |b| b.extend_from_slice(b"junk"));
        assert!(matches!(
            decode_compressed_certificate(&body),
            Err(Error::CertDecompressionFailed)
        ));
    }

    #[test]
    fn decode_rejects_uncompressed_length_over_cap() {
        // Declared uncompressed_length = MAX_UNCOMPRESSED_BYTES + 1.
        let mut body = Vec::new();
        put_u16(&mut body, algorithm::ZLIB);
        let over = MAX_UNCOMPRESSED_BYTES + 1;
        body.extend_from_slice(&over.to_be_bytes()[1..]); // u24
        with_len_u24(&mut body, |b| b.extend_from_slice(b"junk"));
        assert!(matches!(
            decode_compressed_certificate(&body),
            Err(Error::CertDecompressionFailed)
        ));
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        // Compress an 8-byte payload but declare 9.
        let inner = b"abcdefgh";
        let compressed = zlib_compress(inner).expect("compress");
        let mut body = Vec::new();
        put_u16(&mut body, algorithm::ZLIB);
        body.extend_from_slice(&[0x00, 0x00, 0x09]); // wrong: declared 9, actual 8
        with_len_u24(&mut body, |b| b.extend_from_slice(&compressed));
        assert!(matches!(
            decode_compressed_certificate(&body),
            Err(Error::CertDecompressionFailed)
        ));
    }

    #[test]
    fn decode_rejects_truncated_compressed_stream() {
        // Compress then truncate the compressed bytes so the zlib trailer
        // is missing — the decoder must abort.
        let inner = b"the quick brown fox jumps over the lazy dog";
        let compressed = zlib_compress(inner).expect("compress");
        let truncated = &compressed[..compressed.len() / 2];
        let mut body = Vec::new();
        put_u16(&mut body, algorithm::ZLIB);
        body.extend_from_slice(&(inner.len() as u32).to_be_bytes()[1..]);
        with_len_u24(&mut body, |b| b.extend_from_slice(truncated));
        assert!(matches!(
            decode_compressed_certificate(&body),
            Err(Error::CertDecompressionFailed)
        ));
    }

    #[test]
    fn decode_rejects_zlib_bomb_attempting_to_exceed_cap() {
        // Build a payload that, when honestly decompressed, would produce
        // far more than the declared uncompressed_length. The streaming
        // decoder's per-call budget (`cap` = declared length) must abort
        // before the bomb expands.
        let big = alloc::vec![0xABu8; 4096];
        let compressed = zlib_compress(&big).expect("compress");
        // Declare uncompressed_length = 16 (lie). The decoder should
        // overflow its budget and reject.
        let mut body = Vec::new();
        put_u16(&mut body, algorithm::ZLIB);
        body.extend_from_slice(&[0x00, 0x00, 0x10]); // declared 16
        with_len_u24(&mut body, |b| b.extend_from_slice(&compressed));
        assert!(matches!(
            decode_compressed_certificate(&body),
            Err(Error::CertDecompressionFailed)
        ));
    }

    #[test]
    fn encode_compressed_certificate_rejects_unsupported_algorithm() {
        assert!(matches!(
            encode_compressed_certificate(algorithm::BROTLI, b"hello"),
            Err(Error::IllegalParameter)
        ));
    }
}
