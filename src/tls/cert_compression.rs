//! RFC 8879 — TLS Certificate Compression (TLS 1.3).
//!
//! Wire surface:
//!
//! - **`compress_certificate` extension** (IANA code point 27, `0x001b`):
//!   appears in the `ClientHello` (covering the server's `Certificate`) or
//!   in the server's `CertificateRequest` (covering the client's mTLS
//!   `Certificate`). Body: a `u8`-length list of `u16` algorithm IDs the
//!   sender can DECOMPRESS. Unidirectional — the peer either picks one or
//!   does nothing, with no response extension (RFC 8879 §3).
//! - **`CompressedCertificate` handshake message** (type 25): replaces a
//!   regular `Certificate` on the wire when the sender chose to compress.
//!   Body: `algorithm u16 ‖ uncompressed_length u24 ‖
//!   compressed_certificate_message<u24>`. The decompressed bytes are
//!   processed exactly as a `Certificate` message body would be; the
//!   transcript hash is fed the COMPRESSED wire bytes (matching how
//!   BoringSSL / rustls drive it — RFC 8879 leaves the choice unstated
//!   but only this interpretation is reproducible by both peers).
//!
//! Both directions are implemented: a server compresses its `Certificate`
//! for a client that advertised in its `ClientHello`, and a client
//! compresses its mTLS `Certificate` for a server that advertised in its
//! `CertificateRequest`.
//!
//! Algorithm IDs (`CertificateCompressionAlgorithm` registry, RFC 8879
//! §7.3):
//!
//! | id | name   | format   | available |
//! |----|--------|----------|-----------|
//! |  1 | zlib   | RFC 1950 | always    |
//! |  2 | brotli | RFC 7932 | with the `std` feature (compcol's brotli encoder needs floating-point `log2`) |
//! |  3 | zstd   | RFC 8478 | always    |
//!
//! The codecs are the `compcol` crate, the sole vendored dependency of
//! this crate ([[compcol-allowed-for-deflate]] memory documents the
//! carve-out).
//!
//! Which algorithm the sender uses is its own choice among the ones the
//! peer listed (RFC 8879 §4: "The algorithm MUST be one of the algorithms
//! listed in the peer's compress_certificate extension"; the RFC attaches
//! no meaning to the order of the peer's list). The pick therefore walks
//! the LOCAL send list in its configured order.
//!
//! Size policy (RFC 8879 §5):
//!
//! > Implementations MUST limit the size of the resulting decompressed
//! > chain to the specified uncompressed length, and they MUST abort the
//! > connection if the size of the output of the decompression function
//! > exceeds that limit. TLS framing imposes a 16777216-byte limit on the
//! > certificate message size, and implementations MAY impose a limit that
//! > is lower than that; in both cases, they MUST apply the same limit as
//! > if no compression were used.
//!
//! We enforce all of it, identically for every algorithm and for both
//! directions: a hard cap [`MAX_UNCOMPRESSED_BYTES`] on the
//! `uncompressed_length` field itself — the size of the largest
//! uncompressed `Certificate` body the handshake reassembly would accept
//! — checked before anything is allocated or decoded; a streaming-decode
//! budget equal to the declared length, so the decoder stops mid-stream
//! instead of expanding a bomb; and an exact-length check on the result
//! (RFC 8879 §4: "If, after decompression, the specified length does not
//! match the actual length, the party receiving the invalid message MUST
//! abort the connection with the 'bad_certificate' alert").

use crate::tls::Error;
use crate::tls::codec::hs_type;
use crate::tls::codec::{ReadCursor, put_u16, with_len_u8, with_len_u24};
use alloc::vec::Vec;

/// Hard cap on the `uncompressed_length` field of any received
/// `CompressedCertificate`: the largest `Certificate` message body the
/// handshake layer would take uncompressed (the reassembly ceiling
/// `MAX_HANDSHAKE_REASSEMBLY`, 128 KiB, less the 4-byte handshake header).
/// RFC 8879 §5 demands "the same limit as if no compression were used", so
/// that compression is never a way to get a larger chain parsed than the
/// plain path allows. Real-world chains never come close; rejecting
/// before decoding is the classic decompression-bomb defence.
#[doc(hidden)]
pub const MAX_UNCOMPRESSED_BYTES: u32 = (crate::tls::conn::MAX_HANDSHAKE_REASSEMBLY - 4) as u32;

/// IANA `CertificateCompressionAlgorithm` codepoints (RFC 8879 §7.3).
pub mod algorithm {
    /// `zlib(1)` — RFC 1950 zlib container around RFC 1951 DEFLATE.
    pub const ZLIB: u16 = 1;
    /// `brotli(2)` — RFC 7932. Wired in builds with the `std` feature.
    pub const BROTLI: u16 = 2;
    /// `zstd(3)` — RFC 8478.
    pub const ZSTD: u16 = 3;
}

/// Every algorithm this build can encode and decode, in the default
/// preference order: zlib first (what every implementation of RFC 8879
/// has), then brotli, then zstd.
const SUPPORTED: &[u16] = &[
    algorithm::ZLIB,
    #[cfg(feature = "std")]
    algorithm::BROTLI,
    algorithm::ZSTD,
];

/// Default `cert_compression_algorithms`: everything this build
/// implements — zlib, brotli (with `std`), zstd.
pub fn default_algorithms() -> Vec<u16> {
    SUPPORTED.to_vec()
}

/// True when this build can encode/decode `algorithm`.
pub fn supports(algorithm: u16) -> bool {
    SUPPORTED.contains(&algorithm)
}

/// The registry name of `algorithm` (RFC 8879 §7.3), or `None` for a
/// codepoint outside the three the RFC defines.
pub fn algorithm_name(algorithm: u16) -> Option<&'static str> {
    match algorithm {
        algorithm::ZLIB => Some("zlib"),
        algorithm::BROTLI => Some("brotli"),
        algorithm::ZSTD => Some("zstd"),
        _ => None,
    }
}

/// The codepoint a registry name stands for (the inverse of
/// [`algorithm_name`]), whether or not this build implements it.
pub fn algorithm_from_name(name: &str) -> Option<u16> {
    match name {
        "zlib" => Some(algorithm::ZLIB),
        "brotli" => Some(algorithm::BROTLI),
        "zstd" => Some(algorithm::ZSTD),
        _ => None,
    }
}

/// What a configured list puts on the wire and what is accepted back: the
/// entries this build implements, in the configured order, each once.
/// An algorithm we cannot decompress must not be advertised — the peer
/// would be entitled to use it (RFC 8879 §4) and the handshake would then
/// fail on a message we invited.
pub(crate) fn advertised(configured: &[u16]) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::with_capacity(configured.len().min(SUPPORTED.len()));
    for alg in configured {
        if supports(*alg) && !out.contains(alg) {
            out.push(*alg);
        }
    }
    out
}

/// Pick the algorithm to compress our own `Certificate` with: the first
/// entry of `local` (our send list, in our preference order) that the
/// peer listed in its `compress_certificate` extension (`offered`) and
/// that this build implements. `None` when there is no overlap — the
/// certificate then goes out uncompressed.
///
/// RFC 8879 §4 only requires that the algorithm "MUST be one of the
/// algorithms listed in the peer's compress_certificate extension"; the
/// compressing side bears the cost and chooses.
pub(crate) fn pick_from_lists(offered: &[u16], local: &[u16]) -> Option<u16> {
    local
        .iter()
        .copied()
        .find(|a| supports(*a) && offered.contains(a))
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
/// algorithm IDs the peer can DECOMPRESS, in the order it sent them. Per
/// RFC 8879 §3 the inner list length is 2..=254 bytes (1..=127 IDs); we
/// reject a zero-length list and any odd byte count.
#[doc(hidden)]
pub fn decode_extension(body: &[u8]) -> Result<Vec<u16>, Error> {
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
/// 4-byte handshake header) with `algorithm`, which must be one this
/// build [`supports`].
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
    let compressed = compress(algorithm, certificate_message_body)?;
    // RFC 8879 §4: `compressed_certificate_message<1..2^24-1>`.
    if compressed.is_empty() || compressed.len() > 0x00FF_FFFF {
        return Err(Error::IllegalParameter);
    }
    // Build the full handshake message: type (u8) || length (u24) || body.
    let mut msg = Vec::with_capacity(4 + 5 + 3 + compressed.len());
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
///
/// This checks what the build can decompress; whether the algorithm was
/// one we ADVERTISED is the caller's check
/// ([`decode_compressed_certificate_from`]).
#[doc(hidden)]
pub fn decode_compressed_certificate(body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut c = ReadCursor::new(body);
    let algorithm = c.u16().map_err(|_| Error::CertDecompressionFailed)?;
    let uncompressed_length_u32 = c.u24().map_err(|_| Error::CertDecompressionFailed)? as u32;
    let compressed = c.vec_u24().map_err(|_| Error::CertDecompressionFailed)?;
    c.expect_empty()
        .map_err(|_| Error::CertDecompressionFailed)?;
    if !supports(algorithm) {
        return Err(Error::CertDecompressionFailed);
    }
    // RFC 8879 §5: the limit of the uncompressed path, enforced on the
    // declared length before a byte is allocated or decoded.
    if uncompressed_length_u32 > MAX_UNCOMPRESSED_BYTES {
        return Err(Error::CertDecompressionFailed);
    }
    // RFC 8879 §4: `compressed_certificate_message<1..2^24-1>`.
    if compressed.is_empty() {
        return Err(Error::CertDecompressionFailed);
    }
    let out = decompress_capped(algorithm, compressed, uncompressed_length_u32 as usize)?;
    // RFC 8879 §4: "If the received CompressedCertificate message cannot
    // be decompressed, the connection MUST be terminated with the
    // bad_certificate alert." We treat a length mismatch as part of "cannot
    // be decompressed" — the produced bytes were not the original.
    if out.len() != uncompressed_length_u32 as usize {
        return Err(Error::CertDecompressionFailed);
    }
    Ok(out)
}

/// The receive path both roles share: check that a `CompressedCertificate`
/// was invited, then decompress it. `configured` is the endpoint's
/// `cert_compression_algorithms` (what it put in its `ClientHello` or
/// `CertificateRequest`). Returns the algorithm and the recovered
/// `Certificate` message body.
///
/// - Nothing advertised: the message is [`Error::UnexpectedMessage`] — a
///   peer must not invent compression we did not consent to.
/// - RFC 8879 §4: "The algorithm MUST be one of the algorithms listed in
///   the peer's compress_certificate extension" — anything else is
///   [`Error::IllegalParameter`], decided on the header alone, before the
///   decoder sees the payload.
pub(crate) fn decode_compressed_certificate_from(
    configured: &[u16],
    body: &[u8],
) -> Result<(u16, Vec<u8>), Error> {
    let advertised = advertised(configured);
    if advertised.is_empty() {
        return Err(Error::UnexpectedMessage);
    }
    let algorithm = body
        .get(..2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
        .ok_or(Error::CertDecompressionFailed)?;
    if !advertised.contains(&algorithm) {
        return Err(Error::IllegalParameter);
    }
    Ok((algorithm, decode_compressed_certificate(body)?))
}

// -------- compcol glue --------

/// One-shot compression — no size cap on the input (the encoder is the
/// trusted side: we are encoding our own `Certificate` message).
fn compress(algorithm: u16, input: &[u8]) -> Result<Vec<u8>, Error> {
    let out = match algorithm {
        algorithm::ZLIB => compcol::vec::compress_to_vec::<compcol::zlib::Zlib>(input),
        #[cfg(feature = "std")]
        algorithm::BROTLI => compcol::vec::compress_to_vec::<compcol::brotli::Brotli>(input),
        algorithm::ZSTD => compcol::vec::compress_to_vec::<compcol::zstd::Zstd>(input),
        _ => return Err(Error::IllegalParameter),
    };
    // We control the input on this path, so a compress failure means a
    // bug in compcol or memory exhaustion — neither is a peer-driven
    // condition. The callers fall back to the plain Certificate.
    out.map_err(|_| Error::IllegalParameter)
}

/// Streaming decompression of `input` under `algorithm` with an output
/// budget of `cap` bytes; see [`decode_capped`].
fn decompress_capped(algorithm: u16, input: &[u8], cap: usize) -> Result<Vec<u8>, Error> {
    match algorithm {
        algorithm::ZLIB => decode_capped(compcol::zlib::Decoder::new(), input, cap),
        #[cfg(feature = "std")]
        algorithm::BROTLI => decode_capped(compcol::brotli::Decoder::new(), input, cap),
        algorithm::ZSTD => decode_capped(compcol::zstd::Decoder::new(), input, cap),
        _ => Err(Error::CertDecompressionFailed),
    }
}

/// Run `inner` over `input` with an explicit output budget. The decoder
/// is wrapped in compcol's `LimitedDecoder` with the budget set to `cap`
/// bytes — it aborts mid-stream with `OutputLimitExceeded` if the payload
/// would emit beyond `cap`, which we convert to
/// [`Error::CertDecompressionFailed`]. The same loop serves every
/// algorithm, so the bomb limits cannot differ between them.
///
/// Allocates one output buffer of size `cap`; the caller has already
/// bounded `cap` against [`MAX_UNCOMPRESSED_BYTES`]. The stream's end
/// marker must be reached within `input`; bytes after it are ignored,
/// as zlib's `uncompress` (and so BoringSSL) ignores them — the length
/// and content of the output are what the caller checks, and compcol's
/// DEFLATE bit reader over-reads past the end marker, so exact
/// consumption cannot be told from its progress counts anyway.
///
/// Termination: every iteration either consumes input, writes output,
/// moves from the decode phase to the finish phase, or returns — and
/// input and output are both finite.
fn decode_capped<D: compcol::Decoder>(
    inner: D,
    input: &[u8],
    cap: usize,
) -> Result<Vec<u8>, Error> {
    use compcol::limit::LimitedDecoder;
    use compcol::{Decoder, Status};

    let mut dec = LimitedDecoder::new(inner, cap as u64);
    let mut out = alloc::vec![0u8; cap];
    let mut input_pos = 0usize;
    let mut output_pos = 0usize;
    let mut input_drained = false;

    loop {
        let (progress, status) = if input_drained {
            dec.finish(&mut out[output_pos..])
        } else {
            dec.decode(&input[input_pos..], &mut out[output_pos..])
        }
        .map_err(|_| Error::CertDecompressionFailed)?;
        input_pos += progress.consumed;
        output_pos += progress.written;
        let stalled = progress.consumed == 0 && progress.written == 0;
        match status {
            Status::StreamEnd => break,
            // The output room ran out. With the budget not yet spent the
            // decoder is merely handing out what it buffered; once the
            // buffer is full it may still have the stream trailer to
            // read, which produces nothing. A call that neither consumed
            // nor wrote means it has more to emit than the declared
            // length allows — reject.
            Status::OutputFull if stalled => return Err(Error::CertDecompressionFailed),
            Status::OutputFull => {}
            // The decoder wants input the wire does not have: a truncated
            // stream.
            Status::InputEmpty if input_drained => return Err(Error::CertDecompressionFailed),
            Status::InputEmpty if input_pos >= input.len() => input_drained = true,
            Status::InputEmpty if stalled => return Err(Error::CertDecompressionFailed),
            Status::InputEmpty => {}
        }
    }
    out.truncate(output_pos);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A realistic-looking Certificate message body: empty context byte,
    /// then a single 1024-byte "cert" stuffed with a repeating pattern so
    /// every codec gets real compression to work with.
    fn sample_cert_body() -> Vec<u8> {
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
        cert_body
    }

    /// A `CompressedCertificate` body (no handshake header) from its
    /// three fields.
    fn compressed_body(algorithm: u16, uncompressed_length: u32, payload: &[u8]) -> Vec<u8> {
        let mut body = Vec::new();
        put_u16(&mut body, algorithm);
        body.extend_from_slice(&uncompressed_length.to_be_bytes()[1..]); // u24
        with_len_u24(&mut body, |b| b.extend_from_slice(payload));
        body
    }

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
    fn defaults_are_what_the_build_implements() {
        let d = default_algorithms();
        assert_eq!(d[0], algorithm::ZLIB);
        assert!(d.contains(&algorithm::ZSTD));
        assert_eq!(d.contains(&algorithm::BROTLI), cfg!(feature = "std"));
        for a in &d {
            assert!(supports(*a));
        }
        assert!(!supports(0));
        assert!(!supports(4));
        assert!(!supports(0xFFFF));
    }

    #[test]
    fn names_round_trip() {
        for (id, name) in [
            (algorithm::ZLIB, "zlib"),
            (algorithm::BROTLI, "brotli"),
            (algorithm::ZSTD, "zstd"),
        ] {
            assert_eq!(algorithm_name(id), Some(name));
            assert_eq!(algorithm_from_name(name), Some(id));
        }
        assert_eq!(algorithm_name(0), None);
        assert_eq!(algorithm_from_name("deflate"), None);
    }

    /// The advertisement drops what the build cannot decode, keeps the
    /// configured order, and lists each algorithm once.
    #[test]
    fn advertised_filters_and_keeps_order() {
        assert_eq!(
            advertised(&[algorithm::ZSTD, 4, algorithm::ZLIB, algorithm::ZSTD, 0xFFFF]),
            alloc::vec![algorithm::ZSTD, algorithm::ZLIB]
        );
        assert!(advertised(&[]).is_empty());
        assert!(advertised(&[4, 5, 6]).is_empty());
        assert_eq!(
            advertised(&[algorithm::BROTLI]).is_empty(),
            !cfg!(feature = "std")
        );
    }

    /// The sender's own preference order decides, not the peer's.
    #[test]
    fn pick_follows_local_order() {
        let local = alloc::vec![algorithm::ZSTD, algorithm::ZLIB];
        assert_eq!(
            pick_from_lists(&[algorithm::ZLIB, algorithm::ZSTD], &local),
            Some(algorithm::ZSTD)
        );
        assert_eq!(
            pick_from_lists(&[algorithm::ZLIB], &local),
            Some(algorithm::ZLIB)
        );
        // An algorithm the peer lists but we do not send with is skipped.
        assert_eq!(
            pick_from_lists(&[algorithm::BROTLI, algorithm::ZLIB], &[algorithm::ZLIB]),
            Some(algorithm::ZLIB)
        );
    }

    #[test]
    fn pick_returns_none_with_no_overlap() {
        let local = alloc::vec![algorithm::ZLIB];
        assert_eq!(pick_from_lists(&[algorithm::ZSTD], &local), None);
        assert_eq!(pick_from_lists(&[], &local), None);
        assert_eq!(pick_from_lists(&[42, 9000], &local), None);
        // Peer offers zlib but our local config opted it out.
        assert_eq!(pick_from_lists(&[algorithm::ZLIB], &[]), None);
        // A codepoint neither side implements never gets picked even when
        // both list it.
        assert_eq!(pick_from_lists(&[9000], &[9000]), None);
    }

    #[test]
    fn compressed_certificate_round_trip_every_algorithm() {
        let cert_body = sample_cert_body();
        for alg in default_algorithms() {
            let msg = encode_compressed_certificate(alg, &cert_body).expect("encode");
            // The message must begin with type 25 and a u24 length.
            assert_eq!(msg[0], 25);
            let declared_msg_len =
                ((msg[1] as usize) << 16) | ((msg[2] as usize) << 8) | msg[3] as usize;
            assert_eq!(declared_msg_len, msg.len() - 4);
            assert_eq!(u16::from_be_bytes([msg[4], msg[5]]), alg);

            // Round-trip back through the decoder, both entry points.
            let recovered = decode_compressed_certificate(&msg[4..]).expect("decode");
            assert_eq!(recovered, cert_body);
            let (picked, recovered) =
                decode_compressed_certificate_from(&default_algorithms(), &msg[4..])
                    .expect("decode from");
            assert_eq!(picked, alg);
            assert_eq!(recovered, cert_body);
            // And — for a sufficiently repetitive payload — the compressed
            // wire is genuinely smaller.
            assert!(
                msg.len() < cert_body.len(),
                "algorithm {alg}: compressed wire ({}) should be smaller than cert body ({})",
                msg.len(),
                cert_body.len()
            );
        }
    }

    /// The receive helper enforces what was ADVERTISED, not just what the
    /// build can decode (RFC 8879 §4).
    #[test]
    fn decode_from_enforces_the_advertised_list() {
        let cert_body = sample_cert_body();
        let msg = encode_compressed_certificate(algorithm::ZSTD, &cert_body).expect("encode");
        // Nothing advertised: the message itself is unexpected.
        assert!(matches!(
            decode_compressed_certificate_from(&[], &msg[4..]),
            Err(Error::UnexpectedMessage)
        ));
        // Only zlib advertised: zstd is an illegal choice by the peer.
        assert!(matches!(
            decode_compressed_certificate_from(&[algorithm::ZLIB], &msg[4..]),
            Err(Error::IllegalParameter)
        ));
        // Configured but unimplemented entries were never advertised.
        assert!(matches!(
            decode_compressed_certificate_from(&[9000], &msg[4..]),
            Err(Error::UnexpectedMessage)
        ));
        // A header too short to name an algorithm.
        assert!(matches!(
            decode_compressed_certificate_from(&[algorithm::ZSTD], &msg[4..5]),
            Err(Error::CertDecompressionFailed)
        ));
    }

    #[test]
    fn decode_rejects_unsupported_algorithm() {
        // Algorithm 4 (unassigned) with a dummy 4-byte payload claiming
        // uncompressed length 8. The decoder must reject before touching
        // the payload.
        assert!(matches!(
            decode_compressed_certificate(&compressed_body(4, 8, b"junk")),
            Err(Error::CertDecompressionFailed)
        ));
        assert!(matches!(
            decode_compressed_certificate(&compressed_body(0, 8, b"junk")),
            Err(Error::CertDecompressionFailed)
        ));
    }

    #[test]
    fn decode_rejects_uncompressed_length_over_cap() {
        // Declared uncompressed_length = MAX_UNCOMPRESSED_BYTES + 1: refused
        // for every algorithm before any decoding.
        for alg in default_algorithms() {
            let body = compressed_body(alg, MAX_UNCOMPRESSED_BYTES + 1, b"junk");
            assert!(matches!(
                decode_compressed_certificate(&body),
                Err(Error::CertDecompressionFailed)
            ));
        }
    }

    /// RFC 8879 §5: the decompressed message is held to the plain
    /// Certificate limit, not to a limit of its own.
    #[test]
    fn cap_is_the_plain_certificate_limit() {
        assert_eq!(
            MAX_UNCOMPRESSED_BYTES as usize + 4,
            crate::tls::conn::MAX_HANDSHAKE_REASSEMBLY
        );
    }

    #[test]
    fn decode_rejects_empty_payload() {
        // `compressed_certificate_message<1..2^24-1>`: a zero-length
        // payload is malformed on its own.
        for alg in default_algorithms() {
            assert!(matches!(
                decode_compressed_certificate(&compressed_body(alg, 0, b"")),
                Err(Error::CertDecompressionFailed)
            ));
        }
    }

    #[test]
    fn decode_rejects_length_mismatch() {
        // Compress an 8-byte payload but declare 9 (and 7).
        let inner = b"abcdefgh";
        for alg in default_algorithms() {
            let compressed = compress(alg, inner).expect("compress");
            for declared in [9u32, 7] {
                let body = compressed_body(alg, declared, &compressed);
                assert!(
                    matches!(
                        decode_compressed_certificate(&body),
                        Err(Error::CertDecompressionFailed)
                    ),
                    "algorithm {alg}, declared {declared}"
                );
            }
        }
    }

    #[test]
    fn decode_rejects_truncated_compressed_stream() {
        // Compress then truncate the compressed bytes so the stream's end
        // marker is missing — the decoder must abort, for every prefix.
        let inner = sample_cert_body();
        for alg in default_algorithms() {
            let compressed = compress(alg, &inner).expect("compress");
            for cut in 1..compressed.len() {
                let body = compressed_body(alg, inner.len() as u32, &compressed[..cut]);
                assert!(
                    matches!(
                        decode_compressed_certificate(&body),
                        Err(Error::CertDecompressionFailed)
                    ),
                    "algorithm {alg}, truncated to {cut}"
                );
            }
        }
    }

    #[test]
    fn decode_tolerates_trailing_bytes_after_the_stream() {
        // Bytes after the end-of-stream marker are either ignored (the
        // output is still exactly the original) or rejected — never a
        // different output, never a hang.
        let inner = sample_cert_body();
        for alg in default_algorithms() {
            let mut compressed = compress(alg, &inner).expect("compress");
            compressed.extend_from_slice(&[0, 0xFF, 0x42]);
            let body = compressed_body(alg, inner.len() as u32, &compressed);
            if let Ok(out) = decode_compressed_certificate(&body) {
                assert_eq!(out, inner, "algorithm {alg}");
            }
        }
    }

    #[test]
    fn decode_rejects_bomb_attempting_to_exceed_cap() {
        // Build a payload that, when honestly decompressed, would produce
        // far more than the declared uncompressed_length. The streaming
        // decoder's budget (`cap` = declared length) must abort before
        // the bomb expands — under every algorithm.
        let big = alloc::vec![0xABu8; 4096];
        for alg in default_algorithms() {
            let compressed = compress(alg, &big).expect("compress");
            // Declare uncompressed_length = 16 (lie).
            let body = compressed_body(alg, 16, &compressed);
            assert!(
                matches!(
                    decode_compressed_certificate(&body),
                    Err(Error::CertDecompressionFailed)
                ),
                "algorithm {alg}"
            );
        }
    }

    /// A bomb whose declared length is the maximum still costs no more
    /// than the cap: `MAX_UNCOMPRESSED_BYTES` of output buffer plus the
    /// decoder's own working set. This pins the streaming property — the
    /// decoder stops at the budget rather than expanding first and
    /// checking after.
    #[test]
    fn decode_stops_at_the_cap_for_a_large_bomb() {
        let big = alloc::vec![0u8; 4 * MAX_UNCOMPRESSED_BYTES as usize];
        for alg in default_algorithms() {
            let compressed = compress(alg, &big).expect("compress");
            let body = compressed_body(alg, MAX_UNCOMPRESSED_BYTES, &compressed);
            assert!(
                matches!(
                    decode_compressed_certificate(&body),
                    Err(Error::CertDecompressionFailed)
                ),
                "algorithm {alg}"
            );
        }
    }

    #[test]
    fn decode_survives_corrupted_streams() {
        // Flip every byte of a valid stream in turn: the outcome must be
        // an error or an output of exactly the declared length, never a
        // panic. (Brotli carries no checksum, so a flipped literal decodes
        // to different bytes of the same length; the record layer's AEAD
        // is what protects the message in transit, and the certificate
        // itself is then signature-checked.)
        let inner = sample_cert_body();
        for alg in default_algorithms() {
            let compressed = compress(alg, &inner).expect("compress");
            for i in 0..compressed.len() {
                let mut c = compressed.clone();
                c[i] ^= 0x5A;
                let body = compressed_body(alg, inner.len() as u32, &c);
                if let Ok(out) = decode_compressed_certificate(&body) {
                    assert_eq!(out.len(), inner.len(), "algorithm {alg}, byte {i}");
                }
            }
        }
    }

    #[test]
    fn encode_compressed_certificate_rejects_unsupported_algorithm() {
        assert!(matches!(
            encode_compressed_certificate(4, b"hello"),
            Err(Error::IllegalParameter)
        ));
        #[cfg(not(feature = "std"))]
        assert!(matches!(
            encode_compressed_certificate(algorithm::BROTLI, b"hello"),
            Err(Error::IllegalParameter)
        ));
    }
}
