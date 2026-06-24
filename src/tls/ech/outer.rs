//! Outer ClientHello derivation and HPKE seal pipeline
//! (draft-ietf-tls-esni-22 §6.1).
//!
//! The client builds the **inner** ClientHello first (real SNI, real
//! ALPN, all the rendezvous bits the network shouldn't see), pads it
//! to round out its length, then HPKE-seals it into the **outer**
//! ClientHello under the `encrypted_client_hello` extension. The
//! outer CH's SNI is the `ECHConfig.public_name`; everything else on
//! the outer side is bit-shape-identical to a GREASE CH so the wire
//! image of a real-ECH client and a GREASE client is visually the
//! same to an on-path observer.
//!
//! The seal pipeline:
//!
//! 1. Build the inner CH bytes (caller).
//! 2. Pad to a small constant length policy (`encoded_inner_padded`).
//! 3. Compute `info = "tls ech\0" || ECHConfig` (caller-provided).
//! 4. HPKE setup_sender → `enc` + `SenderContext`.
//! 5. Build the outer CH containing an `encrypted_client_hello`
//!    extension whose `payload` field is zeroes of the same length the
//!    sealed ciphertext will occupy (= `len(padded_inner) +
//!    aead_tag_len`).
//! 6. The `ClientHelloOuterAAD` is exactly the outer CH bytes above —
//!    the spec says the `payload` field is treated as zeroes for the
//!    AAD computation, which is what we just built.
//! 7. `sender_ctx.seal(aad, padded_inner)` → ciphertext.
//! 8. Patch the ciphertext into the payload bytes in the outer CH.
//!
//! The functions here implement steps 2 and 7–8 as pure operations on
//! byte slices; the connection-state-machine wave hands the inner CH
//! bytes and outer CH skeleton in and reads the sealed outer CH bytes
//! back out.

use super::config::{EchConfig, HpkeSymCipherSuite};
use super::extension::{EchExtension, decode_outer_position};
use super::hpke_setup::{map_sym_suite, setup_receiver, setup_sender};
use crate::hpke::{ReceiverContext, SenderContext};
use crate::rng::RngCore;
use crate::tls::Error;
use alloc::vec::Vec;

/// AEAD tag length for the HPKE suites we map to: GCM and
/// ChaCha20-Poly1305 both use a 16-byte tag (the only AEADs supported
/// by `map_sym_suite`; ExportOnly is rejected before we get here).
pub(crate) const HPKE_TAG_LEN: usize = 16;

/// Padding policy for the encoded inner CH. The draft (§6.1.3)
/// recommends padding to a multiple of 32 and topping up with extra
/// blocks if the inner CH's host name is shorter than the published
/// `maximum_name_length` so the leaked length doesn't reveal whether
/// the inner SNI is shorter than the public one.
///
/// Given a fully-encoded ClientHelloInner of length `L_in` and a
/// published `maximum_name_length` (the cap the server advertises),
/// the padded plaintext length is:
///
/// ```text
///   L_pad = max(L_in, L_in + (maximum_name_length - L_sni)) rounded up to 32
/// ```
///
/// where `L_sni` is the byte length of the inner SNI host name. If
/// `L_sni >= maximum_name_length` the second term collapses to
/// `L_in`. We then round `L_pad` up to the next multiple of 32 with a
/// minimum of 32 to keep tiny CHs from leaking through the floor.
pub(crate) fn pad_inner(
    encoded_inner: &[u8],
    inner_sni_len: usize,
    maximum_name_length: u8,
) -> Vec<u8> {
    let max_len = maximum_name_length as usize;
    let extra = max_len.saturating_sub(inner_sni_len);
    let target = encoded_inner.len() + extra;
    let target = target.next_multiple_of(32).max(32);
    let mut out = encoded_inner.to_vec();
    out.resize(target, 0);
    out
}

/// Result of [`seal_with`]: the outer CH bytes with the
/// `encrypted_client_hello` payload sealed in place, plus the HPKE
/// sender context (held by the client for any future export steps).
pub(crate) struct SealedOuter {
    /// The outer CH wire bytes with the `encrypted_client_hello`
    /// payload populated with the HPKE ciphertext.
    pub outer_ch: Vec<u8>,
    /// The HPKE sender context, retained by the caller for any later
    /// export-secret derivations the protocol may need.
    pub sender: SenderContext,
}

/// Splices an HPKE-sealed payload into an already-built outer CH
/// skeleton, using a pre-existing [`SenderContext`].
///
/// `outer_ch_skeleton` is the outer CH wire bytes carrying an
/// `encrypted_client_hello` extension whose `payload` field is zeroes
/// of length exactly `padded_inner.len() + HPKE_TAG_LEN`. The
/// function fails with [`Error::EchDecodeError`] if no such extension
/// is present, if there are multiple of them, or if the payload
/// length doesn't match what HPKE will produce. AEAD failure maps to
/// [`Error::EchDecryptionFailed`].
///
/// The seal proceeds with:
/// - `aad = outer_ch_skeleton` (which already has the payload field
///   zeroed and so equals `ClientHelloOuterAAD` per draft §6.1.2)
/// - `plaintext = padded_inner`
pub(crate) fn seal_into_skeleton(
    sender: &mut SenderContext,
    outer_ch_skeleton: Vec<u8>,
    padded_inner: &[u8],
) -> Result<Vec<u8>, Error> {
    let (start, len) = locate_payload_in_handshake(&outer_ch_skeleton)?;
    if len != padded_inner.len() + HPKE_TAG_LEN {
        return Err(Error::EchDecodeError);
    }
    // ClientHelloOuterAAD is the outer CH with the payload field
    // zeroed — and the skeleton already has zeros there. So AAD = the
    // skeleton bytes verbatim.
    let aad = outer_ch_skeleton.clone();
    let ciphertext = sender
        .seal(&aad, padded_inner)
        .map_err(|_| Error::EchDecryptionFailed)?;
    if ciphertext.len() != len {
        return Err(Error::EchDecryptionFailed);
    }
    let mut outer_ch = outer_ch_skeleton;
    outer_ch[start..start + len].copy_from_slice(&ciphertext);
    Ok(outer_ch)
}

/// Locates the `encrypted_client_hello` payload byte range within a
/// CH handshake message (header + body) for in-place ciphertext
/// substitution.
///
/// Returns `(offset, length)` where `offset` is the absolute index
/// into the handshake message at which the payload bytes start, and
/// `length` is the number of bytes they occupy. Fails with
/// [`Error::EchDecodeError`] if the message is not a syntactically
/// valid CH, if no outer-form `encrypted_client_hello` extension is
/// present, or if more than one is present (the second case would
/// make the AAD construction ambiguous).
pub(crate) fn locate_payload_in_handshake(handshake_msg: &[u8]) -> Result<(usize, usize), Error> {
    // Handshake msg: u8 msg_type (1=ClientHello) ++ u24 length ++ body.
    if handshake_msg.len() < 4 || handshake_msg[0] != crate::tls::codec::hs_type::CLIENT_HELLO {
        return Err(Error::EchDecodeError);
    }
    let body_len = ((handshake_msg[1] as usize) << 16)
        | ((handshake_msg[2] as usize) << 8)
        | (handshake_msg[3] as usize);
    if 4 + body_len != handshake_msg.len() {
        return Err(Error::EchDecodeError);
    }
    let body = &handshake_msg[4..];
    // ClientHello body: version(2) || random(32) || session_id(u8) ||
    // cipher_suites(u16) || compression_methods(u8) || extensions(u16).
    let mut idx = 0usize;
    let need = |idx: usize, n: usize| -> Result<(), Error> {
        if idx + n > body.len() {
            Err(Error::EchDecodeError)
        } else {
            Ok(())
        }
    };
    need(idx, 2)?;
    idx += 2;
    need(idx, 32)?;
    idx += 32;
    need(idx, 1)?;
    let sid_len = body[idx] as usize;
    idx += 1;
    need(idx, sid_len)?;
    idx += sid_len;
    need(idx, 2)?;
    let cs_len = ((body[idx] as usize) << 8) | (body[idx + 1] as usize);
    idx += 2;
    need(idx, cs_len)?;
    idx += cs_len;
    need(idx, 1)?;
    let cm_len = body[idx] as usize;
    idx += 1;
    need(idx, cm_len)?;
    idx += cm_len;
    need(idx, 2)?;
    let ext_total = ((body[idx] as usize) << 8) | (body[idx + 1] as usize);
    idx += 2;
    let ext_start_in_body = idx;
    need(idx, ext_total)?;
    let ext_end_in_body = idx + ext_total;

    // Walk extensions; find the unique encrypted_client_hello.
    let mut p = ext_start_in_body;
    let mut found: Option<(usize, usize)> = None;
    while p < ext_end_in_body {
        if p + 4 > ext_end_in_body {
            return Err(Error::EchDecodeError);
        }
        let ty = ((body[p] as u16) << 8) | (body[p + 1] as u16);
        let bl = ((body[p + 2] as usize) << 8) | (body[p + 3] as usize);
        let body_start = p + 4;
        let body_end = body_start + bl;
        if body_end > ext_end_in_body {
            return Err(Error::EchDecodeError);
        }
        if ty == crate::tls::codec::ExtensionType::ENCRYPTED_CLIENT_HELLO.0 {
            if found.is_some() {
                return Err(Error::EchDecodeError);
            }
            // Within an outer-form ECH extension body, locate the
            // payload bytes. The extension body has a precomputable
            // header layout: u8 type=0 || u16 kdf || u16 aead || u8
            // config_id || u16 enc_len || enc || u16 payload_len ||
            // payload. We delegate to the codec helper to find
            // (payload_offset_in_body, payload_len).
            let ext_body = &body[body_start..body_end];
            let (pay_off_in_body, pay_len) = decode_outer_position(ext_body)?;
            // Convert to absolute offset into the handshake msg.
            let abs = 4 + body_start + pay_off_in_body;
            found = Some((abs, pay_len));
        }
        p = body_end;
    }
    found.ok_or(Error::EchDecodeError)
}

/// Builds the outer-form `encrypted_client_hello` extension *body* a
/// real-ECH client emits, with the payload field still zeroed (the
/// caller patches in the HPKE ciphertext later). Returned shape:
///
/// ```text
///   u8 type = 0
///   u16 kdf_id
///   u16 aead_id
///   u8 config_id
///   u16 enc_len || enc
///   u16 payload_len || zeroes(payload_len)
/// ```
///
/// `payload_len` is the AEAD output size = padded inner CH length +
/// 16 (AES-GCM / ChaCha20-Poly1305 tag).
pub(crate) fn build_outer_ext_body(
    sym: HpkeSymCipherSuite,
    config_id: u8,
    enc: &[u8],
    padded_inner_len: usize,
) -> Vec<u8> {
    let payload_len = padded_inner_len + HPKE_TAG_LEN;
    let ext = EchExtension::Outer {
        cipher_suite: sym,
        config_id,
        enc: enc.to_vec(),
        payload: alloc::vec![0u8; payload_len],
    };
    ext.encode()
}

/// Combines [`pad_inner`], encoding the outer skeleton, and the HPKE
/// seal into a single client-side operation.
///
/// `caller_build_outer_skeleton` produces the wire bytes of the outer
/// CH including an `encrypted_client_hello` extension whose payload is
/// already zeroed of length `padded_inner.len() + HPKE_TAG_LEN`. The
/// HPKE setup_sender output is fed back to the caller via the closure
/// so it can compose the correct outer ext body before producing the
/// skeleton.
///
/// This indirection keeps the CH skeleton building (extension order,
/// length-prefix accounting) in the client where the rest of the CH
/// builder lives, while the seal pipeline stays here.
pub(crate) fn seal_with<R, F>(
    config: &EchConfig,
    sym: HpkeSymCipherSuite,
    encoded_inner: &[u8],
    inner_sni_len: usize,
    rng: &mut R,
    caller_build_outer_skeleton: F,
) -> Result<SealedOuter, Error>
where
    R: RngCore,
    F: FnOnce(&[u8], usize) -> Vec<u8>,
{
    let contents = config.contents.as_ref().ok_or(Error::EchDecodeError)?;
    let padded = pad_inner(encoded_inner, inner_sni_len, contents.maximum_name_length);
    let (enc, mut sender, _suite) = setup_sender(rng, config, sym)?;
    let skeleton = caller_build_outer_skeleton(&enc, padded.len());
    let outer_ch = seal_into_skeleton(&mut sender, skeleton, &padded)?;
    Ok(SealedOuter { outer_ch, sender })
}

/// Result of [`try_decap_inner`]: the recovered inner CH plus all the
/// state needed to (a) compute the HRR ECH confirmation signal at HRR
/// emit time and (b) re-decap CH2-outer on the HRR retry path with the
/// same HPKE context advanced to `seq = 1`.
pub(crate) struct DecappedInner {
    /// Recovered inner CH handshake-message bytes (header included).
    pub inner_ch_bytes: Vec<u8>,
    /// HPKE receiver context from CH1's setup_receiver, with its
    /// sequence counter already advanced to 1 by the CH1 `open` call.
    /// Retained across HRR so the CH2 outer-form decap reuses the
    /// same context per draft §7.2.2.
    pub receiver: ReceiverContext,
    /// Symmetric suite advertised in CH1-outer's `encrypted_client_hello`.
    /// CH2-outer MUST advertise the same suite (draft §6.1.5); we
    /// keep a copy here to validate this on the HRR retry path.
    pub sym: HpkeSymCipherSuite,
    /// `config_id` that selected the keypair for CH1. CH2-outer MUST
    /// echo this; keep for the same reason as `sym`.
    pub config_id: u8,
}

/// Server-side: given the outer CH handshake bytes and a configured
/// `EchKeyRing`, try every step of HPKE decap and return the
/// decrypted, padding-stripped inner CH bytes plus the live HPKE
/// receiver context (retained for the HRR retry path).
///
/// Failure modes (all map to "continue under outer CH, signal reject
/// via retry_configs"): no ECH extension in the outer CH, unknown
/// `config_id`, AEAD tag rejection, malformed plaintext, or the
/// expected inner-marker `encrypted_client_hello` extension missing
/// from the decrypted CH.
pub(crate) fn try_decap_inner(
    handshake_msg: &[u8],
    keys: &super::keys::EchKeyRing,
) -> Result<DecappedInner, Error> {
    // Walk the outer CH to find the encrypted_client_hello body and
    // its payload byte range; the AAD computation needs the byte
    // image with the payload zeroed.
    let (payload_off, payload_len) = locate_payload_in_handshake(handshake_msg)?;
    let mut aad = handshake_msg.to_vec();
    for b in aad[payload_off..payload_off + payload_len].iter_mut() {
        *b = 0;
    }
    let ciphertext = handshake_msg[payload_off..payload_off + payload_len].to_vec();

    // Locate and parse the extension body so we recover (sym, config_id, enc).
    let (sym, config_id, enc) = extract_outer_meta(handshake_msg)?;

    // Per draft-ietf-tls-esni-22 §7.1, the client's chosen HPKE
    // symmetric suite MUST be one the server published in this
    // ECHConfig's `cipher_suites`. If it isn't, treat the ECH as a
    // rejection (fall back to the outer ClientHello / retry_configs)
    // rather than attempting decap with an unannounced suite.
    let (kdf, aead) = map_sym_suite(sym)?;
    // The 8-bit `config_id` is only a hint: during key rotation two
    // distinct keys can share it. Per §7.1 the server SHOULD try every
    // config whose `config_id` matches before rejecting, so iterate the
    // ring and attempt HPKE decap against each candidate (skipping any
    // whose announced suites don't include the client's chosen
    // (kdf, aead)). The first candidate that decaps cleanly and yields a
    // well-formed inner CH wins. Only if every candidate fails do we
    // fall back to the reject / public_name path — identical in outcome
    // to committing to a single key, but without the rotation-induced
    // SNI-leak when the client used a newer same-config_id key.
    for pair in keys.matching_by_config_id(config_id) {
        if !pair.accepts(kdf, aead) {
            continue;
        }
        let (mut receiver, _suite) =
            match setup_receiver(pair.config(), pair.private_key_bytes(), &enc, sym) {
                Ok(r) => r,
                Err(_) => continue,
            };
        let plaintext = match receiver.open(&aad, &ciphertext) {
            Ok(p) => p,
            Err(_) => continue,
        };
        // A successful AEAD `open` authenticates this candidate: the
        // ciphertext was sealed under exactly this key + AAD, so this is
        // the client's intended config. From here on, any malformation
        // of the recovered inner CH is a hard protocol error
        // (`illegal_parameter`), NOT a reason to try another key or to
        // fall back to the public_name path — trying further keys after
        // an authenticated open could never succeed and would only blur
        // the failure mode.
        //
        // Strip trailing zero padding to recover the encoded inner CH.
        // Padding consists of an arbitrary number of trailing zero
        // bytes; since a ClientHello body is length-prefixed, anything
        // past the declared length is padding.
        let unpadded = strip_trailing_padding(&plaintext)?;
        // Per draft §7.1, the recovered inner CH MUST carry an
        // `encrypted_client_hello` extension with the inner-form body
        // (`[0x01]`). Reject as malformed otherwise (maps to
        // illegal_parameter at the alert layer).
        require_inner_marker(&unpadded)?;
        let inner_ch_bytes = decompress_inner_against_outer(&unpadded, handshake_msg)?;
        return Ok(DecappedInner {
            inner_ch_bytes,
            receiver,
            sym,
            config_id,
        });
    }
    // No matching config decapped successfully → ECH reject.
    Err(Error::EchDecryptionFailed)
}

/// If the recovered inner CH carries an `ech_outer_extensions` reference,
/// reconstructs the canonical inner CH by expanding it against the outer CH's
/// extensions (draft-ietf-tls-esni §5.1), re-encoding through
/// [`crate::tls::codec::ClientHello::encode`] so the bytes match what the
/// client fed its transcript. An inner CH without the reference is returned
/// byte-for-byte unchanged (the uncompressed path is untouched).
fn decompress_inner_against_outer(
    unpadded: &[u8],
    outer_handshake: &[u8],
) -> Result<Vec<u8>, Error> {
    use crate::tls::codec::{ClientHello, ExtensionType};
    // The 4-byte handshake header (type + 24-bit length) precedes the body.
    let inner_body = unpadded.get(4..).ok_or(Error::EchDecodeError)?;
    let inner = match ClientHello::decode(inner_body) {
        Ok(ch) => ch,
        // Not a parseable ClientHello: leave it for the downstream parser to
        // reject, exactly as before this hook existed.
        Err(_) => return Ok(unpadded.to_vec()),
    };
    if !inner
        .extensions
        .iter()
        .any(|(t, _)| *t == ExtensionType::ECH_OUTER_EXTENSIONS)
    {
        return Ok(unpadded.to_vec());
    }
    let outer_body = outer_handshake.get(4..).ok_or(Error::EchDecodeError)?;
    let outer = ClientHello::decode(outer_body).map_err(|_| Error::EchDecodeError)?;
    let canonical_exts =
        crate::tls::ech::inner::decompress_extensions(&inner.extensions, &outer.extensions)?;
    let canonical = ClientHello {
        extensions: canonical_exts,
        ..inner
    };
    Ok(canonical.encode())
}

/// Server-side CH2-outer decap on the HRR retry path. Uses the
/// `receiver` retained from CH1's [`try_decap_inner`] (its `seq` is
/// already 1) so the AEAD nonces sit at the right HPKE schedule
/// position per draft §7.2.2. The CH2-outer-AAD is the same shape
/// as CH1's: the full CH2-outer handshake bytes with the
/// `encrypted_client_hello` payload field zeroed.
///
/// CH2-outer's `enc` field MUST be empty per draft §6.1.5; the
/// `sym`/`config_id` must equal CH1's. Both checks happen here.
pub(crate) fn try_decap_inner_retry(
    handshake_msg: &[u8],
    state: &mut DecappedInner,
) -> Result<Vec<u8>, Error> {
    let (payload_off, payload_len) = locate_payload_in_handshake(handshake_msg)?;
    let mut aad = handshake_msg.to_vec();
    for b in aad[payload_off..payload_off + payload_len].iter_mut() {
        *b = 0;
    }
    let ciphertext = handshake_msg[payload_off..payload_off + payload_len].to_vec();

    let (sym, config_id, enc) = extract_outer_meta(handshake_msg)?;
    if sym != state.sym || config_id != state.config_id || !enc.is_empty() {
        return Err(Error::EchDecryptionFailed);
    }

    let plaintext = state
        .receiver
        .open(&aad, &ciphertext)
        .map_err(|_| Error::EchDecryptionFailed)?;
    let unpadded = strip_trailing_padding(&plaintext)?;
    // Same inner-marker requirement as on the CH1 path (draft §7.1).
    require_inner_marker(&unpadded)?;
    decompress_inner_against_outer(&unpadded, handshake_msg)
}

/// Walks the outer CH to find the `encrypted_client_hello` extension
/// and returns `(sym, config_id, enc_bytes)` parsed from its outer
/// form.
fn extract_outer_meta(handshake_msg: &[u8]) -> Result<(HpkeSymCipherSuite, u8, Vec<u8>), Error> {
    // Walk to the extensions block.
    let body = handshake_msg.get(4..).ok_or(Error::EchDecodeError)?;
    let mut idx = 0usize;
    let need = |idx: usize, n: usize| -> Result<(), Error> {
        if idx + n > body.len() {
            Err(Error::EchDecodeError)
        } else {
            Ok(())
        }
    };
    need(idx, 2 + 32 + 1)?;
    idx += 2 + 32;
    let sid_len = body[idx] as usize;
    idx += 1;
    need(idx, sid_len + 2)?;
    idx += sid_len;
    let cs_len = ((body[idx] as usize) << 8) | (body[idx + 1] as usize);
    idx += 2;
    need(idx, cs_len + 1)?;
    idx += cs_len;
    let cm_len = body[idx] as usize;
    idx += 1;
    need(idx, cm_len + 2)?;
    idx += cm_len;
    let ext_total = ((body[idx] as usize) << 8) | (body[idx + 1] as usize);
    idx += 2;
    need(idx, ext_total)?;
    let ext_start = idx;
    let ext_end = idx + ext_total;
    let mut p = ext_start;
    while p < ext_end {
        if p + 4 > ext_end {
            return Err(Error::EchDecodeError);
        }
        let ty = ((body[p] as u16) << 8) | (body[p + 1] as u16);
        let bl = ((body[p + 2] as usize) << 8) | (body[p + 3] as usize);
        let body_start = p + 4;
        let body_end = body_start + bl;
        if body_end > ext_end {
            return Err(Error::EchDecodeError);
        }
        if ty == crate::tls::codec::ExtensionType::ENCRYPTED_CLIENT_HELLO.0 {
            let ext_body = &body[body_start..body_end];
            let ext = EchExtension::decode(ext_body)?;
            match ext {
                EchExtension::Outer {
                    cipher_suite,
                    config_id,
                    enc,
                    ..
                } => return Ok((cipher_suite, config_id, enc)),
                EchExtension::Inner => return Err(Error::EchDecodeError),
            }
        }
        p = body_end;
    }
    Err(Error::EchDecodeError)
}

/// Walks the inner CH extensions and requires exactly one
/// `encrypted_client_hello` extension carrying the inner-form body
/// (`type = inner`). The inner-marker is mandatory per
/// draft-ietf-tls-esni-22 §7.1 — without it the decrypted CH is
/// indistinguishable from a non-ECH CH and a network attacker could
/// have crafted the ciphertext from a plain CH the client never
/// intended to be ECH-inner. Returns [`Error::EchDecodeError`] if the
/// marker is missing, malformed, or duplicated; that error maps to
/// the `illegal_parameter(47)` alert at the alert layer.
fn require_inner_marker(inner_ch: &[u8]) -> Result<(), Error> {
    // inner_ch = u8 msg_type ++ u24 length ++ body. We already
    // verified the framing in strip_trailing_padding so the indices
    // below are guaranteed in-bounds, but keep the bounds checks
    // defensive in case the helper is called in isolation.
    if inner_ch.len() < 4 || inner_ch[0] != crate::tls::codec::hs_type::CLIENT_HELLO {
        return Err(Error::EchDecodeError);
    }
    let body_len =
        ((inner_ch[1] as usize) << 16) | ((inner_ch[2] as usize) << 8) | (inner_ch[3] as usize);
    if 4 + body_len != inner_ch.len() {
        return Err(Error::EchDecodeError);
    }
    let body = &inner_ch[4..];
    let mut idx = 0usize;
    let need = |idx: usize, n: usize| -> Result<(), Error> {
        if idx + n > body.len() {
            Err(Error::EchDecodeError)
        } else {
            Ok(())
        }
    };
    need(idx, 2 + 32 + 1)?;
    idx += 2 + 32;
    let sid_len = body[idx] as usize;
    idx += 1;
    need(idx, sid_len + 2)?;
    idx += sid_len;
    let cs_len = ((body[idx] as usize) << 8) | (body[idx + 1] as usize);
    idx += 2;
    need(idx, cs_len + 1)?;
    idx += cs_len;
    let cm_len = body[idx] as usize;
    idx += 1;
    need(idx, cm_len + 2)?;
    idx += cm_len;
    let ext_total = ((body[idx] as usize) << 8) | (body[idx + 1] as usize);
    idx += 2;
    need(idx, ext_total)?;
    let ext_start = idx;
    let ext_end = idx + ext_total;
    let mut p = ext_start;
    let mut found = false;
    while p < ext_end {
        if p + 4 > ext_end {
            return Err(Error::EchDecodeError);
        }
        let ty = ((body[p] as u16) << 8) | (body[p + 1] as u16);
        let bl = ((body[p + 2] as usize) << 8) | (body[p + 3] as usize);
        let body_start = p + 4;
        let body_end = body_start + bl;
        if body_end > ext_end {
            return Err(Error::EchDecodeError);
        }
        if ty == crate::tls::codec::ExtensionType::ENCRYPTED_CLIENT_HELLO.0 {
            if found {
                return Err(Error::EchDecodeError);
            }
            let ext_body = &body[body_start..body_end];
            match EchExtension::decode(ext_body)? {
                EchExtension::Inner => {}
                EchExtension::Outer { .. } => return Err(Error::EchDecodeError),
            }
            found = true;
        }
        p = body_end;
    }
    if !found {
        return Err(Error::EchDecodeError);
    }
    Ok(())
}

/// Strips trailing zero padding from a decrypted padded inner CH and
/// returns the inner CH wire bytes. The inner CH is a complete
/// handshake message with header + length, so anything past the
/// declared length is padding (must all be zero).
fn strip_trailing_padding(padded: &[u8]) -> Result<Vec<u8>, Error> {
    if padded.len() < 4 || padded[0] != crate::tls::codec::hs_type::CLIENT_HELLO {
        return Err(Error::EchDecodeError);
    }
    let body_len =
        ((padded[1] as usize) << 16) | ((padded[2] as usize) << 8) | (padded[3] as usize);
    let total = 4 + body_len;
    if total > padded.len() {
        return Err(Error::EchDecodeError);
    }
    if padded[total..].iter().any(|b| *b != 0) {
        return Err(Error::EchDecodeError);
    }
    Ok(padded[..total].to_vec())
}
