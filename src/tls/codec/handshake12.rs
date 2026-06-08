//! TLS 1.2-only handshake message structures (RFC 5246 + RFC 4492).
//!
//! These messages do not exist in TLS 1.3 (which collapsed the ECDHE
//! parameters and signature into `CertificateVerify` and dropped the
//! separate `ClientKeyExchange`/`ServerHelloDone` steps). They are kept in
//! a separate module from the TLS 1.3 codec so the two protocol paths
//! cannot accidentally cross-pollinate.
//!
//! All structs here are wired into the codec but the *consumers* (state
//! machines for client12/server12) land in commit 3 and later, so the
//! items are flagged `#[allow(dead_code)]`.

#![allow(dead_code)]

use super::{
    NamedGroup, ReadCursor, SignatureScheme, handshake::hs_type, put_u8, put_u16, with_len_u8,
    with_len_u16, with_len_u24,
};
use crate::tls::Error;
use alloc::vec::Vec;

/// `ServerKeyExchange` for ECDHE cipher suites (RFC 5246 §7.4.3, RFC 4492 §5.4).
///
/// Wire form:
/// ```text
/// struct {
///     ECCurveType    curve_type;       // 0x03 = named_curve
///     NamedCurve     namedcurve;       // u16
///     opaque         point<1..2^8-1>;  // u8-length-prefixed
///     SignatureAndHashAlgorithm algorithm;     // 2 bytes (hash | sig)
///     opaque         signature<0..2^16-1>;
/// }
/// ```
///
/// The TLS 1.2 `SignatureAndHashAlgorithm` is two separate bytes (hash | sig),
/// but its on-wire layout is exactly the u16 carried by the IANA-assigned
/// `SignatureScheme` codes used in TLS 1.3 (RFC 5246 §7.4.1.4.1 — the modern
/// codepoint registry was retro-fitted onto the same two-byte slot). Encoding
/// the value as a [`SignatureScheme`] u16 round-trips losslessly.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServerKeyExchange {
    pub(crate) group: NamedGroup,
    pub(crate) point: Vec<u8>,
    pub(crate) scheme: SignatureScheme,
    pub(crate) signature: Vec<u8>,
}

impl ServerKeyExchange {
    /// Encodes the full handshake message (type + u24 length + body).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u8(&mut out, hs_type::SERVER_KEY_EXCHANGE);
        with_len_u24(&mut out, |b| {
            put_u8(b, 0x03); // curve_type = named_curve
            put_u16(b, self.group.0);
            with_len_u8(b, |p| p.extend_from_slice(&self.point));
            put_u16(b, self.scheme.0);
            with_len_u16(b, |s| s.extend_from_slice(&self.signature));
        });
        out
    }

    /// Decodes a `ServerKeyExchange` from a handshake-message body (the bytes
    /// after the 4-byte handshake header).
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut c = ReadCursor::new(body);
        let curve_type = c.u8()?;
        if curve_type != 0x03 {
            // Only `named_curve` is supported; `explicit_prime`/`explicit_char2`
            // were deprecated and have no modern use.
            return Err(Error::IllegalParameter);
        }
        let group = NamedGroup(c.u16()?);
        let point = c.vec_u8()?.to_vec();
        let scheme = SignatureScheme(c.u16()?);
        let signature = c.vec_u16()?.to_vec();
        c.expect_empty()?;
        Ok(ServerKeyExchange {
            group,
            point,
            scheme,
            signature,
        })
    }
}

#[cfg(feature = "tls-legacy")]
impl ServerKeyExchange {
    /// Encodes a TLS 1.0/1.1 ECDHE `ServerKeyExchange`. Identical to the
    /// TLS 1.2 form ([`Self::encode`]) except the 2-byte
    /// `SignatureAndHashAlgorithm` is absent — it did not exist before TLS 1.2,
    /// so the `signature<0..2^16-1>` follows the `point` directly. The `scheme`
    /// field is ignored on this path: pre-1.2 RSA signatures are raw PKCS#1 v1.5
    /// over `MD5(params) ‖ SHA1(params)` and ECDSA signs `SHA1(params)`, both
    /// implied by the certificate's key type rather than carried on the wire.
    pub(crate) fn encode_legacy(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u8(&mut out, hs_type::SERVER_KEY_EXCHANGE);
        with_len_u24(&mut out, |b| {
            put_u8(b, 0x03); // curve_type = named_curve
            put_u16(b, self.group.0);
            with_len_u8(b, |p| p.extend_from_slice(&self.point));
            with_len_u16(b, |s| s.extend_from_slice(&self.signature));
        });
        out
    }

    /// Decodes a TLS 1.0/1.1 ECDHE `ServerKeyExchange` (no
    /// `SignatureAndHashAlgorithm`). The `scheme` field is set to the zero
    /// placeholder; callers on the legacy path recover the signature algorithm
    /// from the negotiated suite's signature kind, not from the message.
    pub(crate) fn decode_legacy(body: &[u8]) -> Result<Self, Error> {
        let mut c = ReadCursor::new(body);
        let curve_type = c.u8()?;
        if curve_type != 0x03 {
            return Err(Error::IllegalParameter);
        }
        let group = NamedGroup(c.u16()?);
        let point = c.vec_u8()?.to_vec();
        let signature = c.vec_u16()?.to_vec();
        c.expect_empty()?;
        Ok(ServerKeyExchange {
            group,
            point,
            scheme: SignatureScheme(0),
            signature,
        })
    }
}

/// Builds the byte string the server signs in a TLS 1.2 ECDHE
/// `ServerKeyExchange` (RFC 5246 §7.4.3 / RFC 4492 §5.4):
///
/// ```text
///     client_random (32) ‖ server_random (32) ‖
///     curve_type (0x03) ‖ namedcurve (u16) ‖
///     point<1..2^8-1>
/// ```
///
/// This is exposed because the message lives in the codec but the
/// `client_random` / `server_random` come from the connection state.
pub(crate) fn signed_message(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    group: NamedGroup,
    point: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32 + 1 + 2 + 1 + point.len());
    out.extend_from_slice(client_random);
    out.extend_from_slice(server_random);
    out.push(0x03); // curve_type = named_curve
    out.extend_from_slice(&group.0.to_be_bytes());
    with_len_u8(&mut out, |p| p.extend_from_slice(point));
    out
}

/// `ClientKeyExchange` for ECDHE cipher suites (RFC 4492 §5.7).
///
/// Wire form is just the client's ephemeral EC point inside a `u8`-length
/// prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClientKeyExchange {
    pub(crate) point: Vec<u8>,
}

impl ClientKeyExchange {
    /// Encodes the full handshake message (type + u24 length + body).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u8(&mut out, hs_type::CLIENT_KEY_EXCHANGE);
        with_len_u24(&mut out, |b| {
            with_len_u8(b, |p| p.extend_from_slice(&self.point));
        });
        out
    }

    /// Decodes a `ClientKeyExchange` from a handshake-message body.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut c = ReadCursor::new(body);
        let point = c.vec_u8()?.to_vec();
        c.expect_empty()?;
        Ok(ClientKeyExchange { point })
    }
}

/// `CertificateRequest` for TLS 1.2 (RFC 5246 §7.4.4). This wire format is
/// distinct from TLS 1.3's `CertificateRequest` (RFC 8446 §4.3.2), which
/// carries extensions instead.
///
/// Wire form:
/// ```text
/// struct {
///     ClientCertificateType certificate_types<1..2^8-1>;
///     SignatureAndHashAlgorithm supported_signature_algorithms<2..2^16-2>;
///     DistinguishedName certificate_authorities<0..2^16-1>;
/// }
/// ```
///
/// Each `DistinguishedName` is a u16-length-prefixed opaque DER blob.
///
/// Standard certificate type codes (RFC 5246 §7.4.4):
/// - 1 = rsa_sign
/// - 64 = ecdsa_sign
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CertificateRequest12 {
    pub(crate) cert_types: Vec<u8>,
    pub(crate) sig_schemes: Vec<SignatureScheme>,
    pub(crate) cas: Vec<Vec<u8>>,
}

impl CertificateRequest12 {
    /// Encodes the full handshake message (type + u24 length + body).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u8(&mut out, hs_type::CERTIFICATE_REQUEST);
        with_len_u24(&mut out, |b| {
            with_len_u8(b, |t| t.extend_from_slice(&self.cert_types));
            with_len_u16(b, |s| {
                for sch in &self.sig_schemes {
                    put_u16(s, sch.0);
                }
            });
            with_len_u16(b, |cas| {
                for ca in &self.cas {
                    with_len_u16(cas, |d| d.extend_from_slice(ca));
                }
            });
        });
        out
    }

    /// Decodes a `CertificateRequest12` from a handshake-message body.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut c = ReadCursor::new(body);
        let cert_types = c.vec_u8()?.to_vec();

        let sig_bytes = c.vec_u16()?;
        // RFC 5246 §7.4.4 requires this list to be a multiple of 2 bytes (one
        // SignatureAndHashAlgorithm per entry).
        if sig_bytes.len() % 2 != 0 {
            return Err(Error::Decode);
        }
        let mut sig_cur = ReadCursor::new(sig_bytes);
        let mut sig_schemes = Vec::with_capacity(sig_bytes.len() / 2);
        while !sig_cur.is_empty() {
            sig_schemes.push(SignatureScheme(sig_cur.u16()?));
        }

        let ca_bytes = c.vec_u16()?;
        let mut ca_cur = ReadCursor::new(ca_bytes);
        let mut cas = Vec::new();
        while !ca_cur.is_empty() {
            cas.push(ca_cur.vec_u16()?.to_vec());
        }

        c.expect_empty()?;
        Ok(CertificateRequest12 {
            cert_types,
            sig_schemes,
            cas,
        })
    }
}

/// `ServerHelloDone` (RFC 5246 §7.4.5). Empty body; signals that the server is
/// done with its half of the key-exchange phase. TLS 1.2 only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct ServerHelloDone;

impl ServerHelloDone {
    /// Encodes the 4-byte handshake header (type = 14, length = 0).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4);
        put_u8(&mut out, hs_type::SERVER_HELLO_DONE);
        with_len_u24(&mut out, |_| {});
        out
    }

    /// Decodes a `ServerHelloDone` body — must be empty.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Error> {
        if !body.is_empty() {
            return Err(Error::Decode);
        }
        Ok(ServerHelloDone)
    }
}

/// `NewSessionTicket` for TLS 1.2 (RFC 5077 §3.3). The wire format is much
/// simpler than the TLS 1.3 message of the same name — just a 32-bit lifetime
/// hint followed by the opaque ticket bytes.
///
/// Wire form:
/// ```text
/// struct {
///     uint32 ticket_lifetime_hint;
///     opaque ticket<0..2^16-1>;
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NewSessionTicket12 {
    pub(crate) lifetime: u32,
    pub(crate) ticket: Vec<u8>,
}

impl NewSessionTicket12 {
    /// Encodes the full handshake message (type + u24 length + body).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_u8(&mut out, hs_type::NEW_SESSION_TICKET);
        with_len_u24(&mut out, |b| {
            b.extend_from_slice(&self.lifetime.to_be_bytes());
            with_len_u16(b, |t| t.extend_from_slice(&self.ticket));
        });
        out
    }

    /// Decodes a `NewSessionTicket12` from a handshake-message body.
    pub(crate) fn decode(body: &[u8]) -> Result<Self, Error> {
        let mut c = ReadCursor::new(body);
        let lifetime = c.take(4)?;
        let lifetime = u32::from_be_bytes([lifetime[0], lifetime[1], lifetime[2], lifetime[3]]);
        let ticket = c.vec_u16()?.to_vec();
        c.expect_empty()?;
        Ok(NewSessionTicket12 { lifetime, ticket })
    }
}

/// `HelloRequest` (RFC 5246 §7.4.1.1). Empty body. The server uses this to
/// prompt the client to renegotiate. We provide only an encoder; we never
/// accept it after the handshake (commit 6 hardens that path).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct HelloRequest;

impl HelloRequest {
    /// Encodes the 4-byte handshake header (type = 0, length = 0).
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4);
        put_u8(&mut out, hs_type::HELLO_REQUEST);
        with_len_u24(&mut out, |_| {});
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::codec::read_handshake;

    /// Helper: encode `m`, parse its handshake header via `read_handshake`,
    /// and return the body bytes (so each test can re-decode them).
    fn parse_one(bytes: &[u8], expected_ty: u8) -> Vec<u8> {
        let mut c = ReadCursor::new(bytes);
        let (ty, body) = read_handshake(&mut c).unwrap();
        assert_eq!(ty, expected_ty);
        body.to_vec()
    }

    #[test]
    fn server_key_exchange_roundtrip() {
        let ske = ServerKeyExchange {
            group: NamedGroup::SECP256R1,
            point: alloc::vec![0x04; 65], // uncompressed P-256 point shape
            scheme: SignatureScheme::ECDSA_SECP256R1_SHA256,
            signature: alloc::vec![0xab; 72],
        };
        let bytes = ske.encode();
        let body = parse_one(&bytes, hs_type::SERVER_KEY_EXCHANGE);
        assert_eq!(ServerKeyExchange::decode(&body).unwrap(), ske);
    }

    #[cfg(feature = "tls-legacy")]
    #[test]
    fn server_key_exchange_legacy_roundtrip() {
        // The TLS 1.0/1.1 SKE omits the 2-byte SignatureAndHashAlgorithm, so
        // the legacy encoding is exactly 2 bytes shorter than the 1.2 form and
        // decode_legacy recovers the params + signature (scheme = placeholder).
        let ske = ServerKeyExchange {
            group: NamedGroup::SECP256R1,
            point: alloc::vec![0x04; 65],
            scheme: SignatureScheme(0),
            signature: alloc::vec![0xcd; 256], // raw PKCS#1 v1.5 over MD5‖SHA1
        };
        let legacy = ske.encode_legacy();
        let modern = ske.encode();
        assert_eq!(legacy.len() + 2, modern.len());
        let body = parse_one(&legacy, hs_type::SERVER_KEY_EXCHANGE);
        assert_eq!(ServerKeyExchange::decode_legacy(&body).unwrap(), ske);
    }

    #[test]
    fn server_key_exchange_truncated() {
        // body says curve_type=0x03 then a NamedGroup but no point/sig left.
        let body = [0x03u8, 0x00, 0x17];
        assert!(matches!(
            ServerKeyExchange::decode(&body),
            Err(Error::Decode)
        ));
    }

    #[test]
    fn server_key_exchange_rejects_explicit_curve() {
        // curve_type = 0x01 (explicit_prime) — must be rejected.
        let body = [
            0x01u8, // explicit_prime
            0x00, 0x17, // would-be NamedGroup
        ];
        assert!(matches!(
            ServerKeyExchange::decode(&body),
            Err(Error::IllegalParameter)
        ));
    }

    #[test]
    fn client_key_exchange_roundtrip() {
        let cke = ClientKeyExchange {
            point: alloc::vec![0x04; 65],
        };
        let bytes = cke.encode();
        let body = parse_one(&bytes, hs_type::CLIENT_KEY_EXCHANGE);
        assert_eq!(ClientKeyExchange::decode(&body).unwrap(), cke);
    }

    #[test]
    fn client_key_exchange_truncated() {
        // Body claims a 65-byte point but only one byte follows the prefix.
        let body = [65u8, 0x04];
        assert!(matches!(
            ClientKeyExchange::decode(&body),
            Err(Error::Decode)
        ));
    }

    #[test]
    fn certificate_request_12_roundtrip() {
        let cr = CertificateRequest12 {
            cert_types: alloc::vec![1u8, 64u8], // rsa_sign, ecdsa_sign
            sig_schemes: alloc::vec![
                SignatureScheme::ED25519,
                SignatureScheme::ECDSA_SECP256R1_SHA256,
                SignatureScheme::RSA_PSS_RSAE_SHA256,
            ],
            cas: alloc::vec![alloc::vec![0xdeu8; 16], alloc::vec![0xadu8; 8],],
        };
        let bytes = cr.encode();
        let body = parse_one(&bytes, hs_type::CERTIFICATE_REQUEST);
        assert_eq!(CertificateRequest12::decode(&body).unwrap(), cr);
    }

    #[test]
    fn certificate_request_12_empty_cas() {
        // Real-world servers often send an empty CA list.
        let cr = CertificateRequest12 {
            cert_types: alloc::vec![1u8, 64u8],
            sig_schemes: alloc::vec![SignatureScheme::ECDSA_SECP256R1_SHA256],
            cas: Vec::new(),
        };
        let bytes = cr.encode();
        let body = parse_one(&bytes, hs_type::CERTIFICATE_REQUEST);
        assert_eq!(CertificateRequest12::decode(&body).unwrap(), cr);
    }

    #[test]
    fn certificate_request_12_truncated() {
        // cert_types list claims 3 bytes but only 1 follows.
        let body = [3u8, 0x01];
        assert!(matches!(
            CertificateRequest12::decode(&body),
            Err(Error::Decode)
        ));
    }

    #[test]
    fn certificate_request_12_odd_sig_list() {
        // cert_types = [1], then sig_schemes list is 3 bytes (not a multiple
        // of 2) — must be rejected.
        let body = [
            1u8, 0x01, // cert_types: [1]
            0x00, 0x03, // sig_schemes outer length = 3
            0x04, 0x03, 0x05, // dangling odd byte
            0x00, 0x00, // empty CA list
        ];
        assert!(matches!(
            CertificateRequest12::decode(&body),
            Err(Error::Decode)
        ));
    }

    #[test]
    fn server_hello_done_roundtrip() {
        let bytes = ServerHelloDone.encode();
        assert_eq!(bytes, alloc::vec![hs_type::SERVER_HELLO_DONE, 0, 0, 0]);
        let body = parse_one(&bytes, hs_type::SERVER_HELLO_DONE);
        assert_eq!(ServerHelloDone::decode(&body).unwrap(), ServerHelloDone);
    }

    #[test]
    fn server_hello_done_rejects_nonempty_body() {
        assert!(matches!(
            ServerHelloDone::decode(&[0x00]),
            Err(Error::Decode)
        ));
    }

    #[test]
    fn hello_request_encode() {
        let bytes = HelloRequest.encode();
        assert_eq!(bytes, alloc::vec![hs_type::HELLO_REQUEST, 0, 0, 0]);
    }

    #[test]
    fn new_session_ticket_12_roundtrip() {
        let nst = NewSessionTicket12 {
            lifetime: 7200,
            ticket: alloc::vec![0xab; 64],
        };
        let bytes = nst.encode();
        let body = parse_one(&bytes, hs_type::NEW_SESSION_TICKET);
        assert_eq!(NewSessionTicket12::decode(&body).unwrap(), nst);
    }

    #[test]
    fn new_session_ticket_12_empty_ticket() {
        // RFC 5077 §3.3: ticket length is `0..2^16-1`; the server MAY send an
        // empty ticket (clients treat it as "no resumption was issued").
        let nst = NewSessionTicket12 {
            lifetime: 0,
            ticket: Vec::new(),
        };
        let bytes = nst.encode();
        let body = parse_one(&bytes, hs_type::NEW_SESSION_TICKET);
        assert_eq!(NewSessionTicket12::decode(&body).unwrap(), nst);
    }

    #[test]
    fn new_session_ticket_12_truncated() {
        // Body claims a 4-byte lifetime but only 3 bytes.
        let body = [0u8, 0, 0];
        assert!(matches!(
            NewSessionTicket12::decode(&body),
            Err(Error::Decode)
        ));
    }

    #[test]
    fn signed_message_layout() {
        let cr = [0x11u8; 32];
        let sr = [0x22u8; 32];
        let point = [0x04u8, 0xaa, 0xbb, 0xcc];
        let m = signed_message(&cr, &sr, NamedGroup::SECP256R1, &point);

        let mut expected = Vec::new();
        expected.extend_from_slice(&cr);
        expected.extend_from_slice(&sr);
        expected.push(0x03); // curve_type
        expected.extend_from_slice(&NamedGroup::SECP256R1.0.to_be_bytes());
        expected.push(point.len() as u8);
        expected.extend_from_slice(&point);

        assert_eq!(m, expected);
    }

    #[test]
    fn ec_point_formats_roundtrip() {
        use crate::tls::codec::extension::{ec_point_formats, parse_ec_point_formats};
        let (_, body) = ec_point_formats();
        // u8-length(1) || uncompressed(0).
        assert_eq!(body, alloc::vec![1u8, 0u8]);
        assert_eq!(parse_ec_point_formats(&body).unwrap(), alloc::vec![0u8]);
    }

    #[test]
    fn ec_point_formats_rejects_length_mismatch() {
        use crate::tls::codec::extension::parse_ec_point_formats;
        // claims length=1 but two payload bytes follow.
        assert!(parse_ec_point_formats(&[1u8, 1u8, 2u8]).is_err());
    }
}
