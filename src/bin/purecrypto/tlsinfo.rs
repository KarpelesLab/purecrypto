//! Shared `s_client` / `s_server` pieces: the negotiated-parameter report
//! both print after a handshake (one `key: value` line per parameter, so a
//! harness can grep a single line per fact), and the parsers for the flags
//! both accept (`-groups`, `-ciphersuites`, `-rpk_peer_key`).

use crate::util::{Args, die};
use purecrypto::tls::{Connection, NamedGroup, ProtocolVersion};

/// Which end of the connection is reporting; a few lines differ.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    Client,
    Server,
}

/// Prints the negotiated parameters of a completed TLS handshake to stderr:
///
/// ```text
/// cipher suite: TLS_AES_128_GCM_SHA256
/// key exchange: X25519MLKEM768
/// HelloRetryRequest: no
/// resumed: no
/// early data: none
/// peer certificate: X.509 (2)
/// peer certificate compression: none
/// own certificate: raw public key
/// own certificate compression: zlib
/// OCSP staple: no
/// record_size_limit: not negotiated
/// ```
///
/// The `own certificate` line is printed only where this side sent one
/// (always on a server; on a client only under mTLS).
pub(crate) fn report_handshake(conn: &Connection, role: Role) {
    let version = conn.negotiated_version();
    eprintln!(
        "cipher suite: {}",
        conn.negotiated_cipher_suite_name().unwrap_or("unknown")
    );
    eprintln!(
        "key exchange: {}",
        conn.negotiated_group()
            .map(NamedGroup::name)
            .unwrap_or("none")
    );
    if version == Some(ProtocolVersion::TLSv1_3) {
        eprintln!(
            "HelloRetryRequest: {}",
            yes_no(conn.hello_retry_request_used())
        );
    }
    eprintln!("resumed: {}", yes_no(conn.resumed()));
    if version == Some(ProtocolVersion::TLSv1_3) {
        let early = if conn.early_data_accepted() {
            "accepted"
        } else if conn.early_data_offered() {
            "rejected"
        } else {
            "none"
        };
        eprintln!("early data: {early}");
    }
    let peer_certs = conn.peer_certificates().len();
    if conn.peer_raw_public_key() {
        eprintln!("peer certificate: raw public key");
    } else if peer_certs > 0 {
        eprintln!("peer certificate: X.509 ({peer_certs})");
    } else {
        eprintln!("peer certificate: none");
    }
    #[cfg(feature = "cert-compression")]
    if role == Role::Client {
        eprintln!(
            "peer certificate compression: {}",
            compression_name(conn.peer_cert_compression())
        );
    }
    if role == Role::Server || conn.own_raw_public_key() {
        eprintln!(
            "own certificate: {}",
            if conn.own_raw_public_key() {
                "raw public key"
            } else {
                "X.509"
            }
        );
    }
    #[cfg(feature = "cert-compression")]
    if role == Role::Server {
        eprintln!(
            "own certificate compression: {}",
            compression_name(conn.own_cert_compression())
        );
    }
    if role == Role::Client && version == Some(ProtocolVersion::TLSv1_3) {
        eprintln!(
            "OCSP staple: {}",
            yes_no(conn.peer_ocsp_response().is_some())
        );
    }
    if version == Some(ProtocolVersion::TLSv1_3) {
        eprintln!(
            "record_size_limit: {}",
            if conn.record_size_limit_negotiated() {
                "negotiated"
            } else {
                "not negotiated"
            }
        );
    }
}

/// Prints, once the data phase is over, the post-handshake `KeyUpdate`
/// tally (RFC 8446 §4.6.3) and whether the peer ended the session with a
/// `close_notify` (§6.1) rather than a bare TCP close:
///
/// ```text
/// KeyUpdate: sent 1, received 1
/// close_notify: received
/// ```
pub(crate) fn report_session_end(conn: &Connection) {
    if conn.negotiated_version() == Some(ProtocolVersion::TLSv1_3) {
        eprintln!(
            "KeyUpdate: sent {}, received {}",
            conn.sent_key_updates(),
            conn.peer_key_updates()
        );
    }
    eprintln!(
        "close_notify: {}",
        if conn.received_close_notify() {
            "received"
        } else {
            "not received"
        }
    );
}

fn yes_no(b: bool) -> &'static str {
    if b { "yes" } else { "no" }
}

#[cfg(feature = "cert-compression")]
fn compression_name(alg: Option<u16>) -> &'static str {
    match alg {
        None => "none",
        Some(1) => "zlib",
        Some(2) => "brotli",
        Some(3) => "zstd",
        Some(_) => "unknown",
    }
}

/// `-groups x25519:secp256r1` (colon- or comma-separated, as `openssl
/// -groups` takes it), in preference order.
pub(crate) fn parse_groups(list: &str, flag: &str) -> Vec<NamedGroup> {
    let groups: Vec<NamedGroup> = list
        .split([':', ','])
        .filter(|g| !g.is_empty())
        .map(|g| crate::util::parse_group(g, flag))
        .collect();
    if groups.is_empty() {
        die(format!("{flag}: expects at least one group"));
    }
    groups
}

/// `-ciphersuites TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256`
/// (colon- or comma-separated IANA names, as `openssl -ciphersuites` takes
/// them), in preference order, as wire identifiers.
pub(crate) fn parse_ciphersuites(list: &str, flag: &str) -> Vec<u16> {
    let suites: Vec<u16> = list
        .split([':', ','])
        .filter(|s| !s.is_empty())
        .map(|s| match s.to_ascii_uppercase().as_str() {
            "TLS_AES_128_GCM_SHA256" => 0x1301,
            "TLS_AES_256_GCM_SHA384" => 0x1302,
            "TLS_CHACHA20_POLY1305_SHA256" => 0x1303,
            _ => die(format!(
                "{flag}: unknown TLS 1.3 cipher suite '{s}' (TLS_AES_128_GCM_SHA256, \
                 TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256)"
            )),
        })
        .collect();
    if suites.is_empty() {
        die(format!("{flag}: expects at least one cipher suite"));
    }
    suites
}

/// Loads a `-rpk_peer_key` file: one or more `PUBLIC KEY` PEM blocks (as
/// `pkey -pubout` / `openssl pkey -pubout` write), returned as DER
/// `SubjectPublicKeyInfo`s for the RFC 7250 allowlist.
pub(crate) fn load_spki_pems(path: &str, flag: &str) -> Vec<Vec<u8>> {
    let pem = std::fs::read_to_string(path)
        .unwrap_or_else(|e| die(format!("{flag}: cannot read {path}: {e}")));
    let mut out = Vec::new();
    let mut rest = pem.as_str();
    while let Some(start) = rest.find("-----BEGIN PUBLIC KEY-----") {
        let block = &rest[start..];
        let end = block
            .find("-----END PUBLIC KEY-----")
            .map(|i| i + "-----END PUBLIC KEY-----".len())
            .unwrap_or_else(|| die(format!("{flag}: unterminated PEM block in {path}")));
        let der = purecrypto::der::pem_decode(&block[..end], "PUBLIC KEY")
            .unwrap_or_else(|e| die(format!("{flag}: {path}: {e:?}")));
        out.push(der);
        rest = &block[end..];
    }
    if out.is_empty() {
        die(format!("{flag}: no PUBLIC KEY PEM block in {path}"));
    }
    out
}

/// `-record_size_limit N` (RFC 8449: 64..=16385).
pub(crate) fn parse_record_size_limit(args: &Args) -> Option<u16> {
    args.value("-record_size_limit").map(|v| {
        let n: u16 = v
            .parse()
            .unwrap_or_else(|_| die("-record_size_limit expects a number"));
        if !(64..=16385).contains(&n) {
            die("-record_size_limit: RFC 8449 allows 64..=16385");
        }
        n
    })
}
