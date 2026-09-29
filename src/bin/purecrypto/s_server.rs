//! `purecrypto s_server` — minimal TLS 1.2, TLS 1.3, DTLS 1.2, or DTLS 1.3
//! echo / `-www` server, like a pared-down `openssl s_server`. Single-shot:
//! accepts one connection, completes the handshake, exchanges data, closes.
//!
//! Version selection mirrors `s_client`:
//!
//! | flag         | protocol | transport |
//! |--------------|----------|-----------|
//! | (default)    | TLS 1.3  | TCP       |
//! | `-tls1_2`    | TLS 1.2  | TCP       |
//! | `-dtls1_2`   | DTLS 1.2 | UDP       |
//! | `-dtls1_3`   | DTLS 1.3 | UDP       |

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::dtls_io::{self, Clock, Link, Step};
use crate::tlsinfo::{self, Role};
use crate::util::{Args, die, load_cert_chain, open_keylog, parse_alpn, zero_buf};
use purecrypto::rng::OsRng;
use purecrypto::tls::{
    ClientAuth, Config, Connection, HandshakeStatus, ProtocolVersion as PcVersion, RootCertStore,
    SigningKey,
};

/// Which protocol/transport combination the CLI should drive.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ProtocolVersion {
    Tls12,
    Tls13,
    Dtls12,
    Dtls13,
}

impl ProtocolVersion {
    fn to_pc_version(self) -> PcVersion {
        match self {
            ProtocolVersion::Tls12 => PcVersion::TLSv1_2,
            ProtocolVersion::Tls13 => PcVersion::TLSv1_3,
            ProtocolVersion::Dtls12 => PcVersion::DTLSv1_2,
            ProtocolVersion::Dtls13 => PcVersion::DTLSv1_3,
        }
    }
}

/// Resolves the requested protocol from CLI flags. Right-most wins.
fn resolve_version(args: &Args) -> ProtocolVersion {
    let candidates = [
        (args.last_pos("-tls1_2"), ProtocolVersion::Tls12),
        (args.last_pos("--tls1_2"), ProtocolVersion::Tls12),
        (args.last_pos("-dtls1_2"), ProtocolVersion::Dtls12),
        (args.last_pos("--dtls1_2"), ProtocolVersion::Dtls12),
        (args.last_pos("-dtls1_3"), ProtocolVersion::Dtls13),
        (args.last_pos("--dtls1_3"), ProtocolVersion::Dtls13),
    ];
    let mut best: Option<(usize, ProtocolVersion)> = None;
    for (pos, v) in candidates {
        if let Some(p) = pos {
            match best {
                Some((bp, _)) if bp >= p => {}
                _ => best = Some((p, v)),
            }
        }
    }
    best.map(|(_, v)| v).unwrap_or(ProtocolVersion::Tls13)
}

/// `true` iff the rightmost protocol flag on the command line is `-quic`
/// (or `--quic`). Used to decide whether to dispatch to the QUIC driver
/// instead of the TLS / DTLS code path below. Mirrors the right-most-wins
/// semantics of [`resolve_version`].
fn has_latest_quic(args: &Args) -> bool {
    let quic_pos = args.last_pos("-quic").max(args.last_pos("--quic"));
    let Some(qp) = quic_pos else {
        return false;
    };
    for name in [
        "-tls1_2",
        "--tls1_2",
        "-tls1_3",
        "--tls1_3",
        "-dtls1_2",
        "--dtls1_2",
        "-dtls1_3",
        "--dtls1_3",
    ] {
        if let Some(op) = args.last_pos(name)
            && op > qp
        {
            return false;
        }
    }
    true
}

/// Loads a PEM CA bundle into a RootCertStore.
fn load_roots_file(path: &str) -> RootCertStore {
    let mut store = RootCertStore::new();
    crate::util::load_pem_certs_into(path, |pem| store.add_pem(pem));
    store
}

/// Reads a server key from PEM as a unified [`SigningKey`].
fn load_signing_key(key_path: &str) -> SigningKey {
    crate::util::warn_if_world_readable_key(key_path);
    let key_pem = std::fs::read_to_string(key_path)
        .unwrap_or_else(|e| die(format!("cannot read key file {key_path}: {e}")));
    crate::util::signing_key_from_pem(&key_pem).unwrap_or_else(|| {
        die(format!(
            "{key_path}: server key must be RSA (PKCS#1 or PKCS#8), ECDSA (SEC1 or PKCS#8), \
             Ed25519 or Ed448 (PKCS#8)"
        ))
    })
}

pub(crate) fn run(args: Args) {
    // -quic dispatches to the QUIC-specific UDP driver. Right-most
    // wins between -quic / -tls1_* / -dtls1_*.
    if has_latest_quic(&args) {
        crate::quic_cli::run_server(args);
        return;
    }
    let version = resolve_version(&args);
    // A server that only serves an external PSK (RFC 8446 §2.2: a PSK
    // handshake sends no certificate) needs no `-cert` / `-key`.
    let psk_only = args.value("-psk").is_some() && args.value("-cert").is_none();
    let identity = match (args.value("-cert"), args.value("-key")) {
        (Some(c), Some(k)) => Some((c, k)),
        (None, None) if psk_only => None,
        _ => die(
            "usage: purecrypto s_server -cert cert.pem -key key.pem -accept PORT \
             [-tls1_2 | -dtls1_2 | -dtls1_3] [-min_protocol TLSv1.2] [-Verify ca.pem] \
             [-alpn h2,http/1.1] [-www] [-naccept N] [-mtu N] [-no_cookie] \
             [-groups x25519:secp256r1] [-prefer-group NAME] \
             [-ciphersuites TLS_AES_128_GCM_SHA256:...] [-no_ticket] \
             [-early_data [-max_early_data N]] [-key_update] [-status_file resp.der] \
             [-enable_server_rpk] [-enable_client_rpk -rpk_peer_key pub.pem] \
             [-record_size_limit N] [-no_cert_comp] [-cid HEX | -cid_len N] \
             [-keylogfile keys.log] \
             [-ech-key key.bin -ech-config config.bin] [-psk_modes psk_dhe_ke:psk_ke] \
             [-psk_identity NAME -psk HEX [-psk_hash sha384] [-psk_import [-psk_context STR]]] (-cert/-key may be \
             omitted with -psk: a PSK-only TLS 1.3 server)",
        ),
    };
    let verify_ca = args.value("-Verify");
    let alpn = args.value("-alpn").map(parse_alpn);
    let www = args.flag("-www") || args.flag("--www");
    let quiet = args.flag("-quiet") || args.flag("--quiet");
    let no_cookie = args.flag("-no_cookie") || args.flag("--no_cookie");
    let mtu: usize = args
        .value("-mtu")
        .unwrap_or("1200")
        .parse()
        .unwrap_or_else(|_| die("-mtu expects a number"));
    let keylog = args.value("-keylogfile").map(open_keylog);
    let naccept: usize = args
        .value("-naccept")
        .unwrap_or("1")
        .parse()
        .ok()
        .filter(|n| *n >= 1)
        .unwrap_or_else(|| die("-naccept expects a positive number"));
    let no_ticket = args.flag("-no_ticket") || args.flag("--no_ticket");
    let early_data = args.flag("-early_data") || args.flag("--early_data");
    let key_update = args.flag("-key_update") || args.flag("--key_update");
    let enable_server_rpk = args.flag("-enable_server_rpk") || args.flag("--enable_server_rpk");
    let enable_client_rpk = args.flag("-enable_client_rpk") || args.flag("--enable_client_rpk");
    let no_cert_comp = args.flag("-no_cert_comp") || args.flag("--no_cert_comp");
    let is_tcp = matches!(version, ProtocolVersion::Tls12 | ProtocolVersion::Tls13);
    if (naccept > 1 || early_data || enable_server_rpk || enable_client_rpk) && !is_tcp {
        die("-naccept / -early_data / -enable_*_rpk are TLS-over-TCP options");
    }
    // DTLS 1.3 rekeys with KeyUpdate too (RFC 9147 §8); DTLS 1.2 has no
    // such mechanism.
    if key_update && !matches!(version, ProtocolVersion::Tls13 | ProtocolVersion::Dtls13) {
        die("-key_update needs TLS 1.3 or DTLS 1.3");
    }
    // RFC 9146 connection IDs (DTLS): this server receives under `-cid
    // HEX` or a random `-cid_len N`-byte one, and follows the client to a
    // new address when its records say so (see `dtls_io::Link`).
    let cid = crate::util::dtls_cid_option(&args, !is_tcp);
    // `-min_protocol TLSv1.2` widens the pinned TLS 1.3 server into one
    // that also accepts TLS 1.2 clients (the engine is picked from the
    // ClientHello).
    let min_version = match args.value("-min_protocol") {
        None => version.to_pc_version(),
        Some("TLSv1.2") | Some("tls1_2") if version == ProtocolVersion::Tls13 => PcVersion::TLSv1_2,
        Some("TLSv1.3") | Some("tls1_3") if version == ProtocolVersion::Tls13 => PcVersion::TLSv1_3,
        Some(v) => die(format!(
            "-min_protocol: '{v}' is not TLSv1.2 or TLSv1.3 (the flag applies to TLS over TCP)"
        )),
    };

    let mut builder = Config::builder()
        .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
        .versions(min_version, version.to_pc_version())
        .max_record_size(mtu);
    let mut own_spki = None;
    if let Some((cert_path, key_path)) = identity {
        let chain = load_cert_chain(cert_path);
        let key = load_signing_key(key_path);
        // The (D)TLS 1.2 server engines sign with RSA, ECDSA, Ed25519 or Ed448
        // (RFC 8422); nothing specifies ML-DSA for that version, and such a key
        // is rejected by `Connection::server` as a bare `UnsupportedVersion` —
        // after `accept()`, so the first client just sees a reset. Say why, up
        // front.
        if matches!(version, ProtocolVersion::Tls12 | ProtocolVersion::Dtls12)
            && !matches!(
                key,
                SigningKey::Rsa(_)
                    | SigningKey::Ecdsa(_)
                    | SigningKey::Ed25519(_)
                    | SigningKey::Ed448(_)
            )
        {
            die(format!(
                "{key_path}: -tls1_2 / -dtls1_2 require an RSA, ECDSA, Ed25519 or Ed448 server key \
                 (ML-DSA is not specified for TLS 1.2)"
            ));
        }

        // RFC 7250: `-enable_server_rpk` lets a client that offers
        // `server_certificate_type = RawPublicKey` receive this key's bare
        // SubjectPublicKeyInfo instead of the chain (X.509 stays available).
        if enable_server_rpk {
            own_spki = Some(
                key.public_key()
                    .unwrap_or_else(|| die("-enable_server_rpk: the server key has no public half"))
                    .to_spki_der(),
            );
        }
        builder = builder
            .try_identity(chain, key)
            .unwrap_or_else(|e| die(crate::util::identity_error(cert_path, key_path, e)));
    } else if enable_server_rpk {
        die("-enable_server_rpk needs -cert and -key");
    } else if min_version != PcVersion::TLSv1_3 || version != ProtocolVersion::Tls13 {
        die(
            "a PSK-only server (no -cert / -key) must be TLS 1.3 over TCP: drop -tls1_2 / -min_protocol / -dtls1_*",
        );
    }
    if let Some(a) = alpn {
        builder = builder.alpn(a);
    }
    if let Some(sink) = keylog {
        builder = builder.key_log(sink);
    }
    if let Some(spki) = own_spki {
        builder = builder
            .server_cert_type_preference(vec![2, 0])
            .raw_public_key_spki(spki);
    }
    // `-enable_client_rpk`: accept a client identity presented as a raw
    // public key, authenticated against the `-rpk_peer_key` allowlist (a
    // raw key has no chain, so the list is the whole trust root).
    if enable_client_rpk {
        let pins = args.value("-rpk_peer_key").unwrap_or_else(|| {
            die("-enable_client_rpk needs -rpk_peer_key FILE (accepted client public keys, PEM)")
        });
        builder = builder.client_cert_type_preference(vec![2, 0]);
        for spki in tlsinfo::load_spki_pems(pins, "-rpk_peer_key") {
            builder = builder.add_expected_client_raw_public_key(spki);
        }
    }
    // `-groups`: the accept-set, in server preference order; a client that
    // shared none of them but offered one is sent a HelloRetryRequest.
    if let Some(list) = args.value("-groups") {
        builder = builder.key_exchange_groups(&tlsinfo::parse_groups(list, "-groups"));
    }
    // `-ciphersuites`: the TLS 1.3 accept-set, in server preference order.
    if let Some(list) = args.value("-ciphersuites") {
        builder = builder.cipher_suites(&tlsinfo::parse_ciphersuites(list, "-ciphersuites"));
    }
    if let Some(n) = tlsinfo::parse_record_size_limit(&args) {
        builder = builder.record_size_limit(n);
    }
    #[cfg(feature = "cert-compression")]
    if no_cert_comp {
        builder = builder.cert_compression_algorithms(Vec::new());
    }
    #[cfg(not(feature = "cert-compression"))]
    let _ = no_cert_comp;
    // `-status_file`: a DER OCSPResponse stapled for clients that ask
    // (RFC 6066 §8; the TLS 1.3 leaf `status_request` entry, RFC 8446
    // §4.4.2.1, or the TLS 1.2 CertificateStatus message).
    if let Some(path) = args.value("-status_file") {
        let der = std::fs::read(path)
            .unwrap_or_else(|e| die(format!("cannot read -status_file {path}: {e}")));
        builder = builder.stapled_ocsp_response(der);
    }
    // Session tickets are issued by default, as `openssl s_server` does,
    // under a per-process random key: a client that reconnects to this
    // same process can resume. `-no_ticket` turns them off; `-early_data`
    // additionally accepts 0-RTT on a resumed connection (echoed back like
    // any other data — this is a test server; early data is replayable).
    if is_tcp && !no_ticket {
        let mut ticket_key = [0u8; 32];
        purecrypto::rng::RngCore::fill_bytes(&mut OsRng, &mut ticket_key);
        builder = builder.ticket_key(ticket_key);
        zero_buf(&mut ticket_key);
        if early_data {
            let max: u32 = args
                .value("-max_early_data")
                .unwrap_or("16384")
                .parse()
                .unwrap_or_else(|_| die("-max_early_data expects a number"));
            builder = builder.max_early_data(max);
        }
    } else if early_data {
        die("-early_data needs session tickets (drop -no_ticket)");
    }
    // `-prefer-group` makes the server answer a ClientHello that did not
    // pre-share a key for NAME with a HelloRetryRequest (RFC 8446 §4.1.4).
    if let Some(name) = args.value("-prefer-group") {
        builder =
            builder.preferred_key_exchange_group(crate::util::parse_group(name, "-prefer-group"));
    }
    let builder = tlsinfo::apply_psk_flags(&args, builder, version == ProtocolVersion::Tls13);
    let (mut builder, ech) = crate::ech::apply_server(&args, builder);
    if ech && version != ProtocolVersion::Tls13 {
        die("-ech-key / -ech-config require TLS 1.3 over TCP (drop -tls1_2 / -dtls1_2 / -dtls1_3)");
    }
    if let Some(p) = verify_ca {
        let roots = load_roots_file(p);
        builder = builder.client_auth(ClientAuth::new(roots, true));
    }
    builder = crate::util::apply_dtls_cid(builder, cid.clone());
    if matches!(version, ProtocolVersion::Dtls12 | ProtocolVersion::Dtls13) {
        if no_cookie {
            builder = builder.no_cookie();
        } else {
            let mut secret = [0u8; 32];
            purecrypto::rng::RngCore::fill_bytes(&mut OsRng, &mut secret);
            builder = builder.cookie_secret(secret);
            // `cookie_secret` copies the array into a wiping `Secret32`,
            // so our stack copy survives; scrub it as `pc_quic_new` does
            // for the QUIC retry secret (commit 316e8a2).
            zero_buf(&mut secret);
        }
    }
    let cfg = builder.build();

    match version {
        ProtocolVersion::Tls12 | ProtocolVersion::Tls13 => {
            // `-accept 0` asks the kernel for a free port. The banner below
            // reports the address that was actually bound, so a harness can
            // read the port back from it instead of probing for a free one
            // itself (a probe-then-release port can be taken by another
            // process before the server binds it).
            let port: u16 = args
                .value("-accept")
                .unwrap_or("4433")
                .parse()
                .unwrap_or_else(|_| die("-accept expects a port number"));
            let listener = TcpListener::bind(("127.0.0.1", port))
                .unwrap_or_else(|e| die(format!("cannot bind 127.0.0.1:{port}: {e}")));
            let bound = listener
                .local_addr()
                .unwrap_or_else(|e| die(format!("cannot read the bound address: {e}")));
            if !quiet {
                eprintln!("listening on {bound}");
            }
            // `-naccept N`: N sequential connections, sharing the ticket key
            // so the later ones can resume the earlier ones.
            for i in 0..naccept {
                let (mut sock, peer) = accept_with_deadline(&listener, ACCEPT_DEADLINE);
                if !quiet {
                    if naccept > 1 {
                        eprintln!("=== connection {}", i + 1);
                    }
                    eprintln!("accepted connection from {peer}");
                }
                let mut conn = Connection::server(&cfg)
                    .unwrap_or_else(|e| die(format!("server config rejected: {e:?}")));
                run_tcp(&mut conn, &mut sock, www, quiet, ech, key_update);
            }
        }
        ProtocolVersion::Dtls12 | ProtocolVersion::Dtls13 => {
            let accept = args.value("-accept").unwrap_or("127.0.0.1:4434");
            // `-accept` takes `host:port` or a bare `PORT` (including `0` for
            // a kernel-chosen one), matching the TCP and QUIC servers; a bare
            // port binds 127.0.0.1.
            let accept = if accept.contains(':') {
                accept.to_string()
            } else {
                format!("127.0.0.1:{accept}")
            };
            run_udp(&cfg, &accept, mtu, quiet, key_update, cid.is_some());
        }
    }
}

/// How long the single-shot TCP server waits for its one client before
/// giving up, so a client that never connects (a failed test, a mistyped
/// port) cannot leave the process blocked in `accept()` forever. The DTLS
/// path bounds its first `recv_from` the same way.
const ACCEPT_DEADLINE: Duration = Duration::from_secs(60);

/// `TcpListener::accept` with a deadline: std has no accept timeout, so the
/// listener is polled non-blocking until a client arrives or `deadline`
/// elapses. The accepted stream is returned in blocking mode (on the BSDs an
/// accepted socket inherits the listener's non-blocking flag).
fn accept_with_deadline(listener: &TcpListener, deadline: Duration) -> (TcpStream, SocketAddr) {
    listener
        .set_nonblocking(true)
        .unwrap_or_else(|e| die(format!("cannot poll the listener: {e}")));
    let start = Instant::now();
    loop {
        match listener.accept() {
            Ok((sock, peer)) => {
                sock.set_nonblocking(false)
                    .unwrap_or_else(|e| die(format!("accept failed: {e}")));
                return (sock, peer);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if start.elapsed() > deadline {
                    die(format!("no client connected within {deadline:?}"));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => die(format!("accept failed: {e}")),
        }
    }
}

fn run_tcp(
    conn: &mut Connection,
    sock: &mut TcpStream,
    www: bool,
    quiet: bool,
    ech: bool,
    key_update: bool,
) {
    drive_tcp_handshake(conn, sock, ech);
    // The handshake loop stops at `Complete` without draining what that
    // last step queued (the NewSessionTicket): put it on the wire now, so a
    // client that only came for a ticket is not left waiting for data.
    flush_out(conn, sock);

    if !quiet {
        let v_str = match conn.negotiated_version() {
            Some(PcVersion::TLSv1_2) => "TLSv1.2",
            Some(PcVersion::TLSv1_3) => "TLSv1.3",
            #[cfg(feature = "tls-legacy")]
            Some(PcVersion::TLSv1_1) => "TLSv1.1",
            #[cfg(feature = "tls-legacy")]
            Some(PcVersion::TLSv1_0) => "TLSv1.0",
            _ => "?",
        };
        eprintln!("handshake complete: {v_str}");
        if let Some(name) = conn.peer_server_name() {
            eprintln!("SNI: {name}");
        }
        crate::ech::report_server(conn, ech);
        if let Some(p) = conn.alpn_selected() {
            eprintln!("ALPN: {}", String::from_utf8_lossy(p));
        }
        if !conn.peer_certificates().is_empty() {
            eprintln!(
                "client presented {} certificate(s)",
                conn.peer_certificates().len()
            );
        }
        tlsinfo::report_handshake(conn, Role::Server);
    }

    // 0-RTT the handshake accepted is replayable (RFC 8446 §8); this test
    // server echoes it like any other input, so a client can see it landed.
    let early = conn.take_early_data().unwrap_or_default();
    if !early.is_empty() {
        if !quiet {
            eprintln!("early data: {} bytes", early.len());
        }
        let _ = conn.send(&early);
        flush_out(conn, sock);
    }
    // `-key_update`: rekey before the first byte of application data
    // (RFC 8446 §4.6.3) and ask the client to rekey too.
    if key_update {
        conn.request_key_update()
            .unwrap_or_else(|e| die(format!("KeyUpdate refused: {e:?}")));
        flush_out(conn, sock);
    }

    sock.set_read_timeout(Some(Duration::from_secs(5))).ok();
    if www {
        // For `-www` the response is canned, so we send it immediately
        // and only optionally drain the request afterwards. This avoids
        // a deadlock when both peers race their own 5-second read
        // timeout: the client (with nothing to send) sits in `sock.read`
        // waiting for the response while the server (waiting for the
        // request) sits in its own `sock.read` waiting for the request.
        //
        // We do still drain any pre-buffered plaintext that the engine
        // may have decoded during the handshake — the client's
        // ClientFinished and first app-data record commonly arrive in
        // the same TCP segment on macOS (Nagle coalescing), and the
        // handshake loop's last `feed` will have decrypted both.
        let _ = conn.recv();
        let body = b"hello from purecrypto s_server\n";
        let resp = format!(
            "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = conn.send(resp.as_bytes());
        let _ = conn.send(body);
        // Send a TLS-level close_notify, drain the engine, then
        // half-close the TCP socket. Without the half-close, dropping
        // the `TcpStream` raced against macOS's send-buffer-flush
        // behavior and was truncating the reply on a slow runner.
        let _ = conn.close();
        let out = conn.pop().unwrap_or_default();
        let _ = sock.write_all(&out);
        let _ = sock.flush();
        let _ = sock.shutdown(std::net::Shutdown::Write);
        let mut tail = [0u8; 256];
        let _ = sock.read(&mut tail);
    } else {
        // Echo mode: same `recv` pre-drain reason as above.
        let plain = conn.recv().unwrap_or_default();
        if !plain.is_empty()
            && let Ok(()) = conn.send(&plain)
        {
            let out = conn.pop().unwrap_or_default();
            if !out.is_empty() {
                let _ = sock.write_all(&out);
            }
        }
        let mut buf = [0u8; 4096];
        loop {
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if conn.feed(&buf[..n]).is_err() {
                        break;
                    }
                    // A KeyUpdate reply the engine owes the client goes out
                    // before any echo under the new key.
                    flush_out(conn, sock);
                    let plain = conn.recv().unwrap_or_default();
                    if !plain.is_empty() {
                        if conn.send(&plain).is_err() {
                            break;
                        }
                        let out = conn.pop().unwrap_or_default();
                        if !out.is_empty() && sock.write_all(&out).is_err() {
                            break;
                        }
                    }
                    // The peer said goodbye: answer in kind and stop, rather
                    // than idling until the read timeout.
                    if conn.received_close_notify() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        // End the session with a close_notify (RFC 8446 §6.1) so the client
        // can tell a clean end of stream from a cut one — its own truncation
        // warning fires on a bare FIN. `-www` already does this above.
        let _ = conn.close();
        let out = conn.pop().unwrap_or_default();
        if !out.is_empty() {
            let _ = sock.write_all(&out);
            let _ = sock.flush();
        }
        let _ = sock.shutdown(std::net::Shutdown::Write);
    }
    if !quiet {
        tlsinfo::report_session_end(conn);
    }
}

/// Writes whatever the engine has queued (a KeyUpdate, an echo, an alert).
fn flush_out(conn: &mut Connection, sock: &mut TcpStream) {
    if let Ok(out) = conn.pop()
        && !out.is_empty()
    {
        let _ = sock.write_all(&out);
        let _ = sock.flush();
    }
}

/// Fails the handshake, first reporting what the server saw of the
/// ClientHello (SNI, ECH) — the useful part when a client aborts after an
/// ECH rejection — and flushing any alert the engine queued.
fn handshake_failed(
    conn: &mut Connection,
    sock: &mut TcpStream,
    ech: bool,
    what: &str,
    e: purecrypto::tls::Error,
) -> ! {
    if let Ok(out) = conn.pop()
        && !out.is_empty()
    {
        let _ = sock.write_all(&out);
        let _ = sock.flush();
    }
    if let Some(name) = conn.peer_server_name() {
        eprintln!("SNI: {name}");
    }
    crate::ech::report_server(conn, ech);
    die(format!("{what}: {e:?}"))
}

fn drive_tcp_handshake(conn: &mut Connection, sock: &mut TcpStream, ech: bool) {
    let mut read_buf = [0u8; 8192];
    loop {
        let out = conn.pop().unwrap_or_default();
        if !out.is_empty() {
            sock.write_all(&out)
                .unwrap_or_else(|e| die(format!("socket write: {e}")));
        }
        match conn.handshake() {
            Ok(HandshakeStatus::Complete) => return,
            Ok(HandshakeStatus::WantWrite) => continue,
            Ok(HandshakeStatus::WantRead) => {
                let n = sock
                    .read(&mut read_buf)
                    .unwrap_or_else(|e| die(format!("socket read: {e}")));
                if n == 0 {
                    die("peer closed during handshake");
                }
                if let Err(e) = conn.feed(&read_buf[..n]) {
                    handshake_failed(conn, sock, ech, "TLS feed failed", e);
                }
            }
            Err(e) => handshake_failed(conn, sock, ech, "TLS handshake failed", e),
        }
    }
}

fn run_udp(cfg: &Config, accept: &str, mtu: usize, quiet: bool, key_update: bool, with_cid: bool) {
    let socket =
        UdpSocket::bind(accept).unwrap_or_else(|e| die(format!("cannot bind UDP {accept}: {e}")));
    let bound = socket.local_addr().ok();
    if !quiet {
        match bound {
            Some(addr) => eprintln!("listening on {addr} (DTLS / UDP)"),
            None => eprintln!("listening on {accept} (DTLS / UDP)"),
        }
    }
    let mut buf = vec![0u8; mtu.max(1500) + 256];
    socket.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let (n, peer) = socket
        .recv_from(&mut buf)
        .unwrap_or_else(|e| die(format!("UDP recv (initial) failed: {e}")));
    if !quiet {
        eprintln!("accepted handshake start from {peer}");
    }
    buf.truncate(n);
    // With connection IDs the socket stays unconnected: the client may
    // move to another address mid-connection, and the link follows it
    // under the RFC 9146 §6 rules. Without them a moved client cannot be
    // recognised anyway, and a connected socket reports it gone (ICMP).
    let mut link = if with_cid {
        Link::addressed(socket, peer)
    } else {
        socket
            .connect(peer)
            .unwrap_or_else(|e| die(format!("UDP connect to peer {peer}: {e}")));
        Link::connected(socket)
    };

    // Bind the DTLS cookie to the source address we just learned. Without
    // it a cookie-requiring server refuses to handshake at all (an
    // address-independent cookie is replayable from any spoofed source),
    // and with it the cookie becomes a real return-routability proof.
    let mut cfg = cfg.clone();
    cfg.peer_address = {
        let mut a = Vec::with_capacity(18);
        match peer.ip() {
            std::net::IpAddr::V4(v4) => a.extend_from_slice(&v4.to_ipv6_mapped().octets()),
            std::net::IpAddr::V6(v6) => a.extend_from_slice(&v6.octets()),
        }
        a.extend_from_slice(&peer.port().to_be_bytes());
        a
    };
    let mut conn =
        Connection::server(&cfg).unwrap_or_else(|e| die(format!("server config rejected: {e:?}")));
    // One clock for the connection's whole life: the engine's timers are
    // expressed in it (see `dtls_io`).
    let clock = Clock::start();
    conn.set_now(clock.now());
    let _ = conn.feed(&buf);

    drive_udp_handshake(&mut conn, &mut link, &clock, mtu);

    if !quiet {
        let v_str = match conn.negotiated_version() {
            Some(PcVersion::DTLSv1_2) => "DTLSv1.2",
            Some(PcVersion::DTLSv1_3) => "DTLSv1.3",
            _ => "?",
        };
        eprintln!("handshake complete: {v_str}");
        if let Some(p) = conn.alpn_selected() {
            eprintln!("ALPN: {}", String::from_utf8_lossy(p));
        }
        tlsinfo::report_handshake(&conn, Role::Server);
    }
    // `-key_update`: rekey before the first byte of application data
    // (RFC 9147 §8) and ask the client to rekey too.
    if key_update {
        conn.set_now(clock.now());
        conn.request_key_update()
            .unwrap_or_else(|e| die(format!("KeyUpdate refused: {e:?}")));
        dtls_io::flush(&mut conn, &link);
    }
    drive_udp_echo(
        &mut conn,
        &mut link,
        &clock,
        mtu,
        Duration::from_secs(5),
        quiet,
    );
    if !quiet {
        tlsinfo::report_session_end(&conn);
    }
    let _ = peer;
    let _: Option<SocketAddr> = bound;
}

fn drive_udp_handshake(conn: &mut Connection, link: &mut Link, clock: &Clock, mtu: usize) {
    let mut buf = vec![0u8; mtu.max(1500) + 256];
    while !conn.is_handshake_complete() {
        if clock.now() > dtls_io::HANDSHAKE_DEADLINE {
            die("DTLS handshake deadline exceeded");
        }
        // The retransmit timer fires on the engine's own schedule (1 s,
        // doubling: RFC 6347 §4.2.4.1 / RFC 9147 §5.8.2), on the
        // connection's clock; see the matching note in `s_client`.
        match dtls_io::step(conn, link, clock, &mut buf) {
            Ok(Step::Datagram | Step::Quiet) => {}
            Ok(Step::Gone) => die("UDP recv failed: the client is unreachable"),
            Err(e) => die(format!("DTLS handshake failed: {e:?}")),
        }
    }
    // The flight that completed the handshake (the final flight, ACKs).
    dtls_io::flush(conn, link);
}

/// Echoes the application data in `plain`; `false` when the engine
/// refuses to send.
fn echo(conn: &mut Connection, plain: &[u8]) -> bool {
    plain.is_empty() || conn.send(plain).is_ok()
}

/// Echoes application data until the client says goodbye (its close_notify
/// is answered in kind) or `idle_limit` passes without a datagram; the
/// session then ends with this side's close_notify (RFC 8446 §6.1 / RFC
/// 5246 §7.2.1). The engine's retransmit timer (a KeyUpdate in flight) is
/// fired on the way.
///
/// A client that has not been heard from since the handshake is given
/// longer than `idle_limit`: it may still be inside its handshake — the
/// last thing this side sent (the ACK for its Finished on DTLS 1.3, the
/// ChangeCipherSpec + Finished flight on DTLS 1.2) was lost — and then it
/// retransmits its Finished on a backoff that outgrows the idle limit. A
/// close_notify sent into that gap fails its handshake.
fn drive_udp_echo(
    conn: &mut Connection,
    link: &mut Link,
    clock: &Clock,
    mtu: usize,
    idle_limit: Duration,
    quiet: bool,
) {
    let mut buf = vec![0u8; mtu.max(1500) + 256];
    let mut last_activity = Instant::now();
    loop {
        if conn.received_close_notify() {
            break;
        }
        if last_activity.elapsed() > idle_limit {
            if conn.handshake_flight_pending() {
                dtls_io::settle(conn, link, clock, &mut buf, |conn, plain| {
                    echo(conn, &plain);
                });
                if !conn.handshake_flight_pending() && !conn.received_close_notify() {
                    // The client has just shown up: back to echoing.
                    last_activity = Instant::now();
                    continue;
                }
            }
            break;
        }
        match dtls_io::step(conn, link, clock, &mut buf) {
            Ok(Step::Datagram) => {
                last_activity = Instant::now();
                // The client moved (RFC 9146 §6: an authenticated, newer
                // record under its connection ID from a new address); the
                // echo below already goes there.
                if let Some((old, new)) = link.take_move()
                    && !quiet
                {
                    eprintln!("peer address updated: {old} -> {new}");
                }
                // (A KeyUpdate reply the engine owed the client went out
                // in `step`, before any echo under the new key.)
                let plain = conn.recv().unwrap_or_default();
                if !echo(conn, &plain) {
                    break;
                }
                dtls_io::flush(conn, link);
            }
            Ok(Step::Quiet) => {}
            Ok(Step::Gone) | Err(_) => break,
        }
    }
    let _ = conn.close();
    dtls_io::flush(conn, link);
}
