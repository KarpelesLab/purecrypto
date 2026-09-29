//! `purecrypto s_client` — open a TLS 1.2, TLS 1.3, DTLS 1.2, or DTLS 1.3
//! connection and report the result, like a minimal `openssl s_client`.
//!
//! Version selection is via mutually-exclusive flags:
//!
//! | flag          | protocol      | transport |
//! |---------------|---------------|-----------|
//! | (default)     | TLS 1.3       | TCP       |
//! | `-tls1_2`     | TLS 1.2       | TCP       |
//! | `-dtls1_2`    | DTLS 1.2      | UDP       |
//! | `-dtls1_3`    | DTLS 1.3      | UDP       |
//!
//! If more than one is given, the rightmost (latest on the command line)
//! wins — matching how `openssl s_client` resolves conflicting protocol
//! flags. The dedicated `s_dtls_client` binary is a convenience shim
//! around `s_client -dtls1_2`.

use std::io::{IsTerminal, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use crate::dtls_io::{self, Clock, Step};
use crate::pki::format_dn;
use crate::tlsinfo::{self, Role};
use crate::util::{Args, die, load_cert_chain, open_keylog, parse_alpn};
use purecrypto::tls::{
    Config, Connection, HandshakeStatus, ProtocolVersion as PcVersion, RootCertStore, SigningKey,
};
use purecrypto::x509::Certificate;

/// Everything the TCP driver needs besides the connection and the socket.
struct TcpOpts<'a> {
    insecure: bool,
    showcerts: bool,
    quiet: bool,
    /// `-key_update`: send `KeyUpdate(update_requested)` right after the
    /// handshake, before any application data.
    key_update: bool,
    /// The 0-RTT payload written before the handshake (`-early_data` on the
    /// resumed connection), re-sent as ordinary data if the server rejected
    /// it (RFC 8446 §4.2.10).
    early_data: Option<&'a [u8]>,
    /// `-read_timeout`: how long to wait for more data from the server
    /// after the last byte before ending the session with close_notify.
    read_timeout: Duration,
    ech: &'a crate::ech::ClientEch,
}

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

/// Resolves the requested protocol from CLI flags. The rightmost protocol
/// flag wins (matches openssl behaviour); if none are given, defaults to
/// TLS 1.3.
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

/// Loads trust roots: from `ca_file` if given, else the embedded `cacrt`
/// bundle (portable, no filesystem access — unlike an OS bundle path).
fn load_roots(ca_file: Option<&str>) -> RootCertStore {
    match ca_file {
        Some(path) => {
            let mut store = RootCertStore::new();
            crate::util::load_pem_certs_into(path, |pem| store.add_pem(pem));
            store
        }
        None => RootCertStore::with_embedded_roots(),
    }
}

fn print_chain(chain: &[Vec<u8>], showcerts: bool) {
    eprintln!("peer certificate chain ({} certs):", chain.len());
    for (i, der) in chain.iter().enumerate() {
        match Certificate::from_der(der.clone()) {
            Ok(cert) => {
                let subject = cert.subject().map(|d| format_dn(&d)).unwrap_or_default();
                let issuer = cert.issuer().map(|d| format_dn(&d)).unwrap_or_default();
                eprintln!("  [{i}] subject: {subject}");
                eprintln!("      issuer:  {issuer}");
                if let Ok(v) = cert.validity() {
                    eprintln!(
                        "      valid:   {} .. {}",
                        v.not_before.as_str(),
                        v.not_after.as_str()
                    );
                }
                if showcerts {
                    eprint!("{}", cert.to_pem());
                }
            }
            Err(_) => eprintln!("  [{i}] <unparseable certificate>"),
        }
    }
}

/// Parses a comma-separated ALPN list ("h2,http/1.1") into a Vec<Vec<u8>>.
/// Loads a client identity (cert chain + key) from `-cert` + `-key` paths.
fn load_client_identity(cert_path: &str, key_path: &str) -> (Vec<Vec<u8>>, SigningKey) {
    let chain = load_cert_chain(cert_path);
    crate::util::warn_if_world_readable_key(key_path);
    let key_pem = std::fs::read_to_string(key_path)
        .unwrap_or_else(|e| die(format!("cannot read key file {key_path}: {e}")));
    let key = crate::util::signing_key_from_pem(&key_pem).unwrap_or_else(|| {
        die(format!(
            "{key_path}: client cert key must be RSA (PKCS#1 or PKCS#8), ECDSA (SEC1 or PKCS#8), \
             Ed25519 or Ed448 (PKCS#8)"
        ))
    });
    (chain, key)
}

pub(crate) fn run(args: Args) {
    // -quic dispatches to the QUIC-specific UDP driver. We treat -quic
    // as the highest-priority protocol flag — if any other version flag
    // appears later on the command line it takes precedence (right-most
    // wins), so `q_client -tls1_3 ...` still demotes to TLS-over-TCP.
    if has_latest_quic(&args) {
        crate::quic_cli::run_client(args);
        return;
    }
    let version = resolve_version(&args);
    let mut value_flags = vec![
        "-connect",
        "-servername",
        "-CAfile",
        "-alpn",
        "-keylogfile",
        "-cert",
        "-key",
        "-mtu",
        "-key-shares",
        "-groups",
        "-ciphersuites",
        "-early_data",
        "-rpk_peer_key",
        "-record_size_limit",
        "-min_protocol",
        "-read_timeout",
        "-resend",
    ];
    value_flags.extend(crate::ech::CLIENT_VALUE_FLAGS);
    value_flags.extend(tlsinfo::PSK_VALUE_FLAGS);
    let connect = args
        .value("-connect")
        .or_else(|| args.positionals(&value_flags).first().copied())
        .unwrap_or_else(|| {
            die(
                "usage: purecrypto s_client -connect host:port [-tls1_2 | -dtls1_2 | -dtls1_3] [-min_protocol TLSv1.2] [-servername name] [-CAfile bundle.pem] [-insecure] [-showcerts] [-alpn h2,http/1.1] [-cert client.pem -key client.key] [-mtu N] [-key-shares x25519,...] [-groups x25519:secp256r1] [-ciphersuites TLS_AES_128_GCM_SHA256:...] [-reconnect [-early_data FILE]] [-key_update] [-enable_server_rpk -rpk_peer_key pub.pem] [-enable_client_rpk] [-record_size_limit N] [-no_cert_comp] [-read_timeout SECS] [-resend N] [-keylogfile keys.log] [-ech-config-list list.bin [-ech-retry-configs-out FILE] | -ech-grease] [-psk_modes psk_dhe_ke:psk_ke] [-psk_identity NAME -psk HEX [-psk_hash sha384] [-psk_import [-psk_context STR]]]",
            )
        });
    let (host, port) = match connect.rsplit_once(':') {
        Some((h, p)) => (
            h,
            p.parse::<u16>()
                .unwrap_or_else(|_| die(format!("invalid port: {p}"))),
        ),
        None => (connect, 443),
    };
    let server_name = args.value("-servername").unwrap_or(host);
    let insecure = args.flag("-insecure") || args.flag("--insecure");
    let showcerts = args.flag("-showcerts") || args.flag("--showcerts");
    let quiet = args.flag("-quiet") || args.flag("--quiet");
    let alpn = args.value("-alpn").map(parse_alpn);
    let mtu: usize = args
        .value("-mtu")
        .unwrap_or("1200")
        .parse()
        .unwrap_or_else(|_| die("-mtu expects a number"));
    let client_id = match (args.value("-cert"), args.value("-key")) {
        (Some(c), Some(k)) => Some((c, k, load_client_identity(c, k))),
        (Some(_), None) | (None, Some(_)) => die("both -cert and -key are required for mTLS"),
        _ => None,
    };
    let keylog = args.value("-keylogfile").map(open_keylog);
    let reconnect = args.flag("-reconnect") || args.flag("--reconnect");
    let key_update = args.flag("-key_update") || args.flag("--key_update");
    let enable_server_rpk = args.flag("-enable_server_rpk") || args.flag("--enable_server_rpk");
    let enable_client_rpk = args.flag("-enable_client_rpk") || args.flag("--enable_client_rpk");
    let no_cert_comp = args.flag("-no_cert_comp") || args.flag("--no_cert_comp");
    let early_data: Option<Vec<u8>> = args.value("-early_data").map(|path| {
        if !reconnect {
            die("-early_data needs -reconnect: 0-RTT rides on the resumed (second) connection");
        }
        std::fs::read(path).unwrap_or_else(|e| die(format!("cannot read -early_data {path}: {e}")))
    });
    let read_timeout = Duration::from_secs(
        args.value("-read_timeout")
            .unwrap_or("5")
            .parse()
            .unwrap_or_else(|_| die("-read_timeout expects a number of seconds")),
    );
    let resend: u32 = args
        .value("-resend")
        .unwrap_or("0")
        .parse()
        .unwrap_or_else(|_| die("-resend expects a number"));
    if resend != 0 && !matches!(version, ProtocolVersion::Dtls12 | ProtocolVersion::Dtls13) {
        die("-resend is a DTLS option: TLS delivers the input reliably");
    }
    let is_tcp = matches!(version, ProtocolVersion::Tls12 | ProtocolVersion::Tls13);
    if (reconnect || enable_server_rpk || enable_client_rpk) && !is_tcp {
        die("-reconnect / -enable_*_rpk are TLS-over-TCP options");
    }
    // DTLS 1.3 rekeys with KeyUpdate too (RFC 9147 §8); DTLS 1.2 has no
    // such mechanism.
    if key_update && !matches!(version, ProtocolVersion::Tls13 | ProtocolVersion::Dtls13) {
        die("-key_update needs TLS 1.3 or DTLS 1.3");
    }
    // `-min_protocol TLSv1.2` widens the pinned TLS 1.3 client into a
    // version-spanning one (1.2..=1.3), so a 1.2-only server can be
    // negotiated with — the fallback `openssl s_client` performs by default.
    let min_version = match args.value("-min_protocol") {
        None => version.to_pc_version(),
        Some("TLSv1.2") | Some("tls1_2") if version == ProtocolVersion::Tls13 => PcVersion::TLSv1_2,
        Some("TLSv1.3") | Some("tls1_3") if version == ProtocolVersion::Tls13 => PcVersion::TLSv1_3,
        Some(v) => die(format!(
            "-min_protocol: '{v}' is not TLSv1.2 or TLSv1.3 (the flag applies to TLS over TCP)"
        )),
    };

    // Build the unified config. Across TLS and DTLS, `-insecure` skips
    // verification; otherwise trust comes from `-CAfile` if supplied, else the
    // embedded `cacrt` bundle (so chain validation works out of the box).
    let roots = if insecure {
        RootCertStore::new()
    } else {
        load_roots(args.value("-CAfile"))
    };

    let mut builder = Config::builder()
        .rng(std::sync::Arc::new(purecrypto::rng::OsRng))
        .versions(min_version, version.to_pc_version())
        .roots(roots)
        .server_name(server_name)
        .verify_certificates(!insecure)
        .max_record_size(mtu);
    if let Some(a) = alpn {
        builder = builder.alpn(a);
    }
    // `-groups x25519:secp256r1`: the `supported_groups` offer, in this
    // order, with a key share for each (see `-key-shares` to narrow those).
    if let Some(list) = args.value("-groups") {
        builder = builder.key_exchange_groups(&tlsinfo::parse_groups(list, "-groups"));
    }
    // `-ciphersuites`: the TLS 1.3 suites offered, in this order.
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
    // RFC 7250 raw public keys. `-enable_server_rpk` offers
    // `server_certificate_type = RawPublicKey` (X.509 still accepted); the
    // server's bare key must then match one of the `-rpk_peer_key` pins,
    // since there is no chain to validate.
    if enable_server_rpk {
        let pins = args.value("-rpk_peer_key").unwrap_or_else(|| {
            die("-enable_server_rpk needs -rpk_peer_key FILE (the server's public key, PEM) to pin")
        });
        builder = builder.server_cert_type_preference(vec![2, 0]);
        for spki in tlsinfo::load_spki_pems(pins, "-rpk_peer_key") {
            builder = builder.add_expected_raw_public_key(spki);
        }
    }
    // `-key-shares x25519,secp256r1`: pre-share keys for these groups only;
    // a server preferring another offered group answers with a
    // HelloRetryRequest.
    if let Some(list) = args.value("-key-shares") {
        let groups: Vec<_> = list
            .split(',')
            .filter(|g| !g.is_empty())
            .map(|g| crate::util::parse_group(g, "-key-shares"))
            .collect();
        builder = builder.key_shares(&groups);
    }
    if let Some((cert_path, key_path, (chain, key))) = client_id {
        // `-enable_client_rpk`: offer to present this identity as a raw
        // public key (`client_certificate_type = RawPublicKey`, X.509 still
        // offered) when the server asks for a certificate.
        if enable_client_rpk {
            let spki = key
                .public_key()
                .unwrap_or_else(|| die("-enable_client_rpk: the client key has no public half"))
                .to_spki_der();
            builder = builder
                .client_cert_type_preference(vec![2, 0])
                .raw_public_key_spki(spki);
        }
        builder = builder
            .try_identity(chain, key)
            .unwrap_or_else(|e| die(crate::util::identity_error(cert_path, key_path, e)));
    } else if enable_client_rpk {
        die("-enable_client_rpk needs -cert and -key (the identity to present as a raw key)");
    }
    if let Some(sink) = keylog {
        builder = builder.key_log(sink);
    }
    let builder = tlsinfo::apply_psk_flags(&args, builder, version == ProtocolVersion::Tls13);
    let (builder, ech) = crate::ech::apply_client(&args, builder);
    // RFC 9849 is a TLS 1.3 mechanism (§6.1: the inner hello MUST NOT offer
    // 1.2), and this stack does not implement it for DTLS.
    if ech.any() && version != ProtocolVersion::Tls13 {
        die("ECH options require TLS 1.3 over TCP (drop -tls1_2 / -dtls1_2 / -dtls1_3)");
    }
    let cfg = builder.build();
    let opts = TcpOpts {
        insecure,
        showcerts,
        quiet,
        key_update,
        early_data: None,
        read_timeout,
        ech: &ech,
    };

    match version {
        ProtocolVersion::Tls12 | ProtocolVersion::Tls13 if reconnect => {
            // `-reconnect`: a first connection whose only purpose is to be
            // issued a session ticket, then a second one that resumes it —
            // carrying `-early_data` as 0-RTT when the ticket allows it.
            let mut conn = Connection::client(&cfg)
                .unwrap_or_else(|e| die(format!("client configuration rejected: {e:?}")));
            let mut sock = TcpStream::connect((host, port))
                .unwrap_or_else(|e| die(format!("TCP connect to {host}:{port} failed: {e}")));
            if !quiet {
                eprintln!("=== connection 1 (full handshake)");
            }
            let session = run_tcp_for_ticket(&mut conn, &mut sock, &opts);
            drop(sock);
            let mut cfg2 = cfg.clone();
            cfg2.resumption = Some(session);
            let mut conn = Connection::client(&cfg2)
                .unwrap_or_else(|e| die(format!("client configuration rejected: {e:?}")));
            if let Some(data) = early_data.as_deref() {
                conn.write_early_data(data).unwrap_or_else(|e| {
                    die(format!(
                        "cannot send early data: {e:?} (the ticket did not permit 0-RTT?)"
                    ))
                });
            }
            let mut sock = TcpStream::connect((host, port))
                .unwrap_or_else(|e| die(format!("TCP connect to {host}:{port} failed: {e}")));
            if !quiet {
                eprintln!("=== connection 2 (resumption offered)");
            }
            let opts = TcpOpts {
                early_data: early_data.as_deref(),
                ..opts
            };
            run_tcp(&mut conn, &mut sock, &opts);
        }
        ProtocolVersion::Tls12 | ProtocolVersion::Tls13 => {
            let mut conn = Connection::client(&cfg)
                .unwrap_or_else(|e| die(format!("client configuration rejected: {e:?}")));
            let mut sock = TcpStream::connect((host, port))
                .unwrap_or_else(|e| die(format!("TCP connect to {host}:{port} failed: {e}")));
            run_tcp(&mut conn, &mut sock, &opts);
        }
        ProtocolVersion::Dtls12 | ProtocolVersion::Dtls13 => {
            let mut conn = Connection::client(&cfg)
                .unwrap_or_else(|e| die(format!("client configuration rejected: {e:?}")));
            let socket = UdpSocket::bind("0.0.0.0:0")
                .unwrap_or_else(|e| die(format!("cannot bind local UDP socket: {e}")));
            socket
                .connect((host, port))
                .unwrap_or_else(|e| die(format!("UDP connect to {host}:{port} failed: {e}")));
            let udp = UdpOpts {
                mtu,
                version,
                insecure,
                showcerts,
                quiet,
                key_update,
                read_timeout,
                resend,
            };
            run_udp(&mut conn, &socket, &udp);
        }
    }
}

/// Everything the UDP (DTLS) driver needs besides the connection and the
/// socket.
struct UdpOpts {
    mtu: usize,
    version: ProtocolVersion,
    insecure: bool,
    showcerts: bool,
    quiet: bool,
    /// `-key_update` (DTLS 1.3): `KeyUpdate(update_requested)` right after
    /// the handshake, before any application data.
    key_update: bool,
    /// `-read_timeout`: how long to wait for more datagrams after the last
    /// one before ending the session with close_notify.
    read_timeout: Duration,
    /// `-resend`: how many more times the input is sent when
    /// `read_timeout` passes without application data from the server.
    resend: u32,
}

/// Handshake + report, shared by the plain and the `-reconnect` flows.
fn tcp_handshake_and_report(conn: &mut Connection, sock: &mut TcpStream, opts: &TcpOpts<'_>) {
    drive_tcp_handshake(conn, sock, opts.ech);
    // The handshake loop stops at `Complete` without draining what that
    // last step queued — our Finished. Put it on the wire now rather than
    // with the first application data: a server that has nothing to read
    // from us (the `-reconnect` ticket wait) would otherwise never see the
    // handshake end.
    flush_out(conn, sock);

    // The "certificate NOT verified" warning is security-relevant: it
    // tells the operator that this connection's peer identity was not
    // checked. We print it to stderr *regardless* of -quiet so an
    // unattended pipeline using `-quiet -insecure` cannot accidentally
    // hide the fact. Match the DTLS path so the two transports speak
    // the same warning string.
    if opts.insecure {
        eprintln!("WARNING: certificate NOT verified (-insecure)");
    }

    if !opts.quiet {
        let v_str = match conn.negotiated_version() {
            Some(PcVersion::TLSv1_2) => "TLSv1.2",
            Some(PcVersion::TLSv1_3) => "TLSv1.3",
            #[cfg(feature = "tls-legacy")]
            Some(PcVersion::TLSv1_1) => "TLSv1.1",
            #[cfg(feature = "tls-legacy")]
            Some(PcVersion::TLSv1_0) => "TLSv1.0",
            _ => "?",
        };
        eprintln!(
            "connected: {v_str}{}",
            if opts.insecure {
                "  (certificate NOT verified)"
            } else {
                "  (certificate verified)"
            }
        );
        if let Some(p) = conn.alpn_selected() {
            eprintln!("ALPN: {}", String::from_utf8_lossy(p));
        }
        crate::ech::report_client(conn, opts.ech);
        tlsinfo::report_handshake(conn, Role::Client);
        print_chain(conn.peer_certificates(), opts.showcerts);
    }
}

fn run_tcp(conn: &mut Connection, sock: &mut TcpStream, opts: &TcpOpts<'_>) {
    tcp_handshake_and_report(conn, sock, opts);
    sock.set_read_timeout(Some(opts.read_timeout)).ok();
    drive_tcp_data(conn, sock, opts);
}

/// The `-reconnect` first connection: handshake, wait for the server's
/// `NewSessionTicket`, say goodbye, and hand the session back. Nothing
/// from stdin is sent on this connection.
///
/// A server need not issue tickets right after the handshake: Apple's
/// Network.framework bundles its NewSessionTickets with its first write —
/// which, for a client that sends nothing, is its close_notify in reply to
/// ours. So after `TICKET_WAIT` without a ticket we send close_notify and
/// keep reading until the peer closes, taking a ticket that arrives with
/// the goodbye.
fn run_tcp_for_ticket(
    conn: &mut Connection,
    sock: &mut TcpStream,
    opts: &TcpOpts<'_>,
) -> purecrypto::tls::ResumptionSession {
    const TICKET_WAIT: Duration = Duration::from_secs(2);
    tcp_handshake_and_report(conn, sock, opts);
    sock.set_read_timeout(Some(Duration::from_millis(250))).ok();
    let start = Instant::now();
    let mut buf = [0u8; 4096];
    let mut closed = false;
    let session = loop {
        if let Some(s) = conn.take_session() {
            break s;
        }
        if !closed && start.elapsed() > TICKET_WAIT {
            let _ = conn.close();
            flush_out(conn, sock);
            let _ = sock.shutdown(std::net::Shutdown::Write);
            closed = true;
        }
        if start.elapsed() > TICKET_WAIT * 2 {
            die("no session ticket arrived within 4 s; cannot -reconnect");
        }
        match sock.read(&mut buf) {
            Ok(0) => die("peer closed before issuing a session ticket"),
            Ok(n) => {
                if let Err(e) = conn.feed(&buf[..n]) {
                    die(format!("TLS error while waiting for a ticket: {e:?}"));
                }
                // Anything the server volunteered (a `-www` page, a banner)
                // is not this connection's business.
                let _ = conn.recv();
                flush_out(conn, sock);
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut => {}
            Err(e) => die(format!("socket read: {e}")),
        }
    };
    if !opts.quiet {
        eprintln!("session ticket received");
    }
    if !closed {
        let _ = conn.close();
        flush_out(conn, sock);
        let _ = sock.shutdown(std::net::Shutdown::Write);
    }
    session
}

/// Writes whatever the engine has queued (a KeyUpdate reply, an alert).
fn flush_out(conn: &mut Connection, sock: &mut TcpStream) {
    if let Ok(out) = conn.pop()
        && !out.is_empty()
    {
        let _ = sock.write_all(&out);
        let _ = sock.flush();
    }
}

fn run_udp(conn: &mut Connection, socket: &UdpSocket, opts: &UdpOpts) {
    // One clock for the connection's whole life: the engine's timers are
    // expressed in it (see `dtls_io`).
    let clock = Clock::start();
    drive_udp_handshake(conn, socket, &clock, opts.mtu);

    // Unconditional security warning — see the TCP path for the rationale.
    if opts.insecure {
        eprintln!("WARNING: certificate NOT verified (-insecure)");
    }

    if !opts.quiet {
        let v_str = match opts.version {
            ProtocolVersion::Dtls12 => "DTLSv1.2",
            ProtocolVersion::Dtls13 => "DTLSv1.3",
            _ => "?",
        };
        eprintln!(
            "connected: {v_str}{}",
            if opts.insecure {
                "  (certificate NOT verified)"
            } else {
                "  (certificate verified)"
            }
        );
        if let Some(p) = conn.alpn_selected() {
            eprintln!("ALPN: {}", String::from_utf8_lossy(p));
        }
        tlsinfo::report_handshake(conn, Role::Client);
        let chain = conn.peer_certificates();
        if !chain.is_empty() {
            print_chain(chain, opts.showcerts);
        }
    }

    drive_udp_data(conn, socket, &clock, opts);
}

/// Fails the handshake: flushes any alert the engine queued (an ECH
/// rejection ends with `ech_required`, RFC 9849 §6.1.6), reports an ECH
/// rejection's `retry_configs`, and exits non-zero.
fn handshake_failed(
    conn: &mut Connection,
    sock: &mut TcpStream,
    ech: &crate::ech::ClientEch,
    what: &str,
    e: purecrypto::tls::Error,
) -> ! {
    if let Ok(out) = conn.pop()
        && !out.is_empty()
    {
        let _ = sock.write_all(&out);
        let _ = sock.flush();
    }
    crate::ech::report_client_error(&e, ech);
    die(format!("{what}: {e:?}"))
}

fn drive_tcp_handshake(conn: &mut Connection, sock: &mut TcpStream, ech: &crate::ech::ClientEch) {
    let mut read_buf = [0u8; 8192];
    loop {
        // Push outbound bytes first.
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

fn drive_tcp_data(conn: &mut Connection, sock: &mut TcpStream, opts: &TcpOpts<'_>) {
    let mut stdout = std::io::stdout();

    // Drain any plaintext the engine already decoded during the
    // handshake — the server may have piggy-backed the
    // CCS/Finished/AppData/close_notify into one TCP segment, in which
    // case the handshake loop's last `feed` already gave us the
    // response (and possibly the EOF too) before we ever entered this
    // function. Print it before we touch the socket.
    let pre = conn.recv().unwrap_or_default();
    if !pre.is_empty() {
        let _ = stdout.write_all(&pre);
    }

    // `-key_update`: rekey before the first byte of application data
    // (RFC 8446 §4.6.3); the request asks the server to rekey too.
    if opts.key_update {
        conn.request_key_update()
            .unwrap_or_else(|e| die(format!("KeyUpdate refused: {e:?}")));
        flush_out(conn, sock);
    }
    // RFC 8446 §4.2.10: early data the server rejected was never
    // delivered; send it again under the 1-RTT keys.
    if let Some(early) = opts.early_data
        && !conn.early_data_accepted()
    {
        let _ = conn.send(early);
        flush_out(conn, sock);
    }

    if !std::io::stdin().is_terminal() {
        let mut input = Vec::new();
        if std::io::stdin().read_to_end(&mut input).is_ok() && !input.is_empty() {
            let _ = conn.send(&input);
            if let Ok(out) = conn.pop() {
                let _ = sock.write_all(&out);
                let _ = sock.flush();
            }
        }
    }

    let mut buf = [0u8; 4096];
    loop {
        match sock.read(&mut buf) {
            Ok(0) => {
                // A TCP EOF is only a clean end of stream if the peer's
                // close_notify came first (RFC 8446 §6.1 / RFC 5246 §7.2.1).
                // Without it, the stream was cut — by the server, or by an
                // on-path attacker injecting a FIN — and whatever we printed
                // may be a truncated response. Say so and fail, like
                // `openssl s_client` reporting "unexpected eof while reading".
                if !conn.received_close_notify() {
                    let _ = stdout.flush();
                    eprintln!(
                        "WARNING: connection closed without close_notify (possible truncation)"
                    );
                    std::process::exit(1);
                }
                break;
            }
            Ok(n) => {
                if let Err(e) = conn.feed(&buf[..n]) {
                    // A record that fails to decrypt / a fatal alert
                    // mid-stream is a broken session, not a clean end.
                    let _ = stdout.flush();
                    die(format!("TLS error after handshake: {e:?}"));
                }
                // The engine answers a `KeyUpdate(update_requested)` with its
                // own KeyUpdate: put it on the wire before anything else
                // goes out under the new key.
                flush_out(conn, sock);
                let plain = conn.recv().unwrap_or_default();
                if !plain.is_empty() && stdout.write_all(&plain).is_err() {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(_) => break,
        }
    }
    // Tell the peer we are done (RFC 8446 §6.1 / RFC 5246 §7.2.1) rather
    // than just dropping the socket: without a close_notify the server sees
    // a bare FIN, which is indistinguishable from a truncation attack — the
    // very thing this client warns about on the receiving side. Failures are
    // ignored (the peer may already be gone).
    if !conn.received_close_notify() {
        let _ = conn.close();
        flush_out(conn, sock);
        let _ = sock.shutdown(std::net::Shutdown::Write);
        // RFC 8446 §6.1: the peer answers our close_notify with its own
        // before closing. Wait (bounded by the read timeout) so a peer that
        // just drops the connection is told apart from one that shuts down
        // cleanly; late application data is still printed.
        while !conn.received_close_notify() {
            match sock.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if conn.feed(&buf[..n]).is_err() {
                        break;
                    }
                    let plain = conn.recv().unwrap_or_default();
                    if !plain.is_empty() {
                        let _ = stdout.write_all(&plain);
                    }
                }
                Err(_) => break,
            }
        }
    }
    let _ = stdout.flush();
    if !opts.quiet {
        tlsinfo::report_session_end(conn);
    }
}

fn drive_udp_handshake(conn: &mut Connection, socket: &UdpSocket, clock: &Clock, mtu: usize) {
    let mut buf = vec![0u8; mtu.max(1500) + 256];
    while !conn.is_handshake_complete() {
        if clock.now() > dtls_io::HANDSHAKE_DEADLINE {
            die("DTLS handshake deadline exceeded");
        }
        // The retransmit timer fires on the engine's own schedule (1 s,
        // doubling: RFC 6347 §4.2.4.1 / RFC 9147 §5.8.2), on the
        // connection's clock.
        match dtls_io::step(conn, socket, clock, &mut buf) {
            Ok(Step::Datagram | Step::Quiet) => {}
            Ok(Step::Gone) => die("UDP recv failed: the server is unreachable"),
            Err(e) => die(format!("DTLS handshake failed: {e:?}")),
        }
    }
    // The flight that completed the handshake (ACKs, our Finished).
    dtls_io::flush(conn, socket);
}

/// What a [`pump_udp`] round saw.
struct Pumped {
    /// Application data arrived.
    data: bool,
    /// The socket reported the server gone, or stdout was closed.
    gone: bool,
}

/// Reads datagrams into the engine until `idle` passes without one (or the
/// peer's close_notify arrives), printing decrypted application data and
/// sending whatever the engine queues in reply; the engine's retransmit
/// timer is fired on the way.
fn pump_udp(
    conn: &mut Connection,
    socket: &UdpSocket,
    clock: &Clock,
    buf: &mut [u8],
    idle: Duration,
    deadline: Duration,
) -> Pumped {
    let mut stdout = std::io::stdout();
    let mut seen = Pumped {
        data: false,
        gone: false,
    };
    let mut last_inbound = Instant::now();
    while clock.now() < deadline && !conn.received_close_notify() {
        match dtls_io::step(conn, socket, clock, buf) {
            Ok(Step::Datagram) => {
                last_inbound = Instant::now();
                let plain = conn.recv().unwrap_or_default();
                if !plain.is_empty() {
                    seen.data = true;
                    if stdout.write_all(&plain).is_err() {
                        seen.gone = true;
                        return seen;
                    }
                }
                let _ = stdout.flush();
                dtls_io::flush(conn, socket);
            }
            Ok(Step::Quiet) => {
                if last_inbound.elapsed() > idle {
                    break;
                }
            }
            Ok(Step::Gone) => {
                seen.gone = true;
                break;
            }
            Err(e) => {
                let _ = stdout.flush();
                die(format!("DTLS error after handshake: {e:?}"));
            }
        }
    }
    let _ = stdout.flush();
    seen
}

/// Prints application data that arrives while the driver is waiting for
/// something else.
fn print_data(_conn: &mut Connection, plain: Vec<u8>) {
    let mut stdout = std::io::stdout();
    let _ = stdout.write_all(&plain);
    let _ = stdout.flush();
}

/// Queues `input` as application data, one record per datagram
/// (application data is not fragmented by the engine, so each record stays
/// under the MTU), and sends it.
fn send_input(conn: &mut Connection, socket: &UdpSocket, input: &[u8], mtu: usize) {
    let chunk = mtu.saturating_sub(64).max(64);
    for piece in input.chunks(chunk) {
        let _ = conn.send(piece);
    }
    dtls_io::flush(conn, socket);
}

fn drive_udp_data(conn: &mut Connection, socket: &UdpSocket, clock: &Clock, opts: &UdpOpts) {
    let mut buf = vec![0u8; opts.mtu.max(1500) + 256];
    // This side is done with the handshake; the server may not be. A DTLS
    // 1.3 client completes when it has *sent* its Finished, and if that
    // datagram is lost the server is still in its handshake, where it
    // discards application data and fails on a close_notify. Keep the
    // retransmission going until the server has acknowledged the Finished
    // (RFC 9147 §5.8.1, §7), bounded, before saying anything.
    dtls_io::settle(conn, socket, clock, &mut buf, print_data);
    // The data phase gets its own budget, on the connection's clock.
    let deadline = clock.now() + Duration::from_secs(30);

    // `-key_update`: rekey before the first byte of application data
    // (RFC 9147 §8); the request asks the server to rekey too.
    if opts.key_update {
        conn.set_now(clock.now());
        conn.request_key_update()
            .unwrap_or_else(|e| die(format!("KeyUpdate refused: {e:?}")));
        dtls_io::flush(conn, socket);
    }
    let mut input = Vec::new();
    if !std::io::stdin().is_terminal() {
        let _ = std::io::stdin().read_to_end(&mut input);
    }
    if !input.is_empty() {
        send_input(conn, socket, &input, opts.mtu);
    }
    // `-resend`: application data is not retransmitted by DTLS, so an
    // application that needs an answer asks again.
    let mut resends = if input.is_empty() { 0 } else { opts.resend };
    loop {
        let seen = pump_udp(conn, socket, clock, &mut buf, opts.read_timeout, deadline);
        if seen.data || seen.gone || resends == 0 || conn.received_close_notify() {
            break;
        }
        if clock.now() >= deadline {
            break;
        }
        resends -= 1;
        send_input(conn, socket, &input, opts.mtu);
    }
    // Say goodbye (RFC 8446 §6.1, in a protected record) rather than just
    // going silent, then wait — bounded by the read timeout — for the peer's
    // own close_notify, so a peer that shuts down cleanly is told apart from
    // one that merely stopped talking.
    if !conn.received_close_notify() && conn.close().is_ok() {
        dtls_io::flush(conn, socket);
        // A close_notify the engine is holding back for an unacknowledged
        // Finished (a KeyUpdate in the air counts too) goes out when the
        // ACK arrives.
        dtls_io::settle(conn, socket, clock, &mut buf, print_data);
        dtls_io::flush(conn, socket);
        let deadline = clock.now() + opts.read_timeout + Duration::from_secs(1);
        pump_udp(conn, socket, clock, &mut buf, opts.read_timeout, deadline);
    }
    if !opts.quiet {
        tlsinfo::report_session_end(conn);
    }
}
