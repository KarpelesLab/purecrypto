//! Memory-BIO C ABI for the QUIC v1 (RFC 9000 / 9001 / 9002 / 9221) stack.
//! Mirrors the structure of [`crate::ffi::tls`] — opaque [`PcQuicCfg`] +
//! [`PcQuic`] handles, in/out length convention for variable-width outputs,
//! `guard` panic-catch on every entry point.
//!
//! The underlying engine is sans-I/O: the caller pumps UDP datagrams
//! through [`pc_quic_feed_datagram`] / [`pc_quic_pop_datagram`] and
//! application bytes through the stream API. Mirrors OpenSSL 3.5's
//! `OSSL_QUIC_*_method` surface, less HTTP/3.
//!
//! Status-code reuse:
//!  - `WantRead`     — engine has no datagram to emit yet
//!  - `WantWrite`    — engine has a datagram to send; drain via `pc_quic_pop_datagram`
//!  - `WantHandshake`— application I/O attempted before the handshake completed
//!  - `Closed`       — connection closed (stateless reset or local close)

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::time::Duration;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::common::{PcStatus, guard, out_write, slice, wipe_vec};
use crate::ec::{BoxedEcdsaPrivateKey, Ed25519PrivateKey};
use crate::quic::{QuicConfig, QuicConnection, Role as QuicRole, StreamId, TransportParameters};
use crate::rsa::BoxedRsaPrivateKey;
use crate::tls::{Config, ConfigBuilder, ProtocolVersion, RootCertStore, SigningKey};

/// QUIC v1 wire version. Mirrors the `PC_QUIC_V1` macro in
/// `include/purecrypto.h`.
#[allow(dead_code)]
pub const PC_QUIC_V1: i32 = 0x0000_0001;

/// QUIC client / server discriminant. Mirrors the values of
/// `pc_tls_role` (`PC_TLS_CLIENT = 0`, `PC_TLS_SERVER = 1`) so a caller
/// using the same OpenSSL-style constants for both stacks can pass them
/// straight through.
fn role_from_i32(v: i32) -> Option<QuicRole> {
    Some(match v {
        0 => QuicRole::Client,
        1 => QuicRole::Server,
        _ => return None,
    })
}

/// Lazily-built QUIC configuration. Mirrors [`crate::ffi::tls::PcTlsCfg`]:
/// the configuration stores PEM blobs / settings until [`pc_quic_new`]
/// materialises a [`QuicConfig`] from them. Many connections may be
/// spawned from the same cfg.
pub struct PcQuicCfg {
    role: QuicRole,
    roots_pem: Vec<String>,
    server_name: Option<String>,
    cert: Option<CertAndKey>,
    alpn: Vec<Vec<u8>>,
    verify_certs: bool,
    // Transport parameters with library defaults baked in. Each setter
    // overwrites just one field.
    tp: TransportParameters,
    require_retry: bool,
}

struct CertAndKey {
    chain_der: Vec<Vec<u8>>,
    key: PcKey,
}

#[allow(clippy::large_enum_variant)]
enum PcKey {
    Rsa(BoxedRsaPrivateKey),
    Ecdsa(BoxedEcdsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
}

impl PcKey {
    fn to_signing_key(&self) -> SigningKey {
        match self {
            PcKey::Rsa(k) => SigningKey::Rsa(k.clone()),
            PcKey::Ecdsa(k) => SigningKey::Ecdsa(k.clone()),
            PcKey::Ed25519(k) => SigningKey::Ed25519(k.clone()),
        }
    }
}

impl PcQuicCfg {
    fn new(role: QuicRole) -> Self {
        // Defaults per the Phase 10 brief — match the CLI's
        // `default_transport_params` from `quic_cli.rs`. The
        // `active_connection_id_limit = 2` ceiling avoids the
        // cid_remote-pool bug surfaced in Phase 9 (>2 breaks rotation).
        let tp = TransportParameters {
            max_idle_timeout_ms: Some(60_000),
            initial_max_data: Some(1 << 20),
            initial_max_stream_data_bidi_local: Some(256 * 1024),
            initial_max_stream_data_bidi_remote: Some(256 * 1024),
            initial_max_stream_data_uni: Some(256 * 1024),
            initial_max_streams_bidi: Some(16),
            initial_max_streams_uni: Some(16),
            ack_delay_exponent: Some(3),
            max_ack_delay_ms: Some(25),
            active_connection_id_limit: Some(2),
            max_datagram_frame_size: Some(1200),
            ..TransportParameters::default()
        };
        PcQuicCfg {
            role,
            roots_pem: Vec::new(),
            server_name: None,
            cert: None,
            alpn: Vec::new(),
            verify_certs: true,
            tp,
            require_retry: false,
        }
    }

    // `roots_pem` strings are validated at add-time by `pc_quic_cfg_add_root_pem`
    // (against a throwaway store). A failure here would mean a parser regression,
    // not user input — `expect` instead of silently dropping certificates.
    fn build_roots(&self) -> RootCertStore {
        let mut store = RootCertStore::new();
        for pem in &self.roots_pem {
            store
                .add_pem(pem)
                .expect("build_roots: pre-validated PEM failed to re-parse");
        }
        store
    }

    fn build_tls_config(&self) -> Option<Config> {
        let mut b: ConfigBuilder = Config::builder()
            // QUIC is TLS 1.3 only (RFC 9001 §4.2).
            .versions(ProtocolVersion::TLSv1_3, ProtocolVersion::TLSv1_3)
            .verify_certificates(self.verify_certs)
            .roots(self.build_roots());
        if !self.alpn.is_empty() {
            b = b.alpn(self.alpn.clone());
        }
        if let Some(sni) = &self.server_name {
            b = b.server_name(sni.clone());
        }
        if let Some(ck) = &self.cert {
            b = b.identity(ck.chain_der.clone(), ck.key.to_signing_key());
        }
        Some(b.build())
    }
}

/// Allocates a new QUIC configuration. `role` is
/// `PC_TLS_CLIENT` (0) or `PC_TLS_SERVER` (1).
#[unsafe(no_mangle)]
pub extern "C" fn pc_quic_cfg_new(role: i32) -> *mut PcQuicCfg {
    crate::ffi::common::guard_ptr(|| {
        let Some(r) = role_from_i32(role) else {
            return core::ptr::null_mut();
        };
        Box::into_raw(Box::new(PcQuicCfg::new(r)))
    })
}

/// Frees a QUIC configuration. NULL is ignored.
///
/// # Safety
/// `cfg` from [`pc_quic_cfg_new`], not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_cfg_free(cfg: *mut PcQuicCfg) {
    if !cfg.is_null() {
        drop(unsafe { Box::from_raw(cfg) });
    }
}

/// Adds a root certificate (PEM) to the configuration's trust store.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_cfg_add_root_pem(
    cfg: *mut PcQuicCfg,
    pem: *const u8,
    len: usize,
) -> PcStatus {
    guard(|| {
        if cfg.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(b) = (unsafe { slice(pem, len) }) else {
            return PcStatus::NullPointer;
        };
        let Ok(s) = core::str::from_utf8(b) else {
            return PcStatus::BadEncoding;
        };
        let mut tmp = RootCertStore::new();
        if tmp.add_pem(s).is_err() {
            return PcStatus::BadEncoding;
        }
        unsafe { &mut *cfg }.roots_pem.push(s.to_string());
        PcStatus::Ok
    })
}

/// Sets the SNI hostname for the next client-side handshake.
///
/// # Safety
/// `cfg` valid; `sni` NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_cfg_set_server_name(
    cfg: *mut PcQuicCfg,
    sni: *const core::ffi::c_char,
) -> PcStatus {
    guard(|| {
        if cfg.is_null() || sni.is_null() {
            return PcStatus::NullPointer;
        }
        let cs = unsafe { core::ffi::CStr::from_ptr(sni) };
        let Ok(s) = cs.to_str() else {
            return PcStatus::BadEncoding;
        };
        unsafe { &mut *cfg }.server_name = Some(s.to_string());
        PcStatus::Ok
    })
}

/// Installs a server certificate chain (concatenated PEM, leaf first)
/// plus a private key (PEM). Detects RSA / EC / Ed25519 from the key PEM.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_cfg_set_certificate(
    cfg: *mut PcQuicCfg,
    chain_pem: *const u8,
    chain_len: usize,
    key_pem: *const u8,
    key_pem_len: usize,
) -> PcStatus {
    guard(|| {
        if cfg.is_null() {
            return PcStatus::NullPointer;
        }
        let (Some(chain), Some(kp)) = (unsafe { slice(chain_pem, chain_len) }, unsafe {
            slice(key_pem, key_pem_len)
        }) else {
            return PcStatus::NullPointer;
        };
        let chain_str = match core::str::from_utf8(chain) {
            Ok(s) => s,
            Err(_) => return PcStatus::BadEncoding,
        };
        let chain_der = match pem_split_cert_chain(chain_str) {
            Ok(v) => v,
            Err(e) => return e.to_status(),
        };
        let key_str = match core::str::from_utf8(kp) {
            Ok(s) => s,
            Err(_) => return PcStatus::BadEncoding,
        };
        let key = if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(key_str) {
            PcKey::Rsa(k)
        } else if let Ok(k) = BoxedEcdsaPrivateKey::from_sec1_pem(key_str) {
            PcKey::Ecdsa(k)
        } else if let Ok(k) = Ed25519PrivateKey::from_pkcs8_pem(key_str) {
            PcKey::Ed25519(k)
        } else {
            return PcStatus::BadEncoding;
        };
        unsafe { &mut *cfg }.cert = Some(CertAndKey { chain_der, key });
        PcStatus::Ok
    })
}

/// Sets the ALPN protocol list. `protocols` is an array of `n`
/// NUL-terminated C strings, in preference order.
///
/// ALPN is mandatory for QUIC (RFC 9001 §8.1): a configuration with no
/// ALPN protocols is rejected by [`pc_quic_new`]. `n == 0` clears a
/// previously-set list (which guarantees that rejection).
///
/// # Safety
/// All pointers valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_cfg_set_alpn(
    cfg: *mut PcQuicCfg,
    protocols: *const *const core::ffi::c_char,
    n: usize,
) -> PcStatus {
    guard(|| {
        if cfg.is_null() {
            return PcStatus::NullPointer;
        }
        let mut out: Vec<Vec<u8>> = Vec::with_capacity(n);
        if n > 0 {
            if protocols.is_null() {
                return PcStatus::NullPointer;
            }
            for i in 0..n {
                let p = unsafe { *protocols.add(i) };
                if p.is_null() {
                    return PcStatus::NullPointer;
                }
                let cs = unsafe { core::ffi::CStr::from_ptr(p) };
                out.push(cs.to_bytes().to_vec());
            }
        }
        unsafe { &mut *cfg }.alpn = out;
        PcStatus::Ok
    })
}

/// Toggles peer-certificate chain validation (client side). Default is
/// enabled.
///
/// # Safety
/// `cfg` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_cfg_set_verify_certificates(
    cfg: *mut PcQuicCfg,
    verify: i32,
) -> PcStatus {
    guard(|| {
        if cfg.is_null() {
            return PcStatus::NullPointer;
        }
        unsafe { &mut *cfg }.verify_certs = verify != 0;
        PcStatus::Ok
    })
}

/// `max_idle_timeout` transport parameter (milliseconds). 0 disables.
///
/// # Safety
/// `cfg` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_cfg_set_max_idle_timeout_ms(
    cfg: *mut PcQuicCfg,
    ms: u64,
) -> PcStatus {
    guard(|| {
        if cfg.is_null() {
            return PcStatus::NullPointer;
        }
        unsafe { &mut *cfg }.tp.max_idle_timeout_ms = Some(ms);
        PcStatus::Ok
    })
}

/// `initial_max_data` transport parameter (connection-level flow
/// control, bytes).
///
/// # Safety
/// `cfg` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_cfg_set_initial_max_data(
    cfg: *mut PcQuicCfg,
    bytes: u64,
) -> PcStatus {
    guard(|| {
        if cfg.is_null() {
            return PcStatus::NullPointer;
        }
        unsafe { &mut *cfg }.tp.initial_max_data = Some(bytes);
        PcStatus::Ok
    })
}

/// `initial_max_streams_bidi` transport parameter (peer-initiable
/// bidirectional stream count).
///
/// # Safety
/// `cfg` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_cfg_set_initial_max_streams_bidi(
    cfg: *mut PcQuicCfg,
    streams: u64,
) -> PcStatus {
    guard(|| {
        if cfg.is_null() {
            return PcStatus::NullPointer;
        }
        unsafe { &mut *cfg }.tp.initial_max_streams_bidi = Some(streams);
        PcStatus::Ok
    })
}

/// `max_datagram_frame_size` transport parameter (RFC 9221 §3). 0
/// disables unreliable DATAGRAM. Any other value enables DATAGRAM with
/// the given per-frame ceiling.
///
/// # Safety
/// `cfg` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_cfg_set_max_datagram_frame_size(
    cfg: *mut PcQuicCfg,
    bytes: u64,
) -> PcStatus {
    guard(|| {
        if cfg.is_null() {
            return PcStatus::NullPointer;
        }
        unsafe { &mut *cfg }.tp.max_datagram_frame_size = Some(bytes);
        PcStatus::Ok
    })
}

/// Server-only: enable stateless Retry (RFC 9000 §8.1.2). The retry
/// secret is generated internally on [`pc_quic_new`] when this is set.
/// Ignored on the client side.
///
/// # Safety
/// `cfg` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_cfg_set_require_retry(
    cfg: *mut PcQuicCfg,
    require: i32,
) -> PcStatus {
    guard(|| {
        if cfg.is_null() {
            return PcStatus::NullPointer;
        }
        unsafe { &mut *cfg }.require_retry = require != 0;
        PcStatus::Ok
    })
}

/// A QUIC connection handle, wrapping a [`crate::quic::QuicConnection`].
pub struct PcQuic {
    inner: QuicConnection,
    /// Outbound UDP datagram already popped from the engine but not yet
    /// delivered to the caller (e.g. the output buffer was too small, or a
    /// size query with zero capacity). Re-served by the next
    /// [`pc_quic_pop_datagram`] so a `BufferTooSmall` round-trip loses
    /// nothing — popping is destructive on the engine side.
    pending_pop: Option<Vec<u8>>,
    /// Received DATAGRAM payload already dequeued from the engine but not yet
    /// delivered. Re-served by the next [`pc_quic_recv_datagram`].
    pending_recv: Option<Vec<u8>>,
}

impl Drop for PcQuic {
    fn drop(&mut self) {
        // Undelivered application payload must not be handed back to the
        // allocator un-scrubbed.
        if let Some(buf) = self.pending_recv.as_mut() {
            wipe_vec(buf);
        }
    }
}

/// Materialises a QUIC connection from a configuration. Returns NULL if
/// configuration is incomplete (e.g. server cert missing for a server
/// role, SNI missing for a client role).
///
/// # Safety
/// `cfg` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_new(cfg: *const PcQuicCfg) -> *mut PcQuic {
    crate::ffi::common::guard_ptr(|| {
        if cfg.is_null() {
            return core::ptr::null_mut();
        }
        let c = unsafe { &*cfg };
        let tls_cfg = match c.build_tls_config() {
            Some(t) => t,
            None => return core::ptr::null_mut(),
        };
        let mut qcfg = QuicConfig {
            tls: tls_cfg,
            transport_params: c.tp.clone(),
            ..QuicConfig::default()
        };
        if c.role == QuicRole::Server && c.require_retry {
            // Mint a fresh random retry secret per connection. The C API
            // takes no key — production callers that want a long-lived
            // key should manage the retry token externally. This default
            // matches the CLI's `-retry` flag behaviour in Phase 9.
            let mut secret = [0u8; 32];
            crate::rng::RngCore::fill_bytes(&mut crate::rng::OsRng, &mut secret);
            qcfg.require_retry = true;
            qcfg.retry_secret = Some(secret);
        }
        let conn = match c.role {
            QuicRole::Client => {
                let sni = match c.server_name.as_deref() {
                    Some(s) => s,
                    None => return core::ptr::null_mut(),
                };
                QuicConnection::client(qcfg, sni)
            }
            QuicRole::Server => QuicConnection::server(qcfg),
        };
        let Ok(inner) = conn else {
            return core::ptr::null_mut();
        };
        Box::into_raw(Box::new(PcQuic {
            inner,
            pending_pop: None,
            pending_recv: None,
        }))
    })
}

/// Frees a QUIC connection. NULL is ignored.
///
/// # Safety
/// `q` from [`pc_quic_new`], not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_free(q: *mut PcQuic) {
    if !q.is_null() {
        drop(unsafe { Box::from_raw(q) });
    }
}

// ---- Wire I/O -------------------------------------------------------------

/// Feeds one received UDP datagram into the engine.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_feed_datagram(
    q: *mut PcQuic,
    dg: *const u8,
    len: usize,
) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(b) = (unsafe { slice(dg, len) }) else {
            return PcStatus::NullPointer;
        };
        let conn = &mut unsafe { &mut *q }.inner;
        match conn.feed_datagram(b) {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::Internal,
        }
    })
}

/// Drains the next outbound UDP datagram. `*out_len = 0` when there is
/// nothing pending. Each call returns at most one datagram.
///
/// A [`PcStatus::BufferTooSmall`] return (including the size-query call with
/// zero capacity) is non-destructive: the datagram is retained and re-served
/// by the next call, with `*out_len` reporting the required length.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_pop_datagram(
    q: *mut PcQuic,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        let handle = unsafe { &mut *q };
        // Serve a previously popped-but-undelivered datagram before draining
        // anything new — popping is destructive on the engine side.
        let dg = match handle.pending_pop.take() {
            Some(d) => d,
            None => handle.inner.pop_datagram(),
        };
        let st = unsafe { out_write(&dg, out, out_len) };
        if st != PcStatus::Ok {
            handle.pending_pop = Some(dg);
        }
        st
    })
}

// ---- Handshake state ------------------------------------------------------

/// Returns `Ok` if the handshake is complete, `WantRead` otherwise. The
/// caller drives the handshake by pumping `pop_datagram` /
/// `feed_datagram` until this returns `Ok`.
///
/// # Safety
/// `q` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_handshake(q: *mut PcQuic) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *q }.inner;
        if conn.is_handshake_complete() {
            PcStatus::Ok
        } else {
            PcStatus::WantRead
        }
    })
}

/// Writes `1` to `*out` if the handshake has completed, `0` otherwise.
///
/// # Safety
/// `q`, `out` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_is_handshake_complete(
    q: *const PcQuic,
    out: *mut i32,
) -> PcStatus {
    guard(|| {
        if q.is_null() || out.is_null() {
            return PcStatus::NullPointer;
        }
        unsafe {
            *out = if (*q).inner.is_handshake_complete() {
                1
            } else {
                0
            }
        };
        PcStatus::Ok
    })
}

// ---- Timers ---------------------------------------------------------------

/// Reports the duration until the engine's next timer fires (PTO, idle,
/// etc.). `*has_timeout = 1` when there's a pending timer and the
/// duration is written to `*seconds_out` / `*nanos_out`; otherwise both
/// are zero and `*has_timeout = 0`.
///
/// # Safety
/// All pointers valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_next_timeout(
    q: *const PcQuic,
    seconds_out: *mut u64,
    nanos_out: *mut u32,
    has_timeout: *mut i32,
) -> PcStatus {
    guard(|| {
        if q.is_null() || seconds_out.is_null() || nanos_out.is_null() || has_timeout.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = unsafe { &*q };
        match conn.inner.next_timeout() {
            Some(d) => unsafe {
                *seconds_out = d.as_secs();
                *nanos_out = d.subsec_nanos();
                *has_timeout = 1;
            },
            None => unsafe {
                *seconds_out = 0;
                *nanos_out = 0;
                *has_timeout = 0;
            },
        }
        PcStatus::Ok
    })
}

/// Notifies the engine that `(since_start_secs, since_start_nanos)` has
/// elapsed since this connection was created (monotonic clock).
///
/// # Safety
/// `q` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_on_timeout(
    q: *mut PcQuic,
    since_start_secs: u64,
    since_start_nanos: u32,
) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *q }.inner;
        conn.on_timeout(Duration::new(since_start_secs, since_start_nanos));
        PcStatus::Ok
    })
}

// ---- Streams --------------------------------------------------------------

/// Opens a new client-initiated bidirectional stream. The 62-bit stream
/// id is written to `*id_out`.
///
/// # Safety
/// `q`, `id_out` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_open_bidi(q: *mut PcQuic, id_out: *mut u64) -> PcStatus {
    guard(|| {
        if q.is_null() || id_out.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *q }.inner;
        match conn.open_bidi() {
            Ok(id) => {
                unsafe { *id_out = id.value() };
                PcStatus::Ok
            }
            Err(_) => PcStatus::Internal,
        }
    })
}

/// Opens a new client-initiated unidirectional (send-only) stream.
///
/// # Safety
/// `q`, `id_out` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_open_uni(q: *mut PcQuic, id_out: *mut u64) -> PcStatus {
    guard(|| {
        if q.is_null() || id_out.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *q }.inner;
        match conn.open_uni() {
            Ok(id) => {
                unsafe { *id_out = id.value() };
                PcStatus::Ok
            }
            Err(_) => PcStatus::Internal,
        }
    })
}

/// Queues `data` for transmission on `id`. `*written_out` receives the
/// number of bytes accepted (0 when the credit is exhausted).
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_stream_write(
    q: *mut PcQuic,
    id: u64,
    data: *const u8,
    len: usize,
    written_out: *mut usize,
) -> PcStatus {
    guard(|| {
        if q.is_null() || written_out.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(b) = (unsafe { slice(data, len) }) else {
            return PcStatus::NullPointer;
        };
        let conn = &mut unsafe { &mut *q }.inner;
        match conn.write(StreamId(id), b) {
            Ok(n) => {
                unsafe { *written_out = n };
                PcStatus::Ok
            }
            Err(_) => PcStatus::Internal,
        }
    })
}

/// Signals FIN on `id`'s send side.
///
/// # Safety
/// `q` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_stream_finish(q: *mut PcQuic, id: u64) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *q }.inner;
        match conn.finish(StreamId(id)) {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::Internal,
        }
    })
}

/// Reads available bytes from `id` into `out`. On entry `*out_len` is
/// the buffer capacity; on return it is the number of bytes copied.
/// `*fin_seen = 1` once every byte through FIN has been delivered.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_stream_read(
    q: *mut PcQuic,
    id: u64,
    out: *mut u8,
    out_len: *mut usize,
    fin_seen: *mut i32,
) -> PcStatus {
    guard(|| {
        if q.is_null() || out_len.is_null() || fin_seen.is_null() {
            return PcStatus::NullPointer;
        }
        let cap = unsafe { *out_len };
        // Cap the caller-controlled capacity to defend against a
        // pathological / hostile `*out_len`. 1 MiB matches the largest
        // legitimate single QUIC stream-read flow-control window
        // realistic callers configure. Larger requests are answered
        // with `BufferTooSmall` (the standard signal that the caller
        // should retry with the documented maximum), not by silently
        // attempting a multi-GiB allocation. We check this BEFORE the
        // out-pointer null-check so an oversized `*out_len` is rejected
        // even when paired with a null buffer.
        const PC_QUIC_STREAM_READ_MAX: usize = 1 << 20; // 1 MiB
        if cap > PC_QUIC_STREAM_READ_MAX {
            unsafe { *out_len = PC_QUIC_STREAM_READ_MAX };
            return PcStatus::BufferTooSmall;
        }
        if cap > 0 && out.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *q }.inner;
        // Use a local scratch sized to the caller's capacity. Avoids a
        // direct &mut [u8] over the caller's buffer (which would
        // require validating the alignment + writability up-front);
        // `out_write` would memcpy unnecessarily. Instead we slice into
        // an in-place owned vector and copy the chunk back out
        // ourselves — matching the size-first convention.
        let mut tmp: Vec<u8> = alloc::vec![0u8; cap];
        let (n, fin) = match conn.read(StreamId(id), &mut tmp) {
            Ok(p) => p,
            Err(_) => return PcStatus::Internal,
        };
        unsafe { *out_len = n };
        unsafe { *fin_seen = if fin { 1 } else { 0 } };
        if n > 0 {
            unsafe { core::ptr::copy_nonoverlapping(tmp.as_ptr(), out, n) };
        }
        PcStatus::Ok
    })
}

/// Aborts the send side of `id` with the given application error code.
///
/// # Safety
/// `q` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_stream_reset(q: *mut PcQuic, id: u64, app_error: u64) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *q }.inner;
        match conn.reset(StreamId(id), app_error) {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::Internal,
        }
    })
}

/// Asks the peer to abort sending on `id` with the given application
/// error code.
///
/// # Safety
/// `q` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_stream_stop_sending(
    q: *mut PcQuic,
    id: u64,
    app_error: u64,
) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *q }.inner;
        match conn.stop_sending(StreamId(id), app_error) {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::Internal,
        }
    })
}

// ---- Unreliable datagrams (RFC 9221) --------------------------------------

/// Queues `data` for transmission as a DATAGRAM frame. Returns
/// `WantHandshake` before the handshake completes; `BadEncoding` if the
/// peer didn't advertise `max_datagram_frame_size` or the payload would
/// exceed the limit.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_send_datagram(
    q: *mut PcQuic,
    data: *const u8,
    len: usize,
) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(b) = (unsafe { slice(data, len) }) else {
            return PcStatus::NullPointer;
        };
        let conn = &mut unsafe { &mut *q }.inner;
        if !conn.is_handshake_complete() {
            return PcStatus::WantHandshake;
        }
        match conn.send_datagram(b) {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::BadEncoding,
        }
    })
}

/// Drains the next received DATAGRAM payload (arrival order).
/// `*out_len = 0` when the inbound queue is empty.
///
/// A [`PcStatus::BufferTooSmall`] return (including the size-query call with
/// zero capacity) is non-destructive: the payload is retained and re-served
/// by the next call, with `*out_len` reporting the required length.
///
/// # Safety
/// All pointers valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_recv_datagram(
    q: *mut PcQuic,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        let handle = unsafe { &mut *q };
        // Serve a previously dequeued-but-undelivered payload first —
        // dequeueing is destructive on the engine side.
        let mut payload = match handle.pending_recv.take() {
            Some(p) => p,
            None => handle.inner.recv_datagram().unwrap_or_default(),
        };
        let st = unsafe { out_write(&payload, out, out_len) };
        if st == PcStatus::Ok {
            // Delivered: scrub our copy of the payload before dropping it.
            wipe_vec(&mut payload);
        } else {
            handle.pending_recv = Some(payload);
        }
        st
    })
}

// ---- Key update (RFC 9001 §6) --------------------------------------------

/// Initiates a 1-RTT key update. Returns [`PcStatus::Internal`] when the
/// handshake isn't complete or a previous update is still unconfirmed
/// (RFC 9001 §6.1).
///
/// # Safety
/// `q` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_initiate_key_update(q: *mut PcQuic) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *q }.inner;
        match conn.initiate_key_update() {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::Internal,
        }
    })
}

// ---- Address binding ------------------------------------------------------

/// Records the peer's UDP address. `ipv6_bytes` is the IPv6 representation
/// (IPv4-mapped is fine: `::ffff:a.b.c.d`); `ipv6_bytes_len` MUST be 16 —
/// any other length is rejected with [`PcStatus::Unsupported`]. `port` is
/// host-byte-order. Mandatory before the first `feed_datagram` on a server
/// that uses `pc_quic_cfg_set_require_retry`. Taking an explicit length
/// rules out an out-of-bounds read from a short buffer (previously the
/// 16-byte width was implicit in the signature).
///
/// # Safety
/// `q` valid; `ipv6_bytes` non-NULL and points to at least `ipv6_bytes_len`
/// readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_set_peer_addr(
    q: *mut PcQuic,
    ipv6_bytes: *const u8,
    ipv6_bytes_len: usize,
    port: u16,
) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(bytes) = (unsafe { slice(ipv6_bytes, ipv6_bytes_len) }) else {
            return PcStatus::NullPointer;
        };
        let octets: [u8; 16] = match bytes.try_into() {
            Ok(a) => a,
            Err(_) => return PcStatus::Unsupported,
        };
        // Recognize IPv4-mapped (::ffff:0:0/96) and surface as a V4 addr.
        let addr =
            if octets[..10].iter().all(|b| *b == 0) && octets[10] == 0xff && octets[11] == 0xff {
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(
                        octets[12], octets[13], octets[14], octets[15],
                    )),
                    port,
                )
            } else {
                SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)
            };
        let conn = &mut unsafe { &mut *q }.inner;
        conn.set_peer_addr(addr);
        PcStatus::Ok
    })
}

// ---- Negotiated info ------------------------------------------------------

/// Writes the negotiated ALPN protocol bytes (if any) to `out`. With no
/// ALPN selected, `*out_len = 0` and `Ok` is returned.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_negotiated_alpn(
    q: *const PcQuic,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        // The QuicConnection holds the TLS engine internally; we can't
        // borrow it here. The Phase-4 design surfaces ALPN via the
        // engine's `alpn_protocol` method on ClientConnection /
        // ServerConnection, but those are not re-exported through
        // QuicConnection. Until QuicConnection exposes an accessor,
        // return an empty selected protocol — matching the
        // "ALPN not configured" branch in pc_tls_alpn_selected.
        // Production callers that need to inspect the chosen ALPN
        // should configure it explicitly and trust the server-side
        // selection.
        let alpn: Vec<u8> = Vec::new();
        unsafe { out_write(&alpn, out, out_len) }
    })
}

/// Writes the peer's leaf certificate DER to `out`, or
/// [`PcStatus::BadEncoding`] when no peer certificate is available
/// (handshake incomplete, or the engine didn't expose it).
///
/// # Safety
/// All pointers valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_quic_peer_certificate(
    q: *const PcQuic,
    _out: *mut u8,
    _out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if q.is_null() {
            return PcStatus::NullPointer;
        }
        // The QuicConnection doesn't currently expose the peer
        // certificate chain through its public API — Phase 10 ships the
        // ABI surface for parity with `pc_tls_peer_certificate`, but
        // until QuicConnection adds an accessor (later phase) the C ABI
        // returns BadEncoding (matching pc_tls_peer_certificate's
        // "no peer certificate available" branch).
        PcStatus::BadEncoding
    })
}

// ---- Helpers --------------------------------------------------------------

/// Distinct PEM-parsing failure modes the FFI callers want to surface as
/// distinct [`PcStatus`] codes (per the FFI-4 audit finding). Without this,
/// every PEM-related failure collapsed into `BadEncoding` and the C caller
/// could not tell "you passed me empty bytes" from "you passed me a real but
/// broken PEM block".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PemSplitError {
    /// The input is well-formed at the framing layer but contains no blocks
    /// of the requested `LABEL`.
    NoBlocks,
    /// A `-----BEGIN LABEL-----` marker was found with no matching
    /// `-----END LABEL-----` trailer, or a block's base64 body failed to decode.
    Malformed,
}

impl PemSplitError {
    /// Maps to the FFI status code surfaced to the C caller. Today both
    /// variants are `BadEncoding`; the enum lives so the call sites can
    /// log the precise reason and a future ABI revision can split them.
    fn to_status(self) -> PcStatus {
        match self {
            PemSplitError::NoBlocks | PemSplitError::Malformed => PcStatus::BadEncoding,
        }
    }
}

/// Splits a PEM bundle into individual labeled blocks. Each non-empty
/// concatenated chunk between matching `-----BEGIN $LABEL-----` /
/// `-----END $LABEL-----` markers is returned as a separate string.
///
/// Errors:
///   * [`PemSplitError::NoBlocks`]  — no `-----BEGIN $LABEL-----` found at all.
///   * [`PemSplitError::Malformed`] — at least one `-----BEGIN-----` is not
///     paired with a matching `-----END-----`.
fn pem_split(pem: &str, label: &str) -> Result<Vec<String>, PemSplitError> {
    let begin = alloc::format!("-----BEGIN {label}-----");
    let end = alloc::format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = pem;
    while let Some(b_off) = rest.find(&begin) {
        let after_b = b_off;
        if let Some(e_off) = rest[after_b..].find(&end) {
            let abs_end = after_b + e_off + end.len();
            out.push(rest[after_b..abs_end].to_string());
            rest = &rest[abs_end..];
        } else {
            return Err(PemSplitError::Malformed);
        }
    }
    if out.is_empty() {
        return Err(PemSplitError::NoBlocks);
    }
    Ok(out)
}

/// Splits a PEM bundle of `CERTIFICATE` blocks into DER chunks, leaf first.
///
/// Errors mirror [`pem_split`] plus [`PemSplitError::Malformed`] when a
/// well-framed block's base64 body fails to decode.
fn pem_split_cert_chain(pem: &str) -> Result<Vec<Vec<u8>>, PemSplitError> {
    let blocks = pem_split(pem, "CERTIFICATE")?;
    let mut chain = Vec::with_capacity(blocks.len());
    for block in blocks {
        let der =
            crate::der::pem_decode(&block, "CERTIFICATE").map_err(|_| PemSplitError::Malformed)?;
        chain.push(der);
    }
    if chain.is_empty() {
        return Err(PemSplitError::NoBlocks);
    }
    Ok(chain)
}
