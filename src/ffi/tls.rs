//! Memory-BIO C ABI for the TLS 1.2/1.3 and DTLS 1.2/1.3 stacks. The
//! underlying engine is sans-I/O — the caller pumps wire bytes through
//! `pc_tls_feed` / `pc_tls_pop` and application bytes through `pc_tls_send`
//! / `pc_tls_recv`. The pattern mirrors OpenSSL's `BIO_s_mem` plus `SSL_*`.
//!
//! Status-code additions live in [`super::common::PcStatus`]:
//!  - `WantRead`  — engine needs more wire bytes before it can make progress
//!  - `WantWrite` — engine has wire bytes to be sent before progress
//!  - `WantHandshake` — application I/O attempted pre-handshake
//!  - `Closed`     — peer (or local) sent close_notify
//!  - `TlsAlert`   — a fatal TLS alert was received

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::common::{PcStatus, guard, out_write, slice};
use crate::ec::{BoxedEcdsaPrivateKey, Ed25519PrivateKey};
use crate::rsa::BoxedRsaPrivateKey;
use crate::tls::{
    ClientAuth, Config, ConfigBuilder, Connection, CrlStore, HandshakeStatus, ProtocolVersion,
    RootCertStore, SigningKey,
};

/// TLS / DTLS role.
#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Role {
    Client = 0,
    Server = 1,
}

impl Role {
    fn from_i32(v: i32) -> Option<Self> {
        Some(match v {
            0 => Role::Client,
            1 => Role::Server,
            _ => return None,
        })
    }
}

/// Version selector. Values match the wire ProtocolVersion encoding so
/// callers using OpenSSL-style constants can pass them straight through.
#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Version {
    Tls12 = 0x0303,
    Tls13 = 0x0304,
    Dtls12 = 0xFEFD_u16 as i32,
    Dtls13 = 0xFEFC_u16 as i32,
}

impl Version {
    fn from_i32(v: i32) -> Option<Self> {
        Some(match v as u16 {
            0x0303 => Version::Tls12,
            0x0304 => Version::Tls13,
            0xFEFD => Version::Dtls12,
            0xFEFC => Version::Dtls13,
            _ => return None,
        })
    }

    fn to_protocol_version(self) -> ProtocolVersion {
        match self {
            Version::Tls12 => ProtocolVersion::TLSv1_2,
            Version::Tls13 => ProtocolVersion::TLSv1_3,
            Version::Dtls12 => ProtocolVersion::DTLSv1_2,
            Version::Dtls13 => ProtocolVersion::DTLSv1_3,
        }
    }
}

/// Builder accumulating settings for a TLS/DTLS endpoint. Stores PEM blobs
/// internally so that `pc_tls_new` can be called multiple times (the same
/// cfg can spawn many connections).
pub struct PcTlsCfg {
    role: Role,
    version: Version,
    roots_pem: Vec<String>,
    crls_pem: Vec<String>,
    client_auth_roots_pem: Vec<String>,
    client_auth_required: bool,
    server_name: Option<String>,
    cert: Option<CertAndKey>,
    alpn: Vec<Vec<u8>>,
    verify_certs: bool,
    cookie_secret: Option<[u8; 32]>,
    no_cookie: bool,
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

impl PcTlsCfg {
    fn new(role: Role, version: Version) -> Self {
        PcTlsCfg {
            role,
            version,
            roots_pem: Vec::new(),
            crls_pem: Vec::new(),
            client_auth_roots_pem: Vec::new(),
            client_auth_required: false,
            server_name: None,
            cert: None,
            alpn: Vec::new(),
            verify_certs: true,
            cookie_secret: None,
            no_cookie: false,
        }
    }

    fn build_roots(&self) -> RootCertStore {
        let mut store = RootCertStore::new();
        for pem in &self.roots_pem {
            let _ = store.add_pem(pem);
        }
        store
    }

    fn build_crls(&self) -> CrlStore {
        let mut store = CrlStore::new();
        for pem in &self.crls_pem {
            let _ = store.add_pem(pem);
        }
        store
    }

    fn build_client_auth_roots(&self) -> RootCertStore {
        let mut store = RootCertStore::new();
        for pem in &self.client_auth_roots_pem {
            let _ = store.add_pem(pem);
        }
        store
    }

    fn build_config(&self) -> Option<Config> {
        let mut b: ConfigBuilder = Config::builder()
            .versions(
                self.version.to_protocol_version(),
                self.version.to_protocol_version(),
            )
            .verify_certificates(self.verify_certs)
            .roots(self.build_roots());
        if !self.alpn.is_empty() {
            b = b.alpn(self.alpn.clone());
        }
        if !self.crls_pem.is_empty() {
            b = b.crls(self.build_crls());
        }
        if let Some(sni) = &self.server_name {
            b = b.server_name(sni.clone());
        }
        if let Some(secret) = self.cookie_secret {
            b = b.cookie_secret(secret);
        }
        if self.no_cookie {
            b = b.no_cookie();
        }
        if let Some(ck) = &self.cert {
            b = b.identity(ck.chain_der.clone(), ck.key.to_signing_key());
        }
        if !self.client_auth_roots_pem.is_empty() {
            b = b.client_auth(ClientAuth {
                roots: self.build_client_auth_roots(),
                required: self.client_auth_required,
            });
        }
        Some(b.build())
    }
}

/// Allocates a new TLS configuration handle.
#[unsafe(no_mangle)]
pub extern "C" fn pc_tls_cfg_new(role: i32, version: i32) -> *mut PcTlsCfg {
    let Some(r) = Role::from_i32(role) else {
        return core::ptr::null_mut();
    };
    let Some(v) = Version::from_i32(version) else {
        return core::ptr::null_mut();
    };
    Box::into_raw(Box::new(PcTlsCfg::new(r, v)))
}

/// Frees a TLS configuration. NULL is ignored.
///
/// # Safety
/// `cfg` from [`pc_tls_cfg_new`], not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_cfg_free(cfg: *mut PcTlsCfg) {
    if !cfg.is_null() {
        drop(unsafe { Box::from_raw(cfg) });
    }
}

/// Adds a root certificate (PEM) to the configuration's trust store.
///
/// # Safety
/// `cfg`, `pem` valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_cfg_add_root_pem(
    cfg: *mut PcTlsCfg,
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
        // Validate by parsing into a transient store first.
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
pub unsafe extern "C" fn pc_tls_cfg_set_server_name(
    cfg: *mut PcTlsCfg,
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

/// Installs a certificate chain (concatenated PEM, leaf first) plus a private
/// key (PEM). Detects RSA / EC / Ed25519 from the key PEM.
///
/// # Safety
/// All pointers valid for their lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_cfg_set_certificate(
    cfg: *mut PcTlsCfg,
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
        let chain_der = pem_split_cert_chain(chain_str);
        if chain_der.is_empty() {
            return PcStatus::BadEncoding;
        }
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

/// Sets the ALPN protocol list. `protocols` is an array of `n` NUL-terminated
/// C strings, in preference order. Pass `n == 0` to disable ALPN.
///
/// # Safety
/// All pointers valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_cfg_set_alpn(
    cfg: *mut PcTlsCfg,
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

/// Enables or disables the chain-validity / host-name check on the peer
/// certificate (client side). Default is enabled. Pass `0` for an
/// `-insecure`-style override (the leaf signature in `CertificateVerify`
/// is still checked).
///
/// # Safety
/// `cfg` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_cfg_set_verify_certificates(
    cfg: *mut PcTlsCfg,
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

/// Server-side: require client authentication (mTLS) under the supplied root
/// store (PEM). `required` mirrors the library's bool: when true a connecting
/// client MUST present a chain we can verify.
///
/// # Safety
/// All pointers valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_cfg_set_client_auth(
    cfg: *mut PcTlsCfg,
    required: i32,
    roots_pem: *const u8,
    roots_pem_len: usize,
) -> PcStatus {
    guard(|| {
        if cfg.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(rp) = (unsafe { slice(roots_pem, roots_pem_len) }) else {
            return PcStatus::NullPointer;
        };
        let Ok(s) = core::str::from_utf8(rp) else {
            return PcStatus::BadEncoding;
        };
        // Validate that each cert parses, then save the PEMs.
        let blocks = pem_split(s, "CERTIFICATE");
        if blocks.is_empty() {
            return PcStatus::BadEncoding;
        }
        let mut tmp = RootCertStore::new();
        for cert in &blocks {
            if tmp.add_pem(cert).is_err() {
                return PcStatus::BadEncoding;
            }
        }
        let cfg_ref = unsafe { &mut *cfg };
        cfg_ref.client_auth_roots_pem = blocks;
        cfg_ref.client_auth_required = required != 0;
        PcStatus::Ok
    })
}

/// Adds a CRL (PEM) consulted during chain validation.
///
/// # Safety
/// All pointers valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_cfg_add_crl_pem(
    cfg: *mut PcTlsCfg,
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
        let mut tmp = CrlStore::new();
        if tmp.add_pem(s).is_err() {
            return PcStatus::BadEncoding;
        }
        unsafe { &mut *cfg }.crls_pem.push(s.to_string());
        PcStatus::Ok
    })
}

/// DTLS server-only: disables the HelloVerifyRequest (1.2) /
/// HelloRetryRequest cookie (1.3) round-trip. Recommended only for tests
/// where the cookie exchange is not needed for amplification defense.
///
/// # Safety
/// `cfg` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_dtls_cfg_set_no_cookie(cfg: *mut PcTlsCfg) -> PcStatus {
    guard(|| {
        if cfg.is_null() {
            return PcStatus::NullPointer;
        }
        unsafe { &mut *cfg }.no_cookie = true;
        PcStatus::Ok
    })
}

/// DTLS server-only: sets the 32-byte HelloVerifyRequest cookie secret.
///
/// # Safety
/// `cfg` valid; `secret` non-NULL, 32 readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_dtls_cfg_set_cookie_secret(
    cfg: *mut PcTlsCfg,
    secret: *const u8,
) -> PcStatus {
    guard(|| {
        if cfg.is_null() || secret.is_null() {
            return PcStatus::NullPointer;
        }
        let mut buf = [0u8; 32];
        unsafe { core::ptr::copy_nonoverlapping(secret, buf.as_mut_ptr(), 32) };
        unsafe { &mut *cfg }.cookie_secret = Some(buf);
        PcStatus::Ok
    })
}

/// A TLS or DTLS connection handle, wrapping a [`crate::tls::Connection`].
pub struct PcTls {
    inner: Connection,
}

/// Materialises a connection from a finished configuration. Returns NULL on a
/// configuration that's missing required fields (e.g. server cert + key, or
/// SNI for a client).
///
/// # Safety
/// `cfg` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_new(cfg: *const PcTlsCfg) -> *mut PcTls {
    if cfg.is_null() {
        return core::ptr::null_mut();
    }
    let c = unsafe { &*cfg };
    let config = match c.build_config() {
        Some(cfg) => cfg,
        None => return core::ptr::null_mut(),
    };
    let conn = match c.role {
        Role::Client => Connection::client(&config),
        Role::Server => Connection::server(&config),
    };
    let Ok(inner) = conn else {
        return core::ptr::null_mut();
    };
    Box::into_raw(Box::new(PcTls { inner }))
}

/// Frees a connection. NULL is ignored.
///
/// # Safety
/// `tls` from [`pc_tls_new`], not freed twice.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_free(tls: *mut PcTls) {
    if !tls.is_null() {
        drop(unsafe { Box::from_raw(tls) });
    }
}

// ---- Wire / app I/O -------------------------------------------------------

/// Push `len` wire bytes received from the peer into the engine. For DTLS
/// the input is one datagram; for TLS it is any contiguous stream slice.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_feed(
    tls: *mut PcTls,
    wire_in: *const u8,
    in_len: usize,
    consumed: *mut usize,
) -> PcStatus {
    guard(|| {
        if tls.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(b) = (unsafe { slice(wire_in, in_len) }) else {
            return PcStatus::NullPointer;
        };
        let conn = &mut unsafe { &mut *tls }.inner;
        let _ = conn.feed(b);
        if !consumed.is_null() {
            unsafe { *consumed = in_len };
        }
        PcStatus::Ok
    })
}

/// Pop the next chunk of wire bytes the engine wants to send to the peer.
/// For DTLS the output is one datagram (the caller MUST send it whole). For
/// TLS it is any number of records; the caller may chunk it freely on the
/// underlying byte stream. Writes `*out_len = 0` when there is nothing
/// pending.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_pop(
    tls: *mut PcTls,
    wire_out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if tls.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *tls }.inner;
        let bytes = conn.pop().unwrap_or_default();
        unsafe { out_write(&bytes, wire_out, out_len) }
    })
}

/// Encrypts `len` application bytes for transmission. Returns
/// [`PcStatus::WantHandshake`] when called before the handshake completes.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_send(
    tls: *mut PcTls,
    app_in: *const u8,
    in_len: usize,
) -> PcStatus {
    guard(|| {
        if tls.is_null() {
            return PcStatus::NullPointer;
        }
        let Some(b) = (unsafe { slice(app_in, in_len) }) else {
            return PcStatus::NullPointer;
        };
        let conn = &mut unsafe { &mut *tls }.inner;
        if !conn.is_handshake_complete() {
            return PcStatus::WantHandshake;
        }
        match conn.send(b) {
            Ok(()) => PcStatus::Ok,
            Err(_) => PcStatus::Internal,
        }
    })
}

/// Drains decrypted application bytes. Writes `*out_len = 0` when nothing is
/// pending.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_recv(
    tls: *mut PcTls,
    app_out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if tls.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *tls }.inner;
        let bytes = conn.recv().unwrap_or_default();
        unsafe { out_write(&bytes, app_out, out_len) }
    })
}

/// Drives the handshake forward. Returns:
///  - `Ok` on completion
///  - `WantWrite` when the engine has wire bytes to drain (caller should
///    call `pc_tls_pop` and send them to the peer)
///  - `WantRead`  when the engine needs more wire bytes (caller should
///    receive from the peer and call `pc_tls_feed`)
///
/// # Safety
/// `tls` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_handshake(tls: *mut PcTls) -> PcStatus {
    guard(|| {
        if tls.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *tls }.inner;
        match conn.handshake() {
            Ok(HandshakeStatus::Complete) => PcStatus::Ok,
            Ok(HandshakeStatus::WantWrite) => PcStatus::WantWrite,
            Ok(HandshakeStatus::WantRead) => PcStatus::WantRead,
            Err(_) => PcStatus::Internal,
        }
    })
}

/// Returns 1 if the handshake has completed, 0 otherwise.
///
/// # Safety
/// `tls` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_is_handshake_complete(tls: *const PcTls) -> i32 {
    if tls.is_null() {
        return 0;
    }
    if unsafe { &*tls }.inner.is_handshake_complete() {
        1
    } else {
        0
    }
}

/// Returns the negotiated wire version in `out`, e.g. `0x0304` for TLS 1.3.
///
/// # Safety
/// `tls`, `out` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_negotiated_version(tls: *const PcTls, out: *mut u16) -> PcStatus {
    guard(|| {
        if tls.is_null() || out.is_null() {
            return PcStatus::NullPointer;
        }
        let v = unsafe { &*tls }
            .inner
            .negotiated_version()
            .map(|p| p.as_u16())
            .unwrap_or(0);
        unsafe { *out = v };
        PcStatus::Ok
    })
}

/// Writes the negotiated ALPN protocol bytes (if any) to `out`. With no ALPN
/// selected, `*out_len = 0` and `Ok` is returned.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_alpn_selected(
    tls: *const PcTls,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if tls.is_null() {
            return PcStatus::NullPointer;
        }
        let alpn: &[u8] = unsafe { &*tls }.inner.alpn_selected().unwrap_or(&[]);
        unsafe { out_write(alpn, out, out_len) }
    })
}

/// Writes the peer's leaf certificate DER to `out`, or
/// [`PcStatus::BadEncoding`] when no peer certificate is available.
///
/// # Safety
/// All pointers valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_peer_certificate(
    tls: *const PcTls,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if tls.is_null() {
            return PcStatus::NullPointer;
        }
        let chain: &[Vec<u8>] = unsafe { &*tls }.inner.peer_certificates();
        let Some(leaf) = chain.first() else {
            return PcStatus::BadEncoding;
        };
        unsafe { out_write(leaf, out, out_len) }
    })
}

/// Sends a close_notify and transitions the connection to Closed.
///
/// # Safety
/// `tls` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_close(tls: *mut PcTls) -> PcStatus {
    guard(|| {
        if tls.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = &mut unsafe { &mut *tls }.inner;
        let _ = conn.close();
        PcStatus::Ok
    })
}

/// DTLS: returns the next retransmission timeout in `(seconds, nanos)`, with
/// `has_timeout` set to 1 if a timeout is currently scheduled and 0
/// otherwise. Returns [`PcStatus::Unsupported`] for TLS connections.
///
/// # Safety
/// All pointers valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_dtls_next_timeout(
    tls: *const PcTls,
    seconds_out: *mut u64,
    nanos_out: *mut u32,
    has_timeout: *mut i32,
) -> PcStatus {
    guard(|| {
        if tls.is_null() || seconds_out.is_null() || nanos_out.is_null() || has_timeout.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = unsafe { &*tls };
        let v = conn.inner.negotiated_version();
        if !matches!(
            v,
            Some(ProtocolVersion::DTLSv1_2) | Some(ProtocolVersion::DTLSv1_3)
        ) {
            return PcStatus::Unsupported;
        }
        let dur = conn.inner.next_timeout();
        match dur {
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

/// DTLS: notifies the engine that a timeout has elapsed. `now_seconds` and
/// `now_nanos` are the time since the connection started.
///
/// # Safety
/// `tls` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_dtls_on_timeout(
    tls: *mut PcTls,
    now_seconds: u64,
    now_nanos: u32,
) -> PcStatus {
    guard(|| {
        if tls.is_null() {
            return PcStatus::NullPointer;
        }
        let conn = unsafe { &mut *tls };
        let v = conn.inner.negotiated_version();
        if !matches!(
            v,
            Some(ProtocolVersion::DTLSv1_2) | Some(ProtocolVersion::DTLSv1_3)
        ) {
            return PcStatus::Unsupported;
        }
        let dur = core::time::Duration::new(now_seconds, now_nanos);
        conn.inner.on_timeout(dur);
        PcStatus::Ok
    })
}

// ---- Helpers --------------------------------------------------------------

/// Splits a PEM bundle into individual labeled blocks. Each non-empty
/// concatenated chunk between matching `-----BEGIN $LABEL-----` /
/// `-----END $LABEL-----` markers is returned as a separate string.
fn pem_split(pem: &str, label: &str) -> Vec<String> {
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
            break;
        }
    }
    out
}

/// Splits a PEM bundle of `CERTIFICATE` blocks into DER chunks, leaf first.
fn pem_split_cert_chain(pem: &str) -> Vec<Vec<u8>> {
    let mut chain = Vec::new();
    for block in pem_split(pem, "CERTIFICATE") {
        if let Ok(der) = crate::der::pem_decode(&block, "CERTIFICATE") {
            chain.push(der);
        }
    }
    chain
}
