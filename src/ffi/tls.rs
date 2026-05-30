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

    // The three `build_*` helpers re-parse PEM strings that were already
    // validated by their `pc_tls_cfg_add_*_pem` entry points (each adds to a
    // throwaway store and rejects on failure before persisting). A failure
    // here therefore indicates a parser regression, not user input — we use
    // `expect` instead of silently dropping certificates from the trust store.

    fn build_roots(&self) -> RootCertStore {
        let mut store = RootCertStore::new();
        for pem in &self.roots_pem {
            store
                .add_pem(pem)
                .expect("build_roots: pre-validated PEM failed to re-parse");
        }
        store
    }

    fn build_crls(&self) -> CrlStore {
        let mut store = CrlStore::new();
        for pem in &self.crls_pem {
            store
                .add_pem(pem)
                .expect("build_crls: pre-validated PEM failed to re-parse");
        }
        store
    }

    fn build_client_auth_roots(&self) -> RootCertStore {
        let mut store = RootCertStore::new();
        for pem in &self.client_auth_roots_pem {
            store
                .add_pem(pem)
                .expect("build_client_auth_roots: pre-validated PEM failed to re-parse");
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
    crate::ffi::common::guard_ptr(|| {
        let Some(r) = Role::from_i32(role) else {
            return core::ptr::null_mut();
        };
        let Some(v) = Version::from_i32(version) else {
            return core::ptr::null_mut();
        };
        Box::into_raw(Box::new(PcTlsCfg::new(r, v)))
    })
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
        let chain_der = match pem_split_cert_chain(chain_str) {
            Ok(v) => v,
            Err(e) => return e.to_status(),
        };
        let key_str = match core::str::from_utf8(kp) {
            Ok(s) => s,
            Err(_) => return PcStatus::BadEncoding,
        };
        // Try formats in roughly best-known-first order: PKCS#1 RSA (the
        // OpenSSL legacy `-----BEGIN RSA PRIVATE KEY-----`), PKCS#8 RSA
        // (the modern `-----BEGIN PRIVATE KEY-----` envelope around an RSA
        // key — what `openssl pkey` and `openssl genpkey` emit by default
        // since 1.0.2), SEC1 EC, then PKCS#8 Ed25519. PKCS#8 with an EC key
        // is not (yet) split out here; SEC1 covers the EC PEM path.
        let key = if let Ok(k) = BoxedRsaPrivateKey::from_pkcs1_pem(key_str) {
            PcKey::Rsa(k)
        } else if let Ok(k) = BoxedRsaPrivateKey::from_pkcs8_pem(key_str) {
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
        let blocks = match pem_split(s, "CERTIFICATE") {
            Ok(v) => v,
            Err(e) => return e.to_status(),
        };
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
    crate::ffi::common::guard_ptr(|| {
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
    })
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
/// If `consumed` is non-NULL, the number of bytes the engine accepted into
/// its input buffer is written before this call returns — including on the
/// error paths. Callers MUST consult `*consumed` after a non-`Ok` return so
/// they neither re-feed already-buffered bytes nor lose the still-unbuffered
/// tail.
///
/// Returns:
///   * `Ok` — bytes accepted; the engine may need more (call `feed` again)
///     or be ready to make progress (call `handshake` / `pop` / `recv`).
///   * `Internal` — the engine produced a fatal error while processing the
///     bytes that were already buffered. `*consumed` reflects what was
///     accepted before the failure (today: the whole slice — `read_tls`
///     buffers eagerly, the diagnostic is raised by post-buffer processing).
///   * `NullPointer` — `tls` is NULL, or `wire_in` is NULL with non-zero
///     `in_len`.
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
        // Helper: report how many bytes the engine took into its buffer
        // before returning to the caller. Done as an inline closure so the
        // error and success paths share the same write — easy to keep them
        // in sync if `feed` ever stops buffering eagerly.
        let write_consumed = |n: usize| {
            if !consumed.is_null() {
                unsafe { *consumed = n };
            }
        };
        if tls.is_null() {
            write_consumed(0);
            return PcStatus::NullPointer;
        }
        let Some(b) = (unsafe { slice(wire_in, in_len) }) else {
            write_consumed(0);
            return PcStatus::NullPointer;
        };
        let conn = &mut unsafe { &mut *tls }.inner;
        match conn.feed(b) {
            Ok(n) => {
                write_consumed(n);
                PcStatus::Ok
            }
            Err(_) => {
                // The TLS engines `read_tls(wire_in)` before
                // `process_new_packets()` errors, so every byte the caller
                // handed in is already inside the engine's input buffer.
                // Reporting that lets the caller advance its read cursor
                // and avoid double-feeding the tail.
                write_consumed(in_len);
                PcStatus::Internal
            }
        }
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
    crate::ffi::common::guard_i32(0, || {
        if tls.is_null() {
            return 0;
        }
        if unsafe { &*tls }.inner.is_handshake_complete() {
            1
        } else {
            0
        }
    })
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

/// Writes the IANA cipher-suite identifier of the negotiated suite to `*out`,
/// or `0` if no suite has been selected yet (handshake not started / not yet
/// past ServerHello). Always returns `Ok` once the pointer check passes.
///
/// Codes follow the IANA TLS Cipher Suite Registry:
///   0x1301 TLS_AES_128_GCM_SHA256, 0x1302 TLS_AES_256_GCM_SHA384,
///   0x1303 TLS_CHACHA20_POLY1305_SHA256, and the TLS 1.2 ECDHE-AEAD set
///   (0xC02B/C02C/C02F/C030, 0xCCA8/CCA9).
///
/// # Safety
/// `tls`, `out` valid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_negotiated_cipher_suite(
    tls: *const PcTls,
    out: *mut u16,
) -> PcStatus {
    guard(|| {
        if tls.is_null() || out.is_null() {
            return PcStatus::NullPointer;
        }
        let v = unsafe { &*tls }
            .inner
            .negotiated_cipher_suite()
            .unwrap_or(0);
        unsafe { *out = v };
        PcStatus::Ok
    })
}

/// Writes the IANA name of the negotiated cipher suite (e.g.
/// `"TLS_AES_128_GCM_SHA256"`) into `out` as raw UTF-8 bytes (no trailing
/// NUL — `*out_len` is the exact byte count, matching the convention used
/// by [`pc_tls_alpn_selected`] / [`pc_tls_peer_server_name`]). When no suite
/// is selected yet, `*out_len = 0` and `Ok` is returned.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_negotiated_cipher_suite_name(
    tls: *const PcTls,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if tls.is_null() {
            return PcStatus::NullPointer;
        }
        let name: &[u8] = unsafe { &*tls }
            .inner
            .negotiated_cipher_suite_name()
            .map(str::as_bytes)
            .unwrap_or(&[]);
        unsafe { out_write(name, out, out_len) }
    })
}

/// Server-side: writes the SNI host_name the client offered in its
/// ClientHello to `out` as raw UTF-8 bytes (no trailing NUL — `*out_len`
/// is the exact byte count). If the client omitted the extension, or this
/// is a client engine, or no ClientHello has been processed yet,
/// `*out_len = 0` and `Ok` is returned.
///
/// # Safety
/// All pointers valid for their declared lengths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pc_tls_peer_server_name(
    tls: *const PcTls,
    out: *mut u8,
    out_len: *mut usize,
) -> PcStatus {
    guard(|| {
        if tls.is_null() {
            return PcStatus::NullPointer;
        }
        let name: &[u8] = unsafe { &*tls }
            .inner
            .peer_server_name()
            .map(str::as_bytes)
            .unwrap_or(&[]);
        unsafe { out_write(name, out, out_len) }
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

/// Distinct PEM-parsing failure modes the FFI callers want to surface as
/// distinct [`PcStatus`] codes (per the FFI-4 audit finding). Without this,
/// every PEM-related failure collapsed into `BadEncoding` and the C caller
/// could not tell "you passed me empty bytes" from "you passed me a real but
/// broken PEM block".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PemSplitError {
    /// The input is well-formed at the framing layer but contains no blocks
    /// of the requested `LABEL`. Maps to [`PcStatus::BadEncoding`] today; a
    /// future header revision may promote it to a dedicated code.
    NoBlocks,
    /// A `-----BEGIN LABEL-----` marker was found with no matching
    /// `-----END LABEL-----` trailer. Maps to [`PcStatus::BadEncoding`] but
    /// kept distinct so the caller can log the precise reason and we don't
    /// pretend the input was simply empty.
    Malformed,
}

impl PemSplitError {
    /// Maps to the FFI status code surfaced to the C caller. Today both
    /// variants are `BadEncoding`; the enum lives so the call sites can
    /// log the precise reason and a future ABI revision can split them.
    pub(crate) fn to_status(self) -> PcStatus {
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
    let mut saw_begin = false;
    while let Some(b_off) = rest.find(&begin) {
        saw_begin = true;
        let after_b = b_off;
        if let Some(e_off) = rest[after_b..].find(&end) {
            let abs_end = after_b + e_off + end.len();
            out.push(rest[after_b..abs_end].to_string());
            rest = &rest[abs_end..];
        } else {
            // BEGIN with no matching END — this is "malformed", not "empty".
            return Err(PemSplitError::Malformed);
        }
    }
    if out.is_empty() {
        // Distinguish "I found nothing at all" (NoBlocks) from "I tried and
        // gave up because the framing was wrong" (Malformed, returned above).
        if saw_begin {
            // Unreachable: a BEGIN without END returns Malformed above.
            return Err(PemSplitError::Malformed);
        }
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
        // A block with framing but unparseable base64 / DER is *malformed*;
        // the old code silently dropped it, masking the bug from the C caller.
        let der =
            crate::der::pem_decode(&block, "CERTIFICATE").map_err(|_| PemSplitError::Malformed)?;
        chain.push(der);
    }
    if chain.is_empty() {
        // Shouldn't reach here (pem_split returns NoBlocks for empty input),
        // but stay defensive — surfacing NoBlocks is the truthful answer.
        return Err(PemSplitError::NoBlocks);
    }
    Ok(chain)
}

#[cfg(test)]
mod tls_ffi_tests {
    //! FFI-3 and FFI-4 regression coverage:
    //!   * FFI-3 — [`pc_tls_feed`] writes the consumed byte count even on
    //!     the error path so the C caller can advance its read cursor.
    //!   * FFI-4 — [`pem_split`] / [`pem_split_cert_chain`] distinguish
    //!     "no blocks" from "malformed framing" from "well-framed but
    //!     undecodable body".
    use super::*;
    use crate::ffi::common::PcStatus;

    // ---- FFI-4 -----------------------------------------------------------

    #[test]
    fn pem_split_no_blocks_returns_no_blocks() {
        let err = pem_split("no PEM here, just chatter", "CERTIFICATE").unwrap_err();
        assert_eq!(err, PemSplitError::NoBlocks);
        assert_eq!(err.to_status(), PcStatus::BadEncoding);
    }

    #[test]
    fn pem_split_empty_input_returns_no_blocks() {
        let err = pem_split("", "CERTIFICATE").unwrap_err();
        assert_eq!(err, PemSplitError::NoBlocks);
    }

    #[test]
    fn pem_split_begin_without_end_returns_malformed() {
        let bad = "-----BEGIN CERTIFICATE-----\nAAAA\n(missing END)\n";
        let err = pem_split(bad, "CERTIFICATE").unwrap_err();
        assert_eq!(err, PemSplitError::Malformed);
        assert_eq!(err.to_status(), PcStatus::BadEncoding);
    }

    #[test]
    fn pem_split_label_mismatch_treated_as_no_blocks() {
        // A PUBLIC KEY block doesn't satisfy a request for CERTIFICATE
        // blocks, and the call must say "no blocks of that label" rather
        // than silently succeeding with an empty Vec.
        let p = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n";
        let err = pem_split(p, "CERTIFICATE").unwrap_err();
        assert_eq!(err, PemSplitError::NoBlocks);
    }

    #[test]
    fn pem_split_two_valid_blocks_returns_both() {
        let two = "\
-----BEGIN CERTIFICATE-----
AAAA
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
BBBB
-----END CERTIFICATE-----
";
        let blocks = pem_split(two, "CERTIFICATE").unwrap();
        assert_eq!(blocks.len(), 2);
        assert!(blocks[0].contains("AAAA"));
        assert!(blocks[1].contains("BBBB"));
    }

    #[test]
    fn pem_split_cert_chain_undecodable_block_is_malformed() {
        // Framing is fine, but the base64 body is garbage; the old code
        // silently dropped this and returned an empty chain (looking
        // identical to "no blocks"). The new code distinguishes them.
        let bad = "\
-----BEGIN CERTIFICATE-----
!!! not base64 !!!
-----END CERTIFICATE-----
";
        let err = pem_split_cert_chain(bad).unwrap_err();
        assert_eq!(err, PemSplitError::Malformed);
    }

    #[test]
    fn pem_split_cert_chain_no_blocks_is_no_blocks() {
        let err = pem_split_cert_chain("not pem at all").unwrap_err();
        assert_eq!(err, PemSplitError::NoBlocks);
    }

    // ---- FFI-3 -----------------------------------------------------------

    /// Builds a minimal client `PcTls` that accepts any cert (no roots
    /// configured). We never run the handshake — we only need a real
    /// engine sitting in the "expecting ServerHello" state.
    fn client_tls() -> *mut PcTls {
        // `pc_tls_cfg_new` is `extern "C" fn` (not `unsafe extern "C" fn`).
        let cfg = pc_tls_cfg_new(Role::Client as i32, Version::Tls13 as i32);
        assert!(!cfg.is_null());
        // Disable verification so no roots are required.
        let st = unsafe { pc_tls_cfg_set_verify_certificates(cfg, 0) };
        assert_eq!(st, PcStatus::Ok);
        // SNI is required for a TLS 1.3 client config to build.
        let sni = b"loopback.example\0";
        let st =
            unsafe { pc_tls_cfg_set_server_name(cfg, sni.as_ptr() as *const core::ffi::c_char) };
        assert_eq!(st, PcStatus::Ok);
        let tls = unsafe { pc_tls_new(cfg) };
        unsafe { pc_tls_cfg_free(cfg) };
        assert!(!tls.is_null());
        tls
    }

    /// `pc_tls_feed` with a valid (zero-byte) slice must report 0 consumed,
    /// not leave `*consumed` undefined.
    #[test]
    fn feed_empty_reports_zero_consumed() {
        let tls = client_tls();
        let mut consumed: usize = 0xdead_beef;
        let st = unsafe { pc_tls_feed(tls, core::ptr::null(), 0, &mut consumed) };
        assert_eq!(st, PcStatus::Ok);
        assert_eq!(consumed, 0);
        unsafe { pc_tls_free(tls) };
    }

    /// FFI-3 — feed bytes that the engine will reject during processing.
    /// `*consumed` MUST be written before the error code is returned so
    /// the caller can advance its read cursor past the rejected bytes
    /// (otherwise the next feed re-delivers them, looping forever or
    /// silently dropping the unbuffered tail).
    #[test]
    fn feed_writes_consumed_on_error_path() {
        let tls = client_tls();
        // Garbage at the record layer: a TLS record header claiming
        // version 0x0000 / length 0xFFFF and zero payload — the engine
        // rejects the first record, not after coalescing more bytes.
        let bad: [u8; 12] = [0x17, 0x03, 0x03, 0x00, 0xff, 0xee, 0xdd, 0, 0, 0, 0, 0];
        let mut consumed: usize = 0xdead_beef;
        let st = unsafe { pc_tls_feed(tls, bad.as_ptr(), bad.len(), &mut consumed) };
        // Either the engine swallows it (Ok) — in which case all bytes
        // were buffered — or it errors. EITHER WAY, `consumed` must have
        // been overwritten from its sentinel.
        assert_ne!(
            consumed, 0xdead_beef,
            "pc_tls_feed must write *consumed before returning",
        );
        // On the error path today, `read_tls` buffers all of `in_len`
        // before `process_new_packets` errors, so we expect a full
        // consumed count when feeding fails.
        if st != PcStatus::Ok {
            assert_eq!(
                consumed,
                bad.len(),
                "engine buffered all bytes before erroring",
            );
        }
        unsafe { pc_tls_free(tls) };
    }

    /// NULL `consumed` is allowed (the C caller may opt out of the
    /// count). The function must not crash when passed NULL there.
    #[test]
    fn feed_with_null_consumed_does_not_crash() {
        let tls = client_tls();
        let bytes = [0u8; 4];
        let st = unsafe { pc_tls_feed(tls, bytes.as_ptr(), bytes.len(), core::ptr::null_mut()) };
        // Either Ok (buffered) or an error — the precise status is
        // not the point; the point is that we didn't deref the NULL.
        let _ = st;
        unsafe { pc_tls_free(tls) };
    }

    /// `pc_tls_feed(NULL, ...)` must write `*consumed = 0` so the C
    /// caller can rely on `*consumed` being initialised across every
    /// error path.
    #[test]
    fn feed_null_handle_reports_zero_consumed() {
        let mut consumed: usize = 99;
        let st = unsafe { pc_tls_feed(core::ptr::null_mut(), core::ptr::null(), 0, &mut consumed) };
        assert_eq!(st, PcStatus::NullPointer);
        assert_eq!(consumed, 0);
    }
}
