//! Transparent pluggable private keys (`std` only).
//!
//! The sans-I/O engine already supports out-of-process signing via the
//! [`SigningKey::External`](super::config::SigningKey::External) primitive plus
//! [`Connection::signature_request`](super::Connection::signature_request) /
//! [`provide_signature`](super::Connection::provide_signature). That primitive
//! is `alloc`-only and fully `no_std`-compatible, but it makes the caller
//! hand-broker each signature.
//!
//! This module layers a *transparent* API on top of it: the caller installs one
//! [`PrivateKey`] trait object on the [`Config`](super::Config) via
//! [`ConfigBuilder::private_key`](super::ConfigBuilder::private_key) and then
//! drives the handshake with [`Connection::drive`](super::Connection::drive),
//! never branching on what kind of key it is. An in-process RSA key, a local
//! TPM, and a network HSM all look identical to the caller.
//!
//! The key owns its own device transport. When a device is slow it must not
//! block the engine, so [`SignOp`] is itself a non-blocking state machine:
//! [`resume`](SignOp::resume) advances one step and returns [`SignProgress`],
//! and while it is [`Pending`](SignProgress::Pending) the op exposes an opaque
//! [`Readiness`] token the caller folds into the event loop it already runs —
//! `poll(2)`/epoll for a synchronous loop, or
//! [`AsyncFd`](https://docs.rs/tokio/latest/tokio/io/unix/struct.AsyncFd.html)
//! for an async one. In-process keys never go [`Pending`] and so never block.
//!
//! This whole module is `#[cfg(feature = "std")]`: [`Readiness`] wraps an OS
//! file descriptor, and the crate confines all descriptor use behind `std`
//! (mirroring [`crate::rng`] and [`super::keylog`]) so the `no_std` core keeps
//! building on bare targets.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use super::config::SigningKey;
use super::error::Error;

/// A private key for the local endpoint, usable whether the key lives in this
/// process or behind a device (TPM/HSM/PKCS#11) driver crate.
///
/// Install one on a [`Config`](super::Config) with
/// [`ConfigBuilder::private_key`](super::ConfigBuilder::private_key). The engine
/// calls [`start_sign`](Self::start_sign) when the handshake reaches the
/// identity signature (TLS 1.3 / DTLS 1.3 `CertificateVerify`, or DTLS 1.2
/// `ServerKeyExchange`) and pumps the returned [`SignOp`] to completion.
///
/// `&self` (not `&mut self`) so one key can be shared across connections behind
/// an `Arc`; per-signature state lives in the [`SignOp`] returned by
/// `start_sign`. In-process keys can be obtained from a [`SigningKey`] via
/// [`LocalSigner`].
pub trait PrivateKey: Send + Sync {
    /// The IANA `SignatureScheme` code points (RFC 8446 §4.2.3) this key can
    /// produce, most-preferred first. Advertised to the peer; the engine
    /// negotiates the concrete scheme against the peer's offer and passes it
    /// back to [`start_sign`](Self::start_sign).
    fn schemes(&self) -> Vec<u16>;

    /// Begin signing `message` under `scheme`. `message` is the exact bytes to
    /// sign (the signer applies the scheme's own hash/padding); the engine has
    /// already framed them. Returns a non-blocking [`SignOp`] driving the work.
    fn start_sign(&self, scheme: u16, message: &[u8]) -> Result<Box<dyn SignOp>, Error>;
}

/// One in-flight signing operation: a non-blocking state machine that owns its
/// device transport.
///
/// The engine calls [`resume`](Self::resume) repeatedly; while it returns
/// [`SignProgress::Pending`] the caller waits on [`readiness`](Self::readiness)
/// before the next call, so a slow device never blocks the engine.
pub trait SignOp: Send {
    /// Advance the operation one non-blocking step.
    fn resume(&mut self) -> Result<SignProgress, Error>;

    /// An opaque readiness token to wait on while the last
    /// [`resume`](Self::resume) returned [`Pending`](SignProgress::Pending).
    /// `None` means "no waitable I/O — just call `resume` again"; in-process
    /// keys return `None` and complete on the first `resume`.
    fn readiness(&self) -> Option<Readiness> {
        None
    }
}

/// The outcome of one [`SignOp::resume`] step.
pub enum SignProgress {
    /// The operation is waiting on its device. Wait on
    /// [`SignOp::readiness`] (if any), then call [`SignOp::resume`] again.
    Pending,
    /// The signature is ready: the raw `signatureValue` bytes for the
    /// negotiated scheme (e.g. an ECDSA `Ecdsa-Sig-Value` DER `SEQUENCE`, or
    /// RSA-PSS / EdDSA / ML-DSA raw bytes).
    Done(Vec<u8>),
}

/// An opaque "wait until the device can make progress" token, exposed by
/// [`SignOp::readiness`].
///
/// On unix it wraps a raw file descriptor. Synchronous callers can block on it
/// with [`wait`](Self::wait); async callers register
/// [`as_raw_fd`](Self::as_raw_fd) with their reactor
/// (`tokio::io::unix::AsyncFd`, `mio::unix::SourceFd`, …). The descriptor is
/// owned by the [`SignOp`] and remains valid until the next
/// [`resume`](SignOp::resume).
#[derive(Clone, Copy)]
pub struct Readiness {
    #[cfg(unix)]
    fd: core::ffi::c_int,
}

impl Readiness {
    /// Wrap a raw, borrowed file descriptor. The caller (a [`SignOp`]
    /// implementation) guarantees the fd outlives this token, i.e. is not
    /// closed before the next `resume`.
    #[cfg(unix)]
    pub fn from_raw_fd(fd: core::ffi::c_int) -> Self {
        Readiness { fd }
    }

    /// The underlying file descriptor, for registration with an async reactor.
    #[cfg(unix)]
    pub fn as_raw_fd(&self) -> core::ffi::c_int {
        self.fd
    }

    /// Block until the descriptor is readable (synchronous callers). Retries on
    /// `EINTR`. Async callers should ignore this and drive readiness through
    /// their reactor via [`as_raw_fd`](Self::as_raw_fd) instead.
    ///
    /// On non-unix platforms this is a no-op (device keys there report no
    /// readiness and are simply re-polled).
    pub fn wait(&self) -> std::io::Result<()> {
        #[cfg(unix)]
        {
            // Wait for readability OR an error/hangup; the SignOp interprets
            // what actually happened on the next resume().
            let want = sys::POLLIN | sys::POLLPRI | sys::POLLERR | sys::POLLHUP;
            loop {
                let mut pfd = sys::Pollfd {
                    fd: self.fd,
                    events: want,
                    revents: 0,
                };
                // SAFETY: `pfd` is a single valid pollfd; nfds = 1; timeout = -1
                // (block indefinitely). `poll` only writes `revents`.
                #[allow(unsafe_code)]
                let rc = unsafe { sys::poll(&mut pfd as *mut sys::Pollfd, 1, -1) };
                if rc < 0 {
                    let err = std::io::Error::last_os_error();
                    if err.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(err);
                }
                return Ok(());
            }
        }
        #[cfg(not(unix))]
        {
            Ok(())
        }
    }
}

#[cfg(unix)]
mod sys {
    //! Minimal direct `poll(2)` binding. Declared inline rather than via a
    //! foreign crate, matching the `arc4random_buf` extern in `crate::rng`. The
    //! `#![allow(unsafe_code)]` scope is local — the rest of the module stays
    //! safe.
    #![allow(unsafe_code)]

    use core::ffi::c_int;

    // `nfds_t` is `unsigned long` on Linux/glibc but `unsigned int` on the
    // BSDs and Apple; match each so the C ABI is correct.
    #[cfg(target_os = "linux")]
    pub(super) type NfdsT = core::ffi::c_ulong;
    #[cfg(not(target_os = "linux"))]
    pub(super) type NfdsT = core::ffi::c_uint;

    pub(super) const POLLIN: core::ffi::c_short = 0x0001;
    pub(super) const POLLPRI: core::ffi::c_short = 0x0002;
    pub(super) const POLLERR: core::ffi::c_short = 0x0008;
    pub(super) const POLLHUP: core::ffi::c_short = 0x0010;

    #[repr(C)]
    pub(super) struct Pollfd {
        pub(super) fd: c_int,
        pub(super) events: core::ffi::c_short,
        pub(super) revents: core::ffi::c_short,
    }

    unsafe extern "C" {
        pub(super) fn poll(fds: *mut Pollfd, nfds: NfdsT, timeout: c_int) -> c_int;
    }
}

/// A [`PrivateKey`] backed by an in-process [`SigningKey`].
///
/// Lets the uniform [`Connection::drive`](super::Connection::drive) loop work
/// for ordinary in-process keys too, so callers need only one code path. Its
/// [`SignOp`] computes the signature eagerly and is [`Done`](SignProgress::Done)
/// on the first [`resume`](SignOp::resume) — it never blocks and exposes no
/// [`Readiness`].
///
/// Note: RSA-PSS / ML-DSA salts here come from the platform
/// [`OsRng`](crate::rng::OsRng), independent of any
/// [`EntropySource`](super::EntropySource) on the `Config`. Callers needing the
/// config RNG for in-process signing should use
/// [`ConfigBuilder::identity`](super::ConfigBuilder::identity) instead.
pub struct LocalSigner {
    key: SigningKey,
}

impl LocalSigner {
    /// Wrap an in-process [`SigningKey`]. Intended for the in-process variants
    /// (`Rsa`/`Ecdsa`/`Ed25519`/`Ed448`/`MlDsa*`); wrapping
    /// [`SigningKey::External`](super::config::SigningKey::External) is a
    /// misuse and fails at sign time.
    pub fn new(key: SigningKey) -> Self {
        LocalSigner { key }
    }
}

impl PrivateKey for LocalSigner {
    fn schemes(&self) -> Vec<u16> {
        let server_key = self.key.to_server_key_13();
        vec![super::crypto::signature_scheme_for(&server_key).0]
    }

    fn start_sign(&self, _scheme: u16, message: &[u8]) -> Result<Box<dyn SignOp>, Error> {
        // The key fixes its own scheme (already what `schemes()` advertised and
        // what the engine negotiated), so `_scheme` is informational here. Sign
        // eagerly; the op is immediately Done.
        let server_key = self.key.to_server_key_13();
        let (_scheme, sig) =
            super::crypto::sign_certificate_verify(&server_key, message, &mut crate::rng::OsRng)?;
        Ok(Box::new(ReadySignOp { sig: Some(sig) }))
    }
}

/// A trivial [`SignOp`] holding an already-computed signature.
struct ReadySignOp {
    sig: Option<Vec<u8>>,
}

impl SignOp for ReadySignOp {
    fn resume(&mut self) -> Result<SignProgress, Error> {
        match self.sig.take() {
            Some(sig) => Ok(SignProgress::Done(sig)),
            // resume() after Done: the driver clears the op on Done, so this is
            // only reachable on misuse.
            None => Err(Error::InappropriateState),
        }
    }
}
