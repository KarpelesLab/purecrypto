//! TLS 1.3 pre-shared keys: the key-exchange modes a PSK may be used with
//! (RFC 8446 §4.2.9) and externally provisioned PSKs (§4.2.11, RFC 9257),
//! including the RFC 9258 importer that binds one to a hash function.

use alloc::vec::Vec;

use crate::zeroize::Zeroizing;

use super::codec::with_len_u16;
use super::crypto::{HashAlg, expand_label_dyn, extract};
use super::error::Error;

/// How a TLS 1.3 pre-shared key — a resumption ticket or an
/// [`ExternalPsk`] — is combined with a key exchange (RFC 8446 §4.2.9,
/// `PskKeyExchangeMode`).
///
/// The list a [`Config`](super::Config) allows is
/// [`psk_modes`](super::Config::psk_modes); the default is
/// [`PskDheKe`](Self::PskDheKe) alone.
///
/// # `psk_ke` gives up forward secrecy
///
/// With [`PskDheKe`](Self::PskDheKe) every connection mixes a fresh
/// (EC)DHE / ML-KEM shared secret into the key schedule, so a PSK that leaks
/// *later* does not open the traffic of connections already made. With
/// [`PskKe`](Self::PskKe) the PSK is the only secret input (the (EC)DHE
/// input of the key schedule is a string of zeros, RFC 8446 §7.1): whoever
/// learns the PSK — for a resumption ticket that includes whoever learns the
/// server's [`ticket_key`](super::Config::ticket_key) — can decrypt every
/// recorded connection made with it, and all the sessions resumed from
/// those. It also takes the post-quantum hybrid groups out of the resumed
/// handshake. It exists for constrained devices that cannot afford the
/// public-key operations; do not enable it otherwise.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub enum PskKeyExchangeMode {
    /// `psk_ke` (0): PSK-only key establishment. No `key_share` is
    /// exchanged; **no forward secrecy** (see the type-level docs).
    PskKe,
    /// `psk_dhe_ke` (1): PSK with (EC)DHE key establishment. The default.
    PskDheKe,
}

impl PskKeyExchangeMode {
    /// The RFC 8446 name of the mode: `"psk_ke"` or `"psk_dhe_ke"`.
    pub const fn name(self) -> &'static str {
        match self {
            PskKeyExchangeMode::PskKe => "psk_ke",
            PskKeyExchangeMode::PskDheKe => "psk_dhe_ke",
        }
    }

    /// The `PskKeyExchangeMode` wire value (RFC 8446 §4.2.9).
    pub(crate) const fn wire(self) -> u8 {
        match self {
            PskKeyExchangeMode::PskKe => 0,
            PskKeyExchangeMode::PskDheKe => 1,
        }
    }
}

/// The wire bytes of a mode list, in order, without duplicates.
pub(crate) fn modes_wire(modes: &[PskKeyExchangeMode]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2);
    for m in modes {
        if !out.contains(&m.wire()) {
            out.push(m.wire());
        }
    }
    out
}

/// Shortest secret [`ExternalPsk::new`] accepts, in bytes: RFC 9257 §6 asks
/// for at least 128 bits of entropy, which fewer than 16 bytes cannot hold.
pub(crate) const MIN_EXTERNAL_PSK_LEN: usize = 16;
/// Longest secret [`ExternalPsk::new`] accepts, in bytes.
pub(crate) const MAX_EXTERNAL_PSK_LEN: usize = 512;
/// Longest identity [`ExternalPsk::new`] accepts, in bytes. The wire field
/// is `opaque identity<1..2^16-1>` (RFC 8446 §4.2.11); an identity is a
/// label, not a payload, and every offered identity rides in the
/// ClientHello.
pub(crate) const MAX_EXTERNAL_PSK_IDENTITY_LEN: usize = 1024;

/// A pre-shared key provisioned out of band (RFC 8446 §4.2.11, RFC 9257):
/// an identity both peers know the key by, the key itself, and the hash
/// function it is used with.
///
/// Install it on both peers with
/// [`ConfigBuilder::external_psk`](super::ConfigBuilder::external_psk). A
/// handshake that selects it is authenticated by the key alone — the server
/// sends no `Certificate` / `CertificateVerify` (RFC 8446 §2.2) — so the
/// key is the whole of the peer authentication:
///
/// * **It must be high-entropy** (RFC 9257 §4.1, §6: at least 128 bits of
///   entropy, from a cryptographically secure generator). Every handshake
///   puts a binder — an HMAC keyed from the PSK over public data — on the
///   wire, so a passive observer can test guesses offline: a password or a
///   short PIN is recovered at once. A low-entropy secret needs a PAKE, not
///   TLS-PSK. [`new`](Self::new) refuses secrets under 16 bytes, which
///   cannot hold 128 bits; it cannot judge the entropy of longer ones.
/// * **One key per pair of peers** (RFC 9257 §4.1). Any holder of the key
///   can impersonate any other holder: a key shared by a group of clients
///   lets each of them act as the server towards the others.
/// * **The identity travels in the clear** in the ClientHello (RFC 9257
///   §5): do not put anything in it that must stay private, and expect it
///   to link the connections of one client.
/// * **One hash per key** (RFC 8446 §4.2.11: "the Hash algorithm MUST be
///   set when the PSK is established", SHA-256 when nothing else is
///   defined). The handshake can only select a cipher suite with that hash.
///
/// The secret is wiped when the value is dropped, and
/// [`Debug`](core::fmt::Debug) never prints it.
///
/// ```
/// use purecrypto::tls::{Config, ExternalPsk, HashAlg};
///
/// let psk = ExternalPsk::new(b"device-17".to_vec(), vec![0x5au8; 32]).unwrap();
/// assert_eq!(psk.identity(), b"device-17");
/// assert_eq!(psk.hash(), HashAlg::Sha256);
/// let cfg = Config::builder().external_psk(psk).build();
/// assert_eq!(cfg.external_psks.len(), 1);
/// // Too short to hold 128 bits of entropy (RFC 9257 §6):
/// assert!(ExternalPsk::new(b"device-17".to_vec(), b"hunter2".to_vec()).is_err());
/// ```
#[derive(Clone)]
pub struct ExternalPsk {
    identity: Vec<u8>,
    secret: Zeroizing<Vec<u8>>,
    hash: HashAlg,
    /// Produced by [`import`](Self::import): the binder is keyed under the
    /// `"imp binder"` label (RFC 9258 §5.2) rather than `"ext binder"`.
    imported: bool,
}

impl ExternalPsk {
    /// A PSK known as `identity`, for use with SHA-256 cipher suites (the
    /// RFC 8446 §4.2.11 default).
    ///
    /// Fails with [`Error::InappropriateState`] when `identity` is empty or
    /// longer than 1024 bytes, or when `secret` is shorter than 16 bytes or
    /// longer than 512. `secret` is moved into a wiping container; a copy
    /// the caller keeps is the caller's to wipe.
    pub fn new(identity: Vec<u8>, secret: Vec<u8>) -> Result<Self, Error> {
        // Into the wiping container first, so a refused secret is wiped too.
        let secret = Zeroizing::new(secret);
        if identity.is_empty()
            || identity.len() > MAX_EXTERNAL_PSK_IDENTITY_LEN
            || secret.len() < MIN_EXTERNAL_PSK_LEN
            || secret.len() > MAX_EXTERNAL_PSK_LEN
        {
            return Err(Error::InappropriateState);
        }
        Ok(ExternalPsk {
            identity,
            secret,
            hash: HashAlg::Sha256,
            imported: false,
        })
    }

    /// Uses the PSK with `hash` (and so with the cipher suites of that
    /// hash) instead of SHA-256. Both peers must agree on it: the binder is
    /// computed with this hash, so a mismatch fails the handshake.
    pub fn with_hash(mut self, hash: HashAlg) -> Self {
        self.hash = hash;
        self
    }

    /// Imports an external PSK per RFC 9258 (the "PSK importer"): the key
    /// actually used is derived from `secret` for TLS 1.3 and `hash`, and
    /// the identity on the wire is the `ImportedIdentity` structure
    /// (`external_identity ‖ context ‖ target_protocol ‖ target_kdf`), so
    /// one provisioned key can serve several protocols and hashes without
    /// the same key being used with different KDFs (RFC 8446 §4.2.11
    /// requires one hash per PSK; the importer is how a key that was not
    /// provisioned with one gets it). `context` is any application
    /// context, empty by default (RFC 9258 §5.1).
    ///
    /// Both peers must import the same way. This is what BoringSSL's
    /// `bssl` does with `-psk-hex` / `-psk-identity` / `-psk-context` (and
    /// `-psk-sha384`); OpenSSL, GnuTLS, wolfSSL and Mbed TLS use the key as
    /// given ([`new`](Self::new)).
    ///
    /// The binder of an imported PSK is derived under the `"imp binder"`
    /// label (RFC 9258 §5.2).
    ///
    /// ```text
    /// ImportedIdentity = external_identity<1..2^16-1> ‖ context<0..2^16-1>
    ///                    ‖ target_protocol (0x0304) ‖ target_kdf (0x0001 HKDF_SHA256 | 0x0002 HKDF_SHA384)
    /// epskx = HKDF-Extract(0, secret)
    /// ipskx = HKDF-Expand-Label(epskx, "derived psk", Hash(ImportedIdentity), Hash.length)
    /// ```
    ///
    /// The same bounds as [`new`](Self::new) apply to `identity` and
    /// `secret`; `context` is limited to 1024 bytes as well.
    pub fn import(
        identity: Vec<u8>,
        context: &[u8],
        secret: Vec<u8>,
        hash: HashAlg,
    ) -> Result<Self, Error> {
        let base = Self::new(identity, secret)?;
        if context.len() > MAX_EXTERNAL_PSK_IDENTITY_LEN {
            return Err(Error::InappropriateState);
        }
        // RFC 9258 §5.1, the `ImportedIdentity` structure.
        let mut imported = Vec::with_capacity(2 + base.identity.len() + 2 + context.len() + 4);
        with_len_u16(&mut imported, |b| b.extend_from_slice(&base.identity));
        with_len_u16(&mut imported, |b| b.extend_from_slice(context));
        // target_protocol: TLS 1.3 (0x0304), the only one this crate uses
        // the key for (DTLS 1.3 would be 0xFEFC).
        imported.extend_from_slice(&[0x03, 0x04]);
        // target_kdf: the HKDF of the target hash (RFC 9258 §7).
        let target_kdf: u16 = match hash {
            HashAlg::Sha256 => 0x0001,
            HashAlg::Sha384 => 0x0002,
        };
        imported.extend_from_slice(&target_kdf.to_be_bytes());
        // §5.1: `epskx = HKDF-Extract(0, EPSK)`, `ipskx = HKDF-Expand-Label(
        // epskx, "derived psk", Hash(ImportedIdentity), L)`, with the
        // KDF's hash. (`extract` copies the result into a wiping `Secret`.)
        let epskx = extract(hash, &[], &base.secret);
        let id_hash = hash.hash(&imported);
        let n = hash.output_len();
        let mut ipskx = Zeroizing::new(alloc::vec![0u8; n]);
        expand_label_dyn(
            hash,
            epskx.as_slice(),
            b"derived psk",
            id_hash.as_slice(),
            &mut ipskx,
        );
        Ok(ExternalPsk {
            identity: imported,
            secret: ipskx,
            hash,
            imported: true,
        })
    }

    /// The identity the PSK is offered and looked up by.
    pub fn identity(&self) -> &[u8] {
        &self.identity
    }

    /// The hash function the PSK is used with.
    pub fn hash(&self) -> HashAlg {
        self.hash
    }

    /// The key.
    pub(crate) fn secret(&self) -> &Zeroizing<Vec<u8>> {
        &self.secret
    }

    /// The label the binder key is derived under (RFC 8446 §4.2.11.2,
    /// RFC 9258 §5.2): `"ext binder"` for a key used as provisioned,
    /// `"imp binder"` for one that went through the importer — so a key
    /// provisioned one way never validates a binder made the other way.
    pub(crate) fn binder_label(&self) -> &'static [u8] {
        if self.imported {
            b"imp binder"
        } else {
            b"ext binder"
        }
    }
}

impl core::fmt::Debug for ExternalPsk {
    /// Prints the identity and the hash, never the secret.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ExternalPsk")
            .field("identity", &self.identity)
            .field("hash", &self.hash)
            .field(
                "secret",
                &format_args!("<{} bytes, redacted>", self.secret.len()),
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;
    use alloc::vec;

    #[test]
    fn external_psk_bounds() {
        assert!(ExternalPsk::new(b"id".to_vec(), vec![1u8; 16]).is_ok());
        assert!(ExternalPsk::new(b"id".to_vec(), vec![1u8; 512]).is_ok());
        assert!(ExternalPsk::new(vec![b'i'; 1024], vec![1u8; 16]).is_ok());
        for (id, secret) in [
            (Vec::new(), vec![1u8; 32]),
            (vec![b'i'; 1025], vec![1u8; 32]),
            (b"id".to_vec(), Vec::new()),
            (b"id".to_vec(), vec![1u8; 15]),
            (b"id".to_vec(), vec![1u8; 513]),
        ] {
            assert_eq!(
                ExternalPsk::new(id, secret).unwrap_err(),
                Error::InappropriateState
            );
        }
    }

    #[test]
    fn external_psk_debug_is_redacted() {
        let psk = ExternalPsk::new(b"id".to_vec(), vec![0xABu8; 32])
            .unwrap()
            .with_hash(HashAlg::Sha384);
        let s = format!("{psk:?}");
        assert!(s.contains("Sha384"));
        assert!(s.contains("<32 bytes, redacted>"));
        assert!(!s.contains("171") && !s.to_lowercase().contains("ab, ab"));
    }

    /// RFC 9258 §5.1 importer: the wire identity is the `ImportedIdentity`
    /// structure, the key is derived (never the EPSK itself), and every
    /// input — identity, context, hash — changes the derived key.
    #[test]
    fn importer_derives_identity_and_key() {
        let epsk = vec![0x5au8; 32];
        let a = ExternalPsk::import(b"id".to_vec(), b"", epsk.clone(), HashAlg::Sha256).unwrap();
        assert_eq!(
            a.identity(),
            [&[0, 2][..], b"id", &[0, 0], &[0x03, 0x04], &[0x00, 0x01]].concat()
        );
        assert_eq!(a.hash(), HashAlg::Sha256);
        assert_eq!(a.secret().len(), 32);
        assert_ne!(&a.secret()[..], &epsk[..]);
        let b = ExternalPsk::import(b"id".to_vec(), b"ctx", epsk.clone(), HashAlg::Sha256).unwrap();
        assert_ne!(a.identity(), b.identity());
        assert_ne!(&a.secret()[..], &b.secret()[..]);
        assert_eq!(a.binder_label(), b"imp binder");
        assert_eq!(
            ExternalPsk::new(b"id".to_vec(), epsk.clone())
                .unwrap()
                .binder_label(),
            b"ext binder"
        );
        let c = ExternalPsk::import(b"id".to_vec(), b"", epsk.clone(), HashAlg::Sha384).unwrap();
        assert_eq!(c.secret().len(), 48);
        assert_eq!(&c.identity()[c.identity().len() - 2..], &[0x00, 0x02]);
        // Deterministic.
        let a2 = ExternalPsk::import(b"id".to_vec(), b"", epsk, HashAlg::Sha256).unwrap();
        assert_eq!(&a.secret()[..], &a2.secret()[..]);
        assert!(
            ExternalPsk::import(b"id".to_vec(), &[0u8; 1025], vec![1u8; 32], HashAlg::Sha256)
                .is_err()
        );
    }

    #[test]
    fn mode_wire_values() {
        assert_eq!(PskKeyExchangeMode::PskKe.wire(), 0);
        assert_eq!(PskKeyExchangeMode::PskDheKe.wire(), 1);
        assert_eq!(PskKeyExchangeMode::PskKe.name(), "psk_ke");
        assert_eq!(PskKeyExchangeMode::PskDheKe.name(), "psk_dhe_ke");
        assert_eq!(
            modes_wire(&[
                PskKeyExchangeMode::PskDheKe,
                PskKeyExchangeMode::PskKe,
                PskKeyExchangeMode::PskDheKe
            ]),
            [1, 0]
        );
        assert!(modes_wire(&[]).is_empty());
    }
}
