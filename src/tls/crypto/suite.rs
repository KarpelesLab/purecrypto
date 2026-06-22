//! Cipher-suite parameters: the mapping from a wire `CipherSuite` to its hash
//! and AEAD.

use super::schedule::HashAlg;
use crate::tls::codec::CipherSuite;

/// The record-protection AEAD of a cipher suite. The key length alone does not
/// identify it — AES-256-GCM and ChaCha20-Poly1305 both take a 32-byte key — so
/// the AEAD is named explicitly.
#[derive(Copy, Clone, PartialEq, Eq)]
pub(crate) enum AeadAlg {
    /// AES-128 in GCM.
    Aes128Gcm,
    /// AES-256 in GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

/// The parameters of a supported TLS 1.3 cipher suite.
#[derive(Copy, Clone)]
pub(crate) struct SuiteParams {
    /// The wire identifier.
    pub(crate) suite: CipherSuite,
    /// The handshake/HKDF hash.
    pub(crate) hash: HashAlg,
    /// The AEAD key length in bytes (16 for AES-128, 32 for AES-256/ChaCha20).
    pub(crate) key_len: usize,
    /// The record-protection AEAD.
    pub(crate) aead: AeadAlg,
}

impl SuiteParams {
    /// Builds a [`RecordCrypter`](super::aead::RecordCrypter) for this suite
    /// keyed from `secret`, supplying the suite's hash, AEAD, and key length in
    /// one call instead of spelling all three out at every key-install site.
    pub(crate) fn crypter(&self, secret: &super::schedule::Secret) -> super::aead::RecordCrypter {
        super::aead::RecordCrypter::new(self.hash, self.aead, self.key_len, secret)
    }
}

/// The suites we support, in descending preference order.
pub(crate) const SUPPORTED: [SuiteParams; 3] = [
    SuiteParams {
        suite: CipherSuite::AES_128_GCM_SHA256,
        hash: HashAlg::Sha256,
        key_len: 16,
        aead: AeadAlg::Aes128Gcm,
    },
    SuiteParams {
        suite: CipherSuite::AES_256_GCM_SHA384,
        hash: HashAlg::Sha384,
        key_len: 32,
        aead: AeadAlg::Aes256Gcm,
    },
    SuiteParams {
        suite: CipherSuite::CHACHA20_POLY1305_SHA256,
        hash: HashAlg::Sha256,
        key_len: 32,
        aead: AeadAlg::ChaCha20Poly1305,
    },
];

/// Looks up the parameters for a wire suite, if supported.
pub(crate) fn lookup(suite: CipherSuite) -> Option<SuiteParams> {
    SUPPORTED.iter().copied().find(|s| s.suite == suite)
}

/// The supported suites in descending preference order.
pub(crate) fn supported() -> &'static [SuiteParams] {
    &SUPPORTED
}
