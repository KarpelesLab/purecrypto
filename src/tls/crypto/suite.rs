//! Cipher-suite parameters: the mapping from a wire `CipherSuite` to its hash
//! and AEAD key length.

use super::schedule::HashAlg;
use crate::tls::codec::CipherSuite;

/// The parameters of a supported TLS 1.3 cipher suite.
#[derive(Copy, Clone)]
pub(crate) struct SuiteParams {
    /// The wire identifier.
    pub(crate) suite: CipherSuite,
    /// The handshake/HKDF hash.
    pub(crate) hash: HashAlg,
    /// The AEAD key length in bytes (16 for AES-128, 32 for AES-256).
    pub(crate) key_len: usize,
}

/// The suites we support, in descending preference order.
pub(crate) const SUPPORTED: [SuiteParams; 2] = [
    SuiteParams {
        suite: CipherSuite::AES_128_GCM_SHA256,
        hash: HashAlg::Sha256,
        key_len: 16,
    },
    SuiteParams {
        suite: CipherSuite::AES_256_GCM_SHA384,
        hash: HashAlg::Sha384,
        key_len: 32,
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
