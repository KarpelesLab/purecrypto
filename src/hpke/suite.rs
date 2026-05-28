//! HPKE cipher-suite glue (RFC 9180 §7.1).

use super::{HpkeAead, HpkeKdf, HpkeKem};

/// An HPKE cipher suite: `(kem_id, kdf_id, aead_id)`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct CipherSuite {
    /// Key Encapsulation Mechanism.
    pub kem: HpkeKem,
    /// Key Derivation Function.
    pub kdf: HpkeKdf,
    /// Authenticated Encryption with Associated Data.
    pub aead: HpkeAead,
}

impl CipherSuite {
    /// Construct a suite from its three components.
    pub const fn new(kem: HpkeKem, kdf: HpkeKdf, aead: HpkeAead) -> Self {
        Self { kem, kdf, aead }
    }

    /// The `suite_id` byte string used by HPKE key-schedule labels
    /// (RFC 9180 §5.1): `"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2)
    /// || I2OSP(aead_id, 2)`.
    pub(crate) fn suite_id(self) -> [u8; 10] {
        let mut out = [0u8; 10];
        out[0..4].copy_from_slice(b"HPKE");
        out[4..6].copy_from_slice(&self.kem.id().to_be_bytes());
        out[6..8].copy_from_slice(&self.kdf.id().to_be_bytes());
        out[8..10].copy_from_slice(&self.aead.id().to_be_bytes());
        out
    }
}

/// The `suite_id` byte string used by DHKEM labels (RFC 9180 §4.1):
/// `"KEM" || I2OSP(kem_id, 2)`.
pub(crate) fn kem_suite_id(kem_id: u16) -> [u8; 5] {
    let mut out = [0u8; 5];
    out[0..3].copy_from_slice(b"KEM");
    out[3..5].copy_from_slice(&kem_id.to_be_bytes());
    out
}
