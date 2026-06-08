//! TLS 1.3 cryptographic core: transcript hash and key schedule.
//!
//! These pieces sit between the wire codec and the handshake state machine.
//! Both are generic over the negotiated hash (SHA-256 / SHA-384) and dispatch
//! at the runtime cipher-suite boundary.

mod aead;
pub(crate) mod aead12;
#[cfg(feature = "tls-legacy")]
pub(crate) mod cbc_rec;
mod hash;
pub(crate) mod prf;
mod schedule;
pub(crate) mod sign;
mod suite;

#[allow(unused_imports)]
pub(crate) use aead::{Aead, RecordCrypter};
#[allow(unused_imports)]
pub(crate) use hash::Transcript;
// `HashAlg` is exposed publicly so callers can store it in resumption sessions.
pub use schedule::HashAlg;
#[allow(unused_imports)]
pub(crate) use schedule::{
    KeySchedule, Secret, binder_finished_key, derive_secret, expand_label_dyn, extract,
    finished_key, finished_verify_data, next_traffic_secret, psk_from_resumption, tls_exporter,
    traffic_key_iv,
};
#[allow(unused_imports)]
pub(crate) use sign::{certificate_verify_content, verify_signature};
#[allow(unused_imports)]
pub(crate) use suite::{
    AeadAlg, SuiteParams, lookup as lookup_suite, supported as supported_suites,
};
