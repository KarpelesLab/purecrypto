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
pub(crate) mod kex;
pub(crate) mod prf;
pub(crate) mod record_prot;
mod schedule;
pub(crate) mod sign;
#[cfg(feature = "tls-legacy")]
pub(crate) mod ssl3;
mod suite;

#[allow(unused_imports)]
pub(crate) use aead::{
    AEAD_TAG_LEN, Aead, KEY_UPDATE_SOFT_LIMIT, RecordCrypter, ct_find_last_nonzero,
};
#[allow(unused_imports)]
pub(crate) use hash::Transcript;
// `HashAlg` is exposed publicly so callers can store it in resumption sessions.
pub use schedule::HashAlg;
#[cfg(feature = "__ct-check")]
pub(crate) use schedule::traffic_key_iv;
#[allow(unused_imports)]
pub(crate) use schedule::{
    KeySchedule, LabelPrefix, Secret, binder_finished_key, derive_secret_with, expand_label_dyn,
    expand_label_dyn_with, extract, finished_verify_data, finished_verify_data_with,
    next_traffic_secret, next_traffic_secret_with, psk_from_resumption, tls_exporter,
    tls_exporter_with,
};
#[cfg(feature = "dtls")]
#[allow(unused_imports)]
pub(crate) use schedule::{psk_binder_with, psk_from_resumption_with};
#[allow(unused_imports)]
pub(crate) use sign::{
    certificate_verify_content, sign_certificate_verify, signature_scheme_for, verify_signature,
    verify_signature_tls12,
};
#[allow(unused_imports)]
pub(crate) use suite::{
    AeadAlg, SuiteParams, lookup as lookup_suite, supported as supported_suites,
};
