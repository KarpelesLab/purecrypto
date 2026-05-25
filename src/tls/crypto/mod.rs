//! TLS 1.3 cryptographic core: transcript hash and key schedule.
//!
//! These pieces sit between the wire codec and the handshake state machine.
//! Both are generic over the negotiated hash (SHA-256 / SHA-384) and dispatch
//! at the runtime cipher-suite boundary.

mod aead;
mod hash;
mod schedule;
mod sign;
mod suite;

#[allow(unused_imports)]
pub(crate) use aead::RecordCrypter;
#[allow(unused_imports)]
pub(crate) use hash::Transcript;
#[allow(unused_imports)]
pub(crate) use schedule::{
    HashAlg, KeySchedule, Secret, derive_secret, expand_label_dyn, finished_key,
    finished_verify_data, traffic_key_iv,
};
#[allow(unused_imports)]
pub(crate) use sign::{certificate_verify_content, verify_signature};
#[allow(unused_imports)]
pub(crate) use suite::{AeadAlg, SuiteParams, lookup as lookup_suite, supported as supported_suites};
