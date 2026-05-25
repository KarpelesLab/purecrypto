//! TLS 1.3 cryptographic core: transcript hash and key schedule.
//!
//! These pieces sit between the wire codec and the handshake state machine.
//! Both are generic over the negotiated hash (SHA-256 / SHA-384) and dispatch
//! at the runtime cipher-suite boundary.

mod aead;
mod hash;
mod schedule;

#[allow(unused_imports)]
pub(crate) use aead::RecordCrypter;
#[allow(unused_imports)]
pub(crate) use hash::Transcript;
#[allow(unused_imports)]
pub(crate) use schedule::{
    HashAlg, KeySchedule, Secret, derive_secret, expand_label_dyn, finished_key, traffic_key_iv,
};
