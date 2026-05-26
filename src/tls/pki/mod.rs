//! TLS PKI: trust anchors and certificate-chain verification.

mod store;
mod verify;

#[allow(unused_imports)]
pub use store::RootCertStore;
#[allow(unused_imports)]
pub(crate) use verify::{ChainPurpose, verify_chain, verify_chain_for_purpose, verify_hostname};
