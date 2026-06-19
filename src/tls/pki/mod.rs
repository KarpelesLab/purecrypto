//! TLS PKI: trust anchors and certificate-chain verification.

mod crls;
mod policy;
mod store;
mod verify;

#[allow(unused_imports)]
pub use crls::CrlStore;
#[allow(unused_imports)]
pub use policy::PolicyOptions;
#[allow(unused_imports)]
pub use store::RootCertStore;
#[allow(unused_imports)]
pub(crate) use verify::{
    ChainPurpose, verify_chain, verify_chain_for_purpose, verify_chain_with_crls,
    verify_chain_with_crls_for_purpose, verify_chain_with_policy, verify_hostname,
};
