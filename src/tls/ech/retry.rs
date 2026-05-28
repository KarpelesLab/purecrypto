//! `retry_configs` codec — the body of the EncryptedExtensions
//! `encrypted_client_hello` extension the server sends on ECH
//! rejection (draft §7).
//!
//! ```text
//! struct {
//!     ECHConfigList retry_configs;
//! } ECHEncryptedExtensions;
//! ```
//!
//! On the wire that is exactly the `ECHConfigList` byte string —
//! `u16 byte_len || (ECHConfig entries)*` — so we just defer to
//! [`super::config::EchConfigList`].

use super::config::EchConfigList;
use crate::tls::Error;
use alloc::vec::Vec;

/// Encode a `retry_configs` ECHConfigList for the EE
/// `encrypted_client_hello` extension body.
pub fn encode_retry_configs(list: &EchConfigList) -> Vec<u8> {
    list.encode()
}

/// Decode a `retry_configs` ECHConfigList from an EE extension body.
pub fn decode_retry_configs(buf: &[u8]) -> Result<EchConfigList, Error> {
    EchConfigList::decode(buf)
}
