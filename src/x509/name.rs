//! X.509 distinguished names (a small, common subset of RDNSequence).

use alloc::string::String;
use alloc::vec::Vec;

use super::{Error, oid};
use crate::der::{Reader, encode_sequence, encode_string, encode_tlv, oid_tlv, parse_oid, tag};

/// A distinguished name with the most common attributes. Encodes/decodes as an
/// X.501 `RDNSequence` (one single-valued RDN per present attribute).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DistinguishedName {
    /// `countryName` (C).
    pub country: Option<String>,
    /// `organizationName` (O).
    pub organization: Option<String>,
    /// `organizationalUnitName` (OU).
    pub organizational_unit: Option<String>,
    /// `commonName` (CN).
    pub common_name: Option<String>,
}

impl DistinguishedName {
    /// An empty name.
    pub fn new() -> Self {
        Self::default()
    }

    /// A name with only a common name set.
    pub fn common_name(cn: &str) -> Self {
        DistinguishedName {
            common_name: Some(String::from(cn)),
            ..Self::default()
        }
    }

    /// Builder setter for the organization.
    pub fn with_organization(mut self, o: &str) -> Self {
        self.organization = Some(String::from(o));
        self
    }

    /// Builder setter for the country.
    pub fn with_country(mut self, c: &str) -> Self {
        self.country = Some(String::from(c));
        self
    }

    /// Encodes the name as a DER `RDNSequence` (`SEQUENCE OF RelativeDistinguishedName`).
    pub(crate) fn to_der(&self) -> Vec<u8> {
        let mut rdns = Vec::new();
        // Conventional ordering: C, O, OU, CN.
        if let Some(c) = &self.country {
            rdns.extend_from_slice(&rdn(oid::COUNTRY, tag::PRINTABLE_STRING, c));
        }
        if let Some(o) = &self.organization {
            rdns.extend_from_slice(&rdn(oid::ORGANIZATION, tag::UTF8_STRING, o));
        }
        if let Some(ou) = &self.organizational_unit {
            rdns.extend_from_slice(&rdn(oid::ORGANIZATIONAL_UNIT, tag::UTF8_STRING, ou));
        }
        if let Some(cn) = &self.common_name {
            rdns.extend_from_slice(&rdn(oid::COMMON_NAME, tag::UTF8_STRING, cn));
        }
        encode_sequence(&rdns)
    }

    /// Reads one `Name` (`RDNSequence`) from `reader`.
    pub(crate) fn decode(reader: &mut Reader) -> Result<Self, Error> {
        let mut dn = DistinguishedName::default();
        let mut seq = reader.read_sequence()?;
        while !seq.is_empty() {
            // RelativeDistinguishedName ::= SET OF AttributeTypeAndValue
            let set = seq.read_tlv(tag::SET)?;
            let mut set_reader = Reader::new(set);
            let mut atv = set_reader.read_sequence()?;
            let oid_body = atv.read_oid()?;
            let (_, value) = atv.read_any()?;
            let s = core::str::from_utf8(value)
                .map_err(|_| Error::Malformed)?
                .into();
            let arcs = parse_oid(oid_body)?;
            let arcs = arcs.as_slice();
            if arcs == oid::COMMON_NAME {
                dn.common_name = Some(s);
            } else if arcs == oid::ORGANIZATION {
                dn.organization = Some(s);
            } else if arcs == oid::ORGANIZATIONAL_UNIT {
                dn.organizational_unit = Some(s);
            } else if arcs == oid::COUNTRY {
                dn.country = Some(s);
            }
            // Unknown attributes are ignored.
        }
        Ok(dn)
    }
}

/// Encodes a single-attribute RDN: `SET { SEQUENCE { type OID, value } }`.
fn rdn(attr_oid: &[u64], value_tag: u8, value: &str) -> Vec<u8> {
    let atv = encode_sequence(&[oid_tlv(attr_oid), encode_string(value_tag, value)].concat());
    encode_tlv(tag::SET, &atv)
}
