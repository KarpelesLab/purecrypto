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
            // RelativeDistinguishedName ::= SET SIZE (1..MAX) OF
            // AttributeTypeAndValue. Multi-valued RDNs are rare but legal —
            // parse every AttributeTypeAndValue in the SET rather than
            // silently dropping trailing ones (which would make two
            // differently-named certificates render identically). An empty
            // SET violates the SIZE (1..MAX) constraint and is rejected.
            let set = seq.read_tlv(tag::SET)?;
            let mut set_reader = Reader::new(set);
            if set_reader.is_empty() {
                return Err(Error::Malformed);
            }
            while !set_reader.is_empty() {
                let mut atv = set_reader.read_sequence()?;
                let oid_body = atv.read_oid()?;
                let (value_tag, value) = atv.read_any()?;
                // Strict DER: an AttributeTypeAndValue is exactly
                // `SEQUENCE { type, value }` — trailing bytes are rejected.
                atv.finish()?;
                // Decode the value according to its ASN.1 string tag rather
                // than blindly treating the raw bytes as UTF-8. A BMPString or
                // UniversalString carries multi-byte code units that, read as
                // UTF-8, would render as a *different* string than the issuer
                // intended — a display-spoofing vector. Unknown / non-string
                // tags are rejected outright.
                let s = decode_directory_string(value_tag, value)?;
                // Reject embedded NUL and other control characters in
                // attribute values. They have no legitimate place in a
                // printable name and enable display spoofing or log injection
                // when the decoded DN is later rendered. The byte-exact
                // issuer/subject comparison used for chain building works on
                // raw TLV bytes elsewhere and is unaffected by this check.
                if s.chars().any(|c| c.is_control()) {
                    return Err(Error::Malformed);
                }
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
            set_reader.finish()?;
        }
        Ok(dn)
    }
}

/// `TeletexString` / `T61String` tag.
const TAG_TELETEX: u8 = 0x14;
/// `BMPString` (UTF-16BE) tag.
const TAG_BMP: u8 = 0x1e;
/// `UniversalString` (UTF-32BE) tag.
const TAG_UNIVERSAL: u8 = 0x1c;

/// Decodes an X.501 attribute value according to its ASN.1 string `tag`,
/// transcoding the wide string types to `String` rather than reinterpreting
/// their raw bytes as UTF-8 (which would silently mis-render and enable
/// display spoofing). Unrecognized / non-string tags are rejected.
fn decode_directory_string(tag: u8, value: &[u8]) -> Result<String, Error> {
    match tag {
        // UTF8String / PrintableString / IA5String are all ASCII- or
        // UTF-8-compatible byte sequences: validate as UTF-8 and keep.
        tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::IA5_STRING => {
            Ok(core::str::from_utf8(value)
                .map_err(|_| Error::Malformed)?
                .into())
        }
        // BMPString: UTF-16BE code units. Reject odd-length bodies and any
        // ill-formed (lone-surrogate) sequence.
        TAG_BMP => {
            if !value.len().is_multiple_of(2) {
                return Err(Error::Malformed);
            }
            let units = value
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]));
            char::decode_utf16(units)
                .collect::<Result<String, _>>()
                .map_err(|_| Error::Malformed)
        }
        // UniversalString: UTF-32BE scalar values. Reject lengths that aren't a
        // multiple of four and any value that isn't a valid Unicode scalar.
        TAG_UNIVERSAL => {
            if !value.len().is_multiple_of(4) {
                return Err(Error::Malformed);
            }
            value
                .chunks_exact(4)
                .map(|c| {
                    let cp = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
                    char::from_u32(cp).ok_or(Error::Malformed)
                })
                .collect::<Result<String, _>>()
        }
        // TeletexString (T.61) has no single portable mapping; in practice CAs
        // emit Latin-1 in this slot. Decode each byte as a Latin-1 code point
        // (a lossless, unambiguous byte→scalar mapping) rather than guessing a
        // multi-byte charset or treating it as UTF-8.
        TAG_TELETEX => Ok(value.iter().map(|&b| b as char).collect()),
        // Any other tag is not a directory string we accept.
        _ => Err(Error::Malformed),
    }
}

/// Encodes a single-attribute RDN: `SET { SEQUENCE { type OID, value } }`.
fn rdn(attr_oid: &[u64], value_tag: u8, value: &str) -> Vec<u8> {
    let atv = encode_sequence(&[oid_tlv(attr_oid), encode_string(value_tag, value)].concat());
    encode_tlv(tag::SET, &atv)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a one-attribute `Name` (RDNSequence) DER whose single
    /// commonName carries `value` as a UTF8String body (verbatim bytes, so a
    /// NUL or control char survives into the encoding).
    fn name_with_cn(value: &[u8]) -> Vec<u8> {
        // commonName OID 2.5.4.3.
        let mut atv = alloc::vec![0x06u8, 0x03, 0x55, 0x04, 0x03];
        // value: UTF8String (0x0c) wrapping the raw bytes.
        atv.push(0x0c);
        atv.push(value.len() as u8);
        atv.extend_from_slice(value);
        let atv = encode_sequence(&atv); // AttributeTypeAndValue SEQUENCE
        let set = encode_tlv(tag::SET, &atv); // RelativeDistinguishedName SET
        encode_sequence(&set) // Name SEQUENCE OF RDN
    }

    #[test]
    fn decode_accepts_clean_common_name() {
        let der = name_with_cn(b"example.com");
        let mut r = Reader::new(&der);
        let dn = DistinguishedName::decode(&mut r).unwrap();
        assert_eq!(dn.common_name.as_deref(), Some("example.com"));
    }

    /// Encodes one AttributeTypeAndValue SEQUENCE with `arcs` as the type and
    /// a UTF8String `value`.
    fn atv(arcs: &[u64], value: &str) -> Vec<u8> {
        encode_sequence(&[oid_tlv(arcs), encode_string(tag::UTF8_STRING, value)].concat())
    }

    #[test]
    fn decode_parses_multi_valued_rdn() {
        // One SET carrying two AttributeTypeAndValues (CN + O). Both must be
        // surfaced — dropping the trailing one would let two distinct names
        // render identically.
        let set = encode_tlv(
            tag::SET,
            &[atv(oid::COMMON_NAME, "leaf"), atv(oid::ORGANIZATION, "org")].concat(),
        );
        let der = encode_sequence(&set);
        let mut r = Reader::new(&der);
        let dn = DistinguishedName::decode(&mut r).unwrap();
        assert_eq!(dn.common_name.as_deref(), Some("leaf"));
        assert_eq!(dn.organization.as_deref(), Some("org"));
    }

    #[test]
    fn decode_rejects_empty_rdn_set() {
        // RelativeDistinguishedName ::= SET SIZE (1..MAX): an empty SET is
        // malformed.
        let set = encode_tlv(tag::SET, &[]);
        let der = encode_sequence(&set);
        let mut r = Reader::new(&der);
        assert!(DistinguishedName::decode(&mut r).is_err());
    }

    #[test]
    fn decode_rejects_trailing_bytes_inside_atv() {
        // An AttributeTypeAndValue with trailing garbage after the value must
        // be rejected, not silently accepted.
        let mut inner = [oid_tlv(oid::COMMON_NAME), encode_string(0x0c, "x")].concat();
        inner.push(0x00); // trailing junk inside the ATV SEQUENCE
        let set = encode_tlv(tag::SET, &encode_sequence(&inner));
        let der = encode_sequence(&set);
        let mut r = Reader::new(&der);
        assert!(DistinguishedName::decode(&mut r).is_err());
    }

    /// Builds a one-attribute commonName `Name` whose value carries the raw
    /// `body` under the given ASN.1 string `tag`.
    fn name_with_cn_tag(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut atv = alloc::vec![0x06u8, 0x03, 0x55, 0x04, 0x03];
        atv.push(tag);
        atv.push(body.len() as u8);
        atv.extend_from_slice(body);
        let atv = encode_sequence(&atv);
        let set = encode_tlv(crate::der::tag::SET, &atv);
        encode_sequence(&set)
    }

    #[test]
    fn decode_transcodes_bmp_string() {
        // BMPString (0x1e) = UTF-16BE. "Aé" = 0x0041 0x00E9.
        let der = name_with_cn_tag(0x1e, &[0x00, 0x41, 0x00, 0xE9]);
        let mut r = Reader::new(&der);
        let dn = DistinguishedName::decode(&mut r).unwrap();
        assert_eq!(dn.common_name.as_deref(), Some("Aé"));
    }

    #[test]
    fn decode_transcodes_universal_string() {
        // UniversalString (0x1c) = UTF-32BE. "A" = 0x00000041.
        let der = name_with_cn_tag(0x1c, &[0x00, 0x00, 0x00, 0x41]);
        let mut r = Reader::new(&der);
        let dn = DistinguishedName::decode(&mut r).unwrap();
        assert_eq!(dn.common_name.as_deref(), Some("A"));
    }

    #[test]
    fn decode_teletex_as_latin1() {
        // TeletexString (0x14): byte 0xE9 is Latin-1 'é'.
        let der = name_with_cn_tag(0x14, &[0x41, 0xE9]);
        let mut r = Reader::new(&der);
        let dn = DistinguishedName::decode(&mut r).unwrap();
        assert_eq!(dn.common_name.as_deref(), Some("Aé"));
    }

    #[test]
    fn decode_rejects_bmp_string_odd_length() {
        // An odd-length BMPString body is not valid UTF-16BE.
        let der = name_with_cn_tag(0x1e, &[0x00, 0x41, 0x00]);
        let mut r = Reader::new(&der);
        assert!(DistinguishedName::decode(&mut r).is_err());
    }

    #[test]
    fn decode_rejects_non_string_value_tag() {
        // An INTEGER (0x02) is not a directory string and must be rejected,
        // not byte-cast as UTF-8.
        let der = name_with_cn_tag(0x02, &[0x01]);
        let mut r = Reader::new(&der);
        assert!(DistinguishedName::decode(&mut r).is_err());
    }

    #[test]
    fn decode_rejects_control_chars_in_value() {
        for bad in [
            b"evil\x00name".as_slice(),
            b"line1\nline2".as_slice(),
            b"tab\there".as_slice(),
        ] {
            let der = name_with_cn(bad);
            let mut r = Reader::new(&der);
            assert!(
                DistinguishedName::decode(&mut r).is_err(),
                "should reject {bad:?}"
            );
        }
    }
}
