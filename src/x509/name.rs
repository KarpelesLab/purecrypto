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
    /// PKCS#9 `emailAddress` (RFC 5280 §4.1.2.6 legacy attribute; encoded
    /// as an IA5String and placed last, after the CN).
    pub email_address: Option<String>,
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

    /// Builder setter for the organizational unit.
    pub fn with_organizational_unit(mut self, ou: &str) -> Self {
        self.organizational_unit = Some(String::from(ou));
        self
    }

    /// Builder setter for the PKCS#9 `emailAddress` attribute.
    pub fn with_email_address(mut self, email: &str) -> Self {
        self.email_address = Some(String::from(email));
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
        if let Some(email) = &self.email_address {
            rdns.extend_from_slice(&rdn(oid::EMAIL_ADDRESS, tag::IA5_STRING, email));
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
                } else if arcs == oid::EMAIL_ADDRESS {
                    dn.email_address = Some(s);
                }
                // Unknown attributes are ignored.
            }
            set_reader.finish()?;
        }
        Ok(dn)
    }

    /// Reads past one `Name`, applying exactly the checks of
    /// [`Self::decode`] (RDN shape, strict DER, the directory-string
    /// decoding and control-character rule, the attribute OID) without
    /// building the decoded strings. For callers that only need to skip a
    /// name they must still reject when malformed.
    pub(crate) fn skip(reader: &mut Reader) -> Result<(), Error> {
        let mut seq = reader.read_sequence()?;
        while !seq.is_empty() {
            let set = seq.read_tlv(tag::SET)?;
            let mut set_reader = Reader::new(set);
            if set_reader.is_empty() {
                return Err(Error::Malformed);
            }
            while !set_reader.is_empty() {
                let mut atv = set_reader.read_sequence()?;
                let oid_body = atv.read_oid()?;
                let (value_tag, value) = atv.read_any()?;
                atv.finish()?;
                let mut control = false;
                if matches!(
                    value_tag,
                    tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::IA5_STRING
                ) && value.is_ascii()
                {
                    // ASCII is valid UTF-8, and its control characters
                    // (`char::is_control`, category Cc) are C0 and DEL.
                    control = value.iter().any(|&b| b < 0x20 || b == 0x7f);
                } else {
                    for_each_directory_char(value_tag, value, |c| control |= c.is_control())?;
                }
                if control {
                    return Err(Error::Malformed);
                }
                parse_oid(oid_body)?;
            }
            set_reader.finish()?;
        }
        Ok(())
    }
}

/// Every PKCS#9 `emailAddress` attribute value in a DER `Name` TLV, in
/// order. RFC 5280 §4.2.1.10 uses these as the rfc822Name-form names of a
/// certificate that has no rfc822Name subjectAltName entry; a name may
/// carry several, so this walks the raw RDNSequence instead of relying on
/// the single [`DistinguishedName::email_address`] slot.
// Consumed only by the `tls`-gated path validator (`tls::pki`).
#[cfg_attr(not(feature = "tls"), allow(dead_code))]
pub(crate) fn email_addresses_in_name(name_der: &[u8]) -> Result<Vec<String>, Error> {
    let mut out = Vec::new();
    let mut reader = Reader::new(name_der);
    let mut seq = reader.read_sequence()?;
    reader.finish()?;
    while !seq.is_empty() {
        let set = seq.read_tlv(tag::SET)?;
        let mut set_reader = Reader::new(set);
        if set_reader.is_empty() {
            return Err(Error::Malformed);
        }
        while !set_reader.is_empty() {
            let mut atv = set_reader.read_sequence()?;
            let oid_body = atv.read_oid()?;
            let (value_tag, value) = atv.read_any()?;
            atv.finish()?;
            if parse_oid(oid_body)?.as_slice() == oid::EMAIL_ADDRESS {
                let s = decode_directory_string(value_tag, value)?;
                if s.chars().any(|c| c.is_control()) {
                    return Err(Error::Malformed);
                }
                out.push(s);
            }
        }
        set_reader.finish()?;
    }
    Ok(out)
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
    let mut s = String::new();
    for_each_directory_char(tag, value, |c| s.push(c))?;
    Ok(s)
}

/// The decoding behind [`decode_directory_string`]: feeds each character of
/// the attribute value to `f`, or fails on a malformed value or an
/// unaccepted tag. Shared with [`DistinguishedName::skip`], which validates
/// without building the string.
fn for_each_directory_char(tag: u8, value: &[u8], mut f: impl FnMut(char)) -> Result<(), Error> {
    match tag {
        // UTF8String / PrintableString / IA5String are all ASCII- or
        // UTF-8-compatible byte sequences: validate as UTF-8 and keep.
        tag::UTF8_STRING | tag::PRINTABLE_STRING | tag::IA5_STRING => {
            core::str::from_utf8(value)
                .map_err(|_| Error::Malformed)?
                .chars()
                .for_each(f);
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
            for c in char::decode_utf16(units) {
                f(c.map_err(|_| Error::Malformed)?);
            }
        }
        // UniversalString: UTF-32BE scalar values. Reject lengths that aren't a
        // multiple of four and any value that isn't a valid Unicode scalar.
        TAG_UNIVERSAL => {
            if !value.len().is_multiple_of(4) {
                return Err(Error::Malformed);
            }
            for c in value.chunks_exact(4) {
                let cp = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
                f(char::from_u32(cp).ok_or(Error::Malformed)?);
            }
        }
        // TeletexString (T.61) has no single portable mapping; in practice CAs
        // emit Latin-1 in this slot. Decode each byte as a Latin-1 code point
        // (a lossless, unambiguous byte→scalar mapping) rather than guessing a
        // multi-byte charset or treating it as UTF-8.
        TAG_TELETEX => value.iter().for_each(|&b| f(b as char)),
        // Any other tag is not a directory string we accept.
        _ => return Err(Error::Malformed),
    }
    Ok(())
}

/// Encodes a single-attribute RDN: `SET { SEQUENCE { type OID, value } }`.
fn rdn(attr_oid: &[u64], value_tag: u8, value: &str) -> Vec<u8> {
    let atv = encode_sequence(&[oid_tlv(attr_oid), encode_string(value_tag, value)].concat());
    encode_tlv(tag::SET, &atv)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `skip` accepts exactly the names `decode` accepts and consumes the
    /// same bytes: checked on hand-built names in every string type, then on
    /// every single-byte corruption of them and a random multi-byte sweep.
    #[test]
    fn skip_agrees_with_decode() {
        fn atv(tag_byte: u8, value: &[u8]) -> Vec<u8> {
            let a =
                encode_sequence(&[oid_tlv(oid::COMMON_NAME), encode_tlv(tag_byte, value)].concat());
            encode_sequence(&encode_tlv(tag::SET, &a))
        }
        let mut names = alloc::vec![
            DistinguishedName::common_name("x")
                .with_organization("Corp")
                .with_country("FR")
                .with_organizational_unit("Unit")
                .with_email_address("a@example.com")
                .to_der(),
            atv(tag::UTF8_STRING, "h\u{e9}llo".as_bytes()),
            atv(tag::UTF8_STRING, b"bad\x01ctl"),
            atv(tag::UTF8_STRING, b"\xff\xfe"),
            atv(tag::PRINTABLE_STRING, b"ok"),
            atv(tag::IA5_STRING, b"tab\there"),
            atv(TAG_BMP, &[0x00, 0x41, 0xd8, 0x00]),
            atv(TAG_BMP, &[0x00, 0x41, 0x00]),
            atv(TAG_BMP, &[0x00, 0x41, 0x00, 0x42]),
            atv(TAG_UNIVERSAL, &[0, 0, 0, 0x41, 0, 0x11, 0, 0]),
            atv(TAG_UNIVERSAL, &[0, 0, 0, 0x41]),
            atv(TAG_TELETEX, &[0x41, 0xe9, 0x85]),
            atv(TAG_TELETEX, &[0x41, 0xe9]),
            atv(0x04, b"octets"),
            encode_sequence(&encode_tlv(tag::SET, &[])),
        ];
        names.push([names[0].clone(), alloc::vec![0x00]].concat());
        let agree = |der: &[u8]| {
            let mut a = Reader::new(der);
            let mut b = Reader::new(der);
            let d = DistinguishedName::decode(&mut a);
            let s = DistinguishedName::skip(&mut b);
            assert_eq!(d.is_ok(), s.is_ok(), "name {der:02x?}");
            if d.is_ok() {
                assert_eq!(a.is_empty(), b.is_empty());
                assert_eq!(a.read_element().ok(), b.read_element().ok());
            }
        };
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for der in &names {
            agree(der);
            for i in 0..der.len() {
                for v in [0x00u8, 0x01, 0x1f, 0x7f, 0x80, 0xff, der[i] ^ 0x20] {
                    let mut m = der.clone();
                    m[i] = v;
                    agree(&m);
                }
            }
            for _ in 0..500 {
                let mut m = der.clone();
                for _ in 0..1 + next() % 3 {
                    let i = (next() as usize) % m.len();
                    m[i] = next() as u8;
                }
                agree(&m);
            }
        }
    }

    /// `emailAddress` round-trips through the builder (as an IA5String,
    /// after the CN) and is picked up by the decoder; `email_addresses_in_name`
    /// sees every occurrence, in order, and ignores the other attributes.
    #[test]
    fn email_address_round_trip_and_raw_walk() {
        let dn = DistinguishedName::common_name("x")
            .with_organization("Corp")
            .with_email_address("alice@example.com");
        let der = dn.to_der();
        let decoded = DistinguishedName::decode(&mut Reader::new(&der)).unwrap();
        assert_eq!(decoded, dn);
        // Last RDN is the IA5String emailAddress.
        assert!(der.ends_with(&encode_string(tag::IA5_STRING, "alice@example.com")));
        assert_eq!(
            email_addresses_in_name(&der).unwrap(),
            alloc::vec![String::from("alice@example.com")]
        );
        // Two emailAddress RDNs: the walker keeps both.
        let two = encode_sequence(
            &[
                rdn(oid::COMMON_NAME, tag::UTF8_STRING, "x"),
                rdn(oid::EMAIL_ADDRESS, tag::IA5_STRING, "a@example.com"),
                rdn(oid::EMAIL_ADDRESS, tag::IA5_STRING, "b@example.org"),
            ]
            .concat(),
        );
        assert_eq!(
            email_addresses_in_name(&two).unwrap(),
            alloc::vec![String::from("a@example.com"), String::from("b@example.org")]
        );
        assert!(
            email_addresses_in_name(&DistinguishedName::common_name("x").to_der())
                .unwrap()
                .is_empty()
        );
        // Malformed names are refused, not read as "no addresses".
        assert!(email_addresses_in_name(&[0x30, 0x02, 0x31, 0x00]).is_err());
        assert!(email_addresses_in_name(&[0x04, 0x00]).is_err());
    }

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
