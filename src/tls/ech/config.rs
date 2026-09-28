//! ECH wire-format codecs (draft-ietf-tls-esni-22 §4).
//!
//! ```text
//! struct {
//!     HpkeKdfId kdf_id;
//!     HpkeAeadId aead_id;
//! } HpkeSymmetricCipherSuite;
//!
//! struct {
//!     uint8 config_id;
//!     HpkeKemId kem_id;
//!     HpkePublicKey public_key;                 // <1..2^16-1>
//!     HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
//! } HpkeKeyConfig;
//!
//! struct {
//!     HpkeKeyConfig key_config;
//!     uint8 maximum_name_length;
//!     opaque public_name<1..255>;
//!     Extension extensions<0..2^16-1>;
//! } ECHConfigContents;
//!
//! struct {
//!     uint16 version;                            // 0xfe0d
//!     uint16 length;
//!     ECHConfigContents contents;
//! } ECHConfig;
//!
//! ECHConfig ECHConfigList<4..2^16-1>;            // wire: u16 len + entries
//! ```

use crate::tls::Error;
use alloc::vec::Vec;

/// The single ECH wire version supported by this implementation
/// (`draft-ietf-tls-esni-22`).
pub const ECH_VERSION_DRAFT_22: u16 = 0xfe0d;

/// `HpkeSymmetricCipherSuite { kdf_id, aead_id }`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct HpkeSymCipherSuite {
    /// HPKE KDF id (RFC 9180 §7.2).
    pub kdf_id: u16,
    /// HPKE AEAD id (RFC 9180 §7.3).
    pub aead_id: u16,
}

impl HpkeSymCipherSuite {
    /// Wire encoding: 4 bytes (`kdf_id` || `aead_id`, both u16 be).
    pub fn encode_into(self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.kdf_id.to_be_bytes());
        out.extend_from_slice(&self.aead_id.to_be_bytes());
    }

    /// Decode 4 wire bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() != 4 {
            return Err(Error::EchDecodeError);
        }
        Ok(Self {
            kdf_id: u16::from_be_bytes([buf[0], buf[1]]),
            aead_id: u16::from_be_bytes([buf[2], buf[3]]),
        })
    }
}

/// `HpkeKeyConfig { config_id, kem_id, public_key, cipher_suites }`.
#[derive(Clone, Debug)]
pub struct HpkeKeyConfig {
    /// The 8-bit identifier the client puts in the outer ECH extension
    /// so the server can pick the right private key.
    pub config_id: u8,
    /// HPKE KEM id (RFC 9180 §7.1).
    pub kem_id: u16,
    /// The serialized HPKE public key for the chosen KEM.
    pub public_key: Vec<u8>,
    /// The list of `(kdf, aead)` HPKE cipher suites accepted by this
    /// key. Must be non-empty.
    pub cipher_suites: Vec<HpkeSymCipherSuite>,
}

impl HpkeKeyConfig {
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(self.config_id);
        out.extend_from_slice(&self.kem_id.to_be_bytes());

        // public_key: opaque <1..2^16-1>
        let pk_len: u16 = u16::try_from(self.public_key.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&pk_len.to_be_bytes());
        out.extend_from_slice(&self.public_key);

        // cipher_suites: HpkeSymmetricCipherSuite <4..2^16-4>, length in bytes.
        let cs_bytes: usize = self.cipher_suites.len() * 4;
        let cs_bytes_u16: u16 = u16::try_from(cs_bytes).unwrap_or(u16::MAX);
        out.extend_from_slice(&cs_bytes_u16.to_be_bytes());
        for cs in &self.cipher_suites {
            cs.encode_into(out);
        }
    }

    fn decode(rd: &mut Reader<'_>) -> Result<Self, Error> {
        let config_id = rd.read_u8()?;
        let kem_id = rd.read_u16()?;
        let pk_len = rd.read_u16()? as usize;
        if pk_len == 0 {
            return Err(Error::EchDecodeError);
        }
        let public_key = rd.read(pk_len)?.to_vec();
        let cs_bytes = rd.read_u16()? as usize;
        if cs_bytes < 4 || !cs_bytes.is_multiple_of(4) {
            return Err(Error::EchDecodeError);
        }
        let cs_buf = rd.read(cs_bytes)?;
        let mut cipher_suites = Vec::with_capacity(cs_bytes / 4);
        for chunk in cs_buf.chunks_exact(4) {
            cipher_suites.push(HpkeSymCipherSuite::decode(chunk)?);
        }
        Ok(Self {
            config_id,
            kem_id,
            public_key,
            cipher_suites,
        })
    }
}

/// `ECHConfigContents { key_config, maximum_name_length, public_name,
/// extensions }`.
#[derive(Clone, Debug)]
pub struct EchConfigContents {
    /// The HPKE key material this config offers.
    pub key_config: HpkeKeyConfig,
    /// `maximum_name_length`: the longest `host_name` length (in bytes)
    /// the client should advertise when sealing with this config. Used
    /// to pad shorter names so the wire size leaks no useful bits.
    pub maximum_name_length: u8,
    /// `public_name`: the SNI carried in the outer CH and the host name
    /// the public_name certificate must cover. Length 1..=255.
    pub public_name: Vec<u8>,
    /// `extensions`: an `Extension extensions<0..2^16-1>` of ECHConfig
    /// extensions. An entry carrying an unrecognised extension whose high
    /// bit is set (mandatory) is ignored (RFC 9849 §4.2): it decodes with
    /// [`EchConfig::contents`] `None`, like an unknown version.
    pub extensions: Vec<u8>,
}

impl EchConfigContents {
    fn encode_into(&self, out: &mut Vec<u8>) {
        self.key_config.encode_into(out);
        out.push(self.maximum_name_length);
        // public_name<1..255>
        let pn_len: u8 = u8::try_from(self.public_name.len()).unwrap_or(255);
        out.push(pn_len);
        out.extend_from_slice(&self.public_name);
        // extensions<0..2^16-1>
        let ext_len: u16 = u16::try_from(self.extensions.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&ext_len.to_be_bytes());
        out.extend_from_slice(&self.extensions);
    }

    fn decode(rd: &mut Reader<'_>) -> Result<Self, Error> {
        let key_config = HpkeKeyConfig::decode(rd)?;
        let maximum_name_length = rd.read_u8()?;
        let pn_len = rd.read_u8()? as usize;
        if pn_len == 0 {
            return Err(Error::EchDecodeError);
        }
        let public_name = rd.read(pn_len)?.to_vec();
        let ext_len = rd.read_u16()? as usize;
        let extensions = rd.read(ext_len)?.to_vec();

        // The extensions field carries a list of `Extension { type<u16>,
        // data<0..2^16-1> }`; a malformed list is a decode error. A
        // well-formed one naming a mandatory extension makes the entry
        // unusable, not the list undecodable — see `decode_entry`.
        has_mandatory_extension(&extensions)?;

        Ok(Self {
            key_config,
            maximum_name_length,
            public_name,
            extensions,
        })
    }
}

/// `ECHConfig { version, length, contents }`. We only support
/// `version == 0xfe0d`; configs with other versions are silently
/// skipped at the `ECHConfigList` layer (draft §4: version
/// negotiation is by skip-unknown).
#[derive(Clone, Debug)]
pub struct EchConfig {
    /// The wire version (`0xfe0d` for the draft we implement).
    pub version: u16,
    /// The parsed contents — present only for the version this crate
    /// implements, and only when the entry carries no mandatory extension
    /// it does not understand (RFC 9849 §4.2: "clients MUST ignore the
    /// ECHConfig"). The raw bytes are kept in `raw_contents` so every entry
    /// round-trips through `ECHConfigList::encode` losslessly.
    pub contents: Option<EchConfigContents>,
    /// The raw `contents` bytes — kept so unknown-version configs
    /// round-trip through `ECHConfigList::encode` losslessly.
    pub raw_contents: Vec<u8>,
}

impl EchConfig {
    /// Build an ECHConfig at the supported version from parsed contents.
    pub fn new(contents: EchConfigContents) -> Self {
        let mut raw = Vec::new();
        contents.encode_into(&mut raw);
        Self {
            version: ECH_VERSION_DRAFT_22,
            contents: Some(contents),
            raw_contents: raw,
        }
    }

    /// True if this entry is a parsed draft-22 ECHConfig the rest of
    /// the stack can act on.
    pub fn is_supported(&self) -> bool {
        self.version == ECH_VERSION_DRAFT_22 && self.contents.is_some()
    }

    /// The HPKE symmetric suite a client would seal against this entry
    /// with, or `None` when the entry cannot be used at all.
    ///
    /// draft-ietf-tls-esni-22 §6.1: the client picks "a compatible
    /// ECHConfig" — one whose version it implements, whose KEM it
    /// implements, and whose `cipher_suites` list holds at least one
    /// (KDF, AEAD) pair it implements — and seals under the first such
    /// pair. [`is_supported`](Self::is_supported) only answers the
    /// version half; a config with an unknown KEM or only exotic
    /// suites parses fine but can never be sealed against, and a
    /// client that picks it anyway has no ECH to offer. `public_name`
    /// must also be a valid DNS host name that cannot be read as an IPv4
    /// literal, since it becomes the outer hello's SNI and the name a
    /// rejected handshake is authenticated as (RFC 9849 §6.1.7: clients
    /// "SHOULD ignore any ECHConfig structure with a public_name that is
    /// not a valid host name in preferred name syntax").
    pub fn usable_cipher_suite(&self) -> Option<HpkeSymCipherSuite> {
        if !self.is_supported() {
            return None;
        }
        let contents = self.contents.as_ref()?;
        if super::hpke_setup::map_kem(contents.key_config.kem_id).is_err()
            || !valid_public_name(&contents.public_name)
        {
            return None;
        }
        contents
            .key_config
            .cipher_suites
            .iter()
            .copied()
            .find(|sc| super::hpke_setup::map_sym_suite(*sc).is_ok())
    }

    /// Encode this single entry to its wire form (`version || u16 length
    /// || contents`) — the `ECHConfig` structure an HPKE `info` string
    /// and a one-entry `ECHConfigList` are built from.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.raw_contents.len());
        self.encode_into(&mut out);
        out
    }

    /// Decode exactly one wire-form `ECHConfig` (no list length prefix);
    /// trailing bytes are an error. An entry at an unknown version decodes
    /// with `contents == None`.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut rd = Reader::new(buf);
        let cfg = Self::decode_entry(&mut rd)?;
        if !rd.is_empty() {
            return Err(Error::EchDecodeError);
        }
        Ok(cfg)
    }

    /// Encode this entry (version || u16 length || contents).
    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.version.to_be_bytes());
        let len: u16 = u16::try_from(self.raw_contents.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&self.raw_contents);
    }

    fn decode_entry(rd: &mut Reader<'_>) -> Result<Self, Error> {
        let version = rd.read_u16()?;
        let len = rd.read_u16()? as usize;
        let raw = rd.read(len)?.to_vec();
        let contents = if version == ECH_VERSION_DRAFT_22 {
            let mut inner = Reader::new(&raw);
            let c = EchConfigContents::decode(&mut inner)?;
            if !inner.is_empty() {
                return Err(Error::EchDecodeError);
            }
            // RFC 9849 §4.2: an unsupported mandatory extension makes the
            // client ignore this ECHConfig — not the whole list, which
            // §6.2.2 even encourages servers to salt with such entries.
            if has_mandatory_extension(&c.extensions)? {
                None
            } else {
                Some(c)
            }
        } else {
            None
        };
        Ok(Self {
            version,
            contents,
            raw_contents: raw,
        })
    }
}

/// A list of `ECHConfig` entries wrapped with a leading `u16` byte
/// length. The first *usable* entry ([`first_usable`](Self::first_usable))
/// is what a sealing client uses (draft §6.1).
#[derive(Clone, Debug)]
pub struct EchConfigList {
    /// The ordered list of configs as they appear on the wire.
    pub configs: Vec<EchConfig>,
}

impl EchConfigList {
    /// Wrap a list of configs.
    pub fn new(configs: Vec<EchConfig>) -> Self {
        Self { configs }
    }

    /// First supported (i.e. draft-22) config. Servers and diagnostics
    /// read the list through this; a sealing client goes through
    /// [`first_usable`](Self::first_usable), which also checks the
    /// entry's HPKE algorithms.
    pub fn first_supported(&self) -> Option<&EchConfig> {
        self.configs.iter().find(|c| c.is_supported())
    }

    /// First config a client can actually seal against, with the HPKE
    /// symmetric suite to use (draft §6.1: "a compatible ECHConfig").
    /// Skips entries [`first_supported`](Self::first_supported) would
    /// return but whose KEM or cipher suites this crate does not
    /// implement — see [`EchConfig::usable_cipher_suite`]. `None`
    /// means the list offers no ECH the client can perform; the
    /// caller must not fall back to a cleartext SNI on its own.
    pub fn first_usable(&self) -> Option<(&EchConfig, HpkeSymCipherSuite)> {
        self.configs
            .iter()
            .find_map(|c| c.usable_cipher_suite().map(|sc| (c, sc)))
    }

    /// Encode to the wire form: `u16 byte_len || (ECHConfig entries)*`.
    pub fn encode(&self) -> Vec<u8> {
        let mut inner = Vec::new();
        for cfg in &self.configs {
            cfg.encode_into(&mut inner);
        }
        let mut out = Vec::with_capacity(2 + inner.len());
        let len: u16 = u16::try_from(inner.len()).unwrap_or(u16::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(&inner);
        out
    }

    /// Decode the wire form. Trailing bytes after the declared length
    /// are an error.
    pub fn decode(buf: &[u8]) -> Result<Self, Error> {
        let mut rd = Reader::new(buf);
        let inner_len = rd.read_u16()? as usize;
        let inner = rd.read(inner_len)?;
        if !rd.is_empty() {
            return Err(Error::EchDecodeError);
        }
        let mut entries = Vec::new();
        let mut sub = Reader::new(inner);
        while !sub.is_empty() {
            entries.push(EchConfig::decode_entry(&mut sub)?);
        }
        if entries.is_empty() {
            return Err(Error::EchDecodeError);
        }
        Ok(Self { configs: entries })
    }
}

/// Tiny self-contained big-endian length-prefix reader used by the
/// ECH codecs. Mirrors the shape of the tls/codec `der::Reader` but
/// over u8/u16 length prefixes rather than ASN.1 tags.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        if self.remaining() < 1 {
            return Err(Error::EchDecodeError);
        }
        let v = self.buf[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        if self.remaining() < 2 {
            return Err(Error::EchDecodeError);
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read(&mut self, n: usize) -> Result<&'a [u8], Error> {
        if self.remaining() < n {
            return Err(Error::EchDecodeError);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

/// Walks `Extension extensions<0..2^16-1>` from
/// `ECHConfigContents.extensions` and reports whether any is "mandatory"
/// (high-bit-set type, RFC 9849 §4.2). This crate recognises no ECHConfig
/// extension, so every mandatory one is unsupported. A structurally
/// malformed list is [`Error::EchDecodeError`].
fn has_mandatory_extension(buf: &[u8]) -> Result<bool, Error> {
    let mut rd = Reader::new(buf);
    let mut mandatory = false;
    while !rd.is_empty() {
        let ty = rd.read_u16()?;
        let len = rd.read_u16()? as usize;
        let _data = rd.read(len)?;
        mandatory |= ty & 0x8000 != 0;
    }
    Ok(mandatory)
}

/// RFC 9849 §6.1.7: a usable `public_name` is a dot-separated sequence of
/// LDH labels (RFC 5890 §2.3.1: letters, digits and hyphens, not starting
/// or ending with a hyphen) of at most 63 octets each, with no leading or
/// trailing dot, whose final label is neither all digits nor `0x`/`0X`
/// followed by hex digits — either would read as an IPv4 literal.
fn valid_public_name(name: &[u8]) -> bool {
    if name.is_empty() || name.first() == Some(&b'.') || name.last() == Some(&b'.') {
        return false;
    }
    let ldh = |label: &[u8]| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'-')
            && label.first() != Some(&b'-')
            && label.last() != Some(&b'-')
    };
    if !name.split(|&b| b == b'.').all(ldh) {
        return false;
    }
    let last = name.rsplit(|&b| b == b'.').next().unwrap_or(name);
    let all_digits = last.iter().all(u8::is_ascii_digit);
    let hex = last.len() >= 2
        && (last[..2] == *b"0x" || last[..2] == *b"0X")
        && last[2..].iter().all(u8::is_ascii_hexdigit);
    !(all_digits || hex)
}
