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
    /// extensions. Unrecognised extensions whose high bit is set
    /// (mandatory) MUST cause clients to reject the config (draft §4.2).
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

        // draft §4.2: reject mandatory unknown extensions (high bit set).
        // The extensions field carries a list of `Extension { type<u16>, data<0..2^16-1> }`.
        validate_config_extensions(&extensions)?;

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
    /// The parsed contents (only present for known versions; the
    /// raw bytes are kept in `raw_contents` for round-tripping
    /// unknown configs in a `ECHConfigList`).
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
            Some(c)
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
/// length. The first supported entry is what a client SHOULD seal
/// against (draft §6.1).
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

    /// First supported (i.e. draft-22) config, the one a sealing
    /// client will use.
    pub fn first_supported(&self) -> Option<&EchConfig> {
        self.configs.iter().find(|c| c.is_supported())
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

/// `validate_config_extensions(bytes)` — walks `Extension extensions<0..2^16-1>`
/// from `ECHConfigContents.extensions` and ensures any "mandatory"
/// (high-bit-set type) extension is recognised. We currently recognise
/// no ECH-config-level extensions, so any mandatory extension is an
/// error per draft §4.2.
fn validate_config_extensions(buf: &[u8]) -> Result<(), Error> {
    let mut rd = Reader::new(buf);
    while !rd.is_empty() {
        let ty = rd.read_u16()?;
        let len = rd.read_u16()? as usize;
        let _data = rd.read(len)?;
        // High bit set ⇒ mandatory.
        if ty & 0x8000 != 0 {
            return Err(Error::EchDecodeError);
        }
    }
    Ok(())
}
