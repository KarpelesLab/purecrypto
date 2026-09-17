//! Algorithm-agnostic public keys and PKIX `SubjectPublicKeyInfo` (SPKI)
//! import/export.

use alloc::string::String;
use alloc::vec::Vec;

use super::{Error, algorithm_identifier, oid};
use crate::der::{
    Reader, encode_bit_string, encode_context, encode_integer, encode_sequence, oid_tlv, parse_oid,
    pem_decode, pem_encode, tag,
};
use crate::ec::{
    BoxedEcdsaPublicKey, CurveId, Ed448PublicKey, Ed25519PublicKey, X448PublicKey, X25519PublicKey,
};
#[cfg(feature = "mldsa")]
use crate::mldsa::{MlDsa44PublicKey, MlDsa65PublicKey, MlDsa87PublicKey};
use crate::rsa::BoxedRsaPublicKey;
#[cfg(feature = "slhdsa")]
use crate::slhdsa;

const SPKI_LABEL: &str = "PUBLIC KEY";

/// Encodes an ML-DSA (FIPS 204) `SubjectPublicKeyInfo`: bare OID
/// AlgorithmIdentifier (no parameters) wrapping the raw key bytes.
#[cfg(feature = "mldsa")]
fn mldsa_spki(oid: &[u64], key: &[u8]) -> Vec<u8> {
    let algid = encode_sequence(&oid_tlv(oid));
    encode_sequence(&[algid, encode_bit_string(key)].concat())
}

/// The X.509 named-curve OID for a curve.
fn curve_oid(curve: CurveId) -> &'static [u64] {
    match curve {
        CurveId::P256 => oid::PRIME256V1,
        CurveId::P384 => oid::SECP384R1,
        CurveId::P521 => oid::SECP521R1,
        CurveId::Secp256k1 => oid::SECP256K1,
        CurveId::Sm2p256v1 => oid::SM2_P256V1,
        CurveId::BrainpoolP256r1 => oid::BRAINPOOL_P256R1,
        CurveId::BrainpoolP384r1 => oid::BRAINPOOL_P384R1,
        CurveId::BrainpoolP512r1 => oid::BRAINPOOL_P512R1,
    }
}

/// Maps a named-curve OID to a [`CurveId`].
fn curve_from_oid(arcs: &[u64]) -> Option<CurveId> {
    if arcs == oid::PRIME256V1 {
        Some(CurveId::P256)
    } else if arcs == oid::SECP384R1 {
        Some(CurveId::P384)
    } else if arcs == oid::SECP521R1 {
        Some(CurveId::P521)
    } else if arcs == oid::SECP256K1 {
        Some(CurveId::Secp256k1)
    } else if arcs == oid::SM2_P256V1 {
        Some(CurveId::Sm2p256v1)
    } else if arcs == oid::BRAINPOOL_P256R1 {
        Some(CurveId::BrainpoolP256r1)
    } else if arcs == oid::BRAINPOOL_P384R1 {
        Some(CurveId::BrainpoolP384r1)
    } else if arcs == oid::BRAINPOOL_P512R1 {
        Some(CurveId::BrainpoolP512r1)
    } else {
        None
    }
}

/// The digest an RSA-PSS key restriction names (RFC 4055 §3.1
/// `hashAlgorithm` / MGF1 hash). Only the SHA-2 digests the signature
/// registry can verify PSS under are representable; an `id-RSASSA-PSS` SPKI
/// restricting its key to any other digest (SHA-1 — the DER default —
/// SHA-224, SHA-512/256, SHA-3, …) is [`Error::UnsupportedAlgorithm`] at
/// parse time rather than a key that can never verify anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PssHash {
    /// SHA-256 (`id-sha256`).
    Sha256,
    /// SHA-384 (`id-sha384`).
    Sha384,
    /// SHA-512 (`id-sha512`).
    Sha512,
}

impl PssHash {
    /// The digest's `AlgorithmIdentifier` OID arcs.
    pub fn oid(self) -> &'static [u64] {
        match self {
            PssHash::Sha256 => oid::ID_SHA256,
            PssHash::Sha384 => oid::ID_SHA384,
            PssHash::Sha512 => oid::ID_SHA512,
        }
    }

    /// The digest output length in octets — the salt length the TLS 1.3 /
    /// X.509 PSS profile pairs with it.
    pub fn output_len(self) -> u32 {
        match self {
            PssHash::Sha256 => 32,
            PssHash::Sha384 => 48,
            PssHash::Sha512 => 64,
        }
    }

    /// The id of the `rsa-pss-pss-*` entry of [`crate::signature_registry`]
    /// that verifies PSS signatures over this digest (MGF1 with the same
    /// digest; the salt length is the signature's, defaulting to the digest
    /// length).
    pub fn registry_id(self) -> &'static str {
        match self {
            PssHash::Sha256 => "rsa-pss-pss-sha256",
            PssHash::Sha384 => "rsa-pss-pss-sha384",
            PssHash::Sha512 => "rsa-pss-pss-sha512",
        }
    }

    /// The same digest as a [`HashAlgorithm`](crate::hash::HashAlgorithm).
    pub fn hash_algorithm(self) -> crate::hash::HashAlgorithm {
        match self {
            PssHash::Sha256 => crate::hash::HashAlgorithm::Sha256,
            PssHash::Sha384 => crate::hash::HashAlgorithm::Sha384,
            PssHash::Sha512 => crate::hash::HashAlgorithm::Sha512,
        }
    }

    fn from_oid(arcs: &[u64]) -> Option<Self> {
        if arcs == oid::ID_SHA256 {
            Some(PssHash::Sha256)
        } else if arcs == oid::ID_SHA384 {
            Some(PssHash::Sha384)
        } else if arcs == oid::ID_SHA512 {
            Some(PssHash::Sha512)
        } else {
            None
        }
    }
}

/// The `RSASSA-PSS-params` (RFC 4055 §3.1) an `id-RSASSA-PSS` SPKI carries
/// when the issuer restricted the key to one parameter set.
///
/// The parser only produces values the registry could verify under:
/// `trailer_field` is always 1 (RFC 4055 requires it), and `hash` /
/// `mgf1_hash` are one of the [`PssHash`] digests. `mgf1_hash != hash` is
/// representable — the restriction is preserved faithfully — but no
/// registry entry implements MGF1 over a digest other than the message
/// digest, so such a key verifies nothing ([`Error::UnsupportedAlgorithm`])
/// rather than something else. Any `salt_len` is representable and
/// honoured: a signature's own `RSASSA-PSS-params` name the salt length the
/// registry verifies with, and a key's restriction only bounds it from
/// below (RFC 4055 §3.3).
///
/// The same structure describes the parameters of an `id-RSASSA-PSS`
/// *signature* `AlgorithmIdentifier`
/// ([`SignatureAlgorithmIdentifier::rsa_pss`](super::SignatureAlgorithmIdentifier::rsa_pss)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct PssParams {
    /// `hashAlgorithm`.
    pub hash: PssHash,
    /// The digest `maskGenAlgorithm` (always MGF1) is parameterised with.
    pub mgf1_hash: PssHash,
    /// `saltLength`, in octets.
    pub salt_len: u32,
    /// `trailerField`; always 1 (`0xBC`).
    pub trailer_field: u8,
}

impl PssParams {
    /// The TLS 1.3 / X.509 profile for `hash`: MGF1 with the same digest and
    /// a salt as long as the digest output.
    pub fn for_hash(hash: PssHash) -> Self {
        PssParams {
            hash,
            mgf1_hash: hash,
            salt_len: hash.output_len(),
            trailer_field: 1,
        }
    }
}

/// The RFC 4055 §1.2 use restriction an `id-RSASSA-PSS` SPKI places on its
/// RSA key: "the key MUST only be used with RSASSA-PSS", and — when
/// `RSASSA-PSS-params` are present — only with parameters compatible with
/// them (§3.3: same digest, MGF1 digest and trailer field, a salt at least
/// as long).
///
/// Carried by [`AnyPublicKey::RsaPss`] so the restriction survives the
/// round trip through [`AnyPublicKey::to_spki_der`]: a PSS-restricted key
/// re-encodes as `id-RSASSA-PSS` (parameters included), never as
/// `rsaEncryption`, and therefore never verifies a PKCS#1 v1.5 signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PssRestriction {
    /// Parameters absent: any RSASSA-PSS parameter set, never PKCS#1 v1.5.
    Unrestricted,
    /// These parameters: the digest, MGF1 digest and trailer field exactly,
    /// and at least this salt length ([`permits_params`](Self::permits_params)).
    Restricted(PssParams),
}

impl PssRestriction {
    /// The restriction that pins the key to the TLS 1.3 / X.509 profile for
    /// `hash` ([`PssParams::for_hash`]).
    pub fn for_hash(hash: PssHash) -> Self {
        PssRestriction::Restricted(PssParams::for_hash(hash))
    }

    /// Whether a signature made with the registry profile for `hash` (MGF1
    /// over `hash`, salt = digest length) is permitted under this
    /// restriction — [`permits_params`](Self::permits_params) of
    /// [`PssParams::for_hash`].
    pub fn permits(&self, hash: PssHash) -> bool {
        self.permits_params(&PssParams::for_hash(hash))
    }

    /// Whether a signature made with `params` is compatible with this
    /// restriction, per RFC 4055 §3.3: always for an unrestricted key;
    /// for a restricted one the digest, the MGF1 digest and the trailer
    /// field must be the key's and the signature's salt must be at least as
    /// long as the key's.
    pub fn permits_params(&self, params: &PssParams) -> bool {
        match self {
            PssRestriction::Unrestricted => true,
            PssRestriction::Restricted(k) => {
                k.hash == params.hash
                    && k.mgf1_hash == params.mgf1_hash
                    && k.trailer_field == params.trailer_field
                    && params.salt_len >= k.salt_len
            }
        }
    }

    /// The digest the key is pinned to, or `None` when unrestricted.
    pub fn hash(&self) -> Option<PssHash> {
        match self {
            PssRestriction::Unrestricted => None,
            PssRestriction::Restricted(p) => Some(p.hash),
        }
    }

    /// Decodes the `AlgorithmIdentifier.parameters` that follow the
    /// `id-RSASSA-PSS` OID: absent (unrestricted) or one strict
    /// `RSASSA-PSS-params` SEQUENCE. `algid` is left positioned after the
    /// parameters; the caller checks for trailing junk.
    ///
    /// DER `DEFAULT` handling is load-bearing: an *absent* field encodes the
    /// SHA-1 / MGF1-SHA-1 / saltLength 20 default, so an empty SEQUENCE is a
    /// SHA-1 restriction and rejected as unsupported like any other SHA-1
    /// one. A `trailerField` other than 1 is malformed (RFC 4055 §3.1).
    pub(crate) fn decode(algid: &mut Reader<'_>) -> Result<Self, Error> {
        if algid.is_empty() {
            return Ok(PssRestriction::Unrestricted);
        }
        let mut params = algid.read_sequence()?;
        // hashAlgorithm [0] EXPLICIT, DEFAULT sha1 — SHA-1 is unsupported,
        // so the field must be present.
        if params.peek_tag() != Some(tag::context(0)) {
            return Err(Error::UnsupportedAlgorithm);
        }
        let hash = decode_hash_algid(params.read_tlv(tag::context(0))?)?;
        // maskGenAlgorithm [1] EXPLICIT, DEFAULT mgf1SHA1 — same reasoning.
        if params.peek_tag() != Some(tag::context(1)) {
            return Err(Error::UnsupportedAlgorithm);
        }
        let body = params.read_tlv(tag::context(1))?;
        let mut r = Reader::new(body);
        let mut mgf = r.read_sequence()?;
        if parse_oid(mgf.read_oid()?)?.as_slice() != oid::ID_MGF1 {
            return Err(Error::UnsupportedAlgorithm);
        }
        let mgf1_hash = decode_hash_algid(mgf.read_element()?)?;
        mgf.finish()?;
        r.finish()?;
        // saltLength [2] EXPLICIT, DEFAULT 20.
        let salt_len = if params.peek_tag() == Some(tag::context(2)) {
            let body = params.read_tlv(tag::context(2))?;
            let mut r = Reader::new(body);
            let bytes = r.read_integer_bytes()?;
            r.finish()?;
            decode_small_uint(bytes)?
        } else {
            20
        };
        // trailerField [3] EXPLICIT, DEFAULT 1 — the only legal value.
        if params.peek_tag() == Some(tag::context(3)) {
            let body = params.read_tlv(tag::context(3))?;
            let mut r = Reader::new(body);
            let trailer = r.read_integer_bytes()?;
            r.finish()?;
            if trailer != [1] {
                return Err(Error::Malformed);
            }
        }
        params.finish()?;
        Ok(PssRestriction::Restricted(PssParams {
            hash,
            mgf1_hash,
            salt_len,
            trailer_field: 1,
        }))
    }

    /// Encodes the `AlgorithmIdentifier.parameters` for this restriction:
    /// nothing when unrestricted, else a DER `RSASSA-PSS-params` SEQUENCE
    /// (fields equal to their `DEFAULT` omitted, as DER requires; the digest
    /// `AlgorithmIdentifier`s carry absent parameters per RFC 4055 §2.1).
    pub(crate) fn encode_params(&self) -> Vec<u8> {
        match self {
            PssRestriction::Unrestricted => Vec::new(),
            PssRestriction::Restricted(p) => {
                let mut body = Vec::new();
                // hashAlgorithm: a `PssHash` is never the SHA-1 default.
                let hash = encode_sequence(&oid_tlv(p.hash.oid()));
                body.extend_from_slice(&encode_context(0, &hash));
                let mgf1_hash = encode_sequence(&oid_tlv(p.mgf1_hash.oid()));
                let mgf = encode_sequence(&[oid_tlv(oid::ID_MGF1), mgf1_hash].concat());
                body.extend_from_slice(&encode_context(1, &mgf));
                if p.salt_len != 20 {
                    let salt = encode_integer(&p.salt_len.to_be_bytes());
                    body.extend_from_slice(&encode_context(2, &salt));
                }
                if p.trailer_field != 1 {
                    let trailer = encode_integer(&[p.trailer_field]);
                    body.extend_from_slice(&encode_context(3, &trailer));
                }
                encode_sequence(&body)
            }
        }
    }
}

/// Decodes one digest `AlgorithmIdentifier` (`SEQUENCE { OID, NULL
/// OPTIONAL }`, both encodings accepted per RFC 4055 §2.1) into a
/// [`PssHash`], refusing any other digest as unsupported.
fn decode_hash_algid(der: &[u8]) -> Result<PssHash, Error> {
    let mut r = Reader::new(der);
    let mut h = r.read_sequence()?;
    let arcs = parse_oid(h.read_oid()?)?;
    if !h.is_empty() {
        h.read_null()?;
    }
    h.finish()?;
    r.finish()?;
    PssHash::from_oid(arcs.as_slice()).ok_or(Error::UnsupportedAlgorithm)
}

/// Decodes the content octets of a non-negative DER INTEGER into a `u32`
/// (a leading `0x00` pad octet is legal; a set sign bit or an overflow is
/// not a salt length any modulus admits).
fn decode_small_uint(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.is_empty() || bytes[0] & 0x80 != 0 {
        return Err(Error::Malformed);
    }
    let mut v: u32 = 0;
    for &b in bytes {
        v = v
            .checked_mul(256)
            .and_then(|v| v.checked_add(u32::from(b)))
            .ok_or(Error::Malformed)?;
    }
    Ok(v)
}

/// A public key whose algorithm is determined at runtime — the form recovered
/// from a certificate or a PKIX SPKI document.
#[derive(Clone, Debug)]
#[non_exhaustive]
// ML-DSA keys are fixed-size inline arrays (that is what makes ML-DSA usable
// without an allocator), so the PQ variants dwarf the classical ones. Boxing
// them would trade this for a heap indirection on every key; the enum is only
// ever built by the `alloc`-gated X.509 parsers and moved rarely.
#[allow(clippy::large_enum_variant)]
pub enum AnyPublicKey {
    /// An RSA public key (runtime-sized) certified as `rsaEncryption`.
    Rsa(BoxedRsaPublicKey),
    /// An RSA public key certified as `id-RSASSA-PSS` (RFC 4055 §1.2): the
    /// key may only be used with RSASSA-PSS, and only with the parameters
    /// the [`PssRestriction`] names. It re-encodes as `id-RSASSA-PSS`
    /// (parameters included), verifies only through the `rsa-pss-pss-*`
    /// registry entries matching the restriction, and refuses PKCS#1 v1.5
    /// and RSA encryption.
    RsaPss(BoxedRsaPublicKey, PssRestriction),
    /// An ECDSA public key on one of the supported curves.
    Ecdsa(BoxedEcdsaPublicKey),
    /// An Ed25519 public key.
    Ed25519(Ed25519PublicKey),
    /// An X25519 key-agreement public key.
    X25519(X25519PublicKey),
    /// An X448 key-agreement public key.
    X448(X448PublicKey),
    /// An Ed448 public key.
    Ed448(Ed448PublicKey),
    /// An ML-DSA-44 (FIPS 204) public key.
    #[cfg(feature = "mldsa")]
    MlDsa44(MlDsa44PublicKey),
    /// An ML-DSA-65 (FIPS 204) public key.
    #[cfg(feature = "mldsa")]
    MlDsa65(MlDsa65PublicKey),
    /// An ML-DSA-87 (FIPS 204) public key.
    #[cfg(feature = "mldsa")]
    MlDsa87(MlDsa87PublicKey),
    /// An SLH-DSA (FIPS 205) public key. The variant carries the parameter
    /// set inside the [`slhdsa::PublicKey`] (so a single enum arm covers all
    /// twelve standardized sets).
    #[cfg(feature = "slhdsa")]
    SlhDsa(slhdsa::PublicKey),
}

impl AnyPublicKey {
    /// Encodes the key as a PKIX `SubjectPublicKeyInfo` DER structure.
    pub fn to_spki_der(&self) -> Vec<u8> {
        match self {
            AnyPublicKey::Rsa(k) => {
                let algid = algorithm_identifier(oid::RSA_ENCRYPTION, true);
                encode_sequence(&[algid, encode_bit_string(&k.to_pkcs1_der())].concat())
            }
            // RFC 4055 §1.2: `id-RSASSA-PSS` with the parameters absent
            // (unrestricted) or the `RSASSA-PSS-params` the key is pinned
            // to — never re-encoded as `rsaEncryption`, which would drop the
            // restriction.
            AnyPublicKey::RsaPss(k, restriction) => {
                let algid = encode_sequence(
                    &[oid_tlv(oid::ID_RSASSA_PSS), restriction.encode_params()].concat(),
                );
                encode_sequence(&[algid, encode_bit_string(&k.to_pkcs1_der())].concat())
            }
            AnyPublicKey::Ecdsa(k) => {
                let algid = encode_sequence(
                    &[oid_tlv(oid::EC_PUBLIC_KEY), oid_tlv(curve_oid(k.curve()))].concat(),
                );
                encode_sequence(&[algid, encode_bit_string(&k.to_sec1())].concat())
            }
            AnyPublicKey::Ed25519(k) => {
                // RFC 8410: AlgorithmIdentifier is the bare OID (no parameters).
                let algid = encode_sequence(&oid_tlv(oid::ID_ED25519));
                encode_sequence(&[algid, encode_bit_string(&k.to_bytes())].concat())
            }
            AnyPublicKey::Ed448(k) => {
                // RFC 8410: AlgorithmIdentifier is the bare OID (no parameters).
                let algid = encode_sequence(&oid_tlv(oid::ID_ED448));
                encode_sequence(&[algid, encode_bit_string(&k.to_bytes())].concat())
            }
            AnyPublicKey::X25519(k) => {
                let algid = encode_sequence(&oid_tlv(oid::ID_X25519));
                encode_sequence(&[algid, encode_bit_string(k.as_bytes())].concat())
            }
            AnyPublicKey::X448(k) => {
                let algid = encode_sequence(&oid_tlv(oid::ID_X448));
                encode_sequence(&[algid, encode_bit_string(k.as_bytes())].concat())
            }
            // ML-DSA (draft-ietf-lamps-dilithium-certificates): bare OID, no
            // parameters; key bytes are the raw FIPS 204 encoding.
            #[cfg(feature = "mldsa")]
            AnyPublicKey::MlDsa44(k) => mldsa_spki(oid::ID_ML_DSA_44, k.to_bytes()),
            #[cfg(feature = "mldsa")]
            AnyPublicKey::MlDsa65(k) => mldsa_spki(oid::ID_ML_DSA_65, k.to_bytes()),
            #[cfg(feature = "mldsa")]
            AnyPublicKey::MlDsa87(k) => mldsa_spki(oid::ID_ML_DSA_87, k.to_bytes()),
            #[cfg(feature = "slhdsa")]
            AnyPublicKey::SlhDsa(k) => k.to_spki_der(),
        }
    }

    /// Encodes the key as a PKIX PEM document (`-----BEGIN PUBLIC KEY-----`).
    pub fn to_spki_pem(&self) -> String {
        pem_encode(SPKI_LABEL, &self.to_spki_der())
    }

    /// Parses a PKIX `SubjectPublicKeyInfo` DER structure.
    ///
    /// The `AlgorithmIdentifier.parameters` field is validated per
    /// algorithm (RFC 5280 §4.1.1.2 / §4.1.2.7, RFC 4055 §2.1, RFC 8410):
    ///
    /// * `rsaEncryption` — explicit NULL required.
    /// * `id-RSASSA-PSS` — parameters absent (an unrestricted PSS key) or
    ///   one strict `RSASSA-PSS-params` SEQUENCE naming a SHA-256/384/512
    ///   digest for both the hash and MGF1 (any other digest, including the
    ///   SHA-1 DER default, is [`Error::UnsupportedAlgorithm`]); yields
    ///   [`AnyPublicKey::RsaPss`] with the [`PssRestriction`] preserved.
    /// * `id-ecPublicKey` — named-curve OID, then no trailing junk.
    /// * `id-Ed25519` — no parameters.
    /// * `id-Ed448` — no parameters.
    /// * `id-X25519` / `id-X448` — no parameters.
    /// * `id-ml-dsa-*` / SLH-DSA — bare OID, no parameters.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(der);
        let mut spki = reader.read_sequence()?;
        // Nothing may follow the outer SEQUENCE: a trailing byte after a
        // well-formed SPKI is not DER (Wycheproof `InvalidAsn`).
        reader.finish()?;
        let mut algid = spki.read_sequence()?;
        let alg = parse_oid(algid.read_oid()?)?;

        if alg.as_slice() == oid::RSA_ENCRYPTION {
            // RFC 3279 §2.3.1: parameters MUST be NULL for rsaEncryption.
            algid.read_null()?;
            algid.finish()?;
            let key_bits = spki.read_bit_string()?;
            spki.finish()?;
            Ok(AnyPublicKey::Rsa(BoxedRsaPublicKey::from_pkcs1_der(
                key_bits,
            )?))
        } else if alg.as_slice() == oid::ID_RSASSA_PSS {
            // RFC 4055 §3.1: absent parameters or one RSASSA-PSS-params.
            let restriction = PssRestriction::decode(&mut algid)?;
            algid.finish()?;
            let key_bits = spki.read_bit_string()?;
            spki.finish()?;
            Ok(AnyPublicKey::RsaPss(
                BoxedRsaPublicKey::from_pkcs1_der(key_bits)?,
                restriction,
            ))
        } else if alg.as_slice() == oid::EC_PUBLIC_KEY {
            let curve_arcs = parse_oid(algid.read_oid()?)?;
            // RFC 5480 §2.1.1: the only parameters we accept after the OID
            // are the namedCurve. Reject ECParameters trailers, implicitCA,
            // or any junk.
            algid.finish()?;
            let curve = curve_from_oid(curve_arcs.as_slice()).ok_or(Error::UnsupportedAlgorithm)?;
            let key_bits = spki.read_bit_string()?;
            spki.finish()?;
            Ok(AnyPublicKey::Ecdsa(
                BoxedEcdsaPublicKey::from_sec1(curve, key_bits).map_err(|_| Error::Malformed)?,
            ))
        } else if alg.as_slice() == oid::ID_ED25519 {
            // RFC 8410 §3: AlgorithmIdentifier MUST be the bare OID — no
            // parameters at all.
            algid.finish()?;
            let key_bits = spki.read_bit_string()?;
            spki.finish()?;
            let bytes: [u8; 32] = key_bits.try_into().map_err(|_| Error::Malformed)?;
            Ok(AnyPublicKey::Ed25519(Ed25519PublicKey::from_bytes(bytes)))
        } else if alg.as_slice() == oid::ID_ED448 {
            // RFC 8410 §3: AlgorithmIdentifier MUST be the bare OID — no
            // parameters at all.
            algid.finish()?;
            let key_bits = spki.read_bit_string()?;
            spki.finish()?;
            let bytes: [u8; 57] = key_bits.try_into().map_err(|_| Error::Malformed)?;
            Ok(AnyPublicKey::Ed448(Ed448PublicKey::from_bytes(bytes)))
        } else if alg.as_slice() == oid::ID_X25519 {
            algid.finish()?;
            let key_bits = spki.read_bit_string()?;
            spki.finish()?;
            let bytes: [u8; 32] = key_bits.try_into().map_err(|_| Error::Malformed)?;
            Ok(AnyPublicKey::X25519(X25519PublicKey::from_bytes(bytes)))
        } else if alg.as_slice() == oid::ID_X448 {
            algid.finish()?;
            let key_bits = spki.read_bit_string()?;
            spki.finish()?;
            let bytes: [u8; 56] = key_bits.try_into().map_err(|_| Error::Malformed)?;
            Ok(AnyPublicKey::X448(X448PublicKey::from_bytes(bytes)))
        } else {
            #[cfg(feature = "mldsa")]
            {
                if alg.as_slice() == oid::ID_ML_DSA_44 {
                    // FIPS 204 / draft-ietf-lamps-dilithium-certificates:
                    // bare OID, no parameters.
                    algid.finish()?;
                    let key_bits = spki.read_bit_string()?;
                    spki.finish()?;
                    return Ok(AnyPublicKey::MlDsa44(
                        MlDsa44PublicKey::from_bytes(key_bits).map_err(|_| Error::Malformed)?,
                    ));
                } else if alg.as_slice() == oid::ID_ML_DSA_65 {
                    algid.finish()?;
                    let key_bits = spki.read_bit_string()?;
                    spki.finish()?;
                    return Ok(AnyPublicKey::MlDsa65(
                        MlDsa65PublicKey::from_bytes(key_bits).map_err(|_| Error::Malformed)?,
                    ));
                } else if alg.as_slice() == oid::ID_ML_DSA_87 {
                    algid.finish()?;
                    let key_bits = spki.read_bit_string()?;
                    spki.finish()?;
                    return Ok(AnyPublicKey::MlDsa87(
                        MlDsa87PublicKey::from_bytes(key_bits).map_err(|_| Error::Malformed)?,
                    ));
                }
            }
            #[cfg(feature = "slhdsa")]
            {
                if let Some(set) = slhdsa::ParamSet::from_oid(alg.as_slice()) {
                    // SLH-DSA: bare OID, no parameters.
                    algid.finish()?;
                    let key_bits = spki.read_bit_string()?;
                    spki.finish()?;
                    let pk = slhdsa::PublicKey::from_bytes(set, key_bits)
                        .map_err(|_| Error::Malformed)?;
                    return Ok(AnyPublicKey::SlhDsa(pk));
                }
            }
            Err(Error::UnsupportedAlgorithm)
        }
    }

    /// Parses a PKIX PEM public key.
    pub fn from_spki_pem(pem: &str) -> Result<Self, Error> {
        Self::from_spki_der(&pem_decode(pem, SPKI_LABEL)?)
    }

    /// Verifies `sig` over `msg` under the signature `AlgorithmIdentifier`
    /// `sig_alg` (OID plus parameters).
    ///
    /// Dispatch goes through [`crate::signature_registry`]: the identifier
    /// picks an entry in [`ALGORITHMS`](crate::signature_registry::ALGORITHMS)
    /// (see [`signature_algorithm`](Self::signature_algorithm)), which then
    /// re-parses the SPKI to recover the key and verifies with the
    /// identifier's parameters
    /// ([`SignatureAlgorithm::verify_with_params`](crate::signature_registry::SignatureAlgorithm::verify_with_params)).
    /// RSA signatures are PKCS#1 v1.5 or RSA-PSS (the OID fixes which; the
    /// `RSASSA-PSS-params` fix the digest and salt length); ECDSA
    /// signatures are DER `Ecdsa-Sig-Value`; Ed25519 is raw 64-byte R‖S.
    ///
    /// An [`RsaPss`](Self::RsaPss) key honours its RFC 4055 restriction:
    /// only `id-RSASSA-PSS` signatures are accepted, and only with
    /// parameters the restriction permits
    /// ([`PssRestriction::permits_params`]); a PKCS#1 v1.5 OID, or
    /// parameters the restriction forbids, is
    /// [`Error::UnsupportedAlgorithm`].
    ///
    /// SECURITY: this performs **no** signature-algorithm-strength or key-size
    /// policy. A SHA-1- or MD5-based RSA signature, or an undersized RSA key,
    /// will verify **successfully** here as long as the math checks out. This
    /// is the low-level primitive every x509 verify entry point routes through
    /// ([`Certificate::verify_signature_with`](crate::x509::Certificate::verify_signature_with),
    /// the CRL/CSR/OCSP verifiers); none of them impose a strength whitelist.
    /// Callers MUST apply their own policy — the TLS path gates every signature
    /// through `SignaturePolicy::permits` in `tls::pki::verify` before
    /// trusting it. Do not treat a successful return as evidence the algorithm
    /// is acceptable.
    pub fn verify(
        &self,
        sig_alg: &super::SignatureAlgorithmIdentifier,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), Error> {
        let algo = self
            .signature_algorithm(sig_alg)
            .ok_or(Error::UnsupportedAlgorithm)?;
        // The registry entry's `verify` parses an SPKI; round-trip ours.
        let spki = self.to_spki_der();
        algo.verify_with_params(&spki, msg, sig, sig_alg.params())
    }

    /// The [`crate::signature_registry`] entry [`verify`](Self::verify)
    /// dispatches to for a signature whose X.509 `AlgorithmIdentifier` is
    /// `sig_alg`, or `None` when no entry would ever accept the pair.
    ///
    /// For every OID but `id-RSASSA-PSS` this is
    /// [`find_by_oid`](crate::signature_registry::find_by_oid) — except
    /// under an [`RsaPss`](Self::RsaPss) key, which maps every other OID
    /// (the PKCS#1 v1.5 family in particular) to `None` per RFC 4055 §1.2.
    ///
    /// `id-RSASSA-PSS` is resolved from the identifier's
    /// `RSASSA-PSS-params` (RFC 4055 §3.1), never from the OID alone: the
    /// `rsa-pss-pss-<digest>` entry for the *signature's* digest, provided
    /// MGF1 uses the same digest and the trailer field is 1 (the only
    /// profile the registry implements), and — for a restricted
    /// [`RsaPss`](Self::RsaPss) key — provided the parameters are
    /// compatible with the key's ([`PssRestriction::permits_params`]).
    /// An identifier without parameters ([`SignatureAlgorithmIdentifier::from_oid`])
    /// names the unsupported SHA-1 defaults and resolves to `None`.
    ///
    /// Policy gates (`SignaturePolicy::permits`) should consult this rather
    /// than the bare OID lookup so the entry they whitelist is the one that
    /// verifies.
    ///
    /// [`SignatureAlgorithmIdentifier::from_oid`]: super::SignatureAlgorithmIdentifier::from_oid
    pub fn signature_algorithm(
        &self,
        sig_alg: &super::SignatureAlgorithmIdentifier,
    ) -> Option<&'static dyn crate::signature_registry::SignatureAlgorithm> {
        use crate::signature_registry::{find_by_id, find_by_oid};
        if sig_alg.oid() == oid::ID_RSASSA_PSS {
            let p = sig_alg.pss_params()?;
            if p.mgf1_hash != p.hash || p.trailer_field != 1 {
                // A MGF1-digest / trailer combination no entry implements.
                return None;
            }
            if let AnyPublicKey::RsaPss(_, restriction) = self
                && !restriction.permits_params(p)
            {
                return None;
            }
            return find_by_id(p.hash.registry_id());
        }
        if matches!(self, AnyPublicKey::RsaPss(..)) {
            // RFC 4055 §1.2: the key MUST only be used with RSASSA-PSS.
            return None;
        }
        find_by_oid(sig_alg.oid())
    }
}

#[cfg(feature = "key")]
impl AnyPublicKey {
    /// Converts this key into a boxed unified [`key::PublicKey`] trait object,
    /// so a parsed-by-OID key can be operated on polymorphically (verify /
    /// encrypt) without matching on the variant.
    ///
    /// [`key::PublicKey`]: crate::key::PublicKey
    pub fn into_dyn(self) -> alloc::boxed::Box<dyn crate::key::PublicKey> {
        use alloc::boxed::Box;
        match self {
            AnyPublicKey::Rsa(k) => Box::new(k),
            // The bare RSA key would accept PKCS#1 v1.5 and encryption; the
            // enum's own `PublicKey` impl is the one that enforces the RFC
            // 4055 restriction, so the boxed object stays an `AnyPublicKey`.
            k @ AnyPublicKey::RsaPss(..) => Box::new(k),
            AnyPublicKey::Ecdsa(k) => Box::new(k),
            AnyPublicKey::Ed25519(k) => Box::new(k),
            AnyPublicKey::Ed448(k) => Box::new(k),
            AnyPublicKey::X25519(k) => Box::new(k),
            AnyPublicKey::X448(k) => Box::new(k),
            #[cfg(feature = "mldsa")]
            AnyPublicKey::MlDsa44(k) => Box::new(k),
            #[cfg(feature = "mldsa")]
            AnyPublicKey::MlDsa65(k) => Box::new(k),
            #[cfg(feature = "mldsa")]
            AnyPublicKey::MlDsa87(k) => Box::new(k),
            #[cfg(feature = "slhdsa")]
            AnyPublicKey::SlhDsa(k) => Box::new(k),
        }
    }

    /// Borrows the matched variant as a [`key::PublicKey`](crate::key::PublicKey).
    ///
    /// For [`RsaPss`](Self::RsaPss) this is the bare RSA key, which knows
    /// nothing of the restriction: the trait impl below intercepts `verify`
    /// and `encrypt` for that variant before delegating, and only
    /// `algorithm` / `as_any` reach the inner key.
    fn inner(&self) -> &dyn crate::key::PublicKey {
        match self {
            AnyPublicKey::Rsa(k) | AnyPublicKey::RsaPss(k, _) => k,
            AnyPublicKey::Ecdsa(k) => k,
            AnyPublicKey::Ed25519(k) => k,
            AnyPublicKey::Ed448(k) => k,
            AnyPublicKey::X25519(k) => k,
            AnyPublicKey::X448(k) => k,
            #[cfg(feature = "mldsa")]
            AnyPublicKey::MlDsa44(k) => k,
            #[cfg(feature = "mldsa")]
            AnyPublicKey::MlDsa65(k) => k,
            #[cfg(feature = "mldsa")]
            AnyPublicKey::MlDsa87(k) => k,
            #[cfg(feature = "slhdsa")]
            AnyPublicKey::SlhDsa(k) => k,
        }
    }
}

/// `AnyPublicKey` is itself a [`key::PublicKey`](crate::key::PublicKey): each
/// operation delegates to the matched variant (including `as_any`, so an
/// `AnyPublicKey` wrapping an ECDSA key works directly as a key-agreement peer).
///
/// An [`RsaPss`](AnyPublicKey::RsaPss) key enforces its RFC 4055 §1.2
/// restriction here as well: `verify` requires
/// [`RsaSigPadding::Pss`](crate::key::RsaSigPadding::Pss) (PKCS#1 v1.5 is
/// [`Error::UnsupportedParam`](crate::key::Error::UnsupportedParam)) with,
/// for a restricted key, exactly the restriction's digest and salt length
/// ([`Error::InvalidParams`](crate::key::Error::InvalidParams) otherwise),
/// and `encrypt` is [`Error::Unsupported`](crate::key::Error::Unsupported) —
/// a PSS-restricted key is a signature key only.
#[cfg(feature = "key")]
impl crate::key::PublicKey for AnyPublicKey {
    fn algorithm(&self) -> crate::key::Algorithm {
        self.inner().algorithm()
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self.inner().as_any()
    }
    fn verify(
        &self,
        msg: &[u8],
        sig: &[u8],
        params: &crate::key::SignParams<'_>,
    ) -> Result<(), crate::key::Error> {
        if let AnyPublicKey::RsaPss(_, restriction) = self {
            pss_restriction_check(restriction, params)?;
        }
        self.inner().verify(msg, sig, params)
    }
    fn encrypt(
        &self,
        pt: &[u8],
        params: &crate::key::EncryptParams<'_>,
        rng: &mut dyn crate::rng::CryptoRngCore,
    ) -> Result<alloc::vec::Vec<u8>, crate::key::Error> {
        if matches!(self, AnyPublicKey::RsaPss(..)) {
            return Err(crate::key::Error::unsupported(
                crate::key::Operation::Encrypt,
                crate::key::Algorithm::Rsa,
            ));
        }
        self.inner().encrypt(pt, params, rng)
    }
}

/// Rejects facade verify parameters an RFC 4055 PSS key restriction forbids:
/// any padding but PSS, and — for a restricted key — a digest other than
/// the restriction's or a salt shorter than the restriction's (RFC 4055
/// §3.3). Only inspects the parameters; the RSA key's own `verify` consumes
/// (and re-validates) them afterwards.
#[cfg(feature = "key")]
fn pss_restriction_check(
    restriction: &PssRestriction,
    params: &crate::key::SignParams<'_>,
) -> Result<(), crate::key::Error> {
    use crate::key::{Error, RsaSigPadding, SaltLen};
    let mut p = params.reader();
    let hash = p.hash();
    let RsaSigPadding::Pss { salt_len } = p.padding() else {
        return Err(Error::UnsupportedParam { param: "padding" });
    };
    let PssRestriction::Restricted(want) = restriction else {
        return Ok(());
    };
    if hash != want.hash.hash_algorithm() || want.mgf1_hash != want.hash {
        return Err(Error::InvalidParams);
    }
    let salt_ok = match salt_len {
        SaltLen::DigestLength => want.hash.output_len() >= want.salt_len,
        SaltLen::Fixed(n) => n as u64 >= u64::from(want.salt_len),
        _ => false,
    };
    if !salt_ok {
        return Err(Error::InvalidParams);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::BoxedEcdsaPrivateKey;
    use crate::hash::{Sha256, Sha384, Sha512};
    use crate::rng::HmacDrbg;
    use crate::test_util::rsa_test_key_a;
    use crate::x509::SignatureAlgorithmIdentifier;

    #[test]
    fn rsa_spki_roundtrip() {
        let pk = rsa_test_key_a().public_key();
        let mut n = [0u8; 256];
        pk.modulus().write_be_bytes(&mut n);
        let mut e = [0u8; 256];
        pk.exponent().write_be_bytes(&mut e);
        let boxed = BoxedRsaPublicKey::new(
            crate::bignum::BoxedUint::from_be_bytes(&n),
            crate::bignum::BoxedUint::from_be_bytes(&e),
        );
        let any = AnyPublicKey::Rsa(boxed);

        let pem = any.to_spki_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        match AnyPublicKey::from_spki_pem(&pem).unwrap() {
            AnyPublicKey::Rsa(k) => assert_eq!(k.modulus().bit_len(), 2048),
            _ => panic!("expected RSA"),
        }
    }

    #[test]
    fn ec_spki_roundtrip_and_verify() {
        // Each supported curve round-trips through SPKI and verifies a signature.
        for (curve, sig_alg) in [
            (CurveId::P256, oid::ECDSA_WITH_SHA256),
            (CurveId::P384, oid::ECDSA_WITH_SHA384),
            (CurveId::P521, oid::ECDSA_WITH_SHA512),
        ] {
            let mut rng = HmacDrbg::<Sha256>::new(b"spki-ec", b"n", &[]);
            let sk = BoxedEcdsaPrivateKey::generate(curve, &mut rng);
            let any = AnyPublicKey::Ecdsa(sk.public_key());

            let der = any.to_spki_der();
            let parsed = AnyPublicKey::from_spki_der(&der).unwrap();
            match &parsed {
                AnyPublicKey::Ecdsa(k) => assert_eq!(k.curve(), curve),
                _ => panic!("expected ECDSA"),
            }

            let sig = match curve {
                CurveId::P256 => sk.sign::<Sha256>(b"hello").unwrap(),
                CurveId::P384 => sk.sign::<Sha384>(b"hello").unwrap(),
                _ => sk.sign::<Sha512>(b"hello").unwrap(),
            };
            let sig_alg = SignatureAlgorithmIdentifier::from_oid(sig_alg);
            parsed
                .verify(&sig_alg, b"hello", &sig.to_der(curve))
                .unwrap();
            assert!(
                parsed
                    .verify(&sig_alg, b"other", &sig.to_der(curve))
                    .is_err()
            );
        }
    }

    #[test]
    fn ed25519_spki_roundtrip_and_verify() {
        use crate::ec::Ed25519PrivateKey;
        let mut rng = HmacDrbg::<Sha256>::new(b"spki-ed", b"n", &[]);
        let sk = Ed25519PrivateKey::generate(&mut rng);
        let any = AnyPublicKey::Ed25519(sk.public_key());

        let pem = any.to_spki_pem();
        let parsed = AnyPublicKey::from_spki_pem(&pem).unwrap();
        assert!(matches!(parsed, AnyPublicKey::Ed25519(_)));

        // Ed25519 signatures are raw 64-byte R‖S, verified under id-Ed25519.
        let sig = sk.sign(b"hello").to_bytes();
        let alg = SignatureAlgorithmIdentifier::from_oid(oid::ID_ED25519);
        parsed.verify(&alg, b"hello", &sig).unwrap();
        assert!(parsed.verify(&alg, b"other", &sig).is_err());
    }

    #[test]
    fn ed448_spki_roundtrip_and_verify() {
        use crate::ec::Ed448PrivateKey;
        let mut rng = HmacDrbg::<Sha256>::new(b"spki-ed448", b"n", &[]);
        let sk = Ed448PrivateKey::generate(&mut rng);
        let any = AnyPublicKey::Ed448(sk.public_key());

        let pem = any.to_spki_pem();
        let parsed = AnyPublicKey::from_spki_pem(&pem).unwrap();
        assert!(matches!(parsed, AnyPublicKey::Ed448(_)));

        // Ed448 signatures are raw 114-byte R‖S (empty context), verified
        // under id-Ed448.
        let sig = sk.sign(b"hello").to_bytes();
        let alg = SignatureAlgorithmIdentifier::from_oid(oid::ID_ED448);
        parsed.verify(&alg, b"hello", &sig).unwrap();
        assert!(parsed.verify(&alg, b"other", &sig).is_err());
    }

    // H-7: RFC 3279 §2.3.1 — rsaEncryption REQUIRES explicit NULL
    // parameters in the AlgorithmIdentifier. An SPKI that places an
    // ECParameters OID (or any other tag) where NULL belongs must be
    // rejected. id-Ed25519 likewise requires NO parameters; id-ecPublicKey
    // requires exactly the namedCurve OID and nothing trailing.
    #[test]
    fn spki_rsa_requires_null_params() {
        use crate::der::{encode_bit_string, encode_sequence, oid_tlv};

        // Build a real RSA public-key BIT STRING from the test key.
        let pk = rsa_test_key_a().public_key();
        let mut n_bytes = [0u8; 256];
        pk.modulus().write_be_bytes(&mut n_bytes);
        let mut e_bytes = [0u8; 256];
        pk.exponent().write_be_bytes(&mut e_bytes);
        let boxed = BoxedRsaPublicKey::new(
            crate::bignum::BoxedUint::from_be_bytes(&n_bytes),
            crate::bignum::BoxedUint::from_be_bytes(&e_bytes),
        );
        let pkcs1 = boxed.to_pkcs1_der();
        let key_bits = encode_bit_string(&pkcs1);

        // (a) rsaEncryption with NULL params — sanity: parses fine.
        let algid_ok =
            encode_sequence(&[oid_tlv(oid::RSA_ENCRYPTION), crate::der::encode_null()].concat());
        let spki_ok = encode_sequence(&[algid_ok, key_bits.clone()].concat());
        assert!(AnyPublicKey::from_spki_der(&spki_ok).is_ok());

        // (b) rsaEncryption with a non-NULL parameter (e.g. an OID where
        //     NULL belongs). Must be rejected.
        let algid_bad =
            encode_sequence(&[oid_tlv(oid::RSA_ENCRYPTION), oid_tlv(oid::PRIME256V1)].concat());
        let spki_bad = encode_sequence(&[algid_bad, key_bits.clone()].concat());
        assert!(AnyPublicKey::from_spki_der(&spki_bad).is_err());

        // (c) rsaEncryption with NO parameter at all (bare OID). Must be
        //     rejected — the NULL is mandatory.
        let algid_missing = encode_sequence(&oid_tlv(oid::RSA_ENCRYPTION));
        let spki_missing = encode_sequence(&[algid_missing, key_bits.clone()].concat());
        assert!(AnyPublicKey::from_spki_der(&spki_missing).is_err());

        // (d) rsaEncryption with NULL params followed by trailing junk
        //     inside the AlgorithmIdentifier SEQUENCE. Must be rejected.
        let algid_trailing = encode_sequence(
            &[
                oid_tlv(oid::RSA_ENCRYPTION),
                crate::der::encode_null(),
                crate::der::encode_tlv(0x01, &[0x00]), // BOOLEAN false
            ]
            .concat(),
        );
        let spki_trailing = encode_sequence(&[algid_trailing, key_bits].concat());
        assert!(AnyPublicKey::from_spki_der(&spki_trailing).is_err());

        // (e) A byte after the outer SEQUENCE (Wycheproof ECDH tcId 421,
        //     "appending unused 0's to sequence"). Must be rejected.
        let spki_padded = [spki_ok.as_slice(), &[0x00]].concat();
        assert!(AnyPublicKey::from_spki_der(&spki_padded).is_err());
    }

    fn boxed_rsa_a() -> BoxedRsaPublicKey {
        let pk = rsa_test_key_a().public_key();
        let mut n = [0u8; 256];
        pk.modulus().write_be_bytes(&mut n);
        let mut e = [0u8; 256];
        pk.exponent().write_be_bytes(&mut e);
        BoxedRsaPublicKey::new(
            crate::bignum::BoxedUint::from_be_bytes(&n),
            crate::bignum::BoxedUint::from_be_bytes(&e),
        )
    }

    /// An `id-RSASSA-PSS` SPKI (RFC 4055 §1.2) parses to `RsaPss` with the
    /// restriction preserved — unrestricted, or the exact parameter set —
    /// and re-encodes byte-for-byte, never as `rsaEncryption`. Digests the
    /// registry cannot verify PSS under (the SHA-1 DER default included)
    /// are refused at parse time; a `trailerField` other than 1 is
    /// malformed.
    #[test]
    fn rsa_pss_spki_roundtrip_preserves_restriction() {
        use crate::der::{encode_context, encode_integer, encode_null};
        let key = boxed_rsa_a();
        for restriction in [
            PssRestriction::Unrestricted,
            PssRestriction::for_hash(PssHash::Sha256),
            PssRestriction::for_hash(PssHash::Sha384),
            PssRestriction::for_hash(PssHash::Sha512),
            PssRestriction::Restricted(PssParams {
                hash: PssHash::Sha256,
                mgf1_hash: PssHash::Sha384,
                salt_len: 20,
                trailer_field: 1,
            }),
        ] {
            let any = AnyPublicKey::RsaPss(key.clone(), restriction);
            let der = any.to_spki_der();
            let parsed = AnyPublicKey::from_spki_der(&der).unwrap();
            match &parsed {
                AnyPublicKey::RsaPss(k, r) => {
                    assert_eq!(*r, restriction);
                    assert_eq!(k.to_pkcs1_der(), key.to_pkcs1_der());
                }
                other => panic!("expected RsaPss, got {other:?}"),
            }
            assert_eq!(parsed.to_spki_der(), der, "{restriction:?}");
            // The key OID is `id-RSASSA-PSS`, not `rsaEncryption`.
            let mut r = Reader::new(&der);
            let mut spki = r.read_sequence().unwrap();
            let mut algid = spki.read_sequence().unwrap();
            assert_eq!(
                parse_oid(algid.read_oid().unwrap()).unwrap().as_slice(),
                oid::ID_RSASSA_PSS
            );
            // PEM round-trips the same way.
            let pem = any.to_spki_pem();
            assert!(matches!(
                AnyPublicKey::from_spki_pem(&pem).unwrap(),
                AnyPublicKey::RsaPss(_, r) if r == restriction
            ));
        }

        // Hand-built parameter blocks the parser must reject.
        let hash_algid = |h: &[u64]| encode_sequence(&[oid_tlv(h), encode_null()].concat());
        let mgf = |h: &[u64]| {
            encode_context(
                1,
                &encode_sequence(&[oid_tlv(oid::ID_MGF1), hash_algid(h)].concat()),
            )
        };
        let spki_with = |params: Vec<u8>| {
            let algid = encode_sequence(&[oid_tlv(oid::ID_RSASSA_PSS), params].concat());
            encode_sequence(&[algid, encode_bit_string(&key.to_pkcs1_der())].concat())
        };
        // Empty params = every DEFAULT = SHA-1: unsupported.
        assert_eq!(
            AnyPublicKey::from_spki_der(&spki_with(encode_sequence(&[]))).err(),
            Some(Error::UnsupportedAlgorithm)
        );
        // SHA-1 named explicitly, or a non-SHA-2 digest: unsupported.
        let sha1 = encode_sequence(
            &[
                encode_context(0, &hash_algid(oid::ID_SHA1)),
                mgf(oid::ID_SHA1),
            ]
            .concat(),
        );
        assert_eq!(
            AnyPublicKey::from_spki_der(&spki_with(sha1)).err(),
            Some(Error::UnsupportedAlgorithm)
        );
        // Hash present but MGF absent (= MGF1-SHA-1 default): unsupported.
        let no_mgf = encode_sequence(&encode_context(0, &hash_algid(oid::ID_SHA256)));
        assert_eq!(
            AnyPublicKey::from_spki_der(&spki_with(no_mgf)).err(),
            Some(Error::UnsupportedAlgorithm)
        );
        // trailerField 2 is not a value RFC 4055 allows: malformed.
        let bad_trailer = encode_sequence(
            &[
                encode_context(0, &hash_algid(oid::ID_SHA256)),
                mgf(oid::ID_SHA256),
                encode_context(2, &encode_integer(&[32])),
                encode_context(3, &encode_integer(&[2])),
            ]
            .concat(),
        );
        assert_eq!(
            AnyPublicKey::from_spki_der(&spki_with(bad_trailer)).err(),
            Some(Error::Malformed)
        );
        // Trailing junk after the params inside the AlgorithmIdentifier.
        let mut junk = encode_sequence(
            &[
                encode_context(0, &hash_algid(oid::ID_SHA256)),
                mgf(oid::ID_SHA256),
                encode_context(2, &encode_integer(&[32])),
            ]
            .concat(),
        );
        junk.extend_from_slice(&encode_null());
        assert!(AnyPublicKey::from_spki_der(&spki_with(junk)).is_err());
    }

    /// RFC 4055 at the `AnyPublicKey` level: an `id-RSASSA-PSS` signature
    /// dispatches to the `rsa-pss-pss-*` entry for the digest *its
    /// parameters* name, a PSS-restricted key refuses every PKCS#1 v1.5 OID
    /// and any PSS parameters incompatible with its restriction (§3.3:
    /// digest equal, salt at least the key's), an identifier without
    /// parameters (the SHA-1 defaults) resolves to nothing — while the same
    /// modulus as `AnyPublicKey::Rsa` still verifies PKCS#1 v1.5 and PSS
    /// over any digest.
    #[test]
    fn rsa_pss_key_dispatches_only_to_matching_pss_entries() {
        let sk = rsa_test_key_a();
        let mut rng = HmacDrbg::<Sha256>::new(b"spki-pss-dispatch", b"n", &[]);
        let pss256 = sk.sign_pss::<Sha256, _>(b"hi", &mut rng).unwrap();
        let pss384 = sk.sign_pss::<Sha384, _>(b"hi", &mut rng).unwrap();
        let pss256_salt20 = sk
            .sign_pss_with_salt_len::<Sha256, _>(b"hi", 20, &mut rng)
            .unwrap();
        let pkcs1 = sk.sign_pkcs1v15::<Sha256>(b"hi").unwrap();
        let key = boxed_rsa_a();
        let alg256 = SignatureAlgorithmIdentifier::rsa_pss(PssParams::for_hash(PssHash::Sha256));
        let alg384 = SignatureAlgorithmIdentifier::rsa_pss(PssParams::for_hash(PssHash::Sha384));
        let alg256_salt20 = SignatureAlgorithmIdentifier::rsa_pss(PssParams {
            hash: PssHash::Sha256,
            mgf1_hash: PssHash::Sha256,
            salt_len: 20,
            trailer_field: 1,
        });
        let bare = SignatureAlgorithmIdentifier::from_oid(oid::ID_RSASSA_PSS);

        let unrestricted = AnyPublicKey::RsaPss(key.clone(), PssRestriction::Unrestricted);
        let r256 = AnyPublicKey::RsaPss(key.clone(), PssRestriction::for_hash(PssHash::Sha256));
        let r384 = AnyPublicKey::RsaPss(key.clone(), PssRestriction::for_hash(PssHash::Sha384));
        let plain = AnyPublicKey::Rsa(key.clone());

        // Dispatch follows the signature's parameters, gated by the key's
        // restriction.
        for (k, alg, id) in [
            (&unrestricted, &alg256, Some("rsa-pss-pss-sha256")),
            (&unrestricted, &alg384, Some("rsa-pss-pss-sha384")),
            (&unrestricted, &alg256_salt20, Some("rsa-pss-pss-sha256")),
            (&r256, &alg256, Some("rsa-pss-pss-sha256")),
            (&r256, &alg384, None),
            (&r256, &alg256_salt20, None),
            (&r384, &alg384, Some("rsa-pss-pss-sha384")),
            (&r384, &alg256, None),
            (&plain, &alg256, Some("rsa-pss-pss-sha256")),
            (&plain, &alg384, Some("rsa-pss-pss-sha384")),
            (&plain, &alg256_salt20, Some("rsa-pss-pss-sha256")),
            // No parameters = SHA-1 defaults: nothing implements them.
            (&unrestricted, &bare, None),
            (&r256, &bare, None),
            (&plain, &bare, None),
        ] {
            assert_eq!(
                k.signature_algorithm(alg).map(|a| a.id()),
                id,
                "{k:?} / {alg:?}"
            );
        }
        for k in [&unrestricted, &r256, &r384] {
            for pkcs1_oid in [
                oid::SHA256_WITH_RSA,
                oid::SHA384_WITH_RSA,
                oid::SHA1_WITH_RSA,
            ] {
                let alg = SignatureAlgorithmIdentifier::from_oid(pkcs1_oid);
                assert!(k.signature_algorithm(&alg).is_none());
                assert_eq!(
                    k.verify(&alg, b"hi", &pkcs1).err(),
                    Some(Error::UnsupportedAlgorithm)
                );
            }
        }
        unrestricted.verify(&alg256, b"hi", &pss256).unwrap();
        unrestricted.verify(&alg384, b"hi", &pss384).unwrap();
        // The signature's salt length is honoured, not assumed.
        unrestricted
            .verify(&alg256_salt20, b"hi", &pss256_salt20)
            .unwrap();
        assert!(unrestricted.verify(&alg256, b"hi", &pss256_salt20).is_err());
        assert!(unrestricted.verify(&alg256_salt20, b"hi", &pss256).is_err());
        r256.verify(&alg256, b"hi", &pss256).unwrap();
        r384.verify(&alg384, b"hi", &pss384).unwrap();
        // Digest the restriction forbids, or a salt shorter than the key's:
        // refused before any RSA math.
        assert_eq!(
            r256.verify(&alg384, b"hi", &pss384).err(),
            Some(Error::UnsupportedAlgorithm)
        );
        assert_eq!(
            r256.verify(&alg256_salt20, b"hi", &pss256_salt20).err(),
            Some(Error::UnsupportedAlgorithm)
        );
        assert!(r384.verify(&alg256, b"hi", &pss256).is_err());
        assert!(unrestricted.verify(&alg256, b"other", &pss256).is_err());
        assert_eq!(
            unrestricted.verify(&bare, b"hi", &pss256).err(),
            Some(Error::UnsupportedAlgorithm)
        );
        // A key restricted to a *shorter* salt accepts the longer one
        // (RFC 4055 §3.3) but not a shorter-still one.
        let salt20_key = AnyPublicKey::RsaPss(
            key.clone(),
            PssRestriction::Restricted(PssParams {
                hash: PssHash::Sha256,
                mgf1_hash: PssHash::Sha256,
                salt_len: 20,
                trailer_field: 1,
            }),
        );
        salt20_key.verify(&alg256, b"hi", &pss256).unwrap();
        salt20_key
            .verify(&alg256_salt20, b"hi", &pss256_salt20)
            .unwrap();
        let alg256_salt16 = SignatureAlgorithmIdentifier::rsa_pss(PssParams {
            hash: PssHash::Sha256,
            mgf1_hash: PssHash::Sha256,
            salt_len: 16,
            trailer_field: 1,
        });
        assert!(salt20_key.signature_algorithm(&alg256_salt16).is_none());
        // A restriction no registry entry implements (MGF1 over another
        // digest) verifies nothing, and neither does a signature with such
        // parameters.
        let odd_params = PssParams {
            hash: PssHash::Sha256,
            mgf1_hash: PssHash::Sha384,
            salt_len: 32,
            trailer_field: 1,
        };
        let odd = AnyPublicKey::RsaPss(key.clone(), PssRestriction::Restricted(odd_params));
        assert!(odd.signature_algorithm(&alg256).is_none());
        assert!(odd.verify(&alg256, b"hi", &pss256).is_err());
        let odd_alg = SignatureAlgorithmIdentifier::rsa_pss(odd_params);
        assert!(plain.signature_algorithm(&odd_alg).is_none());
        assert!(unrestricted.signature_algorithm(&odd_alg).is_none());
        // The unrestricted `rsaEncryption` form of the same key is not bound.
        let pkcs1_alg = SignatureAlgorithmIdentifier::from_oid(oid::SHA256_WITH_RSA);
        plain.verify(&pkcs1_alg, b"hi", &pkcs1).unwrap();
        plain.verify(&alg256, b"hi", &pss256).unwrap();
        plain.verify(&alg384, b"hi", &pss384).unwrap();
        assert_eq!(
            plain.signature_algorithm(&pkcs1_alg).unwrap().id(),
            "rsa-pkcs1-sha256"
        );
    }

    /// The `key` facade honours the restriction too: PSS with the pinned
    /// digest verifies, PKCS#1 v1.5 padding is an unsupported parameter,
    /// another digest or salt length is invalid, and encryption is refused
    /// (a PSS key is signature-only). Both the direct impl and the boxed
    /// `into_dyn` object behave the same.
    #[cfg(feature = "key")]
    #[test]
    fn rsa_pss_key_facade_enforces_restriction() {
        use crate::key::{Error as KeyError, Hash, PublicKey, SignParams};
        let sk = rsa_test_key_a();
        let mut rng = HmacDrbg::<Sha256>::new(b"spki-pss-facade", b"n", &[]);
        let pss256 = sk.sign_pss::<Sha256, _>(b"hi", &mut rng).unwrap();
        let pss384 = sk.sign_pss::<Sha384, _>(b"hi", &mut rng).unwrap();
        let pkcs1 = sk.sign_pkcs1v15::<Sha256>(b"hi").unwrap();

        let restricted =
            AnyPublicKey::RsaPss(boxed_rsa_a(), PssRestriction::for_hash(PssHash::Sha256));
        let unrestricted = AnyPublicKey::RsaPss(boxed_rsa_a(), PssRestriction::Unrestricted);
        let boxed = restricted.clone().into_dyn();
        let keys: [&dyn PublicKey; 2] = [&restricted, boxed.as_ref()];
        for k in keys {
            assert_eq!(k.algorithm(), crate::key::Algorithm::Rsa);
            k.verify(b"hi", &pss256, &SignParams::new()).unwrap();
            k.verify(
                b"hi",
                &pss256,
                &SignParams::new().pss(crate::key::SaltLen::Fixed(32)),
            )
            .unwrap();
            assert!(matches!(
                k.verify(b"hi", &pkcs1, &SignParams::new().pkcs1v15()),
                Err(KeyError::UnsupportedParam { param: "padding" })
            ));
            assert!(matches!(
                k.verify(b"hi", &pss384, &SignParams::new().hash(Hash::Sha384)),
                Err(KeyError::InvalidParams)
            ));
            assert!(matches!(
                k.verify(
                    b"hi",
                    &pss256,
                    &SignParams::new().pss(crate::key::SaltLen::Fixed(20))
                ),
                Err(KeyError::InvalidParams)
            ));
            assert!(matches!(
                k.encrypt(b"pt", &crate::key::EncryptParams::new(), &mut rng),
                Err(KeyError::Unsupported { .. })
            ));
        }
        // Unrestricted: any PSS digest, still never PKCS#1 v1.5.
        PublicKey::verify(
            &unrestricted,
            b"hi",
            &pss384,
            &SignParams::new().hash(Hash::Sha384),
        )
        .unwrap();
        assert!(matches!(
            PublicKey::verify(&unrestricted, b"hi", &pkcs1, &SignParams::new().pkcs1v15()),
            Err(KeyError::UnsupportedParam { param: "padding" })
        ));
    }
}
