//! JSON Web Encryption (RFC 7516): decryption of the compact, flattened
//! JSON and general JSON serializations, and compact encryption.

use super::json::{self, Object, Value};
use super::{Enc, Error, Jwk, JwkKey, JwkSet, KeyAlg, OkpCurve, base64url, cbc_hmac};
use crate::cipher::{Aes128, Aes192, Aes256, AesKw, Gcm};
use crate::ec::{BoxedEcdsaPrivateKey, X448PrivateKey, X25519PrivateKey};
use crate::hash::{Sha1, Sha256, Sha384, Sha512};
use crate::kdf::{concat_kdf, try_pbkdf2};
use crate::rng::{CryptoRng, RngCore};
use crate::zeroize::{Zeroize, Zeroizing};
use alloc::string::String;
use alloc::vec::Vec;

/// Upper bound accepted for the PBES2 `p2c` iteration count when
/// decrypting (a header-controlled work factor is a denial-of-service
/// lever).
pub const MAX_PBES2_ITERATIONS: u64 = 1_000_000;

/// PBES2 iteration count used when encrypting (unless the caller sets
/// `p2c` in the extra header parameters).
const DEFAULT_PBES2_ITERATIONS: u64 = 100_000;

/// Cap on the inflated size of a `zip: DEF` plaintext.
#[cfg(feature = "cert-compression")]
const MAX_INFLATED: u64 = 1 << 24;

/// Header parameter names registered for JWE (RFC 7516 §4.1, RFC 7518
/// §4.6.1 / §4.7.1 / §4.8.1) — these may never appear in `crit`.
const REGISTERED_HEADERS: [&str; 20] = [
    "alg", "enc", "zip", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty",
    "crit", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c",
];

/// Key operations that permit decryption / unwrapping with a key that has
/// `key_ops`.
const DECRYPT_OPS: [&str; 4] = ["decrypt", "unwrapKey", "deriveKey", "deriveBits"];
const ENCRYPT_OPS: [&str; 4] = ["encrypt", "wrapKey", "deriveKey", "deriveBits"];

/// One recipient of a JWE: its per-recipient header and encrypted key.
#[derive(Clone, Debug)]
pub struct JweRecipient {
    header: Option<Object>,
    encrypted_key: Vec<u8>,
}

impl JweRecipient {
    /// The per-recipient unprotected header, if any.
    pub fn header(&self) -> Option<&Object> {
        self.header.as_ref()
    }

    /// The encrypted (wrapped) content encryption key; empty for `dir`
    /// and `ECDH-ES`.
    pub fn encrypted_key(&self) -> &[u8] {
        &self.encrypted_key
    }
}

/// A parsed JWE.
#[derive(Clone, Debug)]
pub struct Jwe {
    protected_b64: String,
    protected: Object,
    unprotected: Option<Object>,
    recipients: Vec<JweRecipient>,
    aad_b64: Option<String>,
    iv: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
}

impl Jwe {
    /// Parses either serialization: JSON when the text starts with `{`,
    /// compact otherwise.
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.trim_start().starts_with('{') {
            Self::parse_json(text)
        } else {
            Self::parse_compact(text)
        }
    }

    /// Parses the compact serialization
    /// `header.encrypted_key.iv.ciphertext.tag`.
    pub fn parse_compact(text: &str) -> Result<Self, Error> {
        let parts: Vec<&str> = text.split('.').collect();
        let [h, ek, iv, ct, tag] = parts[..] else {
            return Err(Error::Malformed);
        };
        let protected = json::parse_object_bytes(&base64url::decode(h)?)?;
        let jwe = Jwe {
            protected_b64: String::from(h),
            protected,
            unprotected: None,
            recipients: alloc::vec![JweRecipient {
                header: None,
                encrypted_key: base64url::decode(ek)?,
            }],
            aad_b64: None,
            iv: base64url::decode(iv)?,
            ciphertext: base64url::decode(ct)?,
            tag: base64url::decode(tag)?,
        };
        jwe.check_headers()?;
        Ok(jwe)
    }

    /// Parses the flattened or general JSON serialization (RFC 7516 §7.2).
    /// The `protected` header is required and must carry `enc` (and `zip`
    /// when used): the content-encryption parameters must be integrity
    /// protected.
    pub fn parse_json(text: &str) -> Result<Self, Error> {
        let obj = json::parse_object(text)?;
        let protected_b64 = obj.require_str("protected")?;
        let protected = json::parse_object_bytes(&base64url::decode(protected_b64)?)?;
        let unprotected = obj.get_object("unprotected")?.cloned();
        let one = |o: &Object| -> Result<JweRecipient, Error> {
            Ok(JweRecipient {
                header: o.get_object("header")?.cloned(),
                encrypted_key: match o.get_str("encrypted_key")? {
                    Some(s) => base64url::decode(s)?,
                    None => Vec::new(),
                },
            })
        };
        let recipients = match obj.get_array("recipients")? {
            Some(list) => {
                if obj.contains("header") || obj.contains("encrypted_key") {
                    return Err(Error::Malformed);
                }
                if list.is_empty() {
                    return Err(Error::Malformed);
                }
                let mut rs = Vec::with_capacity(list.len());
                for item in list {
                    rs.push(one(item.as_object().ok_or(Error::Malformed)?)?);
                }
                rs
            }
            None => alloc::vec![one(&obj)?],
        };
        let aad_b64 = obj.get_str("aad")?.map(String::from);
        if let Some(aad) = &aad_b64 {
            base64url::decode(aad)?;
        }
        let jwe = Jwe {
            protected_b64: String::from(protected_b64),
            protected,
            unprotected,
            recipients,
            aad_b64,
            iv: base64url::decode(obj.require_str("iv")?)?,
            ciphertext: base64url::decode(obj.require_str("ciphertext")?)?,
            tag: base64url::decode(obj.require_str("tag")?)?,
        };
        jwe.check_headers()?;
        Ok(jwe)
    }

    /// Structural header validation for every recipient: disjoint header
    /// locations, `enc` protected, well-formed `crit` (and, as no
    /// extension is understood, absent), `zip` protected and known.
    fn check_headers(&self) -> Result<(), Error> {
        self.protected.require_str("enc")?;
        if let Some(u) = &self.unprotected
            && (u.contains("enc") || u.contains("zip"))
        {
            return Err(Error::Malformed);
        }
        if let Some(zip) = self.protected.get_str("zip")?
            && zip != "DEF"
        {
            return Err(Error::UnsupportedAlgorithm);
        }
        for r in &self.recipients {
            if let Some(h) = &r.header
                && (h.contains("enc") || h.contains("zip"))
            {
                return Err(Error::Malformed);
            }
            let merged = self.merged_header(r)?;
            merged.require_str("alg")?;
            merged.get_str("kid")?;
            if let Some(crit) = merged.get_array("crit")? {
                if crit.is_empty() {
                    return Err(Error::Malformed);
                }
                for item in crit {
                    let name = item.as_str().ok_or(Error::Malformed)?;
                    if REGISTERED_HEADERS.contains(&name) || !merged.contains(name) {
                        return Err(Error::Malformed);
                    }
                }
                return Err(Error::CriticalHeader);
            }
        }
        Ok(())
    }

    /// The union of the protected, shared unprotected and per-recipient
    /// headers, which must be disjoint.
    fn merged_header(&self, r: &JweRecipient) -> Result<Object, Error> {
        let mut merged = self.protected.clone();
        for extra in [self.unprotected.as_ref(), r.header.as_ref()]
            .into_iter()
            .flatten()
        {
            for (name, value) in extra.iter() {
                merged.insert(name, value.clone())?;
            }
        }
        Ok(merged)
    }

    /// The protected header.
    pub fn protected(&self) -> &Object {
        &self.protected
    }

    /// The shared unprotected header, if any.
    pub fn unprotected(&self) -> Option<&Object> {
        self.unprotected.as_ref()
    }

    /// The recipients (one for the compact and flattened serializations).
    pub fn recipients(&self) -> &[JweRecipient] {
        &self.recipients
    }

    /// The content encryption algorithm from the protected header.
    pub fn enc(&self) -> Result<Enc, Error> {
        Enc::from_name(self.protected.require_str("enc")?).ok_or(Error::UnsupportedAlgorithm)
    }

    /// The `alg` of recipient `index` (from its complete header).
    pub fn alg(&self, index: usize) -> Result<KeyAlg, Error> {
        let r = self.recipients.get(index).ok_or(Error::Malformed)?;
        let h = self.merged_header(r)?;
        KeyAlg::from_name(h.require_str("alg")?).ok_or(Error::UnsupportedAlgorithm)
    }

    /// The `kid` of recipient `index` (from its complete header).
    pub fn kid(&self, index: usize) -> Option<String> {
        let r = self.recipients.get(index)?;
        let h = self.merged_header(r).ok()?;
        h.get_str("kid").ok().flatten().map(String::from)
    }

    /// Decrypts with `key` and returns the plaintext. Every recipient is
    /// tried in turn; the key's `alg`, `use` and `key_ops` must permit the
    /// recipient's algorithm.
    pub fn decrypt(&self, key: &Jwk) -> Result<Vec<u8>, Error> {
        let mut last = Error::Decryption;
        for r in &self.recipients {
            match self.decrypt_recipient(r, key) {
                Ok(pt) => return Ok(pt),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Decrypts with the key from `keys` selected by each recipient's
    /// `kid` (or, without one, the single key fitting the algorithm).
    pub fn decrypt_with_set(&self, keys: &JwkSet) -> Result<Vec<u8>, Error> {
        let mut last = Error::Decryption;
        for r in &self.recipients {
            let attempt = (|| {
                let header = self.merged_header(r)?;
                let enc = self.enc()?;
                let alg = KeyAlg::from_name(header.require_str("alg")?)
                    .ok_or(Error::UnsupportedAlgorithm)?;
                let key = keys.select(header.get_str("kid")?, |k| {
                    check_key(k, alg, enc, &DECRYPT_OPS).is_ok()
                })?;
                self.decrypt_recipient(r, key)
            })();
            match attempt {
                Ok(pt) => return Ok(pt),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    fn decrypt_recipient(&self, r: &JweRecipient, key: &Jwk) -> Result<Vec<u8>, Error> {
        let header = self.merged_header(r)?;
        let enc = self.enc()?;
        let alg =
            KeyAlg::from_name(header.require_str("alg")?).ok_or(Error::UnsupportedAlgorithm)?;
        check_key(key, alg, enc, &DECRYPT_OPS)?;
        let zip = self.protected.get_str("zip")?.is_some();
        #[cfg(not(feature = "cert-compression"))]
        if zip {
            return Err(Error::Unsupported("zip"));
        }
        let cek = unwrap_cek(alg, enc, key, &header, &r.encrypted_key)?;
        let aad = self.aad();
        let pt = content_decrypt(enc, &cek, &self.iv, &aad, &self.ciphertext, &self.tag)?;
        if zip {
            return inflate(&pt);
        }
        Ok(pt)
    }

    /// The AEAD additional data: the protected header as transmitted,
    /// plus `.` and the JSON `aad` member when present.
    fn aad(&self) -> Vec<u8> {
        let mut aad = Vec::from(self.protected_b64.as_bytes());
        if let Some(extra) = &self.aad_b64 {
            aad.push(b'.');
            aad.extend_from_slice(extra.as_bytes());
        }
        aad
    }

    /// Encrypts `plaintext` for `key` with key management `alg` and content
    /// encryption `enc`, returning the compact serialization. The
    /// protected header is `{"alg", "enc", "kid"?}` plus whatever the
    /// algorithm needs (`epk`, `iv`/`tag`, `p2s`/`p2c`).
    pub fn encrypt_compact<R: RngCore + CryptoRng>(
        key: &Jwk,
        alg: KeyAlg,
        enc: Enc,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<String, Error> {
        Self::encrypt_compact_with_header(key, alg, enc, &Object::new(), plaintext, rng)
    }

    /// [`encrypt_compact`](Self::encrypt_compact) with additional protected
    /// header parameters. `extra` may set `p2c` (PBES2 iteration count),
    /// `apu` / `apv` (base64url, ECDH-ES party info), `zip: "DEF"` (with
    /// the `cert-compression` feature) and any application parameter; it
    /// must not contain the parameters this function generates.
    pub fn encrypt_compact_with_header<R: RngCore + CryptoRng>(
        key: &Jwk,
        alg: KeyAlg,
        enc: Enc,
        extra: &Object,
        plaintext: &[u8],
        rng: &mut R,
    ) -> Result<String, Error> {
        let mut cek = Zeroizing::new(alloc::vec![0u8; enc.key_len()]);
        rng.fill_bytes(&mut cek);
        let mut iv = alloc::vec![0u8; enc.iv_len()];
        rng.fill_bytes(&mut iv);
        encrypt_inner(key, alg, enc, extra, plaintext, &mut cek, &iv, rng)
    }
}

/// Checks that `key` may serve `alg` / `enc` for the operations `ops`.
fn check_key(key: &Jwk, alg: KeyAlg, enc: Enc, ops: &[&str]) -> Result<(), Error> {
    let dir_enc = if alg == KeyAlg::Dir {
        Some(enc.name())
    } else {
        None
    };
    key.check_usable(alg.name(), dir_enc, alg.family(), false, ops)
}

fn aes_kw_unwrap(kek: &[u8], wrapped: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if wrapped.len() < 8 {
        return Err(Error::Decryption);
    }
    let mut out = Zeroizing::new(alloc::vec![0u8; wrapped.len() - 8]);
    let res = match kek.len() {
        16 => AesKw::new(Aes128::new(kek.try_into().expect("16"))).unwrap(wrapped, &mut out),
        24 => AesKw::new(Aes192::new(kek.try_into().expect("24"))).unwrap(wrapped, &mut out),
        32 => AesKw::new(Aes256::new(kek.try_into().expect("32"))).unwrap(wrapped, &mut out),
        _ => return Err(Error::KeyMismatch),
    };
    res.map_err(|_| Error::Decryption)?;
    Ok(out)
}

fn aes_kw_wrap(kek: &[u8], plain: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = alloc::vec![0u8; plain.len() + 8];
    let res = match kek.len() {
        16 => AesKw::new(Aes128::new(kek.try_into().expect("16"))).wrap(plain, &mut out),
        24 => AesKw::new(Aes192::new(kek.try_into().expect("24"))).wrap(plain, &mut out),
        32 => AesKw::new(Aes256::new(kek.try_into().expect("32"))).wrap(plain, &mut out),
        _ => return Err(Error::KeyMismatch),
    };
    res.map_err(|_| Error::InvalidKey)?;
    Ok(out)
}

/// AES-GCM over `buf` in place with a `key.len()`-selected variant.
/// `tag` is verified when decrypting and returned when encrypting.
fn aes_gcm(
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    buf: &mut [u8],
    tag: Option<&[u8; 16]>,
) -> Result<[u8; 16], Error> {
    macro_rules! run {
        ($cipher:ty) => {{
            let gcm = Gcm::new(<$cipher>::new(key.try_into().expect("key length")));
            match tag {
                Some(t) => gcm
                    .try_decrypt(nonce, aad, buf, t)
                    .map(|()| *t)
                    .map_err(|_| Error::Decryption),
                None => gcm
                    .try_encrypt(nonce, aad, buf)
                    .map_err(|_| Error::Malformed),
            }
        }};
    }
    match key.len() {
        16 => run!(Aes128),
        24 => run!(Aes192),
        32 => run!(Aes256),
        _ => Err(Error::KeyMismatch),
    }
}

fn header_b64(header: &Object, name: &str) -> Result<Vec<u8>, Error> {
    base64url::decode(header.require_str(name)?)
}

/// PBES2 KEK derivation (RFC 7518 §4.8): PBKDF2 over
/// `UTF8(alg) ‖ 0x00 ‖ p2s` with the algorithm's HMAC and key size.
fn pbes2_kek(
    alg: KeyAlg,
    password: &[u8],
    p2s: &[u8],
    p2c: u64,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if p2s.len() < 8 || p2c == 0 || p2c > MAX_PBES2_ITERATIONS {
        return Err(Error::Malformed);
    }
    let klen = alg.wrap_key_len().ok_or(Error::UnsupportedAlgorithm)?;
    let mut salt = Vec::from(alg.name().as_bytes());
    salt.push(0);
    salt.extend_from_slice(p2s);
    let mut kek = Zeroizing::new(alloc::vec![0u8; klen]);
    let iters = p2c as u32;
    let res = match alg {
        KeyAlg::Pbes2Hs256A128KW => try_pbkdf2::<Sha256>(password, &salt, iters, &mut kek),
        KeyAlg::Pbes2Hs384A192KW => try_pbkdf2::<Sha384>(password, &salt, iters, &mut kek),
        KeyAlg::Pbes2Hs512A256KW => try_pbkdf2::<Sha512>(password, &salt, iters, &mut kek),
        _ => return Err(Error::UnsupportedAlgorithm),
    };
    res.map_err(|_| Error::Malformed)?;
    Ok(kek)
}

/// The ECDH shared secret `Z` between our private `key` and the peer's
/// public `epk`, which must be on the same curve.
fn ecdh_z(key: &Jwk, epk: &Jwk) -> Result<Zeroizing<Vec<u8>>, Error> {
    match (key.key(), epk.key()) {
        (JwkKey::Ec { crv, .. }, JwkKey::Ec { crv: peer, .. }) => {
            if crv != peer {
                return Err(Error::Decryption);
            }
            let sk = key.ecdh_private_key()?;
            let pk = epk.ec_public_key()?;
            Ok(Zeroizing::new(
                sk.diffie_hellman(&pk).map_err(|_| Error::Decryption)?,
            ))
        }
        (JwkKey::Okp { crv, .. }, JwkKey::Okp { crv: peer, .. }) => {
            if crv != peer {
                return Err(Error::Decryption);
            }
            match crv {
                OkpCurve::X25519 => {
                    let z = key
                        .x25519_private_key()?
                        .diffie_hellman(epk.x25519_public_key()?.as_bytes())
                        .map_err(|_| Error::Decryption)?;
                    let out = Zeroizing::new(z.to_vec());
                    let mut z = z;
                    z.zeroize();
                    Ok(out)
                }
                OkpCurve::X448 => {
                    let z = key
                        .x448_private_key()?
                        .diffie_hellman(epk.x448_public_key()?.as_bytes())
                        .map_err(|_| Error::Decryption)?;
                    let out = Zeroizing::new(z.to_vec());
                    let mut z = z;
                    z.zeroize();
                    Ok(out)
                }
                _ => Err(Error::KeyMismatch),
            }
        }
        _ => Err(Error::KeyMismatch),
    }
}

/// The ECDH-ES derived key (RFC 7518 §4.6.2): Concat KDF with SHA-256
/// over `Z` and `AlgorithmID ‖ PartyUInfo ‖ PartyVInfo ‖ SuppPubInfo`.
fn ecdh_es_derive(
    alg: KeyAlg,
    enc: Enc,
    z: &[u8],
    header: &Object,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (alg_id, klen) = match alg {
        KeyAlg::EcdhEs => (enc.name(), enc.key_len()),
        _ => (
            alg.name(),
            alg.wrap_key_len().ok_or(Error::UnsupportedAlgorithm)?,
        ),
    };
    let apu = match header.get_str("apu")? {
        Some(s) => base64url::decode(s)?,
        None => Vec::new(),
    };
    let apv = match header.get_str("apv")? {
        Some(s) => base64url::decode(s)?,
        None => Vec::new(),
    };
    let mut out = Zeroizing::new(alloc::vec![0u8; klen]);
    concat_kdf::<Sha256>(
        z,
        &[
            &(alg_id.len() as u32).to_be_bytes(),
            alg_id.as_bytes(),
            &(apu.len() as u32).to_be_bytes(),
            &apu,
            &(apv.len() as u32).to_be_bytes(),
            &apv,
            &((klen as u32) * 8).to_be_bytes(),
        ],
        &mut out,
    )
    .map_err(|_| Error::Malformed)?;
    Ok(out)
}

/// The `epk` header parameter parsed as a public JWK.
fn header_epk(header: &Object) -> Result<Jwk, Error> {
    let epk = header.get_object("epk")?.ok_or(Error::Malformed)?;
    let jwk = Jwk::from_object(epk)?;
    if jwk.is_private() {
        // A private ephemeral key in the header is nonsense; refuse it.
        return Err(Error::Malformed);
    }
    Ok(jwk)
}

/// Recovers the content encryption key for one recipient. Failures that
/// depend on secret material are all [`Error::Decryption`]; for `RSA1_5`
/// a padding failure yields a pseudo-random CEK instead, so that the
/// content authentication tag is what fails.
fn unwrap_cek(
    alg: KeyAlg,
    enc: Enc,
    key: &Jwk,
    header: &Object,
    encrypted_key: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let klen = enc.key_len();
    let cek = match alg {
        KeyAlg::Dir => {
            if !encrypted_key.is_empty() {
                return Err(Error::Malformed);
            }
            Zeroizing::new(key.oct_bytes()?.to_vec())
        }
        KeyAlg::A128KW | KeyAlg::A192KW | KeyAlg::A256KW => {
            aes_kw_unwrap(key.oct_bytes()?, encrypted_key)?
        }
        KeyAlg::A128GCMKW | KeyAlg::A192GCMKW | KeyAlg::A256GCMKW => {
            let iv = header_b64(header, "iv")?;
            let tag = header_b64(header, "tag")?;
            if iv.len() != 12 || tag.len() != 16 {
                return Err(Error::Malformed);
            }
            let tag: [u8; 16] = tag.try_into().expect("16");
            let mut buf = Zeroizing::new(encrypted_key.to_vec());
            aes_gcm(key.oct_bytes()?, &iv, b"", &mut buf, Some(&tag))?;
            buf
        }
        KeyAlg::RSA1_5 => {
            let sk = key.rsa_private_key()?;
            // Implicit rejection: a bad padding yields a pseudo-random CEK
            // of the right length; only a ciphertext of the wrong length
            // (public information) is an error.
            Zeroizing::new(
                sk.decrypt_pkcs1v15_session(encrypted_key, klen)
                    .map_err(|_| Error::Decryption)?,
            )
        }
        KeyAlg::RsaOaep => Zeroizing::new(
            key.rsa_private_key()?
                .decrypt_oaep::<Sha1>(encrypted_key, b"")
                .map_err(|_| Error::Decryption)?,
        ),
        KeyAlg::RsaOaep256 => Zeroizing::new(
            key.rsa_private_key()?
                .decrypt_oaep::<Sha256>(encrypted_key, b"")
                .map_err(|_| Error::Decryption)?,
        ),
        KeyAlg::EcdhEs | KeyAlg::EcdhEsA128KW | KeyAlg::EcdhEsA192KW | KeyAlg::EcdhEsA256KW => {
            let epk = header_epk(header)?;
            let z = ecdh_z(key, &epk)?;
            let derived = ecdh_es_derive(alg, enc, &z, header)?;
            if alg == KeyAlg::EcdhEs {
                if !encrypted_key.is_empty() {
                    return Err(Error::Malformed);
                }
                derived
            } else {
                aes_kw_unwrap(&derived, encrypted_key)?
            }
        }
        KeyAlg::Pbes2Hs256A128KW | KeyAlg::Pbes2Hs384A192KW | KeyAlg::Pbes2Hs512A256KW => {
            let p2s = header_b64(header, "p2s")?;
            let p2c = match header.get("p2c") {
                Some(Value::Number(n)) => n.as_u64().ok_or(Error::Malformed)?,
                _ => return Err(Error::Malformed),
            };
            let kek = pbes2_kek(alg, key.oct_bytes()?, &p2s, p2c)?;
            aes_kw_unwrap(&kek, encrypted_key)?
        }
    };
    if cek.len() != klen {
        return Err(Error::Decryption);
    }
    Ok(cek)
}

fn content_decrypt(
    enc: Enc,
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, Error> {
    if iv.len() != enc.iv_len() || tag.len() != enc.tag_len() {
        return Err(Error::Decryption);
    }
    if enc.is_gcm() {
        let tag: [u8; 16] = tag.try_into().expect("16");
        let mut buf = ciphertext.to_vec();
        aes_gcm(cek, iv, aad, &mut buf, Some(&tag))?;
        Ok(buf)
    } else {
        let iv: &[u8; 16] = iv.try_into().expect("16");
        cbc_hmac::decrypt(enc, cek, iv, aad, ciphertext, tag).map_err(|()| Error::Decryption)
    }
}

fn content_encrypt(
    enc: Enc,
    cek: &[u8],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, Vec<u8>) {
    if enc.is_gcm() {
        let mut buf = plaintext.to_vec();
        let tag = aes_gcm(cek, iv, aad, &mut buf, None).expect("valid GCM parameters");
        (buf, tag.to_vec())
    } else {
        let iv: &[u8; 16] = iv.try_into().expect("16");
        cbc_hmac::encrypt(enc, cek, iv, aad, plaintext)
    }
}

#[cfg(feature = "cert-compression")]
fn inflate(data: &[u8]) -> Result<Vec<u8>, Error> {
    compcol::vec::decompress_to_vec_capped::<compcol::deflate::Deflate>(data, MAX_INFLATED)
        .map_err(|_| Error::Decryption)
}

#[cfg(not(feature = "cert-compression"))]
fn inflate(_data: &[u8]) -> Result<Vec<u8>, Error> {
    Err(Error::Unsupported("zip"))
}

#[cfg(feature = "cert-compression")]
fn deflate(data: &[u8]) -> Result<Vec<u8>, Error> {
    compcol::vec::compress_to_vec::<compcol::deflate::Deflate>(data).map_err(|_| Error::Malformed)
}

#[cfg(not(feature = "cert-compression"))]
fn deflate(_data: &[u8]) -> Result<Vec<u8>, Error> {
    Err(Error::Unsupported("zip"))
}

/// Encryption with caller-supplied CEK and IV (tests pin the RFC values
/// through this). For `dir` and `ECDH-ES` the CEK is replaced by the key
/// / derived key.
#[allow(clippy::too_many_arguments)]
pub(crate) fn encrypt_inner<R: RngCore + CryptoRng>(
    key: &Jwk,
    alg: KeyAlg,
    enc: Enc,
    extra: &Object,
    plaintext: &[u8],
    cek: &mut Zeroizing<Vec<u8>>,
    iv: &[u8],
    rng: &mut R,
) -> Result<String, Error> {
    check_key(key, alg, enc, &ENCRYPT_OPS)?;
    if cek.len() != enc.key_len() || iv.len() != enc.iv_len() {
        return Err(Error::Malformed);
    }
    let mut header = Object::new();
    header.insert_str("alg", alg.name())?;
    header.insert_str("enc", enc.name())?;
    if let Some(kid) = key.kid() {
        header.insert_str("kid", kid)?;
    }
    let mut zip = false;
    let mut p2c = DEFAULT_PBES2_ITERATIONS;
    for (name, value) in extra.iter() {
        match name {
            "crit" => return Err(Error::Unsupported("crit")),
            "zip" => {
                if value.as_str() != Some("DEF") {
                    return Err(Error::UnsupportedAlgorithm);
                }
                zip = true;
            }
            "p2c" => {
                let Value::Number(n) = value else {
                    return Err(Error::Malformed);
                };
                p2c = n.as_u64().ok_or(Error::Malformed)?;
                continue;
            }
            "apu" | "apv" => {
                base64url::decode(value.as_str().ok_or(Error::Malformed)?)?;
            }
            _ => {}
        }
        header.insert(name, value.clone())?;
    }

    let encrypted_key: Vec<u8> = match alg {
        KeyAlg::Dir => {
            let k = key.oct_bytes()?;
            cek.copy_from_slice(k);
            Vec::new()
        }
        KeyAlg::A128KW | KeyAlg::A192KW | KeyAlg::A256KW => aes_kw_wrap(key.oct_bytes()?, cek)?,
        KeyAlg::A128GCMKW | KeyAlg::A192GCMKW | KeyAlg::A256GCMKW => {
            let mut nonce = [0u8; 12];
            rng.fill_bytes(&mut nonce);
            let mut buf = cek.to_vec();
            let tag = aes_gcm(key.oct_bytes()?, &nonce, b"", &mut buf, None)?;
            header.insert_str("iv", &base64url::encode(&nonce))?;
            header.insert_str("tag", &base64url::encode(&tag))?;
            buf
        }
        KeyAlg::RSA1_5 => key
            .rsa_public_key()?
            .encrypt_pkcs1v15(cek, rng)
            .map_err(|_| Error::InvalidKey)?,
        KeyAlg::RsaOaep => key
            .rsa_public_key()?
            .encrypt_oaep::<Sha1, R>(cek, b"", rng)
            .map_err(|_| Error::InvalidKey)?,
        KeyAlg::RsaOaep256 => key
            .rsa_public_key()?
            .encrypt_oaep::<Sha256, R>(cek, b"", rng)
            .map_err(|_| Error::InvalidKey)?,
        KeyAlg::EcdhEs | KeyAlg::EcdhEsA128KW | KeyAlg::EcdhEsA192KW | KeyAlg::EcdhEsA256KW => {
            // Ephemeral key on the recipient's curve.
            let (eph_private, eph_public): (Jwk, Jwk) = match key.key() {
                JwkKey::Ec { crv, .. } => {
                    let sk = BoxedEcdsaPrivateKey::generate(crv.curve_id(), rng);
                    let eph = Jwk::from_ec_private(&sk)?;
                    let public = eph.to_public().expect("asymmetric");
                    (eph, public)
                }
                JwkKey::Okp {
                    crv: OkpCurve::X25519,
                    ..
                } => {
                    let sk = X25519PrivateKey::generate(rng);
                    (
                        Jwk::from_x25519_private(&sk),
                        Jwk::from_x25519_private(&sk)
                            .to_public()
                            .expect("asymmetric"),
                    )
                }
                JwkKey::Okp {
                    crv: OkpCurve::X448,
                    ..
                } => {
                    let sk = X448PrivateKey::generate(rng);
                    (
                        Jwk::from_x448_private(&sk),
                        Jwk::from_x448_private(&sk).to_public().expect("asymmetric"),
                    )
                }
                _ => return Err(Error::KeyMismatch),
            };
            let recipient_public = key.to_public().ok_or(Error::KeyMismatch)?;
            let z = ecdh_z(&eph_private, &recipient_public)?;
            header.insert("epk", Value::Object(eph_public.to_object()))?;
            let derived = ecdh_es_derive(alg, enc, &z, &header)?;
            if alg == KeyAlg::EcdhEs {
                cek.copy_from_slice(&derived);
                Vec::new()
            } else {
                aes_kw_wrap(&derived, cek)?
            }
        }
        KeyAlg::Pbes2Hs256A128KW | KeyAlg::Pbes2Hs384A192KW | KeyAlg::Pbes2Hs512A256KW => {
            let mut p2s = [0u8; 16];
            rng.fill_bytes(&mut p2s);
            header.insert_str("p2s", &base64url::encode(&p2s))?;
            header.insert("p2c", Value::Number(json::Number::from_u64(p2c)))?;
            let kek = pbes2_kek(alg, key.oct_bytes()?, &p2s, p2c)?;
            aes_kw_wrap(&kek, cek)?
        }
    };

    let body: Vec<u8> = if zip {
        deflate(plaintext)?
    } else {
        plaintext.to_vec()
    };
    let protected_b64 = base64url::encode(header.to_json().as_bytes());
    let (ciphertext, tag) = content_encrypt(enc, cek, iv, protected_b64.as_bytes(), &body);
    let mut out = protected_b64;
    out.push('.');
    out.push_str(&base64url::encode(&encrypted_key));
    out.push('.');
    out.push_str(&base64url::encode(iv));
    out.push('.');
    out.push_str(&base64url::encode(&ciphertext));
    out.push('.');
    out.push_str(&base64url::encode(&tag));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn rng() -> HmacDrbg<Sha256> {
        HmacDrbg::new(b"jose jwe tests", b"nonce", b"")
    }

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 7516 Appendix A.1 key.
    const A1_KEY: &str = r#"{"kty":"RSA",
      "n":"oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
      "e":"AQAB",
      "d":"kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
      "p":"1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
      "q":"wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
      "dp":"ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
      "dq":"Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
      "qi":"VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
     }"#;

    const A1_JWE: &str = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ";
    const A1_PT: &[u8] = b"The true sign of intelligence is not knowledge but imagination.";

    /// RFC 7516 Appendix A.2 key.
    const A2_KEY: &str = r#"{"kty":"RSA",
      "n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
      "e":"AQAB",
      "d":"VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
      "p":"9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
      "q":"uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
      "dp":"w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
      "dq":"o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
      "qi":"eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"
     }"#;

    const A2_EK: &str = "UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A";
    const A2_PT: &[u8] = b"Live long and prosper.";
    const A3_KEY: &str = r#"{"kty":"oct","k":"GawgguFyGrWKav7AX4VKUg"}"#;
    const A3_JWE: &str = "eyJhbGciOiJBMTI4S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.U0m_YmjN04DJvceFICbCVQ";
    const A3_CEK: [u8; 32] = [
        4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212,
        45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207,
    ];
    const A3_IV: [u8; 16] = [
        3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101,
    ];

    /// RFC 7516 Appendix A.1 — RSA-OAEP + A256GCM.
    #[test]
    fn rfc7516_a1_rsa_oaep_a256gcm() {
        let key = Jwk::parse(A1_KEY).unwrap();
        let jwe = Jwe::parse(A1_JWE).unwrap();
        assert_eq!(jwe.enc().unwrap(), Enc::A256Gcm);
        assert_eq!(jwe.alg(0).unwrap(), KeyAlg::RsaOaep);
        assert_eq!(jwe.decrypt(&key).unwrap(), A1_PT);
        // Key pinned to another algorithm: refused before any decryption.
        let pinned = key.clone().with_alg("RSA-OAEP-256").unwrap();
        assert_eq!(jwe.decrypt(&pinned).unwrap_err(), Error::KeyMismatch);
        let pinned = key.clone().with_use("sig").unwrap();
        assert_eq!(jwe.decrypt(&pinned).unwrap_err(), Error::KeyMismatch);
        // Public key cannot decrypt.
        assert!(jwe.decrypt(&key.to_public().unwrap()).is_err());
        // Tampering anywhere is Decryption.
        for (from, to) in [
            ("48V1_ALb6US04U3b", "48V1_ALb6US04U3c"),
            ("XFBoMYUZodetZdvTiFvSkQ", "XFBoMYUZodetZdvTiFvSlQ"),
            ("5eym8TW", "5eym8TX"),
            ("OKOawDo", "OKOawDp"),
        ] {
            let t = A1_JWE.replace(from, to);
            assert_eq!(
                Jwe::parse(&t).unwrap().decrypt(&key).unwrap_err(),
                Error::Decryption,
                "{from}"
            );
        }
        // Encrypt round trips (OAEP and OAEP-256).
        for alg in [KeyAlg::RsaOaep, KeyAlg::RsaOaep256] {
            let text = Jwe::encrypt_compact(
                &key.to_public().unwrap(),
                alg,
                Enc::A256Gcm,
                A1_PT,
                &mut rng(),
            )
            .unwrap();
            assert_eq!(Jwe::parse(&text).unwrap().decrypt(&key).unwrap(), A1_PT);
        }
    }

    /// RFC 7516 Appendix A.2 — RSA1_5 + A128CBC-HS256.
    #[test]
    fn rfc7516_a2_rsa1_5_a128cbc_hs256() {
        let text = alloc::format!(
            "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.{A2_EK}.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw"
        );
        let jwe = Jwe::parse(&text).unwrap();
        let bare = Jwk::parse(A2_KEY).unwrap();
        // RSA1_5 requires an explicit opt-in on the key.
        assert_eq!(jwe.decrypt(&bare).unwrap_err(), Error::KeyMismatch);
        let key = bare.with_alg("RSA1_5").unwrap();
        assert_eq!(jwe.decrypt(&key).unwrap(), A2_PT);
        // A padding failure and a wrong key both end in the same error.
        let bad_ek = text.replace("UGhIOguC7IuEvf", "UGhIOguC7IuEvg");
        assert_eq!(
            Jwe::parse(&bad_ek).unwrap().decrypt(&key).unwrap_err(),
            Error::Decryption
        );
        let bad_tag = text.replace("9hH0vgRfYgPnAHOd8stkvw", "9hH0vgRfYgPnAHOd8stkww");
        assert_eq!(
            Jwe::parse(&bad_tag).unwrap().decrypt(&key).unwrap_err(),
            Error::Decryption
        );
        let other = Jwk::parse(A1_KEY).unwrap().with_alg("RSA1_5").unwrap();
        assert_eq!(jwe.decrypt(&other).unwrap_err(), Error::Decryption);
        // Encrypt round trip.
        let sent = Jwe::encrypt_compact(&key, KeyAlg::RSA1_5, Enc::A128CbcHs256, A2_PT, &mut rng())
            .unwrap();
        assert_eq!(Jwe::parse(&sent).unwrap().decrypt(&key).unwrap(), A2_PT);
    }

    /// RFC 7516 Appendix A.3 — A128KW + A128CBC-HS256 (fully deterministic
    /// given the CEK and IV, so encryption must reproduce it exactly).
    #[test]
    fn rfc7516_a3_a128kw_a128cbc_hs256() {
        let key = Jwk::parse(A3_KEY).unwrap();
        let jwe = Jwe::parse(A3_JWE).unwrap();
        assert_eq!(jwe.decrypt(&key).unwrap(), A2_PT);
        let mut cek = Zeroizing::new(A3_CEK.to_vec());
        let text = encrypt_inner(
            &key,
            KeyAlg::A128KW,
            Enc::A128CbcHs256,
            &Object::new(),
            A2_PT,
            &mut cek,
            &A3_IV,
            &mut rng(),
        )
        .unwrap();
        assert_eq!(text, A3_JWE);
        // Wrong key length for the wrap algorithm.
        let short = Jwk::oct(&[1u8; 24]);
        assert_eq!(jwe.decrypt(&short).unwrap_err(), Error::InvalidKey);
        // Key pinned to another wrap algorithm.
        let gcmkw = Jwk::oct(key.oct_bytes().unwrap())
            .with_alg("A128GCMKW")
            .unwrap();
        assert_eq!(jwe.decrypt(&gcmkw).unwrap_err(), Error::KeyMismatch);
        // Truncated tag, modified ciphertext.
        let t = A3_JWE.replace("U0m_YmjN04DJvceFICbCVQ", "U0m_YmjN04DJvceFICbC");
        assert_eq!(
            Jwe::parse(&t).unwrap().decrypt(&key).unwrap_err(),
            Error::Decryption
        );
        let t = A3_JWE.replace(
            "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
            "KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOHY",
        );
        assert_eq!(
            Jwe::parse(&t).unwrap().decrypt(&key).unwrap_err(),
            Error::Decryption
        );
    }

    /// RFC 7516 Appendix A.4 (general) and A.5 (flattened) JSON serialization.
    #[test]
    fn rfc7516_a4_a5_json_serialization() {
        let general = alloc::format!(
            r#"{{
      "protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
      "unprotected":{{"jku":"https://server.example.com/keys.jwks"}},
      "recipients":[
       {{"header":{{"alg":"RSA1_5","kid":"2011-04-29"}},
        "encrypted_key":"{A2_EK}"}},
       {{"header":{{"alg":"A128KW","kid":"7"}},
        "encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ"}}],
      "iv":"AxY8DCtDaGlsbGljb3RoZQ",
      "ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
      "tag":"Mz-VPPyU4RlcuYv1IwIvzw"
     }}"#
        );
        let jwe = Jwe::parse(&general).unwrap();
        assert_eq!(jwe.recipients().len(), 2);
        assert_eq!(jwe.kid(0).as_deref(), Some("2011-04-29"));
        assert_eq!(jwe.alg(1).unwrap(), KeyAlg::A128KW);
        let rsa = Jwk::parse(A2_KEY)
            .unwrap()
            .with_alg("RSA1_5")
            .unwrap()
            .with_kid("2011-04-29");
        let oct = Jwk::parse(A3_KEY).unwrap().with_kid("7");
        assert_eq!(jwe.decrypt(&rsa).unwrap(), A2_PT);
        assert_eq!(jwe.decrypt(&oct).unwrap(), A2_PT);
        let mut set = JwkSet::new();
        set.push(oct.clone()).unwrap();
        assert_eq!(jwe.decrypt_with_set(&set).unwrap(), A2_PT);
        let mut rsa_set = JwkSet::new();
        rsa_set.push(rsa.clone()).unwrap();
        assert_eq!(jwe.decrypt_with_set(&rsa_set).unwrap(), A2_PT);
        // The unprotected header is not authenticated, but it may not
        // override protected parameters or carry `enc`.
        let bad = general.replace(r#"{"jku":"#, r#"{"enc":"A256GCM","jku":"#);
        assert_eq!(Jwe::parse(&bad).unwrap_err(), Error::Malformed);

        let flattened = r#"{
      "protected":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2In0",
      "unprotected":{"jku":"https://server.example.com/keys.jwks"},
      "header":{"alg":"A128KW","kid":"7"},
      "encrypted_key":"6KB707dM9YTIgHtLvtgWQ8mKwboJW3of9locizkDTHzBC2IlrT1oOQ",
      "iv":"AxY8DCtDaGlsbGljb3RoZQ",
      "ciphertext":"KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY",
      "tag":"Mz-VPPyU4RlcuYv1IwIvzw"
     }"#;
        let jwe = Jwe::parse(flattened).unwrap();
        assert_eq!(jwe.decrypt_with_set(&set).unwrap(), A2_PT);
        assert_eq!(jwe.decrypt(&rsa).unwrap_err(), Error::KeyMismatch);
        // `kid` mismatch against the set.
        let other = Jwk::parse(A3_KEY).unwrap().with_kid("8");
        let mut other_set = JwkSet::new();
        other_set.push(other).unwrap();
        assert_eq!(jwe.decrypt_with_set(&other_set).unwrap_err(), Error::NoKey);
    }

    /// RFC 8037 Appendix A.6 / A.7 — ECDH-ES shared secrets with X25519 and X448.
    #[test]
    fn rfc8037_a6_a7_ecdh_es() {
        let bob = Jwk::parse(r#"{"kty":"OKP","crv":"X25519","kid":"Bob","x":"3p7bfXt9wbTTW2HC7OQ1Nz-DQ8hbeGdNrfx-FG-IK08"}"#).unwrap();
        let eph = Jwk::from_x25519_private(&X25519PrivateKey::from_bytes(
            hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .try_into()
                .unwrap(),
        ));
        assert_eq!(
            eph.to_public()
                .unwrap()
                .to_object()
                .get_str("x")
                .unwrap()
                .unwrap(),
            "hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo"
        );
        let z = ecdh_z(&eph, &bob).unwrap();
        assert_eq!(
            z.as_slice(),
            hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        );
        let dave = Jwk::parse(r#"{"kty":"OKP","crv":"X448","kid":"Dave","x":"PreoKbDNIPW8_AtZm2_sz22kYnEHvbDU80W0MCfYuXL8PjT7QjKhPKcG3LV67D2uB73BxnvzNgk"}"#).unwrap();
        let eph = Jwk::from_x448_private(&X448PrivateKey::from_bytes(
            hex("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b").try_into().unwrap(),
        ));
        assert_eq!(
            eph.to_public()
                .unwrap()
                .to_object()
                .get_str("x")
                .unwrap()
                .unwrap(),
            "mwj3zDG34-Z9ItWuoSEHSic70rg94Jxj-qc9LCLF2bvINmRyQdlT1AxbEtqIEg1TF3-A5TLEH6A"
        );
        let z = ecdh_z(&eph, &dave).unwrap();
        assert_eq!(
            z.as_slice(),
            hex(
                "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
            )
        );
        // Curve mismatch is refused.
        assert!(ecdh_z(&eph, &bob).is_err());
    }

    fn oct(len: usize) -> Jwk {
        let k: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(7)).collect();
        Jwk::oct(&k)
    }

    const ALL_ENC: [Enc; 6] = [
        Enc::A128Gcm,
        Enc::A192Gcm,
        Enc::A256Gcm,
        Enc::A128CbcHs256,
        Enc::A192CbcHs384,
        Enc::A256CbcHs512,
    ];

    fn round_trip(key: &Jwk, alg: KeyAlg, enc: Enc, extra: &Object) {
        let pt = b"attack at dawn";
        let public = key.to_public().unwrap_or_else(|| key.clone());
        let text =
            Jwe::encrypt_compact_with_header(&public, alg, enc, extra, pt, &mut rng()).unwrap();
        let jwe = Jwe::parse(&text).unwrap();
        assert_eq!(jwe.alg(0).unwrap(), alg);
        assert_eq!(jwe.enc().unwrap(), enc);
        assert_eq!(jwe.decrypt(key).unwrap(), pt, "{alg:?}/{enc:?}");
        // Flip one ciphertext bit.
        let mut parts: Vec<String> = text.split('.').map(String::from).collect();
        let mut ct = base64url::decode(&parts[3]).unwrap();
        ct[0] ^= 1;
        parts[3] = base64url::encode(&ct);
        let tampered = parts.join(".");
        assert_eq!(
            Jwe::parse(&tampered).unwrap().decrypt(key).unwrap_err(),
            Error::Decryption
        );
    }

    #[test]
    fn round_trips_symmetric() {
        let mut fast = Object::new();
        fast.insert("p2c", Value::Number(json::Number::from_u64(1000)))
            .unwrap();
        for enc in ALL_ENC {
            round_trip(&oct(enc.key_len()), KeyAlg::Dir, enc, &Object::new());
            for (alg, klen) in [
                (KeyAlg::A128KW, 16),
                (KeyAlg::A192KW, 24),
                (KeyAlg::A256KW, 32),
                (KeyAlg::A128GCMKW, 16),
                (KeyAlg::A192GCMKW, 24),
                (KeyAlg::A256GCMKW, 32),
            ] {
                round_trip(&oct(klen), alg, enc, &Object::new());
            }
            for alg in [
                KeyAlg::Pbes2Hs256A128KW,
                KeyAlg::Pbes2Hs384A192KW,
                KeyAlg::Pbes2Hs512A256KW,
            ] {
                round_trip(&Jwk::oct(b"correct horse battery staple"), alg, enc, &fast);
            }
        }
    }

    #[test]
    fn round_trips_ecdh() {
        let mut r = rng();
        let mut keys: Vec<Jwk> = Vec::new();
        for curve in [
            crate::ec::CurveId::P256,
            crate::ec::CurveId::P384,
            crate::ec::CurveId::P521,
            crate::ec::CurveId::Secp256k1,
        ] {
            keys.push(
                Jwk::from_ec_private(&BoxedEcdsaPrivateKey::generate(curve, &mut r)).unwrap(),
            );
        }
        keys.push(Jwk::from_x25519_private(&X25519PrivateKey::generate(
            &mut r,
        )));
        keys.push(Jwk::from_x448_private(&X448PrivateKey::generate(&mut r)));
        let mut party = Object::new();
        party
            .insert_str("apu", &base64url::encode(b"Alice"))
            .unwrap();
        party.insert_str("apv", &base64url::encode(b"Bob")).unwrap();
        for key in &keys {
            for alg in [
                KeyAlg::EcdhEs,
                KeyAlg::EcdhEsA128KW,
                KeyAlg::EcdhEsA192KW,
                KeyAlg::EcdhEsA256KW,
            ] {
                round_trip(key, alg, Enc::A128Gcm, &Object::new());
                round_trip(key, alg, Enc::A256CbcHs512, &party);
            }
        }
        // A ciphertext for one curve cannot be opened by a key on another.
        let text = Jwe::encrypt_compact(
            &keys[0].to_public().unwrap(),
            KeyAlg::EcdhEs,
            Enc::A128Gcm,
            b"x",
            &mut r,
        )
        .unwrap();
        assert_eq!(
            Jwe::parse(&text).unwrap().decrypt(&keys[1]).unwrap_err(),
            Error::Decryption
        );
        assert_eq!(
            Jwe::parse(&text).unwrap().decrypt(&keys[4]).unwrap_err(),
            Error::KeyMismatch
        );
        // An off-curve `epk` is rejected by the JWK parser.
        let jwe = Jwe::parse(&text).unwrap();
        let epk = jwe.protected().get_object("epk").unwrap().unwrap();
        let mut y = base64url::decode(epk.require_str("y").unwrap()).unwrap();
        y[5] ^= 0x10;
        let broken = alloc::format!(
            r#"{{"alg":"ECDH-ES","enc":"A128GCM","epk":{{"kty":"EC","crv":"P-256","x":"{}","y":"{}"}}}}"#,
            epk.require_str("x").unwrap(),
            base64url::encode(&y)
        );
        let mut parts: Vec<String> = text.split('.').map(String::from).collect();
        parts[0] = base64url::encode(broken.as_bytes());
        assert_eq!(
            Jwe::parse(&parts.join("."))
                .unwrap()
                .decrypt(&keys[0])
                .unwrap_err(),
            Error::InvalidKey
        );
    }

    #[test]
    fn pbes2_limits() {
        let key = Jwk::oct(b"password");
        let mut extra = Object::new();
        extra
            .insert(
                "p2c",
                Value::Number(json::Number::from_u64(MAX_PBES2_ITERATIONS + 1)),
            )
            .unwrap();
        assert_eq!(
            Jwe::encrypt_compact_with_header(
                &key,
                KeyAlg::Pbes2Hs256A128KW,
                Enc::A128Gcm,
                &extra,
                b"x",
                &mut rng()
            )
            .unwrap_err(),
            Error::Malformed
        );
        // A header with a short salt or huge count is refused before PBKDF2 runs.
        let hdr = base64url::encode(
            br#"{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2s":"AAAA","p2c":1000}"#,
        );
        let text = alloc::format!(
            "{hdr}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA"
        );
        assert_eq!(
            Jwe::parse(&text).unwrap().decrypt(&key).unwrap_err(),
            Error::Malformed
        );
        let hdr = base64url::encode(
            br#"{"alg":"PBES2-HS256+A128KW","enc":"A128GCM","p2s":"AAAAAAAAAAAA","p2c":100000000}"#,
        );
        let text = alloc::format!(
            "{hdr}.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA"
        );
        assert_eq!(
            Jwe::parse(&text).unwrap().decrypt(&key).unwrap_err(),
            Error::Malformed
        );
    }

    #[test]
    fn structure_and_policy() {
        let key = Jwk::parse(A3_KEY).unwrap();
        assert!(Jwe::parse("").is_err());
        assert!(Jwe::parse("a.b.c.d").is_err());
        assert!(Jwe::parse("a.b.c.d.e.f").is_err());
        // `enc` must be protected; unknown algorithms are refused.
        let hdr = base64url::encode(br#"{"alg":"A128KW"}"#);
        assert_eq!(
            Jwe::parse(&alloc::format!("{hdr}.AA.AA.AA.AA")).unwrap_err(),
            Error::Malformed
        );
        let hdr = base64url::encode(br#"{"alg":"none","enc":"A128GCM"}"#);
        assert_eq!(
            Jwe::parse(&alloc::format!("{hdr}.AA.AA.AA.AA"))
                .unwrap()
                .decrypt(&key)
                .unwrap_err(),
            Error::UnsupportedAlgorithm
        );
        let hdr = base64url::encode(br#"{"alg":"A128KW","enc":"A128GCM","crit":["exp"],"exp":1}"#);
        assert_eq!(
            Jwe::parse(&alloc::format!("{hdr}.AA.AA.AA.AA")).unwrap_err(),
            Error::CriticalHeader
        );
        let hdr = base64url::encode(br#"{"alg":"A128KW","enc":"A128GCM","zip":"GZIP"}"#);
        assert_eq!(
            Jwe::parse(&alloc::format!("{hdr}.AA.AA.AA.AA")).unwrap_err(),
            Error::UnsupportedAlgorithm
        );
        // Missing GCMKW parameters.
        let hdr = base64url::encode(br#"{"alg":"A128GCMKW","enc":"A128GCM"}"#);
        let gk = Jwk::oct(&[0u8; 16]);
        assert_eq!(
            Jwe::parse(&alloc::format!(
                "{hdr}.AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAA.AA.AAAAAAAAAAAAAAAAAAAAAA"
            ))
            .unwrap()
            .decrypt(&gk)
            .unwrap_err(),
            Error::Malformed
        );
        // A signing key never decrypts.
        let sig = Jwk::oct(&[0u8; 32]).with_use("sig").unwrap();
        assert_eq!(
            Jwe::parse(A3_JWE).unwrap().decrypt(&sig).unwrap_err(),
            Error::KeyMismatch
        );
        let ops = Jwk::parse(A3_KEY)
            .unwrap()
            .with_key_ops(&["wrapKey"])
            .unwrap();
        assert_eq!(
            Jwe::parse(A3_JWE).unwrap().decrypt(&ops).unwrap_err(),
            Error::KeyMismatch
        );
        let ops = Jwk::parse(A3_KEY)
            .unwrap()
            .with_key_ops(&["unwrapKey"])
            .unwrap();
        assert_eq!(Jwe::parse(A3_JWE).unwrap().decrypt(&ops).unwrap(), A2_PT);
        // Extra application header parameters survive the round trip.
        let mut extra = Object::new();
        extra.insert_str("typ", "JWE").unwrap();
        let text = Jwe::encrypt_compact_with_header(
            &key,
            KeyAlg::A128KW,
            Enc::A128Gcm,
            &extra,
            b"hi",
            &mut rng(),
        )
        .unwrap();
        let jwe = Jwe::parse(&text).unwrap();
        assert_eq!(jwe.protected().require_str("typ").unwrap(), "JWE");
        assert_eq!(jwe.decrypt(&key).unwrap(), b"hi");
        // `dir` with the key's `alg` naming the content encryption.
        let dir = Jwk::oct(&[9u8; 32]).with_alg("A256GCM").unwrap();
        let text =
            Jwe::encrypt_compact(&dir, KeyAlg::Dir, Enc::A256Gcm, b"hi", &mut rng()).unwrap();
        assert_eq!(Jwe::parse(&text).unwrap().decrypt(&dir).unwrap(), b"hi");
        assert_eq!(
            Jwe::encrypt_compact(&dir, KeyAlg::Dir, Enc::A128CbcHs256, b"hi", &mut rng())
                .unwrap_err(),
            Error::KeyMismatch
        );
    }

    #[test]
    fn zip_deflate() {
        let key = Jwk::parse(A3_KEY).unwrap();
        let mut extra = Object::new();
        extra.insert_str("zip", "DEF").unwrap();
        let pt = alloc::vec![b'a'; 10_000];
        let res = Jwe::encrypt_compact_with_header(
            &key,
            KeyAlg::A128KW,
            Enc::A128Gcm,
            &extra,
            &pt,
            &mut rng(),
        );
        #[cfg(feature = "cert-compression")]
        {
            let text = res.unwrap();
            assert!(text.len() < 1000, "compressed");
            let jwe = Jwe::parse(&text).unwrap();
            assert_eq!(jwe.protected().require_str("zip").unwrap(), "DEF");
            assert_eq!(jwe.decrypt(&key).unwrap(), pt);
        }
        #[cfg(not(feature = "cert-compression"))]
        assert_eq!(res.unwrap_err(), Error::Unsupported("zip"));
    }
}
