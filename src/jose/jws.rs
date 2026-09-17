//! JSON Web Signature (RFC 7515): verification of the compact, flattened
//! JSON and general JSON serializations, and compact signing.

use super::OkpCurve;
use super::json::{self, Object};
use super::{Error, Jwk, JwkSet, SigAlg, base64url};
use crate::bignum::BoxedUint;
use crate::ec::{BoxedEcdsaSignature, Ed448Signature, Ed25519Signature};
use crate::hash::{Digest, Hmac, Sha256, Sha384, Sha512};
use crate::rng::{CryptoRng, RngCore};
use alloc::string::String;
use alloc::vec::Vec;

/// Header parameter names registered for JWS (RFC 7515 §4.1) — these may
/// never appear in `crit`.
const REGISTERED_HEADERS: [&str; 11] = [
    "alg", "jku", "jwk", "kid", "x5u", "x5c", "x5t", "x5t#S256", "typ", "cty", "crit",
];

/// One signature of a JWS: its protected header (verbatim, as it enters
/// the signing input), optional unprotected header and signature bytes.
#[derive(Clone, Debug)]
pub struct JwsSignature {
    protected_b64: String,
    protected: Object,
    header: Option<Object>,
    signature: Vec<u8>,
}

impl JwsSignature {
    fn parse(
        protected_b64: &str,
        header: Option<Object>,
        signature_b64: &str,
    ) -> Result<Self, Error> {
        let protected = json::parse_object_bytes(&base64url::decode(protected_b64)?)?;
        let signature = base64url::decode(signature_b64)?;
        let sig = JwsSignature {
            protected_b64: String::from(protected_b64),
            protected,
            header,
            signature,
        };
        sig.check_header()?;
        Ok(sig)
    }

    /// Validates the header pair: `alg` must be integrity protected, the
    /// two headers must be disjoint, `crit` must be well-formed and — as
    /// no extension is understood — absent.
    fn check_header(&self) -> Result<(), Error> {
        if let Some(h) = &self.header {
            for (name, _) in h.iter() {
                if self.protected.contains(name) {
                    return Err(Error::Malformed);
                }
            }
            // The algorithm must be under the signature's protection.
            if h.contains("alg") {
                return Err(Error::Malformed);
            }
        }
        self.protected.require_str("alg")?;
        for obj in [Some(&self.protected), self.header.as_ref()]
            .into_iter()
            .flatten()
        {
            obj.get_str("kid")?;
            if let Some(crit) = obj.get_array("crit")? {
                if crit.is_empty() {
                    return Err(Error::Malformed);
                }
                for item in crit {
                    let name = item.as_str().ok_or(Error::Malformed)?;
                    if REGISTERED_HEADERS.contains(&name) || !obj.contains(name) {
                        return Err(Error::Malformed);
                    }
                }
                return Err(Error::CriticalHeader);
            }
            if obj.contains("b64") {
                // RFC 7797 unencoded payloads require `crit: ["b64"]` anyway.
                return Err(Error::Unsupported("b64"));
            }
        }
        Ok(())
    }

    /// The protected header.
    pub fn protected(&self) -> &Object {
        &self.protected
    }

    /// The unprotected header, if any. Nothing in it is authenticated.
    pub fn header(&self) -> Option<&Object> {
        self.header.as_ref()
    }

    /// The signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// The `alg` of the protected header.
    pub fn alg(&self) -> Result<SigAlg, Error> {
        let name = self.protected.require_str("alg")?;
        SigAlg::from_name(name).ok_or(Error::UnsupportedAlgorithm)
    }

    /// The `kid` from either header, if any.
    pub fn kid(&self) -> Option<&str> {
        self.protected.get_str("kid").ok().flatten().or_else(|| {
            self.header
                .as_ref()
                .and_then(|h| h.get_str("kid").ok().flatten())
        })
    }

    fn verify(&self, payload_b64: &str, key: &Jwk) -> Result<(), Error> {
        let alg = self.alg()?;
        key.check_usable(alg.name(), None, alg.family(), true, &["verify"])?;
        let mut input = Vec::with_capacity(self.protected_b64.len() + 1 + payload_b64.len());
        input.extend_from_slice(self.protected_b64.as_bytes());
        input.push(b'.');
        input.extend_from_slice(payload_b64.as_bytes());
        verify_raw(alg, key, &input, &self.signature)
    }
}

/// A parsed JWS. The payload is available before verification (it is
/// needed to look at, e.g., a JWT's claims for key selection) but must
/// only be trusted after [`verify`](Self::verify) succeeds.
#[derive(Clone, Debug)]
pub struct Jws {
    payload_b64: String,
    payload: Vec<u8>,
    signatures: Vec<JwsSignature>,
}

impl Jws {
    /// Parses either serialization: JSON when the text starts with `{`,
    /// compact otherwise.
    pub fn parse(text: &str) -> Result<Self, Error> {
        if text.trim_start().starts_with('{') {
            Self::parse_json(text)
        } else {
            Self::parse_compact(text)
        }
    }

    /// Parses the compact serialization `header.payload.signature`.
    pub fn parse_compact(text: &str) -> Result<Self, Error> {
        let mut parts = text.split('.');
        let (Some(h), Some(p), Some(s), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Error::Malformed);
        };
        let payload = base64url::decode(p)?;
        let signature = JwsSignature::parse(h, None, s)?;
        Ok(Jws {
            payload_b64: String::from(p),
            payload,
            signatures: alloc::vec![signature],
        })
    }

    /// Parses the flattened or general JSON serialization (RFC 7515 §7.2).
    pub fn parse_json(text: &str) -> Result<Self, Error> {
        let obj = json::parse_object(text)?;
        let payload_b64 = obj.require_str("payload")?;
        let payload = base64url::decode(payload_b64)?;
        let one = |o: &Object| -> Result<JwsSignature, Error> {
            let protected = o.require_str("protected")?;
            let header = o.get_object("header")?.cloned();
            let signature = o.require_str("signature")?;
            JwsSignature::parse(protected, header, signature)
        };
        let signatures = match obj.get_array("signatures")? {
            Some(list) => {
                if obj.contains("protected") || obj.contains("header") || obj.contains("signature")
                {
                    return Err(Error::Malformed);
                }
                if list.is_empty() {
                    return Err(Error::Malformed);
                }
                let mut sigs = Vec::with_capacity(list.len());
                for item in list {
                    sigs.push(one(item.as_object().ok_or(Error::Malformed)?)?);
                }
                sigs
            }
            None => alloc::vec![one(&obj)?],
        };
        Ok(Jws {
            payload_b64: String::from(payload_b64),
            payload,
            signatures,
        })
    }

    /// The payload — **unverified** until [`verify`](Self::verify) returns
    /// `Ok`.
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// The signatures (one for the compact and flattened serializations).
    pub fn signatures(&self) -> &[JwsSignature] {
        &self.signatures
    }

    /// Verifies the JWS with `key` and returns the payload. Succeeds when
    /// any one signature verifies under the key; `key`'s `alg`, `use` and
    /// `key_ops` must permit the signature's algorithm.
    pub fn verify(&self, key: &Jwk) -> Result<&[u8], Error> {
        let mut last = Error::Verification;
        for sig in &self.signatures {
            match sig.verify(&self.payload_b64, key) {
                Ok(()) => return Ok(&self.payload),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Verifies the JWS with the key from `keys` selected by the header's
    /// `kid` (or, without one, the single key fitting the algorithm) and
    /// returns the payload.
    pub fn verify_with_set(&self, keys: &JwkSet) -> Result<&[u8], Error> {
        let mut last = Error::Verification;
        for sig in &self.signatures {
            let alg = match sig.alg() {
                Ok(a) => a,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            let key = match keys.select(sig.kid(), |k| {
                k.check_usable(alg.name(), None, alg.family(), true, &["verify"])
                    .is_ok()
            }) {
                Ok(k) => k,
                Err(e) => {
                    last = e;
                    continue;
                }
            };
            match sig.verify(&self.payload_b64, key) {
                Ok(()) => return Ok(&self.payload),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Signs `payload` with `key` using `alg` and returns the compact
    /// serialization. The protected header is `{"alg": ..., "kid": ...}`
    /// (`kid` only when the key has one).
    pub fn sign_compact<R: RngCore + CryptoRng>(
        key: &Jwk,
        alg: SigAlg,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<String, Error> {
        Self::sign_compact_with_header(key, alg, &Object::new(), payload, rng)
    }

    /// [`sign_compact`](Self::sign_compact) with additional protected
    /// header parameters (`alg` and `kid` are added by this function and
    /// must not be present in `extra`; `crit` is not supported).
    pub fn sign_compact_with_header<R: RngCore + CryptoRng>(
        key: &Jwk,
        alg: SigAlg,
        extra: &Object,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<String, Error> {
        key.check_usable(alg.name(), None, alg.family(), true, &["sign"])?;
        if !key.is_private() {
            return Err(Error::KeyMismatch);
        }
        let mut header = Object::new();
        header.insert_str("alg", alg.name())?;
        if let Some(kid) = key.kid() {
            header.insert_str("kid", kid)?;
        }
        for (name, value) in extra.iter() {
            if name == "crit" || name == "b64" {
                return Err(Error::Unsupported("crit"));
            }
            header.insert(name, value.clone())?;
        }
        let mut input = base64url::encode(header.to_json().as_bytes());
        input.push('.');
        input.push_str(&base64url::encode(payload));
        let signature = sign_raw(alg, key, input.as_bytes(), rng)?;
        input.push('.');
        input.push_str(&base64url::encode(&signature));
        Ok(input)
    }
}

fn hmac_verify<D: Digest>(key: &[u8], input: &[u8], sig: &[u8]) -> Result<(), Error> {
    if sig.len() != D::OUTPUT_LEN {
        return Err(Error::Verification);
    }
    let mut h = Hmac::<D>::new(key);
    h.update(input);
    if bool::from(h.verify(sig)) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

fn ecdsa_verify<D: Digest>(key: &Jwk, input: &[u8], sig: &[u8]) -> Result<(), Error> {
    let crv = key.ec_curve().ok_or(Error::KeyMismatch)?;
    let n = crv.order_len();
    if sig.len() != 2 * n {
        return Err(Error::Verification);
    }
    let s = BoxedEcdsaSignature::from_components(
        BoxedUint::from_be_bytes(&sig[..n]),
        BoxedUint::from_be_bytes(&sig[n..]),
    );
    key.ec_public_key()?
        .verify::<D>(input, &s)
        .map_err(|_| Error::Verification)
}

/// Verifies `sig` over the raw signing input.
pub(crate) fn verify_raw(alg: SigAlg, key: &Jwk, input: &[u8], sig: &[u8]) -> Result<(), Error> {
    fn bad<E>(_: E) -> Error {
        Error::Verification
    }
    match alg {
        SigAlg::HS256 => hmac_verify::<Sha256>(key.oct_bytes()?, input, sig),
        SigAlg::HS384 => hmac_verify::<Sha384>(key.oct_bytes()?, input, sig),
        SigAlg::HS512 => hmac_verify::<Sha512>(key.oct_bytes()?, input, sig),
        SigAlg::RS256 => key
            .rsa_public_key()?
            .verify_pkcs1v15::<Sha256>(input, sig)
            .map_err(bad),
        SigAlg::RS384 => key
            .rsa_public_key()?
            .verify_pkcs1v15::<Sha384>(input, sig)
            .map_err(bad),
        SigAlg::RS512 => key
            .rsa_public_key()?
            .verify_pkcs1v15::<Sha512>(input, sig)
            .map_err(bad),
        SigAlg::PS256 => key
            .rsa_public_key()?
            .verify_pss::<Sha256>(input, sig)
            .map_err(bad),
        SigAlg::PS384 => key
            .rsa_public_key()?
            .verify_pss::<Sha384>(input, sig)
            .map_err(bad),
        SigAlg::PS512 => key
            .rsa_public_key()?
            .verify_pss::<Sha512>(input, sig)
            .map_err(bad),
        SigAlg::ES256 | SigAlg::ES256K => ecdsa_verify::<Sha256>(key, input, sig),
        SigAlg::ES384 => ecdsa_verify::<Sha384>(key, input, sig),
        SigAlg::ES512 => ecdsa_verify::<Sha512>(key, input, sig),
        SigAlg::EdDSA => match key.okp_curve() {
            Some(OkpCurve::Ed25519) => {
                let bytes: [u8; 64] = sig.try_into().map_err(|_| Error::Verification)?;
                key.ed25519_public_key()?
                    .verify(input, &Ed25519Signature::from_bytes(bytes))
                    .map_err(bad)
            }
            Some(OkpCurve::Ed448) => {
                let bytes: [u8; 114] = sig.try_into().map_err(|_| Error::Verification)?;
                key.ed448_public_key()?
                    .verify(input, &Ed448Signature::from_bytes(bytes))
                    .map_err(bad)
            }
            _ => Err(Error::KeyMismatch),
        },
    }
}

fn sign_raw<R: RngCore + CryptoRng>(
    alg: SigAlg,
    key: &Jwk,
    input: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    fn fail<E>(_: E) -> Error {
        Error::InvalidKey
    }
    Ok(match alg {
        SigAlg::HS256 => Hmac::<Sha256>::mac(key.oct_bytes()?, input).to_vec(),
        SigAlg::HS384 => Hmac::<Sha384>::mac(key.oct_bytes()?, input).to_vec(),
        SigAlg::HS512 => Hmac::<Sha512>::mac(key.oct_bytes()?, input).to_vec(),
        SigAlg::RS256 => key
            .rsa_private_key()?
            .sign_pkcs1v15::<Sha256>(input)
            .map_err(fail)?,
        SigAlg::RS384 => key
            .rsa_private_key()?
            .sign_pkcs1v15::<Sha384>(input)
            .map_err(fail)?,
        SigAlg::RS512 => key
            .rsa_private_key()?
            .sign_pkcs1v15::<Sha512>(input)
            .map_err(fail)?,
        SigAlg::PS256 => key
            .rsa_private_key()?
            .sign_pss::<Sha256, R>(input, rng)
            .map_err(fail)?,
        SigAlg::PS384 => key
            .rsa_private_key()?
            .sign_pss::<Sha384, R>(input, rng)
            .map_err(fail)?,
        SigAlg::PS512 => key
            .rsa_private_key()?
            .sign_pss::<Sha512, R>(input, rng)
            .map_err(fail)?,
        SigAlg::ES256 | SigAlg::ES256K | SigAlg::ES384 | SigAlg::ES512 => {
            let sk = key.ec_private_key()?;
            let curve = sk.curve();
            let sig = match alg {
                SigAlg::ES384 => sk.sign::<Sha384>(input),
                SigAlg::ES512 => sk.sign::<Sha512>(input),
                _ => sk.sign::<Sha256>(input),
            }
            .map_err(fail)?;
            sig.to_bytes(curve)
        }
        SigAlg::EdDSA => match key.okp_curve() {
            Some(OkpCurve::Ed25519) => key.ed25519_private_key()?.sign(input).to_bytes().to_vec(),
            Some(OkpCurve::Ed448) => key.ed448_private_key()?.sign(input).to_bytes().to_vec(),
            _ => return Err(Error::KeyMismatch),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::HmacDrbg;

    fn rng() -> HmacDrbg<Sha256> {
        HmacDrbg::new(b"jose jws tests", b"nonce", b"")
    }

    const PAYLOAD_B64: &str = "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
    const PAYLOAD: &str =
        "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

    /// RFC 7515 Appendix A.1 — HS256.
    #[test]
    fn rfc7515_a1_hs256() {
        let key = Jwk::parse(r#"{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}"#).unwrap();
        let jws_text = alloc::format!(
            "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.{PAYLOAD_B64}.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        let jws = Jws::parse(&jws_text).unwrap();
        assert_eq!(jws.verify(&key).unwrap(), PAYLOAD.as_bytes());
        assert_eq!(
            jws.signatures()[0].protected().require_str("typ").unwrap(),
            "JWT"
        );
        // Signing with the same header bytes reproduces the signature.
        let mut extra = Object::new();
        extra.insert_str("typ", "JWT").unwrap();
        let signed = Jws::sign_compact_with_header(
            &key,
            SigAlg::HS256,
            &extra,
            PAYLOAD.as_bytes(),
            &mut rng(),
        )
        .unwrap();
        assert_eq!(
            Jws::parse(&signed).unwrap().verify(&key).unwrap(),
            PAYLOAD.as_bytes()
        );
        // Our compact header spelling differs from the RFC's pretty-printed
        // one, so the MAC differs too; verifying the RFC's exact signing
        // input directly reproduces the RFC's tag.
        let tag = Hmac::<Sha256>::mac(
            key.oct_bytes().unwrap(),
            &jws_text.as_bytes()[..jws_text.rfind('.').unwrap()],
        );
        assert_eq!(
            base64url::encode(&tag),
            "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        // The key's own metadata must fit.
        let wrong = Jwk::oct(key.oct_bytes().unwrap())
            .with_alg("HS384")
            .unwrap();
        assert_eq!(jws.verify(&wrong).unwrap_err(), Error::KeyMismatch);
        let wrong = Jwk::oct(key.oct_bytes().unwrap()).with_use("enc").unwrap();
        assert_eq!(jws.verify(&wrong).unwrap_err(), Error::KeyMismatch);
        let wrong = Jwk::oct(key.oct_bytes().unwrap())
            .with_key_ops(&["sign"])
            .unwrap();
        assert_eq!(jws.verify(&wrong).unwrap_err(), Error::KeyMismatch);
        // Tampered payload.
        let mut tampered = jws_text.clone();
        tampered.replace_range(41..42, "f");
        assert_eq!(
            Jws::parse(&tampered).unwrap().verify(&key).unwrap_err(),
            Error::Verification
        );
    }

    /// RFC 7515 Appendix A.2 — RS256 (deterministic: signing reproduces it).
    #[test]
    fn rfc7515_a2_rs256() {
        let key = Jwk::parse(r#"{"kty":"RSA",
      "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
      "e":"AQAB",
      "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
      "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc",
      "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
      "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
      "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
      "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
     }"#).unwrap();
        let sig = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw";
        let text = alloc::format!("eyJhbGciOiJSUzI1NiJ9.{PAYLOAD_B64}.{sig}");
        let jws = Jws::parse(&text).unwrap();
        assert_eq!(jws.verify(&key).unwrap(), PAYLOAD.as_bytes());
        let public = key.to_public().unwrap();
        assert_eq!(jws.verify(&public).unwrap(), PAYLOAD.as_bytes());
        let signed =
            Jws::sign_compact(&key, SigAlg::RS256, PAYLOAD.as_bytes(), &mut rng()).unwrap();
        assert_eq!(signed, text);
        // A public key cannot sign; an RS key rejects PS and HS headers.
        assert!(Jws::sign_compact(&public, SigAlg::RS256, b"x", &mut rng()).is_err());
        let ps = Jws::sign_compact(&key, SigAlg::PS256, PAYLOAD.as_bytes(), &mut rng()).unwrap();
        Jws::parse(&ps).unwrap().verify(&public).unwrap();
        let pinned = public.clone().with_alg("RS256").unwrap();
        assert_eq!(
            Jws::parse(&ps).unwrap().verify(&pinned).unwrap_err(),
            Error::KeyMismatch
        );
        // Symmetric-confusion: the public key bytes are not an HMAC key.
        let hs = alloc::format!(
            "eyJhbGciOiJIUzI1NiJ9.{PAYLOAD_B64}.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        );
        assert_eq!(
            Jws::parse(&hs).unwrap().verify(&public).unwrap_err(),
            Error::KeyMismatch
        );
    }

    /// RFC 7515 Appendix A.3 — ES256.
    #[test]
    fn rfc7515_a3_es256() {
        let key = Jwk::parse(
            r#"{"kty":"EC",
      "crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
     }"#,
        )
        .unwrap();
        let text = alloc::format!(
            "eyJhbGciOiJFUzI1NiJ9.{PAYLOAD_B64}.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
        );
        let jws = Jws::parse(&text).unwrap();
        assert_eq!(jws.verify(&key).unwrap(), PAYLOAD.as_bytes());
        assert_eq!(
            jws.verify(&key.to_public().unwrap()).unwrap(),
            PAYLOAD.as_bytes()
        );
        let signed =
            Jws::sign_compact(&key, SigAlg::ES256, PAYLOAD.as_bytes(), &mut rng()).unwrap();
        Jws::parse(&signed).unwrap().verify(&key).unwrap();
        // DER-encoded or wrong-length signatures are rejected.
        let short = alloc::format!(
            "eyJhbGciOiJFUzI1NiJ9.{PAYLOAD_B64}.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU"
        );
        assert_eq!(
            Jws::parse(&short).unwrap().verify(&key).unwrap_err(),
            Error::Verification
        );
    }

    /// RFC 7515 Appendix A.4 — ES512.
    #[test]
    fn rfc7515_a4_es512() {
        let key = Jwk::parse(r#"{"kty":"EC",
      "crv":"P-521",
      "x":"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk",
      "y":"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2",
      "d":"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C"
     }"#).unwrap();
        let text = "eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA.AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn";
        let jws = Jws::parse(text).unwrap();
        assert_eq!(jws.verify(&key).unwrap(), b"Payload");
        let signed = Jws::sign_compact(&key, SigAlg::ES512, b"Payload", &mut rng()).unwrap();
        assert_eq!(
            Jws::parse(&signed)
                .unwrap()
                .verify(&key.to_public().unwrap())
                .unwrap(),
            b"Payload"
        );
        // The P-521 key cannot serve ES256.
        let es256 = Jws::sign_compact(&key, SigAlg::ES256, b"Payload", &mut rng());
        assert_eq!(es256.unwrap_err(), Error::KeyMismatch);
    }

    /// RFC 7515 Appendix A.5 — `alg: none` is rejected even with an empty
    /// signature and a key that would otherwise fit.
    #[test]
    fn rfc7515_a5_none_rejected() {
        let text = alloc::format!("eyJhbGciOiJub25lIn0.{PAYLOAD_B64}.");
        let jws = Jws::parse(&text).unwrap();
        let key = Jwk::oct(&[0u8; 32]);
        assert_eq!(jws.verify(&key).unwrap_err(), Error::UnsupportedAlgorithm);
        let set = {
            let mut s = JwkSet::new();
            s.push(key).unwrap();
            s
        };
        assert!(jws.verify_with_set(&set).is_err());
    }

    /// RFC 7515 Appendix A.6 / A.7 — general and flattened JSON serialization
    /// (A.2's RS256 and A.3's ES256 signatures over the same payload).
    #[test]
    fn rfc7515_a6_a7_json_serialization() {
        let rsa = Jwk::parse(r#"{"kty":"RSA","kid":"2010-12-29",
      "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
      "e":"AQAB"}"#).unwrap();
        let ec = Jwk::parse(
            r#"{"kty":"EC","kid":"e9bc097a-ce51-4036-9562-d2ade882db0d","crv":"P-256",
      "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"}"#,
        )
        .unwrap();
        let general = alloc::format!(
            r#"{{
      "payload":"{PAYLOAD_B64}",
      "signatures":[
       {{"protected":"eyJhbGciOiJSUzI1NiJ9",
        "header":{{"kid":"2010-12-29"}},
        "signature":"cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw"}},
       {{"protected":"eyJhbGciOiJFUzI1NiJ9",
        "header":{{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"}},
        "signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"}}]
     }}"#
        );
        let jws = Jws::parse(&general).unwrap();
        assert_eq!(jws.signatures().len(), 2);
        assert_eq!(jws.verify(&rsa).unwrap(), PAYLOAD.as_bytes());
        assert_eq!(jws.verify(&ec).unwrap(), PAYLOAD.as_bytes());
        let mut set = JwkSet::new();
        set.push(rsa.clone()).unwrap();
        set.push(ec.clone()).unwrap();
        assert_eq!(jws.verify_with_set(&set).unwrap(), PAYLOAD.as_bytes());
        assert_eq!(
            jws.signatures()[1].kid(),
            Some("e9bc097a-ce51-4036-9562-d2ade882db0d")
        );

        let flattened = alloc::format!(
            r#"{{
      "payload":"{PAYLOAD_B64}",
      "protected":"eyJhbGciOiJFUzI1NiJ9",
      "header":{{"kid":"e9bc097a-ce51-4036-9562-d2ade882db0d"}},
      "signature":"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q"
     }}"#
        );
        let jws = Jws::parse(&flattened).unwrap();
        assert_eq!(jws.verify_with_set(&set).unwrap(), PAYLOAD.as_bytes());
        assert_eq!(jws.verify(&rsa).unwrap_err(), Error::KeyMismatch);
        // Header names must be disjoint; `alg` only in the protected header.
        let dup = flattened.replace(r#""header":{"kid""#, r#""header":{"alg":"ES256","kid""#);
        assert_eq!(Jws::parse(&dup).unwrap_err(), Error::Malformed);
    }

    /// RFC 8037 Appendix A.4 / A.5 — Ed25519 (deterministic).
    #[test]
    fn rfc8037_a4_eddsa() {
        let key = Jwk::parse(
            r#"{"kty":"OKP","crv":"Ed25519",
   "d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
   "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#,
        )
        .unwrap();
        let text = "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg";
        let jws = Jws::parse(text).unwrap();
        assert_eq!(jws.verify(&key).unwrap(), b"Example of Ed25519 signing");
        assert_eq!(
            jws.verify(&key.to_public().unwrap()).unwrap(),
            b"Example of Ed25519 signing"
        );
        let signed = Jws::sign_compact(
            &key,
            SigAlg::EdDSA,
            b"Example of Ed25519 signing",
            &mut rng(),
        )
        .unwrap();
        assert_eq!(signed, text);
        assert!(
            Jws::parse(&text.replace("M0KAg", "M0KBg"))
                .unwrap()
                .verify(&key)
                .is_err()
        );
    }

    #[test]
    fn malformed_and_crit() {
        assert!(Jws::parse("").is_err());
        assert!(Jws::parse("a.b").is_err());
        assert!(Jws::parse("a.b.c.d").is_err());
        assert!(
            Jws::parse("eyJhbGciOiJIUzI1NiJ9.Zm9v.").is_ok(),
            "empty signature parses, fails verify"
        );
        let key = Jwk::oct(&[7u8; 32]);
        assert_eq!(
            Jws::parse("eyJhbGciOiJIUzI1NiJ9.Zm9v.")
                .unwrap()
                .verify(&key)
                .unwrap_err(),
            Error::Verification
        );
        // crit with an unknown extension.
        let hdr = base64url::encode(br#"{"alg":"HS256","crit":["exp"],"exp":1}"#);
        assert_eq!(
            Jws::parse(&alloc::format!("{hdr}.Zm9v.AA")).unwrap_err(),
            Error::CriticalHeader
        );
        let hdr = base64url::encode(br#"{"alg":"HS256","crit":[]}"#);
        assert_eq!(
            Jws::parse(&alloc::format!("{hdr}.Zm9v.AA")).unwrap_err(),
            Error::Malformed
        );
        let hdr = base64url::encode(br#"{"alg":"HS256","crit":["alg"]}"#);
        assert_eq!(
            Jws::parse(&alloc::format!("{hdr}.Zm9v.AA")).unwrap_err(),
            Error::Malformed
        );
        // Header must be an object with a string alg.
        let hdr = base64url::encode(br#"{"alg":5}"#);
        assert_eq!(
            Jws::parse(&alloc::format!("{hdr}.Zm9v.AA")).unwrap_err(),
            Error::Malformed
        );
        let hdr = base64url::encode(br#"[1]"#);
        assert_eq!(
            Jws::parse(&alloc::format!("{hdr}.Zm9v.AA")).unwrap_err(),
            Error::Json
        );
        // Embedded jwk is ignored: the caller's key decides.
        let hdr = base64url::encode(br#"{"alg":"HS256","jwk":{"kty":"oct","k":"AAAA"}}"#);
        let jws = Jws::parse(&alloc::format!("{hdr}.Zm9v.AA")).unwrap();
        assert_eq!(jws.verify(&key).unwrap_err(), Error::Verification);
    }
}
