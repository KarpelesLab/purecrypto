//! HPKE DHKEM dispatcher: runtime selection of `DHKEM(X25519, HKDF-SHA-256)`,
//! `DHKEM(P-256, HKDF-SHA-256)`, `DHKEM(P-384, HKDF-SHA-384)`, and
//! `DHKEM(P-521, HKDF-SHA-512)` (RFC 9180 §7.1).
//!
//! The four KEMs share the same DHKEM construction (RFC 9180 §4.1); the
//! only differences are the curve, the encoded public-key length, the
//! private-scalar length, the bitmask used in `DeriveKeyPair`, and the
//! associated HKDF hash. Encoded public keys (`enc`) and raw private
//! scalars (`sk`) cross the API as opaque byte strings; this module
//! handles all curve-specific framing.

use super::labeled::{labeled_expand, labeled_extract};
use super::suite::kem_suite_id;
use super::{Error, HpkeKdf};
use crate::ec::boxed::BoxedEcdhPrivateKey;
use crate::ec::{BoxedEcdsaPublicKey, CurveId};
use crate::rng::RngCore;
use alloc::vec::Vec;

/// HPKE KEM identifiers (RFC 9180 §7.1).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HpkeKem {
    /// `0x0010` — DHKEM(P-256, HKDF-SHA-256).
    DhkemP256HkdfSha256,
    /// `0x0011` — DHKEM(P-384, HKDF-SHA-384).
    DhkemP384HkdfSha384,
    /// `0x0012` — DHKEM(P-521, HKDF-SHA-512).
    DhkemP521HkdfSha512,
    /// `0x0020` — DHKEM(X25519, HKDF-SHA-256).
    DhkemX25519HkdfSha256,
}

impl HpkeKem {
    /// The IANA-assigned KEM id.
    pub const fn id(self) -> u16 {
        match self {
            HpkeKem::DhkemP256HkdfSha256 => 0x0010,
            HpkeKem::DhkemP384HkdfSha384 => 0x0011,
            HpkeKem::DhkemP521HkdfSha512 => 0x0012,
            HpkeKem::DhkemX25519HkdfSha256 => 0x0020,
        }
    }

    /// The HKDF function used internally by this DHKEM (independent of
    /// the suite's KDF choice).
    pub const fn kdf(self) -> HpkeKdf {
        match self {
            HpkeKem::DhkemP256HkdfSha256 => HpkeKdf::HkdfSha256,
            HpkeKem::DhkemP384HkdfSha384 => HpkeKdf::HkdfSha384,
            HpkeKem::DhkemP521HkdfSha512 => HpkeKdf::HkdfSha512,
            HpkeKem::DhkemX25519HkdfSha256 => HpkeKdf::HkdfSha256,
        }
    }

    /// `Nsecret`: the KEM shared-secret length in bytes — equal to the
    /// HKDF output length here.
    pub const fn n_secret(self) -> usize {
        self.kdf().output_len()
    }

    /// `Nenc`: the encoded encapsulated-key length in bytes.
    ///
    /// For NIST curves this is the SEC1 uncompressed form
    /// `0x04 || X || Y` (`1 + 2·field_len`). For X25519 it is the 32-byte
    /// u-coordinate.
    pub const fn n_enc(self) -> usize {
        match self {
            HpkeKem::DhkemP256HkdfSha256 => 65,
            HpkeKem::DhkemP384HkdfSha384 => 97,
            HpkeKem::DhkemP521HkdfSha512 => 133,
            HpkeKem::DhkemX25519HkdfSha256 => 32,
        }
    }

    /// `Npk`: the encoded recipient-public-key length. Identical to
    /// `Nenc` for DHKEM.
    pub const fn n_pk(self) -> usize {
        self.n_enc()
    }

    /// `Nsk`: the raw private-scalar length in bytes.
    pub const fn n_sk(self) -> usize {
        match self {
            HpkeKem::DhkemP256HkdfSha256 => 32,
            HpkeKem::DhkemP384HkdfSha384 => 48,
            HpkeKem::DhkemP521HkdfSha512 => 66,
            HpkeKem::DhkemX25519HkdfSha256 => 32,
        }
    }

    /// `bitmask` used by `DeriveKeyPair` for NIST curves. `0x01` on
    /// P-521 (whose order is 521 bits — the top byte carries one bit);
    /// `0xFF` elsewhere. Unused for X25519.
    const fn bitmask(self) -> u8 {
        match self {
            HpkeKem::DhkemP521HkdfSha512 => 0x01,
            _ => 0xFF,
        }
    }

    /// Returns the NIST curve identifier for this KEM, or `None` for
    /// X25519.
    fn nist_curve(self) -> Option<CurveId> {
        match self {
            HpkeKem::DhkemP256HkdfSha256 => Some(CurveId::P256),
            HpkeKem::DhkemP384HkdfSha384 => Some(CurveId::P384),
            HpkeKem::DhkemP521HkdfSha512 => Some(CurveId::P521),
            HpkeKem::DhkemX25519HkdfSha256 => None,
        }
    }

    /// Validates an encoded public key without computing anything else
    /// with it. For NIST curves this enforces SEC1 framing, in-range
    /// coordinates, and on-curve membership (the underlying group is
    /// prime-order, so a co-factor check is unnecessary). For X25519
    /// every 32-byte string is a valid encoding; small-order rejection
    /// happens later, in `dh`.
    pub(crate) fn validate_public_key(self, pk: &[u8]) -> Result<(), Error> {
        match self.nist_curve() {
            Some(curve) => {
                if pk.len() != self.n_pk() {
                    return Err(Error::InvalidKey);
                }
                BoxedEcdsaPublicKey::from_sec1(curve, pk).map_err(|_| Error::InvalidKey)?;
                Ok(())
            }
            None => {
                if pk.len() != 32 {
                    return Err(Error::InvalidKey);
                }
                Ok(())
            }
        }
    }

    /// `SerializePublicKey(pk(sk))`: derive the encoded public key from
    /// a private scalar `sk`.
    fn pk_from_sk(self, sk: &[u8]) -> Result<Vec<u8>, Error> {
        match self.nist_curve() {
            Some(curve) => {
                if sk.len() != self.n_sk() {
                    return Err(Error::InvalidKey);
                }
                let pk =
                    BoxedEcdhPrivateKey::from_bytes(curve, sk).map_err(|_| Error::InvalidKey)?;
                Ok(pk.public_key().to_sec1())
            }
            None => {
                if sk.len() != 32 {
                    return Err(Error::InvalidKey);
                }
                let mut s = [0u8; 32];
                s.copy_from_slice(sk);
                let pk = crate::ec::x25519::X25519PrivateKey::from_bytes(s);
                Ok(pk.public_key().to_vec())
            }
        }
    }

    /// `DH(sk, pk)`: the curve's Diffie-Hellman primitive. Returns the
    /// raw shared field-element bytes (`field_len` for NIST,
    /// 32 for X25519). All-zero / identity outputs map to
    /// [`Error::InvalidDhOutput`] per RFC 9180 §7.1.3-§7.1.4.
    fn dh(self, sk: &[u8], pk: &[u8]) -> Result<Vec<u8>, Error> {
        match self.nist_curve() {
            Some(curve) => {
                if sk.len() != self.n_sk() || pk.len() != self.n_pk() {
                    return Err(Error::InvalidKey);
                }
                let sk =
                    BoxedEcdhPrivateKey::from_bytes(curve, sk).map_err(|_| Error::InvalidKey)?;
                let pk =
                    BoxedEcdsaPublicKey::from_sec1(curve, pk).map_err(|_| Error::InvalidKey)?;
                sk.diffie_hellman(&pk).map_err(|_| Error::InvalidDhOutput)
            }
            None => {
                if sk.len() != 32 || pk.len() != 32 {
                    return Err(Error::InvalidKey);
                }
                let mut s = [0u8; 32];
                s.copy_from_slice(sk);
                let mut p = [0u8; 32];
                p.copy_from_slice(pk);
                crate::ec::x25519::X25519PrivateKey::from_bytes(s)
                    .diffie_hellman(&p)
                    .map(|out| out.to_vec())
                    .map_err(|_| Error::InvalidDhOutput)
            }
        }
    }

    /// `DeriveKeyPair(ikm)` (RFC 9180 §7.1.3/§7.1.4): deterministically
    /// derives `(sk, enc_pk)` from `ikm`. For NIST curves this is a
    /// rejection-sample loop bounded at 256 candidates; for X25519 it
    /// is a single HKDF expansion.
    pub(crate) fn derive_key_pair(self, ikm: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let suite_id = kem_suite_id(self.id());
        let kdf = self.kdf();
        let dkp_prk = labeled_extract(kdf, b"", &suite_id, b"dkp_prk", ikm);

        match self.nist_curve() {
            Some(curve) => {
                let n_sk = self.n_sk();
                let bitmask = self.bitmask();

                for counter in 0u16..=255 {
                    let mut bytes = alloc::vec![0u8; n_sk];
                    labeled_expand(
                        kdf,
                        &dkp_prk,
                        &suite_id,
                        b"candidate",
                        &[counter as u8],
                        &mut bytes,
                    );
                    bytes[0] &= bitmask;
                    // BoxedEcdhPrivateKey::from_bytes enforces `1 <= sk < n`;
                    // anything outside the valid scalar range is rejected
                    // here and the loop retries with the next counter.
                    if let Ok(sk) = BoxedEcdhPrivateKey::from_bytes(curve, &bytes) {
                        let pk = sk.public_key().to_sec1();
                        return Ok((bytes, pk));
                    }
                }
                Err(Error::DeriveKeyPair)
            }
            None => {
                let mut sk = alloc::vec![0u8; 32];
                labeled_expand(kdf, &dkp_prk, &suite_id, b"sk", b"", &mut sk);
                let pk = self.pk_from_sk(&sk)?;
                Ok((sk, pk))
            }
        }
    }

    /// `GenerateKeyPair`: draws `ikm = Nsk` random bytes from `rng` and
    /// runs the same `DeriveKeyPair` chain (RFC 9180 §7.1.3/§7.1.4) used
    /// for deterministic key derivation. Returns `(sk, encoded_pk)`.
    pub fn generate_key_pair<R: RngCore>(self, rng: &mut R) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut ikm = alloc::vec![0u8; self.n_sk()];
        rng.fill_bytes(&mut ikm);
        self.derive_key_pair(&ikm)
    }

    /// `ExtractAndExpand(dh, kem_context)` (RFC 9180 §4.1): the DHKEM
    /// internal KDF chain.
    fn extract_and_expand(self, dh: &[u8], kem_context: &[u8]) -> Vec<u8> {
        let suite_id = kem_suite_id(self.id());
        let kdf = self.kdf();
        let eae_prk = labeled_extract(kdf, b"", &suite_id, b"eae_prk", dh);
        let mut shared = alloc::vec![0u8; self.n_secret()];
        labeled_expand(
            kdf,
            &eae_prk,
            &suite_id,
            b"shared_secret",
            kem_context,
            &mut shared,
        );
        shared
    }

    /// `Encap(pkR)`: generates an ephemeral DH key, derives the shared
    /// secret, and returns `(shared_secret, enc)`.
    pub(crate) fn encap<R: RngCore>(
        self,
        rng: &mut R,
        pk_r: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.validate_public_key(pk_r)?;
        let (sk_e, pk_e) = self.generate_key_pair(rng)?;
        let dh = self.dh(&sk_e, pk_r)?;
        let mut kem_context = Vec::with_capacity(pk_e.len() + pk_r.len());
        kem_context.extend_from_slice(&pk_e);
        kem_context.extend_from_slice(pk_r);
        let shared = self.extract_and_expand(&dh, &kem_context);
        Ok((shared, pk_e))
    }

    /// `Decap(enc, skR)`.
    pub(crate) fn decap(self, enc: &[u8], sk_r: &[u8]) -> Result<Vec<u8>, Error> {
        if enc.len() != self.n_enc() {
            return Err(Error::InvalidEnc);
        }
        self.validate_public_key(enc)?;
        let dh = self.dh(sk_r, enc)?;
        let pk_r = self.pk_from_sk(sk_r)?;
        let mut kem_context = Vec::with_capacity(enc.len() + pk_r.len());
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_r);
        Ok(self.extract_and_expand(&dh, &kem_context))
    }

    /// `AuthEncap(pkR, skS)`: like [`encap`](Self::encap) but also
    /// binds the sender's static identity into the shared secret.
    pub(crate) fn auth_encap<R: RngCore>(
        self,
        rng: &mut R,
        pk_r: &[u8],
        sk_s: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        self.validate_public_key(pk_r)?;
        let (sk_e, pk_e) = self.generate_key_pair(rng)?;
        let dh1 = self.dh(&sk_e, pk_r)?;
        let dh2 = self.dh(sk_s, pk_r)?;
        let mut dh = Vec::with_capacity(dh1.len() + dh2.len());
        dh.extend_from_slice(&dh1);
        dh.extend_from_slice(&dh2);
        let pk_s = self.pk_from_sk(sk_s)?;
        let mut kem_context = Vec::with_capacity(pk_e.len() + pk_r.len() + pk_s.len());
        kem_context.extend_from_slice(&pk_e);
        kem_context.extend_from_slice(pk_r);
        kem_context.extend_from_slice(&pk_s);
        let shared = self.extract_and_expand(&dh, &kem_context);
        Ok((shared, pk_e))
    }

    /// `AuthDecap(enc, skR, pkS)`.
    pub(crate) fn auth_decap(self, enc: &[u8], sk_r: &[u8], pk_s: &[u8]) -> Result<Vec<u8>, Error> {
        if enc.len() != self.n_enc() {
            return Err(Error::InvalidEnc);
        }
        self.validate_public_key(enc)?;
        self.validate_public_key(pk_s)?;
        let dh1 = self.dh(sk_r, enc)?;
        let dh2 = self.dh(sk_r, pk_s)?;
        let mut dh = Vec::with_capacity(dh1.len() + dh2.len());
        dh.extend_from_slice(&dh1);
        dh.extend_from_slice(&dh2);
        let pk_r = self.pk_from_sk(sk_r)?;
        let mut kem_context = Vec::with_capacity(enc.len() + pk_r.len() + pk_s.len());
        kem_context.extend_from_slice(enc);
        kem_context.extend_from_slice(&pk_r);
        kem_context.extend_from_slice(pk_s);
        Ok(self.extract_and_expand(&dh, &kem_context))
    }
}
