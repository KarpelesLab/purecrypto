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
//!
//! # `alloc`
//!
//! X25519 and P-256 run on the crate's fixed-width arithmetic
//! ([`crate::ec::x25519`], [`crate::ec::ecdh`]) and need no allocator; every
//! intermediate here is a stack buffer sized by [`HpkeKem::MAX_N_ENC`] &co.
//! P-384 and P-521 have no fixed-width backend — they go through the
//! heap-backed [`crate::ec::boxed`] path — so those two *variants* only exist
//! when the `alloc` feature is on.

use super::labeled::{labeled_expand, labeled_extract};
use super::suite::kem_suite_id;
use super::{Error, HpkeKdf};
use crate::rng::RngCore;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// HPKE KEM identifiers (RFC 9180 §7.1).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HpkeKem {
    /// `0x0010` — DHKEM(P-256, HKDF-SHA-256).
    DhkemP256HkdfSha256,
    /// `0x0011` — DHKEM(P-384, HKDF-SHA-384). Requires `alloc`: the P-384
    /// group arithmetic is heap-backed.
    #[cfg(feature = "alloc")]
    DhkemP384HkdfSha384,
    /// `0x0012` — DHKEM(P-521, HKDF-SHA-512). Requires `alloc`: the P-521
    /// group arithmetic is heap-backed.
    #[cfg(feature = "alloc")]
    DhkemP521HkdfSha512,
    /// `0x0020` — DHKEM(X25519, HKDF-SHA-256).
    DhkemX25519HkdfSha256,
}

impl HpkeKem {
    /// The largest `Nenc` / `Npk` across the compiled-in KEMs: P-521's
    /// 133-byte SEC1 point with `alloc`, P-256's 65-byte one without.
    ///
    /// A `[u8; MAX_N_ENC]` holds any encapsulated share or encoded public key,
    /// which is what lets `Encap` / `Decap` run on the stack.
    #[cfg(feature = "alloc")]
    pub const MAX_N_ENC: usize = 133;
    /// The largest `Nenc` / `Npk` across the compiled-in KEMs.
    #[cfg(not(feature = "alloc"))]
    pub const MAX_N_ENC: usize = 65;

    /// The largest `Nsk` across the compiled-in KEMs (P-521's 66 bytes with
    /// `alloc`, 32 without).
    pub const MAX_N_SK: usize = if Self::MAX_N_ENC == 133 { 66 } else { 32 };

    /// The largest raw DH output (one field element) across the compiled-in
    /// KEMs. Same width as [`MAX_N_SK`](Self::MAX_N_SK) for every wired curve.
    const MAX_DH: usize = Self::MAX_N_SK;

    /// The IANA-assigned KEM id.
    pub const fn id(self) -> u16 {
        match self {
            HpkeKem::DhkemP256HkdfSha256 => 0x0010,
            #[cfg(feature = "alloc")]
            HpkeKem::DhkemP384HkdfSha384 => 0x0011,
            #[cfg(feature = "alloc")]
            HpkeKem::DhkemP521HkdfSha512 => 0x0012,
            HpkeKem::DhkemX25519HkdfSha256 => 0x0020,
        }
    }

    /// The HKDF function used internally by this DHKEM (independent of
    /// the suite's KDF choice).
    pub const fn kdf(self) -> HpkeKdf {
        match self {
            HpkeKem::DhkemP256HkdfSha256 => HpkeKdf::HkdfSha256,
            #[cfg(feature = "alloc")]
            HpkeKem::DhkemP384HkdfSha384 => HpkeKdf::HkdfSha384,
            #[cfg(feature = "alloc")]
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
            #[cfg(feature = "alloc")]
            HpkeKem::DhkemP384HkdfSha384 => 97,
            #[cfg(feature = "alloc")]
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
            #[cfg(feature = "alloc")]
            HpkeKem::DhkemP384HkdfSha384 => 48,
            #[cfg(feature = "alloc")]
            HpkeKem::DhkemP521HkdfSha512 => 66,
            HpkeKem::DhkemX25519HkdfSha256 => 32,
        }
    }

    /// `bitmask` used by `DeriveKeyPair` for NIST curves. `0x01` on
    /// P-521 (whose order is 521 bits — the top byte carries one bit);
    /// `0xFF` elsewhere. Unused for X25519.
    const fn bitmask(self) -> u8 {
        match self {
            #[cfg(feature = "alloc")]
            HpkeKem::DhkemP521HkdfSha512 => 0x01,
            _ => 0xFF,
        }
    }

    /// Whether this KEM's group is one of the heap-backed NIST curves
    /// (P-384 / P-521), as opposed to the fixed-width P-256 and X25519
    /// backends.
    #[cfg(feature = "alloc")]
    fn boxed_curve(self) -> Option<crate::ec::CurveId> {
        match self {
            HpkeKem::DhkemP384HkdfSha384 => Some(crate::ec::CurveId::P384),
            HpkeKem::DhkemP521HkdfSha512 => Some(crate::ec::CurveId::P521),
            _ => None,
        }
    }

    /// Validates an encoded public key without computing anything else
    /// with it. For NIST curves this enforces SEC1 framing, in-range
    /// coordinates, and on-curve membership (the underlying group is
    /// prime-order, so a co-factor check is unnecessary).
    ///
    /// For X25519 this is **only a length check**: every 32-byte string is a
    /// syntactically valid u-coordinate, so this method intentionally accepts
    /// all of them. Small-order / low-order point rejection is *not* performed
    /// here — it is deferred to [`dh`](Self::dh), which maps an all-zero
    /// shared secret to [`Error::InvalidDhOutput`] per RFC 9180 §7.1.4. Do not
    /// rely on this method alone to reject contributory-behaviour attacks on
    /// the X25519 KEM; the DH step is the security-relevant gate.
    pub(crate) fn validate_public_key(self, pk: &[u8]) -> Result<(), Error> {
        if pk.len() != self.n_pk() {
            return Err(Error::InvalidKey);
        }
        match self {
            HpkeKem::DhkemX25519HkdfSha256 => Ok(()),
            HpkeKem::DhkemP256HkdfSha256 => {
                crate::ec::ecdsa::EcdsaPublicKey::from_sec1(pk).map_err(|_| Error::InvalidKey)?;
                Ok(())
            }
            #[cfg(feature = "alloc")]
            _ => {
                let curve = self.boxed_curve().expect("non-P-256 NIST KEM");
                crate::ec::BoxedEcdsaPublicKey::from_sec1(curve, pk)
                    .map_err(|_| Error::InvalidKey)?;
                Ok(())
            }
        }
    }

    /// `SerializePublicKey(pk(sk))`: derives the encoded public key from the
    /// private scalar `sk` into `out`, returning its length (`Npk`).
    ///
    /// Returns `None` when `sk` is not a valid scalar for this group; the
    /// `DeriveKeyPair` rejection-sampling loop uses that to retry.
    fn try_pk_from_sk(self, sk: &[u8], out: &mut [u8; Self::MAX_N_ENC]) -> Option<usize> {
        if sk.len() != self.n_sk() {
            return None;
        }
        match self {
            HpkeKem::DhkemX25519HkdfSha256 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(sk);
                let pk = crate::ec::x25519::X25519PrivateKey::from_bytes(s);
                super::wipe(&mut s);
                out[..32].copy_from_slice(&pk.public_key());
                Some(32)
            }
            HpkeKem::DhkemP256HkdfSha256 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(sk);
                // `from_bytes` enforces `1 <= sk < n`; an out-of-range scalar
                // is a `DeriveKeyPair` retry, not an error.
                let key = crate::ec::ecdh::EcdhPrivateKey::from_bytes(&s);
                super::wipe(&mut s);
                let sec1 = key.ok()?.public_key().to_sec1();
                out[..65].copy_from_slice(&sec1);
                Some(65)
            }
            #[cfg(feature = "alloc")]
            _ => {
                let curve = self.boxed_curve().expect("non-P-256 NIST KEM");
                let key = crate::ec::boxed::BoxedEcdhPrivateKey::from_bytes(curve, sk).ok()?;
                let sec1 = key.public_key().to_sec1();
                out[..sec1.len()].copy_from_slice(&sec1);
                Some(sec1.len())
            }
        }
    }

    /// `SerializePublicKey(pk(sk))`, with an out-of-range scalar reported as
    /// [`Error::InvalidKey`].
    fn pk_from_sk(self, sk: &[u8], out: &mut [u8; Self::MAX_N_ENC]) -> Result<usize, Error> {
        self.try_pk_from_sk(sk, out).ok_or(Error::InvalidKey)
    }

    /// `DH(sk, pk)`: the curve's Diffie-Hellman primitive. Writes the raw
    /// shared field-element bytes (`field_len` for NIST, 32 for X25519) into
    /// `out` and returns their length. All-zero / identity outputs map to
    /// [`Error::InvalidDhOutput`] per RFC 9180 §7.1.3-§7.1.4.
    fn dh(self, sk: &[u8], pk: &[u8], out: &mut [u8; Self::MAX_DH]) -> Result<usize, Error> {
        if sk.len() != self.n_sk() || pk.len() != self.n_pk() {
            return Err(Error::InvalidKey);
        }
        match self {
            HpkeKem::DhkemX25519HkdfSha256 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(sk);
                let mut p = [0u8; 32];
                p.copy_from_slice(pk);
                let res = crate::ec::x25519::X25519PrivateKey::from_bytes(s).diffie_hellman(&p);
                // `s` is a copy of the private scalar (`from_bytes` takes it by
                // value, and `[u8; 32]` is `Copy`): wipe our copy.
                super::wipe(&mut s);
                let mut shared = res.map_err(|_| Error::InvalidDhOutput)?;
                out[..32].copy_from_slice(&shared);
                super::wipe(&mut shared);
                Ok(32)
            }
            HpkeKem::DhkemP256HkdfSha256 => {
                let mut s = [0u8; 32];
                s.copy_from_slice(sk);
                let key = crate::ec::ecdh::EcdhPrivateKey::from_bytes(&s);
                super::wipe(&mut s);
                let key = key.map_err(|_| Error::InvalidKey)?;
                let peer = crate::ec::ecdsa::EcdsaPublicKey::from_sec1(pk)
                    .map_err(|_| Error::InvalidKey)?;
                let mut shared = key
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::InvalidDhOutput)?;
                out[..32].copy_from_slice(&shared);
                super::wipe(&mut shared);
                Ok(32)
            }
            #[cfg(feature = "alloc")]
            _ => {
                let curve = self.boxed_curve().expect("non-P-256 NIST KEM");
                let key = crate::ec::boxed::BoxedEcdhPrivateKey::from_bytes(curve, sk)
                    .map_err(|_| Error::InvalidKey)?;
                let peer = crate::ec::BoxedEcdsaPublicKey::from_sec1(curve, pk)
                    .map_err(|_| Error::InvalidKey)?;
                let mut shared = key
                    .diffie_hellman(&peer)
                    .map_err(|_| Error::InvalidDhOutput)?;
                out[..shared.len()].copy_from_slice(&shared);
                let n = shared.len();
                super::wipe(&mut shared);
                Ok(n)
            }
        }
    }

    /// `DeriveKeyPair(ikm)` (RFC 9180 §7.1.3/§7.1.4): deterministically
    /// derives `(sk, enc_pk)` from `ikm` into the caller's buffers, returning
    /// `(Nsk, Npk)`. For NIST curves this is a rejection-sample loop bounded
    /// at 256 candidates; for X25519 it is a single HKDF expansion.
    ///
    /// `sk_out` must hold at least [`n_sk`](Self::n_sk) bytes and `pk_out` at
    /// least [`n_pk`](Self::n_pk); the lengths are runtime values because the
    /// KEM is a runtime enum, so the buffers are caller-supplied rather than
    /// fixed-size returns.
    pub fn derive_key_pair_into(
        self,
        ikm: &[u8],
        sk_out: &mut [u8],
        pk_out: &mut [u8],
    ) -> Result<(usize, usize), Error> {
        let n_sk = self.n_sk();
        let n_pk = self.n_pk();
        if sk_out.len() < n_sk || pk_out.len() < n_pk {
            return Err(Error::BufferTooSmall);
        }
        let suite_id = kem_suite_id(self.id());
        let kdf = self.kdf();
        // `dkp_prk` keys every candidate expansion below; its `Drop` wipes it
        // on every exit path, including the error ones.
        let dkp_prk = labeled_extract(kdf, b"", &suite_id, b"dkp_prk", &[ikm]);

        let mut pk_buf = [0u8; Self::MAX_N_ENC];
        if self == HpkeKem::DhkemX25519HkdfSha256 {
            let mut sk = [0u8; 32];
            labeled_expand(kdf, dkp_prk.as_slice(), &suite_id, b"sk", &[], &mut sk);
            let res = self.try_pk_from_sk(&sk, &mut pk_buf);
            match res {
                Some(len) => {
                    sk_out[..32].copy_from_slice(&sk);
                    super::wipe(&mut sk);
                    pk_out[..len].copy_from_slice(&pk_buf[..len]);
                    Ok((32, len))
                }
                None => {
                    super::wipe(&mut sk);
                    Err(Error::InvalidKey)
                }
            }
        } else {
            let bitmask = self.bitmask();
            for counter in 0u16..=255 {
                let mut bytes = [0u8; Self::MAX_N_SK];
                // `counter` bound to a local: an inline temporary would be
                // dropped while still borrowed (E0716) under the MSRV.
                let counter_byte = [counter as u8];
                labeled_expand(
                    kdf,
                    dkp_prk.as_slice(),
                    &suite_id,
                    b"candidate",
                    &[&counter_byte],
                    &mut bytes[..n_sk],
                );
                bytes[0] &= bitmask;
                // `try_pk_from_sk` enforces `1 <= sk < n`; anything outside the
                // valid scalar range is rejected here and the loop retries with
                // the next counter.
                if let Some(len) = self.try_pk_from_sk(&bytes[..n_sk], &mut pk_buf) {
                    sk_out[..n_sk].copy_from_slice(&bytes[..n_sk]);
                    super::wipe(&mut bytes);
                    pk_out[..len].copy_from_slice(&pk_buf[..len]);
                    return Ok((n_sk, len));
                }
                // A rejected candidate is still key-derived material: wipe it
                // rather than letting the stack slot keep the bytes.
                super::wipe(&mut bytes);
            }
            Err(Error::DeriveKeyPair)
        }
    }

    /// `DeriveKeyPair(ikm)`, returning freshly allocated `(sk, encoded_pk)`.
    ///
    /// Convenience wrapper over
    /// [`derive_key_pair_into`](Self::derive_key_pair_into).
    #[cfg(feature = "alloc")]
    pub fn derive_key_pair(self, ikm: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut sk = alloc::vec![0u8; self.n_sk()];
        let mut pk = alloc::vec![0u8; self.n_pk()];
        match self.derive_key_pair_into(ikm, &mut sk, &mut pk) {
            Ok(_) => Ok((sk, pk)),
            Err(e) => {
                super::wipe(&mut sk);
                Err(e)
            }
        }
    }

    /// `GenerateKeyPair`: draws `ikm = Nsk` random bytes from `rng` and
    /// runs the same `DeriveKeyPair` chain (RFC 9180 §7.1.3/§7.1.4) used
    /// for deterministic key derivation, writing `(sk, encoded_pk)` into the
    /// caller's buffers and returning `(Nsk, Npk)`.
    pub fn generate_key_pair_into<R: RngCore>(
        self,
        rng: &mut R,
        sk_out: &mut [u8],
        pk_out: &mut [u8],
    ) -> Result<(usize, usize), Error> {
        let n_sk = self.n_sk();
        let mut ikm = [0u8; Self::MAX_N_SK];
        rng.fill_bytes(&mut ikm[..n_sk]);
        let out = self.derive_key_pair_into(&ikm[..n_sk], sk_out, pk_out);
        // The seed derives the private key: wipe it on every path.
        super::wipe(&mut ikm);
        out
    }

    /// `GenerateKeyPair`, returning freshly allocated `(sk, encoded_pk)`.
    ///
    /// Convenience wrapper over
    /// [`generate_key_pair_into`](Self::generate_key_pair_into).
    #[cfg(feature = "alloc")]
    pub fn generate_key_pair<R: RngCore>(self, rng: &mut R) -> Result<(Vec<u8>, Vec<u8>), Error> {
        let mut ikm = alloc::vec![0u8; self.n_sk()];
        rng.fill_bytes(&mut ikm);
        let out = self.derive_key_pair(&ikm);
        // The seed derives the private key: wipe it on every path.
        super::wipe(&mut ikm);
        out
    }

    /// `ExtractAndExpand(dh, kem_context)` (RFC 9180 §4.1): the DHKEM
    /// internal KDF chain. Both inputs arrive as part sequences so neither
    /// `dh1 ‖ dh2` nor `pkE ‖ pkR ‖ pkS` has to be concatenated into a buffer.
    ///
    /// `shared` must be exactly [`n_secret`](Self::n_secret) bytes — the
    /// length is bound into `LabeledExpand`'s own input.
    fn extract_and_expand(self, dh: &[&[u8]], kem_context: &[&[u8]], shared: &mut [u8]) {
        debug_assert_eq!(shared.len(), self.n_secret());
        let suite_id = kem_suite_id(self.id());
        let kdf = self.kdf();
        let eae_prk = labeled_extract(kdf, b"", &suite_id, b"eae_prk", dh);
        labeled_expand(
            kdf,
            eae_prk.as_slice(),
            &suite_id,
            b"shared_secret",
            kem_context,
            shared,
        );
    }

    /// `Encap(pkR)`: generates an ephemeral DH key, derives the shared
    /// secret into `shared` (exactly `Nsecret` bytes), and writes the
    /// encapsulated share into `enc_out`, returning `Nenc`.
    pub(crate) fn encap_into<R: RngCore>(
        self,
        rng: &mut R,
        pk_r: &[u8],
        shared: &mut [u8],
        enc_out: &mut [u8],
    ) -> Result<usize, Error> {
        self.validate_public_key(pk_r)?;
        if enc_out.len() < self.n_enc() {
            return Err(Error::BufferTooSmall);
        }
        let mut sk_e = [0u8; Self::MAX_N_SK];
        let mut pk_e = [0u8; Self::MAX_N_ENC];
        let (n_sk, n_pk) = self.generate_key_pair_into(rng, &mut sk_e, &mut pk_e)?;
        // Wipe the ephemeral scalar as soon as the DH is done — before
        // propagating any DH failure.
        let mut dh = [0u8; Self::MAX_DH];
        let res = self.dh(&sk_e[..n_sk], pk_r, &mut dh);
        super::wipe(&mut sk_e);
        let n_dh = match res {
            Ok(n) => n,
            Err(e) => {
                super::wipe(&mut dh);
                return Err(e);
            }
        };
        self.extract_and_expand(&[&dh[..n_dh]], &[&pk_e[..n_pk], pk_r], shared);
        super::wipe(&mut dh);
        enc_out[..n_pk].copy_from_slice(&pk_e[..n_pk]);
        Ok(n_pk)
    }

    /// `Decap(enc, skR)`: derives the shared secret into `shared` (exactly
    /// `Nsecret` bytes).
    pub(crate) fn decap_into(
        self,
        enc: &[u8],
        sk_r: &[u8],
        shared: &mut [u8],
    ) -> Result<(), Error> {
        if enc.len() != self.n_enc() {
            return Err(Error::InvalidEnc);
        }
        self.validate_public_key(enc)?;
        // Derive the public key first so no fallible step sits between the
        // DH output's creation and its wipe below.
        let mut pk_r = [0u8; Self::MAX_N_ENC];
        let n_pk = self.pk_from_sk(sk_r, &mut pk_r)?;
        let mut dh = [0u8; Self::MAX_DH];
        let n_dh = match self.dh(sk_r, enc, &mut dh) {
            Ok(n) => n,
            Err(e) => {
                super::wipe(&mut dh);
                return Err(e);
            }
        };
        self.extract_and_expand(&[&dh[..n_dh]], &[enc, &pk_r[..n_pk]], shared);
        super::wipe(&mut dh);
        Ok(())
    }

    /// `AuthEncap(pkR, skS)`: like [`encap_into`](Self::encap_into) but also
    /// binds the sender's static identity into the shared secret.
    pub(crate) fn auth_encap_into<R: RngCore>(
        self,
        rng: &mut R,
        pk_r: &[u8],
        sk_s: &[u8],
        shared: &mut [u8],
        enc_out: &mut [u8],
    ) -> Result<usize, Error> {
        self.validate_public_key(pk_r)?;
        if enc_out.len() < self.n_enc() {
            return Err(Error::BufferTooSmall);
        }
        // Derive the sender's public key first so no fallible step sits
        // between the DH outputs' creation and their wipes below.
        let mut pk_s = [0u8; Self::MAX_N_ENC];
        let n_pk_s = self.pk_from_sk(sk_s, &mut pk_s)?;
        let mut sk_e = [0u8; Self::MAX_N_SK];
        let mut pk_e = [0u8; Self::MAX_N_ENC];
        let (n_sk_e, n_pk_e) = self.generate_key_pair_into(rng, &mut sk_e, &mut pk_e)?;

        // `dh` holds `dh1 ‖ dh2` back to back so a single wipe covers both.
        let mut dh1 = [0u8; Self::MAX_DH];
        let mut dh2 = [0u8; Self::MAX_DH];
        // Wipe the ephemeral scalar as soon as the DH is done — before
        // propagating any DH failure.
        let res = self.dh(&sk_e[..n_sk_e], pk_r, &mut dh1);
        super::wipe(&mut sk_e);
        let n_dh = match res {
            Ok(n) => n,
            Err(e) => {
                super::wipe(&mut dh1);
                return Err(e);
            }
        };
        if let Err(e) = self.dh(sk_s, pk_r, &mut dh2) {
            super::wipe(&mut dh1);
            super::wipe(&mut dh2);
            return Err(e);
        }
        self.extract_and_expand(
            &[&dh1[..n_dh], &dh2[..n_dh]],
            &[&pk_e[..n_pk_e], pk_r, &pk_s[..n_pk_s]],
            shared,
        );
        super::wipe(&mut dh1);
        super::wipe(&mut dh2);
        enc_out[..n_pk_e].copy_from_slice(&pk_e[..n_pk_e]);
        Ok(n_pk_e)
    }

    /// `AuthDecap(enc, skR, pkS)`.
    pub(crate) fn auth_decap_into(
        self,
        enc: &[u8],
        sk_r: &[u8],
        pk_s: &[u8],
        shared: &mut [u8],
    ) -> Result<(), Error> {
        if enc.len() != self.n_enc() {
            return Err(Error::InvalidEnc);
        }
        self.validate_public_key(enc)?;
        self.validate_public_key(pk_s)?;
        // Derive the public key first so no fallible step sits between the
        // DH outputs' creation and their wipes below.
        let mut pk_r = [0u8; Self::MAX_N_ENC];
        let n_pk_r = self.pk_from_sk(sk_r, &mut pk_r)?;
        let mut dh1 = [0u8; Self::MAX_DH];
        let mut dh2 = [0u8; Self::MAX_DH];
        let n_dh = match self.dh(sk_r, enc, &mut dh1) {
            Ok(n) => n,
            Err(e) => {
                super::wipe(&mut dh1);
                return Err(e);
            }
        };
        if let Err(e) = self.dh(sk_r, pk_s, &mut dh2) {
            super::wipe(&mut dh1);
            super::wipe(&mut dh2);
            return Err(e);
        }
        self.extract_and_expand(
            &[&dh1[..n_dh], &dh2[..n_dh]],
            &[enc, &pk_r[..n_pk_r], pk_s],
            shared,
        );
        super::wipe(&mut dh1);
        super::wipe(&mut dh2);
        Ok(())
    }
}
