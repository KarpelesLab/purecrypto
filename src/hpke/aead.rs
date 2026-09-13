//! HPKE AEAD dispatcher: runtime selection of AES-128-GCM,
//! AES-256-GCM, ChaCha20-Poly1305, and the ExportOnly marker
//! (RFC 9180 §7.3).

use super::Error;
use crate::cipher::{Aes128, Aes128Gcm, Aes256, Aes256Gcm, ChaCha20Poly1305};

/// HPKE AEAD identifiers (RFC 9180 §7.3).
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HpkeAead {
    /// `0x0001` — AES-128-GCM.
    Aes128Gcm,
    /// `0x0002` — AES-256-GCM.
    Aes256Gcm,
    /// `0x0003` — ChaCha20-Poly1305.
    ChaCha20Poly1305,
    /// `0xFFFF` — Export-Only: `seal`/`open` are unsupported; only
    /// [`SenderContext::export`][super::SenderContext::export] /
    /// [`ReceiverContext::export`][super::ReceiverContext::export] are
    /// available.
    #[cfg_attr(
        not(feature = "alloc"),
        doc = "",
        doc = "[super::SenderContext::export]: crate::hpke#alloc",
        doc = "[super::ReceiverContext::export]: crate::hpke#alloc"
    )]
    ExportOnly,
}

impl HpkeAead {
    /// The IANA-assigned AEAD id.
    pub const fn id(self) -> u16 {
        match self {
            HpkeAead::Aes128Gcm => 0x0001,
            HpkeAead::Aes256Gcm => 0x0002,
            HpkeAead::ChaCha20Poly1305 => 0x0003,
            HpkeAead::ExportOnly => 0xFFFF,
        }
    }

    /// `Nk`: AEAD key length in bytes.
    pub const fn key_len(self) -> usize {
        match self {
            HpkeAead::Aes128Gcm => 16,
            HpkeAead::Aes256Gcm => 32,
            HpkeAead::ChaCha20Poly1305 => 32,
            HpkeAead::ExportOnly => 0,
        }
    }

    /// `Nn`: AEAD nonce length in bytes. Always 12 for the wired
    /// algorithms (RFC 9180 §7.3).
    pub const fn nonce_len(self) -> usize {
        match self {
            HpkeAead::Aes128Gcm | HpkeAead::Aes256Gcm | HpkeAead::ChaCha20Poly1305 => 12,
            HpkeAead::ExportOnly => 0,
        }
    }

    /// `Nt`: AEAD tag length in bytes. Always 16 for the wired
    /// algorithms.
    pub const fn tag_len(self) -> usize {
        match self {
            HpkeAead::ExportOnly => 0,
            _ => 16,
        }
    }

    /// Whether this AEAD supports `seal`/`open` (false for
    /// [`HpkeAead::ExportOnly`]).
    pub const fn is_export_only(self) -> bool {
        matches!(self, HpkeAead::ExportOnly)
    }

    /// Encrypts `pt` under `key` and `nonce`, binding `aad`, writing
    /// `ciphertext || tag` into `out` and returning its length
    /// (`pt.len() + Nt`).
    ///
    /// The AEADs encrypt in place, so `pt` is copied into `out` first; `out`
    /// may be longer than needed (the tail is left untouched).
    pub(crate) fn seal(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if self == HpkeAead::ExportOnly {
            return Err(Error::ExportOnly);
        }
        let tag_len = self.tag_len();
        let total = pt.len().checked_add(tag_len).ok_or(Error::BufferTooSmall)?;
        if out.len() < total {
            return Err(Error::BufferTooSmall);
        }
        if key.len() != self.key_len() || nonce.len() != self.nonce_len() {
            return Err(Error::AeadError);
        }
        let (body, tag_out) = out[..total].split_at_mut(pt.len());
        body.copy_from_slice(pt);
        let tag = match self {
            HpkeAead::Aes128Gcm => {
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                let cipher = Aes128Gcm::new(Aes128::new(&k));
                super::wipe(&mut k);
                cipher.encrypt(nonce, aad, body)
            }
            HpkeAead::Aes256Gcm => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let cipher = Aes256Gcm::new(Aes256::new(&k));
                super::wipe(&mut k);
                cipher.encrypt(nonce, aad, body)
            }
            HpkeAead::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let mut n = [0u8; 12];
                n.copy_from_slice(nonce);
                let cipher = ChaCha20Poly1305::new(&k);
                super::wipe(&mut k);
                cipher.encrypt(&n, aad, body)
            }
            // Rejected above; repeated so the match stays exhaustive.
            HpkeAead::ExportOnly => return Err(Error::ExportOnly),
        };
        tag_out.copy_from_slice(&tag);
        Ok(total)
    }

    /// Verifies the trailing 16-byte tag of `ct` against `aad` and, on
    /// success, writes the plaintext into `out` and returns its length
    /// (`ct.len() - Nt`).
    ///
    /// When the tag does not verify, `out[..ct.len() - Nt]` is left holding
    /// the *ciphertext* (the in-place decryptions leave it untouched, or
    /// restore it, on a tag mismatch) — never unauthenticated plaintext.
    pub(crate) fn open(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if self == HpkeAead::ExportOnly {
            return Err(Error::ExportOnly);
        }
        let tag_len = self.tag_len();
        if ct.len() < tag_len {
            return Err(Error::AeadError);
        }
        let (body, tag) = ct.split_at(ct.len() - tag_len);
        if out.len() < body.len() {
            return Err(Error::BufferTooSmall);
        }
        if key.len() != self.key_len() || nonce.len() != self.nonce_len() {
            return Err(Error::AeadError);
        }
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        let buf = &mut out[..body.len()];
        buf.copy_from_slice(body);
        let res = match self {
            HpkeAead::Aes128Gcm => {
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                let cipher = Aes128Gcm::new(Aes128::new(&k));
                super::wipe(&mut k);
                cipher.decrypt(nonce, aad, buf, &tag_arr)
            }
            HpkeAead::Aes256Gcm => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let cipher = Aes256Gcm::new(Aes256::new(&k));
                super::wipe(&mut k);
                cipher.decrypt(nonce, aad, buf, &tag_arr)
            }
            HpkeAead::ChaCha20Poly1305 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let mut n = [0u8; 12];
                n.copy_from_slice(nonce);
                let cipher = ChaCha20Poly1305::new(&k);
                super::wipe(&mut k);
                cipher.decrypt(&n, aad, buf, &tag_arr)
            }
            // Rejected above; repeated so the match stays exhaustive.
            HpkeAead::ExportOnly => return Err(Error::ExportOnly),
        };
        res.map_err(|_| Error::AeadError)?;
        Ok(body.len())
    }
}
