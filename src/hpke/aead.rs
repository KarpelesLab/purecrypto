//! HPKE AEAD dispatcher: runtime selection of AES-128-GCM,
//! AES-256-GCM, ChaCha20-Poly1305, and the ExportOnly marker
//! (RFC 9180 §7.3).

use super::Error;
use crate::cipher::{Aes128, Aes128Gcm, Aes256, Aes256Gcm, ChaCha20Poly1305, Gcm};
use alloc::vec::Vec;

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
    /// [`SenderContext::export`](super::SenderContext::export) /
    /// [`ReceiverContext::export`](super::ReceiverContext::export) are
    /// available.
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

    /// Encrypts `pt` under `key` and `nonce`, binding `aad`, returning
    /// `ciphertext || tag`.
    pub(crate) fn seal(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match self {
            HpkeAead::Aes128Gcm => {
                if key.len() != 16 || nonce.len() != 12 {
                    return Err(Error::AeadError);
                }
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                let mut buf = pt.to_vec();
                let cipher = Aes128Gcm::new(Aes128::new(&k));
                let tag = cipher.encrypt(nonce, aad, &mut buf);
                buf.extend_from_slice(&tag);
                Ok(buf)
            }
            HpkeAead::Aes256Gcm => {
                if key.len() != 32 || nonce.len() != 12 {
                    return Err(Error::AeadError);
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let mut buf = pt.to_vec();
                let cipher = Aes256Gcm::new(Aes256::new(&k));
                let tag = cipher.encrypt(nonce, aad, &mut buf);
                buf.extend_from_slice(&tag);
                Ok(buf)
            }
            HpkeAead::ChaCha20Poly1305 => {
                if key.len() != 32 || nonce.len() != 12 {
                    return Err(Error::AeadError);
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let mut n = [0u8; 12];
                n.copy_from_slice(nonce);
                let mut buf = pt.to_vec();
                let cipher = ChaCha20Poly1305::new(&k);
                let tag = cipher.encrypt(&n, aad, &mut buf);
                buf.extend_from_slice(&tag);
                Ok(buf)
            }
            HpkeAead::ExportOnly => Err(Error::ExportOnly),
        }
    }

    /// Verifies the trailing 16-byte tag of `ct` against `aad` and, on
    /// success, returns the decrypted plaintext.
    pub(crate) fn open(
        self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ct: &[u8],
    ) -> Result<Vec<u8>, Error> {
        if self == HpkeAead::ExportOnly {
            return Err(Error::ExportOnly);
        }
        let tag_len = self.tag_len();
        if ct.len() < tag_len {
            return Err(Error::AeadError);
        }
        let (body, tag) = ct.split_at(ct.len() - tag_len);
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        match self {
            HpkeAead::Aes128Gcm => {
                if key.len() != 16 || nonce.len() != 12 {
                    return Err(Error::AeadError);
                }
                let mut k = [0u8; 16];
                k.copy_from_slice(key);
                let mut buf = body.to_vec();
                let cipher = Aes128Gcm::new(Aes128::new(&k));
                cipher
                    .decrypt(nonce, aad, &mut buf, &tag_arr)
                    .map_err(|_| Error::AeadError)?;
                Ok(buf)
            }
            HpkeAead::Aes256Gcm => {
                if key.len() != 32 || nonce.len() != 12 {
                    return Err(Error::AeadError);
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let mut buf = body.to_vec();
                let cipher = Aes256Gcm::new(Aes256::new(&k));
                cipher
                    .decrypt(nonce, aad, &mut buf, &tag_arr)
                    .map_err(|_| Error::AeadError)?;
                Ok(buf)
            }
            HpkeAead::ChaCha20Poly1305 => {
                if key.len() != 32 || nonce.len() != 12 {
                    return Err(Error::AeadError);
                }
                let mut k = [0u8; 32];
                k.copy_from_slice(key);
                let mut n = [0u8; 12];
                n.copy_from_slice(nonce);
                let mut buf = body.to_vec();
                let cipher = ChaCha20Poly1305::new(&k);
                cipher
                    .decrypt(&n, aad, &mut buf, &tag_arr)
                    .map_err(|_| Error::AeadError)?;
                Ok(buf)
            }
            HpkeAead::ExportOnly => Err(Error::ExportOnly),
        }
    }

    // Suppress dead-code lint when only some entry points are exercised.
    #[allow(dead_code)]
    pub(crate) const _GCM_REUSE_HINT: Option<Gcm<Aes128>> = None;
}
