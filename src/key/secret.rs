//! Zeroize-on-drop container for secret output bytes.

use alloc::vec::Vec;

/// A heap buffer of secret bytes that is wiped when dropped.
///
/// Returned by the operations that produce raw secret material — key agreement
/// ([`PrivateKey::make_secret`](crate::key::PrivateKey::make_secret)),
/// decryption ([`PrivateKey::decrypt`](crate::key::PrivateKey::decrypt)), and
/// KEM decapsulation ([`Decapsulator::decapsulate`](crate::key::Decapsulator::decapsulate))
/// — so the plaintext/shared-secret does not linger on the heap after use.
///
/// The wipe is the same `core::hint::black_box`-guarded zeroing the rest of the
/// crate uses; it is best-effort (the compiler/allocator may still have copied
/// the bytes), not a guarantee against a determined attacker with memory access.
pub struct Secret {
    bytes: Vec<u8>,
}

impl Secret {
    /// Wraps `bytes` as a zeroize-on-drop secret.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrows the secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The length of the secret in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Consumes the wrapper and returns the raw bytes.
    ///
    /// The wiping `Drop` no longer protects the buffer once it is handed out;
    /// the caller owns the secret and is responsible for clearing it.
    pub fn into_bytes(mut self) -> Vec<u8> {
        // `Secret` implements `Drop`, so the field cannot be moved out directly
        // (E0509). Swap the buffer out and let the now-empty `self` drop.
        core::mem::take(&mut self.bytes)
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(&self.bytes);
    }
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print the contents — only the length, to avoid leaking secrets
        // into logs.
        f.debug_struct("Secret")
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
