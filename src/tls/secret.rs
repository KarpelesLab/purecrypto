//! [`Secret32`]: a 32-byte symmetric secret that wipes itself on drop.

use crate::ct::{Choice, ConstantTimeEq};
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// A 32-byte symmetric secret held by a [`Config`](super::Config) (the
/// session-ticket key, the DTLS cookie secrets) or a
/// `QuicConfig` (the `quic` feature's retry secret), wiped when
/// dropped.
///
/// A bare `[u8; 32]` field is `Copy` and is never cleared, so a dropped or
/// reassigned config used to leave its long-lived keys behind in freed
/// memory. This wrapper is the same 32 bytes with a [`Drop`] that zeroizes
/// them (through [`zeroize`](crate::zeroize), with the caveats documented
/// there), a [`Debug`](core::fmt::Debug) that never prints them, and
/// constant-time equality.
///
/// Build one with `From<[u8; 32]>` — every builder method that takes a
/// secret accepts either form:
///
/// ```
/// use purecrypto::tls::{Config, Secret32};
///
/// let key: Secret32 = [0x42u8; 32].into();
/// let cfg = Config::builder().ticket_key(key.clone()).build();
/// assert_eq!(cfg.ticket_key, Some(key));
/// // Or straight from the array:
/// let cfg = Config::builder().ticket_key([0x42u8; 32]).build();
/// assert_eq!(format!("{:?}", cfg.ticket_key), "Some(Secret32([REDACTED]))");
/// ```
///
/// Passing an array literal or a stack array copies it: the caller's copy is
/// not wiped by this type, so callers that fill a stack buffer from an RNG
/// should zeroize it after handing it over (or fill a `Secret32` directly via
/// [`as_mut_bytes`](Self::as_mut_bytes)).
#[cfg_attr(not(feature = "quic"), doc = "", doc = "[`QuicConfig`]: crate")]
#[derive(Clone)]
pub struct Secret32([u8; 32]);

impl Secret32 {
    /// Wraps `bytes`. Equivalent to `Secret32::from(bytes)`.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// An all-zero secret to be filled in place through
    /// [`as_mut_bytes`](Self::as_mut_bytes), so the material never exists
    /// outside a wiping container:
    ///
    /// ```
    /// # #[cfg(feature = "std")] {
    /// use purecrypto::rng::{OsRng, RngCore};
    /// use purecrypto::tls::Secret32;
    ///
    /// let mut secret = Secret32::zeroed();
    /// OsRng.fill_bytes(secret.as_mut_bytes());
    /// # }
    /// ```
    pub const fn zeroed() -> Self {
        Self([0u8; 32])
    }

    /// Borrows the secret bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Mutably borrows the secret bytes (to fill them from an RNG, say).
    pub fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }
}

impl From<[u8; 32]> for Secret32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8; 32]> for Secret32 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Zeroize for Secret32 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Secret32 {}

impl ConstantTimeEq for Secret32 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Secret32 {
    /// Constant-time comparison (see [`ConstantTimeEq`]).
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for Secret32 {}

impl core::fmt::Debug for Secret32 {
    /// Always prints `Secret32([REDACTED])`, never the contents.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Secret32([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::Config;
    use alloc::format;

    /// The wrapper wipes through the crate's `Zeroize`, which is what its
    /// `Drop` runs; and it is a type the compiler runs a destructor for at
    /// all (a plain `[u8; 32]` is not).
    #[test]
    fn zeroizes_and_drops() {
        assert!(core::mem::needs_drop::<Secret32>());
        assert!(!core::mem::needs_drop::<[u8; 32]>());
        fn wipes_on_drop<T: ZeroizeOnDrop>() {}
        wipes_on_drop::<Secret32>();

        let mut s = Secret32::from([0xA5u8; 32]);
        assert_eq!(s.as_bytes(), &[0xA5u8; 32]);
        s.zeroize();
        assert_eq!(s.as_bytes(), &[0u8; 32]);

        // `Option<Secret32>` wipes to `None` like any other zeroizable option.
        let mut o = Some(Secret32::new([0x11u8; 32]));
        o.zeroize();
        assert!(o.is_none());
    }

    #[test]
    fn debug_is_redacted_and_eq_is_by_value() {
        let a = Secret32::from([0x42u8; 32]);
        let b = a.clone();
        let c = Secret32::from([0x43u8; 32]);
        assert_eq!(format!("{a:?}"), "Secret32([REDACTED])");
        assert!(!format!("{a:?}").contains("66"));
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert!(bool::from(a.ct_eq(&b)));
        assert!(bool::from(a.ct_ne(&c)));
        let mut z = Secret32::zeroed();
        z.as_mut_bytes()[0] = 1;
        assert_eq!(z.as_ref()[0], 1);
    }

    /// `Config` has no `Drop` of its own (so struct-update syntax keeps
    /// working); the secrets wipe because the field type does.
    #[test]
    fn config_struct_update_still_compiles_and_secrets_are_wrapped() {
        let cfg = Config {
            ticket_key: Some([0x5a; 32].into()),
            cookie_secret: Some(Secret32::new([0x01; 32])),
            ..Config::default()
        };
        assert_eq!(cfg.ticket_key, Some(Secret32::from([0x5a; 32])));
        assert_eq!(cfg.cookie_secret.as_ref().map(|s| s.as_bytes()[0]), Some(1));
        assert!(cfg.previous_cookie_secret.is_none());
        let via_builder = Config::builder()
            .ticket_key([0x5a; 32])
            .cookie_secret(Secret32::from([0x01; 32]))
            .previous_cookie_secret([0x02; 32])
            .build();
        assert_eq!(via_builder.ticket_key, cfg.ticket_key);
        assert_eq!(via_builder.cookie_secret, cfg.cookie_secret);
        assert_eq!(
            via_builder.previous_cookie_secret,
            Some([0x02u8; 32].into())
        );
        assert!(!core::mem::needs_drop::<u8>());
    }
}
