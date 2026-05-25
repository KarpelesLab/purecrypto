//! Random number generation.
//!
//! [`RngCore`] is the byte-source interface; [`CryptoRng`] marks generators
//! that are cryptographically secure. [`HmacDrbg`] is a deterministic
//! SP 800-90A generator built on our HMAC, and (on Unix with `std`) [`OsRng`]
//! draws directly from the operating system's entropy pool.

mod hmac_drbg;

pub use hmac_drbg::HmacDrbg;

/// A source of random bytes.
pub trait RngCore {
    /// Fills `dest` entirely with random bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]);

    /// Returns the next random `u32` (little-endian from [`fill_bytes`]).
    #[inline]
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    /// Returns the next random `u64` (little-endian from [`fill_bytes`]).
    #[inline]
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
}

/// Marker for generators that are cryptographically secure — suitable for keys,
/// nonces, and other secret material.
///
/// This is a promise about the implementation, not something the type system
/// can verify; do not implement it for non-CSPRNGs.
pub trait CryptoRng {}

/// Operating-system entropy source.
///
/// Reads from `/dev/urandom`. Available on Unix targets with the `std` feature.
#[cfg(all(feature = "std", unix))]
#[derive(Debug, Clone, Copy, Default)]
pub struct OsRng;

#[cfg(all(feature = "std", unix))]
impl RngCore for OsRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        use std::io::Read;
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(dest))
            .expect("failed to read entropy from /dev/urandom");
    }
}

#[cfg(all(feature = "std", unix))]
impl CryptoRng for OsRng {}

#[cfg(all(test, feature = "std", unix))]
mod tests {
    use super::*;

    #[test]
    fn os_rng_fills_and_varies() {
        let mut rng = OsRng;
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut a);
        rng.fill_bytes(&mut b);
        // Astronomically unlikely to be all-zero or identical.
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }
}
