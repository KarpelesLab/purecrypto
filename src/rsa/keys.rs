//! RSA key types, key generation, and the raw modular-exponentiation
//! primitive.
//!
//! Keys are parameterized by the modulus width in 64-bit limbs (`LIMBS`), so a
//! 2048-bit modulus is `LIMBS = 32`. The two prime factors are each half that
//! width, and all key values (`n`, `e`, `d`, `p`, `q`) are stored as
//! `Uint<LIMBS>`.

use super::random_prime;
use crate::bignum::{MontModulus, Uint, inv_mod};
use crate::rng::RngCore;

/// An RSA public key `(n, e)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPublicKey<const LIMBS: usize> {
    n: Uint<LIMBS>,
    e: Uint<LIMBS>,
}

/// An RSA private key. Holds the private exponent `d` and the primes `p`, `q`.
///
/// Does not implement `Debug` — it would expose secret material.
#[derive(Clone)]
pub struct RsaPrivateKey<const LIMBS: usize> {
    n: Uint<LIMBS>,
    e: Uint<LIMBS>,
    d: Uint<LIMBS>,
    p: Uint<LIMBS>,
    q: Uint<LIMBS>,
}

impl<const LIMBS: usize> RsaPublicKey<LIMBS> {
    /// Creates a public key from a modulus and exponent.
    pub fn new(n: Uint<LIMBS>, e: Uint<LIMBS>) -> Self {
        RsaPublicKey { n, e }
    }

    /// The modulus `n`.
    #[inline]
    pub fn modulus(&self) -> &Uint<LIMBS> {
        &self.n
    }

    /// The public exponent `e`.
    #[inline]
    pub fn exponent(&self) -> &Uint<LIMBS> {
        &self.e
    }

    /// The raw RSA public operation `m^e mod n` (encryption / signature
    /// verification primitive). `m` must be less than `n`.
    pub fn raw(&self, m: &Uint<LIMBS>) -> Uint<LIMBS> {
        MontModulus::new(self.n).pow(m, &self.e)
    }
}

impl<const LIMBS: usize> RsaPrivateKey<LIMBS> {
    /// Generates an RSA key pair with an `LIMBS * 64`-bit modulus and the given
    /// public exponent `e` (commonly 65537).
    ///
    /// `rounds` is the number of Miller-Rabin rounds per prime candidate. Key
    /// generation uses a non-constant-time modular inverse (see
    /// [`inv_mod`](crate::bignum::inv_mod)).
    pub fn generate<R: RngCore>(e: Uint<LIMBS>, rng: &mut R, rounds: usize) -> Self {
        let half_bits = LIMBS * 32;
        loop {
            let p = random_prime::<LIMBS, R>(rng, half_bits, rounds);
            let q = random_prime::<LIMBS, R>(rng, half_bits, rounds);
            if p == q {
                continue;
            }

            let n = p.mul_wide(&q).0; // p, q are half-width, so n fits in LIMBS
            let phi = p
                .wrapping_sub(&Uint::ONE)
                .mul_wide(&q.wrapping_sub(&Uint::ONE))
                .0;

            // d = e^-1 mod φ(n); retry if e is not coprime to φ.
            if let Some(d) = inv_mod(&e, &phi) {
                return RsaPrivateKey { n, e, d, p, q };
            }
        }
    }

    /// Constructs a private key from raw components, without the prime factors
    /// `p`/`q` (so CRT-based speedups are unavailable). Useful for importing an
    /// existing key.
    pub fn from_components(n: Uint<LIMBS>, e: Uint<LIMBS>, d: Uint<LIMBS>) -> Self {
        RsaPrivateKey {
            n,
            e,
            d,
            p: Uint::ZERO,
            q: Uint::ZERO,
        }
    }

    /// The public half of this key pair.
    pub fn public_key(&self) -> RsaPublicKey<LIMBS> {
        RsaPublicKey {
            n: self.n,
            e: self.e,
        }
    }

    /// The modulus `n`.
    #[inline]
    pub fn modulus(&self) -> &Uint<LIMBS> {
        &self.n
    }

    /// The two prime factors `(p, q)`.
    #[inline]
    pub fn primes(&self) -> (&Uint<LIMBS>, &Uint<LIMBS>) {
        (&self.p, &self.q)
    }

    /// The public exponent `e`.
    #[inline]
    pub fn exponent(&self) -> &Uint<LIMBS> {
        &self.e
    }

    /// The private exponent `d`.
    #[inline]
    pub fn private_exponent(&self) -> &Uint<LIMBS> {
        &self.d
    }

    /// Constructs a private key from all components, including the primes.
    /// Used by key deserialization.
    pub(crate) fn from_raw_parts(
        n: Uint<LIMBS>,
        e: Uint<LIMBS>,
        d: Uint<LIMBS>,
        p: Uint<LIMBS>,
        q: Uint<LIMBS>,
    ) -> Self {
        RsaPrivateKey { n, e, d, p, q }
    }

    /// The raw RSA private operation `c^d mod n` (decryption / signing
    /// primitive).
    pub fn raw(&self, c: &Uint<LIMBS>) -> Uint<LIMBS> {
        MontModulus::new(self.n).pow(c, &self.d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn rng() -> HmacDrbg<Sha256> {
        HmacDrbg::new(b"rsa-keygen-test", b"nonce", &[])
    }

    // Generating a real RSA-2048 key is fast in release (~0.6s) but slow in an
    // unoptimized debug test build, so this is ignored by default. Run it with
    //   cargo test --release -- --ignored
    // Day-to-day RSA tests use the fixed embedded 2048-bit keys instead.
    #[test]
    #[ignore = "slow in debug; run with --release --ignored"]
    fn keygen_roundtrip_rsa2048() {
        let mut r = rng();
        let e = Uint::<32>::from_u64(65537);
        let key = RsaPrivateKey::<32>::generate(e, &mut r, 16);
        let pubkey = key.public_key();

        assert!(bool::from(key.modulus().is_odd()));
        assert_eq!(pubkey.exponent(), &e);
        assert_eq!(key.modulus().bit_len(), 2048);

        // Encrypt/decrypt round-trips, confirming d = e^-1 mod φ(n) is correct.
        let m = Uint::<32>::from_u64(0x0123_4567_89ab_cdef);
        let c = pubkey.raw(&m);
        assert_ne!(c, m);
        assert_eq!(key.raw(&c), m);
    }
}
