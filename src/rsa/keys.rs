//! RSA key types, key generation, and the raw modular-exponentiation
//! primitive.
//!
//! Keys are parameterized by the modulus width in 64-bit limbs (`LIMBS`), so a
//! 2048-bit modulus is `LIMBS = 32`. The two prime factors are each half that
//! width, and all key values (`n`, `e`, `d`, `p`, `q`) are stored as
//! `Uint<LIMBS>`.

use super::random_prime;
use crate::bignum::{MontModulus, Uint, inv_mod};
use crate::ct::{ConstantTimeEq, ConstantTimeLess};
use crate::hash::{Digest, Sha256};
use crate::rng::{CryptoRng, RngCore};

/// An RSA public key `(n, e)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RsaPublicKey<const LIMBS: usize> {
    n: Uint<LIMBS>,
    e: Uint<LIMBS>,
}

/// An RSA private key. Holds the private exponent `d` and the primes `p`, `q`.
///
/// Does not implement `Debug` — it would expose secret material.
///
/// # Side-channel protection
///
/// The raw private operation applies *base blinding* (RSA-OAEP-Coron 1999):
/// each call multiplies the input by a per-call random-looking blinder `r^e`,
/// performs the secret exponentiation on the masked value, then strips the
/// blinder with `r^{-1}`. The blinder `r` is derived deterministically from a
/// key-bound HMAC keyed by a digest of the secret exponent — so two callers
/// querying the same ciphertext see the same blinder, but the blinder is
/// unpredictable to an external attacker, defeating Bleichenbacher- /
/// Manger-style chosen-ciphertext timing attacks and most cache-timing leaks.
///
/// Blinding requires φ(n), which is only known when the key was generated
/// here (so `p`, `q` are non-zero). Keys imported via
/// [`from_components`](Self::from_components) carry `phi_n = 0` and fall back
/// to unblinded exponentiation — document this when accepting external keys.
#[derive(Clone)]
pub struct RsaPrivateKey<const LIMBS: usize> {
    n: Uint<LIMBS>,
    e: Uint<LIMBS>,
    d: Uint<LIMBS>,
    p: Uint<LIMBS>,
    q: Uint<LIMBS>,
    /// `(p−1)·(q−1) − 1` — the Fermat exponent for `r^{-1} mod n` when blinding
    /// is enabled. Zero when `p` or `q` is unknown.
    phi_n_minus_1: Uint<LIMBS>,
    /// HMAC-SHA256 key for deriving per-call blinding values. Derived once at
    /// key construction from `d` (so it never changes for a given key) and used
    /// only as the HMAC key — the input is the ciphertext bytes.
    blinding_seed: [u8; 32],
}

/// Computes `phi(n) − 1` from the prime factors and the derived HMAC seed.
/// Returns `(phi_n_minus_1, seed)`. `phi_n_minus_1` is zero when either prime
/// is zero (then blinding is disabled).
fn derive_blinding<const LIMBS: usize>(
    p: &Uint<LIMBS>,
    q: &Uint<LIMBS>,
    d: &Uint<LIMBS>,
) -> (Uint<LIMBS>, [u8; 32]) {
    let p_is_zero = bool::from(p.ct_eq(&Uint::ZERO));
    let q_is_zero = bool::from(q.ct_eq(&Uint::ZERO));
    let phi_n_minus_1 = if p_is_zero || q_is_zero {
        Uint::ZERO
    } else {
        // φ(n) = (p−1)·(q−1); we want φ(n) − 1 as a fixed-width Uint<LIMBS>.
        // Both primes are bounded by n.sqrt(), so the product fits in LIMBS
        // limbs (mul_wide.0 is the low half of the full 2·LIMBS-limb product).
        let pm1 = p.wrapping_sub(&Uint::ONE);
        let qm1 = q.wrapping_sub(&Uint::ONE);
        let phi = pm1.mul_wide(&qm1).0;
        phi.wrapping_sub(&Uint::ONE)
    };

    // Blinding-key derivation: SHA-256 over a domain separator and d's bytes.
    // The result is opaque to anyone without `d`; it then keys an HMAC whose
    // input is the ciphertext, yielding a unique-per-ciphertext blinder.
    let mut h = Sha256::new();
    h.update(b"purecrypto-rsa-blinding-seed-v1");
    // Stream `d` limb-by-limb (BE) so we don't need a const-generic stack
    // buffer of `LIMBS * 8` bytes.
    for i in 0..LIMBS {
        let limb_bytes = d.as_limbs()[LIMBS - 1 - i].to_be_bytes();
        h.update(&limb_bytes);
    }
    let digest = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(digest.as_ref());
    (phi_n_minus_1, seed)
}

/// Performs the raw RSA private operation with base blinding (Coron's variant
/// of Kocher / Messerges blinding):
///
/// ```text
///   r        = HMAC-SHA256(blinding_seed, c)    // reduced mod n
///   r_e      = r^e mod n                        // public exponent, cheap
///   r_inv    = r^{φ(n)-1} mod n                 // Fermat inverse, constant time
///   c_blind  = (c · r_e) mod n
///   m_blind  = c_blind^d mod n
///   m        = (m_blind · r_inv) mod n
/// ```
///
/// When `phi_n_minus_1` is zero (key imported without primes), the function
/// falls back to the unblinded `c^d mod n`.
fn raw_private_blinded<const LIMBS: usize>(
    n: &Uint<LIMBS>,
    e: &Uint<LIMBS>,
    d: &Uint<LIMBS>,
    phi_n_minus_1: &Uint<LIMBS>,
    blinding_seed: &[u8; 32],
    c: &Uint<LIMBS>,
) -> Uint<LIMBS> {
    use crate::hash::HmacSha256;

    let modulus = MontModulus::new(*n);

    if bool::from(phi_n_minus_1.ct_eq(&Uint::ZERO)) {
        // Imported key without primes — no φ(n) to drive Fermat. Fall back to
        // the plain constant-time ladder; the caller is responsible for
        // upstream blinding if they need it (see struct docs).
        return modulus.pow(c, d);
    }

    // Derive blinder limbs directly from HMAC-SHA256 output, no heap.
    // Each HMAC call yields 32 bytes; we walk the modulus's limbs from MSB
    // downward and fill 4 limbs per chunk, advancing a counter so successive
    // chunks are independent. The blinder is wider than `n.bit_len()` by up to
    // 64 bits, so the subsequent `reduce(n)` has bias ≤ 2⁻⁶⁴ — negligible
    // because the blinder is not a secret key, only a per-call masking value.
    let mut r_limbs = [0u64; LIMBS];
    let mut counter: u32 = 0;
    let mut limbs_remaining = LIMBS;
    while limbs_remaining > 0 {
        let mut m = HmacSha256::new(blinding_seed);
        m.update(b"r");
        m.update(&counter.to_be_bytes());
        // Stream the ciphertext limb-by-limb (BE) into the HMAC.
        for i in 0..LIMBS {
            let limb_bytes = c.as_limbs()[LIMBS - 1 - i].to_be_bytes();
            m.update(&limb_bytes);
        }
        let tag = m.finalize();
        let tag_bytes = tag.as_ref();
        // Each HMAC tag is 32 bytes = 4 u64 limbs. The high-order limbs go
        // first in `r_limbs` (we fill from the top down so the blinder spans
        // the full width of the modulus).
        for j in 0..4 {
            if limbs_remaining == 0 {
                break;
            }
            limbs_remaining -= 1;
            let off = j * 8;
            let bytes: [u8; 8] = tag_bytes[off..off + 8]
                .try_into()
                .expect("HMAC-SHA256 emits 32 bytes");
            r_limbs[limbs_remaining] = u64::from_be_bytes(bytes);
        }
        counter += 1;
    }
    let r_raw = Uint::<LIMBS>::from_limbs(r_limbs);
    let r = r_raw.reduce(n);
    // If r happens to be 0 or 1, the blinder degenerates (no effective masking).
    // In that astronomically rare case, fall back to r = 2 (still coprime to n
    // with probability 1 − negligible). This keeps the function total.
    let r_is_zero = r.ct_eq(&Uint::ZERO);
    let r_is_one = r.ct_eq(&Uint::ONE);
    let bad = r_is_zero | r_is_one;
    let r = <Uint<LIMBS> as crate::ct::ConditionallySelectable>::conditional_select(
        &Uint::from_u64(2),
        &r,
        bad,
    );

    let r_e = modulus.pow(&r, e);
    let r_inv = modulus.pow(&r, phi_n_minus_1);
    let c_blind = modulus.mul_mod(c, &r_e);
    let m_blind = modulus.pow(&c_blind, d);
    modulus.mul_mod(&m_blind, &r_inv)
}

impl<const LIMBS: usize> RsaPublicKey<LIMBS> {
    /// Creates a public key from a modulus and exponent.
    ///
    /// This constructor performs **no validation** — it is intended for
    /// components that are already trusted (e.g. produced by
    /// [`RsaPrivateKey::generate`]). Untrusted input (anything parsed from a
    /// certificate, SPKI, key file, or the network) must go through the
    /// fallible parsers instead — [`Self::from_pkcs1_der`] /
    /// [`Self::from_spki_der`] — which reject a zero/even modulus and a
    /// degenerate exponent before a key is built.
    ///
    /// # Panics
    /// A key built here with an even (or zero) modulus does not panic
    /// immediately, but every subsequent public operation
    /// ([`Self::raw`], `verify_*`, `encrypt_*`) will panic in
    /// `MontModulus::new`, which requires an odd modulus.
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
    ///
    /// # Panics
    /// Panics if the modulus is even or zero (Montgomery arithmetic requires
    /// an odd modulus). Keys obtained from the fallible parsers
    /// ([`Self::from_pkcs1_der`] / [`Self::from_spki_der`]) are pre-validated
    /// and never trip this; only a key assembled from unchecked components
    /// via [`Self::new`] can.
    pub fn raw(&self, m: &Uint<LIMBS>) -> Uint<LIMBS> {
        // `e` is public, so use the public-exponent ladder (~17 squarings for
        // e = 65537) rather than the secret-width constant-time `pow`.
        MontModulus::new(self.n).pow_public(m, &self.e)
    }
}

impl<const LIMBS: usize> super::emsa::PublicModulus for RsaPublicKey<LIMBS> {
    fn modulus_be_bytes(&self) -> alloc::vec::Vec<u8> {
        // `key_size() == LIMBS * 8` big-endian octets of `n`, matching the
        // width of a validated signature so the RSAVP1 `s < n` comparison in
        // `emsa::verify_*` is over equal lengths.
        let mut buf = alloc::vec![0u8; LIMBS * 8];
        self.n.write_be_bytes(&mut buf);
        buf
    }
}

// Best-effort zeroize on drop: the private exponent `d`, primes `p`/`q`,
// blinding `phi_n_minus_1`, and the HMAC seed all live in fixed-size
// stack arrays that would otherwise be returned to the allocator (or the
// stack frame, for stack-allocated keys) with the secret bytes intact.
// Overwrite the limbs and route the read through `core::hint::black_box`
// so LLVM cannot eliminate the writes as dead stores (same pattern as
// ML-DSA/ML-KEM in `src/mldsa/mod.rs` and `src/mlkem/mod.rs`).
impl<const LIMBS: usize> Drop for RsaPrivateKey<LIMBS> {
    fn drop(&mut self) {
        self.d = Uint::ZERO;
        self.p = Uint::ZERO;
        self.q = Uint::ZERO;
        self.phi_n_minus_1 = Uint::ZERO;
        for b in self.blinding_seed.iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(&self.d);
        let _ = core::hint::black_box(&self.p);
        let _ = core::hint::black_box(&self.q);
        let _ = core::hint::black_box(&self.phi_n_minus_1);
        let _ = core::hint::black_box(&self.blinding_seed);
    }
}

impl<const LIMBS: usize> RsaPrivateKey<LIMBS> {
    /// Generates an RSA key pair with an `LIMBS * 64`-bit modulus and the given
    /// public exponent `e` (commonly 65537).
    ///
    /// `rounds` is the number of Miller-Rabin rounds per prime candidate. Key
    /// generation uses a non-constant-time modular inverse (see
    /// [`inv_mod`](crate::bignum::inv_mod)).
    ///
    /// `rng` must be a cryptographically secure CSPRNG (see [`CryptoRng`]).
    pub fn generate<R: RngCore + CryptoRng>(e: Uint<LIMBS>, rng: &mut R, rounds: usize) -> Self {
        let half_bits = LIMBS * 32;
        loop {
            let p = random_prime::<LIMBS, R>(rng, half_bits, rounds);
            let q = random_prime::<LIMBS, R>(rng, half_bits, rounds);
            if p == q {
                continue;
            }

            // FIPS 186-5 B.3.1: redraw if |p − q| < 2^(bits/2 − 100), which would
            // expose the modulus to Fermat factorization. `|p − q| < 2^k` iff its
            // bit length is ≤ k, so compare bit lengths without materializing the
            // power. `saturating_sub` keeps the bound total for sub-200-bit toy
            // sizes (where the threshold collapses to 0 and the check is a no-op
            // since `p ≠ q`).
            let diff = if bool::from(p.ct_lt(&q)) {
                q.wrapping_sub(&p)
            } else {
                p.wrapping_sub(&q)
            };
            if diff.bit_len() <= half_bits.saturating_sub(100) {
                continue;
            }

            let n = p.mul_wide(&q).0; // p, q are half-width, so n fits in LIMBS
            let phi = p
                .wrapping_sub(&Uint::ONE)
                .mul_wide(&q.wrapping_sub(&Uint::ONE))
                .0;

            // d = e^-1 mod φ(n); retry if e is not coprime to φ.
            if let Some(d) = inv_mod(&e, &phi) {
                let (phi_n_minus_1, blinding_seed) = derive_blinding(&p, &q, &d);
                return RsaPrivateKey {
                    n,
                    e,
                    d,
                    p,
                    q,
                    phi_n_minus_1,
                    blinding_seed,
                };
            }
        }
    }

    /// Constructs a private key from raw components, without the prime factors
    /// `p`/`q` (so CRT-based speedups are unavailable). Useful for importing an
    /// existing key.
    ///
    /// Side-channel note: without the primes the [base-blinding](Self) path is
    /// disabled (φ(n) is not known), so this key is more exposed to timing /
    /// cache side channels than a key generated by [`generate`](Self::generate)
    /// or imported with `from_raw_parts`.
    ///
    /// This constructor performs **no validation**. Untrusted input (key
    /// files, PKCS#1/PKCS#8 blobs) must go through the fallible parsers —
    /// [`Self::from_pkcs1_der`] / [`Self::from_pkcs8_der`] — which validate
    /// the components first. A key built here with an even (or zero) modulus
    /// panics in `MontModulus::new` on every private operation
    /// ([`Self::raw`], `sign_*`, `decrypt_*`).
    pub fn from_components(n: Uint<LIMBS>, e: Uint<LIMBS>, d: Uint<LIMBS>) -> Self {
        let (phi_n_minus_1, blinding_seed) =
            derive_blinding(&Uint::<LIMBS>::ZERO, &Uint::<LIMBS>::ZERO, &d);
        RsaPrivateKey {
            n,
            e,
            d,
            p: Uint::ZERO,
            q: Uint::ZERO,
            phi_n_minus_1,
            blinding_seed,
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
        let (phi_n_minus_1, blinding_seed) = derive_blinding(&p, &q, &d);
        RsaPrivateKey {
            n,
            e,
            d,
            p,
            q,
            phi_n_minus_1,
            blinding_seed,
        }
    }

    /// The raw RSA private operation `c^d mod n` (decryption / signing
    /// primitive), with [base blinding](Self) when the prime factors are
    /// known.
    ///
    /// # Panics
    /// Panics if the modulus is even or zero (Montgomery arithmetic requires
    /// an odd modulus). Keys from [`Self::generate`] or the fallible parsers
    /// are pre-validated; only a key assembled from unchecked components via
    /// [`Self::from_components`] can trip this.
    pub fn raw(&self, c: &Uint<LIMBS>) -> Uint<LIMBS> {
        raw_private_blinded(
            &self.n,
            &self.e,
            &self.d,
            &self.phi_n_minus_1,
            &self.blinding_seed,
            c,
        )
    }

    /// Per-key 32-byte secret used to seed PKCS#1 v1.5 implicit-rejection
    /// fallbacks. Same value as the blinding HMAC key (derived once at key
    /// construction from `d`).
    pub(crate) fn secret_seed_bytes(&self) -> [u8; 32] {
        self.blinding_seed
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

    #[cfg(all(feature = "alloc", feature = "der"))]
    #[test]
    fn blinding_does_not_alter_result() {
        // Sanity check: base blinding must be invisible at the result level —
        // c^d mod n is unchanged whether or not blinding ran. We compare the
        // blinded `raw` path against an unblinded one we synthesize from
        // `from_components` (which has phi_n_minus_1 == 0 and skips blinding).
        let key = crate::test_util::rsa_test_key_a();
        let (n, e, d) = (*key.modulus(), *key.exponent(), *key.private_exponent());
        let unblinded = RsaPrivateKey::<32>::from_components(n, e, d);

        // Construct an arbitrary `c < n`.
        let mut c = Uint::<32>::from_be_bytes(b"some-message-bytes-for-the-rsa-private-op-1234567");
        c = c.reduce(&n);

        let blinded_result = key.raw(&c);
        let unblinded_result = unblinded.raw(&c);
        assert_eq!(
            blinded_result, unblinded_result,
            "base blinding must not change the mathematical result"
        );
    }

    #[cfg(all(feature = "alloc", feature = "der"))]
    #[test]
    fn blinding_is_deterministic_for_same_input() {
        // The same ciphertext under the same key produces the same output
        // bit-for-bit (deterministic blinding via HMAC keyed by `d`).
        let key = crate::test_util::rsa_test_key_a();
        let n = *key.modulus();
        let c = Uint::<32>::from_be_bytes(b"deterministic-c-bytes-here-xxxxx").reduce(&n);
        assert_eq!(key.raw(&c), key.raw(&c));
    }

    #[cfg(all(feature = "alloc", feature = "der"))]
    #[test]
    fn blinding_seed_differs_across_keys() {
        let a = crate::test_util::rsa_test_key_a();
        let b = crate::test_util::rsa_test_key_b();
        assert_ne!(
            a.blinding_seed, b.blinding_seed,
            "distinct private keys must derive distinct blinding seeds"
        );
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
