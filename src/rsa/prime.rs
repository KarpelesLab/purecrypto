//! Probabilistic primality testing (Miller-Rabin) and random prime generation.

use crate::bignum::{MontModulus, Uint};
use crate::rng::RngCore;

/// Odd primes used to cheaply reject composites before the expensive
/// Miller-Rabin rounds.
const SMALL_PRIMES: [u64; 24] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

/// Returns `n mod p` for a small (64-bit) `p`, via Horner over the limbs.
fn mod_small<const LIMBS: usize>(n: &Uint<LIMBS>, p: u64) -> u64 {
    let limbs = n.as_limbs();
    let mut rem: u128 = 0;
    let mut i = LIMBS;
    while i > 0 {
        i -= 1;
        rem = ((rem << 64) | limbs[i] as u128) % p as u128;
    }
    rem as u64
}

/// Draws a uniformly random `Uint<LIMBS>` from `rng`.
fn random_uint<const LIMBS: usize, R: RngCore>(rng: &mut R) -> Uint<LIMBS> {
    let mut limbs = [0u64; LIMBS];
    for limb in &mut limbs {
        *limb = rng.next_u64();
    }
    Uint::from_limbs(limbs)
}

/// Tests whether `n` is (probably) prime using `rounds` of Miller-Rabin with
/// random bases drawn from `rng`.
///
/// A composite passes a single round with probability at most 1/4, so the
/// false-positive probability is at most `4^-rounds`. Deterministic for small
/// factors via trial division. Not constant time.
pub fn is_prime<const LIMBS: usize, R: RngCore>(
    n: &Uint<LIMBS>,
    rng: &mut R,
    rounds: usize,
) -> bool {
    let one = Uint::ONE;
    let two = Uint::from_u64(2);
    if n == &Uint::ZERO || n == &one {
        return false;
    }
    if n == &two {
        return true;
    }
    if !bool::from(n.is_odd()) {
        return false; // even and > 2
    }

    // Trial division by small primes.
    for &p in &SMALL_PRIMES {
        if mod_small(n, p) == 0 {
            // Divisible by p ⇒ composite, unless n *is* p.
            return n == &Uint::from_u64(p);
        }
    }

    // Write n - 1 = d * 2^s with d odd.
    let n_minus_1 = n.wrapping_sub(&one);
    let mut d = n_minus_1;
    let mut s = 0u32;
    while !bool::from(d.is_odd()) {
        d = d.shr1();
        s += 1;
    }

    let modulus = MontModulus::new(*n);
    'rounds: for _ in 0..rounds {
        // Random base a, reduced into [2, n-2].
        let mut a = random_uint::<LIMBS, R>(rng).reduce(n);
        if a == Uint::ZERO || a == one || a == n_minus_1 {
            a = two;
        }

        let mut x = modulus.pow(&a, &d);
        if x == one || x == n_minus_1 {
            continue 'rounds;
        }
        for _ in 0..s.saturating_sub(1) {
            x = modulus.mul_mod(&x, &x);
            if x == n_minus_1 {
                continue 'rounds;
            }
        }
        return false; // witnessed composite
    }
    true
}

/// Masks `limbs` so only the low `bits` bits can be set.
fn mask_to_bits(limbs: &mut [u64], bits: usize) {
    for (i, limb) in limbs.iter_mut().enumerate() {
        let low = i * 64;
        if low >= bits {
            *limb = 0;
        } else if low + 64 > bits {
            let keep = bits - low; // 1..=63
            *limb &= (1u64 << keep) - 1;
        }
    }
}

/// Generates a random (probable) prime of exactly `bits` bits. The top two
/// bits and bit 0 are forced set: bit 0 makes it odd, and setting both
/// `bits-1` and `bits-2` ensures the product of two such primes is a full
/// `2*bits`-bit modulus (the standard RSA construction).
///
/// # Panics
/// Panics if `bits` is not in `2..=LIMBS*64`.
pub fn random_prime<const LIMBS: usize, R: RngCore>(
    rng: &mut R,
    bits: usize,
    rounds: usize,
) -> Uint<LIMBS> {
    assert!(bits >= 2 && bits <= LIMBS * 64, "bits out of range");
    loop {
        let mut limbs = [0u64; LIMBS];
        for limb in &mut limbs {
            *limb = rng.next_u64();
        }
        mask_to_bits(&mut limbs, bits);
        limbs[(bits - 1) / 64] |= 1 << ((bits - 1) % 64); // ensure exact bit size
        limbs[(bits - 2) / 64] |= 1 << ((bits - 2) % 64); // ensure full-width product
        limbs[0] |= 1; // odd
        let candidate = Uint::from_limbs(limbs);
        if is_prime(&candidate, rng, rounds) {
            return candidate;
        }
    }
}

// --- runtime-sized (BoxedUint) variants for arbitrary-size RSA keygen ---

// The Miller-Rabin core for `BoxedUint` lives in `bignum::prime` so the `dh`
// feature (custom-group validation) can share it without depending on `rsa`.
// `rsa` implies `rng`, so under `alloc` the shared module is always present.
#[cfg(feature = "alloc")]
pub(crate) use crate::bignum::prime::is_prime_boxed;

/// Generates a random (probable) prime of exactly `bits` bits as a
/// [`BoxedUint`](crate::bignum::BoxedUint), with the top two bits and bit 0 set.
#[cfg(feature = "alloc")]
pub(crate) fn random_prime_boxed<R: RngCore>(
    rng: &mut R,
    bits: usize,
    rounds: usize,
) -> crate::bignum::BoxedUint {
    use crate::bignum::BoxedUint;
    let nlimbs = bits.div_ceil(64);
    loop {
        let mut limbs = alloc::vec![0u64; nlimbs];
        for limb in &mut limbs {
            *limb = rng.next_u64();
        }
        mask_to_bits(&mut limbs, bits);
        limbs[(bits - 1) / 64] |= 1 << ((bits - 1) % 64);
        limbs[(bits - 2) / 64] |= 1 << ((bits - 2) % 64);
        limbs[0] |= 1;
        let candidate = BoxedUint::from_limbs(limbs);
        if is_prime_boxed(&candidate, rng, rounds) {
            return candidate;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn rng() -> HmacDrbg<Sha256> {
        HmacDrbg::new(b"prime-test-seed", b"nonce", &[])
    }

    #[test]
    fn known_primes_and_composites() {
        let mut r = rng();
        // Primes.
        assert!(is_prime(&Uint::<1>::from_u64(2), &mut r, 20));
        assert!(is_prime(&Uint::<1>::from_u64(7919), &mut r, 20));
        // 2^61 - 1 is a Mersenne prime.
        assert!(is_prime(
            &Uint::<1>::from_u64(2_305_843_009_213_693_951),
            &mut r,
            20
        ));

        // Composites.
        assert!(!is_prime(&Uint::<1>::from_u64(0), &mut r, 20));
        assert!(!is_prime(&Uint::<1>::from_u64(1), &mut r, 20));
        assert!(!is_prime(&Uint::<1>::from_u64(7917), &mut r, 20)); // small factor 3
        // 70747 = 263 * 269 — both factors exceed the trial-division list, so
        // Miller-Rabin itself must reject it.
        assert!(!is_prime(&Uint::<1>::from_u64(70747), &mut r, 20));
        // Even number > 2.
        assert!(!is_prime(&Uint::<1>::from_u64(7918), &mut r, 20));
    }

    #[test]
    fn generated_primes_are_prime() {
        let mut r = rng();
        for _ in 0..3 {
            let p = random_prime::<1, _>(&mut r, 64, 20);
            assert!(bool::from(p.is_odd()));
            assert!(p.as_limbs()[0] >> 63 == 1, "top bit should be set");
            assert!(is_prime(&p, &mut r, 25));
        }
        // A 96-bit prime in a 2-limb Uint exercises masking + the multi-limb
        // path (bit 95 set, limb 1's upper bits clear).
        let p = random_prime::<2, _>(&mut r, 96, 20);
        assert!(is_prime(&p, &mut r, 25));
        assert_eq!(p.as_limbs()[1] >> 31, 1, "bit 95 set, above cleared");
    }
}
