//! Probabilistic primality testing (Miller-Rabin) and random prime generation.

use crate::bignum::{MontModulus, Uint};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use crate::rng::RngCore;

/// Odd primes used to cheaply reject composites before the expensive
/// Miller-Rabin rounds.
const SMALL_PRIMES: [u64; 24] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

/// Returns `n mod p` for a small public `p < 2^32`, without a division
/// instruction on the (secret) candidate.
fn mod_small<const LIMBS: usize>(n: &Uint<LIMBS>, p: u64) -> u64 {
    crate::bignum::mod_small_limbs(n.as_limbs(), p)
}

/// Squarings a Miller-Rabin round always performs after `a^d`, whatever
/// `s = v₂(n − 1)` is, so the round's shape does not reveal `s` (a few bits
/// of the candidate) or how many squarings a base needed to hit `−1`.
/// `s > 64` happens with probability `2⁻⁶⁴` for a random candidate; only
/// then does a variable-length tail run.
const MR_FIXED_SQUARINGS: u32 = 64;

/// `(d, s)` with `x = d · 2^s` and `d` odd, computed without branching on
/// `x`: `s` by a branch-free trailing-zero count over every limb, `d` by a
/// barrel shift selected on the bits of `s`.
fn split_pow2<const LIMBS: usize>(x: &Uint<LIMBS>) -> (Uint<LIMBS>, u32) {
    let mut s = 0u32;
    let mut still_zero = 1u64;
    for &limb in x.as_limbs() {
        crate::bignum::trailing_zeros_step(limb, &mut s, &mut still_zero);
    }
    let mut d = *x;
    let mut k = 0;
    while (1usize << k) < LIMBS * 64 {
        let shifted = d.shr_bits(1 << k);
        d = Uint::conditional_select(&shifted, &d, Choice::from(((s >> k) & 1) as u8));
        k += 1;
    }
    (d, s)
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
/// factors via trial division.
///
/// The verdict is public (a rejected candidate is discarded, an accepted one
/// becomes a key), but the work done on a candidate that *passes* is
/// shaped independently of its value: trial division uses no division
/// instruction, `n − 1 = d·2^s` is split without branching, and every
/// Miller-Rabin round runs the same number of squarings (see
/// [`MR_FIXED_SQUARINGS`]). Only the early exits on a *composite* depend on
/// the value, and those candidates are fresh random draws that leak nothing
/// about the prime eventually chosen.
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
    let (d, s) = split_pow2(&n_minus_1);

    let modulus = MontModulus::new(*n);
    for _ in 0..rounds {
        // Random base a, reduced into [2, n-2]; the three useless values
        // 0, 1, n − 1 map to 2 by a masked select.
        let a = random_uint::<LIMBS, R>(rng).reduce(n);
        let useless = a.is_zero() | a.ct_eq(&one) | a.ct_eq(&n_minus_1);
        let a = Uint::conditional_select(&two, &a, useless);

        let mut x = modulus.pow(&a, &d);
        let mut pass = x.ct_eq(&one) | x.ct_eq(&n_minus_1);
        // x^(2^j) for j in 1..s must hit n − 1: a fixed number of squarings,
        // each result masked by `j < s`.
        for j in 1..MR_FIXED_SQUARINGS {
            x = modulus.mul_mod(&x, &x);
            pass |= j.ct_lt(&s) & x.ct_eq(&n_minus_1);
        }
        for _ in MR_FIXED_SQUARINGS..s {
            x = modulus.mul_mod(&x, &x);
            pass |= x.ct_eq(&n_minus_1);
        }
        if !bool::from(pass) {
            return false; // witnessed composite
        }
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

/// The minimum number of Miller-Rabin rounds a `bits`-bit RSA prime
/// candidate is tested with, regardless of what the caller asked for.
///
/// `rounds = 0` (or 1, or 2) accepts composites with overwhelming
/// probability, and the round count reaches the prime generators from the
/// public `generate` APIs — a caller who passes 0, whether by mistake or to
/// "speed up" key generation, must not end up with a composite modulus. The
/// floors below meet or exceed the FIPS 186-5 Table B.1 minimums for RSA
/// prime generation (which bottom out around 4–5 rounds for 1024-bit and
/// larger primes, at a 2⁻¹⁰⁰ error target) and add margin at the small,
/// non-RSA-sized values the table does not cover, where each round is cheap
/// anyway. Callers asking for *more* rounds always get what they asked for.
pub(crate) const fn min_mr_rounds(bits: usize) -> usize {
    if bits >= 1024 {
        5
    } else if bits >= 512 {
        8
    } else if bits >= 256 {
        16
    } else if bits >= 128 {
        24
    } else {
        32
    }
}

/// Generates a random (probable) prime of exactly `bits` bits. The top two
/// bits and bit 0 are forced set: bit 0 makes it odd, and setting both
/// `bits-1` and `bits-2` ensures the product of two such primes is a full
/// `2*bits`-bit modulus (the standard RSA construction).
///
/// `rounds` is clamped up to a size-appropriate floor (FIPS 186-5 Table B.1;
/// see `min_mr_rounds`), so a caller passing 0 still gets a properly tested
/// prime.
///
/// # Panics
/// Panics if `bits` is not in `2..=LIMBS*64`.
pub fn random_prime<const LIMBS: usize, R: RngCore>(
    rng: &mut R,
    bits: usize,
    rounds: usize,
) -> Uint<LIMBS> {
    assert!(bits >= 2 && bits <= LIMBS * 64, "bits out of range");
    let rounds = rounds.max(min_mr_rounds(bits));
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
///
/// `rounds` is clamped up to the same size-appropriate floor as
/// [`random_prime`].
///
/// # Panics
/// Panics if `bits < 2` — the two forced top bits need two bit positions
/// (the index arithmetic below would underflow otherwise).
#[cfg(feature = "alloc")]
pub(crate) fn random_prime_boxed<R: RngCore>(
    rng: &mut R,
    bits: usize,
    rounds: usize,
) -> crate::bignum::BoxedUint {
    use crate::bignum::BoxedUint;
    assert!(bits >= 2, "random_prime_boxed: bits must be >= 2");
    let rounds = rounds.max(min_mr_rounds(bits));
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

    /// BN-5: `bits = 1` used to underflow the `bits - 2` bit index.
    #[cfg(feature = "alloc")]
    #[test]
    #[should_panic(expected = "bits must be >= 2")]
    fn random_prime_boxed_rejects_tiny_bits() {
        let mut r = rng();
        let _ = random_prime_boxed(&mut r, 1, 4);
    }

    /// `rounds = 0` must not produce a composite: the generators clamp the
    /// caller's round count up to the size-appropriate FIPS floor.
    #[test]
    fn random_prime_clamps_zero_rounds() {
        let mut r = rng();
        for _ in 0..3 {
            let p = random_prime::<2, _>(&mut r, 96, 0);
            assert!(
                is_prime(&p, &mut r, 40),
                "generated a composite with rounds=0"
            );
        }
        assert!(min_mr_rounds(1024) >= 5);
        assert!(min_mr_rounds(512) >= min_mr_rounds(1024));
        assert!(min_mr_rounds(64) >= min_mr_rounds(512));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn random_prime_boxed_clamps_zero_rounds() {
        let mut r = rng();
        let p = random_prime_boxed(&mut r, 128, 0);
        assert!(is_prime_boxed(&p, &mut r, 40));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn random_prime_boxed_small_sizes() {
        let mut r = rng();
        for bits in [2usize, 3, 8, 64, 65, 128] {
            let p = random_prime_boxed(&mut r, bits, 8);
            assert_eq!(p.bit_len(), bits);
            assert!(p.is_odd());
            assert!(is_prime_boxed(&p, &mut r, 8));
        }
    }
}
