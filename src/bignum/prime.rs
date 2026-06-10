//! Miller-Rabin probable-prime testing for runtime-sized integers.
//!
//! Shared by RSA key generation (`rsa::prime`) and finite-field DH custom
//! group validation (`dh`). The two features are independent of each other,
//! so the shared core lives here in `bignum` — which both depend on — rather
//! than one feature depending on the other.

use super::{BoxedMontModulus, BoxedUint};
use crate::rng::RngCore;

/// Odd primes used to cheaply reject composites before the expensive
/// Miller-Rabin rounds. (The fixed-size `Uint` path in `rsa::prime` keeps its
/// own copy: it must also build without `alloc`, where this module is absent.)
const SMALL_PRIMES: [u64; 24] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

/// `n mod p` for a runtime-sized `n` and a small (64-bit) `p`, via Horner
/// over the limbs.
fn mod_small_boxed(n: &BoxedUint, p: u64) -> u64 {
    let limbs = n.as_limbs();
    let mut rem: u128 = 0;
    for i in (0..limbs.len()).rev() {
        rem = ((rem << 64) | limbs[i] as u128) % p as u128;
    }
    rem as u64
}

/// Miller-Rabin primality test for a [`BoxedUint`], using `rounds` rounds
/// with random bases drawn from `rng`.
///
/// A composite survives a single round with probability at most 1/4 — even
/// for an adversarially chosen candidate, since the bases are not known to
/// the adversary in advance — so the false-positive probability is at most
/// `4^-rounds`. Deterministic for small factors via trial division. Not
/// constant time: only feed it public candidates.
pub(crate) fn is_prime_boxed<R: RngCore>(n: &BoxedUint, rng: &mut R, rounds: usize) -> bool {
    let one = BoxedUint::from_u64(1);
    let two = BoxedUint::from_u64(2);
    if n.is_zero() || *n == one {
        return false;
    }
    if *n == two {
        return true;
    }
    if !n.is_odd() {
        return false;
    }
    for &p in &SMALL_PRIMES {
        if mod_small_boxed(n, p) == 0 {
            return *n == BoxedUint::from_u64(p);
        }
    }

    let n_minus_1 = n.sub(&one);
    let mut d = n_minus_1.clone();
    let mut s = 0u32;
    while !d.is_odd() {
        d = d.shr_bits(1);
        s += 1;
    }

    let modulus = BoxedMontModulus::new(n);
    let nlimbs = n.limbs();
    'rounds: for _ in 0..rounds {
        let mut limbs = alloc::vec![0u64; nlimbs];
        for limb in &mut limbs {
            *limb = rng.next_u64();
        }
        let mut a = BoxedUint::from_limbs(limbs).reduce(n);
        if a.is_zero() || a == one || a == n_minus_1 {
            a = two.clone();
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
        return false;
    }
    true
}
