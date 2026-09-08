//! Miller-Rabin probable-prime testing for runtime-sized integers.
//!
//! Shared by RSA key generation (`rsa::prime`) and finite-field DH custom
//! group validation (`dh`). The two features are independent of each other,
//! so the shared core lives here in `bignum` — which both depend on — rather
//! than one feature depending on the other.

use super::{BoxedMontModulus, BoxedUint};
use crate::rng::RngCore;
use alloc::vec::Vec;

/// Exclusive upper bound of the trial-division sieve: every odd prime below
/// `2^14 = 16384` (1899 of them) is tried before the first Miller-Rabin
/// round. A random odd composite has a small factor with probability
/// `1 − 2·∏(1 − 1/p) ≈ 88%` (Mertens), so most composites — including the
/// bulk of the candidates RSA key generation draws — are rejected for a few
/// hundred `u128` divisions instead of a full-width modular exponentiation.
/// (The fixed-size `Uint` path in `rsa::prime` keeps its own short table: it
/// must also build without `alloc`, where this module is absent.)
const TRIAL_DIVISION_BOUND: u64 = 1 << 14;

/// Every candidate below `TRIAL_DIVISION_BOUND²` is *proved* prime or
/// composite by the trial division alone — `2^28`, i.e. 28 bits.
const TRIAL_DIVISION_EXACT_BITS: usize = 28;

/// The odd primes below [`TRIAL_DIVISION_BOUND`], by a plain sieve of
/// Eratosthenes. ~16 KiB of scratch and ~20 µs; negligible next to the
/// modular exponentiation it front-runs.
fn small_odd_primes() -> Vec<u64> {
    let bound = TRIAL_DIVISION_BOUND as usize;
    let mut composite = alloc::vec![false; bound];
    let mut primes = Vec::with_capacity(2000);
    // Odd numbers only: 2 is handled by the caller's parity check, and
    // stepping by `2 * i` keeps the marking on odd multiples.
    for i in (3..bound).step_by(2) {
        if composite[i] {
            continue;
        }
        primes.push(i as u64);
        let mut j = i * i;
        while j < bound {
            composite[j] = true;
            j += 2 * i;
        }
    }
    primes
}

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

/// Trial division of `n` by every odd prime below [`TRIAL_DIVISION_BOUND`].
/// Returns the smallest such prime dividing `n`, or `None`.
///
/// The primes are packed into `u64` products (as many consecutive primes as
/// fit without overflow) so each product costs one Horner pass over the
/// limbs; the residue is then reduced modulo each prime of the batch with
/// native `u64` arithmetic. That is ~4–5x fewer `u128` divisions than one
/// pass per prime.
fn small_factor_boxed(n: &BoxedUint) -> Option<u64> {
    let primes = small_odd_primes();
    let mut i = 0;
    while i < primes.len() {
        // Greedily extend the batch while the product still fits in a u64.
        let mut product: u64 = 1;
        let start = i;
        while i < primes.len() {
            match product.checked_mul(primes[i]) {
                Some(next) => {
                    product = next;
                    i += 1;
                }
                None => break,
            }
        }
        let rem = mod_small_boxed(n, product);
        for &p in &primes[start..i] {
            if rem.is_multiple_of(p) {
                return Some(p);
            }
        }
    }
    None
}

/// Miller-Rabin primality test for a [`BoxedUint`], using `rounds` rounds
/// with random bases drawn from `rng`.
///
/// A composite survives a single round with probability at most 1/4 — even
/// for an adversarially chosen candidate, since the bases are not known to
/// the adversary in advance — so the false-positive probability is at most
/// `4^-rounds`. Trial division by every prime below 2^14 runs first, so a
/// composite with a small factor is rejected without any exponentiation, and
/// a candidate below 2^28 is decided exactly. Not constant time: only feed it
/// public candidates.
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
    if let Some(p) = small_factor_boxed(n) {
        return *n == BoxedUint::from_u64(p);
    }
    if n.bit_len() <= TRIAL_DIVISION_EXACT_BITS {
        // No prime factor below sqrt(n): n is prime, no need for Miller-Rabin.
        return true;
    }

    let n_minus_1 = n.sub(&one);
    let mut d = n_minus_1.clone();
    let mut s = 0u32;
    while !d.is_odd() {
        d = d.shr_bits(1);
        s += 1;
    }

    let modulus = BoxedMontModulus::new(n);
    'rounds: for _ in 0..rounds {
        let a = random_base(n, &n_minus_1, rng);
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

/// A random base in `[2, n − 2]` for an odd `n ≥ 5`: a full-width draw
/// reduced mod `n`, with the three useless values `0`, `1`, `n − 1` mapped
/// to `2`.
fn random_base<R: RngCore>(n: &BoxedUint, n_minus_1: &BoxedUint, rng: &mut R) -> BoxedUint {
    let mut limbs = alloc::vec![0u64; n.limbs()];
    for limb in &mut limbs {
        *limb = rng.next_u64();
    }
    let a = BoxedUint::from_limbs(limbs).reduce(n);
    if a.is_zero() || a == BoxedUint::from_u64(1) || a == *n_minus_1 {
        BoxedUint::from_u64(2)
    } else {
        a
    }
}

/// Safe-prime test: is `p` a (probable) prime with `q = (p − 1) / 2` also
/// prime?
///
/// `q` gets the full `rounds`-round Miller-Rabin treatment (after the trial
/// division), so a composite `q` is rejected either for free or after one
/// exponentiation with probability ≥ 3/4 per round. `p` then needs **no**
/// Miller-Rabin rounds of its own: with `p − 1 = 2·q` completely factored,
/// the Lucas primality test (the converse of Fermat's little theorem;
/// Pocklington's criterion with `F = q > √p`) *proves* `p` prime from a single
/// witness `a` with
///
/// ```text
///   a^(p−1) ≡ 1 (mod p),   a^q ≢ 1 (mod p),   a^2 ≢ 1 (mod p),
/// ```
///
/// i.e. an element of full order `p − 1`, which forces `φ(p) ≥ p − 1` and
/// hence `p` prime. Since `a ∈ [2, p − 2]` already rules out `a^2 ≡ 1` for a
/// prime `p`, and `a^(p−1) = (a^q)^2`, one exponentiation `t = a^q mod p`
/// decides each witness: `t ≡ −1` proves `p` prime, `t ≡ 1` is inconclusive
/// (`a` was a quadratic residue — probability 1/2 for a prime `p`, so the
/// next witness is tried), and anything else proves `p` composite (a prime
/// `p` has no square roots of 1 besides ±1). Up to `rounds` witnesses are
/// tried before giving up: a genuine safe prime is wrongly rejected only if
/// every witness is a residue, probability `2^-rounds`, and the test
/// **fails closed**.
///
/// Total cost for a genuine safe prime: `rounds + ~2` exponentiations — about
/// half the `2 × rounds` a naive pair of Miller-Rabin runs on `p` and `q`
/// would cost — with the false-accept probability *improved* to
/// `4^-rounds` for the whole pair (the only way in is a composite `q`
/// surviving its rounds). Not constant time: only feed it public candidates.
pub(crate) fn is_safe_prime_boxed<R: RngCore>(p: &BoxedUint, rng: &mut R, rounds: usize) -> bool {
    let one = BoxedUint::from_u64(1);
    // p ≥ 7 (the smallest safe prime with q > 2 is 7 = 2·3 + 1; 5 = 2·2 + 1
    // is a safe prime too, but Montgomery form needs p ≥ 3 and q = 2 breaks
    // the "q odd prime" assumption below — treat both via the exact path).
    if !p.is_odd() || p.bit_len() < 3 {
        return false;
    }
    // Cheap reject of p before spending anything on q.
    if let Some(f) = small_factor_boxed(p)
        && *p != BoxedUint::from_u64(f)
    {
        return false;
    }
    let p_minus_1 = p.sub(&one);
    let q = p_minus_1.shr_bits(1);
    if !is_prime_boxed(&q, rng, rounds) {
        return false;
    }
    if p.bit_len() <= TRIAL_DIVISION_EXACT_BITS {
        // Trial division above already decided p exactly.
        return true;
    }

    // Lucas test on p with the factorization p − 1 = 2 · q.
    let modulus = BoxedMontModulus::new(p);
    for _ in 0..rounds {
        let a = random_base(p, &p_minus_1, rng);
        let t = modulus.pow(&a, &q);
        if t == p_minus_1 {
            return true; // a has order 2q = p − 1: p is prime.
        }
        if t != one {
            return false; // a nontrivial square root of 1: p is composite.
        }
        // t == 1: a is a quadratic residue, inconclusive — next witness.
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn rng() -> HmacDrbg<Sha256> {
        HmacDrbg::new(b"bignum-prime-test-seed", b"nonce", &[])
    }

    /// Plain trial-division primality for the test oracle (u64 range).
    fn is_prime_u64(n: u64) -> bool {
        if n < 2 {
            return false;
        }
        let mut d = 2u64;
        while d * d <= n {
            if n.is_multiple_of(d) {
                return false;
            }
            d += 1;
        }
        true
    }

    #[test]
    fn sieve_matches_trial_division() {
        let primes = small_odd_primes();
        assert_eq!(primes.len(), 1899, "odd primes below 2^14");
        assert_eq!(primes[0], 3);
        assert_eq!(*primes.last().unwrap(), 16381);
        for w in primes.windows(2) {
            assert!(w[0] < w[1]);
        }
        for &p in &primes {
            assert!(is_prime_u64(p), "{p} in sieve output but composite");
        }
        let expected = (3..TRIAL_DIVISION_BOUND)
            .filter(|&n| is_prime_u64(n))
            .count();
        assert_eq!(primes.len(), expected);
    }

    #[test]
    fn small_factor_finds_smallest_prime_factor() {
        // 16381 is the largest prime below the bound; 16381 · 16411 has no
        // factor below 16381 but is caught at the very last prime.
        let n = BoxedUint::from_u64(16381 * 16411);
        assert_eq!(small_factor_boxed(&n), Some(16381));
        // 16411 · 16417 (both primes above the bound) must slip through.
        assert!(is_prime_u64(16411) && is_prime_u64(16417));
        assert_eq!(
            small_factor_boxed(&BoxedUint::from_u64(16411 * 16417)),
            None
        );
        // Multi-limb: 3 · (2^127 − 1) has the small factor 3.
        let m127 = BoxedUint::from_limbs(alloc::vec![u64::MAX, u64::MAX >> 1]);
        let n = m127.mul(&BoxedUint::from_u64(3));
        assert_eq!(small_factor_boxed(&n), Some(3));
        // ...and the Mersenne prime itself has none.
        assert_eq!(small_factor_boxed(&m127), None);
    }

    #[test]
    fn is_prime_boxed_small_values_are_exact() {
        let mut r = rng();
        for n in 0..3000u64 {
            assert_eq!(
                is_prime_boxed(&BoxedUint::from_u64(n), &mut r, 4),
                is_prime_u64(n),
                "n = {n}"
            );
        }
        // Around the sieve bound and above the exact-decision range.
        for n in [
            16381u64,
            16383,
            16411,
            16411 * 16417,
            1 << 28,
            (1 << 28) + 1,
        ] {
            assert_eq!(
                is_prime_boxed(&BoxedUint::from_u64(n), &mut r, 8),
                is_prime_u64(n),
                "n = {n}"
            );
        }
        // 2^61 − 1 is prime; 2^127 − 1 too.
        assert!(is_prime_boxed(
            &BoxedUint::from_u64(2_305_843_009_213_693_951),
            &mut r,
            8
        ));
        let m127 = BoxedUint::from_limbs(alloc::vec![u64::MAX, u64::MAX >> 1]);
        assert!(is_prime_boxed(&m127, &mut r, 8));
        // A product of two primes above the trial-division bound must be
        // rejected by Miller-Rabin proper.
        assert!(!is_prime_boxed(
            &BoxedUint::from_u64(4_294_967_291 * 4_294_967_279),
            &mut r,
            8
        ));
    }

    #[test]
    fn safe_prime_small_values_are_exact() {
        let mut r = rng();
        for p in 3..3000u64 {
            let expected = p % 2 == 1 && is_prime_u64(p) && is_prime_u64((p - 1) / 2);
            assert_eq!(
                is_safe_prime_boxed(&BoxedUint::from_u64(p), &mut r, 4),
                expected,
                "p = {p}"
            );
        }
    }

    /// Exercises the Lucas branch on genuine safe primes above the exact
    /// trial-division range (p > 2^28): search from 2^30 upwards.
    #[test]
    fn safe_prime_lucas_accepts_large_safe_primes() {
        let mut r = rng();
        let mut q = (1u64 << 30) + 1;
        let mut found = 0;
        while found < 5 {
            if is_prime_u64(q) && is_prime_u64(2 * q + 1) {
                let p = BoxedUint::from_u64(2 * q + 1);
                assert!(is_safe_prime_boxed(&p, &mut r, 16), "p = {}", 2 * q + 1);
                found += 1;
            }
            q += 2;
        }
    }

    /// One real-world case for the Lucas branch: RFC 3526 group14's
    /// 2048-bit safe prime.
    #[cfg(feature = "dh")]
    #[test]
    fn safe_prime_lucas_accepts_group14() {
        let mut r = rng();
        let p = crate::dh::group14();
        assert!(is_safe_prime_boxed(p.p(), &mut r, 4));
    }

    /// The Lucas branch must reject a composite `p = 2q + 1` whose `q` *is*
    /// prime and which has no factor below the sieve bound — the one shape
    /// trial division and the `q` test both wave through. Search for
    /// `p = r · s` with `r, s` primes above 2^14 and `(p − 1)/2` prime.
    #[test]
    fn safe_prime_lucas_rejects_composite_p_with_prime_q() {
        let mut r = rng();
        let mut found = 0;
        let mut a = TRIAL_DIVISION_BOUND + 1;
        'outer: while found < 3 {
            if is_prime_u64(a) {
                let mut b = a;
                while b < a + 2000 {
                    if is_prime_u64(b) {
                        let p = a * b;
                        if p % 2 == 1 && is_prime_u64((p - 1) / 2) {
                            assert!(p.ilog2() as usize + 1 > TRIAL_DIVISION_EXACT_BITS);
                            assert!(
                                !is_safe_prime_boxed(&BoxedUint::from_u64(p), &mut r, 16),
                                "p = {a} * {b} must be rejected"
                            );
                            found += 1;
                            a += 2;
                            continue 'outer;
                        }
                    }
                    b += 2;
                }
            }
            a += 2;
        }
    }

    /// Non-safe primes (prime `p`, composite `q`) are rejected on `q`.
    #[test]
    fn safe_prime_rejects_prime_with_composite_q() {
        let mut r = rng();
        // 2^61 − 1 is prime; (2^61 − 2)/2 = 2^60 − 1 = 3 · 5² · ... composite.
        let m61 = BoxedUint::from_u64(2_305_843_009_213_693_951);
        assert!(is_prime_boxed(&m61, &mut r, 8));
        assert!(!is_safe_prime_boxed(&m61, &mut r, 8));
    }
}
