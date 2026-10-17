//! Probabilistic primality testing (Miller-Rabin) and random prime generation.

use crate::bignum::{MontModulus, Uint, mod_u32_with_recip, recip_u32};
use crate::ct::{Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeLess};
use crate::rng::RngCore;

/// The first 256 odd primes (3 ..= 1621), used to reject composites before
/// the expensive Miller-Rabin rounds. `u16`: 512 bytes, for the
/// allocator-free fixed-width path (`bignum::prime` sieves ~1900 primes at
/// run time for the runtime-sized one). A random odd composite has a
/// factor in this table with probability `1 − 2·∏(1 − 1/p) ≈ 85%`, so most
/// candidates are rejected without a modular exponentiation.
const SMALL_PRIMES: [u16; 256] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307,
    311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421,
    431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547,
    557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659,
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797,
    809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929,
    937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039,
    1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153,
    1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279,
    1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409,
    1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499,
    1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613,
    1619, 1621,
];

/// Returns `n mod p` for a small public `p < 2^32`, without a division
/// instruction on the (secret) candidate.
fn mod_small<const LIMBS: usize>(n: &Uint<LIMBS>, p: u64) -> u64 {
    crate::bignum::mod_small_limbs(n.as_limbs(), p)
}

/// `n mod p` for every prime of [`SMALL_PRIMES`]: the primes are packed
/// into products below `2^32` (as many consecutive primes as fit), one
/// Horner pass over the limbs per product, then one reciprocal multiply per
/// prime — the residues an incremental sieve starts from.
fn residues<const LIMBS: usize>(n: &Uint<LIMBS>, recips: &[u64; 256]) -> [u32; 256] {
    let mut res = [0u32; 256];
    let mut i = 0;
    while i < SMALL_PRIMES.len() {
        let mut product: u64 = 1;
        let start = i;
        while i < SMALL_PRIMES.len() && product * (SMALL_PRIMES[i] as u64) < (1 << 32) {
            product *= SMALL_PRIMES[i] as u64;
            i += 1;
        }
        let rem = mod_small(n, product);
        for j in start..i {
            res[j] = mod_u32_with_recip(rem, SMALL_PRIMES[j] as u64, recips[j]) as u32;
        }
    }
    res
}

/// The 64-bit reciprocals of [`SMALL_PRIMES`], computed once per candidate
/// loop (2 KiB on the stack rather than a static table).
fn reciprocals() -> [u64; 256] {
    let mut r = [0u64; 256];
    for (c, &p) in r.iter_mut().zip(SMALL_PRIMES.iter()) {
        *c = recip_u32(p as u64);
    }
    r
}

/// Whether `n₀ + delta` has no factor in [`SMALL_PRIMES`], from the residues
/// of `n₀` and a `delta < 2^31`; branch-free over the table, the verdict
/// public (a rejected candidate is discarded).
fn sieve_passes(res: &[u32; 256], recips: &[u64; 256], delta: u64) -> bool {
    let mut any_zero: u64 = 0;
    for i in 0..SMALL_PRIMES.len() {
        let m = mod_u32_with_recip(res[i] as u64 + delta, SMALL_PRIMES[i] as u64, recips[i]);
        // Top bit set iff m == 0 (m < 2^32, so m − 1 wraps only from 0).
        any_zero |= m.wrapping_sub(1) >> 63;
    }
    crate::ct::declassify_value(any_zero) == 0
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
/// `MR_FIXED_SQUARINGS`). Only the early exits on a *composite* depend on
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
    let res = residues(n, &reciprocals());
    for (i, &p) in SMALL_PRIMES.iter().enumerate() {
        if res[i] == 0 {
            // Divisible by p ⇒ composite, unless n *is* p.
            return n == &Uint::from_u64(p as u64);
        }
    }
    miller_rabin(n, rng, rounds)
}

/// The Miller-Rabin rounds proper, for an odd `n ≥ 5` that trial division
/// (or the incremental sieve of [`random_prime`]) has already cleared.
fn miller_rabin<const LIMBS: usize, R: RngCore>(
    n: &Uint<LIMBS>,
    rng: &mut R,
    rounds: usize,
) -> bool {
    let one = Uint::ONE;
    let two = Uint::from_u64(2);
    // Write n - 1 = d * 2^s with d odd.
    let n_minus_1 = n.wrapping_sub(&one);
    let (d, s) = split_pow2(&n_minus_1);

    // The candidate is secret (it may become a key): declassify only the
    // width scan, which is public by convention.
    let modulus = MontModulus::new_secret(*n);
    // The squarings stay in the Montgomery domain (one squaring each,
    // against `mul_mod`'s two multiplies), compared with M(n − 1); `d < n`,
    // so the modulus's (public) width bounds the ladder.
    let n_minus_1_m = modulus.to_mont(&n_minus_1);
    let bits = 64 * modulus.limbs();
    for _ in 0..rounds {
        // Random base a, reduced into [2, n-2] (Montgomery chunk reduction,
        // not the bitwise long division); the three useless values 0, 1,
        // n − 1 map to 2 by a masked select.
        let a = modulus.reduce(&random_uint::<LIMBS, R>(rng));
        let useless = a.is_zero() | a.ct_eq(&one) | a.ct_eq(&n_minus_1);
        let a = Uint::conditional_select(&two, &a, useless);

        let x = modulus.pow_bits(&a, &d, bits);
        let mut pass = x.ct_eq(&one) | x.ct_eq(&n_minus_1);
        let mut x = modulus.to_mont(&x);
        // x^(2^j) for j in 1..s must hit n − 1: a fixed number of squarings,
        // each result masked by `j < s`.
        for j in 1..MR_FIXED_SQUARINGS {
            x = modulus.mont_sqr(&x);
            pass |= j.ct_lt(&s) & x.ct_eq(&n_minus_1_m);
        }
        // The rare tail (`2^64 | n − 1`, probability 2^-64 for a random
        // candidate): whether it runs is the one bit this test reveals about
        // a kept candidate, declassified here. Its length does not depend on
        // `s`: it squares up to the full width, masked by `j < s`.
        if crate::ct::declassify_value(s > MR_FIXED_SQUARINGS) {
            for j in MR_FIXED_SQUARINGS..bits as u32 {
                x = modulus.mont_sqr(&x);
                pass |= j.ct_lt(&s) & x.ct_eq(&n_minus_1_m);
            }
        }
        if !pass.declassify() {
            return false; // witnessed composite
        }
    }
    true
}

/// A fresh random odd candidate of exactly `bits` bits with the top two
/// bits set (see [`random_prime`]).
fn draw_candidate<const LIMBS: usize, R: RngCore>(rng: &mut R, bits: usize) -> Uint<LIMBS> {
    let mut limbs = [0u64; LIMBS];
    for limb in &mut limbs {
        *limb = rng.next_u64();
    }
    mask_to_bits(&mut limbs, bits);
    limbs[(bits - 1) / 64] |= 1 << ((bits - 1) % 64); // ensure exact bit size
    limbs[(bits - 2) / 64] |= 1 << ((bits - 2) % 64); // ensure full-width product
    limbs[0] |= 1; // odd
    Uint::from_limbs(limbs)
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
    if bits <= crate::bignum::SIEVE_MIN_BITS {
        // Tiny sizes: the sieve would reject the primes of its own table.
        loop {
            let candidate = draw_candidate(rng, bits);
            if is_prime(&candidate, rng, rounds) {
                return candidate;
            }
        }
    }
    // Incremental search: from a random start n₀, try n₀, n₀ + 2, n₀ + 4, …
    // against the small primes using only the residues of n₀ (one multiply
    // per prime per candidate), and spend a Miller-Rabin round only on the
    // survivors; redraw after `SIEVE_WINDOW` candidates. See
    // `bignum::prime::SIEVE_WINDOW` for why the position leaks no more than
    // the old draw-and-test loop's rejection count.
    let recips = reciprocals();
    loop {
        let start = draw_candidate::<LIMBS, R>(rng, bits);
        let res = residues(&start, &recips);
        let mut delta: u64 = 0;
        while delta < crate::bignum::SIEVE_WINDOW {
            if sieve_passes(&res, &recips, delta) {
                let (candidate, carry) = start.adc(&Uint::from_u64(delta), 0);
                // The window must not run past `bits` bits (the forced top
                // bits make that need `delta ≥ 2^(bits−2)`, impossible for
                // `bits > 32`, but the full-width wrap and the bound are
                // checked rather than argued): a public redraw verdict.
                let overflow = Choice::from(carry as u8) | !candidate.shr_bits(bits).is_zero();
                if overflow.declassify() {
                    break;
                }
                if miller_rabin(&candidate, rng, rounds) {
                    return candidate;
                }
            }
            delta += 2;
        }
    }
}

// --- runtime-sized (BoxedUint) variants for arbitrary-size RSA keygen ---

// The Miller-Rabin core for `BoxedUint` lives in `bignum::prime` so the `dh`
// feature (custom-group validation) can share it without depending on `rsa`.
// `rsa` implies `rng`, so under `alloc` the shared module is always present.
#[cfg(all(feature = "alloc", test))]
use crate::bignum::prime::is_prime_boxed;
#[cfg(feature = "alloc")]
use crate::bignum::prime::is_prime_boxed_with;
#[cfg(feature = "alloc")]
use crate::bignum::prime::{TrialDivision, miller_rabin_boxed};
#[cfg(feature = "alloc")]
use crate::bignum::{SIEVE_MIN_BITS, SIEVE_WINDOW};

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
    // Sieve the trial-division primes once for the whole candidate loop.
    let td = TrialDivision::new();
    let draw = |rng: &mut R| {
        let mut limbs = alloc::vec![0u64; nlimbs];
        for limb in &mut limbs {
            *limb = rng.next_u64();
        }
        mask_to_bits(&mut limbs, bits);
        limbs[(bits - 1) / 64] |= 1 << ((bits - 1) % 64);
        limbs[(bits - 2) / 64] |= 1 << ((bits - 2) % 64);
        limbs[0] |= 1;
        limbs
    };
    if bits <= SIEVE_MIN_BITS {
        // Tiny sizes: the sieve would reject the primes of its own table.
        loop {
            let candidate = BoxedUint::from_limbs(draw(rng));
            if is_prime_boxed_with(&candidate, rng, rounds, &td) {
                return candidate;
            }
        }
    }
    // Incremental search from a random start (see `SIEVE_WINDOW`): the
    // residues of the start decide each `n₀ + 2k` with one multiply per
    // prime, and only the survivors get a Miller-Rabin round.
    loop {
        let start = draw(rng);
        let res = td.residues(&start);
        let mut delta: u64 = 0;
        while delta < SIEVE_WINDOW {
            if td.passes(&res, delta) {
                // n₀ + delta in place, tracking the carry out of the width.
                let mut limbs = start.clone();
                let mut carry = delta;
                for limb in limbs.iter_mut() {
                    let (s, c) = limb.overflowing_add(carry);
                    *limb = s;
                    carry = c as u64;
                }
                let candidate = BoxedUint::from_limbs(limbs);
                // The window must not run past `bits` bits (the forced top
                // bits make that need `delta ≥ 2^(bits−2)`, impossible for
                // `bits > 32`, but checked rather than argued): a public
                // redraw verdict.
                let overflow =
                    crate::ct::Choice::from(carry as u8) | !candidate.shr_bits(bits).ct_is_zero();
                if overflow.declassify() {
                    break;
                }
                if miller_rabin_boxed(&candidate, rng, rounds) {
                    return candidate;
                }
            }
            delta += 2;
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
