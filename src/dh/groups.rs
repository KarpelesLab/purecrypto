//! Named MODP Diffie-Hellman groups.
//!
//! The five RFC 3526 safe-prime groups (14 through 18) used by SSH, IKEv2,
//! legacy TLS, and other finite-field DH consumers, plus constructors for
//! caller-supplied "custom" groups: safe-prime `(p, g)` pairs (RFC 4419
//! group-exchange) and `(p, g, q)` triples whose generator spans a prime
//! order-`q` subgroup (RFC 5114, ANSI X9.42 / PKCS#3-with-`q` parameters).
//!
//! Each named group is exposed as a `fn group14()` / `group15()` / ... that
//! returns an owned [`DhGroup`] — the primes are several hundred bytes each
//! and live in `static` byte arrays, but the [`BoxedUint`] decoding is done
//! lazily at call time so we never pay for groups the program doesn't use.

use super::key::Error;
use crate::bignum::{BoxedMontModulus, BoxedUint};

/// A MODP DH group: a prime `p`, a generator `g`, and a recommended
/// private-exponent bit length — either over a safe prime (`q = (p - 1) / 2`
/// also prime, `g` of order `q` or `2q`) or, for an explicit-subgroup group,
/// with `g` generating a prime-order-`q` subgroup for a stated `q | p − 1`.
///
/// Constructed via the [`group14`]..[`group18`] free functions for the
/// RFC 3526 groups, via [`DhGroup::from_custom`] for an RFC 4419
/// group-exchange–supplied `(p, g)` pair, or via [`DhGroup::from_params`] for
/// an RFC 5114 / X9.42 `(p, g, q)` triple.
#[derive(Clone)]
pub struct DhGroup {
    pub(crate) name: &'static str,
    pub(crate) p: BoxedUint,
    pub(crate) g: BoxedUint,
    /// Recommended private-exponent bit length. RFC 7919 §A guides a
    /// `2 × security_bits` value (e.g. 256 bits of exponent for AES-128
    /// equivalent symmetric strength). Used by [`DhPrivateKey::generate`]
    /// to size the random scalar.
    ///
    /// [`DhPrivateKey::generate`]: super::DhPrivateKey::generate
    pub(crate) priv_bits: usize,
    /// Set only by the RFC 3526 constructors, whose `p` is a published safe
    /// prime: `shared_secret` then skips the `y^q` consistency check, which
    /// cannot fail for a genuine safe prime. Custom groups — even ones
    /// [`from_custom`](Self::from_custom) validated, whose Miller-Rabin half
    /// uses public bases — keep it.
    pub(crate) known_safe_prime: bool,
    /// The prime subgroup order `q`, for a group built by
    /// [`from_params`](Self::from_params) (`None` for the safe-prime
    /// constructors, whose `q = (p − 1) / 2` is implicit). When set, private
    /// keys are drawn from `[1, q − 1]` and a peer value must satisfy
    /// `y^q ≡ 1 (mod p)`: without a safe prime, `Z_p^*` has small subgroups
    /// besides the order-`q` one, and only that check keeps a peer from
    /// confining the exponent to one of them.
    pub(crate) q: Option<BoxedUint>,
    /// Montgomery parameters for `p`, built once with the group: every
    /// `g^x` / `y^x` on the group reuses them instead of recomputing `R² mod
    /// p` (an `O(log)` chain of full-width squarings) per operation. `p` is
    /// public, so nothing secret is cached.
    pub(crate) mont: BoxedMontModulus,
}

impl DhGroup {
    /// The group's human-readable name (`"group14"`, `"custom"`, ...).
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The bit length of `p` — `2048` for group14, `3072` for group15, ...
    pub fn bit_size(&self) -> usize {
        self.p.bit_len()
    }

    /// The byte length of `p`, used for wire-format public-key padding and
    /// shared-secret length.
    pub fn byte_size(&self) -> usize {
        self.p.bit_len().div_ceil(8)
    }

    /// The prime modulus `p`.
    pub fn p(&self) -> &BoxedUint {
        &self.p
    }

    /// The generator `g`.
    pub fn g(&self) -> &BoxedUint {
        &self.g
    }

    /// The subgroup order `q` of an explicit-subgroup group
    /// ([`from_params`](Self::from_params)); `None` for the safe-prime
    /// groups, where it is `(p − 1) / 2` by construction.
    pub fn q(&self) -> Option<&BoxedUint> {
        self.q.as_ref()
    }

    /// The cached Montgomery parameters for `p`.
    #[inline]
    pub(crate) fn mont(&self) -> &BoxedMontModulus {
        &self.mont
    }

    /// The recommended private-exponent bit length for this group.
    pub fn priv_bits(&self) -> usize {
        self.priv_bits
    }

    /// Minimum bit length accepted by [`from_custom`](Self::from_custom).
    ///
    /// RFC 4419 §3 states implementations SHOULD NOT accept group-exchange
    /// primes shorter than 1024 bits; modern guidance (RFC 8270 §2, NIST
    /// SP 800-56A Rev 3 §5.5.1.1) raises that floor to 2048. Anything below
    /// 2048 has fewer than ~112 bits of security against the General Number
    /// Field Sieve and falls under the precomputation attacks demonstrated
    /// by the LogJam paper. Callers with a documented legacy interop need
    /// can sidestep this floor by using [`from_custom_unchecked`].
    ///
    /// [`from_custom_unchecked`]: Self::from_custom_unchecked
    pub const MIN_CUSTOM_GROUP_BITS: usize = 2048;

    /// Minimum private-exponent bit length accepted by
    /// [`from_custom`](Self::from_custom).
    ///
    /// The exponent must be at least twice the target security level (RFC
    /// 7919 §A, NIST SP 800-56A Rev 3 §5.6.1.1): the best generic attack on
    /// the exponent is Pollard rho / BSGS at `2^(priv_bits/2)` work, so a
    /// 224-bit exponent buys the 112 bits of security a 2048-bit prime is
    /// worth and anything shorter makes the exponent — not the prime — the
    /// weakest part of the exchange. `from_custom_unchecked` keeps the old
    /// permissive floor (any non-zero value) for pinned legacy interop.
    pub const MIN_CUSTOM_PRIV_BITS: usize = 224;

    /// Maximum bit length accepted by [`from_custom`](Self::from_custom) and
    /// [`from_custom_unchecked`](Self::from_custom_unchecked).
    ///
    /// The prime is peer-chosen in RFC 4419 group exchange, and every
    /// operation on it — the Montgomery precomputation, each Miller-Rabin
    /// exponentiation, every `g^x mod p` — is quadratic to cubic in its
    /// width. Without a cap a malicious server can hand over a
    /// megabit "prime" and pin the client's CPU for minutes before the
    /// primality test even finishes (a 65536-bit modulus already costs
    /// ~90 s to validate). 16384 bits is twice the largest RFC 3526 group
    /// (group18, 8192 bits) and matches the RSA modulus cap; 8192 is the
    /// largest size any deployment should actually accept, and RFC 4419
    /// clients bound the size they *ask* for anyway (`max` in the request).
    pub const MAX_CUSTOM_GROUP_BITS: usize = 16384;

    /// Miller-Rabin rounds [`from_custom`](Self::from_custom) spends on
    /// `q = (p − 1) / 2` for primes of at most 3072 bits. For a candidate
    /// that was not built against this specific test, a composite survives
    /// one round with probability ≤ 1/4, so 64 rounds bound the false-accept
    /// probability at `4⁻⁶⁴ = 2⁻¹²⁸` — the worst-case guidance for untrusted
    /// candidates (FIPS 186-5 §B.3, RFC 4419 §3 server-supplied groups).
    ///
    /// The bases are HMAC-DRBG-derived from `p` itself (no ambient RNG is
    /// plumbed through this API, and the verdict must be deterministic per
    /// group). That derivation is **public**, so this is not an adversarial
    /// bound: an attacker who grinds candidates can, in principle, search for
    /// a composite tailored to the bases its own `p` derives (the
    /// Arnault-style pseudoprime construction) — expensive, and steeply more
    /// so per round, but not provably out of reach. What keeps the verdict
    /// sound is the structure around the test: `p` itself is *proved* prime
    /// by a Lucas / Pocklington witness over the factorization `p − 1 = 2q`,
    /// so only `q`'s primality rests on Miller-Rabin. Treat a peer-supplied
    /// group as validated, not certified, and prefer the named RFC 3526
    /// groups where the choice is yours.
    ///
    /// `p` itself needs no Miller-Rabin rounds: with `p − 1 = 2q` fully
    /// factored it is *proved* prime by a Lucas / Pocklington witness (about
    /// two exponentiations; see `bignum::prime::is_safe_prime_boxed`).
    pub const CUSTOM_GROUP_MR_ROUNDS: usize = 64;

    /// Miller-Rabin rounds for primes wider than 3072 bits: 32, i.e. a
    /// `4⁻³² = 2⁻⁶⁴` false-accept bound per candidate. Each round on an
    /// 8192-bit prime is a full 8192-bit exponentiation (~0.17 s), so the
    /// 2⁻¹²⁸ target would cost ~11 s per group; 2⁻⁶⁴ is far below any
    /// practical attack budget against a *single* group-exchange peer and
    /// keeps group18-sized validation around 5 s. The 1/4-per-round bound
    /// holds for these sizes for the same reason as above (bases derived
    /// from `p`, not attacker-chosen).
    pub const CUSTOM_GROUP_MR_ROUNDS_LARGE: usize = 32;

    /// The Miller-Rabin round count [`from_custom`](Self::from_custom) uses
    /// for a `bits`-bit prime: [`CUSTOM_GROUP_MR_ROUNDS`] up to 3072 bits,
    /// [`CUSTOM_GROUP_MR_ROUNDS_LARGE`] above.
    ///
    /// [`CUSTOM_GROUP_MR_ROUNDS`]: Self::CUSTOM_GROUP_MR_ROUNDS
    /// [`CUSTOM_GROUP_MR_ROUNDS_LARGE`]: Self::CUSTOM_GROUP_MR_ROUNDS_LARGE
    pub fn custom_group_mr_rounds(bits: usize) -> usize {
        if bits <= 3072 {
            Self::CUSTOM_GROUP_MR_ROUNDS
        } else {
            Self::CUSTOM_GROUP_MR_ROUNDS_LARGE
        }
    }

    /// Builds a custom group from a caller-supplied `(p, g)` pair. Used for
    /// RFC 4419 SSH group-exchange where the server transmits the prime and
    /// generator.
    ///
    /// This constructor checks:
    /// * `p` is odd (Montgomery arithmetic requires an odd modulus, and any
    ///   safe prime is odd anyway);
    /// * `MIN_CUSTOM_GROUP_BITS ≤ p.bit_len() ≤ MAX_CUSTOM_GROUP_BITS`
    ///   (2048..=16384) — below the floor the DLP is broken in practice, see
    ///   RFC 4419 §3 and the LogJam precomputation results; above the cap a
    ///   peer-chosen prime is a CPU-exhaustion vector. Pinned legacy interop
    ///   can bypass the floor (not the cap) via
    ///   [`from_custom_unchecked`](Self::from_custom_unchecked);
    /// * `g ∈ [2, p - 2]` (the only excluded values are 0, 1, and `p - 1`,
    ///   which are tiny-order elements);
    /// * `priv_bits ≥ MIN_CUSTOM_PRIV_BITS` (224) — a short private exponent
    ///   is attackable in `2^(priv_bits/2)` work regardless of how strong the
    ///   prime is;
    /// * `p` is a **safe prime**: `q = (p − 1) / 2` passes trial division
    ///   and [`custom_group_mr_rounds`] rounds of Miller-Rabin, then `p` is
    ///   proved prime by a Lucas witness over the now-known factorization
    ///   `p − 1 = 2q`. The runtime subgroup-confinement check in
    ///   `shared_secret` (`y^q ∈ {1, p − 1}`) only prevents small-subgroup
    ///   attacks when `p` is a safe prime — for a non-safe `p` with smooth
    ///   `(p − 1) / 2`, a malicious group leaks the private exponent modulo
    ///   the small factors. The Miller-Rabin bases are drawn from an
    ///   HMAC-DRBG seeded with `p` itself, which makes the verdict
    ///   deterministic per group but also *public* — see
    ///   [`CUSTOM_GROUP_MR_ROUNDS`](Self::CUSTOM_GROUP_MR_ROUNDS) for what
    ///   that does and does not rule out;
    /// * `g` has order `q` or `2q`, i.e. `g^q ∈ {1, p − 1}` — anything else
    ///   is impossible for a genuine safe prime and would mean the group is
    ///   not what it claims to be. Both orders are accepted: OpenSSH's
    ///   `moduli` file ships generators that are primitive roots
    ///   (`g = 2` with `p ≡ 3 (mod 8)`, `g = 5`), whose public values fall
    ///   outside the order-`q` subgroup for every odd private exponent.
    ///
    /// The validation costs `custom_group_mr_rounds(bits) + ~3` modular
    /// exponentiations (about 0.2 s for a 2048-bit group, ~5 s for an
    /// 8192-bit one in an optimized build), so RFC 4419 group-exchange
    /// callers should validate a server-supplied group once and cache the
    /// result rather than re-validating on every handshake.
    ///
    /// [`custom_group_mr_rounds`]: Self::custom_group_mr_rounds
    pub fn from_custom(p: BoxedUint, g: BoxedUint, priv_bits: usize) -> Result<Self, Error> {
        use crate::bignum::prime::is_safe_prime_boxed;
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;

        // Size gates first — before any arithmetic on a peer-chosen width.
        let bits = p.bit_len();
        if !(Self::MIN_CUSTOM_GROUP_BITS..=Self::MAX_CUSTOM_GROUP_BITS).contains(&bits) {
            return Err(Error::InvalidGroup);
        }
        // A short private exponent undoes the prime's security: the generic
        // attack costs only `2^(priv_bits/2)`.
        if priv_bits < Self::MIN_CUSTOM_PRIV_BITS {
            return Err(Error::InvalidGroup);
        }
        let group = Self::from_custom_unchecked(p, g, priv_bits)?;

        // Safe-prime validation: q = (p - 1) / 2 must be a (probable) prime,
        // and p is then *proved* prime by a Lucas/Pocklington witness over
        // p - 1 = 2q. Bases come from an HMAC-DRBG seeded with the candidate
        // itself — no ambient RNG is plumbed through this API and the verdict
        // has to be reproducible — but that derivation is public, so the
        // Miller-Rabin half is not an adversarial bound; see
        // `CUSTOM_GROUP_MR_ROUNDS`.
        let mut rng = HmacDrbg::<Sha256>::new(
            &group.p.to_be_bytes(group.byte_size()),
            b"purecrypto-dh-custom-group-mr-bases",
            &[],
        );
        if !is_safe_prime_boxed(&group.p, &mut rng, Self::custom_group_mr_rounds(bits)) {
            return Err(Error::InvalidGroup);
        }

        // Generator order: for a safe prime every element other than 0, ±1
        // has order q or 2q, i.e. g^q ∈ {1, p − 1}. (The range check in
        // `from_custom_unchecked` already excluded 0, 1 and p − 1.)
        let one = BoxedUint::from_u64(1);
        let p_minus_one = group.p.sub(&one);
        let q = p_minus_one.shr_bits(1);
        let g_to_q = group.mont.pow(&group.g, &q);
        if g_to_q != one && g_to_q != p_minus_one {
            return Err(Error::InvalidGroup);
        }
        Ok(group)
    }

    /// Like [`from_custom`](Self::from_custom) but without the
    /// [`MIN_CUSTOM_GROUP_BITS`](Self::MIN_CUSTOM_GROUP_BITS) floor, the
    /// safe-prime (Miller-Rabin) validation, or the generator-order check —
    /// intended only for tests and pinned legacy interop where the caller
    /// has documented why a sub-2048-bit or externally validated prime is
    /// acceptable. The structural checks (odd modulus no wider than
    /// [`MAX_CUSTOM_GROUP_BITS`](Self::MAX_CUSTOM_GROUP_BITS), generator in
    /// range, sane private-exponent bit budget) still apply. Note that the
    /// small-subgroup defense in `shared_secret` assumes a safe prime; the
    /// caller owns that property here.
    pub fn from_custom_unchecked(
        p: BoxedUint,
        g: BoxedUint,
        priv_bits: usize,
    ) -> Result<Self, Error> {
        // Width cap before any arithmetic: `p.sub` below and the Montgomery
        // precomputation later are the first things a huge modulus would
        // make expensive.
        if p.bit_len() > Self::MAX_CUSTOM_GROUP_BITS {
            return Err(Error::InvalidGroup);
        }
        if !p.is_odd() || p.bit_len() < 3 {
            return Err(Error::InvalidGroup);
        }
        let two = BoxedUint::from_u64(2);
        let p_minus_one = p.sub(&BoxedUint::from_u64(1));
        // g ∈ [2, p - 2]  ⇔  g ≥ 2 AND g < p - 1.
        if g.lt(&two) || !g.lt(&p_minus_one) {
            return Err(Error::InvalidGroup);
        }
        if priv_bits == 0 || priv_bits > p.bit_len() {
            return Err(Error::InvalidGroup);
        }
        let mont = BoxedMontModulus::new(&p);
        Ok(DhGroup {
            name: "custom",
            p,
            g,
            priv_bits,
            known_safe_prime: false,
            q: None,
            mont,
        })
    }

    /// Minimum bit length of `p` accepted by
    /// [`from_params`](Self::from_params).
    ///
    /// Lower than [`MIN_CUSTOM_GROUP_BITS`](Self::MIN_CUSTOM_GROUP_BITS)
    /// because the explicit-subgroup groups in actual use start at 1024 bits:
    /// RFC 5114 §2.1's 1024/160 group (IKE group 22, the `dh_1024_160`
    /// OpenSSL ships) and the 1024-bit X9.42 parameters older PKIX / S/MIME
    /// deployments carry. 1024 is also RFC 4419 §3's floor. It is an interop
    /// floor, not a security one — the LogJam caveats on
    /// `MIN_CUSTOM_GROUP_BITS` apply in full.
    pub const MIN_PARAMS_GROUP_BITS: usize = 1024;

    /// Minimum bit length of `q` accepted by
    /// [`from_params`](Self::from_params): 160, the smallest subgroup
    /// RFC 5114 / FIPS 186-2 use. Private exponents live in `[1, q − 1]`,
    /// so Pollard rho in the subgroup costs `2^(N/2)` and a narrower `q`
    /// would be the weakest part of the exchange.
    pub const MIN_PARAMS_Q_BITS: usize = 160;

    /// Builds a group from an explicit `(p, g, q)` triple: `g` generates the
    /// order-`q` subgroup of `Z_p^*` for a prime `q | p − 1` — the RFC 5114
    /// groups and the ANSI X9.42 `DomainParameters` (`openssl dhparam
    /// -dsaparam`, `X9.42 DH PARAMETERS` PEM files), which are not safe
    /// primes and so cannot go through [`from_custom`](Self::from_custom).
    ///
    /// Checks:
    /// * `MIN_PARAMS_GROUP_BITS ≤ p.bit_len() ≤ MAX_CUSTOM_GROUP_BITS`
    ///   (1024..=16384) and `q.bit_len() ≥ MIN_PARAMS_Q_BITS` (160), before
    ///   any arithmetic;
    /// * `p` and `q` odd, `g ∈ [2, p − 2]` (as
    ///   [`from_custom_unchecked`](Self::from_custom_unchecked));
    /// * `q | p − 1`;
    /// * `g^q ≡ 1 (mod p)` — with `g ≠ 1` and `q` prime, `g` has order
    ///   exactly `q`;
    /// * `q` passes trial division and
    ///   [`CUSTOM_GROUP_MR_ROUNDS`](Self::CUSTOM_GROUP_MR_ROUNDS) Miller-Rabin
    ///   rounds, and `p` [`custom_group_mr_rounds`] rounds — both with bases
    ///   HMAC-DRBG-derived from the candidate, i.e. deterministic and
    ///   *public*, with the caveat spelled out on `CUSTOM_GROUP_MR_ROUNDS`.
    ///   Unlike the safe-prime case `p` cannot be proved prime from `q`
    ///   (`q` is far below `√p`), so both verdicts rest on Miller-Rabin.
    ///
    /// The resulting group draws private keys uniformly from `[1, q − 1]`
    /// ([`priv_bits`](Self::priv_bits) reports `q`'s width; NIST SP 800-56A
    /// Rev 3 §5.6.1.1.4), and [`DhPrivateKey::shared_secret`] requires the
    /// peer value to satisfy `y^q ≡ 1 (mod p)` on top of `2 ≤ y ≤ p − 2`
    /// (the SP 800-56A §5.6.2.3.1 full public-key validation for FFC
    /// groups that are not safe primes). Passing a safe prime with
    /// `q = (p − 1) / 2` works too, but then the order-`2q` values that
    /// [`from_custom`](Self::from_custom) admits are rejected.
    ///
    /// Validation costs about `custom_group_mr_rounds(L)` full-width
    /// exponentiations (dominated by the `p` test); validate a group once
    /// and clone it.
    ///
    /// [`custom_group_mr_rounds`]: Self::custom_group_mr_rounds
    /// [`DhPrivateKey::shared_secret`]: super::DhPrivateKey::shared_secret
    pub fn from_params(p: BoxedUint, g: BoxedUint, q: BoxedUint) -> Result<Self, Error> {
        use crate::bignum::prime::is_prime_boxed;
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;

        // Size gates first — before any arithmetic on a peer-chosen width.
        let bits = p.bit_len();
        if !(Self::MIN_PARAMS_GROUP_BITS..=Self::MAX_CUSTOM_GROUP_BITS).contains(&bits)
            || q.bit_len() < Self::MIN_PARAMS_Q_BITS
            || !q.is_odd()
        {
            return Err(Error::InvalidGroup);
        }
        // Odd `p`, `g ∈ [2, p − 2]`; the exponent budget is `q`'s width,
        // which is below `p`'s whenever `q | p − 1` holds.
        let mut group = Self::from_custom_unchecked(p, g, q.bit_len())?;
        let one = BoxedUint::from_u64(1);
        if !group.p.sub(&one).reduce(&q).is_zero() {
            return Err(Error::InvalidGroup);
        }
        // Everything here is public, so the variable-time ladder is fine.
        if group.mont.pow_public(&group.g, &q) != one {
            return Err(Error::InvalidGroup);
        }
        // `q` first: it is narrow, so a bad one is rejected cheaply.
        let mut rng = HmacDrbg::<Sha256>::new(
            &q.to_be_bytes(q.bit_len().div_ceil(8)),
            b"purecrypto-dh-params-q-mr-bases",
            &[],
        );
        if !is_prime_boxed(&q, &mut rng, Self::CUSTOM_GROUP_MR_ROUNDS) {
            return Err(Error::InvalidGroup);
        }
        let mut rng = HmacDrbg::<Sha256>::new(
            &group.p.to_be_bytes(group.byte_size()),
            b"purecrypto-dh-params-p-mr-bases",
            &[],
        );
        if !is_prime_boxed(&group.p, &mut rng, Self::custom_group_mr_rounds(bits)) {
            return Err(Error::InvalidGroup);
        }
        group.q = Some(q);
        Ok(group)
    }
}

// ---------------------------------------------------------------------------
// RFC 3526 — MODP groups 14, 15, 16, 17, 18.
//
// Primes transcribed verbatim from RFC 3526. `g = 2` for every group. Each
// prime byte length:
//   group14 → 256 bytes (2048 bits)
//   group15 → 384 bytes (3072 bits)
//   group16 → 512 bytes (4096 bits)
//   group17 → 768 bytes (6144 bits)
//   group18 → 1024 bytes (8192 bits)
// ---------------------------------------------------------------------------

/// RFC 3526 §3 — 2048-bit MODP group ("group14"). The SSH
/// `diffie-hellman-group14-sha256` key exchange and the legacy
/// `dh_2048` IKEv2 group.
#[rustfmt::skip]
static GROUP14_P: [u8; 256] = [
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
    0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1, 0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
    0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22, 0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B, 0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
    0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45, 0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
    0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B, 0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5, 0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
    0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D, 0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
    0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A, 0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96, 0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
    0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D, 0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
    0xF1,0x74,0x6C,0x08,0xCA,0x18,0x21,0x7C, 0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
    0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03, 0x9B,0x27,0x83,0xA2,0xEC,0x07,0xA2,0x8F,
    0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9, 0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,
    0x39,0x95,0x49,0x7C,0xEA,0x95,0x6A,0xE5, 0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
    0x15,0x72,0x8E,0x5A,0x8A,0xAC,0xAA,0x68, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
];

/// RFC 3526 §4 — 3072-bit MODP group ("group15").
#[rustfmt::skip]
static GROUP15_P: [u8; 384] = [
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
    0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1, 0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
    0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22, 0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B, 0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
    0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45, 0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
    0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B, 0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5, 0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
    0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D, 0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
    0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A, 0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96, 0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
    0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D, 0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
    0xF1,0x74,0x6C,0x08,0xCA,0x18,0x21,0x7C, 0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
    0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03, 0x9B,0x27,0x83,0xA2,0xEC,0x07,0xA2,0x8F,
    0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9, 0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,
    0x39,0x95,0x49,0x7C,0xEA,0x95,0x6A,0xE5, 0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
    0x15,0x72,0x8E,0x5A,0x8A,0xAA,0xC4,0x2D, 0xAD,0x33,0x17,0x0D,0x04,0x50,0x7A,0x33,
    0xA8,0x55,0x21,0xAB,0xDF,0x1C,0xBA,0x64, 0xEC,0xFB,0x85,0x04,0x58,0xDB,0xEF,0x0A,
    0x8A,0xEA,0x71,0x57,0x5D,0x06,0x0C,0x7D, 0xB3,0x97,0x0F,0x85,0xA6,0xE1,0xE4,0xC7,
    0xAB,0xF5,0xAE,0x8C,0xDB,0x09,0x33,0xD7, 0x1E,0x8C,0x94,0xE0,0x4A,0x25,0x61,0x9D,
    0xCE,0xE3,0xD2,0x26,0x1A,0xD2,0xEE,0x6B, 0xF1,0x2F,0xFA,0x06,0xD9,0x8A,0x08,0x64,
    0xD8,0x76,0x02,0x73,0x3E,0xC8,0x6A,0x64, 0x52,0x1F,0x2B,0x18,0x17,0x7B,0x20,0x0C,
    0xBB,0xE1,0x17,0x57,0x7A,0x61,0x5D,0x6C, 0x77,0x09,0x88,0xC0,0xBA,0xD9,0x46,0xE2,
    0x08,0xE2,0x4F,0xA0,0x74,0xE5,0xAB,0x31, 0x43,0xDB,0x5B,0xFC,0xE0,0xFD,0x10,0x8E,
    0x4B,0x82,0xD1,0x20,0xA9,0x3A,0xD2,0xCA, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
];

/// RFC 3526 §5 — 4096-bit MODP group ("group16"). The SSH
/// `diffie-hellman-group16-sha512` key exchange.
#[rustfmt::skip]
static GROUP16_P: [u8; 512] = [
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
    0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1, 0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
    0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22, 0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B, 0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
    0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45, 0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
    0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B, 0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5, 0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
    0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D, 0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
    0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A, 0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96, 0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
    0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D, 0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
    0xF1,0x74,0x6C,0x08,0xCA,0x18,0x21,0x7C, 0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
    0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03, 0x9B,0x27,0x83,0xA2,0xEC,0x07,0xA2,0x8F,
    0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9, 0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,
    0x39,0x95,0x49,0x7C,0xEA,0x95,0x6A,0xE5, 0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
    0x15,0x72,0x8E,0x5A,0x8A,0xAA,0xC4,0x2D, 0xAD,0x33,0x17,0x0D,0x04,0x50,0x7A,0x33,
    0xA8,0x55,0x21,0xAB,0xDF,0x1C,0xBA,0x64, 0xEC,0xFB,0x85,0x04,0x58,0xDB,0xEF,0x0A,
    0x8A,0xEA,0x71,0x57,0x5D,0x06,0x0C,0x7D, 0xB3,0x97,0x0F,0x85,0xA6,0xE1,0xE4,0xC7,
    0xAB,0xF5,0xAE,0x8C,0xDB,0x09,0x33,0xD7, 0x1E,0x8C,0x94,0xE0,0x4A,0x25,0x61,0x9D,
    0xCE,0xE3,0xD2,0x26,0x1A,0xD2,0xEE,0x6B, 0xF1,0x2F,0xFA,0x06,0xD9,0x8A,0x08,0x64,
    0xD8,0x76,0x02,0x73,0x3E,0xC8,0x6A,0x64, 0x52,0x1F,0x2B,0x18,0x17,0x7B,0x20,0x0C,
    0xBB,0xE1,0x17,0x57,0x7A,0x61,0x5D,0x6C, 0x77,0x09,0x88,0xC0,0xBA,0xD9,0x46,0xE2,
    0x08,0xE2,0x4F,0xA0,0x74,0xE5,0xAB,0x31, 0x43,0xDB,0x5B,0xFC,0xE0,0xFD,0x10,0x8E,
    0x4B,0x82,0xD1,0x20,0xA9,0x21,0x08,0x01, 0x1A,0x72,0x3C,0x12,0xA7,0x87,0xE6,0xD7,
    0x88,0x71,0x9A,0x10,0xBD,0xBA,0x5B,0x26, 0x99,0xC3,0x27,0x18,0x6A,0xF4,0xE2,0x3C,
    0x1A,0x94,0x68,0x34,0xB6,0x15,0x0B,0xDA, 0x25,0x83,0xE9,0xCA,0x2A,0xD4,0x4C,0xE8,
    0xDB,0xBB,0xC2,0xDB,0x04,0xDE,0x8E,0xF9, 0x2E,0x8E,0xFC,0x14,0x1F,0xBE,0xCA,0xA6,
    0x28,0x7C,0x59,0x47,0x4E,0x6B,0xC0,0x5D, 0x99,0xB2,0x96,0x4F,0xA0,0x90,0xC3,0xA2,
    0x23,0x3B,0xA1,0x86,0x51,0x5B,0xE7,0xED, 0x1F,0x61,0x29,0x70,0xCE,0xE2,0xD7,0xAF,
    0xB8,0x1B,0xDD,0x76,0x21,0x70,0x48,0x1C, 0xD0,0x06,0x91,0x27,0xD5,0xB0,0x5A,0xA9,
    0x93,0xB4,0xEA,0x98,0x8D,0x8F,0xDD,0xC1, 0x86,0xFF,0xB7,0xDC,0x90,0xA6,0xC0,0x8F,
    0x4D,0xF4,0x35,0xC9,0x34,0x06,0x31,0x99, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
];

/// RFC 3526 §6 — 6144-bit MODP group ("group17").
#[rustfmt::skip]
static GROUP17_P: [u8; 768] = [
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
    0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1, 0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
    0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22, 0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B, 0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
    0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45, 0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
    0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B, 0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5, 0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
    0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D, 0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
    0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A, 0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96, 0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
    0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D, 0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
    0xF1,0x74,0x6C,0x08,0xCA,0x18,0x21,0x7C, 0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
    0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03, 0x9B,0x27,0x83,0xA2,0xEC,0x07,0xA2,0x8F,
    0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9, 0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,
    0x39,0x95,0x49,0x7C,0xEA,0x95,0x6A,0xE5, 0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
    0x15,0x72,0x8E,0x5A,0x8A,0xAA,0xC4,0x2D, 0xAD,0x33,0x17,0x0D,0x04,0x50,0x7A,0x33,
    0xA8,0x55,0x21,0xAB,0xDF,0x1C,0xBA,0x64, 0xEC,0xFB,0x85,0x04,0x58,0xDB,0xEF,0x0A,
    0x8A,0xEA,0x71,0x57,0x5D,0x06,0x0C,0x7D, 0xB3,0x97,0x0F,0x85,0xA6,0xE1,0xE4,0xC7,
    0xAB,0xF5,0xAE,0x8C,0xDB,0x09,0x33,0xD7, 0x1E,0x8C,0x94,0xE0,0x4A,0x25,0x61,0x9D,
    0xCE,0xE3,0xD2,0x26,0x1A,0xD2,0xEE,0x6B, 0xF1,0x2F,0xFA,0x06,0xD9,0x8A,0x08,0x64,
    0xD8,0x76,0x02,0x73,0x3E,0xC8,0x6A,0x64, 0x52,0x1F,0x2B,0x18,0x17,0x7B,0x20,0x0C,
    0xBB,0xE1,0x17,0x57,0x7A,0x61,0x5D,0x6C, 0x77,0x09,0x88,0xC0,0xBA,0xD9,0x46,0xE2,
    0x08,0xE2,0x4F,0xA0,0x74,0xE5,0xAB,0x31, 0x43,0xDB,0x5B,0xFC,0xE0,0xFD,0x10,0x8E,
    0x4B,0x82,0xD1,0x20,0xA9,0x21,0x08,0x01, 0x1A,0x72,0x3C,0x12,0xA7,0x87,0xE6,0xD7,
    0x88,0x71,0x9A,0x10,0xBD,0xBA,0x5B,0x26, 0x99,0xC3,0x27,0x18,0x6A,0xF4,0xE2,0x3C,
    0x1A,0x94,0x68,0x34,0xB6,0x15,0x0B,0xDA, 0x25,0x83,0xE9,0xCA,0x2A,0xD4,0x4C,0xE8,
    0xDB,0xBB,0xC2,0xDB,0x04,0xDE,0x8E,0xF9, 0x2E,0x8E,0xFC,0x14,0x1F,0xBE,0xCA,0xA6,
    0x28,0x7C,0x59,0x47,0x4E,0x6B,0xC0,0x5D, 0x99,0xB2,0x96,0x4F,0xA0,0x90,0xC3,0xA2,
    0x23,0x3B,0xA1,0x86,0x51,0x5B,0xE7,0xED, 0x1F,0x61,0x29,0x70,0xCE,0xE2,0xD7,0xAF,
    0xB8,0x1B,0xDD,0x76,0x21,0x70,0x48,0x1C, 0xD0,0x06,0x91,0x27,0xD5,0xB0,0x5A,0xA9,
    0x93,0xB4,0xEA,0x98,0x8D,0x8F,0xDD,0xC1, 0x86,0xFF,0xB7,0xDC,0x90,0xA6,0xC0,0x8F,
    0x4D,0xF4,0x35,0xC9,0x34,0x02,0x84,0x92, 0x36,0xC3,0xFA,0xB4,0xD2,0x7C,0x70,0x26,
    0xC1,0xD4,0xDC,0xB2,0x60,0x26,0x46,0xDE, 0xC9,0x75,0x1E,0x76,0x3D,0xBA,0x37,0xBD,
    0xF8,0xFF,0x94,0x06,0xAD,0x9E,0x53,0x0E, 0xE5,0xDB,0x38,0x2F,0x41,0x30,0x01,0xAE,
    0xB0,0x6A,0x53,0xED,0x90,0x27,0xD8,0x31, 0x17,0x97,0x27,0xB0,0x86,0x5A,0x89,0x18,
    0xDA,0x3E,0xDB,0xEB,0xCF,0x9B,0x14,0xED, 0x44,0xCE,0x6C,0xBA,0xCE,0xD4,0xBB,0x1B,
    0xDB,0x7F,0x14,0x47,0xE6,0xCC,0x25,0x4B, 0x33,0x20,0x51,0x51,0x2B,0xD7,0xAF,0x42,
    0x6F,0xB8,0xF4,0x01,0x37,0x8C,0xD2,0xBF, 0x59,0x83,0xCA,0x01,0xC6,0x4B,0x92,0xEC,
    0xF0,0x32,0xEA,0x15,0xD1,0x72,0x1D,0x03, 0xF4,0x82,0xD7,0xCE,0x6E,0x74,0xFE,0xF6,
    0xD5,0x5E,0x70,0x2F,0x46,0x98,0x0C,0x82, 0xB5,0xA8,0x40,0x31,0x90,0x0B,0x1C,0x9E,
    0x59,0xE7,0xC9,0x7F,0xBE,0xC7,0xE8,0xF3, 0x23,0xA9,0x7A,0x7E,0x36,0xCC,0x88,0xBE,
    0x0F,0x1D,0x45,0xB7,0xFF,0x58,0x5A,0xC5, 0x4B,0xD4,0x07,0xB2,0x2B,0x41,0x54,0xAA,
    0xCC,0x8F,0x6D,0x7E,0xBF,0x48,0xE1,0xD8, 0x14,0xCC,0x5E,0xD2,0x0F,0x80,0x37,0xE0,
    0xA7,0x97,0x15,0xEE,0xF2,0x9B,0xE3,0x28, 0x06,0xA1,0xD5,0x8B,0xB7,0xC5,0xDA,0x76,
    0xF5,0x50,0xAA,0x3D,0x8A,0x1F,0xBF,0xF0, 0xEB,0x19,0xCC,0xB1,0xA3,0x13,0xD5,0x5C,
    0xDA,0x56,0xC9,0xEC,0x2E,0xF2,0x96,0x32, 0x38,0x7F,0xE8,0xD7,0x6E,0x3C,0x04,0x68,
    0x04,0x3E,0x8F,0x66,0x3F,0x48,0x60,0xEE, 0x12,0xBF,0x2D,0x5B,0x0B,0x74,0x74,0xD6,
    0xE6,0x94,0xF9,0x1E,0x6D,0xCC,0x40,0x24, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
];

/// RFC 3526 §7 — 8192-bit MODP group ("group18").
#[rustfmt::skip]
static GROUP18_P: [u8; 1024] = [
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
    0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1, 0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
    0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22, 0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
    0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B, 0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
    0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45, 0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
    0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B, 0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
    0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5, 0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
    0x49,0x28,0x66,0x51,0xEC,0xE4,0x5B,0x3D, 0xC2,0x00,0x7C,0xB8,0xA1,0x63,0xBF,0x05,
    0x98,0xDA,0x48,0x36,0x1C,0x55,0xD3,0x9A, 0x69,0x16,0x3F,0xA8,0xFD,0x24,0xCF,0x5F,
    0x83,0x65,0x5D,0x23,0xDC,0xA3,0xAD,0x96, 0x1C,0x62,0xF3,0x56,0x20,0x85,0x52,0xBB,
    0x9E,0xD5,0x29,0x07,0x70,0x96,0x96,0x6D, 0x67,0x0C,0x35,0x4E,0x4A,0xBC,0x98,0x04,
    0xF1,0x74,0x6C,0x08,0xCA,0x18,0x21,0x7C, 0x32,0x90,0x5E,0x46,0x2E,0x36,0xCE,0x3B,
    0xE3,0x9E,0x77,0x2C,0x18,0x0E,0x86,0x03, 0x9B,0x27,0x83,0xA2,0xEC,0x07,0xA2,0x8F,
    0xB5,0xC5,0x5D,0xF0,0x6F,0x4C,0x52,0xC9, 0xDE,0x2B,0xCB,0xF6,0x95,0x58,0x17,0x18,
    0x39,0x95,0x49,0x7C,0xEA,0x95,0x6A,0xE5, 0x15,0xD2,0x26,0x18,0x98,0xFA,0x05,0x10,
    0x15,0x72,0x8E,0x5A,0x8A,0xAA,0xC4,0x2D, 0xAD,0x33,0x17,0x0D,0x04,0x50,0x7A,0x33,
    0xA8,0x55,0x21,0xAB,0xDF,0x1C,0xBA,0x64, 0xEC,0xFB,0x85,0x04,0x58,0xDB,0xEF,0x0A,
    0x8A,0xEA,0x71,0x57,0x5D,0x06,0x0C,0x7D, 0xB3,0x97,0x0F,0x85,0xA6,0xE1,0xE4,0xC7,
    0xAB,0xF5,0xAE,0x8C,0xDB,0x09,0x33,0xD7, 0x1E,0x8C,0x94,0xE0,0x4A,0x25,0x61,0x9D,
    0xCE,0xE3,0xD2,0x26,0x1A,0xD2,0xEE,0x6B, 0xF1,0x2F,0xFA,0x06,0xD9,0x8A,0x08,0x64,
    0xD8,0x76,0x02,0x73,0x3E,0xC8,0x6A,0x64, 0x52,0x1F,0x2B,0x18,0x17,0x7B,0x20,0x0C,
    0xBB,0xE1,0x17,0x57,0x7A,0x61,0x5D,0x6C, 0x77,0x09,0x88,0xC0,0xBA,0xD9,0x46,0xE2,
    0x08,0xE2,0x4F,0xA0,0x74,0xE5,0xAB,0x31, 0x43,0xDB,0x5B,0xFC,0xE0,0xFD,0x10,0x8E,
    0x4B,0x82,0xD1,0x20,0xA9,0x21,0x08,0x01, 0x1A,0x72,0x3C,0x12,0xA7,0x87,0xE6,0xD7,
    0x88,0x71,0x9A,0x10,0xBD,0xBA,0x5B,0x26, 0x99,0xC3,0x27,0x18,0x6A,0xF4,0xE2,0x3C,
    0x1A,0x94,0x68,0x34,0xB6,0x15,0x0B,0xDA, 0x25,0x83,0xE9,0xCA,0x2A,0xD4,0x4C,0xE8,
    0xDB,0xBB,0xC2,0xDB,0x04,0xDE,0x8E,0xF9, 0x2E,0x8E,0xFC,0x14,0x1F,0xBE,0xCA,0xA6,
    0x28,0x7C,0x59,0x47,0x4E,0x6B,0xC0,0x5D, 0x99,0xB2,0x96,0x4F,0xA0,0x90,0xC3,0xA2,
    0x23,0x3B,0xA1,0x86,0x51,0x5B,0xE7,0xED, 0x1F,0x61,0x29,0x70,0xCE,0xE2,0xD7,0xAF,
    0xB8,0x1B,0xDD,0x76,0x21,0x70,0x48,0x1C, 0xD0,0x06,0x91,0x27,0xD5,0xB0,0x5A,0xA9,
    0x93,0xB4,0xEA,0x98,0x8D,0x8F,0xDD,0xC1, 0x86,0xFF,0xB7,0xDC,0x90,0xA6,0xC0,0x8F,
    0x4D,0xF4,0x35,0xC9,0x34,0x02,0x84,0x92, 0x36,0xC3,0xFA,0xB4,0xD2,0x7C,0x70,0x26,
    0xC1,0xD4,0xDC,0xB2,0x60,0x26,0x46,0xDE, 0xC9,0x75,0x1E,0x76,0x3D,0xBA,0x37,0xBD,
    0xF8,0xFF,0x94,0x06,0xAD,0x9E,0x53,0x0E, 0xE5,0xDB,0x38,0x2F,0x41,0x30,0x01,0xAE,
    0xB0,0x6A,0x53,0xED,0x90,0x27,0xD8,0x31, 0x17,0x97,0x27,0xB0,0x86,0x5A,0x89,0x18,
    0xDA,0x3E,0xDB,0xEB,0xCF,0x9B,0x14,0xED, 0x44,0xCE,0x6C,0xBA,0xCE,0xD4,0xBB,0x1B,
    0xDB,0x7F,0x14,0x47,0xE6,0xCC,0x25,0x4B, 0x33,0x20,0x51,0x51,0x2B,0xD7,0xAF,0x42,
    0x6F,0xB8,0xF4,0x01,0x37,0x8C,0xD2,0xBF, 0x59,0x83,0xCA,0x01,0xC6,0x4B,0x92,0xEC,
    0xF0,0x32,0xEA,0x15,0xD1,0x72,0x1D,0x03, 0xF4,0x82,0xD7,0xCE,0x6E,0x74,0xFE,0xF6,
    0xD5,0x5E,0x70,0x2F,0x46,0x98,0x0C,0x82, 0xB5,0xA8,0x40,0x31,0x90,0x0B,0x1C,0x9E,
    0x59,0xE7,0xC9,0x7F,0xBE,0xC7,0xE8,0xF3, 0x23,0xA9,0x7A,0x7E,0x36,0xCC,0x88,0xBE,
    0x0F,0x1D,0x45,0xB7,0xFF,0x58,0x5A,0xC5, 0x4B,0xD4,0x07,0xB2,0x2B,0x41,0x54,0xAA,
    0xCC,0x8F,0x6D,0x7E,0xBF,0x48,0xE1,0xD8, 0x14,0xCC,0x5E,0xD2,0x0F,0x80,0x37,0xE0,
    0xA7,0x97,0x15,0xEE,0xF2,0x9B,0xE3,0x28, 0x06,0xA1,0xD5,0x8B,0xB7,0xC5,0xDA,0x76,
    0xF5,0x50,0xAA,0x3D,0x8A,0x1F,0xBF,0xF0, 0xEB,0x19,0xCC,0xB1,0xA3,0x13,0xD5,0x5C,
    0xDA,0x56,0xC9,0xEC,0x2E,0xF2,0x96,0x32, 0x38,0x7F,0xE8,0xD7,0x6E,0x3C,0x04,0x68,
    0x04,0x3E,0x8F,0x66,0x3F,0x48,0x60,0xEE, 0x12,0xBF,0x2D,0x5B,0x0B,0x74,0x74,0xD6,
    0xE6,0x94,0xF9,0x1E,0x6D,0xBE,0x11,0x59, 0x74,0xA3,0x92,0x6F,0x12,0xFE,0xE5,0xE4,
    0x38,0x77,0x7C,0xB6,0xA9,0x32,0xDF,0x8C, 0xD8,0xBE,0xC4,0xD0,0x73,0xB9,0x31,0xBA,
    0x3B,0xC8,0x32,0xB6,0x8D,0x9D,0xD3,0x00, 0x74,0x1F,0xA7,0xBF,0x8A,0xFC,0x47,0xED,
    0x25,0x76,0xF6,0x93,0x6B,0xA4,0x24,0x66, 0x3A,0xAB,0x63,0x9C,0x5A,0xE4,0xF5,0x68,
    0x34,0x23,0xB4,0x74,0x2B,0xF1,0xC9,0x78, 0x23,0x8F,0x16,0xCB,0xE3,0x9D,0x65,0x2D,
    0xE3,0xFD,0xB8,0xBE,0xFC,0x84,0x8A,0xD9, 0x22,0x22,0x2E,0x04,0xA4,0x03,0x7C,0x07,
    0x13,0xEB,0x57,0xA8,0x1A,0x23,0xF0,0xC7, 0x34,0x73,0xFC,0x64,0x6C,0xEA,0x30,0x6B,
    0x4B,0xCB,0xC8,0x86,0x2F,0x83,0x85,0xDD, 0xFA,0x9D,0x4B,0x7F,0xA2,0xC0,0x87,0xE8,
    0x79,0x68,0x33,0x03,0xED,0x5B,0xDD,0x3A, 0x06,0x2B,0x3C,0xF5,0xB3,0xA2,0x78,0xA6,
    0x6D,0x2A,0x13,0xF8,0x3F,0x44,0xF8,0x2D, 0xDF,0x31,0x0E,0xE0,0x74,0xAB,0x6A,0x36,
    0x45,0x97,0xE8,0x99,0xA0,0x25,0x5D,0xC1, 0x64,0xF3,0x1C,0xC5,0x08,0x46,0x85,0x1D,
    0xF9,0xAB,0x48,0x19,0x5D,0xED,0x7E,0xA1, 0xB1,0xD5,0x10,0xBD,0x7E,0xE7,0x4D,0x73,
    0xFA,0xF3,0x6B,0xC3,0x1E,0xCF,0xA2,0x68, 0x35,0x90,0x46,0xF4,0xEB,0x87,0x9F,0x92,
    0x40,0x09,0x43,0x8B,0x48,0x1C,0x6C,0xD7, 0x88,0x9A,0x00,0x2E,0xD5,0xEE,0x38,0x2B,
    0xC9,0x19,0x0D,0xA6,0xFC,0x02,0x6E,0x47, 0x95,0x58,0xE4,0x47,0x56,0x77,0xE9,0xAA,
    0x9E,0x30,0x50,0xE2,0x76,0x56,0x94,0xDF, 0xC8,0x1F,0x56,0xE8,0x80,0xB9,0x6E,0x71,
    0x60,0xC9,0x80,0xDD,0x98,0xED,0xD3,0xDF, 0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
];

/// Constructs a [`DhGroup`] for RFC 3526 group14 (2048-bit prime).
///
/// `priv_bits = 256` per RFC 7919 §A — twice the symmetric security level
/// (~AES-128) targeted by a 2048-bit prime.
pub fn group14() -> DhGroup {
    let p = BoxedUint::from_be_bytes(&GROUP14_P);
    let mont = BoxedMontModulus::new(&p);
    DhGroup {
        name: "group14",
        p,
        g: BoxedUint::from_u64(2),
        priv_bits: 256,
        known_safe_prime: true,
        q: None,
        mont,
    }
}

/// Constructs a [`DhGroup`] for RFC 3526 group15 (3072-bit prime).
///
/// `priv_bits = 288`: RFC 7919 §5.2 / Appendix A recommends at least 275
/// bits of private exponent for a 3072-bit prime (twice the ~137-bit
/// security estimate), rounded up to a whole number of 32-bit words.
pub fn group15() -> DhGroup {
    let p = BoxedUint::from_be_bytes(&GROUP15_P);
    let mont = BoxedMontModulus::new(&p);
    DhGroup {
        name: "group15",
        p,
        g: BoxedUint::from_u64(2),
        priv_bits: 288,
        known_safe_prime: true,
        q: None,
        mont,
    }
}

/// Constructs a [`DhGroup`] for RFC 3526 group16 (4096-bit prime).
///
/// `priv_bits = 384` (RFC 7919 §A guidance for ~AES-192 symmetric strength).
pub fn group16() -> DhGroup {
    let p = BoxedUint::from_be_bytes(&GROUP16_P);
    let mont = BoxedMontModulus::new(&p);
    DhGroup {
        name: "group16",
        p,
        g: BoxedUint::from_u64(2),
        priv_bits: 384,
        known_safe_prime: true,
        q: None,
        mont,
    }
}

/// Constructs a [`DhGroup`] for RFC 3526 group17 (6144-bit prime).
///
/// `priv_bits = 512` (RFC 7919 §A guidance for ~AES-256 symmetric strength).
pub fn group17() -> DhGroup {
    let p = BoxedUint::from_be_bytes(&GROUP17_P);
    let mont = BoxedMontModulus::new(&p);
    DhGroup {
        name: "group17",
        p,
        g: BoxedUint::from_u64(2),
        priv_bits: 512,
        known_safe_prime: true,
        q: None,
        mont,
    }
}

/// Constructs a [`DhGroup`] for RFC 3526 group18 (8192-bit prime).
///
/// `priv_bits = 512` (RFC 7919 §A guidance for ~AES-256 symmetric strength).
pub fn group18() -> DhGroup {
    let p = BoxedUint::from_be_bytes(&GROUP18_P);
    let mont = BoxedMontModulus::new(&p);
    DhGroup {
        name: "group18",
        p,
        g: BoxedUint::from_u64(2),
        priv_bits: 512,
        known_safe_prime: true,
        q: None,
        mont,
    }
}

/// The three RFC 5114 §2.1–2.3 groups, as `(p, g, q)` hex — transcribed
/// from the `dh_1024_160`, `dh_2048_224` and `dh_2048_256` X9.42
/// `DomainParameters` OpenSSL emits for `genpkey -genparam -algorithm DHX
/// -pkeyopt dh_rfc5114:{1,2,3}` (DER order `p, g, q`). Test fixtures for
/// [`DhGroup::from_params`].
#[cfg(test)]
pub(crate) mod rfc5114 {
    use super::DhGroup;
    use crate::bignum::BoxedUint;

    // RFC 5114 §2.1: 1024-bit p, 160-bit q.
    pub(crate) const P_1024_160: &str = "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B61\
        6073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BF\
        ACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0\
        A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371";
    pub(crate) const G_1024_160: &str = "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31\
        266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4\
        D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A\
        D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5";
    pub(crate) const Q_1024_160: &str = "F518AA8781A8DF278ABA4E7D64B7CB9D49462353";
    // RFC 5114 §2.2: 2048-bit p, 224-bit q.
    pub(crate) const P_2048_224: &str = "AD107E1E9123A9D0D660FAA79559C51FA20D64E5683B9FD1B54B1597B61D0A75\
        E6FA141DF95A56DBAF9A3C407BA1DF15EB3D688A309C180E1DE6B85A1274A0A6\
        6D3F8152AD6AC2129037C9EDEFDA4DF8D91E8FEF55B7394B7AD5B7D0B6C12207\
        C9F98D11ED34DBF6C6BA0B2C8BBC27BE6A00E0A0B9C49708B3BF8A3170918836\
        81286130BC8985DB1602E714415D9330278273C7DE31EFDC7310F7121FD5A074\
        15987D9ADC0A486DCDF93ACC44328387315D75E198C641A480CD86A1B9E587E8\
        BE60E69CC928B2B9C52172E413042E9B23F10B0E16E79763C9B53DCF4BA80A29\
        E3FB73C16B8E75B97EF363E2FFA31F71CF9DE5384E71B81C0AC4DFFE0C10E64F";
    pub(crate) const G_2048_224: &str = "AC4032EF4F2D9AE39DF30B5C8FFDAC506CDEBE7B89998CAF74866A08CFE4FFE3\
        A6824A4E10B9A6F0DD921F01A70C4AFAAB739D7700C29F52C57DB17C620A8652\
        BE5E9001A8D66AD7C17669101999024AF4D027275AC1348BB8A762D0521BC98A\
        E247150422EA1ED409939D54DA7460CDB5F6C6B250717CBEF180EB34118E98D1\
        19529A45D6F834566E3025E316A330EFBB77A86F0C1AB15B051AE3D428C8F8AC\
        B70A8137150B8EEB10E183EDD19963DDD9E263E4770589EF6AA21E7F5F2FF381\
        B539CCE3409D13CD566AFBB48D6C019181E1BCFE94B30269EDFE72FE9B6AA4BD\
        7B5A0F1C71CFFF4C19C418E1F6EC017981BC087F2A7065B384B890D3191F2BFA";
    pub(crate) const Q_2048_224: &str = "801C0D34C58D93FE997177101F80535A4738CEBCBF389A99B36371EB";
    // RFC 5114 §2.3: 2048-bit p, 256-bit q.
    pub(crate) const P_2048_256: &str = "87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00\
        E00DF8F1D61957D4FAF7DF4561B2AA3016C3D91134096FAA3BF4296D830E9A7C\
        209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B\
        6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76\
        B63ACAE1CAA6B7902D52526735488A0EF13C6D9A51BFA4AB3AD8347796524D8E\
        F6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026\
        C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103\
        A4B54330C198AF126116D2276E11715F693877FAD7EF09CADB094AE91E1A1597";
    pub(crate) const G_2048_256: &str = "3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA125\
        10DBC15077BE463FFF4FED4AAC0BB555BE3A6C1B0C6B47B1BC3773BF7E8C6F62\
        901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B\
        777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193\
        B5045AF2767164E1DFC967C1FB3F2E55A4BD1BFFE83B9C80D052B985D182EA0A\
        DB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915\
        B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C3\
        2F63078490F00EF8D647D148D47954515E2327CFEF98C582664B4C0F6CC41659";
    pub(crate) const Q_2048_256: &str =
        "8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3";

    pub(crate) fn hex(s: &str) -> BoxedUint {
        let s: alloc::string::String = s.split_whitespace().collect();
        BoxedUint::from_be_bytes(
            &(0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
                .collect::<alloc::vec::Vec<u8>>(),
        )
    }

    /// All three groups, validated by [`DhGroup::from_params`].
    pub(crate) fn groups() -> [DhGroup; 3] {
        [
            (P_1024_160, G_1024_160, Q_1024_160),
            (P_2048_224, G_2048_224, Q_2048_224),
            (P_2048_256, G_2048_256, Q_2048_256),
        ]
        .map(|(p, g, q)| DhGroup::from_params(hex(p), hex(g), hex(q)).expect("RFC 5114 group"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only the RFC 3526 constructors may mark a group as a known safe prime
    /// (it lets `shared_secret` skip the `y^q` check); a custom group with
    /// the very same `p` must not inherit that.
    #[test]
    fn only_named_groups_are_known_safe_primes() {
        for g in [group14(), group15(), group16(), group17(), group18()] {
            assert!(g.known_safe_prime, "{}", g.name());
        }
        let custom =
            DhGroup::from_custom_unchecked(group14().p, BoxedUint::from_u64(2), 256).unwrap();
        assert!(!custom.known_safe_prime);
    }

    #[test]
    fn group14_constants() {
        let g = group14();
        assert_eq!(g.name(), "group14");
        assert_eq!(g.bit_size(), 2048);
        assert_eq!(g.byte_size(), 256);
        assert!(g.p().is_odd());
        assert_eq!(*g.g(), BoxedUint::from_u64(2));
    }

    #[test]
    fn group15_constants() {
        let g = group15();
        assert_eq!(g.bit_size(), 3072);
        assert!(g.p().is_odd());
        // RFC 7919 §A: ≥ 275 bits of private exponent for a 3072-bit prime.
        assert!(g.priv_bits() >= 275);
        assert_eq!(g.priv_bits(), 288);
    }

    /// Every named group's private-exponent budget meets the RFC 7919
    /// Appendix A minimum for its prime size (225/275/325/375/400 bits for
    /// 2048/3072/4096/6144/8192-bit primes).
    #[test]
    fn named_group_priv_bits_meet_rfc7919() {
        for (g, floor) in [
            (group14(), 225),
            (group15(), 275),
            (group16(), 325),
            (group17(), 375),
            (group18(), 400),
        ] {
            assert!(
                g.priv_bits() >= floor,
                "{}: priv_bits {} < RFC 7919 floor {floor}",
                g.name(),
                g.priv_bits()
            );
        }
    }

    #[test]
    fn group16_constants() {
        let g = group16();
        assert_eq!(g.name(), "group16");
        assert_eq!(g.bit_size(), 4096);
        assert_eq!(g.byte_size(), 512);
        assert!(g.p().is_odd());
        assert_eq!(*g.g(), BoxedUint::from_u64(2));
    }

    #[test]
    fn group17_constants() {
        let g = group17();
        assert_eq!(g.bit_size(), 6144);
        assert!(g.p().is_odd());
    }

    #[test]
    fn group18_constants() {
        let g = group18();
        assert_eq!(g.bit_size(), 8192);
        assert!(g.p().is_odd());
    }

    #[test]
    fn from_custom_validates_g() {
        let p = group14().p().clone();
        // g = 0, 1, p - 1, p are all rejected.
        assert!(DhGroup::from_custom(p.clone(), BoxedUint::from_u64(0), 256).is_err());
        assert!(DhGroup::from_custom(p.clone(), BoxedUint::from_u64(1), 256).is_err());
        let pm1 = p.sub(&BoxedUint::from_u64(1));
        assert!(DhGroup::from_custom(p.clone(), pm1, 256).is_err());
        assert!(DhGroup::from_custom(p.clone(), p.clone(), 256).is_err());
        // g = 2 is valid.
        assert!(DhGroup::from_custom(p.clone(), BoxedUint::from_u64(2), 256).is_ok());
    }

    /// `from_custom` Miller-Rabin-tests the candidate: a composite `p` of
    /// sufficient bit length passes every structural check but must still be
    /// rejected. (The verdict is deterministic — the MR bases derive from the
    /// candidate itself.)
    #[test]
    fn from_custom_rejects_composite_p() {
        // Corrupt one byte in the middle of group14's prime: still odd,
        // still exactly 2048 bits, but composite.
        let mut p_bytes = group14().p().to_be_bytes(256);
        p_bytes[128] ^= 0x02;
        let p = BoxedUint::from_be_bytes(&p_bytes);
        assert_eq!(p.bit_len(), 2048);
        assert!(DhGroup::from_custom(p.clone(), BoxedUint::from_u64(2), 256).is_err());
        // ...while the documented escape hatch still accepts it (the caller
        // owns the primality property there).
        assert!(DhGroup::from_custom_unchecked(p, BoxedUint::from_u64(2), 256).is_ok());
    }

    #[test]
    fn from_custom_rejects_even_p() {
        // Probe the even-`p` check via the unchecked variant — `from_custom`
        // would reject the toy 4-bit modulus on size first.
        let even = BoxedUint::from_u64(10);
        assert!(DhGroup::from_custom_unchecked(even, BoxedUint::from_u64(2), 256).is_err());
    }

    /// `from_custom` enforces `MIN_CUSTOM_GROUP_BITS` (2048). A 2047-bit `p`
    /// is rejected; the unchecked variant accepts the same input subject only
    /// to the structural checks. group14 (2048 bits exactly) is the threshold.
    #[test]
    fn from_custom_enforces_min_bits() {
        // Build a 2047-bit odd `p` by clearing the top bit of group14's
        // 2048-bit prime and OR'ing in 1 to keep it odd. We don't care about
        // primality here — only that the bit-length gate fires.
        let mut p_bytes = group14().p().to_be_bytes(256);
        p_bytes[0] &= 0x7f; // clear MSB → now ≤ 2047 bits
        p_bytes[255] |= 0x01; // keep it odd
        let p_2047 = BoxedUint::from_be_bytes(&p_bytes);
        assert!(p_2047.bit_len() <= 2047);
        assert!(DhGroup::from_custom(p_2047.clone(), BoxedUint::from_u64(2), 256).is_err());
        assert!(DhGroup::from_custom_unchecked(p_2047, BoxedUint::from_u64(2), 256).is_ok());
        // group14 (2048 bits exactly) is accepted.
        assert!(DhGroup::from_custom(group14().p().clone(), BoxedUint::from_u64(2), 256).is_ok());
    }

    /// BN-2: a peer-chosen prime wider than `MAX_CUSTOM_GROUP_BITS` must be
    /// rejected *before* any primality arithmetic — a 16385-bit odd `p`
    /// fails fast on both constructors, a 16384-bit one reaches the checks.
    #[test]
    fn from_custom_enforces_max_bits() {
        // 16385 bits = 2049 bytes with only the top bit of the first byte set
        // (bit index 16384), odd.
        let mut p_bytes = alloc::vec![0u8; 2049];
        p_bytes[0] = 0x01;
        p_bytes[2048] = 0x01;
        let p = BoxedUint::from_be_bytes(&p_bytes);
        assert_eq!(p.bit_len(), 16385);
        // Both rejections happen before any primality arithmetic, so this
        // runs in microseconds even though `p` is far beyond group18.
        assert!(matches!(
            DhGroup::from_custom(p.clone(), BoxedUint::from_u64(2), 512),
            Err(Error::InvalidGroup)
        ));
        assert!(matches!(
            DhGroup::from_custom_unchecked(p, BoxedUint::from_u64(2), 512),
            Err(Error::InvalidGroup)
        ));
        // Exactly 16384 bits passes the size gate on the unchecked path
        // (2048 bytes, top bit set, odd).
        let mut p_bytes = alloc::vec![0u8; 2048];
        p_bytes[0] = 0x80;
        p_bytes[2047] = 0x01;
        let p = BoxedUint::from_be_bytes(&p_bytes);
        assert_eq!(p.bit_len(), DhGroup::MAX_CUSTOM_GROUP_BITS);
        assert!(DhGroup::from_custom_unchecked(p, BoxedUint::from_u64(2), 512).is_ok());
    }

    /// A degenerate private-exponent budget must be refused by the checked
    /// constructor: `priv_bits = 1` used to be accepted, making the exponent
    /// (not the 2048-bit prime) the weakest link — recoverable in
    /// `2^(priv_bits/2)` work. The unchecked constructor stays permissive for
    /// pinned legacy interop.
    #[test]
    fn from_custom_enforces_private_exponent_floor() {
        let p = group14().p().clone();
        let g = BoxedUint::from_u64(2);
        for short in [1usize, 8, 128, DhGroup::MIN_CUSTOM_PRIV_BITS - 1] {
            assert!(
                matches!(
                    DhGroup::from_custom(p.clone(), g.clone(), short),
                    Err(Error::InvalidGroup)
                ),
                "priv_bits = {short} must be rejected"
            );
            // …but the unchecked path still accepts it.
            assert!(DhGroup::from_custom_unchecked(p.clone(), g.clone(), short).is_ok());
        }
        // The floor itself, and the RFC 7919 value for this group, pass.
        assert!(
            DhGroup::from_custom(p.clone(), g.clone(), DhGroup::MIN_CUSTOM_PRIV_BITS).is_ok(),
            "the floor value itself must be accepted"
        );
        assert!(DhGroup::from_custom(p, g, 256).is_ok());
    }

    #[test]
    fn mr_round_schedule() {
        assert_eq!(DhGroup::custom_group_mr_rounds(2048), 64);
        assert_eq!(DhGroup::custom_group_mr_rounds(3072), 64);
        assert_eq!(DhGroup::custom_group_mr_rounds(4096), 32);
        assert_eq!(DhGroup::custom_group_mr_rounds(8192), 32);
    }

    /// BN-1: `from_custom` accepts generators of either order `q` or `2q`
    /// (for a genuine safe prime every element of `[2, p − 2]` has one of
    /// the two, so the `g^q ∈ {1, p − 1}` check can only fire on a modulus
    /// that is not what it claims to be). Both orders on group14's modulus:
    /// `g = 2` is a quadratic residue (order `q`) and `p − 2 ≡ −2` is a
    /// non-residue (order `2q`: `−1` is a non-residue for `p ≡ 3 mod 4`,
    /// `2` is a residue for `p ≡ 7 mod 8`).
    #[test]
    fn from_custom_accepts_both_generator_orders() {
        let p = group14().p().clone();
        let one = BoxedUint::from_u64(1);
        let q = p.sub(&one).shr_bits(1);
        let m = crate::bignum::BoxedMontModulus::new(&p);
        let two = BoxedUint::from_u64(2);
        let minus_two = p.sub(&two);
        assert_eq!(m.pow(&two, &q), one, "2 is a QR mod group14 p");
        assert_eq!(
            m.pow(&minus_two, &q),
            p.sub(&one),
            "−2 is a QNR mod group14 p"
        );
        assert!(DhGroup::from_custom(p.clone(), two, 256).is_ok());
        assert!(DhGroup::from_custom(p, minus_two, 256).is_ok());
    }

    /// All five RFC 3526 named groups must pass `from_custom` — they are the
    /// canonical safe primes, so the safe-prime validation must accept them.
    /// Ignored by default because the 6144- and 8192-bit validations are
    /// slow in a debug build; run with `cargo test --release -- --ignored
    /// --nocapture` to see per-group timings.
    #[test]
    #[ignore]
    #[cfg(feature = "std")]
    fn named_groups_pass_from_custom() {
        for (name, g) in [
            ("group14", group14()),
            ("group15", group15()),
            ("group16", group16()),
            ("group17", group17()),
            ("group18", group18()),
        ] {
            let start = std::time::Instant::now();
            let custom = DhGroup::from_custom(g.p().clone(), g.g().clone(), g.priv_bits())
                .unwrap_or_else(|e| panic!("{name} must pass from_custom: {e:?}"));
            assert_eq!(custom.bit_size(), g.bit_size());
            std::println!(
                "from_custom({name}, {} bits): {:?}",
                g.bit_size(),
                start.elapsed()
            );
        }
    }

    #[test]
    fn from_params_accepts_rfc5114_groups() {
        use super::rfc5114::*;
        for (g, (pb, qb)) in groups().iter().zip([(1024, 160), (2048, 224), (2048, 256)]) {
            assert_eq!(g.bit_size(), pb);
            assert_eq!(g.q().unwrap().bit_len(), qb);
            assert_eq!(g.priv_bits(), qb);
            assert_eq!(g.name(), "custom");
            assert!(!g.known_safe_prime);
        }
        // The safe-prime constructors carry no explicit q.
        assert!(group14().q().is_none());
        assert!(
            DhGroup::from_custom_unchecked(hex(P_1024_160), hex(G_1024_160), 160)
                .unwrap()
                .q()
                .is_none()
        );
    }

    #[test]
    fn from_params_rejects_bad_triples() {
        use super::rfc5114::*;
        use crate::bignum::BoxedMontModulus;
        use crate::bignum::prime::is_prime_boxed;
        use crate::hash::Sha256;
        use crate::rng::HmacDrbg;

        let (p, g, q) = (hex(P_1024_160), hex(G_1024_160), hex(Q_1024_160));
        let one = BoxedUint::from_u64(1);
        let bad = |p: &BoxedUint, g: &BoxedUint, q: &BoxedUint| {
            matches!(
                DhGroup::from_params(p.clone(), g.clone(), q.clone()),
                Err(Error::InvalidGroup)
            )
        };
        // q does not divide p - 1: another group's (prime) q.
        assert!(bad(&p, &g, &hex(Q_2048_224)));
        // g outside [2, p - 2], or not of order q (2 is, with overwhelming
        // probability, not in the order-q subgroup).
        assert!(bad(&p, &one, &q));
        assert!(bad(&p, &p.sub(&one), &q));
        assert!(bad(&p, &p, &q));
        assert!(bad(&p, &BoxedUint::from_u64(2), &q));
        // Width floors (checked before any arithmetic) and parity.
        assert!(bad(&p, &g, &q.shr_bits(1)));
        assert!(bad(&p.shr_bits(1), &g, &q));
        assert!(bad(&p, &g, &q.add(&one)));
        // A composite q with q | p - 1 and g^q = 1: q*r for an odd prime r
        // dividing (p - 1)/q. Only Miller-Rabin on q rejects it.
        let (cofactor, _) = p.sub(&one).divrem(&q);
        let r = (3u64..)
            .step_by(2)
            .find(|&r| cofactor.reduce(&BoxedUint::from_u64(r)).is_zero())
            .unwrap();
        let qr = q.mul(&BoxedUint::from_u64(r));
        assert!(p.sub(&one).reduce(&qr).is_zero());
        assert_eq!(BoxedMontModulus::new(&p).pow_public(&g, &qr), one);
        assert!(bad(&p, &g, &qr));
        // A composite p that passes every structural check: p' = p*p2 with
        // p2 = 2kq + 1 prime (so q | p' - 1), and g' = g (mod p),
        // g' = 1 (mod p2) by CRT (so g'^q = 1 mod p'). Only Miller-Rabin on
        // p rejects it.
        let mut rng = HmacDrbg::<Sha256>::new(b"dh-params-composite-p", b"", b"");
        let two_q = q.add(&q);
        let mut p2 = two_q.add(&one);
        while !is_prime_boxed(&p2, &mut rng, 32) {
            p2 = p2.add(&two_q);
        }
        let composite = p.mul(&p2);
        let p2_inv = crate::bignum::inv_mod_boxed(&p2.reduce(&p), &p).unwrap();
        let t = BoxedMontModulus::new(&p).mul_mod(&g.sub(&one), &p2_inv);
        let g_crt = one.add(&p2.mul(&t));
        assert!(composite.sub(&one).reduce(&q).is_zero());
        assert_eq!(
            BoxedMontModulus::new(&composite).pow_public(&g_crt, &q),
            one
        );
        assert!(bad(&composite, &g_crt, &q));
        // The genuine triple passes.
        assert!(DhGroup::from_params(p, g, q).is_ok());
    }
}
