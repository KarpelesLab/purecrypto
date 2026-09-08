//! Finite-field Diffie-Hellman key exchange.
//!
//! [`DhPrivateKey`] / [`DhPublicKey`] perform the classic `g^x mod p`
//! key-agreement protocol on any [`DhGroup`]: a named RFC 3526 group such as
//! [`group14`](super::groups::group14), or a custom group built via
//! [`DhGroup::from_custom`](super::groups::DhGroup::from_custom) for RFC 4419
//! SSH group-exchange.
//!
//! The public-key validation and contributory-failure rejection follow
//! standard subgroup-confinement defense (see NIST SP 800-56A §5.6.2.3).

use super::groups::DhGroup;
use crate::bignum::{BoxedMontModulus, BoxedUint};
use crate::ct::ConstantTimeEq;
use crate::rng::{CryptoRng, RngCore};
use alloc::vec;
use alloc::vec::Vec;

/// Errors from a finite-field DH operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The peer's public value was outside `[2, p - 2]` — i.e. one of
    /// `0`, `1`, `p - 1`, or `≥ p`. These are tiny-order or invalid elements
    /// that would leak the local exponent, so the exchange is aborted.
    InvalidPublicKey,
    /// The shared secret was `0` or `1`. This should not occur for a
    /// well-formed peer once [`Error::InvalidPublicKey`] is screened out; if
    /// it does, the peer chose a pathological public value despite passing
    /// the range check (e.g. on a malformed custom group) and the secret
    /// would be guessable.
    ContributoryFailure,
    /// [`DhGroup::from_custom`](super::groups::DhGroup::from_custom) was
    /// called with parameters that fail the cheap sanity checks (even `p`,
    /// `g` outside `[2, p - 2]`, or a degenerate `priv_bits`).
    InvalidGroup,
    /// A scalar passed to [`DhPrivateKey::from_bytes`] was outside
    /// `[1, p - 1]`.
    InvalidScalar,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidPublicKey => f.write_str("invalid Diffie-Hellman public value"),
            Error::ContributoryFailure => {
                f.write_str("Diffie-Hellman shared secret failed contributory check")
            }
            Error::InvalidGroup => f.write_str("invalid Diffie-Hellman group parameters"),
            Error::InvalidScalar => f.write_str("Diffie-Hellman private scalar out of range"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// A finite-field DH private exponent on a specific group.
///
/// The exponent `x` is drawn from `[1, 2^priv_bits - 1]` per
/// [`DhGroup::priv_bits`](super::groups::DhGroup) — typically 256 bits for a
/// 2048-bit prime, doubled to 512 for the 6144- and 8192-bit primes. Shorter
/// exponents speed up `g^x mod p` substantially while preserving the
/// effective security level (RFC 7919 §A).
#[derive(Clone)]
pub struct DhPrivateKey {
    group: DhGroup,
    x: BoxedUint,
}

/// A finite-field DH public value `y = g^x mod p`.
#[derive(Clone)]
pub struct DhPublicKey {
    group: DhGroup,
    y: BoxedUint,
}

/// The byte-encoded shared secret `g^(x·y) mod p`.
///
/// Encoded big-endian, left-padded to `(p.bit_len() + 7) / 8` bytes — the
/// width SSH and TLS feed into the key-derivation step. Most consumers will
/// run this through a hash (SHA-256 for `diffie-hellman-group14-sha256`,
/// SHA-512 for `…-group16-sha512`) rather than use the raw value directly.
pub struct SharedSecret {
    bytes: Vec<u8>,
}

impl SharedSecret {
    /// The shared secret as big-endian bytes, left-padded to the group's
    /// prime width.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the shared secret and returns the underlying byte buffer.
    pub fn into_bytes(mut self) -> Vec<u8> {
        // `SharedSecret` implements `Drop`, so the field cannot be moved out
        // directly (E0509). Swap the buffer out with an empty `Vec` and hand
        // it to the caller — the wiping `Drop` then runs over the now-empty
        // `self.bytes`, a no-op, and the caller owns (and must protect) the
        // raw secret.
        core::mem::take(&mut self.bytes)
    }
}

impl Drop for SharedSecret {
    fn drop(&mut self) {
        // Best-effort wipe of the raw finite-field shared secret before its
        // heap buffer is freed. Same `core::hint::black_box`-guarded zeroing
        // the rest of the crate uses (e.g. `cipher/cfb.rs`), mirroring the
        // explicit wipe `DhPrivateKey::drop` performs on the exponent `x`.
        for b in self.bytes.iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(&self.bytes);
    }
}

impl DhPrivateKey {
    /// Generates a fresh private exponent of `group.priv_bits()` bits.
    ///
    /// The high bit is forced on so the exponent is guaranteed at least
    /// `priv_bits - 1` bits wide — this prevents a freshly generated value
    /// from coincidentally being 0 or 1 and keeps the modexp running time
    /// stable across keys on the same group.
    ///
    /// `rng` must be a cryptographically secure CSPRNG (see [`CryptoRng`]).
    pub fn generate<R: RngCore + CryptoRng>(group: DhGroup, rng: &mut R) -> Self {
        let priv_bits = group.priv_bits;
        let nbytes = priv_bits.div_ceil(8);
        let mut bytes = vec![0u8; nbytes];
        rng.fill_bytes(&mut bytes);
        // Mask off the high byte to `priv_bits` bits, then set the top bit
        // of that range so the exponent has exactly `priv_bits` bits.
        let high_bits = priv_bits - (nbytes - 1) * 8; // 1..=8
        let mask: u8 = if high_bits == 8 {
            0xFF
        } else {
            (1u8 << high_bits) - 1
        };
        bytes[0] &= mask;
        bytes[0] |= 1 << (high_bits - 1);
        let x = BoxedUint::from_be_bytes(&bytes);
        DhPrivateKey { group, x }
    }

    /// Builds a private key from an explicit big-endian scalar.
    ///
    /// Validates `1 ≤ x < p`. This is `priv_bits`-agnostic — passing a
    /// shorter or longer scalar than the group's default size is allowed,
    /// for interop with peers that demand a fixed exponent.
    pub fn from_bytes(group: DhGroup, bytes: &[u8]) -> Result<Self, Error> {
        let x = BoxedUint::from_be_bytes(bytes);
        if x.is_zero() || !x.lt(group.p()) {
            return Err(Error::InvalidScalar);
        }
        Ok(DhPrivateKey { group, x })
    }

    /// Computes the public value `y = g^x mod p` to send to the peer.
    pub fn public_key(&self) -> DhPublicKey {
        let m = BoxedMontModulus::new(self.group.p());
        let y = m.pow(self.group.g(), &self.x);
        DhPublicKey {
            group: self.group.clone(),
            y,
        }
    }

    /// Computes the shared secret `peer.y ^ x mod p`.
    ///
    /// Rejects:
    /// * `peer.y < 2` or `peer.y ≥ p - 1` — range check: the only values
    ///   outside `[2, p − 2]` are 0, 1, `p - 1` and out-of-range integers,
    ///   the first three being the elements of order 1 and 2. For a **safe
    ///   prime** `p = 2q + 1` (every RFC 3526 / RFC 7919 group, and every
    ///   group [`DhGroup::from_custom`] lets through) this is already the
    ///   complete small-subgroup defense: the multiplicative group has
    ///   order `2q`, so every remaining element has order `q` or `2q` and
    ///   there is no small subgroup to confine `x` into. This is the
    ///   validation NIST SP 800-56A Rev 3 §5.6.2.3.1 prescribes for
    ///   safe-prime groups;
    /// * `peer.y ^ q mod p ∉ {1, p − 1}` where `q = (p − 1) / 2` — a
    ///   consistency check that, by Euler's criterion, can only fail when
    ///   `p` is not prime at all. It costs one full-width exponentiation and
    ///   exists so that a modulus smuggled in through
    ///   [`DhGroup::from_custom_unchecked`] without the primality test still
    ///   cannot silently confine `x` to a subgroup of a composite "prime".
    ///   Note it does **not** protect an unchecked group whose `p` is a
    ///   prime with smooth `(p − 1) / 2`: those callers own that risk. Both
    ///   values are accepted deliberately — `y^q ≡ p − 1` means `y` has
    ///   order `2q` (a generator of the whole group), which is exactly what
    ///   an honest peer with an odd private exponent sends whenever `g` is
    ///   a primitive root, as the RFC 4419 groups in OpenSSH's `moduli`
    ///   file are (`g = 2` with `p ≡ 3 (mod 8)`, or `g = 5`). Insisting on
    ///   `y^q ≡ 1` would reject half of all honest peers on such groups.
    ///   The price is the standard, accepted one: for an order-`2q` peer
    ///   value the shared secret reveals the parity of `x` (one bit of a
    ///   ≥ 256-bit exponent), which does not affect the DLP hardness the
    ///   exchange rests on;
    /// * a resulting shared secret of 0 or 1 — contributory-failure
    ///   rejection per NIST SP 800-56A §5.6.2.3.
    pub fn shared_secret(&self, peer: &DhPublicKey) -> Result<SharedSecret, Error> {
        let p = self.group.p();
        // [2, p - 2]  ⇔  y ≥ 2 AND y < p - 1.
        let two = BoxedUint::from_u64(2);
        let p_minus_one = p.sub(&BoxedUint::from_u64(1));
        if peer.y.lt(&two) || !peer.y.lt(&p_minus_one) {
            return Err(Error::InvalidPublicKey);
        }

        let m = BoxedMontModulus::new(p);

        // peer.y ^ q mod p ∈ {1, p − 1}, q = (p − 1) / 2. For a safe prime
        // this holds for every y in [2, p − 2] (order q → 1, order 2q →
        // p − 1) and the range check above is the whole subgroup defense;
        // only a composite modulus from `from_custom_unchecked` can fail
        // here. Accepting p − 1 (order-2q peer values) is what keeps
        // primitive-root generators — the RFC 4419 / OpenSSH `moduli`
        // groups — interoperable; see the doc comment.
        let q = p_minus_one.shr_bits(1);
        let one = BoxedUint::from_u64(1);
        let y_to_q = m.pow(&peer.y, &q);
        if !bool::from(y_to_q.ct_eq(&one) | y_to_q.ct_eq(&p_minus_one)) {
            return Err(Error::InvalidPublicKey);
        }

        let z = m.pow(&peer.y, &self.x);

        // Contributory-failure rejection: z != 0 and z != 1. Use ct_eq for
        // consistency with the rest of the codebase even though z is no
        // longer secret-input by the time it gets here.
        let zero_eq = z.ct_eq(&BoxedUint::from_u64(0));
        let one_eq = z.ct_eq(&one);
        if bool::from(zero_eq | one_eq) {
            return Err(Error::ContributoryFailure);
        }

        let bytes = z.to_be_bytes(self.group.byte_size());
        Ok(SharedSecret { bytes })
    }

    /// The group this key lives on.
    pub fn group(&self) -> &DhGroup {
        &self.group
    }

    /// The raw private scalar as big-endian bytes, left-padded to the
    /// group's prime width. Exposed mainly for fixture tests and
    /// PKCS#3 / SSH key serialization; treat it as secret.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.x.to_be_bytes(self.group.byte_size())
    }
}

impl Drop for DhPrivateKey {
    fn drop(&mut self) {
        // Best-effort wipe of the secret exponent `x` before its heap-backing
        // `Vec` is freed. `BoxedUint` already zeroizes on its own `Drop`, so
        // this is belt-and-suspenders, but it mirrors the explicit convention
        // used by every EC private-key type (e.g. `BoxedEcdsaPrivateKey`,
        // `BoxedEcdhPrivateKey` in `ec/boxed.rs`).
        self.x.zeroize();
    }
}

impl DhPublicKey {
    /// `y` as big-endian bytes, left-padded to the group's prime byte width.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.y.to_be_bytes(self.group.byte_size())
    }

    /// Builds a public key from big-endian bytes.
    ///
    /// Validates `2 ≤ y < p - 1` (subgroup-confinement check). Values of
    /// `0`, `1`, `p - 1`, and `≥ p` are tiny-order or out-of-range and
    /// rejected with [`Error::InvalidPublicKey`].
    pub fn from_bytes(group: DhGroup, bytes: &[u8]) -> Result<Self, Error> {
        let y = BoxedUint::from_be_bytes(bytes);
        let two = BoxedUint::from_u64(2);
        let p_minus_one = group.p().sub(&BoxedUint::from_u64(1));
        if y.lt(&two) || !y.lt(&p_minus_one) {
            return Err(Error::InvalidPublicKey);
        }
        Ok(DhPublicKey { group, y })
    }

    /// The group this key lives on.
    pub fn group(&self) -> &DhGroup {
        &self.group
    }

    /// The public value as a [`BoxedUint`] reference.
    pub fn y(&self) -> &BoxedUint {
        &self.y
    }
}

#[cfg(test)]
mod tests {
    use super::super::groups::{DhGroup, group14, group15, group16};
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    #[test]
    fn group14_keyx_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"dh-group14", b"nonce", &[]);
        let alice = DhPrivateKey::generate(group14(), &mut rng);
        let bob = DhPrivateKey::generate(group14(), &mut rng);

        let a_shared = alice.shared_secret(&bob.public_key()).unwrap();
        let b_shared = bob.shared_secret(&alice.public_key()).unwrap();
        assert_eq!(a_shared.as_bytes(), b_shared.as_bytes());
        assert_eq!(a_shared.as_bytes().len(), 256);
        // Must not be trivially zero/all-zero.
        assert!(a_shared.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn group15_keyx_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"dh-group15", b"nonce", &[]);
        let alice = DhPrivateKey::generate(group15(), &mut rng);
        let bob = DhPrivateKey::generate(group15(), &mut rng);

        let a_shared = alice.shared_secret(&bob.public_key()).unwrap();
        let b_shared = bob.shared_secret(&alice.public_key()).unwrap();
        assert_eq!(a_shared.as_bytes(), b_shared.as_bytes());
        assert_eq!(a_shared.as_bytes().len(), 384);
    }

    #[test]
    fn group16_keyx_roundtrip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"dh-group16", b"nonce", &[]);
        let alice = DhPrivateKey::generate(group16(), &mut rng);
        let bob = DhPrivateKey::generate(group16(), &mut rng);

        let a_shared = alice.shared_secret(&bob.public_key()).unwrap();
        let b_shared = bob.shared_secret(&alice.public_key()).unwrap();
        assert_eq!(a_shared.as_bytes(), b_shared.as_bytes());
        assert_eq!(a_shared.as_bytes().len(), 512);
    }

    /// 8192-bit group18 round-trip. Excluded from the default test run
    /// because the four 512-bit modexps over the 8192-bit modulus take
    /// ~10s in a debug build; run with `cargo test --release -- --ignored`.
    #[test]
    #[ignore]
    fn group18_keyx_roundtrip() {
        use super::super::groups::{group17, group18};
        let mut rng = HmacDrbg::<Sha256>::new(b"dh-group17-18", b"nonce", &[]);
        let alice = DhPrivateKey::generate(group17(), &mut rng);
        let bob = DhPrivateKey::generate(group17(), &mut rng);
        let a = alice.shared_secret(&bob.public_key()).unwrap();
        let b = bob.shared_secret(&alice.public_key()).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.as_bytes().len(), 768);

        let alice = DhPrivateKey::generate(group18(), &mut rng);
        let bob = DhPrivateKey::generate(group18(), &mut rng);
        let a = alice.shared_secret(&bob.public_key()).unwrap();
        let b = bob.shared_secret(&alice.public_key()).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.as_bytes().len(), 1024);
    }

    fn expect_invalid_pub(r: Result<DhPublicKey, Error>) {
        match r {
            Err(Error::InvalidPublicKey) => {}
            Err(other) => panic!("expected InvalidPublicKey, got {other:?}"),
            Ok(_) => panic!("expected InvalidPublicKey, got Ok"),
        }
    }

    fn expect_invalid_scalar(r: Result<DhPrivateKey, Error>) {
        match r {
            Err(Error::InvalidScalar) => {}
            Err(other) => panic!("expected InvalidScalar, got {other:?}"),
            Ok(_) => panic!("expected InvalidScalar, got Ok"),
        }
    }

    #[test]
    fn rejects_invalid_public_key_zero() {
        let buf = vec![0u8; 256];
        expect_invalid_pub(DhPublicKey::from_bytes(group14(), &buf));
    }

    #[test]
    fn rejects_invalid_public_key_one() {
        let mut buf = vec![0u8; 256];
        buf[255] = 1;
        expect_invalid_pub(DhPublicKey::from_bytes(group14(), &buf));
    }

    #[test]
    fn rejects_invalid_public_key_p_minus_one() {
        let g = group14();
        let pm1 = g.p().sub(&BoxedUint::from_u64(1));
        let buf = pm1.to_be_bytes(256);
        expect_invalid_pub(DhPublicKey::from_bytes(g, &buf));
    }

    #[test]
    fn rejects_invalid_public_key_ge_p() {
        // p itself.
        let buf = group14().p().to_be_bytes(256);
        expect_invalid_pub(DhPublicKey::from_bytes(group14(), &buf));
        // p + 1 — extend by one byte so it parses as a larger value.
        let mut extended = vec![0u8; 257];
        extended[1..].copy_from_slice(&buf);
        let plus_one = BoxedUint::from_be_bytes(&extended).add(&BoxedUint::from_u64(1));
        let plus_one_bytes = plus_one.to_be_bytes(257);
        expect_invalid_pub(DhPublicKey::from_bytes(group14(), &plus_one_bytes));
    }

    #[test]
    fn from_bytes_round_trip_public_key() {
        // A valid `y = g^x mod p` for some small x must survive
        // to_bytes / from_bytes.
        let mut rng = HmacDrbg::<Sha256>::new(b"dh-roundtrip", b"nonce", &[]);
        let alice = DhPrivateKey::generate(group14(), &mut rng);
        let pk = alice.public_key();
        let bytes = pk.to_bytes();
        let pk2 = DhPublicKey::from_bytes(group14(), &bytes).unwrap();
        assert_eq!(pk.to_bytes(), pk2.to_bytes());
    }

    #[test]
    fn group_exchange_custom_group() {
        // Use group14's (p, g) as a "custom" group to exercise the
        // from_custom code path without standing up a separately-validated
        // prime.
        let p = group14().p().clone();
        let g = group14().g().clone();
        let custom = DhGroup::from_custom(p, g, 256).expect("from_custom accepts group14 (p, g)");
        assert_eq!(custom.name(), "custom");
        assert_eq!(custom.bit_size(), 2048);

        let mut rng = HmacDrbg::<Sha256>::new(b"dh-custom", b"nonce", &[]);
        let alice = DhPrivateKey::generate(custom.clone(), &mut rng);
        let bob = DhPrivateKey::generate(custom, &mut rng);
        let a = alice.shared_secret(&bob.public_key()).unwrap();
        let b = bob.shared_secret(&alice.public_key()).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn from_bytes_rejects_out_of_range_scalar() {
        // x = 0
        let buf = vec![0u8; 256];
        expect_invalid_scalar(DhPrivateKey::from_bytes(group14(), &buf));
        // x = p
        let buf = group14().p().to_be_bytes(256);
        expect_invalid_scalar(DhPrivateKey::from_bytes(group14(), &buf));
        // x = 1 is valid.
        let mut buf = vec![0u8; 256];
        buf[255] = 1;
        assert!(DhPrivateKey::from_bytes(group14(), &buf).is_ok());
    }

    /// `into_bytes` must still hand back exactly the same secret it held,
    /// proving the wiping `Drop` (which forbids a direct field move) didn't
    /// change the consuming accessor's output.
    #[test]
    fn shared_secret_into_bytes_preserves_value() {
        let mut rng = HmacDrbg::<Sha256>::new(b"dh-into-bytes", b"nonce", &[]);
        let alice = DhPrivateKey::generate(group14(), &mut rng);
        let bob = DhPrivateKey::generate(group14(), &mut rng);
        let shared = alice.shared_secret(&bob.public_key()).unwrap();
        let expected = shared.as_bytes().to_vec();
        let owned = shared.into_bytes();
        assert_eq!(owned, expected);
        assert_eq!(owned.len(), 256);
    }

    #[test]
    fn shared_secret_byte_length_matches_prime() {
        let mut rng = HmacDrbg::<Sha256>::new(b"dh-len", b"nonce", &[]);
        let alice = DhPrivateKey::generate(group14(), &mut rng);
        let bob = DhPrivateKey::generate(group14(), &mut rng);
        let s = alice.shared_secret(&bob.public_key()).unwrap();
        assert_eq!(s.as_bytes().len(), group14().p().bit_len().div_ceil(8));
    }

    /// DH-1 / BN-1 (subgroup check semantics on an unchecked group): `p = 7`
    /// is a safe prime (`q = 3`). The multiplicative group has order 6;
    /// `6 = p − 1` (order 2) is filtered by the range check, `2` and `4`
    /// have order 3 (`2^3 mod 7 = 1`) and `3`, `5` have order 6 —
    /// generators, with `5^3 mod 7 = 6 = p − 1`. Both kinds are honest
    /// public values (an odd exponent on a primitive-root generator yields
    /// an order-6 value), so both must be accepted.
    #[test]
    fn shared_secret_accepts_order_q_and_order_2q_elements() {
        let p = BoxedUint::from_u64(7);
        let g = BoxedUint::from_u64(3); // primitive root mod 7.
        let group = DhGroup::from_custom_unchecked(p, g, 2).unwrap();
        let alice = DhPrivateKey::from_bytes(group.clone(), &[2u8]).unwrap();
        // `5`: order 6, `5^q = 5^3 ≡ 6 = p − 1`. Accepted.
        let order_2q = DhPublicKey {
            group: group.clone(),
            y: BoxedUint::from_u64(5),
        };
        // 5^2 mod 7 = 4.
        assert_eq!(
            alice.shared_secret(&order_2q).unwrap().as_bytes(),
            &[4u8],
            "order-2q peer value (y^q = p − 1) must be accepted"
        );
        // `2`: order 3, `2^3 ≡ 1`. Accepted; 2^2 mod 7 = 4.
        let order_q = DhPublicKey {
            group,
            y: BoxedUint::from_u64(2),
        };
        assert_eq!(alice.shared_secret(&order_q).unwrap().as_bytes(), &[4u8]);
    }

    /// The `y^q ∈ {1, p − 1}` check is exactly the condition every element
    /// of a prime field satisfies (Euler's criterion), so the only thing it
    /// can reject is a value on a **composite** modulus that
    /// `from_custom_unchecked` let through: `p = 15` (`q = 7`), `y = 2`:
    /// `2^7 mod 15 = 128 mod 15 = 8 ∉ {1, 14}`.
    #[test]
    fn shared_secret_rejects_element_of_composite_modulus() {
        let p = BoxedUint::from_u64(15);
        let group = DhGroup::from_custom_unchecked(p, BoxedUint::from_u64(4), 2).unwrap();
        let alice = DhPrivateKey::from_bytes(group.clone(), &[3u8]).unwrap();
        let peer = DhPublicKey {
            group,
            y: BoxedUint::from_u64(2),
        };
        assert!(
            matches!(alice.shared_secret(&peer), Err(Error::InvalidPublicKey)),
            "y^q ∉ {{1, p − 1}} must be rejected"
        );
    }

    /// BN-1: a primitive-root generator (the RFC 4419 / OpenSSH `moduli`
    /// shape) must interoperate for *every* private exponent, odd ones
    /// included — with the old `y^q == 1` rule every odd `x` produced a
    /// rejected public value. `p = 23` (`q = 11`), `g = 5`:
    /// `5^11 mod 23 = 22 = p − 1`, so 5 is a quadratic non-residue and a
    /// primitive root. All `x ∈ 1..=10` on both sides must succeed and
    /// agree.
    #[test]
    fn primitive_root_generator_interoperates_for_all_exponents() {
        let p = BoxedUint::from_u64(23);
        let g = BoxedUint::from_u64(5);
        let m = BoxedMontModulus::new(&p);
        assert_eq!(
            m.pow(&g, &BoxedUint::from_u64(11)),
            BoxedUint::from_u64(22),
            "5 must be a primitive root mod 23"
        );
        let group = DhGroup::from_custom_unchecked(p, g, 4).unwrap();
        for xa in 1u8..=10 {
            let alice = DhPrivateKey::from_bytes(group.clone(), &[xa]).unwrap();
            let a_pub = alice.public_key();
            for xb in 1u8..=10 {
                let bob = DhPrivateKey::from_bytes(group.clone(), &[xb]).unwrap();
                let b_pub = bob.public_key();
                let a = alice
                    .shared_secret(&b_pub)
                    .unwrap_or_else(|e| panic!("alice x={xa}, bob x={xb}: {e:?}"));
                let b = bob
                    .shared_secret(&a_pub)
                    .unwrap_or_else(|e| panic!("bob x={xb}, alice x={xa}: {e:?}"));
                assert_eq!(a.as_bytes(), b.as_bytes(), "x_a={xa} x_b={xb}");
                // 5^(xa·xb) mod 23 by hand.
                let mut expected = 1u64;
                for _ in 0..(xa as u64 * xb as u64) {
                    expected = expected * 5 % 23;
                }
                assert_eq!(a.as_bytes(), &[expected as u8]);
            }
        }
    }

    /// BN-1 at production size: group14's modulus with a quadratic
    /// non-residue generator (`p − 2 ≡ −2`; `−1` is a non-residue for
    /// `p ≡ 3 mod 4` and `2` a residue for `p ≡ 7 mod 8`) round-trips with
    /// odd private exponents on both sides, i.e. with both public values of
    /// order `2q`.
    #[test]
    fn qnr_generator_on_group14_modulus_round_trips() {
        let p = group14().p().clone();
        let one = BoxedUint::from_u64(1);
        let g = p.sub(&BoxedUint::from_u64(2));
        let q = p.sub(&one).shr_bits(1);
        let m = BoxedMontModulus::new(&p);
        assert_eq!(m.pow(&g, &q), p.sub(&one), "p − 2 must be a QNR");
        let group = DhGroup::from_custom_unchecked(p, g, 256).unwrap();

        let mut xa = vec![0u8; 32];
        xa[31] = 0x0f; // 15: odd
        let mut xb = vec![0u8; 32];
        xb[0] = 0x80;
        xb[31] = 0x01; // 2^255 + 1: odd
        let alice = DhPrivateKey::from_bytes(group.clone(), &xa).unwrap();
        let bob = DhPrivateKey::from_bytes(group, &xb).unwrap();
        let a_pub = alice.public_key();
        let b_pub = bob.public_key();
        // Both public values have order 2q.
        assert_eq!(m.pow(a_pub.y(), &q), group14().p().sub(&one));
        assert_eq!(m.pow(b_pub.y(), &q), group14().p().sub(&one));
        let a = alice.shared_secret(&b_pub).expect("order-2q peer value");
        let b = bob.shared_secret(&a_pub).expect("order-2q peer value");
        assert_eq!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.as_bytes().len(), 256);
    }

    /// All five RFC 3526 named groups are safe primes, so every well-formed
    /// peer-generated public value lies inside the order-`q` subgroup and
    /// the new confinement check is invisible to honest exchanges.
    #[test]
    fn shared_secret_subgroup_check_passes_on_named_group14() {
        let mut rng = HmacDrbg::<Sha256>::new(b"dh-subgroup-honest", b"nonce", &[]);
        let alice = DhPrivateKey::generate(group14(), &mut rng);
        let bob = DhPrivateKey::generate(group14(), &mut rng);
        let a = alice.shared_secret(&bob.public_key()).unwrap();
        let b = bob.shared_secret(&alice.public_key()).unwrap();
        assert_eq!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn known_small_dh_via_custom_group() {
        // A tiny safe-prime group exercises the full pipeline against
        // hand-computable values. p = 23 = 2 * 11 + 1 (11 is prime), g = 2
        // is a quadratic residue mod 23 and so generates the order-11
        // subgroup. Use priv_bits = 4 so the random exponent fits in
        // [1, 15].
        let p = BoxedUint::from_u64(23);
        let g = BoxedUint::from_u64(2);
        // Bypass the MIN_CUSTOM_GROUP_BITS gate — this toy group only exists
        // to exercise the maths against hand-computable values; production
        // callers always go through `from_custom`.
        let group = DhGroup::from_custom_unchecked(p.clone(), g.clone(), 4).unwrap();

        // x_alice = 6, y_alice = 2^6 mod 23 = 64 mod 23 = 18.
        let mut a_buf = vec![0u8];
        a_buf[0] = 6;
        let alice = DhPrivateKey::from_bytes(group.clone(), &a_buf).unwrap();
        let a_pub = alice.public_key();
        assert_eq!(a_pub.y(), &BoxedUint::from_u64(18));

        // x_bob = 9, y_bob = 2^9 mod 23 = 512 mod 23 = 6.
        let mut b_buf = vec![0u8];
        b_buf[0] = 9;
        let bob = DhPrivateKey::from_bytes(group, &b_buf).unwrap();
        let b_pub = bob.public_key();
        assert_eq!(b_pub.y(), &BoxedUint::from_u64(6));

        // Shared = 2^(6*9) mod 23 = 2^54 mod 23. Since 2^11 ≡ 1 mod 23,
        // 2^54 = 2^(4*11 + 10) = 2^10 = 1024 mod 23 = 1024 - 44*23 = 12.
        let a_shared = alice.shared_secret(&b_pub).unwrap();
        let b_shared = bob.shared_secret(&a_pub).unwrap();
        assert_eq!(a_shared.as_bytes(), b_shared.as_bytes());
        // p byte-length is 1.
        assert_eq!(a_shared.as_bytes(), &[12u8]);
    }
}
