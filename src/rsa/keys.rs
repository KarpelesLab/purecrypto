//! RSA key types, key generation, and the raw modular-exponentiation
//! primitive.
//!
//! Keys are parameterized by the modulus width in 64-bit limbs (`LIMBS`), so a
//! 2048-bit modulus is `LIMBS = 32`. The two prime factors are each half that
//! width, and all key values (`n`, `e`, `d`, `p`, `q`) are stored as
//! `Uint<LIMBS>`.

use super::random_prime;
use crate::bignum::{MontModulus, Uint, inv_mod_ct};
use crate::ct::{ConstantTimeEq, ConstantTimeLess};
use crate::hash::{Digest, Sha256};
use crate::rng::{CryptoRng, RngCore};
use core::sync::atomic::{AtomicU32, Ordering};

/// An RSA public key `(n, e)`.
#[derive(Clone, Debug)]
pub struct RsaPublicKey<const LIMBS: usize> {
    n: Uint<LIMBS>,
    e: Uint<LIMBS>,
    /// Montgomery context for `n`, built once with the key so repeated
    /// verifications do not each derive `R² mod n`. `None` when `n` is even
    /// (a key assembled from unchecked components), in which case the public
    /// operation panics as it always did.
    mont: Option<MontModulus<LIMBS>>,
}

// Equality is over the key material; the context is a function of `n`.
impl<const LIMBS: usize> PartialEq for RsaPublicKey<LIMBS> {
    fn eq(&self, other: &Self) -> bool {
        self.n == other.n && self.e == other.e
    }
}

impl<const LIMBS: usize> Eq for RsaPublicKey<LIMBS> {}

/// The Montgomery context for a modulus, or `None` when it is even (so the
/// unvalidated constructors keep deferring the "modulus must be odd" panic
/// to the first operation, as documented).
fn mont_for<const LIMBS: usize>(n: &Uint<LIMBS>) -> Option<MontModulus<LIMBS>> {
    // `n` is public; a plain branch on its parity is fine.
    if bool::from(n.is_odd()) {
        Some(MontModulus::new(*n))
    } else {
        None
    }
}

/// The CRT parameters of a fixed-width private key, as secret as the primes
/// they derive from: `dP = d mod (p − 1)`, `dQ = d mod (q − 1)`,
/// `qInv = q⁻¹ mod p`, and the Montgomery contexts of `p` and `q` (built at
/// the primes' significant width, so a 2048-bit key's halves run 16-limb
/// arithmetic).
#[derive(Clone)]
struct FixedRsaCrt<const LIMBS: usize> {
    dp: Uint<LIMBS>,
    dq: Uint<LIMBS>,
    qinv: Uint<LIMBS>,
    mont_p: MontModulus<LIMBS>,
    mont_q: MontModulus<LIMBS>,
}

impl<const LIMBS: usize> crate::zeroize::Zeroize for FixedRsaCrt<LIMBS> {
    fn zeroize(&mut self) {
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
        self.mont_p.zeroize();
        self.mont_q.zeroize();
    }
}

/// Derives the CRT parameters from the prime factors, or `None` when the key
/// has no usable primes (zero, even, tiny, or equal — the verdicts are
/// public properties of the key, selecting the CRT or the full-width path).
/// `qInv` comes from the constant-time Fermat ladder `q^(p−2) mod p`, like
/// the runtime-sized key's. A key whose primes merely *lie* (wrong factors
/// for `n`) still gets parameters; the fault check in
/// [`RsaPrivateKey::raw`] routes it to the full-width path at runtime.
fn derive_crt_fixed<const LIMBS: usize>(
    p: &Uint<LIMBS>,
    q: &Uint<LIMBS>,
    d: &Uint<LIMBS>,
) -> Option<FixedRsaCrt<LIMBS>> {
    // `r ≥ 4` (bit length ≥ 3) and odd, without scanning the secret limbs.
    let usable = |r: &Uint<LIMBS>| (r.is_odd() & !r.shr_bits(2).is_zero()).declassify();
    if !usable(p) || !usable(q) || p.ct_eq(q).declassify() {
        return None;
    }
    let one = Uint::ONE;
    let two = Uint::from_u64(2);
    // `Uint::reduce` is the bitwise long division (the moduli are even, so
    // no Montgomery shortcut); it runs once per key construction.
    let dp = d.reduce(&p.wrapping_sub(&one));
    let dq = d.reduce(&q.wrapping_sub(&one));
    // The primes are secret: `new_secret` declassifies only the width scan.
    let mont_p = MontModulus::new_secret(*p);
    let mont_q = MontModulus::new_secret(*q);
    let qinv = mont_p.pow_bits(
        &mont_p.reduce(q),
        &p.wrapping_sub(&two),
        64 * mont_p.limbs(),
    );
    Some(FixedRsaCrt {
        dp,
        dq,
        qinv,
        mont_p,
        mont_q,
    })
}

/// An RSA private key. Holds the private exponent `d` and the primes `p`, `q`.
///
/// Does not implement `Debug` — it would expose secret material.
///
/// # Side-channel protection
///
/// The raw private operation applies *base blinding* (RSA-OAEP-Coron 1999):
/// each call multiplies the input by an unpredictable blinder `r^e`, performs
/// the secret exponentiation on the masked value, then strips the blinder
/// with `r^{-1}`. `r` is `HMAC-SHA256(seed, counter ‖ c)`, where `seed` is a
/// digest of the secret exponent and `counter` is a per-key operation counter
/// bumped on every call — so the blinder is unpredictable to anyone without
/// `d`, *and* it differs between two operations on the same ciphertext. The
/// second property is what Coron/Kocher blinding needs: with a blinder fixed
/// per `(key, ciphertext)` an attacker can replay a ciphertext and average
/// many traces of a byte-identical computation, which is the measurement
/// primitive the Marvin / Brumley-class attacks are built on.
///
/// The counter alone is predictable (it starts at 0 on every parse, is copied
/// by `Clone`, and is inherited across `fork(2)`), so a 16-byte *salt* is
/// mixed in alongside it: freshly drawn from the OS CSPRNG for every private
/// operation where the target has one, and otherwise — bare-metal `no_std`,
/// which has no ambient entropy — drawn once per key instance (and re-drawn
/// on `Clone`), falling back to the purely deterministic
/// seed-plus-counter derivation when even that is unavailable. So the
/// blinder sequence is unpredictable on any hosted build, two clones of a key
/// never replay each other's sequence, and the no-entropy targets keep
/// exactly the previous (still constant-time) behaviour rather than failing.
///
/// This defeats Bleichenbacher- / Manger-style chosen-ciphertext timing
/// attacks and raises the cost of trace averaging. It is *not* a claim of
/// resistance to an attacker with unlimited power/EM traces.
///
/// Blinding requires φ(n), which is only known when the key was generated
/// here (so `p`, `q` are non-zero). Keys imported via
/// [`from_components`](Self::from_components) carry `phi_n = 0` and fall back
/// to unblinded exponentiation — document this when accepting external keys.
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
    /// only as the HMAC key — the input is the counter and the ciphertext.
    blinding_seed: [u8; 32],
    /// Per-key operation counter, mixed into every blinder so that repeating a
    /// ciphertext does not repeat the blinded computation. `AtomicU32` (not
    /// `u64`) because 64-bit atomics do not exist on the 32-bit bare-metal
    /// targets this crate builds for; wrapping after 2³² private operations on
    /// one key instance is acceptable.
    blind_counter: AtomicU32,
    /// Per-instance blinding salt (see the struct docs): random on any target
    /// with an OS CSPRNG, all-zero on bare-metal `no_std`. Re-drawn on
    /// `Clone` so a cloned key does not replay the original's blinders.
    blind_salt: [u8; 16],
    /// Montgomery context for `n` (`None` for an even modulus, see
    /// [`RsaPublicKey`]'s field), built once with the key.
    mont: Option<MontModulus<LIMBS>>,
    /// CRT parameters, when the primes are known and usable.
    crt: Option<FixedRsaCrt<LIMBS>>,
}

// Manual `Clone`: `AtomicU32` is not `Clone`. The clone starts from the
// original's current counter value.
impl<const LIMBS: usize> Clone for RsaPrivateKey<LIMBS> {
    fn clone(&self) -> Self {
        RsaPrivateKey {
            n: self.n,
            e: self.e,
            d: self.d,
            p: self.p,
            q: self.q,
            phi_n_minus_1: self.phi_n_minus_1,
            blinding_seed: self.blinding_seed,
            blind_counter: AtomicU32::new(self.blind_counter.load(Ordering::Relaxed)),
            // Fresh salt: two clones must not produce the same blinder
            // sequence (the counter alone is copied).
            blind_salt: fresh_blind_salt(),
            mont: self.mont.clone(),
            crt: self.crt.clone(),
        }
    }
}

/// A per-key-instance blinding salt: 16 bytes of OS entropy where the target
/// has an OS CSPRNG, all-zero otherwise (bare-metal `no_std`, where the
/// blinder stays the pre-existing deterministic seed-plus-counter value).
pub(super) fn fresh_blind_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    let _ = crate::rng::try_os_entropy(&mut salt);
    salt
}

/// The freshness inputs to one private operation's blinder: the per-key
/// operation counter (public, monotone) and a random salt (see
/// [`per_op_blind_salt`]). Bundled so the derivation keeps a readable
/// argument list.
pub(super) struct BlindNonce {
    /// Per-key operation counter.
    pub counter: u32,
    /// Random salt: fresh per operation where the target has an OS CSPRNG.
    pub salt: [u8; 16],
}

/// The salt mixed into one private operation's blinder: fresh OS entropy when
/// available, else the key's per-instance salt.
pub(super) fn per_op_blind_salt(instance: &[u8; 16]) -> [u8; 16] {
    let mut salt = [0u8; 16];
    if crate::rng::try_os_entropy(&mut salt) {
        salt
    } else {
        *instance
    }
}

/// Computes `phi(n) − 1` from the prime factors and the derived HMAC seed.
/// Returns `(phi_n_minus_1, seed)`. `phi_n_minus_1` is zero when either prime
/// is zero (then blinding is disabled).
fn derive_blinding<const LIMBS: usize>(
    p: &Uint<LIMBS>,
    q: &Uint<LIMBS>,
    d: &Uint<LIMBS>,
) -> (Uint<LIMBS>, [u8; 32]) {
    // Whether the key carries its primes is public (it decides which private
    // operation runs); the verdict is declassified like the boxed key's.
    let missing = p.ct_eq(&Uint::ZERO) | q.ct_eq(&Uint::ZERO);
    let phi_n_minus_1 = if missing.declassify() {
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

/// Derives the per-call blinder `r ∈ [2, n)` — `HMAC-SHA256(seed, counter ‖
/// nonce ‖ salt ‖ c)` chunks filling the modulus width, reduced mod `n` —
/// without a heap allocation. The blinder is wider than `n.bit_len()` by up
/// to 64 bits, so the reduction has bias ≤ 2⁻⁶⁴, negligible because the
/// blinder is a per-call masking value, not a key. If `r` happens to be 0
/// or 1 the blinder degenerates; that astronomically rare case maps to
/// `r = 2` by a masked select (still coprime to `n` with probability
/// 1 − negligible), which keeps the function total.
fn derive_blinder_fixed<const LIMBS: usize>(
    modulus: &MontModulus<LIMBS>,
    blinding_seed: &[u8; 32],
    nonce: &BlindNonce,
    c: &Uint<LIMBS>,
) -> Uint<LIMBS> {
    use crate::hash::HmacSha256;

    // Each HMAC call yields 32 bytes; we walk the modulus's limbs from MSB
    // downward and fill 4 limbs per chunk, advancing a counter so successive
    // chunks are independent.
    let mut r_limbs = [0u64; LIMBS];
    let mut counter: u32 = 0;
    let mut limbs_remaining = LIMBS;
    // Key the HMAC once; each chunk continues from a clone of that state.
    let keyed = HmacSha256::new(blinding_seed);
    while limbs_remaining > 0 {
        let mut m = keyed.clone();
        m.update(b"r");
        m.update(&counter.to_be_bytes());
        // Per-operation nonce: without it the whole blinded computation is a
        // pure function of `(key, c)`, so replaying `c` reproduces every
        // intermediate bit-for-bit and lets an attacker average traces.
        m.update(&nonce.counter.to_be_bytes());
        // Per-operation (or at least per-key-instance) random salt: the
        // counter above is predictable and shared by clones and forks, so on
        // its own it does not stop an attacker from predicting — or making a
        // second key instance replay — the blinder sequence.
        m.update(&nonce.salt);
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
    // Montgomery chunk reduction, not the bitwise long division.
    let r = modulus.reduce(&r_raw);
    let bad = r.ct_eq(&Uint::ZERO) | r.ct_eq(&Uint::ONE);
    <Uint<LIMBS> as crate::ct::ConditionallySelectable>::conditional_select(
        &Uint::from_u64(2),
        &r,
        bad,
    )
}

/// Performs the raw RSA private operation with base blinding (Coron's variant
/// of Kocher / Messerges blinding), full width:
///
/// ```text
///   r        = HMAC-SHA256(blinding_seed, nonce ‖ salt ‖ c)  // reduced mod n
///   r_e      = r^e mod n                        // public exponent, cheap
///   c_blind  = (c · r_e) mod n
///   m        = c_blind^d · r^{φ(n)-1} mod n     // one joint CT ladder;
///                                               // r^{φ(n)-1} = r⁻¹ (Fermat)
/// ```
///
/// When `phi_n_minus_1` is zero (key imported without primes), the function
/// falls back to the unblinded `c^d mod n`.
fn raw_private_blinded<const LIMBS: usize>(
    modulus: &MontModulus<LIMBS>,
    e: &Uint<LIMBS>,
    d: &Uint<LIMBS>,
    phi_n_minus_1: &Uint<LIMBS>,
    blinding_seed: &[u8; 32],
    nonce: &BlindNonce,
    c: &Uint<LIMBS>,
) -> Uint<LIMBS> {
    if bool::from(phi_n_minus_1.ct_eq(&Uint::ZERO)) {
        // Imported key without primes — no φ(n) to drive Fermat. Fall back to
        // the plain constant-time ladder; the caller is responsible for
        // upstream blinding if they need it (see struct docs).
        return modulus.pow(c, d);
    }

    let r = derive_blinder_fixed(modulus, blinding_seed, nonce, c);
    // `e` is public, so the exponent-length ladder applies — ~17 iterations
    // for e = 65537 instead of a full modulus-width pass. It is still
    // branchless and constant-time in the secret base `r`.
    let r_e = modulus.pow_public(&r, e);
    let c_blind = modulus.mul_mod(c, &r_e);
    // c_blind^d · r^(φ(n)−1): the unblinding and the Fermat inverse of the
    // blinder share one joint constant-time ladder (half the squarings of
    // two separate exponentiations).
    modulus.pow2(&c_blind, d, &r, phi_n_minus_1)
}

/// The base-blinded private operation via the CRT: two half-width
/// exponentiations instead of one full-width one (~4× fewer limb
/// multiplications), with the blinder inverted per prime by Fermat — folded
/// into the same joint (Straus) ladder as the unblinding exponentiation, so
/// the inverse costs extra multiplies but no extra squarings. The fixed-width
/// counterpart of the runtime-sized key's `raw_private_crt_blinded`:
///
/// ```text
///   c_blind = c · r^e mod n            (pow_public: e is public, base CT)
///   m_p     = (c_blind mod p)^dP · r^(p−2) mod p    ( = m·r·r⁻¹ = m mod p )
///   m_q     = (c_blind mod q)^dQ · r^(q−2) mod q
///   m       = m_q + q · (qInv·(m_p − m_q) mod p)    (Garner)
/// ```
///
/// Every exponentiation runs the constant-time windowed ladder with secret
/// exponents bounded by the (public) width of their prime; the reductions
/// mod each prime are the Montgomery chunk reduction, and `sub_mod` /
/// `mul_mod` / the widening `mul_wide` have operand-independent schedules.
/// The caller MUST fault-check the result (`m^e ≡ c mod n`) before releasing
/// it: a fault in one CRT half — or a key imported with inconsistent primes
/// — otherwise yields output that factors `n` (Boneh–DeMillo–Lipton).
fn raw_private_crt_blinded<const LIMBS: usize>(
    key: &RsaPrivateKey<LIMBS>,
    modulus: &MontModulus<LIMBS>,
    crt: &FixedRsaCrt<LIMBS>,
    nonce: &BlindNonce,
    c: &Uint<LIMBS>,
) -> Uint<LIMBS> {
    use crate::zeroize::Zeroize;

    let mut r = derive_blinder_fixed(modulus, &key.blinding_seed, nonce, c);
    let mut r_e = modulus.pow_public(&r, &key.e);
    let mut c_blind = modulus.mul_mod(c, &r_e);
    let two = Uint::from_u64(2);

    let half = |mp: &MontModulus<LIMBS>, prime: &Uint<LIMBS>, dx: &Uint<LIMBS>| {
        let mut cx = mp.reduce(&c_blind);
        let mut rx = mp.reduce(&r);
        let mut xm2 = prime.wrapping_sub(&two);
        // cx^dx · rx^(x−2) in one joint ladder: the Fermat inverse of the
        // blinder shares the unblinding exponentiation's squarings. Both
        // exponents are below the prime, so its (public) width bounds them.
        let mx = mp.pow2_bits(&cx, dx, &rx, &xm2, 64 * mp.limbs());
        cx.zeroize();
        rx.zeroize();
        xm2.zeroize();
        mx
    };
    let mut m_p = half(&crt.mont_p, &key.p, &crt.dp);
    let mut m_q = half(&crt.mont_q, &key.q, &crt.dq);

    // Garner recombination: m = m_q + q·(qInv·(m_p − m_q) mod p). The
    // product `q·h < q·p = n` fits the key width (low half of `mul_wide`).
    let mut m_q_mod_p = crt.mont_p.reduce(&m_q);
    let mut diff = crt.mont_p.sub_mod(&m_p, &m_q_mod_p);
    let mut h = crt.mont_p.mul_mod(&diff, &crt.qinv);
    let m = m_q.wrapping_add(&key.q.mul_wide(&h).0);

    r.zeroize();
    r_e.zeroize();
    c_blind.zeroize();
    m_p.zeroize();
    m_q.zeroize();
    m_q_mod_p.zeroize();
    diff.zeroize();
    h.zeroize();
    m
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
    #[cfg_attr(
        not(all(feature = "der", feature = "alloc")),
        doc = "",
        doc = "[`Self::from_pkcs1_der`]: crate",
        doc = "[`Self::from_spki_der`]: crate"
    )]
    pub fn new(n: Uint<LIMBS>, e: Uint<LIMBS>) -> Self {
        let mont = mont_for(&n);
        RsaPublicKey { n, e, mont }
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
    #[cfg_attr(
        not(all(feature = "der", feature = "alloc")),
        doc = "",
        doc = "[`Self::from_pkcs1_der`]: crate",
        doc = "[`Self::from_spki_der`]: crate"
    )]
    pub fn raw(&self, m: &Uint<LIMBS>) -> Uint<LIMBS> {
        // `e` is public, so use the public-exponent ladder (~17 squarings for
        // e = 65537) rather than the secret-width constant-time `pow`.
        self.mont
            .as_ref()
            .expect("Montgomery modulus must be odd")
            .pow_public(m, &self.e)
    }
}

// The `emsa` hooks for the fixed-width keys. These live here rather than in
// `pkcs1` so that the padded schemes are available in allocator-free builds:
// `emsa` itself works in caller-supplied buffers, and `k == LIMBS * 8` is known
// at compile time, so the callers below can put that buffer on the stack.
impl<const LIMBS: usize> super::emsa::RawPublic for RsaPublicKey<LIMBS> {
    fn key_size(&self) -> usize {
        LIMBS * 8
    }
    fn modulus_bits(&self) -> usize {
        self.modulus().bit_len()
    }
    fn raw_public_in_place(&self, buf: &mut [u8]) {
        let out = self.raw(&Uint::<LIMBS>::from_be_bytes(buf));
        out.write_be_bytes(buf);
    }
}

impl<const LIMBS: usize> super::emsa::RawPrivate for RsaPrivateKey<LIMBS> {
    fn key_size(&self) -> usize {
        LIMBS * 8
    }
    fn modulus_bits(&self) -> usize {
        self.modulus().bit_len()
    }
    fn raw_private_in_place(&self, buf: &mut [u8]) {
        let mut out = self.raw(&Uint::<LIMBS>::from_be_bytes(buf));
        out.write_be_bytes(buf);
        // `out` is the raw private-op result (decrypted EM / signature
        // representative) on the stack: wipe it before the frame is reused.
        crate::zeroize::Zeroize::zeroize(&mut out);
    }
    fn secret_seed(&self) -> [u8; 32] {
        self.blinding_seed
    }
    fn modulus_be_into(&self, out: &mut [u8]) {
        self.n.write_be_bytes(out);
    }
}

impl<const LIMBS: usize> super::emsa::PublicModulus for RsaPublicKey<LIMBS> {
    fn modulus_be_into(&self, out: &mut [u8]) {
        // `key_size() == LIMBS * 8` big-endian octets of `n`, matching the
        // width of a validated signature so the RSAVP1 `s < n` comparison in
        // `emsa::verify_*` is over equal lengths.
        self.n.write_be_bytes(out);
    }
}

/// A `k`-octet stack scratch buffer for a `LIMBS`-limb key.
///
/// `[u8; LIMBS * 8]` is not expressible on stable (it needs const-expression
/// arithmetic), but `[[u8; 8]; LIMBS]` is exactly the same size and
/// `as_flattened_mut` (stable since 1.80) reinterprets it as `&mut [u8]` safely
/// — so the padded schemes get exact-size scratch with no allocator and no
/// `unsafe`, rather than an oversized fixed maximum.
pub(crate) struct KeyScratch<const LIMBS: usize>;

impl<const LIMBS: usize> KeyScratch<LIMBS> {
    /// A zeroed `k`-octet buffer. (`Default` is not implemented for arrays of
    /// generic length, so this is a plain associated const.)
    pub(crate) const ZEROED: [[u8; 8]; LIMBS] = [[0u8; 8]; LIMBS];
}

// Best-effort zeroize on drop: the private exponent `d`, primes `p`/`q`,
// blinding `phi_n_minus_1`, and the HMAC seed all live in fixed-size
// stack arrays that would otherwise be returned to the allocator (or the
// stack frame, for stack-allocated keys) with the secret bytes intact.
// `crate::zeroize::Zeroize` overwrites them with volatile stores plus a
// compiler fence, so LLVM cannot eliminate the writes as dead stores.
impl<const LIMBS: usize> Drop for RsaPrivateKey<LIMBS> {
    fn drop(&mut self) {
        use crate::zeroize::Zeroize;
        self.d.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        self.phi_n_minus_1.zeroize();
        self.blinding_seed.zeroize();
        self.blind_salt.zeroize();
        // The CRT parameters are as secret as the primes (`n`'s context is
        // public and needs no wipe).
        self.crt.zeroize();
    }
}

impl<const LIMBS: usize> crate::zeroize::ZeroizeOnDrop for RsaPrivateKey<LIMBS> {}

impl<const LIMBS: usize> RsaPrivateKey<LIMBS> {
    /// Generates an RSA key pair with an `LIMBS * 64`-bit modulus and the given
    /// public exponent `e` (commonly 65537).
    ///
    /// `rounds` is the number of Miller-Rabin rounds per prime candidate. It
    /// is clamped *up* to a size-appropriate floor (FIPS 186-5 Table B.1; see
    /// `prime::min_mr_rounds`), so passing 0 cannot yield a composite factor.
    ///
    /// # Panics
    /// Panics if `e < 3`, `e` is even, or `e ≥ 2^256`: an even `e` is never
    /// coprime to `φ(n)`, so the generation loop would spin forever; `e = 1`
    /// yields `d = 1` (encryption is the identity); FIPS 186-5 §A.1.1 bounds
    /// `e` below `2^256`.
    ///
    /// # Side channels
    /// Key generation is shaped independently of the secret material it
    /// produces: `d = e⁻¹ mod φ(n)` comes from the fixed-trip-count
    /// [`inv_mod_ct`](crate::bignum::inv_mod_ct), and the primality test of
    /// the candidate that becomes `p` or `q` uses no division instruction
    /// and a fixed number of squarings per Miller-Rabin round (see
    /// [`is_prime`](super::prime::is_prime)). What remains observable is
    /// public by nature: how many candidates were rejected, and whether the
    /// `|p − q|` / coprimality checks forced a redraw. Still generate keys
    /// somewhere an attacker cannot take power measurements; every *use* of
    /// the key (sign, decrypt) stays on the constant-time ladders.
    ///
    /// `rng` must be a cryptographically secure CSPRNG (see [`CryptoRng`]).
    pub fn generate<R: RngCore + CryptoRng>(e: Uint<LIMBS>, rng: &mut R, rounds: usize) -> Self {
        assert!(
            bool::from(e.is_odd())
                && !bool::from(e.ct_lt(&Uint::<LIMBS>::from_u64(3)))
                && e.bit_len() <= super::MAX_RSA_EXPONENT_BITS,
            "RsaPrivateKey::generate: e must be odd, >= 3 and < 2^256"
        );
        let half_bits = LIMBS * 32;
        loop {
            let p = random_prime::<LIMBS, R>(rng, half_bits, rounds);
            let q = random_prime::<LIMBS, R>(rng, half_bits, rounds);
            if bool::from(p.ct_eq(&q)) {
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

            // d = e^-1 mod φ(n), computed without a data-dependent trip
            // count (`inv_mod_ct`); retry if e is not coprime to φ — that
            // outcome is public by nature.
            if let Some(d) = inv_mod_ct(&e, &phi).into_option() {
                return Self::from_components_with_primes(n, e, d, p, q);
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
    #[cfg_attr(
        not(all(feature = "der", feature = "alloc")),
        doc = "",
        doc = "[`Self::from_pkcs1_der`]: crate",
        doc = "[`Self::from_pkcs8_der`]: crate"
    )]
    pub fn from_components(n: Uint<LIMBS>, e: Uint<LIMBS>, d: Uint<LIMBS>) -> Self {
        let (phi_n_minus_1, blinding_seed) =
            derive_blinding(&Uint::<LIMBS>::ZERO, &Uint::<LIMBS>::ZERO, &d);
        let mont = mont_for(&n);
        RsaPrivateKey {
            n,
            e,
            d,
            p: Uint::ZERO,
            q: Uint::ZERO,
            phi_n_minus_1,
            blinding_seed,
            blind_counter: AtomicU32::new(0),
            blind_salt: fresh_blind_salt(),
            mont,
            crt: None,
        }
    }

    /// Constructs a private key from all components, including the prime
    /// factors `p` and `q`, so that base blinding and the CRT private
    /// operation are available — the fixed-width counterpart of
    /// [`BoxedRsaPrivateKey::from_components_with_primes`].
    ///
    /// This constructor performs **no validation** beyond what the private
    /// operation's fault check enforces at runtime: primes that are not the
    /// factors of `n` make every private operation fall back to the
    /// (blinded) full-width path, and an even or zero `n` panics there as
    /// for [`from_components`](Self::from_components). Untrusted key
    /// material must go through the fallible parsers.
    ///
    /// Derives `dP`, `dQ`, `qInv` and the primes' Montgomery contexts once
    /// (a few hundred microseconds for a 2048-bit key), so build a key once
    /// and keep it rather than reconstructing it per operation.
    #[cfg_attr(
        not(feature = "alloc"),
        doc = "",
        doc = "[`BoxedRsaPrivateKey::from_components_with_primes`]: crate"
    )]
    #[cfg_attr(
        feature = "alloc",
        doc = "",
        doc = "[`BoxedRsaPrivateKey::from_components_with_primes`]: super::BoxedRsaPrivateKey::from_components_with_primes"
    )]
    pub fn from_components_with_primes(
        n: Uint<LIMBS>,
        e: Uint<LIMBS>,
        d: Uint<LIMBS>,
        p: Uint<LIMBS>,
        q: Uint<LIMBS>,
    ) -> Self {
        let (phi_n_minus_1, blinding_seed) = derive_blinding(&p, &q, &d);
        let mont = mont_for(&n);
        let crt = derive_crt_fixed(&p, &q, &d);
        RsaPrivateKey {
            n,
            e,
            d,
            p,
            q,
            phi_n_minus_1,
            blinding_seed,
            blind_counter: AtomicU32::new(0),
            blind_salt: fresh_blind_salt(),
            mont,
            crt,
        }
    }

    /// The public half of this key pair.
    pub fn public_key(&self) -> RsaPublicKey<LIMBS> {
        RsaPublicKey {
            n: self.n,
            e: self.e,
            mont: self.mont.clone(),
        }
    }

    /// Converts this fixed-size key into a runtime-sized
    /// [`BoxedRsaPrivateKey`](super::BoxedRsaPrivateKey) — e.g. to wrap in an
    /// `x509::AnyPrivateKey` for certificate issuance —
    /// directly, without a PKCS#1 DER round-trip. The prime factors are carried
    /// over, so base-blinding stays enabled (a naive `n,e,d`-only copy would
    /// silently disable it). The component limbs are copied via their
    /// big-endian byte form; no ASN.1 encoding/parsing is involved.
    #[cfg(feature = "alloc")]
    pub fn to_boxed(&self) -> super::BoxedRsaPrivateKey {
        use crate::bignum::BoxedUint;
        let conv = |u: &Uint<LIMBS>| {
            let mut bytes = alloc::vec![0u8; LIMBS * 8];
            u.write_be_bytes(&mut bytes);
            BoxedUint::from_be_bytes(&bytes)
        };
        super::BoxedRsaPrivateKey::from_components_with_primes(
            conv(&self.n),
            conv(&self.e),
            conv(&self.d),
            conv(&self.p),
            conv(&self.q),
        )
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

    /// [`from_components_with_primes`](Self::from_components_with_primes),
    /// as key deserialization calls it (which is `alloc`-gated along with
    /// the DER codecs — hence the cfg, which keeps allocator-free builds
    /// free of a dead-code warning).
    #[cfg(feature = "alloc")]
    pub(crate) fn from_raw_parts(
        n: Uint<LIMBS>,
        e: Uint<LIMBS>,
        d: Uint<LIMBS>,
        p: Uint<LIMBS>,
        q: Uint<LIMBS>,
    ) -> Self {
        Self::from_components_with_primes(n, e, d, p, q)
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
    ///
    /// With the primes known the operation runs the CRT (two half-width
    /// exponentiations) and fault-checks the result with the cheap
    /// public-exponent `m^e ≡ c mod n` before releasing it, so a faulted CRT
    /// half can never escape (Boneh–DeMillo–Lipton). On mismatch it
    /// recomputes with the full-width path — and fault-checks *that* too. If
    /// the recomputation also fails to verify (a transient fault on both
    /// attempts, or a key whose `e`, `d` and `n` are not consistent), the op
    /// returns zero: a value that cannot be a valid signature or a
    /// well-padded plaintext, so every caller fails closed.
    pub fn raw(&self, c: &Uint<LIMBS>) -> Uint<LIMBS> {
        let modulus = self.mont.as_ref().expect("Montgomery modulus must be odd");
        let nonce = BlindNonce {
            counter: self.blind_counter.fetch_add(1, Ordering::Relaxed),
            salt: per_op_blind_salt(&self.blind_salt),
        };
        let full_width = || {
            raw_private_blinded(
                modulus,
                &self.e,
                &self.d,
                &self.phi_n_minus_1,
                &self.blinding_seed,
                &nonce,
                c,
            )
        };
        let Some(crt) = self.crt.as_ref() else {
            return full_width();
        };
        let m = raw_private_crt_blinded(self, modulus, crt, &nonce, c);
        // `c` is public in every caller (a ciphertext or an EMSA-encoded
        // digest), so a plain branch on its range leaks nothing; the
        // comparison with `m^e` is the constant-time limb compare (a
        // variable-time `==` would scan a value derived from the secret `m`)
        // and its verdict is public — `true` for every fault-free operation.
        let c_mod_n = if bool::from(c.ct_lt(&self.n)) {
            *c
        } else {
            modulus.reduce(c)
        };
        if modulus.pow_public(&m, &self.e).ct_eq(&c_mod_n).declassify() {
            return m;
        }
        let mut m2 = full_width();
        if modulus
            .pow_public(&m2, &self.e)
            .ct_eq(&c_mod_n)
            .declassify()
        {
            return m2;
        }
        crate::zeroize::Zeroize::zeroize(&mut m2);
        Uint::ZERO
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

    /// The blinding salt must carry real entropy on any target with an OS
    /// CSPRNG: the operation counter alone starts at 0 on every parse, is
    /// copied by `Clone`, and is inherited across `fork(2)`, so without the
    /// salt the whole blinder sequence is predictable and replayable.
    #[cfg(all(feature = "std", any(unix, windows, target_os = "fullrust")))]
    #[test]
    fn blind_salts_are_random_where_an_os_csprng_exists() {
        let a = fresh_blind_salt();
        let b = fresh_blind_salt();
        assert_ne!(a, [0u8; 16], "salt must not be all-zero on a hosted build");
        assert_ne!(a, b, "per-instance salts must differ");
        let instance = [0x5au8; 16];
        assert_ne!(
            per_op_blind_salt(&instance),
            instance,
            "per-operation salt must be fresh, not the instance fallback"
        );
    }

    /// A cloned key gets its own salt but still computes the same results.
    #[cfg(all(feature = "alloc", feature = "der"))]
    #[test]
    fn cloned_key_blinds_independently_but_agrees() {
        let key = crate::test_util::rsa_test_key_a();
        let clone = key.clone();
        #[cfg(all(feature = "std", any(unix, windows, target_os = "fullrust")))]
        assert_ne!(
            key.blind_salt, clone.blind_salt,
            "a clone must not replay the original's blinder sequence"
        );
        let n = *key.modulus();
        let c = Uint::<32>::from_be_bytes(b"clone-blinding-check-bytes-1234x").reduce(&n);
        assert_eq!(key.raw(&c), clone.raw(&c));
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

    /// BN-5: an even `e` can never be inverted mod `φ(n)`; `generate` must
    /// refuse it before drawing a single prime instead of looping forever.
    #[test]
    #[should_panic(expected = "e must be odd")]
    fn generate_panics_on_even_exponent() {
        let mut r = rng();
        let _ = RsaPrivateKey::<16>::generate(Uint::from_u64(2), &mut r, 4);
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

    /// `to_boxed` produces a faithful runtime-sized key: a signature from the
    /// converted key verifies under both the converted and the *original*
    /// public key — proving n/e/d converted consistently — without a DER
    /// round-trip, and (since p/q are carried over) base-blinding stays on.
    #[cfg(feature = "der")]
    #[test]
    fn to_boxed_preserves_the_key() {
        let fixed = crate::test_util::rsa_test_key_a();
        let boxed = fixed.to_boxed();
        let msg = b"to_boxed round-trip";
        let sig = boxed.sign_pkcs1v15::<Sha256>(msg).unwrap();
        boxed
            .public_key()
            .verify_pkcs1v15::<Sha256>(msg, &sig)
            .unwrap();
        fixed
            .public_key()
            .verify_pkcs1v15::<Sha256>(msg, &sig)
            .unwrap();
    }
}
