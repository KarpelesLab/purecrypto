//! Runtime-sized RSA keys.
//!
//! [`BoxedRsaPublicKey`]/[`BoxedRsaPrivateKey`] hold their modulus as a
//! [`BoxedUint`], so they accept keys of a size only known at runtime (e.g.
//! parsed from a certificate). They share the EMSA padding code in
//! [`super::emsa`] with the const-generic keys, so PKCS#1 v1.5 and PSS behave
//! identically.

use alloc::vec;
use alloc::vec::Vec;

use super::blinding::BlindingCache;
use super::emsa::{self, RawPrivate, RawPublic};
use super::{Error, Pkcs1Digest, PssShake};
use crate::bignum::{BoxedMontModulus, BoxedUint};
use crate::ct::ConstantTimeEq;
use crate::hash::{Digest, HmacSha256, Sha256};
use crate::rng::{CryptoRng, RngCore};
use core::sync::atomic::{AtomicU32, Ordering};

/// A runtime-sized RSA public key.
#[derive(Clone, Debug)]
pub struct BoxedRsaPublicKey {
    n: BoxedUint,
    e: BoxedUint,
    mont: BoxedMontModulus,
    /// Modulus length in octets.
    k: usize,
}

/// A runtime-sized RSA private key (signing uses `c^d mod n`; the prime factors
/// `p`, `q` are kept when the key was generated here, enabling PKCS#1 export
/// with CRT parameters, and are zero for keys imported without them).
///
/// # Multi-prime keys
///
/// RFC 8017 §3.2 multi-prime keys (`RSAPrivateKey` `version = 1` with
/// `otherPrimeInfos`, `n = p · q · r₃ ⋯ rᵤ`) are accepted by the PKCS#1 /
/// PKCS#8 parsers and by
/// [`from_components_with_other_primes`](Self::from_components_with_other_primes);
/// the extra primes are kept, the private operation runs the `u`-prime CRT
/// (RFC 8017 §5.1.2 step 2.b, Garner) under the same blinding and fault
/// check as the two-prime path, and the key re-serializes as `version = 1`.
/// Generating multi-prime keys is not supported. The public key is `(n, e)`
/// as always.
///
/// # Side-channel protection
///
/// When the prime factors are known the raw private operation runs Coron's
/// base blinding (see [`RsaPrivateKey`](super::RsaPrivateKey) for the full
/// recipe). The blinder is `HMAC-SHA256(seed, counter ‖ salt ‖ c)` — keyed by
/// a digest of `d`, so unpredictable without the private key, mixed with a
/// per-key operation counter, so replaying a ciphertext does not replay a
/// byte-identical computation, and with a random salt (fresh per operation
/// where the target has an OS CSPRNG, else per key instance) so that the
/// sequence is not predictable from the counter alone and clones / forks do
/// not replay each other. That freshness is what stops an attacker from
/// averaging many traces of the same exponentiation; without it the residual
/// data-dependent signal accumulates coherently while noise falls as
/// `1/√N`. This does not make the exponentiation trace-proof, it removes the
/// replay primitive.
///
/// Keys imported with [`from_components`](Self::from_components) (no primes)
/// fall back to plain `c^d mod n`; the constant-time Montgomery ladder still
/// applies, but base-blinding cannot.
pub struct BoxedRsaPrivateKey {
    n: BoxedUint,
    e: BoxedUint,
    d: BoxedUint,
    p: BoxedUint,
    q: BoxedUint,
    /// The primes beyond `p` and `q` of a multi-prime key (RFC 8017 §3.2
    /// `r_3 … r_u`, in `otherPrimeInfos` order); empty for a two-prime key.
    other_primes: Vec<BoxedUint>,
    mont: BoxedMontModulus,
    k: usize,
    /// `φ(n) − 1 = ∏(rᵢ − 1) − 1` when the primes are known; `None` when
    /// the key was imported without them (then blinding is disabled).
    phi_n_minus_1: Option<BoxedUint>,
    /// CRT parameters (`dP`, `dQ`, `qInv`, Fermat exponents, and the
    /// per-extra-prime `(dᵢ, tᵢ)` of a multi-prime key) when the primes are
    /// known and usable; `None` disables the CRT fast path. Boxed so the
    /// extra `BoxedUint`s don't bloat every `AnyPrivateKey`.
    crt: Option<alloc::boxed::Box<BoxedRsaCrt>>,
    /// HMAC-SHA256 key (derived from `d`) for per-call blinding values.
    blinding_seed: [u8; 32],
    /// Per-key operation counter, mixed into every blinder so that repeating a
    /// ciphertext does not repeat the blinded computation. `AtomicU32` (not
    /// `u64`) because 64-bit atomics do not exist on the 32-bit bare-metal
    /// targets this crate builds for.
    blind_counter: AtomicU32,
    /// Per-instance blinding salt (see the struct docs): random on any target
    /// with an OS CSPRNG, all-zero on bare-metal `no_std`. Re-drawn on
    /// `Clone`.
    blind_salt: [u8; 16],
    /// The cached blinding pair of the two-prime CRT path (see
    /// [`super::blinding`]); empty on construction and on `Clone`.
    blind_cache: BlindingCache,
}

// Manual `Clone`: `AtomicU32` is not `Clone`. The clone starts from the
// original's current counter value.
impl Clone for BoxedRsaPrivateKey {
    fn clone(&self) -> Self {
        BoxedRsaPrivateKey {
            n: self.n.clone(),
            e: self.e.clone(),
            d: self.d.clone(),
            p: self.p.clone(),
            q: self.q.clone(),
            other_primes: self.other_primes.clone(),
            mont: self.mont.clone(),
            k: self.k,
            phi_n_minus_1: self.phi_n_minus_1.clone(),
            crt: self.crt.clone(),
            blinding_seed: self.blinding_seed,
            blind_counter: AtomicU32::new(self.blind_counter.load(Ordering::Relaxed)),
            // Fresh salt: a clone must not replay the original's blinders.
            blind_salt: super::keys::fresh_blind_salt(),
            // Likewise an empty blinding cache.
            blind_cache: BlindingCache::new(self.mont.limbs()),
        }
    }
}

// Manual impl instead of `#[derive(Debug)]`: the derive printed `d`, `p`,
// `q`, `phi_n_minus_1`, the CRT parameters, and the blinding seed — a whole
// private key leaked into any log line that formats the struct. Only the
// public half is shown. (Kept as an impl rather than dropped entirely:
// removing the trait bound would be a breaking change for downstream code
// that formats key-bearing containers.)
impl core::fmt::Debug for BoxedRsaPrivateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BoxedRsaPrivateKey")
            .field("n", &self.n)
            .field("e", &self.e)
            .field("k", &self.k)
            .finish_non_exhaustive()
    }
}

impl Drop for BoxedRsaPrivateKey {
    fn drop(&mut self) {
        // Best-effort wipe of every secret-bearing field. `n`, `e`, `mont`,
        // and `k` are public; `d`, `p`, `q`, `phi_n_minus_1`, and the
        // HMAC-SHA256 blinding seed all leak information about the secret
        // key and must be cleared. The volatile stores inside
        // `BoxedUint::zeroize` keep LLVM from eliding the writes.
        self.d.zeroize();
        self.p.zeroize();
        self.q.zeroize();
        for r in &mut self.other_primes {
            r.zeroize();
        }
        if let Some(phi) = self.phi_n_minus_1.as_mut() {
            phi.zeroize();
        }
        crate::zeroize::Zeroize::zeroize(&mut self.blinding_seed);
        crate::zeroize::Zeroize::zeroize(&mut self.blind_salt);
    }
}

impl crate::zeroize::ZeroizeOnDrop for BoxedRsaPrivateKey {}

/// Computes `φ(n) − 1 = ∏(rᵢ − 1) − 1` from the primes (if all are nonzero)
/// and the blinding HMAC key (always). `primes` is `p`, `q`, then any extra
/// primes of a multi-prime key.
fn derive_blinding_boxed(primes: &[&BoxedUint], d: &BoxedUint) -> (Option<BoxedUint>, [u8; 32]) {
    // "Does the key carry its primes" is a public property of the key (it
    // selects the blinded or the plain private path); the zero test itself
    // scans every limb of every prime.
    let missing = primes
        .iter()
        .fold(crate::ct::Choice::from(0), |acc, r| acc | r.ct_is_zero());
    let phi_n_minus_1 = if missing.declassify() {
        None
    } else {
        let one = BoxedUint::from_u64(1);
        let mut phi = one.clone();
        for r in primes {
            phi = phi.mul(&r.sub(&one));
        }
        Some(phi.sub(&one))
    };

    let mut h = Sha256::new();
    h.update(b"purecrypto-rsa-blinding-seed-v1");
    // Serialize `d` at the fixed width of its limb storage: sizing it by
    // `bit_len()` would make the hashed length (and the top-down limb scan)
    // depend on the leading zero bits of the private exponent.
    let mut d_bytes = d.to_be_bytes(d.limbs() * 8);
    h.update(&d_bytes);
    // `d_bytes` is the private exponent in the clear: wipe it before the
    // `Vec` is freed.
    super::wipe(&mut d_bytes);
    let digest = h.finalize();
    let mut seed = [0u8; 32];
    seed.copy_from_slice(digest.as_ref());
    (phi_n_minus_1, seed)
}

/// Precomputed CRT parameters for the runtime-sized private key: the
/// half-width exponents `dP`/`dQ`, the recombination coefficient
/// `qInv = q⁻¹ mod p`, and the Fermat exponents `p−2`/`q−2` used to invert
/// the per-call blinder inside each prime field. Everything here is derived
/// from (and as secret as) the prime factors.
#[derive(Clone)]
pub(crate) struct BoxedRsaCrt {
    dp: BoxedUint,
    dq: BoxedUint,
    qinv: BoxedUint,
    pm2: BoxedUint,
    qm2: BoxedUint,
    /// Montgomery contexts for the two primes. They depend only on `p`/`q`, so
    /// they are built once with the rest of the CRT parameters rather than on
    /// every private-key operation — constructing one costs about 100 us at
    /// 1024 bits (it reduces R² into the field), and the signing path needs
    /// two, which was ~9% of an RSA-2048 signature.
    mont_p: BoxedMontModulus,
    mont_q: BoxedMontModulus,
    /// The `(dᵢ, tᵢ)` of each extra prime of a multi-prime key (RFC 8017
    /// §3.2, in `otherPrimeInfos` order); empty for a two-prime key.
    others: Vec<BoxedRsaOtherPrime>,
}

/// CRT parameters of one extra prime `rᵢ` (`i ≥ 3`) of a multi-prime key:
/// the exponent `dᵢ = d mod (rᵢ − 1)`, the coefficient
/// `tᵢ = (r₁ ⋯ rᵢ₋₁)⁻¹ mod rᵢ`, the Fermat exponent `rᵢ − 2` for the
/// blinder inverse, and the Montgomery context for `rᵢ`. As secret as the
/// prime itself.
#[derive(Clone)]
pub(crate) struct BoxedRsaOtherPrime {
    d: BoxedUint,
    t: BoxedUint,
    rm2: BoxedUint,
    mont: BoxedMontModulus,
}

impl Drop for BoxedRsaOtherPrime {
    fn drop(&mut self) {
        self.d.zeroize();
        self.t.zeroize();
        self.rm2.zeroize();
        // `mont` holds `rᵢ` and is wiped by its own `Drop`.
    }
}

impl Drop for BoxedRsaCrt {
    fn drop(&mut self) {
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
        self.pm2.zeroize();
        self.qm2.zeroize();
        // `mont_p` / `mont_q` hold `p` and `q` (plus their R² values) and are
        // wiped by `BoxedMontModulus`'s own `Drop`, which runs right after
        // this one; each `others` entry wipes itself.
    }
}

impl core::fmt::Debug for BoxedRsaCrt {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Every field is secret key material — never print it.
        f.write_str("BoxedRsaCrt(<redacted>)")
    }
}

/// Derives the CRT parameters from the prime factors, or `None` when the key
/// has no (usable) primes. `qInv` is computed as `q^(p−2) mod p` through the
/// constant-time Montgomery ladder rather than `inv_mod_boxed` (whose binary
/// GCD is variable-time in its operands — fine for the one-time DER export,
/// not for something derived on every key parse); likewise each multi-prime
/// coefficient `tᵢ = (r₁ ⋯ rᵢ₋₁)^(rᵢ−2) mod rᵢ`. Degenerate primes (even,
/// tiny, or equal) yield `None`; a key whose primes merely *lie* (wrong
/// factors for `n`) still gets parameters, and the fault check in
/// [`raw_private_blinded_boxed`] routes it to the non-CRT path at runtime.
fn derive_crt_boxed(
    p: &BoxedUint,
    q: &BoxedUint,
    other_primes: &[BoxedUint],
    d: &BoxedUint,
) -> Option<alloc::boxed::Box<BoxedRsaCrt>> {
    // `r ≥ 4` (bit length ≥ 3) and odd, evaluated without scanning the
    // secret prime's limbs; the verdict ("this key has usable primes") is a
    // public property of the key — it selects the CRT or full-width path.
    let usable = |r: &BoxedUint| {
        let odd = crate::ct::Choice::from((r.as_limbs().first().copied().unwrap_or(0) & 1) as u8);
        (odd & !r.shr_bits(2).ct_is_zero()).declassify()
    };
    if !usable(p) || !usable(q) || !other_primes.iter().all(usable) {
        return None;
    }
    // Pairwise distinct: `p, q, r₃ … rᵤ` are secret, so each comparison is
    // the constant-time limb compare; the verdict is public, like `usable`.
    let mut all: Vec<&BoxedUint> = Vec::with_capacity(2 + other_primes.len());
    all.push(p);
    all.push(q);
    all.extend(other_primes.iter());
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            if a.ct_eq(b).declassify() {
                return None;
            }
        }
    }
    let one = BoxedUint::from_u64(1);
    let two = BoxedUint::from_u64(2);
    let pm2 = p.sub(&two);
    let qm2 = q.sub(&two);
    let dp = d.reduce(&p.sub(&one));
    let dq = d.reduce(&q.sub(&one));
    let mont_p = BoxedMontModulus::new(p);
    let mont_q = BoxedMontModulus::new(q);
    let qinv = mont_p.pow(&mont_p.reduce(q), &pm2);
    // RFC 8017 §3.2: tᵢ = (r₁ · r₂ ⋯ rᵢ₋₁)⁻¹ mod rᵢ, with r₁ = p, r₂ = q.
    // `prod` is the running product of the preceding primes — secret
    // (it factors `n`), so it is wiped once the last coefficient is out.
    let mut prod = p.mul(q);
    let mut others = Vec::with_capacity(other_primes.len());
    for r in other_primes {
        let rm2 = r.sub(&two);
        let mont = BoxedMontModulus::new(r);
        let t = mont.pow(&mont.reduce(&prod), &rm2);
        others.push(BoxedRsaOtherPrime {
            d: d.reduce(&r.sub(&one)),
            t,
            rm2,
            mont,
        });
        prod = prod.mul(r);
    }
    prod.zeroize();
    Some(alloc::boxed::Box::new(BoxedRsaCrt {
        dp,
        dq,
        qinv,
        pm2,
        qm2,
        mont_p,
        mont_q,
        others,
    }))
}

/// Derives the per-call blinder `r` — `HMAC-SHA256(seed, nonce ‖ salt ‖ c)`, keyed by
/// the key-bound seed — reduced into `[2, n)`. `nonce` is the caller's
/// per-operation counter: it is what makes two operations on the *same*
/// ciphertext use different blinders, so an attacker cannot replay a
/// ciphertext and average traces of a byte-identical computation.
fn derive_blinder_boxed(
    mont: &BoxedMontModulus,
    blinding_seed: &[u8; 32],
    k_bytes: usize,
    nonce: u32,
    salt: &[u8; 16],
    c: &BoxedUint,
) -> BoxedUint {
    let c_bytes = c.to_be_bytes(k_bytes);
    // Reserve a whole number of HMAC tags: the loop appends 32 bytes at a
    // time and only stops once `k_bytes` are present, so for a modulus
    // length that is not a multiple of 32 (a 2056-bit key, say) the last
    // tag would overrun a `k_bytes` capacity. A `Vec` that grows copies its
    // contents and frees the old buffer *unwiped*, leaving most of the
    // blinder on the heap; sized up front, the buffer below is the only
    // copy and `wipe` reaches all of it.
    let reserved = k_bytes.div_ceil(32) * 32;
    let mut blinder_bytes = Vec::with_capacity(reserved);
    let cap = blinder_bytes.capacity();
    debug_assert!(cap >= reserved);
    let mut counter: u32 = 0;
    // Key the HMAC once; each chunk continues from a clone of that state.
    let keyed = HmacSha256::new(blinding_seed);
    while blinder_bytes.len() < k_bytes {
        let mut m = keyed.clone();
        m.update(b"r");
        m.update(&counter.to_be_bytes());
        m.update(&nonce.to_be_bytes());
        // Random salt (see the struct docs): the counter is predictable and
        // copied by `Clone` / inherited across `fork(2)`, so on its own it
        // does not make the blinder sequence unpredictable.
        m.update(salt);
        m.update(&c_bytes);
        let tag = m.finalize();
        blinder_bytes.extend_from_slice(tag.as_ref());
        counter += 1;
    }
    debug_assert_eq!(
        blinder_bytes.capacity(),
        cap,
        "derive_blinder_boxed: the blinder buffer must not reallocate"
    );
    blinder_bytes.truncate(k_bytes);
    let r_raw = BoxedUint::from_be_bytes(&blinder_bytes);
    // The blinder is as secret as the private exponent it masks: wipe the
    // byte form now that it lives in `r_raw` (a `BoxedUint`, which zeroizes
    // itself on drop).
    super::wipe(&mut blinder_bytes);
    let r = mont.reduce(&r_raw);
    // The blinder is secret: replace the two degenerate values by a masked
    // select rather than an early-exit compare.
    let degenerate = r.ct_is_zero() | r.ct_eq(&BoxedUint::from_u64(1));
    BoxedUint::conditional_select(&BoxedUint::from_u64(2), &r, degenerate)
}

/// Base-blinded raw RSA private op via the CRT: two half-width
/// exponentiations instead of one full-width one (~4× fewer limb
/// multiplications), with the blinder inverted per prime by Fermat — folded
/// into the same joint (Straus) ladder as the unblinding exponentiation, so
/// the inverse costs extra multiplies but no extra squarings.
///
/// ```text
///   c_blind = c · r^e mod n            (pow_public: e is public, base CT)
///   m_p     = (c_blind mod p)^dP · r^(p−2) mod p    ( = m·r·r⁻¹ = m mod p )
///   m_q     = (c_blind mod q)^dQ · r^(q−2) mod q
///   m       = m_q + q · (qInv·(m_p − m_q) mod p)    (Garner)
/// ```
///
/// A multi-prime key (RFC 8017 §5.1.2 step 2.b) continues the Garner
/// recombination over its extra primes, each with the same blinded
/// exponentiation and Fermat blinder inverse:
///
/// ```text
///   R = p · q
///   for i = 3 … u:
///     m_i = (c_blind mod rᵢ)^dᵢ · r^(rᵢ−2) mod rᵢ
///     h   = tᵢ · (m_i − (m mod rᵢ)) mod rᵢ
///     m   = m + R · h;  R = R · rᵢ
/// ```
///
/// Every exponentiation runs the constant-time windowed ladder with secret
/// exponents of public width; the reductions mod each prime are
/// constant-time long division, and `sub_mod` / `mul_mod` / the widening
/// `add` and `mul` have operand-independent schedules. The caller MUST
/// fault-check the result (`m^e ≡ c mod n`) before releasing it: a fault in
/// one CRT half — or a key imported with inconsistent primes — otherwise
/// yields output that factors `n` (Boneh–DeMillo–Lipton).
fn raw_private_crt_blinded(
    key: &BoxedRsaPrivateKey,
    crt: &BoxedRsaCrt,
    nonce: u32,
    salt: &[u8; 16],
    c: &BoxedUint,
) -> BoxedUint {
    let mont = &key.mont;
    let mut r = derive_blinder_boxed(mont, &key.blinding_seed, key.k, nonce, salt, c);
    let mut r_e = mont.pow_public(&r, &key.e);
    let mut c_blind = mont.mul_mod(c, &r_e);

    let mont_p = &crt.mont_p;
    let mont_q = &crt.mont_q;

    let half = |mp: &BoxedMontModulus, dx: &BoxedUint, xm2: &BoxedUint| {
        let mut cx = mp.reduce(&c_blind);
        let mut rx = mp.reduce(&r);
        // cx^dx · rx^(x−2) in one joint ladder: the Fermat inverse of the
        // blinder shares the unblinding exponentiation's squarings. Both
        // exponents are below the prime, so its (public) width bounds them.
        let mx = mp.pow2_bits(&cx, dx, &rx, xm2, 64 * mp.limbs());
        cx.zeroize();
        rx.zeroize();
        mx
    };
    // The two halves are independent: run them as one pair (in lock step on
    // the IFMA backend).
    let (mut m_p, mut m_q) = {
        let mut cp = mont_p.reduce(&c_blind);
        let mut rp = mont_p.reduce(&r);
        let mut cq = mont_q.reduce(&c_blind);
        let mut rq = mont_q.reduce(&r);
        let bits = 64 * mont_p.limbs().max(mont_q.limbs());
        let out = BoxedMontModulus::pow2_bits_pair(
            mont_p,
            (&cp, &crt.dp, &rp, &crt.pm2),
            mont_q,
            (&cq, &crt.dq, &rq, &crt.qm2),
            bits,
        );
        cp.zeroize();
        rp.zeroize();
        cq.zeroize();
        rq.zeroize();
        out
    };

    let mut m = garner(key, crt, &m_p, &m_q);

    r_e.zeroize();
    m_p.zeroize();
    m_q.zeroize();

    // Multi-prime continuation (RFC 8017 §5.1.2 step 2.b.v): `m` is so far
    // the residue mod `R = p·q`; each extra prime lifts it to mod `R·rᵢ`.
    // `big_r` is a partial product of the primes — secret past `p·q`.
    if !crt.others.is_empty() {
        let mut big_r = key.p.mul(&key.q);
        for (op, r_i) in crt.others.iter().zip(key.other_primes.iter()) {
            let mut m_i = half(&op.mont, &op.d, &op.rm2);
            let mut m_mod_r = op.mont.reduce(&m);
            let mut diff = op.mont.sub_mod(&m_i, &m_mod_r);
            let mut h = op.mont.mul_mod(&diff, &op.t);
            let mut lifted = m.add(&big_r.mul(&h));
            core::mem::swap(&mut m, &mut lifted);
            lifted.zeroize();
            let mut next_r = big_r.mul(r_i);
            core::mem::swap(&mut big_r, &mut next_r);
            next_r.zeroize();
            m_i.zeroize();
            m_mod_r.zeroize();
            diff.zeroize();
            h.zeroize();
        }
        big_r.zeroize();
    }

    r.zeroize();
    c_blind.zeroize();
    m
}

/// Garner recombination of the two-prime CRT residues:
/// `m = m_q + q·(qInv·(m_p − m_q) mod p)`, the value below `p·q` congruent
/// to `m_p` mod `p` and `m_q` mod `q`. Constant-time arithmetic throughout
/// (masked `sub_mod`, Montgomery `mul_mod`, fixed-schedule `add` / `mul`).
fn garner(
    key: &BoxedRsaPrivateKey,
    crt: &BoxedRsaCrt,
    m_p: &BoxedUint,
    m_q: &BoxedUint,
) -> BoxedUint {
    let mont_p = &crt.mont_p;
    let mut m_q_mod_p = mont_p.reduce(m_q);
    let mut diff = mont_p.sub_mod(m_p, &m_q_mod_p);
    let mut h = mont_p.mul_mod(&diff, &crt.qinv);
    let mut qh = key.q.mul(&h);
    let m = m_q.add(&qh);
    m_q_mod_p.zeroize();
    diff.zeroize();
    h.zeroize();
    qh.zeroize();
    m
}

/// The per-operation multiplier index `t ∈ 0..16` of the cached blinding
/// walk (see [`super::blinding`]): four bits of
/// `HMAC-SHA256(seed, "t" ‖ nonce ‖ salt)`, so fresh whenever the salt is
/// (OS entropy per operation) and unpredictable without the key otherwise.
fn blind_walk_index(blinding_seed: &[u8; 32], nonce: u32, salt: &[u8; 16]) -> usize {
    let mut m = HmacSha256::new(blinding_seed);
    m.update(b"t");
    m.update(&nonce.to_be_bytes());
    m.update(salt);
    let tag = m.finalize();
    (tag.as_ref()[0] & 0x0f) as usize
}

/// A fresh blinding base for the cache: `(xᵉ, x⁻¹) mod n` for an
/// HMAC-derived `x` ([`derive_blinder_boxed`]), with `x⁻¹` by Fermat in each
/// prime field (`x^(p−2)`, `x^(q−2)`, run as one pair) and Garner. `None`
/// when `x` is not invertible mod `n` (only if it shares a factor with `n`,
/// or the key's primes are inconsistent) — checked by `x·x⁻¹ ≡ 1`.
fn fresh_blinding_base(
    key: &BoxedRsaPrivateKey,
    crt: &BoxedRsaCrt,
    nonce: u32,
    salt: &[u8; 16],
    c: &BoxedUint,
) -> Option<(BoxedUint, BoxedUint)> {
    let mont = &key.mont;
    let (mont_p, mont_q) = (&crt.mont_p, &crt.mont_q);
    let mut x = derive_blinder_boxed(mont, &key.blinding_seed, key.k, nonce, salt, c);
    let mut xp = mont_p.reduce(&x);
    let mut xq = mont_q.reduce(&x);
    let bits = 64 * mont_p.limbs().max(mont_q.limbs());
    let (mut ip, mut iq) =
        BoxedMontModulus::pow_bits_pair(mont_p, &xp, &crt.pm2, mont_q, &xq, &crt.qm2, bits);
    let mut xinv = garner(key, crt, &ip, &iq);
    let mut check = mont.mul_mod(&x, &xinv);
    // Public verdict: true for every consistent key.
    let ok = check.ct_eq(&BoxedUint::from_u64(1)).declassify();
    let xe = mont.pow_public(&x, &key.e);
    for v in [&mut x, &mut xp, &mut xq, &mut ip, &mut iq, &mut check] {
        v.zeroize();
    }
    if ok {
        Some((xe, xinv))
    } else {
        let mut xe = xe;
        xe.zeroize();
        xinv.zeroize();
        None
    }
}

/// The two-prime CRT private op with a cached blinding pair
/// ([`super::blinding`]): `m = ((c·rᵉ)^d mod n)·r⁻¹`, the exponentiation
/// split by the CRT into `(c·rᵉ mod p)^dP` and `(c·rᵉ mod q)^dQ` — plain
/// fixed-window ladders, run as one pair — and recombined by Garner. No
/// inversion and no `rᵉ` exponentiation per operation: the cache hands out
/// the pair after a few multiplications.
///
/// `None` when the cache is busy (another thread is in it) or could not be
/// refreshed; the caller then runs [`raw_private_crt_blinded`]. Like that
/// path, the result MUST be fault-checked before release.
fn raw_private_crt_cached(
    key: &BoxedRsaPrivateKey,
    crt: &BoxedRsaCrt,
    nonce: u32,
    salt: &[u8; 16],
    c: &BoxedUint,
) -> Option<BoxedUint> {
    let mont = &key.mont;
    let t = blind_walk_index(&key.blinding_seed, nonce, salt);
    let (mut a, mut b) = key
        .blind_cache
        .take(mont, t, || fresh_blinding_base(key, crt, nonce, salt, c))?;
    // `a`, `b` are in Montgomery form, so one Montgomery multiply by a plain
    // value yields the plain product.
    let mut cb = mont.mont_mul(c, &a);
    let (mont_p, mont_q) = (&crt.mont_p, &crt.mont_q);
    let mut cp = mont_p.reduce(&cb);
    let mut cq = mont_q.reduce(&cb);
    let bits = 64 * mont_p.limbs().max(mont_q.limbs());
    let (mut m_p, mut m_q) =
        BoxedMontModulus::pow_bits_pair(mont_p, &cp, &crt.dp, mont_q, &cq, &crt.dq, bits);
    let mut mr = garner(key, crt, &m_p, &m_q);
    let m = mont.mont_mul(&mr, &b);
    for v in [
        &mut a, &mut b, &mut cb, &mut cp, &mut cq, &mut m_p, &mut m_q, &mut mr,
    ] {
        v.zeroize();
    }
    Some(m)
}

/// The full-width (non-CRT) base-blinded private op, `c^d mod n`.
fn raw_private_full_width(
    key: &BoxedRsaPrivateKey,
    nonce: u32,
    salt: &[u8; 16],
    c: &BoxedUint,
) -> BoxedUint {
    let mont = &key.mont;
    let phi_n_minus_1 = match key.phi_n_minus_1.as_ref() {
        Some(v) => v,
        None => return mont.pow(c, &key.d), // imported key without primes
    };

    let r = derive_blinder_boxed(mont, &key.blinding_seed, key.k, nonce, salt, c);
    // `e` is public, so the exponent-length ladder applies (still branchless
    // and constant-time in the secret base `r`).
    let r_e = mont.pow_public(&r, &key.e);
    let c_blind = mont.mul_mod(c, &r_e);
    // c_blind^d · r^(φ(n)−1) — the unblinding and the Fermat inverse of the
    // blinder in one joint ladder. The bound is the (public) storage width
    // of the exponents, padded to the modulus as `pow` does.
    let bits = 64 * mont.limbs().max(key.d.limbs()).max(phi_n_minus_1.limbs());
    mont.pow2_bits(&c_blind, &key.d, &r, phi_n_minus_1, bits)
}

/// Base-blinded raw RSA private op for the runtime-sized key.
///
/// With CRT parameters available this runs [`raw_private_crt_blinded`] and
/// fault-checks the result with the (cheap, public-exponent) `m^e ≡ c mod n`
/// before releasing it, so a faulted CRT half can never escape
/// (Boneh–DeMillo–Lipton). On mismatch it recomputes with the full-width
/// path — and fault-checks *that* too: releasing an unverified full-width
/// result would hand back exactly the value the CRT check just refused to
/// trust. If the recomputation also fails to verify (a transient fault on
/// both attempts, or a key whose `e`, `d` and `n` are not consistent), the
/// op returns zero: a value that cannot be a valid signature or a
/// well-padded plaintext, so every caller fails closed instead of emitting
/// something an attacker could use to factor `n`.
fn raw_private_blinded_boxed(key: &BoxedRsaPrivateKey, c: &BoxedUint) -> BoxedUint {
    raw_private_checked_boxed(key, c).unwrap_or_else(|| BoxedUint::zero(1))
}

/// [`raw_private_blinded_boxed`] with the double fault-check failure
/// reported as `None` instead of folded into a zero result. The padded
/// schemes want the zero (it fails every padding / signature check on its
/// own); the public [`BoxedRsaPrivateKey::raw_private`] has no padding to
/// fail, and `0` is the legitimate image of `c = 0`, so it needs the
/// distinction.
fn raw_private_checked_boxed(key: &BoxedRsaPrivateKey, c: &BoxedUint) -> Option<BoxedUint> {
    let mont = &key.mont;
    // One counter bump per private operation. `Relaxed` is enough: the value
    // only has to differ between operations, it orders nothing else.
    let nonce = key.blind_counter.fetch_add(1, Ordering::Relaxed);
    let salt = super::keys::per_op_blind_salt(&key.blind_salt);
    let Some(crt) = key.crt.as_deref() else {
        return Some(raw_private_full_width(key, nonce, &salt, c));
    };

    // Two-prime keys take the cached-blinding path unless another thread
    // holds the cache; multi-prime keys always the stateless one.
    let cached = if crt.others.is_empty() {
        raw_private_crt_cached(key, crt, nonce, &salt, c)
    } else {
        None
    };
    let m = match cached {
        Some(m) => m,
        None => raw_private_crt_blinded(key, crt, nonce, &salt, c),
    };
    // `c` is public in every caller (a ciphertext or an EMSA-encoded
    // digest), so the variable-time `lt` shortcut leaks nothing.
    let n = mont.modulus();
    let c_mod_n = if c.lt(&n) { c.clone() } else { mont.reduce(c) };
    // `m^e` is compared with the constant-time limb compare (the variable-
    // time `==` would scan a value derived from the secret `m`); the
    // verdict is public — it is `true` for every fault-free operation.
    if mont.pow_public(&m, &key.e).ct_eq(&c_mod_n).declassify() {
        return Some(m);
    }
    let mut m2 = raw_private_full_width(key, nonce, &salt, c);
    if mont.pow_public(&m2, &key.e).ct_eq(&c_mod_n).declassify() {
        return Some(m2);
    }
    m2.zeroize();
    None
}

/// Lower bound for `BoxedRsaPublicKey` parsing entry points. Anything smaller
/// is rejected as an unsigned-floor sanity check; per-protocol policy (e.g.
/// 2048-bit minimum for TLS signatures) is enforced separately by callers.
/// Set to 1024 to (a) keep `decrypt_pkcs1v15` safe from the
/// `k < 11` indexing-panic class, and (b) refuse the obviously-broken
/// modulus sizes an attacker might inject via a malicious SPKI.
pub(crate) const MIN_RSA_BITS: usize = 1024;

/// Smallest modulus [`BoxedRsaPrivateKey::generate`] /
/// [`try_generate`](BoxedRsaPrivateKey::try_generate) produce and
/// [`from_crt_components`](BoxedRsaPrivateKey::from_crt_components) accepts.
///
/// Far below anything secure — a 256-bit modulus factors in minutes — and
/// below the parse floor [`MIN_RSA_BITS`]; it exists for interop with
/// stacks that still create toy keys (PHP's `openssl_pkey_new` allows 384
/// bits, OpenSSL's `genrsa` historically 512). 256 is the smallest size at
/// which everything the key is built from still holds with margin: both
/// primes are ≥ 128 bits, so far above the trial-division table and the
/// usual exponents (`e = 65537` is 17 bits, so `gcd(e, p − 1) = 1` redraws
/// stay rare), the Miller-Rabin floor for 128-bit candidates is 24 rounds,
/// `k ≥ 32` octets leaves room for PKCS#1 v1.5 encryption padding
/// (`k ≥ 11`), and the "`e` below `n`" invariant the public-exponent check
/// enforces is still satisfiable (keygen requires `e < 2^(bits − 1) ≤ n`).
pub(crate) const MIN_RSA_KEYGEN_BITS: usize = 256;

/// Smallest modulus the `*_insecure` constructors and parsers
/// ([`BoxedRsaPublicKey::try_new_insecure`],
/// `BoxedRsaPublicKey::from_spki_der_insecure`,
/// `BoxedRsaPrivateKey::from_pkcs1_der_insecure`, …) accept, in bits.
///
/// The same 256-bit floor as [`BoxedRsaPrivateKey::generate`], so every key
/// this crate can generate can also be re-imported. Keys this small are
/// breakable — a 512-bit modulus factors in hours on commodity hardware —
/// and exist only for interop with legacy stacks and test suites (PHP's
/// ext/openssl tests use 512-bit keys). The default constructors and parsers
/// keep their 1024-bit floor.
pub const MIN_RSA_INSECURE_BITS: usize = MIN_RSA_KEYGEN_BITS;

/// Upper bound to prevent CPU-exhaustion on parsing huge SPKI moduli.
/// `BoxedMontModulus::new` costs O(log(limbs)) Montgomery squarings for the
/// R² precomp, and every subsequent `mont_mul` is O(limbs²). 16384 bits is
/// well above any legitimate use.
pub(crate) const MAX_RSA_BITS: usize = 16384;

use super::MAX_RSA_EXPONENT_BITS;

/// Validates that `(n, e)` form a well-formed RSA public exponent. RFC 8017
/// §3.1 requires `e` coprime to `λ(n)`; without the prime factors we can only
/// enforce the structural shape: `n` odd (hence non-zero), `e ≥ 3`, `e` odd,
/// `e < n`, and `e < 2^MAX_RSA_EXPONENT_BITS`. These rule out the degenerate
/// values (`0`, `1`, even, oversized) that a malicious SPKI / certificate
/// could otherwise smuggle through and break downstream sign / verify /
/// encrypt math or turn verification into a DoS lever. The `n` odd check is
/// load-bearing: an even (or zero) modulus reaches `BoxedMontModulus::new`,
/// which asserts an odd modulus and would otherwise panic on
/// attacker-controlled input.
fn validate_public_exponent(n: &BoxedUint, e: &BoxedUint) -> Result<(), Error> {
    // A zero modulus is even, so the odd check also rejects `n = 0`.
    if !n.is_odd() {
        return Err(Error::InvalidKey);
    }
    let three = BoxedUint::from_u64(3);
    if e.lt(&three) || !e.is_odd() || !e.lt(n) || e.bit_len() > MAX_RSA_EXPONENT_BITS {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

/// Validates the private exponent's range: `1 ≤ d < n`. `d = 0` turns every
/// private operation into the constant `1`; `d ≥ n` is never what a
/// well-formed PKCS#1 blob carries (RFC 8017 §3.2 defines `d` as a positive
/// integer below `n`), and an oversized `d` widens the constant-time
/// exponentiation past the modulus width — leaking, via timing, that the key
/// is malformed and costing proportionally more per operation.
fn validate_private_exponent(n: &BoxedUint, d: &BoxedUint) -> Result<(), Error> {
    if d.is_zero() || !d.lt(n) {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

/// Validates that the parsed PKCS#1 / PKCS#8 private-key components are
/// internally consistent: each prime is `> 1` and odd, the primes are
/// pairwise distinct, and their product is `n` (RFC 8017 §3.2; `primes` is
/// `p`, `q`, then the extra primes of a multi-prime key). Without this check
/// a corrupted (or maliciously crafted) key file with mismatched primes
/// silently slips through and produces wrong signatures, leaks information
/// through the CRT recombination path, and in the worst case enables a
/// Bleichenbacher-style fault on the secret exponent. We reject before the
/// key is constructed.
///
/// The primes are size-checked *before* anything is multiplied: no prime may
/// be wider than `n`, and the bit lengths must sum to at most
/// `bits(n) + (#primes − 1)` (a product of factors of `b₁ … b_k` bits has at
/// least `Σbᵢ − (k − 1)` bits, so a larger sum can never equal `n`). Without
/// this, an attacker-supplied blob with megabyte-sized "primes" drove the
/// schoolbook product quadratically (a 2 MB key file cost ~12 s of CPU)
/// before the final comparison rejected it.
fn validate_private_components(n: &BoxedUint, primes: &[&BoxedUint]) -> Result<(), Error> {
    let n_bits = n.bit_len();
    let max_sum = n_bits + primes.len().saturating_sub(1);
    let mut sum = 0usize;
    for r in primes {
        let b = r.bit_len();
        if b > n_bits {
            return Err(Error::InvalidKey);
        }
        sum += b;
        if sum > max_sum {
            return Err(Error::InvalidKey);
        }
    }
    let one = BoxedUint::from_u64(1);
    let mut prod = one.clone();
    for (i, r) in primes.iter().enumerate() {
        if !one.lt(r) {
            return Err(Error::InvalidKey);
        }
        // An even prime is invalid for RSA (the only even prime is 2, far
        // below the size of any legitimate factor). Reject even primes
        // explicitly: an even factor cannot be a real prime and never reaches
        // the assert-odd Montgomery path that an even `n` would.
        if !r.is_odd() {
            return Err(Error::InvalidKey);
        }
        // The primes are secret: compare without an early exit at the first
        // differing limb (the branch on the single verdict bit is fine).
        for other in &primes[i + 1..] {
            if bool::from(r.ct_eq(other)) {
                return Err(Error::InvalidKey);
            }
        }
        prod = prod.mul(r);
    }
    if !bool::from(prod.ct_eq(n)) {
        return Err(Error::InvalidKey);
    }
    Ok(())
}

/// Validates that the private exponent really inverts `e` in every prime
/// field: `e·(d mod (rᵢ−1)) ≡ 1 (mod rᵢ−1)` for each prime (RFC 8017 §3.2).
/// This is exactly the relation the CRT exponentiations rely on, and a `d`
/// that violates it — a corrupted key file, a fault-injected blob, or a
/// deliberately inconsistent one — otherwise silently produces wrong
/// signatures whose CRT halves can reveal a factor of `n`. Cheap: one
/// reduction and one multiplication per prime, once per parse.
fn validate_crt_consistency(
    e: &BoxedUint,
    d: &BoxedUint,
    primes: &[&BoxedUint],
) -> Result<(), Error> {
    let one = BoxedUint::from_u64(1);
    for prime in primes {
        let pm1 = prime.sub(&one);
        let dx = d.reduce(&pm1);
        if !bool::from(e.mul(&dx).reduce(&pm1).ct_eq(&one)) {
            return Err(Error::InvalidKey);
        }
    }
    Ok(())
}

/// Whether `e` is a public exponent key generation can use for a `bits`-bit
/// modulus: odd, `≥ 3`, below `2^256` (FIPS 186-5 §A.1.1), and below
/// `2^(bits − 1)` — the generated `n` is at least that, so `e < n` holds and
/// the key passes [`validate_public_exponent`] (only binding for sizes
/// under 257 bits).
fn keygen_exponent_ok(bits: usize, e: &BoxedUint) -> bool {
    e.is_odd()
        && !e.lt(&BoxedUint::from_u64(3))
        && e.bit_len() <= MAX_RSA_EXPONENT_BITS
        && e.bit_len() < bits
}

/// Upper bound on the number of primes of a multi-prime key accepted by the
/// parsers (`u` in RFC 8017 §3.2, counting `p` and `q`). The RFC sets no
/// limit; in practice multi-prime keys have three or four primes (each
/// must stay large enough that ECM cannot find it), and OpenSSL refuses to
/// generate more than five. The cap keeps a hostile blob from making a
/// parse build an unbounded number of Montgomery contexts.
#[cfg(feature = "der")]
pub(crate) const MAX_RSA_PRIMES: usize = 8;

/// Left-pads a raw-primitive `input` to the modulus width `k` and checks it
/// is a representative `< n` (RFC 8017 §5.1.1 / §5.1.2 step 1). The input
/// may be secret (the message of a raw private-key "encryption"), so the
/// range check is the constant-time byte compare and a rejected buffer is
/// wiped; only the verdict is branched on.
fn raw_input_be(k: usize, n: &BoxedUint, input: &[u8]) -> Result<Vec<u8>, Error> {
    if input.len() > k {
        return Err(Error::InvalidLength);
    }
    let mut buf = vec![0u8; k];
    buf[k - input.len()..].copy_from_slice(input);
    if !emsa::ct_lt_be(&buf, &n.to_be_bytes(k)) {
        super::wipe(&mut buf);
        return Err(Error::MessageTooLong);
    }
    Ok(buf)
}

impl BoxedRsaPublicKey {
    /// Builds a public key from modulus `n` and exponent `e`.
    ///
    /// This constructor performs **no validation** — it is intended for
    /// components that are already trusted. Untrusted input (anything parsed
    /// from a certificate, SPKI, key file, or the network) must go through
    /// [`Self::try_new`] or the fallible parsers ([`Self::from_pkcs1_der`] /
    /// [`Self::from_spki_der`]), which reject a zero/even modulus and a
    /// degenerate exponent.
    ///
    /// # Panics
    /// Panics if `n` is even or zero (the Montgomery precomputation requires
    /// an odd modulus). There is also no size cap here — a huge `n` makes the
    /// O(bits²) precomputation arbitrarily slow; `try_new` bounds it.
    pub fn new(n: BoxedUint, e: BoxedUint) -> Self {
        let k = n.bit_len().div_ceil(8);
        let mont = BoxedMontModulus::new(&n);
        BoxedRsaPublicKey { n, e, mont, k }
    }

    /// Builds a public key from modulus `n` and exponent `e`, rejecting
    /// modulus sizes outside `[MIN_RSA_BITS, MAX_RSA_BITS]` and exponents
    /// that fail the public-exponent shape check (i.e. `e < 3`, `e` even,
    /// or `e ≥ n`). Used by the attacker-controlled parse paths
    /// (SPKI / certificates).
    pub fn try_new(n: BoxedUint, e: BoxedUint) -> Result<Self, Error> {
        Self::try_new_with_floor(n, e, MIN_RSA_BITS)
    }

    /// **Insecure.** [`try_new`](Self::try_new) with the modulus floor
    /// lowered from 1024 to [`MIN_RSA_INSECURE_BITS`] (256) bits, for
    /// interop with legacy / test keys such as 512-bit ones. Every other
    /// check (exponent shape, the 16384-bit cap) still applies.
    ///
    /// A modulus this small can be factored by anyone who cares to; never
    /// use such a key to protect anything.
    pub fn try_new_insecure(n: BoxedUint, e: BoxedUint) -> Result<Self, Error> {
        Self::try_new_with_floor(n, e, MIN_RSA_INSECURE_BITS)
    }

    fn try_new_with_floor(n: BoxedUint, e: BoxedUint, min_bits: usize) -> Result<Self, Error> {
        let bits = n.bit_len();
        if !(min_bits..=MAX_RSA_BITS).contains(&bits) {
            return Err(Error::InvalidLength);
        }
        validate_public_exponent(&n, &e)?;
        Ok(Self::new(n, e))
    }

    /// The modulus `n`.
    pub fn modulus(&self) -> &BoxedUint {
        &self.n
    }

    /// The public exponent `e`. Downstream protocols (SSH `ssh-rsa` key
    /// blobs, JWK `RSAPublicKey`) need to re-emit `(n, e)` byte-for-byte
    /// from a parsed key.
    pub fn exponent(&self) -> &BoxedUint {
        &self.e
    }

    /// The raw RSA public operation `m^e mod n` (RFC 8017 §5.1.1 RSAEP /
    /// §5.2.2 RSAVP1) with no padding: the primitive behind OpenSSL's
    /// `RSA_public_encrypt` / `RSA_public_decrypt` with `RSA_NO_PADDING`.
    /// Inverse of [`BoxedRsaPrivateKey::raw_private`].
    ///
    /// `input` is a big-endian integer of at most `k` octets (the modulus
    /// length; shorter input is read as left-padded with zeros); the result
    /// is always exactly `k` octets.
    ///
    /// Unpadded RSA is malleable and deterministic — use it only to
    /// implement a padding scheme or interoperate with one.
    ///
    /// # Errors
    /// * [`Error::InvalidLength`] — `input` is longer than `k` octets.
    /// * [`Error::MessageTooLong`] — the value is `≥ n` (RFC 8017 "message
    ///   representative out of range").
    pub fn raw_public(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = raw_input_be(self.k, &self.n, input)?;
        self.raw_public_in_place(&mut buf);
        Ok(buf)
    }

    /// Verifies a PKCS#1 v1.5 signature over `msg`, hashing with `D`.
    pub fn verify_pkcs1v15<D: Pkcs1Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let (mut em, mut expected) = (vec![0u8; self.k], vec![0u8; self.k]);
        emsa::verify_pkcs1v15::<D, _>(self, msg, sig, &mut em, &mut expected)
    }

    /// Verifies a [`sign_pkcs1v15_prehashed`](BoxedRsaPrivateKey::sign_pkcs1v15_prehashed)
    /// signature over a pre-computed hash (no `DigestInfo`). Legacy interop only.
    #[cfg(feature = "tls-legacy")]
    pub fn verify_pkcs1v15_prehashed(&self, t: &[u8], sig: &[u8]) -> Result<(), Error> {
        let (mut em, mut expected) = (vec![0u8; self.k], vec![0u8; self.k]);
        emsa::verify_pkcs1v15_raw(self, t, sig, &mut em, &mut expected)
    }

    /// Verifies an RSA-PSS signature over `msg`, hashing with `D` and
    /// requiring the salt length to equal `D`'s output length (the strict
    /// TLS 1.3 / X.509 profile).
    pub fn verify_pss<D: Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        self.verify_pss_mgf::<D, D>(msg, sig)
    }

    /// [`verify_pss`](Self::verify_pss) with a distinct MGF1 hash: `D`
    /// hashes the message and fixes the expected salt length, `M` is the
    /// digest MGF1 unmasks the data block with. RFC 8017 §8.1 allows `M` to
    /// differ from `D`; the common case is `M == D`, which is
    /// [`verify_pss`](Self::verify_pss).
    pub fn verify_pss_mgf<D: Digest, M: Digest>(
        &self,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), Error> {
        let (mut em, mut db) = (vec![0u8; self.k], vec![0u8; self.k]);
        emsa::verify_pss::<D, M, _>(self, msg, sig, &mut em, &mut db)
    }

    /// Verifies an RSA-PSS signature over `msg`, requiring the salt to be
    /// exactly `salt_len` octets.
    pub fn verify_pss_with_salt_len<D: Digest>(
        &self,
        msg: &[u8],
        sig: &[u8],
        salt_len: usize,
    ) -> Result<(), Error> {
        self.verify_pss_with_salt_len_mgf::<D, D>(msg, sig, salt_len)
    }

    /// [`verify_pss_with_salt_len`](Self::verify_pss_with_salt_len) with a
    /// distinct MGF1 hash `M` (RFC 8017 §8.1 allows it to differ from the
    /// message hash `D`). The common case is `M == D`, which is
    /// [`verify_pss_with_salt_len`](Self::verify_pss_with_salt_len).
    pub fn verify_pss_with_salt_len_mgf<D: Digest, M: Digest>(
        &self,
        msg: &[u8],
        sig: &[u8],
        salt_len: usize,
    ) -> Result<(), Error> {
        let (mut em, mut db) = (vec![0u8; self.k], vec![0u8; self.k]);
        emsa::verify_pss_with_salt_len::<D, M, _>(self, msg, sig, salt_len, &mut em, &mut db)
    }

    /// Verifies an RSA-PSS signature over `msg`, recovering the salt length
    /// from the encoded message (accepts any valid salt length). Use this for
    /// interop with signers that do not use the salt-length == digest-length
    /// profile.
    pub fn verify_pss_any_salt<D: Digest>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        self.verify_pss_any_salt_mgf::<D, D>(msg, sig)
    }

    /// [`verify_pss_any_salt`](Self::verify_pss_any_salt) with a distinct
    /// MGF1 hash `M` (RFC 8017 §8.1 allows it to differ from the message
    /// hash `D`). The common case is `M == D`, which is
    /// [`verify_pss_any_salt`](Self::verify_pss_any_salt).
    pub fn verify_pss_any_salt_mgf<D: Digest, M: Digest>(
        &self,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), Error> {
        let (mut em, mut db) = (vec![0u8; self.k], vec![0u8; self.k]);
        emsa::verify_pss_any_salt::<D, M, _>(self, msg, sig, &mut em, &mut db)
    }

    /// Verifies an RSASSA-PSS-SHAKE signature (RFC 8702) over `msg`: `X`
    /// (SHAKE128 or SHAKE256) is the hash and the mask generation function
    /// (squeezed directly, not through MGF1), and the salt must be
    /// `X::OUTPUT_LEN` octets (the RFC 8702 §3.1 profile).
    pub fn verify_pss_shake<X: PssShake>(&self, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        self.verify_pss_shake_with_salt_len::<X>(msg, sig, X::OUTPUT_LEN)
    }

    /// [`verify_pss_shake`](Self::verify_pss_shake) requiring the salt to be
    /// exactly `salt_len` octets.
    pub fn verify_pss_shake_with_salt_len<X: PssShake>(
        &self,
        msg: &[u8],
        sig: &[u8],
        salt_len: usize,
    ) -> Result<(), Error> {
        let (mut em, mut db) = (vec![0u8; self.k], vec![0u8; self.k]);
        emsa::verify_pss_shake::<X, _>(self, msg, sig, Some(salt_len), &mut em, &mut db)
    }

    /// [`verify_pss_shake`](Self::verify_pss_shake) recovering the salt
    /// length from the encoded message (accepts any valid salt length).
    pub fn verify_pss_shake_any_salt<X: PssShake>(
        &self,
        msg: &[u8],
        sig: &[u8],
    ) -> Result<(), Error> {
        let (mut em, mut db) = (vec![0u8; self.k], vec![0u8; self.k]);
        emsa::verify_pss_shake::<X, _>(self, msg, sig, None, &mut em, &mut db)
    }

    /// Encrypts `msg` with PKCS#1 v1.5.
    ///
    /// `rng` must be a cryptographically secure CSPRNG (see [`CryptoRng`]) —
    /// the random padding bytes are part of the security argument.
    pub fn encrypt_pkcs1v15<R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; self.k];
        emsa::encrypt_pkcs1v15(self, msg, rng, &mut out)?;
        Ok(out)
    }

    /// Encrypts `msg` with RSAES-OAEP (RFC 8017 §7.1.1), hashing with `D` and
    /// binding the optional `label`.
    ///
    /// `rng` must be a cryptographically secure CSPRNG (see [`CryptoRng`]) —
    /// OAEP's security reduction depends on the seed being unpredictable.
    pub fn encrypt_oaep<D: Digest, R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        label: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        self.encrypt_oaep_mgf::<D, D, R>(msg, label, rng)
    }

    /// [`encrypt_oaep`](Self::encrypt_oaep) with a distinct MGF1 hash: `D`
    /// hashes the label (and sets the seed length and message capacity), `M`
    /// is the digest MGF1 masks the seed and data block with. RFC 8017 §7.1
    /// allows `M` to differ from `D` (`RSAES-OAEP-params` names
    /// `maskGenAlgorithm` separately); the common case is `M == D`, which is
    /// [`encrypt_oaep`](Self::encrypt_oaep). The decryptor must use the same
    /// pair ([`decrypt_oaep_mgf`](BoxedRsaPrivateKey::decrypt_oaep_mgf)).
    pub fn encrypt_oaep_mgf<D: Digest, M: Digest, R: RngCore + CryptoRng>(
        &self,
        msg: &[u8],
        label: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; self.k];
        emsa::encrypt_oaep::<D, M, _, _>(self, msg, label, rng, &mut out)?;
        Ok(out)
    }
}

impl BoxedRsaPrivateKey {
    /// Builds a private key from `n`, `e`, and the private exponent `d` (without
    /// the prime factors, so CRT-based PKCS#1 export and base-blinding are
    /// unavailable; see the struct docs).
    ///
    /// This constructor performs **no validation** — it is intended for
    /// components that are already trusted. Untrusted input (key files,
    /// PKCS#1/PKCS#8 blobs) must go through the fallible parsers —
    /// [`Self::from_pkcs1_der`] / [`Self::from_pkcs8_der`] — which validate
    /// the components first.
    ///
    /// # Panics
    /// Panics if `n` is even or zero (the Montgomery precomputation requires
    /// an odd modulus).
    pub fn from_components(n: BoxedUint, e: BoxedUint, d: BoxedUint) -> Self {
        let k = n.bit_len().div_ceil(8);
        let mont = BoxedMontModulus::new(&n);
        let p = BoxedUint::zero(1);
        let q = BoxedUint::zero(1);
        let (phi_n_minus_1, blinding_seed) = derive_blinding_boxed(&[&p, &q], &d);
        BoxedRsaPrivateKey {
            n,
            e,
            d,
            p,
            q,
            other_primes: Vec::new(),
            mont,
            k,
            phi_n_minus_1,
            crt: None,
            blinding_seed,
            blind_counter: AtomicU32::new(0),
            blind_salt: super::keys::fresh_blind_salt(),
            blind_cache: BlindingCache::new(k.div_ceil(8)),
        }
    }

    /// Builds a private key from `n`, `e`, `d` **and** the prime factors
    /// `p`/`q`, so base-blinding stays enabled (unlike
    /// [`from_components`](Self::from_components), which drops the primes and
    /// thus the blinding). Used by [`RsaPrivateKey::to_boxed`](crate::rsa::RsaPrivateKey::to_boxed)
    /// to convert a fixed-size key without losing its side-channel protection.
    ///
    /// Like the other component constructors this performs **no validation**;
    /// the components must already be a consistent, trusted key.
    /// [`from_crt_components`](Self::from_crt_components) is the checked
    /// form for components that are not.
    ///
    /// # Panics
    /// Panics if `n` is even or zero (the Montgomery precomputation requires an
    /// odd modulus).
    pub fn from_components_with_primes(
        n: BoxedUint,
        e: BoxedUint,
        d: BoxedUint,
        p: BoxedUint,
        q: BoxedUint,
    ) -> Self {
        Self::from_components_with_other_primes(n, e, d, p, q, Vec::new())
    }

    /// Builds a multi-prime private key (RFC 8017 §3.2) from `n`, `e`, `d`,
    /// the first two primes `p`/`q` and the extra primes `r₃ … rᵤ`
    /// (`other_primes`, in `otherPrimeInfos` order, so that
    /// `n = p · q · r₃ ⋯ rᵤ`). The CRT exponents and coefficients
    /// (`dP`, `dQ`, `qInv`, `dᵢ`, `tᵢ`) are derived here on the
    /// constant-time ladder; the private operation runs the `u`-prime CRT
    /// with the same blinding and fault check as the two-prime path. An
    /// empty `other_primes` is exactly
    /// [`from_components_with_primes`](Self::from_components_with_primes).
    ///
    /// Like the other component constructors this performs **no validation**;
    /// the components must already be a consistent, trusted key (untrusted
    /// blobs go through [`from_pkcs1_der`](Self::from_pkcs1_der) /
    /// [`from_pkcs8_der`](Self::from_pkcs8_der), which check the primes
    /// against `n` and `d` against `e` in every prime field). Degenerate
    /// primes (even, below 3 bits, or repeated) disable the CRT fast path
    /// rather than panic; a key whose primes do not actually factor `n` is
    /// caught by the per-operation fault check and served by the full-width
    /// `c^d mod n` path instead.
    ///
    /// # Panics
    /// Panics if `n` is even or zero (the Montgomery precomputation requires an
    /// odd modulus).
    pub fn from_components_with_other_primes(
        n: BoxedUint,
        e: BoxedUint,
        d: BoxedUint,
        p: BoxedUint,
        q: BoxedUint,
        other_primes: Vec<BoxedUint>,
    ) -> Self {
        let k = n.bit_len().div_ceil(8);
        let mont = BoxedMontModulus::new(&n);
        let (phi_n_minus_1, blinding_seed) = {
            let mut all: Vec<&BoxedUint> = alloc::vec![&p, &q];
            all.extend(other_primes.iter());
            derive_blinding_boxed(&all, &d)
        };
        let crt = derive_crt_boxed(&p, &q, &other_primes, &d);
        BoxedRsaPrivateKey {
            n,
            e,
            d,
            p,
            q,
            other_primes,
            mont,
            k,
            phi_n_minus_1,
            crt,
            blinding_seed,
            blind_counter: AtomicU32::new(0),
            blind_salt: super::keys::fresh_blind_salt(),
            blind_cache: BlindingCache::new(k.div_ceil(8)),
        }
    }

    /// Builds a two-prime private key from all eight RFC 8017 §3.2
    /// `RSAPrivateKey` components — `n`, `e`, `d`, `p`, `q`,
    /// `dP = d mod (p − 1)`, `dQ = d mod (q − 1)` and `qInv = q⁻¹ mod p`
    /// (OpenSSL's `n`, `e`, `d`, `p`, `q`, `dmp1`, `dmq1`, `iqmp`) —
    /// checking that they form one consistent key, then building it with
    /// [`from_components_with_primes`](Self::from_components_with_primes).
    ///
    /// Unlike the other component constructors this **validates**, with the
    /// same checks as the PKCS#1 / PKCS#8 parsers (which ignore a blob's
    /// CRT values and recompute them) plus a comparison of the supplied CRT
    /// values against the recomputed ones:
    /// * `n` of 256 to 16384 bits (the keygen floor — lower than the
    ///   1024-bit parse floor — so any key [`generate`](Self::generate)
    ///   makes can be rebuilt here);
    /// * `e` odd, `3 ≤ e < n`, `e < 2^256`; `1 ≤ d < n`;
    /// * `p`, `q` odd, `> 1`, distinct, and `p · q = n`;
    /// * `e · d ≡ 1 (mod p − 1)` and `(mod q − 1)`, i.e. `d` inverts `e`
    ///   modulo `λ(n) = lcm(p − 1, q − 1)` (a `d` reduced mod `λ(n)` and the
    ///   textbook one mod `φ(n)` are both accepted);
    /// * `dP`, `dQ`, `qInv` equal to `d mod (p − 1)`, `d mod (q − 1)` and
    ///   `q⁻¹ mod p` (fully reduced, so `qInv · q ≡ 1 (mod p)`).
    ///
    /// `p` and `q` are not tested for primality (nor are they by the
    /// parsers): a composite factor breaks the CRT relations, which the
    /// per-operation fault check then catches. The secret comparisons run
    /// on the constant-time limb compare; which check failed is not
    /// reported.
    ///
    /// # Errors
    /// * [`Error::InvalidLength`] — `n` outside 256..=16384 bits.
    /// * [`Error::InvalidKey`] — any other inconsistency.
    #[allow(clippy::too_many_arguments)] // the eight RFC 8017 components
    pub fn from_crt_components(
        n: BoxedUint,
        e: BoxedUint,
        d: BoxedUint,
        p: BoxedUint,
        q: BoxedUint,
        dp: BoxedUint,
        dq: BoxedUint,
        qinv: BoxedUint,
    ) -> Result<Self, Error> {
        if !(MIN_RSA_KEYGEN_BITS..=MAX_RSA_BITS).contains(&n.bit_len()) {
            return Err(Error::InvalidLength);
        }
        validate_public_exponent(&n, &e)?;
        validate_private_exponent(&n, &d)?;
        validate_private_components(&n, &[&p, &q])?;
        validate_crt_consistency(&e, &d, &[&p, &q])?;
        let key = Self::from_components_with_primes(n, e, d, p, q);
        // `derive_crt_boxed` recomputed the three values on the
        // constant-time ladder. Of the primes the checks above let through
        // it declines only `3` (below its 3-bit floor), which leaves nothing
        // to compare against.
        let Some(crt) = key.crt.as_deref() else {
            return Err(Error::InvalidKey);
        };
        // One public verdict over the three secret comparisons.
        let ok = crt.dp.ct_eq(&dp) & crt.dq.ct_eq(&dq) & crt.qinv.ct_eq(&qinv);
        if !ok.declassify() {
            return Err(Error::InvalidKey);
        }
        Ok(key)
    }

    /// The number of prime factors the key carries: `2` for a two-prime key
    /// (including one imported without its primes), `u ≥ 3` for a
    /// multi-prime key (RFC 8017 §3.2).
    pub fn num_primes(&self) -> usize {
        2 + self.other_primes.len()
    }

    /// Generates a runtime-sized RSA key pair with a `bits`-bit modulus and
    /// public exponent `e` (commonly 65537). The primes are `⌈bits/2⌉` and
    /// `⌊bits/2⌋` bits (equal for an even `bits`), each with its top two bits
    /// set, so `n` has exactly `bits` bits for odd sizes too. `rounds` is the
    /// Miller-Rabin count per candidate; it is clamped *up* to a
    /// size-appropriate floor (FIPS 186-5 Table B.1; see
    /// `prime::min_mr_rounds`), so passing 0 cannot yield a composite factor.
    ///
    /// Sizes below 2048 bits are insecure and supported for legacy interop
    /// only. [`try_generate`](Self::try_generate) is the fallible form, and
    /// also caps `bits` at the size the parsers accept back.
    ///
    /// # Panics
    /// Panics on parameters that can never yield a usable key rather than
    /// looping forever or producing a broken one:
    /// * `bits < 256` — see `MIN_RSA_KEYGEN_BITS` for why that floor;
    /// * `e < 3`, `e` even, `e ≥ 2^256` or `e ≥ 2^(bits − 1)` — an even `e`
    ///   is never coprime to `φ(n)` (the loop would spin forever), `e = 1`
    ///   makes `d = 1` (encryption is the identity), FIPS 186-5 §A.1.1
    ///   bounds `e` below `2^256`, and `e` must stay below `n`.
    ///
    /// # Side channels
    /// Key generation is shaped independently of the secret material it
    /// produces: `d = e⁻¹ mod φ(n)` comes from the fixed-trip-count
    /// [`inv_mod_ct_boxed`](crate::bignum::inv_mod_ct_boxed), and the
    /// primality test of the candidate that becomes `p` or `q` uses no
    /// division instruction and a fixed number of squarings per Miller-Rabin
    /// round. What remains observable is public by nature: how many
    /// candidates were rejected, and whether the `|p − q|` / coprimality
    /// checks forced a redraw. Still generate keys somewhere an attacker
    /// cannot take power measurements. Every *use* of the key stays on the
    /// constant-time ladders; `qInv` for the PKCS#1 export comes from the
    /// constant-time CRT precomputation.
    ///
    /// `rng` must be a cryptographically secure CSPRNG (see [`CryptoRng`]).
    pub fn generate<R: RngCore + CryptoRng>(
        bits: usize,
        e: BoxedUint,
        rng: &mut R,
        rounds: usize,
    ) -> Self {
        assert!(
            bits >= MIN_RSA_KEYGEN_BITS,
            "RsaPrivateKey::generate: bits must be >= {MIN_RSA_KEYGEN_BITS} (got {bits})"
        );
        assert!(
            keygen_exponent_ok(bits, &e),
            "RsaPrivateKey::generate: e must be odd, >= 3, < 2^256 and < 2^(bits - 1)"
        );
        Self::generate_unchecked(bits, e, rng, rounds)
    }

    /// Fallible [`generate`](Self::generate): any `bits` in
    /// `256..=16384` (odd sizes included), returning an error instead of
    /// panicking on out-of-range parameters.
    ///
    /// # Errors
    /// * [`Error::InvalidLength`] — `bits` below 256 or above 16384 (the
    ///   largest modulus the parsers accept back).
    /// * [`Error::InvalidKey`] — `e < 3`, `e` even, `e ≥ 2^256`, or
    ///   `e ≥ 2^(bits − 1)`.
    pub fn try_generate<R: RngCore + CryptoRng>(
        bits: usize,
        e: BoxedUint,
        rng: &mut R,
        rounds: usize,
    ) -> Result<Self, Error> {
        if !(MIN_RSA_KEYGEN_BITS..=MAX_RSA_BITS).contains(&bits) {
            return Err(Error::InvalidLength);
        }
        if !keygen_exponent_ok(bits, &e) {
            return Err(Error::InvalidKey);
        }
        Ok(Self::generate_unchecked(bits, e, rng, rounds))
    }

    /// The key-generation loop proper, for parameters [`generate`] /
    /// [`try_generate`] have already checked.
    ///
    /// [`generate`]: Self::generate
    /// [`try_generate`]: Self::try_generate
    fn generate_unchecked<R: RngCore + CryptoRng>(
        bits: usize,
        e: BoxedUint,
        rng: &mut R,
        rounds: usize,
    ) -> Self {
        use crate::bignum::inv_mod_ct_boxed;
        let one = BoxedUint::from_u64(1);
        // An odd size splits as ⌈bits/2⌉ + ⌊bits/2⌋. With the top two bits of
        // each prime forced, p·q ≥ (3/4)·2^p_bits · (3/4)·2^q_bits
        // = (9/16)·2^bits ≥ 2^(bits−1), so `n` still has exactly `bits` bits.
        // For an even size both are `bits/2`: the FIPS 186-5 construction,
        // drawing exactly as before.
        let p_bits = bits.div_ceil(2);
        let q_bits = bits / 2;
        loop {
            let p = super::prime::random_prime_boxed(rng, p_bits, rounds);
            let q = super::prime::random_prime_boxed(rng, q_bits, rounds);
            // Redraw decisions are public (only their count is observable).
            if p.ct_eq(&q).declassify() {
                continue;
            }
            // FIPS 186-5 B.3.1: redraw if |p − q| < 2^(bits/2 − 100), which would
            // expose the modulus to Fermat factorization. `|p − q| < 2^k` iff its
            // bit length is ≤ k, so compare bit lengths without materializing the
            // power. `saturating_sub` keeps the bound total for sub-200-bit toy
            // sizes (where the threshold collapses to 0 and the check is a no-op
            // since `p ≠ q`). For an odd size `⌊bits/2⌋` is the bound; there
            // `p` is a bit longer than `q` with both top bits set, so
            // `p − q > 2^(q_bits − 1)` and the check always passes.
            //
            // Both differences are computed and one is selected, so which
            // prime is larger never steers a branch or a load, and the bound
            // is tested as `|p − q| >> k == 0` rather than by scanning the
            // secret difference for its length.
            let p_lt_q = crate::ct::Choice::from(p.lt(&q) as u8);
            let diff = BoxedUint::conditional_select(&q.sub(&p), &p.sub(&q), p_lt_q);
            if diff
                .shr_bits(q_bits.saturating_sub(100))
                .ct_is_zero()
                .declassify()
            {
                continue;
            }
            let n = p.mul(&q);
            // `n` is the public modulus.
            crate::ct::declassify_val(n.as_limbs());
            let phi = p.sub(&one).mul(&q.sub(&one));
            // d = e^-1 mod φ(n), computed without a data-dependent trip
            // count (`inv_mod_ct_boxed`); retry if e is not coprime to φ —
            // that outcome is public by nature.
            if let Some(d) = inv_mod_ct_boxed(&e, &phi).into_public_option() {
                return Self::from_components_with_primes(n, e, d, p, q);
            }
        }
    }

    /// The corresponding public key.
    pub fn public_key(&self) -> BoxedRsaPublicKey {
        BoxedRsaPublicKey::new(self.n.clone(), self.e.clone())
    }

    /// The modulus.
    pub fn modulus(&self) -> &BoxedUint {
        &self.n
    }

    /// The private exponent `d`.
    pub fn private_exponent(&self) -> &BoxedUint {
        &self.d
    }

    /// The prime factors `(p, q)`, or `None` for a key built with
    /// [`from_components`](Self::from_components) (which carries none).
    pub fn primes(&self) -> Option<(&BoxedUint, &BoxedUint)> {
        if self.p.is_zero() || self.q.is_zero() {
            None
        } else {
            Some((&self.p, &self.q))
        }
    }

    /// The CRT parameters `(dP, dQ, qInv)` of RFC 8017 §3.2 —
    /// `d mod (p − 1)`, `d mod (q − 1)` and `q⁻¹ mod p` (OpenSSL's `dmp1`,
    /// `dmq1`, `iqmp`) — as the private operation uses them. `None` for a
    /// key without (usable) primes: one built with
    /// [`from_components`](Self::from_components), or whose primes are
    /// degenerate (even, below 3 bits, or equal). A multi-prime key's
    /// per-prime `(dᵢ, tᵢ)` are not included.
    ///
    /// These are as secret as `d`, `p` and `q`.
    pub fn crt_params(&self) -> Option<(&BoxedUint, &BoxedUint, &BoxedUint)> {
        self.crt.as_deref().map(|c| (&c.dp, &c.dq, &c.qinv))
    }

    /// The raw RSA private operation `c^d mod n` (RFC 8017 §5.1.2 RSADP /
    /// §5.2.1 RSASP1) with no padding: the primitive behind OpenSSL's
    /// `RSA_private_decrypt` / `RSA_private_encrypt` with `RSA_NO_PADDING`.
    /// Inverse of [`BoxedRsaPublicKey::raw_public`].
    ///
    /// `input` is a big-endian integer of at most `k` octets (the modulus
    /// length; shorter input is read as left-padded with zeros); the result
    /// is always exactly `k` octets.
    ///
    /// This is the same private operation every padded scheme on this key
    /// runs: with the primes known, Coron base blinding (`c · r^e`, the
    /// blinder derived as described in the [type docs](Self), so no RNG is
    /// needed) over the CRT, with the result fault-checked by re-applying
    /// the public exponent (`m^e ≡ c mod n`) and recomputed on the
    /// full-width path if that fails. A key built with
    /// [`from_components`](Self::from_components) (no primes) runs the
    /// unblinded constant-time ladder and has no CRT result to check.
    ///
    /// Unpadded RSA is malleable and deterministic, and decrypting
    /// attacker-chosen inputs turns this key into a signing oracle — use it
    /// only to implement a padding scheme or interoperate with one.
    ///
    /// # Errors
    /// * [`Error::InvalidLength`] — `input` is longer than `k` octets.
    /// * [`Error::MessageTooLong`] — the value is `≥ n` (RFC 8017
    ///   "ciphertext / message representative out of range").
    /// * [`Error::InvalidKey`] — the result failed the fault check on both
    ///   the CRT and the full-width path (a persistent fault, or a key whose
    ///   `e`, `d` and primes are not consistent); nothing is released.
    pub fn raw_private(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = raw_input_be(self.k, &self.n, input)?;
        let c = BoxedUint::from_be_bytes(&buf);
        // `buf` held the input, which can be secret (a raw "private
        // encryption" of a message); `c` wipes itself on drop.
        super::wipe(&mut buf);
        let m = raw_private_checked_boxed(self, &c).ok_or(Error::InvalidKey)?;
        Ok(m.to_be_bytes(self.k))
    }

    /// Signs `msg` with PKCS#1 v1.5, hashing with `D`.
    pub fn sign_pkcs1v15<D: Pkcs1Digest>(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; self.k];
        emsa::sign_pkcs1v15::<D, _>(self, msg, &mut out)?;
        Ok(out)
    }

    /// PKCS#1 v1.5 signature over a pre-computed hash with **no `DigestInfo`**
    /// wrapping — the TLS 1.0/1.1 / SSLv3 handshake convention (RSA signs the
    /// bare `MD5(16) || SHA1(20)`). Legacy interop only.
    #[cfg(feature = "tls-legacy")]
    pub fn sign_pkcs1v15_prehashed(&self, t: &[u8]) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; self.k];
        emsa::sign_pkcs1v15_raw(self, t, &mut out)?;
        Ok(out)
    }

    /// Signs `msg` with RSA-PSS, hashing with `D` and a salt of `D`'s output
    /// length (the TLS 1.3 / X.509 profile).
    pub fn sign_pss<D: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        self.sign_pss_mgf::<D, D, R>(msg, rng)
    }

    /// [`sign_pss`](Self::sign_pss) with a distinct MGF1 hash: `D` hashes
    /// the message and sets the salt length, `M` is the digest MGF1 masks
    /// the data block with. RFC 8017 §8.1 allows `M` to differ from `D`; the
    /// common case is `M == D`, which is [`sign_pss`](Self::sign_pss).
    pub fn sign_pss_mgf<D: Digest, M: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; self.k];
        emsa::sign_pss::<D, M, _, R>(self, msg, rng, &mut out)?;
        Ok(out)
    }

    /// Signs `msg` with RSA-PSS using an explicit salt length (in octets).
    /// `salt_len == 0` is permitted; the maximum is bounded by the modulus
    /// size (`Error::MessageTooLong` otherwise).
    pub fn sign_pss_with_salt_len<D: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        salt_len: usize,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        self.sign_pss_with_salt_len_mgf::<D, D, R>(msg, salt_len, rng)
    }

    /// [`sign_pss_with_salt_len`](Self::sign_pss_with_salt_len) with a
    /// distinct MGF1 hash `M` (RFC 8017 §8.1 allows it to differ from the
    /// message hash `D`). The common case is `M == D`, which is
    /// [`sign_pss_with_salt_len`](Self::sign_pss_with_salt_len).
    pub fn sign_pss_with_salt_len_mgf<D: Digest, M: Digest, R: RngCore>(
        &self,
        msg: &[u8],
        salt_len: usize,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; self.k];
        emsa::sign_pss_with_salt_len::<D, M, _, R>(self, msg, salt_len, rng, &mut out)?;
        Ok(out)
    }

    /// Signs `msg` with RSASSA-PSS-SHAKE (RFC 8702): `X` (SHAKE128 or
    /// SHAKE256) is the hash and the mask generation function, the salt is
    /// `X::OUTPUT_LEN` octets (the RFC 8702 §3.1 profile).
    pub fn sign_pss_shake<X: PssShake, R: RngCore>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        self.sign_pss_shake_with_salt_len::<X, R>(msg, X::OUTPUT_LEN, rng)
    }

    /// [`sign_pss_shake`](Self::sign_pss_shake) with an explicit salt length
    /// (in octets; `0` is permitted, the maximum is bounded by the modulus
    /// size — `Error::MessageTooLong` otherwise).
    pub fn sign_pss_shake_with_salt_len<X: PssShake, R: RngCore>(
        &self,
        msg: &[u8],
        salt_len: usize,
        rng: &mut R,
    ) -> Result<Vec<u8>, Error> {
        let mut out = vec![0u8; self.k];
        emsa::sign_pss_shake::<X, _, R>(self, msg, salt_len, rng, &mut out)?;
        Ok(out)
    }

    /// Decrypts a PKCS#1 v1.5 ciphertext.
    ///
    /// # Security
    ///
    /// The padding check itself is constant-time, but the returned `Vec`'s
    /// **length** (and the success / [`Error::Decryption`] distinction)
    /// reveals the position of the PKCS#1 v1.5 separator byte. An adaptive
    /// chosen-ciphertext attacker who observes the protocol response can
    /// mount a Bleichenbacher / Marvin / ROBOT-class oracle.
    ///
    /// For TLS 1.0–1.2 RSA key transport, CMS / PKCS#7, JOSE RSA1_5, and
    /// other contexts where the plaintext length is known at the protocol
    /// layer, use [`decrypt_pkcs1v15_session`](Self::decrypt_pkcs1v15_session)
    /// instead. For new code, prefer OAEP via
    /// [`decrypt_oaep`](Self::decrypt_oaep).
    pub fn decrypt_pkcs1v15(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
        let mut scratch = vec![0u8; self.k];
        let mut out = vec![0u8; self.k];
        // `scratch` holds the decrypted EM (padding + plaintext); wipe it on
        // every exit path before the Vec is freed.
        let res = emsa::decrypt_pkcs1v15(self, ct, &mut scratch, &mut out);
        super::wipe(&mut scratch);
        let n = res?;
        out.truncate(n);
        Ok(out)
    }

    /// Decrypts a PKCS#1 v1.5 ciphertext with implicit rejection (RFC 8017
    /// §7.2.2 Note, the "Marvin" / TLS 1.2-style mitigation against
    /// Bleichenbacher's attack).
    ///
    /// On padding failure, returns a deterministic pseudorandom buffer of
    /// length `expected_len` derived from the ciphertext bytes and a
    /// per-key secret. The caller (and any external observer) cannot
    /// distinguish a real decryption from a synthetic one in timing, error
    /// path, or output length — the only way to defeat a Bleichenbacher
    /// oracle when the caller's downstream behavior would otherwise leak
    /// the padding outcome.
    ///
    /// The returned `Vec` is always exactly `expected_len` bytes: PKCS#1
    /// v1.5 padding alone cannot recover the intended plaintext length, so
    /// the protocol must agree on it (e.g. TLS RSA key transport:
    /// `expected_len = 48` for the 48-byte pre-master secret). A ciphertext
    /// that decrypts to valid padding but a plaintext of a *different*
    /// length is treated exactly like malformed padding and yields the
    /// synthetic output (RFC 5246 §7.4.7.1).
    ///
    /// # Errors
    /// Only [`Error::InvalidLength`] when `ct.len()` does not equal the
    /// modulus octet length. All other failure modes are folded into the
    /// synthetic plaintext.
    pub fn decrypt_pkcs1v15_session(
        &self,
        ct: &[u8],
        expected_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let mut scratch = vec![0u8; self.k];
        let mut out = vec![0u8; expected_len];
        let res = emsa::decrypt_pkcs1v15_session(self, ct, &mut scratch, &mut out);
        super::wipe(&mut scratch);
        res?;
        Ok(out)
    }

    /// Decrypts a PKCS#1 v1.5 ciphertext with **implicit rejection** and a
    /// pseudo-random output length — the mitigation for callers that cannot
    /// pin an expected plaintext length the way
    /// [`decrypt_pkcs1v15_session`](Self::decrypt_pkcs1v15_session) requires.
    ///
    /// On malformed padding (or an out-of-range ciphertext) this returns a
    /// pseudo-random message of pseudo-random length, both derived from the
    /// ciphertext and a secret bound to this key, instead of an error. An
    /// adaptive chosen-ciphertext attacker therefore learns nothing from the
    /// success/failure distinction *or* from the returned length, closing the
    /// Bleichenbacher / Marvin / ROBOT oracle that
    /// [`decrypt_pkcs1v15`](Self::decrypt_pkcs1v15) leaves open. The
    /// application must authenticate the recovered plaintext by other means
    /// (as every sound PKCS#1 v1.5 protocol already does).
    ///
    /// # Errors
    /// Only [`Error::InvalidLength`] when `ct.len()` does not equal the
    /// modulus octet length.
    pub fn decrypt_pkcs1v15_implicit(&self, ct: &[u8]) -> Result<Vec<u8>, Error> {
        let mut scratch = vec![0u8; self.k];
        let mut out = vec![0u8; self.k];
        let res = emsa::decrypt_pkcs1v15_implicit(self, ct, &mut scratch, &mut out);
        super::wipe(&mut scratch);
        let n = match res {
            Ok(n) => n,
            Err(e) => {
                super::wipe(&mut out);
                return Err(e);
            }
        };
        out.truncate(n);
        Ok(out)
    }

    /// Decrypts an RSAES-OAEP ciphertext (RFC 8017 §7.1.2). Hash `D` and
    /// `label` must match those used at encryption.
    pub fn decrypt_oaep<D: Digest>(&self, ct: &[u8], label: &[u8]) -> Result<Vec<u8>, Error> {
        self.decrypt_oaep_mgf::<D, D>(ct, label)
    }

    /// [`decrypt_oaep`](Self::decrypt_oaep) with a distinct MGF1 hash: `D`
    /// is the label hash, `M` the digest MGF1 unmasks with. RFC 8017 §7.1
    /// allows `M` to differ from `D`; the common case is `M == D`, which is
    /// [`decrypt_oaep`](Self::decrypt_oaep). Both must match the encryptor's
    /// ([`encrypt_oaep_mgf`](BoxedRsaPublicKey::encrypt_oaep_mgf)) — a wrong
    /// `M` is reported as [`Error::Decryption`] exactly like a wrong label.
    pub fn decrypt_oaep_mgf<D: Digest, M: Digest>(
        &self,
        ct: &[u8],
        label: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let mut scratch = vec![0u8; self.k];
        let mut out = vec![0u8; self.k];
        let res = emsa::decrypt_oaep::<D, M, _>(self, ct, label, &mut scratch, &mut out);
        super::wipe(&mut scratch);
        let n = res?;
        out.truncate(n);
        Ok(out)
    }
}

impl RawPublic for BoxedRsaPublicKey {
    fn key_size(&self) -> usize {
        self.k
    }
    fn modulus_bits(&self) -> usize {
        self.n.bit_len()
    }
    fn raw_public_in_place(&self, buf: &mut [u8]) {
        // `e` and `m` are both public on every RSA public-key op (signature
        // verification, encryption), so the public-exponent modexp — sized to
        // `e`'s bit length instead of the modulus width — is the right tool. It
        // is still branchless and leaks nothing about a secret. (For e = 65537
        // this is ~17 squarings instead of ~2048.)
        let out = self
            .mont
            .pow_public(&BoxedUint::from_be_bytes(buf), &self.e)
            .to_be_bytes(self.k);
        buf.copy_from_slice(&out);
    }
}

impl emsa::PublicModulus for BoxedRsaPublicKey {
    fn modulus_be_into(&self, out: &mut [u8]) {
        // `k`-wide big-endian `n`, matching the width of a validated signature
        // so the RSAVP1 `s < n` comparison in `emsa::verify_*` is over equal
        // lengths.
        out.copy_from_slice(&self.n.to_be_bytes(self.k));
    }
}

impl RawPrivate for BoxedRsaPrivateKey {
    fn key_size(&self) -> usize {
        self.k
    }
    fn modulus_bits(&self) -> usize {
        self.n.bit_len()
    }
    fn raw_private_in_place(&self, buf: &mut [u8]) {
        let c_uint = BoxedUint::from_be_bytes(buf);
        let mut out = raw_private_blinded_boxed(self, &c_uint).to_be_bytes(self.k);
        buf.copy_from_slice(&out);
        // `out` is the raw private-op result (decrypted EM / signature
        // representative): wipe the temporary before its Vec is freed.
        super::wipe(&mut out);
    }
    fn secret_seed(&self) -> [u8; 32] {
        self.blinding_seed
    }
    fn modulus_be_into(&self, out: &mut [u8]) {
        out.copy_from_slice(&self.n.to_be_bytes(self.k));
    }
}

/// PKCS#1 DER for runtime-sized keys.
#[cfg(feature = "der")]
impl BoxedRsaPublicKey {
    /// Parses a PKCS#1 `RSAPublicKey` DER structure (`SEQUENCE { n, e }`).
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, crate::der::Error> {
        Self::from_pkcs1_der_with_floor(der, MIN_RSA_BITS)
    }

    /// **Insecure.** [`from_pkcs1_der`](Self::from_pkcs1_der) accepting
    /// moduli down to [`MIN_RSA_INSECURE_BITS`] (256) bits instead of 1024
    /// — see [`try_new_insecure`](Self::try_new_insecure).
    pub fn from_pkcs1_der_insecure(der: &[u8]) -> Result<Self, crate::der::Error> {
        Self::from_pkcs1_der_with_floor(der, MIN_RSA_INSECURE_BITS)
    }

    fn from_pkcs1_der_with_floor(der: &[u8], min_bits: usize) -> Result<Self, crate::der::Error> {
        let mut reader = crate::der::Reader::new(der);
        let mut seq = reader.read_sequence()?;
        let n = BoxedUint::from_be_bytes(seq.read_unsigned_integer_bytes()?);
        let e = BoxedUint::from_be_bytes(seq.read_unsigned_integer_bytes()?);
        seq.finish()?;
        reader.finish()?;
        let bits = n.bit_len();
        if !(min_bits..=MAX_RSA_BITS).contains(&bits) {
            return Err(crate::der::Error::Malformed);
        }
        validate_public_exponent(&n, &e).map_err(|_| crate::der::Error::Malformed)?;
        Ok(BoxedRsaPublicKey::new(n, e))
    }

    /// Encodes the key as a PKCS#1 `RSAPublicKey` DER structure.
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        use crate::der::{encode_integer, encode_sequence};
        let n = self.n.to_be_bytes(self.k);
        let e = self.e.to_be_bytes(self.e.bit_len().div_ceil(8).max(1));
        encode_sequence(&[encode_integer(&n), encode_integer(&e)].concat())
    }

    /// Encodes the key as an X.509 `SubjectPublicKeyInfo` (SPKI) DER structure
    /// (RFC 5280 §4.1.2.7). The envelope is
    /// `SEQUENCE { AlgorithmIdentifier, BIT STRING }` where the
    /// AlgorithmIdentifier is `rsaEncryption` (OID `1.2.840.113549.1.1.1`)
    /// with an explicit `NULL` parameter (RFC 3279 §2.3.1), and the
    /// BIT STRING wraps the PKCS#1 `RSAPublicKey` DER produced by
    /// [`to_pkcs1_der`](Self::to_pkcs1_der).
    ///
    /// SPKI is the form X.509 certificates, JWKs, and most modern key-
    /// management tooling expect; the PKCS#1 form is only used by legacy
    /// OpenSSL-style PEM files.
    pub fn to_spki_der(&self) -> Vec<u8> {
        use crate::der::{encode_bit_string, encode_null, encode_sequence, oid_tlv};
        let algid = encode_sequence(&[oid_tlv(&RSA_ENCRYPTION_OID), encode_null()].concat());
        encode_sequence(&[algid, encode_bit_string(&self.to_pkcs1_der())].concat())
    }

    /// Encodes the key as a PEM `-----BEGIN PUBLIC KEY-----` document
    /// (RFC 7468). The body is [`to_spki_der`](Self::to_spki_der). Note the
    /// label has no `RSA ` prefix — the OID inside the SPKI disambiguates
    /// the algorithm.
    pub fn to_spki_pem(&self) -> alloc::string::String {
        crate::der::pem_encode("PUBLIC KEY", &self.to_spki_der())
    }

    /// Parses an X.509 `SubjectPublicKeyInfo` (SPKI) DER structure for an RSA
    /// public key. Validates that the algorithm OID is `rsaEncryption`, the
    /// parameters field is an explicit `NULL` (per RFC 3279 §2.3.1 strict —
    /// absent or non-NULL is rejected, mirroring the hardening from fix H-7
    /// applied to the X.509 SPKI parser), and the inner BIT STRING decodes
    /// as a valid PKCS#1 `RSAPublicKey`.
    pub fn from_spki_der(der: &[u8]) -> Result<Self, crate::der::Error> {
        Self::from_spki_der_with_floor(der, MIN_RSA_BITS)
    }

    /// **Insecure.** [`from_spki_der`](Self::from_spki_der) accepting
    /// moduli down to [`MIN_RSA_INSECURE_BITS`] (256) bits instead of 1024
    /// — see [`try_new_insecure`](Self::try_new_insecure).
    pub fn from_spki_der_insecure(der: &[u8]) -> Result<Self, crate::der::Error> {
        Self::from_spki_der_with_floor(der, MIN_RSA_INSECURE_BITS)
    }

    fn from_spki_der_with_floor(der: &[u8], min_bits: usize) -> Result<Self, crate::der::Error> {
        let mut reader = crate::der::Reader::new(der);
        let mut outer = reader.read_sequence()?;
        let mut algid = outer.read_sequence()?;
        let alg = crate::der::parse_oid(algid.read_oid()?)?;
        if alg.as_slice() != RSA_ENCRYPTION_OID {
            return Err(crate::der::Error::Malformed);
        }
        algid.read_null()?;
        algid.finish()?;
        let key_bits = outer.read_bit_string()?;
        outer.finish()?;
        reader.finish()?;
        Self::from_pkcs1_der_with_floor(key_bits, min_bits)
    }

    /// Parses an SPKI PEM document (`-----BEGIN PUBLIC KEY-----`, RFC 7468).
    /// The legacy `RSA PUBLIC KEY` label (PKCS#1) is **not** accepted here —
    /// use [`from_pkcs1_der`](Self::from_pkcs1_der) after a PEM strip for
    /// that form.
    pub fn from_spki_pem(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_spki_der(&crate::der::pem_decode(pem, "PUBLIC KEY")?)
    }

    /// **Insecure.** [`from_spki_pem`](Self::from_spki_pem) accepting
    /// moduli down to [`MIN_RSA_INSECURE_BITS`] (256) bits instead of 1024.
    pub fn from_spki_pem_insecure(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_spki_der_insecure(&crate::der::pem_decode(pem, "PUBLIC KEY")?)
    }
}

/// DER OID arcs for `rsaEncryption` (RFC 3279 §2.3.1) — shared with the
/// const-generic encoder in [`super::encoding`].
#[cfg(feature = "der")]
use super::encoding::RSA_ENCRYPTION_OID;

/// PKCS#1 DER/PEM for runtime-sized private keys.
#[cfg(feature = "der")]
impl BoxedRsaPrivateKey {
    /// Parses a PKCS#1 `RSAPrivateKey` DER structure, retaining the modulus,
    /// public exponent, private exponent, and the prime factors (the CRT
    /// parameters `dP`/`dQ`/`qInv` — and a multi-prime key's `dᵢ`/`tᵢ` —
    /// are recomputed on the constant-time ladder, so the blob's copies are
    /// not used and need not round-trip). The primes enable base-blinding
    /// on the secret-side path.
    ///
    /// Both RFC 8017 A.1.2 forms are accepted: `version = 0` (two-prime, no
    /// `otherPrimeInfos`) and `version = 1` (multi-prime, with a non-empty
    /// `otherPrimeInfos SEQUENCE OF { prime, exponent, coefficient }`, at
    /// most eight primes in total). A version that does not
    /// match the presence of `otherPrimeInfos`, or any other version, is
    /// rejected.
    ///
    /// Rejects moduli outside `[MIN_RSA_BITS, MAX_RSA_BITS]`, degenerate
    /// public exponents (`e < 3`, even, `≥ n`, or `≥ 2^256`), a private
    /// exponent outside `[1, n)`, primes `≤ 1` or even, repeated primes,
    /// a product of primes `≠ n`, and a `d` that does not invert `e` in
    /// every prime field (`e·dP ≢ 1 mod p−1`, `e·dQ ≢ 1 mod q−1`, and
    /// likewise `dᵢ`) — the relation the CRT path depends on. Any private
    /// INTEGER whose encoding is longer than `n`'s, a prime wider than `n`,
    /// or primes whose bit lengths cannot multiply out to `n`'s are rejected
    /// up front, before any bignum arithmetic runs on them.
    pub fn from_pkcs1_der(der: &[u8]) -> Result<Self, crate::der::Error> {
        Self::from_pkcs1_der_with_floor(der, MIN_RSA_BITS)
    }

    /// **Insecure.** [`from_pkcs1_der`](Self::from_pkcs1_der) accepting
    /// moduli down to [`MIN_RSA_INSECURE_BITS`] (256) bits instead of 1024,
    /// for legacy / test keys (e.g. 512-bit). Every consistency check still
    /// runs. A key this small offers no security.
    pub fn from_pkcs1_der_insecure(der: &[u8]) -> Result<Self, crate::der::Error> {
        Self::from_pkcs1_der_with_floor(der, MIN_RSA_INSECURE_BITS)
    }

    fn from_pkcs1_der_with_floor(der: &[u8], min_bits: usize) -> Result<Self, crate::der::Error> {
        let mut reader = crate::der::Reader::new(der);
        let mut seq = reader.read_sequence()?;
        // RFC 8017 A.1.2: `version` is 0 for the two-prime structure, 1 for
        // the multi-prime form with `otherPrimeInfos`. Anything but a
        // canonical 0 or 1 is rejected.
        let multi = match seq.read_integer_bytes()? {
            [0] => false,
            [1] => true,
            _ => return Err(crate::der::Error::Malformed),
        };
        let n_der = seq.read_unsigned_integer_bytes()?;
        // Every private component is at most `n` (RFC 8017 §3.2), so its
        // minimal DER body is never longer than `n`'s. Bounding the raw
        // lengths up front keeps an oversized blob from reaching any
        // bignum arithmetic (see `validate_private_components`).
        let n_len = n_der.len();
        fn bounded<'a>(
            s: &mut crate::der::Reader<'a>,
            max_len: usize,
        ) -> Result<&'a [u8], crate::der::Error> {
            let v = s.read_unsigned_integer_bytes()?;
            if v.len() > max_len {
                return Err(crate::der::Error::Malformed);
            }
            Ok(v)
        }
        let n = BoxedUint::from_be_bytes(n_der);
        let e = BoxedUint::from_be_bytes(seq.read_unsigned_integer_bytes()?);
        let d = BoxedUint::from_be_bytes(bounded(&mut seq, n_len)?);
        let p = BoxedUint::from_be_bytes(bounded(&mut seq, n_len)?);
        let q = BoxedUint::from_be_bytes(bounded(&mut seq, n_len)?);
        let _dp = bounded(&mut seq, n_len)?;
        let _dq = bounded(&mut seq, n_len)?;
        let _qinv = bounded(&mut seq, n_len)?;
        // otherPrimeInfos: "shall be omitted if version is 0 and shall
        // contain at least one instance of OtherPrimeInfo if version is 1".
        let mut other_primes = Vec::new();
        if multi {
            let mut infos = seq.read_sequence()?;
            while !infos.is_empty() {
                if other_primes.len() + 2 >= MAX_RSA_PRIMES {
                    return Err(crate::der::Error::Malformed);
                }
                let mut info = infos.read_sequence()?;
                let r = BoxedUint::from_be_bytes(bounded(&mut info, n_len)?);
                let _d_i = bounded(&mut info, n_len)?;
                let _t_i = bounded(&mut info, n_len)?;
                info.finish()?;
                other_primes.push(r);
            }
            if other_primes.is_empty() {
                return Err(crate::der::Error::Malformed);
            }
        }
        seq.finish()?;
        reader.finish()?;
        let bits = n.bit_len();
        if !(min_bits..=MAX_RSA_BITS).contains(&bits) {
            return Err(crate::der::Error::Malformed);
        }
        validate_public_exponent(&n, &e).map_err(|_| crate::der::Error::Malformed)?;
        validate_private_exponent(&n, &d).map_err(|_| crate::der::Error::Malformed)?;
        {
            let mut all: Vec<&BoxedUint> = alloc::vec![&p, &q];
            all.extend(other_primes.iter());
            validate_private_components(&n, &all).map_err(|_| crate::der::Error::Malformed)?;
            validate_crt_consistency(&e, &d, &all).map_err(|_| crate::der::Error::Malformed)?;
        }
        Ok(Self::from_components_with_other_primes(
            n,
            e,
            d,
            p,
            q,
            other_primes,
        ))
    }

    /// Decodes a PKCS#1 PEM private key (`-----BEGIN RSA PRIVATE KEY-----`).
    pub fn from_pkcs1_pem(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_pkcs1_der(&crate::zeroize::Zeroizing::new(crate::der::pem_decode(
            pem,
            "RSA PRIVATE KEY",
        )?))
    }

    /// **Insecure.** [`from_pkcs1_pem`](Self::from_pkcs1_pem) accepting
    /// moduli down to [`MIN_RSA_INSECURE_BITS`] (256) bits instead of 1024.
    pub fn from_pkcs1_pem_insecure(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_pkcs1_der_insecure(&crate::zeroize::Zeroizing::new(crate::der::pem_decode(
            pem,
            "RSA PRIVATE KEY",
        )?))
    }

    /// Encodes the key as a PKCS#1 `RSAPrivateKey` DER structure with the CRT
    /// parameters `dP`, `dQ`, `qInv`: `version = 0` for a two-prime key,
    /// `version = 1` with `otherPrimeInfos` (`prime`, `exponent`,
    /// `coefficient` per extra prime) for a multi-prime one.
    ///
    /// # Panics
    /// Panics if the prime factors are not retained (i.e. the key was built via
    /// [`from_components`](Self::from_components) or imported, not generated).
    /// Panics if `gcd(q, p) ≠ 1` — `q⁻¹ mod p` (`qInv`) cannot exist for a
    /// well-formed two-prime RSA key, so reaching this branch means the key
    /// is structurally broken and re-exporting would emit a CRT parameter
    /// silently set to zero. We refuse to round-trip a corrupted key.
    pub fn to_pkcs1_der(&self) -> Vec<u8> {
        use super::encoding::{into_plain, secret_concat, secret_integer, secret_tlv};
        use crate::der::{encode_integer, tag};
        use crate::zeroize::Zeroizing;
        assert!(
            !self.p.is_zero() && !self.q.is_zero(),
            "to_pkcs1_der requires the prime factors (generated keys only)"
        );
        let one = BoxedUint::from_u64(1);
        let dp = self.d.reduce(&self.p.sub(&one));
        let dq = self.d.reduce(&self.q.sub(&one));
        // Reuse the CRT precomputation's `qInv` (and the multi-prime `tᵢ`),
        // which are `q^(p−2) mod p` etc. through the constant-time
        // Montgomery ladder. A key whose primes are degenerate enough that
        // `derive_crt_boxed` refused them (even, tiny or equal) has no
        // meaningful coefficients; emit zero rather than run a
        // variable-time Euclid on the secret primes.
        let qinv = match self.crt.as_deref() {
            Some(crt) => crt.qinv.clone(),
            None => BoxedUint::zero(1),
        };
        // Every intermediate holding secret bytes (the big-endian limbs, the
        // encoded INTEGERs, the concatenated body) is allocated at its final
        // size and wiped on drop; only the returned encoding outlives this
        // call. (`BoxedUint` temporaries wipe themselves.)
        let int = |v: &BoxedUint| {
            secret_integer(&Zeroizing::new(
                v.to_be_bytes(v.bit_len().div_ceil(8).max(1)),
            ))
        };
        let multi = !self.other_primes.is_empty();
        let mut parts: Vec<Zeroizing<Vec<u8>>> = alloc::vec![
            encode_integer(&[u8::from(multi)]).into(),
            int(&self.n),
            int(&self.e),
            int(&self.d),
            int(&self.p),
            int(&self.q),
            int(&dp),
            int(&dq),
            int(&qinv),
        ];
        if multi {
            let mut infos: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(self.other_primes.len());
            for (i, r) in self.other_primes.iter().enumerate() {
                let d_i = self.d.reduce(&r.sub(&one));
                let t_i = match self.crt.as_deref() {
                    Some(crt) => crt.others[i].t.clone(),
                    None => BoxedUint::zero(1),
                };
                let fields = [int(r), int(&d_i), int(&t_i)];
                let body = secret_concat(&[&fields[0], &fields[1], &fields[2]]);
                infos.push(secret_tlv(tag::SEQUENCE, &body));
            }
            let refs: Vec<&[u8]> = infos.iter().map(|v| v.as_slice()).collect();
            parts.push(secret_tlv(tag::SEQUENCE, &secret_concat(&refs)));
        }
        let refs: Vec<&[u8]> = parts.iter().map(|v| v.as_slice()).collect();
        into_plain(secret_tlv(tag::SEQUENCE, &secret_concat(&refs)))
    }

    /// Encodes the key as a PKCS#1 PEM document.
    pub fn to_pkcs1_pem(&self) -> alloc::string::String {
        crate::der::pem_encode(
            "RSA PRIVATE KEY",
            &crate::zeroize::Zeroizing::new(self.to_pkcs1_der()),
        )
    }

    /// Encodes the key as an unencrypted PKCS#8 `PrivateKeyInfo` DER
    /// structure (RFC 5958 §2):
    ///
    /// ```text
    /// PrivateKeyInfo ::= SEQUENCE {
    ///     version INTEGER (0),
    ///     privateKeyAlgorithm AlgorithmIdentifier,  -- rsaEncryption + NULL
    ///     privateKey OCTET STRING                   -- the PKCS#1 DER
    /// }
    /// ```
    ///
    /// Encrypted PKCS#8 (`EncryptedPrivateKeyInfo`, RFC 5958 §3, PBES2 /
    /// PBKDF2) is intentionally not implemented — pick a stream-cipher AEAD
    /// envelope of your own choosing instead.
    ///
    /// # Panics
    /// Panics if the prime factors are not retained (i.e. the key was built
    /// via [`from_components`](Self::from_components) or imported, not
    /// generated). Matches [`to_pkcs1_der`](Self::to_pkcs1_der).
    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        use super::encoding::{into_plain, secret_concat, secret_tlv};
        use crate::der::{encode_integer, encode_null, encode_sequence, oid_tlv, tag};
        let algid = encode_sequence(&[oid_tlv(&RSA_ENCRYPTION_OID), encode_null()].concat());
        let pkcs1 = crate::zeroize::Zeroizing::new(self.to_pkcs1_der());
        let key = secret_tlv(tag::OCTET_STRING, &pkcs1);
        let body = secret_concat(&[&encode_integer(&[0]), &algid, &key]);
        into_plain(secret_tlv(tag::SEQUENCE, &body))
    }

    /// Encodes the key as a PKCS#8 PEM document
    /// (`-----BEGIN PRIVATE KEY-----`, RFC 7468). Distinct from the legacy
    /// `RSA PRIVATE KEY` label which carries a bare PKCS#1 body.
    pub fn to_pkcs8_pem(&self) -> alloc::string::String {
        crate::der::pem_encode(
            "PRIVATE KEY",
            &crate::zeroize::Zeroizing::new(self.to_pkcs8_der()),
        )
    }

    /// Parses an unencrypted PKCS#8 `PrivateKeyInfo` DER structure for an
    /// RSA private key. Validates `version = 0`, `privateKeyAlgorithm` is
    /// `rsaEncryption` with explicit `NULL` parameters, and the inner OCTET
    /// STRING decodes as a valid PKCS#1 `RSAPrivateKey` (two-prime or
    /// multi-prime, see [`from_pkcs1_der`](Self::from_pkcs1_der)).
    ///
    /// Encrypted PKCS#8 (`EncryptedPrivateKeyInfo`, RFC 5958 §3) is rejected
    /// at the outer SEQUENCE — its first field is an `AlgorithmIdentifier`,
    /// not the version INTEGER.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, crate::der::Error> {
        Self::from_pkcs8_der_with_floor(der, MIN_RSA_BITS)
    }

    /// **Insecure.** [`from_pkcs8_der`](Self::from_pkcs8_der) accepting
    /// moduli down to [`MIN_RSA_INSECURE_BITS`] (256) bits instead of 1024
    /// — see [`from_pkcs1_der_insecure`](Self::from_pkcs1_der_insecure).
    pub fn from_pkcs8_der_insecure(der: &[u8]) -> Result<Self, crate::der::Error> {
        Self::from_pkcs8_der_with_floor(der, MIN_RSA_INSECURE_BITS)
    }

    fn from_pkcs8_der_with_floor(der: &[u8], min_bits: usize) -> Result<Self, crate::der::Error> {
        let mut reader = crate::der::Reader::new(der);
        let mut outer = reader.read_sequence()?;
        let version = outer.read_integer_bytes()?;
        // RFC 5958 §2: version MUST be 0 for the v1 (unencrypted) form.
        // The v2 form (which permits an attribute set) uses version = 1.
        if version != [0] {
            return Err(crate::der::Error::Malformed);
        }
        let mut algid = outer.read_sequence()?;
        let alg = crate::der::parse_oid(algid.read_oid()?)?;
        if alg.as_slice() != RSA_ENCRYPTION_OID {
            return Err(crate::der::Error::Malformed);
        }
        algid.read_null()?;
        algid.finish()?;
        let inner = outer.read_octet_string()?;
        // PKCS#8 v1 has no further fields after the privateKey OCTET STRING
        // for our purposes (the optional `attributes [0]` set isn't carried
        // by anything mainstream for RSA). Reject trailing junk strictly.
        outer.finish()?;
        reader.finish()?;
        Self::from_pkcs1_der_with_floor(inner, min_bits)
    }

    /// Parses a PKCS#8 PEM document (`-----BEGIN PRIVATE KEY-----`,
    /// RFC 7468). The legacy `RSA PRIVATE KEY` PKCS#1 label is **not**
    /// accepted here — use [`from_pkcs1_pem`](Self::from_pkcs1_pem) for
    /// that form.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_pkcs8_der(&crate::zeroize::Zeroizing::new(crate::der::pem_decode(
            pem,
            "PRIVATE KEY",
        )?))
    }

    /// **Insecure.** [`from_pkcs8_pem`](Self::from_pkcs8_pem) accepting
    /// moduli down to [`MIN_RSA_INSECURE_BITS`] (256) bits instead of 1024.
    pub fn from_pkcs8_pem_insecure(pem: &str) -> Result<Self, crate::der::Error> {
        Self::from_pkcs8_der_insecure(&crate::zeroize::Zeroizing::new(crate::der::pem_decode(
            pem,
            "PRIVATE KEY",
        )?))
    }

    /// Encrypts the PKCS#8 encoding under PBES2 (RFC 5958 §3 + RFC 8018
    /// §6.2) with caller-supplied parameters, returning the DER-encoded
    /// `EncryptedPrivateKeyInfo`.
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn to_pkcs8_der_encrypted(
        &self,
        password: &[u8],
        params: &crate::kdf::pbes2::Pbes2Params,
        rng: &mut impl crate::rng::RngCore,
    ) -> Vec<u8> {
        crate::kdf::pbes2::encrypt(
            &crate::zeroize::Zeroizing::new(self.to_pkcs8_der()),
            password,
            params,
            rng,
        )
    }

    /// PEM-wrapped variant of [`Self::to_pkcs8_der_encrypted`]
    /// (`-----BEGIN ENCRYPTED PRIVATE KEY-----`, RFC 7468 §11).
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn to_pkcs8_pem_encrypted(
        &self,
        password: &[u8],
        params: &crate::kdf::pbes2::Pbes2Params,
        rng: &mut impl crate::rng::RngCore,
    ) -> alloc::string::String {
        crate::kdf::pbes2::encrypt_pem(
            &crate::zeroize::Zeroizing::new(self.to_pkcs8_der()),
            password,
            params,
            rng,
        )
    }

    /// Parses an `EncryptedPrivateKeyInfo` DER and decrypts it back to a
    /// PKCS#8 RSA private key.
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn from_pkcs8_der_encrypted(
        der: &[u8],
        password: &[u8],
    ) -> Result<Self, crate::der::Error> {
        let inner = crate::zeroize::Zeroizing::new(
            crate::kdf::pbes2::decrypt(der, password).map_err(|_| crate::der::Error::Malformed)?,
        );
        Self::from_pkcs8_der(&inner)
    }

    /// PEM-wrapped variant of [`Self::from_pkcs8_der_encrypted`].
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn from_pkcs8_pem_encrypted(pem: &str, password: &[u8]) -> Result<Self, crate::der::Error> {
        let inner = crate::zeroize::Zeroizing::new(
            crate::kdf::pbes2::decrypt_pem(pem, password)
                .map_err(|_| crate::der::Error::Malformed)?,
        );
        Self::from_pkcs8_der(&inner)
    }

    /// **Insecure.** [`from_pkcs8_der_encrypted`](Self::from_pkcs8_der_encrypted)
    /// accepting moduli down to [`MIN_RSA_INSECURE_BITS`] (256) bits.
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn from_pkcs8_der_encrypted_insecure(
        der: &[u8],
        password: &[u8],
    ) -> Result<Self, crate::der::Error> {
        let inner = crate::zeroize::Zeroizing::new(
            crate::kdf::pbes2::decrypt(der, password).map_err(|_| crate::der::Error::Malformed)?,
        );
        Self::from_pkcs8_der_insecure(&inner)
    }

    /// **Insecure.** [`from_pkcs8_pem_encrypted`](Self::from_pkcs8_pem_encrypted)
    /// accepting moduli down to [`MIN_RSA_INSECURE_BITS`] (256) bits.
    #[cfg(all(feature = "kdf", feature = "der"))]
    pub fn from_pkcs8_pem_encrypted_insecure(
        pem: &str,
        password: &[u8],
    ) -> Result<Self, crate::der::Error> {
        let inner = crate::zeroize::Zeroizing::new(
            crate::kdf::pbes2::decrypt_pem(pem, password)
                .map_err(|_| crate::der::Error::Malformed)?,
        );
        Self::from_pkcs8_der_insecure(&inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha1, Sha256};
    use crate::rng::HmacDrbg;
    use crate::test_util::rsa_test_key_a;

    /// Builds a boxed private key from the const-generic test key's parts.
    fn boxed_priv() -> BoxedRsaPrivateKey {
        let key = rsa_test_key_a();
        let mut nb = [0u8; 256];
        key.modulus().write_be_bytes(&mut nb);
        let mut eb = [0u8; 256];
        key.exponent().write_be_bytes(&mut eb);
        let mut db = [0u8; 256];
        key.private_exponent().write_be_bytes(&mut db);
        BoxedRsaPrivateKey::from_components(
            BoxedUint::from_be_bytes(&nb),
            BoxedUint::from_be_bytes(&eb),
            BoxedUint::from_be_bytes(&db),
        )
    }

    /// The boxed `_mgf` twins: `<D, D>` is byte-identical to the
    /// single-digest form (PSS and OAEP, identically seeded DRBGs), a
    /// `<SHA-256, MGF1-SHA-1>` PSS signature verifies only under that pair,
    /// and a `<SHA-256, MGF1-SHA-1>` OAEP ciphertext decrypts only under it.
    #[test]
    fn boxed_mgf_twins() {
        let (_, pk) = boxed_pub();
        let sk = boxed_priv();
        let drbg = || HmacDrbg::<Sha256>::new(b"boxed-mgf", b"nonce", &[]);

        let a = sk.sign_pss::<Sha256, _>(b"m", &mut drbg()).unwrap();
        let b = sk
            .sign_pss_mgf::<Sha256, Sha256, _>(b"m", &mut drbg())
            .unwrap();
        assert_eq!(a, b);
        let a = sk
            .sign_pss_with_salt_len::<Sha256, _>(b"m", 20, &mut drbg())
            .unwrap();
        let b = sk
            .sign_pss_with_salt_len_mgf::<Sha256, Sha256, _>(b"m", 20, &mut drbg())
            .unwrap();
        assert_eq!(a, b);
        pk.verify_pss_with_salt_len_mgf::<Sha256, Sha256>(b"m", &a, 20)
            .unwrap();
        pk.verify_pss_any_salt_mgf::<Sha256, Sha256>(b"m", &a)
            .unwrap();

        let sig = sk
            .sign_pss_mgf::<Sha256, Sha1, _>(b"m", &mut drbg())
            .unwrap();
        pk.verify_pss_mgf::<Sha256, Sha1>(b"m", &sig).unwrap();
        pk.verify_pss_with_salt_len_mgf::<Sha256, Sha1>(b"m", &sig, 32)
            .unwrap();
        pk.verify_pss_any_salt_mgf::<Sha256, Sha1>(b"m", &sig)
            .unwrap();
        assert_eq!(
            pk.verify_pss::<Sha256>(b"m", &sig),
            Err(Error::Verification)
        );
        assert_eq!(pk.verify_pss::<Sha1>(b"m", &sig), Err(Error::Verification));
        assert_eq!(
            pk.verify_pss_mgf::<Sha1, Sha256>(b"m", &sig),
            Err(Error::Verification)
        );
        assert_eq!(
            pk.verify_pss_mgf::<Sha256, Sha1>(b"other", &sig),
            Err(Error::Verification)
        );

        let a = pk
            .encrypt_oaep::<Sha256, _>(b"secret", b"label", &mut drbg())
            .unwrap();
        let b = pk
            .encrypt_oaep_mgf::<Sha256, Sha256, _>(b"secret", b"label", &mut drbg())
            .unwrap();
        assert_eq!(a, b);
        assert_eq!(
            sk.decrypt_oaep_mgf::<Sha256, Sha256>(&a, b"label").unwrap(),
            b"secret"
        );

        let ct = pk
            .encrypt_oaep_mgf::<Sha256, Sha1, _>(b"secret", b"label", &mut drbg())
            .unwrap();
        assert_eq!(
            sk.decrypt_oaep_mgf::<Sha256, Sha1>(&ct, b"label").unwrap(),
            b"secret"
        );
        assert_eq!(
            sk.decrypt_oaep::<Sha256>(&ct, b"label"),
            Err(Error::Decryption)
        );
        assert_eq!(
            sk.decrypt_oaep_mgf::<Sha1, Sha256>(&ct, b"label"),
            Err(Error::Decryption)
        );
        assert_eq!(
            sk.decrypt_oaep_mgf::<Sha256, Sha1>(&ct, b"other"),
            Err(Error::Decryption)
        );
    }

    /// Builds a boxed public key from the const-generic test key.
    fn boxed_pub() -> (crate::rsa::RsaPrivateKey<32>, BoxedRsaPublicKey) {
        let key = rsa_test_key_a();
        let pk = key.public_key();
        let mut n = [0u8; 256];
        pk.modulus().write_be_bytes(&mut n);
        let mut e = [0u8; 256];
        pk.exponent().write_be_bytes(&mut e);
        let boxed =
            BoxedRsaPublicKey::new(BoxedUint::from_be_bytes(&n), BoxedUint::from_be_bytes(&e));
        (key, boxed)
    }

    #[test]
    fn boxed_oaep_encrypts_const_generic_decrypts() {
        let (key, boxed) = boxed_pub();
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-oaep", b"nonce", &[]);
        let msg = b"OAEP from a runtime-sized public key";
        let ct = boxed
            .encrypt_oaep::<Sha256, _>(msg, b"label", &mut r)
            .unwrap();
        // The const-generic private key decrypts.
        assert_eq!(&key.decrypt_oaep::<Sha256>(&ct, b"label").unwrap()[..], msg);
    }

    #[test]
    fn boxed_verifies_const_generic_signatures() {
        let (key, boxed) = boxed_pub();
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-rsa", b"nonce", &[]);

        let s1 = key.sign_pkcs1v15::<Sha256>(b"hello").unwrap();
        boxed.verify_pkcs1v15::<Sha256>(b"hello", &s1).unwrap();
        assert!(boxed.verify_pkcs1v15::<Sha256>(b"other", &s1).is_err());

        let s2 = key.sign_pss::<Sha256, _>(b"hello", &mut r).unwrap();
        boxed.verify_pss::<Sha256>(b"hello", &s2).unwrap();
    }

    #[test]
    fn boxed_from_pkcs1_der() {
        let key = rsa_test_key_a();
        let der = key.public_key().to_pkcs1_der();
        let boxed = BoxedRsaPublicKey::from_pkcs1_der(&der).unwrap();
        assert_eq!(boxed.modulus().bit_len(), 2048);

        let sig = key.sign_pkcs1v15::<Sha256>(b"via der").unwrap();
        boxed.verify_pkcs1v15::<Sha256>(b"via der", &sig).unwrap();
    }

    #[test]
    fn generate_runtime_key_signs_and_exports() {
        // A small modulus keeps the test fast; the path is identical for larger
        // sizes (the CLI uses this for any non-standard size up to 65536).
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-keygen", b"nonce", &[]);
        let key = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut r, 12);
        assert_eq!(key.modulus().bit_len(), 1024);

        let sig = key.sign_pkcs1v15::<Sha256>(b"runtime keygen").unwrap();
        let pk = key.public_key();
        pk.verify_pkcs1v15::<Sha256>(b"runtime keygen", &sig)
            .unwrap();
        assert!(pk.verify_pkcs1v15::<Sha256>(b"other", &sig).is_err());

        // PKCS#1 export (with CRT params) round-trips through the parser.
        let parsed = BoxedRsaPrivateKey::from_pkcs1_der(&key.to_pkcs1_der()).unwrap();
        let sig2 = parsed.sign_pkcs1v15::<Sha256>(b"via der").unwrap();
        pk.verify_pkcs1v15::<Sha256>(b"via der", &sig2).unwrap();
    }

    /// I-1: a tiny SPKI/PKCS#1 modulus must be rejected at parse time so the
    /// downstream `decrypt_pkcs1v15` indexing path (which assumes `k >= 11`)
    /// is never reached on attacker input.
    #[test]
    fn rsa_decrypt_pkcs1v15_rejects_tiny_modulus() {
        use crate::der::{encode_integer, encode_sequence};
        // Synthesize a PKCS#1 RSAPublicKey with an 8-bit modulus (n=255, e=3).
        let n = [0xff];
        let e = [0x03];
        let der = encode_sequence(&[encode_integer(&n), encode_integer(&e)].concat());
        assert!(BoxedRsaPublicKey::from_pkcs1_der(&der).is_err());
    }

    /// I-2: a 32768-bit SPKI/PKCS#1 modulus must be rejected at parse time so
    /// `BoxedMontModulus::new` doesn't run a quadratic R² precomputation on
    /// attacker-supplied huge keys.
    #[test]
    fn rsa_rejects_modulus_above_16384_bits() {
        use crate::der::{encode_integer, encode_sequence};
        // 32768-bit modulus = 4096 bytes. The leading byte must be < 0x80 so
        // the DER INTEGER is unambiguously positive without a leading zero.
        let mut n = alloc::vec![0xffu8; 4096];
        n[0] = 0x7f;
        let e = [0x01, 0x00, 0x01];
        let der = encode_sequence(&[encode_integer(&n), encode_integer(&e)].concat());
        assert!(BoxedRsaPublicKey::from_pkcs1_der(&der).is_err());
    }

    /// Big-endian bytes of a const-generic test-key component, for hand-built
    /// PKCS#1 blobs.
    fn be32(u: &crate::bignum::Uint<32>) -> Vec<u8> {
        let mut b = vec![0u8; 256];
        u.write_be_bytes(&mut b);
        b
    }

    /// BN-6: an SPKI whose public exponent is wider than 256 bits (here
    /// 2000 bits, still `< n`) must be rejected on every parse path — the
    /// public op would otherwise cost ~2000 squarings per verification.
    #[test]
    fn rejects_public_exponent_above_256_bits() {
        let (_, boxed) = boxed_pub();
        let n = boxed.modulus().clone();
        // 2000-bit odd e: 250 bytes, top bit set, low bit set.
        let mut e_bytes = vec![0u8; 250];
        e_bytes[0] = 0x80;
        e_bytes[249] = 0x01;
        let big_e = BoxedUint::from_be_bytes(&e_bytes);
        assert_eq!(big_e.bit_len(), 2000);
        assert!(big_e.lt(&n), "e must still be below n for this test");
        assert!(matches!(
            BoxedRsaPublicKey::try_new(n.clone(), big_e.clone()),
            Err(Error::InvalidKey)
        ));
        // Through the unchecked constructor + encoder, then back through
        // the SPKI and PKCS#1 parsers.
        let unchecked = BoxedRsaPublicKey::new(n.clone(), big_e);
        assert!(BoxedRsaPublicKey::from_spki_der(&unchecked.to_spki_der()).is_err());
        assert!(BoxedRsaPublicKey::from_pkcs1_der(&unchecked.to_pkcs1_der()).is_err());
        // A 256-bit odd e is the boundary and still accepted.
        let mut e_bytes = vec![0u8; 32];
        e_bytes[0] = 0x80;
        e_bytes[31] = 0x01;
        let e256 = BoxedUint::from_be_bytes(&e_bytes);
        assert_eq!(e256.bit_len(), 256);
        assert!(BoxedRsaPublicKey::try_new(n, e256).is_ok());
    }

    /// BN-9: the boxed PKCS#1 private-key parser must reject `d = 0` and
    /// `d ≥ n`; the same blob with the genuine `d` parses.
    #[test]
    fn from_pkcs1_der_rejects_private_exponent_out_of_range() {
        use crate::der::{encode_integer, encode_sequence};
        let key = rsa_test_key_a();
        let (p, q) = key.primes();
        let blob = |d: &[u8]| {
            encode_sequence(
                &[
                    encode_integer(&[0]),
                    encode_integer(&be32(key.modulus())),
                    encode_integer(&be32(key.exponent())),
                    encode_integer(d),
                    encode_integer(&be32(p)),
                    encode_integer(&be32(q)),
                    encode_integer(&[1]),
                    encode_integer(&[1]),
                    encode_integer(&[1]),
                ]
                .concat(),
            )
        };
        assert!(BoxedRsaPrivateKey::from_pkcs1_der(&blob(&be32(key.private_exponent()))).is_ok());
        assert!(
            BoxedRsaPrivateKey::from_pkcs1_der(&blob(&[0])).is_err(),
            "d = 0"
        );
        assert!(
            BoxedRsaPrivateKey::from_pkcs1_der(&blob(&be32(key.modulus()))).is_err(),
            "d = n"
        );
        // d = n + 1, encoded one byte wider.
        let np1 = BoxedUint::from_be_bytes(&be32(key.modulus()))
            .add(&BoxedUint::from_u64(1))
            .to_be_bytes(257);
        assert!(
            BoxedRsaPrivateKey::from_pkcs1_der(&blob(&np1)).is_err(),
            "d > n"
        );
    }

    /// BN-5: an even public exponent can never be coprime to φ(n), so
    /// `generate` must refuse it up front instead of looping forever.
    #[test]
    #[should_panic(expected = "e must be odd")]
    fn generate_panics_on_even_exponent() {
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-keygen-bad-e", b"nonce", &[]);
        let _ = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(2), &mut r, 4);
    }

    /// BN-5: `e = 1` gives `d = 1` (the identity map); refused.
    #[test]
    #[should_panic(expected = "e must be odd")]
    fn generate_panics_on_unit_exponent() {
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-keygen-bad-e", b"nonce", &[]);
        let _ = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(1), &mut r, 4);
    }

    /// BN-5: `bits = 2` used to underflow inside the prime generator.
    #[test]
    #[should_panic(expected = "bits must be >= 256")]
    fn generate_panics_on_tiny_modulus() {
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-keygen-bad-bits", b"nonce", &[]);
        let _ = BoxedRsaPrivateKey::generate(2, BoxedUint::from_u64(65537), &mut r, 4);
    }

    /// The CRT fast path must be bit-for-bit identical to the plain
    /// full-width `c^d mod n` path (PKCS#1 v1.5 signing is deterministic, so
    /// signature equality is exactly result equality).
    #[test]
    fn crt_path_matches_full_width_result() {
        let fixed = rsa_test_key_a();
        let with_primes = fixed.to_boxed();
        assert!(
            with_primes.crt.is_some(),
            "key with primes must enable the CRT path"
        );

        let mut nb = [0u8; 256];
        fixed.modulus().write_be_bytes(&mut nb);
        let mut eb = [0u8; 256];
        fixed.exponent().write_be_bytes(&mut eb);
        let mut db = [0u8; 256];
        fixed.private_exponent().write_be_bytes(&mut db);
        let no_primes = BoxedRsaPrivateKey::from_components(
            BoxedUint::from_be_bytes(&nb),
            BoxedUint::from_be_bytes(&eb),
            BoxedUint::from_be_bytes(&db),
        );
        assert!(no_primes.crt.is_none());

        for msg in [&b"crt-vs-full-1"[..], b"crt-vs-full-2", b""] {
            assert_eq!(
                with_primes.sign_pkcs1v15::<Sha256>(msg).unwrap(),
                no_primes.sign_pkcs1v15::<Sha256>(msg).unwrap(),
                "CRT and full-width paths diverged"
            );
        }
    }

    /// The `Debug` impl must never print secret key material: not the private
    /// exponent, not the primes, not the CRT parameters, not the blinding
    /// seed.
    #[test]
    fn private_key_debug_redacts_secrets() {
        let key = rsa_test_key_a().to_boxed();
        let s = alloc::format!("{key:?}");
        for (name, secret) in [
            ("d", alloc::format!("{:?}", key.d)),
            ("p", alloc::format!("{:?}", key.p)),
            ("q", alloc::format!("{:?}", key.q)),
        ] {
            assert!(!s.contains(&secret), "Debug output leaks `{name}`");
        }
        assert!(s.contains("BoxedRsaPrivateKey"));
        assert!(s.ends_with(".. }"), "expected finish_non_exhaustive: {s}");
    }

    /// Boneh–DeMillo–Lipton guard: corrupt one CRT half and the `m^e ≡ c`
    /// fault check must reject it and fall back to the full-width path — the
    /// emitted signature is still correct, and the factorable half-fault
    /// never escapes.
    #[test]
    fn corrupted_crt_half_falls_back_to_correct_signature() {
        let mut key = rsa_test_key_a().to_boxed();
        let crt = key.crt.as_deref_mut().expect("CRT params present");
        crt.dp = BoxedUint::from_u64(0x1337);

        let sig = key.sign_pkcs1v15::<Sha256>(b"fault me").unwrap();
        key.public_key()
            .verify_pkcs1v15::<Sha256>(b"fault me", &sig)
            .unwrap();
    }

    /// When *both* the CRT path and the full-width recomputation fail the
    /// `m^e ≡ c mod n` fault check — here because the key's `d` is not the
    /// inverse of `e`, which is what a fault on the exponent looks like — the
    /// private op must fail closed (return zero) rather than release an
    /// unchecked result. Before, the full-width fallback was emitted without
    /// any verification at all.
    #[test]
    fn unverifiable_private_op_fails_closed() {
        let good = rsa_test_key_a().to_boxed();
        // Same modulus and primes, but a `d` that inverts nothing.
        let mut key = BoxedRsaPrivateKey::from_components_with_primes(
            good.n.clone(),
            good.e.clone(),
            good.d.sub(&BoxedUint::from_u64(2)),
            good.p.clone(),
            good.q.clone(),
        );
        assert!(key.crt.is_some());
        let c = BoxedUint::from_u64(0x1234_5678);
        assert!(
            raw_private_blinded_boxed(&key, &c).is_zero(),
            "an unverifiable private-op result must not be released"
        );
        // A signature from such a key is the all-zero representative, which
        // no verifier accepts.
        let sig = key.sign_pkcs1v15::<Sha256>(b"broken key").unwrap();
        assert!(
            good.public_key()
                .verify_pkcs1v15::<Sha256>(b"broken key", &sig)
                .is_err()
        );
        // Sanity: with the correct `d` the same path still works.
        key = good;
        let sig = key.sign_pkcs1v15::<Sha256>(b"broken key").unwrap();
        key.public_key()
            .verify_pkcs1v15::<Sha256>(b"broken key", &sig)
            .unwrap();
    }

    /// A PKCS#1 blob whose `d` does not invert `e` in the prime fields is
    /// rejected at parse time (RFC 8017 §3.2) rather than producing a key
    /// whose CRT halves disagree at signing time.
    #[test]
    fn from_pkcs1_der_rejects_inconsistent_private_exponent() {
        use crate::der::{encode_integer, encode_sequence};
        let key = rsa_test_key_a().to_boxed();
        let be = |v: &BoxedUint| v.to_be_bytes(v.bit_len().div_ceil(8).max(1));
        let der = |d: &BoxedUint| {
            encode_sequence(
                &[
                    encode_integer(&[0]),
                    encode_integer(&be(&key.n)),
                    encode_integer(&be(&key.e)),
                    encode_integer(&be(d)),
                    encode_integer(&be(&key.p)),
                    encode_integer(&be(&key.q)),
                    encode_integer(&[0]),
                    encode_integer(&[0]),
                    encode_integer(&[0]),
                ]
                .concat(),
            )
        };
        // The honest key round-trips…
        BoxedRsaPrivateKey::from_pkcs1_der(&der(&key.d)).expect("valid key must parse");
        // …a corrupted private exponent does not.
        assert!(
            BoxedRsaPrivateKey::from_pkcs1_der(&der(&key.d.sub(&BoxedUint::from_u64(2)))).is_err()
        );
    }

    #[test]
    fn boxed_private_key_signs() {
        // Reconstruct a boxed private key from the const-generic key's parts.
        let key = rsa_test_key_a();
        let mut nb = [0u8; 256];
        key.modulus().write_be_bytes(&mut nb);
        let mut eb = [0u8; 256];
        key.exponent().write_be_bytes(&mut eb);
        let mut db = [0u8; 256];
        key.private_exponent().write_be_bytes(&mut db);
        let boxed = BoxedRsaPrivateKey::from_components(
            BoxedUint::from_be_bytes(&nb),
            BoxedUint::from_be_bytes(&eb),
            BoxedUint::from_be_bytes(&db),
        );

        let sig = boxed.sign_pkcs1v15::<Sha256>(b"sign me").unwrap();
        // Verify with the const-generic public key.
        key.public_key()
            .verify_pkcs1v15::<Sha256>(b"sign me", &sig)
            .unwrap();
    }

    /// Raw (no-DigestInfo) PKCS#1 v1.5 round-trip over a 36-byte MD5||SHA1-shaped
    /// pre-hash — the TLS 1.0/1.1 handshake-signature convention.
    #[cfg(feature = "tls-legacy")]
    #[test]
    fn boxed_prehashed_sign_verify_roundtrip() {
        let key = rsa_test_key_a();
        let mut nb = [0u8; 256];
        key.modulus().write_be_bytes(&mut nb);
        let mut eb = [0u8; 256];
        key.exponent().write_be_bytes(&mut eb);
        let mut db = [0u8; 256];
        key.private_exponent().write_be_bytes(&mut db);
        let sk = BoxedRsaPrivateKey::from_components(
            BoxedUint::from_be_bytes(&nb),
            BoxedUint::from_be_bytes(&eb),
            BoxedUint::from_be_bytes(&db),
        );
        let pk = sk.public_key();

        let mut t = [0u8; 36]; // MD5(16) || SHA1(20)
        for (i, b) in t.iter_mut().enumerate() {
            *b = i as u8;
        }
        let sig = sk.sign_pkcs1v15_prehashed(&t).unwrap();
        pk.verify_pkcs1v15_prehashed(&t, &sig).unwrap();

        // A flipped hash byte must fail.
        let mut bad = t;
        bad[0] ^= 1;
        assert!(pk.verify_pkcs1v15_prehashed(&bad, &sig).is_err());
    }

    // ---- SPKI / PKCS#8 round-trip and reject tests ----

    /// Helper: generates a small (1024-bit) RSA key. Faster than 2048 in
    /// debug and exercises the same encoding path.
    fn gen_small_key(seed: &[u8]) -> BoxedRsaPrivateKey {
        let mut rng = HmacDrbg::<Sha256>::new(seed, b"n", &[]);
        BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut rng, 12)
    }

    #[test]
    fn rsa_public_key_spki_der_roundtrip() {
        let sk = gen_small_key(b"rsa-spki-der");
        let pk = sk.public_key();
        let der = pk.to_spki_der();
        // Sanity: outer SEQUENCE.
        assert_eq!(der[0], 0x30);
        let parsed = BoxedRsaPublicKey::from_spki_der(&der).unwrap();
        assert_eq!(parsed.to_pkcs1_der(), pk.to_pkcs1_der());

        // Cross-check against the X.509 layer: an SPKI built by AnyPublicKey
        // for the same key bytes must be byte-identical, so SPKI bytes
        // produced by either route are interchangeable.
        #[cfg(feature = "x509")]
        {
            let any_spki =
                crate::x509::AnyPublicKey::Rsa(BoxedRsaPublicKey::new(pk.n.clone(), pk.e.clone()))
                    .to_spki_der();
            assert_eq!(der, any_spki);
        }
    }

    #[test]
    fn rsa_public_key_spki_pem_roundtrip() {
        let sk = gen_small_key(b"rsa-spki-pem");
        let pk = sk.public_key();
        let pem = pk.to_spki_pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
        let parsed = BoxedRsaPublicKey::from_spki_pem(&pem).unwrap();
        assert_eq!(parsed.to_pkcs1_der(), pk.to_pkcs1_der());
    }

    #[test]
    fn rsa_private_key_pkcs8_der_roundtrip() {
        let sk = gen_small_key(b"rsa-pkcs8-der");
        let der = sk.to_pkcs8_der();
        assert_eq!(der[0], 0x30);
        let parsed = BoxedRsaPrivateKey::from_pkcs8_der(&der).unwrap();
        // PKCS#1 export is byte-deterministic for a given key, so the
        // round-tripped key re-serializes to the same PKCS#1 bytes.
        assert_eq!(parsed.to_pkcs1_der(), sk.to_pkcs1_der());

        // Functional: the round-tripped key still signs.
        let sig = parsed.sign_pkcs1v15::<Sha256>(b"via pkcs8").unwrap();
        sk.public_key()
            .verify_pkcs1v15::<Sha256>(b"via pkcs8", &sig)
            .unwrap();
    }

    #[test]
    fn rsa_private_key_pkcs8_pem_roundtrip() {
        let sk = gen_small_key(b"rsa-pkcs8-pem");
        let pem = sk.to_pkcs8_pem();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PRIVATE KEY-----"));
        let parsed = BoxedRsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(parsed.to_pkcs1_der(), sk.to_pkcs1_der());
    }

    /// Full encrypted-PKCS#8 round trip on a real RSA key: encrypt to PEM
    /// with PBES2 (AES-256-GCM + PBKDF2-HMAC-SHA256), parse back, and
    /// verify the recovered key signs identically.
    // PBES2 (the shrouded-key wrapper) lives in `kdf`.
    #[cfg(feature = "kdf")]
    #[test]
    fn rsa_encrypted_pkcs8_pem_roundtrip() {
        let sk = gen_small_key(b"rsa-pkcs8-pem-enc");
        let mut rng = HmacDrbg::<Sha256>::new(b"pbes2-enc", b"nonce", &[]);
        let params = crate::kdf::pbes2::Pbes2Params {
            // Tests run with a tiny iteration count for speed.
            kdf: crate::kdf::pbes2::KdfChoice::Pbkdf2HmacSha256 { iterations: 10_000 },
            cipher: crate::kdf::pbes2::CipherChoice::Aes256Gcm,
            salt_len: 16,
        };
        let pem = sk.to_pkcs8_pem_encrypted(b"swordfish", &params, &mut rng);
        assert!(pem.starts_with("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"));
        assert!(
            pem.trim_end()
                .ends_with("-----END ENCRYPTED PRIVATE KEY-----")
        );

        let parsed = BoxedRsaPrivateKey::from_pkcs8_pem_encrypted(&pem, b"swordfish").unwrap();
        // PKCS#1 export is byte-deterministic, so the re-serialized keys
        // must match exactly.
        assert_eq!(parsed.to_pkcs1_der(), sk.to_pkcs1_der());

        // Wrong password is rejected.
        assert!(BoxedRsaPrivateKey::from_pkcs8_pem_encrypted(&pem, b"wrong").is_err());

        // Functional: the round-tripped key still signs and verifies.
        let sig = parsed
            .sign_pkcs1v15::<Sha256>(b"via encrypted pkcs8")
            .unwrap();
        sk.public_key()
            .verify_pkcs1v15::<Sha256>(b"via encrypted pkcs8", &sig)
            .unwrap();
    }

    /// Same round trip via AES-256-CBC (PKCS#7 padded), the other PBES2
    /// cipher we support.
    #[cfg(feature = "kdf")]
    #[test]
    fn rsa_encrypted_pkcs8_der_roundtrip_cbc() {
        let sk = gen_small_key(b"rsa-pkcs8-der-cbc");
        let mut rng = HmacDrbg::<Sha256>::new(b"pbes2-cbc", b"nonce", &[]);
        let params = crate::kdf::pbes2::Pbes2Params {
            kdf: crate::kdf::pbes2::KdfChoice::Pbkdf2HmacSha512 { iterations: 10_000 },
            cipher: crate::kdf::pbes2::CipherChoice::Aes256Cbc,
            salt_len: 16,
        };
        let der = sk.to_pkcs8_der_encrypted(b"pass", &params, &mut rng);
        let parsed = BoxedRsaPrivateKey::from_pkcs8_der_encrypted(&der, b"pass").unwrap();
        assert_eq!(parsed.to_pkcs1_der(), sk.to_pkcs1_der());
    }

    /// SPKI carrying a non-RSA algorithm OID (here: id-Ed25519) must be
    /// rejected, not silently treated as RSA.
    #[test]
    fn rsa_public_key_from_spki_rejects_non_rsa_oid() {
        use crate::der::{encode_bit_string, encode_sequence, oid_tlv};
        // Ed25519 OID `1.3.101.112`, no parameters; key body is irrelevant
        // because we should reject before reaching it.
        let algid = encode_sequence(&oid_tlv(&[1, 3, 101, 112]));
        let dummy_key = [0u8; 32];
        let spki = encode_sequence(&[algid, encode_bit_string(&dummy_key)].concat());
        assert!(BoxedRsaPublicKey::from_spki_der(&spki).is_err());
    }

    /// SPKI for `rsaEncryption` with the parameters field absent must be
    /// rejected (RFC 3279 §2.3.1; matches the strict-NULL fix H-7 applied
    /// to the X.509 SPKI parser).
    #[test]
    fn rsa_public_key_from_spki_rejects_missing_null_params() {
        use crate::der::{encode_bit_string, encode_sequence, oid_tlv};
        // AlgorithmIdentifier with the OID but no NULL after it.
        let algid = encode_sequence(&oid_tlv(&RSA_ENCRYPTION_OID));
        // The BIT STRING content must still be valid PKCS#1 to ensure we're
        // failing on the algid check, not on a later parse step — but the
        // algid check happens first, so even garbage here is fine.
        let dummy = [0u8; 16];
        let spki = encode_sequence(&[algid, encode_bit_string(&dummy)].concat());
        assert!(BoxedRsaPublicKey::from_spki_der(&spki).is_err());
    }

    /// A PEM with the legacy PKCS#1 label (`RSA PUBLIC KEY`) must not be
    /// accepted by the SPKI PEM importer — the label disambiguates the
    /// inner format.
    #[test]
    fn rsa_public_key_from_spki_pem_rejects_pkcs1_label() {
        let sk = gen_small_key(b"rsa-spki-wrong-label");
        // The boxed public key only owns to_pkcs1_der, no to_pkcs1_pem on
        // the public type — wrap manually with the legacy label.
        let pkcs1_pem = crate::der::pem_encode("RSA PUBLIC KEY", &sk.public_key().to_pkcs1_der());
        assert!(BoxedRsaPublicKey::from_spki_pem(&pkcs1_pem).is_err());
    }

    /// PKCS#8 with `version = 1` (v2 of the format, RFC 5958 §2) is not
    /// supported here — the v1 form is what every OpenSSL-style tool emits
    /// for unencrypted RSA.
    #[test]
    fn rsa_private_key_from_pkcs8_rejects_nonzero_version() {
        use crate::der::{
            encode_integer, encode_null, encode_octet_string, encode_sequence, oid_tlv,
        };
        let sk = gen_small_key(b"rsa-pkcs8-v1");
        let algid = encode_sequence(&[oid_tlv(&RSA_ENCRYPTION_OID), encode_null()].concat());
        let der = encode_sequence(
            &[
                encode_integer(&[1]), // version = 1, not 0
                algid,
                encode_octet_string(&sk.to_pkcs1_der()),
            ]
            .concat(),
        );
        assert!(BoxedRsaPrivateKey::from_pkcs8_der(&der).is_err());
    }

    /// RFC 8017 A.1.2: a PKCS#1 `RSAPrivateKey` whose `version` is not 0 is
    /// not a two-prime key. The parser used to read and discard the field, so
    /// a blob tagged `version = 1` (multi-prime) — or any other value — was
    /// accepted as long as the remaining fields parsed. Both a wrong value
    /// and a non-canonical encoding of 0 must be rejected.
    #[test]
    fn from_pkcs1_der_rejects_nonzero_version() {
        use crate::der::{Reader, encode_sequence, tag};
        let sk = gen_small_key(b"rsa-pkcs1-version");
        let der = sk.to_pkcs1_der();
        // The outer SEQUENCE body starts with the canonical `INTEGER 0`.
        let body = Reader::new(&der).read_tlv(tag::SEQUENCE).unwrap();
        assert_eq!(&body[..3], &[0x02, 0x01, 0x00], "version = 0 leads");
        // Sanity: the untouched blob still parses.
        assert!(BoxedRsaPrivateKey::from_pkcs1_der(&der).is_ok());
        for bad_version in [
            &[0x02u8, 0x01, 0x01][..], // version = 1 (multi-prime marker)
            &[0x02, 0x01, 0x02],       // undefined
            &[0x02, 0x02, 0x00, 0x00], // non-canonical encoding of 0
        ] {
            let patched = encode_sequence(&[bad_version, &body[3..]].concat());
            assert!(
                BoxedRsaPrivateKey::from_pkcs1_der(&patched).is_err(),
                "version {bad_version:02x?} must be rejected"
            );
        }
    }

    /// PKCS#8 carrying a non-RSA private-key algorithm OID is rejected.
    #[test]
    fn rsa_private_key_from_pkcs8_rejects_non_rsa_oid() {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        // Ed25519 PrivateKey OID `1.3.101.112`, no NULL (RFC 8410).
        let algid = encode_sequence(&oid_tlv(&[1, 3, 101, 112]));
        let dummy = [0u8; 34];
        let der =
            encode_sequence(&[encode_integer(&[0]), algid, encode_octet_string(&dummy)].concat());
        assert!(BoxedRsaPrivateKey::from_pkcs8_der(&der).is_err());
    }

    /// PKCS#8 SPKI with absent NULL parameters is rejected (strict-NULL
    /// policy, fix H-7).
    #[test]
    fn rsa_private_key_from_pkcs8_rejects_missing_null_params() {
        use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
        let sk = gen_small_key(b"rsa-pkcs8-no-null");
        // AlgorithmIdentifier with no parameters at all.
        let algid = encode_sequence(&oid_tlv(&RSA_ENCRYPTION_OID));
        let der = encode_sequence(
            &[
                encode_integer(&[0]),
                algid,
                encode_octet_string(&sk.to_pkcs1_der()),
            ]
            .concat(),
        );
        assert!(BoxedRsaPrivateKey::from_pkcs8_der(&der).is_err());
    }

    /// Exhaustive `try_new` exponent shape rejection: 0, 1, 2 (even), `n`, `n+1`
    /// all fail, while a legitimate 65537 against a real modulus passes.
    #[test]
    fn try_new_rejects_degenerate_exponents() {
        let (_, boxed) = boxed_pub();
        let n = boxed.modulus().clone();
        let cases: [(BoxedUint, &'static str); 5] = [
            (BoxedUint::from_u64(0), "e=0"),
            (BoxedUint::from_u64(1), "e=1"),
            (BoxedUint::from_u64(2), "e=2 (even)"),
            (n.clone(), "e=n"),
            (n.add(&BoxedUint::from_u64(1)), "e=n+1"),
        ];
        for (e, why) in cases {
            assert!(
                matches!(
                    BoxedRsaPublicKey::try_new(n.clone(), e),
                    Err(Error::InvalidKey)
                ),
                "{why} should be rejected as InvalidKey"
            );
        }
        // Sanity: 65537 against a real 2048-bit modulus is accepted.
        assert!(BoxedRsaPublicKey::try_new(n, BoxedUint::from_u64(65537)).is_ok());
    }

    /// PKCS#1 DER carrying a degenerate `e` is rejected as Malformed (the
    /// validate_public_exponent failure surfaces through the DER layer).
    #[test]
    fn from_pkcs1_der_rejects_even_exponent() {
        use crate::der::{encode_integer, encode_sequence};
        let (_, boxed) = boxed_pub();
        let n_bytes = boxed.modulus().to_be_bytes(256);
        // e = 4 (even, < 3 false but evenness gate fires).
        let der = encode_sequence(&[encode_integer(&n_bytes), encode_integer(&[4])].concat());
        assert!(BoxedRsaPublicKey::from_pkcs1_der(&der).is_err());
    }

    /// An even (or zero) modulus must be rejected as an error, never reach
    /// `BoxedMontModulus::new` (whose `assert!(n is odd)` would panic). This is
    /// the HIGH-severity reachable-panic DoS: a crafted SPKI/cert with an even
    /// modulus is attacker-controlled input on the X.509 verification path.
    #[test]
    fn from_pkcs1_der_rejects_even_modulus() {
        use crate::der::{encode_integer, encode_sequence};
        let (_, boxed) = boxed_pub();
        // Take the real 2048-bit modulus and clear bit 0 to make it even while
        // keeping its bit length (so the size gate still passes and the
        // odd-modulus gate is what must fire).
        let one = BoxedUint::from_u64(1);
        let mut n = boxed.modulus().clone();
        if n.is_odd() {
            n = n.sub(&one);
        }
        assert!(!n.is_odd(), "test modulus must be even");
        let n_bytes = n.to_be_bytes(256);
        let e_bytes = BoxedUint::from_u64(65537).to_be_bytes(3);
        let der = encode_sequence(&[encode_integer(&n_bytes), encode_integer(&e_bytes)].concat());
        assert!(BoxedRsaPublicKey::from_pkcs1_der(&der).is_err());
    }

    /// PKCS#1 private-key DER whose modulus doesn't match `p · q` is rejected.
    /// Forge a key by taking a real key and swapping in a foreign `n` (the
    /// public key's modulus) while keeping the original primes — `p · q`
    /// no longer equals the surface `n`. This is the file-corruption /
    /// fault-injection signature that
    /// [`validate_private_components`] catches.
    #[test]
    fn from_pkcs1_der_rejects_mismatched_modulus() {
        use crate::der::{encode_integer, encode_sequence};
        let sk_a = gen_small_key(b"rsa-pkcs1-pq-a");
        let sk_b = gen_small_key(b"rsa-pkcs1-pq-b");
        let be = |v: &BoxedUint| v.to_be_bytes(v.bit_len().div_ceil(8).max(1));
        // Take sk_a's everything but graft sk_b's modulus on top.
        let one = BoxedUint::from_u64(1);
        let dp = sk_a.d.reduce(&sk_a.p.sub(&one));
        let dq = sk_a.d.reduce(&sk_a.q.sub(&one));
        let qinv = crate::bignum::inv_mod_boxed(&sk_a.q, &sk_a.p).unwrap();
        let der = encode_sequence(
            &[
                encode_integer(&[0]),
                encode_integer(&be(sk_b.modulus())), // mismatched n
                encode_integer(&be(&sk_a.e)),
                encode_integer(&be(&sk_a.d)),
                encode_integer(&be(&sk_a.p)),
                encode_integer(&be(&sk_a.q)),
                encode_integer(&be(&dp)),
                encode_integer(&be(&dq)),
                encode_integer(&be(&qinv)),
            ]
            .concat(),
        );
        assert!(matches!(
            BoxedRsaPrivateKey::from_pkcs1_der(&der),
            Err(crate::der::Error::Malformed)
        ));
    }

    /// Oversized "primes" are rejected before any multiplication: a crafted
    /// PKCS#1 blob carrying megabyte-wide `p`/`q` (or extra primes) used to
    /// run the schoolbook product quadratically (~12 s for 2 MB) before the
    /// `prod == n` comparison failed.
    #[test]
    fn from_pkcs1_der_rejects_oversized_primes_quickly() {
        use crate::der::{encode_integer, encode_sequence};
        let sk = gen_small_key(b"rsa-pkcs1-oversized");
        let be = |v: &BoxedUint| v.to_be_bytes(v.bit_len().div_ceil(8).max(1));
        // A 1 MiB odd integer: harmless to build, several seconds to square
        // with the schoolbook product.
        let mut huge = alloc::vec![0x5au8; 1024 * 1024];
        *huge.last_mut().unwrap() |= 1;
        let small = be(&BoxedUint::from_u64(3));
        let build = |p: &[u8], q: &[u8], d: &[u8]| {
            encode_sequence(
                &[
                    encode_integer(&[0]),
                    encode_integer(&be(sk.modulus())),
                    encode_integer(&be(&sk.e)),
                    encode_integer(d),
                    encode_integer(p),
                    encode_integer(q),
                    encode_integer(&small),
                    encode_integer(&small),
                    encode_integer(&small),
                ]
                .concat(),
            )
        };
        #[cfg(feature = "std")]
        let start = std::time::Instant::now();
        for der in [
            build(&huge, &huge, &be(&sk.d)),
            build(&be(&sk.p), &huge, &be(&sk.d)),
            build(&be(&sk.p), &be(&sk.q), &huge),
        ] {
            assert!(matches!(
                BoxedRsaPrivateKey::from_pkcs1_der_insecure(&der),
                Err(crate::der::Error::Malformed)
            ));
        }
        // The component-level guard (also reached via `from_crt_components`):
        // a prime wider than `n`, and primes each narrower than `n` whose bit
        // lengths cannot multiply to `n`.
        let n = sk.modulus();
        let wide = BoxedUint::from_be_bytes(&huge);
        assert!(validate_private_components(n, &[&wide, &sk.q]).is_err());
        let mut half = n.shr_bits(1);
        if !half.is_odd() {
            half = half.add(&BoxedUint::from_u64(1));
        }
        assert!(validate_private_components(n, &[&half, &half]).is_err());
        assert!(validate_private_components(n, &[&sk.p, &sk.q]).is_ok());
        assert!(
            BoxedRsaPrivateKey::from_crt_components(
                n.clone(),
                sk.e.clone(),
                sk.d.clone(),
                wide.clone(),
                wide,
                BoxedUint::from_u64(3),
                BoxedUint::from_u64(3),
                BoxedUint::from_u64(3),
            )
            .is_err()
        );
        #[cfg(feature = "std")]
        assert!(start.elapsed() < std::time::Duration::from_secs(2));
    }

    /// `p == q` is rejected — the resulting `n = p²` shares only one prime
    /// factor and the CRT path collapses (qInv is undefined since
    /// `gcd(q, p) = p ≠ 1`).
    #[test]
    fn from_pkcs1_der_rejects_equal_primes() {
        use crate::der::{encode_integer, encode_sequence};
        let sk = gen_small_key(b"rsa-pkcs1-eq-primes");
        let be = |v: &BoxedUint| v.to_be_bytes(v.bit_len().div_ceil(8).max(1));
        // Forge a key with p = q = sk.p. Then n = p² is the modulus we present.
        let p_sq = sk.p.mul(&sk.p);
        let der = encode_sequence(
            &[
                encode_integer(&[0]),
                encode_integer(&be(&p_sq)),
                encode_integer(&be(&sk.e)),
                encode_integer(&be(&sk.d)),
                encode_integer(&be(&sk.p)),
                encode_integer(&be(&sk.p)), // q := p
                // Padding for the three CRT params — parser doesn't validate
                // them, so any nonzero value works.
                encode_integer(&[1]),
                encode_integer(&[1]),
                encode_integer(&[1]),
            ]
            .concat(),
        );
        assert!(matches!(
            BoxedRsaPrivateKey::from_pkcs1_der(&der),
            Err(crate::der::Error::Malformed)
        ));
    }

    // ---- RSA-2: implicit-rejection (decrypt_pkcs1v15_session) ----

    /// Round-trips a real PKCS#1 v1.5 ciphertext through the boxed
    /// session-decrypt path. The implementation must recover the original
    /// plaintext when `expected_len` matches.
    #[test]
    fn boxed_session_decrypt_recovers_message_on_valid_ct() {
        let key = rsa_test_key_a();
        // Build a runtime-sized clone of `key` so we exercise the boxed
        // `decrypt_pkcs1v15_session` path end-to-end.
        let mut nb = [0u8; 256];
        key.modulus().write_be_bytes(&mut nb);
        let mut eb = [0u8; 256];
        key.exponent().write_be_bytes(&mut eb);
        let mut db = [0u8; 256];
        key.private_exponent().write_be_bytes(&mut db);
        let boxed_sk = BoxedRsaPrivateKey::from_components(
            BoxedUint::from_be_bytes(&nb),
            BoxedUint::from_be_bytes(&eb),
            BoxedUint::from_be_bytes(&db),
        );

        let pk = key.public_key();
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-session-ok", b"nonce", &[]);
        let msg = [0x5au8; 48];
        let ct = pk.encrypt_pkcs1v15(&msg, &mut r).unwrap();
        let out = boxed_sk.decrypt_pkcs1v15_session(&ct, msg.len()).unwrap();
        assert_eq!(out, msg);
    }

    /// A ciphertext whose RSA decryption yields malformed padding must
    /// surface a `Ok`-shaped synthetic plaintext of length `expected_len`,
    /// not an error. This is the core Bleichenbacher / Marvin / ROBOT
    /// defense.
    #[test]
    fn boxed_session_decrypt_returns_synthetic_on_bad_padding() {
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-session-syn", b"nonce", &[]);
        let key = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut r, 12);
        let bogus_ct = [0x42u8; 128];
        let out = key.decrypt_pkcs1v15_session(&bogus_ct, 48).unwrap();
        assert_eq!(out.len(), 48);
    }

    /// The synthetic plaintext is deterministic: repeated calls on the
    /// same key with the same ciphertext yield the same bytes.
    #[test]
    fn boxed_session_decrypt_is_deterministic_under_same_key() {
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-session-det", b"nonce", &[]);
        let key = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut r, 12);
        let bogus_ct = [0xa9u8; 128];
        let a = key.decrypt_pkcs1v15_session(&bogus_ct, 48).unwrap();
        let b = key.decrypt_pkcs1v15_session(&bogus_ct, 48).unwrap();
        assert_eq!(a, b);
    }

    /// `InvalidLength` is the only externally observable error: ciphertext
    /// length is public.
    #[test]
    fn boxed_session_decrypt_rejects_wrong_length_ct() {
        let mut r = HmacDrbg::<Sha256>::new(b"boxed-session-len", b"nonce", &[]);
        let key = BoxedRsaPrivateKey::generate(1024, BoxedUint::from_u64(65537), &mut r, 12);
        let short = [0u8; 127];
        assert_eq!(
            key.decrypt_pkcs1v15_session(&short, 48),
            Err(Error::InvalidLength)
        );
    }

    /// RFC 8017 §7.2.2 step 1 on the runtime-sized key: a ciphertext
    /// representative `>= n` is rejected before the private operation, and
    /// the session variant keeps its implicit-rejection contract.
    #[test]
    fn out_of_range_ciphertext_is_rejected_boxed() {
        let sk = gen_small_key(b"rsa-oor");
        let ct = vec![0xffu8; 128]; // 2^1024 − 1 > n for any 1024-bit n

        assert!(sk.decrypt_pkcs1v15(&ct).is_err());
        assert!(sk.decrypt_oaep::<Sha256>(&ct, b"label").is_err());

        let synthetic = sk.decrypt_pkcs1v15_session(&ct, 48).unwrap();
        assert_eq!(synthetic.len(), 48);
        assert_eq!(sk.decrypt_pkcs1v15_session(&ct, 48).unwrap(), synthetic);

        // A well-formed ciphertext still round-trips.
        let mut rng = HmacDrbg::<Sha256>::new(b"rsa-oor-ok", b"n", &[]);
        let good = sk
            .public_key()
            .encrypt_pkcs1v15(b"secret", &mut rng)
            .unwrap();
        assert_eq!(sk.decrypt_pkcs1v15(&good).unwrap().as_slice(), b"secret");
    }

    /// A modulus length that is not a multiple of the HMAC output (2056
    /// bits = 257 bytes → 9 tags = 288 bytes) must still derive a blinder
    /// without the byte buffer reallocating mid-loop (the `debug_assert`
    /// in `derive_blinder_boxed` checks the capacity; this test exercises
    /// that path, which no 2048/3072/4096-bit key reaches).
    #[test]
    fn blinder_derivation_handles_non_multiple_of_32_modulus_length() {
        // An odd 2056-bit modulus (top bit set, low bit set); it need not be
        // an RSA modulus for the derivation itself.
        let k = 257;
        let mut nb = vec![0u8; k];
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for b in nb.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        nb[0] |= 0x80;
        nb[k - 1] |= 1;
        let n = BoxedUint::from_be_bytes(&nb);
        let mont = BoxedMontModulus::new(&n);
        let seed = [0x5au8; 32];
        let salt = [0x3cu8; 16];
        let c = BoxedUint::from_u64(7);
        let r0 = derive_blinder_boxed(&mont, &seed, k, 0, &salt, &c);
        let r1 = derive_blinder_boxed(&mont, &seed, k, 1, &salt, &c);
        assert!(r0.lt(&n) && r1.lt(&n), "blinder must be reduced mod n");
        assert!(!r0.is_zero() && r0 != BoxedUint::from_u64(1));
        assert_ne!(r0, r1);
    }

    /// The blinder must be fresh per operation: two calls with the same
    /// ciphertext must not reproduce the same blinded computation. Checked at
    /// the derivation, since the blinder never leaves the private path.
    #[test]
    fn blinder_differs_between_operations_on_the_same_ciphertext() {
        let sk = gen_small_key(b"rsa-blind-nonce");
        let c = BoxedUint::from_u64(0x1234_5678_9abc_def0);
        let salt = [0u8; 16];
        let r0 = derive_blinder_boxed(&sk.mont, &sk.blinding_seed, sk.k, 0, &salt, &c);
        let r1 = derive_blinder_boxed(&sk.mont, &sk.blinding_seed, sk.k, 1, &salt, &c);
        assert_ne!(r0, r1, "blinder must depend on the operation counter");
        // …and on the random salt, which is what makes the sequence
        // unpredictable (the counter is public and replayable).
        let other_salt = [0xa5u8; 16];
        let r0b = derive_blinder_boxed(&sk.mont, &sk.blinding_seed, sk.k, 0, &other_salt, &c);
        assert_ne!(r0, r0b, "blinder must depend on the random salt");

        // …and the operation itself still produces the same plaintext twice.
        let mut rng = HmacDrbg::<Sha256>::new(b"rsa-blind-nonce-ct", b"n", &[]);
        let ct = sk
            .public_key()
            .encrypt_pkcs1v15(b"stable", &mut rng)
            .unwrap();
        assert_eq!(
            sk.decrypt_pkcs1v15(&ct).unwrap(),
            sk.decrypt_pkcs1v15(&ct).unwrap()
        );
        // The counter advanced across those operations.
        assert!(sk.blind_counter.load(Ordering::Relaxed) >= 2);
    }

    // ---- Multi-prime (RFC 8017 §3.2) ----

    /// The components of a three-prime key: `n = p · q · r`, `e = 65537`,
    /// `d = e⁻¹ mod φ(n)`.
    struct ThreePrime {
        n: BoxedUint,
        e: BoxedUint,
        d: BoxedUint,
        p: BoxedUint,
        q: BoxedUint,
        r: BoxedUint,
    }

    /// Draws three 384-bit primes from a seeded DRBG (a 1152-bit modulus,
    /// above `MIN_RSA_BITS` so the DER parsers accept it) and derives `d`.
    fn three_prime_components(seed: &[u8]) -> ThreePrime {
        let mut rng = HmacDrbg::<Sha256>::new(seed, b"three-prime", &[]);
        let e = BoxedUint::from_u64(65537);
        let one = BoxedUint::from_u64(1);
        loop {
            let p = super::super::prime::random_prime_boxed(&mut rng, 384, 8);
            let q = super::super::prime::random_prime_boxed(&mut rng, 384, 8);
            let r = super::super::prime::random_prime_boxed(&mut rng, 384, 8);
            let n = p.mul(&q).mul(&r);
            let phi = p.sub(&one).mul(&q.sub(&one)).mul(&r.sub(&one));
            if let Some(d) = crate::bignum::inv_mod_boxed(&e, &phi) {
                return ThreePrime { n, e, d, p, q, r };
            }
        }
    }

    fn three_prime_key(c: &ThreePrime) -> BoxedRsaPrivateKey {
        BoxedRsaPrivateKey::from_components_with_other_primes(
            c.n.clone(),
            c.e.clone(),
            c.d.clone(),
            c.p.clone(),
            c.q.clone(),
            vec![c.r.clone()],
        )
    }

    /// Big-endian minimal encoding, as the DER encoder wants it.
    fn be_min(v: &BoxedUint) -> Vec<u8> {
        v.to_be_bytes(v.bit_len().div_ceil(8).max(1))
    }

    /// A hand-built PKCS#1 `RSAPrivateKey` blob: `version`, the two-prime
    /// fields (with the CRT parameters as given), and — when `others` is
    /// non-empty — an `otherPrimeInfos` SEQUENCE of `(r, d_i, t_i)` triples.
    fn pkcs1_blob(
        version: u8,
        c: &ThreePrime,
        d: &BoxedUint,
        others: &[(&BoxedUint, &BoxedUint, &BoxedUint)],
        empty_infos: bool,
    ) -> Vec<u8> {
        use crate::der::{encode_integer, encode_sequence};
        let one = BoxedUint::from_u64(1);
        let dp = d.reduce(&c.p.sub(&one));
        let dq = d.reduce(&c.q.sub(&one));
        let qinv = crate::bignum::inv_mod_boxed(&c.q, &c.p).unwrap();
        let mut body = [
            encode_integer(&[version]),
            encode_integer(&be_min(&c.n)),
            encode_integer(&be_min(&c.e)),
            encode_integer(&be_min(d)),
            encode_integer(&be_min(&c.p)),
            encode_integer(&be_min(&c.q)),
            encode_integer(&be_min(&dp)),
            encode_integer(&be_min(&dq)),
            encode_integer(&be_min(&qinv)),
        ]
        .concat();
        if !others.is_empty() || empty_infos {
            let mut infos = Vec::new();
            for (r, d_i, t_i) in others {
                infos.extend_from_slice(&encode_sequence(
                    &[
                        encode_integer(&be_min(r)),
                        encode_integer(&be_min(d_i)),
                        encode_integer(&be_min(t_i)),
                    ]
                    .concat(),
                ));
            }
            body.extend_from_slice(&encode_sequence(&infos));
        }
        encode_sequence(&body)
    }

    /// A three-prime key takes the multi-prime CRT path and its result is
    /// bit-identical to the plain `c^d mod n` — on the raw operation, on
    /// deterministic PKCS#1 v1.5 signatures against a primes-less
    /// `from_components` key, and through OAEP / PKCS#1 v1.5 / PSS round
    /// trips with the public key.
    #[test]
    fn three_prime_crt_matches_full_width_and_roundtrips() {
        let c = three_prime_components(b"rsa-three-prime-a");
        let key = three_prime_key(&c);
        assert_eq!(key.num_primes(), 3);
        let crt = key.crt.as_deref().expect("multi-prime CRT parameters");
        assert_eq!(crt.others.len(), 1);
        // The derived coefficient is the RFC 8017 §3.2 `t₃ = (p·q)⁻¹ mod r`
        // and the exponent `d₃ = d mod (r − 1)`.
        let pq_inv = crate::bignum::inv_mod_boxed(&c.p.mul(&c.q), &c.r).unwrap();
        assert_eq!(crt.others[0].t, pq_inv);
        assert_eq!(
            crt.others[0].d,
            c.d.reduce(&c.r.sub(&BoxedUint::from_u64(1)))
        );

        // Raw private op: blinded multi-prime CRT == direct c^d mod n.
        for &v in &[2u64, 0x1234_5678_9abc_def0, u64::MAX] {
            let x = BoxedUint::from_u64(v);
            assert_eq!(
                raw_private_blinded_boxed(&key, &x),
                key.mont.pow(&x, &c.d),
                "c = {v:#x}"
            );
        }
        let big = c.n.sub(&BoxedUint::from_u64(12345));
        assert_eq!(
            raw_private_blinded_boxed(&key, &big),
            key.mont.pow(&big, &c.d)
        );

        let plain = BoxedRsaPrivateKey::from_components(c.n.clone(), c.e.clone(), c.d.clone());
        assert!(plain.crt.is_none());
        for msg in [&b"three primes"[..], b"", b"garner"] {
            assert_eq!(
                key.sign_pkcs1v15::<Sha256>(msg).unwrap(),
                plain.sign_pkcs1v15::<Sha256>(msg).unwrap(),
                "multi-prime CRT and full-width paths diverged"
            );
        }

        let pk = key.public_key();
        let mut rng = HmacDrbg::<Sha256>::new(b"rsa-three-prime-ops", b"n", &[]);
        let ct = pk
            .encrypt_oaep::<Sha256, _>(b"oaep over three primes", b"label", &mut rng)
            .unwrap();
        assert_eq!(
            key.decrypt_oaep::<Sha256>(&ct, b"label").unwrap(),
            b"oaep over three primes"
        );
        let ct = pk.encrypt_pkcs1v15(b"v1.5", &mut rng).unwrap();
        assert_eq!(key.decrypt_pkcs1v15(&ct).unwrap(), b"v1.5");
        let sig = key.sign_pss::<Sha256, _>(b"pss", &mut rng).unwrap();
        pk.verify_pss::<Sha256>(b"pss", &sig).unwrap();
        let sig = key
            .sign_pss_shake::<crate::hash::Shake128, _>(b"pss", &mut rng)
            .unwrap();
        pk.verify_pss_shake::<crate::hash::Shake128>(b"pss", &sig)
            .unwrap();

        // The blinded operation stays correct across repeated calls (fresh
        // blinder each time) and a clone.
        let sig = key.sign_pkcs1v15::<Sha256>(b"again").unwrap();
        assert_eq!(key.sign_pkcs1v15::<Sha256>(b"again").unwrap(), sig);
        assert_eq!(key.clone().sign_pkcs1v15::<Sha256>(b"again").unwrap(), sig);
    }

    /// A three-prime key serializes as `version = 1` with `otherPrimeInfos`
    /// and parses back — through PKCS#1 and PKCS#8 — to a key that carries
    /// the extra prime, re-encodes byte-identically and signs identically.
    #[test]
    fn three_prime_pkcs1_and_pkcs8_roundtrip() {
        use crate::der::{Reader, tag};
        let c = three_prime_components(b"rsa-three-prime-der");
        let key = three_prime_key(&c);
        let der = key.to_pkcs1_der();
        let body = Reader::new(&der).read_tlv(tag::SEQUENCE).unwrap();
        assert_eq!(&body[..3], &[0x02, 0x01, 0x01], "version = 1 leads");
        // The emitted blob is the hand-built one with the RFC's `t₃`.
        let one = BoxedUint::from_u64(1);
        let d3 = c.d.reduce(&c.r.sub(&one));
        let t3 = crate::bignum::inv_mod_boxed(&c.p.mul(&c.q), &c.r).unwrap();
        assert_eq!(der, pkcs1_blob(1, &c, &c.d, &[(&c.r, &d3, &t3)], false));

        let parsed = BoxedRsaPrivateKey::from_pkcs1_der(&der).unwrap();
        assert_eq!(parsed.num_primes(), 3);
        assert!(
            parsed
                .crt
                .as_deref()
                .is_some_and(|crt| crt.others.len() == 1)
        );
        assert_eq!(parsed.other_primes, vec![c.r.clone()]);
        assert_eq!(parsed.to_pkcs1_der(), der);
        assert_eq!(
            parsed.sign_pkcs1v15::<Sha256>(b"via der").unwrap(),
            key.sign_pkcs1v15::<Sha256>(b"via der").unwrap()
        );

        let pkcs8 = key.to_pkcs8_der();
        let parsed = BoxedRsaPrivateKey::from_pkcs8_der(&pkcs8).unwrap();
        assert_eq!(parsed.num_primes(), 3);
        assert_eq!(parsed.to_pkcs8_der(), pkcs8);
        let parsed = BoxedRsaPrivateKey::from_pkcs8_pem(&key.to_pkcs8_pem()).unwrap();
        assert_eq!(parsed.to_pkcs1_der(), der);
        let parsed = BoxedRsaPrivateKey::from_pkcs1_pem(&key.to_pkcs1_pem()).unwrap();
        assert_eq!(parsed.to_pkcs1_der(), der);

        // A two-prime key still serializes as version 0 without the field.
        let two = gen_small_key(b"rsa-two-prime-still-v0");
        let der = two.to_pkcs1_der();
        let body = Reader::new(&der).read_tlv(tag::SEQUENCE).unwrap();
        assert_eq!(&body[..3], &[0x02, 0x01, 0x00]);
        assert_eq!(two.num_primes(), 2);
    }

    /// The multi-prime parser rejects: a version that disagrees with the
    /// presence of `otherPrimeInfos`, an empty `otherPrimeInfos`, an extra
    /// prime that does not divide `n`, a repeated prime, a `d` that does not
    /// invert `e` mod `r − 1`, and more primes than the cap allows.
    #[test]
    fn three_prime_pkcs1_der_rejections() {
        let c = three_prime_components(b"rsa-three-prime-bad");
        let one = BoxedUint::from_u64(1);
        let two = BoxedUint::from_u64(2);
        let d3 = c.d.reduce(&c.r.sub(&one));
        let t3 = crate::bignum::inv_mod_boxed(&c.p.mul(&c.q), &c.r).unwrap();
        let good = pkcs1_blob(1, &c, &c.d, &[(&c.r, &d3, &t3)], false);
        BoxedRsaPrivateKey::from_pkcs1_der(&good).expect("the honest blob parses");
        // The blob's own d₃ / t₃ are recomputed, not trusted: garbage there
        // still parses to a correct key.
        let garbage = pkcs1_blob(1, &c, &c.d, &[(&c.r, &two, &two)], false);
        let k = BoxedRsaPrivateKey::from_pkcs1_der(&garbage).unwrap();
        assert_eq!(k.to_pkcs1_der(), good);

        let cases: [(&str, Vec<u8>); 6] = [
            (
                "version 0 with otherPrimeInfos",
                pkcs1_blob(0, &c, &c.d, &[(&c.r, &d3, &t3)], false),
            ),
            (
                "version 1 without otherPrimeInfos",
                pkcs1_blob(1, &c, &c.d, &[], false),
            ),
            (
                "version 1 with empty otherPrimeInfos",
                pkcs1_blob(1, &c, &c.d, &[], true),
            ),
            (
                "r does not divide n",
                pkcs1_blob(1, &c, &c.d, &[(&c.r.add(&two), &d3, &t3)], false),
            ),
            (
                "d inconsistent mod r − 1",
                pkcs1_blob(1, &c, &c.d.sub(&two), &[(&c.r, &d3, &t3)], false),
            ),
            (
                "nine primes",
                pkcs1_blob(1, &c, &c.d, &[(&c.r, &d3, &t3); 7], false),
            ),
        ];
        for (why, blob) in &cases {
            // The version / `otherPrimeInfos` disagreements surface as DER
            // structure errors, the semantic checks as `Malformed`.
            assert!(
                BoxedRsaPrivateKey::from_pkcs1_der(blob).is_err(),
                "{why} must be rejected"
            );
        }
        // A repeated prime: n = p·q·p presented with primes (p, q, p). The
        // product matches, so this is the pairwise-distinct check firing.
        let dup_n = c.p.mul(&c.q).mul(&c.p);
        let dup = ThreePrime {
            // `d` is folded below the bogus modulus (whether the honest `d`
            // is already below `p·q·p` depends on the draw), so `d` out of
            // range is not what fires: the component checks run on any blob
            // whose `d < n`.
            d: c.d.reduce(&dup_n),
            n: dup_n,
            e: c.e.clone(),
            p: c.p.clone(),
            q: c.q.clone(),
            r: c.p.clone(),
        };
        let blob = pkcs1_blob(1, &dup, &dup.d, &[(&dup.r, &d3, &t3)], false);
        assert!(BoxedRsaPrivateKey::from_pkcs1_der(&blob).is_err());
        assert!(dup.d.lt(&dup.n));
    }

    /// Boneh–DeMillo–Lipton on the multi-prime path: corrupt the third
    /// prime's CRT exponent and the `m^e ≡ c` fault check must reject the
    /// Garner result and fall back to the full-width path — the emitted
    /// signature is still correct, and the factorable faulty value never
    /// escapes.
    #[test]
    fn corrupted_third_prime_exponent_falls_back_to_correct_signature() {
        let c = three_prime_components(b"rsa-three-prime-fault");
        let mut key = three_prime_key(&c);
        let sig_good = key.sign_pkcs1v15::<Sha256>(b"fault me").unwrap();
        let crt = key.crt.as_deref_mut().expect("CRT params present");
        crt.others[0].d = BoxedUint::from_u64(0x1337);
        let sig = key.sign_pkcs1v15::<Sha256>(b"fault me").unwrap();
        assert_eq!(sig, sig_good);
        key.public_key()
            .verify_pkcs1v15::<Sha256>(b"fault me", &sig)
            .unwrap();
        // The raw faulty CRT output really is wrong (so the check did work).
        let x = BoxedUint::from_u64(0xabcdef);
        let salt = [0u8; 16];
        let faulty = raw_private_crt_blinded(&key, key.crt.as_deref().unwrap(), 0, &salt, &x);
        assert_ne!(faulty, key.mont.pow(&x, &c.d));
        assert_eq!(raw_private_blinded_boxed(&key, &x), key.mont.pow(&x, &c.d));
    }

    // ---- raw private / public primitive, any-size keygen, from_crt_components ----

    /// The eight RFC 8017 components of a key, as `from_crt_components`
    /// takes them.
    fn crt_parts(key: &BoxedRsaPrivateKey) -> [BoxedUint; 8] {
        let (dp, dq, qinv) = key.crt_params().expect("CRT params present");
        let (p, q) = key.primes().expect("primes present");
        [
            key.n.clone(),
            key.e.clone(),
            key.d.clone(),
            p.clone(),
            q.clone(),
            dp.clone(),
            dq.clone(),
            qinv.clone(),
        ]
    }

    fn from_parts(parts: [BoxedUint; 8]) -> Result<BoxedRsaPrivateKey, Error> {
        let [n, e, d, p, q, dp, dq, qinv] = parts;
        BoxedRsaPrivateKey::from_crt_components(n, e, d, p, q, dp, dq, qinv)
    }

    /// Key generation at odd and sub-512-bit sizes: the modulus has exactly
    /// the requested bit length, the primes split it as ⌈bits/2⌉ + ⌊bits/2⌋,
    /// the key works (raw round trip and PKCS#1 v1.5 where it fits), and its
    /// own parts rebuild it through the checked constructor.
    #[test]
    fn generate_accepts_odd_and_small_sizes() {
        for bits in [256usize, 384, 511, 513, 1023, 1025] {
            let mut rng = HmacDrbg::<Sha256>::new(b"rsa-odd-keygen", &bits.to_be_bytes(), &[]);
            let key = BoxedRsaPrivateKey::generate(bits, BoxedUint::from_u64(65537), &mut rng, 0);
            assert_eq!(key.modulus().bit_len(), bits, "modulus size at {bits}");
            let (p, q) = key.primes().unwrap();
            assert_eq!(p.bit_len(), bits.div_ceil(2), "p size at {bits}");
            assert_eq!(q.bit_len(), bits / 2, "q size at {bits}");
            assert!(crate::bignum::prime::is_prime_boxed(p, &mut rng, 20));
            assert!(crate::bignum::prime::is_prime_boxed(q, &mut rng, 20));

            let pk = key.public_key();
            let m = [0x5au8; 20];
            let c = pk.raw_public(&m).unwrap();
            assert_eq!(c.len(), bits.div_ceil(8));
            let back = key.raw_private(&c).unwrap();
            assert_eq!(&back[back.len() - m.len()..], &m);
            assert!(back[..back.len() - m.len()].iter().all(|&b| b == 0));
            // SHA-256 DigestInfo is 51 octets, so PKCS#1 v1.5 needs k ≥ 62.
            if bits >= 512 {
                let sig = key.sign_pkcs1v15::<Sha256>(b"odd size").unwrap();
                pk.verify_pkcs1v15::<Sha256>(b"odd size", &sig).unwrap();
            }

            let rebuilt = from_parts(crt_parts(&key)).expect("own parts must rebuild");
            assert_eq!(rebuilt.raw_private(&c).unwrap(), back);
        }
    }

    /// Standard even sizes draw exactly as before the odd-size split: the
    /// same DRBG seed yields the same key through `generate` and
    /// `try_generate`.
    #[test]
    fn try_generate_matches_generate_and_rejects_out_of_range() {
        let e = BoxedUint::from_u64(65537);
        let mut r1 = HmacDrbg::<Sha256>::new(b"rsa-try-keygen", b"nonce", &[]);
        let mut r2 = HmacDrbg::<Sha256>::new(b"rsa-try-keygen", b"nonce", &[]);
        let a = BoxedRsaPrivateKey::generate(1024, e.clone(), &mut r1, 0);
        let b = BoxedRsaPrivateKey::try_generate(1024, e.clone(), &mut r2, 0).unwrap();
        assert_eq!(a.modulus(), b.modulus());
        assert_eq!(a.private_exponent(), b.private_exponent());

        let mut r = HmacDrbg::<Sha256>::new(b"rsa-try-keygen-bad", b"nonce", &[]);
        for bits in [0usize, 2, 255, MAX_RSA_BITS + 1] {
            assert_eq!(
                BoxedRsaPrivateKey::try_generate(bits, e.clone(), &mut r, 0).err(),
                Some(Error::InvalidLength),
                "bits = {bits}"
            );
        }
        // e even, e = 1, e ≥ 2^256, and e that does not fit below n.
        let big_e = BoxedUint::from_limbs(alloc::vec![1, 0, 0, 0, 1]);
        let e_255 = BoxedUint::from_limbs(alloc::vec![1, 0, 0, 1 << 63]);
        for (bits, bad) in [
            (1024, BoxedUint::from_u64(65536)),
            (1024, BoxedUint::from_u64(1)),
            (1024, big_e),
            (256, e_255.clone()),
        ] {
            assert_eq!(
                BoxedRsaPrivateKey::try_generate(bits, bad, &mut r, 0).err(),
                Some(Error::InvalidKey),
            );
        }
        // A 256-bit `e` is fine once the modulus is 257 bits or more.
        let key = BoxedRsaPrivateKey::try_generate(257, e_255, &mut r, 0).unwrap();
        assert_eq!(key.modulus().bit_len(), 257);
    }

    /// `raw_private` inverts `raw_public` (and vice versa), equals the
    /// unblinded `c^d mod n`, pads short input, and rejects input `≥ n` or
    /// wider than the modulus.
    #[test]
    fn raw_private_roundtrips_against_raw_public() {
        let key = rsa_test_key_a().to_boxed();
        let pk = key.public_key();
        let k = key.k;
        let mut m = vec![0u8; k];
        for (i, b) in m.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        m[0] = 0x01; // below n
        let c = pk.raw_public(&m).unwrap();
        assert_eq!(key.raw_private(&c).unwrap(), m);
        // Raw "private encryption" (the signing primitive) the other way.
        let s = key.raw_private(&m).unwrap();
        assert_eq!(s.len(), k);
        assert_eq!(pk.raw_public(&s).unwrap(), m);
        // Matches the plain full-width exponentiation.
        let expect = key
            .mont
            .pow(&BoxedUint::from_be_bytes(&m), &key.d)
            .to_be_bytes(k);
        assert_eq!(s, expect);
        // Repeated calls (fresh blinders) agree.
        assert_eq!(key.raw_private(&m).unwrap(), s);

        // Short input is a left-padded integer; zero maps to zero.
        let short = key.raw_private(&[0x02]).unwrap();
        let mut padded = vec![0u8; k];
        padded[k - 1] = 0x02;
        assert_eq!(short, key.raw_private(&padded).unwrap());
        assert_eq!(key.raw_private(&[]).unwrap(), vec![0u8; k]);
        assert_eq!(pk.raw_public(&[0, 0]).unwrap(), vec![0u8; k]);

        // Out of range: n itself, n − 1 is the largest accepted value.
        let n_be = key.n.to_be_bytes(k);
        assert_eq!(key.raw_private(&n_be), Err(Error::MessageTooLong));
        assert_eq!(pk.raw_public(&n_be), Err(Error::MessageTooLong));
        assert_eq!(key.raw_private(&vec![0xff; k]), Err(Error::MessageTooLong));
        let n_minus_1 = key.n.sub(&BoxedUint::from_u64(1)).to_be_bytes(k);
        let r = key.raw_private(&n_minus_1).unwrap();
        assert_eq!(pk.raw_public(&r).unwrap(), n_minus_1);
        // Wider than the modulus, even with a leading zero.
        let mut wide = vec![0u8; k + 1];
        wide[k] = 1;
        assert_eq!(key.raw_private(&wide), Err(Error::InvalidLength));
        assert_eq!(pk.raw_public(&wide), Err(Error::InvalidLength));
    }

    /// A key without primes still serves `raw_private` (plain ladder), and
    /// a key whose `d` fails the fault check on both paths reports
    /// `InvalidKey` rather than releasing a value.
    #[test]
    fn raw_private_without_primes_and_on_fault() {
        let good = rsa_test_key_a().to_boxed();
        let m = [0x42u8; 64];
        let s = good.raw_private(&m).unwrap();
        assert_eq!(boxed_priv().raw_private(&m).unwrap(), s);

        let broken = BoxedRsaPrivateKey::from_components_with_primes(
            good.n.clone(),
            good.e.clone(),
            good.d.sub(&BoxedUint::from_u64(2)),
            good.p.clone(),
            good.q.clone(),
        );
        assert_eq!(broken.raw_private(&m), Err(Error::InvalidKey));
    }

    /// `from_crt_components` accepts a consistent key — including one whose
    /// `d` is reduced mod `λ(n)` rather than `φ(n)` — and the accessors
    /// return exactly what PKCS#1 carries.
    #[test]
    fn from_crt_components_accepts_consistent_parts() {
        let key = rsa_test_key_a().to_boxed();
        let parts = crt_parts(&key);
        let one = BoxedUint::from_u64(1);
        let (p, q) = (&parts[3], &parts[4]);
        assert_eq!(parts[5], key.d.reduce(&p.sub(&one)));
        assert_eq!(parts[6], key.d.reduce(&q.sub(&one)));
        assert_eq!(parts[7], crate::bignum::inv_mod_boxed(q, p).unwrap());

        let rebuilt = from_parts(parts.clone()).unwrap();
        let sig = rebuilt.sign_pkcs1v15::<Sha256>(b"from parts").unwrap();
        key.public_key()
            .verify_pkcs1v15::<Sha256>(b"from parts", &sig)
            .unwrap();
        assert_eq!(rebuilt.private_exponent(), key.private_exponent());

        // d mod λ(n), λ = (p−1)(q−1) / gcd(p−1, q−1).
        let (pm1, qm1) = (p.sub(&one), q.sub(&one));
        let (mut a, mut b) = (pm1.clone(), qm1.clone());
        while !b.is_zero() {
            let r = a.reduce(&b);
            a = b;
            b = r;
        }
        let lambda = pm1.mul(&qm1).divrem(&a).0;
        let d_lambda = key.d.reduce(&lambda);
        let mut lp = parts.clone();
        lp[2] = d_lambda.clone();
        lp[5] = d_lambda.reduce(&pm1);
        lp[6] = d_lambda.reduce(&qm1);
        let k2 = from_parts(lp).expect("d mod λ(n) is a valid private exponent");
        assert_eq!(k2.sign_pkcs1v15::<Sha256>(b"from parts").unwrap(), sig);
    }

    /// Each kind of inconsistent part is refused.
    #[test]
    fn from_crt_components_rejects_inconsistent_parts() {
        let key = rsa_test_key_a().to_boxed();
        let other = gen_small_key(b"rsa-from-parts-other");
        let good = crt_parts(&key);
        let one = BoxedUint::from_u64(1);
        let two = BoxedUint::from_u64(2);
        let with = |i: usize, v: BoxedUint| {
            let mut parts = good.clone();
            parts[i] = v;
            parts
        };
        let (n, d, p, q) = (&good[0], &good[2], &good[3], &good[4]);
        let (dp, dq, qinv) = (&good[5], &good[6], &good[7]);
        let cases: alloc::vec::Vec<(&str, [BoxedUint; 8], Error)> = alloc::vec![
            // n
            ("n ≠ p·q", with(0, other.n.clone()), Error::InvalidKey),
            ("n even", with(0, n.add(&one)), Error::InvalidKey),
            (
                "n too small",
                with(0, BoxedUint::from_u64(0xffff_fff1)),
                Error::InvalidLength
            ),
            // e
            (
                "e even",
                with(1, BoxedUint::from_u64(65536)),
                Error::InvalidKey
            ),
            ("e = 1", with(1, one.clone()), Error::InvalidKey),
            (
                "e ≠ the inverse of d",
                with(1, BoxedUint::from_u64(3)),
                Error::InvalidKey
            ),
            ("e ≥ n", with(1, n.add(&two)), Error::InvalidKey),
            // d
            ("d = 0", with(2, BoxedUint::zero(1)), Error::InvalidKey),
            ("d ≥ n", with(2, n.add(&one)), Error::InvalidKey),
            ("d not e⁻¹", with(2, d.sub(&two)), Error::InvalidKey),
            // p, q
            ("p = 1", with(3, one.clone()), Error::InvalidKey),
            ("p even", with(3, p.add(&one)), Error::InvalidKey),
            (
                "p from another key",
                with(3, other.p.clone()),
                Error::InvalidKey
            ),
            ("q = p", with(4, p.clone()), Error::InvalidKey),
            ("q = 0", with(4, BoxedUint::zero(1)), Error::InvalidKey),
            // CRT values
            ("dP off by two", with(5, dp.sub(&two)), Error::InvalidKey),
            (
                "dP unreduced",
                with(5, dp.add(&p.sub(&one))),
                Error::InvalidKey
            ),
            ("dP = dQ", with(5, dq.clone()), Error::InvalidKey),
            ("dQ off by two", with(6, dq.add(&two)), Error::InvalidKey),
            (
                "dQ unreduced",
                with(6, dq.add(&q.sub(&one))),
                Error::InvalidKey
            ),
            (
                "qInv off by one",
                with(7, qinv.add(&one)),
                Error::InvalidKey
            ),
            ("qInv unreduced", with(7, qinv.add(p)), Error::InvalidKey),
            (
                "qInv = p⁻¹ mod q",
                with(7, crate::bignum::inv_mod_boxed(p, q).unwrap()),
                Error::InvalidKey
            ),
            ("qInv = 0", with(7, BoxedUint::zero(1)), Error::InvalidKey),
        ];
        for (what, parts, want) in cases {
            assert_eq!(from_parts(parts).err(), Some(want), "{what}");
        }
        // p and q swapped is a different (equally valid) labelling, but only
        // with the CRT values swapped and qInv recomputed to match.
        let mut swapped = good.clone();
        swapped.swap(3, 4);
        assert!(from_parts(swapped.clone()).is_err());
        swapped.swap(5, 6);
        swapped[7] = crate::bignum::inv_mod_boxed(p, q).unwrap();
        let k2 = from_parts(swapped).expect("p/q swapped consistently");
        assert_eq!(
            k2.raw_private(&[7; 32]).unwrap(),
            key.raw_private(&[7; 32]).unwrap()
        );
        // The good parts themselves pass (so each case above failed for its
        // own reason).
        from_parts(good).unwrap();
    }
    /// A 512-bit key generated by OpenSSL 3.5 (`genpkey -algorithm RSA
    /// -pkeyopt rsa_keygen_bits:512`) in its PKCS#8, PKCS#1 and SPKI forms.
    #[cfg(feature = "der")]
    const RSA512_PKCS8: &str = "-----BEGIN PRIVATE KEY-----
MIIBUwIBADANBgkqhkiG9w0BAQEFAASCAT0wggE5AgEAAkEAp5m74bV6vpYubUNe
51fjdq4rfqlSFvOy0cmuR6+ZqmxRwjXNbFgof/kLhUpFPv5OTg/VxVMfwaY64lB1
cAw/qwIDAQABAkBlzNQ5CaFPqCr1BQndHR41lR8oJTKObGG+WXE5a6i7wWm6QZPH
s/Uo3qNFUcW9eX1Winm34iD8NLmtnuoVQPoZAiEA1bdM7wI4qqlLHv+AzJWMHnqj
PmB76h0wEECUzMs3c0cCIQDIwq/toOkf4Dy5WebAXcVIikW9Z8l8j8mmAkPycf5a
fQIgcLGNceLb+rH2mMvmIPsivdexSO0bqmHlvEwxqqPmA3UCIH/+l9mBqH+5IB3v
8k0cu6XW+kWagPwYVDCx6w4MnWSlAiAUKvxa3NXxkGZa2bLgm93kKehpLx72n2H0
tpN+A9zZgw==
-----END PRIVATE KEY-----
";
    #[cfg(feature = "der")]
    const RSA512_PKCS1: &str = "-----BEGIN RSA PRIVATE KEY-----
MIIBOQIBAAJBAKeZu+G1er6WLm1DXudX43auK36pUhbzstHJrkevmapsUcI1zWxY
KH/5C4VKRT7+Tk4P1cVTH8GmOuJQdXAMP6sCAwEAAQJAZczUOQmhT6gq9QUJ3R0e
NZUfKCUyjmxhvllxOWuou8FpukGTx7P1KN6jRVHFvXl9Vop5t+Ig/DS5rZ7qFUD6
GQIhANW3TO8COKqpSx7/gMyVjB56oz5ge+odMBBAlMzLN3NHAiEAyMKv7aDpH+A8
uVnmwF3FSIpFvWfJfI/JpgJD8nH+Wn0CIHCxjXHi2/qx9pjL5iD7Ir3XsUjtG6ph
5bxMMaqj5gN1AiB//pfZgah/uSAd7/JNHLul1vpFmoD8GFQwsesODJ1kpQIgFCr8
WtzV8ZBmWtmy4Jvd5CnoaS8e9p9h9LaTfgPc2YM=
-----END RSA PRIVATE KEY-----
";
    #[cfg(feature = "der")]
    const RSA512_SPKI: &str = "-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKeZu+G1er6WLm1DXudX43auK36pUhbz
stHJrkevmapsUcI1zWxYKH/5C4VKRT7+Tk4P1cVTH8GmOuJQdXAMP6sCAwEAAQ==
-----END PUBLIC KEY-----
";

    /// The default parsers keep the 1024-bit floor; the `*_insecure` ones
    /// load the 512-bit OpenSSL key, and it interoperates: OpenSSL's
    /// `dgst -sha256 -sign` signature over `"hello"` verifies, and our
    /// (deterministic) PKCS#1 v1.5 signature is byte-identical to it.
    #[cfg(feature = "der")]
    #[test]
    fn insecure_parsers_accept_512_bit_openssl_key() {
        use crate::der::Error as DerError;
        use crate::test_util::from_hex_vec;
        let ossl_sig = from_hex_vec(
            "1ff21365a01c26137e0cc3c1299614ffa8a4aa1bbd77283e26f88be4cfae3764\
             81c57ea06e7009341eb603ea9d16abe59850fce9cdf1f8fa9d7087d82d92d86a",
        );

        assert_eq!(
            BoxedRsaPrivateKey::from_pkcs8_pem(RSA512_PKCS8).err(),
            Some(DerError::Malformed)
        );
        assert_eq!(
            BoxedRsaPrivateKey::from_pkcs1_pem(RSA512_PKCS1).err(),
            Some(DerError::Malformed)
        );
        assert_eq!(
            BoxedRsaPublicKey::from_spki_pem(RSA512_SPKI).err(),
            Some(DerError::Malformed)
        );

        let sk8 = BoxedRsaPrivateKey::from_pkcs8_pem_insecure(RSA512_PKCS8).unwrap();
        let sk1 = BoxedRsaPrivateKey::from_pkcs1_pem_insecure(RSA512_PKCS1).unwrap();
        let pk = BoxedRsaPublicKey::from_spki_pem_insecure(RSA512_SPKI).unwrap();
        assert_eq!(pk.modulus().bit_len(), 512);
        assert!(bool::from(sk8.modulus().ct_eq(pk.modulus())));
        assert!(bool::from(sk1.modulus().ct_eq(pk.modulus())));
        assert_eq!(sk1.to_pkcs1_pem(), RSA512_PKCS1);
        assert_eq!(sk8.to_pkcs8_pem(), RSA512_PKCS8);
        assert_eq!(pk.to_spki_pem(), RSA512_SPKI);

        pk.verify_pkcs1v15::<Sha256>(b"hello", &ossl_sig).unwrap();
        assert_eq!(sk8.sign_pkcs1v15::<Sha256>(b"hello").unwrap(), ossl_sig);
        assert!(pk.verify_pkcs1v15::<Sha256>(b"hellO", &ossl_sig).is_err());

        // The DER entry points and the raw-component constructor agree.
        let spki_der = pk.to_spki_der();
        assert!(BoxedRsaPublicKey::from_spki_der(&spki_der).is_err());
        let pk2 = BoxedRsaPublicKey::from_spki_der_insecure(&spki_der).unwrap();
        assert!(BoxedRsaPublicKey::from_pkcs1_der(&pk.to_pkcs1_der()).is_err());
        BoxedRsaPublicKey::from_pkcs1_der_insecure(&pk.to_pkcs1_der()).unwrap();
        assert!(BoxedRsaPrivateKey::from_pkcs8_der(&sk8.to_pkcs8_der()).is_err());
        BoxedRsaPrivateKey::from_pkcs8_der_insecure(&sk8.to_pkcs8_der()).unwrap();
        assert!(BoxedRsaPrivateKey::from_pkcs1_der(&sk8.to_pkcs1_der()).is_err());
        BoxedRsaPrivateKey::from_pkcs1_der_insecure(&sk8.to_pkcs1_der()).unwrap();
        assert_eq!(
            BoxedRsaPublicKey::try_new(pk2.modulus().clone(), pk2.exponent().clone()).err(),
            Some(Error::InvalidLength)
        );
        BoxedRsaPublicKey::try_new_insecure(pk2.modulus().clone(), pk2.exponent().clone()).unwrap();
    }

    /// The insecure floor is 256 bits (the keygen floor): a generated
    /// 256-bit key round-trips through the insecure parsers, anything
    /// shorter is refused, and the other public-key checks still apply.
    #[cfg(feature = "der")]
    #[test]
    fn insecure_floor_is_256_bits() {
        let mut rng = HmacDrbg::<Sha256>::new(b"insecure-floor", b"nonce", &[]);
        let sk = BoxedRsaPrivateKey::generate(256, BoxedUint::from_u64(65537), &mut rng, 12);
        let back = BoxedRsaPrivateKey::from_pkcs1_der_insecure(&sk.to_pkcs1_der()).unwrap();
        assert!(bool::from(back.modulus().ct_eq(sk.modulus())));
        BoxedRsaPublicKey::from_spki_der_insecure(&sk.public_key().to_spki_der()).unwrap();
        assert_eq!(MIN_RSA_INSECURE_BITS, 256);

        // A 255-bit odd modulus is below the floor.
        let mut nb = [0u8; 32];
        nb[0] = 0x40;
        nb[31] = 1;
        let n = BoxedUint::from_be_bytes(&nb);
        assert_eq!(n.bit_len(), 255);
        assert_eq!(
            BoxedRsaPublicKey::try_new_insecure(n, BoxedUint::from_u64(65537)).err(),
            Some(Error::InvalidLength)
        );
        // An even exponent is still refused.
        let pk = sk.public_key();
        assert_eq!(
            BoxedRsaPublicKey::try_new_insecure(pk.modulus().clone(), BoxedUint::from_u64(4)).err(),
            Some(Error::InvalidKey)
        );
    }

    /// The cached-blinding CRT path through several refresh cycles: PKCS#1
    /// v1.5 signatures are deterministic, so every one must equal the
    /// first (whatever blinder it ran under), and the cache must actually
    /// be in use (its counter moves) — then a busy cache must fall back to
    /// the stateless path with the same result, and a clone must start
    /// empty.
    #[test]
    fn cached_blinding_through_refreshes() {
        use super::super::blinding::REFRESH_INTERVAL;
        let key = gen_small_key(b"blinding-cache");
        let pk = key.public_key();
        let sig0 = key.sign_pkcs1v15::<Sha256>(b"cache").unwrap();
        pk.verify_pkcs1v15::<Sha256>(b"cache", &sig0).unwrap();
        assert_eq!(key.blind_cache.uses_left(), REFRESH_INTERVAL - 1);
        for i in 0..2 * REFRESH_INTERVAL + 5 {
            let sig = key.sign_pkcs1v15::<Sha256>(b"cache").unwrap();
            assert_eq!(sig, sig0, "signature {i}");
        }
        let left = key.blind_cache.uses_left();
        assert!(left > 0 && left < REFRESH_INTERVAL);

        key.blind_cache.set_busy(true);
        assert_eq!(key.sign_pkcs1v15::<Sha256>(b"cache").unwrap(), sig0);
        assert_eq!(key.blind_cache.uses_left(), left, "busy cache untouched");
        key.blind_cache.set_busy(false);

        let clone = key.clone();
        assert_eq!(clone.blind_cache.uses_left(), 0);
        assert_eq!(clone.sign_pkcs1v15::<Sha256>(b"cache").unwrap(), sig0);
    }

    /// Every pair the cache hands out is a valid blinding pair:
    /// `A = rᵉ`, `B = r⁻¹`, so `A·Bᵉ ≡ 1 (mod n)`, for every walk index and
    /// across a refresh; and consecutive pairs differ.
    #[test]
    fn cached_blinding_pairs_are_consistent() {
        use super::super::blinding::REFRESH_INTERVAL;
        let key = gen_small_key(b"blinding-pairs");
        let crt = key.crt.as_deref().unwrap();
        let mont = &key.mont;
        let c = BoxedUint::from_u64(12345);
        let mut prev: Option<BoxedUint> = None;
        for i in 0..REFRESH_INTERVAL as usize + 20 {
            let salt = [i as u8; 16];
            let (a, b) = key
                .blind_cache
                .take(mont, i % 16, || {
                    fresh_blinding_base(&key, crt, i as u32, &salt, &c)
                })
                .unwrap();
            let (a, b) = (mont.from_mont(&a), mont.from_mont(&b));
            let check = mont.mul_mod(&a, &mont.pow_public(&b, &key.e));
            assert!(
                check.ct_eq(&BoxedUint::from_u64(1)).declassify(),
                "pair {i}"
            );
            assert!(prev.as_ref() != Some(&a), "pair {i} repeats");
            prev = Some(a);
        }
    }

    /// Raw private / public round trips (both directions) at modulus sizes
    /// that land on and off the limb and 52-bit-digit boundaries of the
    /// exponentiation kernels, under the cached-blinding CRT path.
    #[test]
    fn raw_round_trips_across_sizes() {
        for bits in [512usize, 768, 1024, 1031, 1536, 2048, 2049] {
            let mut rng = HmacDrbg::<Sha256>::new(b"sizes", &bits.to_be_bytes(), &[]);
            let key = BoxedRsaPrivateKey::generate(bits, BoxedUint::from_u64(65537), &mut rng, 4);
            let pk = key.public_key();
            let k = key.k;
            for j in 0..3u8 {
                let mut msg = vec![0u8; k];
                for (i, b) in msg.iter_mut().enumerate().skip(1) {
                    *b = (i as u8).wrapping_mul(31).wrapping_add(j);
                }
                let c = pk.raw_public(&msg).unwrap();
                assert_eq!(key.raw_private(&c).unwrap(), msg, "bits={bits} j={j}");
                let s = key.raw_private(&msg).unwrap();
                assert_eq!(pk.raw_public(&s).unwrap(), msg, "bits={bits} j={j}");
            }
        }
    }

    /// Concurrent signing with one key: threads race for the blinding
    /// cache, the losers take the stateless path, and every signature is
    /// still the deterministic PKCS#1 v1.5 one.
    #[cfg(feature = "std")]
    #[test]
    fn concurrent_signing_with_shared_cache() {
        let key = std::sync::Arc::new(gen_small_key(b"blinding-threads"));
        let sig0 = key.sign_pkcs1v15::<Sha256>(b"threads").unwrap();
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let key = key.clone();
                let sig0 = sig0.clone();
                std::thread::spawn(move || {
                    for _ in 0..40 {
                        assert_eq!(key.sign_pkcs1v15::<Sha256>(b"threads").unwrap(), sig0);
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
    }
}
