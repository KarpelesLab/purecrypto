//! Falcon (FN-DSA) signatures — Falcon-512 and Falcon-1024: key generation,
//! signing, and verification.
//!
//! Falcon is the NTRU-lattice hash-and-sign signature scheme selected by NIST
//! for standardization as FN-DSA (FIPS 206, draft). This module implements the
//! full scheme: [`FalconPrivateKey::generate`] / [`FalconPrivateKey::sign`] and
//! the [`verify`] / [`FalconPublicKey`] verification path.
//!
//! **Floating point.** Signing needs an FFT, an LDL tree, and a discrete
//! Gaussian sampler — all floating-point — but the crate is `no_std` with no
//! `libm`, and the signing path is secret-dependent. So all FP runs in an
//! emulated constant-time IEEE-754 double (`fpr`, the approach Falcon's
//! reference calls FPEMU): pure integer ops, data-oblivious, identical on every
//! target (no FPU required), and bit-reproducible.
//!
//! **Constant-time scope.** The **signing path is strictly constant-time** (the
//! sampler and all FFT/tree arithmetic on secrets are data-oblivious). **Key
//! generation is best-effort** — NTRUSolve's big-integer arithmetic and the
//! Gaussian-rejection retries are variable-time (as in the reference); keygen is
//! one-time, on fresh entropy. **Verification** takes only public inputs, never
//! panics on malformed input (every access is bounds-checked), and returns
//! `false`/`Err` instead.
//!
//! Verification needs only SHAKE-256 (for `HashToPoint`) and integer arithmetic
//! modulo `q = 12289`.
//!
//! Implemented against the Falcon specification v1.2 (2020-10-01), the document
//! underlying the NIST round-3 submission and the FN-DSA draft:
//!
//! * `HashToPoint` — spec §3.7, Algorithm 3.
//! * `Verify` — spec §3.10, Algorithm 16.
//! * `Decompress` (signature `s`) — spec §3.11.2, Algorithm 18, including the
//!   three canonicality checks (fixed bit length, no `100000001` encoding of
//!   zero, trailing bits must be zero).
//! * Public-key / signature encoding — spec §3.11.3–3.11.4.
//! * Parameters (`q`, `⌊β²⌋`, byte lengths) — spec §3.13, Table 3.3.
//!
//! # Example
//!
//! ```ignore
//! use purecrypto::falcon::verify;
//! let ok = verify(public_key, message, signature);
//! ```

#![allow(clippy::needless_range_loop)]

mod encode;
mod fft;
mod fpr;
#[cfg(feature = "key")]
mod key_impl;
mod keygen;
mod sampler;
mod sign;
mod tree;
mod zint;

use crate::hash::{ExtendableOutput, Shake256, XofReader};

/// Falcon modulus `q`.
const Q: u32 = 12289;

/// `k = ⌊2¹⁶ / q⌋`; the `HashToPoint` rejection threshold is `k·q`
/// (spec §3.7, Algorithm 3, line 1).
const HASH_REJECT: u32 = 5 * Q; // 61445

/// Errors returned by Falcon parsing/verification helpers.
///
/// The top-level [`verify`] function maps every failure to `false`; the typed
/// API ([`FalconPublicKey::verify`]) surfaces these so callers can distinguish
/// a malformed key from a signature that simply did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A public key, signature, or one of their fields had the wrong length.
    InvalidLength,
    /// A header byte, packing, or encoding was structurally invalid.
    Malformed,
}

/// A Falcon parameter set (degree).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Degree {
    /// Falcon-512 (`n = 512`, NIST level I).
    Falcon512,
    /// Falcon-1024 (`n = 1024`, NIST level V).
    Falcon1024,
}

impl Degree {
    /// Ring degree `n`.
    const fn n(self) -> usize {
        match self {
            Degree::Falcon512 => 512,
            Degree::Falcon1024 => 1024,
        }
    }

    /// Encoded public-key length, in bytes (spec §3.13).
    ///
    /// `1` header byte `+ ⌈14·n / 8⌉` for the 14-bit-packed `h`.
    const fn pubkey_len(self) -> usize {
        match self {
            Degree::Falcon512 => 897,
            Degree::Falcon1024 => 1793,
        }
    }

    /// Full padded signature length `sbytelen`, in bytes (spec §3.13).
    const fn sig_len(self) -> usize {
        match self {
            Degree::Falcon512 => 666,
            Degree::Falcon1024 => 1280,
        }
    }

    /// Acceptance bound `⌊β²⌋` (spec §3.13, Table 3.3).
    const fn sig_bound(self) -> u64 {
        match self {
            Degree::Falcon512 => 34_034_726,
            Degree::Falcon1024 => 70_265_242,
        }
    }

    /// The `logn` nibble used in encoding headers (`log₂ n`).
    const fn logn(self) -> u8 {
        match self {
            Degree::Falcon512 => 9,
            Degree::Falcon1024 => 10,
        }
    }

    /// Recover the parameter set from a header `logn` nibble.
    const fn from_logn(logn: u8) -> Option<Degree> {
        match logn {
            9 => Some(Degree::Falcon512),
            10 => Some(Degree::Falcon1024),
            _ => None,
        }
    }
}

/// Length of the salt/nonce `r` prepended to the message before hashing.
const NONCE_LEN: usize = 40;

/// A parsed Falcon public key: the polynomial `h` with `n` coefficients in
/// `[0, q)`, plus its degree.
pub struct FalconPublicKey {
    degree: Degree,
    /// `h`, `n` coefficients, each already reduced into `[0, q)`.
    h: alloc::vec::Vec<u16>,
}

use alloc::vec::Vec;

impl FalconPublicKey {
    /// Parse an encoded Falcon public key (spec §3.11.4).
    ///
    /// The first byte is a header `0000nnnn`; the four high bits must be zero
    /// and `nnnn` selects the degree. The remaining `⌈14n/8⌉` bytes pack the
    /// `n` coefficients of `h` at 14 bits each, big-endian within the bit
    /// stream. Every coefficient must lie in `[0, q)`.
    pub fn from_bytes(pk: &[u8]) -> Result<FalconPublicKey, Error> {
        let header = *pk.first().ok_or(Error::InvalidLength)?;
        // Header must be exactly 0000nnnn (top nibble zero).
        if header & 0xF0 != 0x00 {
            return Err(Error::Malformed);
        }
        let degree = Degree::from_logn(header & 0x0F).ok_or(Error::Malformed)?;
        let n = degree.n();

        if pk.len() != degree.pubkey_len() {
            return Err(Error::InvalidLength);
        }

        let body = &pk[1..];
        // Unpack n 14-bit big-endian values from `body`.
        let mut h = Vec::with_capacity(n);
        let mut acc: u32 = 0;
        let mut acc_bits: u32 = 0;
        let mut idx = 0usize;
        while h.len() < n {
            // Refill the accumulator until at least 14 bits are buffered.
            while acc_bits < 14 {
                let byte = *body.get(idx).ok_or(Error::InvalidLength)?;
                idx += 1;
                acc = (acc << 8) | byte as u32;
                acc_bits += 8;
            }
            acc_bits -= 14;
            let coeff = (acc >> acc_bits) & 0x3FFF;
            if coeff >= Q {
                return Err(Error::Malformed);
            }
            h.push(coeff as u16);
        }

        // Any leftover bits (the padding tail of the final byte) must be zero,
        // and there must be no trailing bytes — both already implied by the
        // exact-length check plus consuming `idx` up to the end. Enforce the
        // padding-bits-zero rule for canonicality.
        let leftover_mask = if acc_bits == 0 {
            0
        } else {
            (1u32 << acc_bits) - 1
        };
        if acc & leftover_mask != 0 {
            return Err(Error::Malformed);
        }
        // All input bytes must have been consumed.
        if idx != body.len() {
            return Err(Error::Malformed);
        }

        Ok(FalconPublicKey { degree, h })
    }

    /// The parameter set (degree) of this key.
    pub fn degree(&self) -> Degree {
        self.degree
    }

    /// Verify `sig` over `msg` under this public key.
    ///
    /// Returns `Ok(true)` for a valid signature, `Ok(false)` for a
    /// well-formed-but-invalid one, and `Err` if the signature is structurally
    /// malformed (wrong length, bad header, non-canonical compression). Never
    /// panics.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> Result<bool, Error> {
        let n = self.degree.n();

        // --- Parse signature header. ---
        //
        // Falcon defines two on-the-wire encodings of the compressed signature
        // (spec §3.11.3 / §3.11.6):
        //
        //   * **Padded**: header byte `0011nnnn` (`0x30 + logn`); the whole
        //     signature is a fixed `sbytelen` bytes, the compressed `s` being
        //     zero-padded up to that length (`Degree::sig_len`).
        //   * **Compressed / unpadded**: header byte `0010nnnn`
        //     (`0x20 + logn`); the signature is variable length, exactly
        //     `1 + 40 + |compressed-s|` bytes — this is what the NIST KAT
        //     vectors carry.
        //
        // Both wrap `header || nonce(40) || compressed-s`. We accept either.
        let header = *sig.first().ok_or(Error::InvalidLength)?;
        if Degree::from_logn(header & 0x0F) != Some(self.degree) {
            return Err(Error::Malformed);
        }
        match header & 0xF0 {
            0x30 => {
                // Padded: must be exactly sbytelen, with zero-byte tail (the
                // trailing-bit-zero check in `decompress` enforces canonicality
                // of that padding).
                if sig.len() != self.degree.sig_len() {
                    return Err(Error::InvalidLength);
                }
            }
            0x20 => {
                // Unpadded: just needs room for the header + nonce, and must
                // not exceed the padded length.
                if sig.len() <= 1 + NONCE_LEN || sig.len() > self.degree.sig_len() {
                    return Err(Error::InvalidLength);
                }
            }
            _ => return Err(Error::Malformed),
        }

        let nonce = &sig[1..1 + NONCE_LEN];
        let s_bytes = &sig[1 + NONCE_LEN..];

        // --- Decompress s -> s2 (n signed coefficients), canonical. ---
        let s2 = match decompress(s_bytes, n) {
            Some(v) => v,
            None => return Ok(false),
        };

        // --- c = HashToPoint(nonce || msg). ---
        let c = hash_to_point(nonce, msg, n);

        // --- s1 = c - s2*h mod q, centered; accumulate ||(s1, s2)||^2. ---
        // Compute s2*h mod (x^n + 1) mod q via schoolbook negacyclic convolution.
        let prod = poly_mul_mod_q(&s2, &self.h, n);

        let bound = self.degree.sig_bound();
        let mut norm: u64 = 0;
        for i in 0..n {
            // s1_i = c_i - prod_i (mod q), then centered to (-q/2, q/2].
            let mut v = c[i] as i32 - prod[i] as i32;
            v = v.rem_euclid(Q as i32); // in [0, q)
            let centered = center(v as u32);
            norm += (centered as i64 * centered as i64) as u64;

            // s2 is already a centered signed value.
            let s2v = s2[i] as i64;
            norm += (s2v * s2v) as u64;

            if norm > bound {
                return Ok(false);
            }
        }

        Ok(norm <= bound)
    }
}

/// Center a value `v ∈ [0, q)` into the symmetric range `(-q/2, q/2]`.
#[inline]
fn center(v: u32) -> i32 {
    let v = v as i32;
    if v > (Q as i32) / 2 { v - Q as i32 } else { v }
}

/// `HashToPoint(r ‖ msg, q, n)` — spec §3.7, Algorithm 3.
///
/// Absorbs `nonce ‖ msg` into SHAKE-256, then squeezes 16 bits at a time
/// (big-endian), rejecting any draw `≥ 5q` and reducing the rest mod `q`,
/// until `n` coefficients are produced.
fn hash_to_point(nonce: &[u8], msg: &[u8], n: usize) -> Vec<u16> {
    let mut xof = Shake256::new();
    xof.update(nonce);
    xof.update(msg);
    let mut reader = xof.finalize_xof();

    let mut c = Vec::with_capacity(n);
    let mut buf = [0u8; 2];
    while c.len() < n {
        reader.read(&mut buf);
        let t = ((buf[0] as u32) << 8) | buf[1] as u32;
        if t < HASH_REJECT {
            c.push((t % Q) as u16);
        }
    }
    c
}

/// Schoolbook negacyclic polynomial multiplication mod `q`:
/// returns `(a · b) mod (x^n + 1) mod q`, with coefficients in `[0, q)`.
///
/// `a` holds signed coefficients (the decompressed `s2`); `b` holds the
/// already-reduced unsigned `h`. `O(n²)` — fine for verification.
fn poly_mul_mod_q(a: &[i16], b: &[u16], n: usize) -> Vec<u16> {
    // Accumulate in i64 to avoid overflow: |a_i| < q, b_j < q, n ≤ 1024, so the
    // partial sums stay well within i64.
    let mut acc = alloc::vec![0i64; n];
    for i in 0..n {
        let ai = a[i] as i64;
        if ai == 0 {
            continue;
        }
        for j in 0..n {
            let term = ai * b[j] as i64;
            let k = i + j;
            if k < n {
                acc[k] += term;
            } else {
                // x^n = -1 in the ring, so wrap with a sign flip.
                acc[k - n] -= term;
            }
        }
    }
    let q = Q as i64;
    acc.iter().map(|&v| v.rem_euclid(q) as u16).collect()
}

/// `Decompress(str, slen)` for the signature polynomial `s` — spec §3.11.2,
/// Algorithm 18, with all three canonicality checks.
///
/// `s_bytes` is the byte region following the nonce in the signature; the bit
/// length `slen = 8·sbytelen − 328` is therefore `8 · s_bytes.len()`. Returns
/// `None` (the spec's `⊥`) on any malformed / non-canonical input.
fn decompress(s_bytes: &[u8], n: usize) -> Option<Vec<i16>> {
    // A bit cursor over `s_bytes`, MSB-first within each byte.
    let total_bits = s_bytes.len() * 8;
    let mut pos = 0usize;

    // Read one bit at the cursor, advancing it. Returns None past the end.
    let get_bit = |s: &[u8], p: &mut usize| -> Option<u32> {
        if *p >= total_bits {
            return None;
        }
        let byte = s[*p >> 3];
        let bit = (byte >> (7 - (*p & 7))) & 1;
        *p += 1;
        Some(bit as u32)
    };

    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        // Sign bit.
        let sign = get_bit(s_bytes, &mut pos)?;
        // 7 low bits, most-significant first.
        let mut low: u32 = 0;
        for _ in 0..7 {
            low = (low << 1) | get_bit(s_bytes, &mut pos)?;
        }
        // Unary high bits: count zeros until a terminating 1.
        let mut high: u32 = 0;
        loop {
            let b = get_bit(s_bytes, &mut pos)?;
            if b == 1 {
                break;
            }
            high += 1;
            // Guard against absurdly long runs (coefficient magnitudes are
            // small in any valid signature); also prevents overflow.
            if high > 2048 {
                return None;
            }
        }

        let magnitude = (high << 7) | low;
        // Canonical: reject the encoding "1 0000000 1" of zero (sign=1, mag=0),
        // i.e. a negative zero. (Spec §3.11.2 check 2 / Alg 18 lines 9-10.)
        if magnitude == 0 && sign == 1 {
            return None;
        }
        let val = if sign == 1 {
            -(magnitude as i32)
        } else {
            magnitude as i32
        };
        // Coefficients of a valid Falcon signature fit comfortably in i16.
        if !(-(i16::MAX as i32)..=i16::MAX as i32).contains(&val) {
            return None;
        }
        out.push(val as i16);
    }

    // Canonical: every remaining bit must be zero (Alg 18 lines 12-13).
    while pos < total_bits {
        if get_bit(s_bytes, &mut pos)? != 0 {
            return None;
        }
    }

    Some(out)
}

/// A Falcon secret key: the NTRU polynomials `(f, g, F, G)`, the public key
/// `h`, and a cached expanded form (FFT basis + LDL tree) for fast signing.
///
/// Generation and signing require a CSPRNG. The secret polynomials are wiped on
/// drop. The signing path is constant-time; key generation is one-time and
/// best-effort (it samples and solves the NTRU equation with variable-time
/// big-integer arithmetic).
pub struct FalconPrivateKey {
    degree: Degree,
    f: Vec<i64>,
    g: Vec<i64>,
    cap_f: Vec<i64>,
    cap_g: Vec<i64>,
    h: Vec<u16>,
    expanded: sign::ExpandedKey,
}

/// Adapts a [`crate::rng::RngCore`] CSPRNG to the sampler's byte-source trait.
struct RngBytes<'a, R>(&'a mut R);

impl<R: crate::rng::RngCore> sampler::SamplerRng for RngBytes<'_, R> {
    fn next_bytes(&mut self, buf: &mut [u8]) {
        self.0.fill_bytes(buf);
    }
}

impl FalconPrivateKey {
    /// Generate a fresh Falcon key of the given degree from a CSPRNG.
    pub fn generate<R: crate::rng::RngCore + crate::rng::CryptoRng>(
        degree: Degree,
        rng: &mut R,
    ) -> FalconPrivateKey {
        let n = degree.n();
        let (f, g, cap_f, cap_g, h) = {
            let mut src = RngBytes(rng);
            keygen::ntru_gen(n, &mut src)
        };
        let expanded = sign::expand_key(&f, &g, &cap_f, &cap_g, degree);
        FalconPrivateKey {
            degree,
            f,
            g,
            cap_f,
            cap_g,
            h,
            expanded,
        }
    }

    /// The parameter set of this key.
    pub fn degree(&self) -> Degree {
        self.degree
    }

    /// Sign `msg`, returning an encoded Falcon signature (padded format,
    /// `header || salt || compressed-s`). Draws a fresh salt and sampler
    /// randomness from `rng`; the per-signature path is constant-time.
    pub fn sign<R: crate::rng::RngCore + crate::rng::CryptoRng>(
        &self,
        msg: &[u8],
        rng: &mut R,
    ) -> Vec<u8> {
        let mut salt = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut salt);
        let mut src = RngBytes(rng);
        sign::sign_internal(&self.expanded, msg, &salt, &mut src)
    }

    /// The matching public key.
    pub fn public_key(&self) -> FalconPublicKey {
        FalconPublicKey {
            degree: self.degree,
            h: self.h.clone(),
        }
    }

    /// The encoded public key bytes (header + 14-bit-packed `h`).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        encode::encode_pubkey(&self.h, self.degree.logn())
    }

    /// Serialize to the compact secret-key encoding (`0101nnnn` header, then
    /// `f`, `g`, `F`; `G` is recomputed on import).
    pub fn to_bytes(&self) -> Vec<u8> {
        encode::encode_privkey(&self.f, &self.g, &self.cap_f, self.degree.logn())
    }

    /// Parse a compact secret-key encoding, recomputing `G` and `h` and
    /// rebuilding the expanded form. Returns `Err` if the key is malformed or
    /// `f` is not invertible mod `q`.
    pub fn from_bytes(sk: &[u8]) -> Result<FalconPrivateKey, Error> {
        let header = *sk.first().ok_or(Error::InvalidLength)?;
        if header & 0xF0 != 0x50 {
            return Err(Error::Malformed);
        }
        let degree = Degree::from_logn(header & 0x0F).ok_or(Error::Malformed)?;
        let n = degree.n();
        let (f, g, cap_f) = encode::decode_privkey(sk, n).ok_or(Error::InvalidLength)?;
        let h = keygen::compute_h(&f, &g, n).ok_or(Error::Malformed)?;
        let cap_g = keygen::recompute_g(&f, &g, &cap_f, n);
        let expanded = sign::expand_key(&f, &g, &cap_f, &cap_g, degree);
        Ok(FalconPrivateKey {
            degree,
            f,
            g,
            cap_f,
            cap_g,
            h,
            expanded,
        })
    }
}

impl Drop for FalconPrivateKey {
    fn drop(&mut self) {
        // Wipe the secret polynomials; route through black_box so the writes are
        // not elided (same pattern as the RSA/ML-DSA private keys).
        for v in [&mut self.f, &mut self.g, &mut self.cap_f, &mut self.cap_g] {
            for x in v.iter_mut() {
                *x = 0;
            }
            let _ = core::hint::black_box(&*v);
        }
    }
}

/// Verify a Falcon signature.
///
/// `pk` is an encoded Falcon public key (header + packed `h`), `msg` the signed
/// message, and `sig` an encoded compressed Falcon signature (header + 40-byte
/// nonce + compressed `s`). The parameter set (Falcon-512 vs Falcon-1024) is
/// detected from the public-key header and cross-checked against the signature
/// header.
///
/// Returns `true` iff the signature is valid. Any malformed input, length
/// mismatch, non-canonical encoding, or failed bound check yields `false`.
/// Never panics.
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match FalconPublicKey::from_bytes(pk) {
        Ok(key) => key.verify(msg, sig).unwrap_or(false),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests;
