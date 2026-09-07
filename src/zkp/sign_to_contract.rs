//! ECDSA sign-to-contract: commit to arbitrary data inside a signature's nonce.
//!
//! **EXPERIMENTAL** — no semver-stability guarantee. See the [module-level
//! documentation](super) for the clean-room policy and interop caveats.
//!
//! # The construction
//!
//! Sign-to-contract (the signing-side twin of pay-to-contract, as used by
//! OpenTimestamps) hides a commitment to arbitrary `data` inside an ECDSA
//! signature's nonce. The signature still verifies as an ordinary ECDSA
//! signature, is indistinguishable from one, and costs **zero extra bytes**
//! on-chain; anyone holding the *opening* can additionally check that it
//! commits to `data`.
//!
//! Signing, with `G` the secp256k1 generator and `n` the group order:
//!
//! 1. derive the original nonce `k₁` (deterministically, see below) and set
//!    `R₁ = k₁·G`;
//! 2. compute the tweak `t = H(ser(R₁) ‖ data) mod n`;
//! 3. set `k₂ = k₁ + t mod n` and sign with `k₂` as the ECDSA nonce, so that
//!    `R₂ = k₂·G = R₁ + t·G`;
//! 4. publish the signature plus the *opening* `R₁`.
//!
//! Verifying the commitment needs only the signature, `data` and `R₁`:
//! recompute `R₂' = R₁ + H(ser(R₁) ‖ data)·G` and check
//! `x(R₂') mod n == r`. It does **not** need the public key or the message —
//! a signature can carry a valid commitment without being a valid signature,
//! which is why [`verify_commitment`] and [`verify_signature`] are separate.
//!
//! Binding follows from `H` being collision-resistant and from the signer
//! being unable to choose `t` after seeing `R₁`: changing `data` changes `t`,
//! which moves `R₂` to an essentially random point, so `r` no longer matches.
//!
//! # Exact choices
//!
//! These match Blockstream's `secp256k1-zkp` byte for byte (see **Interop**):
//!
//! - **Hash `H`** — the BIP340-style tagged SHA-256
//!   `H(m) = SHA256(SHA256(tag) ‖ SHA256(tag) ‖ m)` with the ASCII tag
//!   `"s2c/ecdsa/point"`, over `m = ser(R₁) ‖ data`, reduced mod `n`.
//! - **Point serialization** — `ser(·)` is the 33-byte **compressed** SEC1
//!   encoding (`0x02`/`0x03 ‖ X`).
//! - **Data** — exactly 32 bytes. Commit to a longer message by hashing it
//!   first.
//! - **Nonce `k₁`** — RFC 6979 with HMAC-SHA-256: the HMAC-DRBG is seeded with
//!   `seckey ‖ bits2octets(msg32) ‖ aux`, where `bits2octets(msg32)` is the
//!   message digest reduced mod `n` and the auxiliary 32 bytes are
//!   `aux = SHA256_tagged("s2c/ecdsa/data", data)` — the same value the
//!   anti-exfil protocol calls the *host commitment*. Committing `data` into
//!   the nonce derivation as well as into the tweak is what makes the scheme
//!   safe to reuse across different `data` for one `(key, message)` pair:
//!   without it, two openings for one message would share `k₁` and leak the
//!   private key.
//! - **S normalization** — the returned signature is always **low-S**
//!   (`s ≤ (n−1)/2`), as libsecp256k1 produces. Whether `s` was negated is
//!   recorded in [`Opening::nonce_negated`]; it is *not* needed to verify the
//!   commitment, because negating `s` corresponds to negating `R₂`, and
//!   `x(−P) = x(P)`.
//!
//! # Opening layout
//!
//! [`Opening::to_bytes`] returns the 33 bytes that `secp256k1-zkp`'s
//! `secp256k1_ecdsa_s2c_opening_serialize` returns: the compressed `R₁`. The
//! reference's in-memory opening also carries the negation flag, but its
//! 33-byte serialization does not, and its `verify_commit` does not use it —
//! so [`Opening::from_bytes`] restores the flag as `false`. Use
//! [`Opening::from_parts`] to carry it explicitly.
//!
//! # Interop
//!
//! **Verified.** The tag, the hash input layout, the opening layout and the
//! nonce derivation above were established by driving `secp256k1-zkp` as a
//! black-box oracle through its **public C API** only
//! (`secp256k1_ecdsa_s2c_sign`, `secp256k1_ecdsa_s2c_opening_serialize`,
//! `secp256k1_ecdsa_s2c_verify_commit`,
//! `secp256k1_ecdsa_anti_exfil_host_commit`) and comparing its output bytes
//! against candidate constructions. No implementation source was read; only
//! `include/secp256k1_ecdsa_s2c.h`, which is the interface contract.
//!
//! `tools/zkp-interop/vectors/sign_to_contract.json` holds 14 oracle-generated
//! vectors, and the test `interop_vectors` in this module checks that
//! [`sign_with_commitment`] reproduces the oracle's 64-byte signature *and*
//! 33-byte opening exactly, for every one of them. The test reads the JSON; it
//! never links against the oracle.
//!
//! **Not verified:** behaviour on the cryptographically unreachable edge cases
//! (a tweak or tweaked nonce that overflows `n`, `r = 0`, `s = 0`) — the
//! oracle cannot be steered into them — and the anti-exfil protocol as a
//! whole, of which only the host-commitment hash is used here.
//!
//! # Source of truth
//!
//! Pay-to-contract / sign-to-contract as described by OpenTimestamps and
//! Eternity Wall: the map `(P, m) ↦ P + H(P ‖ m)·G` is a binding commitment,
//! applied here to the signature nonce point.

use crate::ct::ConstantTimeEq;
use crate::ec::Error;
use crate::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use crate::hash::{Digest, Hmac, Sha256};

/// Tag for the nonce tweak `t = H(ser(R₁) ‖ data)`.
const TAG_POINT: &[u8] = b"s2c/ecdsa/point";

/// Tag for the auxiliary randomness folded into the RFC 6979 nonce derivation
/// (the anti-exfil protocol's *host commitment*).
const TAG_DATA: &[u8] = b"s2c/ecdsa/data";

/// `(n − 1) / 2`, big-endian: the largest low-S value.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// The opening of a sign-to-contract commitment: the original, untweaked nonce
/// point `R₁ = k₁·G`, plus the low-S negation flag.
///
/// The 33 bytes of [`to_bytes`](Self::to_bytes) are all a verifier needs; the
/// flag is bookkeeping for callers that want to reconstruct the effective
/// nonce point `R₂` exactly (see the [module docs](self#opening-layout)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opening {
    /// Compressed SEC1 encoding of `R₁`. Always a valid, non-identity point:
    /// every constructor validates it.
    r1: [u8; 33],
    /// Whether the signature's `s` was negated by low-S normalization, i.e.
    /// whether the effective nonce point is `−R₂` rather than `R₂`.
    nonce_negated: bool,
}

impl Opening {
    /// Parses a 33-byte opening — the compressed original nonce point `R₁`,
    /// matching `secp256k1_ecdsa_s2c_opening_parse`.
    ///
    /// The negation flag is not carried by this encoding and is set to
    /// `false`; use [`from_parts`](Self::from_parts) to supply it.
    ///
    /// # Errors
    /// [`Error::Malformed`] for a bad SEC1 tag byte, [`Error::InvalidInput`]
    /// if the bytes do not decode to a point on secp256k1.
    pub fn from_bytes(bytes: &[u8; 33]) -> Result<Opening, Error> {
        Opening::from_parts(bytes, false)
    }

    /// Builds an opening from the compressed original nonce point and an
    /// explicit negation flag.
    ///
    /// # Errors
    /// As [`from_bytes`](Self::from_bytes).
    pub fn from_parts(r1: &[u8; 33], nonce_negated: bool) -> Result<Opening, Error> {
        AffinePoint::from_sec1(r1)?;
        Ok(Opening {
            r1: *r1,
            nonce_negated,
        })
    }

    /// The 33-byte serialization: the compressed original nonce point `R₁`.
    ///
    /// Byte-identical to `secp256k1_ecdsa_s2c_opening_serialize`.
    pub fn to_bytes(&self) -> [u8; 33] {
        self.r1
    }

    /// Whether the signature's `s` was negated during low-S normalization.
    ///
    /// Irrelevant to [`verify_commitment`] — negating `s` negates the
    /// effective nonce point, and negation preserves the x-coordinate the
    /// commitment check compares.
    pub fn nonce_negated(&self) -> bool {
        self.nonce_negated
    }
}

/// BIP340-style tagged SHA-256: `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ parts…)`.
fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(tag_hash.as_ref());
    h.update(tag_hash.as_ref());
    for part in parts {
        h.update(part);
    }
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// The anti-exfil *host commitment* to `data`, which doubles as the auxiliary
/// randomness of the sign-to-contract nonce derivation
/// (`secp256k1_ecdsa_anti_exfil_host_commit`).
fn host_commit(data32: &[u8; 32]) -> [u8; 32] {
    tagged_hash(TAG_DATA, &[data32])
}

/// The nonce tweak `t = H(ser(R₁) ‖ data) mod n`.
fn nonce_tweak(r1_ser: &[u8; 33], data32: &[u8; 32]) -> Scalar {
    Scalar::from_bytes_be_reduce(&tagged_hash(TAG_POINT, &[r1_ser, data32]))
}

/// RFC 6979 deterministic nonce: an HMAC-SHA-256 DRBG seeded with
/// `seckey ‖ bits2octets(msg) ‖ aux`, retried until the output is a valid
/// scalar in `[1, n)`.
///
/// `msg32_reduced` must already be the message scalar reduced mod `n` (RFC
/// 6979 `bits2octets`) — that is what libsecp256k1 feeds its nonce function,
/// and it only differs from the raw digest when the digest is `>= n`.
fn rfc6979_nonce(seckey: &[u8; 32], msg32_reduced: &[u8; 32], aux: &[u8; 32]) -> Scalar {
    let mut seed = [0u8; 96];
    seed[..32].copy_from_slice(seckey);
    seed[32..64].copy_from_slice(msg32_reduced);
    seed[64..].copy_from_slice(aux);

    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];

    // K = HMAC_K(V ‖ sep ‖ seed); V = HMAC_K(V), for sep in {0x00, 0x01}.
    for &sep in &[0x00u8, 0x01u8] {
        let mut mac = Hmac::<Sha256>::new(&k);
        mac.update(&v);
        mac.update(&[sep]);
        mac.update(&seed);
        let out = mac.finalize();
        k.copy_from_slice(out.as_ref());
        let out = Hmac::<Sha256>::mac(&k, &v);
        v.copy_from_slice(out.as_ref());
    }

    let mut retry = false;
    let nonce = loop {
        if retry {
            let mut mac = Hmac::<Sha256>::new(&k);
            mac.update(&v);
            mac.update(&[0x00]);
            let out = mac.finalize();
            k.copy_from_slice(out.as_ref());
            let out = Hmac::<Sha256>::mac(&k, &v);
            v.copy_from_slice(out.as_ref());
        }
        let out = Hmac::<Sha256>::mac(&k, &v);
        v.copy_from_slice(out.as_ref());
        retry = true;

        let mut candidate = [0u8; 32];
        candidate.copy_from_slice(&v);
        let parsed = Scalar::from_bytes_be(&candidate);
        candidate.fill(0);
        let _ = core::hint::black_box(&candidate);
        if let Ok(scalar) = parsed
            && !bool::from(scalar.is_zero())
        {
            break scalar;
        }
    };

    // The seed is a verbatim copy of the private key and the DRBG state
    // reproduces the nonce; wipe both, with a `black_box` barrier so the
    // stores are not elided (the idiom used by `ec::ecdsa::generate_k`).
    seed.fill(0);
    k.fill(0);
    v.fill(0);
    let _ = core::hint::black_box((&seed, &k, &v));
    nonce
}

/// Branch-free big-endian "greater than" over 32-byte values: returns `0xff`
/// if `a > b`, else `0x00`.
fn ct_gt_mask(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    let mut gt = 0u8;
    let mut eq = 1u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        // 1 iff x > y (the borrow bit of y − x).
        let x_gt = (((y as u16).wrapping_sub(x as u16) >> 8) & 1) as u8;
        // 1 iff x == y.
        let x_eq = ((((x ^ y) as u16).wrapping_sub(1) >> 8) & 1) as u8;
        gt |= x_gt & eq;
        eq &= x_eq;
    }
    gt.wrapping_neg()
}

/// Signs `msg32` under `seckey` with a sign-to-contract commitment to
/// `data32`, returning the 64-byte compact signature `r ‖ s` and its opening.
///
/// The signature is an ordinary secp256k1 ECDSA signature — it verifies with
/// [`verify_signature`], or with any other ECDSA verifier — and is
/// deterministic: the same inputs always produce the same output, byte for
/// byte, including the same bytes `secp256k1-zkp`'s `secp256k1_ecdsa_s2c_sign`
/// produces. `s` is always in low-S form.
///
/// `data32` is exactly 32 bytes; hash longer payloads down to 32 bytes first.
/// `msg32` is a message *digest*, not a message.
///
/// # Errors
/// [`Error::InvalidInput`] if `seckey` is not a valid scalar in `[1, n)`, or —
/// with negligible probability, and not reachable by an attacker who does not
/// know `seckey` — if the tweaked nonce, `r` or `s` comes out zero.
///
/// # Security
/// Never sign the same `(seckey, msg32, data32)` triple with two different
/// nonces, and never reuse a nonce: ECDSA leaks the private key if `k` repeats
/// across distinct messages. That is why the nonce here is fully deterministic
/// in all three inputs.
pub fn sign_with_commitment(
    seckey: &[u8; 32],
    msg32: &[u8; 32],
    data32: &[u8; 32],
) -> Result<([u8; 64], Opening), Error> {
    // `Scalar` wipes its limbs in `Drop` with a `black_box` barrier, so the
    // private key `d` and both nonces `k1` / `k2` are zeroized on every exit
    // path below, including the early `?` returns.
    let d = Scalar::from_bytes_be(seckey)?;
    if bool::from(d.is_zero()) {
        return Err(Error::InvalidInput);
    }
    let z = Scalar::from_bytes_be_reduce(msg32);

    // k1 = RFC6979(seckey, bits2octets(msg32), host_commit(data32)); R1 = k1·G.
    let k1 = rfc6979_nonce(seckey, &z.to_bytes_be(), &host_commit(data32));
    let r1 = ProjectivePoint::mul_generator(&k1)
        .to_affine()
        .ok_or(Error::InvalidInput)?;
    let r1_ser = r1.to_sec1_compressed();

    // k2 = k1 + H(ser(R1) ‖ data); R2 = k2·G = R1 + H(ser(R1) ‖ data)·G.
    let k2 = k1.add(&nonce_tweak(&r1_ser, data32));
    if bool::from(k2.is_zero()) {
        return Err(Error::InvalidInput);
    }
    let r2 = ProjectivePoint::mul_generator(&k2)
        .to_affine()
        .ok_or(Error::InvalidInput)?;

    let r = Scalar::from_bytes_be_reduce(&r2.x_bytes());
    if bool::from(r.is_zero()) {
        return Err(Error::InvalidInput);
    }

    // s = k2⁻¹ (z + r·d). The inversion must be constant time in the secret
    // nonce — `Scalar::invert` is Fermat over the constant-time ladder, not a
    // variable-time extended Euclid (Brumley–Tuveri).
    let s = k2.invert().mul(&z.add(&r.mul(&d)));
    if bool::from(s.is_zero()) {
        return Err(Error::InvalidInput);
    }

    // Low-S normalization, branch-free. `s` is a public output, so the flag
    // itself is not secret, but selecting rather than branching keeps the
    // signing path free of secret-dependent control flow by construction.
    let s_be = s.to_bytes_be();
    let neg_be = s.negate().to_bytes_be();
    let high = ct_gt_mask(&s_be, &HALF_ORDER);

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r.to_bytes_be());
    for (out, (&lo, &hi)) in sig[32..].iter_mut().zip(s_be.iter().zip(neg_be.iter())) {
        *out = (lo & !high) | (hi & high);
    }

    Ok((
        sig,
        Opening {
            r1: r1_ser,
            nonce_negated: high == 0xff,
        },
    ))
}

/// Verifies that `sig` commits to `data32` under `opening`.
///
/// This checks the *commitment* only: it needs neither the public key nor the
/// message, and says nothing about whether `sig` is a valid signature. Pair it
/// with [`verify_signature`] when both properties are wanted.
///
/// Never panics, for any input.
///
/// # Errors
/// [`Error::Verification`] if `sig`'s `r`/`s` are out of range or the
/// recomputed nonce point does not match `r`.
pub fn verify_commitment(
    sig: &[u8; 64],
    data32: &[u8; 32],
    opening: &Opening,
) -> Result<(), Error> {
    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);

    // Reject non-canonical (r, s) exactly as a compact-signature parser would.
    let r_scalar = Scalar::from_bytes_be(&r).map_err(|_| Error::Verification)?;
    let s_scalar = Scalar::from_bytes_be(&s).map_err(|_| Error::Verification)?;
    if bool::from(r_scalar.is_zero()) || bool::from(s_scalar.is_zero()) {
        return Err(Error::Verification);
    }

    // R2' = R1 + H(ser(R1) ‖ data)·G.
    let r1 = AffinePoint::from_sec1(&opening.r1).map_err(|_| Error::Verification)?;
    let tweak = nonce_tweak(&opening.r1, data32);
    let r2 = r1
        .to_projective()
        .add(&ProjectivePoint::mul_generator(&tweak))
        .to_affine()
        .ok_or(Error::Verification)?;

    let computed = Scalar::from_bytes_be_reduce(&r2.x_bytes()).to_bytes_be();
    if bool::from(computed.ct_eq(&r)) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

/// Verifies `sig` as an ordinary secp256k1 ECDSA signature over the digest
/// `msg32`, under the 33-byte compressed public key `pubkey`.
///
/// Provided so a caller can check the whole point of the scheme — that a
/// sign-to-contract signature is just a signature — without pulling in the
/// `alloc`-gated multi-curve `ec::boxed` path. Both `s`
/// and `n − s` are accepted, as ECDSA defines; require
/// `sig[32..] <= (n−1)/2` yourself if low-S is a protocol requirement.
///
/// Never panics, for any input.
///
/// # Errors
/// [`Error::Verification`] if the public key is not a valid point, `r`/`s` are
/// out of range, or the signature does not verify.
pub fn verify_signature(pubkey: &[u8; 33], msg32: &[u8; 32], sig: &[u8; 64]) -> Result<(), Error> {
    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    let mut s = [0u8; 32];
    s.copy_from_slice(&sig[32..]);

    let r_scalar = Scalar::from_bytes_be(&r).map_err(|_| Error::Verification)?;
    let s_scalar = Scalar::from_bytes_be(&s).map_err(|_| Error::Verification)?;
    if bool::from(r_scalar.is_zero()) || bool::from(s_scalar.is_zero()) {
        return Err(Error::Verification);
    }
    let q = AffinePoint::from_sec1(pubkey).map_err(|_| Error::Verification)?;

    let z = Scalar::from_bytes_be_reduce(msg32);
    let w = s_scalar.invert();
    let u1 = z.mul(&w);
    let u2 = r_scalar.mul(&w);

    let point = ProjectivePoint::mul_generator(&u1).add(&q.to_projective().mul(&u2));
    let affine = point.to_affine().ok_or(Error::Verification)?;
    let v = Scalar::from_bytes_be_reduce(&affine.x_bytes()).to_bytes_be();
    if bool::from(v.ct_eq(&r)) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

/// Derives the 33-byte compressed public key `seckey·G`.
///
/// # Errors
/// [`Error::InvalidInput`] if `seckey` is not a valid scalar in `[1, n)`.
pub fn public_key(seckey: &[u8; 32]) -> Result<[u8; 33], Error> {
    let d = Scalar::from_bytes_be(seckey)?;
    if bool::from(d.is_zero()) {
        return Err(Error::InvalidInput);
    }
    Ok(ProjectivePoint::mul_generator(&d)
        .to_affine()
        .ok_or(Error::InvalidInput)?
        .to_sec1_compressed())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle-generated interop vectors. Produced by driving `secp256k1-zkp`
    /// through its public C API; see `tools/zkp-interop/README.md`. The test
    /// reads this JSON and never links against the oracle.
    const VECTORS: &str = include_str!("../../tools/zkp-interop/vectors/sign_to_contract.json");

    fn hex_nibble(b: u8) -> u8 {
        match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => panic!("bad hex digit"),
        }
    }

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 2 * N, "expected {N} bytes of hex");
        let mut out = [0u8; N];
        for (i, o) in out.iter_mut().enumerate() {
            *o = (hex_nibble(bytes[2 * i]) << 4) | hex_nibble(bytes[2 * i + 1]);
        }
        out
    }

    /// Finds the next `"<name>": "<value>"` at or after `from`, returning the
    /// value and the offset just past it. Deliberately tiny — a real JSON
    /// parser would need `alloc`, which this module does not have.
    fn next_field<'a>(json: &'a str, from: usize, name: &str) -> Option<(&'a str, usize)> {
        let mut cursor = from;
        while let Some(offset) = json[cursor..].find(name) {
            let after = cursor + offset + name.len();
            cursor = after;
            let Some(rest) = json[after..].strip_prefix("\": \"") else {
                continue;
            };
            let end = rest.find('"')?;
            return Some((&rest[..end], after + 4 + end + 1));
        }
        None
    }

    struct Vector {
        seckey: [u8; 32],
        pubkey: [u8; 33],
        msg32: [u8; 32],
        data32: [u8; 32],
        host_commit: [u8; 32],
        opening33: [u8; 33],
        sig64: [u8; 64],
    }

    /// Walks the vector file, yielding one `Vector` per object. Fields are
    /// read in file order, so a single moving cursor is enough.
    fn vectors(mut f: impl FnMut(&Vector)) -> usize {
        let mut cursor = 0usize;
        let mut count = 0usize;
        while let Some((seckey, next)) = next_field(VECTORS, cursor, "seckey") {
            let (pubkey, next) = next_field(VECTORS, next, "pubkey33").expect("pubkey33");
            let (msg32, next) = next_field(VECTORS, next, "msg32").expect("msg32");
            let (data32, next) = next_field(VECTORS, next, "data32").expect("data32");
            let (hc, next) = next_field(VECTORS, next, "host_commit32").expect("host_commit32");
            let (opening, next) = next_field(VECTORS, next, "opening33").expect("opening33");
            let (sig, next) = next_field(VECTORS, next, "sig64").expect("sig64");
            f(&Vector {
                seckey: unhex(seckey),
                pubkey: unhex(pubkey),
                msg32: unhex(msg32),
                data32: unhex(data32),
                host_commit: unhex(hc),
                opening33: unhex(opening),
                sig64: unhex(sig),
            });
            count += 1;
            cursor = next;
        }
        count
    }

    /// Byte-exact interop with `secp256k1-zkp`: our signature, our opening and
    /// our host commitment must equal the oracle's, for every vector.
    #[test]
    fn interop_vectors() {
        let mut checked = 0;
        let n = vectors(|v| {
            assert_eq!(public_key(&v.seckey).unwrap(), v.pubkey, "public key");
            assert_eq!(host_commit(&v.data32), v.host_commit, "host commitment");

            let (sig, opening) = sign_with_commitment(&v.seckey, &v.msg32, &v.data32).unwrap();
            assert_eq!(sig, v.sig64, "signature bytes");
            assert_eq!(opening.to_bytes(), v.opening33, "opening bytes");

            // The oracle's own signature must verify and open under our code.
            verify_commitment(
                &v.sig64,
                &v.data32,
                &Opening::from_bytes(&v.opening33).unwrap(),
            )
            .unwrap();
            verify_signature(&v.pubkey, &v.msg32, &v.sig64).unwrap();
            checked += 1;
        });
        assert_eq!(n, checked);
        assert!(n >= 14, "expected at least 14 interop vectors, got {n}");
    }

    /// The oracle always returns low-S, so matching its bytes already proves
    /// our normalization; this pins the flag's meaning.
    #[test]
    fn low_s_normalization() {
        let mut seen_negated = false;
        let mut seen_plain = false;
        for i in 0u8..40 {
            let seckey = [i.wrapping_add(1); 32];
            let msg32 = [i ^ 0x5a; 32];
            let data32 = [i ^ 0xa5; 32];
            let (sig, opening) = sign_with_commitment(&seckey, &msg32, &data32).unwrap();
            let mut s = [0u8; 32];
            s.copy_from_slice(&sig[32..]);
            assert_eq!(ct_gt_mask(&s, &HALF_ORDER), 0x00, "s must be low");
            if opening.nonce_negated() {
                seen_negated = true;
            } else {
                seen_plain = true;
            }
            // The flag never affects the commitment check.
            let flipped =
                Opening::from_parts(&opening.to_bytes(), !opening.nonce_negated()).unwrap();
            verify_commitment(&sig, &data32, &flipped).unwrap();
        }
        assert!(seen_negated && seen_plain, "both negation cases must occur");
    }

    /// Round trip: the commitment opens, and the signature is still an
    /// ordinary ECDSA signature under the same key and message.
    #[test]
    fn round_trip_signature_still_valid() {
        let seckey = [0x11u8; 32];
        let msg32 = [0x22u8; 32];
        let data32 = [0x33u8; 32];
        let pubkey = public_key(&seckey).unwrap();

        let (sig, opening) = sign_with_commitment(&seckey, &msg32, &data32).unwrap();
        verify_commitment(&sig, &data32, &opening).unwrap();
        verify_signature(&pubkey, &msg32, &sig).unwrap();

        // Deterministic.
        let (sig2, opening2) = sign_with_commitment(&seckey, &msg32, &data32).unwrap();
        assert_eq!(sig, sig2);
        assert_eq!(opening, opening2);

        // Serialized opening round-trips.
        let parsed = Opening::from_bytes(&opening.to_bytes()).unwrap();
        verify_commitment(&sig, &data32, &parsed).unwrap();

        // A different `data` gives a different nonce, hence a different
        // signature: openings for one message never share a nonce.
        let (sig3, _) = sign_with_commitment(&seckey, &msg32, &[0x34u8; 32]).unwrap();
        assert_ne!(sig[..32], sig3[..32]);
    }

    /// The commitment binds: nothing but the committed `data`, with the
    /// matching opening and signature, opens it.
    #[test]
    fn commitment_binds() {
        let seckey = [0x0fu8; 32];
        let msg32 = [0x1eu8; 32];
        let data32 = [0x2du8; 32];
        let (sig, opening) = sign_with_commitment(&seckey, &msg32, &data32).unwrap();

        // Modified data, in every byte position.
        for i in 0..32 {
            let mut other = data32;
            other[i] ^= 1;
            assert_eq!(
                verify_commitment(&sig, &other, &opening),
                Err(Error::Verification),
                "data byte {i} must not open the commitment"
            );
        }

        // Modified opening: flip the parity byte, and perturb the x-coordinate.
        let mut ser = opening.to_bytes();
        ser[0] ^= 1;
        if let Ok(flipped) = Opening::from_bytes(&ser) {
            assert_eq!(
                verify_commitment(&sig, &data32, &flipped),
                Err(Error::Verification)
            );
        }
        for i in 1..33 {
            let mut ser = opening.to_bytes();
            ser[i] ^= 0x80;
            if let Ok(other) = Opening::from_bytes(&ser) {
                assert_eq!(
                    verify_commitment(&sig, &data32, &other),
                    Err(Error::Verification),
                    "opening byte {i}"
                );
            }
        }

        // A signature over a different message does not carry this commitment.
        let (other_sig, _) = sign_with_commitment(&seckey, &[0x1fu8; 32], &data32).unwrap();
        assert_eq!(
            verify_commitment(&other_sig, &data32, &opening),
            Err(Error::Verification)
        );

        // Nor does one from a different key.
        let (other_key_sig, _) = sign_with_commitment(&[0x10u8; 32], &msg32, &data32).unwrap();
        assert_eq!(
            verify_commitment(&other_key_sig, &data32, &opening),
            Err(Error::Verification)
        );

        // The signature itself must not verify under a wrong message or key.
        let pubkey = public_key(&seckey).unwrap();
        assert!(verify_signature(&pubkey, &[0x1fu8; 32], &sig).is_err());
        assert!(verify_signature(&public_key(&[0x10u8; 32]).unwrap(), &msg32, &sig).is_err());
    }

    /// Invalid secret keys are rejected rather than signed with.
    #[test]
    fn rejects_invalid_secret_keys() {
        let msg32 = [7u8; 32];
        let data32 = [8u8; 32];
        // Zero.
        assert_eq!(
            sign_with_commitment(&[0u8; 32], &msg32, &data32).unwrap_err(),
            Error::InvalidInput
        );
        assert_eq!(public_key(&[0u8; 32]).unwrap_err(), Error::InvalidInput);
        // n and above.
        let n: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];
        assert_eq!(
            sign_with_commitment(&n, &msg32, &data32).unwrap_err(),
            Error::InvalidInput
        );
        assert_eq!(
            sign_with_commitment(&[0xffu8; 32], &msg32, &data32).unwrap_err(),
            Error::InvalidInput
        );
    }

    /// Malformed openings and signatures must return `Err`, never panic.
    #[test]
    fn malformed_inputs_never_panic() {
        let seckey = [0x5au8; 32];
        let msg32 = [0x6bu8; 32];
        let data32 = [0x7cu8; 32];
        let (good_sig, good_opening) = sign_with_commitment(&seckey, &msg32, &data32).unwrap();
        let pubkey = public_key(&seckey).unwrap();

        // Every tag byte, over a fixed x, plus structured junk.
        for tag in 0u16..=255 {
            let mut ser = good_opening.to_bytes();
            ser[0] = tag as u8;
            if let Ok(o) = Opening::from_bytes(&ser) {
                let _ = verify_commitment(&good_sig, &data32, &o);
            }
        }

        // A deterministic byte-soup sweep over openings and signatures.
        let mut state = [0u8; 32];
        state.copy_from_slice(Sha256::digest(b"s2c-fuzz-seed").as_ref());
        for _ in 0..256 {
            let next = Sha256::digest(&state);
            state.copy_from_slice(next.as_ref());

            let mut ser = [0u8; 33];
            ser[0] = state[0];
            ser[1..].copy_from_slice(&state);
            let opening = Opening::from_bytes(&ser);

            let mut sig = [0u8; 64];
            sig[..32].copy_from_slice(&state);
            let flip = Sha256::digest(&state);
            sig[32..].copy_from_slice(flip.as_ref());

            // Openings: whatever parses must verify or fail, never panic.
            if let Ok(o) = opening {
                assert!(verify_commitment(&sig, &data32, &o).is_err());
                let _ = verify_commitment(&good_sig, &data32, &o);
            }
            // Signatures: garbage never verifies, and never panics.
            assert!(verify_commitment(&sig, &data32, &good_opening).is_err());
            assert!(verify_signature(&pubkey, &msg32, &sig).is_err());

            // Garbage public keys.
            let mut pk = [0u8; 33];
            pk[0] = state[31];
            pk[1..].copy_from_slice(&state);
            assert!(verify_signature(&pk, &msg32, &good_sig).is_err());
        }

        // All-zero and all-ones signatures.
        assert!(verify_commitment(&[0u8; 64], &data32, &good_opening).is_err());
        assert!(verify_commitment(&[0xffu8; 64], &data32, &good_opening).is_err());
        assert!(verify_signature(&pubkey, &msg32, &[0u8; 64]).is_err());
        assert!(verify_signature(&pubkey, &msg32, &[0xffu8; 64]).is_err());
        // r or s exactly zero / exactly n.
        let mut sig = good_sig;
        sig[..32].fill(0);
        assert!(verify_commitment(&sig, &data32, &good_opening).is_err());
        let mut sig = good_sig;
        sig[32..].fill(0);
        assert!(verify_commitment(&sig, &data32, &good_opening).is_err());
        // Identity-ish openings.
        assert!(Opening::from_bytes(&[0u8; 33]).is_err());
        assert!(Opening::from_bytes(&[0xffu8; 33]).is_err());
    }

    #[test]
    fn ct_gt_mask_matches_reference() {
        let cases: [([u8; 32], [u8; 32], u8); 5] = [
            ([0u8; 32], [0u8; 32], 0x00),
            ([1u8; 32], [0u8; 32], 0xff),
            ([0u8; 32], [1u8; 32], 0x00),
            (HALF_ORDER, HALF_ORDER, 0x00),
            ([0xffu8; 32], HALF_ORDER, 0xff),
        ];
        for (a, b, want) in cases {
            assert_eq!(ct_gt_mask(&a, &b), want);
        }
        // Differing only in the last byte.
        let mut a = HALF_ORDER;
        a[31] = a[31].wrapping_add(1);
        assert_eq!(ct_gt_mask(&a, &HALF_ORDER), 0xff);
        assert_eq!(ct_gt_mask(&HALF_ORDER, &a), 0x00);
    }
}
