//! ECDSA adaptor signatures ("encrypted signatures") for DLCs and atomic swaps.
//!
//! **EXPERIMENTAL** — no semver-stability guarantee. See the [module-level
//! documentation](super) for the clean-room policy and interop caveats.
//!
//! An adaptor signature is an ECDSA signature encrypted under a public
//! *encryption key* `Y = y·G`. It has three properties that make atomic swaps
//! and Discreet Log Contracts (DLCs) work:
//!
//! * it can be **verified** against the signer's public key `X` and `Y`
//!   without learning anything about `y` or about the finished signature;
//! * anyone holding `y` can **decrypt** it into an ordinary ECDSA signature
//!   that any Bitcoin/ECDSA verifier accepts;
//! * anyone holding the adaptor signature and the *published* finished
//!   signature can **recover** `y`.
//!
//! That last property is the interesting one: publishing the decrypted
//! signature (e.g. by broadcasting a transaction) unavoidably reveals the
//! decryption key to the counterparty.
//!
//! # Source of truth
//!
//! The construction is the ECDSA adaptor signature of Aumayr, Ersoy, Erwig,
//! Faust, Hostáková, Maffei, Moreno-Sanchez and Riahi, *Generalized
//! Bitcoin-Compatible Channels* (IACR ePrint 2020/476), refining the schemes of
//! Moreno-Sanchez and Fournier. The concrete algorithms, byte layout and hash
//! tags implemented here follow the [DLC specification's `ECDSA-adaptor.md`][dlc],
//! which is the normative prose description of the wire format, together with
//! the public C header `include/secp256k1_ecdsa_adaptor.h` of Blockstream's
//! `secp256k1-zkp` (the interface contract: the 162-byte length and the
//! `encrypt`/`verify`/`decrypt`/`recover` API shape).
//!
//! [dlc]: https://github.com/discreetlogcontracts/dlcspecs/blob/master/ECDSA-adaptor.md
//!
//! # The scheme
//!
//! With signing key `x` (public key `X = x·G`), encryption key `Y = y·G` and
//! 32-byte message hash `m`:
//!
//! * **Encrypt**: derive a nonce `k`, set `R_a = k·G` and `R = k·Y`, let
//!   `r = x(R) mod n` and `s_a = k⁻¹·(m + r·x) mod n`. Attach a
//!   Chaum–Pedersen proof that `log_G(R_a) == log_Y(R)` (both equal `k`).
//! * **Verify**: check the proof, then `s_a⁻¹·m·G + s_a⁻¹·r·X == R_a`.
//! * **Decrypt**: `s = s_a·y⁻¹ mod n`, normalised to low-S; the finished
//!   signature is `(r, s)`. It is a plain ECDSA signature because the
//!   effective nonce is `k·y` and `(k·y)·G = k·Y = R`.
//! * **Recover**: `y' = s⁻¹·s_a mod n`, then return `y'` if `y'·G == Y` and
//!   `−y'` if `y'·G == −Y`.
//!
//! ## The DLEQ proof is mandatory
//!
//! Without the discrete-log-equality proof the scheme is *insecure*: nothing
//! would tie `R = k·Y` to `R_a = k·G`, so a signer could pick the two points
//! independently and hand out an "adaptor signature" that verifies but whose
//! decryption is not a valid signature (or whose recovered key is not `y`).
//! [`verify`] therefore always checks the proof, and rejects if it is absent,
//! malformed or invalid.
//!
//! ## Low-S normalisation and the negation case
//!
//! Bitcoin requires low-S signatures (BIP-62), so [`decrypt`] negates `s`
//! whenever `s_a·y⁻¹` lands in the upper half of the group order — which
//! happens about half the time. When it does, the naive recovery
//! `y' = s⁻¹·s_a` yields `−y`, not `y`. This is the classic bug in the
//! scheme. [`recover`] handles it explicitly: it compares `y'·G` against both
//! `Y` and `−Y` and negates `y'` in the second case, so it always returns the
//! decryption key that matches the encryption key it was given. The bundled
//! interop vectors deliberately contain both cases.
//!
//! ## Warning: adaptor signatures leak an ECDH key
//!
//! As noted by Fournier and repeated in the reference implementation's header,
//! an ECDSA adaptor signature reveals the Diffie–Hellman value `Y^x = X^y`
//! between the signing key and the encryption key. That is harmless for the
//! adaptor scheme itself, but it can be fatal when the same signing key is
//! reused in a protocol whose security rests on CDH (Diffie–Hellman key
//! exchange, ElGamal, …). **Do not reuse an adaptor signing key elsewhere.**
//!
//! # Wire format
//!
//! An adaptor signature is exactly [`ADAPTOR_SIGNATURE_LEN`] = 162 bytes:
//!
//! | offset | length | contents |
//! |---|---|---|
//! | 0   | 33 | `R = k·Y`, compressed SEC1 |
//! | 33  | 33 | `R_a = k·G`, compressed SEC1 |
//! | 66  | 32 | `s_a`, big-endian |
//! | 98  | 32 | DLEQ challenge `b`, big-endian |
//! | 130 | 32 | DLEQ response `c`, big-endian |
//!
//! # Interop
//!
//! **Verified.** The algorithms, the 162-byte layout, the DLEQ challenge hash
//! and the nonce derivations were checked byte-for-byte against
//! `secp256k1-zkp` used as a black-box oracle (built outside the crate, driven
//! only through `include/secp256k1_ecdsa_adaptor.h`; no implementation source
//! was read). Concretely, what was established:
//!
//! * `encrypt` reproduces the oracle's 162 output bytes exactly, both with and
//!   without auxiliary randomness, over the committed vectors;
//! * `verify` accepts every vector the oracle accepts and rejects the
//!   tampered ones it rejects;
//! * `decrypt` reproduces the oracle's compact signature, including the low-S
//!   negation;
//! * `recover` returns the original decryption key in both the negated and the
//!   non-negated case.
//!
//! The vectors are committed at `tools/zkp-interop/vectors/ecdsa_adaptor.json`
//! and the test reads them directly; it never links against the oracle.
//!
//! **Not verified**, and deliberately stricter than the oracle:
//!
//! * this implementation rejects a `s_a`, `b` or `c` that is not canonically
//!   reduced (`≥ n`), and rejects zero scalars, rather than reducing them.
//!   Honest signing never produces such an encoding (probability ≈ 2⁻¹²⁸), so
//!   no interop difference is observable, but a hand-crafted signature could
//!   in principle be accepted by the reference and rejected here. This is a
//!   non-malleability choice, not an interop claim.
//! * `decrypt` does *not* check the DLEQ proof, matching the oracle (whose
//!   `decrypt` also ignores it, as confirmed by probing). Callers must call
//!   [`verify`] before trusting an adaptor signature received from a peer.

use crate::ec::Error;
use crate::ec::secp256k1::{AffinePoint, ProjectivePoint, Scalar};
use crate::hash::{Digest, Sha256};
use crate::rng::{CryptoRng, RngCore};

/// Length in bytes of the serialised adaptor signature
/// (`R ‖ R_a ‖ s_a ‖ b ‖ c`).
pub const ADAPTOR_SIGNATURE_LEN: usize = 162;

/// `(n − 1) / 2`, the largest "low-S" value, big-endian. A signature `s` above
/// this is negated by [`decrypt`] per BIP-62.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// BIP-340-style tag for the nonce of the encrypted-signing nonce `k`.
const ALGO_ENCRYPT: &[u8] = b"ECDSAadaptor/non";
/// BIP-340-style tag for the nonce of the DLEQ proof.
const ALGO_DLEQ: &[u8] = b"DLEQ";
/// BIP-340-style tag masking the secret key with auxiliary randomness.
const TAG_AUX: &[u8] = b"ECDSAadaptor/aux";
/// Tag for the DLEQ Fiat–Shamir challenge hash.
const TAG_DLEQ: &[u8] = b"DLEQ";

// =====================================================================
// Hashing helpers
// =====================================================================

/// BIP-340 tagged hash: `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ parts…)`.
fn tagged_hash(tag: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let t = Sha256::digest(tag);
    let mut h = Sha256::new();
    h.update(t.as_ref());
    h.update(t.as_ref());
    for p in parts {
        h.update(p);
    }
    let out = h.finalize();
    let mut o = [0u8; 32];
    o.copy_from_slice(out.as_ref());
    o
}

/// The hardened nonce function shared by encrypted signing and the DLEQ proof.
///
/// `nonce = tagged_hash(algo, t ‖ pk33 ‖ msg32)` where `t` is `key32`, masked
/// with `tagged_hash("ECDSAadaptor/aux", aux)` when auxiliary randomness is
/// supplied (the BIP-340 construction). Binding the public key `pk33` into the
/// hash is what stops a nonce being reused across two different encryption
/// keys, which would leak the signing key.
fn hardened_nonce(
    algo: &[u8],
    key32: &[u8; 32],
    pk33: &[u8; 33],
    msg32: &[u8; 32],
    aux: Option<&[u8; 32]>,
) -> [u8; 32] {
    let mut t = *key32;
    if let Some(a) = aux {
        let mask = tagged_hash(TAG_AUX, &[a]);
        for (b, m) in t.iter_mut().zip(mask.iter()) {
            *b ^= *m;
        }
    }
    let out = tagged_hash(algo, &[&t, pk33.as_slice(), msg32]);
    // `t` is the (possibly masked) signing key / nonce; wipe it.
    t.fill(0);
    let _ = core::hint::black_box(&t);
    out
}

// =====================================================================
// Chaum–Pedersen discrete-log-equality proof
// =====================================================================

/// The Fiat–Shamir challenge of the DLEQ proof for the statement
/// "there is `k` with `X = k·G` and `Z = k·Y`":
/// `b = scalar(tagged_hash("DLEQ", X ‖ Y ‖ Z ‖ A_G ‖ A_Y))`.
///
/// Every point of the statement *and* both commitments go into the hash; the
/// generator `G` is implicit. Reducing the digest mod `n` (rather than
/// rejecting an out-of-range digest) is what the specification's `scalar(·)`
/// means.
fn dleq_challenge(
    x: &AffinePoint,
    y: &AffinePoint,
    z: &AffinePoint,
    a_g: &AffinePoint,
    a_y: &AffinePoint,
) -> Scalar {
    let h = tagged_hash(
        TAG_DLEQ,
        &[
            &x.to_sec1_compressed(),
            &y.to_sec1_compressed(),
            &z.to_sec1_compressed(),
            &a_g.to_sec1_compressed(),
            &a_y.to_sec1_compressed(),
        ],
    );
    Scalar::from_bytes_be_reduce(&h)
}

/// Proves knowledge of `k` with `X = k·G` and `Z = k·Y`, returning `b ‖ c`.
///
/// `k` is secret; every scalar operation below is constant time and the
/// commitment scalar `a` is wiped on the way out (it is as sensitive as `k`:
/// `k = (c − a)·b⁻¹`).
fn dleq_prove(
    k: &Scalar,
    k_bytes: &[u8; 32],
    x: &AffinePoint,
    y: &AffinePoint,
    z: &AffinePoint,
    aux: Option<&[u8; 32]>,
) -> Result<[u8; 64], Error> {
    // The DLEQ nonce binds the witness, the second generator `Y` and a
    // compression of the two statement points.
    let inner = {
        let mut h = Sha256::new();
        h.update(&x.to_sec1_compressed());
        h.update(&z.to_sec1_compressed());
        let o = h.finalize();
        let mut b = [0u8; 32];
        b.copy_from_slice(o.as_ref());
        b
    };
    let mut a_bytes = hardened_nonce(ALGO_DLEQ, k_bytes, &y.to_sec1_compressed(), &inner, aux);
    let a = Scalar::from_bytes_be(&a_bytes);
    a_bytes.fill(0);
    let _ = core::hint::black_box(&a_bytes);
    let a = a?;
    if bool::from(a.is_zero()) {
        return Err(Error::InvalidInput);
    }

    let a_g = ProjectivePoint::mul_generator(&a)
        .to_affine()
        .ok_or(Error::InvalidInput)?;
    let a_y = y
        .to_projective()
        .mul(&a)
        .to_affine()
        .ok_or(Error::InvalidInput)?;

    let b = dleq_challenge(x, y, z, &a_g, &a_y);
    let c = a.add(&b.mul(k));

    let mut proof = [0u8; 64];
    proof[..32].copy_from_slice(&b.to_bytes_be());
    proof[32..].copy_from_slice(&c.to_bytes_be());
    Ok(proof)
}

/// Verifies a DLEQ proof of `log_G(X) == log_Y(Z)`.
///
/// Recomputes `A_G = c·G − b·X` and `A_Y = c·Y − b·Z` and checks that the
/// challenge hash over the statement and those commitments reproduces `b`.
fn dleq_verify(
    x: &AffinePoint,
    y: &AffinePoint,
    z: &AffinePoint,
    proof: &[u8; 64],
) -> Result<(), Error> {
    let mut b_raw = [0u8; 32];
    let mut c_raw = [0u8; 32];
    b_raw.copy_from_slice(&proof[..32]);
    c_raw.copy_from_slice(&proof[32..]);
    // Canonical (reduced) encodings only — see the module's Interop note.
    let b = Scalar::from_bytes_be(&b_raw).map_err(|_| Error::Verification)?;
    let c = Scalar::from_bytes_be(&c_raw).map_err(|_| Error::Verification)?;
    // An honest prover never produces a zero challenge or response
    // (probability ≈ 2⁻²⁵⁶ each); a zero `b` would also make the recomputed
    // commitments independent of the statement. Reject, as the docs promise.
    if bool::from(b.is_zero() | c.is_zero()) {
        return Err(Error::Verification);
    }

    let neg_b = b.negate();
    // A_G = c·G − b·X, A_Y = c·Y − b·Z. Both must be non-identity: the
    // challenge hash serialises them as compressed points, which the identity
    // has no encoding for.
    let a_g = ProjectivePoint::mul_generator(&c)
        .add(&x.to_projective().mul(&neg_b))
        .to_affine()
        .ok_or(Error::Verification)?;
    let a_y = y
        .to_projective()
        .mul(&c)
        .add(&z.to_projective().mul(&neg_b))
        .to_affine()
        .ok_or(Error::Verification)?;

    let implied = dleq_challenge(x, y, z, &a_g, &a_y);
    if bool::from(implied.ct_eq(&b)) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

// =====================================================================
// Parsing
// =====================================================================

/// The parsed pieces of a 162-byte adaptor signature that every entry point
/// needs: `R`, `R_a`, `s_a` and the raw 64-byte DLEQ proof.
struct Parsed {
    r_point: AffinePoint,
    r_a: AffinePoint,
    s_a: Scalar,
    proof: [u8; 64],
}

/// Parses an adaptor signature, rejecting non-canonical scalars, off-curve or
/// identity points and non-compressed point encodings. Never panics.
fn parse(sig: &[u8; ADAPTOR_SIGNATURE_LEN]) -> Result<Parsed, Error> {
    let r_point = AffinePoint::from_sec1(&sig[0..33])?;
    let r_a = AffinePoint::from_sec1(&sig[33..66])?;
    let mut s_raw = [0u8; 32];
    s_raw.copy_from_slice(&sig[66..98]);
    let s_a = Scalar::from_bytes_be(&s_raw)?;
    if bool::from(s_a.is_zero()) {
        return Err(Error::InvalidInput);
    }
    let mut proof = [0u8; 64];
    proof.copy_from_slice(&sig[98..162]);
    Ok(Parsed {
        r_point,
        r_a,
        s_a,
        proof,
    })
}

/// `r = x(R) mod n`, the ECDSA `r` component implied by an adaptor signature.
fn r_of(point: &AffinePoint) -> Scalar {
    Scalar::from_bytes_be_reduce(&point.x_bytes())
}

// =====================================================================
// Public API
// =====================================================================

/// Creates an adaptor signature over `msg32` with signing key `seckey`,
/// encrypted under `enckey`.
///
/// The nonce is derived deterministically from the signing key, the encryption
/// key and the message, matching the reference implementation's default nonce
/// function; the output is byte-for-byte identical to it. Use
/// [`encrypt_with_rng`] if you want the extra hedge of auxiliary randomness.
///
/// * `seckey` — 32-byte big-endian signing key, in `[1, n−1]`.
/// * `enckey` — the encryption key `Y`, 33-byte compressed SEC1.
/// * `msg32` — the 32-byte message *hash* (this function does no hashing).
///
/// # Errors
/// [`Error::InvalidInput`] if `seckey` is out of range, `enckey` is not a
/// valid compressed point, or the derived nonce is degenerate (probability
/// ≈ 2⁻¹²⁸).
///
/// # Security
/// Reusing `seckey` in a protocol that relies on the hardness of
/// Diffie–Hellman is unsafe — see the module documentation.
pub fn encrypt(
    seckey: &[u8; 32],
    enckey: &[u8; 33],
    msg32: &[u8; 32],
) -> Result<[u8; ADAPTOR_SIGNATURE_LEN], Error> {
    encrypt_inner(seckey, enckey, msg32, None)
}

/// Like [`encrypt`], but mixes 32 bytes of auxiliary randomness into the nonce
/// derivation (the BIP-340 hedge: the signing key is masked with
/// `tagged_hash("ECDSAadaptor/aux", aux_rand)` before nonce derivation).
///
/// This makes the nonce — and therefore the whole adaptor signature —
/// unpredictable to an attacker who knows the message, which protects against
/// fault and differential side-channel attacks on deterministic signing. The
/// scheme stays secure if `aux_rand` is poor; it is a hedge, not a
/// requirement.
///
/// # Errors
/// As [`encrypt`].
pub fn encrypt_with_aux(
    seckey: &[u8; 32],
    enckey: &[u8; 33],
    msg32: &[u8; 32],
    aux_rand: &[u8; 32],
) -> Result<[u8; ADAPTOR_SIGNATURE_LEN], Error> {
    encrypt_inner(seckey, enckey, msg32, Some(aux_rand))
}

/// Like [`encrypt_with_aux`], drawing the 32 auxiliary bytes from `rng`.
///
/// The RNG must be a cryptographically secure CSPRNG (see [`CryptoRng`]).
///
/// # Errors
/// As [`encrypt`].
pub fn encrypt_with_rng<R: RngCore + CryptoRng>(
    seckey: &[u8; 32],
    enckey: &[u8; 33],
    msg32: &[u8; 32],
    rng: &mut R,
) -> Result<[u8; ADAPTOR_SIGNATURE_LEN], Error> {
    let mut aux = [0u8; 32];
    rng.fill_bytes(&mut aux);
    let out = encrypt_inner(seckey, enckey, msg32, Some(&aux));
    aux.fill(0);
    let _ = core::hint::black_box(&aux);
    out
}

fn encrypt_inner(
    seckey: &[u8; 32],
    enckey: &[u8; 33],
    msg32: &[u8; 32],
    aux: Option<&[u8; 32]>,
) -> Result<[u8; ADAPTOR_SIGNATURE_LEN], Error> {
    let x = Scalar::from_bytes_be(seckey)?;
    if bool::from(x.is_zero()) {
        return Err(Error::InvalidInput);
    }
    let y_point = AffinePoint::from_sec1(enckey)?;
    let y_ser = y_point.to_sec1_compressed();

    // k = tagged_hash("ECDSAadaptor/non", x ‖ Y ‖ m). The nonce is the most
    // sensitive value here: k together with the published signature yields the
    // signing key, so it is wiped on every exit path below.
    let mut k_bytes = hardened_nonce(ALGO_ENCRYPT, seckey, &y_ser, msg32, aux);
    let k = Scalar::from_bytes_be(&k_bytes);

    // Single exit so `k_bytes` and `k` are wiped even on the error paths.
    let out = (|| {
        let k = k.as_ref().map_err(|e| *e)?;
        if bool::from(k.is_zero()) {
            return Err(Error::InvalidInput);
        }
        let r_a = ProjectivePoint::mul_generator(k)
            .to_affine()
            .ok_or(Error::InvalidInput)?;
        let r_point = y_point
            .to_projective()
            .mul(k)
            .to_affine()
            .ok_or(Error::InvalidInput)?;

        let proof = dleq_prove(k, &k_bytes, &r_a, &y_point, &r_point, aux)?;

        let m = Scalar::from_bytes_be_reduce(msg32);
        let r = r_of(&r_point);
        if bool::from(r.is_zero()) {
            return Err(Error::InvalidInput);
        }
        // s_a = k⁻¹·(m + r·x). `invert` is a constant-time Fermat inversion —
        // a variable-time inversion here would leak the nonce and hence `x`.
        let s_a = k.invert().mul(&m.add(&r.mul(&x)));
        if bool::from(s_a.is_zero()) {
            return Err(Error::InvalidInput);
        }

        let mut sig = [0u8; ADAPTOR_SIGNATURE_LEN];
        sig[0..33].copy_from_slice(&r_point.to_sec1_compressed());
        sig[33..66].copy_from_slice(&r_a.to_sec1_compressed());
        sig[66..98].copy_from_slice(&s_a.to_bytes_be());
        sig[98..162].copy_from_slice(&proof);
        Ok(sig)
    })();

    // `Scalar`'s own `Drop` wipes `x` and `k`; the raw nonce bytes need an
    // explicit store plus a `black_box` barrier so LLVM cannot elide it.
    k_bytes.fill(0);
    let _ = core::hint::black_box(&k_bytes);
    out
}

/// Verifies an adaptor signature against the signer's public key, the
/// encryption key and the message hash.
///
/// This checks **both** halves of the statement: that the DLEQ proof binds
/// `R = k·Y` and `R_a = k·G` to the same `k`, and that `s_a` is a correct
/// encrypted signature under `pubkey`. A missing, malformed or invalid proof
/// is rejected — see the module documentation for why that matters.
///
/// * `adaptor_sig` — the 162-byte adaptor signature.
/// * `pubkey` — the signer's public key `X`, 33-byte compressed SEC1.
/// * `enckey` — the encryption key `Y`, 33-byte compressed SEC1.
/// * `msg32` — the 32-byte message hash.
///
/// # Errors
/// [`Error::Malformed`] / [`Error::InvalidInput`] for an unparseable input and
/// [`Error::Verification`] when the proof or the encrypted signature does not
/// check out — including a zero DLEQ challenge or response, and an `R` whose
/// `x(R) mod n` is zero (which would make the ECDSA equation independent of
/// `pubkey`). Never panics, whatever the input bytes are.
pub fn verify(
    adaptor_sig: &[u8; ADAPTOR_SIGNATURE_LEN],
    pubkey: &[u8; 33],
    enckey: &[u8; 33],
    msg32: &[u8; 32],
) -> Result<(), Error> {
    let p = parse(adaptor_sig)?;
    let x_point = AffinePoint::from_sec1(pubkey)?;
    let y_point = AffinePoint::from_sec1(enckey)?;

    // DLEQ first: it is the cheap, mandatory gate.
    dleq_verify(&p.r_a, &y_point, &p.r_point, &p.proof)?;

    let m = Scalar::from_bytes_be_reduce(msg32);
    let r = r_of(&p.r_point);
    // `x(R) = n` is a valid curve abscissa, so `r = 0` *is* encodable. With
    // `r = 0` the equation below degenerates to `s_a⁻¹·m·G == R_a`, which no
    // longer involves `pubkey` at all — an attacker could satisfy it for any
    // key. ECDSA requires `r ≠ 0`; enforce it here as `encrypt` does.
    if bool::from(r.is_zero()) {
        return Err(Error::Verification);
    }
    let s_inv = p.s_a.invert();
    let u1 = s_inv.mul(&m);
    let u2 = s_inv.mul(&r);

    // Everything here is public, but the hazmat API only offers the
    // constant-time ladder; using it costs a little speed and leaks nothing.
    let lhs = ProjectivePoint::mul_generator(&u1).add(&x_point.to_projective().mul(&u2));
    if bool::from(lhs.ct_eq(&p.r_a.to_projective())) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

/// Decrypts an adaptor signature with the decryption key `secret_y`, producing
/// an ordinary compact ECDSA signature `r ‖ s` (64 bytes, big-endian halves).
///
/// `s` is normalised to low-S per BIP-62, so the result is directly usable in
/// Bitcoin.
///
/// The DLEQ proof is **not** checked here (matching the reference
/// implementation). Call [`verify`] first on any adaptor signature that came
/// from a peer; otherwise the result may not be a valid signature.
///
/// # Errors
/// [`Error::Malformed`] / [`Error::InvalidInput`] if `adaptor_sig` is
/// unparseable or `secret_y` is not a scalar in `[1, n−1]`. Never panics.
pub fn decrypt(
    adaptor_sig: &[u8; ADAPTOR_SIGNATURE_LEN],
    secret_y: &[u8; 32],
) -> Result<[u8; 64], Error> {
    let p = parse(adaptor_sig)?;
    let y = Scalar::from_bytes_be(secret_y)?;
    if bool::from(y.is_zero()) {
        return Err(Error::InvalidInput);
    }

    // s = s_a·y⁻¹. `y` is secret, so this inversion must be constant time.
    let s = p.s_a.mul(&y.invert());
    if bool::from(s.is_zero()) {
        return Err(Error::InvalidInput);
    }
    // Low-S normalisation (BIP-62), branch-free. `s` is a public output, so
    // the flag itself is not secret, but selecting rather than branching keeps
    // the decryption path free of data-dependent control flow by construction.
    let s_be = s.to_bytes_be();
    let neg_be = s.negate().to_bytes_be();
    let high = ct_gt_mask(&s_be, &HALF_ORDER);

    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r_of(&p.r_point).to_bytes_be());
    for (o, (&lo, &hi)) in out[32..].iter_mut().zip(s_be.iter().zip(neg_be.iter())) {
        *o = (lo & !high) | (hi & high);
    }
    Ok(out)
}

/// Branch-free big-endian "greater than" over 32-byte values: returns `0xff`
/// if `a > b`, else `0x00`. (Same helper as `sign_to_contract`'s; the two
/// modules are independently feature-gated, so each carries its own copy.)
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

/// Recovers the decryption key `y` from an adaptor signature and the finished
/// ECDSA signature decrypted from it.
///
/// This is the property that makes atomic swaps work: once the counterparty
/// publishes the decrypted signature, `y` falls out.
///
/// The low-S normalisation applied by [`decrypt`] negates `s` about half the
/// time, which negates the naively recovered key too. This function detects
/// that by comparing `y'·G` against both `Y` and `−Y`, and returns the key
/// that actually matches `enckey`.
///
/// * `enckey` — the encryption key `Y`, 33-byte compressed SEC1.
/// * `adaptor_sig` — the 162-byte adaptor signature.
/// * `sig` — the finished compact ECDSA signature `r ‖ s`.
///
/// # Errors
/// [`Error::Malformed`] / [`Error::InvalidInput`] for unparseable input, and
/// [`Error::Verification`] if `sig`'s `r` does not match the adaptor
/// signature's `R`, or the recovered key matches neither `Y` nor `−Y`. Never
/// panics.
pub fn recover(
    enckey: &[u8; 33],
    adaptor_sig: &[u8; ADAPTOR_SIGNATURE_LEN],
    sig: &[u8; 64],
) -> Result<[u8; 32], Error> {
    let p = parse(adaptor_sig)?;
    let y_point = AffinePoint::from_sec1(enckey)?;

    let mut r_raw = [0u8; 32];
    let mut s_raw = [0u8; 32];
    r_raw.copy_from_slice(&sig[..32]);
    s_raw.copy_from_slice(&sig[32..]);
    let r = Scalar::from_bytes_be(&r_raw)?;
    let s = Scalar::from_bytes_be(&s_raw)?;
    if bool::from(s.is_zero()) {
        return Err(Error::InvalidInput);
    }
    // `r = 0` is not a signature (and, because `x(R) = n` is encodable, it
    // could still match this adaptor signature's `R` below); reject it as
    // [`verify`] does.
    if bool::from(r.is_zero()) {
        return Err(Error::Verification);
    }
    // The signature must belong to this adaptor signature.
    if !bool::from(r.ct_eq(&r_of(&p.r_point))) {
        return Err(Error::Verification);
    }

    // y' = s⁻¹·s_a. Both operands are public here (the signature has been
    // published), but `y'` is the secret being recovered, so it is treated as
    // secret from this point on.
    let y = s.invert().mul(&p.s_a);
    if bool::from(y.is_zero()) {
        return Err(Error::Verification);
    }
    let implied = ProjectivePoint::mul_generator(&y);
    let target = y_point.to_projective();
    if bool::from(implied.ct_eq(&target)) {
        Ok(y.to_bytes_be())
    } else if bool::from(implied.ct_eq(&target.negate())) {
        // `decrypt` negated `s` for low-S, so the naive recovery gave −y.
        Ok(y.negate().to_bytes_be())
    } else {
        Err(Error::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    /// The oracle-generated interop vectors (see the module's Interop note).
    const VECTORS: &str = include_str!("../../tools/zkp-interop/vectors/ecdsa_adaptor.json");

    // --- a deliberately tiny JSON reader for the flat, machine-generated
    // vector file: one `"key": value` per line, no nesting inside objects.

    fn section<'a>(json: &'a str, name: &str) -> &'a str {
        let mut needle = [0u8; 32];
        let n = name.len();
        needle[0] = b'"';
        needle[1..1 + n].copy_from_slice(name.as_bytes());
        needle[1 + n..4 + n].copy_from_slice(b"\": ");
        let needle = core::str::from_utf8(&needle[..4 + n]).unwrap();
        let start = json.find(needle).expect("section present") + needle.len();
        let rest = &json[start..];
        let end = rest.find(']').expect("array closes");
        &rest[..end]
    }

    fn objects(section: &str) -> impl Iterator<Item = &str> {
        section
            .split('{')
            .skip(1)
            .map(|o| o.split('}').next().unwrap_or(""))
    }

    fn get<'a>(obj: &'a str, key: &str) -> &'a str {
        for line in obj.lines() {
            let t = line.trim().trim_end_matches(',');
            let Some(rest) = t.strip_prefix('"') else {
                continue;
            };
            let Some((k, v)) = rest.split_once("\": ") else {
                continue;
            };
            if k == key {
                return v.trim_matches('"');
            }
        }
        panic!("missing key {key}");
    }

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), 2 * N, "hex length");
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex");
        }
        out
    }

    fn pubkey_of(seckey: &[u8; 32]) -> [u8; 33] {
        let d = Scalar::from_bytes_be(seckey).unwrap();
        ProjectivePoint::mul_generator(&d)
            .to_affine()
            .unwrap()
            .to_sec1_compressed()
    }

    /// Reference ECDSA verification over secp256k1, so the round-trip test can
    /// assert that a decrypted adaptor signature is a genuine signature. (The
    /// crate's `ec::ecdsa` is P-256 only.)
    fn ecdsa_verify(pubkey: &[u8; 33], msg32: &[u8; 32], sig: &[u8; 64]) -> bool {
        let x_point = match AffinePoint::from_sec1(pubkey) {
            Ok(p) => p,
            Err(_) => return false,
        };
        let mut rb = [0u8; 32];
        let mut sb = [0u8; 32];
        rb.copy_from_slice(&sig[..32]);
        sb.copy_from_slice(&sig[32..]);
        let (r, s) = match (Scalar::from_bytes_be(&rb), Scalar::from_bytes_be(&sb)) {
            (Ok(r), Ok(s)) => (r, s),
            _ => return false,
        };
        if bool::from(r.is_zero()) || bool::from(s.is_zero()) {
            return false;
        }
        let m = Scalar::from_bytes_be_reduce(msg32);
        let w = s.invert();
        let u1 = m.mul(&w);
        let u2 = r.mul(&w);
        let point = ProjectivePoint::mul_generator(&u1).add(&x_point.to_projective().mul(&u2));
        match point.to_affine() {
            Some(p) => bool::from(r_of(&p).ct_eq(&r)),
            None => false,
        }
    }

    // =============================================================
    // Interop vectors
    // =============================================================

    #[test]
    fn oracle_vectors_valid() {
        let mut count = 0;
        let mut negated = 0;
        for obj in objects(section(VECTORS, "valid")) {
            let seckey: [u8; 32] = unhex(get(obj, "seckey"));
            let pubkey: [u8; 33] = unhex(get(obj, "pubkey"));
            let deckey: [u8; 32] = unhex(get(obj, "deckey"));
            let enckey: [u8; 33] = unhex(get(obj, "enckey"));
            let msg: [u8; 32] = unhex(get(obj, "msg"));
            let expected: [u8; 162] = unhex(get(obj, "adaptor_sig"));
            let expected_sig: [u8; 64] = unhex(get(obj, "signature"));
            let comment = get(obj, "comment");

            // Our public key derivation agrees with the oracle's.
            assert_eq!(pubkey_of(&seckey), pubkey, "{comment}: pubkey");

            // Byte-exact encryption, with and without auxiliary randomness.
            let aux = get(obj, "aux_rand");
            let ours = if aux == "null" {
                encrypt(&seckey, &enckey, &msg).unwrap()
            } else {
                encrypt_with_aux(&seckey, &enckey, &msg, &unhex::<32>(aux)).unwrap()
            };
            assert_eq!(ours, expected, "{comment}: adaptor signature bytes");

            verify(&expected, &pubkey, &enckey, &msg).unwrap_or_else(|e| panic!("{comment}: {e}"));

            let sig = decrypt(&expected, &deckey).unwrap();
            assert_eq!(sig, expected_sig, "{comment}: decrypted signature");
            assert!(ecdsa_verify(&pubkey, &msg, &sig), "{comment}: ECDSA valid");

            let rec = recover(&enckey, &expected, &sig).unwrap();
            assert_eq!(rec, deckey, "{comment}: recovered decryption key");
            assert_eq!(rec, unhex::<32>(get(obj, "recovered")));

            if get(obj, "low_s_negated") == "true" {
                negated += 1;
            }
            count += 1;
        }
        assert!(count >= 16, "expected a real vector set, got {count}");
        // Both branches of the low-S negation must be exercised by the file.
        assert!(negated > 0 && negated < count, "negated={negated}/{count}");
    }

    #[test]
    fn oracle_vectors_invalid() {
        let mut count = 0;
        for obj in objects(section(VECTORS, "invalid")) {
            let sig: [u8; 162] = unhex(get(obj, "adaptor_sig"));
            let pubkey: [u8; 33] = unhex(get(obj, "pubkey"));
            let enckey: [u8; 33] = unhex(get(obj, "enckey"));
            let msg: [u8; 32] = unhex(get(obj, "msg"));
            assert!(
                verify(&sig, &pubkey, &enckey, &msg).is_err(),
                "accepted an invalid vector: {}",
                get(obj, "comment")
            );
            count += 1;
        }
        assert!(count >= 8, "expected the negative vectors, got {count}");
    }

    // =============================================================
    // Round trip and soundness
    // =============================================================

    #[test]
    fn full_round_trip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"adaptor-roundtrip", b"nonce", &[]);
        for i in 0..16u8 {
            let mut seckey = [0u8; 32];
            let mut deckey = [0u8; 32];
            rng.fill_bytes(&mut seckey);
            rng.fill_bytes(&mut deckey);
            seckey[0] &= 0x7f;
            deckey[0] &= 0x7f;
            let msg = {
                let mut m = [0u8; 32];
                m.copy_from_slice(Sha256::digest(&[i]).as_ref());
                m
            };
            let pubkey = pubkey_of(&seckey);
            let enckey = pubkey_of(&deckey);

            let a = encrypt(&seckey, &enckey, &msg).unwrap();
            verify(&a, &pubkey, &enckey, &msg).unwrap();
            let sig = decrypt(&a, &deckey).unwrap();
            // The decrypted signature is a genuine ECDSA signature ...
            assert!(ecdsa_verify(&pubkey, &msg, &sig));
            // ... in low-S form ...
            let mut s = [0u8; 32];
            s.copy_from_slice(&sig[32..]);
            assert!(s <= HALF_ORDER, "decrypt must produce low-S");
            // ... and publishing it reveals exactly the decryption key.
            assert_eq!(recover(&enckey, &a, &sig).unwrap(), deckey);

            // The randomised nonce path round-trips too, and differs.
            let b = encrypt_with_rng(&seckey, &enckey, &msg, &mut rng).unwrap();
            assert_ne!(a, b, "aux randomness must change the nonce");
            verify(&b, &pubkey, &enckey, &msg).unwrap();
            assert_eq!(
                recover(&enckey, &b, &decrypt(&b, &deckey).unwrap()).unwrap(),
                deckey
            );
        }
    }

    /// The low-S negation is the subtle case: when `s_a·y⁻¹` is high, `decrypt`
    /// negates it and the naive `s⁻¹·s_a` recovery returns `−y`. Drive both
    /// branches explicitly and assert `recover` still returns `y` exactly.
    #[test]
    fn low_s_negation_recovery() {
        let mut rng = HmacDrbg::<Sha256>::new(b"adaptor-low-s", b"nonce", &[]);
        let mut seen_negated = 0;
        let mut seen_plain = 0;
        for _ in 0..200 {
            if seen_negated >= 8 && seen_plain >= 8 {
                break;
            }
            let mut seckey = [0u8; 32];
            let mut deckey = [0u8; 32];
            let mut msg = [0u8; 32];
            rng.fill_bytes(&mut seckey);
            rng.fill_bytes(&mut deckey);
            rng.fill_bytes(&mut msg);
            seckey[0] &= 0x7f;
            deckey[0] &= 0x7f;
            let pubkey = pubkey_of(&seckey);
            let enckey = pubkey_of(&deckey);

            let a = encrypt(&seckey, &enckey, &msg).unwrap();
            verify(&a, &pubkey, &enckey, &msg).unwrap();

            // Was the raw s = s_a·y⁻¹ in the upper half (so `decrypt` negated it)?
            let mut sa_raw = [0u8; 32];
            sa_raw.copy_from_slice(&a[66..98]);
            let s_a = Scalar::from_bytes_be(&sa_raw).unwrap();
            let y = Scalar::from_bytes_be(&deckey).unwrap();
            let raw = s_a.mul(&y.invert()).to_bytes_be();
            let negated = raw > HALF_ORDER;

            let sig = decrypt(&a, &deckey).unwrap();
            let mut s = [0u8; 32];
            s.copy_from_slice(&sig[32..]);
            assert!(s <= HALF_ORDER);
            if negated {
                assert_ne!(s, raw, "high-S must have been negated");
                seen_negated += 1;
            } else {
                assert_eq!(s, raw, "low-S must be left alone");
                seen_plain += 1;
            }

            // The whole point: recovery returns y, not −y, in both branches.
            assert_eq!(
                recover(&enckey, &a, &sig).unwrap(),
                deckey,
                "recover failed (negated={negated})"
            );
        }
        assert!(seen_negated >= 8, "never hit the negation branch");
        assert!(seen_plain >= 8, "never hit the non-negation branch");
    }

    #[test]
    fn verify_rejects_tampering() {
        let seckey = [7u8; 32];
        let deckey = [9u8; 32];
        let msg = [3u8; 32];
        let pubkey = pubkey_of(&seckey);
        let enckey = pubkey_of(&deckey);
        let a = encrypt(&seckey, &enckey, &msg).unwrap();
        verify(&a, &pubkey, &enckey, &msg).unwrap();

        // A tampered DLEQ proof (challenge or response) must be rejected.
        for off in [98usize, 130, 161] {
            let mut bad = a;
            bad[off] ^= 1;
            assert!(
                verify(&bad, &pubkey, &enckey, &msg).is_err(),
                "accepted tampered proof at offset {off}"
            );
        }
        // Wrong encryption key.
        let other_enc = pubkey_of(&[11u8; 32]);
        assert!(verify(&a, &pubkey, &other_enc, &msg).is_err());
        // Wrong public key.
        let other_pub = pubkey_of(&[13u8; 32]);
        assert!(verify(&a, &other_pub, &enckey, &msg).is_err());
        // Wrong message.
        let mut other_msg = msg;
        other_msg[31] ^= 1;
        assert!(verify(&a, &pubkey, &enckey, &other_msg).is_err());
        // Tampered s_a and swapped points.
        let mut bad = a;
        bad[97] ^= 1;
        assert!(verify(&bad, &pubkey, &enckey, &msg).is_err());
        let mut swapped = a;
        swapped[0..33].copy_from_slice(&a[33..66]);
        swapped[33..66].copy_from_slice(&a[0..33]);
        assert!(verify(&swapped, &pubkey, &enckey, &msg).is_err());
    }

    /// A DLEQ proof is mandatory: an adaptor signature whose `R` and `R_a` use
    /// *different* nonces must be rejected, and it is the proof that catches
    /// it (the `s_a` check alone would pass).
    #[test]
    fn mismatched_nonces_are_rejected() {
        let seckey = [21u8; 32];
        let deckey = [22u8; 32];
        let msg = [23u8; 32];
        let pubkey = pubkey_of(&seckey);
        let enckey = pubkey_of(&deckey);
        let a = encrypt(&seckey, &enckey, &msg).unwrap();

        // Replace R = k·Y with k·Y' for a different encryption key, keeping
        // everything else. `s_a` no longer matches either, but the DLEQ check
        // runs first and must already reject.
        let y2 = pubkey_of(&[24u8; 32]);
        let mut forged = a;
        forged[0..33].copy_from_slice(&y2);
        assert!(verify(&forged, &pubkey, &enckey, &msg).is_err());
        // Zeroing the proof outright is also a rejection.
        let mut no_proof = a;
        no_proof[98..162].fill(0);
        assert!(verify(&no_proof, &pubkey, &enckey, &msg).is_err());
    }

    /// Malformed input must produce `Err`, never a panic.
    #[test]
    fn no_panic_on_malformed_input() {
        let seckey = [5u8; 32];
        let deckey = [6u8; 32];
        let msg = [1u8; 32];
        let pubkey = pubkey_of(&seckey);
        let enckey = pubkey_of(&deckey);
        let good = encrypt(&seckey, &enckey, &msg).unwrap();

        let n_bytes: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];

        let mut cases: alloc::vec::Vec<[u8; 162]> = alloc::vec::Vec::new();
        cases.push([0u8; 162]);
        cases.push([0xffu8; 162]);
        // Every single-byte corruption of a valid signature.
        for i in 0..162 {
            let mut c = good;
            c[i] ^= 0xff;
            cases.push(c);
        }
        // Out-of-range and zero scalars in each scalar slot.
        for off in [66usize, 98, 130] {
            let mut c = good;
            c[off..off + 32].copy_from_slice(&n_bytes);
            cases.push(c);
            let mut z = good;
            z[off..off + 32].fill(0);
            cases.push(z);
            let mut hi = good;
            hi[off..off + 32].fill(0xff);
            cases.push(hi);
        }
        // Bad point tags.
        for off in [0usize, 33] {
            for tag in [0x00u8, 0x01, 0x04, 0x05, 0xff] {
                let mut c = good;
                c[off] = tag;
                cases.push(c);
            }
        }

        for c in &cases {
            // The only thing asserted is that nothing panics and a valid
            // signature is not conjured out of corruption.
            let _ = verify(c, &pubkey, &enckey, &msg);
            let _ = decrypt(c, &deckey);
            let _ = recover(&enckey, c, &[0u8; 64]);
            if c != &good {
                assert!(verify(c, &pubkey, &enckey, &msg).is_err());
            }
        }

        // Malformed keys and scalars on the other arguments.
        assert!(verify(&good, &[0u8; 33], &enckey, &msg).is_err());
        assert!(verify(&good, &pubkey, &[0u8; 33], &msg).is_err());
        assert!(decrypt(&good, &[0u8; 32]).is_err());
        assert!(decrypt(&good, &n_bytes).is_err());
        assert!(recover(&[0u8; 33], &good, &[0u8; 64]).is_err());
        assert!(encrypt(&[0u8; 32], &enckey, &msg).is_err());
        assert!(encrypt(&n_bytes, &enckey, &msg).is_err());
        assert!(encrypt(&seckey, &[0u8; 33], &msg).is_err());

        // A well-formed signature under the wrong decryption key decrypts to
        // something, but must not recover a key.
        let sig = decrypt(&good, &[8u8; 32]).unwrap();
        assert!(recover(&enckey, &good, &sig).is_err());
    }

    #[test]
    fn recover_rejects_foreign_signature() {
        let seckey = [31u8; 32];
        let deckey = [32u8; 32];
        let msg = [33u8; 32];
        let enckey = pubkey_of(&deckey);
        let a = encrypt(&seckey, &enckey, &msg).unwrap();
        let sig = decrypt(&a, &deckey).unwrap();

        // A signature whose r does not match this adaptor signature's R.
        let mut foreign = sig;
        foreign[0] ^= 1;
        assert!(recover(&enckey, &a, &foreign).is_err());
        // A zero s.
        let mut zero_s = sig;
        zero_s[32..].fill(0);
        assert!(recover(&enckey, &a, &zero_s).is_err());
        // The correct signature against the wrong encryption key.
        assert!(recover(&pubkey_of(&[34u8; 32]), &a, &sig).is_err());
    }

    #[test]
    fn encrypt_is_deterministic() {
        let seckey = [41u8; 32];
        let enckey = pubkey_of(&[42u8; 32]);
        let msg = [43u8; 32];
        assert_eq!(
            encrypt(&seckey, &enckey, &msg).unwrap(),
            encrypt(&seckey, &enckey, &msg).unwrap()
        );
        // Aux randomness is deterministic in the aux value, and different from
        // the un-hedged nonce.
        let aux = [44u8; 32];
        assert_eq!(
            encrypt_with_aux(&seckey, &enckey, &msg, &aux).unwrap(),
            encrypt_with_aux(&seckey, &enckey, &msg, &aux).unwrap()
        );
        assert_ne!(
            encrypt(&seckey, &enckey, &msg).unwrap(),
            encrypt_with_aux(&seckey, &enckey, &msg, &aux).unwrap()
        );
        // Changing any input changes the signature.
        let mut msg2 = msg;
        msg2[0] ^= 1;
        assert_ne!(
            encrypt(&seckey, &enckey, &msg).unwrap(),
            encrypt(&seckey, &enckey, &msg2).unwrap()
        );
    }

    /// `x = n` is a valid secp256k1 abscissa, so an `R` with `r = x(R) mod n
    /// = 0` is encodable. Build an adaptor signature around such an `R`, with
    /// a *genuine* DLEQ proof (choose `k`, set `Y = k⁻¹·R`) and an `s_a`
    /// chosen so that `s_a⁻¹·m·G == R_a`: without the `r ≠ 0` guard, `verify`
    /// would accept it under any public key whatsoever.
    #[test]
    fn r_zero_adaptor_signature_is_rejected() {
        // R = lift_x(n) (even-Y root); r = n mod n = 0.
        let mut r_enc = [0u8; 33];
        r_enc[0] = 0x02;
        r_enc[1..].copy_from_slice(&unhex::<32>(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        ));
        let r_point = AffinePoint::from_sec1(&r_enc).expect("x = n lies on the curve");
        assert!(bool::from(r_of(&r_point).is_zero()));

        let k_bytes = [5u8; 32];
        let k = Scalar::from_bytes_be(&k_bytes).unwrap();
        let r_a = ProjectivePoint::mul_generator(&k).to_affine().unwrap();
        // Y = k⁻¹·R, so that R = k·Y and the DLEQ statement is true.
        let y_point = r_point
            .to_projective()
            .mul(&k.invert())
            .to_affine()
            .unwrap();
        let proof = dleq_prove(&k, &k_bytes, &r_a, &y_point, &r_point, None).unwrap();

        let msg = [77u8; 32];
        let m = Scalar::from_bytes_be_reduce(&msg);
        // s_a = k⁻¹·m makes s_a⁻¹·m·G = k·G = R_a, the degenerate r = 0 check.
        let s_a = k.invert().mul(&m);

        let mut sig = [0u8; ADAPTOR_SIGNATURE_LEN];
        sig[0..33].copy_from_slice(&r_point.to_sec1_compressed());
        sig[33..66].copy_from_slice(&r_a.to_sec1_compressed());
        sig[66..98].copy_from_slice(&s_a.to_bytes_be());
        sig[98..162].copy_from_slice(&proof);
        let enckey = y_point.to_sec1_compressed();

        // The DLEQ half is genuinely valid ...
        dleq_verify(&r_a, &y_point, &r_point, &proof).expect("the DLEQ proof is honest");
        // ... yet the adaptor signature must be rejected under any key.
        for sk in [[1u8; 32], [2u8; 32], [99u8; 32]] {
            assert_eq!(
                verify(&sig, &pubkey_of(&sk), &enckey, &msg).unwrap_err(),
                Error::Verification
            );
        }

        // `recover` with the matching r = 0 "signature" is rejected too.
        let mut ecdsa_sig = [0u8; 64];
        ecdsa_sig[32..].copy_from_slice(&s_a.to_bytes_be());
        assert_eq!(
            recover(&enckey, &sig, &ecdsa_sig).unwrap_err(),
            Error::Verification
        );
    }

    /// The documented rule: a DLEQ proof whose challenge `b` or response `c`
    /// encodes zero is rejected (an honest prover never produces one).
    #[test]
    fn zero_dleq_scalars_are_rejected() {
        let seckey = [51u8; 32];
        let deckey = [52u8; 32];
        let msg = [53u8; 32];
        let pubkey = pubkey_of(&seckey);
        let enckey = pubkey_of(&deckey);
        let a = encrypt(&seckey, &enckey, &msg).unwrap();
        let p = parse(&a).unwrap();
        dleq_verify(&p.r_a, &enckey_point(&enckey), &p.r_point, &p.proof).unwrap();

        let mut zero_b = p.proof;
        zero_b[..32].fill(0);
        assert_eq!(
            dleq_verify(&p.r_a, &enckey_point(&enckey), &p.r_point, &zero_b).unwrap_err(),
            Error::Verification
        );
        let mut zero_c = p.proof;
        zero_c[32..].fill(0);
        assert_eq!(
            dleq_verify(&p.r_a, &enckey_point(&enckey), &p.r_point, &zero_c).unwrap_err(),
            Error::Verification
        );
        // And through the public entry point.
        let mut sig = a;
        sig[98..130].fill(0);
        assert_eq!(
            verify(&sig, &pubkey, &enckey, &msg).unwrap_err(),
            Error::Verification
        );
        let mut sig = a;
        sig[130..162].fill(0);
        assert_eq!(
            verify(&sig, &pubkey, &enckey, &msg).unwrap_err(),
            Error::Verification
        );
    }

    fn enckey_point(enckey: &[u8; 33]) -> AffinePoint {
        AffinePoint::from_sec1(enckey).unwrap()
    }

    #[test]
    fn ct_gt_mask_matches_reference() {
        let mut lo = HALF_ORDER;
        lo[31] -= 1;
        let mut hi = HALF_ORDER;
        hi[31] += 1;
        let cases: [([u8; 32], [u8; 32], u8); 6] = [
            ([0u8; 32], [0u8; 32], 0x00),
            (HALF_ORDER, HALF_ORDER, 0x00),
            ([0xffu8; 32], HALF_ORDER, 0xff),
            (lo, HALF_ORDER, 0x00),
            (hi, HALF_ORDER, 0xff),
            (HALF_ORDER, hi, 0x00),
        ];
        for (a, b, want) in cases {
            assert_eq!(ct_gt_mask(&a, &b), want);
            assert_eq!(ct_gt_mask(&a, &b) == 0xff, a > b);
        }
        // A difference in the most significant byte dominates the rest.
        let mut a = [0u8; 32];
        a[0] = 1;
        let mut b = [0xffu8; 32];
        b[0] = 0;
        assert_eq!(ct_gt_mask(&a, &b), 0xff);
        assert_eq!(ct_gt_mask(&b, &a), 0x00);
    }

    /// The branch-free low-S select agrees with the plain comparison.
    #[test]
    fn decrypt_low_s_select_matches_branching_reference() {
        for i in 0..16u8 {
            let seckey = [60 + i; 32];
            let deckey = [90 + i; 32];
            let msg = [120 + i; 32];
            let enckey = pubkey_of(&deckey);
            let a = encrypt(&seckey, &enckey, &msg).unwrap();
            let sig = decrypt(&a, &deckey).unwrap();
            let p = parse(&a).unwrap();
            let y = Scalar::from_bytes_be(&deckey).unwrap();
            let raw = p.s_a.mul(&y.invert());
            let mut want = raw.to_bytes_be();
            if want > HALF_ORDER {
                want = raw.negate().to_bytes_be();
            }
            assert_eq!(&sig[32..], &want[..]);
            assert!(ecdsa_verify(&pubkey_of(&seckey), &msg, &sig));
        }
    }
}
