//! BIP340 Schnorr signatures over secp256k1 (x-only public keys).
//!
//! Unlike the [`zkp`](crate::zkp) modules, BIP340 is a frozen published
//! standard with official test vectors, and carries this crate's normal
//! semver guarantee.
//!
//! # Source of truth
//!
//! BIP340, *Schnorr Signatures for secp256k1* (Wuille, Nick, Ruffing), and its
//! published `test-vectors.csv`.
//!
//! # Overview
//!
//! A BIP340 public key is the **32-byte x-only** encoding of a point whose `Y`
//! coordinate is even (`lift_x` always returns the even-`Y` lift), and a
//! signature is the fixed 64-byte string `bytes(R) ‖ bytes(s)`. Messages may be
//! of **any length** — the original draft was 32-byte-only, but the final BIP
//! hashes a variable-length message directly.
//!
//! ```
//! # #[cfg(feature = "bip340")] {
//! use purecrypto::ec::secp256k1::schnorr;
//!
//! let sk = [0x03u8; 32];
//! let pk = schnorr::public_key(&sk).unwrap();
//! let sig = schnorr::sign(&sk, b"hello bip340", &[0u8; 32]).unwrap();
//! schnorr::verify(&pk, b"hello bip340", &sig).unwrap();
//! # }
//! ```
//!
//! # Nonce generation
//!
//! [`sign`] takes the BIP340 auxiliary randomness `a` explicitly and derives
//! the nonce as `hash_BIP0340/nonce(t ‖ bytes(P) ‖ m)` with
//! `t = bytes(d) XOR hash_BIP0340/aux(a)`. Fresh randomness is
//! **recommended whenever available** — use [`sign_with_rng`]. When no entropy
//! is available at signing time the BIP explicitly permits an all-zero `a`;
//! [`sign_deterministic`] is that case. The scheme's normal security does not
//! depend on the quality of `a`, but unpredictable `a` adds protection against
//! fault-injection and other side-channel attacks.
//!
//! # Constant time
//!
//! The secret scalar `d`, the nonce `k` and the masked secret `t` never drive a
//! branch or a memory index: the two BIP340 negations (`d = n − d'` when `P` has
//! odd `Y`, `k = n − k'` when `R` has odd `Y`) are done with a constant-time
//! byte select, and all point/scalar arithmetic uses the constant-time
//! [`Scalar`] / [`ProjectivePoint`] operations. Every secret intermediate is
//! wiped with a [`core::hint::black_box`] barrier before the frame is released.
//!
//! [`verify`] operates purely on public data, so it takes no such precautions.

use super::field_backend::FieldBackend;
use super::{AffinePoint, ProjectivePoint, Scalar};
use crate::ct::{Choice, ConditionallySelectable};
use crate::ec::Error;
use crate::hash::{Digest, Sha256};
use crate::rng::{CryptoRng, RngCore};

/// BIP340 tag for the auxiliary-randomness hash.
const TAG_AUX: &str = "BIP0340/aux";
/// BIP340 tag for the nonce-derivation hash.
const TAG_NONCE: &str = "BIP0340/nonce";
/// BIP340 tag for the challenge hash.
const TAG_CHALLENGE: &str = "BIP0340/challenge";

/// The BIP340 tagged hash
/// `hash_tag(x) = SHA256(SHA256(tag) ‖ SHA256(tag) ‖ x)`, where `tag` is the
/// UTF-8 encoding of `tag` and `x` is the concatenation of `msgs`.
///
/// Prefixing with the 64-byte repeated tag hash domain-separates each use and
/// (because it is exactly one SHA-256 block) lets implementations precompute
/// the midstate.
///
/// Taking the message as a slice of parts avoids needing a heap buffer to
/// concatenate them — this module builds without `alloc`.
///
/// ```
/// # #[cfg(feature = "bip340")] {
/// use purecrypto::ec::secp256k1::schnorr::tagged_hash;
/// // hash_BIP0340/aux(0x00…00), the value XORed into the secret key when
/// // signing with all-zero auxiliary randomness.
/// let h = tagged_hash("BIP0340/aux", &[&[0u8; 32]]);
/// assert_eq!(h.len(), 32);
/// # }
/// ```
pub fn tagged_hash(tag: &str, msgs: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_hash.as_ref());
    h.update(tag_hash.as_ref());
    for m in msgs {
        h.update(m);
    }
    let out = h.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(out.as_ref());
    result
}

/// [`tagged_hash`] for a *secret* preimage: the hasher that absorbed the input
/// is explicitly zeroised instead of being consumed by `finalize`, so neither
/// the buffered block (which holds the last partial input) nor the chaining
/// state survives in the dead frame.
///
/// Used for the nonce hash, whose input `t` equals the secret key masked with
/// the aux hash — for all-zero aux (`sign_deterministic`) that mask is a public
/// constant, so leaking `t` would leak `d` outright.
fn tagged_hash_secret(tag: &str, msgs: &[&[u8]]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut h = Sha256::new();
    h.update(tag_hash.as_ref());
    h.update(tag_hash.as_ref());
    for m in msgs {
        h.update(m);
    }
    // Finalise a clone and zeroise the original, whose lifetime this function
    // controls; the consumed clone is the hash module's responsibility.
    let mut out = h.clone().finalize();
    h.zeroize();
    let mut result = [0u8; 32];
    result.copy_from_slice(out.as_ref());
    wipe(&mut out);
    result
}

/// Best-effort wipe of a 32-byte secret buffer, with an optimization barrier so
/// the stores are not elided (the idiom used by `ecdsa` and `secp256k1::Scalar`).
#[inline]
fn wipe(buf: &mut [u8; 32]) {
    buf.fill(0);
    let _ = core::hint::black_box(&buf);
}

/// BIP340 `lift_x`: the point `P` with `x(P) = x` and even `Y`.
///
/// Fails if `x ≥ p` or if `x³ + 7` is not a quadratic residue (i.e. `x` is not
/// the abscissa of any curve point). This is exactly the compressed-SEC1
/// decoding of `0x02 ‖ x`, which validates the range, recovers `y` by the
/// `p ≡ 3 (mod 4)` square root, verifies the root, and selects the even branch.
fn lift_x(x: &[u8; 32]) -> Result<AffinePoint, Error> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(x);
    AffinePoint::from_sec1(&compressed)
}

/// BIP340 `has_even_y(P)`, as a [`Choice`].
#[inline]
fn has_even_y(p: &AffinePoint) -> Choice {
    Choice::from((p.y_bytes()[31] & 1) ^ 1)
}

/// Constant-time `if choice { a } else { b }` for scalars.
///
/// [`Scalar`] does not implement [`ConditionallySelectable`], so the choice is
/// made over the canonical big-endian encodings and re-decoded. Both operands
/// are already reduced (`< n`), so the re-decode cannot fail.
fn select_scalar(a: &Scalar, b: &Scalar, choice: Choice) -> Scalar {
    let mut ab = a.to_bytes_be();
    let mut bb = b.to_bytes_be();
    let mut sel = <[u8; 32]>::conditional_select(&ab, &bb, choice);
    let out = Scalar::from_bytes_be(&sel);
    wipe(&mut ab);
    wipe(&mut bb);
    wipe(&mut sel);
    out.expect("both operands are canonical scalars < n")
}

/// `e = int(hash_BIP0340/challenge(bytes(R) ‖ bytes(P) ‖ m)) mod n`.
fn challenge(r: &[u8; 32], p: &[u8; 32], msg: &[u8]) -> Scalar {
    Scalar::from_bytes_be_reduce(&tagged_hash(TAG_CHALLENGE, &[r, p, msg]))
}

/// BIP340 `PubKey(sk)`: the 32-byte x-only public key `bytes(d'⋅G)`.
///
/// Note that `PubKey(sk) == PubKey(bytes(n − int(sk)))`, so every x-only public
/// key has two corresponding secret keys.
///
/// # Errors
/// [`Error::InvalidInput`] if `int(sk)` is `0` or `≥ n`.
pub fn public_key(seckey: &[u8; 32]) -> Result<[u8; 32], Error> {
    let d = Scalar::from_bytes_be(seckey).map_err(|_| Error::InvalidInput)?;
    if bool::from(d.is_zero()) {
        return Err(Error::InvalidInput);
    }
    let p = ProjectivePoint::mul_generator(&d)
        .to_affine()
        .ok_or(Error::InvalidInput)?;
    Ok(p.x_bytes())
}

/// BIP340 `Sign(sk, m)` with explicit auxiliary randomness `a`.
///
/// `msg` may be of any length. The returned 64-byte signature is
/// `bytes(R) ‖ bytes(s)`. As the BIP recommends, the signature is verified
/// before it is returned, so a computation fault cannot publish a signature
/// that leaks the secret key.
///
/// `aux_rand` should be 32 fresh random bytes; see the [module
/// docs](self#nonce-generation) and [`sign_with_rng`].
///
/// # Errors
/// [`Error::InvalidInput`] if `int(seckey)` is `0` or `≥ n`, or in the
/// cryptographically unreachable cases where the derived nonce is `0` or a
/// scalar multiplication yields the point at infinity.
/// [`Error::Verification`] if the final self-check fails.
pub fn sign(seckey: &[u8; 32], msg: &[u8], aux_rand: &[u8; 32]) -> Result<[u8; 64], Error> {
    // d' = int(sk); fail if d' = 0 or d' >= n.
    let d0 = Scalar::from_bytes_be(seckey).map_err(|_| Error::InvalidInput)?;
    if bool::from(d0.is_zero()) {
        return Err(Error::InvalidInput);
    }

    // P = d'⋅G; d = d' if has_even_y(P) else n - d'.
    let p = ProjectivePoint::mul_generator(&d0)
        .to_affine()
        .ok_or(Error::InvalidInput)?;
    let px = p.x_bytes();
    let d = select_scalar(&d0, &d0.negate(), has_even_y(&p));

    // t = bytes(d) XOR hash_BIP0340/aux(a).
    let mut t = d.to_bytes_be();
    let mut aux = tagged_hash(TAG_AUX, &[aux_rand]);
    for (tb, ab) in t.iter_mut().zip(aux.iter()) {
        *tb ^= *ab;
    }

    // rand = hash_BIP0340/nonce(t ‖ bytes(P) ‖ m); k' = int(rand) mod n.
    // `t` is the secret key under a mask that `aux` reveals (and that is a
    // public constant for all-zero aux), so both go through the wiping hash
    // path and are wiped themselves.
    let mut rand = tagged_hash_secret(TAG_NONCE, &[&t, &px, msg]);
    wipe(&mut t);
    wipe(&mut aux);
    let k0 = Scalar::from_bytes_be_reduce(&rand);
    wipe(&mut rand);
    if bool::from(k0.is_zero()) {
        return Err(Error::InvalidInput);
    }

    // R = k'⋅G; k = k' if has_even_y(R) else n - k'.
    let r = ProjectivePoint::mul_generator(&k0)
        .to_affine()
        .ok_or(Error::InvalidInput)?;
    let rx = r.x_bytes();
    let k = select_scalar(&k0, &k0.negate(), has_even_y(&r));

    // sig = bytes(R) ‖ bytes((k + e·d) mod n).
    let e = challenge(&rx, &px, msg);
    let s = k.add(&e.mul(&d));
    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&rx);
    sig[32..].copy_from_slice(&s.to_bytes_be());

    // BIP340: verify before leaving the signer.
    verify(&px, msg, &sig)?;
    Ok(sig)
}

/// [`sign`] with all-zero auxiliary randomness, i.e. a fully deterministic
/// signature.
///
/// The BIP explicitly permits this when randomness is not available at signing
/// time; it is what the official test vectors with an all-zero `aux_rand`
/// column exercise. Prefer [`sign_with_rng`] when entropy is available.
///
/// # Errors
/// As [`sign`].
pub fn sign_deterministic(seckey: &[u8; 32], msg: &[u8]) -> Result<[u8; 64], Error> {
    sign(seckey, msg, &[0u8; 32])
}

/// [`sign`] with the auxiliary randomness drawn from `rng`, producing a
/// *synthetic* nonce. This is the recommended way to sign.
///
/// `rng` must be a cryptographically secure CSPRNG (see [`CryptoRng`]).
///
/// # Errors
/// As [`sign`].
pub fn sign_with_rng<R: RngCore + CryptoRng>(
    seckey: &[u8; 32],
    msg: &[u8],
    rng: &mut R,
) -> Result<[u8; 64], Error> {
    let mut aux = [0u8; 32];
    rng.fill_bytes(&mut aux);
    let out = sign(seckey, msg, &aux);
    wipe(&mut aux);
    out
}

/// BIP340 `Verify(pk, m, sig)`.
///
/// Applies every validity rule in the BIP: `lift_x(int(pk))` must succeed
/// (so `pk < p` and `pk` must be a curve abscissa), `r = int(sig[0:32])` must
/// be `< p`, `s = int(sig[32:64])` must be `< n`, and with
/// `e = int(hash_BIP0340/challenge(bytes(r) ‖ bytes(P) ‖ m)) mod n` the point
/// `R = s⋅G − e⋅P` must not be infinite, must have even `Y`, and must satisfy
/// `x(R) = r`.
///
/// This function never panics: every 32-byte key and 64-byte signature is
/// accepted as input and answered with `Ok` or `Err`.
///
/// # Errors
/// [`Error::Verification`] if any of the above checks fails.
pub fn verify(pubkey_xonly: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), Error> {
    // P = lift_x(int(pk)); fail if that fails.
    let p = lift_x(pubkey_xonly).map_err(|_| Error::Verification)?;

    let mut r = [0u8; 32];
    r.copy_from_slice(&sig[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&sig[32..]);

    // r = int(sig[0:32]); fail if r >= p. (`from_bytes_be` is the field
    // decoder's range check, so `p` is not duplicated here.)
    if super::field().from_bytes_be(&r).into_option().is_none() {
        return Err(Error::Verification);
    }
    // s = int(sig[32:64]); fail if s >= n.
    let s = Scalar::from_bytes_be(&s_bytes).map_err(|_| Error::Verification)?;

    // R = s⋅G - e⋅P. Everything here is public, so no constant-time care is
    // owed; the ladder is used simply because it is the available primitive.
    let e = challenge(&r, pubkey_xonly, msg);
    let big_r = ProjectivePoint::mul_generator(&s).add(&p.to_projective().mul(&e.negate()));

    // Fail if is_infinite(R), if not has_even_y(R), or if x(R) != r.
    let r_aff = big_r.to_affine().ok_or(Error::Verification)?;
    if r_aff.y_bytes()[31] & 1 != 0 {
        return Err(Error::Verification);
    }
    if r_aff.x_bytes() != r {
        return Err(Error::Verification);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::HmacDrbg;

    // ---------------------------------------------------------------
    // Hex helpers (no `alloc`: everything lands in fixed-size buffers).
    // ---------------------------------------------------------------

    fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex digit"),
        }
    }

    /// Decodes `s` into `out`, returning the byte length.
    fn hex_into(s: &str, out: &mut [u8]) -> usize {
        let b = s.as_bytes();
        assert!(b.len().is_multiple_of(2), "odd-length hex");
        let n = b.len() / 2;
        assert!(n <= out.len(), "hex too long for buffer");
        for i in 0..n {
            out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        }
        n
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut o = [0u8; 32];
        assert_eq!(hex_into(s, &mut o), 32);
        o
    }

    fn hex64(s: &str) -> [u8; 64] {
        let mut o = [0u8; 64];
        assert_eq!(hex_into(s, &mut o), 64);
        o
    }

    // ---------------------------------------------------------------
    // The official BIP340 test vectors (bip-0340/test-vectors.csv,
    // indices 0..=18). An empty `seckey` means the vector is
    // verification-only.
    // ---------------------------------------------------------------

    struct Vector {
        index: u32,
        seckey: &'static str,
        pubkey: &'static str,
        aux: &'static str,
        msg: &'static str,
        sig: &'static str,
        valid: bool,
        comment: &'static str,
    }

    const VECTORS: &[Vector] = &[
        Vector {
            index: 0,
            seckey: "0000000000000000000000000000000000000000000000000000000000000003",
            pubkey: "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            aux: "0000000000000000000000000000000000000000000000000000000000000000",
            msg: "0000000000000000000000000000000000000000000000000000000000000000",
            sig: "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215\
                  25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
            valid: true,
            comment: "",
        },
        Vector {
            index: 1,
            seckey: "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
            pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux: "0000000000000000000000000000000000000000000000000000000000000001",
            msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            sig: "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341\
                  8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
            valid: true,
            comment: "",
        },
        Vector {
            index: 2,
            seckey: "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
            pubkey: "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
            aux: "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
            msg: "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
            sig: "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B\
                  AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
            valid: true,
            comment: "",
        },
        Vector {
            index: 3,
            seckey: "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
            pubkey: "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
            aux: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            msg: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            sig: "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC\
                  97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
            valid: true,
            comment: "test fails if msg is reduced modulo p or n",
        },
        Vector {
            index: 4,
            seckey: "",
            pubkey: "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
            aux: "",
            msg: "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
            sig: "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63\
                  76AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
            valid: true,
            comment: "",
        },
        Vector {
            index: 5,
            seckey: "",
            pubkey: "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
            aux: "",
            msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            sig: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769\
                  69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            valid: false,
            comment: "public key not on the curve",
        },
        Vector {
            index: 6,
            seckey: "",
            pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux: "",
            msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            sig: "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556\
                  3CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
            valid: false,
            comment: "has_even_y(R) is false",
        },
        Vector {
            index: 7,
            seckey: "",
            pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux: "",
            msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            sig: "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F\
                  28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
            valid: false,
            comment: "negated message",
        },
        Vector {
            index: 8,
            seckey: "",
            pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux: "",
            msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            sig: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769\
                  961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
            valid: false,
            comment: "negated s value",
        },
        Vector {
            index: 9,
            seckey: "",
            pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux: "",
            msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            sig: "0000000000000000000000000000000000000000000000000000000000000000\
                  123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
            valid: false,
            comment: "sG - eP is infinite; fails only if has_even_y(inf) is true and x(inf) is 0",
        },
        Vector {
            index: 10,
            seckey: "",
            pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux: "",
            msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            sig: "0000000000000000000000000000000000000000000000000000000000000001\
                  7615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
            valid: false,
            comment: "sG - eP is infinite; fails only if has_even_y(inf) is true and x(inf) is 1",
        },
        Vector {
            index: 11,
            seckey: "",
            pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux: "",
            msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            sig: "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D\
                  69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            valid: false,
            comment: "sig[0:32] is not an X coordinate on the curve",
        },
        Vector {
            index: 12,
            seckey: "",
            pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux: "",
            msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            sig: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F\
                  69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            valid: false,
            comment: "sig[0:32] is equal to field size",
        },
        Vector {
            index: 13,
            seckey: "",
            pubkey: "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            aux: "",
            msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            sig: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769\
                  FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            valid: false,
            comment: "sig[32:64] is equal to curve order",
        },
        Vector {
            index: 14,
            seckey: "",
            pubkey: "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
            aux: "",
            msg: "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
            sig: "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769\
                  69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
            valid: false,
            comment: "public key is not a valid X coordinate because it exceeds the field size",
        },
        Vector {
            index: 15,
            seckey: "0340034003400340034003400340034003400340034003400340034003400340",
            pubkey: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
            aux: "0000000000000000000000000000000000000000000000000000000000000000",
            msg: "",
            sig: "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF\
                  6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
            valid: true,
            comment: "message of size 0",
        },
        Vector {
            index: 16,
            seckey: "0340034003400340034003400340034003400340034003400340034003400340",
            pubkey: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
            aux: "0000000000000000000000000000000000000000000000000000000000000000",
            msg: "11",
            sig: "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303\
                  EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
            valid: true,
            comment: "message of size 1",
        },
        Vector {
            index: 17,
            seckey: "0340034003400340034003400340034003400340034003400340034003400340",
            pubkey: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
            aux: "0000000000000000000000000000000000000000000000000000000000000000",
            msg: "0102030405060708090A0B0C0D0E0F1011",
            sig: "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370\
                  C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
            valid: true,
            comment: "message of size 17",
        },
        Vector {
            index: 18,
            seckey: "0340034003400340034003400340034003400340034003400340034003400340",
            pubkey: "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
            aux: "0000000000000000000000000000000000000000000000000000000000000000",
            msg: "9999999999999999999999999999999999999999999999999999999999999999\
                  9999999999999999999999999999999999999999999999999999999999999999\
                  9999999999999999999999999999999999999999999999999999999999999999\
                  99999999",
            sig: "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8\
                  585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
            valid: true,
            comment: "message of size 100",
        },
    ];

    /// The full official table: for every vector with a secret key, the derived
    /// x-only public key and the produced signature must match byte for byte;
    /// for every vector, `verify` must return exactly the stated verdict.
    #[test]
    fn bip340_official_test_vectors() {
        let mut msg_buf = [0u8; 128];
        let mut count = 0usize;
        for v in VECTORS {
            let msg_len = hex_into(v.msg, &mut msg_buf);
            let msg = &msg_buf[..msg_len];
            let pk = hex32(v.pubkey);
            let sig = hex64(v.sig);

            if !v.seckey.is_empty() {
                let sk = hex32(v.seckey);
                let aux = hex32(v.aux);
                assert_eq!(
                    public_key(&sk).unwrap(),
                    pk,
                    "vector {}: public key mismatch",
                    v.index
                );
                assert_eq!(
                    sign(&sk, msg, &aux).unwrap(),
                    sig,
                    "vector {}: signature mismatch",
                    v.index
                );
            }

            let got = verify(&pk, msg, &sig).is_ok();
            assert_eq!(
                got, v.valid,
                "vector {}: expected verify == {} ({})",
                v.index, v.valid, v.comment
            );
            count += 1;
        }
        assert_eq!(count, 19, "the official CSV has 19 vectors (0..=18)");
    }

    /// Vectors 15..=18 alone: BIP340 signs a message of any length, including
    /// the empty message.
    #[test]
    fn variable_length_messages() {
        let sk = hex32("0340034003400340034003400340034003400340034003400340034003400340");
        let pk = public_key(&sk).unwrap();
        let long = [0x99u8; 100];
        for msg in [&[][..], &[0x11][..], &long[..70], &long[..]] {
            let sig = sign_deterministic(&sk, msg).unwrap();
            verify(&pk, msg, &sig).unwrap();
            // A one-byte-longer message must not verify under the same sig.
            let mut extended = [0u8; 101];
            extended[..msg.len()].copy_from_slice(msg);
            assert!(verify(&pk, &extended[..msg.len() + 1], &sig).is_err());
        }
    }

    /// `sign_deterministic` is exactly `sign` with all-zero auxiliary
    /// randomness (the convention the official vectors use).
    #[test]
    fn deterministic_matches_zero_aux() {
        let sk = hex32("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
        let msg = b"deterministic";
        assert_eq!(
            sign_deterministic(&sk, msg).unwrap(),
            sign(&sk, msg, &[0u8; 32]).unwrap()
        );
    }

    /// Round trip through the RNG-fed signing path: synthetic nonces differ
    /// between runs, and every resulting signature verifies.
    #[test]
    fn sign_with_rng_round_trip() {
        let mut rng = HmacDrbg::<Sha256>::new(b"bip340-sign", b"nonce", &[]);
        let sk = hex32("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9");
        let pk = public_key(&sk).unwrap();
        let msg = b"synthetic nonce round trip";

        let a = sign_with_rng(&sk, msg, &mut rng).unwrap();
        let b = sign_with_rng(&sk, msg, &mut rng).unwrap();
        verify(&pk, msg, &a).unwrap();
        verify(&pk, msg, &b).unwrap();
        assert_ne!(a, b, "fresh aux randomness must change the nonce");
        // Wrong message / wrong key are rejected.
        assert!(verify(&pk, b"other message", &a).is_err());
        let other = public_key(&hex32(
            "0000000000000000000000000000000000000000000000000000000000000003",
        ))
        .unwrap();
        assert!(verify(&other, msg, &a).is_err());
    }

    /// BIP340 `Sign` fails for `d' = 0` and for `d' >= n`; so does `PubKey`.
    #[test]
    fn rejects_out_of_range_secret_keys() {
        let n = hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
        for bad in [
            [0u8; 32],
            n,
            [0xffu8; 32],
            hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142"),
        ] {
            assert_eq!(public_key(&bad), Err(Error::InvalidInput));
            assert_eq!(sign(&bad, b"m", &[0u8; 32]), Err(Error::InvalidInput));
            assert_eq!(sign_deterministic(&bad, b"m"), Err(Error::InvalidInput));
        }
        // n - 1 is the largest valid secret key.
        let max = hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
        let pk = public_key(&max).unwrap();
        verify(&pk, b"m", &sign_deterministic(&max, b"m").unwrap()).unwrap();
    }

    /// `PubKey(sk) == PubKey(n - sk)`: every x-only key has two secret keys,
    /// and both produce signatures that verify under it.
    #[test]
    fn negated_secret_key_yields_same_public_key() {
        let sk = hex32("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF");
        let neg = Scalar::from_bytes_be(&sk).unwrap().negate().to_bytes_be();
        assert_eq!(public_key(&sk).unwrap(), public_key(&neg).unwrap());
        let pk = public_key(&sk).unwrap();
        verify(&pk, b"twin", &sign_deterministic(&neg, b"twin").unwrap()).unwrap();
    }

    /// `verify` must answer, never panic, for arbitrary 32-byte keys and
    /// 64-byte signatures — including the all-zero and all-one extremes and
    /// bit-flipped valid signatures.
    #[test]
    fn verify_never_panics_on_arbitrary_input() {
        let sk = hex32("0340034003400340034003400340034003400340034003400340034003400340");
        let pk = public_key(&sk).unwrap();
        let sig = sign_deterministic(&sk, b"fuzz").unwrap();

        assert!(verify(&[0u8; 32], b"fuzz", &[0u8; 64]).is_err());
        assert!(verify(&[0xffu8; 32], b"fuzz", &[0xffu8; 64]).is_err());
        assert!(verify(&pk, b"fuzz", &[0u8; 64]).is_err());

        // Every single-bit corruption of a valid signature is rejected.
        for byte in 0..64usize {
            for bit in 0..8u32 {
                let mut bad = sig;
                bad[byte] ^= 1 << bit;
                assert!(verify(&pk, b"fuzz", &bad).is_err());
            }
        }
        // Random keys and signatures: just must not panic.
        let mut rng = HmacDrbg::<Sha256>::new(b"bip340-fuzz", b"nonce", &[]);
        for _ in 0..256 {
            let mut k = [0u8; 32];
            let mut s = [0u8; 64];
            rng.fill_bytes(&mut k);
            rng.fill_bytes(&mut s);
            let _ = verify(&k, b"fuzz", &s);
            let _ = verify(&pk, b"fuzz", &s);
        }
    }

    /// `tagged_hash` really is `SHA256(SHA256(tag) ‖ SHA256(tag) ‖ x)`, and the
    /// message parts are concatenated (splitting them changes nothing).
    #[test]
    fn tagged_hash_structure() {
        let tag = "BIP0340/challenge";
        let th = Sha256::digest(tag.as_bytes());
        let mut h = Sha256::new();
        h.update(th.as_ref());
        h.update(th.as_ref());
        h.update(b"abcdef");
        let expected = h.finalize();
        assert_eq!(tagged_hash(tag, &[b"abcdef"]), *expected.as_ref());
        assert_eq!(
            tagged_hash(tag, &[b"abc", b"def"]),
            tagged_hash(tag, &[b"abcdef"])
        );
        // Distinct tags are domain-separated.
        assert_ne!(
            tagged_hash("BIP0340/aux", &[b"x"]),
            tagged_hash("BIP0340/nonce", &[b"x"])
        );
    }

    /// `lift_x` is BIP340's: it rejects `x >= p` and non-residues, and always
    /// returns the even-`Y` lift.
    #[test]
    fn lift_x_rules() {
        // x = p and x = p + 1 are out of range.
        assert!(
            lift_x(&hex32(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
            ))
            .is_err()
        );
        assert!(
            lift_x(&hex32(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30"
            ))
            .is_err()
        );
        // Vector 5's key is a valid field element but not a curve abscissa.
        assert!(
            lift_x(&hex32(
                "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34"
            ))
            .is_err()
        );
        // A real key lifts to the even-Y point with the same x.
        let pk = hex32("DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659");
        let p = lift_x(&pk).unwrap();
        assert_eq!(p.x_bytes(), pk);
        assert_eq!(p.y_bytes()[31] & 1, 0);
        assert!(bool::from(has_even_y(&p)));
    }
}
