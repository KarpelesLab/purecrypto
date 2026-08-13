//! Shared EMSA padding for RSA signatures and encryption (RFC 8017),
//! parameterized over the raw RSA primitive so both the const-generic
//! [`RsaPublicKey`](super::RsaPublicKey)/[`RsaPrivateKey`](super::RsaPrivateKey)
//! and the runtime-sized boxed keys reuse one implementation.
//!
//! # Allocation
//!
//! This module is allocator-free: every routine works in caller-supplied
//! buffers, so the const-generic keys can drive it from exact-size stack
//! scratch while the boxed keys hand it `Vec`s. There is exactly one
//! implementation of each constant-time check — the padding logic here is
//! Bleichenbacher/Manger-sensitive and must never be forked per backend.
//!
//! The buffers a caller must supply are all `k = key_size()` octets. Two
//! techniques keep it to that: `m'` in PSS is streamed into the digest rather
//! than assembled, and MGF1 XORs its mask directly into the destination
//! ([`mgf1_xor`]) rather than materializing it.

use super::{Error, Pkcs1Digest};
use crate::ct::{ConstantTimeEq, ConstantTimeLess};
use crate::hash::Digest;
use crate::rng::RngCore;

/// The raw RSA public operation (`m^e mod n`) plus modulus metadata.
pub(crate) trait RawPublic {
    /// Modulus length in octets (`k`).
    fn key_size(&self) -> usize;
    /// Modulus bit length.
    fn modulus_bits(&self) -> usize;
    /// `m^e mod n` computed in place: `buf` is exactly `key_size()` octets and
    /// holds the big-endian base (`< n`) on entry, the big-endian result on
    /// exit. In-place so a whole operation needs one `k`-byte buffer rather
    /// than a separate input and output.
    fn raw_public_in_place(&self, buf: &mut [u8]);
}

/// Exposes the modulus `n` as a `k`-byte big-endian buffer so signature
/// verification can enforce RFC 8017 §5.2.2 RSAVP1 step 1 (`0 <= s < n`)
/// before applying the public op. Without this check, the Montgomery `pow`
/// implicitly reduces the base mod `n`, so `s + t·n` would verify identically
/// to `s` — a signature-malleability gap.
///
/// This is a separate trait from [`RawPublic`] so that the two public-key
/// backends (const-generic `RsaPublicKey` and runtime-sized
/// `BoxedRsaPublicKey`) each supply it from the module that owns their
/// modulus, without routing `n` through the raw primitive (which would also
/// affect the signing / encryption callers that legitimately operate on
/// values already reduced mod `n`).
pub(crate) trait PublicModulus {
    /// Writes the modulus `n` into `out` as exactly `key_size()` big-endian
    /// octets.
    fn modulus_be_into(&self, out: &mut [u8]);
}

/// Constant-time `a < b` for two equal-length big-endian byte slices.
///
/// Walks every byte; the running time depends only on the (public) length,
/// not on where the slices first differ. Used to reject signature
/// representatives `s >= n` (RFC 8017 §5.2.2 step 1) without an early-exit
/// that would leak the magnitude of `s` relative to `n`.
fn ct_lt_be(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    // `lt` is set (low bit 1) once a strictly-smaller higher-order byte has
    // been seen, `gt` likewise for strictly-greater. Only the first differing
    // position (scanning MSB -> LSB) may flip a flag, since each update is
    // gated on neither flag being set yet; the final `lt` is therefore the
    // big-integer comparison. No data-dependent branches.
    let mut lt: u8 = 0;
    let mut gt: u8 = 0;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let undecided = !(lt | gt);
        lt |= undecided & ct_lt_u8(x, y);
        gt |= undecided & ct_lt_u8(y, x);
    }
    (lt & 1) == 1
}

/// Returns `0xff` if `a < b`, else `0x00`, in constant time.
#[inline]
fn ct_lt_u8(a: u8, b: u8) -> u8 {
    0u8.wrapping_sub(a.ct_lt(&b).unwrap_u8())
}

/// The raw RSA private operation (`c^d mod n`) plus modulus metadata.
pub(crate) trait RawPrivate {
    /// Modulus length in octets (`k`).
    fn key_size(&self) -> usize;
    /// Modulus bit length.
    fn modulus_bits(&self) -> usize;
    /// `c^d mod n` computed in place, with the same buffer contract as
    /// [`RawPublic::raw_public_in_place`].
    fn raw_private_in_place(&self, buf: &mut [u8]);
    /// A stable per-key 32-byte secret used to derive the synthetic
    /// plaintext for PKCS#1 v1.5 implicit rejection (RFC 8017 §7.2.2 Note).
    /// Must be the same value for every call on a given key, and unknown to
    /// anyone without the private key.
    fn secret_seed(&self) -> [u8; 32];
}

// --------------------------------------------------------------------------
// PKCS#1 v1.5
// --------------------------------------------------------------------------

/// Encrypts into `out`, which must be exactly `key_size()` octets and receives
/// the ciphertext.
pub(crate) fn encrypt_pkcs1v15<K: RawPublic, R: RngCore>(
    key: &K,
    msg: &[u8],
    rng: &mut R,
    out: &mut [u8],
) -> Result<(), Error> {
    let k = key.key_size();
    if out.len() != k {
        return Err(Error::InvalidLength);
    }
    if msg.len() + 11 > k {
        return Err(Error::MessageTooLong);
    }
    let ps_len = k - msg.len() - 3;
    out.fill(0);
    out[1] = 0x02;
    fill_nonzero(&mut out[2..2 + ps_len], rng);
    // out[2 + ps_len] stays 0x00 (separator)
    out[k - msg.len()..].copy_from_slice(msg);
    key.raw_public_in_place(out);
    Ok(())
}

/// Decrypts a PKCS#1 v1.5 ciphertext and returns the recovered message bytes.
///
/// The padding check itself is constant-time, but the **length** of the
/// returned `Vec` (and the success / `Error::Decryption` distinction) reveals
/// where the 0x00 separator was found — i.e. a classic Bleichenbacher
/// length / padding oracle when the caller's downstream behavior is
/// observable to an attacker (timing, error visibility, response length).
///
/// Use [`decrypt_pkcs1v15_session`] for protocols where the plaintext length
/// is known a priori (TLS 1.0–1.2 RSA key transport, CMS): it produces a
/// fixed-width, key-bound synthetic plaintext on padding failure that the
/// attacker cannot distinguish from a real one.
/// RFC 8017 §7.2.2 constant-time PKCS#1 v1.5 padding validation, shared by
/// [`decrypt_pkcs1v15`] and [`decrypt_pkcs1v15_session`].
///
/// Walks the decrypted block `em` (which the callers guarantee is at least 11
/// bytes long) and returns `(bad, sep_idx)`. Every check on plaintext bytes is
/// folded into the single `bad` accumulator — nonzero iff the padding is
/// malformed — so the running time is independent of the (secret) contents
/// (Bleichenbacher / Manger / ROBOT). `sep_idx` is the index of the first
/// `0x00` separator after the `00 02` prefix; the plaintext is
/// `em[sep_idx + 1..]`.
fn pkcs1v15_padding_check(em: &[u8]) -> (u8, u32) {
    let mut bad: u8 = em[0]; // must be 0x00
    bad |= em[1] ^ 0x02; //   must be 0x02

    // Scan em[2..] for the first 0x00 separator. We unconditionally walk every
    // byte; the only state that depends on the value is the captured `sep_idx`
    // (the position of the first zero) and the `found` flag.
    let mut found: u8 = 0;
    let mut sep_idx: u32 = 0;
    for (i, &b) in em.iter().enumerate().skip(2) {
        let is_zero = ct_eq_u8(b, 0x00) & !found;
        // Broadcast the per-byte mask (0x00/0xff) to the full index width before
        // AND-ing. A bare `is_zero as u32` zero-extends to 0x000000ff, which would
        // keep only the low 8 bits of `i` and truncate any separator at index
        // >= 256 (keys > 2048-bit). The wrapping_sub turns the boolean low bit
        // into an all-ones / all-zeros u32 mask.
        let mask = 0u32.wrapping_sub((is_zero & 1) as u32);
        sep_idx |= (i as u32) & mask;
        found |= is_zero;
    }
    bad |= !found; // no separator found ⇒ invalid

    // PS must be at least 8 bytes ⇒ sep_idx >= 10 (positions 2..10 are PS).
    // ct_lt yields a Choice that is true when sep_idx < 10.
    let too_small = sep_idx.ct_lt(&10u32).unwrap_u8();
    bad |= 0u8.wrapping_sub(too_small);

    (bad, sep_idx)
}

/// `scratch` must be exactly `key_size()` octets. The recovered message is
/// written to `out` and its length returned; `out` must be large enough for the
/// longest plaintext the caller is willing to accept (`k - 11` always
/// suffices). Both lengths are public, so the checks on them leak nothing.
pub(crate) fn decrypt_pkcs1v15<K: RawPrivate>(
    key: &K,
    ct: &[u8],
    scratch: &mut [u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let k = key.key_size();
    if ct.len() != k || scratch.len() != k {
        return Err(Error::InvalidLength);
    }
    // RFC 8017 §7.2.2 step 1: `k` must be at least 11 octets so the PS field
    // (>= 8 bytes) plus the three framing bytes (0x00 0x02 ... 0x00) can fit.
    // A smaller modulus could otherwise drive the `em[0]` / `em[1]` indexing
    // below into a panic on attacker-controlled tiny keys.
    if k < 11 {
        return Err(Error::InvalidLength);
    }
    scratch.copy_from_slice(ct);
    key.raw_private_in_place(scratch);

    // Constant-time padding validation. The returned length below still leaks
    // across success/failure boundaries — for protocol-level implicit rejection
    // that hides even that, see [`decrypt_pkcs1v15_session`].
    let (bad, sep_idx) = pkcs1v15_padding_check(scratch);

    if bad != 0 {
        return Err(Error::Decryption);
    }
    let msg = &scratch[(sep_idx as usize) + 1..];
    if out.len() < msg.len() {
        return Err(Error::InvalidLength);
    }
    out[..msg.len()].copy_from_slice(msg);
    Ok(msg.len())
}

/// Constant-time PKCS#1 v1.5 decryption with implicit rejection (RFC 8017
/// §7.2.2 Note, the "Marvin" / TLS 1.2-style construction): on padding failure
/// the function returns a deterministic pseudorandom buffer of length
/// `expected_len` derived from the ciphertext and a key-bound secret, instead
/// of an error. The caller therefore sees no observable difference between a
/// successful decryption with the wrong content and a padding-malformed
/// ciphertext — this is the only way to defeat a Bleichenbacher oracle when
/// the caller's subsequent processing might leak the outcome via timing,
/// length, or behavior.
///
/// The per-key secret is obtained from the [`RawPrivate::secret_seed`] hook so
/// that every call on the same key sees the same fallback seed but an
/// attacker without the private key cannot predict it.
///
/// # Errors
/// Only [`Error::InvalidLength`] when the ciphertext length is wrong (this is
/// public, not secret-dependent). All padding outcomes return `Ok` — either
/// the real plaintext or the synthetic fallback.
/// `out.len()` is the `expected_len` of the construction: the caller sizes the
/// buffer to the plaintext length its protocol mandates, and the buffer is
/// always filled completely. `scratch` must be exactly `key_size()` octets.
pub(crate) fn decrypt_pkcs1v15_session<K: RawPrivate>(
    key: &K,
    ct: &[u8],
    scratch: &mut [u8],
    out: &mut [u8],
) -> Result<(), Error> {
    use crate::ct::ConditionallySelectable;
    use crate::hash::HmacSha256;

    let k = key.key_size();
    if ct.len() != k || scratch.len() != k {
        return Err(Error::InvalidLength);
    }
    // RFC 8017 §7.2.2 step 1: see [`decrypt_pkcs1v15`].
    if k < 11 {
        return Err(Error::InvalidLength);
    }
    scratch.copy_from_slice(ct);
    key.raw_private_in_place(scratch);
    let em: &[u8] = scratch;

    // Same constant-time padding check as decrypt_pkcs1v15.
    let (bad, sep_idx) = pkcs1v15_padding_check(em);

    // Derive the synthetic fallback: HMAC(key_secret, ct) expanded to expected_len.
    // The derivation is keyed by the long-term private value so the attacker
    // cannot predict the fallback. Pseudorandomness is provided by HMAC-SHA256.
    // Expanded straight into `out` rather than into a temporary: `out` is
    // overwritten in place below by the constant-time merge, which reads each
    // fallback byte once before replacing it.
    let key_secret = key.secret_seed();
    let mut counter: u32 = 0;
    let mut off = 0;
    while off < out.len() {
        let mut h = HmacSha256::new(&key_secret);
        h.update(b"purecrypto-rsa-pkcs1v15-implicit-reject-v1");
        h.update(ct);
        h.update(&counter.to_be_bytes());
        let tag = h.finalize();
        let take = core::cmp::min(tag.as_ref().len(), out.len() - off);
        out[off..off + take].copy_from_slice(&tag.as_ref()[..take]);
        off += take;
        counter += 1;
    }

    // Constant-time merge: when bad == 0, take the real plaintext bytes; else
    // take the fallback. The real-plaintext length is variable (depends on
    // sep_idx) but the OUTPUT length is always `expected_len`, so the timing /
    // size of the return value reveals nothing.
    // The real plaintext starts one past the separator. `sep_idx` (and thus
    // this offset) is secret, so the copy below must not index `em` with it:
    // a secret-offset load is a cache side channel that would re-open the
    // exact Bleichenbacher oracle this function exists to close. Instead, for
    // each output position the inner loop touches EVERY byte of `em` in a
    // fixed address sequence and masks in the one whose index matches
    // `real_start + j`. O(k²) over a ≤512-byte buffer on a per-handshake path
    // — negligible next to the private-key operation above.
    let real_start = sep_idx.wrapping_add(1);
    // Fold any nonzero bit of `bad` down into bit 0 so we can build a Choice.
    let mut fold = bad;
    fold |= fold >> 4;
    fold |= fold >> 2;
    fold |= fold >> 1;
    let bad_choice = crate::ct::Choice::from(fold & 1);

    for (j, slot) in out.iter_mut().enumerate() {
        // The "real" byte is em[real_start + j] when it exists. When that
        // index falls past the end of `em` (bad padding, or a message shorter
        // than out.len()), no index matches and `real_byte` stays 0 — and
        // the conditional select suppresses it anyway.
        let want = real_start.wrapping_add(j as u32);
        let mut real_byte = 0u8;
        for (i, &b) in em.iter().enumerate() {
            let hit = (i as u32).ct_eq(&want).unwrap_u8();
            real_byte |= b & 0u8.wrapping_sub(hit);
        }
        // `conditional_select(a, b, choice)` returns `a` iff `choice`; we want
        // the fallback when padding was bad, otherwise the real byte. `out[j]`
        // still holds the fallback byte at this point, so it is read into
        // `fallback_byte` before being overwritten — keeping the argument order
        // (and therefore the polarity) identical to the allocating version.
        let fallback_byte = *slot;
        *slot = u8::conditional_select(&fallback_byte, &real_byte, bad_choice);
    }
    Ok(())
}

/// Signs into `out`, which must be exactly `key_size()` octets.
pub(crate) fn sign_pkcs1v15<D: Pkcs1Digest, K: RawPrivate>(
    key: &K,
    msg: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    if out.len() != key.key_size() {
        return Err(Error::InvalidLength);
    }
    encode_pkcs1v15::<D>(msg, out)?;
    key.raw_private_in_place(out);
    Ok(())
}

/// Verification needs two `key_size()`-octet scratch buffers: one for the
/// recovered encoded message and one that holds first the modulus (for the
/// RSAVP1 range check) and then the expected encoding to compare against.
pub(crate) fn verify_pkcs1v15<D: Pkcs1Digest, K: RawPublic + PublicModulus>(
    key: &K,
    msg: &[u8],
    sig: &[u8],
    em: &mut [u8],
    expected: &mut [u8],
) -> Result<(), Error> {
    let k = key.key_size();
    if sig.len() != k || em.len() != k || expected.len() != k {
        return Err(Error::InvalidLength);
    }
    // RFC 8017 §5.2.2 RSAVP1 step 1: reject the signature representative unless
    // `0 <= s < n`. The Montgomery `pow` would otherwise reduce `s` mod `n`
    // implicitly, so `s + t·n` would verify identically to `s` (signature
    // malleability). `sig` is already exactly `k` bytes (length checked above)
    // and `n`'s buffer is `k` bytes, so the comparison is over equal widths.
    key.modulus_be_into(expected);
    if !ct_lt_be(sig, expected) {
        return Err(Error::Verification);
    }
    em.copy_from_slice(sig);
    key.raw_public_in_place(em);
    // `expected` has served its turn as the modulus buffer; reuse it for the
    // expected encoding rather than demanding a third buffer from the caller.
    encode_pkcs1v15::<D>(msg, expected)?;
    if bool::from(em.ct_eq(&*expected)) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

/// EMSA-PKCS1-v1_5 over an already-formed `T` block (`DigestInfo`, or a bare
/// pre-hash with no `DigestInfo` as TLS 1.0/1.1 use): `0x00 || 0x01 || PS(0xff…)
/// || 0x00 || t`. Legacy-TLS only.
#[cfg(feature = "tls-legacy")]
fn encode_pkcs1v15_prehashed(t: &[u8], em: &mut [u8]) -> Result<(), Error> {
    let k = em.len();
    if t.len() + 11 > k {
        return Err(Error::MessageTooLong);
    }
    let ps_len = k - t.len() - 3;
    em.fill(0);
    em[1] = 0x01;
    for b in &mut em[2..2 + ps_len] {
        *b = 0xff;
    }
    let t_start = 2 + ps_len + 1;
    em[t_start..].copy_from_slice(t);
    Ok(())
}

/// PKCS#1 v1.5 signature over a pre-computed hash `t` with **no `DigestInfo`
/// wrapping** — the TLS 1.0/1.1 (and SSLv3) handshake-signature convention,
/// where RSA signs the bare `MD5(16) || SHA1(20)` (or SHA-1 alone). Legacy only.
#[cfg(feature = "tls-legacy")]
pub(crate) fn sign_pkcs1v15_raw<K: RawPrivate>(
    key: &K,
    t: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    if out.len() != key.key_size() {
        return Err(Error::InvalidLength);
    }
    encode_pkcs1v15_prehashed(t, out)?;
    key.raw_private_in_place(out);
    Ok(())
}

/// Verifies a [`sign_pkcs1v15_raw`] signature over the pre-computed hash `t`.
#[cfg(feature = "tls-legacy")]
pub(crate) fn verify_pkcs1v15_raw<K: RawPublic + PublicModulus>(
    key: &K,
    t: &[u8],
    sig: &[u8],
    em: &mut [u8],
    expected: &mut [u8],
) -> Result<(), Error> {
    let k = key.key_size();
    if sig.len() != k || em.len() != k || expected.len() != k {
        return Err(Error::InvalidLength);
    }
    // RSAVP1 step 1: reject unless 0 <= s < n (same malleability guard as the
    // DigestInfo path above).
    key.modulus_be_into(expected);
    if !ct_lt_be(sig, expected) {
        return Err(Error::Verification);
    }
    em.copy_from_slice(sig);
    key.raw_public_in_place(em);
    encode_pkcs1v15_prehashed(t, expected)?;
    if bool::from(em.ct_eq(&*expected)) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

/// EMSA-PKCS1-v1_5: `0x00 || 0x01 || PS(0xff…) || 0x00 || DigestInfo`.
fn encode_pkcs1v15<D: Pkcs1Digest>(msg: &[u8], em: &mut [u8]) -> Result<(), Error> {
    let k = em.len();
    let digest = D::digest(msg);
    let prefix = D::DIGEST_INFO_PREFIX;
    let t_len = prefix.len() + digest.as_ref().len();
    if t_len + 11 > k {
        return Err(Error::MessageTooLong);
    }
    let ps_len = k - t_len - 3;
    em.fill(0);
    em[1] = 0x01;
    for b in &mut em[2..2 + ps_len] {
        *b = 0xff;
    }
    let t_start = 2 + ps_len + 1;
    em[t_start..t_start + prefix.len()].copy_from_slice(prefix);
    em[t_start + prefix.len()..].copy_from_slice(digest.as_ref());
    Ok(())
}

fn fill_nonzero<R: RngCore>(dst: &mut [u8], rng: &mut R) {
    for slot in dst.iter_mut() {
        loop {
            let mut b = [0u8; 1];
            rng.fill_bytes(&mut b);
            if b[0] != 0 {
                *slot = b[0];
                break;
            }
        }
    }
}

// --------------------------------------------------------------------------
// PSS (RFC 8017 §8.1). The default salt length is the digest length (the
// profile used by TLS 1.3 and the X.509 PSS parameter set); the
// `*_with_salt_len` / `*_any_salt` variants relax that for general interop.
// --------------------------------------------------------------------------

pub(crate) fn sign_pss<D: Digest, K: RawPrivate, R: RngCore>(
    key: &K,
    msg: &[u8],
    rng: &mut R,
    out: &mut [u8],
) -> Result<(), Error> {
    sign_pss_with_salt_len::<D, K, R>(key, msg, D::OUTPUT_LEN, rng, out)
}

pub(crate) fn sign_pss_with_salt_len<D: Digest, K: RawPrivate, R: RngCore>(
    key: &K,
    msg: &[u8],
    salt_len: usize,
    rng: &mut R,
    out: &mut [u8],
) -> Result<(), Error> {
    let k = key.key_size();
    if out.len() != k {
        return Err(Error::InvalidLength);
    }
    let em_bits = key.modulus_bits() - 1;
    let em_len = em_bits.div_ceil(8);
    // EM is right-aligned in the k-octet block: when the modulus top byte is
    // < 0x80, em_len == k - 1 and the leading octet stays zero.
    out.fill(0);
    emsa_pss_encode::<D, R>(msg, em_bits, salt_len, rng, &mut out[k - em_len..])?;
    key.raw_private_in_place(out);
    Ok(())
}

pub(crate) fn verify_pss<D: Digest, K: RawPublic + PublicModulus>(
    key: &K,
    msg: &[u8],
    sig: &[u8],
    em: &mut [u8],
    db: &mut [u8],
) -> Result<(), Error> {
    verify_pss_inner::<D, K>(key, msg, sig, Some(D::OUTPUT_LEN), em, db)
}

/// Verifies an RSA-PSS signature requiring the salt to be exactly `salt_len`
/// octets.
pub(crate) fn verify_pss_with_salt_len<D: Digest, K: RawPublic + PublicModulus>(
    key: &K,
    msg: &[u8],
    sig: &[u8],
    salt_len: usize,
    em: &mut [u8],
    db: &mut [u8],
) -> Result<(), Error> {
    verify_pss_inner::<D, K>(key, msg, sig, Some(salt_len), em, db)
}

/// Verifies an RSA-PSS signature, recovering the salt length from the encoded
/// message (accepts any valid salt length).
pub(crate) fn verify_pss_any_salt<D: Digest, K: RawPublic + PublicModulus>(
    key: &K,
    msg: &[u8],
    sig: &[u8],
    em: &mut [u8],
    db: &mut [u8],
) -> Result<(), Error> {
    verify_pss_inner::<D, K>(key, msg, sig, None, em, db)
}

/// `em` and `db` are both `key_size()`-octet scratch buffers: `em` holds the
/// modulus for the RSAVP1 range check and then the recovered encoded message,
/// `db` the unmasked data block (which is shorter than `k`, so only a prefix is
/// used).
fn verify_pss_inner<D: Digest, K: RawPublic + PublicModulus>(
    key: &K,
    msg: &[u8],
    sig: &[u8],
    salt_len: Option<usize>,
    em: &mut [u8],
    db: &mut [u8],
) -> Result<(), Error> {
    let k = key.key_size();
    if sig.len() != k || em.len() != k || db.len() != k {
        return Err(Error::InvalidLength);
    }
    // RFC 8017 §5.2.2 RSAVP1 step 1: reject `s >= n` (see verify_pkcs1v15 for
    // why the implicit Montgomery reduction makes this a malleability gap).
    key.modulus_be_into(em);
    if !ct_lt_be(sig, em) {
        return Err(Error::Verification);
    }
    em.copy_from_slice(sig);
    key.raw_public_in_place(em);
    let m: &[u8] = em;
    let em_bits = key.modulus_bits() - 1;
    let em_len = em_bits.div_ceil(8);
    // RFC 8017 §9.1.2 EMSA-PSS-VERIFY step 5 (read as the inverse of EME-PSS
    // step 12 in §8.1.1): when `em_len < k` (modulus top byte < 0x80) the
    // leading `k - em_len` octets of `m` are not part of the encoded message
    // and MUST be zero. Slicing them away silently — as the previous code did
    // — would accept a representative whose high octets are nonzero. With the
    // `s < n` check above this is already implied, but RFC 8017 requires the
    // explicit check, so we keep it.
    if m[..k - em_len].iter().any(|&b| b != 0) {
        return Err(Error::Verification);
    }
    emsa_pss_verify::<D>(msg, &m[k - em_len..], em_bits, salt_len, db)
}

// --------------------------------------------------------------------------
// OAEP (RFC 8017 §7.1)
// --------------------------------------------------------------------------

/// Encrypts into `out`, which must be exactly `key_size()` octets.
///
/// EM = `0x00 ‖ maskedSeed ‖ maskedDB` is assembled directly in `out`: the seed
/// and DB are built at their final offsets and masked through disjoint
/// `split_at_mut` borrows, so no separate seed/DB/mask buffers are needed.
pub(crate) fn encrypt_oaep<D: Digest, K: RawPublic, R: RngCore>(
    key: &K,
    msg: &[u8],
    label: &[u8],
    rng: &mut R,
    out: &mut [u8],
) -> Result<(), Error> {
    let k = key.key_size();
    let h_len = D::OUTPUT_LEN;
    if out.len() != k {
        return Err(Error::InvalidLength);
    }
    if k < 2 * h_len + 2 || msg.len() > k - 2 * h_len - 2 {
        return Err(Error::MessageTooLong);
    }

    out[0] = 0x00;
    let (seed, db) = out[1..].split_at_mut(h_len);

    // DB = lHash ‖ PS ‖ 0x01 ‖ M
    db.fill(0);
    db[..h_len].copy_from_slice(D::digest(label).as_ref());
    let one_off = k - msg.len() - h_len - 2; // index of the 0x01 separator
    db[one_off] = 0x01;
    db[one_off + 1..].copy_from_slice(msg);

    // seed = h_len random bytes, freshly drawn for every encryption.
    rng.fill_bytes(seed);

    // maskedDB = DB ⊕ MGF1(seed), then maskedSeed = seed ⊕ MGF1(maskedDB).
    // Order matters: the second mask is derived from the *masked* DB.
    mgf1_xor::<D>(seed, db);
    mgf1_xor::<D>(db, seed);

    key.raw_public_in_place(out);
    Ok(())
}

/// `scratch` must be exactly `key_size()` octets; the recovered message is
/// written to `out` and its length returned.
pub(crate) fn decrypt_oaep<D: Digest, K: RawPrivate>(
    key: &K,
    ciphertext: &[u8],
    label: &[u8],
    scratch: &mut [u8],
    out: &mut [u8],
) -> Result<usize, Error> {
    let k = key.key_size();
    let h_len = D::OUTPUT_LEN;
    if ciphertext.len() != k || k < 2 * h_len + 2 {
        return Err(Error::Decryption);
    }
    if scratch.len() != k {
        return Err(Error::InvalidLength);
    }
    scratch.copy_from_slice(ciphertext);
    key.raw_private_in_place(scratch);

    // Split EM = Y ‖ maskedSeed ‖ maskedDB, then unmask both halves in place
    // through disjoint borrows: seed = maskedSeed ⊕ MGF1(maskedDB) first, then
    // DB = maskedDB ⊕ MGF1(seed) — the same order as the masking in
    // `encrypt_oaep`, run backwards.
    let y = scratch[0];
    let (seed, db) = scratch[1..].split_at_mut(h_len);
    mgf1_xor::<D>(db, seed);
    mgf1_xor::<D>(seed, db);

    // Constant-time padding validation. Accumulate a single u8 that is 0 iff
    // every check passed; only branch on it at the very end.
    //
    //   Y must be 0x00.
    //   db[..h_len] must equal Hash(label).
    //   db[h_len..] must be (zero-padding) ‖ 0x01 ‖ M; find the 0x01 separator
    //     CT, ensuring no non-{0,1} byte precedes it.
    let l_hash = D::digest(label);
    let mut bad: u8 = y; // any non-zero Y is bad

    // CT compare lHash.
    let mut diff: u8 = 0;
    for (b, h) in db.iter().take(h_len).zip(l_hash.as_ref().iter()) {
        diff |= b ^ h;
    }
    bad |= diff;

    // Find the 0x01 separator without leaking its position via early-exit.
    // `found = 0` until we hit the first 0x01; once set, any subsequent
    // non-{0,1} byte is irrelevant. Before the separator, any non-zero byte
    // is bad.
    let ps_region = &db[h_len..];
    let mut found: u8 = 0;
    let mut sep_idx: usize = 0;
    let mut pre_bad: u8 = 0;
    for (i, &b) in ps_region.iter().enumerate() {
        // is_one = 0xff iff b == 0x01 and not yet found.
        let is_one = ct_eq_u8(b, 0x01) & !found;
        // Broadcast the per-byte mask to usize width before AND-ing; a bare
        // `is_one as usize` zero-extends to 0xff and truncates separators at
        // index >= 256 (keys > 2048-bit) to `i & 0xff`.
        let mask = 0usize.wrapping_sub((is_one & 1) as usize);
        sep_idx |= i & mask; // captures the first matching index
        found |= is_one;
        // Before separator (!found), byte must be 0x00.
        pre_bad |= b & !found;
    }
    bad |= !found;
    bad |= pre_bad;

    if bad != 0 {
        return Err(Error::Decryption);
    }

    let msg = &ps_region[sep_idx + 1..];
    if out.len() < msg.len() {
        return Err(Error::InvalidLength);
    }
    out[..msg.len()].copy_from_slice(msg);
    Ok(msg.len())
}

/// Returns `0xff` if `a == b`, else `0x00`. Wraps the crate's constant-time
/// byte equality and broadcasts the boolean to a full-byte mask.
#[inline]
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    0u8.wrapping_sub(a.ct_eq(&b).unwrap_u8())
}

/// MGF1 (RFC 8017 B.2.1) using hash `D`, XOR-ed into `dst` a digest block at a
/// time.
///
/// Every use of MGF1 in this module immediately XORs the mask into a buffer, so
/// generating it in place removes the mask-sized allocation entirely. (Mirrors
/// the shape of the allocation-free MGF1 in `slhdsa::hash`.)
fn mgf1_xor<D: Digest>(seed: &[u8], dst: &mut [u8]) {
    let mut counter: u32 = 0;
    let mut off = 0;
    while off < dst.len() {
        let mut h = D::new();
        h.update(seed);
        h.update(&counter.to_be_bytes());
        let block = h.finalize();
        for (d, m) in dst[off..].iter_mut().zip(block.as_ref().iter()) {
            *d ^= *m;
        }
        off += block.as_ref().len();
        counter += 1;
    }
}

/// Writes the PSS encoded message into `em`, which must be exactly `em_len`
/// (`em_bits.div_ceil(8)`) octets.
///
/// Everything is built in place. The salt is drawn straight into its final
/// position inside DB, so `m' = 0x00⁸ ‖ mHash ‖ salt` can be streamed into the
/// digest instead of assembled in a buffer, and the DB masking reads `H` out of
/// `em` through a `split_at_mut` so no copy of it is needed either.
fn emsa_pss_encode<D: Digest, R: RngCore>(
    msg: &[u8],
    em_bits: usize,
    salt_len: usize,
    rng: &mut R,
    em: &mut [u8],
) -> Result<(), Error> {
    let h_len = D::OUTPUT_LEN;
    let s_len = salt_len;
    let em_len = em_bits.div_ceil(8);
    if em_len < h_len + s_len + 2 {
        return Err(Error::MessageTooLong);
    }
    if em.len() != em_len {
        return Err(Error::InvalidLength);
    }

    let m_hash = D::digest(msg);
    let db_len = em_len - h_len - 1;

    // DB = PS(0x00…) ‖ 0x01 ‖ salt, with the salt drawn in place.
    em[..db_len].fill(0);
    rng.fill_bytes(&mut em[db_len - s_len..db_len]);

    // H = Hash(0x00⁸ ‖ mHash ‖ salt), streamed rather than buffered.
    let h = {
        let mut d = D::new();
        d.update(&[0u8; 8]);
        d.update(m_hash.as_ref());
        d.update(&em[db_len - s_len..db_len]);
        d.finalize()
    };
    em[db_len - s_len - 1] = 0x01;
    em[db_len..db_len + h_len].copy_from_slice(h.as_ref());
    em[em_len - 1] = 0xbc;

    // maskedDB = DB ⊕ MGF1(H, db_len). `split_at_mut` hands out disjoint
    // borrows of the DB region and the H region, both of which live in `em`.
    let (db_part, tail) = em.split_at_mut(db_len);
    mgf1_xor::<D>(&tail[..h_len], db_part);

    let clear = 8 * em_len - em_bits;
    if clear > 0 {
        db_part[0] &= 0xff >> clear;
    }
    Ok(())
}

/// EMSA-PSS-VERIFY (RFC 8017 §9.1.2).
///
/// `salt_len` selects how the salt length is determined:
/// * `Some(n)` — require the salt to be exactly `n` octets (the `0x01`
///   separator sits at a fixed offset). This is the strict profile mandated
///   by TLS 1.3 / the X.509 PSS parameter set, where `n == D::OUTPUT_LEN`.
/// * `None` — recover the salt length from the encoded message (the standard
///   variable-salt verify): DB is zero padding, then a single `0x01` octet,
///   then the salt. More interoperable; salt length does not affect PSS
///   security.
fn emsa_pss_verify<D: Digest>(
    msg: &[u8],
    em: &[u8],
    em_bits: usize,
    salt_len: Option<usize>,
    db_buf: &mut [u8],
) -> Result<(), Error> {
    let h_len = D::OUTPUT_LEN;
    let em_len = em.len();
    // Absolute minimum: maskedDB (>= 1 octet) ‖ H ‖ 0xBC.
    if em_len < h_len + 2 || em[em_len - 1] != 0xbc {
        return Err(Error::Verification);
    }

    let db_len = em_len - h_len - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..db_len + h_len];

    let clear = 8 * em_len - em_bits;
    if clear > 0 && masked_db[0] & (0xffu8 << (8 - clear)) != 0 {
        return Err(Error::Verification);
    }

    if db_buf.len() < db_len {
        return Err(Error::InvalidLength);
    }
    let db = &mut db_buf[..db_len];
    db.copy_from_slice(masked_db);
    mgf1_xor::<D>(h, db);
    if clear > 0 {
        db[0] &= 0xff >> clear;
    }

    // Locate the `PS ‖ 0x01 ‖ salt` structure of DB and extract the salt.
    let salt: &[u8] = match salt_len {
        Some(n) => {
            // Fixed salt length: the 0x01 separator sits at a known offset.
            if db_len < n + 1 {
                return Err(Error::Verification);
            }
            let ps_len = db_len - n - 1;
            if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
                return Err(Error::Verification);
            }
            &db[ps_len + 1..]
        }
        None => {
            // Recover the salt length: the first non-zero DB octet must be
            // exactly 0x01 (everything before it is the zero PS).
            match db.iter().position(|&b| b != 0) {
                Some(i) if db[i] == 0x01 => &db[i + 1..],
                _ => return Err(Error::Verification),
            }
        }
    };

    let m_hash = D::digest(msg);
    // m' = 0x00⁸ ‖ mHash ‖ salt, streamed into the digest (see emsa_pss_encode).
    let h_prime = {
        let mut d = D::new();
        d.update(&[0u8; 8]);
        d.update(m_hash.as_ref());
        d.update(salt);
        d.finalize()
    };

    // Both inputs are derived from public values, but the codebase uses
    // constant-time comparison throughout for hygiene.
    if bool::from(h_prime.as_ref().ct_eq(h)) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

// These exercise the boxed (heap) backend and the DER-parsed test keys, so
// they need `alloc`; the allocator-free paths are covered in `rsa::nobuf`.
#[cfg(all(test, feature = "alloc"))]
mod tests {
    use crate::bignum::BoxedUint;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;
    use crate::rsa::BoxedRsaPrivateKey;

    // Regression test for the separator-index truncation bug: the padding
    // scanners captured the first-separator position by AND-ing the byte index
    // `i` with a per-byte mask returned by `ct_eq_u8` (0x00 / 0xff). Casting
    // that one-octet mask to `u32` / `usize` zero-extended it to 0x..00ff, so
    // only the low 8 bits of `i` survived. Any separator at absolute index
    // >= 256 — i.e. on keys larger than 2048-bit — was captured as `i & 0xff`,
    // and because `found`/`bad` were still computed correctly the function
    // returned `Ok(...)` sliced at the wrong, smaller offset → silently wrong
    // plaintext. A 3072-bit key (k = 384 octets) with a short message places
    // the separator well past index 255, so it exercises the fixed code path;
    // these tests fail against the pre-fix scanners and pass after the fix.
    //
    // Generating a 3072-bit key is fast in release but slow in an unoptimized
    // debug build, so (like `keygen_roundtrip_rsa2048` in `keys.rs`) these are
    // ignored by default. Run them with:
    //   cargo test --release -- --ignored separator_index_above_255

    fn sk_3072() -> BoxedRsaPrivateKey {
        // Deterministic CSPRNG so the test is reproducible; 3072-bit ⇒ k = 384,
        // guaranteeing the 0x00 (PKCS#1) / 0x01 (OAEP) separator lands at an
        // index > 255 for a short message.
        let mut rng = HmacDrbg::<Sha256>::new(b"emsa-sep-idx-regression", b"nonce", &[]);
        BoxedRsaPrivateKey::generate(3072, BoxedUint::from_u64(65537), &mut rng, 16)
    }

    #[test]
    #[ignore = "slow in debug; run with --release --ignored"]
    fn pkcs1v15_roundtrip_separator_index_above_255() {
        let key = sk_3072();
        let pk = key.public_key();
        let mut rng = HmacDrbg::<Sha256>::new(b"emsa-pkcs1-ct", b"nonce", &[]);
        let msg = b"hello"; // separator at index k - 5 - 1 = 378 > 255
        let ct = pk.encrypt_pkcs1v15(msg, &mut rng).unwrap();
        let pt = key.decrypt_pkcs1v15(&ct).unwrap();
        assert_eq!(pt.as_slice(), msg);
    }

    #[test]
    #[ignore = "slow in debug; run with --release --ignored"]
    fn oaep_roundtrip_separator_index_above_255() {
        let key = sk_3072();
        let pk = key.public_key();
        let mut rng = HmacDrbg::<Sha256>::new(b"emsa-oaep-ct", b"nonce", &[]);
        let label = b"";
        let msg = b"hi";
        let ct = pk.encrypt_oaep::<Sha256, _>(msg, label, &mut rng).unwrap();
        let pt = key.decrypt_oaep::<Sha256>(&ct, label).unwrap();
        assert_eq!(pt.as_slice(), msg);
    }

    // ----------------------------------------------------------------------
    // F4: RSAVP1 step 1 (`s < n`) + strict PSS leading-octet check.
    // ----------------------------------------------------------------------

    use crate::bignum::Uint;
    use crate::rsa::{Error, RsaPrivateKey};
    use crate::test_util::rsa_test_key_a;

    /// A const-generic private key holding the embedded 2048-bit test key but
    /// carried in **33 limbs** (`k = 264` octets) instead of the minimal 32.
    ///
    /// Because the modulus only occupies ~2048 of the 2112 available bits, its
    /// top 8 octets are zero (`n < 2^(8·k)` with margin). This buys two things
    /// the minimal-width boxed keys cannot give a test:
    ///  * `s + n < 2^2048 + 2^2048 < 2^2112`, so the malleable representative
    ///    `s + n` fits in `k = 264` octets and round-trips as a value `>= n` —
    ///    the exact thing RSAVP1 step 1 must reject. With a full-width modulus
    ///    `s + n` would overflow `k` octets and not be expressible.
    ///  * `em_len = ceil(2047/8) = 256 < k`, so `k - em_len = 8` leading octets
    ///    are dropped by `verify_pss` — exercising the strict leading-octet
    ///    zero-check (RFC 8017 §9.1.2, F4 part 2).
    ///
    /// Built via `from_components` (no primes → unblinded path), which is fine:
    /// signing correctness only needs `d`.
    fn widened_test_key_33() -> RsaPrivateKey<33> {
        let key = rsa_test_key_a();
        let widen = |v: &Uint<32>| -> Uint<33> {
            let mut be = [0u8; 33 * 8];
            // Right-align the 32-limb big-endian bytes into the 33-limb buffer.
            v.write_be_bytes(&mut be[8..]);
            Uint::<33>::from_be_bytes(&be)
        };
        RsaPrivateKey::<33>::from_components(
            widen(key.modulus()),
            widen(key.exponent()),
            widen(key.private_exponent()),
        )
    }

    /// Re-serializes `s + n` to exactly `k` big-endian octets. Asserts the sum
    /// still fits in `k` octets (requires a non-full-width modulus).
    fn sig_plus_modulus(sig: &[u8], n: &Uint<33>) -> alloc::vec::Vec<u8> {
        let k = sig.len();
        let s = BoxedUint::from_be_bytes(sig);
        let n_boxed = BoxedUint::from_be_bytes(&{
            let mut b = alloc::vec![0u8; k];
            n.write_be_bytes(&mut b);
            b
        });
        let sum = s.add(&n_boxed);
        assert!(
            sum.bit_len() <= 8 * k,
            "s + n overflowed k octets — test needs a non-full-width modulus"
        );
        sum.to_be_bytes(k)
    }

    /// (a) A genuine signature still verifies, and (b) `s + n` (re-serialized to
    /// the `k`-octet key width) is rejected, for PKCS#1 v1.5 on the
    /// **const-generic** verify path.
    ///
    /// PKCS#1 v1.5 sizes the encoded message to `k = LIMBS·8` octets, so the
    /// widened (over-provisioned-limb) key cannot be used here — its EM would
    /// exceed the modulus and signing would not round-trip. We instead use the
    /// natural 32-limb 2048-bit key (full width) and, like the boxed sibling
    /// test, scan messages for one whose `s + n` still fits in `k` octets.
    #[test]
    fn pkcs1v15_rejects_s_plus_n() {
        let sk = rsa_test_key_a();
        let pk = sk.public_key();
        let n = {
            let mut nb = [0u8; 256];
            sk.modulus().write_be_bytes(&mut nb);
            BoxedUint::from_be_bytes(&nb)
        };
        let k = 256;

        for i in 0u32..256 {
            let mut msg = *b"f4-cg-s-plus-n-0000";
            msg[15..].copy_from_slice(&i.to_be_bytes());
            let sig = sk.sign_pkcs1v15::<Sha256>(&msg).unwrap();
            // (a) the honest signature verifies on the const-generic path.
            pk.verify_pkcs1v15::<Sha256>(&msg, &sig).unwrap();

            let s = BoxedUint::from_be_bytes(&sig);
            let sum = s.add(&n);
            if sum.bit_len() > 8 * k {
                continue; // s + n overflows k octets — not representable.
            }
            // (b) s + n is the malleable representative — must be rejected.
            let mal = sum.to_be_bytes(k);
            assert_ne!(mal, sig, "s + n must differ from s");
            assert_eq!(
                pk.verify_pkcs1v15::<Sha256>(&msg, &mal),
                Err(Error::Verification),
                "const-generic: s + n must be rejected (RSAVP1 step 1)"
            );
            return;
        }
        panic!("no message yielded a representable s + n in 256 tries");
    }

    /// (a) A genuine PSS signature still verifies, and (b) `s + n` is rejected.
    /// The widened modulus also drives `verify_pss` through the leading-octet
    /// drop (`k - em_len = 8 > 0`), so part (a) doubles as the strict
    /// leading-zero-octet path (F4 part 2): a correct zero-check accepts a
    /// legitimately zero-padded `m`.
    #[test]
    fn pss_rejects_s_plus_n_and_exercises_leading_octet() {
        let sk = widened_test_key_33();
        let pk = sk.public_key();

        // Confirm the leading-octet path is exercised: k - em_len > 0.
        let k = 33 * 8;
        let em_len = (pk.modulus().bit_len() - 1).div_ceil(8);
        assert!(
            k - em_len > 0,
            "expected a non-full-width modulus (k - em_len = {})",
            k - em_len
        );

        let mut rng = HmacDrbg::<Sha256>::new(b"f4-pss", b"nonce", &[]);
        let msg = b"f4 pss";
        let sig = sk.sign_pss::<Sha256, _>(msg, &mut rng).unwrap();

        // (a) valid signature verifies through the leading-octet drop path.
        pk.verify_pss::<Sha256>(msg, &sig).unwrap();

        // (b) s + n must be rejected.
        let mal = sig_plus_modulus(&sig, pk.modulus());
        assert_ne!(mal, sig, "s + n must differ from s");
        assert_eq!(
            pk.verify_pss::<Sha256>(msg, &mal),
            Err(Error::Verification),
            "PSS s + n must be rejected (RSAVP1 step 1)"
        );
    }

    /// The boxed verify path (minimal-width modulus) also rejects `s + n`.
    /// A full-width 2048-bit modulus has the top bit set, so `s + n` overflows
    /// `k` octets for roughly half of all signatures; we scan messages until we
    /// find one whose `s + n` still fits in `k` octets (and is therefore a
    /// representable value `>= n`), then assert it is rejected.
    #[test]
    fn boxed_pkcs1v15_rejects_s_plus_n() {
        let key = rsa_test_key_a();
        let mut nb = [0u8; 256];
        key.modulus().write_be_bytes(&mut nb);
        let mut eb = [0u8; 256];
        key.exponent().write_be_bytes(&mut eb);
        let boxed_pk = crate::rsa::BoxedRsaPublicKey::new(
            BoxedUint::from_be_bytes(&nb),
            BoxedUint::from_be_bytes(&eb),
        );
        let n = BoxedUint::from_be_bytes(&nb);
        let k = 256;

        for i in 0u32..256 {
            let mut msg = *b"f4-boxed-s-plus-n-0000";
            msg[18..].copy_from_slice(&i.to_be_bytes());
            let sig = key.sign_pkcs1v15::<Sha256>(&msg).unwrap();
            // Sanity: the honest signature verifies on the boxed path.
            boxed_pk.verify_pkcs1v15::<Sha256>(&msg, &sig).unwrap();

            let s = BoxedUint::from_be_bytes(&sig);
            let sum = s.add(&n);
            if sum.bit_len() > 8 * k {
                continue; // s + n overflows k octets — not representable here.
            }
            let mal = sum.to_be_bytes(k);
            assert_ne!(mal, sig);
            assert_eq!(
                boxed_pk.verify_pkcs1v15::<Sha256>(&msg, &mal),
                Err(Error::Verification),
                "boxed: s + n must be rejected (RSAVP1 step 1)"
            );
            return; // found a representable s + n and asserted rejection.
        }
        panic!("no message yielded a representable s + n in 256 tries");
    }

    /// Direct unit test for the constant-time big-endian comparator used by the
    /// RSAVP1 check, covering equal / less / greater across byte positions.
    #[test]
    fn ct_lt_be_matches_integer_order() {
        let cases: &[(&[u8], &[u8], bool)] = &[
            (&[0, 0, 0], &[0, 0, 0], false), // equal
            (&[0, 0, 1], &[0, 0, 2], true),  // differ in LSB
            (&[0, 1, 0], &[0, 2, 0], true),  // differ in middle
            (&[1, 0, 0], &[2, 0, 0], true),  // differ in MSB
            (&[2, 0, 0], &[1, 0, 0], false), // greater in MSB
            (&[0, 2, 0], &[1, 0, 0], true),  // MSB dominates over middle
            (&[0xff, 0xff], &[0xff, 0xff], false),
            (&[0x7f, 0xff], &[0x80, 0x00], true),
        ];
        for (a, b, want) in cases {
            assert_eq!(super::ct_lt_be(a, b), *want, "ct_lt_be({a:?}, {b:?})");
        }
    }
}
