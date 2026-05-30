//! Shared EMSA padding for RSA signatures and encryption (RFC 8017),
//! parameterized over the raw RSA primitive so both the const-generic
//! [`RsaPublicKey`](super::RsaPublicKey)/[`RsaPrivateKey`](super::RsaPrivateKey)
//! and the runtime-sized boxed keys reuse one implementation.

use alloc::vec;
use alloc::vec::Vec;

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
    /// `m^e mod n`: `m` is big-endian and `< n`; returns the `k`-byte result.
    fn raw_public(&self, m: &[u8]) -> Vec<u8>;
}

/// The raw RSA private operation (`c^d mod n`) plus modulus metadata.
pub(crate) trait RawPrivate {
    /// Modulus length in octets (`k`).
    fn key_size(&self) -> usize;
    /// Modulus bit length.
    fn modulus_bits(&self) -> usize;
    /// `c^d mod n`: `c` is big-endian and `< n`; returns the `k`-byte result.
    fn raw_private(&self, c: &[u8]) -> Vec<u8>;
    /// A stable per-key 32-byte secret used to derive the synthetic
    /// plaintext for PKCS#1 v1.5 implicit rejection (RFC 8017 §7.2.2 Note).
    /// Must be the same value for every call on a given key, and unknown to
    /// anyone without the private key.
    fn secret_seed(&self) -> [u8; 32];
}

// --------------------------------------------------------------------------
// PKCS#1 v1.5
// --------------------------------------------------------------------------

pub(crate) fn encrypt_pkcs1v15<K: RawPublic, R: RngCore>(
    key: &K,
    msg: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let k = key.key_size();
    if msg.len() + 11 > k {
        return Err(Error::MessageTooLong);
    }
    let ps_len = k - msg.len() - 3;
    let mut em = vec![0u8; k];
    em[1] = 0x02;
    fill_nonzero(&mut em[2..2 + ps_len], rng);
    // em[2 + ps_len] stays 0x00 (separator)
    em[k - msg.len()..].copy_from_slice(msg);
    Ok(key.raw_public(&em))
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
pub(crate) fn decrypt_pkcs1v15<K: RawPrivate>(key: &K, ct: &[u8]) -> Result<Vec<u8>, Error> {
    let k = key.key_size();
    if ct.len() != k {
        return Err(Error::InvalidLength);
    }
    // RFC 8017 §7.2.2 step 1: `k` must be at least 11 octets so the PS field
    // (>= 8 bytes) plus the three framing bytes (0x00 0x02 ... 0x00) can fit.
    // A smaller modulus could otherwise drive the `em[0]` / `em[1]` indexing
    // below into a panic on attacker-controlled tiny keys.
    if k < 11 {
        return Err(Error::InvalidLength);
    }
    let em = key.raw_private(ct);

    // RFC 8017 §7.2.2 constant-time padding validation. Every branch on plaintext
    // bytes is folded into a single `bad` accumulator so the running time of a
    // failed unwrap is indistinguishable from a successful one (Bleichenbacher's
    // padding oracle is the canonical attack — see also Manger / ROBOT). The
    // resulting Vec length still leaks across success/failure boundaries — for
    // protocol-level implicit rejection that hides even that, see
    // [`decrypt_pkcs1v15_session`].
    let mut bad: u8 = em[0]; // must be 0x00
    bad |= em[1] ^ 0x02; //   must be 0x02

    // Scan em[2..] for the first 0x00 separator. We unconditionally walk every
    // byte; the only state that depends on the value is the captured `sep_idx`
    // (the position of the first zero) and the `found` flag.
    let mut found: u8 = 0;
    let mut sep_idx: u32 = 0;
    for (i, &b) in em.iter().enumerate().skip(2) {
        let is_zero = ct_eq_u8(b, 0x00) & !found;
        sep_idx |= (i as u32) & (is_zero as u32);
        found |= is_zero;
    }
    bad |= !found; // no separator found ⇒ invalid

    // PS must be at least 8 bytes ⇒ sep_idx >= 10 (positions 2..10 are PS).
    // ct_lt yields a Choice that is true when sep_idx < 10.
    let too_small = sep_idx.ct_lt(&10u32).unwrap_u8();
    bad |= 0u8.wrapping_sub(too_small);

    if bad != 0 {
        return Err(Error::Decryption);
    }
    Ok(em[(sep_idx as usize) + 1..].to_vec())
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
pub(crate) fn decrypt_pkcs1v15_session<K: RawPrivate>(
    key: &K,
    ct: &[u8],
    expected_len: usize,
) -> Result<Vec<u8>, Error> {
    use crate::ct::ConditionallySelectable;
    use crate::hash::HmacSha256;

    let k = key.key_size();
    if ct.len() != k {
        return Err(Error::InvalidLength);
    }
    // RFC 8017 §7.2.2 step 1: see [`decrypt_pkcs1v15`].
    if k < 11 {
        return Err(Error::InvalidLength);
    }
    let em = key.raw_private(ct);

    // Same constant-time padding check as decrypt_pkcs1v15.
    let mut bad: u8 = em[0];
    bad |= em[1] ^ 0x02;
    let mut found: u8 = 0;
    let mut sep_idx: u32 = 0;
    for (i, &b) in em.iter().enumerate().skip(2) {
        let is_zero = ct_eq_u8(b, 0x00) & !found;
        sep_idx |= (i as u32) & (is_zero as u32);
        found |= is_zero;
    }
    bad |= !found;
    let too_small = sep_idx.ct_lt(&10u32).unwrap_u8();
    bad |= 0u8.wrapping_sub(too_small);

    // Derive the synthetic fallback: HMAC(key_secret, ct) expanded to expected_len.
    // The derivation is keyed by the long-term private value so the attacker
    // cannot predict the fallback. Pseudorandomness is provided by HMAC-SHA256.
    let key_secret = key.secret_seed();
    let mut fallback = Vec::with_capacity(expected_len);
    let mut counter: u32 = 0;
    while fallback.len() < expected_len {
        let mut h = HmacSha256::new(&key_secret);
        h.update(b"purecrypto-rsa-pkcs1v15-implicit-reject-v1");
        h.update(ct);
        h.update(&counter.to_be_bytes());
        let tag = h.finalize();
        fallback.extend_from_slice(tag.as_ref());
        counter += 1;
    }
    fallback.truncate(expected_len);

    // Constant-time merge: when bad == 0, take the real plaintext bytes; else
    // take the fallback. The real-plaintext length is variable (depends on
    // sep_idx) but the OUTPUT length is always `expected_len`, so the timing /
    // size of the return value reveals nothing.
    let real_start = (sep_idx as usize).saturating_add(1);
    // Fold any nonzero bit of `bad` down into bit 0 so we can build a Choice.
    let mut fold = bad;
    fold |= fold >> 4;
    fold |= fold >> 2;
    fold |= fold >> 1;
    let bad_choice = crate::ct::Choice::from(fold & 1);

    let mut out = Vec::with_capacity(expected_len);
    for (i, &fallback_byte) in fallback.iter().enumerate() {
        // The "real" byte is em[real_start + i] when it exists. Because
        // real_start + i may exceed em.len() if the padding is bad, we clamp
        // to a valid index unconditionally; the resulting byte is suppressed
        // by the conditional select.
        let idx = real_start.saturating_add(i).min(em.len().saturating_sub(1));
        let real_byte = em[idx];
        // `conditional_select(a, b, choice)` returns `a` iff `choice`; we want
        // the fallback when padding was bad, otherwise the real byte.
        out.push(u8::conditional_select(
            &fallback_byte,
            &real_byte,
            bad_choice,
        ));
    }
    Ok(out)
}

pub(crate) fn sign_pkcs1v15<D: Pkcs1Digest, K: RawPrivate>(
    key: &K,
    msg: &[u8],
) -> Result<Vec<u8>, Error> {
    let em = encode_pkcs1v15::<D>(msg, key.key_size())?;
    Ok(key.raw_private(&em))
}

pub(crate) fn verify_pkcs1v15<D: Pkcs1Digest, K: RawPublic>(
    key: &K,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    let k = key.key_size();
    if sig.len() != k {
        return Err(Error::InvalidLength);
    }
    let em = key.raw_public(sig);
    let expected = encode_pkcs1v15::<D>(msg, k)?;
    if bool::from(em.as_slice().ct_eq(expected.as_slice())) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

/// EMSA-PKCS1-v1_5: `0x00 || 0x01 || PS(0xff…) || 0x00 || DigestInfo`.
fn encode_pkcs1v15<D: Pkcs1Digest>(msg: &[u8], k: usize) -> Result<Vec<u8>, Error> {
    let digest = D::digest(msg);
    let prefix = D::DIGEST_INFO_PREFIX;
    let t_len = prefix.len() + digest.as_ref().len();
    if t_len + 11 > k {
        return Err(Error::MessageTooLong);
    }
    let ps_len = k - t_len - 3;
    let mut em = vec![0u8; k];
    em[1] = 0x01;
    for b in &mut em[2..2 + ps_len] {
        *b = 0xff;
    }
    let t_start = 2 + ps_len + 1;
    em[t_start..t_start + prefix.len()].copy_from_slice(prefix);
    em[t_start + prefix.len()..].copy_from_slice(digest.as_ref());
    Ok(em)
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
// PSS (salt length = digest length)
// --------------------------------------------------------------------------

pub(crate) fn sign_pss<D: Digest, K: RawPrivate, R: RngCore>(
    key: &K,
    msg: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let em = emsa_pss_encode::<D, R>(msg, key.modulus_bits() - 1, rng)?;
    Ok(key.raw_private(&em))
}

pub(crate) fn verify_pss<D: Digest, K: RawPublic>(
    key: &K,
    msg: &[u8],
    sig: &[u8],
) -> Result<(), Error> {
    let k = key.key_size();
    if sig.len() != k {
        return Err(Error::InvalidLength);
    }
    let m = key.raw_public(sig);
    let em_bits = key.modulus_bits() - 1;
    let em_len = em_bits.div_ceil(8);
    emsa_pss_verify::<D>(msg, &m[k - em_len..], em_bits)
}

// --------------------------------------------------------------------------
// OAEP (RFC 8017 §7.1)
// --------------------------------------------------------------------------

pub(crate) fn encrypt_oaep<D: Digest, K: RawPublic, R: RngCore>(
    key: &K,
    msg: &[u8],
    label: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let k = key.key_size();
    let h_len = D::OUTPUT_LEN;
    if k < 2 * h_len + 2 || msg.len() > k - 2 * h_len - 2 {
        return Err(Error::MessageTooLong);
    }

    // DB = lHash ‖ PS ‖ 0x01 ‖ M
    let mut db = vec![0u8; k - h_len - 1];
    db[..h_len].copy_from_slice(D::digest(label).as_ref());
    let one_off = k - msg.len() - h_len - 2; // index of the 0x01 separator
    db[one_off] = 0x01;
    db[one_off + 1..].copy_from_slice(msg);

    // seed = h_len random bytes, freshly drawn for every encryption.
    let mut seed = vec![0u8; h_len];
    rng.fill_bytes(&mut seed);

    let db_mask = mgf1::<D>(&seed, k - h_len - 1);
    for (b, m) in db.iter_mut().zip(db_mask.iter()) {
        *b ^= m;
    }
    let seed_mask = mgf1::<D>(&db, h_len);
    for (s, m) in seed.iter_mut().zip(seed_mask.iter()) {
        *s ^= m;
    }

    // EM = 0x00 ‖ maskedSeed ‖ maskedDB
    let mut em = vec![0u8; k];
    em[1..1 + h_len].copy_from_slice(&seed);
    em[1 + h_len..].copy_from_slice(&db);

    Ok(key.raw_public(&em))
}

pub(crate) fn decrypt_oaep<D: Digest, K: RawPrivate>(
    key: &K,
    ciphertext: &[u8],
    label: &[u8],
) -> Result<Vec<u8>, Error> {
    let k = key.key_size();
    let h_len = D::OUTPUT_LEN;
    if ciphertext.len() != k || k < 2 * h_len + 2 {
        return Err(Error::Decryption);
    }
    let em = key.raw_private(ciphertext);

    // Split EM = Y ‖ maskedSeed ‖ maskedDB.
    let y = em[0];
    let masked_seed = &em[1..1 + h_len];
    let masked_db = &em[1 + h_len..];

    let seed_mask = mgf1::<D>(masked_db, h_len);
    let mut seed = vec![0u8; h_len];
    for i in 0..h_len {
        seed[i] = masked_seed[i] ^ seed_mask[i];
    }

    let db_mask = mgf1::<D>(&seed, k - h_len - 1);
    let mut db = vec![0u8; k - h_len - 1];
    for i in 0..db.len() {
        db[i] = masked_db[i] ^ db_mask[i];
    }

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
        sep_idx |= i & (is_one as usize); // captures the first matching index
        found |= is_one;
        // Before separator (!found), byte must be 0x00.
        pre_bad |= b & !found;
    }
    bad |= !found;
    bad |= pre_bad;

    if bad != 0 {
        return Err(Error::Decryption);
    }

    Ok(ps_region[sep_idx + 1..].to_vec())
}

/// Returns `0xff` if `a == b`, else `0x00`. Wraps the crate's constant-time
/// byte equality and broadcasts the boolean to a full-byte mask.
#[inline]
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    0u8.wrapping_sub(a.ct_eq(&b).unwrap_u8())
}

/// MGF1 (RFC 8017 B.2.1) using hash `D`.
pub(crate) fn mgf1<D: Digest>(seed: &[u8], mask_len: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(mask_len);
    let mut counter: u32 = 0;
    while mask.len() < mask_len {
        let mut h = D::new();
        h.update(seed);
        h.update(&counter.to_be_bytes());
        mask.extend_from_slice(h.finalize().as_ref());
        counter += 1;
    }
    mask.truncate(mask_len);
    mask
}

fn emsa_pss_encode<D: Digest, R: RngCore>(
    msg: &[u8],
    em_bits: usize,
    rng: &mut R,
) -> Result<Vec<u8>, Error> {
    let h_len = D::OUTPUT_LEN;
    let s_len = h_len;
    let em_len = em_bits.div_ceil(8);
    if em_len < h_len + s_len + 2 {
        return Err(Error::MessageTooLong);
    }

    let m_hash = D::digest(msg);
    let mut salt = vec![0u8; s_len];
    rng.fill_bytes(&mut salt);

    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(m_hash.as_ref());
    m_prime.extend_from_slice(&salt);
    let h = D::digest(&m_prime);

    let db_len = em_len - h_len - 1;
    let mut db = vec![0u8; db_len];
    db[db_len - s_len - 1] = 0x01;
    db[db_len - s_len..].copy_from_slice(&salt);

    let db_mask = mgf1::<D>(h.as_ref(), db_len);
    for (b, m) in db.iter_mut().zip(db_mask.iter()) {
        *b ^= *m;
    }
    let clear = 8 * em_len - em_bits;
    if clear > 0 {
        db[0] &= 0xff >> clear;
    }

    let mut em = db;
    em.extend_from_slice(h.as_ref());
    em.push(0xbc);
    Ok(em)
}

fn emsa_pss_verify<D: Digest>(msg: &[u8], em: &[u8], em_bits: usize) -> Result<(), Error> {
    let h_len = D::OUTPUT_LEN;
    let s_len = h_len;
    let em_len = em.len();
    if em_len < h_len + s_len + 2 || em[em_len - 1] != 0xbc {
        return Err(Error::Verification);
    }

    let db_len = em_len - h_len - 1;
    let masked_db = &em[..db_len];
    let h = &em[db_len..db_len + h_len];

    let clear = 8 * em_len - em_bits;
    if clear > 0 && masked_db[0] & (0xffu8 << (8 - clear)) != 0 {
        return Err(Error::Verification);
    }

    let db_mask = mgf1::<D>(h, db_len);
    let mut db = vec![0u8; db_len];
    for i in 0..db_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }
    if clear > 0 {
        db[0] &= 0xff >> clear;
    }

    let ps_len = db_len - s_len - 1;
    if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 0x01 {
        return Err(Error::Verification);
    }
    let salt = &db[ps_len + 1..];

    let m_hash = D::digest(msg);
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(m_hash.as_ref());
    m_prime.extend_from_slice(salt);
    let h_prime = D::digest(&m_prime);

    // Both inputs are derived from public values, but the codebase uses
    // constant-time comparison throughout for hygiene.
    if bool::from(h_prime.as_ref().ct_eq(h)) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}
