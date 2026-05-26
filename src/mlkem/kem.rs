//! ML-KEM key encapsulation (FIPS 203 §6) — the Fujisaki–Okamoto wrapper around
//! K-PKE, including the constant-time implicit rejection in decapsulation.

use super::indcpa::{self, CT_BYTES, PKE_DK_BYTES, PKE_EK_BYTES};
use crate::ct::{ConditionallySelectable, ConstantTimeEq};
use crate::hash::{sha3_256, sha3_512, shake256};

/// Encapsulation-key bytes.
pub(crate) const EK_BYTES: usize = PKE_EK_BYTES;
/// Decapsulation-key bytes (`dk_PKE ‖ ek ‖ H(ek) ‖ z`).
pub(crate) const DK_BYTES: usize = PKE_DK_BYTES + PKE_EK_BYTES + 64;
/// Ciphertext bytes.
pub(crate) const CIPHERTEXT_BYTES: usize = CT_BYTES;

/// ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16).
pub(crate) fn keygen(d: &[u8; 32], z: &[u8; 32]) -> ([u8; EK_BYTES], [u8; DK_BYTES]) {
    let (ek, dk_pke) = indcpa::keygen(d);
    let mut dk = [0u8; DK_BYTES];
    dk[..PKE_DK_BYTES].copy_from_slice(&dk_pke);
    dk[PKE_DK_BYTES..PKE_DK_BYTES + PKE_EK_BYTES].copy_from_slice(&ek);
    dk[PKE_DK_BYTES + PKE_EK_BYTES..PKE_DK_BYTES + PKE_EK_BYTES + 32].copy_from_slice(&sha3_256(&ek));
    dk[DK_BYTES - 32..].copy_from_slice(z);
    (ek, dk)
}

/// ML-KEM.Encaps_internal (FIPS 203 Algorithm 17). Returns `(ciphertext, K)`.
pub(crate) fn encaps(ek: &[u8; EK_BYTES], m: &[u8; 32]) -> ([u8; CIPHERTEXT_BYTES], [u8; 32]) {
    // (K, r) ← G(m ‖ H(ek)).
    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(m);
    g_in[32..].copy_from_slice(&sha3_256(ek));
    let g = sha3_512(&g_in);

    let mut shared = [0u8; 32];
    shared.copy_from_slice(&g[..32]);
    let mut r = [0u8; 32];
    r.copy_from_slice(&g[32..]);

    let ct = indcpa::encrypt(ek, m, &r);
    (ct, shared)
}

/// ML-KEM.Decaps_internal (FIPS 203 Algorithm 18). The chosen shared secret is
/// selected in constant time: the re-encryption check never branches on secret
/// data, and the implicit-rejection value replaces `K'` via a masked copy.
pub(crate) fn decaps(dk: &[u8; DK_BYTES], ct: &[u8; CIPHERTEXT_BYTES]) -> [u8; 32] {
    let mut dk_pke = [0u8; PKE_DK_BYTES];
    dk_pke.copy_from_slice(&dk[..PKE_DK_BYTES]);
    let mut ek = [0u8; PKE_EK_BYTES];
    ek.copy_from_slice(&dk[PKE_DK_BYTES..PKE_DK_BYTES + PKE_EK_BYTES]);
    let hek = &dk[PKE_DK_BYTES + PKE_EK_BYTES..PKE_DK_BYTES + PKE_EK_BYTES + 32];
    let z = &dk[DK_BYTES - 32..];

    let m_prime = indcpa::decrypt(&dk_pke, ct);

    // (K', r') ← G(m' ‖ h).
    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(&m_prime);
    g_in[32..].copy_from_slice(hek);
    let g = sha3_512(&g_in);
    let mut k_prime = [0u8; 32];
    k_prime.copy_from_slice(&g[..32]);
    let mut r_prime = [0u8; 32];
    r_prime.copy_from_slice(&g[32..]);

    // K̄ ← J(z ‖ c), the implicit-rejection secret.
    let mut j_in = [0u8; 32 + CIPHERTEXT_BYTES];
    j_in[..32].copy_from_slice(z);
    j_in[32..].copy_from_slice(ct);
    let mut k_bar = [0u8; 32];
    shake256(&j_in, &mut k_bar);

    // Re-encrypt and compare in constant time; keep K' iff the ciphertext matches.
    let ct_cmp = indcpa::encrypt(&ek, &m_prime, &r_prime);
    let matches = ct.ct_eq(&ct_cmp);
    let mut out = k_bar;
    out.conditional_assign(&k_prime, matches);
    out
}
