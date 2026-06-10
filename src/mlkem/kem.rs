//! ML-KEM key encapsulation (FIPS 203 §6) — the Fujisaki–Okamoto wrapper
//! around K-PKE, including the constant-time implicit rejection in
//! decapsulation. Parameterized over the FIPS 203 set constants by const
//! generics; the per-set wrapper macro in [`super`] instantiates one
//! monomorphization per ML-KEM set.

use super::indcpa::{self, POLYBYTES, du_bytes, dv_bytes};
use crate::ct::{ConditionallySelectable, ConstantTimeEq};
use crate::hash::{ExtendableOutput, Shake256, XofReader, sha3_256, sha3_512};

/// Encapsulation-key bytes = K-PKE encryption key.
pub(crate) const fn ek_bytes(k: usize) -> usize {
    POLYBYTES * k + 32
}
/// Decapsulation-key bytes = K-PKE decryption key ‖ ek ‖ H(ek) ‖ z.
pub(crate) const fn dk_bytes(k: usize) -> usize {
    POLYBYTES * k + ek_bytes(k) + 64
}
/// Ciphertext bytes = compressed u (K polynomials at du bits/coeff) ‖ compressed v.
pub(crate) const fn ct_bytes(k: usize, du: usize, dv: usize) -> usize {
    du_bytes(du) * k + dv_bytes(dv)
}

/// Maximum ciphertext size across all FIPS 203 sets — used as the scratch
/// buffer for the constant-time re-encryption check.
/// `K=4, DU=11, DV=5 ⇒ 32·11·4 + 32·5 = 1568` bytes (ML-KEM-1024).
const MAX_CT_BYTES: usize = 1568;

/// ML-KEM.KeyGen_internal (FIPS 203 Algorithm 16).
pub(crate) fn keygen<const K: usize, const ETA1: usize>(
    d: &[u8; 32],
    z: &[u8; 32],
    ek: &mut [u8],
    dk: &mut [u8],
) {
    debug_assert_eq!(ek.len(), ek_bytes(K));
    debug_assert_eq!(dk.len(), dk_bytes(K));

    let pke_dk = POLYBYTES * K;
    let pke_ek = ek_bytes(K);

    // K-PKE keygen writes ek (full ek_bytes) and dk_pke (first POLYBYTES·K of dk).
    indcpa::keygen::<K, ETA1>(d, ek, &mut dk[..pke_dk]);

    // dk = dk_pke ‖ ek ‖ H(ek) ‖ z
    dk[pke_dk..pke_dk + pke_ek].copy_from_slice(ek);
    dk[pke_dk + pke_ek..pke_dk + pke_ek + 32].copy_from_slice(&sha3_256(ek));
    let total = dk.len();
    dk[total - 32..].copy_from_slice(z);
}

/// ML-KEM.Encaps_internal (FIPS 203 Algorithm 17). Writes the ciphertext to
/// `ct` and returns the 32-byte shared secret.
pub(crate) fn encaps<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    ek: &[u8],
    m: &[u8; 32],
    ct: &mut [u8],
) -> [u8; 32] {
    debug_assert_eq!(ek.len(), ek_bytes(K));
    debug_assert_eq!(ct.len(), ct_bytes(K, DU, DV));

    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(m);
    g_in[32..].copy_from_slice(&sha3_256(ek));
    let mut g = sha3_512(&g_in);
    let mut shared = [0u8; 32];
    shared.copy_from_slice(&g[..32]);
    let mut r = [0u8; 32];
    r.copy_from_slice(&g[32..]);

    indcpa::encrypt::<K, ETA1, ETA2, DU, DV>(ek, m, &r, ct);

    // Wipe the transient secrets (the G input containing `m`, the G output
    // containing both the shared secret and the coins, and the coins copy)
    // before they drop — same hygiene as `decaps`. `shared` is the caller's
    // return value; `black_box` keeps the writes from being eliminated as
    // dead stores.
    for b in g_in.iter_mut().chain(g.iter_mut()).chain(r.iter_mut()) {
        *b = 0;
    }
    let _ = core::hint::black_box((&g_in, &g, &r));
    shared
}

/// ML-KEM.Decaps_internal (FIPS 203 Algorithm 18). The chosen shared secret is
/// selected in constant time: the re-encryption check never branches on secret
/// data, and the implicit-rejection value replaces `K'` via a masked copy.
pub(crate) fn decaps<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: usize,
    const DV: usize,
>(
    dk: &[u8],
    ct: &[u8],
) -> [u8; 32] {
    debug_assert_eq!(dk.len(), dk_bytes(K));
    debug_assert_eq!(ct.len(), ct_bytes(K, DU, DV));

    let pke_dk = POLYBYTES * K;
    let pke_ek = ek_bytes(K);

    let dk_pke = &dk[..pke_dk];
    let ek = &dk[pke_dk..pke_dk + pke_ek];
    let hek = &dk[pke_dk + pke_ek..pke_dk + pke_ek + 32];
    let z = &dk[dk.len() - 32..];

    let mut m_prime = indcpa::decrypt::<K, DU, DV>(dk_pke, ct);

    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(&m_prime);
    g_in[32..].copy_from_slice(hek);
    let mut g = sha3_512(&g_in);
    let mut k_prime = [0u8; 32];
    k_prime.copy_from_slice(&g[..32]);
    let mut r_prime = [0u8; 32];
    r_prime.copy_from_slice(&g[32..]);

    // K̄ ← J(z ‖ c) via SHAKE256 over the two slices.
    let mut k_bar = [0u8; 32];
    let mut shake = Shake256::new();
    shake.update(z);
    shake.update(ct);
    shake.finalize_xof().read(&mut k_bar);

    // Re-encrypt and compare in constant time; keep K' iff the ciphertext
    // matches. The scratch buffer is sized for the largest ML-KEM set
    // (1024) so this branchlessly handles every set.
    let mut ct_cmp = [0u8; MAX_CT_BYTES];
    let ct_len = ct_bytes(K, DU, DV);
    indcpa::encrypt::<K, ETA1, ETA2, DU, DV>(ek, &m_prime, &r_prime, &mut ct_cmp[..ct_len]);

    let matches = ct.ct_eq(&ct_cmp[..ct_len]);
    let mut out = k_bar;
    out.conditional_assign(&k_prime, matches);

    // Wipe the transient secrets (the decrypted message, the G output, the
    // key/coins derived from it, the implicit-rejection secret K̄ — `out`
    // already holds its own copy — and the re-encryption buffer, which on the
    // reject path is a deterministic function of the secret m') before they
    // drop; `black_box` keeps the writes from being eliminated as dead stores.
    for b in m_prime
        .iter_mut()
        .chain(g_in.iter_mut())
        .chain(g.iter_mut())
        .chain(k_prime.iter_mut())
        .chain(r_prime.iter_mut())
        .chain(k_bar.iter_mut())
        .chain(ct_cmp.iter_mut())
    {
        *b = 0;
    }
    let _ = core::hint::black_box((&m_prime, &g_in, &g, &k_prime, &r_prime, &k_bar, &ct_cmp));
    out
}
