//! ML-DSA — the Module-Lattice Digital Signature Algorithm (FIPS 204), the
//! standardized form of Dilithium.
//!
//! Three security levels are provided — ML-DSA-44, -65, and -87 — built on a
//! single const-generic core (`K`, `L`) plus a per-level [`Params`] bundle. The
//! module needs `alloc`: keys and signatures are returned as `Vec<u8>` (their
//! sizes are fixed per level), while the heavy polynomial arithmetic stays on
//! the stack.
//!
//! Signing is hedged by default (32 bytes of fresh randomness) with a
//! deterministic variant available; both are validated against the FIPS 204
//! ACVP vectors.

mod encode;
mod field;
mod reduce;
#[cfg(feature = "x509")]
pub(crate) mod registry;
mod sample;

use alloc::vec::Vec;

use crate::rng::RngCore;
use encode::*;
use field::{D, N, Poly, ntt_mul, sub};
use reduce::{
    GAMMA2_32, GAMMA2_88, decompose, high_bits, inf_norm, make_hint, power2_round, use_hint,
};
use sample::{expand_mask, sample_bounded_poly, sample_challenge, sample_ntt_poly};

/// Size of the key-generation seed.
pub const SEED_SIZE: usize = 32;

/// Errors from ML-DSA operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A key or signature had the wrong length.
    InvalidLength,
    /// The context string exceeded 255 bytes.
    ContextTooLong,
    /// A key encoding was structurally invalid.
    Malformed,
}

/// Per-level ML-DSA parameters.
#[derive(Clone, Copy)]
pub(crate) struct Params {
    eta: u32,
    tau: usize,
    gamma1_bits: u32,
    gamma1: u32,
    gamma2: u32,
    omega: usize,
    beta: u32,
    /// Length of the commitment hash `c̃` (= λ/4).
    ctilde: usize,
    pubkey: usize,
    privkey: usize,
    sig: usize,
}

const POLY_T1: usize = N * 10 / 8; // 320
const POLY_T0: usize = N * 13 / 8; // 416

impl Params {
    const fn eta_bytes(&self) -> usize {
        if self.eta == 2 { N * 3 / 8 } else { N * 4 / 8 }
    }
    const fn z_bytes(&self) -> usize {
        if self.gamma1_bits == 17 {
            N * 18 / 8
        } else {
            N * 20 / 8
        }
    }
}

/// ML-DSA-44 (security level 2).
pub(crate) const P44: Params = Params {
    eta: 2,
    tau: 39,
    gamma1_bits: 17,
    gamma1: 1 << 17,
    gamma2: GAMMA2_88,
    omega: 80,
    beta: 2 * 39,
    ctilde: 128 / 4,
    pubkey: 32 + 4 * POLY_T1,
    privkey: 128 + (4 + 4) * (N * 3 / 8) + 4 * POLY_T0,
    sig: 128 / 4 + 4 * (N * 18 / 8) + 80 + 4,
};

/// ML-DSA-65 (security level 3).
pub(crate) const P65: Params = Params {
    eta: 4,
    tau: 49,
    gamma1_bits: 19,
    gamma1: 1 << 19,
    gamma2: GAMMA2_32,
    omega: 55,
    beta: 4 * 49,
    ctilde: 192 / 4,
    pubkey: 32 + 6 * POLY_T1,
    privkey: 128 + (6 + 5) * (N * 4 / 8) + 6 * POLY_T0,
    sig: 192 / 4 + 5 * (N * 20 / 8) + 55 + 6,
};

/// ML-DSA-87 (security level 5).
pub(crate) const P87: Params = Params {
    eta: 2,
    tau: 60,
    gamma1_bits: 19,
    gamma1: 1 << 19,
    gamma2: GAMMA2_32,
    omega: 75,
    beta: 2 * 60,
    ctilde: 256 / 4,
    pubkey: 32 + 8 * POLY_T1,
    privkey: 128 + (8 + 7) * (N * 3 / 8) + 8 * POLY_T0,
    sig: 256 / 4 + 7 * (N * 20 / 8) + 75 + 8,
};

// --- encoding dispatch helpers ---

fn pack_eta(f: &Poly, p: &Params) -> Vec<u8> {
    if p.eta == 2 {
        pack_eta2(f)
    } else {
        pack_eta4(f)
    }
}
fn unpack_eta(b: &[u8], p: &Params) -> Result<Poly, Error> {
    let r = if p.eta == 2 {
        unpack_eta2(b)
    } else {
        unpack_eta4(b)
    };
    r.map_err(|_| Error::Malformed)
}
fn pack_z(f: &Poly, p: &Params) -> Vec<u8> {
    if p.gamma1_bits == 17 {
        pack_z17(f)
    } else {
        pack_z19(f)
    }
}
fn unpack_z(b: &[u8], p: &Params) -> Poly {
    if p.gamma1_bits == 17 {
        unpack_z17(b)
    } else {
        unpack_z19(b)
    }
}
fn pack_w1(f: &Poly, p: &Params) -> Vec<u8> {
    if p.gamma2 == GAMMA2_88 {
        pack_w1_6(f)
    } else {
        pack_w1_4(f)
    }
}

fn shake256(parts: &[&[u8]], out: &mut [u8]) {
    use crate::hash::{ExtendableOutput, Shake256};
    let mut h = Shake256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize_into(out);
}

fn vec_inf_norm(v: &[Poly]) -> u32 {
    let mut m = 0;
    for p in v {
        for &c in &p.c {
            let n = inf_norm(c);
            if n > m {
                m = n;
            }
        }
    }
    m
}

fn vec_inf_norm_signed<const K: usize>(v: &[[i32; N]; K]) -> i32 {
    let mut m = 0;
    for row in v {
        for &c in row {
            let a = c.abs();
            if a > m {
                m = a;
            }
        }
    }
    m
}

fn count_ones(v: &[Poly]) -> usize {
    v.iter()
        .map(|p| p.c.iter().filter(|&&c| c != 0).count())
        .sum()
}

/// Samples the public matrix `Â` (NTT domain) from `rho`.
fn matrix<const K: usize, const L: usize>(rho: &[u8]) -> [[Poly; L]; K] {
    let mut a = [[Poly::zero(); L]; K];
    for (i, row) in a.iter_mut().enumerate() {
        for (j, cell) in row.iter_mut().enumerate() {
            *cell = sample_ntt_poly(rho, j as u8, i as u8);
        }
    }
    a
}

/// ML-DSA.KeyGen_internal (FIPS 204 Algorithm 6). Returns `(pk, sk)`.
pub(crate) fn keygen<const K: usize, const L: usize>(
    seed: &[u8; 32],
    p: &Params,
) -> (Vec<u8>, Vec<u8>) {
    let mut expanded = [0u8; 128];
    shake256(&[seed, &[K as u8, L as u8]], &mut expanded);
    let rho = &expanded[..32];
    let rho1 = &expanded[32..96];
    let key = &expanded[96..128];

    let mut s1 = [Poly::zero(); L];
    for (i, s) in s1.iter_mut().enumerate() {
        *s = sample_bounded_poly(rho1, p.eta, i as u16);
    }
    let mut s2 = [Poly::zero(); K];
    for (i, s) in s2.iter_mut().enumerate() {
        *s = sample_bounded_poly(rho1, p.eta, (L + i) as u16);
    }
    let a = matrix::<K, L>(rho);

    let mut s1_ntt = s1;
    for s in s1_ntt.iter_mut() {
        s.ntt();
    }

    let mut t1 = [Poly::zero(); K];
    let mut t0 = [Poly::zero(); K];
    for i in 0..K {
        let mut acc = Poly::zero();
        for j in 0..L {
            acc = acc.add(&ntt_mul(&a[i][j], &s1_ntt[j]));
        }
        acc.inv_ntt();
        let t = acc.add(&s2[i]);
        for jj in 0..N {
            let (hi, lo) = power2_round(t.c[jj]);
            t1[i].c[jj] = hi;
            t0[i].c[jj] = lo;
        }
    }

    // Public key: rho || ByteEncode(t1).
    let mut pk = Vec::with_capacity(p.pubkey);
    pk.extend_from_slice(rho);
    for t in &t1 {
        pk.extend_from_slice(&pack_t1(t));
    }

    let mut tr = [0u8; 64];
    shake256(&[&pk], &mut tr);

    // Secret key: rho || key || tr || s1 || s2 || t0.
    let mut sk = Vec::with_capacity(p.privkey);
    sk.extend_from_slice(rho);
    sk.extend_from_slice(key);
    sk.extend_from_slice(&tr);
    for s in &s1 {
        sk.extend_from_slice(&pack_eta(s, p));
    }
    for s in &s2 {
        sk.extend_from_slice(&pack_eta(s, p));
    }
    for t in &t0 {
        sk.extend_from_slice(&pack_t0(t));
    }
    (pk, sk)
}

/// ML-DSA.Sign_internal (FIPS 204 Algorithm 7). `m_prime` is the already-formed
/// message representative; `rnd` is the per-signature randomness (zero for the
/// deterministic variant).
pub(crate) fn sign_internal<const K: usize, const L: usize>(
    sk: &[u8],
    rnd: &[u8; 32],
    m_prime: &[u8],
    p: &Params,
) -> Vec<u8> {
    let rho = &sk[..32];
    let key = &sk[32..64];
    let tr = &sk[64..128];

    let mut off = 128;
    let eb = p.eta_bytes();
    let mut s1 = [Poly::zero(); L];
    for s in s1.iter_mut() {
        *s = unpack_eta(&sk[off..off + eb], p).expect("valid sk");
        off += eb;
    }
    let mut s2 = [Poly::zero(); K];
    for s in s2.iter_mut() {
        *s = unpack_eta(&sk[off..off + eb], p).expect("valid sk");
        off += eb;
    }
    let mut t0 = [Poly::zero(); K];
    for t in t0.iter_mut() {
        *t = unpack_t0(&sk[off..off + POLY_T0]);
        off += POLY_T0;
    }
    let a = matrix::<K, L>(rho);

    let mut s1_ntt = s1;
    let mut s2_ntt = s2;
    let mut t0_ntt = t0;
    for s in s1_ntt.iter_mut() {
        s.ntt();
    }
    for s in s2_ntt.iter_mut() {
        s.ntt();
    }
    for t in t0_ntt.iter_mut() {
        t.ntt();
    }

    let mut mu = [0u8; 64];
    shake256(&[tr, m_prime], &mut mu);
    let mut rho_prime = [0u8; 64];
    shake256(&[key, rnd, &mu], &mut rho_prime);

    let mut seed_buf = [0u8; 66];
    seed_buf[..64].copy_from_slice(&rho_prime);

    let mut kappa: u16 = 0;
    loop {
        // Masking vector y.
        let mut y = [Poly::zero(); L];
        for (i, yi) in y.iter_mut().enumerate() {
            let nu = kappa + i as u16;
            seed_buf[64] = nu as u8;
            seed_buf[65] = (nu >> 8) as u8;
            *yi = expand_mask(&seed_buf, p.gamma1_bits);
        }

        let mut y_ntt = y;
        for yi in y_ntt.iter_mut() {
            yi.ntt();
        }

        // w = A·y; w1 = HighBits(w).
        let mut w = [Poly::zero(); K];
        let mut w1 = [Poly::zero(); K];
        for i in 0..K {
            let mut acc = Poly::zero();
            for j in 0..L {
                acc = acc.add(&ntt_mul(&a[i][j], &y_ntt[j]));
            }
            acc.inv_ntt();
            w[i] = acc;
            for jj in 0..N {
                w1[i].c[jj] = high_bits(w[i].c[jj], p.gamma2);
            }
        }

        // c̃ = H(mu || w1); c = SampleInBall(c̃).
        let mut ctilde = alloc::vec![0u8; p.ctilde];
        {
            use crate::hash::{ExtendableOutput, Shake256};
            let mut h = Shake256::new();
            h.update(&mu);
            for wi in &w1 {
                h.update(&pack_w1(wi, p));
            }
            h.finalize_into(&mut ctilde);
        }
        let c = sample_challenge(&ctilde, p.tau);
        let mut c_ntt = c;
        c_ntt.ntt();

        // z = y + c·s1.
        let mut z = [Poly::zero(); L];
        for i in 0..L {
            let mut cs1 = ntt_mul(&c_ntt, &s1_ntt[i]);
            cs1.inv_ntt();
            z[i] = y[i].add(&cs1);
        }
        if vec_inf_norm(&z) >= p.gamma1 - p.beta {
            kappa += L as u16;
            continue;
        }

        // r0 = LowBits(w − c·s2).
        let mut r0 = [[0i32; N]; K];
        for i in 0..K {
            let mut cs2 = ntt_mul(&c_ntt, &s2_ntt[i]);
            cs2.inv_ntt();
            for (jj, slot) in r0[i].iter_mut().enumerate() {
                let (_, low) = decompose(sub(w[i].c[jj], cs2.c[jj]), p.gamma2);
                *slot = low;
            }
        }
        if vec_inf_norm_signed(&r0) >= (p.gamma2 - p.beta) as i32 {
            kappa += L as u16;
            continue;
        }

        // ct0 = c·t0; bound check.
        let mut ct0 = [Poly::zero(); K];
        for i in 0..K {
            let mut x = ntt_mul(&c_ntt, &t0_ntt[i]);
            x.inv_ntt();
            ct0[i] = x;
        }
        if vec_inf_norm(&ct0) >= p.gamma2 {
            kappa += L as u16;
            continue;
        }

        // Hints.
        let mut hints = [Poly::zero(); K];
        for i in 0..K {
            let mut cs2 = ntt_mul(&c_ntt, &s2_ntt[i]);
            cs2.inv_ntt();
            for jj in 0..N {
                let r = sub(w[i].c[jj], cs2.c[jj]);
                hints[i].c[jj] = make_hint(ct0[i].c[jj], r, p.gamma2);
            }
        }
        if count_ones(&hints) > p.omega {
            kappa += L as u16;
            continue;
        }

        // Encode the signature.
        let mut sig = Vec::with_capacity(p.sig);
        sig.extend_from_slice(&ctilde);
        for zi in &z {
            sig.extend_from_slice(&pack_z(zi, p));
        }
        sig.extend_from_slice(&pack_hint(&hints, p.omega));
        return sig;
    }
}

/// ML-DSA.Verify_internal (FIPS 204 Algorithm 8).
pub(crate) fn verify_internal<const K: usize, const L: usize>(
    pk: &[u8],
    sig: &[u8],
    m_prime: &[u8],
    p: &Params,
) -> bool {
    if pk.len() != p.pubkey || sig.len() != p.sig {
        return false;
    }
    let rho = &pk[..32];
    let mut t1 = [Poly::zero(); K];
    let mut off = 32;
    for t in t1.iter_mut() {
        *t = unpack_t1(&pk[off..off + POLY_T1]);
        off += POLY_T1;
    }

    let mut tr = [0u8; 64];
    shake256(&[pk], &mut tr);
    let mut mu = [0u8; 64];
    shake256(&[&tr, m_prime], &mut mu);

    // Decode the signature.
    let ctilde = &sig[..p.ctilde];
    let mut so = p.ctilde;
    let zb = p.z_bytes();
    let mut z = [Poly::zero(); L];
    for zi in z.iter_mut() {
        *zi = unpack_z(&sig[so..so + zb], p);
        so += zb;
    }
    if vec_inf_norm(&z) >= p.gamma1 - p.beta {
        return false;
    }
    let mut hints = [Poly::zero(); K];
    if !unpack_hint(&sig[so..], &mut hints, p.omega) {
        return false;
    }

    let a = matrix::<K, L>(rho);
    let c = sample_challenge(ctilde, p.tau);
    let mut c_ntt = c;
    c_ntt.ntt();
    let mut z_ntt = z;
    for zi in z_ntt.iter_mut() {
        zi.ntt();
    }
    let mut t1_ntt = [Poly::zero(); K];
    for i in 0..K {
        let mut scaled = Poly::zero();
        for jj in 0..N {
            scaled.c[jj] = t1[i].c[jj] << D;
        }
        scaled.ntt();
        t1_ntt[i] = scaled;
    }

    // w'1 = UseHint(A·z − c·t1·2ᵈ), accumulated into the commitment hash.
    use crate::hash::{ExtendableOutput, Shake256};
    let mut h = Shake256::new();
    h.update(&mu);
    for i in 0..K {
        let mut acc = Poly::zero();
        for j in 0..L {
            acc = acc.add(&ntt_mul(&a[i][j], &z_ntt[j]));
        }
        acc = acc.sub(&ntt_mul(&c_ntt, &t1_ntt[i]));
        acc.inv_ntt();
        let mut w1 = Poly::zero();
        for jj in 0..N {
            w1.c[jj] = use_hint(hints[i].c[jj], acc.c[jj], p.gamma2);
        }
        h.update(&pack_w1(&w1, p));
    }
    let mut check = alloc::vec![0u8; p.ctilde];
    h.finalize_into(&mut check);

    // Constant-time comparison of c̃ — both inputs are public, but uniform
    // with the rest of the codebase. The explicit length check protects
    // against zip silently truncating to the shorter slice.
    if ctilde.len() != check.len() {
        return false;
    }
    bool::from(<[u8] as crate::ct::ConstantTimeEq>::ct_eq(
        ctilde,
        check.as_slice(),
    ))
}

/// Derives the public key bytes from a parsed private key (FIPS 204 §7.2:
/// `pk = ρ ‖ ByteEncode₁₀(t1)` where `t = A·s₁ + s₂` and `t = t1·2ᵈ + t0`).
pub(crate) fn derive_public_from_sk<const K: usize, const L: usize>(
    sk: &[u8],
    p: &Params,
) -> Vec<u8> {
    let rho = &sk[..32];
    let mut off = 128;
    let eb = p.eta_bytes();
    let mut s1 = [Poly::zero(); L];
    for s in s1.iter_mut() {
        *s = unpack_eta(&sk[off..off + eb], p).expect("valid sk");
        off += eb;
    }
    let mut s2 = [Poly::zero(); K];
    for s in s2.iter_mut() {
        *s = unpack_eta(&sk[off..off + eb], p).expect("valid sk");
        off += eb;
    }
    let a = matrix::<K, L>(rho);
    let mut s1_ntt = s1;
    for s in s1_ntt.iter_mut() {
        s.ntt();
    }
    let mut pk = Vec::with_capacity(p.pubkey);
    pk.extend_from_slice(rho);
    for i in 0..K {
        let mut acc = Poly::zero();
        for j in 0..L {
            acc = acc.add(&ntt_mul(&a[i][j], &s1_ntt[j]));
        }
        acc.inv_ntt();
        let t = acc.add(&s2[i]);
        let mut t1 = Poly::zero();
        for jj in 0..N {
            (t1.c[jj], _) = power2_round(t.c[jj]);
        }
        pk.extend_from_slice(&pack_t1(&t1));
    }
    pk
}

/// Builds `M' = 0 ‖ len(ctx) ‖ ctx ‖ msg` for the external signing interface.
fn m_prime(ctx: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(2 + ctx.len() + msg.len());
    m.push(0);
    m.push(ctx.len() as u8);
    m.extend_from_slice(ctx);
    m.extend_from_slice(msg);
    m
}

/// Generates a per-level type family `(PrivateKey, PublicKey)`.
macro_rules! ml_dsa_level {
    (
        $(#[$km:meta])* $kind:ident,
        $sk:ident, $pk:ident,
        $k:expr, $l:expr, $params:ident, $oid:expr
    ) => {
        $(#[$km])*
        #[derive(Clone)]
        pub struct $sk(Vec<u8>);

        #[doc = concat!("An ", stringify!($kind), " public (verification) key.")]
        #[derive(Clone, PartialEq, Eq, Debug)]
        pub struct $pk(Vec<u8>);

        impl $sk {
            /// Deterministically derives a key pair from a 32-byte seed.
            pub fn from_seed(seed: &[u8; SEED_SIZE]) -> ($sk, $pk) {
                let (pk, sk) = keygen::<$k, $l>(seed, &$params);
                ($sk(sk), $pk(pk))
            }

            /// Generates a fresh key pair from `rng`.
            pub fn generate<R: RngCore>(rng: &mut R) -> ($sk, $pk) {
                let mut seed = [0u8; SEED_SIZE];
                rng.fill_bytes(&mut seed);
                Self::from_seed(&seed)
            }

            /// Signs `msg` with an optional `ctx` string (≤ 255 bytes), hedged
            /// with randomness from `rng`.
            pub fn sign<R: RngCore>(
                &self,
                rng: &mut R,
                msg: &[u8],
                ctx: &[u8],
            ) -> Result<Vec<u8>, Error> {
                if ctx.len() > 255 {
                    return Err(Error::ContextTooLong);
                }
                let mut rnd = [0u8; 32];
                rng.fill_bytes(&mut rnd);
                Ok(sign_internal::<$k, $l>(&self.0, &rnd, &m_prime(ctx, msg), &$params))
            }

            /// Signs `msg` deterministically (zero randomness).
            pub fn sign_deterministic(&self, msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, Error> {
                if ctx.len() > 255 {
                    return Err(Error::ContextTooLong);
                }
                Ok(sign_internal::<$k, $l>(&self.0, &[0u8; 32], &m_prime(ctx, msg), &$params))
            }

            /// Derives the matching public key from this private key.
            pub fn public_key(&self) -> $pk {
                $pk(derive_public_from_sk::<$k, $l>(&self.0, &$params))
            }

            /// The encoded private key.
            pub fn to_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Restores a private key from its encoding.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != $params.privkey {
                    return Err(Error::InvalidLength);
                }
                Ok($sk(bytes.to_vec()))
            }

            /// Encodes the private key as a PKCS#8 `PrivateKeyInfo` DER. The
            /// `privateKey` OCTET STRING holds the raw expanded key bytes
            /// (purecrypto's own format).
            #[cfg(feature = "der")]
            pub fn to_pkcs8_der(&self) -> Vec<u8> {
                use crate::der::{encode_integer, encode_octet_string, encode_sequence, oid_tlv};
                let algid = encode_sequence(&oid_tlv($oid));
                encode_sequence(
                    &[encode_integer(&[0]), algid, encode_octet_string(&self.0)].concat(),
                )
            }

            /// Encodes the private key as a PKCS#8 PEM document.
            #[cfg(feature = "der")]
            pub fn to_pkcs8_pem(&self) -> alloc::string::String {
                crate::der::pem_encode("PRIVATE KEY", &self.to_pkcs8_der())
            }

            /// Parses a PKCS#8 `PrivateKeyInfo` DER, expecting the raw expanded
            /// key bytes in the `privateKey` OCTET STRING.
            #[cfg(feature = "der")]
            pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, Error> {
                use crate::der::{Reader, parse_oid};
                let mut r = Reader::new(der);
                let mut seq = r.read_sequence().map_err(|_| Error::Malformed)?;
                seq.read_integer_bytes().map_err(|_| Error::Malformed)?;
                let mut algid = seq.read_sequence().map_err(|_| Error::Malformed)?;
                let oid = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
                    .map_err(|_| Error::Malformed)?;
                if oid.as_slice() != $oid {
                    return Err(Error::Malformed);
                }
                let inner = seq.read_octet_string().map_err(|_| Error::Malformed)?;
                Self::from_bytes(inner)
            }

            /// Parses a PKCS#8 PEM private key.
            #[cfg(feature = "der")]
            pub fn from_pkcs8_pem(pem: &str) -> Result<Self, Error> {
                let der = crate::der::pem_decode(pem, "PRIVATE KEY")
                    .map_err(|_| Error::Malformed)?;
                Self::from_pkcs8_der(&der)
            }

            /// Encrypts the PKCS#8 encoding under PBES2 (RFC 5958 §3 +
            /// RFC 8018 §6.2), returning the DER-encoded
            /// `EncryptedPrivateKeyInfo`.
            #[cfg(all(feature = "der", feature = "kdf"))]
            pub fn to_pkcs8_der_encrypted(
                &self,
                password: &[u8],
                params: &crate::kdf::pbes2::Pbes2Params,
                rng: &mut impl crate::rng::RngCore,
            ) -> Vec<u8> {
                crate::kdf::pbes2::encrypt(&self.to_pkcs8_der(), password, params, rng)
            }

            /// PEM-wrapped variant of [`Self::to_pkcs8_der_encrypted`].
            #[cfg(all(feature = "der", feature = "kdf"))]
            pub fn to_pkcs8_pem_encrypted(
                &self,
                password: &[u8],
                params: &crate::kdf::pbes2::Pbes2Params,
                rng: &mut impl crate::rng::RngCore,
            ) -> alloc::string::String {
                crate::kdf::pbes2::encrypt_pem(&self.to_pkcs8_der(), password, params, rng)
            }

            /// Parses an `EncryptedPrivateKeyInfo` DER and decrypts it
            /// back to a PKCS#8 ML-DSA private key.
            #[cfg(all(feature = "der", feature = "kdf"))]
            pub fn from_pkcs8_der_encrypted(der: &[u8], password: &[u8]) -> Result<Self, Error> {
                let inner = crate::kdf::pbes2::decrypt(der, password)
                    .map_err(|_| Error::Malformed)?;
                Self::from_pkcs8_der(&inner)
            }

            /// PEM-wrapped variant of [`Self::from_pkcs8_der_encrypted`].
            #[cfg(all(feature = "der", feature = "kdf"))]
            pub fn from_pkcs8_pem_encrypted(pem: &str, password: &[u8]) -> Result<Self, Error> {
                let inner = crate::kdf::pbes2::decrypt_pem(pem, password)
                    .map_err(|_| Error::Malformed)?;
                Self::from_pkcs8_der(&inner)
            }
        }

        impl $pk {
            /// Verifies `sig` over `msg` with optional `ctx`.
            pub fn verify(&self, sig: &[u8], msg: &[u8], ctx: &[u8]) -> bool {
                if ctx.len() > 255 {
                    return false;
                }
                verify_internal::<$k, $l>(&self.0, sig, &m_prime(ctx, msg), &$params)
            }

            /// The raw encoded public key.
            pub fn to_bytes(&self) -> &[u8] {
                &self.0
            }

            /// Restores a public key from its raw encoding.
            pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
                if bytes.len() != $params.pubkey {
                    return Err(Error::InvalidLength);
                }
                Ok($pk(bytes.to_vec()))
            }

            /// Encodes the key as a PKIX `SubjectPublicKeyInfo` DER structure
            /// (draft-ietf-lamps-dilithium-certificates).
            #[cfg(feature = "der")]
            pub fn to_spki_der(&self) -> Vec<u8> {
                use crate::der::{encode_bit_string, encode_sequence, oid_tlv};
                let algid = encode_sequence(&oid_tlv($oid));
                encode_sequence(&[algid, encode_bit_string(&self.0)].concat())
            }

            /// Encodes the key as a PKIX PEM document.
            #[cfg(feature = "der")]
            pub fn to_spki_pem(&self) -> alloc::string::String {
                crate::der::pem_encode("PUBLIC KEY", &self.to_spki_der())
            }

            /// Parses a PKIX `SubjectPublicKeyInfo` DER structure.
            #[cfg(feature = "der")]
            pub fn from_spki_der(der: &[u8]) -> Result<Self, Error> {
                use crate::der::{Reader, parse_oid};
                let mut reader = Reader::new(der);
                let mut spki = reader.read_sequence().map_err(|_| Error::Malformed)?;
                let mut algid = spki.read_sequence().map_err(|_| Error::Malformed)?;
                let oid = parse_oid(algid.read_oid().map_err(|_| Error::Malformed)?)
                    .map_err(|_| Error::Malformed)?;
                if oid.as_slice() != $oid {
                    return Err(Error::Malformed);
                }
                let bits = spki.read_bit_string().map_err(|_| Error::Malformed)?;
                Self::from_bytes(bits)
            }

            /// Parses a PKIX PEM public key.
            #[cfg(feature = "der")]
            pub fn from_spki_pem(pem: &str) -> Result<Self, Error> {
                let der = crate::der::pem_decode(pem, "PUBLIC KEY").map_err(|_| Error::Malformed)?;
                Self::from_spki_der(&der)
            }
        }
    };
}

/// `id-ml-dsa-44` (2.16.840.1.101.3.4.3.17).
#[cfg(feature = "der")]
const OID_44: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 17];
/// `id-ml-dsa-65` (2.16.840.1.101.3.4.3.18).
#[cfg(feature = "der")]
const OID_65: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
/// `id-ml-dsa-87` (2.16.840.1.101.3.4.3.19).
#[cfg(feature = "der")]
const OID_87: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 19];

#[cfg(not(feature = "der"))]
const OID_44: &[u64] = &[];
#[cfg(not(feature = "der"))]
const OID_65: &[u64] = &[];
#[cfg(not(feature = "der"))]
const OID_87: &[u64] = &[];

ml_dsa_level!(
    /// An ML-DSA-44 private (signing) key.
    MlDsa44, MlDsa44PrivateKey, MlDsa44PublicKey, 4, 4, P44, OID_44
);
ml_dsa_level!(
    /// An ML-DSA-65 private (signing) key.
    MlDsa65, MlDsa65PrivateKey, MlDsa65PublicKey, 6, 5, P65, OID_65
);
ml_dsa_level!(
    /// An ML-DSA-87 private (signing) key.
    MlDsa87, MlDsa87PrivateKey, MlDsa87PublicKey, 8, 7, P87, OID_87
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn unhex(s: &str) -> Vec<u8> {
        let b = s.as_bytes();
        let mut v = Vec::with_capacity(b.len() / 2);
        let mut i = 0;
        while i < b.len() {
            let hi = (b[i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[i + 1] as char).to_digit(16).unwrap() as u8;
            v.push((hi << 4) | lo);
            i += 2;
        }
        v
    }

    // ACVP FIPS 204 known-answer tests (keyGen, deterministic sigGen, sigVer).
    macro_rules! acvp_tests {
        ($kg:ident, $sg:ident, $sv:ident, $k:expr, $l:expr, $params:expr,
         $kgf:expr, $sgf:expr, $svf:expr) => {
            #[test]
            fn $kg() {
                for line in include_str!($kgf).lines() {
                    let mut it = line.split_whitespace();
                    let seed: [u8; 32] = unhex(it.next().unwrap()).try_into().unwrap();
                    let pk_exp = unhex(it.next().unwrap());
                    let sk_exp = unhex(it.next().unwrap());
                    let (pk, sk) = keygen::<$k, $l>(&seed, &$params);
                    assert_eq!(pk, pk_exp, "pk");
                    assert_eq!(sk, sk_exp, "sk");
                }
            }

            #[test]
            fn $sg() {
                for line in include_str!($sgf).lines() {
                    let mut it = line.split_whitespace();
                    let sk = unhex(it.next().unwrap());
                    let rnd: [u8; 32] = unhex(it.next().unwrap()).try_into().unwrap();
                    let msg = unhex(it.next().unwrap());
                    let sig_exp = unhex(it.next().unwrap());
                    let sig = sign_internal::<$k, $l>(&sk, &rnd, &msg, &$params);
                    assert_eq!(sig, sig_exp, "signature");
                }
            }

            #[test]
            fn $sv() {
                for line in include_str!($svf).lines() {
                    let mut it = line.split_whitespace();
                    let pk = unhex(it.next().unwrap());
                    let msg = unhex(it.next().unwrap());
                    let sig = unhex(it.next().unwrap());
                    let want = it.next().unwrap() == "1";
                    let got = verify_internal::<$k, $l>(&pk, &sig, &msg, &$params);
                    assert_eq!(got, want, "verify");
                }
            }
        };
    }

    acvp_tests!(
        acvp_keygen_44,
        acvp_siggen_44,
        acvp_sigver_44,
        4,
        4,
        P44,
        "../../testdata/mldsa44_keygen.kat",
        "../../testdata/mldsa44_siggen.kat",
        "../../testdata/mldsa44_sigver.kat"
    );
    acvp_tests!(
        acvp_keygen_65,
        acvp_siggen_65,
        acvp_sigver_65,
        6,
        5,
        P65,
        "../../testdata/mldsa65_keygen.kat",
        "../../testdata/mldsa65_siggen.kat",
        "../../testdata/mldsa65_sigver.kat"
    );
    acvp_tests!(
        acvp_keygen_87,
        acvp_siggen_87,
        acvp_sigver_87,
        8,
        7,
        P87,
        "../../testdata/mldsa87_keygen.kat",
        "../../testdata/mldsa87_siggen.kat",
        "../../testdata/mldsa87_sigver.kat"
    );

    #[cfg(feature = "der")]
    #[test]
    fn spki_matches_openssl() {
        // OpenSSL 3.5 ML-DSA-65 public key for seed = 0³², as a PKIX SPKI.
        let expected = unhex(include_str!("../../testdata/mldsa65_openssl_spki.hex").trim());
        let (_sk, pk) = MlDsa65PrivateKey::from_seed(&[0u8; 32]);
        assert_eq!(pk.to_spki_der(), expected);
        // Round-trip through SPKI PEM.
        let parsed = MlDsa65PublicKey::from_spki_pem(&pk.to_spki_pem()).unwrap();
        assert_eq!(parsed, pk);
    }

    #[test]
    fn roundtrip_and_reject() {
        let mut rng = HmacDrbg::<Sha256>::new(b"mldsa", b"nonce", &[]);
        let (sk, pk) = MlDsa65PrivateKey::generate(&mut rng);
        let sig = sk.sign(&mut rng, b"hello purecrypto", b"ctx").unwrap();
        assert!(pk.verify(&sig, b"hello purecrypto", b"ctx"));
        // Wrong message, wrong context, and a tampered signature all fail.
        assert!(!pk.verify(&sig, b"other", b"ctx"));
        assert!(!pk.verify(&sig, b"hello purecrypto", b"other"));
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(!pk.verify(&bad, b"hello purecrypto", b"ctx"));

        // Deterministic signing is reproducible and verifies.
        let d1 = sk.sign_deterministic(b"abc", b"").unwrap();
        let d2 = sk.sign_deterministic(b"abc", b"").unwrap();
        assert_eq!(d1, d2);
        assert!(pk.verify(&d1, b"abc", b""));
    }
}
