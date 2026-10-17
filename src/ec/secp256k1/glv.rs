//! The secp256k1 GLV endomorphism: constants and the constant-time scalar
//! split shared by the constant-time ladder ([`super::group::Point::mul`])
//! and the variable-time verifier ([`super::vartime`]).
//!
//! secp256k1 has an efficiently computable endomorphism `φ(x, y) = (β·x, y)`
//! acting on the group as multiplication by `λ`, a cube root of unity mod the
//! group order `n`. A scalar `k` decomposes as `k ≡ k₁ + k₂·λ (mod n)` with
//! both halves of at most 128 bits, so `k·P = k₁·P + k₂·φ(P)` costs ~128
//! doublings instead of 256 (the GLV method, Gallant–Lambert–Vanstone 2001),
//! using the lattice basis and rounding constants of libsecp256k1's
//! `secp256k1_scalar_split_lambda`.

use super::Scalar;
use super::field_backend::{Fe, fe_from_hex};

/// `β`, a primitive cube root of unity mod `p`: `(x, y) ↦ (β·x, y)` is the
/// endomorphism acting as multiplication by [`LAMBDA`].
pub(super) const BETA: Fe =
    fe_from_hex("7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee");

/// `λ`, the matching cube root of unity mod `n`.
pub(super) const LAMBDA: Fe =
    fe_from_hex("5363ad4cc05c30e0a5261c028812645a122e22ea20816678df02967c1b23bd72");

/// `−b₁ mod n` and `−b₂ mod n` for the short lattice basis
/// `(a₁, b₁) = (0x3086…eb15, −0xe443…e4c3)`, `(a₂, b₂) = (0x1_14ca…4cfd8, a₁)`
/// of `{(x, y) : x + y·λ ≡ 0 (mod n)}` (the libsecp256k1 constants).
const MINUS_B1: Fe =
    fe_from_hex("00000000000000000000000000000000e4437ed6010e88286f547fa90abfe4c3");
const MINUS_B2: Fe =
    fe_from_hex("fffffffffffffffffffffffffffffffe8a280ac50774346dd765cda83db1562c");

/// `round(2³⁸⁴·b₂ / n)` and `round(2³⁸⁴·(−b₁) / n)`: `round(k·gᵢ / 2³⁸⁴)`
/// approximates the Babai rounding coefficients of `k` in that basis.
const G1: Fe = fe_from_hex("3086d221a7d46bcde86c90e49284eb153daa8a1471e8ca7fe893209a45dbb031");
const G2: Fe = fe_from_hex("e4437ed6010e88286f547fa90abfe4c4221208ac9df506c61571b4ae8ac47f71");

/// `2⁻¹ mod n`.
pub(super) const INV2: Fe =
    fe_from_hex("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1");

/// `2¹²⁸`, the offset that lifts a signed split half into `[0, 2¹²⁹)`.
pub(super) const TWO_128: Fe = Fe::from_limbs([0, 0, 1, 0]);

/// `(2¹³² − 2¹²⁹ − 1)·2⁻¹·(1 + λ) mod n`: see [`glv_prepare`].
const GLV_OFFSET: Fe =
    fe_from_hex("bb58ec9e87d71e35990ac3a5ca749c0919f36d7a32da3575b9a37d9953f62c2e");

/// `(2²⁵⁶ − 1)·2⁻¹ mod n`: see [`comb_prepare`].
#[cfg(any(feature = "secp256k1-table", test))]
const COMB_OFFSET: Fe =
    fe_from_hex("00000000000000000000000000000000a2a8918ca85bafe22016d0b997e4df5f");

/// `round(k·g / 2³⁸⁴)` for 256-bit `k` and `g`. Constant time: fixed loops,
/// no data-dependent control flow.
fn mul_shift_384(k: &Fe, g: &Fe) -> Fe {
    let (k, g) = (k.as_limbs(), g.as_limbs());
    let mut t = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let acc = t[i + j] as u128 + (k[i] as u128) * (g[j] as u128) + carry;
            t[i + j] = acc as u64;
            carry = acc >> 64;
        }
        t[i + 4] = carry as u64;
    }
    // Bits 384.. plus the rounding bit 383 (no overflow: the quotient is
    // < 2¹²⁸ since g < 2²⁵⁶ and k < 2²⁵⁶).
    let round = t[5] >> 63;
    let (lo, c) = t[6].overflowing_add(round);
    Fe::from_limbs([lo, t[7] + c as u64, 0, 0])
}

/// GLV split of `k < n` as residues: returns `(k₁, k₂)` with
/// `k ≡ k₁ + k₂·λ (mod n)` where each residue is the image of a signed
/// integer of magnitude below `2¹²⁸` (i.e. `kᵢ < 2¹²⁸` or `kᵢ > n − 2¹²⁸`).
/// **Constant time** in `k`: a fixed sequence of modular operations.
pub(super) fn split_residues(k: &Fe) -> (Fe, Fe) {
    let m = &Scalar::MODULUS;
    let c1 = mul_shift_384(k, &G1);
    let c2 = mul_shift_384(k, &G2);
    let k2 = m.add_mod(&m.mul_mod(&c1, &MINUS_B1), &m.mul_mod(&c2, &MINUS_B2));
    let k1 = m.sub_mod(k, &m.mul_mod(&k2, &LAMBDA));
    (k1, k2)
}

/// Prepares `k < n` for the signed-digit GLV ladder: returns `(v₁, v₂)`,
/// both in `[0, 2¹²⁹)`, such that `k ≡ D(v₁) + D(v₂)·λ (mod n)` where
/// `D(v) = 2v + 1 − 2¹³²` is the value whose 33 base-16 digits are the
/// signed odd digits `2u + 1 − 16` of `v`'s nibbles `u`.
///
/// With `vᵢ = sᵢ + 2¹²⁸` for a split `q ≡ s₁ + s₂·λ`,
/// `D(v₁) + D(v₂)·λ = 2q + (2¹²⁹ + 1 − 2¹³²)(1 + λ)`, so the scalar to split
/// is `q = k·2⁻¹ + (2¹³² − 2¹²⁹ − 1)·2⁻¹·(1 + λ)`. The offset keeps every
/// half non-negative without a sign-dependent negation.
/// **Constant time** in `k`.
pub(super) fn glv_prepare(k: &Fe) -> (Fe, Fe) {
    let m = &Scalar::MODULUS;
    let q = m.add_mod(&m.mul_mod(k, &INV2), &GLV_OFFSET);
    let (s1, s2) = split_residues(&q);
    (m.add_mod(&s1, &TWO_128), m.add_mod(&s2, &TWO_128))
}

/// Prepares `k < n` for the 64-window signed-digit comb: returns `v < n`
/// with `k ≡ D(v) = 2v + 1 − 2²⁵⁶ (mod n)`, i.e. `v = (k + 2²⁵⁶ − 1)·2⁻¹`.
/// **Constant time** in `k`.
#[cfg(feature = "secp256k1-table")]
pub(super) fn comb_prepare(k: &Fe) -> Fe {
    let m = &Scalar::MODULUS;
    m.add_mod(&m.mul_mod(k, &INV2), &COMB_OFFSET)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The hard-coded scalar constants against their definitions.
    #[test]
    fn constants_match_definitions() {
        let m = &Scalar::MODULUS;
        let two = Fe::from_u64(2);
        assert_eq!(m.mul_mod(&INV2, &two), Fe::ONE);
        // 2¹³² − 2¹²⁹ − 1 mod n, built from powers of two.
        let pow2 = |e: usize| {
            let mut l = [0u64; 4];
            l[e / 64] = 1 << (e % 64);
            Fe::from_limbs(l)
        };
        let t = m.sub_mod(&m.sub_mod(&pow2(132), &pow2(129)), &Fe::ONE);
        let one_plus_lambda = m.add_mod(&Fe::ONE, &LAMBDA);
        assert_eq!(
            m.mul_mod(&m.mul_mod(&t, &INV2), &one_plus_lambda),
            GLV_OFFSET
        );
        // 2²⁵⁶ − 1 ≡ (2²⁵⁶ − 1) − n·1 … reduce the all-ones value mod n.
        let all_ones = Fe::from_limbs([u64::MAX; 4]).reduce(&Scalar::ORDER);
        assert_eq!(m.mul_mod(&all_ones, &INV2), COMB_OFFSET);
        assert_eq!(TWO_128, pow2(128));
    }
}
