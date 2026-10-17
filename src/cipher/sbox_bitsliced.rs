//! Bitsliced evaluation of the non-AES block-cipher S-boxes.
//!
//! Every 8-bit S-box in ARIA, Camellia, SM4 and SEED is affine-equivalent to
//! the AES S-box: `S(x) = post(S_aes(pre(x)))` for fixed GF(2)-affine maps
//! `pre` and `post`. (Each is an inversion in some GF(2⁸) — ARIA/Camellia in
//! the AES field, SM4 modulo `0x1f5`, SEED modulo `0x163` — dressed in affine
//! layers; a field isomorphism moves the inversion into the AES field, and
//! SEED's `x²⁴⁷ = (x⁻¹)⁸` is the inverse followed by three Frobenius
//! squarings, which are linear.) The maps were recovered numerically from the
//! reference tables, and every module's tests recompute them from its
//! reference table with [`derive`] / [`field_iso`].
//!
//! [`sbox_custom`] therefore evaluates any of these S-boxes on up to 32 bytes
//! at once with the AES bitsliced circuit ([`super::aes::gf::sbox_planes`],
//! Boyar–Peralta, 113 gates on eight 32-bit planes): transpose the bytes to
//! planes, apply `pre` as a handful of plane XORs, run the circuit, apply
//! `post` (which absorbs the AES output affine), transpose back. The maps
//! may differ per byte lane — ARIA's four S-boxes by byte position,
//! Camellia's rotated variants, SEED's two — at no extra cost, since each
//! matrix entry is a lane mask. Everything is fixed word operations: no
//! table, no secret-dependent branch or index.
//!
//! Compared with the previous per-byte `gf_inv` addition chains (13 masked
//! field multiplications per byte) this is 30–50× fewer operations per byte,
//! and the ciphers batch independent blocks to fill the 32 lanes.

use super::aes::gf::sbox_planes;

/// An affine map on bytes, `y = M·x ⊕ c`: `rows[i]` holds (LSB-first) the
/// input bits that feed output bit `i`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Affine {
    pub(crate) rows: [u8; 8],
    pub(crate) c: u8,
}

impl Affine {
    pub(crate) const IDENTITY: Affine = Affine {
        rows: [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80],
        c: 0,
    };

    /// Evaluates the map on one byte.
    #[cfg(test)]
    pub(crate) fn apply(&self, x: u8) -> u8 {
        let mut y = self.c;
        for (i, &row) in self.rows.iter().enumerate() {
            y ^= (((row & x).count_ones() & 1) as u8) << i;
        }
        y
    }
}

/// An affine map on the plane layout, possibly different per byte lane:
/// output plane `i` is `c[i] ⊕ ⨁ⱼ (q[j] & m[i][j])`, where bit `l` of
/// `m[i][j]` says that in lane `l` input bit `j` feeds output bit `i`, and
/// bit `l` of `c[i]` complements output bit `i` of lane `l`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlaneAffine {
    m: [[u32; 8]; 8],
    c: [u32; 8],
}

impl PlaneAffine {
    /// The same byte map on every lane.
    pub(crate) const fn uniform(a: Affine) -> Self {
        Self::per_lane(&[a], &[0; 32])
    }

    /// Lane `l` uses `maps[pattern[l]]`. (Lane `l` is byte `l % 8` of word
    /// `l / 8` of the `sbox_custom` input.)
    pub(crate) const fn per_lane(maps: &[Affine], pattern: &[u8; 32]) -> Self {
        let mut m = [[0u32; 8]; 8];
        let mut c = [0u32; 8];
        let mut l = 0;
        while l < 32 {
            let a = maps[pattern[l] as usize];
            let mut i = 0;
            while i < 8 {
                let mut j = 0;
                while j < 8 {
                    if (a.rows[i] >> j) & 1 == 1 {
                        m[i][j] |= 1 << l;
                    }
                    j += 1;
                }
                if (a.c >> i) & 1 == 1 {
                    c[i] |= 1 << l;
                }
                i += 1;
            }
            l += 1;
        }
        PlaneAffine { m, c }
    }
}

/// Transposes the 8×8 bit matrix held in `x` (byte `j` bit `i` ↔ byte `i`
/// bit `j`), Hacker's Delight §7-3. An involution.
#[inline(always)]
fn transpose8(mut x: u64) -> u64 {
    let t = (x ^ (x >> 7)) & 0x00aa_00aa_00aa_00aa;
    x ^= t ^ (t << 7);
    let t = (x ^ (x >> 14)) & 0x0000_cccc_0000_cccc;
    x ^= t ^ (t << 14);
    let t = (x ^ (x >> 28)) & 0x0000_0000_f0f0_f0f0;
    x ^= t ^ (t << 28);
    x
}

/// Splits `N ≤ 4` little-endian words into bit-planes: bit `8w + j` of
/// `q[i]` is bit `i` of byte `j` of word `w`. Lanes of absent words are zero.
#[inline(always)]
fn to_planes<const N: usize>(words: &[u64; N]) -> [u32; 8] {
    let mut q = [0u32; 8];
    for (w, &x) in words.iter().enumerate() {
        let t = transpose8(x);
        for (i, p) in q.iter_mut().enumerate() {
            *p |= ((t >> (8 * i)) as u8 as u32) << (8 * w);
        }
    }
    q
}

/// Inverse of [`to_planes`].
#[inline(always)]
fn from_planes<const N: usize>(q: &[u32; 8], words: &mut [u64; N]) {
    for (w, x) in words.iter_mut().enumerate() {
        let mut t = 0u64;
        for (i, &p) in q.iter().enumerate() {
            t |= ((p >> (8 * w)) as u8 as u64) << (8 * i);
        }
        *x = transpose8(t);
    }
}

/// Applies a plane affine map. With a `const` map inlined, the zero masks
/// vanish and the all-ones ones become plain XORs.
#[inline(always)]
fn apply_planes(q: &mut [u32; 8], a: &PlaneAffine) {
    let x = *q;
    for (i, out) in q.iter_mut().enumerate() {
        let mut y = a.c[i];
        for (j, &p) in x.iter().enumerate() {
            y ^= p & a.m[i][j];
        }
        *out = y;
    }
}

/// The one shared, out-of-line copy of the AES circuit.
#[inline(never)]
fn circuit(q: &mut [u32; 8]) {
    sbox_planes(q);
}

/// Substitutes every byte of `words` (`N ≤ 4` little-endian words, lane
/// `8w + j` = byte `j` of word `w`) through `post ∘ S_aes ∘ pre`, where
/// `post` is applied to the raw AES S-box output (it absorbs the AES output
/// affine when the target S-box is built on the plain field inverse).
#[inline(always)]
pub(crate) fn sbox_custom<const N: usize>(
    words: &mut [u64; N],
    pre: &PlaneAffine,
    post: &PlaneAffine,
) {
    const { assert!(N >= 1 && N <= 4) };
    let mut q = to_planes(words);
    apply_planes(&mut q, pre);
    circuit(&mut q);
    apply_planes(&mut q, post);
    from_planes(&q, words);
}

/// Recovers `(pre, post)` for a reference S-box table given its `pre` map as
/// a function: `post = S ∘ pre⁻¹ ∘ S_aes⁻¹`, checked to be affine and to
/// reproduce the table. The cipher modules' tests use this to confirm their
/// hard-coded constants.
#[cfg(test)]
pub(crate) fn derive(sbox: &[u8; 256], pre: impl Fn(u8) -> u8) -> (Affine, Affine) {
    use super::aes::gf::{inv_sub_byte, sub_byte};
    fn to_affine(f: impl Fn(u8) -> u8) -> Affine {
        let c = f(0);
        let cols: [u8; 8] = core::array::from_fn(|j| f(1 << j) ^ c);
        let mut rows = [0u8; 8];
        for (j, col) in cols.iter().enumerate() {
            for (i, row) in rows.iter_mut().enumerate() {
                *row |= ((col >> i) & 1) << j;
            }
        }
        let a = Affine { rows, c };
        for x in 0..=255u8 {
            assert_eq!(a.apply(x), f(x), "map is not affine at {x:#04x}");
        }
        a
    }
    let mut pre_inv = [0u8; 256];
    let mut seen = [false; 256];
    for x in 0..=255u8 {
        let y = pre(x);
        assert!(!seen[y as usize], "pre is not a bijection");
        seen[y as usize] = true;
        pre_inv[y as usize] = x;
    }
    let pre_a = to_affine(&pre);
    let post_a = to_affine(|y| sbox[pre_inv[inv_sub_byte(y) as usize] as usize]);
    for x in 0..=255u8 {
        assert_eq!(post_a.apply(sub_byte(pre_a.apply(x))), sbox[x as usize]);
    }
    (pre_a, post_a)
}

/// The field isomorphism `GF(2⁸)/poly → GF(2⁸)/0x11b` that maps `x` to
/// `β^x` for the smallest root `β` of `poly` in the AES field, as a linear
/// map (`x = ⨁ xᵢ·αⁱ ↦ ⨁ xᵢ·βⁱ`).
#[cfg(test)]
pub(crate) fn field_iso(poly: u16) -> Affine {
    use super::aes::gf::gf_mul;
    let pow = |b: u8, e: u32| (0..e).fold(1u8, |acc, _| gf_mul(acc, b));
    for beta in 2..=255u8 {
        let mut acc = 0u8;
        for i in 0..9 {
            if (poly >> i) & 1 == 1 {
                acc ^= pow(beta, i);
            }
        }
        if acc == 0 {
            let cols: [u8; 8] = core::array::from_fn(|i| pow(beta, i as u32));
            let mut rows = [0u8; 8];
            for (j, col) in cols.iter().enumerate() {
                for (i, row) in rows.iter_mut().enumerate() {
                    *row |= ((col >> i) & 1) << j;
                }
            }
            return Affine { rows, c: 0 };
        }
    }
    panic!("no root of {poly:#x} in the AES field");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::aes::gf::{inv_sub_byte, sub_byte};

    /// Identity maps give the AES S-box in every lane, for every width.
    #[test]
    fn identity_maps_give_aes_sbox() {
        const ID: PlaneAffine = PlaneAffine::uniform(Affine::IDENTITY);
        for base in 0..8u8 {
            let mut w = [0u64; 4];
            for (k, word) in w.iter_mut().enumerate() {
                *word = u64::from_le_bytes(core::array::from_fn(|j| {
                    base.wrapping_mul(32).wrapping_add((8 * k + j) as u8)
                }));
            }
            let orig = w;
            sbox_custom(&mut w, &ID, &ID);
            for (word, o) in w.iter().zip(orig.iter()) {
                for (y, x) in word.to_le_bytes().iter().zip(o.to_le_bytes()) {
                    assert_eq!(*y, sub_byte(x));
                }
            }
            let mut one = [orig[0]];
            sbox_custom(&mut one, &ID, &ID);
            assert_eq!(one[0], w[0]);
            let mut two = [orig[0], orig[1]];
            sbox_custom(&mut two, &ID, &ID);
            assert_eq!(two, [w[0], w[1]]);
        }
    }

    /// Per-lane maps: alternate the AES S-box and its inverse by lane parity.
    #[test]
    fn per_lane_maps() {
        let inv_affine = Affine {
            rows: [0xa4, 0x49, 0x92, 0x25, 0x4a, 0x94, 0x29, 0x52],
            c: 0x05,
        };
        let pattern: [u8; 32] = core::array::from_fn(|l| (l % 2) as u8);
        let pre = PlaneAffine::per_lane(&[Affine::IDENTITY, inv_affine], &pattern);
        let post = PlaneAffine::per_lane(&[Affine::IDENTITY, inv_affine], &pattern);
        let mut w: [u64; 4] = core::array::from_fn(|k| 0x0123_4567_89ab_cdef ^ (k as u64 * 0x1111));
        let orig = w;
        sbox_custom(&mut w, &pre, &post);
        for (word, o) in w.iter().zip(orig.iter()) {
            for (j, (y, x)) in word.to_le_bytes().iter().zip(o.to_le_bytes()).enumerate() {
                let want = if j % 2 == 0 {
                    sub_byte(x)
                } else {
                    inv_sub_byte(x)
                };
                assert_eq!(*y, want);
            }
        }
    }

    /// `derive` on the AES S-box and its inverse gives the identity and the
    /// inverse-affine pair, and `field_iso` for the AES polynomial itself is
    /// the identity.
    #[test]
    fn derive_known_cases() {
        let mut aes = [0u8; 256];
        let mut inv = [0u8; 256];
        for x in 0..=255u8 {
            aes[x as usize] = sub_byte(x);
            inv[x as usize] = inv_sub_byte(x);
        }
        assert_eq!(derive(&aes, |x| x), (Affine::IDENTITY, Affine::IDENTITY));
        let a_inv = Affine {
            rows: [0xa4, 0x49, 0x92, 0x25, 0x4a, 0x94, 0x29, 0x52],
            c: 0x05,
        };
        assert_eq!(derive(&inv, |x| a_inv.apply(x)), (a_inv, a_inv));
        assert_eq!(field_iso(0x11b), Affine::IDENTITY);
    }
}
