//! The Ascon-`p`[rnd] permutation over a 320-bit state (NIST SP 800-232 §3).
//!
//! The state is five 64-bit words `S0..S4`, each holding a little-endian view
//! of eight state bytes (SP 800-232 §A.1: byte sequences load into words with
//! `u64::from_le_bytes` and no reversal on little-endian machines). The round
//! function is the composition `p = pL ∘ pS ∘ pC` of the constant-addition,
//! substitution, and linear-diffusion layers (§3.2–§3.4).
//!
//! The S-box here is the bit-sliced Boolean form of SP 800-232 Eq. (7); it was
//! cross-checked against the Table 6 lookup and against the precomputed
//! Ascon-Hash256 initialization state (Table 12) in the unit tests.

/// Round constants `const0 … const15` (SP 800-232 Table 5). Round `i` of an
/// `rnd`-round permutation uses `const[16 - rnd + i]`, added to `S2`.
const ROUND_CONSTANTS: [u64; 16] = [
    0x0000_0000_0000_003c,
    0x0000_0000_0000_002d,
    0x0000_0000_0000_001e,
    0x0000_0000_0000_000f,
    0x0000_0000_0000_00f0,
    0x0000_0000_0000_00e1,
    0x0000_0000_0000_00d2,
    0x0000_0000_0000_00c3,
    0x0000_0000_0000_00b4,
    0x0000_0000_0000_00a5,
    0x0000_0000_0000_0096,
    0x0000_0000_0000_0087,
    0x0000_0000_0000_0078,
    0x0000_0000_0000_0069,
    0x0000_0000_0000_005a,
    0x0000_0000_0000_004b,
];

/// The 320-bit Ascon state: five 64-bit words `S0..S4`.
///
/// Stored as integer words; conversion to and from byte sequences is
/// little-endian (SP 800-232 §A.1).
#[derive(Clone, Copy, Default)]
pub(super) struct State(pub(super) [u64; 5]);

impl State {
    /// Applies the 12-round permutation `Ascon-p[12]` (`pa`).
    #[inline]
    pub(super) fn permute12(&mut self) {
        self.permute(12);
    }

    /// Applies the 8-round permutation `Ascon-p[8]` (`pb`, used by AEAD data
    /// processing).
    #[inline]
    pub(super) fn permute8(&mut self) {
        self.permute(8);
    }

    /// Applies `Ascon-p[rnd]` for `1 <= rnd <= 16`.
    #[inline]
    fn permute(&mut self, rnd: usize) {
        let s = &mut self.0;
        for &c in &ROUND_CONSTANTS[16 - rnd..] {
            // pC: constant addition to S2.
            s[2] ^= c;

            // pS: the 5-bit S-box applied bitsliced across all 64 columns.
            // (SP 800-232 Eq. (7), Boolean form.)
            s[0] ^= s[4];
            s[4] ^= s[3];
            s[2] ^= s[1];
            let t0 = s[0] ^ (!s[1] & s[2]);
            let t1 = s[1] ^ (!s[2] & s[3]);
            let t2 = s[2] ^ (!s[3] & s[4]);
            let t3 = s[3] ^ (!s[4] & s[0]);
            let t4 = s[4] ^ (!s[0] & s[1]);
            s[0] = t0;
            s[1] = t1;
            s[2] = t2;
            s[3] = t3;
            s[4] = t4;
            s[1] ^= s[0];
            s[0] ^= s[4];
            s[3] ^= s[2];
            s[2] = !s[2];

            // pL: per-lane linear diffusion Σi (SP 800-232 Eq. (8)–(12)).
            s[0] ^= s[0].rotate_right(19) ^ s[0].rotate_right(28);
            s[1] ^= s[1].rotate_right(61) ^ s[1].rotate_right(39);
            s[2] ^= s[2].rotate_right(1) ^ s[2].rotate_right(6);
            s[3] ^= s[3].rotate_right(10) ^ s[3].rotate_right(17);
            s[4] ^= s[4].rotate_right(7) ^ s[4].rotate_right(41);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Table 6 S-box, used to cross-check the bitsliced Boolean form.
    const SBOX: [u8; 32] = [
        0x04, 0x0b, 0x1f, 0x14, 0x1a, 0x15, 0x09, 0x02, 0x1b, 0x05, 0x08, 0x12, 0x1d, 0x03, 0x06,
        0x1c, 0x1e, 0x13, 0x07, 0x0e, 0x00, 0x0d, 0x11, 0x18, 0x10, 0x0c, 0x01, 0x19, 0x16, 0x0a,
        0x0f, 0x17,
    ];

    /// One bitsliced S-box layer (extracted from `permute`) applied to a state.
    fn sbox_layer(s: &mut [u64; 5]) {
        s[0] ^= s[4];
        s[4] ^= s[3];
        s[2] ^= s[1];
        let t0 = s[0] ^ (!s[1] & s[2]);
        let t1 = s[1] ^ (!s[2] & s[3]);
        let t2 = s[2] ^ (!s[3] & s[4]);
        let t3 = s[3] ^ (!s[4] & s[0]);
        let t4 = s[4] ^ (!s[0] & s[1]);
        s[0] = t0;
        s[1] = t1;
        s[2] = t2;
        s[3] = t3;
        s[4] = t4;
        s[1] ^= s[0];
        s[0] ^= s[4];
        s[3] ^= s[2];
        s[2] = !s[2];
    }

    // The bitsliced S-box must agree with the SP 800-232 Table 6 lookup on
    // every 5-bit column input.
    #[test]
    fn sbox_matches_lookup_table() {
        for x in 0u8..32 {
            // SBOX takes the tuple (x0,x1,x2,x3,x4) = (s0,s1,s2,s3,s4) placed in
            // column 0 (bit j=0, the LSB of each word). SP 800-232 Table 6
            // notes that index `x=1` denotes the tuple (0,0,0,0,1) — i.e. the
            // hex index's most significant bit is x0 and its LSB is x4.
            let mut s = [0u64; 5];
            for (i, word) in s.iter_mut().enumerate() {
                *word = u64::from((x >> (4 - i)) & 1);
            }
            sbox_layer(&mut s);
            let mut y = 0u8;
            for (i, &word) in s.iter().enumerate() {
                y |= ((word & 1) as u8) << (4 - i);
            }
            assert_eq!(y, SBOX[x as usize], "S-box mismatch at input {x:#x}");
        }
    }

    // SP 800-232 §A.3 / Table 12: the Ascon-Hash256 initialization state is the
    // precomputed `p12(IV ‖ 0^256)` for `IV = 0x0000080100cc0002`. This is the
    // load-bearing end-to-end check of `pC`, `pS`, and `pL` together.
    #[test]
    fn hash256_precomputed_init_matches_spec() {
        let mut s = State([0x0000_0801_00cc_0002, 0, 0, 0, 0]);
        s.permute12();
        assert_eq!(
            s.0,
            [
                0x9b1e_5494_e934_d681,
                0x4bc3_a01e_3337_51d2,
                0xae65_396c_6b34_b81a,
                0x3c7f_d4a4_d56a_4db3,
                0x1a5c_4649_06c5_976d,
            ]
        );
    }

    // SP 800-232 Table 12: Ascon-XOF128 precomputed init (`IV = ...cc0003`).
    #[test]
    fn xof128_precomputed_init_matches_spec() {
        let mut s = State([0x0000_0800_00cc_0003, 0, 0, 0, 0]);
        s.permute12();
        assert_eq!(s.0[0], 0xda82_ce76_8d94_47eb);
    }

    // SP 800-232 Table 12: Ascon-CXOF128 precomputed init (`IV = ...cc0004`).
    #[test]
    fn cxof128_precomputed_init_matches_spec() {
        let mut s = State([0x0000_0800_00cc_0004, 0, 0, 0, 0]);
        s.permute12();
        assert_eq!(s.0[0], 0x6755_27c2_a0e8_de03);
    }
}
