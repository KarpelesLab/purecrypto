//! SHA-384, SHA-512, SHA-512/224 and SHA-512/256 (FIPS 180-4), built on a
//! shared 64-bit SHA-2 core.

use super::Digest;

/// SHA-512 initial hash value.
const H512: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// SHA-384 initial hash value.
const H384: [u64; 8] = [
    0xcbbb_9d5d_c105_9ed8,
    0x629a_292a_367c_d507,
    0x9159_015a_3070_dd17,
    0x152f_ecd8_f70e_5939,
    0x6733_2667_ffc0_0b31,
    0x8eb4_4a87_6858_1511,
    0xdb0c_2e0d_64f9_8fa7,
    0x47b5_481d_befa_4fa4,
];

/// SHA-512/224 initial hash value.
const H512_224: [u64; 8] = [
    0x8c3d_37c8_1954_4da2,
    0x73e1_9966_89dc_d4d6,
    0x1dfa_b7ae_32ff_9c82,
    0x679d_d514_582f_9fcf,
    0x0f6d_2b69_7bd4_4da8,
    0x77e3_6f73_04c4_8942,
    0x3f9d_85a8_6a1d_36c8,
    0x1112_e6ad_91d6_92a1,
];

/// SHA-512/256 initial hash value.
const H512_256: [u64; 8] = [
    0x2231_2194_fc2b_f72c,
    0x9f55_5fa3_c84c_64c2,
    0x2393_b86b_6f53_b151,
    0x9638_7719_5940_eabd,
    0x9628_3ee2_a88e_ffe3,
    0xbe5e_1e25_5386_3992,
    0x2b01_99fc_2c85_b8aa,
    0x0eb7_2ddc_81c5_2ca2,
];

/// SHA-512 round constants (first 64 bits of the fractional parts of the cube
/// roots of the first 80 primes).
pub(crate) const K512: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

/// Streaming state shared by all SHA-512 variants (they differ only in IV and
/// output truncation).
#[derive(Clone)]
struct State512 {
    h: [u64; 8],
    /// Partial input not yet compressed (`block_len` valid bytes).
    block: [u8; 128],
    block_len: usize,
    /// Total message length in bytes (a 128-bit counter).
    msg_len: u128,
}

impl State512 {
    #[inline]
    fn new(iv: [u64; 8]) -> Self {
        State512 {
            h: iv,
            block: [0u8; 128],
            block_len: 0,
            msg_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.msg_len = self.msg_len.wrapping_add(data.len() as u128);

        if self.block_len > 0 {
            let take = (128 - self.block_len).min(data.len());
            self.block[self.block_len..self.block_len + take].copy_from_slice(&data[..take]);
            self.block_len += take;
            data = &data[take..];
            if self.block_len == 128 {
                compress512(&mut self.h, &self.block);
                self.block_len = 0;
            }
        }

        while data.len() >= 128 {
            let block: &[u8; 128] = data[..128].try_into().unwrap();
            compress512(&mut self.h, block);
            data = &data[128..];
        }

        if !data.is_empty() {
            self.block[..data.len()].copy_from_slice(data);
            self.block_len = data.len();
        }
    }

    /// Best-effort wipe of the state words and partial block.
    fn zeroize(&mut self) {
        super::zeroize::zero_words(&mut self.h);
        super::zeroize::zero_bytes(&mut self.block);
        self.block_len = 0;
        self.msg_len = 0;
    }

    /// Applies SHA-2 padding and returns the final state words.
    fn finalize(mut self) -> [u64; 8] {
        // 128-bit big-endian bit length occupies the last 16 bytes.
        let bit_len = self.msg_len.wrapping_mul(8);

        let mut i = self.block_len;
        self.block[i] = 0x80;
        i += 1;

        if i > 112 {
            while i < 128 {
                self.block[i] = 0;
                i += 1;
            }
            compress512(&mut self.h, &self.block);
            i = 0;
        }
        while i < 112 {
            self.block[i] = 0;
            i += 1;
        }
        self.block[112..128].copy_from_slice(&bit_len.to_be_bytes());
        compress512(&mut self.h, &self.block);

        self.h
    }
}

/// `u64` right-rotation as an explicit shift-or rather than
/// [`u64::rotate_right`]. In debug builds `rotate_right` lowers to a real
/// (non-inlined) `core::intrinsics::rotate_right` call; the shift-or inlines,
/// and release codegen is identical. (See the SHA-256 `rotr` for the profile.)
// Intentionally NOT `x.rotate_right(n)` — see the SHA-256 `rotr`.
#[inline(always)]
#[allow(clippy::manual_rotate)]
const fn rotr(x: u64, n: u32) -> u64 {
    (x >> n) | (x << (64 - n))
}

/// SHA-512 compression function: folds a 128-byte block into the state.
///
/// Dispatches to the aarch64 `sha512` hardware extension when available, else
/// the portable software path. Both produce identical state and are
/// constant-time. (x86 has no broadly-available SHA-512 instruction.)
#[inline]
fn compress512(h: &mut [u64; 8], block: &[u8; 128]) {
    #[cfg(all(feature = "std", target_arch = "aarch64"))]
    if super::sha_hw::sha512_supported() {
        super::sha_hw::compress512(h, block);
        return;
    }
    compress512_soft(h, block);
}

/// Portable software SHA-512 compression (the constant-time fallback).
#[inline]
fn compress512_soft(h: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for (word, chunk) in w.iter_mut().zip(block.chunks_exact(8)) {
        *word = u64::from_be_bytes(chunk.try_into().unwrap());
    }
    for i in 16..80 {
        let s0 = rotr(w[i - 15], 1) ^ rotr(w[i - 15], 8) ^ (w[i - 15] >> 7);
        let s1 = rotr(w[i - 2], 19) ^ rotr(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;

    for i in 0..80 {
        let s1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K512[i])
            .wrapping_add(w[i]);
        let s0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);

        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    h[0] = h[0].wrapping_add(a);
    h[1] = h[1].wrapping_add(b);
    h[2] = h[2].wrapping_add(c);
    h[3] = h[3].wrapping_add(d);
    h[4] = h[4].wrapping_add(e);
    h[5] = h[5].wrapping_add(f);
    h[6] = h[6].wrapping_add(g);
    h[7] = h[7].wrapping_add(hh);
}

/// Serializes the leftmost `N` bytes of the state words (big-endian),
/// including a partial trailing word when `N` is not a multiple of 8 (needed
/// for SHA-512/224).
#[inline]
fn truncate_words<const N: usize>(h: &[u64; 8]) -> [u8; N] {
    let mut out = [0u8; N];
    let full = N / 8;
    for i in 0..full {
        out[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_be_bytes());
    }
    let rem = N % 8;
    if rem > 0 {
        let be = h[full].to_be_bytes();
        out[full * 8..full * 8 + rem].copy_from_slice(&be[..rem]);
    }
    out
}

/// Generates a SHA-512-variant type with the given IV and output length.
macro_rules! sha512_variant {
    ($(#[$meta:meta])* $name:ident, $iv:expr, $out:literal, $fn_name:ident, $fn_doc:literal) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            state: State512,
        }

        impl Digest for $name {
            type Output = [u8; $out];
            type Block = [u8; 128];
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = 128;

            #[inline]
            fn new() -> Self {
                $name {
                    state: State512::new($iv),
                }
            }

            #[inline]
            fn zeroed_block() -> [u8; 128] {
                [0u8; 128]
            }

            #[inline]
            fn zeroed_output() -> [u8; $out] {
                [0u8; $out]
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.state.update(data);
            }

            #[inline]
            fn finalize(self) -> [u8; $out] {
                truncate_words(&self.state.finalize())
            }

            #[inline]
            fn zeroize(&mut self) {
                self.state.zeroize();
            }
        }

        #[doc = $fn_doc]
        #[inline]
        pub fn $fn_name(data: &[u8]) -> [u8; $out] {
            $name::digest(data)
        }
    };
}

sha512_variant!(
    /// The SHA-512 hash function.
    Sha512, H512, 64, sha512, "Computes the SHA-512 digest of `data`."
);
sha512_variant!(
    /// The SHA-384 hash function (SHA-512 with a different IV, truncated to 384 bits).
    Sha384, H384, 48, sha384, "Computes the SHA-384 digest of `data`."
);
sha512_variant!(
    /// The SHA-512/256 hash function.
    Sha512_256, H512_256, 32, sha512_256, "Computes the SHA-512/256 digest of `data`."
);
sha512_variant!(
    /// The SHA-512/224 hash function.
    Sha512_224, H512_224, 28, sha512_224, "Computes the SHA-512/224 digest of `data`."
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// The aarch64 `sha512` hardware compression must equal the software path
    /// for every block. Runs only where the extension exists.
    #[cfg(all(feature = "std", target_arch = "aarch64"))]
    #[test]
    fn sha512_hardware_matches_software() {
        if !super::super::sha_hw::sha512_supported() {
            return;
        }
        let mut s = 0x0123_4567_89ab_cdefu64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        for _ in 0..1000 {
            let mut hw = H512;
            for (j, v) in hw.iter_mut().enumerate() {
                if j % 2 == 0 {
                    *v = next();
                }
            }
            let sw = hw;
            let mut block = [0u8; 128];
            for b in block.iter_mut() {
                *b = (next() >> 24) as u8;
            }
            let mut a = sw;
            let mut b = hw;
            compress512_soft(&mut a, &block);
            super::super::sha_hw::compress512(&mut b, &block);
            assert_eq!(a, b, "sha512 HW/soft mismatch");
        }
        // Dispatched digest must equal a pure-software digest of the same data.
        let data: alloc::vec::Vec<u8> = (0..900u32).map(|i| (i * 5) as u8).collect();
        assert_eq!(sha512(&data).to_vec(), software_sha512(&data));
    }

    /// Pure-software SHA-512 digest (bypasses the HW dispatch) for the test.
    #[cfg(all(feature = "std", target_arch = "aarch64"))]
    fn software_sha512(data: &[u8]) -> alloc::vec::Vec<u8> {
        let mut h = H512;
        let mut buf = data.to_vec();
        let bitlen = (buf.len() as u128) * 8;
        buf.push(0x80);
        while buf.len() % 128 != 112 {
            buf.push(0);
        }
        buf.extend_from_slice(&bitlen.to_be_bytes());
        for chunk in buf.chunks_exact(128) {
            compress512_soft(&mut h, chunk.try_into().unwrap());
        }
        let mut out = alloc::vec::Vec::new();
        for w in h {
            out.extend_from_slice(&w.to_be_bytes());
        }
        out
    }

    #[test]
    fn sha512_vectors() {
        assert_eq!(
            sha512(b""),
            from_hex::<64>(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
                 47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
            )
        );
        assert_eq!(
            sha512(b"abc"),
            from_hex::<64>(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
                 2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
    }

    #[test]
    fn sha512_one_million_a() {
        let mut h = Sha512::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            h.finalize(),
            from_hex::<64>(
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
                 de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
            )
        );
    }

    #[test]
    fn sha384_vectors() {
        assert_eq!(
            sha384(b""),
            from_hex::<48>(
                "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da\
                 274edebfe76f65fbd51ad2f14898b95b"
            )
        );
        assert_eq!(
            sha384(b"abc"),
            from_hex::<48>(
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
                 8086072ba1e7cc2358baeca134c825a7"
            )
        );
    }

    #[test]
    fn sha512_256_vectors() {
        assert_eq!(
            sha512_256(b""),
            from_hex::<32>("c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a")
        );
        assert_eq!(
            sha512_256(b"abc"),
            from_hex::<32>("53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23")
        );
    }

    #[test]
    fn sha512_224_vectors() {
        assert_eq!(
            sha512_224(b""),
            from_hex::<28>("6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4")
        );
        assert_eq!(
            sha512_224(b"abc"),
            from_hex::<28>("4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa")
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        // ~1.5 blocks, exercising the 112-byte length-field boundary handling.
        let big = [0xa5u8; 250];
        let oneshot = sha512(&big);
        let mut h = Sha512::new();
        h.update(&big[..1]);
        h.update(&big[1..111]);
        h.update(&big[111..200]);
        h.update(&big[200..]);
        assert_eq!(h.finalize(), oneshot);
    }
}
