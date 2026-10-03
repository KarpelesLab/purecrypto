//! AES (FIPS-197) block cipher, constant-time.
//!
//! Supports 128-, 192- and 256-bit keys. The state is held as 16 bytes in
//! column-major order (`state[4*col + row]`), matching FIPS-197. All
//! transforms are branchless and table-free, so encryption time does not
//! depend on key or data values.

pub(crate) mod gf;

#[cfg(all(feature = "std", target_arch = "aarch64"))]
mod aes_arm;
#[cfg(all(feature = "std", target_arch = "x86_64"))]
mod aesni;

use super::BlockCipher;
use gf::sub_words;

/// Which implementation a keyed AES instance dispatches to. Chosen once at
/// construction from a cached runtime CPU-feature probe; the software path is
/// the table-free constant-time fallback used everywhere a hardware AES
/// extension is absent (including all `no_std` builds).
#[derive(Clone, Copy)]
enum AesBackend {
    Software,
    #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
    Hardware,
}

/// Probes for a hardware AES extension. Both detection macros cache their
/// result internally, so this is cheap to call per `Aes*::new()`.
#[inline]
fn detect_backend() -> AesBackend {
    // The constant-time harness can force the portable path (the constant
    // `false` outside the hidden `__ct-check` feature).
    if crate::ct::force_portable() {
        return AesBackend::Software;
    }
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("aes") {
            return AesBackend::Hardware;
        }
    }
    #[cfg(all(feature = "std", target_arch = "aarch64"))]
    {
        if std::arch::is_aarch64_feature_detected!("aes") {
            return AesBackend::Hardware;
        }
    }
    AesBackend::Software
}

// The four dispatch helpers route a keyed operation to the active backend. The
// `Hardware` arms are reached only after `detect_backend` confirmed the
// extension, satisfying the `#[target_feature]` safety contract.
#[inline]
#[allow(unsafe_code)]
fn dispatch_encrypt_block(backend: AesBackend, rk: &[u8], nr: usize, block: &mut [u8; 16]) {
    match backend {
        AesBackend::Software => encrypt(rk, nr, block),
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        AesBackend::Hardware => unsafe { aesni::encrypt_block(rk, nr, block) },
        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        AesBackend::Hardware => unsafe { aes_arm::encrypt_block(rk, nr, block) },
    }
}

#[inline]
#[allow(unsafe_code)]
fn dispatch_decrypt_block(backend: AesBackend, rk: &[u8], nr: usize, block: &mut [u8; 16]) {
    match backend {
        AesBackend::Software => decrypt(rk, nr, block),
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        AesBackend::Hardware => unsafe { aesni::decrypt_block(rk, nr, block) },
        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        AesBackend::Hardware => unsafe { aes_arm::decrypt_block(rk, nr, block) },
    }
}

#[inline]
#[allow(unsafe_code)]
fn dispatch_encrypt_blocks(backend: AesBackend, rk: &[u8], nr: usize, blocks: &mut [u8]) {
    match backend {
        AesBackend::Software => crypt_blocks_soft::<false>(rk, nr, blocks),
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        AesBackend::Hardware => unsafe { aesni::encrypt_blocks(rk, nr, blocks) },
        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        AesBackend::Hardware => unsafe { aes_arm::encrypt_blocks(rk, nr, blocks) },
    }
}

#[inline]
#[allow(unsafe_code)]
fn dispatch_decrypt_blocks(backend: AesBackend, rk: &[u8], nr: usize, blocks: &mut [u8]) {
    match backend {
        AesBackend::Software => crypt_blocks_soft::<true>(rk, nr, blocks),
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        AesBackend::Hardware => unsafe { aesni::decrypt_blocks(rk, nr, blocks) },
        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        AesBackend::Hardware => unsafe { aes_arm::decrypt_blocks(rk, nr, blocks) },
    }
}

// --- Software backend --------------------------------------------------------
//
// The state is one little-endian `u128` per block (byte `4·col + row` at bits
// `8·(4·col + row)`), so ShiftRows, MixColumns and AddRoundKey are a handful of
// whole-state shifts, masks and XORs. SubBytes goes through the bitsliced
// S-box in [`gf`], two blocks per evaluation when a batch allows it.

/// Bytes of row 0 (state bytes 0, 4, 8, 12); row `r` is this shifted by `8r`.
const ROW0: u128 = 0x0000_00ff_0000_00ff_0000_00ff_0000_00ff;
/// The low bit of every byte lane.
const LSB: u128 = 0x0101_0101_0101_0101_0101_0101_0101_0101;
/// The low bit of every 32-bit column.
const EVERY_COLUMN: u128 = 0x0000_0001_0000_0001_0000_0001_0000_0001;

/// Loads round key `i` as a state word.
#[inline(always)]
fn round_key(rk: &[u8], i: usize) -> u128 {
    u128::from_le_bytes(
        rk[16 * i..16 * i + 16]
            .try_into()
            .expect("16-byte round key"),
    )
}

/// SubBytes (`inv == false`) or InvSubBytes on one or two states.
#[inline(always)]
fn sub_layer(s: &mut [u128], inv: bool) {
    debug_assert!(s.len() <= 2);
    let mut w = [0u64; 4];
    for (pair, &x) in w.chunks_exact_mut(2).zip(s.iter()) {
        pair[0] = x as u64;
        pair[1] = (x >> 64) as u64;
    }
    sub_words(&mut w, inv);
    for (pair, x) in w.chunks_exact(2).zip(s.iter_mut()) {
        *x = pair[0] as u128 | (pair[1] as u128) << 64;
    }
}

/// ShiftRows: row `r` moves left by `r` columns, i.e. byte `4c + r` takes
/// byte `4(c + r) + r`, which is a rotation of the whole state by `32r` bits.
#[inline(always)]
fn shift_rows(s: u128) -> u128 {
    (s & ROW0)
        | (s.rotate_right(32) & ROW0 << 8)
        | (s.rotate_right(64) & ROW0 << 16)
        | (s.rotate_right(96) & ROW0 << 24)
}

/// Inverse of [`shift_rows`].
#[inline(always)]
fn inv_shift_rows(s: u128) -> u128 {
    (s & ROW0)
        | (s.rotate_left(32) & ROW0 << 8)
        | (s.rotate_left(64) & ROW0 << 16)
        | (s.rotate_left(96) & ROW0 << 24)
}

/// `xtime` (multiplication by `x` mod `0x11b`) on every byte lane. The
/// reduction is a shift-XOR of each lane's carried-out top bit: branch-free
/// and multiplier-free.
#[inline(always)]
fn xtime(x: u128) -> u128 {
    let hi = (x >> 7) & LSB;
    ((x & (LSB * 0x7f)) << 1) ^ hi ^ (hi << 1) ^ (hi << 3) ^ (hi << 4)
}

/// Rotates every column by `k` bytes: byte `r` of each column takes byte
/// `r + k` of the same column.
#[inline(always)]
fn rot_columns<const K: u32>(s: u128) -> u128 {
    // The low `32 - 8k` bits of every column: the right shift fills them from
    // the same column, the left shift fills the rest.
    let low = ((u32::MAX >> (8 * K)) as u128) * EVERY_COLUMN;
    ((s >> (8 * K)) & low) | ((s << (32 - 8 * K)) & !low)
}

/// MixColumns: `out_r = 2·a_r ⊕ 3·a_{r+1} ⊕ a_{r+2} ⊕ a_{r+3}`
/// `= 2·(a_r ⊕ a_{r+1}) ⊕ a_{r+1} ⊕ (a_{r+2} ⊕ a_{r+3})` in every column.
#[inline(always)]
fn mix_columns(s: u128) -> u128 {
    let r1 = rot_columns::<1>(s);
    let t = s ^ r1;
    xtime(t) ^ r1 ^ rot_columns::<2>(t)
}

/// InvMixColumns = MixColumns ∘ (`a_r ⊕= 4·(a_r ⊕ a_{r+2})`), the
/// factorisation of the inverse matrix from *The Design of Rijndael*.
#[inline(always)]
fn inv_mix_columns(s: u128) -> u128 {
    mix_columns(s ^ xtime(xtime(s ^ rot_columns::<2>(s))))
}

/// SubWord: the S-box on the four bytes of a key-schedule word, on the
/// backend's S-box (the AES instruction when present, else the bitsliced
/// circuit with the spare lanes zero).
#[inline]
#[allow(unsafe_code)]
fn sub_word(backend: AesBackend, w: [u8; 4]) -> [u8; 4] {
    match backend {
        AesBackend::Software => {}
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        AesBackend::Hardware => return unsafe { aesni::sub_word(w) },
        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        AesBackend::Hardware => return unsafe { aes_arm::sub_word(w) },
    }
    let mut s = [u32::from_le_bytes(w) as u128];
    sub_layer(&mut s, false);
    let out = (s[0] as u32).to_le_bytes();
    crate::zeroize::Zeroize::zeroize(&mut s);
    out
}

/// Expands `key` (`nk` 32-bit words) into `out`, the round-key bytes for `nr`
/// rounds (`16 * (nr + 1)` bytes). The control flow depends only on the public
/// key length, not on key contents.
fn key_expansion(backend: AesBackend, key: &[u8], nk: usize, nr: usize, out: &mut [u8]) {
    let total_words = 4 * (nr + 1);
    out[..key.len()].copy_from_slice(key);

    let mut rcon = 1u8;
    // The temporary word is (a transform of) the previous round-key word;
    // hoisted so one wipe after the loop covers it.
    let mut t = [0u8; 4];
    for i in nk..total_words {
        let prev = i - 1;
        t = [
            out[prev * 4],
            out[prev * 4 + 1],
            out[prev * 4 + 2],
            out[prev * 4 + 3],
        ];

        if i % nk == 0 {
            // RotWord, then SubWord, then XOR the round constant.
            t = sub_word(backend, [t[1], t[2], t[3], t[0]]);
            t[0] ^= rcon;
            // rcon = xtime(rcon); public, so the branch is fine.
            rcon = (rcon << 1) ^ if rcon & 0x80 != 0 { 0x1b } else { 0 };
        } else if nk > 6 && i % nk == 4 {
            // AES-256 applies an extra SubWord a quarter of the way in.
            t = sub_word(backend, t);
        }

        let base = i * 4;
        let src = (i - nk) * 4;
        for j in 0..4 {
            out[base + j] = out[src + j] ^ t[j];
        }
    }
    crate::zeroize::Zeroize::zeroize(&mut t);
}

/// Encrypts one or two states with the expanded round keys. SubBytes is
/// a byte-wise map and ShiftRows a byte permutation, so they commute; the
/// S-box layer runs first so both states share one bitsliced evaluation.
fn encrypt_n(rk: &[u8], nr: usize, s: &mut [u128]) {
    let k = round_key(rk, 0);
    s.iter_mut().for_each(|x| *x ^= k);
    for round in 1..nr {
        sub_layer(s, false);
        let k = round_key(rk, round);
        s.iter_mut()
            .for_each(|x| *x = mix_columns(shift_rows(*x)) ^ k);
    }
    sub_layer(s, false);
    let k = round_key(rk, nr);
    s.iter_mut().for_each(|x| *x = shift_rows(*x) ^ k);
}

/// Decrypts one or two states (FIPS-197 inverse cipher).
fn decrypt_n(rk: &[u8], nr: usize, s: &mut [u128]) {
    let k = round_key(rk, nr);
    s.iter_mut().for_each(|x| *x ^= k);
    for round in (1..nr).rev() {
        sub_layer(s, true);
        let k = round_key(rk, round);
        s.iter_mut()
            .for_each(|x| *x = inv_mix_columns(inv_shift_rows(*x) ^ k));
    }
    sub_layer(s, true);
    let k = round_key(rk, 0);
    s.iter_mut().for_each(|x| *x = inv_shift_rows(*x) ^ k);
}

/// Encrypts one block using the expanded round keys.
fn encrypt(rk: &[u8], nr: usize, block: &mut [u8; 16]) {
    let mut s = [u128::from_le_bytes(*block)];
    encrypt_n(rk, nr, &mut s);
    *block = s[0].to_le_bytes();
}

/// Decrypts one block using the expanded round keys.
fn decrypt(rk: &[u8], nr: usize, block: &mut [u8; 16]) {
    let mut s = [u128::from_le_bytes(*block)];
    decrypt_n(rk, nr, &mut s);
    *block = s[0].to_le_bytes();
}

/// Applies the software cipher to every 16-byte block of `blocks`, two at a
/// time (one bitsliced S-box evaluation covers both), then the odd one.
fn crypt_blocks_soft<const INV: bool>(rk: &[u8], nr: usize, blocks: &mut [u8]) {
    let mut pairs = blocks.chunks_exact_mut(32);
    for pair in &mut pairs {
        let (a, b) = pair.split_at_mut(16);
        let mut s = [
            u128::from_le_bytes((&*a).try_into().expect("16-byte block")),
            u128::from_le_bytes((&*b).try_into().expect("16-byte block")),
        ];
        if INV {
            decrypt_n(rk, nr, &mut s);
        } else {
            encrypt_n(rk, nr, &mut s);
        }
        a.copy_from_slice(&s[0].to_le_bytes());
        b.copy_from_slice(&s[1].to_le_bytes());
    }
    for block in pairs.into_remainder().chunks_exact_mut(16) {
        let b: &mut [u8; 16] = block.try_into().expect("16-byte chunk");
        if INV {
            decrypt(rk, nr, b);
        } else {
            encrypt(rk, nr, b);
        }
    }
}

/// Applies one full AES round to `state`: `MixColumns(ShiftRows(SubBytes(state)))`
/// XOR'd with `round_key`. This is the AESENC primitive (the per-round transform
/// of the FIPS-197 cipher, sans the key schedule), exposed for constructions —
/// such as AEGIS and AEZ — that build on the bare round function rather than on a
/// keyed AES instance.
///
/// Dispatches to the hardware AES round (AES-NI `aesenc` / ARMv8 `aese`+`aesmc`)
/// when available, else the table-free software round. Both are constant-time and
/// return identical results.
#[inline]
#[allow(unsafe_code)]
pub(crate) fn aes_round(state: [u8; 16], round_key: [u8; 16]) -> [u8; 16] {
    match detect_backend() {
        AesBackend::Software => aes_round_soft(state, round_key),
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        AesBackend::Hardware => unsafe { aesni::aes_round(state, round_key) },
        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        AesBackend::Hardware => unsafe { aes_arm::aes_round(state, round_key) },
    }
}

/// Table-free constant-time AES round (the software fallback for [`aes_round`]).
fn aes_round_soft(state: [u8; 16], round_key: [u8; 16]) -> [u8; 16] {
    let mut s = [u128::from_le_bytes(state)];
    sub_layer(&mut s, false);
    (mix_columns(shift_rows(s[0])) ^ u128::from_le_bytes(round_key)).to_le_bytes()
}

/// Defines an AES variant with a given key size, key-word count, round count,
/// and round-key buffer length.
macro_rules! aes_variant {
    ($(#[$meta:meta])* $name:ident, $key_bytes:literal, $nk:literal, $nr:literal, $rk_len:literal) => {
        $(#[$meta])*
        #[derive(Clone)]
        pub struct $name {
            rk: [u8; $rk_len],
            backend: AesBackend,
        }

        impl $name {
            /// Creates a cipher instance from the given key, expanding the key
            /// schedule. The fastest available backend (hardware AES extension
            /// when present, otherwise the constant-time software path) is
            /// selected once here.
            pub fn new(key: &[u8; $key_bytes]) -> Self {
                let mut rk = [0u8; $rk_len];
                let backend = detect_backend();
                key_expansion(backend, key, $nk, $nr, &mut rk);
                $name { rk, backend }
            }

            /// Forces the constant-time software backend, regardless of CPU
            /// support. Test-only: used to differentially check a hardware
            /// backend against the reference software path.
            #[cfg(test)]
            pub(crate) fn new_software(key: &[u8; $key_bytes]) -> Self {
                let mut rk = [0u8; $rk_len];
                key_expansion(AesBackend::Software, key, $nk, $nr, &mut rk);
                $name { rk, backend: AesBackend::Software }
            }
        }

        impl BlockCipher for $name {
            const BLOCK_SIZE: usize = 16;
            const KEY_SIZE: usize = $key_bytes;

            #[inline]
            fn encrypt_block(&self, block: &mut [u8; 16]) {
                dispatch_encrypt_block(self.backend, &self.rk, $nr, block);
            }

            #[inline]
            fn decrypt_block(&self, block: &mut [u8; 16]) {
                dispatch_decrypt_block(self.backend, &self.rk, $nr, block);
            }

            #[inline]
            fn encrypt_blocks(&self, blocks: &mut [u8]) {
                debug_assert_eq!(blocks.len() % 16, 0, "encrypt_blocks needs whole blocks");
                dispatch_encrypt_blocks(self.backend, &self.rk, $nr, blocks);
            }

            #[inline]
            fn decrypt_blocks(&self, blocks: &mut [u8]) {
                debug_assert_eq!(blocks.len() % 16, 0, "decrypt_blocks needs whole blocks");
                dispatch_decrypt_blocks(self.backend, &self.rk, $nr, blocks);
            }

            // Exposes the round-key schedule to the GCM fused CTR+GHASH loop,
            // but only when the hardware AES backend is active (the fused loop
            // is built on the AES instruction-set extensions).
            #[doc(hidden)]
            fn hw_aes_schedule(&self) -> Option<(&[u8], usize)> {
                #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
                if matches!(self.backend, AesBackend::Hardware) {
                    return Some((&self.rk[..], $nr));
                }
                None
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // Best-effort wipe of the expanded key material, through
                // `Zeroize` (volatile stores plus a compiler fence).
                crate::zeroize::Zeroize::zeroize(&mut self.rk);
            }
        }

        impl crate::zeroize::ZeroizeOnDrop for $name {}
    };
}

aes_variant!(
    /// AES with a 128-bit key (10 rounds).
    Aes128, 16, 4, 10, 176
);
aes_variant!(
    /// AES with a 192-bit key (12 rounds).
    Aes192, 24, 6, 12, 208
);
aes_variant!(
    /// AES with a 256-bit key (14 rounds).
    Aes256, 32, 8, 14, 240
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    #[test]
    fn fips197_aes128() {
        let key = from_hex::<16>("000102030405060708090a0b0c0d0e0f");
        let cipher = Aes128::new(&key);
        let mut block = from_hex::<16>("00112233445566778899aabbccddeeff");
        cipher.encrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("69c4e0d86a7b0430d8cdb78070b4c55a"));
        cipher.decrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn fips197_aes192() {
        let key = from_hex::<24>("000102030405060708090a0b0c0d0e0f1011121314151617");
        let cipher = Aes192::new(&key);
        let mut block = from_hex::<16>("00112233445566778899aabbccddeeff");
        cipher.encrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("dda97ca4864cdfe06eaf70a0ec0d7191"));
        cipher.decrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn fips197_aes256() {
        let key =
            from_hex::<32>("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let cipher = Aes256::new(&key);
        let mut block = from_hex::<16>("00112233445566778899aabbccddeeff");
        cipher.encrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("8ea2b7ca516745bfeafc49904b496089"));
        cipher.decrypt_block(&mut block);
        assert_eq!(block, from_hex::<16>("00112233445566778899aabbccddeeff"));
    }

    /// Deterministic pseudo-random byte fill (xorshift64*) for differential
    /// tests — no RNG dependency, reproducible.
    fn fill(seed: u64, out: &mut [u8]) {
        let mut x = seed | 1;
        for b in out.iter_mut() {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            *b = (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 56) as u8;
        }
    }

    /// On a host with a hardware AES extension, the default backend must agree
    /// byte-for-byte with the constant-time software path — for single blocks
    /// and for the batched `encrypt_blocks`/`decrypt_blocks` (which exercise the
    /// wide pipeline plus the sub-8/sub-4-block remainder), across all key
    /// sizes. On a host without the extension both sides are software and this
    /// still holds trivially. CI's aarch64 runner exercises the ARM path here.
    #[test]
    fn hardware_matches_software() {
        macro_rules! check {
            ($ty:ident, $kb:literal) => {{
                let mut key = [0u8; $kb];
                fill(0xA5A5_0000 + $kb, &mut key);
                let hw = $ty::new(&key);
                let sw = $ty::new_software(&key);

                // Single block.
                let mut a = [0u8; 16];
                fill(1, &mut a);
                let (mut h1, mut s1) = (a, a);
                hw.encrypt_block(&mut h1);
                sw.encrypt_block(&mut s1);
                assert_eq!(h1, s1, "{} enc_block", stringify!($ty));
                hw.decrypt_block(&mut h1);
                assert_eq!(h1, a, "{} dec_block roundtrip", stringify!($ty));

                // Batched: 19 blocks → exercises the 8-wide (x86) / 4-wide (arm)
                // path and the remainder tail.
                let mut data = [0u8; 16 * 19];
                fill(0xDEAD_BEEF, &mut data);
                let (mut hb, mut sb) = (data, data);
                hw.encrypt_blocks(&mut hb);
                sw.encrypt_blocks(&mut sb);
                assert_eq!(hb, sb, "{} encrypt_blocks", stringify!($ty));
                hw.decrypt_blocks(&mut hb);
                assert_eq!(hb, data, "{} decrypt_blocks roundtrip", stringify!($ty));
            }};
        }
        check!(Aes128, 16);
        check!(Aes192, 24);
        check!(Aes256, 32);
    }

    /// Byte-wise FIPS-197 rounds over the scalar `gf_inv` S-box and `gf_mul`
    /// (the implementation the word-level software path replaced), as an
    /// oracle for the forward and inverse round transforms.
    fn reference_round(s: [u8; 16], rk: [u8; 16]) -> [u8; 16] {
        use gf::{gf_mul, sub_byte};
        let mut t = [0u8; 16];
        for c in 0..4 {
            for r in 0..4 {
                t[4 * c + r] = sub_byte(s[4 * ((c + r) % 4) + r]);
            }
        }
        let mut out = [0u8; 16];
        for c in 0..4 {
            let a = &t[4 * c..4 * c + 4];
            for r in 0..4 {
                out[4 * c + r] = gf_mul(a[r], 2)
                    ^ gf_mul(a[(r + 1) % 4], 3)
                    ^ a[(r + 2) % 4]
                    ^ a[(r + 3) % 4]
                    ^ rk[4 * c + r];
            }
        }
        out
    }

    fn reference_inv_round(s: [u8; 16]) -> [u8; 16] {
        use gf::{gf_mul, inv_sub_byte};
        let mut m = [0u8; 16];
        for c in 0..4 {
            let a = &s[4 * c..4 * c + 4];
            for r in 0..4 {
                m[4 * c + r] = gf_mul(a[r], 0x0e)
                    ^ gf_mul(a[(r + 1) % 4], 0x0b)
                    ^ gf_mul(a[(r + 2) % 4], 0x0d)
                    ^ gf_mul(a[(r + 3) % 4], 0x09);
            }
        }
        let mut out = [0u8; 16];
        for c in 0..4 {
            for r in 0..4 {
                out[4 * ((c + r) % 4) + r] = inv_sub_byte(m[4 * c + r]);
            }
        }
        out
    }

    #[test]
    fn software_round_matches_bytewise_reference() {
        let mut st = [0u8; 16];
        let mut rk = [0u8; 16];
        for seed in 0..512u64 {
            fill(seed, &mut st);
            fill(seed ^ 0xA5A5, &mut rk);
            if seed < 256 {
                st = [seed as u8; 16]; // every byte value in every lane
            }
            let fwd = aes_round_soft(st, rk);
            assert_eq!(fwd, reference_round(st, rk), "fwd seed {seed}");
            // inv_mix_columns ∘ inv_shift_rows ∘ inv_sub undoes the round.
            let mut s = [u128::from_le_bytes(fwd) ^ u128::from_le_bytes(rk)];
            s[0] = inv_mix_columns(s[0]);
            assert_eq!(reference_inv_round(fwd_xor(fwd, rk)), st, "ref inv {seed}");
            s[0] = inv_shift_rows(s[0]);
            sub_layer(&mut s, true);
            assert_eq!(s[0].to_le_bytes(), st, "inv seed {seed}");
        }
    }

    fn fwd_xor(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
        core::array::from_fn(|i| a[i] ^ b[i])
    }

    /// The key-schedule SubWord on the detected backend (the AES instruction
    /// on a host that has one) must match the bitsliced software S-box for
    /// every byte value in every lane.
    #[test]
    fn sub_word_backends_agree() {
        let hw = detect_backend();
        for x in 0u32..256 {
            for lane in 0..4 {
                let w = (0x9e37_79b9u32.rotate_left(x) & !(0xff << (8 * lane)) | x << (8 * lane))
                    .to_le_bytes();
                let expect: [u8; 4] = core::array::from_fn(|i| gf::sub_byte(w[i]));
                assert_eq!(sub_word(AesBackend::Software, w), expect, "sw {w:02x?}");
                assert_eq!(sub_word(hw, w), expect, "hw {w:02x?}");
            }
        }
    }

    /// The hardware bare AES round must equal the software round for all inputs.
    #[test]
    fn aes_round_hardware_matches_software() {
        let mut st = [0u8; 16];
        let mut rk = [0u8; 16];
        for seed in 0..256u64 {
            fill(seed, &mut st);
            fill(seed ^ 0x5555, &mut rk);
            assert_eq!(aes_round(st, rk), aes_round_soft(st, rk), "seed {seed}");
        }
    }

    #[test]
    fn roundtrip_all_byte_values() {
        let key = from_hex::<16>("2b7e151628aed2a6abf7158809cf4f3c");
        let cipher = Aes128::new(&key);
        for v in 0u16..=255 {
            let original = [v as u8; 16];
            let mut block = original;
            cipher.encrypt_block(&mut block);
            assert_ne!(block, original, "ciphertext should differ from plaintext");
            cipher.decrypt_block(&mut block);
            assert_eq!(block, original);
        }
    }
}
