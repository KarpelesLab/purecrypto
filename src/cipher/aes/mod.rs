//! AES (FIPS-197) block cipher, constant-time.
//!
//! Supports 128-, 192- and 256-bit keys. The state is held as 16 bytes in
//! column-major order (`state[4*col + row]`), matching FIPS-197. All
//! transforms are branchless and table-free, so encryption time does not
//! depend on key or data values.

mod gf;

#[cfg(all(feature = "std", target_arch = "aarch64"))]
mod aes_arm;
#[cfg(all(feature = "std", target_arch = "x86_64"))]
mod aesni;

use super::BlockCipher;
use gf::{gf_mul, inv_sub_byte, sub_byte};

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
        AesBackend::Software => {
            for block in blocks.chunks_exact_mut(16) {
                let b: &mut [u8; 16] = block.try_into().expect("16-byte chunk");
                encrypt(rk, nr, b);
            }
        }
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
        AesBackend::Software => {
            for block in blocks.chunks_exact_mut(16) {
                let b: &mut [u8; 16] = block.try_into().expect("16-byte chunk");
                decrypt(rk, nr, b);
            }
        }
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        AesBackend::Hardware => unsafe { aesni::decrypt_blocks(rk, nr, blocks) },
        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        AesBackend::Hardware => unsafe { aes_arm::decrypt_blocks(rk, nr, blocks) },
    }
}

/// XORs a 16-byte round key into the state.
#[inline]
fn add_round_key(state: &mut [u8; 16], rk: &[u8]) {
    for (s, k) in state.iter_mut().zip(rk.iter()) {
        *s ^= *k;
    }
}

#[inline]
fn sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = sub_byte(*b);
    }
}

#[inline]
fn inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = inv_sub_byte(*b);
    }
}

/// Cyclically shifts row `r` left by `r` bytes (column-major layout).
#[inline]
fn shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    // Row 1: <<< 1
    s[1] = t[5];
    s[5] = t[9];
    s[9] = t[13];
    s[13] = t[1];
    // Row 2: <<< 2
    s[2] = t[10];
    s[6] = t[14];
    s[10] = t[2];
    s[14] = t[6];
    // Row 3: <<< 3
    s[3] = t[15];
    s[7] = t[3];
    s[11] = t[7];
    s[15] = t[11];
}

/// Inverse of [`shift_rows`]: cyclically shifts row `r` right by `r` bytes.
#[inline]
fn inv_shift_rows(s: &mut [u8; 16]) {
    let t = *s;
    // Row 1: >>> 1
    s[1] = t[13];
    s[5] = t[1];
    s[9] = t[5];
    s[13] = t[9];
    // Row 2: >>> 2
    s[2] = t[10];
    s[6] = t[14];
    s[10] = t[2];
    s[14] = t[6];
    // Row 3: >>> 3
    s[3] = t[7];
    s[7] = t[11];
    s[11] = t[15];
    s[15] = t[3];
}

#[inline]
fn mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3;
        s[i + 1] = a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3;
        s[i + 2] = a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3);
        s[i + 3] = gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2);
    }
}

#[inline]
fn inv_mix_columns(s: &mut [u8; 16]) {
    for c in 0..4 {
        let i = 4 * c;
        let (a0, a1, a2, a3) = (s[i], s[i + 1], s[i + 2], s[i + 3]);
        s[i] = gf_mul(a0, 0x0e) ^ gf_mul(a1, 0x0b) ^ gf_mul(a2, 0x0d) ^ gf_mul(a3, 0x09);
        s[i + 1] = gf_mul(a0, 0x09) ^ gf_mul(a1, 0x0e) ^ gf_mul(a2, 0x0b) ^ gf_mul(a3, 0x0d);
        s[i + 2] = gf_mul(a0, 0x0d) ^ gf_mul(a1, 0x09) ^ gf_mul(a2, 0x0e) ^ gf_mul(a3, 0x0b);
        s[i + 3] = gf_mul(a0, 0x0b) ^ gf_mul(a1, 0x0d) ^ gf_mul(a2, 0x09) ^ gf_mul(a3, 0x0e);
    }
}

/// Expands `key` (`nk` 32-bit words) into `out`, the round-key bytes for `nr`
/// rounds (`16 * (nr + 1)` bytes). The control flow depends only on the public
/// key length, not on key contents.
fn key_expansion(key: &[u8], nk: usize, nr: usize, out: &mut [u8]) {
    let total_words = 4 * (nr + 1);
    out[..key.len()].copy_from_slice(key);

    let mut rcon = 1u8;
    for i in nk..total_words {
        let prev = i - 1;
        let mut t = [
            out[prev * 4],
            out[prev * 4 + 1],
            out[prev * 4 + 2],
            out[prev * 4 + 3],
        ];

        if i % nk == 0 {
            // RotWord, then SubWord, then XOR the round constant.
            t = [t[1], t[2], t[3], t[0]];
            for b in t.iter_mut() {
                *b = sub_byte(*b);
            }
            t[0] ^= rcon;
            rcon = gf_mul(rcon, 2);
        } else if nk > 6 && i % nk == 4 {
            // AES-256 applies an extra SubWord a quarter of the way in.
            for b in t.iter_mut() {
                *b = sub_byte(*b);
            }
        }

        let base = i * 4;
        let src = (i - nk) * 4;
        for j in 0..4 {
            out[base + j] = out[src + j] ^ t[j];
        }
    }
}

/// Encrypts one block using the expanded round keys.
fn encrypt(rk: &[u8], nr: usize, block: &mut [u8; 16]) {
    add_round_key(block, &rk[0..16]);
    for round in 1..nr {
        sub_bytes(block);
        shift_rows(block);
        mix_columns(block);
        add_round_key(block, &rk[round * 16..round * 16 + 16]);
    }
    sub_bytes(block);
    shift_rows(block);
    add_round_key(block, &rk[nr * 16..nr * 16 + 16]);
}

/// Decrypts one block using the expanded round keys (FIPS-197 inverse cipher).
fn decrypt(rk: &[u8], nr: usize, block: &mut [u8; 16]) {
    add_round_key(block, &rk[nr * 16..nr * 16 + 16]);
    for round in (1..nr).rev() {
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, &rk[round * 16..round * 16 + 16]);
        inv_mix_columns(block);
    }
    inv_shift_rows(block);
    inv_sub_bytes(block);
    add_round_key(block, &rk[0..16]);
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
    let mut s = state;
    sub_bytes(&mut s);
    shift_rows(&mut s);
    mix_columns(&mut s);
    add_round_key(&mut s, &round_key);
    s
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
                key_expansion(key, $nk, $nr, &mut rk);
                $name { rk, backend: detect_backend() }
            }

            /// Forces the constant-time software backend, regardless of CPU
            /// support. Test-only: used to differentially check a hardware
            /// backend against the reference software path.
            #[cfg(test)]
            pub(crate) fn new_software(key: &[u8; $key_bytes]) -> Self {
                let mut rk = [0u8; $rk_len];
                key_expansion(key, $nk, $nr, &mut rk);
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
        }

        impl Drop for $name {
            fn drop(&mut self) {
                // Best-effort wipe of the expanded key material.
                for b in self.rk.iter_mut() {
                    *b = 0;
                }
                core::hint::black_box(&self.rk);
            }
        }
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
