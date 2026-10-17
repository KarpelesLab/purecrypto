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
// extension, satisfying the `#[target_feature]` safety contract. The round
// count is a const generic so each `Aes*` variant gets its own fully unrolled
// hardware kernels (the software path takes it as a value).
#[inline]
#[allow(unsafe_code)]
fn dispatch_encrypt_block<const NR: usize>(backend: AesBackend, rk: &[u8], block: &mut [u8; 16]) {
    match backend {
        AesBackend::Software => encrypt(rk, NR, block),
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        AesBackend::Hardware => unsafe { aesni::encrypt_block(rk, NR, block) },
        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        AesBackend::Hardware => unsafe { aes_arm::encrypt_block::<NR>(rk, block) },
    }
}

#[inline]
#[allow(unsafe_code)]
fn dispatch_decrypt_block<const NR: usize>(backend: AesBackend, rk: &[u8], block: &mut [u8; 16]) {
    match backend {
        AesBackend::Software => decrypt(rk, NR, block),
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        AesBackend::Hardware => unsafe { aesni::decrypt_block(rk, NR, block) },
        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        AesBackend::Hardware => unsafe { aes_arm::decrypt_block::<NR>(rk, block) },
    }
}

#[inline]
#[allow(unsafe_code)]
fn dispatch_encrypt_blocks<const NR: usize>(backend: AesBackend, rk: &[u8], blocks: &mut [u8]) {
    match backend {
        AesBackend::Software => crypt_blocks_soft::<false>(rk, NR, blocks),
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        AesBackend::Hardware => unsafe { aesni::encrypt_blocks(rk, NR, blocks) },
        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        AesBackend::Hardware => unsafe { aes_arm::encrypt_blocks::<NR>(rk, blocks) },
    }
}

#[inline]
#[allow(unsafe_code)]
fn dispatch_decrypt_blocks<const NR: usize>(backend: AesBackend, rk: &[u8], blocks: &mut [u8]) {
    match backend {
        AesBackend::Software => crypt_blocks_soft::<true>(rk, NR, blocks),
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        AesBackend::Hardware => unsafe { aesni::decrypt_blocks(rk, NR, blocks) },
        #[cfg(all(feature = "std", target_arch = "aarch64"))]
        AesBackend::Hardware => unsafe { aes_arm::decrypt_blocks::<NR>(rk, blocks) },
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
///
/// Word-oriented (FIPS-197 §5.2 as written): the schedule is built as
/// little-endian `u32` words - RotWord is a rotate, the XORs are one word
/// each - and serialised once at the end, instead of byte loops per word.
fn key_expansion(backend: AesBackend, key: &[u8], nk: usize, nr: usize, out: &mut [u8]) {
    let total_words = 4 * (nr + 1);
    // At most 60 words (AES-256: 4 × 15).
    let mut w = [0u32; 60];
    for (wi, k) in w.iter_mut().zip(key.chunks_exact(4)) {
        *wi = u32::from_le_bytes(k.try_into().expect("4-byte word"));
    }

    let mut rcon = 1u8;
    for i in nk..total_words {
        let mut t = w[i - 1];
        if i % nk == 0 {
            // RotWord (bytes `t1 t2 t3 t0`; byte 0 is the low byte of the
            // little-endian word, so this is a rotate right by 8), then
            // SubWord, then XOR the round constant into byte 0.
            t = u32::from_le_bytes(sub_word(backend, t.rotate_right(8).to_le_bytes()))
                ^ rcon as u32;
            // rcon = xtime(rcon); public, so the branch is fine.
            rcon = (rcon << 1) ^ if rcon & 0x80 != 0 { 0x1b } else { 0 };
        } else if nk > 6 && i % nk == 4 {
            // AES-256 applies an extra SubWord a quarter of the way in.
            t = u32::from_le_bytes(sub_word(backend, t.to_le_bytes()));
        }
        w[i] = w[i - nk] ^ t;
    }
    for (o, wi) in out.chunks_exact_mut(4).zip(w.iter()) {
        o.copy_from_slice(&wi.to_le_bytes());
    }
    // The word array is a second copy of the whole schedule.
    crate::zeroize::Zeroize::zeroize(&mut w);
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

/// Table-free constant-time AES round: `MixColumns(ShiftRows(SubBytes(state)))`
/// ⊕ `round_key`, the AESENC primitive (the software arm of [`AesRounds::round`]).
fn aes_round_soft(state: [u8; 16], round_key: [u8; 16]) -> [u8; 16] {
    let mut s = [u128::from_le_bytes(state)];
    sub_layer(&mut s, false);
    (mix_columns(shift_rows(s[0])) ^ u128::from_le_bytes(round_key)).to_le_bytes()
}

/// Round-function modes of the AEGIS bulk kernels: absorb the data
/// unchanged, encrypt it in place (update with the plaintext), or decrypt it
/// in place (update with the recovered plaintext).
#[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
const AEGIS_ABSORB: u8 = 0;
#[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
const AEGIS_ENC: u8 = 1;
#[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
const AEGIS_DEC: u8 = 2;

/// Dispatch handle for the constructions built on the bare AES round (AEGIS,
/// AEZ). The backend is probed once per key (instead of once per round
/// through a per-call probe) and the bulk kernels run with the whole state in
/// registers, where the `[u8; 16]` round API costs a load/store round trip
/// per round. Both backends are constant-time and produce identical results;
/// the bulk methods report whether a hardware kernel ran so the caller keeps
/// a single portable definition of the construction as its fallback.
#[derive(Clone, Copy)]
pub(crate) struct AesRounds {
    backend: AesBackend,
}

impl AesRounds {
    /// Probes the CPU (cached) and picks the backend.
    #[inline]
    pub(crate) fn detect() -> Self {
        AesRounds {
            backend: detect_backend(),
        }
    }

    /// Forces the portable round. Test-only, for differential checks of the
    /// hardware kernels against the reference construction.
    #[cfg(test)]
    pub(crate) fn software() -> Self {
        AesRounds {
            backend: AesBackend::Software,
        }
    }

    /// One bare AES round (AESENC: `MixColumns(ShiftRows(SubBytes(state))) ⊕ rk`) on the cached backend.
    #[inline]
    #[allow(unsafe_code)]
    pub(crate) fn round(self, state: [u8; 16], round_key: [u8; 16]) -> [u8; 16] {
        match self.backend {
            AesBackend::Software => aes_round_soft(state, round_key),
            #[cfg(all(feature = "std", target_arch = "x86_64"))]
            AesBackend::Hardware => unsafe { aesni::aes_round(state, round_key) },
            #[cfg(all(feature = "std", target_arch = "aarch64"))]
            AesBackend::Hardware => unsafe { aes_arm::aes_round(state, round_key) },
        }
    }

    #[cfg(feature = "aez")]
    /// AEZ-core pass 1 over the `buf.len() / 32` i-block pairs of `buf` on
    /// the hardware backend, all three `AES4` stages register-resident with
    /// several pairs in flight and the tweak offsets formed in registers:
    /// `keys` are the `AES4` round keys, `i1`/`j1` the `1I`/`1J` subkeys, `l`
    /// the `L[0..8]` table, `i2 = 2I` the initial running offset, `x` the
    /// running `X`. Returns `false` (touching nothing) without a hardware
    /// backend, for the caller's portable loop.
    // Without a hardware backend only the `Software => false` arm remains
    // and the arguments go unused.
    #[cfg_attr(
        not(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64"))),
        allow(unused_variables)
    )]
    #[inline]
    #[allow(unsafe_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn aez_pass1(
        self,
        keys: &[[u8; 16]; 4],
        i1: &[u8; 16],
        j1: &[u8; 16],
        l: &[[u8; 16]; 8],
        i2: &[u8; 16],
        buf: &mut [u8],
        x: &mut [u8; 16],
    ) -> bool {
        debug_assert!(buf.len().is_multiple_of(32));
        let n = buf.len() / 32;
        match self.backend {
            AesBackend::Software => false,
            #[cfg(all(feature = "std", target_arch = "x86_64"))]
            AesBackend::Hardware => {
                // SAFETY: `buf` is a live exclusive slice of `32 * n` bytes.
                unsafe { aesni::aez_pass1(keys, i1, j1, l, i2, n, buf.as_mut_ptr(), x) };
                true
            }
            #[cfg(all(feature = "std", target_arch = "aarch64"))]
            AesBackend::Hardware => {
                // SAFETY: as above.
                unsafe { aes_arm::aez_pass1(keys, i1, j1, l, i2, n, buf.as_mut_ptr(), x) };
                true
            }
        }
    }

    #[cfg(feature = "aez")]
    /// AEZ-core pass 2, the counterpart of [`Self::aez_pass1`]: `j2 = 2J`,
    /// `s` the `S` block, `y` the running `Y`.
    // Without a hardware backend only the `Software => false` arm remains
    // and the arguments go unused.
    #[cfg_attr(
        not(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64"))),
        allow(unused_variables)
    )]
    #[inline]
    #[allow(unsafe_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn aez_pass2(
        self,
        keys: &[[u8; 16]; 4],
        i1: &[u8; 16],
        j1: &[u8; 16],
        j2: &[u8; 16],
        l: &[[u8; 16]; 8],
        i2: &[u8; 16],
        s: &[u8; 16],
        buf: &mut [u8],
        y: &mut [u8; 16],
    ) -> bool {
        debug_assert!(buf.len().is_multiple_of(32));
        let n = buf.len() / 32;
        match self.backend {
            AesBackend::Software => false,
            #[cfg(all(feature = "std", target_arch = "x86_64"))]
            AesBackend::Hardware => {
                // SAFETY: `buf` is a live exclusive slice of `32 * n` bytes.
                unsafe { aesni::aez_pass2(keys, i1, j1, j2, l, i2, s, n, buf.as_mut_ptr(), y) };
                true
            }
            #[cfg(all(feature = "std", target_arch = "aarch64"))]
            AesBackend::Hardware => {
                // SAFETY: as above.
                unsafe { aes_arm::aez_pass2(keys, i1, j1, j2, l, i2, s, n, buf.as_mut_ptr(), y) };
                true
            }
        }
    }
}

/// Defines the AEGIS bulk methods on [`AesRounds`]: `$absorb` feeds whole
/// blocks of `data` through the state update, `$crypt` encrypts
/// (`decrypt == false`) or decrypts `buf` in place. Both require the length
/// to be a multiple of `$blk` and return `true` when the hardware kernel
/// ran; `false` leaves the state and buffer untouched for the caller's
/// portable loop. `$kernel` is the backend function, generic over the mode.
macro_rules! aegis_bulk {
    ($absorb:ident, $crypt:ident, $words:literal, $blk:literal, $kernel:ident) => {
        impl AesRounds {
            // Without a hardware backend only the `Software => false` arm remains
            // and the arguments go unused.
            #[cfg_attr(
                not(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64"))),
                allow(unused_variables)
            )]
            #[inline]
            #[allow(unsafe_code)]
            pub(crate) fn $absorb(self, s: &mut [[u8; 16]; $words], data: &[u8]) -> bool {
                debug_assert!(data.len().is_multiple_of($blk));
                match self.backend {
                    AesBackend::Software => false,
                    #[cfg(all(feature = "std", target_arch = "x86_64"))]
                    AesBackend::Hardware => {
                        // SAFETY: the absorb mode never writes through the
                        // pointer, which is valid for `data.len()` bytes.
                        unsafe {
                            aesni::$kernel::<AEGIS_ABSORB>(s, data.as_ptr() as *mut u8, data.len())
                        }
                        true
                    }
                    #[cfg(all(feature = "std", target_arch = "aarch64"))]
                    AesBackend::Hardware => {
                        // SAFETY: as above.
                        unsafe {
                            aes_arm::$kernel::<AEGIS_ABSORB>(
                                s,
                                data.as_ptr() as *mut u8,
                                data.len(),
                            )
                        }
                        true
                    }
                }
            }

            // Without a hardware backend only the `Software => false` arm remains
            // and the arguments go unused.
            #[cfg_attr(
                not(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64"))),
                allow(unused_variables)
            )]
            #[inline]
            #[allow(unsafe_code)]
            pub(crate) fn $crypt(
                self,
                s: &mut [[u8; 16]; $words],
                buf: &mut [u8],
                decrypt: bool,
            ) -> bool {
                debug_assert!(buf.len().is_multiple_of($blk));
                match self.backend {
                    AesBackend::Software => false,
                    #[cfg(all(feature = "std", target_arch = "x86_64"))]
                    AesBackend::Hardware => {
                        // SAFETY: `buf` is a live exclusive slice of `len` bytes.
                        unsafe {
                            if decrypt {
                                aesni::$kernel::<AEGIS_DEC>(s, buf.as_mut_ptr(), buf.len())
                            } else {
                                aesni::$kernel::<AEGIS_ENC>(s, buf.as_mut_ptr(), buf.len())
                            }
                        }
                        true
                    }
                    #[cfg(all(feature = "std", target_arch = "aarch64"))]
                    AesBackend::Hardware => {
                        // SAFETY: as above.
                        unsafe {
                            if decrypt {
                                aes_arm::$kernel::<AEGIS_DEC>(s, buf.as_mut_ptr(), buf.len())
                            } else {
                                aes_arm::$kernel::<AEGIS_ENC>(s, buf.as_mut_ptr(), buf.len())
                            }
                        }
                        true
                    }
                }
            }
        }
    };
}

aegis_bulk!(aegis128l_absorb, aegis128l_crypt, 8, 32, aegis128l);
aegis_bulk!(aegis256_absorb, aegis256_crypt, 6, 16, aegis256);
#[cfg(feature = "legacy-ciphers")]
aegis_bulk!(aegis128_absorb, aegis128_crypt, 5, 16, aegis128);

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
                dispatch_encrypt_block::<$nr>(self.backend, &self.rk, block);
            }

            #[inline]
            fn decrypt_block(&self, block: &mut [u8; 16]) {
                dispatch_decrypt_block::<$nr>(self.backend, &self.rk, block);
            }

            #[inline]
            fn encrypt_blocks(&self, blocks: &mut [u8]) {
                // Hard check (see the trait docs): every backend walks
                // `chunks_exact_mut(16)` and would silently leave a trailing
                // partial block unencrypted.
                assert!(
                    blocks.len().is_multiple_of(16),
                    "encrypt_blocks needs whole blocks"
                );
                dispatch_encrypt_blocks::<$nr>(self.backend, &self.rk, blocks);
            }

            #[inline]
            fn decrypt_blocks(&self, blocks: &mut [u8]) {
                assert!(
                    blocks.len().is_multiple_of(16),
                    "decrypt_blocks needs whole blocks"
                );
                dispatch_decrypt_blocks::<$nr>(self.backend, &self.rk, blocks);
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

    /// A buffer that is not a whole number of blocks is rejected outright
    /// (in release builds too) instead of having its tail skipped.
    #[test]
    #[should_panic(expected = "encrypt_blocks needs whole blocks")]
    fn encrypt_blocks_rejects_partial_block() {
        let cipher = Aes128::new(&[0u8; 16]);
        let mut buf = [0u8; 24];
        cipher.encrypt_blocks(&mut buf);
    }

    #[test]
    #[should_panic(expected = "decrypt_blocks needs whole blocks")]
    fn decrypt_blocks_rejects_partial_block() {
        let cipher = Aes256::new(&[0u8; 32]);
        let mut buf = [0u8; 40];
        cipher.decrypt_blocks(&mut buf);
    }

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

                // Batched: 19 blocks → exercises the 8-wide path, the
                // 4-block remainder group and the single-block tail.
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
            assert_eq!(
                AesRounds::detect().round(st, rk),
                aes_round_soft(st, rk),
                "seed {seed}"
            );
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
