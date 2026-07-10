//! AES-GCM — Galois/Counter Mode authenticated encryption (NIST SP 800-38D).
//!
//! GCM combines CTR-mode confidentiality with a GHASH authenticator over the
//! GF(2¹²⁸) field. The field multiply here is the branchless, table-free
//! bit-by-bit algorithm, so it leaks nothing about the (secret) hash subkey
//! through cache timing.
//!
//! A given (key, nonce) pair must **never** be reused: nonce reuse in GCM is
//! catastrophic, revealing the hash subkey and breaking authenticity.

use super::{BlockCipher, TagMismatch};
use crate::ct::ConstantTimeEq;

/// GF(2¹²⁸) reduction constant `R = 11100001 ‖ 0¹²⁰` in the GCM bit ordering.
const R: u128 = 0xe1000000000000000000000000000000;

/// Multiplies two field elements in GF(2¹²⁸) using the GCM bit convention,
/// in constant time (128 fixed iterations, no branches or table lookups).
fn gf_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    let mut i = 0;
    while i < 128 {
        // GCM bit i of x is u128 bit (127 - i): process from the left.
        let xi = (x >> (127 - i)) & 1;
        z ^= 0u128.wrapping_sub(xi) & v;
        // Shift v right (toward GCM bit 127); reduce if the bit shifted out set.
        let lsb = v & 1;
        v >>= 1;
        v ^= 0u128.wrapping_sub(lsb) & R;
        i += 1;
    }
    z
}

/// Loads up to 16 bytes as a big-endian block, zero-padded on the right.
#[inline]
fn load_block(chunk: &[u8]) -> u128 {
    let mut b = [0u8; 16];
    b[..chunk.len()].copy_from_slice(chunk);
    u128::from_be_bytes(b)
}

/// Increments the rightmost 32 bits of a counter block (GCM `inc32`).
#[inline]
fn inc32(block: u128) -> u128 {
    let ctr = (block as u32).wrapping_add(1);
    (block & !0xffff_ffffu128) | ctr as u128
}

/// AES-GCM context, parameterized over the underlying block cipher.
#[derive(Clone)]
pub struct Gcm<C: BlockCipher> {
    cipher: C,
    /// Hash subkey `H = E_K(0¹²⁸)`.
    h: u128,
    /// Whether to use the hardware (PCLMULQDQ) GHASH multiply. Probed once at
    /// construction; the software `gf_mul` is the fallback. Only present on the
    /// one target that currently has a hardware GHASH backend.
    #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
    ghash_hw: bool,
    /// Precomputed hash-subkey powers `hpow[i] = H^{i+1}` for the aggregated
    /// (multi-block, single-reduction) hardware GHASH. Computed once here so
    /// neither the bulk hash nor the fused CTR+GHASH loop rederives them per
    /// message. All zero when the hardware backend is absent.
    #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
    hpow: [u128; 8],
}

impl<C: BlockCipher> Gcm<C> {
    /// Creates a GCM context, deriving the hash subkey from `cipher`.
    #[allow(unsafe_code)]
    pub fn new(cipher: C) -> Self {
        let mut h = [0u8; 16];
        cipher.encrypt_block(&mut h);
        let h = u128::from_be_bytes(h);
        #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
        let (ghash_hw, hpow) = {
            let hw = super::clmul::supported();
            let mut hp = [0u128; 8];
            if hw {
                hp[0] = h;
                for i in 1..8 {
                    // SAFETY: `supported()` confirmed the carryless-multiply
                    // features `gf_mul` requires.
                    hp[i] = unsafe { super::clmul::gf_mul(hp[i - 1], h) };
                }
            }
            (hw, hp)
        };
        Gcm {
            cipher,
            h,
            #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
            ghash_hw,
            #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
            hpow,
        }
    }

    /// GF(2¹²⁸) multiply by the hash subkey, dispatched to the hardware GHASH
    /// when available. Both paths are constant-time and return identical values.
    #[inline]
    #[allow(unsafe_code)]
    fn mul_h(&self, x: u128) -> u128 {
        #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
        if self.ghash_hw {
            // SAFETY: `ghash_hw` is only set when `clmul::supported()` confirmed
            // the PCLMULQDQ/SSSE3 features this function requires.
            return unsafe { super::clmul::gf_mul(x, self.h) };
        }
        gf_mul(x, self.h)
    }

    /// Computes the pre-counter block `J0` for a nonce of any length.
    fn j0(&self, nonce: &[u8]) -> u128 {
        if nonce.len() == 12 {
            // Recommended case: J0 = IV ‖ 0³¹ ‖ 1.
            let mut block = [0u8; 16];
            block[..12].copy_from_slice(nonce);
            block[15] = 1;
            u128::from_be_bytes(block)
        } else {
            // J0 = GHASH_H(IV padded ‖ 0⁶⁴ ‖ [len(IV)]₆₄).
            let mut x = 0u128;
            for chunk in nonce.chunks(16) {
                x = self.mul_h(x ^ load_block(chunk));
            }
            x = self.mul_h(x ^ (nonce.len() as u128 * 8));
            x
        }
    }

    /// GHASH over associated data `aad` and ciphertext `ct`.
    #[allow(unsafe_code)]
    fn ghash(&self, aad: &[u8], ct: &[u8]) -> u128 {
        let mut x = 0u128;
        for chunk in aad.chunks(16) {
            x = self.mul_h(x ^ load_block(chunk));
        }
        // The ciphertext is the bulk; on a hardware GHASH backend fold its full
        // blocks via the aggregated-reduction path (one reduction per four
        // blocks), leaving any partial trailing block to the serial multiply.
        // NB: keep `ct` intact — the length block below reads `ct.len()`.
        #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
        let tail = if self.ghash_hw {
            let full = ct.len() & !15;
            // SAFETY: `ghash_hw` is only set when `clmul::supported()` confirmed
            // the carryless-multiply features `ghash_blocks` requires.
            x = unsafe { super::clmul::ghash_blocks(x, &self.hpow, &ct[..full]) };
            &ct[full..]
        } else {
            ct
        };
        #[cfg(not(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64"))))]
        let tail = ct;
        for chunk in tail.chunks(16) {
            x = self.mul_h(x ^ load_block(chunk));
        }
        // Length block: [len(aad)]₆₄ ‖ [len(ct)]₆₄, in bits.
        let len_block = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
        self.mul_h(x ^ len_block)
    }

    /// XORs the GCTR keystream (counter increments only its low 32 bits) into
    /// `buf`, starting from `counter`.
    ///
    /// Keystream blocks are generated a window at a time and permuted with the
    /// batched [`encrypt_blocks`](super::BlockCipher::encrypt_blocks), so a
    /// hardware AES backend pipelines them; the per-block counter sequence is
    /// identical to the scalar form.
    fn gctr(&self, counter: u128, buf: &mut [u8]) {
        super::ctr::windowed_ctr(
            counter.to_be_bytes(),
            buf,
            // GCM advances the rightmost 32 bits of the big-endian block.
            |b| *b = inc32(u128::from_be_bytes(*b)).to_be_bytes(),
            |ks| self.cipher.encrypt_blocks(ks),
        );
    }

    /// Computes the authentication tag `E_K(J0) ⊕ GHASH(aad, ct)`.
    fn tag(&self, j0: u128, aad: &[u8], ct: &[u8]) -> [u8; 16] {
        let s = self.ghash(aad, ct);
        let mut ej0 = j0.to_be_bytes();
        self.cipher.encrypt_block(&mut ej0);
        (u128::from_be_bytes(ej0) ^ s).to_be_bytes()
    }

    /// Folds `data` (any length; the final partial block is zero-padded) into
    /// the GHASH accumulator `x` via the aggregated hardware path. Only called
    /// from the fused path, i.e. with `ghash_hw` set.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[allow(unsafe_code)]
    fn ghash_partial(&self, mut x: u128, data: &[u8]) -> u128 {
        let full = data.len() & !15;
        if full > 0 {
            // SAFETY: the fused path runs only when `clmul::supported()`
            // confirmed the features `ghash_blocks` requires.
            x = unsafe { super::clmul::ghash_blocks(x, &self.hpow, &data[..full]) };
        }
        if full < data.len() {
            x = self.mul_h(x ^ load_block(&data[full..]));
        }
        x
    }

    /// Single-pass AES-CTR ⊕ GHASH ("stitched") implementation of the GCM
    /// bulk work, used when both a hardware AES schedule and the carryless
    /// multiplier are available. Interleaving the two dependency chains in one
    /// loop lets the CPU's AES units and carryless multiplier run
    /// concurrently, where the generic path makes two serial passes over the
    /// buffer.
    ///
    /// Encrypts (`encrypt = true`) or decrypts (`false`) `buffer` in place and
    /// returns the authentication tag; `None` means no fused backend, caller
    /// falls back to the generic path. NB: on decrypt the tag is computed but
    /// NOT verified here — and the buffer has already been decrypted — so the
    /// caller must check the tag and restore the ciphertext on mismatch.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[allow(unsafe_code)]
    fn crypt_fused(
        &self,
        j0: u128,
        aad: &[u8],
        buffer: &mut [u8],
        encrypt: bool,
    ) -> Option<[u8; 16]> {
        if !self.ghash_hw {
            return None;
        }
        let (rk, nr) = self.cipher.hw_aes_schedule()?;
        let total_len = buffer.len();

        // AAD prefix of the GHASH (outside the bulk loop).
        let mut x = self.ghash_partial(0, aad);

        // Bulk: whole 128-byte (8-block) groups run through the fused loop.
        let fused = total_len & !127;
        let ctr0 = inc32(j0);
        if fused > 0 {
            // SAFETY: `ghash_hw` plus `hw_aes_schedule()` returning `Some`
            // confirmed the AES-NI + PCLMULQDQ features the kernel requires;
            // `rk` is the cipher's own `16 * (nr + 1)`-byte schedule.
            x = unsafe {
                super::clmul::ctr_ghash_fused(
                    rk,
                    nr,
                    ctr0,
                    &self.hpow,
                    x,
                    &mut buffer[..fused],
                    encrypt,
                )
            };
        }

        // Tail (< 8 blocks): generic windowed CTR + aggregated GHASH. The
        // counter after `fused/16` blocks; GCM `inc32` wraps modulo 2³².
        let ctr_tail =
            (ctr0 & !0xffff_ffffu128) | ((ctr0 as u32).wrapping_add((fused / 16) as u32) as u128);
        let tail = &mut buffer[fused..];
        if encrypt {
            self.gctr(ctr_tail, tail);
            x = self.ghash_partial(x, tail);
        } else {
            // Hash the ciphertext before overwriting it with plaintext.
            x = self.ghash_partial(x, tail);
            self.gctr(ctr_tail, tail);
        }

        // Length block, then the tag mask E_K(J0).
        let len_block = ((aad.len() as u128 * 8) << 64) | (total_len as u128 * 8);
        x = self.mul_h(x ^ len_block);
        let mut ej0 = j0.to_be_bytes();
        self.cipher.encrypt_block(&mut ej0);
        Some((u128::from_be_bytes(ej0) ^ x).to_be_bytes())
    }

    /// NIST SP 800-38D §5.2.1.1: |IV| ∈ [1, 2^64−1] bits. We surface the
    /// upper end as a byte cap; the lower end forbids zero-length nonces.
    ///
    /// Computed in `u64` and saturated to `usize::MAX` so 16/32-bit targets
    /// (where `1usize << 61` would not even compile) keep a valid bound: any
    /// slice they can address is shorter than 2^61 − 1 bytes anyway.
    const MAX_NONCE_LEN: usize = {
        const CAP: u64 = (1u64 << 61) - 1;
        if CAP > usize::MAX as u64 {
            usize::MAX
        } else {
            CAP as usize
        }
    };
    /// NIST SP 800-38D §5.2.1.1: |P| ≤ 2^39 − 256 bits, i.e. `(1<<36) − 32`
    /// bytes. Above this, the 32-bit GCTR counter wraps and reuses keystream.
    pub const MAX_PLAINTEXT_LEN: u64 = (1u64 << 36) - 32;

    fn validate(nonce: &[u8], buffer: &[u8]) {
        assert!(
            !nonce.is_empty() && nonce.len() <= Self::MAX_NONCE_LEN,
            "AES-GCM nonce must be 1..=2^61-1 bytes (NIST SP 800-38D §5.2.1.1)"
        );
        assert!(
            (buffer.len() as u64) <= Self::MAX_PLAINTEXT_LEN,
            "AES-GCM plaintext exceeds 2^39 − 256 bits (NIST SP 800-38D §5.2.1.1)"
        );
    }

    /// Encrypts `buffer` in place and returns the 16-byte authentication tag,
    /// binding the optional `aad`.
    ///
    /// # Panics
    /// Panics if `nonce.is_empty()` or `buffer.len()` exceeds the NIST
    /// SP 800-38D plaintext cap (`2^39 − 256` bits).
    pub fn encrypt(&self, nonce: &[u8], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        Self::validate(nonce, buffer);
        let j0 = self.j0(nonce);
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        if let Some(tag) = self.crypt_fused(j0, aad, buffer, true) {
            return tag;
        }
        self.gctr(inc32(j0), buffer);
        self.tag(j0, aad, buffer)
    }

    /// Verifies `tag` and, only if it matches, decrypts `buffer` in place.
    ///
    /// The tag is checked in constant time. On mismatch the ciphertext is
    /// **left untouched** (no unauthenticated plaintext is produced) and
    /// [`TagMismatch`] is returned.
    ///
    /// # Panics
    /// Panics if `nonce.is_empty()` or `buffer.len()` exceeds the NIST cap.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        Self::validate(nonce, buffer);
        let j0 = self.j0(nonce);
        #[cfg(all(feature = "std", target_arch = "x86_64"))]
        if let Some(expected) = self.crypt_fused(j0, aad, buffer, false) {
            if bool::from(expected.ct_eq(tag)) {
                return Ok(());
            }
            // The stitched pass decrypts while it hashes, so `buffer` already
            // holds the (unauthenticated) plaintext; re-applying the keystream
            // restores the ciphertext before returning, upholding the
            // documented contract. The plaintext never leaves this function.
            self.gctr(inc32(j0), buffer);
            return Err(TagMismatch);
        }
        // GHASH is computed over the ciphertext, which is still in `buffer`.
        let expected = self.tag(j0, aad, buffer);
        if !bool::from(expected.ct_eq(tag)) {
            return Err(TagMismatch);
        }
        self.gctr(inc32(j0), buffer);
        Ok(())
    }
}

impl<C: BlockCipher> Drop for Gcm<C> {
    fn drop(&mut self) {
        // Best-effort wipe of the GHASH subkey `H = E_K(0¹²⁸)` and its
        // precomputed powers, which are secret-equivalent (they let an
        // attacker forge tags, and nonce reuse already leaks H). Same
        // `core::hint::black_box`-guarded zeroing as the AES round-key drop
        // in `cipher/aes/mod.rs`.
        self.h = 0;
        let _ = core::hint::black_box(&self.h);
        #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            self.hpow = [0u128; 8];
            let _ = core::hint::black_box(&self.hpow);
        }
    }
}

/// AES-128 in GCM mode.
pub type Aes128Gcm = Gcm<super::Aes128>;
/// AES-256 in GCM mode.
pub type Aes256Gcm = Gcm<super::Aes256>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::Aes128;
    use crate::test_util::from_hex;

    fn gcm128(key_hex: &str) -> Gcm<Aes128> {
        Gcm::new(Aes128::new(&from_hex::<16>(key_hex)))
    }

    /// The hardware (PCLMULQDQ) GHASH multiply must return exactly the same
    /// value as the constant-time software `gf_mul` for every input — this pins
    /// the reflected bit-order/reduction. Runs only where the extension exists.
    #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
    #[test]
    #[allow(unsafe_code)]
    fn ghash_hardware_matches_software() {
        if !crate::cipher::clmul::supported() {
            return;
        }
        let mut s = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s
        };
        // Edge cases plus randomized coverage.
        let edges: [u128; 4] = [0, 1, u128::MAX, 1u128 << 127];
        for &x in &edges {
            for &y in &edges {
                let hw = unsafe { crate::cipher::clmul::gf_mul(x, y) };
                assert_eq!(hw, gf_mul(x, y), "edge x={x:032x} y={y:032x}");
            }
        }
        for _ in 0..20_000 {
            let x = ((next() as u128) << 64) | next() as u128;
            let y = ((next() as u128) << 64) | next() as u128;
            let hw = unsafe { crate::cipher::clmul::gf_mul(x, y) };
            assert_eq!(hw, gf_mul(x, y), "rand x={x:032x} y={y:032x}");
        }
    }

    /// Independent serial-software GHASH reference: `X = 0`, then fold each
    /// 16-byte (zero-padded) block of `aad`, then each block of `ct`, then the
    /// length block — every step a single `gf_mul` by `h`. Deliberately *not*
    /// the aggregated-reduction path, so it cross-checks the hardware
    /// `ghash_blocks` 4-block grouping + serial remainder.
    fn ghash_serial_ref(h: u128, aad: &[u8], ct: &[u8]) -> u128 {
        let mut x = 0u128;
        for chunk in aad.chunks(16) {
            x = gf_mul(x ^ load_block(chunk), h);
        }
        for chunk in ct.chunks(16) {
            x = gf_mul(x ^ load_block(chunk), h);
        }
        let len_block = ((aad.len() as u128 * 8) << 64) | (ct.len() as u128 * 8);
        gf_mul(x ^ len_block, h)
    }

    /// Differential guard for the aggregated-reduction GHASH (`clmul::ghash_blocks`,
    /// reached via `Gcm::encrypt`'s hardware path): the real tag must match an
    /// independent serial-software GHASH reference across many ciphertext lengths
    /// — spanning every full/partial 4-block group residue and multiple groups —
    /// and AAD lengths that exercise the AAD→CT accumulator handoff. The shipped
    /// NIST KATs only hit the 0-remainder and single-4-block-group cases.
    #[cfg(all(feature = "std", any(target_arch = "x86_64", target_arch = "aarch64")))]
    #[test]
    fn aggregated_ghash_matches_serial_reference() {
        use std::vec::Vec;
        if !crate::cipher::clmul::supported() {
            return;
        }
        let key = from_hex::<16>("feffe9928665731c6d6a8f9467308308");
        let g = Gcm::new(Aes128::new(&key));
        // H = E_K(0¹²⁸) and J0 for a 12-byte nonce, reconstructed as the code does.
        let mut h = [0u8; 16];
        Aes128::new(&key).encrypt_block(&mut h);
        let h = u128::from_be_bytes(h);
        let nonce = from_hex::<12>("cafebabefacedbaddecaf888");
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(&nonce);
        j0[15] = 1;
        let mut ej0 = j0;
        Aes128::new(&key).encrypt_block(&mut ej0);
        let ej0 = u128::from_be_bytes(ej0);

        // msg lengths 0..=200 span 0..12+ blocks → every group/remainder residue
        // and several full groups; AAD lengths probe the AAD→CT handoff.
        for &aad_len in &[0usize, 1, 16, 17, 31, 48, 63] {
            let aad: Vec<u8> = (0..aad_len).map(|i| (i as u8).wrapping_mul(31)).collect();
            for msg_len in 0..=200usize {
                let mut buf: Vec<u8> = (0..msg_len)
                    .map(|i| (i as u8).wrapping_mul(37).wrapping_add(13))
                    .collect();
                let tag = g.encrypt(&nonce, &aad, &mut buf);
                // buf now holds the ciphertext GHASH actually ran over.
                let expected = (ej0 ^ ghash_serial_ref(h, &aad, &buf)).to_be_bytes();
                assert_eq!(
                    tag, expected,
                    "tag mismatch at aad_len={aad_len} msg_len={msg_len}"
                );
            }
        }
    }

    /// Differential guard for the fused (stitched AES-CTR ⊕ GHASH) bulk path:
    /// on hardware with AES-NI + PCLMULQDQ the default context takes the fused
    /// path, while a context built on the software AES backend (no
    /// `hw_aes_schedule`) takes the generic two-pass path. Ciphertext and tag
    /// must be byte-identical across a length sweep covering every block,
    /// 4-block, 8-block-group and partial-block residue, with several AAD
    /// lengths, for encrypt AND decrypt — including tag rejection leaving the
    /// buffer untouched (the fused decrypt must restore the ciphertext).
    /// Without the hardware features both sides take the generic path and the
    /// test still holds trivially.
    #[cfg(all(feature = "std", target_arch = "x86_64"))]
    #[test]
    fn fused_matches_two_pass() {
        use std::vec::Vec;
        let key128 = from_hex::<16>("feffe9928665731c6d6a8f9467308308");
        let key256 =
            from_hex::<32>("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308");
        let fused128 = Gcm::new(Aes128::new(&key128));
        let plain128 = Gcm::new(Aes128::new_software(&key128));
        let fused256 = Gcm::new(crate::cipher::Aes256::new(&key256));
        let plain256 = Gcm::new(crate::cipher::Aes256::new_software(&key256));
        let nonce = from_hex::<12>("cafebabefacedbaddecaf888");

        let mut lens: Vec<usize> = (0..=300).collect();
        lens.extend([511, 512, 513, 1023, 1024, 1025, 4096, 8191]);

        fn check<C: crate::cipher::BlockCipher>(
            fused: &Gcm<C>,
            plain: &Gcm<C>,
            nonce: &[u8; 12],
            aad: &[u8],
            len: usize,
        ) {
            use std::vec::Vec;
            let pt: Vec<u8> = (0..len)
                .map(|i| (i as u8).wrapping_mul(41).wrapping_add(7))
                .collect();
            let mut a = pt.clone();
            let mut b = pt.clone();
            let ta = fused.encrypt(nonce, aad, &mut a);
            let tb = plain.encrypt(nonce, aad, &mut b);
            assert_eq!(a, b, "ciphertext len={len} aad={}", aad.len());
            assert_eq!(ta, tb, "tag len={len} aad={}", aad.len());

            // Fused decrypt round-trips.
            fused.decrypt(nonce, aad, &mut a, &ta).unwrap();
            assert_eq!(a, pt, "roundtrip len={len} aad={}", aad.len());

            // Rejection restores the ciphertext byte-for-byte.
            let ct = b.clone();
            let mut bad = ta;
            bad[15] ^= 1;
            assert_eq!(fused.decrypt(nonce, aad, &mut b, &bad), Err(TagMismatch));
            assert_eq!(b, ct, "restore on mismatch len={len} aad={}", aad.len());
        }

        for &aad_len in &[0usize, 5, 16, 37] {
            let aad: Vec<u8> = (0..aad_len).map(|i| (i as u8) ^ 0xa5).collect();
            for &len in &lens {
                check(&fused128, &plain128, &nonce, &aad, len);
            }
            // AES-256 exercises the 14-round schedule in the fused kernel.
            for &len in &[0usize, 96, 127, 128, 129, 1024, 4096] {
                check(&fused256, &plain256, &nonce, &aad, len);
            }
        }
    }

    // McGrew & Viega GCM test vectors (AES-128).

    #[test]
    fn tc1_empty() {
        let g = gcm128("00000000000000000000000000000000");
        let nonce = from_hex::<12>("000000000000000000000000");
        let mut buf: [u8; 0] = [];
        let tag = g.encrypt(&nonce, &[], &mut buf);
        assert_eq!(tag, from_hex::<16>("58e2fccefa7e3061367f1d57a4e7455a"));
    }

    #[test]
    fn tc2_one_block() {
        let g = gcm128("00000000000000000000000000000000");
        let nonce = from_hex::<12>("000000000000000000000000");
        let mut buf = from_hex::<16>("00000000000000000000000000000000");
        let tag = g.encrypt(&nonce, &[], &mut buf);
        assert_eq!(buf, from_hex::<16>("0388dace60b6a392f328c2b971b2fe78"));
        assert_eq!(tag, from_hex::<16>("ab6e47d42cec13bdf53a67b21257bddf"));
    }

    #[test]
    fn tc3_multiblock() {
        let g = gcm128("feffe9928665731c6d6a8f9467308308");
        let nonce = from_hex::<12>("cafebabefacedbaddecaf888");
        let mut buf = from_hex::<64>(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
        );
        let tag = g.encrypt(&nonce, &[], &mut buf);
        assert_eq!(
            buf,
            from_hex::<64>(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985"
            )
        );
        assert_eq!(tag, from_hex::<16>("4d5c2af327cd64a62cf35abd2ba6fab4"));
    }

    #[test]
    fn tc4_with_aad() {
        let g = gcm128("feffe9928665731c6d6a8f9467308308");
        let nonce = from_hex::<12>("cafebabefacedbaddecaf888");
        let aad = from_hex::<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let mut buf = from_hex::<60>(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let tag = g.encrypt(&nonce, &aad, &mut buf);
        assert_eq!(
            buf,
            from_hex::<60>(
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e\
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
            )
        );
        assert_eq!(tag, from_hex::<16>("5bc94fbc3221a5db94fae95ae7121a47"));
    }

    #[test]
    fn decrypt_roundtrip_and_reject() {
        let g = gcm128("feffe9928665731c6d6a8f9467308308");
        let nonce = from_hex::<12>("cafebabefacedbaddecaf888");
        let aad = from_hex::<20>("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let plaintext = from_hex::<60>(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72\
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );

        let mut buf = plaintext;
        let tag = g.encrypt(&nonce, &aad, &mut buf);
        // Correct tag decrypts back to the plaintext.
        g.decrypt(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plaintext);

        // A corrupted tag is rejected, and the buffer is left as ciphertext.
        let mut ct = plaintext;
        let tag = g.encrypt(&nonce, &aad, &mut ct);
        let ciphertext = ct;
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        assert_eq!(g.decrypt(&nonce, &aad, &mut ct, &bad_tag), Err(TagMismatch));
        assert_eq!(ct, ciphertext, "buffer must be unchanged on auth failure");

        // Tampered AAD is also rejected.
        let mut ct = ciphertext;
        let mut bad_aad = aad;
        bad_aad[0] ^= 1;
        assert_eq!(g.decrypt(&nonce, &bad_aad, &mut ct, &tag), Err(TagMismatch));
    }
}
