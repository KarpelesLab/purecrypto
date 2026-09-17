//! VMAC (draft-krovetz-vmac-01): a Wegman–Carter message authentication code
//! built on the universal hash VHASH and a block cipher.
//!
//! Two output sizes are provided:
//!
//! - [`Vmac64`] — 8-byte tag (`VMAC-64`, one VHASH iteration).
//! - [`Vmac128`] — 16-byte tag (`VMAC-128`, two VHASH iterations).
//!
//! Both are generic over the 128-bit [`BlockCipher`] and default to
//! [`Aes128`], the cipher the draft assumes; AES-192 and AES-256 (or any
//! other 128-bit block cipher) plug in through `with_cipher`. The
//! construction (draft §3–§5):
//!
//! 1. **KDF** — derive the hash keys with the block cipher in counter mode
//!    over the blocks `index || counter` (`index` = 128 for L1, 192 for L2,
//!    224 for L3).
//! 2. **L1-HASH (NH)** — break the message into 128-byte blocks, read each as
//!    little-endian 64-bit words and reduce it to a 126-bit value with NH
//!    (a sum of products of key-offset word pairs modulo 2¹²⁸, then masked).
//! 3. **L2-HASH** — evaluate a polynomial over GF(2¹²⁷−1) on the NH outputs,
//!    then add the message bit length modulo 1024 (shifted by 64 bits).
//! 4. **L3-HASH** — split the 127-bit value at 2⁶⁴−2³², offset both halves by
//!    key words and multiply them modulo 2⁶⁴−257.
//! 5. **PDF** — encrypt the (zero-left-padded) nonce with the block cipher
//!    and add the resulting pad to the hash, 64-bit word by 64-bit word.
//!
//! The nonce is at most 127 bits: up to 15 bytes, or 16 bytes whose most
//! significant bit is clear (the KDF uses the blocks with that bit set). It
//! must not repeat under a key. For VMAC-64 the nonce's low bit only selects
//! a pad half, so nonces differing in that bit share one cipher call.
//!
//! The whole pipeline runs without table lookups (NH and the polynomial are
//! integer arithmetic, the cipher is the crate's constant-time AES) and
//! without secret-dependent branches: every modular reduction is a fold plus
//! masked conditional subtraction, the L3 division by 2⁶⁴−2³² is done with
//! shifts and masked carries rather than a hardware divide, and the L3 key
//! rejection sampling (draft §5.5, "k₁ < p64 and k₂ < p64") is resolved by
//! masked selection over a fixed window of KDF blocks. Only the message and
//! nonce lengths steer control flow.
//!
//! # Example
//!
//! ```
//! use purecrypto::mac::Vmac64;
//!
//! let key   = *b"abcdefghijklmnop";
//! let nonce = b"bcdefghi";
//! let tag   = Vmac64::compute(&key, b"abc", nonce).unwrap();
//! assert_eq!(tag, [0x2d, 0x37, 0x6c, 0xf5, 0xb1, 0x81, 0x3c, 0xe5]);
//! assert!(Vmac64::new(&key).chain(b"abc").verify(nonce, &tag));
//! ```

use crate::cipher::{Aes128, BlockCipher};
use crate::ct::ConstantTimeEq;
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

// ---------------------------------------------------------------------------
//  Constants
// ---------------------------------------------------------------------------

/// 2¹²⁷ − 1, the L2-HASH prime (draft §5.4).
const P127: u128 = (1u128 << 127) - 1;

/// 2⁶⁴ − 257, the L3-HASH prime (draft §5.5).
const P64: u64 = 0xffff_ffff_ffff_feff;

/// `2⁶⁴ mod p64`: the fold constant for reductions modulo `P64`.
const P64_OFFSET: u64 = 257;

/// 2⁶⁴ − 2³², the L3-HASH split point.
const L3_SPLIT: u128 = (1u128 << 64) - (1u128 << 32);

/// NH output mask: the draft zeroes the top two bits (`mod 2¹²⁶`).
const NH_MASK: u128 = (1u128 << 126) - 1;

/// L2 key mask: the top three bits of every 32-bit word are cleared
/// (draft §5.4, `zeros(3) || T[4...32] || ...`), so `k < 2¹²⁵`.
const L2_MASK: u128 = 0x1fff_ffff_1fff_ffff_1fff_ffff_1fff_ffff;

/// L1KEYLEN in bytes: one NH block.
const L1_BLOCK: usize = 128;

/// Maximum number of VHASH iterations (VMAC-128 uses 2).
const MAX_ITER: usize = 2;

/// L1 key words for the largest iteration count: iteration `i` uses words
/// `2i .. 2i + 16`.
const L1_KEY_WORDS: usize = L1_BLOCK / 8 + 2 * (MAX_ITER - 1);

/// KDF indices (draft §5.3–§5.5).
const KDF_L1: u8 = 128;
const KDF_L2: u8 = 192;
const KDF_L3: u8 = 224;

/// Number of KDF(224) blocks examined by the branchless L3 key selection.
/// Each block is rejected with probability about 2⁻⁵⁵, so this window fails
/// to contain `MAX_ITER` acceptable blocks with probability around 2⁻³³⁰.
const L3_WINDOW: usize = 8;

// ---------------------------------------------------------------------------
//  Branchless helpers
// ---------------------------------------------------------------------------

/// All-ones iff `flag` is true, zero otherwise — the usual branchless mask.
/// The mask goes through [`core::hint::black_box`] so the optimizer cannot
/// see the `0`/`!0` shape and turn the masked selects back into branches.
#[inline]
fn mask64(flag: bool) -> u64 {
    core::hint::black_box((flag as u64).wrapping_neg())
}

#[inline]
fn mask128(flag: bool) -> u128 {
    core::hint::black_box((flag as u128).wrapping_neg())
}

/// Constant-time `x mod p64` for `x < 2·p64`.
#[inline]
fn csub_p64(x: u64) -> u64 {
    let (d, borrow) = x.overflowing_sub(P64);
    (d & !mask64(borrow)) | (x & mask64(borrow))
}

/// Constant-time `x mod p127` for `x < 2·p127`.
#[inline]
fn csub_p127(x: u128) -> u128 {
    let (d, borrow) = x.overflowing_sub(P127);
    (d & !mask128(borrow)) | (x & mask128(borrow))
}

/// Constant-time `x mod p127` for any `x < 2¹²⁸`: fold with `2¹²⁷ ≡ 1`,
/// which leaves at most `2¹²⁷`, then one conditional subtraction.
#[inline]
fn reduce_p127(x: u128) -> u128 {
    csub_p127((x & P127) + (x >> 127))
}

/// `(a + b) mod p127` for `a, b < 2¹²⁷` (no overflow in the sum).
#[inline]
fn add_mod_p127(a: u128, b: u128) -> u128 {
    reduce_p127(a + b)
}

/// `(a * b) mod p127` for `a < 2¹²⁷`, `b < 2¹²⁵`. Schoolbook-multiplies into
/// four 64-bit limbs and collapses with `2¹²⁸ ≡ 2 (mod p127)`.
fn mul_mod_p127(a: u128, b: u128) -> u128 {
    let a_lo = a as u64;
    let a_hi = (a >> 64) as u64;
    let b_lo = b as u64;
    let b_hi = (b >> 64) as u64;

    let ll = (a_lo as u128) * (b_lo as u128);
    let lh = (a_lo as u128) * (b_hi as u128);
    let hl = (a_hi as u128) * (b_lo as u128);
    let hh = (a_hi as u128) * (b_hi as u128);

    // a·b = w3·2¹⁹² + w2·2¹²⁸ + w1·2⁶⁴ + w0
    let w0 = ll as u64;
    let s1 = (ll >> 64) + ((lh as u64) as u128) + ((hl as u64) as u128);
    let w1 = s1 as u64;
    let s2 = (lh >> 64) + (hl >> 64) + ((hh as u64) as u128) + (s1 >> 64);
    let w2 = s2 as u64;
    let w3 = ((hh >> 64) as u64).wrapping_add((s2 >> 64) as u64);

    let lo = (w0 as u128) | ((w1 as u128) << 64);
    // a·b < 2²⁵² ⇒ hi < 2¹²⁴ ⇒ 2·hi < 2¹²⁵.
    let hi = (w2 as u128) | ((w3 as u128) << 64);
    // lo ≡ (lo mod 2¹²⁷) + (lo >> 127); the sum is < 2¹²⁷ + 1 + 2¹²⁵ < 2¹²⁸.
    reduce_p127((lo & P127) + (lo >> 127) + (hi << 1))
}

/// `(a + b) mod p64` for `b < p64` and any `a` (a u64).
#[inline]
fn add_mod_p64(a: u64, b: u64) -> u64 {
    let (s, carry) = a.overflowing_add(b);
    // 2⁶⁴ ≡ 257; the carry case leaves s ≤ p64 − 2, so the add cannot wrap.
    let s = s.wrapping_add(P64_OFFSET & mask64(carry));
    csub_p64(s)
}

/// `(a * b) mod p64` for `a, b < p64`, folding the 128-bit product twice with
/// `2⁶⁴ ≡ 257 (mod p64)`.
fn mul_mod_p64(a: u64, b: u64) -> u64 {
    let prod = (a as u128) * (b as u128);
    // prod ≡ lo + 257·hi, which is < 258·2⁶⁴.
    let r = ((prod as u64) as u128) + (P64_OFFSET as u128) * (prod >> 64);
    let r_lo = r as u64;
    let r_hi = (r >> 64) as u64; // < 258
    // r ≡ r_lo + 257·r_hi, which is < 2⁶⁴ + 2¹⁷.
    let (t, carry) = r_lo.overflowing_add(P64_OFFSET * r_hi);
    let t = t.wrapping_add(P64_OFFSET & mask64(carry));
    csub_p64(t)
}

/// Branchless `(x div (2⁶⁴ − 2³²), x mod (2⁶⁴ − 2³²))` for `x < 2¹²⁷`
/// (draft §5.5, the L3-HASH split).
///
/// `x` is the secret L2 output, so no hardware divide is used. With
/// `d = 2⁶⁴ − 2³²` and `2⁶⁴ = d + 2³²`, write `x = p1·2⁶⁴ + a·2³² + b`
/// (`a`, `b` 32-bit). Then `x = p1·d + (p1 + a)·2³² + b`; splitting
/// `s = p1 + a` into 32-bit halves and applying `2⁶⁴ = d + 2³²` twice more
/// leaves a remainder below `2⁶⁴ + 2³²`, which one masked subtraction of
/// `d` finishes.
fn l3_split(x: u128) -> (u64, u64) {
    let p1 = (x >> 64) as u64; // < 2⁶³
    let p2 = x as u64;
    let a = p2 >> 32;
    let b = p2 & 0xffff_ffff;
    let s = p1 + a; // < 2⁶³ + 2³²
    let s_hi = s >> 32;
    let s_lo = s & 0xffff_ffff;
    let u = s_hi + s_lo; // < 2³³
    let c1 = u >> 32; // 0 or 1
    let v = (u & 0xffff_ffff) + c1; // ≤ 2³²
    let r = ((v as u128) << 32) | (b as u128); // < 2⁶⁴ + 2³²
    let q = p1 + s_hi + c1;
    let over = mask128(r >= L3_SPLIT);
    let r = r - (L3_SPLIT & over);
    let q = q + (over as u64 & 1);
    (q, r as u64)
}

// ---------------------------------------------------------------------------
//  KDF, NH
// ---------------------------------------------------------------------------

/// Draft §3.2: the block cipher in counter mode over `index || counter`,
/// writing `out.len()` bytes.
fn kdf<C: BlockCipher>(cipher: &C, index: u8, out: &mut [u8]) {
    let mut block = [0u8; 16];
    block[0] = index;
    for (i, chunk) in out.chunks_mut(16).enumerate() {
        block[8..16].copy_from_slice(&(i as u64).to_be_bytes());
        let mut ct = block;
        cipher.encrypt_block(&mut ct);
        chunk.copy_from_slice(&ct[..chunk.len()]);
        ct.zeroize();
    }
}

/// NH (draft §5.3, "NH Algorithm") over `data`, which must be a multiple of
/// 16 bytes and at most 128 bytes. Message words are little-endian
/// (ENDIAN-SWAP), key words are `str2uint`, i.e. big-endian, and the sum of
/// the 128-bit products is taken modulo 2¹²⁸ then masked to 126 bits.
fn nh(key: &[u64], data: &[u8]) -> u128 {
    debug_assert!(data.len().is_multiple_of(16) && data.len() <= L1_BLOCK);
    let mut y: u128 = 0;
    for (j, pair) in data.chunks_exact(16).enumerate() {
        let m0 = u64::from_le_bytes(pair[..8].try_into().expect("8 bytes"));
        let m1 = u64::from_le_bytes(pair[8..].try_into().expect("8 bytes"));
        let a = m0.wrapping_add(key[2 * j]) as u128;
        let b = m1.wrapping_add(key[2 * j + 1]) as u128;
        y = y.wrapping_add(a * b);
    }
    y & NH_MASK
}

// ---------------------------------------------------------------------------
//  Shared streaming state
// ---------------------------------------------------------------------------

/// The nonce is longer than 127 bits: more than 16 bytes, or 16 bytes with
/// the most significant bit set (draft §3.3.1 prepends at least one zero bit
/// so that pads never collide with the KDF's `index ≥ 128` blocks).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidNonce;

impl core::fmt::Display for InvalidNonce {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("VMAC nonce must be at most 127 bits (16 bytes with the top bit clear)")
    }
}

impl core::error::Error for InvalidNonce {}

/// Checks the nonce length rule and returns the 16-byte block
/// `zeros || Nonce` the PDF encrypts (draft §3.3.1).
fn nonce_block(nonce: &[u8]) -> Result<[u8; 16], InvalidNonce> {
    if nonce.len() > 16 || (nonce.len() == 16 && nonce[0] & 0x80 != 0) {
        return Err(InvalidNonce);
    }
    let mut block = [0u8; 16];
    block[16 - nonce.len()..].copy_from_slice(nonce);
    Ok(block)
}

/// VHASH state for `ITER` 64-bit output words, generic over the cipher.
#[derive(Clone)]
struct VmacInner<C: BlockCipher, const ITER: usize> {
    cipher: C,
    /// L1 keys as big-endian words; iteration `i` uses `l1_key[2i..2i+16]`.
    l1_key: [u64; L1_KEY_WORDS],
    /// L2 keys, post-mask, per iteration.
    l2_key: [u128; ITER],
    /// L3 key words `(k₁, k₂)` per iteration, both `< p64`.
    l3_key: [(u64, u64); ITER],
    /// Polynomial accumulator per iteration.
    poly: [u128; ITER],
    /// 128-byte block buffer for streaming.
    block: [u8; L1_BLOCK],
    block_off: usize,
    /// Total bytes absorbed.
    total_bytes: u64,
}

impl<C: BlockCipher, const ITER: usize> VmacInner<C, ITER> {
    fn new(cipher: C) -> Self {
        const { assert!(ITER >= 1 && ITER <= MAX_ITER) };

        // L1: KDF(K, 128, 1024 + 128·(ITER−1)) bits, as big-endian words.
        let mut l1_bytes = [0u8; 8 * L1_KEY_WORDS];
        let l1_len = L1_BLOCK + 16 * (ITER - 1);
        kdf(&cipher, KDF_L1, &mut l1_bytes[..l1_len]);
        let mut l1_key = [0u64; L1_KEY_WORDS];
        for (w, chunk) in l1_key.iter_mut().zip(l1_bytes.chunks_exact(8)) {
            *w = u64::from_be_bytes(chunk.try_into().expect("8 bytes"));
        }
        l1_bytes.zeroize();

        // L2: the (iter+1)-th 16-byte block of KDF(K, 192), masked.
        let mut l2_bytes = [0u8; 16 * MAX_ITER];
        kdf(&cipher, KDF_L2, &mut l2_bytes[..16 * ITER]);
        let mut l2_key = [0u128; ITER];
        for (k, chunk) in l2_key.iter_mut().zip(l2_bytes.chunks_exact(16)) {
            *k = u128::from_be_bytes(chunk.try_into().expect("16 bytes")) & L2_MASK;
        }
        l2_bytes.zeroize();

        let l3_key = Self::l3_keys(&cipher);

        Self {
            cipher,
            l1_key,
            l2_key,
            l3_key,
            poly: [1; ITER],
            block: [0; L1_BLOCK],
            block_off: 0,
            total_bytes: 0,
        }
    }

    /// Draft §5.5: the L3 key for iteration `i` is the `(i+1)`-th 16-byte
    /// block of KDF(K, 224) whose two big-endian halves are both below
    /// `p64`. The acceptance test is on secret key material, so instead of
    /// looping until enough blocks pass, a fixed window of [`L3_WINDOW`]
    /// blocks is scanned and each iteration's key is picked out with masks
    /// keyed on the running count of accepted blocks. The window comes up
    /// short only with probability about 2⁻³³⁰; that (data-dependent)
    /// remainder falls back to the draft's loop.
    fn l3_keys(cipher: &C) -> [(u64, u64); ITER] {
        let mut out = [(0u64, 0u64); ITER];
        let mut buf = [0u8; 16 * L3_WINDOW];
        kdf(cipher, KDF_L3, &mut buf);
        // Number of accepted blocks so far, kept as a mask-friendly integer.
        let mut accepted: u64 = 0;
        for chunk in buf.chunks_exact(16) {
            let k1 = u64::from_be_bytes(chunk[..8].try_into().expect("8 bytes"));
            let k2 = u64::from_be_bytes(chunk[8..].try_into().expect("8 bytes"));
            let ok = mask64(k1 < P64 && k2 < P64);
            for (i, slot) in out.iter_mut().enumerate() {
                let sel = ok & mask64(accepted == i as u64);
                slot.0 |= k1 & sel;
                slot.1 |= k2 & sel;
            }
            accepted += ok & 1;
        }
        buf.zeroize();
        if accepted < ITER as u64 {
            Self::l3_keys_tail(cipher, &mut out, accepted as usize);
        }
        out
    }

    /// Continues the L3 key search past the fixed window, in the draft's
    /// plain loop form. Practically unreachable (see [`Self::l3_keys`]).
    #[cold]
    fn l3_keys_tail(cipher: &C, out: &mut [(u64, u64); ITER], mut accepted: usize) {
        let mut block = [0u8; 16];
        block[0] = KDF_L3;
        let mut counter = L3_WINDOW as u64;
        while accepted < ITER {
            block[8..16].copy_from_slice(&counter.to_be_bytes());
            let mut t = block;
            cipher.encrypt_block(&mut t);
            let k1 = u64::from_be_bytes(t[..8].try_into().expect("8 bytes"));
            let k2 = u64::from_be_bytes(t[8..].try_into().expect("8 bytes"));
            if k1 < P64 && k2 < P64 {
                out[accepted] = (k1, k2);
                accepted += 1;
            }
            counter += 1;
        }
    }

    /// Absorbs one (zero-padded, 16-byte-multiple) NH block into every
    /// iteration's polynomial.
    fn absorb_block(&mut self, data: &[u8]) {
        for i in 0..ITER {
            let m = nh(&self.l1_key[2 * i..2 * i + 16], data);
            self.poly[i] = add_mod_p127(mul_mod_p127(self.poly[i], self.l2_key[i]), m);
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let take = (L1_BLOCK - self.block_off).min(data.len());
            self.block[self.block_off..self.block_off + take].copy_from_slice(&data[..take]);
            self.block_off += take;
            self.total_bytes = self.total_bytes.wrapping_add(take as u64);
            data = &data[take..];
            if self.block_off == L1_BLOCK {
                let block = self.block;
                self.absorb_block(&block);
                self.block_off = 0;
            }
        }
    }

    /// Finishes VHASH and writes `ITER` big-endian words into `out`, then
    /// adds the pad for `nonce` word by word (draft §4.1).
    fn finalize_into(&mut self, nonce: &[u8], out: &mut [u8]) -> Result<(), InvalidNonce> {
        debug_assert_eq!(out.len(), 8 * ITER);
        let mut pad = nonce_block(nonce)?;
        if ITER == 1 {
            // taglen 64: the nonce's low bit selects the pad half and is
            // cleared before encryption (draft §3.3.1). The nonce is public,
            // so indexing on it is fine.
            let index = (pad[15] & 1) as usize;
            pad[15] &= !1;
            self.cipher.encrypt_block(&mut pad);
            pad.copy_within(8 * index..8 * index + 8, 0);
        } else {
            self.cipher.encrypt_block(&mut pad);
        }

        // L1/L2 close-out: a trailing partial block is zero-padded to a
        // multiple of 16 bytes; an empty message has no NH output at all and
        // L2 yields the key itself (draft §5.4).
        if self.total_bytes == 0 {
            self.poly = self.l2_key;
        } else if self.block_off > 0 {
            let padded = self.block_off.div_ceil(16) * 16;
            self.block[self.block_off..padded].fill(0);
            let mut block = [0u8; L1_BLOCK];
            block[..padded].copy_from_slice(&self.block[..padded]);
            self.absorb_block(&block[..padded]);
            block.zeroize();
        }
        let len_term = (((self.total_bytes % L1_BLOCK as u64) * 8) as u128) << 64;

        for i in 0..ITER {
            let y = add_mod_p127(self.poly[i], len_term);
            // L3-HASH.
            let (m1, m2) = l3_split(y);
            let (k1, k2) = self.l3_key[i];
            let h = mul_mod_p64(add_mod_p64(m1, k1), add_mod_p64(m2, k2));
            let p = u64::from_be_bytes(pad[8 * i..8 * i + 8].try_into().expect("8 bytes"));
            out[8 * i..8 * i + 8].copy_from_slice(&p.wrapping_add(h).to_be_bytes());
        }
        pad.zeroize();
        Ok(())
    }
}

impl<C: BlockCipher, const ITER: usize> Drop for VmacInner<C, ITER> {
    fn drop(&mut self) {
        // The cipher wipes its own round keys. Everything else is key
        // material derived through the KDF, buffered plaintext, or a keyed
        // function of the message.
        self.l1_key.zeroize();
        self.l2_key.zeroize();
        for k in self.l3_key.iter_mut() {
            k.0.zeroize();
            k.1.zeroize();
        }
        self.poly.zeroize();
        self.block.zeroize();
        self.block_off = 0;
        self.total_bytes = 0;
    }
}

impl<C: BlockCipher, const ITER: usize> ZeroizeOnDrop for VmacInner<C, ITER> {}

// ---------------------------------------------------------------------------
//  Public types
// ---------------------------------------------------------------------------

macro_rules! vmac_type {
    ($name:ident, $iter:literal, $bytes:literal, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Construct with `new` (AES-128) or `with_cipher` (any 128-bit
        /// block cipher), absorb input via `update` / `chain`, and commit
        /// with `finalize` given the per-message nonce, or check a received
        /// tag with `verify`. The nonce must be at most 127 bits (up to 15
        /// bytes, or 16 bytes with the top bit clear; anything longer is an
        /// [`InvalidNonce`] error) and must not repeat under the same key.
        #[derive(Clone)]
        pub struct $name<C: BlockCipher = Aes128> {
            inner: VmacInner<C, $iter>,
        }

        impl $name<Aes128> {
            /// Creates a new state under a 128-bit AES key.
            pub fn new(key: &[u8; 16]) -> Self {
                Self::with_cipher(Aes128::new(key))
            }

            /// One-shot: the tag of `data` with `nonce` under the AES-128
            /// `key`. Fails only for an over-long nonce.
            pub fn compute(
                key: &[u8; 16],
                data: &[u8],
                nonce: &[u8],
            ) -> Result<[u8; $bytes], InvalidNonce> {
                Self::new(key).chain(data).finalize(nonce)
            }
        }

        impl<C: BlockCipher> $name<C> {
            /// Creates a new state from a pre-keyed 128-bit block cipher.
            pub fn with_cipher(cipher: C) -> Self {
                Self {
                    inner: VmacInner::new(cipher),
                }
            }

            /// Absorbs `data` into the streaming state.
            pub fn update(&mut self, data: &[u8]) {
                self.inner.update(data);
            }

            /// Absorbs `data` and returns the state, for one-line
            /// construction.
            #[must_use]
            pub fn chain(mut self, data: &[u8]) -> Self {
                self.update(data);
                self
            }

            /// Finalizes the MAC and returns the tag. `nonce` must be at most
            /// 127 bits (up to 15 bytes, or 16 bytes with the top bit clear)
            /// and unique per key; a longer nonce is an [`InvalidNonce`]
            /// error.
            pub fn finalize(mut self, nonce: &[u8]) -> Result<[u8; $bytes], InvalidNonce> {
                let mut tag = [0u8; $bytes];
                self.inner.finalize_into(nonce, &mut tag)?;
                Ok(tag)
            }

            /// Consumes the MAC and checks the tag for `nonce` against
            /// `expected` in constant time.
            ///
            /// Returns `true` iff `nonce` is valid and `expected` is a
            /// full-length tag equal to the recomputed tag. Truncated tags
            /// (including the empty slice) are rejected unconditionally:
            /// accepting a short `n`-byte prefix would drop forgery
            /// resistance to `2^(8n)`, and an empty tag would be an
            /// unconditional accept. The comparison time of the full-length
            /// path depends only on the (public) tag length, not on where
            /// any mismatch occurs, and the recomputed tag is wiped before
            /// returning.
            pub fn verify(self, nonce: &[u8], expected: &[u8]) -> bool {
                if expected.len() != $bytes {
                    return false;
                }
                let Ok(mut tag) = self.finalize(nonce) else {
                    return false;
                };
                let ok = bool::from(tag[..].ct_eq(expected));
                tag.zeroize();
                ok
            }
        }
    };
}

vmac_type!(
    Vmac64,
    1,
    8,
    "VMAC-64 (draft-krovetz-vmac-01 §4.2): an 8-byte tag from one VHASH iteration."
);
vmac_type!(
    Vmac128,
    2,
    16,
    "VMAC-128 (draft-krovetz-vmac-01 §4.2): a 16-byte tag from two VHASH iterations."
);

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{Aes192, Aes256};

    fn from_hex<const N: usize>(s: &str) -> [u8; N] {
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), 2 * N, "hex string has wrong length");
        let mut out = [0u8; N];
        for i in 0..N {
            let hi = (bytes[2 * i] as char).to_digit(16).expect("hex") as u8;
            let lo = (bytes[2 * i + 1] as char).to_digit(16).expect("hex") as u8;
            out[i] = (hi << 4) | lo;
        }
        out
    }

    const KEY: &[u8; 16] = b"abcdefghijklmnop";
    const NONCE: &[u8; 8] = b"bcdefghi";

    /// Draft appendix: `'abc'` repeated `reps` times, with the 64- and
    /// 128-bit tags under `K = "abcdefghijklmnop"`, `N = "bcdefghi"`.
    const DRAFT_VECTORS: [(usize, &str, &str); 5] = [
        (0, "2576BE1C56D8B81B", "472766C70F74ED23481D6D7DE4E80DAC"),
        (1, "2D376CF5B1813CE5", "4EE815A06A1D71EDD36FC75D51188A42"),
        (16, "E8421F61D573D298", "09F2C80C8E1007A0C12FAE19FE4504AE"),
        (100, "4492DF6C5CAC1BBE", "66438817154850C61D8A412164803BCB"),
        (
            1_000_000,
            "09BA597DD7601113",
            "2B6B02288FFC461B75485DE893C629DC",
        ),
    ];

    #[test]
    fn draft_vectors() {
        for &(reps, t64, t128) in &DRAFT_VECTORS {
            if cfg!(miri) && reps > 1000 {
                continue;
            }
            let mut s64 = Vmac64::new(KEY);
            let mut s128 = Vmac128::new(KEY);
            // Feed the pattern in irregular pieces so the block buffer is
            // exercised at every offset.
            let mut i = 0;
            while i < reps {
                let n = ((i % 37) + 1).min(reps - i);
                for _ in 0..n {
                    s64.update(b"abc");
                }
                let mut chunk = [0u8; 3 * 37];
                for j in 0..n {
                    chunk[3 * j..3 * j + 3].copy_from_slice(b"abc");
                }
                s128.update(&chunk[..3 * n]);
                i += n;
            }
            let expected64: [u8; 8] = from_hex(t64);
            let expected128: [u8; 16] = from_hex(t128);
            assert_eq!(
                s64.clone().finalize(NONCE).unwrap(),
                expected64,
                "'abc' x{reps}"
            );
            assert!(s64.verify(NONCE, &expected64));
            assert_eq!(
                s128.clone().finalize(NONCE).unwrap(),
                expected128,
                "'abc' x{reps}"
            );
            assert!(s128.verify(NONCE, &expected128));
        }
    }

    #[test]
    fn wycheproof_samples_other_key_sizes() {
        // Wycheproof cases under AES-192 and AES-256 (the full files run in
        // the integration harness): `vmac_64` tcIds 320 and 560 ("special
        // case for l1_hash").
        let key192: [u8; 24] = from_hex("000102030405060708090a0b0c0d0e0f1011121314151617");
        let key256: [u8; 32] =
            from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let nonce: [u8; 8] = from_hex("1011121314151617");
        let msg: [u8; 16] = from_hex("6c21893d4e4d9cf2b84125c9820c4df9");
        let tag = Vmac64::with_cipher(Aes192::new(&key192))
            .chain(&msg)
            .finalize(&nonce)
            .unwrap();
        assert_eq!(tag, from_hex("62c0959bf8f4d269"));
        let msg: [u8; 16] = from_hex("7841a418d00adf9976c26bdbf9738ad4");
        let tag = Vmac64::with_cipher(Aes256::new(&key256))
            .chain(&msg)
            .finalize(&nonce)
            .unwrap();
        assert_eq!(tag, from_hex("7bea9e0e5b861b75"));

        // `vmac_128` tcIds 262 and 508 (`Pseudorandom`, "short message").
        let key192: [u8; 24] = from_hex("b991805ad2d8ca1b18b79e33c36ec2fa02f62099d8a5c113");
        let nonce: [u8; 8] = from_hex("06f2aadd3e8a920f");
        let msg: [u8; 8] = from_hex("ba7f9377c3195fbd");
        let tag = Vmac128::with_cipher(Aes192::new(&key192))
            .chain(&msg)
            .finalize(&nonce)
            .unwrap();
        assert_eq!(tag, from_hex("a8827b5d069e00d75a458cc19933ad68"));
        let key256: [u8; 32] =
            from_hex("2a1acc7e1cb654a694c28e9254fe2602831bf1efeb5c256e748cc0a440817d3d");
        let nonce: [u8; 8] = from_hex("368a0ca58c454784");
        let msg: [u8; 8] = from_hex("8c0b66622e52839d");
        let tag = Vmac128::with_cipher(Aes256::new(&key256))
            .chain(&msg)
            .finalize(&nonce)
            .unwrap();
        assert_eq!(tag, from_hex("7b63e9dc799bdc4f395f97e773acc19c"));
    }

    #[test]
    fn nonce_rules() {
        let tag = Vmac64::compute(KEY, b"abc", NONCE).unwrap();
        // 17 bytes: too long.
        assert_eq!(Vmac64::compute(KEY, b"abc", &[0u8; 17]), Err(InvalidNonce));
        assert!(!Vmac64::new(KEY).chain(b"abc").verify(&[0u8; 17], &tag));
        // 16 bytes with the top bit set: rejected; with it clear: accepted
        // and identical to the 15-byte nonce it left-pads.
        let mut n16 = [0u8; 16];
        n16[8..].copy_from_slice(NONCE);
        n16[0] = 0x80;
        assert_eq!(Vmac64::compute(KEY, b"abc", &n16), Err(InvalidNonce));
        assert_eq!(Vmac128::compute(KEY, b"abc", &n16), Err(InvalidNonce));
        n16[0] = 0x00;
        assert_eq!(Vmac64::compute(KEY, b"abc", &n16).unwrap(), tag);
        assert_eq!(
            Vmac128::compute(KEY, b"abc", &n16).unwrap(),
            Vmac128::compute(KEY, b"abc", NONCE).unwrap()
        );
        assert_eq!(Vmac64::compute(KEY, b"abc", &n16[1..]).unwrap(), tag);
        // The empty nonce is a legal (zero-length) nonce.
        assert!(Vmac64::compute(KEY, b"abc", b"").is_ok());
        // VMAC-64: nonces differing only in the low bit share a cipher call
        // but select different pad halves, so the tags differ.
        let mut odd = *NONCE;
        odd[7] |= 1;
        let mut even = *NONCE;
        even[7] &= !1;
        assert_ne!(
            Vmac64::compute(KEY, b"abc", &odd).unwrap(),
            Vmac64::compute(KEY, b"abc", &even).unwrap()
        );
    }

    #[test]
    fn verify_is_length_strict() {
        let tag = Vmac64::compute(KEY, b"abc", NONCE).unwrap();
        let state = Vmac64::new(KEY).chain(b"abc");
        assert!(state.clone().verify(NONCE, &tag));
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(!state.clone().verify(NONCE, &bad));
        assert!(!state.clone().verify(NONCE, &tag[..7]));
        assert!(!state.clone().verify(NONCE, &[]));
        assert!(!state.verify(b"bcdefghj", &tag));

        let tag = Vmac128::compute(KEY, b"abc", NONCE).unwrap();
        let state = Vmac128::new(KEY).chain(b"abc");
        assert!(state.clone().verify(NONCE, &tag));
        let mut bad = tag;
        bad[15] ^= 0x80;
        assert!(!state.clone().verify(NONCE, &bad));
        assert!(!state.clone().verify(NONCE, &tag[..15]));
        assert!(!state.clone().verify(NONCE, &[]));
        // A VMAC-64 tag is not a truncated VMAC-128 tag (and is rejected as
        // a length mismatch regardless).
        assert!(!state.verify(NONCE, &Vmac64::compute(KEY, b"abc", NONCE).unwrap()));
    }

    #[test]
    fn streaming_matches_one_shot() {
        let mut data = [0u8; 3000];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        let one_shot = Vmac64::compute(KEY, &data, NONCE).unwrap();
        let one_shot_128 = Vmac128::compute(KEY, &data, NONCE).unwrap();
        let splits: [usize; 9] = [1, 7, 127, 128, 129, 16, 17, 600, 1000];
        let mut s = Vmac64::new(KEY);
        let mut s128 = Vmac128::new(KEY);
        let mut off = 0;
        let mut idx = 0;
        while off < data.len() {
            let take = splits[idx % splits.len()].min(data.len() - off);
            s.update(&data[off..off + take]);
            s128.update(&data[off..off + take]);
            off += take;
            idx += 1;
        }
        assert_eq!(s.finalize(NONCE).unwrap(), one_shot);
        assert_eq!(s128.finalize(NONCE).unwrap(), one_shot_128);
    }

    /// The branchless arithmetic must agree with the textbook `%` / `/`
    /// forms on random and edge inputs, in particular the L3 split and the
    /// carry cases of the folded reductions.
    #[test]
    fn branchless_arithmetic_matches_reference() {
        fn xorshift(s: &mut u64) -> u64 {
            *s ^= *s << 13;
            *s ^= *s >> 7;
            *s ^= *s << 17;
            *s
        }
        let mut s = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || xorshift(&mut s);
        let mut t = 0x2545_f491_4f6c_dd1du64;
        let mut next128 = || ((xorshift(&mut t) as u128) << 64) | xorshift(&mut t) as u128;

        // Small-number reference for the L2 polynomial step.
        fn mulmod_ref(a: u128, b: u128) -> u128 {
            // Double-and-add with everything kept below 2¹²⁸.
            let mut acc: u128 = 0;
            let mut a = a % P127;
            let mut b = b;
            while b > 0 {
                if b & 1 == 1 {
                    acc = (acc + a) % P127;
                }
                a = (a * 2) % P127;
                b >>= 1;
            }
            acc
        }

        let edges128 = [
            0u128,
            1,
            P127 - 1,
            P127,
            P127 + 1,
            (1u128 << 126) - 1,
            L3_SPLIT - 1,
            L3_SPLIT,
            L3_SPLIT + 1,
            u128::MAX >> 1,
            (1u128 << 64) - 1,
            1u128 << 64,
            (1u128 << 96) - (1u128 << 64),
            (1u128 << 96) | 0xffff_ffff,
            ((1u128 << 63) << 64) | ((1u128 << 64) - 1),
        ];
        for &x in &edges128 {
            let y = x & (u128::MAX >> 1); // < 2¹²⁷
            let (q, r) = l3_split(y);
            assert_eq!(q as u128, y / L3_SPLIT, "split q {y:#x}");
            assert_eq!(r as u128, y % L3_SPLIT, "split r {y:#x}");
            assert_eq!(reduce_p127(x), x % P127, "reduce_p127 {x:#x}");
        }
        for &a in &[0u64, 1, P64 - 1, P64, P64 + 1, u64::MAX] {
            for &b in &[0u64, 1, P64 - 1, u64::MAX - 300, u64::MAX] {
                let b = b % P64;
                assert_eq!(
                    add_mod_p64(a, b),
                    ((a as u128 + b as u128) % P64 as u128) as u64
                );
                let a = a % P64;
                assert_eq!(
                    mul_mod_p64(a, b),
                    ((a as u128 * b as u128) % P64 as u128) as u64
                );
            }
        }

        for _ in 0..3_000 {
            let y = next128() >> 1;
            let (q, r) = l3_split(y);
            assert_eq!(q as u128, y / L3_SPLIT, "split q {y:#x}");
            assert_eq!(r as u128, y % L3_SPLIT, "split r {y:#x}");

            let a = next();
            let b = next() % P64;
            assert_eq!(
                add_mod_p64(a, b),
                ((a as u128 + b as u128) % P64 as u128) as u64
            );
            let a = a % P64;
            assert_eq!(
                mul_mod_p64(a, b),
                ((a as u128 * b as u128) % P64 as u128) as u64
            );

            let a = next128() >> 1;
            let k = next128() & L2_MASK;
            assert_eq!(
                mul_mod_p127(a, k),
                mulmod_ref(a, k),
                "mul_mod_p127 {a:#x} {k:#x}"
            );
            let m = next128() & NH_MASK;
            assert_eq!(add_mod_p127(a % P127, m), (a % P127 + m) % P127);
        }
    }
}
