//! AEZ v5 — robust authenticated-encryption by enciphering
//! (Hoang–Krovetz–Rogaway, "AEZ v5", March 2017).
//!
//! AEZ is an authenticated-encryption scheme built entirely from the AES round
//! function. Unlike a conventional nonce-based AEAD it *enciphers*: the
//! ciphertext is the plaintext plus a user-chosen expansion of `tau` bytes (the
//! authenticator), and decryption succeeds only if that expansion decrypts back
//! to zeros. This yields three notable properties:
//!
//! * **Nonce-misuse resistance** — reusing a nonce leaks only whether two
//!   (nonce, AD, message) triples are equal; it is not catastrophic the way
//!   nonce reuse is for GCM. (Unique nonces are still recommended.)
//! * **Arbitrary, caller-chosen expansion `tau`** — pick the authenticator
//!   strength you want, including `tau = 0`.
//! * **Vector-valued associated data** — authenticate any number of AD strings.
//!
//! AEZ is a CAESAR candidate; it is well analyzed but not standardized or used
//! in TLS, so it is provided here as a toolkit primitive. Like [`AEGIS`] it is
//! constant-time on a constant-time AES core (this crate's software AES round is
//! table-free; the round is not yet hardware-accelerated, so AEZ currently runs
//! at software-AES speed).
//!
//! ```
//! use purecrypto::cipher::Aez;
//! let aez = Aez::new(b"a 16, 32, or 48-byte key, or any length");
//! let ct = aez.encrypt(b"nonce", &[b"associated data".as_slice()], 16, b"hello");
//! let pt = aez.decrypt(b"nonce", &[b"associated data".as_slice()], 16, &ct).unwrap();
//! assert_eq!(pt, b"hello");
//! ```
//!
//! [`AEGIS`]: super::Aegis128L

use super::TagMismatch;
use super::aes::aes_round;
use crate::ct::ConstantTimeEq;
use crate::hash::{Blake2b384, Digest};
use alloc::vec;
use alloc::vec::Vec;

const BLOCK: usize = 16;
type Block = [u8; BLOCK];
const ZERO: Block = [0u8; BLOCK];

#[inline]
fn xor16(a: &Block, b: &Block) -> Block {
    let mut o = [0u8; BLOCK];
    for i in 0..BLOCK {
        o[i] = a[i] ^ b[i];
    }
    o
}

#[inline]
fn xor_into(dst: &mut Block, a: &Block) {
    for i in 0..BLOCK {
        dst[i] ^= a[i];
    }
}

#[inline]
fn rd(buf: &[u8], off: usize) -> Block {
    let mut b = [0u8; BLOCK];
    b.copy_from_slice(&buf[off..off + BLOCK]);
    b
}

#[inline]
fn wr(buf: &mut [u8], off: usize, b: &Block) {
    buf[off..off + BLOCK].copy_from_slice(b);
}

/// `dst = 2 · src` in GF(2¹²⁸) (the GCM/AEZ doubling: left-shift the 128-bit
/// big-endian value by one bit, reduce by `0x87` on carry-out). Constant-time.
fn double_block(p: &mut Block) {
    let top = p[0] >> 7;
    for i in 0..15 {
        p[i] = (p[i] << 1) | (p[i + 1] >> 7);
    }
    // 0x00 or 0x87, branchlessly on the (public) top bit.
    p[15] = (p[15] << 1) ^ (0u8.wrapping_sub(top) & 0x87);
}

/// `x · src` in GF(2¹²⁸) for a small non-negative integer `x`, via binary
/// doubling. `x` is a public tweak coefficient, never secret.
fn mult_block(mut x: u32, src: &Block) -> Block {
    let mut t = *src;
    let mut r = ZERO;
    while x != 0 {
        if x & 1 != 0 {
            xor_into(&mut r, &t);
        }
        double_block(&mut t);
        x >>= 1;
    }
    r
}

/// One-zero pad: `dst = src[..sz] ‖ 0x80 ‖ 0…0`.
fn one_zero_pad(src: &[u8], sz: usize) -> Block {
    let mut dst = ZERO;
    dst[..sz].copy_from_slice(&src[..sz]);
    dst[sz] = 0x80;
    dst
}

/// AEZ key state: the extracted subkeys I, J, L and their precomputed GF
/// multiples, exactly as the reference `eState` stores them.
pub struct Aez {
    i: [Block; 2], // 1I, 2I
    j: [Block; 3], // 1J, 2J, 4J
    l: [Block; 8], // 0L (=0), 1L … 7L
}

impl Drop for Aez {
    fn drop(&mut self) {
        for b in self
            .i
            .iter_mut()
            .chain(self.j.iter_mut())
            .chain(self.l.iter_mut())
        {
            *b = ZERO;
        }
        core::hint::black_box(&self.i);
    }
}

impl Aez {
    /// Derives the AEZ subkeys from a key of any length (AEZ `Extract`): a
    /// 48-byte key is used directly as `I‖J‖L`; any other length is run through
    /// BLAKE2b to a 48-byte digest first.
    pub fn new(key: &[u8]) -> Self {
        let ek: [u8; 48] = if key.len() == 48 {
            let mut e = [0u8; 48];
            e.copy_from_slice(key);
            e
        } else {
            Blake2b384::digest(key)
        };

        let mut i = [ZERO; 2];
        let mut j = [ZERO; 3];
        let mut l = [ZERO; 8];
        i[0].copy_from_slice(&ek[0..16]); // 1I
        i[1] = mult_block(2, &i[0]); // 2I
        j[0].copy_from_slice(&ek[16..32]); // 1J
        j[1] = mult_block(2, &j[0]); // 2J
        j[2] = mult_block(2, &j[1]); // 4J
        l[1].copy_from_slice(&ek[32..48]); // 1L
        l[2] = mult_block(2, &l[1]); // 2L
        l[3] = xor16(&l[2], &l[1]); // 3L
        l[4] = mult_block(2, &l[2]); // 4L
        l[5] = xor16(&l[4], &l[1]); // 5L
        l[6] = mult_block(2, &l[3]); // 6L
        l[7] = xor16(&l[6], &l[1]); // 7L
        Aez { i, j, l }
    }

    /// The scaled-down tweakable block cipher `E_K^{j,i}` for `j ≠ -1`:
    /// four AES rounds (keys 1J, 1I, 1L, 0) over `src ⊕ off_j ⊕ off_i ⊕ off_l`,
    /// where the offsets are the caller-selected GF multiples that encode the
    /// tweak.
    #[inline]
    fn aes4(&self, off_j: &Block, off_i: &Block, off_l: &Block, src: &Block) -> Block {
        let mut x = xor16(src, off_j);
        xor_into(&mut x, off_i);
        xor_into(&mut x, off_l);
        let t = aes_round(x, self.j[0]); // 1J
        let t = aes_round(t, self.i[0]); // 1I
        let t = aes_round(t, self.l[1]); // 1L
        aes_round(t, ZERO)
    }

    /// `E_K^{-1,i}`: ten AES rounds (keys 1I,1J,1L repeating) over `src ⊕ off_l`,
    /// where `off_l = i · L`.
    #[inline]
    fn aes10(&self, off_l: &Block, src: &Block) -> Block {
        let mut t = xor16(src, off_l);
        let keys = [
            self.i[0], self.j[0], self.l[1], self.i[0], self.j[0], self.l[1], self.i[0], self.j[0],
            self.l[1], self.i[0],
        ];
        for k in keys {
            t = aes_round(t, k);
        }
        t
    }

    /// AEZ-hash: AXU hash of the tweak vector `([tau]₁₂₈, nonce, ad…)` to a
    /// 128-bit `Δ`. `tau_bits` is the expansion in *bits*.
    fn aez_hash(&self, nonce: &[u8], ad: &[&[u8]], tau_bits: u32) -> Block {
        let mut sum;

        // T1 = [tau]_128, tweak (3,1): E(3,1) with j-offset 3J = 1J ⊕ 2J.
        let mut buf = ZERO;
        buf[12..16].copy_from_slice(&tau_bits.to_be_bytes());
        let j3 = xor16(&self.j[0], &self.j[1]);
        sum = self.aes4(&j3, &self.i[1], &self.l[1], &buf);

        // T2 = nonce, tweak (4,i): j-offset 4J.
        self.hash_component(&self.j[2], nonce, &mut sum);

        // T(3+k) = ad[k], tweak (5+k, i): j-offset (5+k)·J.
        for (k, p) in ad.iter().enumerate() {
            let jk = mult_block(5 + k as u32, &self.j[0]);
            self.hash_component(&jk, p, &mut sum);
        }
        sum
    }

    /// Absorbs one tweak-vector element `data` under the fixed j-offset `oj`,
    /// XORing each `E(j, i)` block into `sum`. Mirrors the per-element loop used
    /// for the nonce and each AD string (including the empty/partial last block).
    fn hash_component(&self, oj: &Block, data: &[u8], sum: &mut Block) {
        let empty = data.is_empty();
        let mut ii = self.i[1]; // running 2^ceil(i/8) · I, starting at 2I
        let mut i: u32 = 1;
        let mut off = 0;
        let mut remaining = data.len();
        while remaining >= BLOCK {
            let blk = rd(data, off);
            let e = self.aes4(oj, &ii, &self.l[(i % 8) as usize], &blk);
            xor_into(sum, &e);
            off += BLOCK;
            remaining -= BLOCK;
            if i.is_multiple_of(8) {
                double_block(&mut ii);
            }
            i += 1;
        }
        if remaining > 0 || empty {
            let blk = one_zero_pad(&data[off..], remaining);
            let e = self.aes4(oj, &self.i[0], &self.l[0], &blk); // E(j,0)
            xor_into(sum, &e);
        }
    }

    /// AEZ-prf: keystream `(E^{-1,3}(Δ) ‖ E^{-1,3}(Δ⊕1) ‖ …)[..tau]`.
    fn aez_prf(&self, delta: &Block, tau: usize) -> Vec<u8> {
        let mut out = vec![0u8; tau];
        let mut ctr = ZERO;
        let mut off = 0;
        while off < tau {
            let buf = self.aes10(&self.l[3], &xor16(delta, &ctr)); // E(-1,3)
            let n = (tau - off).min(BLOCK);
            out[off..off + n].copy_from_slice(&buf[..n]);
            // ctr += 1 (big-endian, 128-bit)
            let mut k = 15;
            loop {
                ctr[k] = ctr[k].wrapping_add(1);
                if ctr[k] != 0 {
                    break;
                }
                if k == 0 {
                    break;
                }
                k -= 1;
            }
            off += BLOCK;
        }
        out
    }

    /// AEZ-core pass 1 (in place over the i-blocks): computes `X` and writes the
    /// first-Feistel-round intermediates back into `buf`.
    fn core_pass1(&self, buf: &mut [u8], x: &mut Block) {
        let mut ii = self.i[1];
        let mut i: u32 = 1;
        let mut off = 0usize;
        let mut remaining = buf.len();
        while remaining >= 64 {
            let m0 = rd(buf, off);
            let m1 = rd(buf, off + BLOCK);
            let t = self.aes4(&self.j[0], &ii, &self.l[(i % 8) as usize], &m1); // E(1,i)
            let o0 = xor16(&m0, &t);
            wr(buf, off, &o0);
            let t = self.aes4(&ZERO, &self.i[0], &self.l[0], &o0); // E(0,0)
            let o1 = xor16(&m1, &t);
            wr(buf, off + BLOCK, &o1);
            xor_into(x, &o1);
            off += 32;
            remaining -= 32;
            if i.is_multiple_of(8) {
                double_block(&mut ii);
            }
            i += 1;
        }
    }

    /// AEZ-core pass 2 (in place over the i-blocks): injects `S` and completes
    /// the second Feistel rounds, computing `Y` and the final i-block ciphertext.
    fn core_pass2(&self, buf: &mut [u8], y: &mut Block, s: &Block) {
        let mut ii = self.i[1];
        let mut i: u32 = 1;
        let mut off = 0usize;
        let mut remaining = buf.len();
        while remaining >= 64 {
            let t = self.aes4(&self.j[1], &ii, &self.l[(i % 8) as usize], s); // E(2,i)
            let mut o0 = xor16(&rd(buf, off), &t);
            let mut o1 = xor16(&rd(buf, off + BLOCK), &t);
            xor_into(y, &o0);
            let t = self.aes4(&ZERO, &self.i[0], &self.l[0], &o1); // E(0,0)
            xor_into(&mut o0, &t);
            let t = self.aes4(&self.j[0], &ii, &self.l[(i % 8) as usize], &o0); // E(1,i)
            xor_into(&mut o1, &t);
            // swap the two blocks on write-back
            wr(buf, off, &o1);
            wr(buf, off + BLOCK, &o0);
            off += 32;
            remaining -= 32;
            if i.is_multiple_of(8) {
                double_block(&mut ii);
            }
            i += 1;
        }
    }

    /// AEZ-core: encipher (`d = 0`) or decipher (`d = 1`) a buffer of ≥ 32 bytes
    /// in place. The only direction-dependence is the two `L` tweak indices.
    fn aez_core(&self, delta: &Block, buf: &mut [u8], d: usize) {
        let total = buf.len();
        let mut frag_bytes = total % 32;
        let initial_bytes = total - frag_bytes - 32;

        // Pass 1 over the i-blocks (the >= 64 loop bound stops before the final
        // 32 bytes + any fragment, so the full buffer can be passed).
        let mut x = ZERO;
        if total >= 64 {
            self.core_pass1(buf, &mut x);
        }

        // Finish X over the fragment region (still original here).
        let fpos = initial_bytes;
        if frag_bytes >= BLOCK {
            let t = self.aes4(&ZERO, &self.i[1], &self.l[4], &rd(buf, fpos)); // E(0,4)
            xor_into(&mut x, &t);
            let pad = one_zero_pad(&buf[fpos + BLOCK..], frag_bytes - BLOCK);
            let t = self.aes4(&ZERO, &self.i[1], &self.l[5], &pad); // E(0,5)
            xor_into(&mut x, &t);
        } else if frag_bytes > 0 {
            let pad = one_zero_pad(&buf[fpos..], frag_bytes);
            let t = self.aes4(&ZERO, &self.i[1], &self.l[4], &pad); // E(0,4)
            xor_into(&mut x, &t);
        }

        // Calculate S over the last two blocks (Mx, My).
        let xy = total - 32;
        let mx = rd(buf, xy);
        let my = rd(buf, xy + BLOCK);
        let t = self.aes4(&ZERO, &self.i[1], &self.l[(1 + d) % 8], &my); // E(0,1+d)
        let mut sx = x;
        xor_into(&mut sx, &mx);
        xor_into(&mut sx, delta);
        xor_into(&mut sx, &t);
        wr(buf, xy, &sx);
        let t = self.aes10(&self.l[(1 + d) % 8], &sx); // E(-1,1+d)
        let sy = xor16(&my, &t);
        wr(buf, xy + BLOCK, &sy);
        let s = xor16(&sx, &sy);

        // Pass 2 over the i-blocks.
        let mut y = ZERO;
        if total >= 64 {
            self.core_pass2(buf, &mut y, &s);
        }

        // Finish Y and the fragment ciphertext.
        if frag_bytes >= BLOCK {
            let t = self.aes10(&self.l[4], &s); // E(-1,4)
            let c = xor16(&rd(buf, fpos), &t);
            wr(buf, fpos, &c);
            let t = self.aes4(&ZERO, &self.i[1], &self.l[4], &c); // E(0,4)
            xor_into(&mut y, &t);
            let fpos2 = fpos + BLOCK;
            frag_bytes -= BLOCK;
            let t = self.aes10(&self.l[5], &s); // E(-1,5)
            for k in 0..frag_bytes {
                buf[fpos2 + k] ^= t[k];
            }
            let mut pad = ZERO;
            pad[..frag_bytes].copy_from_slice(&buf[fpos2..fpos2 + frag_bytes]);
            pad[frag_bytes] = 0x80;
            let t = self.aes4(&ZERO, &self.i[1], &self.l[5], &pad); // E(0,5)
            xor_into(&mut y, &t);
        } else if frag_bytes > 0 {
            let t = self.aes10(&self.l[4], &s); // E(-1,4)
            for k in 0..frag_bytes {
                buf[fpos + k] ^= t[k];
            }
            let mut pad = ZERO;
            pad[..frag_bytes].copy_from_slice(&buf[fpos..fpos + frag_bytes]);
            pad[frag_bytes] = 0x80;
            let t = self.aes4(&ZERO, &self.i[1], &self.l[4], &pad); // E(0,4)
            xor_into(&mut y, &t);
        }

        // Finish the last two blocks (buf[xy]=Sx, buf[xy+16]=Sy still), writing
        // them swapped per the reference.
        let t = self.aes10(&self.l[(2 - d) % 8], &rd(buf, xy + BLOCK)); // E(-1,2-d)
        let cx = xor16(&rd(buf, xy), &t);
        let t = self.aes4(&ZERO, &self.i[1], &self.l[(2 - d) % 8], &cx); // E(0,2-d)
        let mut cy = rd(buf, xy + BLOCK);
        xor_into(&mut cy, &t);
        xor_into(&mut cy, delta);
        xor_into(&mut cy, &y);
        wr(buf, xy, &cy);
        wr(buf, xy + BLOCK, &cx);
    }

    /// AEZ-tiny: encipher (`d = 0`) / decipher (`d = 1`) a buffer of 1..31 bytes
    /// in place via a balanced Feistel network with an AES4 round function.
    fn aez_tiny(&self, delta: &Block, buf: &mut [u8], d: usize) {
        let in_bytes = buf.len();
        let (i_idx, rounds): (usize, usize) = if in_bytes == 1 {
            (7, 24)
        } else if in_bytes == 2 {
            (7, 16)
        } else if in_bytes < 16 {
            (7, 10)
        } else {
            (6, 8)
        };

        let half = in_bytes.div_ceil(2);
        let mut l = ZERO;
        let mut r = ZERO;
        l[..half].copy_from_slice(&buf[..half]);
        r[..half].copy_from_slice(&buf[in_bytes / 2..in_bytes / 2 + half]);
        let (mut mask, mut pad) = (0x00u8, 0x80u8);
        if in_bytes & 1 != 0 {
            for k in 0..in_bytes / 2 {
                r[k] = (r[k] << 4) | (r[k + 1] >> 4);
            }
            r[in_bytes / 2] <<= 4;
            pad = 0x08;
            mask = 0xf0;
        }

        let (mut j, step): (i64, i64) = if d != 0 {
            if in_bytes < 16 {
                let mut b = ZERO;
                b[..in_bytes].copy_from_slice(&buf[..in_bytes]);
                b[0] |= 0x80;
                xor_into(&mut b, delta);
                let t = self.aes4(&ZERO, &self.i[1], &self.l[3], &b); // E(0,3)
                l[0] ^= t[0] & 0x80;
            }
            (rounds as i64 - 1, -1)
        } else {
            (0, 1)
        };

        for _ in 0..rounds / 2 {
            let mut b = ZERO;
            b[..half].copy_from_slice(&r[..half]);
            b[in_bytes / 2] = (b[in_bytes / 2] & mask) | pad;
            xor_into(&mut b, delta);
            b[15] ^= j as u8;
            let t = self.aes4(&ZERO, &self.i[1], &self.l[i_idx], &b); // E(0,i)
            xor_into(&mut l, &t);

            let mut b = ZERO;
            b[..half].copy_from_slice(&l[..half]);
            b[in_bytes / 2] = (b[in_bytes / 2] & mask) | pad;
            xor_into(&mut b, delta);
            b[15] ^= (j + step) as u8;
            let t = self.aes4(&ZERO, &self.i[1], &self.l[i_idx], &b); // E(0,i)
            xor_into(&mut r, &t);

            j += 2 * step;
        }

        let mut out = [0u8; 2 * BLOCK];
        out[..in_bytes / 2].copy_from_slice(&r[..in_bytes / 2]);
        out[in_bytes / 2..in_bytes / 2 + half].copy_from_slice(&l[..half]);
        if in_bytes & 1 != 0 {
            let mut k = in_bytes - 1;
            while k > in_bytes / 2 {
                out[k] = (out[k] >> 4) | (out[k - 1] << 4);
                k -= 1;
            }
            out[in_bytes / 2] = (l[0] >> 4) | (r[in_bytes / 2] & 0xf0);
        }
        buf[..in_bytes].copy_from_slice(&out[..in_bytes]);

        if in_bytes < 16 && d == 0 {
            let mut b = ZERO;
            b[..in_bytes].copy_from_slice(&buf[..in_bytes]);
            b[0] |= 0x80;
            xor_into(&mut b, delta);
            let t = self.aes4(&ZERO, &self.i[1], &self.l[3], &b); // E(0,3)
            buf[0] ^= t[0] & 0x80;
        }
    }

    fn encipher(&self, delta: &Block, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        if buf.len() < 32 {
            self.aez_tiny(delta, buf, 0);
        } else {
            self.aez_core(delta, buf, 0);
        }
    }

    fn decipher(&self, delta: &Block, buf: &mut [u8]) {
        if buf.is_empty() {
            return;
        }
        if buf.len() < 32 {
            self.aez_tiny(delta, buf, 1);
        } else {
            self.aez_core(delta, buf, 1);
        }
    }

    /// Encrypts and authenticates `m`, authenticating the associated-data vector
    /// `ad`, with a `tau`-byte expansion. Returns `m.len() + tau` ciphertext
    /// bytes. A given `(key, nonce)` should be unique, though AEZ degrades
    /// gracefully on reuse.
    pub fn encrypt(&self, nonce: &[u8], ad: &[&[u8]], tau: usize, m: &[u8]) -> Vec<u8> {
        let delta = self.aez_hash(nonce, ad, (tau * 8) as u32);
        let mut out = vec![0u8; m.len() + tau];
        if m.is_empty() {
            let prf = self.aez_prf(&delta, tau);
            out.copy_from_slice(&prf);
        } else {
            out[..m.len()].copy_from_slice(m);
            // trailing tau bytes are already zero
            self.encipher(&delta, &mut out);
        }
        out
    }

    /// Verifies and decrypts `c` (which must be `plaintext_len + tau` bytes),
    /// returning the plaintext on success and [`TagMismatch`] if authentication
    /// fails. The accept/reject check is constant-time.
    pub fn decrypt(
        &self,
        nonce: &[u8],
        ad: &[&[u8]],
        tau: usize,
        c: &[u8],
    ) -> Result<Vec<u8>, TagMismatch> {
        if c.len() < tau {
            return Err(TagMismatch);
        }
        let delta = self.aez_hash(nonce, ad, (tau * 8) as u32);
        if c.len() == tau {
            // Empty plaintext: ciphertext is exactly the PRF tag.
            let prf = self.aez_prf(&delta, tau);
            if bool::from(prf.ct_eq(c)) {
                return Ok(Vec::new());
            }
            return Err(TagMismatch);
        }
        let mut buf = c.to_vec();
        self.decipher(&delta, &mut buf);
        let m_len = c.len() - tau;
        // The trailing tau bytes must all be zero (constant-time check).
        let zeros = vec![0u8; tau];
        if bool::from(buf[m_len..].ct_eq(&zeros)) {
            buf.truncate(m_len);
            Ok(buf)
        } else {
            Err(TagMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decodes a hex string to bytes (test helper).
    fn h(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2));
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn ad_refs(ad: &[Vec<u8>]) -> Vec<&[u8]> {
        ad.iter().map(|v| v.as_slice()).collect()
    }

    include!("aez_test_vectors.rs");

    #[test]
    fn extract_vectors() {
        for (k, b) in EXTRACT {
            let aez = Aez::new(&h(k));
            let mut got = [0u8; 48];
            got[0..16].copy_from_slice(&aez.i[0]);
            got[16..32].copy_from_slice(&aez.j[0]);
            got[32..48].copy_from_slice(&aez.l[1]);
            assert_eq!(got.to_vec(), h(b), "extract key={k}");
        }
    }

    #[test]
    fn hash_vectors() {
        for (k, tau, data, v) in HASH {
            let aez = Aez::new(&h(k));
            let parts: Vec<Vec<u8>> = data.iter().map(|s| h(s)).collect();
            let (nonce, ad): (&[u8], Vec<&[u8]>) = match parts.split_first() {
                Some((n, rest)) => (n.as_slice(), rest.iter().map(|v| v.as_slice()).collect()),
                None => (&[], Vec::new()),
            };
            let got = aez.aez_hash(nonce, &ad, *tau);
            assert_eq!(got.to_vec(), h(v), "hash k={k}");
        }
    }

    #[test]
    fn prf_vectors() {
        for (k, delta, tau, r) in PRF {
            let aez = Aez::new(&h(k));
            let mut d = [0u8; 16];
            d.copy_from_slice(&h(delta));
            let got = aez.aez_prf(&d, *tau);
            assert_eq!(got, h(r), "prf k={k}");
        }
    }

    fn check_encrypt(table: &[EncVec], label: &str) {
        for (k, nonce, adhex, tau, m, c) in table {
            let aez = Aez::new(&h(k));
            let ad: Vec<Vec<u8>> = adhex.iter().map(|s| h(s)).collect();
            let adr = ad_refs(&ad);
            let n = h(nonce);
            let mp = h(m);
            let cp = h(c);

            let ct = aez.encrypt(&n, &adr, *tau, &mp);
            assert_eq!(ct, cp, "{label} encrypt m={m}");

            let pt = aez.decrypt(&n, &adr, *tau, &cp).expect("decrypt ok");
            assert_eq!(pt, mp, "{label} decrypt m={m}");
        }
    }

    #[test]
    fn encrypt_no_ad_vectors() {
        check_encrypt(ENC_NO_AD, "no_ad");
    }

    #[test]
    fn encrypt_16byte_key_vectors() {
        check_encrypt(ENC_16K, "16k");
    }

    #[test]
    fn encrypt_33byte_ad_vectors() {
        check_encrypt(ENC_33AD, "33ad");
    }

    #[test]
    fn encrypt_length_spread_vectors() {
        check_encrypt(ENC_MAIN, "main");
    }

    #[test]
    fn decrypt_rejects_tampering() {
        // Use a non-trivial case with AD and a tag.
        let (k, nonce, adhex, tau, m, c) = ENC_33AD[1];
        let aez = Aez::new(&h(k));
        let ad: Vec<Vec<u8>> = adhex.iter().map(|s| h(s)).collect();
        let adr = ad_refs(&ad);
        let n = h(nonce);
        let mp = h(m);
        let mut cp = h(c);
        assert_eq!(tau, 16);

        // Flip a ciphertext bit → reject.
        cp[0] ^= 1;
        assert!(aez.decrypt(&n, &adr, tau, &cp).is_err(), "flipped bit");
        cp[0] ^= 1;
        // Wrong nonce → reject.
        let mut bad_n = n.clone();
        bad_n[0] ^= 1;
        assert!(aez.decrypt(&bad_n, &adr, tau, &cp).is_err(), "wrong nonce");
        // Wrong AD → reject.
        let mut bad_ad = ad.clone();
        bad_ad[0][0] ^= 1;
        assert!(
            aez.decrypt(&n, &ad_refs(&bad_ad), tau, &cp).is_err(),
            "wrong ad"
        );
        // The untampered ciphertext still decrypts.
        assert_eq!(aez.decrypt(&n, &adr, tau, &cp).unwrap(), mp);
    }

    #[test]
    fn roundtrip_all_lengths() {
        let aez = Aez::new(b"a key of some length here!");
        let ad: [&[u8]; 2] = [b"header", b""];
        for len in 0..=130usize {
            let m: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
            for tau in [0usize, 1, 16] {
                let ct = aez.encrypt(b"nonce123", &ad, tau, &m);
                assert_eq!(ct.len(), m.len() + tau, "ct len for m={len} tau={tau}");
                let pt = aez.decrypt(b"nonce123", &ad, tau, &ct).expect("ok");
                assert_eq!(pt, m, "roundtrip m={len} tau={tau}");
            }
        }
    }
}
