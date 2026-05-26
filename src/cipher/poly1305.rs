//! The Poly1305 one-time authenticator (RFC 8439 §2.5).
//!
//! Poly1305 evaluates a polynomial in the secret evaluation point `r` modulo
//! the prime `2¹³⁰ − 5`, then adds the secret pad `s` modulo `2¹²⁸`. The
//! 130-bit arithmetic here is carried in five 26-bit limbs (the "donna" layout),
//! which keeps every step within 64-bit products and uses a branchless final
//! reduction — there are no secret-dependent branches or table lookups.
//!
//! The (`r`, `s`) key is **single-use**: authenticating two messages under the
//! same Poly1305 key reveals `r` and breaks the MAC. In ChaCha20-Poly1305 a
//! fresh key is derived per record from the cipher keystream.

/// Reads four bytes as a little-endian `u32`.
#[inline]
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// A Poly1305 authenticator state.
///
/// Implements [`Drop`] to wipe the clamped `r`, the precomputed `5·r`, the
/// accumulator `h`, the additive pad `s`, and the input-side buffer when the
/// state goes out of scope — these are all derived from the secret one-time
/// key.
#[derive(Clone)]
pub struct Poly1305 {
    /// Clamped evaluation point `r`, in five 26-bit limbs.
    r: [u32; 5],
    /// Precomputed `5·r[1..=4]` for the modular reduction.
    s: [u32; 4],
    /// Accumulator `h`, in five 26-bit limbs.
    h: [u32; 5],
    /// The final additive pad `s`, as four 32-bit words.
    pad: [u32; 4],
    /// Bytes held back until a full 16-byte block (or finalization).
    buffer: [u8; 16],
    leftover: usize,
}

impl Poly1305 {
    /// Creates a Poly1305 state from a 32-byte one-time key (`r ‖ s`).
    pub fn new(key: &[u8; 32]) -> Self {
        // Clamp r (RFC 8439 §2.5): clear the high 4 bits of each r byte group
        // and the low 2 bits of the upper three words.
        let r0 = le32(&key[0..4]) & 0x03ff_ffff;
        let r1 = (le32(&key[3..7]) >> 2) & 0x03ff_ff03;
        let r2 = (le32(&key[6..10]) >> 4) & 0x03ff_c0ff;
        let r3 = (le32(&key[9..13]) >> 6) & 0x03f0_3fff;
        let r4 = (le32(&key[12..16]) >> 8) & 0x000f_ffff;
        Poly1305 {
            r: [r0, r1, r2, r3, r4],
            s: [r1 * 5, r2 * 5, r3 * 5, r4 * 5],
            h: [0; 5],
            pad: [
                le32(&key[16..20]),
                le32(&key[20..24]),
                le32(&key[24..28]),
                le32(&key[28..32]),
            ],
            buffer: [0; 16],
            leftover: 0,
        }
    }

    /// Absorbs one 16-byte block. `hibit` is `1 << 24` (the implicit 2¹²⁸ bit)
    /// for a full block, or `0` for the padded final block.
    fn block(&mut self, m: &[u8; 16], hibit: u32) {
        let t0 = le32(&m[0..4]);
        let t1 = le32(&m[4..8]);
        let t2 = le32(&m[8..12]);
        let t3 = le32(&m[12..16]);

        // h += m
        let h0 = (self.h[0] + (t0 & 0x03ff_ffff)) as u64;
        let h1 = (self.h[1] + (((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff)) as u64;
        let h2 = (self.h[2] + (((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff)) as u64;
        let h3 = (self.h[3] + (((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff)) as u64;
        let h4 = (self.h[4] + ((t3 >> 8) | hibit)) as u64;

        let [r0, r1, r2, r3, r4] = self.r.map(u64::from);
        let [s1, s2, s3, s4] = self.s.map(u64::from);

        // h *= r mod 2¹³⁰−5 (schoolbook with the 5·r wrap-around terms)
        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;

        // Partial carry propagation back into 26-bit limbs.
        let mut c = d0 >> 26;
        let nh0 = (d0 as u32) & 0x03ff_ffff;
        let d1 = d1 + c;
        c = d1 >> 26;
        let nh1 = (d1 as u32) & 0x03ff_ffff;
        let d2 = d2 + c;
        c = d2 >> 26;
        let nh2 = (d2 as u32) & 0x03ff_ffff;
        let d3 = d3 + c;
        c = d3 >> 26;
        let nh3 = (d3 as u32) & 0x03ff_ffff;
        let d4 = d4 + c;
        c = d4 >> 26;
        let nh4 = (d4 as u32) & 0x03ff_ffff;
        let nh0 = nh0 as u64 + c * 5;
        let carry = (nh0 >> 26) as u32;
        self.h = [(nh0 as u32) & 0x03ff_ffff, nh1 + carry, nh2, nh3, nh4];
    }

    /// Absorbs `data` into the authenticator.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.leftover > 0 {
            let want = 16 - self.leftover;
            let take = want.min(data.len());
            self.buffer[self.leftover..self.leftover + take].copy_from_slice(&data[..take]);
            self.leftover += take;
            data = &data[take..];
            if self.leftover < 16 {
                return;
            }
            let block = self.buffer;
            self.block(&block, 1 << 24);
            self.leftover = 0;
        }

        let mut chunks = data.chunks_exact(16);
        for chunk in &mut chunks {
            let mut block = [0u8; 16];
            block.copy_from_slice(chunk);
            self.block(&block, 1 << 24);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.buffer[..rem.len()].copy_from_slice(rem);
            self.leftover = rem.len();
        }
    }

    /// Finalizes and returns the 16-byte authentication tag.
    pub fn finish(mut self) -> [u8; 16] {
        if self.leftover > 0 {
            let mut block = [0u8; 16];
            block[..self.leftover].copy_from_slice(&self.buffer[..self.leftover]);
            block[self.leftover] = 1;
            self.block(&block, 0);
        }

        // Fully carry h.
        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;
        let mut c = h1 >> 26;
        h1 &= 0x03ff_ffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x03ff_ffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x03ff_ffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x03ff_ffff;
        h0 += c * 5;
        c = h0 >> 26;
        h0 &= 0x03ff_ffff;
        h1 += c;

        // Compute h − p; if it does not borrow, h ≥ p and we keep the result.
        let mut g0 = h0 + 5;
        c = g0 >> 26;
        g0 &= 0x03ff_ffff;
        let mut g1 = h1 + c;
        c = g1 >> 26;
        g1 &= 0x03ff_ffff;
        let mut g2 = h2 + c;
        c = g2 >> 26;
        g2 &= 0x03ff_ffff;
        let mut g3 = h3 + c;
        c = g3 >> 26;
        g3 &= 0x03ff_ffff;
        let g4 = (h4 + c).wrapping_sub(1 << 26);

        // mask = 0 when h < p (g4 borrowed, high bit set), else all-ones.
        let mask = (g4 >> 31).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let g4 = g4 & mask;
        let nmask = !mask;
        h0 = (h0 & nmask) | g0;
        h1 = (h1 & nmask) | g1;
        h2 = (h2 & nmask) | g2;
        h3 = (h3 & nmask) | g3;
        h4 = (h4 & nmask) | g4;

        // Repack the 26-bit limbs into four 32-bit words (mod 2¹²⁸).
        let h0 = h0 | (h1 << 26);
        let h1 = (h1 >> 6) | (h2 << 20);
        let h2 = (h2 >> 12) | (h3 << 14);
        let h3 = (h3 >> 18) | (h4 << 8);

        // tag = (h + pad) mod 2¹²⁸.
        let mut f = h0 as u64 + self.pad[0] as u64;
        let m0 = f as u32;
        f = h1 as u64 + self.pad[1] as u64 + (f >> 32);
        let m1 = f as u32;
        f = h2 as u64 + self.pad[2] as u64 + (f >> 32);
        let m2 = f as u32;
        f = h3 as u64 + self.pad[3] as u64 + (f >> 32);
        let m3 = f as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&m0.to_le_bytes());
        tag[4..8].copy_from_slice(&m1.to_le_bytes());
        tag[8..12].copy_from_slice(&m2.to_le_bytes());
        tag[12..16].copy_from_slice(&m3.to_le_bytes());
        tag
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        // Best-effort secret wipe: zero every field that's derived from the
        // one-time key, then apply the standard `black_box` optimisation
        // barrier so LLVM doesn't elide the writes as a dead store.
        self.r = [0; 5];
        self.s = [0; 4];
        self.h = [0; 5];
        self.pad = [0; 4];
        self.buffer = [0u8; 16];
        self.leftover = 0;
        let _ = core::hint::black_box(&self.r);
        let _ = core::hint::black_box(&self.s);
        let _ = core::hint::black_box(&self.h);
        let _ = core::hint::black_box(&self.pad);
        let _ = core::hint::black_box(&self.buffer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    #[test]
    fn rfc8439_tag() {
        // RFC 8439 §2.5.2.
        let key =
            from_hex::<32>("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let msg = b"Cryptographic Forum Research Group";
        let mut p = Poly1305::new(&key);
        p.update(msg);
        assert_eq!(
            p.finish(),
            from_hex::<16>("a8061dc1305136c6c22b8baf0c0127a9")
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let key =
            from_hex::<32>("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
        let msg = b"Cryptographic Forum Research Group";
        let mut split = Poly1305::new(&key);
        split.update(&msg[..7]);
        split.update(&msg[7..16]);
        split.update(&msg[16..]);
        assert_eq!(
            split.finish(),
            from_hex::<16>("a8061dc1305136c6c22b8baf0c0127a9")
        );
    }
}
