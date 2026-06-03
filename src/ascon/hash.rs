//! Ascon hashing and extendable-output functions (NIST SP 800-232 §5):
//! [`AsconHash256`], [`AsconXof128`], and [`AsconCxof128`].
//!
//! All three share one sponge over the 320-bit Ascon permutation with a 64-bit
//! rate (`S0`) and `Ascon-p[12]` as the round function. They differ only in
//! their initialization value and — for Ascon-CXOF128 — a customization string
//! absorbed before the message (§5.3).

use super::permutation::State;
use crate::hash::{Digest, ExtendableOutput, XofReader};

/// The sponge rate in bytes (64 bits = word `S0`).
const RATE: usize = 8;

/// Ascon-Hash256 initialization value (SP 800-232 §5.1, Alg. 5).
const IV_HASH256: u64 = 0x0000_0801_00cc_0002;
/// Ascon-XOF128 initialization value (SP 800-232 §5.2, Alg. 6).
const IV_XOF128: u64 = 0x0000_0800_00cc_0003;
/// Ascon-CXOF128 initialization value (SP 800-232 §5.3, Alg. 7).
const IV_CXOF128: u64 = 0x0000_0800_00cc_0004;

/// The shared 64-bit-rate Ascon sponge: absorb message bytes, then squeeze.
///
/// Initialization is `S ← p12(IV ‖ 0^256)`. Absorption XORs each 8-byte block
/// into `S0` and applies `p12`; the final (padded) block is XORed but the
/// permutation that mixes it in is deferred to the first squeeze, matching the
/// SP 800-232 algorithms.
#[derive(Clone)]
struct Sponge {
    state: State,
    /// Buffered absorb bytes not yet forming a full `RATE`-byte block.
    buf: [u8; RATE],
    buf_len: usize,
}

impl Sponge {
    /// Initializes the sponge for the given precomputed IV word.
    fn new(iv: u64) -> Self {
        let mut state = State([iv, 0, 0, 0, 0]);
        state.permute12();
        Sponge {
            state,
            buf: [0u8; RATE],
            buf_len: 0,
        }
    }

    /// XORs the full 8-byte buffer into `S0` and permutes.
    fn absorb_block(&mut self) {
        self.state.0[0] ^= u64::from_le_bytes(self.buf);
        self.state.permute12();
    }

    /// Absorbs `data` (streaming; may be called repeatedly).
    fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (RATE - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == RATE {
                self.absorb_block();
                self.buf_len = 0;
            }
        }
        while data.len() >= RATE {
            self.buf.copy_from_slice(&data[..RATE]);
            self.absorb_block();
            data = &data[RATE..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Finalizes absorption: XORs the `pad10*`-padded final block into `S0`
    /// (without permuting — the first squeeze does that).
    fn finalize(&mut self) {
        let len = self.buf_len;
        for b in self.buf[len..].iter_mut() {
            *b = 0;
        }
        self.buf[len] = 0x01;
        self.state.0[0] ^= u64::from_le_bytes(self.buf);
        self.buf_len = 0;
    }

    /// Squeezes `out.len()` bytes. Must be called after [`finalize`](Self::finalize).
    ///
    /// Follows SP 800-232 squeezing: permute, then read `S0`, repeating; the
    /// rate is treated as a fresh 8-byte block each time `squeeze_offset`
    /// reaches `RATE`. `squeeze_offset == RATE` on entry forces the leading
    /// permutation for the very first output byte.
    fn squeeze(&mut self, out: &mut [u8], squeeze_offset: &mut usize) {
        for b in out.iter_mut() {
            if *squeeze_offset == RATE {
                self.state.permute12();
                *squeeze_offset = 0;
            }
            *b = self.state.0[0].to_le_bytes()[*squeeze_offset];
            *squeeze_offset += 1;
        }
    }

    fn zeroize(&mut self) {
        self.state.0 = [0u64; 5];
        self.buf = [0u8; RATE];
        self.buf_len = 0;
        let _ = core::hint::black_box(&self.state.0);
    }
}

/// Ascon-Hash256 (NIST SP 800-232 §5.1): a 256-bit cryptographic hash.
#[derive(Clone)]
pub struct AsconHash256 {
    sponge: Sponge,
}

impl Digest for AsconHash256 {
    type Output = [u8; 32];
    type Block = [u8; RATE];
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = RATE;

    #[inline]
    fn new() -> Self {
        AsconHash256 {
            sponge: Sponge::new(IV_HASH256),
        }
    }

    #[inline]
    fn zeroed_block() -> [u8; RATE] {
        [0u8; RATE]
    }

    #[inline]
    fn zeroed_output() -> [u8; 32] {
        [0u8; 32]
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.sponge.update(data);
    }

    fn finalize(mut self) -> [u8; 32] {
        self.sponge.finalize();
        let mut out = [0u8; 32];
        let mut offset = RATE;
        self.sponge.squeeze(&mut out, &mut offset);
        out
    }

    #[inline]
    fn zeroize(&mut self) {
        self.sponge.zeroize();
    }
}

impl Drop for AsconHash256 {
    fn drop(&mut self) {
        self.sponge.zeroize();
    }
}

/// Ascon-XOF128 (NIST SP 800-232 §5.2): an extendable-output function with up
/// to 128-bit security strength.
#[derive(Clone)]
pub struct AsconXof128 {
    sponge: Sponge,
}

impl ExtendableOutput for AsconXof128 {
    type Reader = AsconXofReader;
    const BLOCK_LEN: usize = RATE;

    #[inline]
    fn new() -> Self {
        AsconXof128 {
            sponge: Sponge::new(IV_XOF128),
        }
    }

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.sponge.update(data);
    }

    fn finalize_xof(mut self) -> AsconXofReader {
        self.sponge.finalize();
        // Move the sponge out, leaving a zeroed stand-in for this wrapper's Drop.
        let sponge = core::mem::replace(&mut self.sponge, Sponge::new(IV_XOF128));
        AsconXofReader {
            sponge,
            squeeze_offset: RATE,
        }
    }
}

impl Drop for AsconXof128 {
    fn drop(&mut self) {
        self.sponge.zeroize();
    }
}

/// A [`XofReader`] over a finalized Ascon-XOF128 / Ascon-CXOF128 sponge.
#[derive(Clone)]
pub struct AsconXofReader {
    sponge: Sponge,
    squeeze_offset: usize,
}

impl XofReader for AsconXofReader {
    #[inline]
    fn read(&mut self, out: &mut [u8]) {
        self.sponge.squeeze(out, &mut self.squeeze_offset);
    }
}

impl Drop for AsconXofReader {
    fn drop(&mut self) {
        self.sponge.zeroize();
    }
}

/// Ascon-CXOF128 (NIST SP 800-232 §5.3): a customized extendable-output
/// function. A customization string `Z` (at most 2048 bits / 256 bytes) is
/// absorbed before the message, so distinct `Z` values yield independent output
/// streams for the same message — providing domain separation.
#[derive(Clone)]
pub struct AsconCxof128 {
    sponge: Sponge,
}

impl AsconCxof128 {
    /// Length cap on the customization string `Z` (SP 800-232 §5.3: at most
    /// 2048 bits = 256 bytes).
    pub const MAX_CUSTOMIZATION_LEN: usize = 256;

    /// Creates an Ascon-CXOF128 context with customization string `z`.
    ///
    /// # Panics
    /// Panics if `z.len()` exceeds [`MAX_CUSTOMIZATION_LEN`](Self::MAX_CUSTOMIZATION_LEN).
    pub fn new(z: &[u8]) -> Self {
        assert!(
            z.len() <= Self::MAX_CUSTOMIZATION_LEN,
            "Ascon-CXOF128 customization string must be at most 256 bytes (SP 800-232 §5.3)"
        );
        let mut sponge = Sponge::new(IV_CXOF128);
        // Customization phase (SP 800-232 Alg. 7): absorb Z0 = int64(|Z| in
        // bits) as a full 8-byte block, then the customization string with
        // `pad10*`, permuting after each block (including the final one).
        sponge.state.0[0] ^= (z.len() as u64) * 8;
        sponge.state.permute12();
        let mut chunks = z.chunks_exact(RATE);
        for block in chunks.by_ref() {
            sponge.state.0[0] ^= u64::from_le_bytes(block.try_into().unwrap());
            sponge.state.permute12();
        }
        let rem = chunks.remainder();
        let mut last = [0u8; RATE];
        last[..rem.len()].copy_from_slice(rem);
        last[rem.len()] = 0x01;
        sponge.state.0[0] ^= u64::from_le_bytes(last);
        sponge.state.permute12();
        AsconCxof128 { sponge }
    }

    /// Feeds message bytes. May be called any number of times before
    /// [`finalize_xof`](Self::finalize_xof).
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.sponge.update(data);
    }

    /// Finalizes absorption and returns a reader over the output stream.
    pub fn finalize_xof(mut self) -> AsconXofReader {
        self.sponge.finalize();
        let sponge = core::mem::replace(&mut self.sponge, Sponge::new(IV_CXOF128));
        AsconXofReader {
            sponge,
            squeeze_offset: RATE,
        }
    }

    /// One-shot: customization `z`, message `data`, squeeze `out.len()` bytes.
    pub fn xof(z: &[u8], data: &[u8], out: &mut [u8]) {
        let mut x = Self::new(z);
        x.update(data);
        x.finalize_xof().read(out);
    }
}

impl Drop for AsconCxof128 {
    fn drop(&mut self) {
        self.sponge.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{from_hex, from_hex_vec};

    // All KAT vectors below are from the official Ascon reference repository's
    // NIST SP 800-232 known-answer-test files (github.com/ascon/ascon-c):
    //   crypto_hash/asconhash256/LWC_HASH_KAT_128_256.txt
    //   crypto_hash/asconxof128/LWC_XOF_KAT_128_512.txt   (512-bit output)
    //   crypto_cxof/asconcxof128/LWC_CXOF_KAT_128_512.txt (512-bit output)
    // Messages/customization strings are the byte sequence 00,01,02,... .

    fn ramp(n: usize) -> alloc::vec::Vec<u8> {
        (0..n as u8).collect()
    }

    // -- Ascon-Hash256 (Count 1, 2, 4, 9, 17, 33) --

    #[test]
    fn hash256_kat() {
        let cases: &[(usize, &str)] = &[
            (
                0,
                "0B3BE5850F2F6B98CAF29F8FDEA89B64A1FA70AA249B8F839BD53BAA304D92B2",
            ),
            (
                1,
                "0728621035AF3ED2BCA03BF6FDE900F9456F5330E4B5EE23E7F6A1E70291BC80",
            ),
            (
                3,
                "265AB89A609F5A05DCA57E83FBBA700F9A2D2C4211BA4CC9F0A1A369E17B915C",
            ),
            (
                8,
                "B88E497AE8E6FB641B87EF622EB8F2FCA0ED95383F7FFEBE167ACF1099BA764F",
            ),
            (
                16,
                "3158C1940A2FBADBD68AB661777859B94A689E4EFC375911467ADDD641835C38",
            ),
            (
                32,
                "BD9D3D60A66B53868EAB2A5C74539A518A1F60F01EB176C60E43DEE81680B33E",
            ),
        ];
        for &(n, md) in cases {
            assert_eq!(
                AsconHash256::digest(&ramp(n)),
                from_hex::<32>(md),
                "Ascon-Hash256 mismatch for {n}-byte message"
            );
        }
    }

    // Streaming must equal one-shot across an arbitrary chunk split spanning
    // multiple rate blocks (rate = 8 bytes).
    #[test]
    fn hash256_streaming_matches_oneshot() {
        let msg = ramp(100);
        let oneshot = AsconHash256::digest(&msg);
        let mut h = AsconHash256::new();
        h.update(&msg[..1]);
        h.update(&msg[1..9]);
        h.update(&msg[9..50]);
        h.update(&msg[50..]);
        assert_eq!(h.finalize(), oneshot);
    }

    // -- Ascon-XOF128 (Count 1, 2, 4, 33; 64-byte / 512-bit output) --

    fn xof128(msg: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        let mut x = AsconXof128::new();
        x.update(msg);
        x.finalize_xof().read(&mut out);
        out
    }

    #[test]
    fn xof128_kat() {
        assert_eq!(
            xof128(&ramp(0)),
            from_hex::<64>(
                "473D5E6164F58B39DFD84AACDB8AE42EC2D91FED33388EE0D960D9B3993295C6\
                 AD77855A5D3B13FE6AD9E6098988373AF7D0956D05A8F1665D2C67D1A3AD10FF"
            )
        );
        assert_eq!(
            xof128(&ramp(1)),
            from_hex::<64>(
                "51430E0438ECDF642B393630D977625F5F337656BA58AB1E960784AC32A16E0D\
                 446405551F5469384F8EA283CF12E64FA72C426BFEBAEA3AA1529E2C4AB23A2F"
            )
        );
        assert_eq!(
            xof128(&ramp(3)),
            from_hex::<64>(
                "9C96F31C3E7BDFDC5EF6BA836F760A0D6548D94DD0A512033022C9242E8BA916\
                 C30C3961D37D7DD7282E2191494D60DC5058588B276C60C90BE2AAA7E7013D96"
            )
        );
        assert_eq!(
            xof128(&ramp(32)),
            from_hex::<64>(
                "2E5F3403F4171471CC7934B51982CECE8D6628435DB70E89880F3BE4E0B7B052\
                 32DFE63C44A836D771337C9C5A2688D1B71ECABE0D5C2006FEF36EF3186138AD"
            )
        );
    }

    // Incremental squeezing must equal a single read of the same length, and
    // streamed absorption must equal one-shot.
    #[test]
    fn xof128_incremental_squeeze_and_absorb() {
        let msg = ramp(40);
        let full = xof128(&msg);

        let mut x = AsconXof128::new();
        x.update(&msg[..5]);
        x.update(&msg[5..]);
        let mut reader = x.finalize_xof();
        let mut piecewise = [0u8; 64];
        reader.read(&mut piecewise[..1]);
        reader.read(&mut piecewise[1..9]);
        reader.read(&mut piecewise[9..30]);
        reader.read(&mut piecewise[30..]);
        assert_eq!(piecewise, full);
    }

    // -- Ascon-CXOF128 (64-byte / 512-bit output) --

    fn cxof128(z: &[u8], msg: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        AsconCxof128::xof(z, msg, &mut out);
        out
    }

    #[test]
    fn cxof128_kat() {
        // Count 1: empty message, empty customization.
        assert_eq!(
            cxof128(&[], &[]),
            from_hex::<64>(
                "4F50159EF70BB3DAD8807E034EAEBD44C4FA2CBBC8CF1F05511AB66CDCC52990\
                 5CA12083FC186AD899B270B1473DC5F7EC88D1052082DCDFE69FB75D269E7B74"
            )
        );
        // Count 2: empty message, customization Z = 10.
        assert_eq!(
            cxof128(&from_hex::<1>("10"), &[]),
            from_hex::<64>(
                "0C93A483E7D574D49FE52CCE03EE646117977D57A8AA57704AB4DAF44B501430\
                 FF6AC11A5D1FD6F2154B5C65728268270C8BB578508487B8965718ADA6272FD6"
            )
        );
        // Count 3: empty message, customization Z = 1011.
        assert_eq!(
            cxof128(&from_hex::<2>("1011"), &[]),
            from_hex::<64>(
                "D1106C7622E79FE955BD9D79E03B918E770FE0E0CDDDE28BEB924B02C5FC936B\
                 33ACCA299C89ECA5D71886CBBFA4D54A21C55FDE2B679F5E2488063A1719DC32"
            )
        );
        // Count 266: 8-byte message 0001020304050607, customization Z = 10.
        assert_eq!(
            cxof128(&from_hex::<1>("10"), &from_hex_vec("0001020304050607")),
            from_hex::<64>(
                "72C1F546BD462150BB0F1C5F2A3A3693FD62909A79A411E5BB2DBAC12578A72A\
                 A6DB2CC91F88FF6D686CA05D357E69A98C9E85DD345B090AC34D066C86B4FCF2"
            )
        );
    }

    // Distinct customization strings yield distinct outputs for the same
    // message (the domain-separation property of CXOF).
    #[test]
    fn cxof128_customization_separates_domains() {
        let msg = ramp(20);
        let a = cxof128(b"context-A", &msg);
        let b = cxof128(b"context-B", &msg);
        assert_ne!(a, b);
        // And differs from the un-customized XOF128 over the same message.
        assert_ne!(cxof128(b"", &msg), xof128(&msg));
    }
}
