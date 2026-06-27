//! TurboSHAKE and KangarooTwelve — fast Keccak-based XOFs using the
//! reduced-round Keccak-p[1600, 12] permutation.
//!
//! [`TurboShake128`]/[`TurboShake256`] are the reduced-round analogues of
//! SHAKE, with a caller-chosen domain-separation byte. [`KangarooTwelve`] is a
//! tree hash built on TurboSHAKE128 (1 KiB leaf chunks, 8 KiB root node),
//! parallelizable in principle and very fast in software.
//!
//! [`MarsupilamiFourteen`] is the 256-bit-security sibling of KangarooTwelve
//! from the original K12 paper: the identical tree construction over
//! Keccak-p[1600, **14**] (rate 136, 64-byte chaining values) rather than
//! Keccak-p[1600, 12]. Note this is the original 14-round variant, distinct
//! from the later CFRG `KT256`, which is a 12-round TurboSHAKE256 tree.
//!
//! All of these are `no_std` and allocation-free.

use super::keccak::{Keccak, KeccakReader};

const TS128_RATE: usize = 168;
const TS256_RATE: usize = 136;
const ROUNDS: usize = 12;

/// MarsupilamiFourteen permutation rounds: Keccak-p[1600, 14] (vs. 12 for K12).
const M14_ROUNDS: usize = 14;
/// MarsupilamiFourteen chaining-value / capacity size in bytes (vs. 32 for K12).
const M14_CV: usize = 64;

/// KangarooTwelve chunk size: 8192 bytes (the root node and each leaf).
/// MarsupilamiFourteen shares the same 8 KiB chunking.
const K12_CHUNK: usize = 8192;

/// Defines a TurboSHAKE variant at the given rate.
macro_rules! turboshake {
    ($name:ident, $rate:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            keccak: Keccak,
            domain: u8,
        }
        impl $name {
            /// Creates a TurboSHAKE with domain-separation byte `domain`
            /// (`0x01..=0x7F`).
            pub fn new(domain: u8) -> Self {
                debug_assert!(
                    (0x01..=0x7F).contains(&domain),
                    "TurboSHAKE domain must be in 0x01..=0x7F"
                );
                $name {
                    keccak: Keccak::with_rounds($rate, ROUNDS),
                    domain,
                }
            }
            /// Feeds input.
            pub fn update(&mut self, data: &[u8]) {
                self.keccak.update(data);
            }
            /// Finalizes and returns an output reader.
            pub fn finalize_xof(self) -> KeccakReader {
                KeccakReader::new(self.keccak, self.domain)
            }
            /// Finalizes and squeezes `out.len()` bytes.
            pub fn finalize_into(self, out: &mut [u8]) {
                use super::XofReader;
                self.finalize_xof().read(out);
            }
        }
    };
}

turboshake!(
    TurboShake128,
    TS128_RATE,
    "TurboSHAKE128 (12-round SHAKE128)."
);
turboshake!(
    TurboShake256,
    TS256_RATE,
    "TurboSHAKE256 (12-round SHAKE256)."
);

/// KangarooTwelve's `length_encode(x)`: the minimal big-endian bytes of `x`
/// followed by a single byte giving their count. Note `length_encode(0)` is the
/// single byte `0x00` (unlike SP 800-185's `right_encode`).
fn length_encode(buf: &mut [u8; 9], x: u64) -> usize {
    let mut len = 0usize;
    let mut v = x;
    while v > 0 {
        len += 1;
        v >>= 8;
    }
    for (i, slot) in buf[..len].iter_mut().enumerate() {
        *slot = (x >> (8 * (len - 1 - i))) as u8;
    }
    buf[len] = len as u8;
    len + 1
}

/// KangarooTwelve (draft-irtf-cfrg-kangarootwelve), an XOF over a message and an
/// optional customization string.
///
/// The customization is borrowed for the lifetime of the hasher; it is appended
/// to the message stream at finalization, as the construction requires.
#[derive(Clone)]
pub struct KangarooTwelve<'a> {
    custom: &'a [u8],
    /// Buffer for the first 8 KiB node (the root prefix in tree mode).
    node0: [u8; K12_CHUNK],
    node0_len: usize,
    /// Root sponge (final node), used once in tree mode.
    root: Keccak,
    /// Current leaf sponge and its fill level (tree mode only).
    leaf: Keccak,
    leaf_len: usize,
    /// Number of completed leaves.
    leaves: u64,
    /// Whether the input has exceeded one chunk (switched to tree mode).
    tree: bool,
}

impl<'a> KangarooTwelve<'a> {
    /// Creates a KangarooTwelve hasher with customization string `custom`
    /// (use `b""` for none).
    pub fn new(custom: &'a [u8]) -> Self {
        KangarooTwelve {
            custom,
            node0: [0u8; K12_CHUNK],
            node0_len: 0,
            root: Keccak::with_rounds(TS128_RATE, ROUNDS),
            leaf: Keccak::with_rounds(TS128_RATE, ROUNDS),
            leaf_len: 0,
            leaves: 0,
            tree: false,
        }
    }

    /// Absorbs bytes of the logical stream `S = M || C || length_encode(|C|)`,
    /// chunking into the tree as 8 KiB boundaries are crossed.
    fn feed(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if !self.tree {
                let take = (K12_CHUNK - self.node0_len).min(data.len());
                self.node0[self.node0_len..self.node0_len + take].copy_from_slice(&data[..take]);
                self.node0_len += take;
                data = &data[take..];
                // The root node is full and more input follows: switch to the
                // tree, absorbing node0 and the 8-byte chaining-mode marker.
                if self.node0_len == K12_CHUNK && !data.is_empty() {
                    self.root.update(&self.node0);
                    self.root.update(&[0x03, 0, 0, 0, 0, 0, 0, 0]);
                    self.tree = true;
                }
            } else {
                let take = (K12_CHUNK - self.leaf_len).min(data.len());
                self.leaf.update(&data[..take]);
                self.leaf_len += take;
                data = &data[take..];
                if self.leaf_len == K12_CHUNK {
                    self.absorb_leaf();
                }
            }
        }
    }

    /// Finalizes the current leaf to a 32-byte chaining value into the root.
    fn absorb_leaf(&mut self) {
        let mut cv = [0u8; 32];
        self.leaf.finalize(0x0B);
        self.leaf.squeeze(&mut cv);
        self.root.update(&cv);
        self.leaves += 1;
        self.leaf = Keccak::with_rounds(TS128_RATE, ROUNDS);
        self.leaf_len = 0;
    }

    /// Feeds input.
    pub fn update(&mut self, data: &[u8]) {
        self.feed(data);
    }

    /// Finalizes and returns an output reader.
    pub fn finalize_xof(mut self) -> KeccakReader {
        // Complete the logical stream: append C and length_encode(|C|).
        let custom = self.custom;
        self.feed(custom);
        let mut enc = [0u8; 9];
        let n = length_encode(&mut enc, self.custom.len() as u64);
        self.feed(&enc[..n]);

        if !self.tree {
            // Short message: a single TurboSHAKE128 with domain 0x07.
            let mut k = Keccak::with_rounds(TS128_RATE, ROUNDS);
            k.update(&self.node0[..self.node0_len]);
            KeccakReader::new(k, 0x07)
        } else {
            // Fold the final (partial) leaf, then the leaf count and trailer.
            if self.leaf_len > 0 {
                self.absorb_leaf();
            }
            let mut enc = [0u8; 9];
            let n = length_encode(&mut enc, self.leaves);
            self.root.update(&enc[..n]);
            self.root.update(&[0xFF, 0xFF]);
            KeccakReader::new(self.root, 0x06)
        }
    }

    /// Finalizes and squeezes `out.len()` bytes.
    pub fn finalize_into(self, out: &mut [u8]) {
        use super::XofReader;
        self.finalize_xof().read(out);
    }
}

/// Computes a 32-byte KangarooTwelve digest of `data` (no customization).
#[inline]
pub fn k12(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut h = KangarooTwelve::new(b"");
    h.update(data);
    h.finalize_into(&mut out);
    out
}

/// MarsupilamiFourteen, the 256-bit-security sibling of [`KangarooTwelve`] from
/// the original K12 paper.
///
/// The construction is byte-for-byte identical to KangarooTwelve — same 8 KiB
/// chunking, same `length_encode`, same domain/tree bytes
/// (`0x07`/`0x0B`/`0x06`/`0x03`/`0xFF 0xFF`) — but built on Keccak-p[1600, 14]
/// (rate 136, capacity 512) with 64-byte chaining values. The extra rounds and
/// larger capacity raise the claimed strength to 256 bits; the security
/// separation between the two functions comes entirely from the permutation.
///
/// As with KangarooTwelve, the customization string is borrowed for the lifetime
/// of the hasher and appended to the message stream at finalization.
#[derive(Clone)]
pub struct MarsupilamiFourteen<'a> {
    custom: &'a [u8],
    /// Buffer for the first 8 KiB node (the root prefix in tree mode).
    node0: [u8; K12_CHUNK],
    node0_len: usize,
    /// Root sponge (final node), used once in tree mode.
    root: Keccak,
    /// Current leaf sponge and its fill level (tree mode only).
    leaf: Keccak,
    leaf_len: usize,
    /// Number of completed leaves.
    leaves: u64,
    /// Whether the input has exceeded one chunk (switched to tree mode).
    tree: bool,
}

impl<'a> MarsupilamiFourteen<'a> {
    /// Creates a MarsupilamiFourteen hasher with customization string `custom`
    /// (use `b""` for none).
    pub fn new(custom: &'a [u8]) -> Self {
        MarsupilamiFourteen {
            custom,
            node0: [0u8; K12_CHUNK],
            node0_len: 0,
            root: Keccak::with_rounds(TS256_RATE, M14_ROUNDS),
            leaf: Keccak::with_rounds(TS256_RATE, M14_ROUNDS),
            leaf_len: 0,
            leaves: 0,
            tree: false,
        }
    }

    /// Absorbs bytes of the logical stream `S = M || C || length_encode(|C|)`,
    /// chunking into the tree as 8 KiB boundaries are crossed.
    fn feed(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if !self.tree {
                let take = (K12_CHUNK - self.node0_len).min(data.len());
                self.node0[self.node0_len..self.node0_len + take].copy_from_slice(&data[..take]);
                self.node0_len += take;
                data = &data[take..];
                // The root node is full and more input follows: switch to the
                // tree, absorbing node0 and the 8-byte chaining-mode marker.
                if self.node0_len == K12_CHUNK && !data.is_empty() {
                    self.root.update(&self.node0);
                    self.root.update(&[0x03, 0, 0, 0, 0, 0, 0, 0]);
                    self.tree = true;
                }
            } else {
                let take = (K12_CHUNK - self.leaf_len).min(data.len());
                self.leaf.update(&data[..take]);
                self.leaf_len += take;
                data = &data[take..];
                if self.leaf_len == K12_CHUNK {
                    self.absorb_leaf();
                }
            }
        }
    }

    /// Finalizes the current leaf to a 64-byte chaining value into the root.
    fn absorb_leaf(&mut self) {
        let mut cv = [0u8; M14_CV];
        self.leaf.finalize(0x0B);
        self.leaf.squeeze(&mut cv);
        self.root.update(&cv);
        self.leaves += 1;
        self.leaf = Keccak::with_rounds(TS256_RATE, M14_ROUNDS);
        self.leaf_len = 0;
    }

    /// Feeds input.
    pub fn update(&mut self, data: &[u8]) {
        self.feed(data);
    }

    /// Finalizes and returns an output reader.
    pub fn finalize_xof(mut self) -> KeccakReader {
        // Complete the logical stream: append C and length_encode(|C|).
        let custom = self.custom;
        self.feed(custom);
        let mut enc = [0u8; 9];
        let n = length_encode(&mut enc, self.custom.len() as u64);
        self.feed(&enc[..n]);

        if !self.tree {
            // Short message: a single TurboSHAKE256-rate sponge with domain 0x07.
            let mut k = Keccak::with_rounds(TS256_RATE, M14_ROUNDS);
            k.update(&self.node0[..self.node0_len]);
            KeccakReader::new(k, 0x07)
        } else {
            // Fold the final (partial) leaf, then the leaf count and trailer.
            if self.leaf_len > 0 {
                self.absorb_leaf();
            }
            let mut enc = [0u8; 9];
            let n = length_encode(&mut enc, self.leaves);
            self.root.update(&enc[..n]);
            self.root.update(&[0xFF, 0xFF]);
            KeccakReader::new(self.root, 0x06)
        }
    }

    /// Finalizes and squeezes `out.len()` bytes.
    pub fn finalize_into(self, out: &mut [u8]) {
        use super::XofReader;
        self.finalize_xof().read(out);
    }
}

/// Computes a 64-byte MarsupilamiFourteen digest of `data` (no customization).
///
/// 64 bytes is the natural output for its 256-bit security level; use
/// [`MarsupilamiFourteen`] directly for other lengths or a customization string.
#[inline]
pub fn m14(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut h = MarsupilamiFourteen::new(b"");
    h.update(data);
    h.finalize_into(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::XofReader;
    use crate::test_util::from_hex;

    /// `input[i] = i % 251`, the KangarooTwelve test pattern.
    fn ptn(buf: &mut [u8]) {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
    }

    // Cross-checked with pycryptodome and an independent Keccak reference.
    #[test]
    fn turboshake_vectors() {
        let mut out = [0u8; 32];
        TurboShake128::new(0x1F).finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<32>("1e415f1c5983aff2169217277d17bb538cd945a397ddec541f1ce41af2c1b74c")
        );

        let mut out = [0u8; 64];
        TurboShake256::new(0x1F).finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<64>(
                "367a329dafea871c7802ec67f905ae13c57695dc2c6663c61035f59a18f8e7db11edc0e12e91ea60eb6b32df06dd7f002fbafabb6e13ec1cc20d995547600db0"
            )
        );
    }

    // KangarooTwelve, including the official empty-input vector and the
    // single-chunk / tree boundary at 8191/8192 bytes plus a multi-leaf tree.
    #[test]
    fn k12_vectors() {
        assert_eq!(
            k12(b""),
            from_hex::<32>("1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5")
        );

        let mut buf = [0u8; 20000];
        ptn(&mut buf);

        let mut out = [0u8; 32];
        let mut h = KangarooTwelve::new(b"");
        h.update(&buf[..8191]);
        h.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<32>("1b577636f723643e990cc7d6a659837436fd6a103626600eb8301cd1dbe553d6")
        );

        // Exactly one chunk of input -> S is 8193 bytes -> the tree path.
        let mut out = [0u8; 32];
        let mut h = KangarooTwelve::new(b"");
        h.update(&buf[..8192]);
        h.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<32>("48f256f6772f9edfb6a8b661ec92dc93b95ebd05a08a17b39ae3490870c926c3")
        );

        // Multi-leaf tree.
        let mut out = [0u8; 32];
        let mut h = KangarooTwelve::new(b"");
        h.update(&buf[..20000]);
        h.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<32>("aaceb6bef2500ce3e21cb7521a9d0fca8e315fc6490785cead7eefb99aefb912")
        );
    }

    #[test]
    fn k12_customization() {
        let mut msg = [0u8; 100];
        ptn(&mut msg);
        let mut cust = [0u8; 20];
        ptn(&mut cust);

        let mut out = [0u8; 32];
        let mut h = KangarooTwelve::new(&cust);
        h.update(&msg);
        h.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<32>("6c37a41c15832f04231f8ef17a31266b957191dd5423dc8e7d7c6b090c0c19ec")
        );
    }

    // MarsupilamiFourteen (Keccak-p[1600,14], rate 136, 64-byte CVs).
    //
    // No direct hex KATs are published for the original 14-round M14 (the K12
    // paper's Appendix B is K12-only, and later code packages replaced M14 with
    // the 12-round CFRG `KT256`). These vectors were produced by an independent
    // Python Keccak-p tree-hash reference that was first validated to reproduce
    // every published K12 vector (paper Appendix B) and this module's own K12
    // boundary vectors byte-for-byte, then re-parameterized to rate 136 / 64-byte
    // CV / 14 rounds. Covers the single-node path, the 8191/8192 tree boundary,
    // and a multi-leaf tree.
    #[test]
    fn m14_vectors() {
        assert_eq!(
            m14(b""),
            from_hex::<64>(
                "6f66ef1474eb53807aa329257c768bb88893d9f086e51da2f5c80d17ca0fc57d5a24fac879014f8b30a3fdf5ac56ebafa219eb891d4bbbab7e1df3b27205b459"
            )
        );

        let mut buf = [0u8; 20000];
        ptn(&mut buf);

        // 8191 bytes -> S is 8192 bytes -> the single-node path.
        let mut out = [0u8; 64];
        let mut h = MarsupilamiFourteen::new(b"");
        h.update(&buf[..8191]);
        h.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<64>(
                "8884e4ea956aba88d03cc52e4ccbe236543a494d850bc8c663ed1606fef9ab608d5f223ecd73ea2a832a3f717eb18218baf5cacd214d2aff41c4e9f82136c13d"
            )
        );

        // 8192 bytes -> S is 8193 bytes -> the tree path (one leaf).
        let mut out = [0u8; 64];
        let mut h = MarsupilamiFourteen::new(b"");
        h.update(&buf[..8192]);
        h.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<64>(
                "56926c1964f5f1051da69d7d550b7377817cb084527efaedddfc49a07b829bd02ab73cd5dff77a6e8bfb30eb627674273dbb7530b688c4e9e03317e516f098a5"
            )
        );

        // Multi-leaf tree.
        let mut out = [0u8; 64];
        let mut h = MarsupilamiFourteen::new(b"");
        h.update(&buf[..20000]);
        h.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<64>(
                "5f568c5d2bfb708dacfd7687b8cd30c6f19ff78566996e420c5e52601d332d02ff6519c15766ec414ba84badeeab18a802a1622cbe8e0d0b804aba08f419b685"
            )
        );
    }

    // Arbitrary chunking across the 8 KiB tree boundary equals the one-shot.
    #[test]
    fn m14_streaming_matches_oneshot() {
        let mut buf = [0u8; 20000];
        ptn(&mut buf);

        let mut a = [0u8; 64];
        let mut h = MarsupilamiFourteen::new(b"");
        for c in buf.chunks(777) {
            h.update(c);
        }
        h.finalize_into(&mut a);

        assert_eq!(a, m14(&buf));
    }

    #[test]
    fn k12_streaming_and_xof_read() {
        let mut buf = [0u8; 20000];
        ptn(&mut buf);

        // Arbitrary chunking matches one-shot.
        let mut a = [0u8; 64];
        let mut h = KangarooTwelve::new(b"ctx");
        for c in buf.chunks(777) {
            h.update(c);
        }
        let mut r = h.finalize_xof();
        r.read(&mut a[..7]);
        r.read(&mut a[7..]);

        let mut b = [0u8; 64];
        let mut h = KangarooTwelve::new(b"ctx");
        h.update(&buf);
        h.finalize_into(&mut b);
        assert_eq!(a, b);
    }
}
