//! SipHash (Aumasson–Bernstein): a fast keyed pseudorandom function for
//! short inputs, with 64-bit ([`SipHash`]) and 128-bit ([`SipHashX`]) output.
//!
//! SipHash-c-d runs `c` rounds of the ARX permutation per 8-byte message
//! word and `d` rounds at the end. The standard parameter sets are:
//!
//! - [`SipHash24`] — SipHash-2-4, the default recommended by the authors.
//! - [`SipHash13`] — SipHash-1-3, the faster variant used by many hash-table
//!   implementations (including Rust's own `DefaultHasher`).
//! - [`SipHash48`] — SipHash-4-8, the conservative variant.
//! - [`SipHashX24`] / [`SipHashX48`] — the 128-bit-output "SipHash-X"
//!   variants from the reference implementation (`siphash.c` with
//!   `OUTLEN 16`): the initial state is tweaked with `v1 ^= 0xee`, the
//!   finalization constant is `0xee` instead of `0xff`, and a second
//!   finalization with `v1 ^= 0xdd` produces the high half.
//!
//! All of them take a 128-bit key. The message is read as little-endian
//! 64-bit words; the last (partial) word carries the message length modulo
//! 256 in its top byte.
//!
//! SipHash is a MAC/PRF with a 64-bit (or 128-bit) security level against
//! forgery; it is **not** a collision-resistant hash and must not be used
//! unkeyed. The permutation is pure add-rotate-xor on 64-bit words, so the
//! computation is inherently free of secret-dependent branches, table
//! lookups and indexing; only the message length steers control flow.
//!
//! # Example
//!
//! ```
//! use purecrypto::mac::SipHash24;
//!
//! let key = [0u8; 16];
//! let tag = SipHash24::compute(&key, b"hello");
//! assert!(SipHash24::new(&key).chain(b"hello").verify(&tag));
//! ```

use crate::ct::ConstantTimeEq;
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// SipHash-1-3: one compression round, three finalization rounds.
pub type SipHash13 = SipHash<1, 3>;
/// SipHash-2-4, the default parameter set.
pub type SipHash24 = SipHash<2, 4>;
/// SipHash-4-8, the conservative parameter set.
pub type SipHash48 = SipHash<4, 8>;
/// SipHash-2-4 with 128-bit output.
pub type SipHashX24 = SipHashX<2, 4>;
/// SipHash-4-8 with 128-bit output.
pub type SipHashX48 = SipHashX<4, 8>;

/// The four initialization constants: ASCII `"somepseudorandomlygeneratedbytes"`.
const V0: u64 = 0x736f_6d65_7073_6575;
const V1: u64 = 0x646f_7261_6e64_6f6d;
const V2: u64 = 0x6c79_6765_6e65_7261;
const V3: u64 = 0x7465_6462_7974_6573;

/// One SipRound.
#[inline(always)]
fn sip_round(v: &mut [u64; 4]) {
    v[0] = v[0].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(13);
    v[1] ^= v[0];
    v[0] = v[0].rotate_left(32);
    v[2] = v[2].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(16);
    v[3] ^= v[2];
    v[0] = v[0].wrapping_add(v[3]);
    v[3] = v[3].rotate_left(21);
    v[3] ^= v[0];
    v[2] = v[2].wrapping_add(v[1]);
    v[1] = v[1].rotate_left(17);
    v[1] ^= v[2];
    v[2] = v[2].rotate_left(32);
}

/// `n` SipRounds.
#[inline(always)]
fn sip_rounds(v: &mut [u64; 4], n: usize) {
    for _ in 0..n {
        sip_round(v);
    }
}

/// The streaming core shared by [`SipHash`] and [`SipHashX`]. `XLEN` is
/// true for the 128-bit-output variant, which differs only in three
/// constants.
#[derive(Clone)]
struct Core<const C: usize, const D: usize, const XLEN: bool> {
    v: [u64; 4],
    /// Up to 7 bytes of the current (incomplete) message word.
    tail: [u8; 8],
    tail_len: usize,
    /// Total message length in bytes; only the low byte is used by the
    /// algorithm, but it wraps naturally.
    len: u64,
}

impl<const C: usize, const D: usize, const XLEN: bool> Core<C, D, XLEN> {
    fn new(key: &[u8; 16]) -> Self {
        let k0 = u64::from_le_bytes(key[..8].try_into().expect("8 bytes"));
        let k1 = u64::from_le_bytes(key[8..].try_into().expect("8 bytes"));
        let mut v = [V0 ^ k0, V1 ^ k1, V2 ^ k0, V3 ^ k1];
        if XLEN {
            v[1] ^= 0xee;
        }
        Self {
            v,
            tail: [0; 8],
            tail_len: 0,
            len: 0,
        }
    }

    #[inline(always)]
    fn compress(&mut self, m: u64) {
        self.v[3] ^= m;
        sip_rounds(&mut self.v, C);
        self.v[0] ^= m;
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.tail_len > 0 {
            let take = (8 - self.tail_len).min(data.len());
            self.tail[self.tail_len..self.tail_len + take].copy_from_slice(&data[..take]);
            self.tail_len += take;
            data = &data[take..];
            if self.tail_len < 8 {
                return;
            }
            self.compress(u64::from_le_bytes(self.tail));
            self.tail_len = 0;
        }
        let mut words = data.chunks_exact(8);
        for w in &mut words {
            self.compress(u64::from_le_bytes(w.try_into().expect("8 bytes")));
        }
        let rest = words.remainder();
        self.tail[..rest.len()].copy_from_slice(rest);
        self.tail_len = rest.len();
    }

    /// Consumes the state and returns `(low, high)` output words; `high` is
    /// only meaningful (and only computed) when `XLEN` is set.
    fn finalize(mut self) -> (u64, u64) {
        // Last word: the remaining bytes little-endian, with `len mod 256`
        // in the top byte. The unused bytes of `tail` are zero.
        self.tail[self.tail_len..7].fill(0);
        self.tail[7] = self.len as u8;
        let b = u64::from_le_bytes(self.tail);
        self.compress(b);
        self.v[2] ^= if XLEN { 0xee } else { 0xff };
        sip_rounds(&mut self.v, D);
        let lo = self.v[0] ^ self.v[1] ^ self.v[2] ^ self.v[3];
        if !XLEN {
            return (lo, 0);
        }
        self.v[1] ^= 0xdd;
        sip_rounds(&mut self.v, D);
        let hi = self.v[0] ^ self.v[1] ^ self.v[2] ^ self.v[3];
        (lo, hi)
    }
}

impl<const C: usize, const D: usize, const XLEN: bool> Drop for Core<C, D, XLEN> {
    fn drop(&mut self) {
        // The state is a keyed function of the message; wipe both it and the
        // buffered plaintext bytes.
        self.v.zeroize();
        self.tail.zeroize();
        self.tail_len = 0;
        self.len = 0;
    }
}

impl<const C: usize, const D: usize, const XLEN: bool> ZeroizeOnDrop for Core<C, D, XLEN> {}

/// SipHash-`C`-`D` with a 64-bit output.
///
/// Construct with [`new`](Self::new), absorb input via
/// [`update`](Self::update) (or [`chain`](Self::chain)), and commit with
/// [`finalize`](Self::finalize) / [`finalize_u64`](Self::finalize_u64), or
/// check a received tag in constant time with [`verify`](Self::verify).
/// The state also implements [`core::hash::Hasher`], so it can be used
/// directly as a keyed hasher for `Hash` types.
#[derive(Clone)]
pub struct SipHash<const C: usize, const D: usize> {
    core: Core<C, D, false>,
}

impl<const C: usize, const D: usize> SipHash<C, D> {
    /// Creates a new SipHash-`C`-`D` state under the 128-bit `key`.
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            core: Core::new(key),
        }
    }

    /// Absorbs `data` into the streaming state.
    pub fn update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    /// Absorbs `data` and returns the state, for one-line construction.
    #[must_use]
    pub fn chain(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }

    /// Consumes the state and returns the 64-bit output as an integer.
    pub fn finalize_u64(self) -> u64 {
        self.core.finalize().0
    }

    /// Consumes the state and returns the 8-byte tag (the output word in
    /// little-endian order, as in the reference implementation).
    pub fn finalize(self) -> [u8; 8] {
        self.finalize_u64().to_le_bytes()
    }

    /// Consumes the state and checks `expected` against the recomputed tag
    /// in constant time.
    ///
    /// Returns `true` iff `expected` is a full 8-byte tag equal to the
    /// recomputed tag. Truncated tags (including the empty slice) are
    /// rejected unconditionally: accepting a short `n`-byte prefix would drop
    /// forgery resistance to `2^(8n)`, and an empty tag would be an
    /// unconditional accept. The comparison time of the full-length path
    /// depends only on the (public) tag length, not on where any mismatch
    /// occurs, and the recomputed tag is wiped before returning.
    pub fn verify(self, expected: &[u8]) -> bool {
        if expected.len() != 8 {
            return false;
        }
        let mut tag = self.finalize();
        let ok = bool::from(tag[..].ct_eq(expected));
        tag.zeroize();
        ok
    }

    /// One-shot: the 8-byte SipHash-`C`-`D` tag of `data` under `key`.
    pub fn compute(key: &[u8; 16], data: &[u8]) -> [u8; 8] {
        Self::new(key).chain(data).finalize()
    }

    /// One-shot: the 64-bit SipHash-`C`-`D` output of `data` under `key`.
    pub fn compute_u64(key: &[u8; 16], data: &[u8]) -> u64 {
        Self::new(key).chain(data).finalize_u64()
    }
}

impl<const C: usize, const D: usize> core::hash::Hasher for SipHash<C, D> {
    /// The 64-bit SipHash output of everything written so far. The state
    /// is left untouched, so further `write`s continue the same message.
    fn finish(&self) -> u64 {
        self.clone().finalize_u64()
    }

    fn write(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}

/// SipHash-`C`-`D` with a 128-bit output ("SipHash-X", the `OUTLEN 16` mode
/// of the reference implementation).
///
/// Same API as [`SipHash`], minus the `Hasher` impl and the `u64` accessors.
#[derive(Clone)]
pub struct SipHashX<const C: usize, const D: usize> {
    core: Core<C, D, true>,
}

impl<const C: usize, const D: usize> SipHashX<C, D> {
    /// Creates a new SipHash-`C`-`D`-128 state under the 128-bit `key`.
    pub fn new(key: &[u8; 16]) -> Self {
        Self {
            core: Core::new(key),
        }
    }

    /// Absorbs `data` into the streaming state.
    pub fn update(&mut self, data: &[u8]) {
        self.core.update(data);
    }

    /// Absorbs `data` and returns the state, for one-line construction.
    #[must_use]
    pub fn chain(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }

    /// Consumes the state and returns the 16-byte tag (both output words
    /// little-endian, low word first, as in the reference implementation).
    pub fn finalize(self) -> [u8; 16] {
        let (lo, hi) = self.core.finalize();
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&lo.to_le_bytes());
        out[8..].copy_from_slice(&hi.to_le_bytes());
        out
    }

    /// Consumes the state and checks `expected` against the recomputed tag
    /// in constant time. Returns `true` iff `expected` is a full 16-byte tag
    /// equal to the recomputed tag; see [`SipHash::verify`] for why
    /// truncated tags are rejected unconditionally.
    pub fn verify(self, expected: &[u8]) -> bool {
        if expected.len() != 16 {
            return false;
        }
        let mut tag = self.finalize();
        let ok = bool::from(tag[..].ct_eq(expected));
        tag.zeroize();
        ok
    }

    /// One-shot: the 16-byte SipHash-`C`-`D`-128 tag of `data` under `key`.
    pub fn compute(key: &[u8; 16], data: &[u8]) -> [u8; 16] {
        Self::new(key).chain(data).finalize()
    }
}

// ---------------------------------------------------------------------------
//  Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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

    /// The key and messages of the reference `vectors.h`: `key[i] = i`,
    /// `msg[i] = i`, message lengths 0..64.
    const KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

    fn msg() -> [u8; 64] {
        let mut m = [0u8; 64];
        for (i, b) in m.iter_mut().enumerate() {
            *b = i as u8;
        }
        m
    }

    /// `vectors_sip64` from the reference repository: SipHash-2-4, 64-bit
    /// output, for message lengths 0..64.
    const SIP64: [&str; 64] = [
        "310e0edd47db6f72",
        "fd67dc93c539f874",
        "5a4fa9d909806c0d",
        "2d7efbd796666785",
        "b7877127e09427cf",
        "8da699cd64557618",
        "cee3fe586e46c9cb",
        "37d1018bf50002ab",
        "6224939a79f5f593",
        "b0e4a90bdf82009e",
        "f3b9dd94c5bb5d7a",
        "a7ad6b22462fb3f4",
        "fbe50e86bc8f1e75",
        "903d84c02756ea14",
        "eef27a8e90ca23f7",
        "e545be4961ca29a1",
        "db9bc2577fcc2a3f",
        "9447be2cf5e99a69",
        "9cd38d96f0b3c14b",
        "bd6179a71dc96dbb",
        "98eea21af25cd6be",
        "c7673b2eb0cbf2d0",
        "883ea3e395675393",
        "c8ce5ccd8c030ca8",
        "94af49f6c650adb8",
        "eab8858ade92e1bc",
        "f315bb5bb835d817",
        "adcf6b0763612e2f",
        "a5c91da7acaa4dde",
        "716595876650a2a6",
        "28ef495c53a387ad",
        "42c341d8fa92d832",
        "ce7cf2722f512771",
        "e37859f94623f3a7",
        "381205bb1ab0e012",
        "ae97a10fd434e015",
        "b4a31508beff4d31",
        "81396229f0907902",
        "4d0cf49ee5d4dcca",
        "5c73336a76d8bf9a",
        "d0a704536ba93e0e",
        "925958fcd6420cad",
        "a915c29bc8067318",
        "952b79f3bc0aa6d4",
        "f21df2e41d4535f9",
        "87577519048f53a9",
        "10a56cf5dfcd9adb",
        "eb75095ccd986cd0",
        "51a9cb9ecba312e6",
        "96afadfc2ce666c7",
        "72fe52975a4364ee",
        "5a1645b276d592a1",
        "b274cb8ebf87870a",
        "6f9bb4203de7b381",
        "eaecb2a30b22a87f",
        "9924a43cc1315724",
        "bd838d3aafbf8db7",
        "0b1a2a3265d51aea",
        "135079a3231ce660",
        "932b2846e4d70666",
        "e1915f5cb1eca46c",
        "f325965ca16d629f",
        "575ff28e60381be5",
        "724506eb4c328a95",
    ];

    /// `vectors_sip128` from the reference repository: SipHash-2-4, 128-bit
    /// output, for message lengths 0..64.
    const SIP128: [&str; 64] = [
        "a3817f04ba25a8e66df67214c7550293",
        "da87c1d86b99af44347659119b22fc45",
        "8177228da4a45dc7fca38bdef60affe4",
        "9c70b60c5267a94e5f33b6b02985ed51",
        "f88164c12d9c8faf7d0f6e7c7bcd5579",
        "1368875980776f8854527a07690e9627",
        "14eeca338b208613485ea0308fd7a15e",
        "a1f1ebbed8dbc153c0b84aa61ff08239",
        "3b62a9ba6258f5610f83e264f31497b4",
        "264499060ad9baabc47f8b02bb6d71ed",
        "00110dc378146956c95447d3f3d0fbba",
        "0151c568386b6677a2b4dc6f81e5dc18",
        "d626b266905ef35882634df68532c125",
        "9869e247e9c08b10d029934fc4b952f7",
        "31fcefac66d7de9c7ec7485fe4494902",
        "5493e99933b0a8117e08ec0f97cfc3d9",
        "6ee2a4ca67b054bbfd3315bf85230577",
        "473d06e8738db89854c066c47ae47740",
        "a426e5e423bf4885294da481feaef723",
        "78017731cf65fab074d5208952512eb1",
        "9e25fc833f2290733e9344a5e83839eb",
        "568e495abe525a218a2214cd3e071d12",
        "4a29b54552d16b9a469c10528eff0aae",
        "c9d184ddd5a9f5e0cf8ce29a9abf691c",
        "2db479ae78bd50d8882a8a178a6132ad",
        "8ece5f042d5e447b5051b9eacb8d8f6f",
        "9c0b53b4b3c307e87eaee08678141f66",
        "abf248af69a6eae4bfd3eb2f129eeb94",
        "0664da1668574b88b935f3027358aef4",
        "aa4b9dc4bf337de90cd4fd3c467c6ab7",
        "ea5c7f471faf6bde2b1ad7d4686d2287",
        "2939b0183223fafc1723de4f52c43d35",
        "7c3956ca5eeafc3e363e9d556546eb68",
        "77c6077146f01c32b6b69d5f4ea9ffcf",
        "37a6986cb8847edf0925f0f1309b54de",
        "a705f0e69da9a8f907241a2e923c8cc8",
        "3dc47d1f29c448461e9e76ed904f6711",
        "0d62bf01e6fc0e1a0d3c4751c5d3692b",
        "8c03468bca7c669ee4fd5e084bbee7b5",
        "528a5bb93baf2c9c4473cce5d0d22bd9",
        "df6a301e95c95dad97ae0cc8c6913bd8",
        "801189902c857f39e73591285e70b6db",
        "e617346ac9c231bb3650ae34ccca0c5b",
        "27d93437efb721aa401821dcec5adf89",
        "89237d9ded9c5e78d8b1c9b166cc7342",
        "4a6d8091bf5e7d651189fa94a250b14c",
        "0e33f96055e7ae893ffc0e3dcf492902",
        "e61c432b720b19d18ec8d84bdc63151b",
        "f7e5aef549f782cf379055a608269b16",
        "438d030fd0b7a54fa837f2ad201a6403",
        "a590d3ee4fbf04e3247e0d27f286423f",
        "5fe2c1a172fe93c4b15cd37caef9f538",
        "2c97325cbd06b36eb2133dd08b3a017c",
        "92c814227a6bca949ff0659f002ad39e",
        "dce850110bd8328cfbd50841d6911d87",
        "67f14984c7da791248e32bb5922583da",
        "1938f2cf72d54ee97e94166fa91d2a36",
        "74481e9646ed49fe0f6224301604698e",
        "57fca5de98a9d6d8006438d0583d8a1d",
        "9fecde1cefdc1cbed4763674d9575359",
        "e3040c00eb28f15366ca73cbd872e740",
        "7697009a6a831dfecca91c5993670f7a",
        "5853542321f567a005d547a4f04759bd",
        "5150d1772f50834a503e069a973fbd7c",
    ];

    #[test]
    fn paper_example() {
        // SipHash paper, Appendix A: SipHash-2-4 of the 15-byte message
        // 00 01 .. 0e under the key 00 01 .. 0f.
        let m = msg();
        assert_eq!(
            SipHash24::compute_u64(&KEY, &m[..15]),
            0xa129_ca61_49be_45e5
        );
    }

    #[test]
    fn reference_vectors_sip64() {
        let m = msg();
        for (len, expected) in SIP64.iter().enumerate() {
            let expected: [u8; 8] = from_hex(expected);
            assert_eq!(SipHash24::compute(&KEY, &m[..len]), expected, "len {len}");
            assert!(SipHash24::new(&KEY).chain(&m[..len]).verify(&expected));
        }
    }

    #[test]
    fn reference_vectors_sip128() {
        let m = msg();
        for (len, expected) in SIP128.iter().enumerate() {
            let expected: [u8; 16] = from_hex(expected);
            assert_eq!(SipHashX24::compute(&KEY, &m[..len]), expected, "len {len}");
            assert!(SipHashX24::new(&KEY).chain(&m[..len]).verify(&expected));
        }
    }

    #[test]
    fn other_parameter_sets() {
        // Empty-message outputs of the other parameter sets, cross-checked
        // against the Wycheproof `siphash_*` / `siphashx_*` files (tcId 1
        // of each; the full files run in the integration harness).
        let key: [u8; 16] = from_hex("e7ab5e259fe55d624340e495e65a5bf8");
        assert_eq!(SipHash13::compute(&key, b""), from_hex("4e2113cd24d3fa47"));
        assert_eq!(SipHash24::compute(&key, b""), from_hex("885d34ee080998a8"));
        assert_eq!(SipHash48::compute(&key, b""), from_hex("6c1dfa47ef16a260"));
        let key: [u8; 16] = from_hex("e34f15c7bd819930fe9d66e0c166e61c");
        assert_eq!(
            SipHashX24::compute(&key, b""),
            from_hex("b3d2df1f8506643dc8f803a3ceb67f85")
        );
        assert_eq!(
            SipHashX48::compute(&key, b""),
            from_hex("aa385bc1d9a1b1d755213066bc5a973b")
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let mut data = [0u8; 300];
        for (i, b) in data.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        let one_shot = SipHash24::compute(&KEY, &data);
        let one_shot_x = SipHashX48::compute(&KEY, &data);
        // Every split point pattern that crosses word boundaries oddly.
        for &splits in &[
            [1usize, 7, 9, 16, 3, 100],
            [8, 8, 8, 1, 1, 1],
            [5, 3, 13, 64, 2, 200],
        ] {
            let mut s = SipHash24::new(&KEY);
            let mut sx = SipHashX48::new(&KEY);
            let mut off = 0;
            let mut i = 0;
            while off < data.len() {
                let take = splits[i % splits.len()].min(data.len() - off);
                s.update(&data[off..off + take]);
                sx.update(&data[off..off + take]);
                off += take;
                i += 1;
            }
            assert_eq!(s.finalize(), one_shot);
            assert_eq!(sx.finalize(), one_shot_x);
        }
    }

    #[test]
    fn hasher_impl() {
        use core::hash::Hasher;
        let m = msg();
        let mut h = SipHash24::new(&KEY);
        h.write(&m[..3]);
        h.write(&m[3..20]);
        assert_eq!(h.finish(), SipHash24::compute_u64(&KEY, &m[..20]));
        // `finish` does not consume: continuing the stream still works.
        h.write(&m[20..33]);
        assert_eq!(h.finish(), SipHash24::compute_u64(&KEY, &m[..33]));
    }

    #[test]
    fn verify_is_length_strict() {
        let tag = SipHash24::compute(&KEY, b"abc");
        assert!(SipHash24::new(&KEY).chain(b"abc").verify(&tag));
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(!SipHash24::new(&KEY).chain(b"abc").verify(&bad));
        assert!(!SipHash24::new(&KEY).chain(b"abc").verify(&tag[..7]));
        assert!(!SipHash24::new(&KEY).chain(b"abc").verify(&[]));
        assert!(!SipHash24::new(&KEY).chain(b"abd").verify(&tag));

        let tag = SipHashX24::compute(&KEY, b"abc");
        assert!(SipHashX24::new(&KEY).chain(b"abc").verify(&tag));
        assert!(!SipHashX24::new(&KEY).chain(b"abc").verify(&tag[..15]));
        assert!(!SipHashX24::new(&KEY).chain(b"abc").verify(&[]));
        // The 64-bit tag is not a prefix of the 128-bit one (different
        // initialization), and is rejected as a length mismatch anyway.
        assert!(
            !SipHashX24::new(&KEY)
                .chain(b"abc")
                .verify(&SipHash24::compute(&KEY, b"abc"))
        );
    }
}
