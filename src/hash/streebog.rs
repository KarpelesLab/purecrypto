//! Streebog — GOST R 34.11-2012 (RFC 6986), 256-bit and 512-bit variants.
//!
//! The Russian national hash standard, included for GOST TLS/PKI interop in the
//! same spirit as SM3 (the Chinese national hash). Both output sizes share one
//! compression function; the 256-bit variant differs only in its initial vector
//! and by emitting the most-significant 32 bytes of the final state.
//!
//! The compression uses a fixed 256-byte substitution table (`PI`) plus a linear
//! transform built at compile time from the published `A` constants. As with the
//! other table-based hashes here, the lookups are not constant-time with respect
//! to the (public) message bytes.

use super::Digest;

/// Decodes a single ASCII hex digit (`0-9`, `a-f`, `A-F`) to its 4-bit value.
const fn hexval(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Decodes a 128-char ASCII hex literal into the 64 bytes it represents.
const fn dehex(s: &[u8; 128]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut i = 0;
    while i < 64 {
        out[i] = (hexval(s[2 * i]) << 4) | hexval(s[2 * i + 1]);
        i += 1;
    }
    out
}

/// The Streebog substitution box `π` (RFC 6986 §5.1).
#[rustfmt::skip]
const PI: [u8; 256] = [
    252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77,
    233, 119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193,
    249, 24, 101, 90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79,
    5, 132, 2, 174, 227, 106, 143, 160, 6, 11, 237, 152, 127, 212, 211, 31,
    235, 52, 44, 81, 234, 200, 72, 171, 242, 42, 104, 162, 253, 58, 206, 204,
    181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71, 156, 183, 93, 135,
    21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158, 178, 177,
    50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87,
    223, 245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3,
    224, 15, 236, 222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74,
    167, 151, 96, 115, 30, 0, 98, 68, 26, 184, 56, 130, 100, 159, 38, 65,
    173, 69, 70, 146, 39, 94, 85, 47, 140, 163, 165, 125, 105, 213, 149, 59,
    7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228, 136, 217, 231, 137,
    225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216, 133, 97,
    32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82,
    89, 166, 116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182,
];

/// The 64 row vectors of the linear transform `l` (RFC 6986 §5.3), as the
/// published big-endian `A` constants in MSB-first order (`A[0]` is the row for
/// the most-significant bit). The compression function works on little-endian
/// `u64` lanes, so the fast `SHUFFLED_LIN_TABLE` indexes a reversed copy.
#[rustfmt::skip]
const A: [u64; 64] = [
    0x8e20faa72ba0b470, 0x47107ddd9b505a38, 0xad08b0e0c3282d1c, 0xd8045870ef14980e,
    0x6c022c38f90a4c07, 0x3601161cf205268d, 0x1b8e0b0e798c13c8, 0x83478b07b2468764,
    0xa011d380818e8f40, 0x5086e740ce47c920, 0x2843fd2067adea10, 0x14aff010bdd87508,
    0x0ad97808d06cb404, 0x05e23c0468365a02, 0x8c711e02341b2d01, 0x46b60f011a83988e,
    0x90dab52a387ae76f, 0x486dd4151c3dfdb9, 0x24b86a840e90f0d2, 0x125c354207487869,
    0x092e94218d243cba, 0x8a174a9ec8121e5d, 0x4585254f64090fa0, 0xaccc9ca9328a8950,
    0x9d4df05d5f661451, 0xc0a878a0a1330aa6, 0x60543c50de970553, 0x302a1e286fc58ca7,
    0x18150f14b9ec46dd, 0x0c84890ad27623e0, 0x0642ca05693b9f70, 0x0321658cba93c138,
    0x86275df09ce8aaa8, 0x439da0784e745554, 0xafc0503c273aa42a, 0xd960281e9d1d5215,
    0xe230140fc0802984, 0x71180a8960409a42, 0xb60c05ca30204d21, 0x5b068c651810a89e,
    0x456c34887a3805b9, 0xac361a443d1c8cd2, 0x561b0d22900e4669, 0x2b838811480723ba,
    0x9bcf4486248d9f5d, 0xc3e9224312c8c1a0, 0xeffa11af0964ee50, 0xf97d86d98a327728,
    0xe4fa2054a80b329c, 0x727d102a548b194e, 0x39b008152acb8227, 0x9258048415eb419d,
    0x492c024284fbaec0, 0xaa16012142f35760, 0x550b8e9e21f7a530, 0xa48b474f9ef5dc18,
    0x70a6a56e2440598e, 0x3853dc371220a247, 0x1ca76e95091051ad, 0x0edd37c48a08a6d8,
    0x07e095624504536c, 0x8d70c431ac02a736, 0xc83862965601dd1b, 0x641c314b2b8ee083,
];

/// The 12 round constants `C[1..=12]` (RFC 6986 §8), one 512-bit value each.
const C: [[u8; 64]; 12] = [
    dehex(b"b1085bda1ecadae9ebcb2f81c0657c1f2f6a76432e45d016714eb88d7585c4fc4b7ce09192676901a2422a08a460d31505767436cc744d23dd806559f2a64507"),
    dehex(b"6fa3b58aa99d2f1a4fe39d460f70b5d7f3feea720a232b9861d55e0f16b501319ab5176b12d699585cb561c2db0aa7ca55dda21bd7cbcd56e679047021b19bb7"),
    dehex(b"f574dcac2bce2fc70a39fc286a3d843506f15e5f529c1f8bf2ea7514b1297b7bd3e20fe490359eb1c1c93a376062db09c2b6f443867adb31991e96f50aba0ab2"),
    dehex(b"ef1fdfb3e81566d2f948e1a05d71e4dd488e857e335c3c7d9d721cad685e353fa9d72c82ed03d675d8b71333935203be3453eaa193e837f1220cbebc84e3d12e"),
    dehex(b"4bea6bacad4747999a3f410c6ca923637f151c1f1686104a359e35d7800fffbdbfcd1747253af5a3dfff00b723271a167a56a27ea9ea63f5601758fd7c6cfe57"),
    dehex(b"ae4faeae1d3ad3d96fa4c33b7a3039c02d66c4f95142a46c187f9ab49af08ec6cffaa6b71c9ab7b40af21f66c2bec6b6bf71c57236904f35fa68407a46647d6e"),
    dehex(b"f4c70e16eeaac5ec51ac86febf240954399ec6c7e6bf87c9d3473e33197a93c90992abc52d822c3706476983284a05043517454ca23c4af38886564d3a14d493"),
    dehex(b"9b1f5b424d93c9a703e7aa020c6e41414eb7f8719c36de1e89b4443b4ddbc49af4892bcb929b069069d18d2bd1a5c42f36acc2355951a8d9a47f0dd4bf02e71e"),
    dehex(b"378f5a541631229b944c9ad8ec165fde3a7d3a1b258942243cd955b7e00d0984800a440bdbb2ceb17b2b8a9aa6079c540e38dc92cb1f2a607261445183235adb"),
    dehex(b"abbedea680056f52382ae548b2e4f3f38941e71cff8a78db1fffe18a1b3361039fe76702af69334b7a1e6c303b7652f43698fad1153bb6c374b4c7fb98459ced"),
    dehex(b"7bcd9ed0efc889fb3002c6cd635afe94d8fa6bbbebab076120018021148466798a1d71efea48b9caefbacd1d7d476e98dea2594ac06fd85d6bcaa4cd81f32d1b"),
    dehex(b"378ee767f11631bad21380b00449b17acda43c32bcdf1d77f82012d430219f9b5d80ef9d1891cc86e71da4aa88e12852faf417d5d9b21b9948bc924af11bd720"),
];

/// The `A` rows in reversed (LSB-first) order, matching the little-endian `u64`
/// lane convention: bit `k` of a lane selects `A_REV[8*i + k]`.
const A_REV: [u64; 64] = {
    let mut r = [0u64; 64];
    let mut i = 0;
    while i < 64 {
        r[i] = A[63 - i];
        i += 1;
    }
    r
};

/// Precomputed `L ∘ P ∘ S` table: `SHUFFLED_LIN_TABLE[j][b]` is the contribution
/// of byte value `b` occupying lane `j` to the transformed state. Built at
/// compile time from `PI` (the S-box) and `A_REV` (the linear rows); the byte
/// permutation `P` is realized by the lane/byte transposition in `lps`.
const SHUFFLED_LIN_TABLE: [[u64; 256]; 8] = {
    let mut table = [[0u64; 256]; 8];
    let mut i = 0;
    while i < 8 {
        let mut b = 0;
        while b < 256 {
            let mut acc = 0u64;
            let mut k = 0;
            while k < 8 {
                if PI[b] & (1u8 << k) != 0 {
                    acc ^= A_REV[8 * i + k];
                }
                k += 1;
            }
            table[i][b] = acc;
            b += 1;
        }
        i += 1;
    }
    table
};

/// The 12 round constants as little-endian `u64` lanes. Each published constant
/// is byte-reversed (RFC 6986 gives it big-endian) before being split into eight
/// little-endian lanes, so it lines up with the state's lane representation.
const C64: [[u64; 8]; 12] = {
    let mut out = [[0u64; 8]; 12];
    let mut i = 0;
    while i < 12 {
        let mut rev = [0u8; 64];
        let mut p = 0;
        while p < 64 {
            rev[p] = C[i][63 - p];
            p += 1;
        }
        let mut j = 0;
        while j < 8 {
            let mut lane = 0u64;
            let mut k = 0;
            while k < 8 {
                lane |= (rev[8 * j + k] as u64) << (8 * k);
                k += 1;
            }
            out[i][j] = lane;
            j += 1;
        }
        i += 1;
    }
    out
};

/// Add-with-carry: `*a = a + b + carry`, updating `carry`.
#[inline(always)]
fn adc(a: &mut u64, b: u64, carry: &mut bool) {
    let (x, c1) = a.overflowing_add(b);
    let (y, c2) = x.overflowing_add(*carry as u64);
    *a = y;
    *carry = c1 || c2;
}

/// Reads a 512-bit block as eight little-endian `u64` lanes.
#[inline]
fn from_bytes(b: &[u8; 64]) -> [u64; 8] {
    let mut t = [0u64; 8];
    let mut i = 0;
    while i < 8 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&b[8 * i..8 * i + 8]);
        t[i] = u64::from_le_bytes(chunk);
        i += 1;
    }
    t
}

/// Serializes eight little-endian `u64` lanes back to a 512-bit block.
#[inline]
fn to_bytes(h: &[u64; 8]) -> [u8; 64] {
    let mut t = [0u8; 64];
    let mut i = 0;
    while i < 8 {
        t[8 * i..8 * i + 8].copy_from_slice(&h[i].to_le_bytes());
        i += 1;
    }
    t
}

/// The `LPS` transform fused with the preceding XOR: `h ← L(P(S(h ⊕ n)))`.
#[inline(always)]
fn lps(h: &mut [u64; 8], n: &[u64; 8]) {
    for i in 0..8 {
        h[i] ^= n[i];
    }
    let mut buf = [0u64; 8];
    for (i, slot) in buf.iter_mut().enumerate() {
        for j in 0..8 {
            let idx = ((h[j] >> (8 * i)) & 0xff) as usize;
            *slot ^= SHUFFLED_LIN_TABLE[j][idx];
        }
    }
    *h = buf;
}

/// The compression function `g_N(h, m)` (RFC 6986 §7): `E(LPS(h ⊕ N), m) ⊕ h ⊕ m`.
fn g(h: &mut [u64; 8], n: &[u64; 8], m: &[u64; 8]) {
    let mut key = *h;
    let mut block = *m;
    lps(&mut key, n);
    let mut i = 0;
    while i < 12 {
        lps(&mut block, &key);
        lps(&mut key, &C64[i]);
        i += 1;
    }
    for i in 0..8 {
        h[i] ^= block[i] ^ key[i] ^ m[i];
    }
}

/// Shared Streebog state, parameterized only by its initial vector. The 512-bit
/// hash state `h`, message-bit counter `n`, and checksum `sigma` are each held as
/// eight little-endian `u64` lanes.
#[derive(Clone)]
struct Core {
    h: [u64; 8],
    n: [u64; 8],
    sigma: [u64; 8],
    buf: [u8; 64],
    buf_len: usize,
}

impl Core {
    #[inline]
    fn new(iv: u64) -> Self {
        Core {
            h: [iv; 8],
            n: [0u64; 8],
            sigma: [0u64; 8],
            buf: [0u8; 64],
            buf_len: 0,
        }
    }

    /// Advances the message-bit counter `N` by `len` bytes (`8 * len` bits).
    #[inline]
    fn update_n(&mut self, len: u64) {
        let mut carry = false;
        // `len` never exceeds the 64-byte block size, so `8 * len` cannot overflow.
        adc(&mut self.n[0], 8 * len, &mut carry);
        for i in 1..8 {
            adc(&mut self.n[i], 0, &mut carry);
        }
    }

    /// Adds the block lanes into the checksum `Sigma` (512-bit modular add).
    #[inline]
    fn update_sigma(&mut self, m: &[u64; 8]) {
        let mut carry = false;
        for (s, &mi) in self.sigma.iter_mut().zip(m.iter()) {
            adc(s, mi, &mut carry);
        }
    }

    /// Compresses one full 512-bit block carrying `msg_len` message bytes, then
    /// advances `N` and `Sigma`.
    fn compress(&mut self, block: &[u8; 64], msg_len: u64) {
        let m = from_bytes(block);
        g(&mut self.h, &self.n, &m);
        self.update_n(msg_len);
        self.update_sigma(&m);
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block, 64);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let block: [u8; 64] = data[..64].try_into().unwrap();
            self.compress(&block, 64);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Runs the RFC 6986 finalization (Stage 3) and returns the 512-bit state.
    fn finish(&mut self) -> [u8; 64] {
        // Pad the final partial block: a single 0x01 just above the message bytes.
        let pos = self.buf_len;
        let mut block = [0u8; 64];
        block[..pos].copy_from_slice(&self.buf[..pos]);
        block[pos] = 1;
        self.compress(&block, pos as u64);

        let zero = [0u64; 8];
        let n = self.n;
        let sigma = self.sigma;
        g(&mut self.h, &zero, &n);
        g(&mut self.h, &zero, &sigma);
        to_bytes(&self.h)
    }

    #[inline]
    fn zeroize(&mut self) {
        super::zeroize::zero_words(&mut self.h);
        super::zeroize::zero_words(&mut self.n);
        super::zeroize::zero_words(&mut self.sigma);
        super::zeroize::zero_bytes(&mut self.buf);
        self.buf_len = 0;
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Streebog-512 (GOST R 34.11-2012, 512-bit output).
#[derive(Clone)]
pub struct Streebog512(Core);

impl Digest for Streebog512 {
    type Output = [u8; 64];
    type Block = [u8; 64];
    const OUTPUT_LEN: usize = 64;
    const BLOCK_LEN: usize = 64;

    #[inline]
    fn new() -> Self {
        Streebog512(Core::new(0))
    }
    #[inline]
    fn zeroed_block() -> [u8; 64] {
        [0u8; 64]
    }
    #[inline]
    fn zeroed_output() -> [u8; 64] {
        [0u8; 64]
    }
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    #[inline]
    fn finalize(mut self) -> [u8; 64] {
        self.0.finish()
    }
    #[inline]
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Streebog-256 (GOST R 34.11-2012, 256-bit output).
#[derive(Clone)]
pub struct Streebog256(Core);

impl Digest for Streebog256 {
    type Output = [u8; 32];
    type Block = [u8; 64];
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;

    #[inline]
    fn new() -> Self {
        Streebog256(Core::new(0x0101_0101_0101_0101))
    }
    #[inline]
    fn zeroed_block() -> [u8; 64] {
        [0u8; 64]
    }
    #[inline]
    fn zeroed_output() -> [u8; 32] {
        [0u8; 32]
    }
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    #[inline]
    fn finalize(mut self) -> [u8; 32] {
        // The 256-bit digest is the most-significant 32 bytes of the state,
        // which live at the high byte indices under the little-endian layout.
        let full = self.0.finish();
        let mut out = [0u8; 32];
        out.copy_from_slice(&full[32..64]);
        out
    }
    #[inline]
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// Computes the Streebog-256 digest of `data`.
#[inline]
pub fn streebog256(data: &[u8]) -> [u8; 32] {
    Streebog256::digest(data)
}

/// Computes the Streebog-512 digest of `data`.
#[inline]
pub fn streebog512(data: &[u8]) -> [u8; 64] {
    Streebog512::digest(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    #[test]
    fn empty_string() {
        assert_eq!(
            streebog512(b""),
            from_hex::<64>(
                "8e945da209aa869f0455928529bcae4679e9873ab707b55315f56ceb98bef0a7\
                 362f715528356ee83cda5f2aac4c6ad2ba3a715c1bcd81cb8e9f90bf4c1c1a8a"
            )
        );
        assert_eq!(
            streebog256(b""),
            from_hex::<32>("3f539a213e97c802cc229d474c6aa32a825a360b2a933a949fd925208d9ce1bb")
        );
    }

    // RFC 6986 §10.1 / §10.2: M1 is given there as a big-endian 63-byte hex
    // literal (`0x3231...3130`). The hash processes the message as a byte stream
    // in the natural (low-to-high) order, i.e. the reverse of that display, which
    // is the ASCII digits "0123456789" repeated.
    #[test]
    fn rfc6986_m1() {
        let m1 = b"012345678901234567890123456789012345678901234567890123456789012";
        assert_eq!(m1.len(), 63);
        assert_eq!(
            streebog512(m1),
            from_hex::<64>(
                "1b54d01a4af5b9d5cc3d86d68d285462b19abc2475222f35c085122be4ba1ffa\
                 00ad30f8767b3a82384c6574f024c311e2a481332b08ef7f41797891c1646f48"
            )
        );
        assert_eq!(
            streebog256(m1),
            from_hex::<32>("9d151eefd8590b89daa6ba6cb74af9275dd051026bb149a452fd84e5e57b5500")
        );
    }

    // RFC 6986 §10.2: M2 is a 576-bit (72-byte) message — a multi-block input that
    // exercises a full-block compression with a non-zero `N`. The message and the
    // digests are stored here verbatim in the RFC's big-endian display and reversed
    // at runtime to the byte-stream order the implementation consumes/produces.
    #[test]
    fn rfc6986_m2() {
        fn rev<const N: usize>(mut a: [u8; N]) -> [u8; N] {
            a.reverse();
            a
        }
        let m2 = rev(from_hex::<72>(
            "fbe2e5f0eee3c820fbeafaebef20fffbf0e1e0f0f520e0ed20e8ece0ebe5f0f2\
             f120fff0eeec20f120faf2fee5e2202ce8f6f3ede220e8e6eee1e8f0f2d1202c\
             e8f0f2e5e220e5d1",
        ));
        assert_eq!(
            streebog512(&m2),
            rev(from_hex::<64>(
                "28fbc9bada033b1460642bdcddb90c3fb3e56c497ccd0f62b8a2ad4935e85f03\
                 7613966de4ee00531ae60f3b5a47f8dae06915d5f2f194996fcabf2622e6881e"
            ))
        );
        assert_eq!(
            streebog256(&m2),
            rev(from_hex::<32>(
                "508f7e553c06501d749a66fc28c6cac0b005746d97537fa85d9e40904efed29d"
            ))
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let msg = [0x61u8; 200];
        let oneshot = streebog512(&msg);
        let mut h = Streebog512::new();
        h.update(&msg[..1]);
        h.update(&msg[1..65]);
        h.update(&msg[65..130]);
        h.update(&msg[130..]);
        assert_eq!(h.finalize(), oneshot);

        let oneshot256 = streebog256(&msg);
        let mut h256 = Streebog256::new();
        h256.update(&msg[..63]);
        h256.update(&msg[63..]);
        assert_eq!(h256.finalize(), oneshot256);
    }
}
