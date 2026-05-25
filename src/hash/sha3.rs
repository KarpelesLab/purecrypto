//! SHA-3 (FIPS 202): SHA3-224, SHA3-256, SHA3-384, SHA3-512.
//!
//! Built on the Keccak-`f`[1600] permutation and a sponge. The rate (and hence
//! the block size used by HMAC) is `200 - 2·output_len` bytes.

use super::Digest;

/// Keccak-f[1600] round constants.
const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// Rotation offsets for the combined ρ/π step.
const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane permutation for the combined ρ/π step.
const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation over a 5×5 array of 64-bit lanes.
fn keccak_f(a: &mut [u64; 25]) {
    for &rc in RC.iter() {
        // θ
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }

        // ρ and π
        let mut last = a[1];
        for i in 0..24 {
            let j = PI[i];
            let tmp = a[j];
            a[j] = last.rotate_left(RHO[i]);
            last = tmp;
        }

        // χ
        for y in 0..5 {
            let row = [
                a[5 * y],
                a[5 * y + 1],
                a[5 * y + 2],
                a[5 * y + 3],
                a[5 * y + 4],
            ];
            for x in 0..5 {
                a[5 * y + x] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }

        // ι
        a[0] ^= rc;
    }
}

/// Maximum SHA-3 rate (SHA3-224), bounding the buffer.
const MAX_RATE: usize = 144;

/// A Keccak sponge in absorbing mode, with the given rate (in bytes).
#[derive(Clone)]
struct Keccak {
    state: [u64; 25],
    buf: [u8; MAX_RATE],
    buf_len: usize,
    rate: usize,
}

impl Keccak {
    fn new(rate: usize) -> Self {
        Keccak {
            state: [0u64; 25],
            buf: [0u8; MAX_RATE],
            buf_len: 0,
            rate,
        }
    }

    /// XORs the full `rate`-byte buffer into the state and permutes.
    fn absorb_buf(&mut self) {
        for (i, chunk) in self.buf[..self.rate].chunks_exact(8).enumerate() {
            self.state[i] ^= u64::from_le_bytes(chunk.try_into().unwrap());
        }
        keccak_f(&mut self.state);
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buf_len > 0 {
            let take = (self.rate - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == self.rate {
                self.absorb_buf();
                self.buf_len = 0;
            }
        }
        while data.len() >= self.rate {
            self.buf[..self.rate].copy_from_slice(&data[..self.rate]);
            self.absorb_buf();
            data = &data[self.rate..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Applies the SHA-3 pad (`0x06` … `0x80`) and squeezes `out.len()` bytes.
    fn finalize_into(mut self, out: &mut [u8]) {
        let len = self.buf_len;
        for b in self.buf[len..self.rate].iter_mut() {
            *b = 0;
        }
        self.buf[len] ^= 0x06;
        self.buf[self.rate - 1] ^= 0x80;
        self.absorb_buf();

        let mut i = 0;
        let mut lane = 0;
        while i < out.len() {
            if lane * 8 >= self.rate {
                keccak_f(&mut self.state);
                lane = 0;
            }
            let bytes = self.state[lane].to_le_bytes();
            let take = (out.len() - i).min(8);
            out[i..i + take].copy_from_slice(&bytes[..take]);
            i += take;
            lane += 1;
        }
    }
}

/// Generates a SHA-3 variant with the given output length (and rate).
macro_rules! sha3 {
    ($name:ident, $func:ident, $out:expr, $rate:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            keccak: Keccak,
        }

        impl Digest for $name {
            type Output = [u8; $out];
            type Block = [u8; $rate];
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = $rate;

            #[inline]
            fn new() -> Self {
                $name {
                    keccak: Keccak::new($rate),
                }
            }
            #[inline]
            fn zeroed_block() -> [u8; $rate] {
                [0u8; $rate]
            }
            #[inline]
            fn zeroed_output() -> [u8; $out] {
                [0u8; $out]
            }
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.keccak.update(data);
            }
            #[inline]
            fn finalize(self) -> [u8; $out] {
                let mut out = [0u8; $out];
                self.keccak.finalize_into(&mut out);
                out
            }
        }

        #[doc = $doc]
        #[inline]
        pub fn $func(data: &[u8]) -> [u8; $out] {
            $name::digest(data)
        }
    };
}

sha3!(Sha3_224, sha3_224, 28, 144, "The SHA3-224 hash function.");
sha3!(Sha3_256, sha3_256, 32, 136, "The SHA3-256 hash function.");
sha3!(Sha3_384, sha3_384, 48, 104, "The SHA3-384 hash function.");
sha3!(Sha3_512, sha3_512, 64, 72, "The SHA3-512 hash function.");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    #[test]
    fn sha3_256_vectors() {
        assert_eq!(
            sha3_256(b""),
            from_hex::<32>("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
        assert_eq!(
            sha3_256(b"abc"),
            from_hex::<32>("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        );
    }

    #[test]
    fn sha3_224_vectors() {
        assert_eq!(
            sha3_224(b""),
            from_hex::<28>("6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7")
        );
        assert_eq!(
            sha3_224(b"abc"),
            from_hex::<28>("e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf")
        );
    }

    #[test]
    fn sha3_384_vectors() {
        assert_eq!(
            sha3_384(b""),
            from_hex::<48>(
                "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
            )
        );
        assert_eq!(
            sha3_384(b"abc"),
            from_hex::<48>(
                "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25"
            )
        );
    }

    #[test]
    fn sha3_512_vectors() {
        assert_eq!(
            sha3_512(b""),
            from_hex::<64>(
                "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
            )
        );
        assert_eq!(
            sha3_512(b"abc"),
            from_hex::<64>(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            )
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        // A message spanning multiple SHA3-256 blocks (rate 136).
        let msg = [0x5au8; 400];
        let oneshot = sha3_256(&msg);
        let mut h = Sha3_256::new();
        h.update(&msg[..1]);
        h.update(&msg[1..137]);
        h.update(&msg[137..300]);
        h.update(&msg[300..]);
        assert_eq!(h.finalize(), oneshot);
    }
}
