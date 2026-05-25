//! SHA-3 (FIPS 202): SHA3-224/256/384/512, plus legacy Keccak-256 (Ethereum).
//!
//! Built on the shared Keccak-`f`[1600] sponge ([`super::keccak`]). SHA-3 uses
//! the `0x06` domain byte; the original Keccak (as used by Ethereum) uses
//! `0x01`. The rate (and the block size HMAC keys on) is `200 - 2*output_len`.

use super::Digest;
use super::keccak::Keccak;

/// Generates a fixed-output Keccak hash with the given rate and domain byte.
macro_rules! keccak_hash {
    ($name:ident, $func:ident, $out:expr, $rate:expr, $pad:expr, $doc:literal) => {
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
            fn finalize(mut self) -> [u8; $out] {
                let mut out = [0u8; $out];
                self.keccak.finalize($pad);
                self.keccak.squeeze(&mut out);
                out
            }
            #[inline]
            fn zeroize(&mut self) {
                self.keccak.zeroize();
            }
        }

        #[doc = $doc]
        #[inline]
        pub fn $func(data: &[u8]) -> [u8; $out] {
            $name::digest(data)
        }
    };
}

keccak_hash!(
    Sha3_224,
    sha3_224,
    28,
    144,
    0x06,
    "The SHA3-224 hash function."
);
keccak_hash!(
    Sha3_256,
    sha3_256,
    32,
    136,
    0x06,
    "The SHA3-256 hash function."
);
keccak_hash!(
    Sha3_384,
    sha3_384,
    48,
    104,
    0x06,
    "The SHA3-384 hash function."
);
keccak_hash!(
    Sha3_512,
    sha3_512,
    64,
    72,
    0x06,
    "The SHA3-512 hash function."
);
keccak_hash!(
    Keccak256,
    keccak256,
    32,
    136,
    0x01,
    "The legacy Keccak-256 hash (Ethereum), i.e. SHA3-256 with `0x01` padding."
);

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

    // Legacy Keccak-256 (Ethereum) — distinct from SHA3-256 (0x01 vs 0x06 pad).
    #[test]
    fn keccak256_vectors() {
        assert_eq!(
            keccak256(b""),
            from_hex::<32>("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        );
        assert_eq!(
            keccak256(b"abc"),
            from_hex::<32>("4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45")
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
