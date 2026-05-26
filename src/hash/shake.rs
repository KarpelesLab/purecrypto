//! SHAKE128 and SHAKE256 (FIPS 202) — the extendable-output functions of the
//! SHA-3 family. Same Keccak sponge as SHA-3, with the `0x1F` domain byte and
//! arbitrary-length squeezing.

use super::ExtendableOutput;
use super::keccak::{Keccak, KeccakReader};

/// Generates a SHAKE variant with the given rate.
macro_rules! shake {
    ($name:ident, $func:ident, $rate:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            keccak: Keccak,
        }

        impl ExtendableOutput for $name {
            type Reader = KeccakReader;
            const BLOCK_LEN: usize = $rate;

            #[inline]
            fn new() -> Self {
                $name {
                    keccak: Keccak::new($rate),
                }
            }
            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.keccak.update(data);
            }
            #[inline]
            fn finalize_xof(self) -> KeccakReader {
                KeccakReader::new(self.keccak, 0x1F)
            }
        }

        #[doc = $doc]
        ///
        /// Squeezes `out.len()` bytes in one call.
        #[inline]
        pub fn $func(data: &[u8], out: &mut [u8]) {
            $name::xof(data, out);
        }
    };
}

shake!(
    Shake128,
    shake128,
    168,
    "The SHAKE128 extendable-output function."
);
shake!(
    Shake256,
    shake256,
    136,
    "The SHAKE256 extendable-output function."
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::XofReader;
    use crate::test_util::from_hex;

    // NIST / openssl `shake256 -xoflen 32` of the empty string.
    #[test]
    fn shake256_empty() {
        let mut out = [0u8; 32];
        shake256(b"", &mut out);
        assert_eq!(
            out,
            from_hex::<32>("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
        );
    }

    // openssl `shake128 -xoflen 32` of "abc".
    #[test]
    fn shake128_abc() {
        let mut out = [0u8; 32];
        shake128(b"abc", &mut out);
        assert_eq!(
            out,
            from_hex::<32>("5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8")
        );
    }

    #[test]
    fn multi_block_squeeze_crosses_rate() {
        use crate::test_util::from_hex;
        // SHAKE128("") past the 168-byte rate (verified against Python hashlib).
        let x = Shake128::new();
        let mut r = x.finalize_xof();
        let mut o = [0u8; 336];
        r.read(&mut o[..100]);
        r.read(&mut o[100..170]);
        r.read(&mut o[170..]);
        assert_eq!(
            o[160..176],
            from_hex::<16>("aee7eef47cb0fca9767be1fda69419df")
        );
        assert_eq!(o[330..336], from_hex::<6>("aff268e0b170"));

        // SHAKE256("the quick brown fox") past its 136-byte rate, two boundaries.
        let mut y = Shake256::new();
        y.update(b"the quick brown fox");
        let mut r2 = y.finalize_xof();
        let mut o2 = [0u8; 300];
        r2.read(&mut o2);
        assert_eq!(
            o2[130..146],
            from_hex::<16>("86ad97a43bc8a29bc2c78a9e848769e2")
        );
        assert_eq!(
            o2[266..282],
            from_hex::<16>("9fa475b09da0ad5ce765ae1e2a9edd56")
        );
    }

    // Incremental reads must concatenate into the same stream as one big read.
    #[test]
    fn incremental_read_matches() {
        let mut x = Shake256::new();
        x.update(b"the quick brown fox");
        let mut reader = x.finalize_xof();
        let mut a = [0u8; 50];
        let mut b = [0u8; 50];
        reader.read(&mut a[..7]);
        reader.read(&mut a[7..30]);
        reader.read(&mut a[30..]);

        let mut oneshot = Shake256::new();
        oneshot.update(b"the quick brown fox");
        oneshot.finalize_into(&mut b);
        assert_eq!(a, b);
    }
}
