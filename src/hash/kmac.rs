//! cSHAKE, KMAC, and KMAC-XOF (NIST SP 800-185), built on the Keccak sponge.
//!
//! All `no_std` and allocation-free: the SP 800-185 prefix (`bytepad` of the
//! encoded function name, customization, and key) is absorbed incrementally
//! into the sponge rather than materialized.

use super::keccak::{Keccak, KeccakReader};

/// `left_encode(x)` into `buf`, returning the encoded length.
fn left_encode(buf: &mut [u8; 9], x: u64) -> usize {
    let mut len = 1usize;
    let mut v = x;
    while {
        v >>= 8;
        v
    } != 0
    {
        len += 1;
    }
    buf[0] = len as u8;
    for (i, slot) in buf[1..1 + len].iter_mut().enumerate() {
        *slot = (x >> (8 * (len - 1 - i))) as u8;
    }
    1 + len
}

/// `right_encode(x)` into `buf`, returning the encoded length.
fn right_encode(buf: &mut [u8; 9], x: u64) -> usize {
    let mut len = 1usize;
    let mut v = x;
    while {
        v >>= 8;
        v
    } != 0
    {
        len += 1;
    }
    for (i, slot) in buf[..len].iter_mut().enumerate() {
        *slot = (x >> (8 * (len - 1 - i))) as u8;
    }
    buf[len] = len as u8;
    len + 1
}

/// Absorbs into a sponge while tracking the byte count, for `bytepad`.
struct Absorb<'a> {
    k: &'a mut Keccak,
    count: usize,
}

impl Absorb<'_> {
    fn raw(&mut self, data: &[u8]) {
        self.k.update(data);
        self.count += data.len();
    }
    fn left_encode(&mut self, x: u64) {
        let mut b = [0u8; 9];
        let n = left_encode(&mut b, x);
        self.raw(&b[..n]);
    }
    /// `encode_string(s)` = `left_encode(8·len(s)) || s`.
    fn encode_string(&mut self, s: &[u8]) {
        self.left_encode(8 * s.len() as u64);
        self.raw(s);
    }
    /// Zero-pads the bytes absorbed so far to a multiple of `rate` (`bytepad`).
    fn bytepad_to(&mut self, rate: usize) {
        let pad = (rate - self.count % rate) % rate;
        let zeros = [0u8; 168];
        self.k.update(&zeros[..pad]);
        self.count += pad;
    }
}

/// Builds the cSHAKE sponge for `(name, custom)` at the given rate, returning it
/// with the domain byte to use at finalization (`0x1F` when both strings are
/// empty — i.e. plain SHAKE — else `0x04`).
fn cshake_init(rate: usize, name: &[u8], custom: &[u8]) -> (Keccak, u8) {
    let mut k = Keccak::new(rate);
    if name.is_empty() && custom.is_empty() {
        return (k, 0x1F);
    }
    let mut a = Absorb {
        k: &mut k,
        count: 0,
    };
    a.left_encode(rate as u64); // bytepad's leading left_encode(w)
    a.encode_string(name);
    a.encode_string(custom);
    a.bytepad_to(rate);
    (k, 0x04)
}

/// Builds the KMAC sponge: cSHAKE with name `"KMAC"` and customization `custom`,
/// then `bytepad(encode_string(key), rate)`.
fn kmac_init(rate: usize, key: &[u8], custom: &[u8]) -> Keccak {
    let (mut k, _) = cshake_init(rate, b"KMAC", custom);
    let mut a = Absorb {
        k: &mut k,
        count: 0,
    };
    a.left_encode(rate as u64); // bytepad's leading left_encode(w)
    a.encode_string(key);
    a.bytepad_to(rate);
    k
}

/// Defines a cSHAKE XOF at the given rate.
macro_rules! cshake {
    ($name:ident, $rate:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            keccak: Keccak,
            pad: u8,
        }
        impl $name {
            /// Creates a cSHAKE with function name `name` and customization
            /// string `custom` (both may be empty, giving plain SHAKE).
            pub fn new(name: &[u8], custom: &[u8]) -> Self {
                let (keccak, pad) = cshake_init($rate, name, custom);
                $name { keccak, pad }
            }
            /// Feeds input.
            pub fn update(&mut self, data: &[u8]) {
                self.keccak.update(data);
            }
            /// Finalizes and returns an output reader.
            pub fn finalize_xof(self) -> KeccakReader {
                KeccakReader::new(self.keccak, self.pad)
            }
            /// Finalizes and squeezes `out.len()` bytes.
            pub fn finalize_into(self, out: &mut [u8]) {
                use super::XofReader;
                self.finalize_xof().read(out);
            }
        }
    };
}

cshake!(CShake128, 168, "cSHAKE128 (customizable SHAKE128).");
cshake!(CShake256, 136, "cSHAKE256 (customizable SHAKE256).");

/// Defines a fixed-output KMAC at the given rate.
macro_rules! kmac {
    ($name:ident, $rate:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            keccak: Keccak,
        }
        impl $name {
            /// Creates a KMAC keyed with `key` and customization `custom`.
            pub fn new(key: &[u8], custom: &[u8]) -> Self {
                $name {
                    keccak: kmac_init($rate, key, custom),
                }
            }
            /// Feeds message bytes.
            pub fn update(&mut self, data: &[u8]) {
                self.keccak.update(data);
            }
            /// Finalizes the MAC into `out` (the output length is `out.len()`).
            pub fn finalize_into(mut self, out: &mut [u8]) {
                let mut b = [0u8; 9];
                let n = right_encode(&mut b, 8 * out.len() as u64);
                self.keccak.update(&b[..n]);
                self.keccak.finalize(0x04);
                self.keccak.squeeze(out);
            }
            /// Consumes the MAC and checks it against `expected` in constant
            /// time (tags up to 64 bytes; see [`Mac::verify`](super::Mac::verify)).
            pub fn verify(self, expected: &[u8]) -> crate::ct::Choice {
                super::Mac::verify(self, expected)
            }
        }
        impl super::Mac for $name {
            fn update(&mut self, data: &[u8]) {
                $name::update(self, data);
            }
            fn finalize_into(self, out: &mut [u8]) {
                $name::finalize_into(self, out);
            }
        }
    };
}

kmac!(Kmac128, 168, "KMAC128 (keyed MAC, SP 800-185).");
kmac!(Kmac256, 136, "KMAC256 (keyed MAC, SP 800-185).");

/// Defines a KMAC in XOF mode at the given rate.
macro_rules! kmac_xof {
    ($name:ident, $rate:expr, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            keccak: Keccak,
        }
        impl $name {
            /// Creates a KMACXOF keyed with `key` and customization `custom`.
            pub fn new(key: &[u8], custom: &[u8]) -> Self {
                $name {
                    keccak: kmac_init($rate, key, custom),
                }
            }
            /// Feeds message bytes.
            pub fn update(&mut self, data: &[u8]) {
                self.keccak.update(data);
            }
            /// Finalizes and returns an arbitrary-length output reader
            /// (`right_encode(0)`).
            pub fn finalize_xof(mut self) -> KeccakReader {
                let mut b = [0u8; 9];
                let n = right_encode(&mut b, 0);
                self.keccak.update(&b[..n]);
                KeccakReader::new(self.keccak, 0x04)
            }
            /// Finalizes and squeezes `out.len()` bytes.
            pub fn finalize_into(self, out: &mut [u8]) {
                use super::XofReader;
                self.finalize_xof().read(out);
            }
        }
    };
}

kmac_xof!(KmacXof128, 168, "KMAC128 in XOF mode.");
kmac_xof!(KmacXof256, 136, "KMAC256 in XOF mode.");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // NIST SP 800-185 key for the KMAC/cSHAKE samples: 0x40..=0x5F.
    fn sample_key() -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = 0x40 + i as u8;
        }
        k
    }

    // KMAC samples 1, 2 (KMAC128) and 4 (KMAC256), verified with `openssl mac`.
    #[test]
    fn kmac_nist_samples() {
        let key = sample_key();
        let data = [0x00u8, 0x01, 0x02, 0x03];

        let mut out = [0u8; 32];
        let mut m = Kmac128::new(&key, b"");
        m.update(&data);
        m.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<32>("e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e")
        );

        let mut out = [0u8; 32];
        let mut m = Kmac128::new(&key, b"My Tagged Application");
        m.update(&data);
        m.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<32>("3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5")
        );

        let mut out = [0u8; 64];
        let mut m = Kmac256::new(&key, b"My Tagged Application");
        m.update(&data);
        m.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<64>(
                "20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd"
            )
        );
    }

    // SP 800-185 cSHAKE128 sample 1: N="", S="Email Signature", data=00010203.
    #[test]
    fn cshake128_sample() {
        let mut out = [0u8; 32];
        let mut c = CShake128::new(b"", b"Email Signature");
        c.update(&[0x00, 0x01, 0x02, 0x03]);
        c.finalize_into(&mut out);
        assert_eq!(
            out,
            from_hex::<32>("c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5")
        );
    }

    #[test]
    fn kmac_verify_constant_time() {
        let key = sample_key();
        let data = [0x00u8, 0x01, 0x02, 0x03];
        let mut tag = [0u8; 32];
        let mut m = Kmac128::new(&key, b"");
        m.update(&data);
        m.finalize_into(&mut tag);

        // Good tag verifies.
        let mut m = Kmac128::new(&key, b"");
        m.update(&data);
        assert!(bool::from(m.verify(&tag)));

        // Flipped bit fails.
        let mut bad = tag;
        bad[0] ^= 1;
        let mut m = Kmac128::new(&key, b"");
        m.update(&data);
        assert!(!bool::from(m.verify(&bad)));

        // Wrong length fails.
        let mut m = Kmac128::new(&key, b"");
        m.update(&data);
        assert!(!bool::from(m.verify(&tag[..31])));
    }

    #[test]
    fn kmacxof_incremental_matches() {
        use super::super::XofReader;
        let key = sample_key();
        let mut x = KmacXof128::new(&key, b"App");
        x.update(b"streamed message");
        let mut reader = x.finalize_xof();
        let mut a = [0u8; 40];
        reader.read(&mut a[..5]);
        reader.read(&mut a[5..]);

        let mut b = [0u8; 40];
        let mut x2 = KmacXof128::new(&key, b"App");
        x2.update(b"streamed message");
        x2.finalize_into(&mut b);
        assert_eq!(a, b);
    }
}
