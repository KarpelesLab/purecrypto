//! HMAC — Hash-based Message Authentication Code (RFC 2104), generic over any
//! [`Digest`].

use super::{Digest, Mac};
use crate::ct::{Choice, ConstantTimeEq};

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

/// HMAC keyed with a hash function `D`.
///
/// `HMAC(K, m) = H((K' ^ opad) || H((K' ^ ipad) || m))`, where `K'` is the key
/// reduced to a single block: hashed first if longer than the block size, then
/// zero-padded.
///
/// ```
/// use purecrypto::hash::HmacSha256;
/// let tag = HmacSha256::mac(b"key", b"message");
/// assert!(bool::from(HmacSha256::new(b"key").chain(b"message").verify(&tag)));
/// ```
#[derive(Clone)]
pub struct Hmac<D: Digest> {
    /// Hasher fed `K' ^ ipad`, then the message.
    inner: D,
    /// Hasher fed `K' ^ opad`, finalized over the inner digest at the end.
    outer: D,
}

impl<D: Digest> Hmac<D> {
    /// Creates an HMAC instance keyed with `key`.
    pub fn new(key: &[u8]) -> Self {
        // Reduce the key to a single zero-padded block.
        let mut block = D::zeroed_block();
        let buf = block.as_mut();
        if key.len() > buf.len() {
            let hashed = D::digest(key);
            let h = hashed.as_ref();
            buf[..h.len()].copy_from_slice(h);
        } else {
            buf[..key.len()].copy_from_slice(key);
        }

        let mut ipad_block = block;
        let mut opad_block = block;
        for b in ipad_block.as_mut() {
            *b ^= IPAD;
        }
        for b in opad_block.as_mut() {
            *b ^= OPAD;
        }

        let mut inner = D::new();
        inner.update(ipad_block.as_ref());
        let mut outer = D::new();
        outer.update(opad_block.as_ref());

        Hmac { inner, outer }
    }

    /// Feeds `data` into the MAC. May be called any number of times.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Feeds `data` and returns `self`, for call chaining.
    #[inline]
    pub fn chain(mut self, data: &[u8]) -> Self {
        self.update(data);
        self
    }

    /// Consumes the MAC and returns the authentication tag.
    #[inline]
    pub fn finalize(mut self) -> D::Output {
        let inner = self.inner.finalize();
        self.outer.update(inner.as_ref());
        self.outer.finalize()
    }

    /// Consumes the MAC and checks it against `expected` in constant time.
    ///
    /// The comparison time depends only on the (public) tag length, not on
    /// where a mismatch occurs — avoiding the timing leak of a byte-by-byte
    /// `==`.
    #[inline]
    pub fn verify(self, expected: &[u8]) -> Choice {
        let tag = self.finalize();
        tag.as_ref().ct_eq(expected)
    }

    /// Computes the tag for `data` under `key` in one call.
    #[inline]
    pub fn mac(key: &[u8], data: &[u8]) -> D::Output {
        let mut h = Self::new(key);
        h.update(data);
        h.finalize()
    }
}

impl<D: Digest> Mac for Hmac<D> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        Hmac::update(self, data);
    }
    /// Writes the full HMAC tag, truncated to `out.len()` if it is shorter than
    /// the digest length.
    #[inline]
    fn finalize_into(self, out: &mut [u8]) {
        let tag = self.finalize();
        let t = tag.as_ref();
        let n = out.len().min(t.len());
        out[..n].copy_from_slice(&t[..n]);
    }
    #[inline]
    fn verify(self, expected: &[u8]) -> Choice {
        Hmac::verify(self, expected)
    }
}

/// HMAC-SHA-224.
pub type HmacSha224 = Hmac<super::Sha224>;
/// HMAC-SHA-256.
pub type HmacSha256 = Hmac<super::Sha256>;
/// HMAC-SHA-384.
pub type HmacSha384 = Hmac<super::Sha384>;
/// HMAC-SHA-512.
pub type HmacSha512 = Hmac<super::Sha512>;
/// HMAC-SHA-512/224.
pub type HmacSha512_224 = Hmac<super::Sha512_224>;
/// HMAC-SHA-512/256.
pub type HmacSha512_256 = Hmac<super::Sha512_256>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // RFC 4231 test vectors.

    #[test]
    fn rfc4231_tc1() {
        // 20-byte key, short message.
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        assert_eq!(
            HmacSha256::mac(&key, data),
            from_hex::<32>("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );
        assert_eq!(
            HmacSha224::mac(&key, data),
            from_hex::<28>("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22")
        );
        assert_eq!(
            HmacSha384::mac(&key, data),
            from_hex::<48>(
                "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
                 faea9ea9076ede7f4af152e8b2fa9cb6"
            )
        );
        assert_eq!(
            HmacSha512::mac(&key, data),
            from_hex::<64>(
                "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
                 daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
            )
        );
    }

    #[test]
    fn rfc4231_tc2() {
        // 4-byte key.
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        assert_eq!(
            HmacSha256::mac(key, data),
            from_hex::<32>("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
        assert_eq!(
            HmacSha512::mac(key, data),
            from_hex::<64>(
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554\
                 9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
            )
        );
    }

    #[test]
    fn rfc4231_tc6_long_key() {
        // 131-byte key (> 64-byte block) forces the hash-the-key path.
        let key = [0xaau8; 131];
        let data = b"Test Using Larger Than Block-Size Key - Hash Key First";
        assert_eq!(
            HmacSha256::mac(&key, data),
            from_hex::<32>("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
        );
    }

    #[test]
    fn streaming_matches_oneshot() {
        let key = b"secret key";
        let msg = b"The quick brown fox jumps over the lazy dog";
        let oneshot = HmacSha256::mac(key, msg);
        let mut h = HmacSha256::new(key);
        for &byte in msg {
            h.update(&[byte]);
        }
        assert_eq!(h.finalize(), oneshot);
    }

    #[test]
    fn verify_constant_time() {
        let key = b"k";
        let msg = b"data";
        let tag = HmacSha256::mac(key, msg);
        assert!(bool::from(HmacSha256::new(key).chain(msg).verify(&tag)));

        // A flipped bit must fail.
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(!bool::from(HmacSha256::new(key).chain(msg).verify(&bad)));
        // Wrong length must fail.
        assert!(!bool::from(
            HmacSha256::new(key).chain(msg).verify(&tag[..31])
        ));
    }
}
