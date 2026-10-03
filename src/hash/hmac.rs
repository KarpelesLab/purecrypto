//! HMAC — Hash-based Message Authentication Code (RFC 2104), generic over any
//! [`Digest`].
//!
//! # Choose a constant-time digest
//!
//! `Hmac::new` seeds the hash state with `K' ^ ipad` / `K' ^ opad`, so the
//! whole first compression is driven by the key. Under a table-driven digest —
//! [`Md2`](super::Md2), [`Whirlpool`](super::Whirlpool),
//! [`Streebog256`](super::Streebog256)/[`Streebog512`](super::Streebog512) —
//! that turns the S-box lookups into *secret*-indexed table accesses, and the
//! cache-timing channel those modules document as harmless for public message
//! bytes then leaks key material instead. Nothing here gates it. Use a
//! constant-time digest (SHA-2, SHA-3, BLAKE2) for HMAC; those three are for
//! unkeyed interop hashing only.

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
            // `H(key)` *is* the effective HMAC key for a long key; wipe this
            // copy once it has been folded into the block (which is wiped
            // below).
            let mut hashed = D::digest(key);
            let h = hashed.as_ref();
            buf[..h.len()].copy_from_slice(h);
            super::zeroize::zero_bytes(hashed.as_mut());
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

        // K' and both pad blocks are trivially key-equivalent — `K' ^ ipad` is
        // one XOR away from K' — so leaving them in the constructor's stack
        // frame would defeat the careful `Drop` on `inner`/`outer` below.
        super::zeroize::zero_bytes(block.as_mut());
        super::zeroize::zero_bytes(ipad_block.as_mut());
        super::zeroize::zero_bytes(opad_block.as_mut());

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
        // Extract the hashers rather than moving them out of `self`, which the
        // `Drop` impl forbids; the leftover fresh hashers are wiped on drop.
        let mut inner = core::mem::replace(&mut self.inner, D::new()).finalize();
        let mut outer = core::mem::replace(&mut self.outer, D::new());
        outer.update(inner.as_ref());
        // The inner digest is keyed intermediate state (H(K ^ ipad || m)),
        // not the tag; wipe it once it has been folded into the outer hash.
        super::zeroize::zero_bytes(inner.as_mut());
        outer.finalize()
    }

    /// Consumes the MAC and checks it against `expected` in constant time.
    ///
    /// The comparison time depends only on the (public) tag length, not on
    /// where a mismatch occurs — avoiding the timing leak of a byte-by-byte
    /// `==`.
    #[inline]
    pub fn verify(self, expected: &[u8]) -> Choice {
        let mut tag = self.finalize();
        let ok = tag.as_ref().ct_eq(expected);
        // The recomputed tag is exactly what a forger wants; don't let it
        // drop in the clear.
        super::zeroize::zero_bytes(tag.as_mut());
        ok
    }

    /// Computes the tag for `data` under `key` in one call.
    #[inline]
    pub fn mac(key: &[u8], data: &[u8]) -> D::Output {
        let mut h = Self::new(key);
        h.update(data);
        h.finalize()
    }

    /// Iterated HMAC, the PBKDF2 inner loop: `rounds` times sets
    /// `u = HMAC(K, u)` and XORs the new `u` into `acc`. Uses the digest's
    /// raw-compression fast path ([`Digest::hmac_iterate`]) when it has one,
    /// else clones the keyed state per round.
    #[cfg_attr(not(feature = "kdf"), allow(dead_code))]
    pub(crate) fn iterate_xor(&self, u: &mut D::Output, acc: &mut D::Output, rounds: u32) {
        if D::hmac_iterate(&self.inner, &self.outer, u, acc, rounds) {
            return;
        }
        for _ in 0..rounds {
            *u = self.clone().chain(u.as_ref()).finalize();
            for (a, b) in acc.as_mut().iter_mut().zip(u.as_ref().iter()) {
                *a ^= *b;
            }
        }
    }
}

/// The shared raw-compression loop behind the [`Digest::hmac_iterate`] fast
/// paths of the Merkle–Damgård hashes.
///
/// `inner_h` / `outer_h` are the chaining values after absorbing exactly the
/// `K ⊕ ipad` / `K ⊕ opad` block. Every message hashed in the loop is one
/// digest (`u.len()` bytes) after that block, so both the inner and the outer
/// hash are a single compression of the same pre-padded block template:
/// `u ‖ 0x80 ‖ 0… ‖ len_field`, where `len_field` is the encoded bit length
/// of `B + u.len()` bytes. Each round compresses it under the inner state,
/// writes the inner digest over its head (`out`), compresses it under the
/// outer state, and writes the new `u` back over the head. The template and
/// the working state hold key-derived values and are wiped once at the end.
pub(super) fn hmac_iterate_with<H, const B: usize>(
    (inner_h, outer_h): (&H, &H),
    len_field: &[u8],
    u: &mut [u8],
    acc: &mut [u8],
    rounds: u32,
    compress: impl Fn(&mut H, &[u8; B]),
    out: impl Fn(&H, &mut [u8]),
) where
    H: Copy + crate::zeroize::Zeroize,
{
    use crate::zeroize::Zeroize;
    let n = u.len();
    let mut block = [0u8; B];
    block[..n].copy_from_slice(u);
    block[n] = 0x80;
    block[B - len_field.len()..].copy_from_slice(len_field);
    let mut h = *inner_h;
    for _ in 0..rounds {
        h = *inner_h;
        compress(&mut h, &block);
        out(&h, &mut block[..n]);
        h = *outer_h;
        compress(&mut h, &block);
        out(&h, &mut block[..n]);
        for (a, b) in acc.iter_mut().zip(&block[..n]) {
            *a ^= *b;
        }
    }
    u.copy_from_slice(&block[..n]);
    block.zeroize();
    h.zeroize();
}

impl<D: Digest> Drop for Hmac<D> {
    fn drop(&mut self) {
        // Wipe the key-derived inner/outer hash state.
        self.inner.zeroize();
        self.outer.zeroize();
    }
}

impl<D: Digest> Mac for Hmac<D> {
    // HMAC is a fixed-output MAC: its tag is exactly the digest length. This
    // makes the default `Mac::verify` length-strict (rejecting truncated tags)
    // for code that reaches the MAC through the trait.
    const OUTPUT_LEN: Option<usize> = Some(D::OUTPUT_LEN);

    #[inline]
    fn update(&mut self, data: &[u8]) {
        Hmac::update(self, data);
    }
    /// Writes the full HMAC tag, truncated to `out.len()` if it is shorter than
    /// the digest length.
    #[inline]
    fn finalize_into(self, out: &mut [u8]) {
        let mut tag = self.finalize();
        let t = tag.as_ref();
        let n = out.len().min(t.len());
        out[..n].copy_from_slice(&t[..n]);
        // Wipe the untruncated tag: the bytes a shorter `out` did not receive
        // must not linger on the stack.
        super::zeroize::zero_bytes(tag.as_mut());
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

    /// The raw-compression `hmac_iterate` fast paths must equal the generic
    /// clone-and-finalize loop bit for bit, for short and over-long keys,
    /// several round counts and every digest that has the fast path (plus
    /// one without it, to exercise the fallback through `iterate_xor`).
    #[test]
    fn hmac_iterate_fast_paths_match_generic_loop() {
        fn check<D: Digest>() {
            let long_key = [0x5au8; 200];
            for key in [&b"pw"[..], &long_key[..]] {
                let mac = Hmac::<D>::new(key);
                for rounds in [0u32, 1, 2, 7] {
                    let mut u = mac.clone().chain(b"salt\0\0\0\x01").finalize();
                    let (mut acc, mut u_ref) = (u, u);
                    let mut acc_ref = acc;
                    for _ in 0..rounds {
                        u_ref = mac.clone().chain(u_ref.as_ref()).finalize();
                        for (a, b) in acc_ref.as_mut().iter_mut().zip(u_ref.as_ref()) {
                            *a ^= *b;
                        }
                    }
                    mac.iterate_xor(&mut u, &mut acc, rounds);
                    assert_eq!(u.as_ref(), u_ref.as_ref(), "{} r={rounds}", D::OUTPUT_LEN);
                    assert_eq!(
                        acc.as_ref(),
                        acc_ref.as_ref(),
                        "{} r={rounds}",
                        D::OUTPUT_LEN
                    );
                }
            }
            // A state that is not right after the pad block must be refused.
            let mut mac = Hmac::<D>::new(b"k");
            mac.update(b"x");
            let (mut u, mut acc) = (D::zeroed_output(), D::zeroed_output());
            assert!(!D::hmac_iterate(
                &mac.inner, &mac.outer, &mut u, &mut acc, 1
            ));
        }
        check::<crate::hash::Sha1>();
        check::<crate::hash::Sha224>();
        check::<crate::hash::Sha256>();
        check::<crate::hash::Sha384>();
        check::<crate::hash::Sha512>();
        check::<crate::hash::Sha512_224>();
        check::<crate::hash::Sha512_256>();
        check::<crate::hash::Md5>();
    }

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

    #[test]
    fn trait_verify_rejects_truncated_tag() {
        use crate::hash::Mac;

        let key = b"k";
        let msg = b"data";
        let tag = HmacSha256::mac(key, msg);

        // The full-length tag verifies through the trait path.
        let m = HmacSha256::new(key).chain(msg);
        assert!(bool::from(Mac::verify(m, &tag)));

        // A truncated tag must be rejected via the trait path: the default
        // `Mac::verify` is length-strict for fixed-output MACs, so checking
        // only a prefix of the tag cannot forge a match.
        for trunc in [16usize, 24, 31] {
            let m = HmacSha256::new(key).chain(msg);
            assert!(
                !bool::from(Mac::verify(m, &tag[..trunc])),
                "truncated tag of len {trunc} was accepted"
            );
        }

        // A trailing-zero-padded over-length tag must also fail.
        let mut over = [0u8; 40];
        over[..tag.len()].copy_from_slice(&tag);
        let m = HmacSha256::new(key).chain(msg);
        assert!(!bool::from(Mac::verify(m, &over)));
    }
}
