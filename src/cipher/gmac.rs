//! GMAC — the Galois Message Authentication Code (NIST SP 800-38D).
//!
//! GMAC is GCM run in MAC-only mode: it authenticates a message supplied
//! entirely as associated data, with an empty plaintext. The resulting tag is
//! exactly the GCM authentication tag `E_K(J0) ⊕ GHASH_H(data)`.
//!
//! This wraps the existing [`Gcm`] context so the field arithmetic, `J0`
//! derivation and tag computation are shared (and constant-time) with AES-GCM.
//! The message is streamed into the GHASH accumulator as it arrives rather than
//! buffered, so there is no message-length limit and no allocation.
//! [`Gmac`] is generic over any 128-bit [`BlockCipher`]; the [`AesGmac128`] /
//! [`AesGmac256`] aliases pin it to AES.
//!
//! As with GCM, a given (key, nonce) pair must **never** be reused.

use super::BlockCipher;
use super::gcm::Gcm;

/// A GMAC context: GCM in MAC-only mode over a fixed nonce.
///
/// Construct with [`Gmac::new`], feed the message with [`Gmac::update`], then
/// produce the 16-byte tag with [`Gmac::finalize`]. The message is streamed
/// straight into the GHASH accumulator — only a single partial 16-byte block is
/// ever held — so this works on messages of any size, with or without `alloc`.
#[derive(Clone)]
pub struct Gmac<C: BlockCipher> {
    gcm: Gcm<C>,
    nonce: [u8; 12],
    /// GHASH accumulator over every whole block folded in so far.
    acc: u128,
    /// The trailing bytes of an incomplete block, not yet folded in.
    block: [u8; 16],
    /// How many bytes of `block` are live (`0..16`).
    block_len: usize,
    /// Total message length in bytes, for the GHASH length block.
    total: u64,
}

impl<C: BlockCipher> Gmac<C> {
    /// SP 800-38D caps the associated data at `2^64 − 1` bits; GMAC's message
    /// *is* the associated data, so this is its length limit. Reaching it would
    /// mean pushing two exabytes through [`Gmac::update`].
    pub const MAX_MESSAGE_LEN: u64 = (1u64 << 61) - 1;

    /// Creates a GMAC context from a pre-keyed block cipher and a 12-byte
    /// nonce. The 96-bit nonce is the SP 800-38D recommended size.
    pub fn new(cipher: C, nonce: &[u8; 12]) -> Self {
        Gmac {
            gcm: Gcm::new(cipher),
            nonce: *nonce,
            acc: 0,
            block: [0u8; 16],
            block_len: 0,
            total: 0,
        }
    }

    /// Feeds message bytes. May be called any number of times, with any
    /// chunking: whole blocks go straight into the GHASH accumulator and at
    /// most 15 bytes are ever buffered.
    ///
    /// # Panics
    /// Panics only if the total message would exceed
    /// [`MAX_MESSAGE_LEN`](Self::MAX_MESSAGE_LEN) (2^61 − 1 bytes), the point
    /// at which the GHASH length block overflows.
    pub fn update(&mut self, mut data: &[u8]) {
        self.total = match self
            .total
            .checked_add(data.len() as u64)
            .filter(|&t| t <= Self::MAX_MESSAGE_LEN)
        {
            Some(t) => t,
            None => panic!("GMAC message exceeds 2^64 − 1 bits (NIST SP 800-38D §5.2.1.1)"),
        };

        // Top up a partial block left by a previous call first.
        if self.block_len > 0 {
            let n = data.len().min(16 - self.block_len);
            self.block[self.block_len..self.block_len + n].copy_from_slice(&data[..n]);
            self.block_len += n;
            data = &data[n..];
            if self.block_len < 16 {
                // `data` is exhausted and we are still short of a full block.
                return;
            }
            let block = self.block;
            self.acc = self.gcm.ghash_fold(self.acc, &block);
            self.block_len = 0;
        }

        // Whole blocks go straight into the accumulator (the hardware GHASH
        // aggregates these eight at a time); stash the remainder.
        let full = data.len() & !15;
        if full > 0 {
            self.acc = self.gcm.ghash_fold(self.acc, &data[..full]);
        }
        let rem = &data[full..];
        self.block[..rem.len()].copy_from_slice(rem);
        self.block_len = rem.len();
    }

    /// Consumes the MAC and returns the 16-byte tag: the GCM tag over the
    /// message as AAD with an empty plaintext.
    pub fn finalize(self) -> [u8; 16] {
        // GHASH zero-pads the final partial block; the length block below
        // carries the true byte count, so the padding stays unambiguous.
        let x = self.gcm.ghash_fold(self.acc, &self.block[..self.block_len]);
        let j0 = self.gcm.j0(&self.nonce);
        self.gcm.tag_from_ghash(j0, x, self.total, 0)
    }

    /// Consumes the MAC and writes the tag into `out`, truncated to `out.len()`
    /// (which must be <= 16).
    pub fn finalize_into(self, out: &mut [u8]) {
        let tag = self.finalize();
        let n = out.len().min(16);
        out[..n].copy_from_slice(&tag[..n]);
    }
}

impl<C: BlockCipher> Drop for Gmac<C> {
    fn drop(&mut self) {
        // The message and the running accumulator are not themselves secret,
        // but wipe them along with the nonce, mirroring the other MAC drops in
        // this module. (`Gcm`'s own `Drop` handles H and its powers.)
        self.nonce = [0u8; 12];
        self.block = [0u8; 16];
        self.acc = 0;
        let _ = core::hint::black_box(&self.nonce);
        let _ = core::hint::black_box(&self.block);
        let _ = core::hint::black_box(&self.acc);
    }
}

// The `Mac` trait lives in the `hash` module, so this impl is only available
// when that module is compiled in.
#[cfg(feature = "hash")]
impl<C: BlockCipher + Clone> crate::hash::Mac for Gmac<C> {
    /// GMAC always produces a 16-byte tag, so the trait's default `verify`
    /// rejects any `expected` that is not exactly 16 bytes.
    const OUTPUT_LEN: Option<usize> = Some(16);

    fn update(&mut self, data: &[u8]) {
        Gmac::update(self, data);
    }

    fn finalize_into(self, out: &mut [u8]) {
        Gmac::finalize_into(self, out);
    }
}

/// AES-128 in GMAC mode (NIST SP 800-38D).
pub type AesGmac128 = Gmac<super::Aes128>;
/// AES-256 in GMAC mode (NIST SP 800-38D).
pub type AesGmac256 = Gmac<super::Aes256>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{Aes128, Aes256};
    use crate::test_util::from_hex;

    fn gmac128(key: &str, nonce: &str, data: &[u8]) -> [u8; 16] {
        let mut m = AesGmac128::new(Aes128::new(&from_hex::<16>(key)), &from_hex::<12>(nonce));
        m.update(data);
        m.finalize()
    }

    // NIST GCM/GMAC test vectors with empty plaintext: the tag is GMAC over the
    // (possibly empty) AAD. Values are from the NIST CAVS GCM validation set
    // (gcmEncryptExtIV*.rsp), which is GMAC exactly when PTlen=0.

    // gcmEncryptExtIV128: Keylen=128, IVlen=96, AADlen=0, PTlen=0, Count 0.
    #[test]
    fn nist_aes128_gmac() {
        let tag = gmac128(
            "11754cd72aec309bf52f7687212e8957",
            "3c819d9a9bed087615030b65",
            &[],
        );
        assert_eq!(tag, from_hex::<16>("250327c674aaf477aef2675748cf6971"));
    }

    // NIST CAVS gcmEncryptExtIV128: AADlen=128, PTlen=0, Taglen=128, Count 0.
    #[test]
    fn nist_aes128_gmac_with_aad() {
        let aad = from_hex::<16>("7a43ec1d9c0a5a78a0b16533a6213cab");
        let tag = gmac128(
            "77be63708971c4e240d1cb79e8d77feb",
            "e0e00f19fed7ba0136a797f3",
            &aad,
        );
        assert_eq!(tag, from_hex::<16>("209fcc8d3675ed938e9c7166709dd946"));
    }

    // NIST CAVS gcmEncryptExtIV256: Keylen=256, IVlen=96, AADlen=0, PTlen=0.
    #[test]
    fn nist_aes256_gmac() {
        let mut m = AesGmac256::new(
            Aes256::new(&from_hex::<32>(
                "b52c505a37d78eda5dd34f20c22540ea1b58963cf8e5bf8ffa85f9f2492505b4",
            )),
            &from_hex::<12>("516c33929df5a3284ff463d7"),
        );
        m.update(&[]);
        assert_eq!(
            m.finalize(),
            from_hex::<16>("bdc1ac884d332457a1d2664f168c76f0")
        );
    }

    // Streaming updates in chunks match a one-shot tag.
    #[test]
    fn streaming_matches_oneshot() {
        let key = "11754cd72aec309bf52f7687212e8957";
        let nonce = "3c819d9a9bed087615030b65";
        let data =
            from_hex::<32>("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72");
        let oneshot = gmac128(key, nonce, &data);

        let mut m = AesGmac128::new(Aes128::new(&from_hex::<16>(key)), &from_hex::<12>(nonce));
        m.update(&data[..7]);
        m.update(&data[7..16]);
        m.update(&data[16..]);
        assert_eq!(m.finalize(), oneshot);
    }

    // Streaming must be independent of the chunking, including chunk
    // boundaries that land inside a GHASH block and updates that never fill
    // one. Regression guard for the incremental accumulator that replaced the
    // whole-message buffer.
    #[test]
    fn every_chunking_matches_oneshot() {
        let key = from_hex::<16>("11754cd72aec309bf52f7687212e8957");
        let nonce = from_hex::<12>("3c819d9a9bed087615030b65");
        let msg: [u8; 70] = core::array::from_fn(|i| (i as u8).wrapping_mul(31) ^ 0x5a);

        for len in 0..=msg.len() {
            let data = &msg[..len];
            let mut one = AesGmac128::new(Aes128::new(&key), &nonce);
            one.update(data);
            let want = one.finalize();

            // Every single split point.
            for split in 0..=len {
                let mut m = AesGmac128::new(Aes128::new(&key), &nonce);
                m.update(&data[..split]);
                m.update(&data[split..]);
                assert_eq!(m.finalize(), want, "len {len} split {split}");
            }
            // Byte at a time: the partial-block path on every call.
            let mut m = AesGmac128::new(Aes128::new(&key), &nonce);
            for b in data {
                m.update(core::slice::from_ref(b));
            }
            assert_eq!(m.finalize(), want, "len {len} byte-at-a-time");
        }
    }

    // The old fixed-capacity buffer aborted at 1025 bytes without `alloc`,
    // which made a network-facing GMAC a remote panic. Nothing is buffered any
    // more, so a message far past that must simply work — and must agree with
    // the same bytes fed as one slice.
    #[test]
    fn long_message_without_buffering() {
        let key = from_hex::<16>("11754cd72aec309bf52f7687212e8957");
        let nonce = from_hex::<12>("3c819d9a9bed087615030b65");
        let msg: [u8; 5000] = core::array::from_fn(|i| (i % 251) as u8);

        let mut one = AesGmac128::new(Aes128::new(&key), &nonce);
        one.update(&msg);
        let want = one.finalize();

        let mut m = AesGmac128::new(Aes128::new(&key), &nonce);
        for chunk in msg.chunks(7) {
            m.update(chunk);
        }
        assert_eq!(m.finalize(), want);
    }

    // The crate `Mac` trait routes through the same finalize as the inherent
    // methods and provides constant-time verify.
    #[cfg(feature = "hash")]
    #[test]
    fn mac_trait_verify() {
        use crate::hash::Mac;
        let key = from_hex::<16>("11754cd72aec309bf52f7687212e8957");
        let nonce = from_hex::<12>("3c819d9a9bed087615030b65");
        let mut m = AesGmac128::new(Aes128::new(&key), &nonce);
        Mac::update(&mut m, &[]);
        let expected = from_hex::<16>("250327c674aaf477aef2675748cf6971");
        assert!(bool::from(Mac::verify(m, &expected)));

        let mut m = AesGmac128::new(Aes128::new(&key), &nonce);
        Mac::update(&mut m, &[]);
        let mut bad = expected;
        bad[0] ^= 1;
        assert!(!bool::from(Mac::verify(m.clone(), &bad)));
        // OUTPUT_LEN = Some(16): the trait verify rejects anything that is not
        // exactly the full 16-byte tag — truncated, empty, or over-length.
        assert!(!bool::from(Mac::verify(m.clone(), &expected[..8])));
        assert!(!bool::from(Mac::verify(m.clone(), &[])));
        let mut long = [0u8; 17];
        long[..16].copy_from_slice(&expected);
        assert!(!bool::from(Mac::verify(m, &long)));
    }
}
