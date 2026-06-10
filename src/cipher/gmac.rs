//! GMAC — the Galois Message Authentication Code (NIST SP 800-38D).
//!
//! GMAC is GCM run in MAC-only mode: it authenticates a message supplied
//! entirely as associated data, with an empty plaintext. The resulting tag is
//! exactly the GCM authentication tag `E_K(J0) ⊕ GHASH_H(data)`.
//!
//! This wraps the existing [`Gcm`] context so the field arithmetic, `J0`
//! derivation and tag computation are shared (and constant-time) with AES-GCM.
//! [`Gmac`] is generic over any 128-bit [`BlockCipher`]; the [`AesGmac128`] /
//! [`AesGmac256`] aliases pin it to AES.
//!
//! As with GCM, a given (key, nonce) pair must **never** be reused.

use super::BlockCipher;
use super::gcm::Gcm;

/// A GMAC context: GCM in MAC-only mode over a fixed nonce.
///
/// Construct with [`Gmac::new`], feed the message with [`Gmac::update`], then
/// produce the 16-byte tag with [`Gmac::finalize`]. The data is buffered until
/// finalization so the underlying GHASH sees it as one contiguous AAD stream.
#[derive(Clone)]
pub struct Gmac<C: BlockCipher> {
    gcm: Gcm<C>,
    nonce: [u8; 12],
    #[cfg(feature = "alloc")]
    data: alloc::vec::Vec<u8>,
    #[cfg(not(feature = "alloc"))]
    data: GmacBuf,
}

/// Fixed-capacity message buffer used when the `alloc` feature is off.
#[cfg(not(feature = "alloc"))]
#[derive(Clone)]
struct GmacBuf {
    bytes: [u8; 1024],
    len: usize,
}

impl<C: BlockCipher> Gmac<C> {
    /// Creates a GMAC context from a pre-keyed block cipher and a 12-byte
    /// nonce. The 96-bit nonce is the SP 800-38D recommended size.
    pub fn new(cipher: C, nonce: &[u8; 12]) -> Self {
        Gmac {
            gcm: Gcm::new(cipher),
            nonce: *nonce,
            #[cfg(feature = "alloc")]
            data: alloc::vec::Vec::new(),
            #[cfg(not(feature = "alloc"))]
            data: GmacBuf {
                bytes: [0u8; 1024],
                len: 0,
            },
        }
    }

    /// Feeds message bytes. May be called any number of times.
    ///
    /// # Panics
    /// Without the `alloc` feature, panics if the total message exceeds the
    /// 1024-byte fixed buffer.
    pub fn update(&mut self, data: &[u8]) {
        #[cfg(feature = "alloc")]
        {
            self.data.extend_from_slice(data);
        }
        #[cfg(not(feature = "alloc"))]
        {
            let end = self.data.len + data.len();
            assert!(
                end <= self.data.bytes.len(),
                "GMAC message exceeds 1024 bytes; enable the `alloc` feature"
            );
            self.data.bytes[self.data.len..end].copy_from_slice(data);
            self.data.len = end;
        }
    }

    /// Returns the buffered message as a slice.
    #[inline]
    fn message(&self) -> &[u8] {
        #[cfg(feature = "alloc")]
        {
            &self.data
        }
        #[cfg(not(feature = "alloc"))]
        {
            &self.data.bytes[..self.data.len]
        }
    }

    /// Consumes the MAC and returns the 16-byte tag: the GCM tag computed with
    /// the buffered message as AAD and an empty plaintext.
    pub fn finalize(self) -> [u8; 16] {
        let mut empty: [u8; 0] = [];
        self.gcm.encrypt(&self.nonce, self.message(), &mut empty)
    }

    /// Consumes the MAC and writes the tag into `out`, truncated to `out.len()`
    /// (which must be ≤ 16).
    pub fn finalize_into(self, out: &mut [u8]) {
        let tag = self.finalize();
        let n = out.len().min(16);
        out[..n].copy_from_slice(&tag[..n]);
    }
}

impl<C: BlockCipher> Drop for Gmac<C> {
    fn drop(&mut self) {
        // The buffered message is not secret, but wipe it and the nonce as a
        // matter of hygiene, mirroring the other MAC drops in this module.
        for b in self.nonce.iter_mut() {
            *b = 0;
        }
        let _ = core::hint::black_box(&self.nonce);
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
