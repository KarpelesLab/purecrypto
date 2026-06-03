//! Ascon-AEAD128 authenticated encryption (NIST SP 800-232 §4).
//!
//! A nonce-based AEAD with a 128-bit key, 128-bit nonce, and 128-bit tag,
//! built on the 320-bit Ascon permutation with a 128-bit rate (`S0 ‖ S1`).
//! Initialization and finalization use `Ascon-p[12]`; associated-data and
//! plaintext blocks are absorbed with `Ascon-p[8]`.
//!
//! As with any nonce-based AEAD, a `(key, nonce)` pair must **never** be
//! reused: nonce reuse breaks the confidentiality and authenticity guarantees.

use super::permutation::State;
use crate::cipher::TagMismatch;
use crate::ct::ConstantTimeEq;

/// Ascon-AEAD128 initialization value (SP 800-232 §4.1.1, Alg. 3): the 64-bit
/// constant placed in `S0` before `Ascon-p[12]`.
const IV: u64 = 0x0000_1000_808c_0001;

/// Domain-separation constant XORed into `S4` after associated-data processing
/// (SP 800-232 §A.2: the bit `0^319 ‖ 1` is `0x8000000000000000` as an integer
/// added to `S4`).
const DOMAIN_SEP: u64 = 0x8000_0000_0000_0000;

/// The AEAD rate in bytes (128 bits = words `S0`,`S1`).
const RATE: usize = 16;

/// Ascon-AEAD128 (NIST SP 800-232): 128-bit key/nonce/tag AEAD.
///
/// Constructed from a 16-byte key; each call binds a fresh 16-byte nonce and
/// optional associated data. The key words are wiped on drop.
#[derive(Clone)]
pub struct AsconAead128 {
    /// Key words `K0 ‖ K1`, loaded little-endian from the 16-byte key.
    k0: u64,
    k1: u64,
}

impl AsconAead128 {
    /// Creates an Ascon-AEAD128 context from a 16-byte key.
    pub fn new(key: &[u8; 16]) -> Self {
        AsconAead128 {
            k0: u64::from_le_bytes(key[0..8].try_into().unwrap()),
            k1: u64::from_le_bytes(key[8..16].try_into().unwrap()),
        }
    }

    /// Initialization phase (SP 800-232 Alg. 3, steps producing the keyed
    /// state): `S ← IV ‖ K ‖ N`, then `p12`, then XOR `K` into `S3 ‖ S4`.
    fn init(&self, nonce: &[u8; 16]) -> State {
        let n0 = u64::from_le_bytes(nonce[0..8].try_into().unwrap());
        let n1 = u64::from_le_bytes(nonce[8..16].try_into().unwrap());
        let mut s = State([IV, self.k0, self.k1, n0, n1]);
        s.permute12();
        s.0[3] ^= self.k0;
        s.0[4] ^= self.k1;
        s
    }

    /// Absorbs associated data and applies the domain-separation bit
    /// (SP 800-232 Alg. 3, "Processing associated data"). Always applies the
    /// domain separator, even when `aad` is empty.
    fn absorb_ad(s: &mut State, aad: &[u8]) {
        if !aad.is_empty() {
            let mut chunks = aad.chunks_exact(RATE);
            for block in chunks.by_ref() {
                s.0[0] ^= u64::from_le_bytes(block[0..8].try_into().unwrap());
                s.0[1] ^= u64::from_le_bytes(block[8..16].try_into().unwrap());
                s.permute8();
            }
            // Final (possibly empty) block with `pad10*` (SP 800-232 §A.2).
            let rem = chunks.remainder();
            let (w0, w1) = load_padded_rate(rem);
            s.0[0] ^= w0;
            s.0[1] ^= w1;
            s.permute8();
        }
        // Domain separation: applied unconditionally (SP 800-232 Eq. (22)).
        s.0[4] ^= DOMAIN_SEP;
    }

    /// Finalization phase (SP 800-232 Alg. 3): XOR `K` into `S2 ‖ S3`, `p12`,
    /// then `T ← (S3 ‖ S4) ⊕ K`.
    fn finalize(&self, s: &mut State) -> [u8; 16] {
        s.0[2] ^= self.k0;
        s.0[3] ^= self.k1;
        s.permute12();
        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&(s.0[3] ^ self.k0).to_le_bytes());
        tag[8..16].copy_from_slice(&(s.0[4] ^ self.k1).to_le_bytes());
        tag
    }

    /// Encrypts `buffer` in place and returns the 16-byte authentication tag,
    /// binding the optional `aad`.
    ///
    /// `nonce` must be unique per key (see the type-level note on nonce reuse).
    pub fn encrypt(&self, nonce: &[u8; 16], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        let mut s = self.init(nonce);
        Self::absorb_ad(&mut s, aad);

        let mut chunks = buffer.chunks_exact_mut(RATE);
        for block in chunks.by_ref() {
            s.0[0] ^= u64::from_le_bytes(block[0..8].try_into().unwrap());
            s.0[1] ^= u64::from_le_bytes(block[8..16].try_into().unwrap());
            block[0..8].copy_from_slice(&s.0[0].to_le_bytes());
            block[8..16].copy_from_slice(&s.0[1].to_le_bytes());
            s.permute8();
        }
        // Final partial block: XOR padded plaintext into the rate, emit `ℓ`
        // ciphertext bytes (SP 800-232 Eq. (27)–(28)).
        let rem = chunks.into_remainder();
        let (p0, p1) = load_padded_rate(rem);
        s.0[0] ^= p0;
        s.0[1] ^= p1;
        let mut rate_bytes = [0u8; RATE];
        rate_bytes[0..8].copy_from_slice(&s.0[0].to_le_bytes());
        rate_bytes[8..16].copy_from_slice(&s.0[1].to_le_bytes());
        rem.copy_from_slice(&rate_bytes[..rem.len()]);

        self.finalize(&mut s)
    }

    /// Verifies `tag` and, only if it matches, decrypts `buffer` in place.
    ///
    /// The tag is checked in constant time. On mismatch the ciphertext is
    /// **left untouched** (no unauthenticated plaintext is produced) and
    /// [`TagMismatch`] is returned.
    pub fn decrypt(
        &self,
        nonce: &[u8; 16],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        let mut s = self.init(nonce);
        Self::absorb_ad(&mut s, aad);

        // Decrypt into a scratch copy so the input buffer is untouched until the
        // tag is verified. `n` full blocks plus one (possibly empty) partial.
        let full = buffer.len() / RATE * RATE;
        let mut plain = [0u8; RATE];

        // Process full ciphertext blocks: P = rate ⊕ C, then rate ← C.
        let mut i = 0;
        while i < full {
            let c0 = u64::from_le_bytes(buffer[i..i + 8].try_into().unwrap());
            let c1 = u64::from_le_bytes(buffer[i + 8..i + 16].try_into().unwrap());
            let q0 = s.0[0] ^ c0;
            let q1 = s.0[1] ^ c1;
            plain[0..8].copy_from_slice(&q0.to_le_bytes());
            plain[8..16].copy_from_slice(&q1.to_le_bytes());
            s.0[0] = c0;
            s.0[1] = c1;
            s.permute8();
            buffer[i..i + 16].copy_from_slice(&plain);
            i += RATE;
        }

        // Final partial ciphertext block (SP 800-232 Alg. 4, ciphertext tail):
        //   P̃ ← S[0..ℓ] ⊕ C̃ ; S[ℓ..] ⊕= pad ; S[0..ℓ] ← C̃.
        let rem_len = buffer.len() - full;
        let mut rate_bytes = [0u8; RATE];
        rate_bytes[0..8].copy_from_slice(&s.0[0].to_le_bytes());
        rate_bytes[8..16].copy_from_slice(&s.0[1].to_le_bytes());
        for j in 0..rem_len {
            plain[j] = rate_bytes[j] ^ buffer[full + j];
        }
        // Replace the absorbed rate bytes with the ciphertext bytes, and apply
        // the `pad10*` bit at byte `rem_len`.
        rate_bytes[..rem_len].copy_from_slice(&buffer[full..full + rem_len]);
        rate_bytes[rem_len] ^= 0x01;
        s.0[0] = u64::from_le_bytes(rate_bytes[0..8].try_into().unwrap());
        s.0[1] = u64::from_le_bytes(rate_bytes[8..16].try_into().unwrap());

        let expected = self.finalize(&mut s);
        if bool::from(expected.ct_eq(tag)) {
            // Authentic: commit the recovered plaintext tail.
            buffer[full..full + rem_len].copy_from_slice(&plain[..rem_len]);
            Ok(())
        } else {
            // Inauthentic: restore the full blocks we overwrote in-place and
            // leave the partial tail (never written) as the original
            // ciphertext, so the buffer is unchanged on failure.
            let mut s2 = self.init(nonce);
            Self::absorb_ad(&mut s2, aad);
            let mut k = 0;
            while k < full {
                let p0 = u64::from_le_bytes(buffer[k..k + 8].try_into().unwrap());
                let p1 = u64::from_le_bytes(buffer[k + 8..k + 16].try_into().unwrap());
                let c0 = s2.0[0] ^ p0;
                let c1 = s2.0[1] ^ p1;
                buffer[k..k + 8].copy_from_slice(&c0.to_le_bytes());
                buffer[k + 8..k + 16].copy_from_slice(&c1.to_le_bytes());
                s2.0[0] = c0;
                s2.0[1] = c1;
                s2.permute8();
                k += RATE;
            }
            Err(TagMismatch)
        }
    }
}

/// Loads `rem` (length `< 16`) into a 128-bit rate `(S0, S1)` value with the
/// `pad10*` bit set at byte `rem.len()` (SP 800-232 §A.2).
#[inline]
fn load_padded_rate(rem: &[u8]) -> (u64, u64) {
    let mut block = [0u8; RATE];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] = 0x01;
    (
        u64::from_le_bytes(block[0..8].try_into().unwrap()),
        u64::from_le_bytes(block[8..16].try_into().unwrap()),
    )
}

impl Drop for AsconAead128 {
    fn drop(&mut self) {
        // Best-effort wipe of the secret key words.
        self.k0 = 0;
        self.k1 = 0;
        let _ = core::hint::black_box(&self.k0);
        let _ = core::hint::black_box(&self.k1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    // All Ascon-AEAD128 KAT vectors below are from the official Ascon reference
    // repository's NIST SP 800-232 known-answer-test file
    // `crypto_aead/asconaead128/LWC_AEAD_KAT_128_128.txt`
    // (github.com/ascon/ascon-c). In that file `CT` is ciphertext ‖ 16-byte
    // tag. Every vector uses key 000102…0F and nonce 101112…1F.

    const KEY: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    const NONCE: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

    fn check(aad_hex: &str, pt_hex: &str, ct_tag_hex: &str) {
        let aad = crate::test_util::from_hex_vec(aad_hex);
        let pt = crate::test_util::from_hex_vec(pt_hex);
        let ct_tag = crate::test_util::from_hex_vec(ct_tag_hex);
        let (expect_ct, expect_tag) = ct_tag.split_at(ct_tag.len() - 16);

        let cipher = AsconAead128::new(&KEY);
        let mut buf = pt.clone();
        let tag = cipher.encrypt(&NONCE, &aad, &mut buf);
        assert_eq!(buf, expect_ct, "ciphertext mismatch");
        assert_eq!(&tag[..], expect_tag, "tag mismatch");

        // Round-trip decryption recovers the plaintext.
        let mut dec = buf.clone();
        cipher.decrypt(&NONCE, &aad, &mut dec, &tag).unwrap();
        assert_eq!(dec, pt, "decrypt round-trip mismatch");
    }

    // Count 1: empty PT, empty AD.
    #[test]
    fn kat_empty_empty() {
        check("", "", "4F9C278211BEC9316BF68F46EE8B2EC6");
    }

    // Count 2: empty PT, 1-byte AD (with-AD case, auth only).
    #[test]
    fn kat_empty_pt_with_ad() {
        check("30", "", "CCCB674FE18A09A285D6AB11B35675C0");
    }

    // Count 545: 16-byte PT + 16-byte AD (one full block each).
    #[test]
    fn kat_full_block_pt_and_ad() {
        check(
            "303132333435363738393A3B3C3D3E3F",
            "202122232425262728292A2B2C2D2E2F",
            "6373EBB28BE97C9BAC090CF399C13EF13ABFC0D209E8F4844C90814D13F32C59",
        );
    }

    // Count 1057: 32-byte PT, empty AD (multi-block plaintext, exact boundary).
    #[test]
    fn kat_multiblock_pt_no_ad() {
        check(
            "",
            "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
            "E8C3DEEE246CC5EAE3E872313897A2BB6089AA3E15E80307970F2D1F006654C2\
             AAA5FA172CB9F07D07463CEFC7440BC1",
        );
    }

    // Count 579: 17-byte PT + 17-byte AD (partial trailing blocks on both).
    #[test]
    fn kat_partial_blocks_pt_and_ad() {
        check(
            "303132333435363738393A3B3C3D3E3F40",
            "202122232425262728292A2B2C2D2E2F30",
            "BF77C71B3DE9F1C5B372EF273A08E89BE9D507D7B3C2AEE97911E791F7970D6635",
        );
    }

    // Authentication-failure case: a corrupted tag is rejected and the buffer
    // (ciphertext) is left unchanged; tampered AAD is likewise rejected.
    #[test]
    fn auth_failure_rejects_and_preserves_buffer() {
        let cipher = AsconAead128::new(&KEY);
        let aad = from_hex::<16>("303132333435363738393A3B3C3D3E3F");
        let plaintext =
            from_hex::<33>("202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F40");

        let mut ct = plaintext;
        let tag = cipher.encrypt(&NONCE, &aad, &mut ct);
        let ciphertext = ct;

        // Corrupted tag.
        let mut bad_tag = tag;
        bad_tag[0] ^= 1;
        let mut buf = ciphertext;
        assert_eq!(
            cipher.decrypt(&NONCE, &aad, &mut buf, &bad_tag),
            Err(TagMismatch)
        );
        assert_eq!(buf, ciphertext, "buffer must be unchanged on auth failure");

        // Tampered AAD.
        let mut bad_aad = aad;
        bad_aad[0] ^= 1;
        let mut buf = ciphertext;
        assert_eq!(
            cipher.decrypt(&NONCE, &bad_aad, &mut buf, &tag),
            Err(TagMismatch)
        );
        assert_eq!(buf, ciphertext, "buffer must be unchanged on auth failure");

        // Correct tag still decrypts.
        let mut buf = ciphertext;
        cipher.decrypt(&NONCE, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, plaintext);
    }
}
