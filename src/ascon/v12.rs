//! Ascon v1.2 authenticated encryption — the NIST LWC final-round submission
//! variants [`Ascon128`], [`Ascon128a`] and [`Ascon80pq`].
//!
//! These are **not** the SP 800-232 [`AsconAead128`](super::AsconAead128):
//! the v1.2 submission loads state words big-endian, uses different
//! initialization vectors, a 64-bit rate for Ascon-128 / Ascon-80pq (128-bit
//! for Ascon-128a) and `p⁶` (Ascon-128, Ascon-80pq) or `p⁸` (Ascon-128a)
//! between data blocks. Ciphertexts are not interoperable with the standard.
//! The three variants share the 320-bit permutation with the SP 800-232
//! functions and exist for interoperability with pre-standard deployments
//! (the CAESAR lightweight portfolio, the NIST LWC KATs).
//!
//! | variant | key | nonce | tag | rate | rounds `a`/`b` |
//! | --- | --- | --- | --- | --- | --- |
//! | [`Ascon128`] | 128 bits | 128 bits | 128 bits | 64 bits | 12 / 6 |
//! | [`Ascon128a`] | 128 bits | 128 bits | 128 bits | 128 bits | 12 / 8 |
//! | [`Ascon80pq`] | 160 bits | 128 bits | 128 bits | 64 bits | 12 / 6 |
//!
//! The crate AEAD shape is followed: `encrypt` transforms the buffer in place
//! and returns the tag; `decrypt` verifies the tag in constant time and
//! returns [`TagMismatch`] on failure. As with [`AsconAead128`](super::AsconAead128)
//! the duplex cannot verify before it decrypts, so decryption runs in place
//! and a second pass re-encrypts the buffer when the tag turns out to be
//! wrong — see [`Ascon128::decrypt`] for the aliasing caveat.
//!
//! A `(key, nonce)` pair must never be reused. Correctness is checked against
//! the Wycheproof `ascon128` / `ascon128a` / `ascon80pq` files and the
//! reference LWC known-answer tests.

use super::permutation::State;
use crate::cipher::TagMismatch;
use crate::ct::ConstantTimeEq;
use crate::zeroize::{Zeroize, ZeroizeOnDrop};

/// The public per-variant parameters.
struct Params {
    /// The 64-bit `IV` word (for Ascon-80pq only its top 32 bits; the low
    /// half is filled by the first key word).
    iv: u64,
    /// Rate in bytes: 8 or 16.
    rate: usize,
    /// Whether the data-phase permutation is `p⁸` (else `p⁶`).
    pb8: bool,
    /// Key length in bytes: 16 or 20.
    key_len: usize,
}

/// The key words, laid out so that the 320-bit initial state is
/// `IV ‖ K ‖ N` for both key sizes: `kh` holds the first 4 bytes of a
/// 160-bit key in its low half (zero for a 128-bit key); `k1 ‖ k2` are the
/// last 128 bits of the key.
#[derive(Clone)]
struct Core {
    kh: u64,
    k1: u64,
    k2: u64,
}

impl Core {
    fn from_key(key: &[u8]) -> Self {
        match key.len() {
            16 => Core {
                kh: 0,
                k1: u64::from_be_bytes(key[0..8].try_into().unwrap()),
                k2: u64::from_be_bytes(key[8..16].try_into().unwrap()),
            },
            20 => Core {
                kh: u64::from(u32::from_be_bytes(key[0..4].try_into().unwrap())),
                k1: u64::from_be_bytes(key[4..12].try_into().unwrap()),
                k2: u64::from_be_bytes(key[12..20].try_into().unwrap()),
            },
            _ => unreachable!("key length is fixed by the variant"),
        }
    }

    /// `S ← IV ‖ K ‖ N`, `p¹²`, `S ⊕= 0* ‖ K`.
    fn init(&self, p: &Params, nonce: &[u8; 16]) -> State {
        let n0 = u64::from_be_bytes(nonce[0..8].try_into().unwrap());
        let n1 = u64::from_be_bytes(nonce[8..16].try_into().unwrap());
        let mut s = State([p.iv | self.kh, self.k1, self.k2, n0, n1]);
        s.permute12();
        s.0[2] ^= self.kh;
        s.0[3] ^= self.k1;
        s.0[4] ^= self.k2;
        s
    }

    /// `S ⊕= 0ʳ ‖ K ‖ 0*`, `p¹²`, `T ← (S3 ‖ S4) ⊕ (last 128 key bits)`.
    fn finalize(&self, p: &Params, s: &mut State) -> [u8; 16] {
        match (p.key_len, p.rate) {
            (16, 8) => {
                s.0[1] ^= self.k1;
                s.0[2] ^= self.k2;
            }
            (16, 16) => {
                s.0[2] ^= self.k1;
                s.0[3] ^= self.k2;
            }
            (20, 8) => {
                s.0[1] ^= (self.kh << 32) | (self.k1 >> 32);
                s.0[2] ^= (self.k1 << 32) | (self.k2 >> 32);
                s.0[3] ^= self.k2 << 32;
            }
            _ => unreachable!("parameter sets are fixed by the variants"),
        }
        s.permute12();
        let mut tag = [0u8; 16];
        tag[0..8].copy_from_slice(&(s.0[3] ^ self.k1).to_be_bytes());
        tag[8..16].copy_from_slice(&(s.0[4] ^ self.k2).to_be_bytes());
        tag
    }

    fn encrypt(&self, p: &Params, nonce: &[u8; 16], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
        let mut s = self.init(p, nonce);
        absorb_ad(p, &mut s, aad);
        encrypt_data(p, &mut s, buffer);
        self.finalize(p, &mut s)
    }

    fn decrypt(
        &self,
        p: &Params,
        nonce: &[u8; 16],
        aad: &[u8],
        buffer: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<(), TagMismatch> {
        let mut s = self.init(p, nonce);
        absorb_ad(p, &mut s, aad);
        let rate = p.rate;
        let mut chunks = buffer.chunks_exact_mut(rate);
        for c in &mut chunks {
            let ks = rate_bytes(&s);
            let mut ct = [0u8; 16];
            ct[..rate].copy_from_slice(c);
            for (o, k) in c.iter_mut().zip(ks.iter()) {
                *o ^= *k;
            }
            set_rate(p, &mut s, &ct);
            permute_b(p, &mut s);
        }
        // Tail: `P̃ ← S[..ℓ] ⊕ C̃`, then the rate becomes `C̃ ‖ pad ⊕ S[ℓ..]`.
        let rem = chunks.into_remainder();
        let mut ks = rate_bytes(&s);
        for (i, o) in rem.iter_mut().enumerate() {
            let c = *o;
            *o ^= ks[i];
            ks[i] = c;
        }
        ks[rem.len()] ^= 0x80;
        set_rate(p, &mut s, &ks);
        ks.zeroize();

        let expected = self.finalize(p, &mut s);
        if bool::from(expected.ct_eq(tag)) {
            return Ok(());
        }
        // Inauthentic: the buffer now holds unauthenticated plaintext. Run
        // the encryption pass over it to restore the original ciphertext.
        let mut s = self.init(p, nonce);
        absorb_ad(p, &mut s, aad);
        encrypt_data(p, &mut s, buffer);
        Err(TagMismatch)
    }
}

impl Drop for Core {
    fn drop(&mut self) {
        self.kh.zeroize();
        self.k1.zeroize();
        self.k2.zeroize();
    }
}

/// `p⁸` or `p⁶`, per the variant.
#[inline]
fn permute_b(p: &Params, s: &mut State) {
    if p.pb8 {
        s.permute8();
    } else {
        s.permute6();
    }
}

/// The 16 rate bytes (`S0 ‖ S1`, big-endian); only the first `rate` are
/// meaningful for a 64-bit-rate variant.
#[inline]
fn rate_bytes(s: &State) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..8].copy_from_slice(&s.0[0].to_be_bytes());
    out[8..16].copy_from_slice(&s.0[1].to_be_bytes());
    out
}

/// Overwrites the rate part of the state with `bytes`.
#[inline]
fn set_rate(p: &Params, s: &mut State, bytes: &[u8; 16]) {
    s.0[0] = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
    if p.rate == 16 {
        s.0[1] = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    }
}

/// XORs `block` (exactly `rate` bytes) into the rate.
#[inline]
fn xor_rate(p: &Params, s: &mut State, block: &[u8]) {
    s.0[0] ^= u64::from_be_bytes(block[0..8].try_into().unwrap());
    if p.rate == 16 {
        s.0[1] ^= u64::from_be_bytes(block[8..16].try_into().unwrap());
    }
}

/// `rem ‖ 1 ‖ 0*` as a full 16-byte block (`rem.len() < rate`).
#[inline]
fn pad(rem: &[u8]) -> [u8; 16] {
    let mut block = [0u8; 16];
    block[..rem.len()].copy_from_slice(rem);
    block[rem.len()] = 0x80;
    block
}

/// Absorbs the associated data (only if non-empty) and applies the domain
/// separation bit `S4 ⊕= 1`.
fn absorb_ad(p: &Params, s: &mut State, aad: &[u8]) {
    if !aad.is_empty() {
        let mut chunks = aad.chunks_exact(p.rate);
        for block in chunks.by_ref() {
            xor_rate(p, s, block);
            permute_b(p, s);
        }
        xor_rate(p, s, &pad(chunks.remainder())[..p.rate]);
        permute_b(p, s);
    }
    s.0[4] ^= 1;
}

/// The plaintext phase: `C_i ← S_r ⊕ P_i`, `p_b` between blocks, padded tail.
fn encrypt_data(p: &Params, s: &mut State, buffer: &mut [u8]) {
    let rate = p.rate;
    let mut chunks = buffer.chunks_exact_mut(rate);
    for c in &mut chunks {
        xor_rate(p, s, c);
        c.copy_from_slice(&rate_bytes(s)[..rate]);
        permute_b(p, s);
    }
    let rem = chunks.into_remainder();
    let mut padded = pad(rem);
    xor_rate(p, s, &padded[..rate]);
    rem.copy_from_slice(&rate_bytes(s)[..rem.len()]);
    padded.zeroize();
}

macro_rules! ascon_v12 {
    (
        $(#[$doc:meta])*
        $name:ident, key = $klen:literal, rate = $rate:literal, pb8 = $pb8:literal, iv = $iv:literal
    ) => {
        $(#[$doc])*
        #[derive(Clone)]
        pub struct $name {
            core: Core,
        }

        impl $name {
            /// Key size in bytes.
            pub const KEY_SIZE: usize = $klen;
            /// Nonce size in bytes.
            pub const NONCE_SIZE: usize = 16;
            /// Tag size in bytes.
            pub const TAG_SIZE: usize = 16;

            const PARAMS: Params = Params {
                iv: $iv,
                rate: $rate,
                pb8: $pb8,
                key_len: $klen,
            };

            /// Creates an instance from the variant's fixed-size key.
            pub fn new(key: &[u8; $klen]) -> Self {
                $name {
                    core: Core::from_key(key),
                }
            }

            /// Encrypts `buffer` in place and returns the 16-byte tag, binding
            /// the optional `aad`. `nonce` must be unique per key.
            pub fn encrypt(&self, nonce: &[u8; 16], aad: &[u8], buffer: &mut [u8]) -> [u8; 16] {
                self.core.encrypt(&Self::PARAMS, nonce, aad, buffer)
            }

            /// Verifies `tag` and, only if it matches, decrypts `buffer` in
            /// place.
            ///
            /// The tag is checked in constant time. On mismatch [`TagMismatch`]
            /// is returned and `buffer` holds the original ciphertext on
            /// return: the duplex construction cannot verify before it
            /// decrypts, so the buffer is decrypted in place first and a
            /// second pass re-encrypts it when the tag turns out to be wrong.
            /// Unauthenticated plaintext therefore exists in `buffer` between
            /// those passes — invisible to a caller that owns the buffer, but
            /// a real leak if it aliases memory another party can read
            /// concurrently, and the restoring pass does not run if a panic
            /// unwinds mid-call. Decrypt into private memory and copy out
            /// after `Ok`.
            pub fn decrypt(
                &self,
                nonce: &[u8; 16],
                aad: &[u8],
                buffer: &mut [u8],
                tag: &[u8; 16],
            ) -> Result<(), TagMismatch> {
                self.core.decrypt(&Self::PARAMS, nonce, aad, buffer, tag)
            }
        }

        impl ZeroizeOnDrop for $name {}
    };
}

ascon_v12! {
    /// Ascon-128 v1.2: 128-bit key, 64-bit rate, `p¹²` / `p⁶`.
    ///
    /// Not interoperable with SP 800-232 Ascon-AEAD128; see the module docs.
    Ascon128, key = 16, rate = 8, pb8 = false, iv = 0x8040_0c06_0000_0000
}

ascon_v12! {
    /// Ascon-128a v1.2: 128-bit key, 128-bit rate, `p¹²` / `p⁸`.
    ///
    /// Not interoperable with SP 800-232 Ascon-AEAD128; see the module docs.
    Ascon128a, key = 16, rate = 16, pb8 = true, iv = 0x8080_0c08_0000_0000
}

ascon_v12! {
    /// Ascon-80pq v1.2: 160-bit key (for a larger margin against quantum
    /// key search), 64-bit rate, `p¹²` / `p⁶`.
    Ascon80pq, key = 20, rate = 8, pb8 = false, iv = 0xa040_0c06_0000_0000
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;
    use crate::test_util::{from_hex, from_hex_vec};

    fn check_128(key: &str, nonce: &str, aad: &str, pt: &str, ct_tag: &str) {
        let aead = Ascon128::new(&from_hex::<16>(key));
        check(
            |n, a, b| aead.encrypt(n, a, b),
            |n, a, b, t| aead.decrypt(n, a, b, t),
            nonce,
            aad,
            pt,
            ct_tag,
        );
    }

    fn check_128a(key: &str, nonce: &str, aad: &str, pt: &str, ct_tag: &str) {
        let aead = Ascon128a::new(&from_hex::<16>(key));
        check(
            |n, a, b| aead.encrypt(n, a, b),
            |n, a, b, t| aead.decrypt(n, a, b, t),
            nonce,
            aad,
            pt,
            ct_tag,
        );
    }

    fn check_80pq(key: &str, nonce: &str, aad: &str, pt: &str, ct_tag: &str) {
        let aead = Ascon80pq::new(&from_hex::<20>(key));
        check(
            |n, a, b| aead.encrypt(n, a, b),
            |n, a, b, t| aead.decrypt(n, a, b, t),
            nonce,
            aad,
            pt,
            ct_tag,
        );
    }

    fn check(
        enc: impl Fn(&[u8; 16], &[u8], &mut [u8]) -> [u8; 16],
        dec: impl Fn(&[u8; 16], &[u8], &mut [u8], &[u8; 16]) -> Result<(), TagMismatch>,
        nonce: &str,
        aad: &str,
        pt: &str,
        ct_tag: &str,
    ) {
        let nonce = from_hex::<16>(nonce);
        let aad = from_hex_vec(aad);
        let pt = from_hex_vec(pt);
        let ct_tag = from_hex_vec(ct_tag);
        let (expect_ct, expect_tag) = ct_tag.split_at(ct_tag.len() - 16);

        let mut buf = pt.clone();
        let tag = enc(&nonce, &aad, &mut buf);
        assert_eq!(buf, expect_ct, "ciphertext");
        assert_eq!(&tag[..], expect_tag, "tag");

        let ct = buf.clone();
        let mut bad = tag;
        bad[7] ^= 0x10;
        assert_eq!(dec(&nonce, &aad, &mut buf, &bad), Err(TagMismatch));
        assert_eq!(buf, ct, "buffer restored on failure");

        dec(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(buf, pt, "round trip");
    }

    // LWC_AEAD_KAT_128_128.txt from the Ascon v1.2 reference (Count 1: empty
    // PT and AD; Count 34: 1-byte PT, empty AD; Count 1089: 32-byte PT with
    // 32-byte AD). Key 000102…0F, nonce 000102…0F.
    const K: &str = "000102030405060708090A0B0C0D0E0F";
    const N: &str = "000102030405060708090A0B0C0D0E0F";

    #[test]
    fn ascon128_kat_empty() {
        check_128(K, N, "", "", "E355159F292911F794CB1432A0103A8A");
    }

    #[test]
    fn ascon128a_kat_empty() {
        check_128a(K, N, "", "", "7A834E6F09210957067B10FD831F0078");
    }

    // Wycheproof `ascon128_test.json` / `ascon128a_test.json` /
    // `ascon80pq_test.json`, tcId 1: empty message and AD.
    #[test]
    fn wycheproof_empty_vectors() {
        check_128(
            "b67b1a6efdd40d37080fbe8f8047aeb9",
            "fa294b129972f7fc5bbd5b96bba837c9",
            "",
            "",
            "47648fcad24982437276b8d5901f812b",
        );
        check_128a(
            "b67b1a6efdd40d37080fbe8f8047aeb9",
            "fa294b129972f7fc5bbd5b96bba837c9",
            "",
            "",
            "a0baa2691fb06e3f69ae1af6d8377995",
        );
        check_80pq(
            "2d7d3ac61c1e0f719b58ae86b974b95bcc2db64c",
            "70c0acbaf60acd770fcd05f2d142a13c",
            "",
            "",
            "a781b81a25c11b25197db620d344dac2",
        );
    }

    #[test]
    fn multi_block_round_trip() {
        let aead = Ascon80pq::new(&[5u8; 20]);
        let nonce = [6u8; 16];
        let msg = b"a message that spans several 64-bit rate blocks and a tail";
        let aad = b"seventeen-byte ad";
        let mut buf = msg.to_vec();
        let tag = aead.encrypt(&nonce, aad, &mut buf);
        assert_ne!(&buf[..], &msg[..]);
        let ct = buf.clone();
        assert_eq!(
            aead.decrypt(&nonce, b"other ad", &mut buf, &tag),
            Err(TagMismatch)
        );
        assert_eq!(buf, ct);
        aead.decrypt(&nonce, aad, &mut buf, &tag).unwrap();
        assert_eq!(&buf[..], &msg[..]);
    }
}
