//! TLS 1.0 / 1.1 CBC MAC-then-encrypt record protection (RFC 2246 / 4346 §6.2.3.2).
//!
//! Legacy CBC suites protect a record as
//! `CBC(content || MAC || padding)` where
//! `MAC = HMAC_h(mac_key, seq(8) || type(1) || version(2) || len(2) || content)`
//! and the padding is `pad_len+1` bytes each equal to `pad_len` (so the total is
//! a multiple of the cipher block size). TLS 1.1 prepends a fresh random
//! explicit IV per record; TLS 1.0 chains the IV from the previous record's last
//! ciphertext block.
//!
//! # Security
//!
//! These suites are deprecated (RFC 8996) and gated behind `tls-legacy`; they
//! exist only to talk to legacy devices. The decrypt path validates the CBC
//! padding in constant time, verifies the MAC with a constant-time comparison,
//! and returns a single uniform `BadRecordMac` for any failure (no early return,
//! no padding-vs-MAC distinction) — which defeats the classic Vaudenay / POODLE
//! padding oracle.
//!
//! It does **not** yet equalise the number of hash-compression blocks across
//! padding lengths, so the MAC *recomputation time* retains a small residual
//! dependence on the padding length (the Lucky13 signal). Exploiting it needs a
//! local, high-volume timing adversary against an already-deprecated cipher;
//! full block-count equalisation is tracked as a follow-up. Do not expose this
//! path to untrusted high-precision timing where it matters — prefer TLS 1.2+
//! AEAD, which this crate keeps fully constant-time.

// The suite-selection enums and the crypter are exercised by this module's
// tests now and wired into the legacy handshake in later phases; allow the
// transient dead code until then.
#![allow(dead_code)]

use crate::cipher::{Aes128, Aes256, BlockCipher, BlockCipher64, TdesEde3};
use crate::ct::ConstantTimeEq;
use crate::hash::{Hmac, Sha1, Sha256};
use crate::rng::RngCore;
use crate::tls::ContentType;
use crate::tls::Error;
use crate::tls::codec::CipherSuite;
use crate::tls::version::ProtocolVersion;
use alloc::vec;
use alloc::vec::Vec;

/// Key-exchange of a legacy CBC suite.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LegacyKx {
    /// Static RSA key transport (`TLS_RSA_WITH_*`): the client encrypts the
    /// premaster to the server's RSA cert key. No forward secrecy.
    Rsa,
    /// Ephemeral ECDHE with an RSA-signed ServerKeyExchange (`TLS_ECDHE_RSA_*`).
    EcdheRsa,
}

/// A legacy CBC cipher suite: its wire code and the cipher/MAC/kx it selects.
#[derive(Clone, Copy)]
pub(crate) struct LegacyCbcSuite {
    pub(crate) suite: CipherSuite,
    pub(crate) cipher: CbcCipherAlg,
    pub(crate) mac: CbcMacAlg,
    pub(crate) kx: LegacyKx,
}

/// The legacy CBC suites we support, strongest-first within each kx family.
/// ECDHE-RSA (forward-secret) is preferred over static RSA; AES over 3DES;
/// AES-256 over AES-128 (legacy peers rarely prefer 256 but offer it anyway).
pub(crate) const LEGACY_CBC_SUITES: [LegacyCbcSuite; 10] = [
    LegacyCbcSuite {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA256,
        cipher: CbcCipherAlg::Aes256,
        mac: CbcMacAlg::Sha256,
        kx: LegacyKx::EcdheRsa,
    },
    LegacyCbcSuite {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
        cipher: CbcCipherAlg::Aes128,
        mac: CbcMacAlg::Sha256,
        kx: LegacyKx::EcdheRsa,
    },
    LegacyCbcSuite {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
        cipher: CbcCipherAlg::Aes256,
        mac: CbcMacAlg::Sha1,
        kx: LegacyKx::EcdheRsa,
    },
    LegacyCbcSuite {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
        cipher: CbcCipherAlg::Aes128,
        mac: CbcMacAlg::Sha1,
        kx: LegacyKx::EcdheRsa,
    },
    LegacyCbcSuite {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
        cipher: CbcCipherAlg::Tdes,
        mac: CbcMacAlg::Sha1,
        kx: LegacyKx::EcdheRsa,
    },
    LegacyCbcSuite {
        suite: CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA256,
        cipher: CbcCipherAlg::Aes256,
        mac: CbcMacAlg::Sha256,
        kx: LegacyKx::Rsa,
    },
    LegacyCbcSuite {
        suite: CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA256,
        cipher: CbcCipherAlg::Aes128,
        mac: CbcMacAlg::Sha256,
        kx: LegacyKx::Rsa,
    },
    LegacyCbcSuite {
        suite: CipherSuite::TLS_RSA_WITH_AES_256_CBC_SHA,
        cipher: CbcCipherAlg::Aes256,
        mac: CbcMacAlg::Sha1,
        kx: LegacyKx::Rsa,
    },
    LegacyCbcSuite {
        suite: CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA,
        cipher: CbcCipherAlg::Aes128,
        mac: CbcMacAlg::Sha1,
        kx: LegacyKx::Rsa,
    },
    LegacyCbcSuite {
        suite: CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA,
        cipher: CbcCipherAlg::Tdes,
        mac: CbcMacAlg::Sha1,
        kx: LegacyKx::Rsa,
    },
];

/// Looks up a legacy CBC suite by its wire code.
pub(crate) fn lookup_legacy_cbc(s: CipherSuite) -> Option<LegacyCbcSuite> {
    LEGACY_CBC_SUITES.iter().copied().find(|p| p.suite == s)
}

/// One direction's CBC key material, sliced from the `key_block`.
pub(crate) struct CbcKeyMaterial {
    pub(crate) client_mac: Vec<u8>,
    pub(crate) server_mac: Vec<u8>,
    pub(crate) client_key: Vec<u8>,
    pub(crate) server_key: Vec<u8>,
    /// `fixed_iv` per direction — non-empty only for TLS 1.0 (`explicit_iv`
    /// false); TLS 1.1+ uses a fresh per-record explicit IV instead.
    pub(crate) client_iv: Vec<u8>,
    pub(crate) server_iv: Vec<u8>,
}

/// `key_block` length for a CBC suite (RFC 5246 §6.3):
/// `2·mac_key + 2·enc_key + 2·fixed_iv`, where `fixed_iv = block_size` for
/// TLS 1.0 and `0` for TLS 1.1+ (explicit per-record IV).
pub(crate) fn cbc_key_block_len(cipher: CbcCipherAlg, mac: CbcMacAlg, explicit_iv: bool) -> usize {
    let fixed_iv = if explicit_iv { 0 } else { cipher.block_size() };
    2 * mac.key_len() + 2 * cipher.key_len() + 2 * fixed_iv
}

/// Slices a derived `key_block` into the per-direction CBC key material in the
/// RFC 5246 §6.3 order: client/server MAC keys, client/server enc keys, then
/// (TLS 1.0 only) client/server fixed IVs.
pub(crate) fn split_cbc_key_block(
    kb: &[u8],
    cipher: CbcCipherAlg,
    mac: CbcMacAlg,
    explicit_iv: bool,
) -> CbcKeyMaterial {
    let mk = mac.key_len();
    let ek = cipher.key_len();
    let iv = if explicit_iv { 0 } else { cipher.block_size() };
    let mut o = 0;
    let mut take = |n: usize| {
        let s = kb[o..o + n].to_vec();
        o += n;
        s
    };
    CbcKeyMaterial {
        client_mac: take(mk),
        server_mac: take(mk),
        client_key: take(ek),
        server_key: take(ek),
        client_iv: take(iv),
        server_iv: take(iv),
    }
}

/// The two directional CBC record crypters for a legacy connection.
pub(crate) struct LegacyCrypters {
    /// Protects/parses records the client sends.
    pub(crate) client: CbcRecordCrypter,
    /// Protects/parses records the server sends.
    pub(crate) server: CbcRecordCrypter,
}

/// Derives the legacy `key_block` and builds both directions' CBC record
/// crypters. `version` selects the IV regime (TLS 1.1+ explicit per-record IV
/// vs TLS 1.0 chained). Used by both the client and server legacy handshakes so
/// the key-block layout is computed in exactly one place.
///
/// The TLS 1.1 explicit-IV CSPRNG seeds come from 64 extra bytes of `key_block`
/// PRF stream past the keys/MACs — secret, unique per connection, and unused by
/// the spec, so safe to repurpose as private DRBG seeds (they never appear on
/// the wire). For TLS 1.0 the seeds are unused (the IV is chained).
pub(crate) fn build_legacy_crypters(
    ls: LegacyCbcSuite,
    version: ProtocolVersion,
    master: &[u8; 48],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> LegacyCrypters {
    let explicit_iv = version.as_u16() >= ProtocolVersion::TLSv1_1.as_u16();
    let kb_len = cbc_key_block_len(ls.cipher, ls.mac, explicit_iv);
    let mut kb = vec![0u8; kb_len + 64];
    crate::tls::crypto::prf::key_block_legacy(master, server_random, client_random, &mut kb);
    let km = split_cbc_key_block(&kb[..kb_len], ls.cipher, ls.mac, explicit_iv);
    let client_iv_seed = &kb[kb_len..kb_len + 32];
    let server_iv_seed = &kb[kb_len + 32..kb_len + 64];
    let client = CbcRecordCrypter::new(
        ls.cipher,
        &km.client_key,
        ls.mac,
        &km.client_mac,
        explicit_iv,
        &km.client_iv,
        client_iv_seed,
    );
    let server = CbcRecordCrypter::new(
        ls.cipher,
        &km.server_key,
        ls.mac,
        &km.server_mac,
        explicit_iv,
        &km.server_iv,
        server_iv_seed,
    );
    LegacyCrypters { client, server }
}

/// CBC block cipher selection for a legacy suite.
#[derive(Clone, Copy)]
pub(crate) enum CbcCipherAlg {
    Aes128,
    Aes256,
    Tdes,
}

impl CbcCipherAlg {
    pub(crate) fn block_size(self) -> usize {
        match self {
            CbcCipherAlg::Aes128 | CbcCipherAlg::Aes256 => 16,
            CbcCipherAlg::Tdes => 8,
        }
    }
    pub(crate) fn key_len(self) -> usize {
        match self {
            CbcCipherAlg::Aes128 => 16,
            CbcCipherAlg::Aes256 => 32,
            CbcCipherAlg::Tdes => 24,
        }
    }
}

/// HMAC hash for a legacy CBC suite.
#[derive(Clone, Copy)]
pub(crate) enum CbcMacAlg {
    Sha1,
    Sha256,
}

impl CbcMacAlg {
    pub(crate) fn mac_len(self) -> usize {
        match self {
            CbcMacAlg::Sha1 => 20,
            CbcMacAlg::Sha256 => 32,
        }
    }
    /// HMAC key length equals the digest length for the standard CBC suites.
    pub(crate) fn key_len(self) -> usize {
        self.mac_len()
    }
}

/// The keyed block cipher backing a CBC record crypter.
enum Cipher {
    Aes128(Aes128),
    Aes256(Aes256),
    Tdes(TdesEde3),
}

impl Cipher {
    fn cbc_encrypt(&self, iv: &[u8], buf: &mut [u8]) {
        match self {
            Cipher::Aes128(c) => cbc_encrypt16(c, iv, buf),
            Cipher::Aes256(c) => cbc_encrypt16(c, iv, buf),
            Cipher::Tdes(c) => cbc_encrypt8(c, iv, buf),
        }
    }
    fn cbc_decrypt(&self, iv: &[u8], buf: &mut [u8]) {
        match self {
            Cipher::Aes128(c) => cbc_decrypt16(c, iv, buf),
            Cipher::Aes256(c) => cbc_decrypt16(c, iv, buf),
            Cipher::Tdes(c) => cbc_decrypt8(c, iv, buf),
        }
    }
}

fn cbc_encrypt16<C: BlockCipher>(c: &C, iv: &[u8], buf: &mut [u8]) {
    let mut chain = [0u8; 16];
    chain.copy_from_slice(iv);
    for blk in buf.chunks_exact_mut(16) {
        for (b, ch) in blk.iter_mut().zip(chain.iter()) {
            *b ^= *ch;
        }
        let b: &mut [u8; 16] = blk.try_into().unwrap();
        c.encrypt_block(b);
        chain.copy_from_slice(blk);
    }
}

fn cbc_decrypt16<C: BlockCipher>(c: &C, iv: &[u8], buf: &mut [u8]) {
    let mut chain = [0u8; 16];
    chain.copy_from_slice(iv);
    for blk in buf.chunks_exact_mut(16) {
        let saved = <[u8; 16]>::try_from(&blk[..]).unwrap();
        let b: &mut [u8; 16] = blk.try_into().unwrap();
        c.decrypt_block(b);
        for (b, ch) in blk.iter_mut().zip(chain.iter()) {
            *b ^= *ch;
        }
        chain = saved;
    }
}

fn cbc_encrypt8<C: BlockCipher64>(c: &C, iv: &[u8], buf: &mut [u8]) {
    let mut chain = [0u8; 8];
    chain.copy_from_slice(iv);
    for blk in buf.chunks_exact_mut(8) {
        for (b, ch) in blk.iter_mut().zip(chain.iter()) {
            *b ^= *ch;
        }
        let b: &mut [u8; 8] = blk.try_into().unwrap();
        c.encrypt_block(b);
        chain.copy_from_slice(blk);
    }
}

fn cbc_decrypt8<C: BlockCipher64>(c: &C, iv: &[u8], buf: &mut [u8]) {
    let mut chain = [0u8; 8];
    chain.copy_from_slice(iv);
    for blk in buf.chunks_exact_mut(8) {
        let saved = <[u8; 8]>::try_from(&blk[..]).unwrap();
        let b: &mut [u8; 8] = blk.try_into().unwrap();
        c.decrypt_block(b);
        for (b, ch) in blk.iter_mut().zip(chain.iter()) {
            *b ^= *ch;
        }
        chain = saved;
    }
}

// ---- small constant-time helpers over public-but-secret-derived lengths ----

/// `0xff` if `a == b`, else `0x00` (constant-time).
#[inline]
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let d = a ^ b;
    // d == 0  →  0xff ; d != 0  →  0x00
    let z = (d as i32 - 1) >> 8; // 0xffffff.. iff d==0 (for d in 0..=255)
    z as u8
}

/// `0xff` if `a <= b`, else `0x00` (constant-time; inputs are small lengths).
#[inline]
fn ct_le(a: usize, b: usize) -> u8 {
    let r = (b as i64).wrapping_sub(a as i64); // >= 0 iff a <= b
    !((r >> 63) as u8) // r>=0 → !0x00=0xff ; r<0 → !0xff=0x00
}

/// One direction's TLS 1.0/1.1 CBC record protection (MAC-then-encrypt).
pub(crate) struct CbcRecordCrypter {
    cipher: Cipher,
    mac_key: Vec<u8>,
    mac: CbcMacAlg,
    block_size: usize,
    /// TLS 1.1+ prepends a fresh random explicit IV; TLS 1.0 chains.
    explicit_iv: bool,
    /// Running chaining value for TLS 1.0 (the previous record's last ciphertext
    /// block); unused when `explicit_iv` is set.
    chain: Vec<u8>,
    /// CSPRNG for the TLS 1.1 per-record explicit IV, seeded once at
    /// construction from the connection RNG so record emission needs no RNG
    /// threading. Unused (but kept) for the TLS 1.0 chained path.
    iv_rng: crate::rng::HmacDrbg<crate::hash::Sha256>,
    seq: u64,
}

impl CbcRecordCrypter {
    /// Builds a record crypter for one direction. `enc_key`/`mac_key` come from
    /// the CBC `key_block`; `initial_iv` is that direction's `key_block` IV and
    /// is used only for TLS 1.0 (the `explicit_iv = false` case). `iv_seed` seeds
    /// the per-record explicit-IV CSPRNG for TLS 1.1; the caller supplies fresh
    /// randomness from the connection RNG.
    #[allow(dead_code)] // wired into the legacy handshake in a later phase
    pub(crate) fn new(
        cipher_alg: CbcCipherAlg,
        enc_key: &[u8],
        mac_alg: CbcMacAlg,
        mac_key: &[u8],
        explicit_iv: bool,
        initial_iv: &[u8],
        iv_seed: &[u8],
    ) -> Self {
        let cipher = match cipher_alg {
            CbcCipherAlg::Aes128 => {
                Cipher::Aes128(Aes128::new(enc_key.try_into().expect("aes128 key")))
            }
            CbcCipherAlg::Aes256 => {
                Cipher::Aes256(Aes256::new(enc_key.try_into().expect("aes256 key")))
            }
            CbcCipherAlg::Tdes => {
                Cipher::Tdes(TdesEde3::new(enc_key.try_into().expect("3des key")))
            }
        };
        CbcRecordCrypter {
            cipher,
            mac_key: mac_key.to_vec(),
            mac: mac_alg,
            block_size: cipher_alg.block_size(),
            explicit_iv,
            chain: initial_iv.to_vec(),
            iv_rng: crate::rng::HmacDrbg::new(iv_seed, b"tls-cbc-explicit-iv", &[]),
            seq: 0,
        }
    }

    /// HMAC over `seq || type || version || len(content) || content`.
    fn compute_mac(&self, ct: ContentType, version: ProtocolVersion, content: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 13];
        header[..8].copy_from_slice(&self.seq.to_be_bytes());
        header[8] = ct.as_u8();
        header[9..11].copy_from_slice(&version.as_u16().to_be_bytes());
        header[11..13].copy_from_slice(&(content.len() as u16).to_be_bytes());
        match self.mac {
            CbcMacAlg::Sha1 => Hmac::<Sha1>::new(&self.mac_key)
                .chain(&header)
                .chain(content)
                .finalize()
                .as_ref()
                .to_vec(),
            CbcMacAlg::Sha256 => Hmac::<Sha256>::new(&self.mac_key)
                .chain(&header)
                .chain(content)
                .finalize()
                .as_ref()
                .to_vec(),
        }
    }

    /// Encrypts one record's `plaintext`, returning the record fragment
    /// (`explicit_iv || ciphertext` for TLS 1.1, `ciphertext` for TLS 1.0).
    #[allow(dead_code)]
    pub(crate) fn encrypt(
        &mut self,
        ct: ContentType,
        version: ProtocolVersion,
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mac = self.compute_mac(ct, version, plaintext);
        let mut buf = Vec::with_capacity(plaintext.len() + mac.len() + self.block_size);
        buf.extend_from_slice(plaintext);
        buf.extend_from_slice(&mac);
        // TLS padding: append `pad_total` bytes each equal to `pad_total - 1`.
        let pad_total = self.block_size - (buf.len() % self.block_size);
        let pad_val = (pad_total - 1) as u8;
        buf.resize(buf.len() + pad_total, pad_val);

        let out = if self.explicit_iv {
            let mut iv = vec![0u8; self.block_size];
            self.iv_rng.fill_bytes(&mut iv);
            self.cipher.cbc_encrypt(&iv, &mut buf);
            let mut out = iv;
            out.extend_from_slice(&buf);
            out
        } else {
            let iv = core::mem::take(&mut self.chain);
            self.cipher.cbc_encrypt(&iv, &mut buf);
            self.chain = buf[buf.len() - self.block_size..].to_vec();
            buf
        };
        self.seq = self.seq.wrapping_add(1);
        out
    }

    /// Verifies and decrypts one record fragment, returning the plaintext
    /// content. Any padding or MAC failure yields a single uniform
    /// [`Error::BadRecordMac`]; see the module-level security note.
    #[allow(dead_code)]
    pub(crate) fn decrypt(
        &mut self,
        ct: ContentType,
        version: ProtocolVersion,
        fragment: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let bs = self.block_size;
        let mac_len = self.mac.mac_len();

        // Split off the explicit IV (TLS 1.1) or use the running chain (TLS 1.0).
        let (iv, ciphertext): (Vec<u8>, &[u8]) = if self.explicit_iv {
            if fragment.len() < bs {
                return Err(Error::BadRecordMac);
            }
            (fragment[..bs].to_vec(), &fragment[bs..])
        } else {
            (self.chain.clone(), fragment)
        };

        // The ciphertext must be a non-empty whole number of blocks, with room
        // for at least one MAC plus the mandatory padding-length byte. These are
        // public-length checks (independent of plaintext), so an early return is
        // safe here.
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(bs) {
            return Err(Error::BadRecordMac);
        }
        let total = ciphertext.len();
        if total < mac_len + 1 {
            return Err(Error::BadRecordMac);
        }

        // For TLS 1.0, the next IV is this record's last ciphertext block.
        let next_chain = ciphertext[total - bs..].to_vec();
        let mut buf = ciphertext.to_vec();
        self.cipher.cbc_decrypt(&iv, &mut buf);
        if !self.explicit_iv {
            self.chain = next_chain;
        }

        // ---- constant-time padding validation ----
        let pad_len = buf[total - 1] as usize;
        // Enough room for content(>=0) + MAC + (pad_len + 1) padding bytes.
        let mut good = ct_le(mac_len + pad_len + 1, total);
        // Every one of the trailing `pad_len + 1` bytes must equal `pad_len`.
        // Scan a fixed window (max TLS padding is 255 bytes) bounded by `total`.
        let window = core::cmp::min(256, total);
        for i in 0..window {
            let byte = buf[total - 1 - i];
            let in_pad = ct_le(i, pad_len); // 0xff if this byte is in the padding
            let is_val = ct_eq_u8(byte, pad_len as u8);
            // if in_pad then require is_val:  good &= (is_val | !in_pad)
            good &= is_val | !in_pad;
        }

        // content_len = total - mac_len - pad_len - 1 when the padding is valid,
        // else 0 (chosen with a constant-time mask). When `good`, the value is in
        // range [0, total - mac_len]; when not, the mask forces 0 (also in range,
        // since total >= mac_len + 1 was checked above).
        let cand = total
            .wrapping_sub(mac_len)
            .wrapping_sub(pad_len)
            .wrapping_sub(1);
        let mask = 0usize.wrapping_sub((good & 1) as usize);
        let content_len = cand & mask;

        let received_mac = &buf[content_len..content_len + mac_len];
        let computed_mac = self.compute_mac(ct, version, &buf[..content_len]);
        let mac_ok = computed_mac.as_slice().ct_eq(received_mac);

        self.seq = self.seq.wrapping_add(1);

        if good == 0xff && bool::from(mac_ok) {
            Ok(buf[..content_len].to_vec())
        } else {
            Err(Error::BadRecordMac)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::version::ProtocolVersion;

    fn pair(
        cipher: CbcCipherAlg,
        mac: CbcMacAlg,
        explicit_iv: bool,
    ) -> (CbcRecordCrypter, CbcRecordCrypter) {
        let enc = vec![0x11u8; cipher.key_len()];
        let mk = vec![0x22u8; mac.key_len()];
        let iv = vec![0x33u8; cipher.block_size()];
        (
            CbcRecordCrypter::new(cipher, &enc, mac, &mk, explicit_iv, &iv, b"iv-seed-a"),
            CbcRecordCrypter::new(cipher, &enc, mac, &mk, explicit_iv, &iv, b"iv-seed-b"),
        )
    }

    #[test]
    fn roundtrip_all_variants() {
        for &cipher in &[
            CbcCipherAlg::Aes128,
            CbcCipherAlg::Aes256,
            CbcCipherAlg::Tdes,
        ] {
            for &mac in &[CbcMacAlg::Sha1, CbcMacAlg::Sha256] {
                for &explicit in &[true, false] {
                    let (mut enc, mut dec) = pair(cipher, mac, explicit);
                    // Several records of varying length to exercise padding and
                    // (for TLS 1.0) the IV chaining across records.
                    for len in [0usize, 1, 15, 16, 17, 31, 200] {
                        let pt: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(7)).collect();
                        let rec = enc.encrypt(
                            ContentType::ApplicationData,
                            ProtocolVersion::TLSv1_1,
                            &pt,
                        );
                        let got = dec
                            .decrypt(ContentType::ApplicationData, ProtocolVersion::TLSv1_1, &rec)
                            .expect("decrypt ok");
                        assert_eq!(got, pt, "cipher/mac/explicit roundtrip len={len}");
                    }
                }
            }
        }
    }

    #[test]
    fn tampering_yields_bad_record_mac() {
        let (mut enc, mut dec) = pair(CbcCipherAlg::Aes128, CbcMacAlg::Sha1, true);
        let pt = b"provisioning config payload";
        let rec = enc.encrypt(ContentType::ApplicationData, ProtocolVersion::TLSv1_1, pt);

        // Flip a ciphertext byte → corrupts plaintext/MAC/padding → BadRecordMac.
        let mut bad = rec.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(matches!(
            dec.decrypt(ContentType::ApplicationData, ProtocolVersion::TLSv1_1, &bad),
            Err(Error::BadRecordMac)
        ));

        // A truncated record (not a whole number of blocks) is rejected.
        assert!(matches!(
            dec.decrypt(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_1,
                &rec[..rec.len() - 1]
            ),
            Err(Error::BadRecordMac)
        ));
    }

    #[test]
    fn legacy_suite_lookup() {
        let s = lookup_legacy_cbc(CipherSuite::TLS_RSA_WITH_AES_128_CBC_SHA).unwrap();
        assert!(matches!(s.cipher, CbcCipherAlg::Aes128));
        assert!(matches!(s.mac, CbcMacAlg::Sha1));
        assert!(matches!(s.kx, LegacyKx::Rsa));

        let s = lookup_legacy_cbc(CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA256).unwrap();
        assert!(matches!(s.cipher, CbcCipherAlg::Aes256));
        assert!(matches!(s.mac, CbcMacAlg::Sha256));
        assert!(matches!(s.kx, LegacyKx::EcdheRsa));

        let s = lookup_legacy_cbc(CipherSuite::TLS_RSA_WITH_3DES_EDE_CBC_SHA).unwrap();
        assert!(matches!(s.cipher, CbcCipherAlg::Tdes));

        assert!(lookup_legacy_cbc(CipherSuite::AES_128_GCM_SHA256).is_none());
    }

    #[test]
    fn cbc_key_block_layout() {
        // AES-128 + HMAC-SHA1, TLS 1.1 (explicit IV → no fixed IVs):
        //   2*20 (mac) + 2*16 (key) = 72 bytes.
        let len = cbc_key_block_len(CbcCipherAlg::Aes128, CbcMacAlg::Sha1, true);
        assert_eq!(len, 72);
        let kb: Vec<u8> = (0..len as u8).collect();
        let km = split_cbc_key_block(&kb, CbcCipherAlg::Aes128, CbcMacAlg::Sha1, true);
        assert_eq!(km.client_mac, &kb[0..20]);
        assert_eq!(km.server_mac, &kb[20..40]);
        assert_eq!(km.client_key, &kb[40..56]);
        assert_eq!(km.server_key, &kb[56..72]);
        assert!(km.client_iv.is_empty() && km.server_iv.is_empty());

        // AES-256 + HMAC-SHA1, TLS 1.0 (chained → 16-byte fixed IVs each):
        //   2*20 + 2*32 + 2*16 = 136 bytes.
        let len = cbc_key_block_len(CbcCipherAlg::Aes256, CbcMacAlg::Sha1, false);
        assert_eq!(len, 136);
        let kb: Vec<u8> = (0..len as u8).collect();
        let km = split_cbc_key_block(&kb, CbcCipherAlg::Aes256, CbcMacAlg::Sha1, false);
        assert_eq!(km.client_mac.len(), 20);
        assert_eq!(km.client_key.len(), 32);
        assert_eq!(km.client_iv, &kb[104..120]);
        assert_eq!(km.server_iv, &kb[120..136]);
    }

    /// The MAC input construction matches an independent Python `hmac` reference
    /// (HMAC-SHA1 over `seq || type || version || len || content`). This pins the
    /// byte layout that interop depends on.
    #[test]
    fn mac_input_known_answer() {
        let mk = vec![0x22u8; 20];
        let c = CbcRecordCrypter::new(
            CbcCipherAlg::Aes128,
            &[0u8; 16],
            CbcMacAlg::Sha1,
            &mk,
            true,
            &[0u8; 16],
            b"seed",
        );
        // seq=0, type=23 (application_data), version=0x0301 (TLS 1.0), content="hi"
        let mac = c.compute_mac(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_0,
            b"hi",
        );
        let expected = [
            0xa2, 0xf1, 0xca, 0x0b, 0x8e, 0xce, 0x38, 0x5e, 0x27, 0x0b, 0x9b, 0xab, 0x0e, 0x55,
            0x38, 0x2c, 0xda, 0x40, 0x81, 0xc1,
        ];
        assert_eq!(mac, expected);
    }
}
