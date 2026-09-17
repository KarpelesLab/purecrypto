//! C2SP chunked encryption, "Cobblestone"
//! (<https://c2sp.org/chunked-encryption>).
//!
//! Cobblestone encrypts a *message* of up to 4 PiB as a sequence of 16 KiB
//! chunks, each sealed with an AEAD under a per-message key, so that the
//! ciphertext can be produced and consumed in a streaming fashion and every
//! chunk is authenticated before any of its plaintext is released. The design
//! is the TLS 1.3 record layer plus an HKDF-Expand key-derivation step that
//! also yields a key *commitment*.
//!
//! Two instantiations are defined, both with HKDF-Expand over SHA-512:
//!
//! * [`Cobblestone128`] — `AEAD_AES_128_GCM`, 16-byte input key (recommended);
//! * [`Cobblestone256`] — `AEAD_AES_256_GCM`, 32-byte input key.
//!
//! # Format
//!
//! ```text
//! ciphertext = salt (24) || commitment (32) || chunk_0 || chunk_1 || ... || chunk_n
//! chunk_k    = AES-GCM(key, base_nonce XOR k, aad = "", plaintext_k) || tag (16)
//! ```
//!
//! `key || base_nonce || commitment` is `HKDF-Expand(prk = input key,
//! info = "c2sp.org/chunked-encryption@v1+" || aead || 0x00 || salt || ctx)`.
//! The message is split into 16 KiB chunks and the final chunk is always
//! *shorter* than 16 KiB (possibly empty), which is how the end of the message
//! is authenticated: a ciphertext whose last chunk is full is truncated. The
//! nonce of chunk `k` is the base nonce XORed with `k` as a big-endian integer;
//! a message has at most 2³⁸ chunks.
//!
//! # API
//!
//! * [`encrypt`] / [`decrypt`] — one-shot;
//! * [`Encryptor`] / [`Decryptor`] — streaming, with 16 KiB of buffering; a
//!   [`Decryptor`] never releases plaintext of a chunk that did not
//!   authenticate and, once it has failed, keeps failing;
//! * [`RawCipher`] — the per-chunk primitive under the header, exposed for
//!   the spec's *raw mode* (appendix) and for random access: given the derived
//!   key and base nonce, [`RawCipher::open_chunk`] decrypts any chunk by index
//!   (chunk `k` starts at ciphertext offset `56 + k * 16400`, see
//!   [`chunk_offset`]). This is a hazmat primitive; the header-mode API above
//!   is what applications should use.
//!
//! ```
//! use purecrypto::chunked::{Cobblestone128, decrypt, encrypt};
//! use purecrypto::rng::OsRng;
//!
//! let key = [0x42u8; 16];
//! let ct = encrypt::<Cobblestone128>(&key, b"app context", b"hello", &mut OsRng).unwrap();
//! assert_eq!(ct.len(), 56 + 5 + 16);
//! assert_eq!(decrypt::<Cobblestone128>(&key, b"app context", &ct).unwrap(), b"hello");
//! assert!(decrypt::<Cobblestone128>(&key, b"other context", &ct).is_err());
//! ```

use alloc::vec::Vec;

use crate::cipher::{Aes128, Aes256, BlockCipher, Gcm};
use crate::ct::ConstantTimeEq;
use crate::hash::{Digest, Hmac, Sha512};
use crate::rng::CryptoRngCore;
use crate::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Plaintext bytes per chunk (all chunks but the last are exactly this long).
pub const CHUNK_SIZE: usize = 16384;
/// AEAD tag length (AES-GCM).
pub const TAG_LEN: usize = 16;
/// AEAD nonce length (AES-GCM).
pub const NONCE_LEN: usize = 12;
/// Length of an encrypted full chunk: [`CHUNK_SIZE`] + [`TAG_LEN`].
pub const ENCRYPTED_CHUNK_LEN: usize = CHUNK_SIZE + TAG_LEN;
/// Salt length; the salt is the first 24 bytes of the ciphertext.
pub const SALT_LEN: usize = 24;
/// Commitment length; the commitment follows the salt.
pub const COMMITMENT_LEN: usize = 32;
/// Header length: salt plus commitment.
pub const HEADER_LEN: usize = SALT_LEN + COMMITMENT_LEN;
/// Maximum number of chunks per message (2³⁸); the counter is XORed into
/// the low 38 bits of the base nonce.
pub const MAX_CHUNKS: u64 = 1 << 38;

/// Fixed prefix of the HKDF-Expand `info` string.
const INFO_PREFIX: &[u8] = b"c2sp.org/chunked-encryption@v1+";

/// Errors of the chunked-encryption layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input key is not the instantiation's key length (16 bytes for
    /// [`Cobblestone128`], 32 for [`Cobblestone256`]).
    InvalidKeyLength,
    /// The ciphertext ends early: the header is incomplete, or the last chunk
    /// is missing (a full 16 KiB chunk in final position, or a final chunk
    /// shorter than a tag).
    Truncated,
    /// The commitment in the header does not match the one derived from the
    /// input key, salt and context: wrong key, wrong context, or a corrupted
    /// header.
    CommitmentMismatch,
    /// A chunk failed authentication (corrupted, reordered, or misplaced).
    TagMismatch,
    /// The message would need more than [`MAX_CHUNKS`] chunks.
    TooManyChunks,
    /// More ciphertext was pushed after the final chunk was decrypted.
    TrailingData,
    /// A chunk handed to [`RawCipher`] is longer than the format allows
    /// (a plaintext chunk over [`CHUNK_SIZE`], or an encrypted chunk over
    /// [`ENCRYPTED_CHUNK_LEN`]).
    InvalidChunkLength,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InvalidKeyLength => "chunked: invalid input key length",
            Error::Truncated => "chunked: ciphertext truncated",
            Error::CommitmentMismatch => "chunked: key commitment mismatch",
            Error::TagMismatch => "chunked: chunk authentication failed",
            Error::TooManyChunks => "chunked: message exceeds 2^38 chunks",
            Error::TrailingData => "chunked: data after the final chunk",
            Error::InvalidChunkLength => "chunked: chunk longer than the format allows",
        })
    }
}

impl core::error::Error for Error {}

mod sealed {
    pub trait Sealed {}
}

/// A Cobblestone instantiation: the AEAD (and therefore the input key length)
/// and its IANA registry name, which is bound into the key derivation.
///
/// Implemented by [`Cobblestone128`] and [`Cobblestone256`]; the trait is
/// sealed because the spec only defines these two.
pub trait Instantiation: sealed::Sealed {
    /// Input key (and AEAD key) length in bytes.
    const KEY_LEN: usize;
    /// The AEAD's name in the IANA AEAD Algorithms registry.
    const AEAD_NAME: &'static str;
    /// The block cipher under GCM.
    type Cipher: BlockCipher;
    /// Keys the block cipher; `key` is exactly [`KEY_LEN`](Self::KEY_LEN)
    /// bytes (callers have validated the length).
    fn cipher(key: &[u8]) -> Self::Cipher;
}

/// Cobblestone-128: SHA-512 and `AEAD_AES_128_GCM` with a 16-byte input key.
/// The spec's recommended instantiation.
#[derive(Debug, Clone, Copy)]
pub struct Cobblestone128;

/// Cobblestone-256: SHA-512 and `AEAD_AES_256_GCM` with a 32-byte input key.
#[derive(Debug, Clone, Copy)]
pub struct Cobblestone256;

impl sealed::Sealed for Cobblestone128 {}
impl sealed::Sealed for Cobblestone256 {}

impl Instantiation for Cobblestone128 {
    const KEY_LEN: usize = 16;
    const AEAD_NAME: &'static str = "AEAD_AES_128_GCM";
    type Cipher = Aes128;
    fn cipher(key: &[u8]) -> Aes128 {
        Aes128::new(key.try_into().expect("Cobblestone-128 key is 16 bytes"))
    }
}

impl Instantiation for Cobblestone256 {
    const KEY_LEN: usize = 32;
    const AEAD_NAME: &'static str = "AEAD_AES_256_GCM";
    type Cipher = Aes256;
    fn cipher(key: &[u8]) -> Aes256 {
        Aes256::new(key.try_into().expect("Cobblestone-256 key is 32 bytes"))
    }
}

/// Ciphertext offset of chunk `index` in header mode: `56 + index * 16400`.
/// Subtract [`HEADER_LEN`] for raw mode.
pub const fn chunk_offset(index: u64) -> u64 {
    HEADER_LEN as u64 + index * ENCRYPTED_CHUNK_LEN as u64
}

/// HKDF-Expand with HMAC-SHA-512 (RFC 5869 §2.3) over a PRK of any length.
///
/// The crate's `kdf::hkdf_expand` types the PRK as a full hash output; here
/// the PRK is the 16- or 32-byte input key, so the (two-block) feedback loop
/// is spelled out.
fn hkdf_expand_sha512(prk: &[u8], info: &[&[u8]], out: &mut [u8]) {
    debug_assert!(out.len() <= 255 * Sha512::OUTPUT_LEN);
    let prf = Hmac::<Sha512>::new(prk);
    let mut prev = Zeroizing::new([0u8; 64]);
    let mut counter = 0u8;
    let mut filled = 0;
    while filled < out.len() {
        counter += 1;
        let mut mac = prf.clone();
        if counter > 1 {
            mac.update(prev.as_ref());
        }
        for part in info {
            mac.update(part);
        }
        mac.update(&[counter]);
        *prev = mac.finalize();
        let take = (out.len() - filled).min(prev.len());
        out[filled..filled + take].copy_from_slice(&prev[..take]);
        filled += take;
    }
}

/// The per-chunk AEAD layer: the derived (or, in raw mode, externally
/// supplied) AEAD key and base nonce.
///
/// This is the spec's *raw mode* (appendix): no salt or commitment is
/// involved, and the caller is responsible for the key and base nonce being
/// uniformly random and never reused. Applications should use [`encrypt`],
/// [`decrypt`], [`Encryptor`] and [`Decryptor`] instead, which derive these
/// from an input key and prepend the header; `RawCipher` is what they run on,
/// and is exposed for protocols with their own key schedule and for random
/// access via [`open_chunk`](Self::open_chunk).
pub struct RawCipher<I: Instantiation> {
    aead: Gcm<I::Cipher>,
    base_nonce: [u8; NONCE_LEN],
}

impl<I: Instantiation> RawCipher<I> {
    /// Raw mode: wraps an AEAD `key` (exactly [`Instantiation::KEY_LEN`]
    /// bytes) and `base_nonce` supplied by a higher-level key schedule.
    pub fn new(key: &[u8], base_nonce: &[u8; NONCE_LEN]) -> Result<Self, Error> {
        if key.len() != I::KEY_LEN {
            return Err(Error::InvalidKeyLength);
        }
        Ok(RawCipher {
            aead: Gcm::new(I::cipher(key)),
            base_nonce: *base_nonce,
        })
    }

    /// Header mode: derives the AEAD key, base nonce and commitment from
    /// `input_key`, `salt` and `ctx` with HKDF-Expand-SHA-512, returning the
    /// cipher and the 32-byte commitment.
    pub fn derive(
        input_key: &[u8],
        ctx: &[u8],
        salt: &[u8; SALT_LEN],
    ) -> Result<(Self, [u8; COMMITMENT_LEN]), Error> {
        if input_key.len() != I::KEY_LEN {
            return Err(Error::InvalidKeyLength);
        }
        let mut okm = Zeroizing::new([0u8; 32 + NONCE_LEN + COMMITMENT_LEN]);
        let n = I::KEY_LEN + NONCE_LEN + COMMITMENT_LEN;
        hkdf_expand_sha512(
            input_key,
            &[INFO_PREFIX, I::AEAD_NAME.as_bytes(), &[0], salt, ctx],
            &mut okm[..n],
        );
        let (key, rest) = okm[..n].split_at(I::KEY_LEN);
        let (nonce, commitment) = rest.split_at(NONCE_LEN);
        let cipher = RawCipher {
            aead: Gcm::new(I::cipher(key)),
            base_nonce: nonce.try_into().expect("12-byte nonce"),
        };
        Ok((cipher, commitment.try_into().expect("32-byte commitment")))
    }

    /// Nonce of chunk `index`: the base nonce XOR the big-endian counter.
    fn nonce(&self, index: u64) -> Result<[u8; NONCE_LEN], Error> {
        if index >= MAX_CHUNKS {
            return Err(Error::TooManyChunks);
        }
        let mut nonce = self.base_nonce;
        for (n, c) in nonce[NONCE_LEN - 8..].iter_mut().zip(index.to_be_bytes()) {
            *n ^= c;
        }
        Ok(nonce)
    }

    /// Encrypts chunk `index` and appends ciphertext and tag to `out`.
    ///
    /// `plaintext` is at most [`CHUNK_SIZE`] bytes; the caller is responsible
    /// for the chunking rule (every chunk but the last is exactly
    /// `CHUNK_SIZE` bytes, the last is shorter).
    pub fn seal_chunk(&self, index: u64, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        if plaintext.len() > CHUNK_SIZE {
            return Err(Error::InvalidChunkLength);
        }
        let nonce = self.nonce(index)?;
        let start = out.len();
        out.extend_from_slice(plaintext);
        let tag = self.aead.encrypt(&nonce, &[], &mut out[start..]);
        out.extend_from_slice(&tag);
        Ok(())
    }

    /// Authenticates and decrypts `chunk` (ciphertext plus tag) as chunk
    /// `index`, appending the plaintext to `out`. Nothing is appended on
    /// error.
    ///
    /// `chunk` is between [`TAG_LEN`] and [`ENCRYPTED_CHUNK_LEN`] bytes;
    /// anything shorter is [`Error::Truncated`], anything longer
    /// [`Error::InvalidChunkLength`]. Random-access readers use this with
    /// [`chunk_offset`]; a chunk of exactly `ENCRYPTED_CHUNK_LEN` bytes is a
    /// full chunk, a shorter one is the final chunk, and decrypting the final
    /// chunk at its index authenticates the message length.
    pub fn open_chunk(&self, index: u64, chunk: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        if chunk.len() < TAG_LEN {
            return Err(Error::Truncated);
        }
        if chunk.len() > ENCRYPTED_CHUNK_LEN {
            return Err(Error::InvalidChunkLength);
        }
        let nonce = self.nonce(index)?;
        let (body, tag) = chunk.split_at(chunk.len() - TAG_LEN);
        let tag: &[u8; TAG_LEN] = tag.try_into().expect("16-byte tag");
        let start = out.len();
        out.extend_from_slice(body);
        // `Gcm::decrypt` restores the ciphertext on a tag mismatch, so the
        // truncation below never leaves unauthenticated plaintext behind.
        if self
            .aead
            .decrypt(&nonce, &[], &mut out[start..], tag)
            .is_err()
        {
            out.truncate(start);
            return Err(Error::TagMismatch);
        }
        Ok(())
    }

    /// Raw-mode one-shot encryption: the chunked ciphertext of `msg` without
    /// a header, appended to `out`.
    pub fn seal(&self, msg: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        out.reserve(msg.len() + TAG_LEN * (msg.len() / CHUNK_SIZE + 1));
        let mut index = 0u64;
        // The final chunk is `msg.len() % CHUNK_SIZE` bytes, empty when the
        // message is a multiple of the chunk size (including empty).
        for chunk in msg.chunks_exact(CHUNK_SIZE) {
            self.seal_chunk(index, chunk, out)?;
            index += 1;
        }
        self.seal_chunk(index, msg.chunks_exact(CHUNK_SIZE).remainder(), out)
    }

    /// Raw-mode one-shot decryption of a header-less chunked ciphertext,
    /// appended to `out`. On error `out` may hold the plaintext of the chunks
    /// that authenticated before the failure.
    pub fn open(&self, ct: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        // Every full 16400-byte block is a full chunk; the remainder is the
        // final chunk, which must exist (be at least a tag).
        let rem = ct.len() % ENCRYPTED_CHUNK_LEN;
        if rem < TAG_LEN {
            return Err(Error::Truncated);
        }
        out.reserve(ct.len() - TAG_LEN * (ct.len() / ENCRYPTED_CHUNK_LEN + 1));
        for (index, chunk) in ct.chunks(ENCRYPTED_CHUNK_LEN).enumerate() {
            self.open_chunk(index as u64, chunk, out)?;
        }
        Ok(())
    }
}

impl<I: Instantiation> Drop for RawCipher<I> {
    fn drop(&mut self) {
        // The GCM state (key schedule, GHASH key) wipes itself.
        self.base_nonce.zeroize();
    }
}

impl<I: Instantiation> ZeroizeOnDrop for RawCipher<I> {}

/// Derives the cipher for `salt` and lays out the header.
fn header<I: Instantiation>(
    key: &[u8],
    ctx: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<(RawCipher<I>, [u8; HEADER_LEN]), Error> {
    let (cipher, commitment) = RawCipher::<I>::derive(key, ctx, salt)?;
    let mut hdr = [0u8; HEADER_LEN];
    hdr[..SALT_LEN].copy_from_slice(salt);
    hdr[SALT_LEN..].copy_from_slice(&commitment);
    Ok((cipher, hdr))
}

/// Checks the commitment in `header` and returns the cipher.
fn open_header<I: Instantiation>(
    key: &[u8],
    ctx: &[u8],
    header: &[u8; HEADER_LEN],
) -> Result<RawCipher<I>, Error> {
    let salt: &[u8; SALT_LEN] = header[..SALT_LEN].try_into().expect("24-byte salt");
    let (cipher, commitment) = RawCipher::<I>::derive(key, ctx, salt)?;
    if !bool::from(commitment[..].ct_eq(&header[SALT_LEN..])) {
        return Err(Error::CommitmentMismatch);
    }
    Ok(cipher)
}

/// Encrypts `msg` under the input `key` and application `ctx` with a random
/// salt from `rng`, returning `salt || commitment || chunks`.
///
/// `key` must be uniformly random and exactly `I::KEY_LEN` bytes
/// ([`Error::InvalidKeyLength`] otherwise). `ctx` is bound into the key
/// derivation and must be presented again to decrypt.
pub fn encrypt<I: Instantiation>(
    key: &[u8],
    ctx: &[u8],
    msg: &[u8],
    rng: &mut dyn CryptoRngCore,
) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    encrypt_with_salt::<I>(key, ctx, msg, &salt)
}

/// [`encrypt`] with a caller-supplied salt.
///
/// The salt MUST NOT repeat for a given input key: reusing one derives the
/// same AEAD key and nonces for two messages. Meant for callers with their
/// own unique-salt discipline (and for testing against fixed vectors).
pub fn encrypt_with_salt<I: Instantiation>(
    key: &[u8],
    ctx: &[u8],
    msg: &[u8],
    salt: &[u8; SALT_LEN],
) -> Result<Vec<u8>, Error> {
    let (cipher, hdr) = header::<I>(key, ctx, salt)?;
    let mut out =
        Vec::with_capacity(HEADER_LEN + msg.len() + TAG_LEN * (msg.len() / CHUNK_SIZE + 1));
    out.extend_from_slice(&hdr);
    cipher.seal(msg, &mut out)?;
    Ok(out)
}

/// Decrypts a ciphertext produced by [`encrypt`] under `key` and `ctx`.
///
/// The key length and the commitment are checked before any chunk is
/// decrypted; every chunk is then authenticated in order, and the final
/// chunk must be shorter than a full one ([`Error::Truncated`] otherwise).
pub fn decrypt<I: Instantiation>(key: &[u8], ctx: &[u8], ct: &[u8]) -> Result<Vec<u8>, Error> {
    if key.len() != I::KEY_LEN {
        return Err(Error::InvalidKeyLength);
    }
    let Some((hdr, body)) = ct.split_at_checked(HEADER_LEN) else {
        return Err(Error::Truncated);
    };
    let cipher = open_header::<I>(key, ctx, hdr.try_into().expect("56-byte header"))?;
    let mut out = Vec::new();
    cipher.open(body, &mut out)?;
    Ok(out)
}

/// Streaming encryption: buffers up to 16 KiB of plaintext and emits each
/// full chunk as soon as it is complete.
///
/// Write [`header`](Self::header) first, then everything [`push`](Self::push)
/// appends, then everything [`finish`](Self::finish) appends. The buffered
/// plaintext is wiped on drop.
pub struct Encryptor<I: Instantiation> {
    cipher: RawCipher<I>,
    header: [u8; HEADER_LEN],
    buf: Zeroizing<Vec<u8>>,
    index: u64,
}

impl<I: Instantiation> Encryptor<I> {
    /// Starts a message under `key` and `ctx` with a random salt from `rng`.
    pub fn new(key: &[u8], ctx: &[u8], rng: &mut dyn CryptoRngCore) -> Result<Self, Error> {
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        Self::with_salt(key, ctx, &salt)
    }

    /// [`new`](Self::new) with a caller-supplied salt, which MUST NOT repeat
    /// for a given input key (see [`encrypt_with_salt`]).
    pub fn with_salt(key: &[u8], ctx: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self, Error> {
        let (cipher, header) = header::<I>(key, ctx, salt)?;
        Ok(Encryptor {
            cipher,
            header,
            buf: Zeroizing::new(Vec::with_capacity(CHUNK_SIZE)),
            index: 0,
        })
    }

    /// The 56-byte `salt || commitment` header that precedes the chunks.
    pub fn header(&self) -> &[u8; HEADER_LEN] {
        &self.header
    }

    /// Feeds plaintext, appending every chunk it completes to `out`.
    ///
    /// The only error is [`Error::TooManyChunks`]; after it the encryptor
    /// is unusable and should be dropped.
    pub fn push(&mut self, msg: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let mut data = msg;
        loop {
            // Invariant: the buffer holds fewer than CHUNK_SIZE bytes. A
            // full buffer is never the final chunk (that one is always
            // shorter), so it can be sealed the moment it fills up.
            let room = CHUNK_SIZE - self.buf.len();
            if data.len() < room {
                self.buf.extend_from_slice(data);
                return Ok(());
            }
            if self.buf.is_empty() {
                let (chunk, rest) = data.split_at(CHUNK_SIZE);
                self.cipher.seal_chunk(self.index, chunk, out)?;
                data = rest;
            } else {
                let (head, rest) = data.split_at(room);
                self.buf.extend_from_slice(head);
                self.cipher.seal_chunk(self.index, &self.buf, out)?;
                self.buf.clear();
                data = rest;
            }
            self.index += 1;
        }
    }

    /// Seals the final (short, possibly empty) chunk and appends it to `out`.
    pub fn finish(self, out: &mut Vec<u8>) -> Result<(), Error> {
        self.cipher.seal_chunk(self.index, &self.buf, out)
    }
}

/// Where a [`Decryptor`] stands.
#[derive(Clone, Copy)]
enum State {
    /// Accepting ciphertext.
    Open,
    /// The final chunk was decrypted; nothing more may follow.
    Done,
    /// Failed; every further call returns the same error.
    Failed(Error),
}

/// Streaming decryption: buffers up to one encrypted chunk and releases the
/// plaintext of a chunk only after it authenticated.
///
/// Feed the ciphertext after the header with [`push`](Self::push) in pieces
/// of any size, then call [`finish`](Self::finish) at end of input, which
/// decrypts the final chunk and verifies that it is shorter than a full one.
/// Once any call has failed, every later call returns the same error: an
/// authentication failure is never followed by a clean end of message.
pub struct Decryptor<I: Instantiation> {
    cipher: RawCipher<I>,
    /// Pending ciphertext, at most [`ENCRYPTED_CHUNK_LEN`] bytes.
    buf: Vec<u8>,
    index: u64,
    state: State,
}

impl<I: Instantiation> Decryptor<I> {
    /// Verifies the commitment in the 56-byte `header` under `key` and `ctx`
    /// and, only if it matches, returns a decryptor for the chunks that
    /// follow it.
    pub fn new(key: &[u8], ctx: &[u8], header: &[u8; HEADER_LEN]) -> Result<Self, Error> {
        Ok(Self::from_raw(open_header::<I>(key, ctx, header)?))
    }

    /// Raw mode: a decryptor for a header-less ciphertext under an
    /// externally derived [`RawCipher`].
    pub fn from_raw(cipher: RawCipher<I>) -> Self {
        Decryptor {
            cipher,
            buf: Vec::with_capacity(ENCRYPTED_CHUNK_LEN),
            index: 0,
            state: State::Open,
        }
    }

    fn fail(&mut self, e: Error) -> Result<(), Error> {
        self.state = State::Failed(e);
        self.buf.clear();
        Err(e)
    }

    /// Feeds ciphertext, appending the plaintext of every chunk it can
    /// authenticate to `out`. A chunk is decrypted once at least one byte of
    /// the next one has arrived (which proves it is not the final chunk).
    ///
    /// Nothing is appended for a chunk that fails, and the error is sticky.
    pub fn push(&mut self, ct: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        match self.state {
            State::Open => {}
            State::Failed(e) => return Err(e),
            State::Done => {
                return if ct.is_empty() {
                    Ok(())
                } else {
                    self.fail(Error::TrailingData)
                };
            }
        }
        let mut data = ct;
        loop {
            // Invariant: the buffer holds at most ENCRYPTED_CHUNK_LEN bytes.
            // A buffered full chunk is only decrypted when more data follows
            // it, since a full chunk in final position is a truncation.
            let room = ENCRYPTED_CHUNK_LEN - self.buf.len();
            if data.len() <= room {
                self.buf.extend_from_slice(data);
                return Ok(());
            }
            let res = if self.buf.is_empty() {
                let (chunk, rest) = data.split_at(ENCRYPTED_CHUNK_LEN);
                data = rest;
                self.cipher.open_chunk(self.index, chunk, out)
            } else {
                let (head, rest) = data.split_at(room);
                self.buf.extend_from_slice(head);
                data = rest;
                let res = self.cipher.open_chunk(self.index, &self.buf, out);
                self.buf.clear();
                res
            };
            if let Err(e) = res {
                return self.fail(e);
            }
            self.index += 1;
        }
    }

    /// Signals end of input: decrypts the buffered final chunk (which must
    /// be shorter than a full chunk and at least a tag) and appends its
    /// plaintext to `out`. Idempotent once it succeeded; sticky once it
    /// failed.
    pub fn finish(&mut self, out: &mut Vec<u8>) -> Result<(), Error> {
        match self.state {
            State::Open => {}
            State::Failed(e) => return Err(e),
            State::Done => return Ok(()),
        }
        if self.buf.len() < TAG_LEN || self.buf.len() == ENCRYPTED_CHUNK_LEN {
            return self.fail(Error::Truncated);
        }
        let res = self.cipher.open_chunk(self.index, &self.buf, out);
        self.buf.clear();
        match res {
            Ok(()) => {
                self.state = State::Done;
                Ok(())
            }
            Err(e) => self.fail(e),
        }
    }

    /// Whether the final chunk has been decrypted successfully.
    pub fn is_finished(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// The error that stopped this decryptor, if any.
    pub fn error(&self) -> Option<Error> {
        match self.state {
            State::Failed(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::sha512;
    use crate::rng::OsRng;
    use alloc::vec;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Wycheproof `c2sp_chunked_encryption_aes_128_gcm` tcId 2 (a 7-byte
    /// message), inflated; the spec itself defers to that suite.
    const KEY128: &str = "59454c4c4f57205355424d4152494e45";
    const CT128_TC2: &str = "99ef5b6b98795b7b37a41d6321d8dd472347c76185f40027e921542dd7e4305bb67a175e5088a8a4db92ef4d3419bda917dd5099085be2f35cf32165613d4fe58db45dd4619b454586232f2661a2bf";
    const AEAD_KEY128_TC2: &str = "18efc971cf196407e112951a187c63b6";
    const BASE_NONCE128_TC2: &str = "5f73d9f150410098b2cc408c";
    const SHA_TC2: &str = "e85f32a85f1d4f7c9b2d36d20eca8435d81253e7075e9dea069eb1b6da48daf92ef1797367b520d8a46c4f72cecb85b1daff8887fcb41721d39943d1952fc180";
    /// tcId 1 of the AES-256 file: the empty message.
    const KEY256: &str = "59454c4c4f57205355424d4152494e452059454c4c4f57205355424d4152494e";
    const CT256_TC1: &str = "43a2e39431cbae0389d3fc86adf46f7c3a24de88d9311617e53f3164cc1d5dc738a66b97f0bf786565c31799c2f463d50a7e10046011dc6fc3c939e3a5db7affb6191551669554fb";

    #[test]
    fn wycheproof_128_tc2() {
        let ct = hex(CT128_TC2);
        let msg = decrypt::<Cobblestone128>(&hex(KEY128), b"", &ct).unwrap();
        assert_eq!(msg.len(), 7);
        assert_eq!(sha512(&msg)[..], hex(SHA_TC2)[..]);

        // The derived AEAD key and base nonce match the vector's, so raw
        // mode round-trips the header-less ciphertext both ways.
        let raw = RawCipher::<Cobblestone128>::new(
            &hex(AEAD_KEY128_TC2),
            &hex(BASE_NONCE128_TC2).try_into().unwrap(),
        )
        .unwrap();
        let mut sealed = Vec::new();
        raw.seal(&msg, &mut sealed).unwrap();
        assert_eq!(sealed, ct[HEADER_LEN..]);
        let mut opened = Vec::new();
        raw.open(&ct[HEADER_LEN..], &mut opened).unwrap();
        assert_eq!(opened, msg);

        // Injecting the salt reproduces the whole ciphertext.
        let salt: [u8; SALT_LEN] = ct[..SALT_LEN].try_into().unwrap();
        assert_eq!(
            encrypt_with_salt::<Cobblestone128>(&hex(KEY128), b"", &msg, &salt).unwrap(),
            ct
        );
    }

    #[test]
    fn wycheproof_256_tc1_empty() {
        let ct = hex(CT256_TC1);
        assert_eq!(ct.len(), HEADER_LEN + TAG_LEN);
        assert_eq!(
            decrypt::<Cobblestone256>(&hex(KEY256), b"", &ct).unwrap(),
            b""
        );
        assert_eq!(
            decrypt::<Cobblestone128>(&hex(KEY128), b"", &ct),
            Err(Error::CommitmentMismatch)
        );
    }

    #[test]
    fn header_checks_before_chunks() {
        let ct = hex(CT128_TC2);
        let key = hex(KEY128);
        assert_eq!(
            decrypt::<Cobblestone128>(&key[..15], b"", &ct),
            Err(Error::InvalidKeyLength)
        );
        assert_eq!(
            decrypt::<Cobblestone256>(&key, b"", &ct),
            Err(Error::InvalidKeyLength)
        );
        assert_eq!(
            decrypt::<Cobblestone128>(&key, b"ctx", &ct),
            Err(Error::CommitmentMismatch)
        );
        let mut bad = ct.clone();
        bad[0] ^= 1;
        assert_eq!(
            decrypt::<Cobblestone128>(&key, b"", &bad),
            Err(Error::CommitmentMismatch)
        );
        let mut bad = ct.clone();
        bad[SALT_LEN] ^= 1;
        assert_eq!(
            decrypt::<Cobblestone128>(&key, b"", &bad),
            Err(Error::CommitmentMismatch)
        );
        for n in [0, 1, 24, 55] {
            assert_eq!(
                decrypt::<Cobblestone128>(&key, b"", &ct[..n]),
                Err(Error::Truncated),
                "{n}"
            );
        }
        // Header intact, payload broken.
        assert_eq!(
            decrypt::<Cobblestone128>(&key, b"", &ct[..HEADER_LEN]),
            Err(Error::Truncated)
        );
        assert_eq!(
            decrypt::<Cobblestone128>(&key, b"", &ct[..HEADER_LEN + 15]),
            Err(Error::Truncated)
        );
        let mut bad = ct.clone();
        bad[HEADER_LEN] ^= 1;
        assert_eq!(
            decrypt::<Cobblestone128>(&key, b"", &bad),
            Err(Error::TagMismatch)
        );
    }

    #[test]
    fn chunking_boundaries() {
        let key = [7u8; 32];
        for len in [
            0,
            1,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            2 * CHUNK_SIZE,
            2 * CHUNK_SIZE + 5,
        ] {
            let msg: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
            let ct = encrypt::<Cobblestone256>(&key, b"ctx", &msg, &mut OsRng).unwrap();
            let chunks = len / CHUNK_SIZE + 1;
            assert_eq!(ct.len(), HEADER_LEN + len + chunks * TAG_LEN, "{len}");
            assert_eq!(
                decrypt::<Cobblestone256>(&key, b"ctx", &ct).unwrap(),
                msg,
                "{len}"
            );
            // Dropping the final chunk (or its tag) is a truncation, never a
            // shorter valid message.
            let last = ct.len() - (len % CHUNK_SIZE + TAG_LEN);
            assert_eq!(
                decrypt::<Cobblestone256>(&key, b"ctx", &ct[..last]),
                Err(Error::Truncated),
                "{len}"
            );
            // One byte short: an empty final chunk becomes shorter than a
            // tag (truncation), a non-empty one loses a tag byte.
            let short = if len % CHUNK_SIZE == 0 {
                Error::Truncated
            } else {
                Error::TagMismatch
            };
            assert_eq!(
                decrypt::<Cobblestone256>(&key, b"ctx", &ct[..ct.len() - 1]),
                Err(short),
                "{len}"
            );
        }
    }

    #[test]
    fn streaming_matches_one_shot() {
        let key = [9u8; 16];
        let msg: Vec<u8> = (0..3 * CHUNK_SIZE + 123).map(|i| (i % 253) as u8).collect();
        let salt = [1u8; SALT_LEN];
        let expected = encrypt_with_salt::<Cobblestone128>(&key, b"", &msg, &salt).unwrap();
        for step in [
            1usize,
            100,
            CHUNK_SIZE - 1,
            CHUNK_SIZE,
            CHUNK_SIZE + 1,
            50_000,
            usize::MAX,
        ] {
            let mut enc = Encryptor::<Cobblestone128>::with_salt(&key, b"", &salt).unwrap();
            let mut ct = enc.header().to_vec();
            for piece in msg.chunks(step) {
                enc.push(piece, &mut ct).unwrap();
            }
            enc.finish(&mut ct).unwrap();
            assert_eq!(ct, expected, "encrypt step {step}");

            let mut dec =
                Decryptor::<Cobblestone128>::new(&key, b"", &ct[..HEADER_LEN].try_into().unwrap())
                    .unwrap();
            let mut out = Vec::new();
            for piece in ct[HEADER_LEN..].chunks(step) {
                dec.push(piece, &mut out).unwrap();
            }
            assert!(!dec.is_finished());
            dec.finish(&mut out).unwrap();
            assert!(dec.is_finished());
            assert_eq!(out, msg, "decrypt step {step}");
            // Idempotent finish, and trailing data is refused.
            dec.finish(&mut out).unwrap();
            assert_eq!(dec.push(b"x", &mut out), Err(Error::TrailingData));
            assert_eq!(out, msg);
        }
    }

    #[test]
    fn streaming_errors_are_sticky_and_release_nothing_bad() {
        let key = [3u8; 16];
        let msg = vec![0xAB; 2 * CHUNK_SIZE + 10];
        let mut ct = encrypt::<Cobblestone128>(&key, b"", &msg, &mut OsRng).unwrap();
        // Corrupt the second chunk: the first still comes out, the rest never.
        ct[HEADER_LEN + ENCRYPTED_CHUNK_LEN + 5] ^= 1;
        let mut dec =
            Decryptor::<Cobblestone128>::new(&key, b"", &ct[..HEADER_LEN].try_into().unwrap())
                .unwrap();
        let mut out = Vec::new();
        assert_eq!(
            dec.push(&ct[HEADER_LEN..], &mut out),
            Err(Error::TagMismatch)
        );
        assert_eq!(out.len(), CHUNK_SIZE);
        assert_eq!(dec.error(), Some(Error::TagMismatch));
        assert_eq!(dec.push(b"more", &mut out), Err(Error::TagMismatch));
        assert_eq!(dec.finish(&mut out), Err(Error::TagMismatch));
        assert_eq!(out.len(), CHUNK_SIZE);

        // Reordering chunks 0 and 1 fails at chunk 0.
        let good = encrypt::<Cobblestone128>(&key, b"", &msg, &mut OsRng).unwrap();
        let mut swapped = good.clone();
        let (a, b) = (HEADER_LEN, HEADER_LEN + ENCRYPTED_CHUNK_LEN);
        swapped[a..a + ENCRYPTED_CHUNK_LEN].copy_from_slice(&good[b..b + ENCRYPTED_CHUNK_LEN]);
        swapped[b..b + ENCRYPTED_CHUNK_LEN].copy_from_slice(&good[a..a + ENCRYPTED_CHUNK_LEN]);
        assert_eq!(
            decrypt::<Cobblestone128>(&key, b"", &swapped),
            Err(Error::TagMismatch)
        );

        // A full chunk with no terminator is a truncation at finish.
        let mut dec =
            Decryptor::<Cobblestone128>::new(&key, b"", &good[..HEADER_LEN].try_into().unwrap())
                .unwrap();
        let mut out = Vec::new();
        dec.push(
            &good[HEADER_LEN..HEADER_LEN + ENCRYPTED_CHUNK_LEN],
            &mut out,
        )
        .unwrap();
        assert!(
            out.is_empty(),
            "a possibly-final chunk is not released early"
        );
        assert_eq!(dec.finish(&mut out), Err(Error::Truncated));
        assert_eq!(dec.finish(&mut out), Err(Error::Truncated));
    }

    #[test]
    fn nonce_counter_and_limits() {
        let raw = RawCipher::<Cobblestone128>::new(&[0u8; 16], &[0xFF; NONCE_LEN]).unwrap();
        assert_eq!(raw.nonce(0).unwrap(), [0xFF; 12]);
        assert_eq!(
            raw.nonce(1).unwrap(),
            [
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE
            ]
        );
        assert_eq!(raw.nonce(0x100).unwrap()[10..], [0xFE, 0xFF]);
        assert_eq!(
            raw.nonce(MAX_CHUNKS - 1).unwrap()[6..],
            [0xFF, 0xC0, 0, 0, 0, 0]
        );
        assert_eq!(raw.nonce(MAX_CHUNKS), Err(Error::TooManyChunks));
        let mut out = Vec::new();
        assert_eq!(
            raw.seal_chunk(MAX_CHUNKS, b"", &mut out),
            Err(Error::TooManyChunks)
        );
        assert_eq!(
            raw.seal_chunk(0, &[0; CHUNK_SIZE + 1], &mut out),
            Err(Error::InvalidChunkLength)
        );
        assert_eq!(
            raw.open_chunk(0, &[0; ENCRYPTED_CHUNK_LEN + 1], &mut out),
            Err(Error::InvalidChunkLength)
        );
        assert_eq!(
            raw.open_chunk(0, &[0; TAG_LEN - 1], &mut out),
            Err(Error::Truncated)
        );
        assert!(out.is_empty());
        assert_eq!(
            RawCipher::<Cobblestone128>::new(&[0u8; 32], &[0; NONCE_LEN]).err(),
            Some(Error::InvalidKeyLength)
        );
        assert_eq!(chunk_offset(0), 56);
        assert_eq!(chunk_offset(3), 56 + 3 * 16400);
    }

    #[test]
    fn random_access_by_chunk() {
        let key = [5u8; 16];
        let msg: Vec<u8> = (0..2 * CHUNK_SIZE + 77).map(|i| (i % 199) as u8).collect();
        let ct = encrypt::<Cobblestone128>(&key, b"ra", &msg, &mut OsRng).unwrap();
        let cipher =
            open_header::<Cobblestone128>(&key, b"ra", ct[..HEADER_LEN].try_into().unwrap())
                .unwrap();
        // Chunk 1 alone, then the final chunk (which authenticates the length).
        let start = chunk_offset(1) as usize;
        let mut out = Vec::new();
        cipher
            .open_chunk(1, &ct[start..start + ENCRYPTED_CHUNK_LEN], &mut out)
            .unwrap();
        assert_eq!(out, msg[CHUNK_SIZE..2 * CHUNK_SIZE]);
        let last = chunk_offset(2) as usize;
        out.clear();
        cipher.open_chunk(2, &ct[last..], &mut out).unwrap();
        assert_eq!(out, msg[2 * CHUNK_SIZE..]);
        // The same bytes at another index do not authenticate.
        assert_eq!(
            cipher.open_chunk(0, &ct[last..], &mut out),
            Err(Error::TagMismatch)
        );
    }
}
