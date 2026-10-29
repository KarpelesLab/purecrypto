//! Exporting and importing a hasher's internal state: [`ExportableState`],
//! its error type, and the field codec the per-algorithm impls share.

/// The format version written as the first byte of every exported state.
pub const STATE_FORMAT_VERSION: u8 = 1;

/// Why [`ExportableState::from_state`] rejected a serialized state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StateError {
    /// The input is not exactly [`ExportableState::STATE_LEN`] bytes.
    InvalidLength,
    /// The format version byte is not one this build reads.
    UnsupportedVersion,
    /// The state was exported by a different algorithm (or a different
    /// variant with an incompatible initial value or parameters).
    WrongAlgorithm,
    /// The fields are inconsistent: a buffered byte count outside the block,
    /// a length counter that does not match it, non-zero bytes past the
    /// buffered data, or an out-of-range BLAKE2 parameter.
    Inconsistent,
    /// The algorithm has no exportable state (BLAKE3, through
    /// [`Hasher`](super::Hasher)).
    Unsupported,
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            StateError::InvalidLength => "hash state has the wrong length",
            StateError::UnsupportedVersion => "hash state format version not supported",
            StateError::WrongAlgorithm => "hash state belongs to a different algorithm",
            StateError::Inconsistent => "hash state fields are inconsistent",
            StateError::Unsupported => "this hash algorithm's state cannot be exported",
        })
    }
}

impl core::error::Error for StateError {}

/// A hasher whose mid-message state can be exported to bytes and rebuilt.
///
/// [`ExportableState`] snapshots a streaming hasher mid-message — the chaining
/// value, the buffered partial block and the length counters — as a
/// fixed-size byte string, and rebuilds an equivalent hasher from one. Feeding
/// the rest of the message to the rebuilt hasher gives the same digest as
/// never having stopped. This is what a serializable hash context needs (PHP's
/// `HashContext`, libsodium's `crypto_generichash` state, checkpointing a long
/// hash across processes).
///
/// # The format
///
/// The byte layout is **purecrypto's own**, stable across semver-compatible
/// releases (a state exported by one imports into any later compatible
/// release; an incompatible change would bump [`STATE_FORMAT_VERSION`]).
/// It is not any other library's layout — translate at the boundary if
/// you need one (e.g. PHP's serialized `HashContext`). Every state is:
///
/// | bytes | field |
/// |---|---|
/// | 1 | format version ([`STATE_FORMAT_VERSION`]) |
/// | 1 | algorithm tag (distinct per state layout and initial value) |
/// | … | the algorithm's fields, integers little-endian, fixed width |
///
/// The algorithm fields, in order:
///
/// - **MD4, MD5, SHA-1, RIPEMD-160, SM3, SHA-224, SHA-256**: the `W` 32-bit
///   chaining words, the total message length in bytes (`u64`), the number of
///   buffered bytes (`u8`, `< 64`) and the 64-byte block buffer.
/// - **SHA-384, SHA-512, SHA-512/224, SHA-512/256**: eight 64-bit chaining
///   words, the message length in bytes (`u128`), the buffered byte count
///   (`u8`, `< 128`) and the 128-byte buffer.
/// - **Whirlpool**: eight 64-bit chaining words, the message length in *bits*
///   (`u128`), the buffered byte count (`< 64`) and the 64-byte buffer.
/// - **Streebog**: the 512-bit state `h`, bit counter `N` and checksum `Σ`
///   (each eight `u64`, least significant first), the buffered byte count
///   (`< 64`) and the 64-byte buffer.
/// - **MD2**: the 48-byte state `X`, the 16-byte checksum, the buffered byte
///   count (`< 16`) and the 16-byte buffer.
/// - **SHA-3, Keccak-256, SHAKE**: the 25 Keccak lanes (`u64`), the buffered
///   byte count (`< rate`) and the `rate`-byte buffer of input not yet XORed
///   into the lanes.
/// - **BLAKE2b / BLAKE2s**: the eight chaining words, the byte counter
///   `t0, t1`, the buffered byte count (`<= block`, since BLAKE2 holds back a
///   full final block), the block buffer, the digest length (`u8`) and the
///   BLAKE2X output length (`u32` for BLAKE2Xb, `u16` for BLAKE2Xs; `0` for
///   the plain hash and MAC). A keyed state still carries the key block in
///   its buffer until more input arrives, and the chaining value is
///   key-derived either way: **treat an exported keyed state as secret**.
/// - With `legacy-hashes`: **RIPEMD-128/256/320** use the MD4 layout above
///   (4, 8 or 10 words). **Tiger** writes its three 64-bit words, **Snefru**
///   and **HAVAL** their eight 32-bit chaining words, and **GOST R 34.11-94**
///   its eight 32-bit chaining words followed by the eight 32-bit words of
///   the running block sum Σ (least significant first); then each the
///   message length in bytes (`u64`), the buffered byte count (`u8`, below
///   the block: 64 for Tiger, 32 for Snefru and GOST, 128 for HAVAL) and the
///   block buffer. Every pass count and output length has its own tag.
///
/// Buffer bytes past the buffered count are always written as zero and must
/// be zero on import, so each hasher state has exactly one encoding.
///
/// # Validation
///
/// [`ExportableState::from_state`] never panics. It rejects a wrong length, an
/// unknown version, a state for another algorithm, a buffered count outside
/// the block, a length counter that disagrees with the buffered count, and
/// non-zero padding, with a [`StateError`]. The chaining value itself cannot
/// be checked — any value is a possible state — so a well-formed but forged
/// state simply hashes to something else.
///
/// For a runtime-chosen algorithm, [`Hasher::export_state`](crate::hash::Hasher::export_state)
/// and [`Hasher::from_state`](crate::hash::Hasher::from_state) produce and accept the
/// same bytes. BLAKE3, the cSHAKE/KMAC/TupleHash/ParallelHash family,
/// TurboSHAKE/KangarooTwelve and [`Hmac`](super::Hmac) do not implement it.
///
/// # Example
///
/// ```
/// use purecrypto::hash::{Digest, ExportableState, Sha256};
///
/// let mut h = Sha256::new();
/// h.update(b"first half, ");
/// let saved = h.export_state();
///
/// let mut resumed = Sha256::from_state(saved.as_ref()).unwrap();
/// resumed.update(b"second half");
/// assert_eq!(resumed.finalize(), Sha256::digest(b"first half, second half"));
/// ```
pub trait ExportableState: Sized {
    /// Length of the serialized state, in bytes.
    const STATE_LEN: usize;

    /// The serialized state: `[u8; STATE_LEN]`.
    type State: AsRef<[u8]> + AsMut<[u8]> + Copy;

    /// Serializes the current state. The hasher is left untouched.
    fn export_state(&self) -> Self::State;

    /// Rebuilds a hasher from a state produced by
    /// [`export_state`](Self::export_state).
    fn from_state(state: &[u8]) -> Result<Self, StateError>;
}

/// Algorithm tags (second byte of every state).
pub(super) mod tag {
    pub(crate) const MD2: u8 = 1;
    pub(crate) const MD4: u8 = 2;
    pub(crate) const MD5: u8 = 3;
    pub(crate) const SHA1: u8 = 4;
    pub(crate) const SHA224: u8 = 5;
    pub(crate) const SHA256: u8 = 6;
    pub(crate) const SHA384: u8 = 7;
    pub(crate) const SHA512: u8 = 8;
    pub(crate) const SHA512_224: u8 = 9;
    pub(crate) const SHA512_256: u8 = 10;
    pub(crate) const RIPEMD160: u8 = 11;
    pub(crate) const SM3: u8 = 12;
    pub(crate) const WHIRLPOOL: u8 = 13;
    pub(crate) const STREEBOG256: u8 = 14;
    pub(crate) const STREEBOG512: u8 = 15;
    pub(crate) const SHA3_224: u8 = 16;
    pub(crate) const SHA3_256: u8 = 17;
    pub(crate) const SHA3_384: u8 = 18;
    pub(crate) const SHA3_512: u8 = 19;
    pub(crate) const KECCAK256: u8 = 20;
    pub(crate) const SHAKE128: u8 = 21;
    pub(crate) const SHAKE256: u8 = 22;
    /// All BLAKE2b states (fixed-output, MAC, BLAKE2Xb); the digest-length
    /// and XOF-length fields tell them apart.
    pub(crate) const BLAKE2B: u8 = 23;
    /// All BLAKE2s states.
    pub(crate) const BLAKE2S: u8 = 24;
    #[cfg(feature = "legacy-hashes")]
    pub(crate) const RIPEMD128: u8 = 25;
    #[cfg(feature = "legacy-hashes")]
    pub(crate) const RIPEMD256: u8 = 26;
    #[cfg(feature = "legacy-hashes")]
    pub(crate) const RIPEMD320: u8 = 27;
    /// Tiger: `TIGER + 3 * (passes - 3) + (bytes - 16) / 4`, so 28..=33 for
    /// tiger128,3, tiger160,3, tiger192,3, tiger128,4, tiger160,4, tiger192,4.
    #[cfg(feature = "legacy-hashes")]
    pub(crate) const TIGER: u8 = 28;
    #[cfg(feature = "legacy-hashes")]
    pub(crate) const SNEFRU256: u8 = 34;
    #[cfg(feature = "legacy-hashes")]
    pub(crate) const GOST94: u8 = 35;
    #[cfg(feature = "legacy-hashes")]
    pub(crate) const GOST94_CRYPTOPRO: u8 = 36;
    /// HAVAL: `HAVAL + 5 * (passes - 3) + (bytes - 16) / 4`, so 37..=51 for
    /// haval128,3 … haval256,3, haval128,4 … haval256,5.
    #[cfg(feature = "legacy-hashes")]
    pub(crate) const HAVAL: u8 = 37;
}

/// Serializes fields into a state buffer after the two header bytes.
pub(super) struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    pub(super) fn new(buf: &'a mut [u8], tag: u8) -> Self {
        buf[0] = STATE_FORMAT_VERSION;
        buf[1] = tag;
        Writer { buf, pos: 2 }
    }

    pub(super) fn bytes(&mut self, b: &[u8]) {
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
    }

    pub(super) fn u8(&mut self, v: u8) {
        self.bytes(&[v]);
    }

    pub(super) fn u16(&mut self, v: u16) {
        self.bytes(&v.to_le_bytes());
    }

    pub(super) fn u32(&mut self, v: u32) {
        self.bytes(&v.to_le_bytes());
    }

    pub(super) fn u64(&mut self, v: u64) {
        self.bytes(&v.to_le_bytes());
    }

    pub(super) fn u128(&mut self, v: u128) {
        self.bytes(&v.to_le_bytes());
    }

    pub(super) fn u32s(&mut self, v: &[u32]) {
        for &w in v {
            self.u32(w);
        }
    }

    pub(super) fn u64s(&mut self, v: &[u64]) {
        for &w in v {
            self.u64(w);
        }
    }

    /// A buffer of which the first `len` bytes are live: written in full,
    /// with the stale tail as zeros. Also writes `len` (as a `u8`) first.
    pub(super) fn buffer(&mut self, buf: &[u8], len: usize) {
        self.u8(len as u8);
        self.bytes(&buf[..len]);
        for _ in len..buf.len() {
            self.u8(0);
        }
    }

    /// Asserts the layout was filled exactly.
    pub(super) fn finish(self) {
        debug_assert_eq!(self.pos, self.buf.len(), "state layout length mismatch");
    }
}

/// Parses fields from a state, after checking its length and header.
///
/// The length is checked up front against the layout, so the field reads
/// cannot run past the end.
pub(super) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(super) fn new(buf: &'a [u8], tag: u8, len: usize) -> Result<Self, StateError> {
        if buf.len() != len {
            return Err(StateError::InvalidLength);
        }
        if buf[0] != STATE_FORMAT_VERSION {
            return Err(StateError::UnsupportedVersion);
        }
        if buf[1] != tag {
            return Err(StateError::WrongAlgorithm);
        }
        Ok(Reader { buf, pos: 2 })
    }

    pub(super) fn array<const N: usize>(&mut self) -> [u8; N] {
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        out
    }

    pub(super) fn u8(&mut self) -> u8 {
        self.array::<1>()[0]
    }

    pub(super) fn u16(&mut self) -> u16 {
        u16::from_le_bytes(self.array())
    }

    pub(super) fn u32(&mut self) -> u32 {
        u32::from_le_bytes(self.array())
    }

    pub(super) fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.array())
    }

    pub(super) fn u128(&mut self) -> u128 {
        u128::from_le_bytes(self.array())
    }

    pub(super) fn u32s<const N: usize>(&mut self) -> [u32; N] {
        core::array::from_fn(|_| self.u32())
    }

    pub(super) fn u64s<const N: usize>(&mut self) -> [u64; N] {
        core::array::from_fn(|_| self.u64())
    }

    /// The counterpart of [`Writer::buffer`]: reads the live length and a
    /// `buf.len()`-byte buffer into `buf`, requiring `len <= max` and the tail
    /// past `len` to be zero. Returns `len`.
    pub(super) fn buffer(&mut self, buf: &mut [u8], max: usize) -> Result<usize, StateError> {
        let len = self.u8() as usize;
        let raw = &self.buf[self.pos..self.pos + buf.len()];
        self.pos += buf.len();
        if len > max || raw[len..].iter().any(|&b| b != 0) {
            return Err(StateError::Inconsistent);
        }
        buf.copy_from_slice(raw);
        Ok(len)
    }

    /// Asserts the layout was consumed exactly.
    pub(super) fn finish(self) {
        debug_assert_eq!(self.pos, self.buf.len(), "state layout length mismatch");
    }
}

/// `2 + 4W + 8 + 1 + 64`: the layout of a 64-byte-block Merkle–Damgård state
/// over `W` 32-bit words with a 64-bit byte counter.
pub(super) const fn md32_state_len(words: usize) -> usize {
    2 + 4 * words + 8 + 1 + 64
}

/// Implements [`ExportableState`] for a hasher type that wraps its streaming
/// core in a field and whose core has `export_into` / `import_from`.
macro_rules! impl_exportable_state {
    ($ty:ty, $tag:expr, $len:expr, |$s:ident| $core:expr, $new:expr) => {
        impl $crate::hash::ExportableState for $ty {
            const STATE_LEN: usize = $len;
            type State = [u8; $len];

            fn export_state(&self) -> [u8; $len] {
                let $s = self;
                let mut out = [0u8; $len];
                let mut w = $crate::hash::state::Writer::new(&mut out, $tag);
                $core.export_into(&mut w);
                w.finish();
                out
            }

            fn from_state(state: &[u8]) -> Result<Self, $crate::hash::StateError> {
                let mut r = $crate::hash::state::Reader::new(state, $tag, $len)?;
                let mut $s: $ty = $new;
                $core.import_from(&mut r)?;
                r.finish();
                Ok($s)
            }
        }
    };
}
pub(super) use impl_exportable_state;

#[cfg(test)]
mod tests {
    use super::super::{
        Blake2b256, Blake2b384, Blake2b512, Blake2bMac, Blake2s256, Blake2sMac, Blake2xb, Blake2xs,
        Digest, ExportableState, ExtendableOutput, HashAlgorithm, Hasher, Keccak256, Md2, Md4, Md5,
        Ripemd160, Sha1, Sha3_224, Sha3_256, Sha3_384, Sha3_512, Sha224, Sha256, Sha384, Sha512,
        Sha512_224, Sha512_256, Shake128, Shake256, Sm3, Streebog256, Streebog512, Whirlpool,
        compress, md4, md5,
    };
    use super::{STATE_FORMAT_VERSION, StateError};

    /// A deterministic message long enough to cross several blocks of every
    /// algorithm (the widest block is SHA3-224's 144-byte rate).
    fn message() -> [u8; 700] {
        core::array::from_fn(|i| (i as u8).wrapping_mul(31) ^ (i >> 3) as u8)
    }

    /// Split points around every block size in play.
    const SPLITS: &[usize] = &[
        0, 1, 15, 16, 17, 63, 64, 65, 71, 72, 73, 103, 104, 105, 127, 128, 129, 135, 136, 137, 143,
        144, 145, 167, 168, 169, 255, 256, 257, 500, 700,
    ];

    /// Hash a prefix, export, import into a fresh hasher, finish the message:
    /// must equal the one-shot digest, and re-exporting the imported state
    /// must give the same bytes.
    fn roundtrip<D>()
    where
        D: Digest + ExportableState,
        D::Output: PartialEq + core::fmt::Debug,
    {
        let msg = message();
        let want = D::digest(&msg);
        for &split in SPLITS {
            let mut h = D::new();
            h.update(&msg[..split]);
            let saved = h.export_state();
            assert_eq!(saved.as_ref().len(), D::STATE_LEN);
            assert_eq!(saved.as_ref()[0], STATE_FORMAT_VERSION);
            let mut resumed = D::from_state(saved.as_ref()).expect("own state imports");
            assert_eq!(
                resumed.export_state().as_ref(),
                saved.as_ref(),
                "canonical re-export at split {split}"
            );
            resumed.update(&msg[split..]);
            assert_eq!(resumed.finalize(), want, "split {split}");
            // The exporting hasher itself is untouched.
            h.update(&msg[split..]);
            assert_eq!(h.finalize(), want);
        }
        malformed::<D>();
    }

    /// Generic rejection checks: wrong length, version and tag; plus byte
    /// flips over the whole state, which must never panic (they may
    /// legitimately import when they only touch the chaining value).
    fn malformed<D: Digest + ExportableState>() {
        let mut h = D::new();
        h.update(&message()[..37]);
        let good = h.export_state();
        let good = good.as_ref();

        assert_eq!(
            D::from_state(&good[..good.len() - 1]).err(),
            Some(StateError::InvalidLength)
        );
        assert_eq!(D::from_state(&[]).err(), Some(StateError::InvalidLength));
        let mut long = [0u8; 512];
        long[..good.len()].copy_from_slice(good);
        assert_eq!(
            D::from_state(&long[..good.len() + 1]).err(),
            Some(StateError::InvalidLength)
        );

        let mut bad = [0u8; 512];
        let bad = &mut bad[..good.len()];
        bad.copy_from_slice(good);
        bad[0] ^= 0xff;
        assert_eq!(
            D::from_state(bad).err(),
            Some(StateError::UnsupportedVersion)
        );
        bad.copy_from_slice(good);
        bad[1] ^= 0x80;
        assert_eq!(D::from_state(bad).err(), Some(StateError::WrongAlgorithm));

        for i in 2..good.len() {
            for flip in [0x01u8, 0x80, 0xff] {
                bad.copy_from_slice(good);
                bad[i] ^= flip;
                let _ = D::from_state(bad);
            }
        }
    }

    #[test]
    fn digest_states_round_trip() {
        roundtrip::<Md2>();
        roundtrip::<Md4>();
        roundtrip::<Md5>();
        roundtrip::<Sha1>();
        roundtrip::<Sha224>();
        roundtrip::<Sha256>();
        roundtrip::<Sha384>();
        roundtrip::<Sha512>();
        roundtrip::<Sha512_224>();
        roundtrip::<Sha512_256>();
        roundtrip::<Ripemd160>();
        roundtrip::<Sm3>();
        roundtrip::<Whirlpool>();
        roundtrip::<Streebog256>();
        roundtrip::<Streebog512>();
        roundtrip::<Sha3_224>();
        roundtrip::<Sha3_256>();
        roundtrip::<Sha3_384>();
        roundtrip::<Sha3_512>();
        roundtrip::<Keccak256>();
        roundtrip::<Blake2b256>();
        roundtrip::<Blake2b384>();
        roundtrip::<Blake2b512>();
        roundtrip::<Blake2s256>();
    }

    #[cfg(feature = "legacy-hashes")]
    #[test]
    fn legacy_hashes_states_round_trip() {
        use super::super::{
            Gost94, Gost94CryptoPro, Haval128_3, Haval128_4, Haval128_5, Haval160_3, Haval160_4,
            Haval160_5, Haval192_3, Haval192_4, Haval192_5, Haval224_3, Haval224_4, Haval224_5,
            Haval256_3, Haval256_4, Haval256_5, Ripemd128, Ripemd256, Ripemd320, Snefru256,
            Tiger128_3, Tiger128_4, Tiger160_3, Tiger160_4, Tiger192_3, Tiger192_4,
        };
        roundtrip::<Ripemd128>();
        roundtrip::<Ripemd256>();
        roundtrip::<Ripemd320>();
        roundtrip::<Tiger128_3>();
        roundtrip::<Tiger160_3>();
        roundtrip::<Tiger192_3>();
        roundtrip::<Tiger128_4>();
        roundtrip::<Tiger160_4>();
        roundtrip::<Tiger192_4>();
        roundtrip::<Snefru256>();
        roundtrip::<Gost94>();
        roundtrip::<Gost94CryptoPro>();
        roundtrip::<Haval128_3>();
        roundtrip::<Haval160_3>();
        roundtrip::<Haval192_3>();
        roundtrip::<Haval224_3>();
        roundtrip::<Haval256_3>();
        roundtrip::<Haval128_4>();
        roundtrip::<Haval160_4>();
        roundtrip::<Haval192_4>();
        roundtrip::<Haval224_4>();
        roundtrip::<Haval256_4>();
        roundtrip::<Haval128_5>();
        roundtrip::<Haval160_5>();
        roundtrip::<Haval192_5>();
        roundtrip::<Haval224_5>();
        roundtrip::<Haval256_5>();
    }

    #[cfg(feature = "legacy-hashes")]
    #[test]
    fn legacy_hashes_inconsistent_states_are_rejected() {
        use super::super::{
            Gost94, Gost94CryptoPro, Haval128_3, Haval256_3, Haval256_5, Ripemd128, Snefru256,
            Tiger128_3, Tiger192_3, Tiger192_4,
        };

        // Tiger: header, 3 × u64, u64 byte count, u8 buffered, 64-byte buffer.
        let mut h = Tiger192_3::new();
        h.update(b"abc");
        let good = h.export_state();
        let count = 2 + 24;
        let buffered = count + 8;
        let mut s = good;
        s[count] = 4; // 4 bytes absorbed, 3 buffered
        assert_eq!(
            Tiger192_3::from_state(&s).err(),
            Some(StateError::Inconsistent)
        );
        let mut s = good;
        s[buffered] = 64;
        s[count] = 64;
        assert_eq!(
            Tiger192_3::from_state(&s).err(),
            Some(StateError::Inconsistent)
        );
        let mut s = good;
        s[buffered + 1 + 3] = 1; // stale byte past the buffered data
        assert_eq!(
            Tiger192_3::from_state(&s).err(),
            Some(StateError::Inconsistent)
        );
        let mut s = good;
        s[count..count + 8].copy_from_slice(&(64u64 * 9 + 3).to_le_bytes());
        assert!(Tiger192_3::from_state(&s).is_ok());

        // Snefru and GOST buffer 32-byte blocks; HAVAL 128-byte ones.
        let mut h = Snefru256::new();
        h.update(&[5u8; 40]);
        let mut s = h.export_state();
        s[2 + 32 + 8] = 32;
        assert_eq!(
            Snefru256::from_state(&s).err(),
            Some(StateError::Inconsistent)
        );
        let mut h = Gost94::new();
        h.update(&[5u8; 40]);
        let mut s = h.export_state();
        s[2 + 64] ^= 1; // byte count 41, buffered 8
        assert_eq!(Gost94::from_state(&s).err(), Some(StateError::Inconsistent));
        let mut h = Haval256_3::new();
        h.update(&[5u8; 130]);
        let mut s = h.export_state();
        s[2 + 32 + 8] = 128;
        assert_eq!(
            Haval256_3::from_state(&s).err(),
            Some(StateError::Inconsistent)
        );

        // Each pass count, output length and S-box set has its own tag, even
        // where the layouts coincide.
        let s = Tiger192_3::new().export_state();
        assert_eq!(
            Tiger192_4::from_state(&s).err(),
            Some(StateError::WrongAlgorithm)
        );
        assert_eq!(
            Tiger128_3::from_state(&s).err(),
            Some(StateError::WrongAlgorithm)
        );
        let s = Haval256_3::new().export_state();
        assert_eq!(
            Haval256_5::from_state(&s).err(),
            Some(StateError::WrongAlgorithm)
        );
        assert_eq!(
            Haval128_3::from_state(&s).err(),
            Some(StateError::WrongAlgorithm)
        );
        let s = Gost94::new().export_state();
        assert_eq!(
            Gost94CryptoPro::from_state(&s).err(),
            Some(StateError::WrongAlgorithm)
        );
        let s = Md4::new().export_state();
        assert_eq!(
            Ripemd128::from_state(&s).err(),
            Some(StateError::WrongAlgorithm)
        );

        // The tags are distinct across every exportable algorithm (BLAKE2
        // aside: one tag per family, told apart by the length fields).
        let mut seen = [false; 256];
        for &alg in HashAlgorithm::ALL {
            let mut buf = [0u8; HashAlgorithm::MAX_STATE_LEN];
            if matches!(alg, HashAlgorithm::Blake2b384 | HashAlgorithm::Blake2b512) {
                continue;
            }
            if alg.hasher().export_state(&mut buf).is_ok() {
                assert!(!seen[buf[1] as usize], "{alg}: tag {} reused", buf[1]);
                seen[buf[1] as usize] = true;
            }
        }
    }

    /// A fresh `T` rebuilt from `x`'s exported state.
    fn resumed<T: ExportableState>(x: &T) -> T {
        T::from_state(x.export_state().as_ref()).expect("own state imports")
    }

    /// Round trip for the types whose `update` / finish are not `Digest`'s.
    macro_rules! resume_check {
        ($split:expr, $msg:expr, $out:expr, $make:expr, $finish:ident, $what:literal) => {{
            let mut want = [0u8; $out];
            let mut got = [0u8; $out];
            let mut x = $make;
            x.update($msg);
            x.$finish(&mut want);
            let mut x = $make;
            x.update(&$msg[..$split]);
            let mut y = resumed(&x);
            y.update(&$msg[$split..]);
            y.$finish(&mut got);
            assert_eq!(want[..], got[..], "{} split {}", $what, $split);
        }};
    }

    #[test]
    fn xof_and_mac_states_round_trip() {
        let msg = &message()[..];
        let key = [0x42u8; 40];
        for &split in SPLITS {
            resume_check!(split, msg, 300, Shake128::new(), finalize_into, "SHAKE128");
            resume_check!(split, msg, 300, Shake256::new(), finalize_into, "SHAKE256");
            resume_check!(
                split,
                msg,
                300,
                Blake2xb::new(300),
                finalize_into,
                "BLAKE2Xb"
            );
            resume_check!(
                split,
                msg,
                300,
                Blake2xs::new(300),
                finalize_into,
                "BLAKE2Xs"
            );
            // Keyed, salted and personalized BLAKE2: the parameters live in
            // the chaining value (and the key block in the buffer), so they
            // survive the round trip.
            resume_check!(
                split,
                msg,
                48,
                Blake2bMac::try_new_with_salt_personal(&key, 48, b"salt", b"pers").unwrap(),
                finalize_into,
                "BLAKE2b MAC"
            );
            resume_check!(
                split,
                msg,
                20,
                Blake2sMac::try_new_with_salt_personal(&key[..20], 20, b"s", b"p").unwrap(),
                finalize_into,
                "BLAKE2s MAC"
            );
        }
    }

    #[test]
    fn inconsistent_states_are_rejected() {
        // MD5 layout: header, 4 words, u64 byte count, u8 buffered, buffer.
        let mut h = Md5::new();
        h.update(b"abc");
        let good = h.export_state();
        let count = 2 + 16;
        let buffered = count + 8;

        let mut s = good;
        s[count] = 4; // 4 bytes absorbed, 3 buffered
        assert_eq!(Md5::from_state(&s).err(), Some(StateError::Inconsistent));
        let mut s = good;
        s[buffered] = 64; // a full block never sits in the buffer
        s[count] = 64;
        assert_eq!(Md5::from_state(&s).err(), Some(StateError::Inconsistent));
        let mut s = good;
        s[buffered + 1 + 3] = 1; // stale byte past the buffered data
        assert_eq!(Md5::from_state(&s).err(), Some(StateError::Inconsistent));
        // Any whole number of earlier blocks is fine as long as it agrees.
        let mut s = good;
        s[count..count + 8].copy_from_slice(&(64u64 * 1000 + 3).to_le_bytes());
        assert!(Md5::from_state(&s).is_ok());

        // Whirlpool counts bits.
        let mut h = Whirlpool::new();
        h.update(b"abc");
        let mut s = h.export_state();
        s[2 + 64] = 25; // 25 bits is not whole bytes
        assert_eq!(
            Whirlpool::from_state(&s).err(),
            Some(StateError::Inconsistent)
        );

        // Streebog's N only ever counts whole blocks before finalization.
        let mut h = Streebog256::new();
        h.update(&[7u8; 70]);
        let mut s = h.export_state();
        s[2 + 64] ^= 8;
        assert_eq!(
            Streebog256::from_state(&s).err(),
            Some(StateError::Inconsistent)
        );

        // SHA-3: the buffered count must stay below the rate.
        let mut h = Sha3_256::new();
        h.update(b"abc");
        let mut s = h.export_state();
        s[2 + 200] = 136;
        assert_eq!(
            Sha3_256::from_state(&s).err(),
            Some(StateError::Inconsistent)
        );

        // BLAKE2b: the counter must be whole blocks, a compressed block
        // implies a held-back byte, the digest length must be in range, and
        // the fixed-output types insist on their own length.
        let mut h = Blake2b512::new();
        h.update(&[1u8; 200]);
        let good = h.export_state();
        let t0 = 2 + 64;
        let buffered = t0 + 16;
        let out_len = buffered + 1 + 128;
        let mut s = good;
        s[t0] ^= 1;
        assert_eq!(
            Blake2b512::from_state(&s).err(),
            Some(StateError::Inconsistent)
        );
        let mut s = good;
        s[buffered] = 0;
        s[buffered + 1..buffered + 1 + 128].fill(0);
        assert_eq!(
            Blake2b512::from_state(&s).err(),
            Some(StateError::Inconsistent)
        );
        let mut s = good;
        s[out_len] = 65;
        assert_eq!(
            Blake2bMac::from_state(&s).err(),
            Some(StateError::Inconsistent)
        );
        assert_eq!(
            Blake2b256::from_state(&good).err(),
            Some(StateError::WrongAlgorithm)
        );
        assert_eq!(
            Blake2xb::from_state(&good).err(),
            Some(StateError::WrongAlgorithm)
        );
        // …but the MAC takes any digest length, and computes the same digest.
        let mut m = Blake2bMac::from_state(&good).unwrap();
        m.update(b"tail");
        let mut tag = [0u8; 64];
        m.finalize_into(&mut tag);
        h.update(b"tail");
        assert_eq!(tag, h.finalize());

        // A full held-back block is fine for BLAKE2 (unlike the MD hashes).
        let mut h = Blake2s256::new();
        h.update(&[9u8; 64]);
        let s = h.export_state();
        assert_eq!(s[2 + 32 + 8], 64);
        assert!(Blake2s256::from_state(&s).is_ok());

        // States of one algorithm do not import as another of the same size.
        let s = Sha256::new().export_state();
        assert_eq!(
            Sha224::from_state(&s).err(),
            Some(StateError::WrongAlgorithm)
        );
        assert_eq!(Sm3::from_state(&s).err(), Some(StateError::WrongAlgorithm));
    }

    #[test]
    fn hasher_states_round_trip() {
        let msg = message();
        let mut buf = [0u8; HashAlgorithm::MAX_STATE_LEN];
        let mut widest = 0;
        for &alg in HashAlgorithm::ALL {
            let Some(len) = alg.state_len() else {
                // BLAKE3 is the only digest without an exportable state.
                assert_eq!(alg, HashAlgorithm::Blake3);
                assert_eq!(
                    alg.hasher().export_state(&mut buf).err(),
                    Some(StateError::Unsupported)
                );
                assert_eq!(
                    Hasher::from_state(alg, &buf).err(),
                    Some(StateError::Unsupported)
                );
                continue;
            };
            widest = widest.max(len);
            let mut h = alg.hasher();
            h.update(&msg[..333]);
            assert_eq!(
                h.export_state(&mut buf[..len - 1]).err(),
                Some(StateError::InvalidLength)
            );
            assert_eq!(h.export_state(&mut buf), Ok(len), "{alg}");
            let mut r = Hasher::from_state(alg, &buf[..len]).unwrap();
            r.update(&msg[333..]);
            assert_eq!(r.finalize(), alg.digest(msg), "{alg}");
        }
        assert_eq!(widest, HashAlgorithm::MAX_STATE_LEN);
    }

    fn words32<const W: usize>(s: &[u8]) -> [u32; W] {
        core::array::from_fn(|i| u32::from_le_bytes(s[2 + 4 * i..6 + 4 * i].try_into().unwrap()))
    }

    fn words64(s: &[u8]) -> [u64; 8] {
        core::array::from_fn(|i| u64::from_le_bytes(s[2 + 8 * i..10 + 8 * i].try_into().unwrap()))
    }

    /// The raw compression functions, driven by hand with the standard
    /// padding, reproduce the digests; and each is exactly the step the
    /// exported chaining value advances by over one block.
    #[test]
    fn compression_functions() {
        let mut padded = [0u8; 64];
        padded[..3].copy_from_slice(b"abc");
        padded[3] = 0x80;
        padded[56..].copy_from_slice(&24u64.to_le_bytes());
        let iv = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
        let to_le = |st: [u32; 4]| -> [u8; 16] {
            let mut out = [0u8; 16];
            for (o, w) in out.chunks_exact_mut(4).zip(st) {
                o.copy_from_slice(&w.to_le_bytes());
            }
            out
        };
        let mut st = iv;
        compress::md5(&mut st, &padded);
        assert_eq!(to_le(st), md5(b"abc"));
        let mut st = iv;
        compress::md4(&mut st, &padded);
        assert_eq!(to_le(st), md4(b"abc"));

        let block = [0x61u8; 64];
        macro_rules! one_block_32 {
            ($ty:ty, $f:path, $w:literal) => {{
                let mut st = words32::<$w>(&<$ty>::new().export_state());
                $f(&mut st, &block);
                let mut h = <$ty>::new();
                h.update(&block);
                assert_eq!(st, words32::<$w>(&h.export_state()));
            }};
        }
        one_block_32!(Md4, compress::md4, 4);
        one_block_32!(Md5, compress::md5, 4);
        one_block_32!(Sha1, compress::sha1, 5);
        one_block_32!(Sha224, compress::sha256, 8);
        one_block_32!(Sha256, compress::sha256, 8);
        one_block_32!(Ripemd160, compress::ripemd160, 5);
        one_block_32!(Sm3, compress::sm3, 8);

        let mut st = [0u64; 8];
        compress::whirlpool(&mut st, &block);
        let mut h = Whirlpool::new();
        h.update(&block);
        assert_eq!(st, words64(&h.export_state()));

        let block = [0x62u8; 128];
        let mut st = words64(&Sha384::new().export_state());
        compress::sha512(&mut st, &block);
        let mut h = Sha384::new();
        h.update(&block);
        assert_eq!(st, words64(&h.export_state()));
    }
}
