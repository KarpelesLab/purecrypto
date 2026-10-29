//! Runtime hash selection: the [`HashAlgorithm`] enum, the object-safe
//! [`DynDigest`] trait, and the [`Hasher`] that bridges the two.
//!
//! The [`Digest`] trait is the *static* interface: the algorithm is a type
//! parameter, fixed at compile time. Protocol code often has to go the other
//! way — an algorithm identifier arrives on the wire, in a certificate, on a
//! command line, or through the C ABI, and the hasher has to be chosen at
//! runtime. [`HashAlgorithm`] is that identifier, [`Hasher`] is the resulting
//! state, and [`DynDigest`] is the `dyn`-compatible view both a concrete
//! hasher and a [`Hasher`] can be used through.
//!
//! ```
//! use purecrypto::hash::{Digest, DynDigest, HashAlgorithm, Sha256};
//!
//! // Runtime-selected.
//! let alg: HashAlgorithm = "sha256".parse().unwrap();
//! let digest = alg.digest(b"abc");
//! assert_eq!(digest.len(), 32);
//!
//! // The same bytes through the static hasher, behind `&mut dyn DynDigest`.
//! fn absorb(h: &mut dyn DynDigest, data: &[u8]) {
//!     h.update(data);
//! }
//! let mut h = <Sha256 as Digest>::new();
//! absorb(&mut h, b"abc");
//! let mut out = [0u8; 32];
//! DynDigest::finalize_into(&mut h, &mut out).unwrap();
//! assert_eq!(&out[..], digest.as_slice());
//! ```
//!
//! Everything here is `no_std` and allocation-free: [`Hasher`] is an enum over
//! the concrete hasher states (no `Box<dyn …>` required) and [`HashOutput`] is
//! an inline buffer sized for the widest digest.

use super::{Digest, ExportableState, StateError};

/// Errors from [`DynDigest::finalize_into`]: the output buffer's length did not
/// match the algorithm's digest length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidOutputLen {
    /// The digest length the algorithm produces, in bytes.
    pub expected: usize,
    /// The length of the buffer the caller supplied, in bytes.
    pub got: usize,
}

impl core::fmt::Display for InvalidOutputLen {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "digest output buffer must be exactly {} bytes, got {}",
            self.expected, self.got
        )
    }
}

impl core::error::Error for InvalidOutputLen {}

/// The error from parsing a [`HashAlgorithm`] name that is not recognised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownHashAlgorithm;

impl core::fmt::Display for UnknownHashAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("unknown hash algorithm name")
    }
}

impl core::error::Error for UnknownHashAlgorithm {}

/// A digest value: an inline buffer holding up to
/// [`HashAlgorithm::MAX_OUTPUT_LEN`] bytes plus the actual length.
///
/// Returned by [`HashAlgorithm::digest`] and [`Hasher::finalize`] so a
/// runtime-selected hash can be taken without allocating.
#[derive(Clone, Copy)]
pub struct HashOutput {
    bytes: [u8; HashAlgorithm::MAX_OUTPUT_LEN],
    len: u8,
}

#[allow(clippy::len_without_is_empty)] // never empty: every algorithm has a non-zero output
impl HashOutput {
    /// The digest bytes.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }

    /// The digest length in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }
}

impl AsRef<[u8]> for HashOutput {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl core::ops::Deref for HashOutput {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// Compares in constant time (over the — public — digest length), so a
/// `HashOutput` may be compared against an expected value without leaking where
/// the first difference lies.
impl PartialEq for HashOutput {
    fn eq(&self, other: &Self) -> bool {
        use crate::ct::ConstantTimeEq;
        bool::from(self.as_slice().ct_eq(other.as_slice()))
    }
}

impl Eq for HashOutput {}

impl core::fmt::Debug for HashOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in self.as_slice() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl core::fmt::Display for HashOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(self, f)
    }
}

/// The `dyn`-compatible (object-safe) view of a hash function.
///
/// [`Digest`] fixes the algorithm — and its output length — at compile time.
/// `DynDigest` erases it: the output length becomes a runtime value, so one
/// `&mut dyn DynDigest` can stand for any hasher in the crate, including the
/// runtime-selected [`Hasher`].
///
/// Implemented by every fixed-output hasher in [`crate::hash`] (plus
/// [`AsconHash256`][crate::ascon::AsconHash256] when the `ascon` feature is on)
/// and by [`Hasher`]. Use `<Sha256 as Digest>::new()` for a compile-time
/// algorithm or [`Hasher::new`] for a runtime-selected one.
///
/// Unlike [`Digest::finalize`], which consumes the hasher,
/// [`finalize_into`](DynDigest::finalize_into) takes `&mut self` — an
/// object-safe signature cannot consume `Self` without a `Box` — and resets the
/// hasher to its initial state, so the same object can hash another message.
///
/// # Ambiguity with `Digest`
///
/// A concrete hasher implements both traits, so with `Digest` *and* `DynDigest`
/// in scope a bare `h.update(…)` is ambiguous. Disambiguate with
/// `Digest::update(&mut h, …)`, or import only the one being used.
#[cfg_attr(
    not(feature = "ascon"),
    doc = "",
    doc = "[crate::ascon::AsconHash256]: crate"
)]
pub trait DynDigest {
    /// The digest output length, in bytes.
    fn output_len(&self) -> usize;

    /// The internal block length, in bytes.
    fn block_len(&self) -> usize;

    /// The algorithm this hasher computes, if it is one [`HashAlgorithm`]
    /// names. Defaults to `None` for hashers outside that set.
    fn algorithm(&self) -> Option<HashAlgorithm> {
        None
    }

    /// Feeds `data` into the hasher. May be called any number of times.
    fn update(&mut self, data: &[u8]);

    /// Writes the digest of everything absorbed so far into `out` and resets
    /// the hasher to its initial state.
    ///
    /// `out.len()` must be exactly [`output_len`](DynDigest::output_len) — a
    /// mismatch returns [`InvalidOutputLen`] and leaves the hasher untouched,
    /// rather than silently truncating a digest to a length that would be
    /// cheaper to forge.
    fn finalize_into(&mut self, out: &mut [u8]) -> Result<(), InvalidOutputLen>;

    /// Discards the absorbed data, returning the hasher to its initial state.
    fn reset(&mut self);

    /// Best-effort wipe of the hasher's internal state (see
    /// [`Digest::zeroize`]).
    fn zeroize(&mut self);
}

/// Generates the [`DynDigest`] impl for a concrete [`Digest`] type.
///
/// A blanket `impl<D: Digest> DynDigest for D` would be preferable, but it
/// would overlap with the [`Hasher`] impl (coherence cannot rule out a future
/// `impl Digest for Hasher`), so each hasher gets its own generated impl.
macro_rules! impl_dyn_digest {
    ($ty:ty $(, $alg:expr)?) => {
        impl $crate::hash::DynDigest for $ty {
            #[inline]
            fn output_len(&self) -> usize {
                <$ty as $crate::hash::Digest>::OUTPUT_LEN
            }
            #[inline]
            fn block_len(&self) -> usize {
                <$ty as $crate::hash::Digest>::BLOCK_LEN
            }
            $(
                #[inline]
                fn algorithm(&self) -> Option<$crate::hash::HashAlgorithm> {
                    Some($alg)
                }
            )?
            #[inline]
            fn update(&mut self, data: &[u8]) {
                <$ty as $crate::hash::Digest>::update(self, data)
            }
            fn finalize_into(
                &mut self,
                out: &mut [u8],
            ) -> Result<(), $crate::hash::InvalidOutputLen> {
                let expected = <$ty as $crate::hash::Digest>::OUTPUT_LEN;
                if out.len() != expected {
                    return Err($crate::hash::InvalidOutputLen {
                        expected,
                        got: out.len(),
                    });
                }
                let fresh = <$ty as $crate::hash::Digest>::new();
                let digest =
                    <$ty as $crate::hash::Digest>::finalize(core::mem::replace(self, fresh));
                out.copy_from_slice(digest.as_ref());
                Ok(())
            }
            #[inline]
            fn reset(&mut self) {
                let mut old =
                    core::mem::replace(self, <$ty as $crate::hash::Digest>::new());
                <$ty as $crate::hash::Digest>::zeroize(&mut old);
            }
            #[inline]
            fn zeroize(&mut self) {
                <$ty as $crate::hash::Digest>::zeroize(self)
            }
        }
    };
}

pub(crate) use impl_dyn_digest;

/// Defines [`HashAlgorithm`], its per-variant metadata, and the [`Hasher`]
/// state enum from one table, so the algorithm list is stated exactly once.
/// An entry may carry one `#[cfg(...)]` (after its doc comment), which then
/// gates the variant and every arm generated for it.
macro_rules! hash_algorithms {
    ($(
        $(#[doc = $doc:literal])*
        $(#[cfg($cfg:meta)])?
        $variant:ident => $ty:ty, $name:literal $(| $alias:literal)*, legacy: $legacy:literal;
    )*) => {
        /// A hash function selected at runtime.
        ///
        /// Covers every fixed-output digest in [`crate::hash`].
        /// Extendable-output functions (SHAKE, cSHAKE, KangarooTwelve, the
        /// BLAKE2X family) are *not* listed: their output length is a caller
        /// choice rather than a property of the algorithm, so they do not fit
        /// the fixed-length contract this enum and [`DynDigest`] promise.
        /// [`Blake3`](crate::hash::Blake3) appears in its 32-byte digest form
        /// only.
        ///
        /// `#[non_exhaustive]`, so adding a digest stays a minor release:
        /// downstream `match`es need a `_` arm. Enumerate the variants of the
        /// build you compiled against with [`ALL`](HashAlgorithm::ALL) rather
        /// than by hand.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[non_exhaustive]
        pub enum HashAlgorithm {
            $( $(#[doc = $doc])* $(#[cfg($cfg)])? $variant, )*
        }

        impl HashAlgorithm {
            /// Every algorithm this enum names, in declaration order.
            pub const ALL: &'static [HashAlgorithm] = &[$($(#[cfg($cfg)])? HashAlgorithm::$variant,)*];

            /// The digest output length, in bytes.
            pub const fn output_len(self) -> usize {
                match self {
                    $($(#[cfg($cfg)])? HashAlgorithm::$variant => <$ty as Digest>::OUTPUT_LEN,)*
                }
            }

            /// The internal block length (the rate, for the sponge
            /// constructions), in bytes.
            pub const fn block_len(self) -> usize {
                match self {
                    $($(#[cfg($cfg)])? HashAlgorithm::$variant => <$ty as Digest>::BLOCK_LEN,)*
                }
            }

            /// The canonical lowercase name, e.g. `"sha256"`, `"sha3-512"`,
            /// `"blake2b512"`. Round-trips through
            /// [`from_name`](HashAlgorithm::from_name).
            pub const fn name(self) -> &'static str {
                match self {
                    $($(#[cfg($cfg)])? HashAlgorithm::$variant => $name,)*
                }
            }

            /// Whether the algorithm is kept only for interop and must not be
            /// used for new signatures or commitments — the digests with
            /// broken (MD2, MD4, MD5, SHA-1) or sub-128-bit (RIPEMD-160)
            /// collision resistance, and every digest of the `legacy-hashes`
            /// feature.
            pub const fn is_legacy(self) -> bool {
                match self {
                    $($(#[cfg($cfg)])? HashAlgorithm::$variant => $legacy,)*
                }
            }

            /// Looks an algorithm up by name, ASCII-case-insensitively.
            ///
            /// Accepts the canonical [`name`](HashAlgorithm::name) plus the
            /// common spellings (`"sha-256"`, `"sha2-256"`, `"sha512/256"`, …).
            pub fn from_name(name: &str) -> Option<Self> {
                $(
                    $(#[cfg($cfg)])?
                    if name.eq_ignore_ascii_case($name)
                        $(|| name.eq_ignore_ascii_case($alias))*
                    {
                        return Some(HashAlgorithm::$variant);
                    }
                )*
                None
            }

            /// A [`Hasher`] for this algorithm, in its initial state.
            pub fn hasher(self) -> Hasher {
                Hasher(match self {
                    $(
                        $(#[cfg($cfg)])?
                        HashAlgorithm::$variant => HasherState::$variant(<$ty as Digest>::new()),
                    )*
                })
            }
        }

        // The runtime hasher state. Private: the variants are an
        // implementation detail, so adding an algorithm is not a breaking
        // change for `Hasher`'s users.
        #[allow(clippy::large_enum_variant)]
        #[derive(Clone)]
        enum HasherState {
            $( $(#[cfg($cfg)])? $variant($ty), )*
        }

        impl Hasher {
            /// The algorithm being computed.
            pub fn algorithm(&self) -> HashAlgorithm {
                match &self.0 {
                    $($(#[cfg($cfg)])? HasherState::$variant(_) => HashAlgorithm::$variant,)*
                }
            }

            // The monomorphic core of `update`; the public generic wrapper
            // funnels every input shape through this one match.
            fn update_bytes(&mut self, data: &[u8]) {
                match &mut self.0 {
                    $($(#[cfg($cfg)])? HasherState::$variant(h) => Digest::update(h, data),)*
                }
            }

            /// Best-effort wipe of the internal state. Called on drop.
            pub fn zeroize(&mut self) {
                match &mut self.0 {
                    $($(#[cfg($cfg)])? HasherState::$variant(h) => Digest::zeroize(h),)*
                }
            }

            // Writes the digest into `out` (whose length the callers above
            // have already checked against `output_len`) and resets the state.
            fn finalize_reset_into(&mut self, out: &mut [u8]) {
                match &mut self.0 {
                    $($(#[cfg($cfg)])? HasherState::$variant(h) => {
                        let fresh = <$ty as Digest>::new();
                        let digest = Digest::finalize(core::mem::replace(h, fresh));
                        out.copy_from_slice(digest.as_ref());
                    })*
                }
            }
        }

        $( $(#[cfg($cfg)])? impl_dyn_digest!($ty, HashAlgorithm::$variant); )*
    };
}

hash_algorithms! {
    /// SHA-224 (FIPS 180-4).
    Sha224 => crate::hash::Sha224, "sha224" | "sha-224" | "sha2-224", legacy: false;
    /// SHA-256 (FIPS 180-4).
    Sha256 => crate::hash::Sha256, "sha256" | "sha-256" | "sha2-256", legacy: false;
    /// SHA-384 (FIPS 180-4).
    Sha384 => crate::hash::Sha384, "sha384" | "sha-384" | "sha2-384", legacy: false;
    /// SHA-512 (FIPS 180-4).
    Sha512 => crate::hash::Sha512, "sha512" | "sha-512" | "sha2-512", legacy: false;
    /// SHA-512/224 (FIPS 180-4).
    Sha512_224 => crate::hash::Sha512_224, "sha512-224" | "sha512/224" | "sha-512/224", legacy: false;
    /// SHA-512/256 (FIPS 180-4).
    Sha512_256 => crate::hash::Sha512_256, "sha512-256" | "sha512/256" | "sha-512/256", legacy: false;
    /// SHA3-224 (FIPS 202).
    Sha3_224 => crate::hash::Sha3_224, "sha3-224" | "sha3_224", legacy: false;
    /// SHA3-256 (FIPS 202).
    Sha3_256 => crate::hash::Sha3_256, "sha3-256" | "sha3_256", legacy: false;
    /// SHA3-384 (FIPS 202).
    Sha3_384 => crate::hash::Sha3_384, "sha3-384" | "sha3_384", legacy: false;
    /// SHA3-512 (FIPS 202).
    Sha3_512 => crate::hash::Sha3_512, "sha3-512" | "sha3_512", legacy: false;
    /// Keccak-256 — the original padding, as used by Ethereum.
    Keccak256 => crate::hash::Keccak256, "keccak256" | "keccak-256", legacy: false;
    /// BLAKE2b with a 256-bit output (RFC 7693).
    Blake2b256 => crate::hash::Blake2b256, "blake2b256" | "blake2b-256", legacy: false;
    /// BLAKE2b with a 384-bit output (RFC 7693).
    Blake2b384 => crate::hash::Blake2b384, "blake2b384" | "blake2b-384", legacy: false;
    /// BLAKE2b with a 512-bit output (RFC 7693).
    Blake2b512 => crate::hash::Blake2b512, "blake2b512" | "blake2b-512" | "blake2b", legacy: false;
    /// BLAKE2s with a 256-bit output (RFC 7693).
    Blake2s256 => crate::hash::Blake2s256, "blake2s256" | "blake2s-256" | "blake2s", legacy: false;
    /// BLAKE3, in its default 32-byte digest form.
    Blake3 => crate::hash::Blake3, "blake3", legacy: false;
    /// SM3 (GB/T 32905-2016) — the Chinese national digest.
    Sm3 => crate::hash::Sm3, "sm3", legacy: false;
    /// Streebog-256 (GOST R 34.11-2012).
    Streebog256 => crate::hash::Streebog256, "streebog256" | "streebog-256", legacy: false;
    /// Streebog-512 (GOST R 34.11-2012).
    Streebog512 => crate::hash::Streebog512, "streebog512" | "streebog-512", legacy: false;
    /// Whirlpool (ISO/IEC 10118-3).
    Whirlpool => crate::hash::Whirlpool, "whirlpool", legacy: false;
    /// RIPEMD-160 — legacy; 160-bit output, below the 128-bit collision bar.
    Ripemd160 => crate::hash::Ripemd160, "ripemd160" | "ripemd-160", legacy: true;
    /// SHA-1 — legacy interop only; collisions are practical (SHAttered).
    Sha1 => crate::hash::Sha1, "sha1" | "sha-1", legacy: true;
    /// MD5 — legacy interop only; collisions are trivial.
    Md5 => crate::hash::Md5, "md5", legacy: true;
    /// MD4 — legacy interop only; thoroughly broken.
    Md4 => crate::hash::Md4, "md4", legacy: true;
    /// MD2 — legacy interop only; thoroughly broken.
    Md2 => crate::hash::Md2, "md2", legacy: true;
    /// RIPEMD-128 — legacy; 128-bit output.
    #[cfg(feature = "legacy-hashes")]
    Ripemd128 => crate::hash::Ripemd128, "ripemd128" | "ripemd-128", legacy: true;
    /// RIPEMD-256 — legacy; RIPEMD-128's security with a longer output.
    #[cfg(feature = "legacy-hashes")]
    Ripemd256 => crate::hash::Ripemd256, "ripemd256" | "ripemd-256", legacy: true;
    /// RIPEMD-320 — legacy; RIPEMD-160's security with a longer output.
    #[cfg(feature = "legacy-hashes")]
    Ripemd320 => crate::hash::Ripemd320, "ripemd320" | "ripemd-320", legacy: true;
    /// Tiger, 3 passes, 128-bit truncation — legacy.
    #[cfg(feature = "legacy-hashes")]
    Tiger128_3 => crate::hash::Tiger128_3, "tiger128,3" | "tiger128-3", legacy: true;
    /// Tiger, 3 passes, 160-bit truncation — legacy.
    #[cfg(feature = "legacy-hashes")]
    Tiger160_3 => crate::hash::Tiger160_3, "tiger160,3" | "tiger160-3", legacy: true;
    /// Tiger, 3 passes, 192-bit (the original Tiger) — legacy.
    #[cfg(feature = "legacy-hashes")]
    Tiger192_3 => crate::hash::Tiger192_3, "tiger192,3" | "tiger192-3" | "tiger192" | "tiger", legacy: true;
    /// Tiger, 4 passes, 128-bit truncation — legacy.
    #[cfg(feature = "legacy-hashes")]
    Tiger128_4 => crate::hash::Tiger128_4, "tiger128,4" | "tiger128-4", legacy: true;
    /// Tiger, 4 passes, 160-bit truncation — legacy.
    #[cfg(feature = "legacy-hashes")]
    Tiger160_4 => crate::hash::Tiger160_4, "tiger160,4" | "tiger160-4", legacy: true;
    /// Tiger, 4 passes, 192-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Tiger192_4 => crate::hash::Tiger192_4, "tiger192,4" | "tiger192-4", legacy: true;
    /// Snefru-256, 8 passes — legacy.
    #[cfg(feature = "legacy-hashes")]
    Snefru256 => crate::hash::Snefru256, "snefru" | "snefru256" | "snefru-256", legacy: true;
    /// GOST R 34.11-94, test parameter S-boxes — legacy.
    #[cfg(feature = "legacy-hashes")]
    Gost94 => crate::hash::Gost94, "gost" | "gost94" | "gostr3411-94", legacy: true;
    /// GOST R 34.11-94, CryptoPro S-boxes (RFC 4357) — legacy.
    #[cfg(feature = "legacy-hashes")]
    Gost94CryptoPro => crate::hash::Gost94CryptoPro, "gost-crypto" | "gost94-cryptopro", legacy: true;
    /// HAVAL, 3 passes, 128-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval128_3 => crate::hash::Haval128_3, "haval128,3" | "haval128-3", legacy: true;
    /// HAVAL, 3 passes, 160-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval160_3 => crate::hash::Haval160_3, "haval160,3" | "haval160-3", legacy: true;
    /// HAVAL, 3 passes, 192-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval192_3 => crate::hash::Haval192_3, "haval192,3" | "haval192-3", legacy: true;
    /// HAVAL, 3 passes, 224-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval224_3 => crate::hash::Haval224_3, "haval224,3" | "haval224-3", legacy: true;
    /// HAVAL, 3 passes, 256-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval256_3 => crate::hash::Haval256_3, "haval256,3" | "haval256-3", legacy: true;
    /// HAVAL, 4 passes, 128-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval128_4 => crate::hash::Haval128_4, "haval128,4" | "haval128-4", legacy: true;
    /// HAVAL, 4 passes, 160-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval160_4 => crate::hash::Haval160_4, "haval160,4" | "haval160-4", legacy: true;
    /// HAVAL, 4 passes, 192-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval192_4 => crate::hash::Haval192_4, "haval192,4" | "haval192-4", legacy: true;
    /// HAVAL, 4 passes, 224-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval224_4 => crate::hash::Haval224_4, "haval224,4" | "haval224-4", legacy: true;
    /// HAVAL, 4 passes, 256-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval256_4 => crate::hash::Haval256_4, "haval256,4" | "haval256-4", legacy: true;
    /// HAVAL, 5 passes, 128-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval128_5 => crate::hash::Haval128_5, "haval128,5" | "haval128-5", legacy: true;
    /// HAVAL, 5 passes, 160-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval160_5 => crate::hash::Haval160_5, "haval160,5" | "haval160-5", legacy: true;
    /// HAVAL, 5 passes, 192-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval192_5 => crate::hash::Haval192_5, "haval192,5" | "haval192-5", legacy: true;
    /// HAVAL, 5 passes, 224-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval224_5 => crate::hash::Haval224_5, "haval224,5" | "haval224-5", legacy: true;
    /// HAVAL, 5 passes, 256-bit — legacy.
    #[cfg(feature = "legacy-hashes")]
    Haval256_5 => crate::hash::Haval256_5, "haval256,5" | "haval256-5", legacy: true;
}

/// Bridges a runtime [`HashAlgorithm`] into code that is generic over a
/// compile-time [`Digest`] type: runs `$body` once per algorithm, with `$d`
/// aliased to that algorithm's concrete hasher.
///
/// [`Hasher`] covers the case where a hasher *object* is enough. It cannot
/// serve `Hmac<D>`, `hkdf::<D>`, `pbkdf2::<D>`, `sign_pss::<D>` and friends,
/// which need the digest as a *type* — that is what this macro is for:
///
/// ```
/// use purecrypto::hash::{Digest, HashAlgorithm, Hmac, Mac};
/// use purecrypto::dispatch_digest;
///
/// fn hmac(alg: HashAlgorithm, key: &[u8], msg: &[u8]) -> Option<[u8; 64]> {
///     let mut tag = [0u8; 64];
///     dispatch_digest!(alg, |D| {
///         let mut m = Hmac::<D>::new(key);
///         Mac::update(&mut m, msg);
///         Mac::finalize_into(m, &mut tag[..<D as Digest>::OUTPUT_LEN]);
///     }, _ => return None);
///     Some(tag)
/// }
/// # assert!(hmac(HashAlgorithm::Sha256, b"k", b"m").is_some());
/// ```
///
/// The `_ =>` arm is required: [`HashAlgorithm`] is `#[non_exhaustive]`, so a
/// build against a newer `purecrypto` may hand you a variant this macro's
/// caller was not compiled for. It is also the hook for refusing digests a
/// scheme has no encoding for.
///
/// `$body` is instantiated once per algorithm, so a large body costs code
/// size. To dispatch over a subset, `match` the algorithm first and call this
/// only on the arm you accept.
#[macro_export]
macro_rules! dispatch_digest {
    ($alg:expr, |$d:ident| $body:block, _ => $fallback:expr $(,)?) => {
        match $alg {
            $crate::hash::HashAlgorithm::Sha224 => {
                type $d = $crate::hash::Sha224;
                $body
            }
            $crate::hash::HashAlgorithm::Sha256 => {
                type $d = $crate::hash::Sha256;
                $body
            }
            $crate::hash::HashAlgorithm::Sha384 => {
                type $d = $crate::hash::Sha384;
                $body
            }
            $crate::hash::HashAlgorithm::Sha512 => {
                type $d = $crate::hash::Sha512;
                $body
            }
            $crate::hash::HashAlgorithm::Sha512_224 => {
                type $d = $crate::hash::Sha512_224;
                $body
            }
            $crate::hash::HashAlgorithm::Sha512_256 => {
                type $d = $crate::hash::Sha512_256;
                $body
            }
            $crate::hash::HashAlgorithm::Sha3_224 => {
                type $d = $crate::hash::Sha3_224;
                $body
            }
            $crate::hash::HashAlgorithm::Sha3_256 => {
                type $d = $crate::hash::Sha3_256;
                $body
            }
            $crate::hash::HashAlgorithm::Sha3_384 => {
                type $d = $crate::hash::Sha3_384;
                $body
            }
            $crate::hash::HashAlgorithm::Sha3_512 => {
                type $d = $crate::hash::Sha3_512;
                $body
            }
            $crate::hash::HashAlgorithm::Keccak256 => {
                type $d = $crate::hash::Keccak256;
                $body
            }
            $crate::hash::HashAlgorithm::Blake2b256 => {
                type $d = $crate::hash::Blake2b256;
                $body
            }
            $crate::hash::HashAlgorithm::Blake2b384 => {
                type $d = $crate::hash::Blake2b384;
                $body
            }
            $crate::hash::HashAlgorithm::Blake2b512 => {
                type $d = $crate::hash::Blake2b512;
                $body
            }
            $crate::hash::HashAlgorithm::Blake2s256 => {
                type $d = $crate::hash::Blake2s256;
                $body
            }
            $crate::hash::HashAlgorithm::Blake3 => {
                type $d = $crate::hash::Blake3;
                $body
            }
            $crate::hash::HashAlgorithm::Sm3 => {
                type $d = $crate::hash::Sm3;
                $body
            }
            $crate::hash::HashAlgorithm::Streebog256 => {
                type $d = $crate::hash::Streebog256;
                $body
            }
            $crate::hash::HashAlgorithm::Streebog512 => {
                type $d = $crate::hash::Streebog512;
                $body
            }
            $crate::hash::HashAlgorithm::Whirlpool => {
                type $d = $crate::hash::Whirlpool;
                $body
            }
            $crate::hash::HashAlgorithm::Ripemd160 => {
                type $d = $crate::hash::Ripemd160;
                $body
            }
            $crate::hash::HashAlgorithm::Sha1 => {
                type $d = $crate::hash::Sha1;
                $body
            }
            $crate::hash::HashAlgorithm::Md5 => {
                type $d = $crate::hash::Md5;
                $body
            }
            $crate::hash::HashAlgorithm::Md4 => {
                type $d = $crate::hash::Md4;
                $body
            }
            $crate::hash::HashAlgorithm::Md2 => {
                type $d = $crate::hash::Md2;
                $body
            }
            // The `legacy-hashes` variants exist only when *this* crate was
            // built with that feature, which a `cfg` written here would test
            // against the caller's features instead; the helper below is
            // defined per this crate's build. Past those, the fallback is
            // reachable only for a caller outside this crate (where the
            // `#[non_exhaustive]` enum may carry a newer variant); in-crate
            // uses cover every variant, so silence the lint there.
            #[allow(unreachable_patterns)]
            __other => $crate::__dispatch_digest_legacy!(__other, |$d| $body, _ => $fallback),
        }
    };
}

/// The `legacy-hashes` arms of [`dispatch_digest!`]; not public API.
#[cfg(feature = "legacy-hashes")]
#[doc(hidden)]
#[macro_export]
macro_rules! __dispatch_digest_legacy {
    ($alg:expr, |$d:ident| $body:block, _ => $fallback:expr) => {
        $crate::__dispatch_digest_legacy!(@arms $alg, $d, $body, $fallback;
            Ripemd128 Ripemd256 Ripemd320
            Tiger128_3 Tiger160_3 Tiger192_3 Tiger128_4 Tiger160_4 Tiger192_4
            Snefru256 Gost94 Gost94CryptoPro
            Haval128_3 Haval160_3 Haval192_3 Haval224_3 Haval256_3
            Haval128_4 Haval160_4 Haval192_4 Haval224_4 Haval256_4
            Haval128_5 Haval160_5 Haval192_5 Haval224_5 Haval256_5)
    };
    (@arms $alg:expr, $d:ident, $body:block, $fallback:expr; $($v:ident)*) => {
        match $alg {
            $(
                $crate::hash::HashAlgorithm::$v => {
                    type $d = $crate::hash::$v;
                    $body
                }
            )*
            #[allow(unreachable_patterns)]
            _ => $fallback,
        }
    };
}

/// Without `legacy-hashes` there are no further arms: straight to the
/// fallback.
#[cfg(not(feature = "legacy-hashes"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __dispatch_digest_legacy {
    ($alg:expr, |$d:ident| $body:block, _ => $fallback:expr) => {{
        let _ = $alg;
        $fallback
    }};
}

impl HashAlgorithm {
    /// The widest [`output_len`](HashAlgorithm::output_len) of any variant, and
    /// so the capacity of a [`HashOutput`].
    pub const MAX_OUTPUT_LEN: usize = 64;

    /// The widest [`block_len`](HashAlgorithm::block_len) of any variant (the
    /// SHA3-224 rate).
    pub const MAX_BLOCK_LEN: usize = 144;

    /// Hashes `data` in one call.
    ///
    /// Takes anything byte-like — `&[u8]`, `[u8; N]`, `&str`, `String`,
    /// `Vec<u8>` — so `HashAlgorithm::Sha256.digest("hello")` and
    /// `alg.digest(&buf)` both work. The result is a [`HashOutput`], which
    /// derefs to `&[u8]` and `Display`s as lowercase hex.
    pub fn digest(self, data: impl AsRef<[u8]>) -> HashOutput {
        let mut h = self.hasher();
        h.update(data);
        h.finalize()
    }

    /// Hashes `data` in one call, writing into `out`.
    ///
    /// `out.len()` must be exactly [`output_len`](HashAlgorithm::output_len).
    pub fn digest_into(
        self,
        data: impl AsRef<[u8]>,
        out: &mut [u8],
    ) -> Result<(), InvalidOutputLen> {
        let mut h = self.hasher();
        h.update(data);
        DynDigest::finalize_into(&mut h, out)
    }

    /// Hashes the concatenation of `parts`, without joining them into one
    /// buffer first.
    pub fn digest_parts<'a>(self, parts: impl IntoIterator<Item = &'a [u8]>) -> HashOutput {
        let mut h = self.hasher();
        for part in parts {
            h.update(part);
        }
        h.finalize()
    }
}

impl core::fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl core::str::FromStr for HashAlgorithm {
    type Err = UnknownHashAlgorithm;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        HashAlgorithm::from_name(s).ok_or(UnknownHashAlgorithm)
    }
}

/// A hash function chosen at runtime: the state of a [`HashAlgorithm`]'s
/// hasher, with the same streaming interface as [`Digest`].
///
/// Obtain one with [`HashAlgorithm::hasher`] or [`Hasher::new`]. The state is
/// held inline (no allocation), so the struct is as large as the widest hasher
/// it can hold — around 2 KiB, dominated by BLAKE3's chunk stack. Prefer the
/// concrete types when the algorithm is known at compile time, and box (or
/// heap-allocate) a `Hasher` that would otherwise sit on a small stack.
///
/// The internal state is wiped on drop.
pub struct Hasher(HasherState);

impl Hasher {
    /// A hasher for `alg`, in its initial state.
    pub fn new(alg: HashAlgorithm) -> Self {
        alg.hasher()
    }

    /// The digest output length, in bytes.
    pub fn output_len(&self) -> usize {
        self.algorithm().output_len()
    }

    /// The internal block length, in bytes.
    pub fn block_len(&self) -> usize {
        self.algorithm().block_len()
    }

    /// Feeds `data` into the hasher. May be called any number of times, and
    /// takes anything byte-like (`&[u8]`, `[u8; N]`, `&str`, `String`,
    /// `Vec<u8>`); the digest depends only on the concatenated bytes, not on
    /// how they were chunked.
    #[inline]
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.update_bytes(data.as_ref());
    }

    /// [`update`](Hasher::update) as a builder step, for one-liners:
    /// `alg.hasher().chain("a").chain(b).finalize()`.
    #[must_use]
    pub fn chain(mut self, data: impl AsRef<[u8]>) -> Self {
        self.update_bytes(data.as_ref());
        self
    }

    /// Consumes the hasher and returns the digest.
    pub fn finalize(mut self) -> HashOutput {
        self.finalize_reset()
    }

    /// Returns the digest of everything absorbed so far and resets the hasher
    /// to its initial state, so it can hash another message.
    pub fn finalize_reset(&mut self) -> HashOutput {
        let len = self.output_len();
        let mut out = HashOutput {
            bytes: [0u8; HashAlgorithm::MAX_OUTPUT_LEN],
            len: len as u8,
        };
        self.finalize_reset_into(&mut out.bytes[..len]);
        out
    }

    /// Discards the absorbed data, returning the hasher to its initial state.
    pub fn reset(&mut self) {
        self.zeroize();
        *self = Hasher::new(self.algorithm());
    }
}

impl Clone for Hasher {
    fn clone(&self) -> Self {
        Hasher(self.0.clone())
    }
}

/// Runs `$m!` over every [`HashAlgorithm`] variant whose hasher implements
/// [`ExportableState`] (all but BLAKE3).
macro_rules! exportable_algorithms {
    ($m:ident) => {
        $m!(
            Sha224,
            Sha256,
            Sha384,
            Sha512,
            Sha512_224,
            Sha512_256,
            Sha3_224,
            Sha3_256,
            Sha3_384,
            Sha3_512,
            Keccak256,
            Blake2b256,
            Blake2b384,
            Blake2b512,
            Blake2s256,
            Sm3,
            Streebog256,
            Streebog512,
            Whirlpool,
            Ripemd160,
            Sha1,
            Md5,
            Md4,
            Md2
        )
    };
}

impl HashAlgorithm {
    /// The largest [`state_len`](HashAlgorithm::state_len) of any variant
    /// (SHA3-224, whose rate-sized buffer is the widest).
    pub const MAX_STATE_LEN: usize = 347;

    /// Length of this algorithm's [exported state](Hasher::export_state), or
    /// `None` when its state cannot be exported (BLAKE3 and the
    /// `legacy-hashes` digests).
    pub const fn state_len(self) -> Option<usize> {
        macro_rules! arms {
            ($($v:ident),*) => {
                match self {
                    $(HashAlgorithm::$v => {
                        Some(<crate::hash::$v as ExportableState>::STATE_LEN)
                    })*
                    // BLAKE3 and the `legacy-hashes` digests.
                    _ => None,
                }
            };
        }
        exportable_algorithms!(arms)
    }
}

impl Hasher {
    /// Serializes the current state into `out` (see [`ExportableState`] for
    /// the format) and returns the number of bytes written,
    /// [`state_len`](HashAlgorithm::state_len).
    ///
    /// Fails with [`StateError::InvalidLength`] when `out` is shorter than
    /// that, and with [`StateError::Unsupported`] for BLAKE3 and the
    /// `legacy-hashes` digests. A buffer of
    /// [`HashAlgorithm::MAX_STATE_LEN`] bytes fits every algorithm.
    pub fn export_state(&self, out: &mut [u8]) -> Result<usize, StateError> {
        macro_rules! arms {
            ($($v:ident),*) => {
                match &self.0 {
                    $(HasherState::$v(h) => {
                        let state = ExportableState::export_state(h);
                        let state = state.as_ref();
                        let dst = out.get_mut(..state.len()).ok_or(StateError::InvalidLength)?;
                        dst.copy_from_slice(state);
                        Ok(state.len())
                    })*
                    _ => Err(StateError::Unsupported),
                }
            };
        }
        exportable_algorithms!(arms)
    }

    /// Rebuilds a hasher for `alg` from a state written by
    /// [`export_state`](Self::export_state) (or by the concrete type's
    /// [`ExportableState::export_state`]; the bytes are the same).
    pub fn from_state(alg: HashAlgorithm, state: &[u8]) -> Result<Hasher, StateError> {
        macro_rules! arms {
            ($($v:ident),*) => {
                match alg {
                    $(HashAlgorithm::$v => Ok(Hasher(HasherState::$v(
                        <crate::hash::$v as ExportableState>::from_state(state)?,
                    ))),)*
                    _ => Err(StateError::Unsupported),
                }
            };
        }
        exportable_algorithms!(arms)
    }
}

impl core::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The absorbed state may be secret; print only the algorithm.
        f.debug_tuple("Hasher").field(&self.algorithm()).finish()
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Hashes formatted text: `write!(hasher, "{id}:{n}")` absorbs the rendered
/// UTF-8 without building a `String` first.
impl core::fmt::Write for Hasher {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.update_bytes(s.as_bytes());
        Ok(())
    }
}

/// Hashes an I/O stream: `std::io::copy(&mut file, &mut hasher)` digests a file
/// without reading it into memory. Writes always succeed; `flush` is a no-op.
#[cfg(feature = "std")]
impl std::io::Write for Hasher {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.update_bytes(buf);
        Ok(buf.len())
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.update_bytes(buf);
        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl DynDigest for Hasher {
    fn output_len(&self) -> usize {
        Hasher::output_len(self)
    }

    fn block_len(&self) -> usize {
        Hasher::block_len(self)
    }

    fn algorithm(&self) -> Option<HashAlgorithm> {
        Some(Hasher::algorithm(self))
    }

    fn update(&mut self, data: &[u8]) {
        self.update_bytes(data)
    }

    fn finalize_into(&mut self, out: &mut [u8]) -> Result<(), InvalidOutputLen> {
        let expected = self.output_len();
        if out.len() != expected {
            return Err(InvalidOutputLen {
                expected,
                got: out.len(),
            });
        }
        self.finalize_reset_into(out);
        Ok(())
    }

    fn reset(&mut self) {
        Hasher::reset(self)
    }

    fn zeroize(&mut self) {
        Hasher::zeroize(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{Sha256, Sha512};

    #[test]
    fn metadata_matches_the_concrete_hashers() {
        for &alg in HashAlgorithm::ALL {
            let h = alg.hasher();
            assert_eq!(h.algorithm(), alg);
            assert_eq!(h.output_len(), alg.output_len(), "{alg}");
            assert_eq!(h.block_len(), alg.block_len(), "{alg}");
            assert!(alg.output_len() > 0 && alg.output_len() <= HashAlgorithm::MAX_OUTPUT_LEN);
            assert!(alg.block_len() > 0 && alg.block_len() <= HashAlgorithm::MAX_BLOCK_LEN);
            assert_eq!(alg.digest(b"abc").len(), alg.output_len(), "{alg}");
        }
        // The declared maxima are tight.
        assert_eq!(
            HashAlgorithm::ALL
                .iter()
                .map(|a| a.output_len())
                .max()
                .unwrap(),
            HashAlgorithm::MAX_OUTPUT_LEN
        );
        assert_eq!(
            HashAlgorithm::ALL
                .iter()
                .map(|a| a.block_len())
                .max()
                .unwrap(),
            HashAlgorithm::MAX_BLOCK_LEN
        );
    }

    #[test]
    fn names_round_trip_and_are_unique() {
        // Uppercase in place, on the stack: the name test must not need `alloc`.
        let mut upper = [0u8; 32];
        for (i, &alg) in HashAlgorithm::ALL.iter().enumerate() {
            assert_eq!(HashAlgorithm::from_name(alg.name()), Some(alg));
            assert_eq!(alg.name().parse::<HashAlgorithm>(), Ok(alg));

            let n = alg.name().len();
            upper[..n].copy_from_slice(alg.name().as_bytes());
            upper[..n].make_ascii_uppercase();
            let upper = core::str::from_utf8(&upper[..n]).unwrap();
            assert_eq!(HashAlgorithm::from_name(upper), Some(alg));

            for &other in &HashAlgorithm::ALL[i + 1..] {
                assert_ne!(alg.name(), other.name());
            }
        }
        assert_eq!(
            HashAlgorithm::from_name("SHA-256"),
            Some(HashAlgorithm::Sha256)
        );
        assert_eq!(
            HashAlgorithm::from_name("sha512/256"),
            Some(HashAlgorithm::Sha512_256)
        );
        assert_eq!(HashAlgorithm::from_name("nope"), None);
        assert_eq!("nope".parse::<HashAlgorithm>(), Err(UnknownHashAlgorithm));
    }

    #[test]
    fn runtime_digests_match_the_static_ones() {
        let msg = b"purecrypto runtime hash dispatch";

        assert_eq!(
            HashAlgorithm::Sha256.digest(msg).as_slice(),
            &crate::hash::sha256(msg)[..]
        );
        assert_eq!(
            HashAlgorithm::Sha512.digest(msg).as_slice(),
            &crate::hash::sha512(msg)[..]
        );
        assert_eq!(
            HashAlgorithm::Sha3_256.digest(msg).as_slice(),
            &crate::hash::sha3_256(msg)[..]
        );
        assert_eq!(
            HashAlgorithm::Blake2b512.digest(msg).as_slice(),
            &crate::hash::blake2b512(msg)[..]
        );
        assert_eq!(
            HashAlgorithm::Blake3.digest(msg).as_slice(),
            &crate::hash::blake3(msg)[..]
        );
        assert_eq!(
            HashAlgorithm::Sha1.digest(msg).as_slice(),
            &crate::hash::sha1(msg)[..]
        );
        assert_eq!(
            HashAlgorithm::Whirlpool.digest(msg).as_slice(),
            &crate::hash::whirlpool(msg)[..]
        );
    }

    #[test]
    fn chunked_updates_match_one_shot() {
        let msg: [u8; 300] = core::array::from_fn(|i| i as u8);
        for &alg in HashAlgorithm::ALL {
            let mut h = alg.hasher();
            for chunk in msg.chunks(7) {
                h.update(chunk);
            }
            assert_eq!(h.finalize(), alg.digest(msg), "{alg}");
        }
    }

    #[test]
    fn finalize_resets_the_state() {
        let mut h = HashAlgorithm::Sha256.hasher();
        h.update(b"first");
        let first = h.finalize_reset();
        assert_eq!(first, HashAlgorithm::Sha256.digest(b"first"));
        h.update(b"second");
        assert_eq!(h.finalize(), HashAlgorithm::Sha256.digest(b"second"));
    }

    #[test]
    fn reset_discards_absorbed_data() {
        let mut h = HashAlgorithm::Sha3_512.hasher();
        h.update(b"discard me");
        h.reset();
        h.update(b"kept");
        assert_eq!(h.finalize(), HashAlgorithm::Sha3_512.digest(b"kept"));
    }

    #[test]
    fn dyn_dispatch_over_concrete_and_runtime_hashers() {
        fn hash_through_dyn(h: &mut dyn DynDigest, data: &[u8]) -> HashOutput {
            h.update(data);
            let mut out = HashOutput {
                bytes: [0u8; HashAlgorithm::MAX_OUTPUT_LEN],
                len: h.output_len() as u8,
            };
            let n = h.output_len();
            h.finalize_into(&mut out.bytes[..n]).unwrap();
            out
        }

        let msg = b"one interface, two hashers";
        let expected = HashAlgorithm::Sha256.digest(msg);

        let mut concrete = <Sha256 as Digest>::new();
        assert_eq!(hash_through_dyn(&mut concrete, msg), expected);
        assert_eq!(DynDigest::algorithm(&concrete), Some(HashAlgorithm::Sha256));

        let mut runtime = HashAlgorithm::Sha256.hasher();
        assert_eq!(hash_through_dyn(&mut runtime, msg), expected);

        // `finalize_into` on a concrete hasher also resets it.
        let mut out = [0u8; 64];
        let mut d = <Sha512 as Digest>::new();
        DynDigest::update(&mut d, b"a");
        DynDigest::finalize_into(&mut d, &mut out).unwrap();
        assert_eq!(out, crate::hash::sha512(b"a"));
        DynDigest::update(&mut d, b"a");
        DynDigest::finalize_into(&mut d, &mut out).unwrap();
        assert_eq!(out, crate::hash::sha512(b"a"));
    }

    #[test]
    fn wrong_output_length_is_rejected() {
        let mut short = [0u8; 31];
        let mut long = [0u8; 33];
        for buf in [&mut short[..], &mut long[..]] {
            let mut h = HashAlgorithm::Sha256.hasher();
            h.update(b"data");
            let err = DynDigest::finalize_into(&mut h, buf).unwrap_err();
            assert_eq!(err.expected, 32);
            assert_eq!(err.got, buf.len());
            // The hasher was left untouched, so the digest is still available.
            assert_eq!(h.finalize(), HashAlgorithm::Sha256.digest(b"data"));
        }

        let mut h = <Sha256 as Digest>::new();
        assert!(DynDigest::finalize_into(&mut h, &mut short).is_err());

        assert!(
            HashAlgorithm::Sha256
                .digest_into(b"data", &mut short)
                .is_err()
        );
        let mut exact = [0u8; 32];
        assert!(
            HashAlgorithm::Sha256
                .digest_into(b"data", &mut exact)
                .is_ok()
        );
        assert_eq!(exact, crate::hash::sha256(b"data"));
    }

    #[test]
    fn helpers_accept_every_byte_like_input() {
        let expected = HashAlgorithm::Sha256.digest(b"hello");

        // &str / [u8; N] / &[u8] all go through `AsRef` (as do `String` and
        // `Vec<u8>` — see the `alloc`-gated test below).
        assert_eq!(HashAlgorithm::Sha256.digest("hello"), expected);
        assert_eq!(HashAlgorithm::Sha256.digest(*b"hello"), expected);
        assert_eq!(HashAlgorithm::Sha256.digest(&b"hello"[..]), expected);

        // Concatenation without joining, and the builder form.
        assert_eq!(
            HashAlgorithm::Sha256.digest_parts([&b"he"[..], &b"l"[..], &b"lo"[..]]),
            expected
        );
        assert_eq!(
            HashAlgorithm::Sha256
                .hasher()
                .chain("he")
                .chain(b"llo")
                .finalize(),
            expected
        );

        // `HashOutput` derefs to the digest bytes.
        assert_eq!(expected.first(), Some(&0x2c));
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn owned_inputs_and_hex_display() {
        let expected = HashAlgorithm::Sha256.digest("hello");
        assert_eq!(
            HashAlgorithm::Sha256.digest(alloc::string::String::from("hello")),
            expected
        );
        assert_eq!(
            HashAlgorithm::Sha256.digest(alloc::vec![b'h', b'e', b'l', b'l', b'o']),
            expected
        );
        // `HashOutput` displays as lowercase hex.
        assert_eq!(
            alloc::format!("{expected}"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn hasher_is_a_fmt_write_target() {
        use core::fmt::Write as _;

        let mut h = HashAlgorithm::Sha256.hasher();
        write!(h, "id:{}", 42).unwrap();
        assert_eq!(h.finalize(), HashAlgorithm::Sha256.digest("id:42"));
    }

    #[cfg(feature = "std")]
    #[test]
    fn hasher_is_an_io_write_target() {
        let mut h = HashAlgorithm::Sha512.hasher();
        std::io::copy(&mut std::io::Cursor::new(&b"streamed"[..]), &mut h).unwrap();
        assert_eq!(h.finalize(), HashAlgorithm::Sha512.digest("streamed"));
    }

    // Guards the one piece of duplication the macro cannot avoid: its arm list
    // must name every `HashAlgorithm` variant, and pair each with the right
    // type. A variant added to the table without a macro arm falls through to
    // `_` and fails here.
    #[test]
    fn dispatch_digest_covers_every_variant() {
        for &alg in HashAlgorithm::ALL {
            let (out, block, digest) = crate::dispatch_digest!(alg, |D| {
                (
                    <D as Digest>::OUTPUT_LEN,
                    <D as Digest>::BLOCK_LEN,
                    <D as Digest>::digest(b"abc").as_ref().to_vec(),
                )
            }, _ => panic!("dispatch_digest! has no arm for {alg}"));

            assert_eq!(out, alg.output_len(), "{alg}");
            assert_eq!(block, alg.block_len(), "{alg}");
            // Same type, not merely the same length: the digest must match the
            // one the enum's own hasher produces.
            assert_eq!(digest, alg.digest(b"abc").as_slice(), "{alg}");
        }
    }

    #[test]
    fn legacy_flags() {
        for &alg in HashAlgorithm::ALL {
            let expect = matches!(
                alg,
                HashAlgorithm::Md2
                    | HashAlgorithm::Md4
                    | HashAlgorithm::Md5
                    | HashAlgorithm::Sha1
                    | HashAlgorithm::Ripemd160
            ) || is_legacy_hashes_variant(alg);
            assert_eq!(alg.is_legacy(), expect, "{alg}");
        }
    }

    /// Whether `alg` comes from the `legacy-hashes` feature (all of which
    /// are legacy): the table lists them last, from RIPEMD-128 on.
    fn is_legacy_hashes_variant(alg: HashAlgorithm) -> bool {
        #[cfg(feature = "legacy-hashes")]
        {
            HashAlgorithm::ALL
                .iter()
                .position(|&a| a == HashAlgorithm::Ripemd128)
                .is_some_and(|first| HashAlgorithm::ALL[first..].contains(&alg))
        }
        #[cfg(not(feature = "legacy-hashes"))]
        {
            let _ = alg;
            false
        }
    }

    // The `legacy-hashes` digests under their PHP `hash()` names.
    #[cfg(feature = "legacy-hashes")]
    #[test]
    fn legacy_hashes_by_php_name() {
        let cases: [(&str, &str); 4] = [
            (
                "tiger192,3",
                "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93",
            ),
            ("haval128,3", "9e40ed883fb63e985d299b40cda2b8f2"),
            ("ripemd128", "c14a12199c66e4ba84636b0f69144c77"),
            (
                "snefru256",
                "7d033205647a2af3dc8339f6cb25643c33ebc622d32979c4b612b02c4903031b",
            ),
        ];
        for (name, want) in cases {
            let alg = HashAlgorithm::from_name(name).unwrap();
            assert!(alg.is_legacy());
            let got = alg.digest(b"abc");
            let mut hex = [0u8; 2 * HashAlgorithm::MAX_OUTPUT_LEN];
            for (i, b) in got.iter().enumerate() {
                hex[2 * i] = b"0123456789abcdef"[(b >> 4) as usize];
                hex[2 * i + 1] = b"0123456789abcdef"[(b & 15) as usize];
            }
            assert_eq!(&hex[..2 * got.len()], want.as_bytes(), "{name}");
        }
        assert_eq!(
            HashAlgorithm::from_name("GOST-CRYPTO"),
            Some(HashAlgorithm::Gost94CryptoPro)
        );
        assert_eq!(HashAlgorithm::Haval256_5.name(), "haval256,5");
        assert_eq!(HashAlgorithm::Haval256_5.block_len(), 128);
        assert_eq!(HashAlgorithm::Snefru256.block_len(), 32);
    }
}
