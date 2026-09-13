//! Secret wiping: the [`Zeroize`] trait, the [`ZeroizeOnDrop`] marker and the
//! [`Zeroizing`] guard.
//!
//! This module mirrors the API of the `zeroize` crate (minus its derive macro)
//! so that users of `purecrypto` need not pull in a second dependency to wipe
//! key material. The crate's own secret-holding types are wiped through it.
//!
//! # Contract
//!
//! [`Zeroize::zeroize`] overwrites a value with zeros using **volatile stores**
//! followed by a [`compiler_fence`](core::sync::atomic::compiler_fence), so the
//! optimizer cannot treat the writes as dead stores and drop them, even when the
//! value is never read again (the usual situation in a destructor).
//!
//! What it does *not* do, and honestly cannot: reach copies of the secret the
//! compiler or operating system made elsewhere. Values that lived in registers,
//! were spilled to the stack by the compiler, were moved (a Rust move is a
//! bit-copy that leaves the source intact), were copied by a reallocating
//! `Vec`, or were paged out to swap are outside its reach. Treat wiping as
//! hygiene that shrinks the window in which secrets linger, not as a guarantee
//! against an attacker who can read process memory.
//!
//! # Example
//!
//! ```
//! use purecrypto::zeroize::{Zeroize, Zeroizing};
//!
//! // Explicit wipe.
//! let mut key = [0x42u8; 32];
//! key.zeroize();
//! assert_eq!(key, [0u8; 32]);
//!
//! // Wipe on drop: `Zeroizing<T>` derefs to `T` and zeroes it when it goes
//! // out of scope. Its `Debug` output never shows the contents.
//! let secret = Zeroizing::new([0x42u8; 32]);
//! assert_eq!(secret[0], 0x42);
//! assert_eq!(format!("{secret:?}"), "Zeroizing([REDACTED])");
//! drop(secret); // wiped here
//! ```
//!
//! A type holding secrets implements [`Zeroize`] by wiping each field, and
//! wipes itself on drop with a two-line `Drop` impl:
//!
//! ```
//! use purecrypto::zeroize::{Zeroize, ZeroizeOnDrop};
//!
//! struct SigningKey {
//!     seed: [u8; 32],
//!     public: [u8; 32], // not secret, but cheap to clear too
//! }
//!
//! impl Zeroize for SigningKey {
//!     fn zeroize(&mut self) {
//!         self.seed.zeroize();
//!         self.public.zeroize();
//!     }
//! }
//!
//! impl Drop for SigningKey {
//!     fn drop(&mut self) {
//!         self.zeroize();
//!     }
//! }
//!
//! impl ZeroizeOnDrop for SigningKey {}
//! ```

#[cfg(feature = "alloc")]
use alloc::{boxed::Box, string::String, vec::Vec};

/// Types whose contents can be overwritten with zeros.
///
/// See the [module documentation](self) for what the wipe does and does not
/// guarantee. Implementations must leave the value in a valid state (an
/// all-zero one for plain data; an empty one for containers such as `Vec`), so
/// that a zeroized value can still be dropped or reused normally.
pub trait Zeroize {
    /// Overwrites `self` with zeros using volatile stores that the compiler
    /// cannot elide.
    fn zeroize(&mut self);

    /// Wipes a whole slice of `Self`.
    ///
    /// This exists so that [`Zeroize for [Z]`](Zeroize#impl-Zeroize-for-%5BZ%5D)
    /// can pick a better strategy per element type than "call
    /// [`zeroize`](Zeroize::zeroize) on each element" — which costs one
    /// compiler fence per element. Plain-data types go through
    /// [`DefaultIsZeroes::zeroize_slice_impl`] instead, which fences once for
    /// the whole slice. Not part of the stable surface; override
    /// `DefaultIsZeroes::zeroize_slice_impl` rather than this.
    #[doc(hidden)]
    #[inline]
    fn zeroize_slice(slice: &mut [Self])
    where
        Self: Sized,
    {
        for z in slice.iter_mut() {
            z.zeroize();
        }
    }
}

/// Marker for types that wipe their secrets when dropped.
///
/// This is purely documentary — it carries no methods — and lets generic code
/// and readers see at a glance that a type takes care of its own cleanup.
/// [`Zeroizing`] implements it; so does [`key::Secret`][crate::key::Secret].
#[cfg_attr(not(feature = "key"), doc = "", doc = "[crate::key::Secret]: crate")]
pub trait ZeroizeOnDrop {}

/// Marker for `Copy` types whose [`Default`] value is the all-zero bit
/// pattern, which is the only thing needed to wipe them.
///
/// Implemented for every primitive integer, `bool`, `char`, `f32` and `f64`.
/// Implementing it for your own `Copy + Default` types (a `#[repr(C)]` struct
/// of integers, say) gives them [`Zeroize`] for free through the blanket impl.
/// It is deliberately **not** implemented for arrays, which are wiped
/// element-wise by their own [`Zeroize`] impl.
pub trait DefaultIsZeroes: Copy + Default {
    /// Wipes a whole slice of `Self` with a single compiler fence at the end.
    ///
    /// The default body stores [`Default::default()`] into each element, which
    /// is sound for any implementor. The primitives below override it with a
    /// word-at-a-time raw-byte wipe: a volatile store is never merged or
    /// vectorized by the compiler, so a byte-typed slice would otherwise cost
    /// one store per byte. Override this only if `Self`'s all-zero *bit
    /// pattern* is a valid value (it is for plain integers and `#[repr(C)]`
    /// structs of them) — and see [`volatile::zero_bytes_of`] for the exact
    /// contract. Not part of the stable surface.
    #[doc(hidden)]
    #[inline]
    fn zeroize_slice_impl(slice: &mut [Self]) {
        for z in slice.iter_mut() {
            volatile::write_unfenced(z, Self::default());
        }
        volatile::fence();
    }
}

macro_rules! impl_default_is_zeroes {
    ($($t:ty),+ $(,)?) => {$(
        impl DefaultIsZeroes for $t {
            // Scoped opt-in, as the crate's `unsafe_code = "deny"` policy
            // requires: the only `unsafe` is the call below.
            #[allow(unsafe_code)]
            #[inline]
            fn zeroize_slice_impl(slice: &mut [Self]) {
                // SAFETY: `$t` is a primitive (integer, `bool`, `char`, `f32`
                // or `f64`) whose all-zero bit pattern is both a valid value
                // and its `Default`: `0`, `false`, `'\0'`, `0.0`.
                unsafe { volatile::zero_bytes_of(slice) }
            }
        }
    )+};
}

impl_default_is_zeroes!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, bool, char, f32, f64
);

/// A fixed-width big integer is a plain array of limbs whose `Default` is
/// zero, so it wipes through the blanket impl below. Secret scalars (EC
/// private keys, ECDSA nonces) are `Uint`s, and their `Drop` impls want a
/// volatile wipe rather than a plain assignment.
#[cfg(feature = "bignum")]
impl<const LIMBS: usize> DefaultIsZeroes for crate::bignum::Uint<LIMBS> {
    // Scoped opt-in, as above.
    #[allow(unsafe_code)]
    #[inline]
    fn zeroize_slice_impl(slice: &mut [Self]) {
        // SAFETY: `Uint<LIMBS>` is a `#[repr(transparent)]` wrapper over
        // `[Limb; LIMBS]`, i.e. plain integers, so the all-zero bit pattern is
        // a valid value and is its `Default` (the zero integer).
        unsafe { volatile::zero_bytes_of(slice) }
    }
}

impl<Z: DefaultIsZeroes> Zeroize for Z {
    #[inline]
    fn zeroize(&mut self) {
        volatile::write(self, Z::default());
    }

    #[inline]
    fn zeroize_slice(slice: &mut [Self]) {
        Z::zeroize_slice_impl(slice);
    }
}

impl<Z: Zeroize, const N: usize> Zeroize for [Z; N] {
    #[inline]
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<Z: Zeroize> Zeroize for [Z] {
    #[inline]
    fn zeroize(&mut self) {
        Z::zeroize_slice(self);
    }
}

impl<Z: Zeroize> Zeroize for Option<Z> {
    /// Wipes the inner value (if any) and sets `self` to `None`.
    #[inline]
    fn zeroize(&mut self) {
        if let Some(z) = self.as_mut() {
            z.zeroize();
        }
        // `Option<Z>` has no volatile-write path of its own: the discriminant
        // is set through a normal store, and the barrier below keeps the inner
        // wipe from being reordered past it.
        *self = None;
        volatile::fence();
    }
}

#[cfg(feature = "alloc")]
impl<Z: Zeroize> Zeroize for Vec<Z> {
    /// Wipes every live element, empties the vector, then zeroes the **whole
    /// capacity** as raw bytes — so elements that were previously popped,
    /// truncated or drained do not survive in the spare capacity.
    ///
    /// The capacity is kept, so the buffer can be reused without reallocating.
    /// This cannot reach copies left behind by earlier reallocations (growing a
    /// `Vec` moves its contents to a fresh buffer and frees the old one
    /// unwiped); reserve the final capacity up front for buffers that will hold
    /// secrets.
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
        self.clear();
        volatile::zero_uninit(self.spare_capacity_mut());
    }
}

#[cfg(feature = "alloc")]
impl Zeroize for String {
    /// Wipes the whole capacity of the backing buffer and empties the string.
    #[inline]
    fn zeroize(&mut self) {
        volatile::zeroize_string(self);
    }
}

// There is deliberately no `impl<Z: Zeroize> Zeroize for Box<Z>`: `Box` is
// `#[fundamental]`, so coherence must assume a downstream crate could implement
// `DefaultIsZeroes for Box<Local>`, which would overlap the blanket impl.
// Callers wipe a `Box<Z>` through `DerefMut` (`(**b).zeroize()`).
#[cfg(feature = "alloc")]
impl<Z: Zeroize> Zeroize for Box<[Z]> {
    #[inline]
    fn zeroize(&mut self) {
        self.iter_mut().for_each(Zeroize::zeroize);
    }
}

#[cfg(feature = "alloc")]
impl Zeroize for Box<str> {
    /// Overwrites every byte with `0` (which is valid UTF-8, so the string
    /// stays well-formed at the same length).
    #[inline]
    fn zeroize(&mut self) {
        volatile::zeroize_box_str(self);
    }
}

/// A guard that wipes the wrapped value when dropped.
///
/// `Zeroizing<Z>` dereferences to `Z`, so it can be used wherever the plain
/// value would be, and calls [`Zeroize::zeroize`] on it in `Drop`. Its
/// [`Debug`](core::fmt::Debug) output is always `Zeroizing([REDACTED])` and it
/// deliberately implements no equality trait: compare the contents through
/// [`ct::ConstantTimeEq`](crate::ct::ConstantTimeEq) instead.
///
/// ```
/// # #[cfg(feature = "alloc")] {
/// use purecrypto::zeroize::Zeroizing;
///
/// let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(64));
/// buf.extend_from_slice(b"shared secret");
/// assert_eq!(&buf[..6], b"shared");
/// // dropped here: contents and spare capacity wiped
/// # }
/// ```
pub struct Zeroizing<Z: Zeroize>(Z);

impl<Z: Zeroize> Zeroizing<Z> {
    /// Wraps `value` so it is wiped on drop.
    #[inline]
    pub fn new(value: Z) -> Self {
        Zeroizing(value)
    }
}

impl<Z: Zeroize> From<Z> for Zeroizing<Z> {
    #[inline]
    fn from(value: Z) -> Self {
        Zeroizing(value)
    }
}

impl<Z: Zeroize> core::ops::Deref for Zeroizing<Z> {
    type Target = Z;
    #[inline]
    fn deref(&self) -> &Z {
        &self.0
    }
}

impl<Z: Zeroize> core::ops::DerefMut for Zeroizing<Z> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Z {
        &mut self.0
    }
}

impl<Z: Zeroize> AsRef<Z> for Zeroizing<Z> {
    #[inline]
    fn as_ref(&self) -> &Z {
        &self.0
    }
}

impl<Z: Zeroize> AsMut<Z> for Zeroizing<Z> {
    #[inline]
    fn as_mut(&mut self) -> &mut Z {
        &mut self.0
    }
}

impl<Z: Zeroize> Zeroize for Zeroizing<Z> {
    #[inline]
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl<Z: Zeroize> Drop for Zeroizing<Z> {
    #[inline]
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<Z: Zeroize> ZeroizeOnDrop for Zeroizing<Z> {}

impl<Z: Zeroize + Clone> Clone for Zeroizing<Z> {
    #[inline]
    fn clone(&self) -> Self {
        Zeroizing(self.0.clone())
    }
}

impl<Z: Zeroize + Default> Default for Zeroizing<Z> {
    #[inline]
    fn default() -> Self {
        Zeroizing(Z::default())
    }
}

impl<Z: Zeroize> core::fmt::Debug for Zeroizing<Z> {
    /// Always prints `Zeroizing([REDACTED])`, never the contents.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Zeroizing([REDACTED])")
    }
}

/// The volatile stores behind every [`Zeroize`] impl.
///
/// This is the module's only `unsafe`; it is kept to the bare minimum needed to
/// issue [`core::ptr::write_volatile`] through references that safe Rust has
/// already proven valid. The `#![allow(unsafe_code)]` scope is local, matching
/// the crate's `unsafe_code = "deny"` policy of scoped opt-ins.
mod volatile {
    #![allow(unsafe_code)]

    #[cfg(feature = "alloc")]
    use core::mem::MaybeUninit;
    use core::sync::atomic::{Ordering, compiler_fence};

    /// Stops the compiler from moving or eliding the preceding stores.
    #[inline(always)]
    pub(super) fn fence() {
        compiler_fence(Ordering::SeqCst);
    }

    /// Volatile-stores `value` into `dst`.
    #[inline]
    pub(super) fn write<T: Copy>(dst: &mut T, value: T) {
        // SAFETY: `dst` is a live `&mut T`, hence non-null, properly aligned
        // and pointing at an initialised `T` we hold exclusively; storing a
        // `T` through it is what `*dst = value` does, and `T: Copy` means no
        // destructor is skipped by not dropping the old value.
        unsafe { core::ptr::write_volatile(dst, value) };
        fence();
    }

    /// Volatile-stores `value` into `dst` **without** a trailing fence.
    ///
    /// For wiping many values in a row: volatile stores are never reordered
    /// among themselves, so one fence after the last one is enough to keep the
    /// whole run in place.
    #[inline]
    pub(super) fn write_unfenced<T: Copy>(dst: &mut T, value: T) {
        // SAFETY: as in `write`; only the fence is deferred to the caller.
        unsafe { core::ptr::write_volatile(dst, value) };
    }

    /// Volatile-stores zero over every byte of `slice`, a machine word at a
    /// time where alignment allows, then fences once.
    ///
    /// A volatile store is never merged or vectorized, so wiping an `[u8]`
    /// element-wise costs one store instruction per byte; going through
    /// `usize` cuts that by a factor of `size_of::<usize>()` while keeping
    /// every store volatile.
    ///
    /// # Safety
    ///
    /// The all-zero bit pattern must be a valid value of `T` — true for plain
    /// integers, `bool`, `char`, `f32`/`f64` and `#[repr(C)]` aggregates of
    /// them, but not for a type with a niche (a `NonZero*`, a reference, or an
    /// enum without a zero discriminant), where it would be undefined
    /// behaviour.
    #[inline]
    pub(super) unsafe fn zero_bytes_of<T>(slice: &mut [T]) {
        const W: usize = core::mem::size_of::<usize>();

        let len = core::mem::size_of_val(slice);
        let ptr = slice.as_mut_ptr().cast::<u8>();
        let mut i = 0usize;

        // Head: single bytes until the cursor is `usize`-aligned. When `T` is
        // already word-aligned the condition is a compile-time constant, so
        // this whole prologue folds away.
        let misalign = if core::mem::align_of::<T>() >= W {
            0
        } else {
            (ptr as usize) % W
        };
        if misalign != 0 {
            let head = core::cmp::min(W - misalign, len);
            while i < head {
                // SAFETY: `i < len`, and `slice` is a live exclusive borrow of
                // `len` contiguous bytes from `ptr`, so `ptr.add(i)` is in
                // bounds and trivially aligned for `u8`. Writing a zero byte
                // is valid for `T` by this function's contract.
                unsafe { core::ptr::write_volatile(ptr.add(i), 0u8) };
                i += 1;
            }
        }

        // Middle: one machine word per store.
        while i + W <= len {
            // SAFETY: `i + W <= len` keeps the whole word in bounds, and `i`
            // is now a multiple of `W` away from a `W`-aligned address, so the
            // `*mut usize` is properly aligned.
            unsafe { core::ptr::write_volatile(ptr.add(i).cast::<usize>(), 0usize) };
            i += W;
        }

        // Tail: the remaining bytes.
        while i < len {
            // SAFETY: as in the head loop.
            unsafe { core::ptr::write_volatile(ptr.add(i), 0u8) };
            i += 1;
        }

        fence();
    }

    /// Volatile-stores zero bytes over every byte of `slice`, which may be
    /// uninitialised (hence `MaybeUninit`, which has no validity invariant to
    /// uphold).
    ///
    /// Only the `alloc` container impls (`Vec`, `String`, `Box<str>`) wipe
    /// spare capacity, so without `alloc` this would be dead code and trip
    /// `-D warnings` on a no-alloc build (`--no-default-features --features
    /// ec`).
    #[cfg(feature = "alloc")]
    #[inline]
    pub(super) fn zero_uninit<T>(slice: &mut [MaybeUninit<T>]) {
        let len = slice
            .len()
            .checked_mul(core::mem::size_of::<T>())
            .expect("slice byte length overflows usize");
        let ptr = slice.as_mut_ptr().cast::<u8>();
        for i in 0..len {
            // SAFETY: `slice` is a live exclusive borrow of `len` contiguous
            // bytes starting at `ptr` (a slice never exceeds `isize::MAX`
            // bytes), so `ptr.add(i)` with `i < len` stays in bounds, is
            // trivially aligned for `u8`, and writing an arbitrary byte into a
            // `MaybeUninit<T>` cannot break any invariant. For a zero-sized
            // `T` the loop body never runs.
            unsafe { core::ptr::write_volatile(ptr.add(i), 0u8) };
        }
        fence();
    }

    /// Wipes a `String` through its byte vector.
    #[cfg(feature = "alloc")]
    #[inline]
    pub(super) fn zeroize_string(s: &mut alloc::string::String) {
        // SAFETY: `Vec<u8>::zeroize` leaves the vector empty, and the empty
        // byte sequence is valid UTF-8, so the `String` invariant holds once
        // the borrow ends.
        super::Zeroize::zeroize(unsafe { s.as_mut_vec() });
    }

    /// Wipes a `Box<str>` in place, keeping its length.
    #[cfg(feature = "alloc")]
    #[inline]
    pub(super) fn zeroize_box_str(s: &mut alloc::boxed::Box<str>) {
        // SAFETY: every byte becomes `0`, and a run of NUL bytes is valid
        // UTF-8, so the `str` invariant holds once the borrow ends.
        super::Zeroize::zeroize(unsafe { s.as_bytes_mut() });
    }

    /// Test helper: marks the entire capacity of `v` as live, so a test can
    /// inspect the bytes that `zero_uninit` wrote into the spare capacity.
    #[cfg(all(test, feature = "alloc"))]
    pub(super) fn expose_capacity(v: &mut alloc::vec::Vec<u8>) {
        let cap = v.capacity();
        // SAFETY: the caller has just zeroized `v`, which initialised every
        // byte of its capacity with a volatile store; every `u8` bit pattern
        // is valid, so all `cap` elements are initialised.
        unsafe { v.set_len(cap) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn primitives() {
        macro_rules! check {
            ($($t:ty => $v:expr),+ $(,)?) => {$(
                let mut x: $t = $v;
                x.zeroize();
                assert_eq!(x, <$t>::default());
            )+};
        }
        check!(
            u8 => 0xAB, u16 => 0xABCD, u32 => 0xDEAD_BEEF, u64 => u64::MAX,
            u128 => u128::MAX, usize => usize::MAX, i8 => -1, i16 => i16::MIN,
            i32 => -7, i64 => i64::MIN, i128 => -1, isize => isize::MIN,
            bool => true, char => 'x', f32 => 1.5, f64 => -2.25,
        );
    }

    #[test]
    fn arrays_and_slices() {
        let mut a = [0xABu8; 16];
        a.zeroize();
        assert_eq!(a, [0u8; 16]);

        let mut w = [0xDEAD_BEEFu32; 8];
        w.zeroize();
        assert_eq!(w, [0u32; 8]);

        let mut nested = [[0xFFu8; 4]; 3];
        nested.zeroize();
        assert_eq!(nested, [[0u8; 4]; 3]);

        let mut buf = [0x11u64; 5];
        buf[1..4].zeroize();
        assert_eq!(buf, [0x11, 0, 0, 0, 0x11]);

        let mut empty: [u8; 0] = [];
        empty.zeroize();
    }

    /// The word-at-a-time path splits a slice into an unaligned head, a run of
    /// machine words and a tail, so walk every combination of start offset and
    /// length around the word size and check that exactly the requested range
    /// is wiped and nothing either side of it is touched.
    #[test]
    fn wordwise_wipe_covers_every_alignment_and_length() {
        const PAD: usize = 8;
        for start in 0..16usize {
            for len in 0..40usize {
                let mut buf = [0xA5u8; PAD + 16 + 40 + PAD];
                let from = PAD + start;
                buf[from..from + len].zeroize();

                assert!(
                    buf[from..from + len].iter().all(|&b| b == 0),
                    "start {start} len {len}: range not fully wiped"
                );
                assert!(
                    buf[..from].iter().all(|&b| b == 0xA5)
                        && buf[from + len..].iter().all(|&b| b == 0xA5),
                    "start {start} len {len}: wiped outside the range"
                );
            }
        }

        // Same, for a wider element type: the tail path runs when the byte
        // length is not a whole number of machine words.
        for len in 0..10usize {
            let mut buf = [0xDEAD_BEEFu32; 12];
            buf[1..1 + len].zeroize();
            assert!(buf[1..1 + len].iter().all(|&w| w == 0));
            assert!(buf[1 + len..].iter().all(|&w| w == 0xDEAD_BEEF));
        }
    }

    #[test]
    fn option_becomes_none() {
        let mut some = Some([0xAAu8; 8]);
        some.zeroize();
        assert!(some.is_none());

        let mut none: Option<u32> = None;
        none.zeroize();
        assert!(none.is_none());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn vec_wipes_whole_capacity() {
        let mut v: Vec<u8> = Vec::with_capacity(64);
        let cap = v.capacity();
        v.extend_from_slice(&[0xAA; 48]);
        v.truncate(16); // 32 stale bytes now sit in the spare capacity
        v.zeroize();
        assert!(v.is_empty());
        assert_eq!(v.capacity(), cap);
        volatile::expose_capacity(&mut v);
        assert_eq!(v.len(), cap);
        assert!(v.iter().all(|&b| b == 0));

        let mut words = alloc::vec![0xDEAD_BEEFu32; 10];
        words.zeroize();
        assert!(words.is_empty());
        words.push(1);
        assert_eq!(words, [1]);

        let mut nested: Vec<[u8; 4]> = alloc::vec![[0xFF; 4]; 3];
        nested.zeroize();
        assert!(nested.is_empty());

        let mut empty: Vec<u64> = Vec::new();
        empty.zeroize();
        assert_eq!(empty.capacity(), 0);

        struct Zst;
        impl Zeroize for Zst {
            fn zeroize(&mut self) {}
        }
        let mut zst: Vec<Zst> = Vec::with_capacity(5);
        zst.push(Zst);
        zst.zeroize();
        assert!(zst.is_empty());
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn string_and_boxes() {
        let mut s = String::from("hunter2");
        let cap = s.capacity();
        s.zeroize();
        assert!(s.is_empty());
        assert_eq!(s.capacity(), cap);
        s.push_str("ok");
        assert_eq!(s, "ok");

        let mut bs: Box<str> = "secret".into();
        bs.zeroize();
        assert_eq!(bs.len(), 6);
        assert!(bs.bytes().all(|b| b == 0));

        let mut b: Box<[u16]> = alloc::vec![0xFFFF; 7].into_boxed_slice();
        b.zeroize();
        assert_eq!(b.len(), 7);
        assert!(b.iter().all(|&w| w == 0));
    }

    /// A `Zeroize` type that records whether it was wiped.
    struct Spy<'a>(&'a Cell<u32>);

    impl Zeroize for Spy<'_> {
        fn zeroize(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    #[test]
    fn zeroizing_wipes_on_drop() {
        let wipes = Cell::new(0);
        {
            let guard = Zeroizing::new(Spy(&wipes));
            assert_eq!(wipes.get(), 0);
            let _ = &*guard;
        }
        assert_eq!(wipes.get(), 1);

        let guard: Zeroizing<Spy<'_>> = Spy(&wipes).into();
        drop(guard);
        assert_eq!(wipes.get(), 2);
    }

    #[test]
    fn zeroizing_deref_and_explicit_wipe() {
        let mut z = Zeroizing::new([0x55u8; 4]);
        assert_eq!(*z, [0x55; 4]);
        z[0] = 1;
        assert_eq!(z.as_ref()[0], 1);
        z.as_mut()[1] = 2;
        assert_eq!(&z[..2], &[1, 2]);
        z.zeroize();
        assert_eq!(*z, [0u8; 4]);

        let d: Zeroizing<u64> = Zeroizing::default();
        assert_eq!(*d, 0);
        let c = Zeroizing::new(7u8);
        let c2 = c.clone();
        assert_eq!(*c2, 7);
    }

    #[test]
    fn zeroizing_debug_is_redacted() {
        use core::fmt::Write;
        let z = Zeroizing::new([0xAAu8; 4]);
        let mut out = heapless_string::Buf::default();
        write!(out, "{z:?}").unwrap();
        assert_eq!(out.as_str(), "Zeroizing([REDACTED])");
        assert!(!out.as_str().contains("170"));
    }

    /// A tiny fixed-capacity `fmt::Write` sink so the redaction test also runs
    /// in `no_std` configurations without `alloc`.
    mod heapless_string {
        #[derive(Default)]
        pub(super) struct Buf {
            bytes: [u8; 32],
            len: usize,
        }

        impl Buf {
            pub(super) fn as_str(&self) -> &str {
                core::str::from_utf8(&self.bytes[..self.len]).unwrap()
            }
        }

        impl core::fmt::Write for Buf {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                let end = self.len + s.len();
                if end > self.bytes.len() {
                    return Err(core::fmt::Error);
                }
                self.bytes[self.len..end].copy_from_slice(s.as_bytes());
                self.len = end;
                Ok(())
            }
        }
    }
}
