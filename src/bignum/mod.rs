//! Constant-time big-integer arithmetic.
//!
//! [`Uint<LIMBS>`] is a fixed-size unsigned integer stored as `LIMBS` 64-bit
//! limbs in little-endian order. The size is part of the type, and every
//! operation processes all limbs unconditionally, so running time depends only
//! on the (public) size — never on the values. Data-dependent choices route
//! through the [`crate::ct`] primitives.
//!
//! This is the foundation for the integer-based asymmetric algorithms (RSA,
//! Diffie-Hellman, ECDSA). Modular arithmetic (Montgomery form, modexp,
//! inversion) is layered on top.

#[cfg(feature = "alloc")]
mod boxed;
#[cfg(feature = "alloc")]
mod boxed_montgomery;
mod inverse;
mod modpow;
mod montgomery;
mod mul;
mod uint;

#[cfg(feature = "alloc")]
pub use boxed::BoxedUint;
#[cfg(feature = "alloc")]
pub use boxed_montgomery::BoxedMontModulus;
pub use inverse::inv_mod;
#[cfg(feature = "alloc")]
pub use inverse::inv_mod_boxed;
pub use montgomery::MontModulus;
pub use uint::{LIMB_BITS, Limb, Uint};
