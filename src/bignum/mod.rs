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

mod inverse;
mod modpow;
mod montgomery;
mod mul;
mod uint;

pub use inverse::inv_mod;
pub use montgomery::MontModulus;
pub use uint::{LIMB_BITS, Limb, Uint};
