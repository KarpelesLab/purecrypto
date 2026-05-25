//! X25519 Diffie-Hellman over Curve25519 (RFC 7748).
//!
//! The field is GF(2²⁵⁵−19); arithmetic reuses the constant-time
//! [`MontModulus`](crate::bignum::MontModulus). The scalar multiplication is
//! the Montgomery ladder with constant-time conditional swaps.

use crate::bignum::{MontModulus, Uint, inv_mod};
use crate::ct::{Choice, ConditionallySelectable};
use crate::rng::RngCore;

/// `p = 2^255 - 19` (big-endian hex).
const P25519_HEX: &str = "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed";
/// `(A - 2) / 4 = 121665` for Curve25519.
const A24: u64 = 121665;

type Fe = Uint<4>;

fn fe_from_hex(hex: &str) -> Fe {
    let h = hex.as_bytes();
    let mut bytes = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = (h[2 * i] as char).to_digit(16).unwrap() as u8;
        let lo = (h[2 * i + 1] as char).to_digit(16).unwrap() as u8;
        bytes[i] = (hi << 4) | lo;
        i += 1;
    }
    Fe::from_be_bytes(&bytes)
}

/// Computes the raw X25519 function: `scalar * point` on Curve25519, returning
/// the resulting u-coordinate (little-endian, 32 bytes).
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    let fp = MontModulus::new(fe_from_hex(P25519_HEX));

    // Clamp the scalar (RFC 7748 §5).
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let k = Fe::from_le_bytes(&k);

    // Decode the u-coordinate: mask the top bit, reduce mod p.
    let mut ub = *point;
    ub[31] &= 127;
    let u = Fe::from_le_bytes(&ub).reduce(fp.modulus());

    let one = fp.to_mont(&Fe::ONE);
    let x1 = fp.to_mont(&u);
    let mut x2 = one;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = one;
    let a24 = fp.to_mont(&Fe::from_u64(A24));

    let mul = |a: &Fe, b: &Fe| fp.mont_mul(a, b);
    let add = |a: &Fe, b: &Fe| fp.add_mod(a, b);
    let sub = |a: &Fe, b: &Fe| fp.sub_mod(a, b);

    let mut swap = 0u8;
    let limbs = k.as_limbs();
    let mut t = 255;
    while t > 0 {
        t -= 1;
        let kt = ((limbs[t / 64] >> (t % 64)) & 1) as u8;
        swap ^= kt;
        let sw = Choice::from(swap);
        Fe::conditional_swap(&mut x2, &mut x3, sw);
        Fe::conditional_swap(&mut z2, &mut z3, sw);
        swap = kt;

        let a = add(&x2, &z2);
        let aa = mul(&a, &a);
        let b = sub(&x2, &z2);
        let bb = mul(&b, &b);
        let e = sub(&aa, &bb);
        let c = add(&x3, &z3);
        let d = sub(&x3, &z3);
        let da = mul(&d, &a);
        let cb = mul(&c, &b);
        let t0 = add(&da, &cb);
        x3 = mul(&t0, &t0);
        let t1 = sub(&da, &cb);
        let t1sq = mul(&t1, &t1);
        z3 = mul(&x1, &t1sq);
        x2 = mul(&aa, &bb);
        let t2 = add(&aa, &mul(&a24, &e));
        z2 = mul(&e, &t2);
    }
    let sw = Choice::from(swap);
    Fe::conditional_swap(&mut x2, &mut x3, sw);
    Fe::conditional_swap(&mut z2, &mut z3, sw);

    // result = x2 / z2 (or 0 if z2 == 0)
    let z2_plain = fp.from_mont(&z2);
    let mut out = [0u8; 32];
    if let Some(z_inv) = inv_mod(&z2_plain, fp.modulus()) {
        let res = fp.mul_mod(&fp.from_mont(&x2), &z_inv);
        res.write_le_bytes(&mut out);
    }
    out
}

/// The X25519 base point (`u = 9`).
pub const BASE_POINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// An X25519 private key (a 32-byte scalar).
#[derive(Clone)]
pub struct X25519PrivateKey {
    scalar: [u8; 32],
}

impl X25519PrivateKey {
    /// Generates a new private key from `rng`.
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let mut scalar = [0u8; 32];
        rng.fill_bytes(&mut scalar);
        X25519PrivateKey { scalar }
    }

    /// Creates a private key from raw scalar bytes (clamped on use).
    pub fn from_bytes(scalar: [u8; 32]) -> Self {
        X25519PrivateKey { scalar }
    }

    /// The public key `X25519(scalar, 9)` to send to the peer.
    pub fn public_key(&self) -> [u8; 32] {
        x25519(&self.scalar, &BASE_POINT)
    }

    /// The shared secret with `peer`'s public key.
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> [u8; 32] {
        x25519(&self.scalar, peer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        let h = s.as_bytes();
        for i in 0..32 {
            let hi = (h[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (h[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            out[i] = (hi << 4) | lo;
        }
        out
    }

    #[test]
    fn rfc7748_test_vector() {
        // RFC 7748 §5.2, first vector.
        let scalar = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let out = x25519(&scalar, &u);
        assert_eq!(
            out,
            hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        );
    }

    #[test]
    fn rfc7748_diffie_hellman() {
        // RFC 7748 §6.1.
        let a = X25519PrivateKey::from_bytes(hex32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let b = X25519PrivateKey::from_bytes(hex32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));

        assert_eq!(
            a.public_key(),
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        assert_eq!(
            b.public_key(),
            hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        );

        let shared = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(a.diffie_hellman(&b.public_key()), shared);
        assert_eq!(b.diffie_hellman(&a.public_key()), shared);
    }

    #[test]
    fn generated_keys_agree() {
        let mut rng = HmacDrbg::<Sha256>::new(b"x25519", b"nonce", &[]);
        let a = X25519PrivateKey::generate(&mut rng);
        let b = X25519PrivateKey::generate(&mut rng);
        assert_eq!(
            a.diffie_hellman(&b.public_key()),
            b.diffie_hellman(&a.public_key())
        );
    }
}
