//! PBKDF2 — Password-Based Key Derivation Function 2 (RFC 8018 §5.2).

use crate::hash::{Digest, Hmac};

/// Derives a key of length `out.len()` from `password` and `salt` using
/// PBKDF2 with `iterations` rounds of HMAC-`D` as the PRF.
///
/// Higher iteration counts increase the cost of brute-force guessing; pick the
/// largest value tolerable for your latency budget.
///
/// # Panics
///
/// Panics if `iterations` is zero, or if `out.len()` would require more than
/// `2^32 - 1` blocks (RFC 8018 §5.2 caps the block counter at a 32-bit
/// integer). The block-count limit is `(2^32 - 1) * hlen` bytes — i.e.
/// hundreds of GiB even for SHA-256 — and is unreachable in practice;
/// enforcing it makes a future caller's bug fail loudly rather than wrap
/// the counter into `block_index = 1` and silently re-derive the first
/// blocks.
///
/// ```
/// use purecrypto::hash::Sha256;
/// use purecrypto::kdf::pbkdf2;
///
/// let mut key = [0u8; 32];
/// pbkdf2::<Sha256>(b"password", b"salt", 4096, &mut key);
/// ```
pub fn pbkdf2<D: Digest>(password: &[u8], salt: &[u8], iterations: u32, out: &mut [u8]) {
    assert!(iterations >= 1, "PBKDF2 requires at least one iteration");

    let hlen = D::OUTPUT_LEN;
    // RFC 8018 §5.2 step 1: derived-key length must fit within the
    // 32-bit block counter. The maximum is (2^32 - 1) * hlen bytes.
    let max_len = (u32::MAX as usize).saturating_mul(hlen);
    assert!(
        out.len() <= max_len,
        "PBKDF2 output length exceeds RFC 8018 §5.2 limit (2^32 - 1 blocks)",
    );

    // Key the HMAC with the password exactly once. Each U_j is then a cheap
    // `clone()` of this keyed state, which skips re-deriving the ipad/opad
    // key schedule (two extra compressions) on every one of the `iterations`
    // rounds. `prf` holds password-derived state and is wiped on drop.
    let prf = Hmac::<D>::new(password);

    let mut block_index: u32 = 1;
    for chunk in out.chunks_mut(hlen) {
        derive_block::<D>(&prf, salt, iterations, block_index, chunk);
        // Use checked_add so an off-by-one bug would trip the assert
        // above on entry rather than silently wrap to 1.
        block_index = block_index
            .checked_add(1)
            .expect("PBKDF2 block counter overflowed 2^32");
    }
}

/// Computes one PBKDF2 output block `T_i = U_1 ^ U_2 ^ … ^ U_c` and copies its
/// leading bytes into `out` (which is at most one digest long). `prf` is the
/// HMAC already keyed with the password; each `U_j` clones it.
fn derive_block<D: Digest>(
    prf: &Hmac<D>,
    salt: &[u8],
    iterations: u32,
    index: u32,
    out: &mut [u8],
) {
    // U_1 = PRF(password, salt || INT_32_BE(index))
    let mut u = prf
        .clone()
        .chain(salt)
        .chain(&index.to_be_bytes())
        .finalize();

    let mut acc = u; // running XOR, starts at U_1
    for _ in 1..iterations {
        // U_j = PRF(password, U_{j-1})
        u = prf.clone().chain(u.as_ref()).finalize();
        for (a, b) in acc.as_mut().iter_mut().zip(u.as_ref().iter()) {
            *a ^= *b;
        }
    }

    let n = out.len().min(acc.as_ref().len());
    out[..n].copy_from_slice(&acc.as_ref()[..n]);

    // Wipe the PRF chaining value and the block accumulator: both are
    // password-derived key material (`acc` IS the derived block). Overwrite
    // plus a `black_box` fence so the stores are not elided.
    for b in u.as_mut() {
        *b = 0;
    }
    for b in acc.as_mut() {
        *b = 0;
    }
    let _ = core::hint::black_box(u.as_ref());
    let _ = core::hint::black_box(acc.as_ref());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::test_util::from_hex;

    // Well-known PBKDF2-HMAC-SHA256 test vectors.

    #[test]
    fn sha256_c1() {
        let mut out = [0u8; 32];
        pbkdf2::<Sha256>(b"password", b"salt", 1, &mut out);
        assert_eq!(
            out,
            from_hex::<32>("120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b")
        );
    }

    #[test]
    fn sha256_c2() {
        let mut out = [0u8; 32];
        pbkdf2::<Sha256>(b"password", b"salt", 2, &mut out);
        assert_eq!(
            out,
            from_hex::<32>("ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43")
        );
    }

    #[test]
    fn sha256_c4096() {
        let mut out = [0u8; 32];
        pbkdf2::<Sha256>(b"password", b"salt", 4096, &mut out);
        assert_eq!(
            out,
            from_hex::<32>("c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a")
        );
    }

    #[test]
    fn sha256_multiblock_output() {
        // 40-byte output spans two SHA-256 digest blocks.
        let mut out = [0u8; 40];
        pbkdf2::<Sha256>(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            &mut out,
        );
        assert_eq!(
            out,
            from_hex::<40>(
                "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1\
                 c635518c7dac47e9"
            )
        );
    }

    #[test]
    fn partial_block_output() {
        // Output shorter than one digest must match the prefix of a full block.
        let mut full = [0u8; 32];
        pbkdf2::<Sha256>(b"pw", b"salt", 10, &mut full);
        let mut short = [0u8; 20];
        pbkdf2::<Sha256>(b"pw", b"salt", 10, &mut short);
        assert_eq!(short, full[..20]);
    }
}
