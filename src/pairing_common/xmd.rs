//! RFC 9380 `expand_message_xmd` with SHA-256, shared by the hash-to-curve
//! suites of every pairing-friendly curve in the crate.

use crate::hash::{Digest, Sha256};

/// `expand_message_xmd` (RFC 9380 §5.3.1) with SHA-256, writing
/// `out.len()` uniform bytes.
///
/// A DST longer than 255 bytes is replaced by
/// `SHA-256("H2C-OVERSIZE-DST-" || DST)` as §5.3.3 prescribes.
///
/// # Panics
///
/// If `out.len()` exceeds `255 · 32` bytes (the `ell ≤ 255` bound) or
/// `65535`, or is zero; or if `dst` is empty (§3.1: tags MUST be non-empty,
/// as an empty one collapses the domain separation this function exists
/// to provide).
pub fn expand_message_xmd(msg: &[u8], dst: &[u8], out: &mut [u8]) {
    expand_message_xmd_parts(&[msg], dst, out);
}

/// [`expand_message_xmd`] of the concatenation of `parts`, streamed into the
/// hash instead of copied into a buffer (the BLS Message Augmentation
/// scheme hashes `PK || msg` this way without an allocator).
pub(crate) fn expand_message_xmd_parts(parts: &[&[u8]], dst: &[u8], out: &mut [u8]) {
    const B_IN_BYTES: usize = 32;
    const S_IN_BYTES: usize = 64;
    assert!(!dst.is_empty(), "expand_message_xmd: empty DST");
    let len_in_bytes = out.len();
    assert!(
        len_in_bytes > 0 && len_in_bytes <= 65535,
        "expand_message_xmd: bad output length"
    );
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    assert!(ell <= 255, "expand_message_xmd: output too long");

    // DST' = DST || I2OSP(len(DST), 1), hashing oversized tags first.
    let hashed_dst: [u8; 32];
    let dst: &[u8] = if dst.len() > 255 {
        let mut h = Sha256::new();
        h.update(b"H2C-OVERSIZE-DST-");
        h.update(dst);
        hashed_dst = h.finalize();
        &hashed_dst
    } else {
        dst
    };
    let dst_len = [dst.len() as u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || 0x00 || DST')
    let mut h = Sha256::new();
    h.update(&[0u8; S_IN_BYTES]);
    for part in parts {
        h.update(part);
    }
    h.update(&(len_in_bytes as u16).to_be_bytes());
    h.update(&[0u8]);
    h.update(dst);
    h.update(&dst_len);
    let b0 = h.finalize();

    // b_1 = H(b_0 || 0x01 || DST'); b_i = H(strxor(b_0, b_{i-1}) || i || DST').
    let mut prev = [0u8; B_IN_BYTES];
    for i in 1..=ell {
        let mut h = Sha256::new();
        if i == 1 {
            h.update(&b0);
        } else {
            let mut x = [0u8; B_IN_BYTES];
            for (k, xk) in x.iter_mut().enumerate() {
                *xk = b0[k] ^ prev[k];
            }
            h.update(&x);
        }
        h.update(&[i as u8]);
        h.update(dst);
        h.update(&dst_len);
        prev = h.finalize();
        let off = (i - 1) * B_IN_BYTES;
        let n = core::cmp::min(B_IN_BYTES, len_in_bytes - off);
        out[off..off + n].copy_from_slice(&prev[..n]);
    }
}
