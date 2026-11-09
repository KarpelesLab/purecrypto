//! Signature compression and public-key packing (spec §3.11).
//!
//! [`compress`] is the exact inverse of the verifier's `decompress`
//! (`falcon/mod.rs`): per coefficient, 1 sign bit, 7 low bits (MSB first), then
//! the high bits in unary. [`encode_pubkey`] packs `h` at 14 bits/coefficient,
//! matching `FalconPublicKey::from_bytes`.

use crate::zeroize::Zeroizing;
use alloc::vec::Vec;

/// Compress the signature polynomial `s` into exactly `slen` bytes, or `None`
/// if it does not fit (the caller resamples). Mirrors the reference `compress`.
///
/// A coefficient of magnitude `>= 2048` is rejected with `None` rather than
/// encoded: its unary high part would be 16 zeros or more, which the verifier's
/// `decompress` (and the reference `comp_decode`) refuses outright — so emitting
/// it would produce a signature that can never verify, and the unary run would
/// also let one wild coefficient balloon the bit buffer. Returning `None` makes
/// the signer resample, which is exactly what the reference does.
pub(crate) fn compress(s: &[i16], slen: usize) -> Option<Vec<u8>> {
    // Range check over every coefficient before any early exit, so the
    // position of an oversized coefficient (of a candidate the signer then
    // discards) is not exposed through the loop count.
    let overflow = s
        .iter()
        .fold(0u32, |acc, &c| acc | (c as i32).unsigned_abs());
    if overflow >= 2048 {
        return None;
    }
    // One byte per bit of a signature candidate the signer may yet discard:
    // wiped on drop, on the too-long path as well. (The capacity is only a
    // hint; `Vec` growth may still move the buffer, which a signature that is
    // about to be published or resampled can tolerate.)
    let mut bits: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(s.len() * 9));
    for &coef in s {
        let c = coef as i32;
        bits.push((c < 0) as u8);
        let a = c.unsigned_abs();
        // 7 low bits, most-significant first.
        for k in (0..7).rev() {
            bits.push(((a >> k) & 1) as u8);
        }
        // High bits in unary: `a >> 7` zeros, then a terminating 1.
        let unary_end = bits.len() + (a >> 7) as usize;
        bits.resize(unary_end, 0);
        bits.push(1);
    }
    if bits.len() > 8 * slen {
        return None; // too long
    }
    bits.resize(8 * slen, 0);
    let mut out = alloc::vec![0u8; slen];
    for (i, &b) in bits.iter().enumerate() {
        if b == 1 {
            out[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    Some(out)
}

/// `true` iff every coefficient fits a `w`-bit two's-complement field — that
/// is, iff [`pack_signed`] can encode it without truncation. This is exactly
/// the range [`unpack_signed`] can produce, so anything that passes here
/// round-trips.
pub(crate) fn fits_signed(coeffs: &[i64], w: u32) -> bool {
    let hi = (1i64 << (w - 1)) - 1;
    let lo = -(1i64 << (w - 1));
    in_range_all(coeffs, lo, hi)
}

/// Branch-free "every coefficient in `[lo, hi]`": ORs the sign bits of
/// `c - lo` and `hi - c` over the whole slice instead of `all()`, which would
/// stop at the first out-of-range secret coefficient.
fn in_range_all(coeffs: &[i64], lo: i64, hi: i64) -> bool {
    let bad = coeffs
        .iter()
        .fold(0i64, |acc, &c| acc | (c - lo) | (hi - c));
    bad >= 0
}

/// The stricter *symmetric* range the Falcon reference implementation demands
/// of a freshly generated key (`Zf(trim_i8_encode)`: `[-(2^(w-1) − 1),
/// 2^(w-1) − 1]`, excluding the most-negative value). Key generation retries
/// until every coefficient fits, so keys this crate produces stay byte-
/// compatible with the reference encoder.
pub(crate) fn fits_reference_signed(coeffs: &[i64], w: u32) -> bool {
    let hi = (1i64 << (w - 1)) - 1;
    in_range_all(coeffs, -hi, hi)
}

/// Pack `n` signed coefficients at `w` bits each (two's complement, MSB first).
/// `n·w` is a multiple of 8 for the Falcon parameter sets, so the result is
/// byte-aligned.
///
/// Returns `None` if any coefficient is outside the `w`-bit range. Truncating
/// instead (`c & ((1 << w) - 1)`, as this used to do) produces a corrupt
/// encoding that the decoder later rejects — silent, unrecoverable key loss for
/// anyone who generated a key, wrote it to disk and restarted.
fn pack_signed(coeffs: &[i64], w: u32) -> Option<Zeroizing<Vec<u8>>> {
    if !fits_signed(coeffs, w) {
        return None;
    }
    // One byte per bit of a secret polynomial: exactly sized (so it never
    // reallocates) and wiped on drop, as is the packed result — the caller
    // copies it into the key encoding.
    let mut bits: Zeroizing<Vec<u8>> =
        Zeroizing::new(Vec::with_capacity(coeffs.len() * w as usize));
    for &c in coeffs {
        let u = c & ((1i64 << w) - 1);
        for k in (0..w).rev() {
            bits.push(((u >> k) & 1) as u8);
        }
    }
    let mut out = Zeroizing::new(alloc::vec![0u8; bits.len() / 8]);
    for (i, &b) in bits.iter().enumerate() {
        if b == 1 {
            out[i / 8] |= 1 << (7 - (i % 8));
        }
    }
    Some(out)
}

/// Inverse of [`pack_signed`]: read `n` sign-extended `w`-bit coefficients.
///
/// Returns `None` if `bytes` is too short to hold `n·w` bits, so the primitive
/// is total on any input rather than relying on the caller having pre-validated
/// the length (which would otherwise panic on an out-of-bounds index).
fn unpack_signed(bytes: &[u8], n: usize, w: u32) -> Option<Zeroizing<Vec<i64>>> {
    // Reject inputs that cannot supply every requested bit before indexing.
    if (n * w as usize).div_ceil(8) > bytes.len() {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(n));
    let mut pos = 0usize;
    for _ in 0..n {
        let mut v: i64 = 0;
        for _ in 0..w {
            let bit = (bytes[pos >> 3] >> (7 - (pos & 7))) & 1;
            v = (v << 1) | bit as i64;
            pos += 1;
        }
        // Sign-extend from w bits without branching on the (secret) sign bit.
        let sign = 1i64 << (w - 1);
        v = (v ^ sign) - sign;
        out.push(v);
    }
    Some(out)
}

/// Bit width for `f`/`g` coefficients in the compact secret key: 6 bits for
/// `n = 512`, 5 bits for `n = 1024` (spec §3.11.5).
pub(crate) fn fg_bits(n: usize) -> u32 {
    if n <= 512 { 6 } else { 5 }
}

/// Encode a secret key into the compact form: `0101nnnn` header, then `f` and
/// `g` at `fg_bits` each and `F` at 8 bits (`G` is recomputed on decode).
///
/// Returns `None` if any coefficient is outside the field width it is packed
/// into, rather than emitting a wrapped encoding that would decode to a
/// different — and invalid — key.
pub(crate) fn encode_privkey(f: &[i64], g: &[i64], cap_f: &[i64], logn: u8) -> Option<Vec<u8>> {
    let n = f.len();
    let w = fg_bits(n);
    // The packed fields are wiped on drop (also when a later field fails),
    // and the output is allocated at its final size so appending them never
    // reallocates and strands a partial copy of the key.
    let pf = pack_signed(f, w)?;
    let pg = pack_signed(g, w)?;
    let pcf = pack_signed(cap_f, 8)?;
    let mut out = Vec::with_capacity(1 + pf.len() + pg.len() + pcf.len());
    out.push(0x50 | logn);
    out.extend_from_slice(&pf);
    out.extend_from_slice(&pg);
    out.extend_from_slice(&pcf);
    Some(out)
}

/// Decode the compact secret key into `(f, g, F)`; returns `None` on a bad
/// header or length. `G` must be recomputed by the caller.
///
/// Every field is additionally required to be in the *symmetric* range
/// [`fits_reference_signed`] describes — the most-negative `w`-bit value
/// (`-2^(w-1)`) is forbidden, matching the reference `Zf(trim_i8_decode)`, which
/// returns failure on exactly that pattern. Key generation never emits it, so
/// this only ever rejects keys the reference implementation would reject too.
pub(crate) fn decode_privkey(bytes: &[u8], n: usize) -> Option<(Vec<i64>, Vec<i64>, Vec<i64>)> {
    let w = fg_bits(n);
    let fg_len = n * w as usize / 8;
    let f_len = 8 * n / 8; // F at 8 bits
    let expected = 1 + 2 * fg_len + f_len;
    if bytes.len() != expected {
        return None;
    }
    let body = &bytes[1..];
    // Held wiped-on-drop until the range checks pass, so a rejected key's
    // polynomials are not freed in the clear.
    let mut f = unpack_signed(&body[..fg_len], n, w)?;
    let mut g = unpack_signed(&body[fg_len..2 * fg_len], n, w)?;
    let mut cap_f = unpack_signed(&body[2 * fg_len..], n, 8)?;
    if !fits_reference_signed(&f, w)
        || !fits_reference_signed(&g, w)
        || !fits_reference_signed(&cap_f, 8)
    {
        return None;
    }
    Some((
        core::mem::take(&mut *f),
        core::mem::take(&mut *g),
        core::mem::take(&mut *cap_f),
    ))
}

/// Pack a public key `h` (each coefficient in `[0, q)`) into the encoded form:
/// a `0000nnnn` header byte followed by `⌈14n/8⌉` bytes of 14-bit big-endian
/// coefficients. Inverse of `FalconPublicKey::from_bytes`.
pub(crate) fn encode_pubkey(h: &[u16], logn: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + (14 * h.len()).div_ceil(8));
    out.push(logn); // top nibble zero
    let mut acc: u32 = 0;
    let mut acc_bits: u32 = 0;
    for &c in h {
        acc = (acc << 14) | (c as u32 & 0x3FFF);
        acc_bits += 14;
        while acc_bits >= 8 {
            acc_bits -= 8;
            out.push((acc >> acc_bits) as u8);
        }
    }
    if acc_bits > 0 {
        out.push((acc << (8 - acc_bits)) as u8);
    }
    out
}
