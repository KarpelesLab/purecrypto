//! Argon2 v1.3 — memory-hard password-hashing function (RFC 9106), all three
//! variants:
//!
//!  - [`Argon2Type::Argon2d`]  — data-dependent indexing; fastest on a GPU
//!    adversary but offers no resistance to side-channel attacks. Suitable
//!    for back-end uses where the attacker has no concurrent observation.
//!  - [`Argon2Type::Argon2i`]  — data-independent indexing; constant-time
//!    memory access pattern, resistant to side channels at the cost of
//!    some TMTO weakness for low memory.
//!  - [`Argon2Type::Argon2id`] — the recommended hybrid: Argon2i for the
//!    first half of the first pass (where the side-channel risk is highest),
//!    Argon2d for the remainder.
//!
//! All variants share the same memory matrix layout `B[i][j]` and compression
//! function `G`; they differ only in how each block's reference index is
//! chosen. The implementation is sequential — no thread parallelism even
//! when `parallelism > 1` — the output is byte-identical to a parallel
//! implementation because the slice ordering serializes lanes deterministically.
//!
//! Behind `feature = "alloc"`: Argon2 allocates `m_cost_kib · 1024` bytes
//! for the memory matrix.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::hash::Blake2bMac;

/// Argon2 variant: which addressing scheme to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Argon2Type {
    /// Data-dependent indexing (fastest but side-channel-exposed).
    Argon2d,
    /// Data-independent indexing (constant-time memory access).
    Argon2i,
    /// Hybrid (recommended default).
    Argon2id,
}

impl Argon2Type {
    fn ty_byte(self) -> u32 {
        match self {
            Argon2Type::Argon2d => 0,
            Argon2Type::Argon2i => 1,
            Argon2Type::Argon2id => 2,
        }
    }
}

/// Argon2 cost parameters.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    /// Number of iterations (`t`).
    pub t_cost: u32,
    /// Memory cost in KiB (`m`).
    pub m_cost_kib: u32,
    /// Lane count / parallelism (`p`).
    pub parallelism: u32,
    /// Variant.
    pub variant: Argon2Type,
    /// Version (Argon2 v1.3 = `0x13`).
    pub version: u32,
}

impl Argon2Params {
    /// RFC 9106 §4 high-memory recommendation, with `t_cost = 1`.
    pub fn recommended() -> Self {
        Argon2Params {
            t_cost: 1,
            m_cost_kib: 2 * 1024 * 1024, // 2 GiB
            parallelism: 4,
            variant: Argon2Type::Argon2id,
            version: 0x13,
        }
    }
}

/// Argon2 parameter-validation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// One of the cost parameters is outside RFC 9106's permitted range, or
    /// the output buffer is too small / large.
    InvalidParam,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("argon2: invalid parameter")
    }
}

impl core::error::Error for Error {}

/// Computes Argon2 over `(password, salt, secret, ad)` with the chosen
/// parameters, writing `out.len()` bytes into `out`. `out.len()` must be
/// in `4..=2^32 − 1` and `salt.len()` in `8..=2^32 − 1` (RFC 9106 §3.1:
/// the reference implementation's 8-byte minimum; 16 bytes is
/// recommended).
///
/// # Untrusted parameters
///
/// `m_cost_kib` and `t_cost` have **no upper bound** here: Argon2 allocates
/// `m_cost_kib · 1024` bytes and runs `t_cost` passes over them, so a
/// hostile `(m, t)` pair is an OOM/CPU-exhaustion DoS vector. Callers that
/// derive these costs from untrusted input — e.g. the `m=`/`t=` fields of a
/// parsed PHC `$argon2...$` string — MUST clamp them to sane maxima before
/// calling. (Compare PBES2, which caps the attacker-controlled PBKDF2
/// iteration count it accepts from a key file.)
pub fn argon2(
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    ad: &[u8],
    out: &mut [u8],
) -> Result<(), Error> {
    // --- Parameter bounds (RFC 9106 §3.1) ---
    if params.parallelism == 0 || params.parallelism > (1u32 << 24) - 1 {
        return Err(Error::InvalidParam);
    }
    if params.t_cost == 0 {
        return Err(Error::InvalidParam);
    }
    if params.m_cost_kib < 8 * params.parallelism {
        return Err(Error::InvalidParam);
    }
    if !matches!(params.version, 0x10 | 0x13) {
        return Err(Error::InvalidParam);
    }
    if !(4..=(u32::MAX as usize)).contains(&out.len()) {
        return Err(Error::InvalidParam);
    }
    if password.len() > u32::MAX as usize
        || salt.len() > u32::MAX as usize
        || secret.len() > u32::MAX as usize
        || ad.len() > u32::MAX as usize
    {
        return Err(Error::InvalidParam);
    }
    // RFC 9106 §3.1 / reference implementation: at least 8 bytes of salt.
    // Shorter (or empty) salts gut Argon2's defense against precomputation.
    if salt.len() < 8 {
        return Err(Error::InvalidParam);
    }

    let p = params.parallelism as usize;
    let m_prime = 4 * p * (params.m_cost_kib as usize / (4 * p)); // floor to multiple of 4p
    if m_prime < 8 * p {
        return Err(Error::InvalidParam);
    }
    let q = m_prime / p;
    let seg_len = q / 4;

    // --- H0 = BLAKE2b(p ‖ T ‖ m ‖ t ‖ v ‖ y ‖ |P| ‖ P ‖ |S| ‖ S ‖ |K| ‖ K ‖ |X| ‖ X) ---
    let mut h0 = [0u8; 64];
    {
        let mut mac = Blake2bMac::new_unkeyed(64);
        let outlen = out.len() as u32;
        mac.update(&params.parallelism.to_le_bytes());
        mac.update(&outlen.to_le_bytes());
        mac.update(&params.m_cost_kib.to_le_bytes());
        mac.update(&params.t_cost.to_le_bytes());
        mac.update(&params.version.to_le_bytes());
        mac.update(&params.variant.ty_byte().to_le_bytes());
        mac.update(&(password.len() as u32).to_le_bytes());
        mac.update(password);
        mac.update(&(salt.len() as u32).to_le_bytes());
        mac.update(salt);
        mac.update(&(secret.len() as u32).to_le_bytes());
        mac.update(secret);
        mac.update(&(ad.len() as u32).to_le_bytes());
        mac.update(ad);
        mac.finalize_into(&mut h0);
    }

    // --- Allocate the memory matrix: m' 1024-byte blocks ---
    // Guard the matrix size: on 32-bit targets m' · 1024 can wrap usize for
    // per-RFC "valid" params, which would under-allocate and lead to OOB
    // panics. Match the checked_mul discipline of the sibling scrypt code.
    let mem_len = m_prime.checked_mul(1024).ok_or(Error::InvalidParam)?;
    let mut mem: Vec<u8> = vec![0u8; mem_len];
    let block_off = |i: usize, j: usize| -> usize { (i * q + j) * 1024 };

    // --- Initialize B[i][0] and B[i][1] for each lane i ---
    for i in 0..p {
        // B[i][0] = H'(H0 ‖ LE32(0) ‖ LE32(i), 1024)
        let mut input = [0u8; 64 + 8];
        input[..64].copy_from_slice(&h0);
        input[64..68].copy_from_slice(&0u32.to_le_bytes());
        input[68..72].copy_from_slice(&(i as u32).to_le_bytes());
        let off = block_off(i, 0);
        h_prime(&input, &mut mem[off..off + 1024]);

        // B[i][1] = H'(H0 ‖ LE32(1) ‖ LE32(i), 1024)
        input[64..68].copy_from_slice(&1u32.to_le_bytes());
        let off = block_off(i, 1);
        h_prime(&input, &mut mem[off..off + 1024]);
    }

    // H0 is password-derived and only needed for lane initialization; wipe
    // it before the long main loop runs.
    h0.iter_mut().for_each(|b| *b = 0);
    let _ = core::hint::black_box(&h0);

    // --- Main loop: t passes × 4 slices × p lanes × seg_len blocks ---
    for pass in 0..params.t_cost as usize {
        for slice in 0..4 {
            for lane in 0..p {
                fill_segment(&mut mem, pass, slice, lane, p, q, seg_len, params);
            }
        }
    }

    // --- Final block C = ⨁ B[i][q-1] ---
    let mut c = [0u8; 1024];
    c.copy_from_slice(&mem[block_off(0, q - 1)..block_off(0, q - 1) + 1024]);
    for i in 1..p {
        let off = block_off(i, q - 1);
        for k in 0..1024 {
            c[k] ^= mem[off + k];
        }
    }

    // --- Output = H'(C, T) ---
    h_prime(&c, out);

    // Wipe the password-derived working buffers before they drop. There are no
    // early returns past the `mem` allocation above, so this single pass covers
    // every non-panic exit; `black_box` keeps the writes from being elided.
    c.iter_mut().for_each(|b| *b = 0);
    mem.iter_mut().for_each(|b| *b = 0);
    let _ = core::hint::black_box(&c);
    let _ = core::hint::black_box(&mem);
    Ok(())
}

/// Processes one (pass, slice, lane) segment: `seg_len` blocks in lane `lane`,
/// columns `slice·seg_len .. (slice+1)·seg_len`. Reads B[i][j-1] and a
/// reference block determined per the variant's indexing rules.
#[allow(clippy::too_many_arguments)]
fn fill_segment(
    mem: &mut [u8],
    pass: usize,
    slice: usize,
    lane: usize,
    p: usize,
    q: usize,
    seg_len: usize,
    params: &Argon2Params,
) {
    let block_off = |i: usize, j: usize| -> usize { (i * q + j) * 1024 };

    // Decide whether THIS segment uses data-independent (Argon2i-style) addressing.
    let data_independent = match params.variant {
        Argon2Type::Argon2i => true,
        Argon2Type::Argon2d => false,
        Argon2Type::Argon2id => pass == 0 && slice < 2,
    };

    // Pre-compute (J1, J2) pairs for the Argon2i / Argon2id-first-half path.
    let pseudo_random_pairs: Vec<(u32, u32)> = if data_independent {
        compute_addresses(pass, lane, slice, p, q, seg_len, params)
    } else {
        Vec::new()
    };

    let start_idx = if pass == 0 && slice == 0 { 2 } else { 0 };

    // Stack copies of the previous / reference blocks, reused across the
    // segment and wiped once at the end (they hold password-derived state).
    let mut prev_buf = [0u8; 1024];
    let mut ref_buf = [0u8; 1024];

    #[allow(clippy::needless_range_loop)]
    for i_seg in start_idx..seg_len {
        let j_abs = slice * seg_len + i_seg; // absolute column
        let prev_col = if j_abs == 0 { q - 1 } else { j_abs - 1 };

        // Get J1, J2 — either from previous block (Argon2d) or precomputed
        // pseudo-random stream (Argon2i / first-half Argon2id).
        let (j1, j2) = if data_independent {
            pseudo_random_pairs[i_seg]
        } else {
            let prev = &mem[block_off(lane, prev_col)..block_off(lane, prev_col) + 1024];
            let j1 = u32::from_le_bytes(prev[..4].try_into().unwrap());
            let j2 = u32::from_le_bytes(prev[4..8].try_into().unwrap());
            (j1, j2)
        };

        // Reference block index.
        let (ref_lane, ref_col) =
            compute_ref_index(pass, lane, slice, i_seg, p, q, seg_len, j1, j2);

        // B[lane][j_abs] = G(B[lane][prev_col], B[ref_lane][ref_col])
        // (or XOR with current B[lane][j_abs] on pass > 0, per v1.3).
        let prev_off = block_off(lane, prev_col);
        let ref_off = block_off(ref_lane, ref_col);
        let dst_off = block_off(lane, j_abs);

        prev_buf.copy_from_slice(&mem[prev_off..prev_off + 1024]);
        ref_buf.copy_from_slice(&mem[ref_off..ref_off + 1024]);

        let xor_into = pass > 0 && params.version == 0x13;
        g_compress(
            &prev_buf,
            &ref_buf,
            &mut mem[dst_off..dst_off + 1024],
            xor_into,
        );
    }

    prev_buf.iter_mut().for_each(|b| *b = 0);
    ref_buf.iter_mut().for_each(|b| *b = 0);
    let _ = core::hint::black_box(&prev_buf);
    let _ = core::hint::black_box(&ref_buf);
}

/// Argon2i / Argon2id (first-half) pseudo-random address generation. Produces
/// one (J1, J2) pair per block in the segment.
fn compute_addresses(
    pass: usize,
    lane: usize,
    slice: usize,
    p: usize,
    q: usize,
    seg_len: usize,
    params: &Argon2Params,
) -> Vec<(u32, u32)> {
    let mut pairs = Vec::with_capacity(seg_len);
    let zero_block = [0u8; 1024];
    let mut input = [0u8; 1024];
    let mut addr_block = [0u8; 1024];

    // Each ADDR_BLOCK gives 128 (J1, J2) pairs.
    let mut counter: u64 = 0;
    while pairs.len() < seg_len {
        counter += 1;

        // Build INPUT_BLOCK with the segment parameters and counter.
        for b in input.iter_mut() {
            *b = 0;
        }
        input[0..8].copy_from_slice(&(pass as u64).to_le_bytes());
        input[8..16].copy_from_slice(&(lane as u64).to_le_bytes());
        input[16..24].copy_from_slice(&(slice as u64).to_le_bytes());
        input[24..32].copy_from_slice(&((p * q) as u64).to_le_bytes()); // total blocks m'
        input[32..40].copy_from_slice(&(params.t_cost as u64).to_le_bytes());
        input[40..48].copy_from_slice(&(params.variant.ty_byte() as u64).to_le_bytes());
        input[48..56].copy_from_slice(&counter.to_le_bytes());

        // ADDR_BLOCK = G(zero, G(zero, INPUT_BLOCK))
        let mut tmp = [0u8; 1024];
        g_compress(&zero_block, &input, &mut tmp, false);
        g_compress(&zero_block, &tmp, &mut addr_block, false);

        for chunk_idx in 0..128 {
            if pairs.len() >= seg_len {
                break;
            }
            let off = chunk_idx * 8;
            let j1 = u32::from_le_bytes(addr_block[off..off + 4].try_into().unwrap());
            let j2 = u32::from_le_bytes(addr_block[off + 4..off + 8].try_into().unwrap());
            pairs.push((j1, j2));
        }
    }
    pairs
}

/// Maps (J1, J2) to a `(ref_lane, ref_col)` using RFC 9106 §3.4's mapping.
#[allow(clippy::too_many_arguments)]
fn compute_ref_index(
    pass: usize,
    lane: usize,
    slice: usize,
    j_within_seg: usize,
    p: usize,
    q: usize,
    seg_len: usize,
    j1: u32,
    j2: u32,
) -> (usize, usize) {
    // Reference lane.
    let ref_lane = if pass == 0 && slice == 0 {
        lane
    } else {
        (j2 as usize) % p
    };

    let same_lane = ref_lane == lane;

    // Size of the reference area W.
    let w: usize = if pass == 0 {
        if slice == 0 {
            // Only this segment is candidate (this block depends on prev only).
            j_within_seg - 1
        } else if same_lane {
            slice * seg_len + j_within_seg - 1
        } else if j_within_seg == 0 {
            slice * seg_len - 1
        } else {
            slice * seg_len
        }
    } else if same_lane {
        q - seg_len + j_within_seg - 1
    } else if j_within_seg == 0 {
        q - seg_len - 1
    } else {
        q - seg_len
    };

    // Map J1 into [0, W-1].
    let x = ((j1 as u64).wrapping_mul(j1 as u64)) >> 32;
    let y = ((w as u64).wrapping_mul(x)) >> 32;
    let z = w - 1 - (y as usize);

    let start: usize = if pass == 0 {
        0
    } else {
        ((slice + 1) * seg_len) % q
    };

    let ref_col = (start + z) % q;
    (ref_lane, ref_col)
}

// --------------------------------------------------------------------------
// H' — Argon2's variable-output BLAKE2b wrapper (RFC 9106 §3.3).
// --------------------------------------------------------------------------
fn h_prime(input: &[u8], out: &mut [u8]) {
    let outlen = out.len() as u32;
    let outlen_bytes = outlen.to_le_bytes();
    if out.len() <= 64 {
        let mut mac = Blake2bMac::new_unkeyed(out.len());
        mac.update(&outlen_bytes);
        mac.update(input);
        mac.finalize_into(out);
        return;
    }

    // V_1 = BLAKE2b_64(LE32(T) ‖ input).
    let mut v = [0u8; 64];
    {
        let mut mac = Blake2bMac::new_unkeyed(64);
        mac.update(&outlen_bytes);
        mac.update(input);
        mac.finalize_into(&mut v);
    }
    out[..32].copy_from_slice(&v[..32]);

    let r = out.len().div_ceil(32) - 2;
    let mut written = 32;
    for _ in 1..r {
        let mut next = [0u8; 64];
        let mut mac = Blake2bMac::new_unkeyed(64);
        mac.update(&v);
        mac.finalize_into(&mut next);
        out[written..written + 32].copy_from_slice(&next[..32]);
        written += 32;
        v = next;
    }
    // V_{r+1} = BLAKE2b(V_r, T - 32·r).
    let final_len = out.len() - 32 * r;
    let mut mac = Blake2bMac::new_unkeyed(final_len);
    mac.update(&v);
    mac.finalize_into(&mut out[written..]);
}

// --------------------------------------------------------------------------
// G compression function (RFC 9106 §3.6).
// --------------------------------------------------------------------------

/// BLAKE2b-style mixing function `GB` used by Argon2.
#[inline]
fn gb(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    let f = |x: u64, y: u64| 2u64.wrapping_mul((x & 0xffff_ffff).wrapping_mul(y & 0xffff_ffff));
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(f(v[a], v[b]));
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]).wrapping_add(f(v[c], v[d]));
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(f(v[a], v[b]));
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]).wrapping_add(f(v[c], v[d]));
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// One BLAKE2b round: column-then-diagonal GB sequence on a `[u64; 16]`.
fn p_round(v: &mut [u64; 16]) {
    gb(v, 0, 4, 8, 12);
    gb(v, 1, 5, 9, 13);
    gb(v, 2, 6, 10, 14);
    gb(v, 3, 7, 11, 15);
    gb(v, 0, 5, 10, 15);
    gb(v, 1, 6, 11, 12);
    gb(v, 2, 7, 8, 13);
    gb(v, 3, 4, 9, 14);
}

/// `G(X, Y)` writes the resulting 1024-byte block to `out`. If `xor_into` is
/// true, the result is XORed into the existing contents of `out` (Argon2 v1.3
/// pass > 0 behavior).
fn g_compress(x: &[u8; 1024], y: &[u8; 1024], out: &mut [u8], xor_into: bool) {
    let mut r = [0u64; 128];
    let mut z = [0u64; 128];
    for i in 0..128 {
        let xi = u64::from_le_bytes(x[i * 8..i * 8 + 8].try_into().unwrap());
        let yi = u64::from_le_bytes(y[i * 8..i * 8 + 8].try_into().unwrap());
        r[i] = xi ^ yi;
        z[i] = r[i];
    }

    // Apply P to each row (16 consecutive u64s).
    for row in 0..8 {
        let mut tmp = [0u64; 16];
        tmp.copy_from_slice(&z[row * 16..row * 16 + 16]);
        p_round(&mut tmp);
        z[row * 16..row * 16 + 16].copy_from_slice(&tmp);
    }

    // Apply P to each "column" (2 consecutive u64s per row, 8 rows → 16 u64s).
    for col in 0..8 {
        let mut tmp = [0u64; 16];
        for i in 0..8 {
            tmp[2 * i] = z[16 * i + 2 * col];
            tmp[2 * i + 1] = z[16 * i + 2 * col + 1];
        }
        p_round(&mut tmp);
        for i in 0..8 {
            z[16 * i + 2 * col] = tmp[2 * i];
            z[16 * i + 2 * col + 1] = tmp[2 * i + 1];
        }
    }

    // Output = R ⊕ Z (optionally XORed into existing `out`).
    for i in 0..128 {
        let val = r[i] ^ z[i];
        let off = i * 8;
        if xor_into {
            let prev = u64::from_le_bytes(out[off..off + 8].try_into().unwrap());
            out[off..off + 8].copy_from_slice(&(prev ^ val).to_le_bytes());
        } else {
            out[off..off + 8].copy_from_slice(&val.to_le_bytes());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::from_hex;

    /// Common RFC 9106 §5 test-vector parameters.
    fn rfc_inputs() -> (Argon2Params, [u8; 32], [u8; 16], [u8; 8], [u8; 12]) {
        let mut p = [0u8; 32];
        for b in p.iter_mut() {
            *b = 1;
        }
        let mut s = [0u8; 16];
        for b in s.iter_mut() {
            *b = 2;
        }
        let mut k = [0u8; 8];
        for b in k.iter_mut() {
            *b = 3;
        }
        let mut x = [0u8; 12];
        for b in x.iter_mut() {
            *b = 4;
        }
        let params = Argon2Params {
            t_cost: 3,
            m_cost_kib: 32,
            parallelism: 4,
            variant: Argon2Type::Argon2d,
            version: 0x13,
        };
        (params, p, s, k, x)
    }

    /// RFC 9106 §5.1: Argon2d test vector.
    #[test]
    fn rfc9106_argon2d() {
        let (mut params, p, s, k, x) = rfc_inputs();
        params.variant = Argon2Type::Argon2d;
        let expected = from_hex::<32>(
            "512b391b6f1162975371d3091973429\
             4f868e3be3984f3c1a13a4db9fabe4acb",
        );
        let mut out = [0u8; 32];
        argon2(&params, &p, &s, &k, &x, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    /// RFC 9106 §5.2: Argon2i test vector.
    #[test]
    fn rfc9106_argon2i() {
        let (mut params, p, s, k, x) = rfc_inputs();
        params.variant = Argon2Type::Argon2i;
        let expected = from_hex::<32>(
            "c814d9d1dc7f37aa13f0d77f2494bd\
             a1c8de6b016dd388d29952a4c4672b6ce8",
        );
        let mut out = [0u8; 32];
        argon2(&params, &p, &s, &k, &x, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    /// RFC 9106 §5.3: Argon2id test vector.
    #[test]
    fn rfc9106_argon2id() {
        let (mut params, p, s, k, x) = rfc_inputs();
        params.variant = Argon2Type::Argon2id;
        let expected = from_hex::<32>(
            "0d640df58d78766c08c037a34a8b\
             53c9d01ef0452d75b65eb52520e96b01e659",
        );
        let mut out = [0u8; 32];
        argon2(&params, &p, &s, &k, &x, &mut out).unwrap();
        assert_eq!(out, expected);
    }

    #[test]
    fn rejects_invalid_params() {
        let mut out = [0u8; 32];
        let bad_t = Argon2Params {
            t_cost: 0,
            m_cost_kib: 32,
            parallelism: 4,
            variant: Argon2Type::Argon2id,
            version: 0x13,
        };
        assert_eq!(
            argon2(&bad_t, b"p", b"saltsalt", b"", b"", &mut out),
            Err(Error::InvalidParam)
        );
        let bad_p = Argon2Params {
            t_cost: 1,
            m_cost_kib: 32,
            parallelism: 0,
            variant: Argon2Type::Argon2id,
            version: 0x13,
        };
        assert_eq!(
            argon2(&bad_p, b"p", b"saltsalt", b"", b"", &mut out),
            Err(Error::InvalidParam)
        );
        let bad_m = Argon2Params {
            t_cost: 1,
            m_cost_kib: 16, // < 8·p = 32
            parallelism: 4,
            variant: Argon2Type::Argon2id,
            version: 0x13,
        };
        assert_eq!(
            argon2(&bad_m, b"p", b"saltsalt", b"", b"", &mut out),
            Err(Error::InvalidParam)
        );
        let bad_v = Argon2Params {
            t_cost: 1,
            m_cost_kib: 32,
            parallelism: 4,
            variant: Argon2Type::Argon2id,
            version: 0x42,
        };
        assert_eq!(
            argon2(&bad_v, b"p", b"saltsalt", b"", b"", &mut out),
            Err(Error::InvalidParam)
        );
        // Salt below the RFC 9106 8-byte minimum (incl. empty) is rejected.
        let ok = Argon2Params {
            t_cost: 1,
            m_cost_kib: 32,
            parallelism: 4,
            variant: Argon2Type::Argon2id,
            version: 0x13,
        };
        assert_eq!(
            argon2(&ok, b"p", b"7bytes!", b"", b"", &mut out),
            Err(Error::InvalidParam)
        );
        assert_eq!(
            argon2(&ok, b"p", b"", b"", b"", &mut out),
            Err(Error::InvalidParam)
        );
        // The 8-byte boundary itself is accepted.
        assert!(argon2(&ok, b"p", b"saltsalt", b"", b"", &mut out).is_ok());
    }
}
