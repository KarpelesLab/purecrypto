//! OBJECT IDENTIFIER arc encoding/decoding.

use super::{Error, encode_oid};
use alloc::string::String;
use alloc::vec::Vec;

/// Appends `value` to `out` in base-128, high bit set on all but the final
/// (least-significant) group.
fn push_base128(out: &mut Vec<u8>, value: u64) {
    let mut groups = [0u8; 10];
    let mut n = 0;
    let mut v = value;
    loop {
        groups[n] = (v & 0x7f) as u8;
        v >>= 7;
        n += 1;
        if v == 0 {
            break;
        }
    }
    for i in (0..n).rev() {
        out.push(if i > 0 { groups[i] | 0x80 } else { groups[i] });
    }
}

/// Encodes OID arcs (e.g. `[1, 2, 840, 113549, 1, 1, 1]`) into the DER OID
/// body. Requires at least two arcs.
///
/// The first sub-identifier carries `arc0` and `arc1` jointly: for
/// `arc0 ∈ {0, 1}`, X.690 §8.19.4 mandates `arc1 < 40`, and the encoded
/// value is `40·arc0 + arc1`. For `arc0 = 2`, `arc1` is unbounded, and the
/// encoded value is `80 + arc1`. The decoder in [`parse_oid`] mirrors this.
///
/// # Panics
/// Panics if fewer than two arcs are given.
pub fn encode_oid_arcs(arcs: &[u64]) -> Vec<u8> {
    assert!(arcs.len() >= 2, "OID needs at least two arcs");
    let mut body = Vec::new();
    let first = if arcs[0] < 2 {
        40 * arcs[0] + arcs[1]
    } else {
        80 + arcs[1]
    };
    push_base128(&mut body, first);
    for &arc in &arcs[2..] {
        push_base128(&mut body, arc);
    }
    body
}

/// Parses a DER OID body into its arcs. Enforces X.690 §8.19 canonical
/// encoding: no leading 0x80 (would be a redundant continuation byte), and
/// rejects arcs that don't fit in `u64`.
pub fn parse_oid(body: &[u8]) -> Result<Vec<u64>, Error> {
    if body.is_empty() {
        return Err(Error::Malformed);
    }
    let mut arcs = Vec::new();
    let mut acc: u64 = 0;
    let mut started = false;
    let mut arc_first_byte_idx: Option<usize> = None;
    for (i, &b) in body.iter().enumerate() {
        // Canonical encoding: the first byte of a multi-byte arc must not
        // be 0x80 (that would be a redundant leading-zero continuation).
        if !started && b == 0x80 {
            return Err(Error::Malformed);
        }
        // Detect arc overflow: shifting `acc` left by 7 must not lose bits.
        // `acc` is at most `(2^64 − 1) >> 7` before the shift, so any high
        // 7 bits indicate a value too wide for `u64`.
        if (acc >> 57) != 0 {
            return Err(Error::Malformed);
        }
        if !started {
            arc_first_byte_idx = Some(i);
            started = true;
        }
        acc = (acc << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                // Per X.690 §8.19.4 the first sub-identifier encodes the
                // joint value `40·arc0 + arc1` for `arc0 ∈ {0, 1}` (with
                // `arc1 < 40`). For `arc0 = 2`, `arc1` may be ≥ 40, and the
                // encoded value is `80 + arc1`.
                if acc < 80 {
                    arcs.push(acc / 40);
                    arcs.push(acc % 40);
                } else {
                    arcs.push(2);
                    arcs.push(acc - 80);
                }
            } else {
                arcs.push(acc);
            }
            acc = 0;
            started = false;
            arc_first_byte_idx = None;
        }
    }
    if started {
        return Err(Error::Malformed); // truncated multi-byte arc
    }
    let _ = arc_first_byte_idx;
    Ok(arcs)
}

/// Formats a DER OID body as a dotted string (e.g. `"1.2.840.113549.1.1.1"`).
pub fn oid_to_string(body: &[u8]) -> Result<String, Error> {
    let arcs = parse_oid(body)?;
    let mut out = String::new();
    for (i, arc) in arcs.iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        // Append the decimal arc without pulling in formatting machinery beyond core.
        out.push_str(&arc_to_string(*arc));
    }
    Ok(out)
}

fn arc_to_string(mut v: u64) -> String {
    if v == 0 {
        return String::from("0");
    }
    let mut digits = [0u8; 20];
    let mut n = 0;
    while v > 0 {
        digits[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut s = String::with_capacity(n);
    for i in (0..n).rev() {
        s.push(digits[i] as char);
    }
    s
}

/// Convenience: a full DER `OBJECT IDENTIFIER` TLV from arcs.
pub fn oid_tlv(arcs: &[u64]) -> Vec<u8> {
    encode_oid(&encode_oid_arcs(arcs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rsa_encryption_oid() {
        // 1.2.840.113549.1.1.1 -> 2a 86 48 86 f7 0d 01 01 01
        let arcs = [1, 2, 840, 113549, 1, 1, 1];
        let body = encode_oid_arcs(&arcs);
        assert_eq!(body, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
        assert_eq!(parse_oid(&body).unwrap(), arcs);
        assert_eq!(oid_to_string(&body).unwrap(), "1.2.840.113549.1.1.1");
    }

    #[test]
    fn common_name_oid() {
        // 2.5.4.3 -> 55 04 03
        let arcs = [2, 5, 4, 3];
        let body = encode_oid_arcs(&arcs);
        assert_eq!(body, [0x55, 0x04, 0x03]);
        assert_eq!(parse_oid(&body).unwrap(), arcs);
    }

    #[test]
    fn rejects_truncated_arc() {
        // Trailing high-bit byte with no terminator.
        assert_eq!(parse_oid(&[0x2a, 0x86]), Err(Error::Malformed));
        assert_eq!(parse_oid(&[]), Err(Error::Malformed));
    }

    #[test]
    fn joint_iso_itu_t_arc1_at_or_above_40() {
        // X.690 §8.19.4: for arc0 = 2, arc1 may be ≥ 40, encoded as
        // `80 + arc1`. The classic "arcs[0] = X/40; arcs[1] = X%40" split
        // mis-decodes `2.40` (joint value 120) as `3.0`.
        for arcs in [
            alloc::vec![2u64, 40, 5],
            alloc::vec![2, 100, 7],
            alloc::vec![2, 999],
            alloc::vec![2, 48, 1, 7],
        ] {
            let body = encode_oid_arcs(&arcs);
            assert_eq!(parse_oid(&body).unwrap(), arcs);
        }

        // Sanity-check a couple of PKIX OIDs that fall in the standard
        // `arc0 < 2` or `arc0 = 2, arc1 < 40` range — they're unaffected.
        for arcs in [
            alloc::vec![1u64, 2, 840, 113549, 1, 1, 1],
            alloc::vec![2, 5, 29, 17],
        ] {
            let body = encode_oid_arcs(&arcs);
            assert_eq!(parse_oid(&body).unwrap(), arcs);
        }
    }
}
