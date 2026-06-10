//! X.509 time values and the validity period.

use alloc::string::String;
use alloc::vec::Vec;

use super::Error;
use crate::der::{Reader, encode_sequence, encode_string, tag};

/// An X.509 time, stored in its ASN.1 textual form. Encoded as `UTCTime`
/// (`YYMMDDHHMMSSZ`), which is valid for years 1950–2049.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Time {
    repr: String,
}

impl Time {
    /// Builds a time from UTC calendar components.
    pub fn utc(year: u64, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Time {
        let mut repr = String::with_capacity(13);
        push2(&mut repr, (year % 100) as u8);
        push2(&mut repr, month);
        push2(&mut repr, day);
        push2(&mut repr, hour);
        push2(&mut repr, minute);
        push2(&mut repr, second);
        repr.push('Z');
        Time { repr }
    }

    /// Builds a time from a Unix timestamp (seconds since 1970-01-01 UTC).
    pub fn from_unix(secs: u64) -> Time {
        let days = (secs / 86_400) as i64;
        let tod = secs % 86_400;
        let (year, month, day) = civil_from_days(days);
        Time::utc(
            year as u64,
            month,
            day,
            (tod / 3600) as u8,
            ((tod % 3600) / 60) as u8,
            (tod % 60) as u8,
        )
    }

    /// Converts the time to a Unix timestamp (seconds since 1970-01-01 UTC).
    /// Returns 0 if the stored representation is malformed or predates the
    /// Unix epoch.
    ///
    /// This collapses "malformed" and "epoch / pre-epoch" into the same `0`,
    /// so a security check that must distinguish a parse failure from a real
    /// 1970 timestamp (e.g. OCSP freshness, which would otherwise treat a
    /// malformed `thisUpdate` as forever-in-the-past) should use
    /// [`Time::to_unix_checked`] instead.
    pub fn to_unix(&self) -> u64 {
        self.to_unix_checked().unwrap_or(0)
    }

    /// Like [`Time::to_unix`], but returns `None` when the stored
    /// representation is malformed (rather than coercing it to `0`). A valid
    /// pre-epoch time also yields `None`, since a Unix timestamp is unsigned.
    /// Callers that must fail closed on unparsable times use this.
    pub fn to_unix_checked(&self) -> Option<u64> {
        let (y, m, d, hh, mm, ss) = self.components()?;
        let days = days_from_civil(y as i64, m, d);
        if days < 0 {
            return None;
        }
        Some((days as u64) * 86_400 + (hh as u64) * 3600 + (mm as u64) * 60 + ss as u64)
    }

    /// The raw ASN.1 time string (e.g. `"240131120000Z"`).
    pub fn as_str(&self) -> &str {
        &self.repr
    }

    pub(crate) fn from_repr(s: &str) -> Time {
        Time {
            repr: String::from(s),
        }
    }

    pub(crate) fn to_der(&self) -> Vec<u8> {
        encode_string(tag::UTC_TIME, &self.repr)
    }

    /// Encodes the time as an ASN.1 `GeneralizedTime`
    /// (`YYYYMMDDHHMMSSZ`, four-digit year), regardless of the year range.
    ///
    /// Used by parts of the OCSP wire format that mandate `GeneralizedTime`
    /// even for dates inside the UTCTime range (RFC 6960's
    /// `producedAt`, `thisUpdate`, `nextUpdate`, and
    /// `RevokedInfo.revocationTime` are all `GeneralizedTime`).
    ///
    /// A [`Time::utc`]-built repr is the 13-byte `YYMMDDHHMMSSZ` form, which
    /// this widens to the 15-byte form using the RFC 5280 century rule
    /// (`YY < 50 ⇒ 2000 + YY` else `1900 + YY`). A repr already in
    /// the 15-byte form is emitted unchanged.
    pub(crate) fn to_generalized_time(&self) -> Vec<u8> {
        let b = self.repr.as_bytes();
        if b.len() == 15 {
            return encode_string(tag::GENERALIZED_TIME, &self.repr);
        }
        // Widen the two-digit year, but only when the first two bytes are
        // actually digits. `two` returns `None` on a non-digit, in which case
        // we fall through to the malformed branch below rather than computing
        // `(b[0] - b'0')` directly (which would underflow on, e.g., `b'-'`).
        if b.len() == 13
            && let Some(yy) = two(b, 0)
        {
            let prefix = if yy < 50 { "20" } else { "19" };
            let mut s = String::with_capacity(15);
            s.push_str(prefix);
            // The remaining 13 bytes (`YYMMDDHHMMSSZ`) carry over verbatim.
            s.push_str(core::str::from_utf8(b).unwrap_or(""));
            return encode_string(tag::GENERALIZED_TIME, &s);
        }
        // Malformed length: fall through with whatever's stored; parsers
        // will surface the malformedness on round-trip.
        encode_string(tag::GENERALIZED_TIME, &self.repr)
    }

    /// Encodes the time using the RFC 5280 §5.1.2.4 `Time` CHOICE: `UTCTime`
    /// for years 1950–2049 (two-digit year, `YYMMDDHHMMSSZ`), otherwise
    /// `GeneralizedTime` (four-digit year, `YYYYMMDDHHMMSSZ`).
    ///
    /// The internal representation is either the 13-byte UTCTime form (as
    /// produced by [`Time::utc`]) or the 15-byte GeneralizedTime form (as
    /// produced by [`Time::from_repr`] for 4-digit-year strings). The tag is
    /// chosen by inspecting which form is stored, with the documented
    /// fall-back rule for years 2050+ — i.e. a Time built via
    /// [`Time::from_repr("20500101000000Z")`] is emitted with the
    /// GeneralizedTime tag (0x18).
    pub(crate) fn to_der_choice(&self) -> Vec<u8> {
        let b = self.repr.as_bytes();
        // GeneralizedTime form: 15 bytes, 4-digit year.
        if b.len() == 15 {
            // Inspect the parsed year to follow RFC 5280: even if stored as
            // 4-digit-year form, prefer UTCTime when the year fits 1950–2049.
            if let Some((y, _m, _d, _h, _mi, _s)) = self.components()
                && (1950..=2049).contains(&y)
            {
                // Build the UTCTime variant by stripping the leading century.
                let yy = y % 100;
                let mut s = alloc::string::String::with_capacity(13);
                s.push(((yy / 10) as u8 + b'0') as char);
                s.push(((yy % 10) as u8 + b'0') as char);
                // Bytes 4..14 hold MMDDHHMMSS, byte 14 is 'Z'.
                s.push_str(core::str::from_utf8(&b[4..15]).unwrap_or(""));
                return encode_string(tag::UTC_TIME, &s);
            }
            return encode_string(tag::GENERALIZED_TIME, &self.repr);
        }
        // UTCTime form: 13 bytes, 2-digit year.
        if b.len() == 13 {
            // Year is in 1950–2049 by the YY < 50 ⇒ 20YY rule; emit UTCTime.
            return encode_string(tag::UTC_TIME, &self.repr);
        }
        // Malformed length: fall back to UTCTime — round-trip will fail at
        // parse time, surfacing the malformedness rather than silently
        // emitting a structurally valid-but-wrong encoding.
        encode_string(tag::UTC_TIME, &self.repr)
    }

    /// Parses the stored ASN.1 time into chronologically sortable components
    /// `(year, month, day, hour, minute, second)`. Handles both `UTCTime`
    /// (`YYMMDDHHMMSSZ`, with the RFC 5280 1950–2049 century rule) and
    /// `GeneralizedTime` (`YYYYMMDDHHMMSSZ`). Returns `None` if malformed —
    /// including calendar-range violations such as month 13, day 32, or a
    /// non-leap-year Feb 29.
    fn components(&self) -> Option<(u16, u8, u8, u8, u8, u8)> {
        let b = self.repr.as_bytes();
        if b.last() != Some(&b'Z') {
            return None;
        }
        let (year, off) = match b.len() {
            13 => {
                let yy = two(b, 0)?;
                let year = if yy < 50 {
                    2000 + yy as u16
                } else {
                    1900 + yy as u16
                };
                (year, 2)
            }
            15 => {
                let year = digit(b, 0)? as u16 * 1000
                    + digit(b, 1)? as u16 * 100
                    + digit(b, 2)? as u16 * 10
                    + digit(b, 3)? as u16;
                (year, 4)
            }
            _ => return None,
        };
        let month = two(b, off)?;
        let day = two(b, off + 2)?;
        let hour = two(b, off + 4)?;
        let minute = two(b, off + 6)?;
        let second = two(b, off + 8)?;
        // Calendar-range validation. RFC 5280 §4.1.2.5 inherits the X.509
        // restriction that hour ∈ 0..=23, minute/second ∈ 0..=59, and the
        // year/month/day triple is a real Gregorian date (Feb 29 only on
        // leap years).
        if !(1..=12).contains(&month) {
            return None;
        }
        if !(1..=days_in_month(year, month)).contains(&day) {
            return None;
        }
        if hour > 23 || minute > 59 || second > 59 {
            return None;
        }
        Some((year, month, day, hour, minute, second))
    }
}

/// Whether `year` is a leap year on the proleptic Gregorian calendar.
fn is_leap_year(year: u16) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Days in `month` (1..=12) of `year`. Returns 0 for an out-of-range month.
fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

fn digit(b: &[u8], i: usize) -> Option<u8> {
    let c = *b.get(i)?;
    // Use `then` (lazy) rather than `then_some` (eager): `c - b'0'` would
    // underflow for a non-digit byte (debug panic / release wrap) if computed
    // unconditionally. This guards every caller, including `two` and the
    // `to_generalized_time` two-digit-year widening.
    c.is_ascii_digit().then(|| c - b'0')
}

fn two(b: &[u8], i: usize) -> Option<u8> {
    Some(digit(b, i)? * 10 + digit(b, i + 1)?)
}

fn push2(s: &mut String, v: u8) {
    s.push((b'0' + (v / 10) % 10) as char);
    s.push((b'0' + v % 10) as char);
}

/// Converts `(year, month, day)` to a day count since 1970-01-01 using Howard
/// Hinnant's `days_from_civil` algorithm.
fn days_from_civil(year: i64, month: u8, day: u8) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let m = month as i64;
    let d = day as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Converts a day count (days since 1970-01-01) to `(year, month, day)` using
/// Howard Hinnant's `civil_from_days` algorithm.
fn civil_from_days(days: i64) -> (i64, u8, u8) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// A certificate validity period.
#[derive(Clone, Debug)]
pub struct Validity {
    /// Not valid before this time.
    pub not_before: Time,
    /// Not valid after this time.
    pub not_after: Time,
}

impl Validity {
    /// Creates a validity period.
    pub fn new(not_before: Time, not_after: Time) -> Self {
        Validity {
            not_before,
            not_after,
        }
    }

    /// Whether `now` falls within `[not_before, not_after]` (inclusive).
    /// Returns `false` if any of the three times is malformed (fail-closed).
    pub fn accepts(&self, now: &Time) -> bool {
        match (
            self.not_before.components(),
            self.not_after.components(),
            now.components(),
        ) {
            (Some(nb), Some(na), Some(n)) => nb <= n && n <= na,
            _ => false,
        }
    }

    pub(crate) fn to_der(&self) -> Vec<u8> {
        encode_sequence(&[self.not_before.to_der(), self.not_after.to_der()].concat())
    }

    pub(crate) fn decode(reader: &mut Reader) -> Result<Self, Error> {
        let mut seq = reader.read_sequence()?;
        let not_before = read_time(&mut seq)?;
        let not_after = read_time(&mut seq)?;
        Ok(Validity {
            not_before,
            not_after,
        })
    }
}

/// Reads one RFC 5280 `Time` (`UTCTime` or `GeneralizedTime`) from `reader`,
/// keying the expected body format off the ASN.1 tag rather than the body
/// length: `UTCTime` (0x17) must be exactly the 13-byte `YYMMDDHHMMSSZ` form
/// and `GeneralizedTime` (0x18) exactly the 15-byte `YYYYMMDDHHMMSSZ` form.
/// RFC 5280 §4.1.2.5 binds each format to its tag, so a mismatched pair —
/// e.g. a 13-byte body under the GeneralizedTime tag — is rejected up front.
/// This guarantees the two-digit-year century rule in [`Time::components`]
/// (which keys off the 13-byte stored form) only ever applies to a value
/// that was actually tagged `UTCTime` on the wire; after this check the
/// stored length uniquely identifies the kind, so `Time` needs no separate
/// discriminant.
pub(super) fn read_time(reader: &mut Reader) -> Result<Time, Error> {
    let (t, value) = reader.read_any()?;
    let expected_len = match t {
        tag::UTC_TIME => 13,
        tag::GENERALIZED_TIME => 15,
        _ => return Err(Error::Malformed),
    };
    if value.len() != expected_len {
        return Err(Error::Malformed);
    }
    let s = core::str::from_utf8(value).map_err(|_| Error::Malformed)?;
    Ok(Time::from_repr(s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formatting() {
        assert_eq!(Time::utc(2024, 1, 31, 12, 0, 0).as_str(), "240131120000Z");
        assert_eq!(Time::utc(2005, 3, 9, 8, 7, 6).as_str(), "050309080706Z");
    }

    #[test]
    fn from_unix_epoch_and_known_dates() {
        assert_eq!(Time::from_unix(0).as_str(), "700101000000Z");
        // 2021-01-01 00:00:00 UTC = 1609459200.
        assert_eq!(Time::from_unix(1_609_459_200).as_str(), "210101000000Z");
        // 2024-02-29 (leap day) 23:59:59 UTC = 1709251199.
        assert_eq!(Time::from_unix(1_709_251_199).as_str(), "240229235959Z");
    }

    #[test]
    fn to_unix_roundtrips() {
        // UTCTime's two-digit year convention pins YY < 50 to 20YY and
        // YY >= 50 to 19YY, so the round-trip is only well defined inside
        // 2000-01-01 .. 2049-12-31 UTC.
        for &s in &[0u64, 1_609_459_200, 1_709_251_199] {
            assert_eq!(Time::from_unix(s).to_unix(), s, "roundtrip fails for {s}");
        }
        // GeneralizedTime path: 4-digit year reaches beyond the UTCTime
        // window.
        assert_eq!(Time::from_repr("20210101000000Z").to_unix(), 1_609_459_200);
        assert_eq!(Time::from_repr("20500101000000Z").to_unix(), 2_524_608_000);
    }

    #[test]
    fn validity_accepts_window() {
        let v = Validity::new(
            Time::utc(2024, 1, 1, 0, 0, 0),
            Time::utc(2034, 1, 1, 0, 0, 0),
        );
        assert!(v.accepts(&Time::utc(2026, 5, 26, 12, 0, 0)));
        assert!(v.accepts(&Time::utc(2024, 1, 1, 0, 0, 0))); // boundary
        assert!(v.accepts(&Time::utc(2034, 1, 1, 0, 0, 0))); // boundary
        assert!(!v.accepts(&Time::utc(2023, 12, 31, 23, 59, 59))); // too early
        assert!(!v.accepts(&Time::utc(2034, 1, 1, 0, 0, 1))); // expired
    }

    #[test]
    fn to_der_choice_picks_utctime_or_generalized() {
        // 1950–2049 ⇒ UTCTime (tag 0x17). 13-byte body.
        let utc = Time::utc(2024, 1, 1, 0, 0, 0).to_der_choice();
        assert_eq!(utc[0], tag::UTC_TIME);
        assert_eq!(utc[1] as usize, 13);
        // 2050+ ⇒ GeneralizedTime (tag 0x18). 15-byte body.
        let g = Time::from_repr("20500101000000Z").to_der_choice();
        assert_eq!(g[0], tag::GENERALIZED_TIME);
        assert_eq!(g[1] as usize, 15);
        // A Time built as a 4-digit-year string but inside the UTCTime window
        // emits UTCTime per RFC 5280 §5.1.2.4.
        let utc2 = Time::from_repr("20240101000000Z").to_der_choice();
        assert_eq!(utc2[0], tag::UTC_TIME);
        assert_eq!(utc2[1] as usize, 13);
    }

    #[test]
    fn components_rejects_out_of_range_fields() {
        // Month 13 is impossible.
        assert!(Time::from_repr("240001000000Z").components().is_none());
        assert!(Time::from_repr("241301000000Z").components().is_none());
        // Day 32 is impossible.
        assert!(Time::from_repr("240132000000Z").components().is_none());
        // Hour 25, minute 60, second 60 are all out of range.
        assert!(Time::from_repr("240101250000Z").components().is_none());
        assert!(Time::from_repr("240101006000Z").components().is_none());
        assert!(Time::from_repr("240101000060Z").components().is_none());
        // April has 30 days, not 31.
        assert!(Time::from_repr("240431000000Z").components().is_none());
        // Feb 29 is valid in leap years, invalid otherwise.
        assert!(Time::from_repr("240229000000Z").components().is_some()); // 2024 leap
        assert!(Time::from_repr("250229000000Z").components().is_none()); // 2025 not leap
        // GeneralizedTime form: 1900 is not a leap year (century not /400).
        assert!(Time::from_repr("20240229000000Z").components().is_some());
        assert!(Time::from_repr("19000229000000Z").components().is_none());
        // 2000 is a leap year (divisible by 400).
        assert!(Time::from_repr("20000229000000Z").components().is_some());
        // A validity built from an invalid not-after time fail-closes.
        let v = Validity::new(
            Time::from_repr("240101000000Z"),
            Time::from_repr("241301000000Z"), // month 13
        );
        assert!(!v.accepts(&Time::utc(2026, 5, 26, 12, 0, 0)));
    }

    #[test]
    fn utctime_century_rule_and_generalized() {
        // UTCTime: YY < 50 => 20YY, so 49 (2049) sorts after 24 (2024).
        let v = Validity::new(
            Time::from_repr("240101000000Z"),
            Time::from_repr("490101000000Z"),
        );
        assert!(v.accepts(&Time::utc(2030, 6, 1, 0, 0, 0)));
        // A GeneralizedTime instant compares correctly against UTCTime bounds.
        assert!(v.accepts(&Time::from_repr("20300601000000Z")));
        assert!(!v.accepts(&Time::from_repr("20500101000000Z")));
    }

    #[test]
    fn to_generalized_time_no_panic_on_non_digit_year() {
        // A 13-byte repr whose year field is non-numeric must not underflow the
        // `b - b'0'` widening (debug panic / release wrap). It falls through to
        // the verbatim GeneralizedTime branch.
        let g = Time::from_repr("--0101000000Z").to_generalized_time();
        assert_eq!(g[0], tag::GENERALIZED_TIME);
        // No 4-digit-year widening happened — the body is the original 13 bytes.
        assert_eq!(g[1] as usize, 13);
    }

    #[test]
    fn read_time_binds_format_to_tag() {
        // RFC 5280 §4.1.2.5 binds the body format to the tag. The correct
        // pairings parse...
        let ok_utc = encode_string(tag::UTC_TIME, "240101000000Z");
        let t = read_time(&mut Reader::new(&ok_utc)).unwrap();
        assert_eq!(t.to_unix_checked(), Some(1_704_067_200)); // 2024-01-01
        let ok_gen = encode_string(tag::GENERALIZED_TIME, "20240101000000Z");
        let t = read_time(&mut Reader::new(&ok_gen)).unwrap();
        assert_eq!(t.to_unix_checked(), Some(1_704_067_200));
        // ...a 13-byte (UTCTime-shaped) body under the GeneralizedTime tag is
        // rejected up front — otherwise the century rule would silently apply
        // to a GeneralizedTime, shifting the year by ±100...
        let bad_gen = encode_string(tag::GENERALIZED_TIME, "240101000000Z");
        assert!(read_time(&mut Reader::new(&bad_gen)).is_err());
        // ...a 15-byte (GeneralizedTime-shaped) body under the UTCTime tag is
        // rejected too...
        let bad_utc = encode_string(tag::UTC_TIME, "20240101000000Z");
        assert!(read_time(&mut Reader::new(&bad_utc)).is_err());
        // ...and any other tag (here UTF8String) never parses as a Time.
        let other = encode_string(tag::UTF8_STRING, "240101000000Z");
        assert!(read_time(&mut Reader::new(&other)).is_err());
    }

    #[test]
    fn validity_decode_rejects_tag_format_mismatch() {
        // A Validity whose notAfter is a UTCTime-shaped body under the
        // GeneralizedTime tag must fail to decode.
        let body = [
            encode_string(tag::UTC_TIME, "240101000000Z"),
            encode_string(tag::GENERALIZED_TIME, "340101000000Z"),
        ]
        .concat();
        let der = encode_sequence(&body);
        assert!(Validity::decode(&mut Reader::new(&der)).is_err());
        // The well-formed mixed-tag variant still decodes.
        let body = [
            encode_string(tag::UTC_TIME, "240101000000Z"),
            encode_string(tag::GENERALIZED_TIME, "20340101000000Z"),
        ]
        .concat();
        let der = encode_sequence(&body);
        let v = Validity::decode(&mut Reader::new(&der)).unwrap();
        assert!(v.accepts(&Time::utc(2026, 5, 26, 12, 0, 0)));
    }

    #[test]
    fn to_unix_checked_distinguishes_malformed_from_epoch() {
        // Malformed → None, not 0.
        assert_eq!(Time::from_repr("garbage").to_unix_checked(), None);
        assert_eq!(Time::from_repr("241301000000Z").to_unix_checked(), None); // month 13
        // But `to_unix` still coerces malformed to 0 for back-compat.
        assert_eq!(Time::from_repr("garbage").to_unix(), 0);
        // A real time agrees between the two accessors.
        let t = Time::from_repr("20210101000000Z");
        assert_eq!(t.to_unix_checked(), Some(1_609_459_200));
        assert_eq!(t.to_unix(), 1_609_459_200);
    }
}
