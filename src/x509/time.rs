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
}

fn push2(s: &mut String, v: u8) {
    s.push((b'0' + (v / 10) % 10) as char);
    s.push((b'0' + v % 10) as char);
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

fn read_time(reader: &mut Reader) -> Result<Time, Error> {
    let (t, value) = reader.read_any()?;
    if t != tag::UTC_TIME && t != tag::GENERALIZED_TIME {
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
}
